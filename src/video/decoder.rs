//! HEVC and H.264 decoding through libavcodec, using NVDEC (CUDA) or VAAPI
//! when available and falling back to the software decoder.
//!
//! All tiles go through one decoder context: tiles are separate pictures in
//! one coded sequence and reference each other. Output frames are mapped
//! back to tiles by PTS.

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::{Result, anyhow, bail};

use super::ffi::{self, AVPixelFormat as PixFmt};
use crate::codec::Codec;

/// One image plane: `rows` rows of `stride` bytes, of which the first
/// `width * texel bytes` are pixels. The last row may be only that long.
#[derive(Clone, Copy)]
pub struct PlaneRef<'a> {
    pub data: &'a [u8],
    pub stride: u32,
    /// Size in texels.
    pub width: u32,
    pub height: u32,
}

/// Owns a reference to a decoded (or downloaded) frame so its planes can be
/// read without copying. The buffer is recycled once the last reference drops.
struct FrameRef(*mut ffi::AVFrame);

// The frame is refcounted and never written once decoded.
unsafe impl Send for FrameRef {}

impl Drop for FrameRef {
    fn drop(&mut self) {
        unsafe { ffi::av_frame_free(&mut self.0) };
    }
}

/// How a picture's samples are laid out in its planes. The renderer uploads
/// each plane as one texture and picks the channels apart in the shader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Y, U (Cb) and V (Cr) planes of one byte per sample.
    Planar,
    /// A Y plane and an interleaved U/V plane (NV12, NV24).
    SemiPlanar,
    /// One plane of V, U, Y, X/A bytes per pixel (VUYX, VUYA).
    Vuyx,
}

impl Layout {
    pub fn planes(self) -> usize {
        match self {
            Layout::Planar => 3,
            Layout::SemiPlanar => 2,
            Layout::Vuyx => 1,
        }
    }

    /// Bytes per texel of plane `i`.
    pub fn texel_bytes(self, i: usize) -> u32 {
        match (self, i) {
            (Layout::SemiPlanar, 1) => 2,
            (Layout::Vuyx, _) => 4,
            _ => 1,
        }
    }
}

/// A decoded picture.
pub struct Picture {
    pub pts: i64,
    pub width: u32,
    pub height: u32,
    pub chroma_width: u32,
    pub chroma_height: u32,
    pub layout: Layout,
    frame: FrameRef,
    /// The decoder flagged concealment or a reference error in this frame.
    pub damaged: bool,
}

impl Picture {
    /// Plane `i` of `layout.planes()`; plane 0 holds luma.
    pub fn plane(&self, i: usize) -> PlaneRef<'_> {
        let (w, h) = match (self.layout, i) {
            (Layout::Vuyx, _) | (_, 0) => (self.width, self.height),
            _ => (self.chroma_width, self.chroma_height),
        };
        let row = (w * self.layout.texel_bytes(i)) as usize;
        unsafe {
            let f = self.frame.0;
            let stride = (*f).linesize[i] as u32;
            let len = if h == 0 { 0 } else { (h - 1) as usize * stride as usize + row };
            PlaneRef { data: std::slice::from_raw_parts((*f).data[i], len), stride, width: w, height: h }
        }
    }
}

/// Which decoder to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum DecoderKind {
    /// CUDA, then VAAPI, then software.
    #[default]
    Auto,
    Cuda,
    Vaapi,
    Software,
}

/// How to open the decoder.
#[derive(Debug, Clone)]
pub struct DecoderOptions {
    pub kind: DecoderKind,
    pub codec: Codec,
    /// Software decoding threads. Apple's stream enables wavefront parallel
    /// processing with entry points, so slice threading splits each picture
    /// by CTU row without delaying output. Past ~5 threads the 16-row tiles
    /// stop scaling and synchronisation costs win.
    pub threads: u32,
    /// DRM render node for VAAPI; None lets FFmpeg pick.
    pub vaapi_device: Option<String>,
}

impl DecoderOptions {
    /// Backends to try, in order. Software is always last.
    pub fn candidates(&self) -> &'static [Backend] {
        match self.kind {
            DecoderKind::Auto => &[Backend::Cuda, Backend::Vaapi, Backend::Software],
            DecoderKind::Cuda => &[Backend::Cuda, Backend::Software],
            DecoderKind::Vaapi => &[Backend::Vaapi, Backend::Software],
            DecoderKind::Software => &[Backend::Software],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Cuda,
    Vaapi,
    Software,
}

impl Backend {
    pub fn is_hw(self) -> bool {
        self != Backend::Software
    }
}

/// Hardware backends that failed on the host's stream, as `1 << Backend`.
/// Kept for the process so reconnects skip them instead of wasting a
/// keyframe on each.
static BROKEN: AtomicU8 = AtomicU8::new(0);

/// Skips `backend` in `Decoder::open_first` from now on.
pub fn remember_broken(backend: Backend) {
    if backend.is_hw() {
        BROKEN.fetch_or(1 << backend as u8, Ordering::Relaxed);
    }
}

pub struct Decoder {
    ctx: *mut ffi::AVCodecContext,
    pkt: *mut ffi::AVPacket,
    frame: *mut ffi::AVFrame,
    backend: Backend,
    /// Pixel format of hardware frames, for hardware backends.
    hw_fmt: Option<PixFmt::Type>,
    /// Frames libavcodec marks corrupt only for coming before its idea of a
    /// recovery point are shown; see `open`.
    show_unrecovered: bool,
    warned_format: bool,
    broken: bool,
}

// The decoder is used from a single thread at a time; the raw pointers are
// owned exclusively by this struct.
unsafe impl Send for Decoder {}

fn av_err(code: i32) -> String {
    let mut buf = [0 as std::os::raw::c_char; 128];
    unsafe {
        ffi::av_strerror(code, buf.as_mut_ptr(), buf.len());
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

fn pix_fmt_name(fmt: PixFmt::Type) -> String {
    let name = unsafe { ffi::av_get_pix_fmt_name(fmt) };
    if name.is_null() { format!("#{fmt}") } else { unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned() }
}

const EAGAIN: i32 = -(libc::EAGAIN);

/// Takes the hardware format `HW` if libavcodec offers it. Otherwise the
/// default is software decoding, which `extract` notices and reports.
unsafe extern "C" fn pick_format<const HW: PixFmt::Type>(
    ctx: *mut ffi::AVCodecContext,
    fmts: *const PixFmt::Type,
) -> PixFmt::Type {
    unsafe {
        let mut p = fmts;
        while *p != PixFmt::AV_PIX_FMT_NONE {
            if *p == HW {
                return HW;
            }
            p = p.add(1);
        }
        ffi::avcodec_default_get_format(ctx, fmts)
    }
}

pub fn set_log_level(verbose: bool) {
    let level = if verbose { ffi::AV_LOG_ERROR as i32 } else { ffi::AV_LOG_QUIET };
    unsafe { ffi::av_log_set_level(level) };
}

impl Decoder {
    pub fn new(opts: &DecoderOptions) -> Result<Self> {
        Self::open_first(opts.candidates(), opts)
    }

    /// Opens the first of `backends` that works.
    pub fn open_first(backends: &[Backend], opts: &DecoderOptions) -> Result<Self> {
        let mut last = None;
        for &b in backends {
            if BROKEN.load(Ordering::Relaxed) & (1 << b as u8) != 0 {
                tracing::debug!("skipping {b:?}: it failed on this stream earlier");
                continue;
            }
            match Self::open(b, opts) {
                Ok(d) => return Ok(d),
                // Expected for auto on most machines; not when asked for.
                Err(e) if opts.kind == DecoderKind::Auto => {
                    tracing::info!("{b:?} decoding unavailable: {e:#}");
                    last = Some(e);
                }
                Err(e) => {
                    tracing::warn!("{b:?} decoding unavailable: {e:#}");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no decoder backend")))
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The hardware backend can't show this stream: frame download failed,
    /// the downloaded format is unsupported, or libavcodec quietly decoded
    /// in software. Reopen with the next backend.
    pub fn broken(&self) -> bool {
        self.broken
    }

    fn open(backend: Backend, opts: &DecoderOptions) -> Result<Self> {
        unsafe {
            let id = match opts.codec {
                Codec::Hevc => ffi::AVCodecID::AV_CODEC_ID_HEVC,
                Codec::H264 => ffi::AVCodecID::AV_CODEC_ID_H264,
            };
            let codec = ffi::avcodec_find_decoder(id);
            if codec.is_null() {
                bail!("libavcodec has no {} decoder", opts.codec);
            }
            let ctx = ffi::avcodec_alloc_context3(codec);
            if ctx.is_null() {
                bail!("avcodec_alloc_context3 failed");
            }
            let mut dec = Decoder {
                ctx,
                pkt: ffi::av_packet_alloc(),
                frame: ffi::av_frame_alloc(),
                backend,
                hw_fmt: None,
                show_unrecovered: opts.codec == Codec::H264,
                warned_format: false,
                broken: false,
            };
            if dec.pkt.is_null() || dec.frame.is_null() {
                bail!("allocating FFmpeg packet/frame failed");
            }
            (*ctx).flags |= ffi::AV_CODEC_FLAG_LOW_DELAY as i32;
            (*ctx).flags2 |= ffi::AV_CODEC_FLAG2_FAST as i32;
            if dec.show_unrecovered {
                // Apple's H.264 keyframes are mostly I slices, not IDRs, and
                // libavcodec shows nothing after a non-IDR start until a
                // recovery point it may never see. The session only feeds
                // the decoder from a keyframe, so show those pictures.
                (*ctx).flags |= ffi::AV_CODEC_FLAG_OUTPUT_CORRUPT as i32;
            }
            let hw = match backend {
                Backend::Cuda => Some((ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_CUDA, PixFmt::AV_PIX_FMT_CUDA, None)),
                Backend::Vaapi => {
                    let dev = opts.vaapi_device.as_deref().map(CString::new).transpose()?;
                    Some((ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI, PixFmt::AV_PIX_FMT_VAAPI, dev))
                }
                Backend::Software => None,
            };
            if let Some((ty, fmt, name)) = hw {
                let mut dev = ptr::null_mut();
                let name_ptr = name.as_ref().map_or(ptr::null(), |n| n.as_ptr());
                // No timeout: a driver that hangs here (or later inside a
                // hardware decode) stalls video for good and no fallback
                // runs. These logs show where it stopped.
                tracing::debug!("{backend:?}: creating device {name:?}");
                let r = ffi::av_hwdevice_ctx_create(&mut dev, ty, name_ptr, ptr::null_mut(), 0);
                tracing::debug!("{backend:?}: device created: {}", if r < 0 { av_err(r) } else { "ok".into() });
                if r < 0 {
                    bail!("{backend:?} device: {}", av_err(r));
                }
                (*ctx).hw_device_ctx = dev;
                (*ctx).get_format = Some(if fmt == PixFmt::AV_PIX_FMT_CUDA {
                    pick_format::<{ PixFmt::AV_PIX_FMT_CUDA }>
                } else {
                    pick_format::<{ PixFmt::AV_PIX_FMT_VAAPI }>
                });
                dec.hw_fmt = Some(fmt);
            } else {
                // Not 0 (auto): that picks one thread per core plus one, and
                // on Apple Silicon the extra efficiency-core threads make
                // decoding nearly twice as slow as 4.
                (*ctx).thread_type = ffi::FF_THREAD_SLICE as i32;
                (*ctx).thread_count = opts.threads.max(1) as i32;
            }
            let r = ffi::avcodec_open2(ctx, codec, ptr::null_mut());
            if r < 0 {
                bail!("avcodec_open2: {}", av_err(r));
            }
            Ok(dec)
        }
    }

    /// Decodes one access unit (Annex B). Calls `out` for every picture the
    /// decoder emits. Returns false if libavcodec rejected the data.
    pub fn decode(&mut self, annexb: &[u8], pts: i64, out: &mut impl FnMut(Picture)) -> bool {
        let mut ok = true;
        unsafe {
            let pad = ffi::AV_INPUT_BUFFER_PADDING_SIZE as usize;
            if ffi::av_new_packet(self.pkt, annexb.len() as i32) < 0 {
                return false;
            }
            ptr::copy_nonoverlapping(annexb.as_ptr(), (*self.pkt).data, annexb.len());
            ptr::write_bytes((*self.pkt).data.add(annexb.len()), 0, pad);
            (*self.pkt).pts = pts;
            (*self.pkt).dts = pts;
            let r = ffi::avcodec_send_packet(self.ctx, self.pkt);
            ffi::av_packet_unref(self.pkt);
            if r < 0 && r != EAGAIN {
                tracing::debug!("decode error: {}", av_err(r));
                ok = false;
            }
            loop {
                let r = ffi::avcodec_receive_frame(self.ctx, self.frame);
                if r < 0 {
                    if r != EAGAIN {
                        tracing::debug!("receive_frame: {}", av_err(r));
                    }
                    break;
                }
                if let Some(p) = self.extract() {
                    out(p);
                }
                ffi::av_frame_unref(self.frame);
            }
        }
        ok
    }

    /// Wraps the received frame as a Picture, downloading it first if it's
    /// in GPU memory. No plane is copied on the CPU.
    unsafe fn extract(&mut self) -> Option<Picture> {
        unsafe {
            let f = self.frame;
            let corrupt = ((*f).flags & ffi::AV_FRAME_FLAG_CORRUPT as i32) != 0;
            let damaged = (*f).decode_error_flags != 0 || (corrupt && !self.show_unrecovered);
            let pts = (*f).pts;
            // For hardware frames: whether the stream is 4:4:4. Drivers may
            // download other bit depths under an 8-bit format, so only
            // streams software decoding could show are accepted.
            let mut full_chroma = None;
            let frame = if Some((*f).format) == self.hw_fmt {
                let stream = (*self.ctx).sw_pix_fmt;
                full_chroma = match stream {
                    x if x == PixFmt::AV_PIX_FMT_YUV444P || x == PixFmt::AV_PIX_FMT_YUVJ444P => Some(true),
                    x if x == PixFmt::AV_PIX_FMT_YUV420P || x == PixFmt::AV_PIX_FMT_YUVJ420P => Some(false),
                    other => return self.unsupported(other),
                };
                // Downloads in the first format the driver offers.
                let mut sw = ffi::av_frame_alloc();
                if sw.is_null() {
                    return None;
                }
                let r = ffi::av_hwframe_transfer_data(sw, f, 0);
                if r < 0 {
                    ffi::av_frame_free(&mut sw);
                    if !self.broken {
                        tracing::warn!("GPU frame download failed: {}", av_err(r));
                    }
                    self.broken = true;
                    return None;
                }
                FrameRef(sw)
            } else {
                if self.backend.is_hw() && !self.broken {
                    tracing::warn!(
                        "{:?} does not support this stream; libavcodec fell back to software ({})",
                        self.backend,
                        pix_fmt_name((*f).format)
                    );
                    self.broken = true;
                }
                let r = ffi::av_frame_clone(f);
                if r.is_null() {
                    return None;
                }
                FrameRef(r)
            };
            let (w, h) = ((*frame.0).width as u32, (*frame.0).height as u32);
            let half = (w.div_ceil(2), h.div_ceil(2));
            let (layout, (cw, ch)) = match (*frame.0).format {
                x if x == PixFmt::AV_PIX_FMT_YUV444P || x == PixFmt::AV_PIX_FMT_YUVJ444P => (Layout::Planar, (w, h)),
                x if x == PixFmt::AV_PIX_FMT_YUV420P || x == PixFmt::AV_PIX_FMT_YUVJ420P => (Layout::Planar, half),
                x if x == PixFmt::AV_PIX_FMT_NV12 => (Layout::SemiPlanar, half),
                x if x == PixFmt::AV_PIX_FMT_NV24 => (Layout::SemiPlanar, (w, h)),
                x if x == PixFmt::AV_PIX_FMT_VUYX || x == PixFmt::AV_PIX_FMT_VUYA => (Layout::Vuyx, (w, h)),
                other => return self.unsupported(other),
            };
            if full_chroma.is_some_and(|full| full != (cw == w)) {
                return self.unsupported((*frame.0).format);
            }
            Some(Picture {
                pts,
                width: w,
                height: h,
                chroma_width: cw,
                chroma_height: ch,
                layout,
                frame,
                damaged,
            })
        }
    }

    /// Logs `fmt` once. A hardware backend is then broken: software
    /// decoding may yield a format we can show.
    fn unsupported(&mut self, fmt: PixFmt::Type) -> Option<Picture> {
        if !self.warned_format {
            self.warned_format = true;
            tracing::error!("{:?}: unsupported decoded pixel format {}", self.backend, pix_fmt_name(fmt));
        }
        self.broken |= self.backend.is_hw();
        None
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe {
            ffi::av_frame_free(&mut self.frame);
            ffi::av_packet_free(&mut self.pkt);
            ffi::avcodec_free_context(&mut self.ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::h264;

    /// The NAL units of an Annex B stream.
    fn nal_units(data: &[u8]) -> Vec<&[u8]> {
        let mut starts = Vec::new();
        let mut i = 0;
        while i + 3 <= data.len() {
            if data[i..i + 3] == [0, 0, 1] {
                starts.push(i + 3);
                i += 3;
            } else {
                i += 1;
            }
        }
        starts
            .iter()
            .enumerate()
            .map(|(k, &s)| {
                let mut end = starts.get(k + 1).map_or(data.len(), |&n| n - 3);
                while end > s && data[end - 1] == 0 {
                    end -= 1;
                }
                &data[s..end]
            })
            .collect()
    }

    /// Groups NAL units into Annex B access units (a new one starts at each
    /// slice that begins a picture, or a non-VCL unit after slices).
    fn group_access_units<'a>(nals: impl IntoIterator<Item = &'a [u8]>, codec: Codec) -> Vec<Vec<u8>> {
        let mut aus: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        let mut cur_has_slice = false;
        for nal in nals {
            let slice = codec.is_slice(nal);
            if cur_has_slice && (!slice || codec.first_in_picture(nal)) {
                aus.push(std::mem::take(&mut cur));
                cur_has_slice = false;
            }
            cur.extend_from_slice(&[0, 0, 0, 1]);
            cur.extend_from_slice(nal);
            cur_has_slice |= slice;
        }
        if !cur.is_empty() {
            aus.push(cur);
        }
        aus
    }

    fn access_units(data: &[u8]) -> Vec<Vec<u8>> {
        group_access_units(nal_units(data), Codec::Hevc)
    }

    /// Y, U and V of a picture, unpacked to one byte per sample, so every
    /// layout can be compared with software output.
    fn samples(p: &Picture) -> [Vec<u8>; 3] {
        let mut out: [Vec<u8>; 3] = Default::default();
        for (c, o) in out.iter_mut().enumerate() {
            // Plane and byte within a texel holding component c.
            let (i, off) = match p.layout {
                Layout::Planar => (c, 0),
                Layout::SemiPlanar => (c.min(1), c.saturating_sub(1)),
                Layout::Vuyx => (0, [2, 1, 0][c]),
            };
            let pl = p.plane(i);
            let bpt = p.layout.texel_bytes(i);
            assert!(pl.stride >= pl.width * bpt);
            assert_eq!(pl.data.len(), ((pl.height - 1) * pl.stride + pl.width * bpt) as usize);
            let (w, h) = if c == 0 { (p.width, p.height) } else { (p.chroma_width, p.chroma_height) };
            if i > 0 {
                assert_eq!((pl.width, pl.height), (w, h));
            }
            for y in 0..h {
                let row = &pl.data[(y * pl.stride) as usize..];
                o.extend((0..w).map(|x| row[(x * bpt) as usize + off]));
            }
        }
        out
    }

    struct Decoded {
        backend: Backend,
        broken: bool,
        layout: Option<Layout>,
        dims: Vec<(u32, u32, u32, u32)>,
        samples: Vec<[Vec<u8>; 3]>,
        damaged: usize,
    }

    fn decode_file(path: &str, backend: Backend, threads: u32) -> Option<Decoded> {
        decode_aus(&access_units(&std::fs::read(path).unwrap()), Codec::Hevc, backend, threads)
    }

    fn decode_aus(aus: &[Vec<u8>], codec: Codec, backend: Backend, threads: u32) -> Option<Decoded> {
        let vaapi_device = std::env::var("MACSHARE_VAAPI_DEVICE").ok();
        let opts = DecoderOptions { kind: DecoderKind::Auto, codec, threads, vaapi_device };
        let mut d = match Decoder::open_first(&[backend], &opts) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{backend:?}: {e:#}");
                return None;
            }
        };
        let (mut layout, mut dims, mut pics, mut damaged) = (None, Vec::new(), Vec::new(), 0);
        for (i, au) in aus.iter().enumerate() {
            d.decode(au, i as i64, &mut |p: Picture| {
                layout = Some(p.layout);
                dims.push((p.width, p.height, p.chroma_width, p.chroma_height));
                pics.push(samples(&p));
                damaged += p.damaged as usize;
            });
        }
        Some(Decoded { backend: d.backend(), broken: d.broken(), layout, dims, samples: pics, damaged })
    }

    /// H.264 access units the way the session feeds them: SPS patched for
    /// Apple's reference count, starting from the `skip_keyframes`th
    /// keyframe (with the parameter sets kept).
    fn h264_access_units(path: &str, skip_keyframes: usize) -> Vec<Vec<u8>> {
        let data = std::fs::read(path).unwrap();
        let nals = nal_units(&data);
        let params: Vec<Vec<u8>> =
            nals.iter().filter(|n| h264::is_param_set(n)).map(|n| h264::patch_sps_dpb(n)).collect();
        let from = nals
            .iter()
            .enumerate()
            .filter(|(_, n)| h264::is_keyframe(n) && h264::first_in_picture(n))
            .nth(skip_keyframes)
            .map(|(i, _)| i)
            .expect("not enough keyframes");
        let rest = nals[from..].iter().copied().filter(|n| !h264::is_param_set(n));
        group_access_units(params.iter().map(|p| p.as_slice()).chain(rest), Codec::H264)
    }

    /// Needs MACSHARE_TEST_HEVC_DIR containing t264.h264 (1280x720 4:2:0,
    /// 30 frames). Its SPS is patched as the session does. Every backend
    /// that opens must match software output. x264's B-frames leave the
    /// last two pictures in the reorder buffer, since nothing flushes it.
    #[test]
    #[ignore]
    fn decodes_h264_stream() {
        let dir = std::env::var("MACSHARE_TEST_HEVC_DIR").expect("MACSHARE_TEST_HEVC_DIR");
        let aus = h264_access_units(&format!("{dir}/t264.h264"), 0);
        let reference = decode_aus(&aus, Codec::H264, Backend::Software, 1).unwrap();
        assert!(reference.dims.len() >= 28 && reference.damaged == 0, "{}", reference.dims.len());
        for (backend, threads) in [(Backend::Software, 4), (Backend::Cuda, 1), (Backend::Vaapi, 1)] {
            let Some(got) = decode_aus(&aus, Codec::H264, backend, threads) else {
                eprintln!("t264 {backend:?}: unavailable");
                continue;
            };
            eprintln!(
                "t264 {backend:?} threads={threads}: {:?}{}, {} pictures ({} damaged), {:?}",
                got.backend,
                if got.broken { " (broken: would fall back)" } else { "" },
                got.dims.len(),
                got.damaged,
                got.layout,
            );
            assert!(!got.broken, "{backend:?} can't show H.264 4:2:0");
            assert!(got.dims.len() >= 25 && got.damaged == 0, "{backend:?}");
            assert!(got.dims.iter().all(|&p| p == (1280, 720, 640, 360)));
            for (k, (a, b)) in got.samples.iter().zip(&reference.samples).enumerate() {
                assert!(a == b, "t264 {backend:?}: picture {k} differs from software");
            }
        }
    }

    /// Starting from a non-IDR I picture, as Apple's H.264 keyframes mostly
    /// are, still shows pictures. Needs t264open.h264 in
    /// MACSHARE_TEST_HEVC_DIR: open GOPs, 4 references and no SEI, so
    /// libavcodec sees no recovery point:
    /// ffmpeg -f lavfi -i testsrc2=size=1280x720 -frames:v 60 -c:v libx264 -bf 2
    ///   -x264-params keyint=20:min-keyint=20:open-gop=1:scenecut=0:ref=4
    ///   -pix_fmt yuv420p -bsf:v filter_units=remove_types=6 -f h264 t264open.h264
    #[test]
    #[ignore]
    fn h264_starts_from_non_idr_keyframe() {
        let dir = std::env::var("MACSHARE_TEST_HEVC_DIR").expect("MACSHARE_TEST_HEVC_DIR");
        let path = format!("{dir}/t264open.h264");
        if !std::path::Path::new(&path).exists() {
            eprintln!("t264open.h264: missing");
            return;
        }
        let aus = h264_access_units(&path, 1);
        for backend in [Backend::Software, Backend::Cuda, Backend::Vaapi] {
            let Some(got) = decode_aus(&aus, Codec::H264, backend, 1) else { continue };
            eprintln!("t264open {backend:?}: {} of {} pictures, {} damaged", got.dims.len(), aus.len(), got.damaged);
            assert!(got.dims.len() + 4 >= aus.len(), "{backend:?}");
        }
    }

    /// Needs sample streams: MACSHARE_TEST_HEVC_DIR containing t444.hevc and
    /// t420.hevc (1280x720, 30 frames). Hardware backends that can't open
    /// are skipped; one that opens must either match software output
    /// exactly or report itself broken, so the session falls back.
    #[test]
    #[ignore]
    fn decodes_sample_streams() {
        let dir = std::env::var("MACSHARE_TEST_HEVC_DIR").expect("MACSHARE_TEST_HEVC_DIR");
        let runs = [(Backend::Software, 1), (Backend::Software, 4), (Backend::Cuda, 1), (Backend::Vaapi, 1)];
        for (file, chroma) in [("t444.hevc", (1280, 720)), ("t420.hevc", (640, 360))] {
            let path = format!("{dir}/{file}");
            let reference = decode_file(&path, Backend::Software, 1).unwrap();
            for (backend, threads) in runs {
                let Some(got) = decode_file(&path, backend, threads) else {
                    assert!(backend.is_hw());
                    eprintln!("{file} {backend:?}: unavailable");
                    continue;
                };
                eprintln!(
                    "{file} {backend:?} threads={threads}: {:?}{}, {} pictures, {:?}",
                    got.backend,
                    if got.broken { " (broken: would fall back)" } else { "" },
                    got.dims.len(),
                    got.layout,
                );
                if got.broken {
                    assert!(backend.is_hw());
                    continue;
                }
                // The decoder may hold back the last few pictures.
                assert!(got.dims.len() >= 25, "{file}: only {} pictures", got.dims.len());
                assert!(got.dims.iter().all(|&p| p == (1280, 720, chroma.0, chroma.1)));
                for (k, (a, b)) in got.samples.iter().zip(&reference.samples).enumerate() {
                    for c in 0..3 {
                        assert!(a[c] == b[c], "{file} {backend:?}: picture {k} component {c} differs from software");
                    }
                }
            }
        }
    }

    /// Streams a hardware decoder may not take, from MACSHARE_TEST_HEVC_DIR
    /// if present: t444p10.hevc (yuv444p10, 1280x720: downloads in a format
    /// we can't show) and twide.hevc (yuv420p, 8448x256: past NVDEC's width
    /// limit, so libavcodec decodes in software). Whatever a hardware
    /// backend can't show must leave it broken.
    #[test]
    #[ignore]
    fn hw_rejects_unsupported_streams() {
        let dir = std::env::var("MACSHARE_TEST_HEVC_DIR").expect("MACSHARE_TEST_HEVC_DIR");
        for file in ["t444p10.hevc", "twide.hevc"] {
            let path = format!("{dir}/{file}");
            if !std::path::Path::new(&path).exists() {
                eprintln!("{file}: missing");
                continue;
            }
            let reference = decode_file(&path, Backend::Software, 4).unwrap();
            for backend in [Backend::Cuda, Backend::Vaapi] {
                let Some(got) = decode_file(&path, backend, 1) else { continue };
                eprintln!(
                    "{file} {backend:?}: broken {}, {} pictures, {:?} (software: {} pictures)",
                    got.broken,
                    got.dims.len(),
                    got.layout,
                    reference.dims.len()
                );
                if !got.broken {
                    assert!(got.samples == reference.samples, "{file} {backend:?} differs from software");
                }
            }
        }
    }

    /// Times software decoding of a captured stream (MACSHARE_DUMP_HEVC)
    /// at several thread counts:
    /// MACSHARE_BENCH_HEVC=stream.hevc cargo test --release bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_threads() {
        let path = std::env::var("MACSHARE_BENCH_HEVC").expect("MACSHARE_BENCH_HEVC");
        let aus = access_units(&std::fs::read(path).unwrap());
        for threads in [1, 2, 3, 4, 5, 6, 8] {
            let opts = DecoderOptions { kind: DecoderKind::Software, codec: Codec::Hevc, threads, vaapi_device: None };
            let mut d = Decoder::new(&opts).unwrap();
            let mut pics = 0;
            let started = std::time::Instant::now();
            for (i, au) in aus.iter().enumerate() {
                d.decode(au, i as i64, &mut |_| pics += 1);
            }
            let secs = started.elapsed().as_secs_f64();
            eprintln!("{threads} threads: {secs:.2} s, {:.0} pictures/s ({pics} pictures)", pics as f64 / secs);
        }
    }
}
