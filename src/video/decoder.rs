//! HEVC decoding through libavcodec, using NVDEC (CUDA) when available and
//! falling back to the software decoder.
//!
//! All tiles go through one decoder context: tiles are separate pictures in
//! one coded sequence and reference each other. Output frames are mapped
//! back to tiles by PTS.

use std::ffi::CStr;
use std::ptr;

use anyhow::{Result, bail};

use super::ffi::{self, AVPixelFormat as PixFmt};

/// A decoded picture with tightly packed planes (stride == width).
pub struct Picture {
    pub pts: i64,
    pub width: u32,
    pub height: u32,
    pub chroma_width: u32,
    pub chroma_height: u32,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    /// The decoder flagged concealment or a reference error in this frame.
    pub damaged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Cuda,
    Software,
}

pub struct Decoder {
    ctx: *mut ffi::AVCodecContext,
    pkt: *mut ffi::AVPacket,
    frame: *mut ffi::AVFrame,
    sw_frame: *mut ffi::AVFrame,
    backend: Backend,
    warned_format: bool,
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

const EAGAIN: i32 = -(libc::EAGAIN);

unsafe extern "C" fn pick_format(ctx: *mut ffi::AVCodecContext, fmts: *const PixFmt::Type) -> PixFmt::Type {
    unsafe {
        if !(*ctx).hw_device_ctx.is_null() {
            let mut p = fmts;
            while *p != PixFmt::AV_PIX_FMT_NONE {
                if *p == PixFmt::AV_PIX_FMT_CUDA {
                    return *p;
                }
                p = p.add(1);
            }
        }
        ffi::avcodec_default_get_format(ctx, fmts)
    }
}

pub fn set_log_level(verbose: bool) {
    let level = if verbose { ffi::AV_LOG_ERROR as i32 } else { ffi::AV_LOG_QUIET };
    unsafe { ffi::av_log_set_level(level) };
}

impl Decoder {
    pub fn new(prefer_hw: bool) -> Result<Self> {
        if prefer_hw {
            match Self::open(true) {
                Ok(d) => return Ok(d),
                Err(e) => tracing::warn!("hardware decoding unavailable ({e}); using software"),
            }
        }
        Self::open(false)
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    fn open(hw: bool) -> Result<Self> {
        unsafe {
            let codec = ffi::avcodec_find_decoder(ffi::AVCodecID::AV_CODEC_ID_HEVC);
            if codec.is_null() {
                bail!("libavcodec has no HEVC decoder");
            }
            let ctx = ffi::avcodec_alloc_context3(codec);
            if ctx.is_null() {
                bail!("avcodec_alloc_context3 failed");
            }
            let dec = Decoder {
                ctx,
                pkt: ffi::av_packet_alloc(),
                frame: ffi::av_frame_alloc(),
                sw_frame: ffi::av_frame_alloc(),
                backend: if hw { Backend::Cuda } else { Backend::Software },
                warned_format: false,
            };
            if dec.pkt.is_null() || dec.frame.is_null() || dec.sw_frame.is_null() {
                bail!("allocating FFmpeg packet/frame failed");
            }
            (*ctx).flags |= ffi::AV_CODEC_FLAG_LOW_DELAY as i32;
            (*ctx).flags2 |= ffi::AV_CODEC_FLAG2_FAST as i32;
            if hw {
                let mut dev = ptr::null_mut();
                let r = ffi::av_hwdevice_ctx_create(
                    &mut dev,
                    ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_CUDA,
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                );
                if r < 0 {
                    bail!("CUDA device: {}", av_err(r));
                }
                (*ctx).hw_device_ctx = dev;
                (*ctx).get_format = Some(pick_format);
            } else {
                (*ctx).thread_type = ffi::FF_THREAD_SLICE as i32;
                (*ctx).thread_count = 0;
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

    unsafe fn extract(&mut self) -> Option<Picture> {
        unsafe {
            let mut f = self.frame;
            let damaged = (*f).decode_error_flags != 0 || ((*f).flags & ffi::AV_FRAME_FLAG_CORRUPT as i32) != 0;
            let pts = (*f).pts;
            if (*f).format == PixFmt::AV_PIX_FMT_CUDA {
                ffi::av_frame_unref(self.sw_frame);
                let r = ffi::av_hwframe_transfer_data(self.sw_frame, f, 0);
                if r < 0 {
                    tracing::warn!("GPU frame download failed: {}", av_err(r));
                    return None;
                }
                f = self.sw_frame;
            }
            let (w, h) = ((*f).width as usize, (*f).height as usize);
            let fmt = (*f).format;
            let plane = |i: usize, pw: usize, ph: usize| -> Vec<u8> {
                let stride = (*f).linesize[i] as usize;
                let base = (*f).data[i];
                let mut v = Vec::with_capacity(pw * ph);
                for row in 0..ph {
                    v.extend_from_slice(std::slice::from_raw_parts(base.add(row * stride), pw));
                }
                v
            };
            let (y, u, v, cw, ch) = match fmt {
                x if x == PixFmt::AV_PIX_FMT_YUV444P || x == PixFmt::AV_PIX_FMT_YUVJ444P => {
                    (plane(0, w, h), plane(1, w, h), plane(2, w, h), w, h)
                }
                x if x == PixFmt::AV_PIX_FMT_YUV420P || x == PixFmt::AV_PIX_FMT_YUVJ420P => {
                    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
                    (plane(0, w, h), plane(1, cw, ch), plane(2, cw, ch), cw, ch)
                }
                x if x == PixFmt::AV_PIX_FMT_NV12 || x == PixFmt::AV_PIX_FMT_NV24 => {
                    let (cw, ch) = if x == PixFmt::AV_PIX_FMT_NV12 {
                        (w.div_ceil(2), h.div_ceil(2))
                    } else {
                        (w, h)
                    };
                    let uv = plane(1, cw * 2, ch);
                    let (u, v) = uv.as_chunks::<2>().0.iter().map(|p| (p[0], p[1])).unzip();
                    (plane(0, w, h), u, v, cw, ch)
                }
                other => {
                    if !self.warned_format {
                        self.warned_format = true;
                        let name = ffi::av_get_pix_fmt_name(other);
                        let name =
                            if name.is_null() { "?".into() } else { CStr::from_ptr(name).to_string_lossy() };
                        tracing::error!("unsupported decoded pixel format {name}");
                    }
                    return None;
                }
            };
            Some(Picture {
                pts,
                width: w as u32,
                height: h as u32,
                chroma_width: cw as u32,
                chroma_height: ch as u32,
                y,
                u,
                v,
                damaged,
            })
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe {
            ffi::av_frame_free(&mut self.frame);
            ffi::av_frame_free(&mut self.sw_frame);
            ffi::av_packet_free(&mut self.pkt);
            ffi::avcodec_free_context(&mut self.ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Splits an Annex B stream into access units (a new one starts at each
    /// slice with `first_slice_segment_in_pic_flag`, or a parameter set
    /// after slices).
    fn access_units(data: &[u8]) -> Vec<Vec<u8>> {
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
        let mut aus: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        let mut cur_has_slice = false;
        for (k, &s) in starts.iter().enumerate() {
            let mut end = starts.get(k + 1).map_or(data.len(), |&n| n - 3);
            while end > s && data[end - 1] == 0 {
                end -= 1;
            }
            let nal = &data[s..end];
            let t = (nal[0] >> 1) & 0x3f;
            let first_slice = t <= 31 && nal.len() > 2 && nal[2] & 0x80 != 0;
            if cur_has_slice && (first_slice || (32..=40).contains(&t)) {
                aus.push(std::mem::take(&mut cur));
                cur_has_slice = false;
            }
            cur.extend_from_slice(&[0, 0, 0, 1]);
            cur.extend_from_slice(nal);
            cur_has_slice |= t <= 31;
        }
        if !cur.is_empty() {
            aus.push(cur);
        }
        aus
    }

    fn decode_file(path: &str, hw: bool) -> (Backend, Vec<(u32, u32, u32, u32)>) {
        let data = std::fs::read(path).unwrap();
        let mut d = Decoder::new(hw).unwrap();
        let mut got = Vec::new();
        for (i, au) in access_units(&data).iter().enumerate() {
            d.decode(au, i as i64, &mut |p: Picture| {
                assert_eq!(p.y.len(), (p.width * p.height) as usize);
                assert_eq!(p.u.len(), (p.chroma_width * p.chroma_height) as usize);
                got.push((p.width, p.height, p.chroma_width, p.chroma_height));
            });
        }
        (d.backend(), got)
    }

    /// Needs sample streams: MACSHARE_TEST_HEVC_DIR containing t444.hevc and
    /// t420.hevc (1280x720, 30 frames).
    #[test]
    #[ignore]
    fn decodes_sample_streams() {
        let dir = std::env::var("MACSHARE_TEST_HEVC_DIR").expect("MACSHARE_TEST_HEVC_DIR");
        for hw in [false, true] {
            for (file, chroma) in [("t444.hevc", (1280, 720)), ("t420.hevc", (640, 360))] {
                let (backend, pics) = decode_file(&format!("{dir}/{file}"), hw);
                eprintln!("{file} hw={hw}: {backend:?}, {} pictures", pics.len());
                // Low-delay decoding may hold back the last few pictures.
                assert!(pics.len() >= 25, "{file}: only {} pictures", pics.len());
                assert!(pics.iter().all(|&p| p == (1280, 720, chroma.0, chroma.1)));
            }
        }
    }
}
