//! AAC-ELD with SBR decoding through libfdk-aac, loaded at run time.
//!
//! The host's audio is one raw AAC-ELD access unit per RTP packet (PT 101),
//! 48 kHz stereo, 480 frames (10 ms) each; silence is sent as 4-byte
//! all-zero units. FFmpeg has no AAC-ELD decoder, so libfdk-aac is the only
//! choice on Linux. It's loaded with dlopen rather than linked so it stays
//! optional: without it pippin runs without sound.

use std::ffi::{c_int, c_uint, c_void};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};

/// AudioSpecificConfig the host's encoder uses: AOT 39 (ELD), 48 kHz,
/// stereo, 480-sample frames, low-delay SBR.
const AUDIO_SPECIFIC_CONFIG: [u8; 6] = [0xf8, 0xe6, 0x51, 0x32, 0xe0, 0x00];

pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: usize = 2;

const TT_MP4_RAW: c_int = 0;
const AAC_DEC_OK: c_uint = 0;
/// `aacDecoder_DecodeFrame` flag: synthesize a frame for a lost one.
const AACDEC_CONCEAL: c_uint = 1;
/// Room for the largest frame fdk can produce (2048 samples x 8 channels).
const OUT_SAMPLES: usize = 2048 * 8;

type Handle = *mut c_void;

/// The few libfdk-aac decoder entry points we use.
struct Lib {
    open: unsafe extern "C" fn(c_int, c_uint) -> Handle,
    config_raw: unsafe extern "C" fn(Handle, *mut *mut u8, *const c_uint) -> c_uint,
    fill: unsafe extern "C" fn(Handle, *mut *mut u8, *const c_uint, *mut c_uint) -> c_uint,
    decode_frame: unsafe extern "C" fn(Handle, *mut i16, c_int, c_uint) -> c_uint,
    stream_info: unsafe extern "C" fn(Handle) -> *const StreamInfo,
    close: unsafe extern "C" fn(Handle),
    _lib: libloading::Library,
}

/// Leading fields of fdk's `CStreamInfo`; only these are read.
#[repr(C)]
struct StreamInfo {
    sample_rate: c_int,
    frame_size: c_int,
    num_channels: c_int,
}

fn load() -> Result<Lib> {
    let mut last = None;
    for name in ["libfdk-aac.so.2", "libfdk-aac.so"] {
        // SAFETY: loading a well-known system library; its initializers
        // have no preconditions.
        match unsafe { libloading::Library::new(name) } {
            Ok(lib) => unsafe {
                return Ok(Lib {
                    open: *lib.get(b"aacDecoder_Open\0")?,
                    config_raw: *lib.get(b"aacDecoder_ConfigRaw\0")?,
                    fill: *lib.get(b"aacDecoder_Fill\0")?,
                    decode_frame: *lib.get(b"aacDecoder_DecodeFrame\0")?,
                    stream_info: *lib.get(b"aacDecoder_GetStreamInfo\0")?,
                    close: *lib.get(b"aacDecoder_Close\0")?,
                    _lib: lib,
                });
            },
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow!(last.expect("tried at least one name")))
}

fn lib() -> Result<&'static Lib> {
    static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
    LIB.get_or_init(|| load().map_err(|e| format!("{e:#}")))
        .as_ref()
        .map_err(|e| anyhow!("libfdk-aac is needed for audio ({e})"))
}

/// Whether libfdk-aac can be loaded.
pub fn available() -> Result<()> {
    lib().map(drop)
}

/// One stream's decoder state.
pub struct Decoder {
    lib: &'static Lib,
    handle: Handle,
    out: Vec<i16>,
}

// SAFETY: the handle is owned exclusively and only used through &mut self.
unsafe impl Send for Decoder {}

impl Decoder {
    pub fn new() -> Result<Self> {
        let lib = lib()?;
        // SAFETY: plain FFI calls; the config buffer outlives ConfigRaw,
        // which copies what it needs.
        unsafe {
            let handle = (lib.open)(TT_MP4_RAW, 1);
            if handle.is_null() {
                return Err(anyhow!("aacDecoder_Open failed"));
            }
            let mut asc = AUDIO_SPECIFIC_CONFIG;
            let mut ptr = asc.as_mut_ptr();
            let len = asc.len() as c_uint;
            let err = (lib.config_raw)(handle, &mut ptr, &len);
            if err != AAC_DEC_OK {
                (lib.close)(handle);
                return Err(anyhow!("aacDecoder_ConfigRaw: {err:#x}"));
            }
            Ok(Self { lib, handle, out: vec![0; OUT_SAMPLES] })
        }
    }

    /// Decodes one access unit into interleaved 48 kHz stereo.
    pub fn decode(&mut self, au: &[u8]) -> Result<&[i16]> {
        let mut ptr = au.as_ptr().cast_mut();
        let len = au.len() as c_uint;
        let mut valid = len;
        // SAFETY: fdk only reads `len` bytes from the buffer; it copies them
        // into its own internal buffer before returning.
        let err = unsafe { (self.lib.fill)(self.handle, &mut ptr, &len, &mut valid) };
        if err != AAC_DEC_OK {
            return Err(anyhow!("aacDecoder_Fill: {err:#x}"));
        }
        self.frame(0)
    }

    /// Synthesizes a replacement for a lost access unit.
    pub fn conceal(&mut self) -> Result<&[i16]> {
        self.frame(AACDEC_CONCEAL)
    }

    fn frame(&mut self, flags: c_uint) -> Result<&[i16]> {
        // SAFETY: the output buffer holds OUT_SAMPLES samples, as passed.
        let (err, info) = unsafe {
            let err = (self.lib.decode_frame)(self.handle, self.out.as_mut_ptr(), OUT_SAMPLES as c_int, flags);
            (err, (self.lib.stream_info)(self.handle))
        };
        if err != AAC_DEC_OK {
            return Err(anyhow!("aacDecoder_DecodeFrame: {err:#x}"));
        }
        // SAFETY: fdk returns a pointer into the decoder, valid until the
        // next call on this handle.
        let info = unsafe { info.as_ref() }.context("no stream info")?;
        if info.sample_rate != SAMPLE_RATE as c_int || info.num_channels != CHANNELS as c_int {
            return Err(anyhow!(
                "unexpected stream format: {} Hz, {} channels",
                info.sample_rate,
                info.num_channels
            ));
        }
        let n = (info.frame_size.max(0) as usize * CHANNELS).min(self.out.len());
        Ok(&self.out[..n])
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: the handle came from aacDecoder_Open and is closed once.
        unsafe { (self.lib.close)(self.handle) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_silence_units() {
        let Ok(mut dec) = Decoder::new() else {
            eprintln!("libfdk-aac not installed; skipping");
            return;
        };
        for _ in 0..3 {
            let pcm = dec.decode(&[0; 4]).unwrap();
            assert_eq!(pcm.len(), 480 * CHANNELS);
            assert!(pcm.iter().all(|&s| s == 0));
        }
        assert_eq!(dec.conceal().unwrap().len(), 480 * CHANNELS);
    }
}
