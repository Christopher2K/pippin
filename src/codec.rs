//! The video codec asked of the host, and the codec-specific NAL rules that
//! assembly and decoding need.

use crate::rtp::{h264, hevc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Codec {
    /// HEVC 4:4:4 in 4 tiles, with DONL and long-term-reference acks.
    #[default]
    Hevc,
    /// H.264 4:2:0 in one tile. Decodes on more GPUs.
    H264,
}

impl std::fmt::Display for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Codec::Hevc => "hevc",
            Codec::H264 => "h264",
        })
    }
}

impl Codec {
    /// Payloads carry DONL, and the host takes long-term-reference acks.
    pub fn has_donl(self) -> bool {
        self == Codec::Hevc
    }

    pub fn is_param_set(self, nal: &[u8]) -> bool {
        match self {
            Codec::Hevc => hevc::is_param_set(nal),
            Codec::H264 => h264::is_param_set(nal),
        }
    }

    pub fn is_slice(self, nal: &[u8]) -> bool {
        match self {
            Codec::Hevc => hevc::is_slice(nal),
            Codec::H264 => h264::is_slice(nal),
        }
    }

    /// A slice the decoder can start from (see [`h264::is_keyframe`]).
    pub fn is_irap(self, nal: &[u8]) -> bool {
        match self {
            Codec::Hevc => hevc::is_irap(nal),
            Codec::H264 => h264::is_keyframe(nal),
        }
    }

    /// The slice begins its picture.
    pub fn first_in_picture(self, nal: &[u8]) -> bool {
        match self {
            Codec::Hevc => nal.len() > 2 && nal[2] & 0x80 != 0,
            Codec::H264 => h264::first_in_picture(nal),
        }
    }

    /// The payload continues a fragmented NAL instead of starting one.
    pub fn continues_nal(self, p: &[u8]) -> bool {
        match self {
            Codec::Hevc => p.len() >= 3 && hevc::nal_type(p) == hevc::NAL_FU && p[2] & 0x80 == 0,
            Codec::H264 => h264::continues_nal(p),
        }
    }

    pub fn depayload(self, payloads: &[(u16, &[u8])]) -> Vec<Vec<u8>> {
        match self {
            Codec::Hevc => hevc::depayload(payloads),
            Codec::H264 => h264::depayload(payloads),
        }
    }

    /// DONL of the first packet of an access unit; always None for H.264.
    pub fn first_donl(self, payloads: &[(u16, &[u8])]) -> Option<u16> {
        match self {
            Codec::Hevc => hevc::first_donl(payloads),
            Codec::H264 => None,
        }
    }
}
