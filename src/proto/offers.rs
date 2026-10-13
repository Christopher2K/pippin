//! AVCMediaStreamNegotiator offers (0x1c MediaStreamOptions) and answer
//! parsing.
//!
//! Each offer is a binary plist wrapping a zlib-compressed protobuf
//! "MediaBlob". The video offer requests HEVC 4:4:4 split into horizontal
//! tiles; the audio offer must be present for the host to start streaming.

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use rand::RngCore;
use rand::rngs::OsRng;

pub const SRTP_BLOB_LEN: usize = 46;
pub const TILES_PER_FRAME: u64 = 4;

const MODE_VIDEO: i64 = 7;
const MODE_AUDIO: i64 = 8;

const HEVC_PARAMS: &[u8] =
    b"FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
/// The same without the `LTR;` capability, as the reference offers with
/// long-term references off.
const HEVC_PARAMS_NO_LTR: &[u8] = b"FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
const AVC_PARAMS: &[u8] = b"FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;";

/// Stream config flag bits in the 0x1c header (see [`MediaOffer::message`]).
/// "60 fps supported" for video stream 1 and stream 2; with both clear the
/// host is expected to encode at 30 fps (unverified). The daemon forces both
/// on for message version <= 1; we send version 3, so clearing them sticks.
///
/// The word is written big-endian although the host reads it raw: it
/// forwards the value to the streaming agent, which tests the bits after the
/// IPC boundary has byte-swapped it, so big-endian is what arrives. The
/// reference found this the hard way (negotiation.py:194-204): big-endian
/// `00 00 00 07` makes the host honour the no-cursor bit, little-endian
/// leaves the cursor baked into the video. The fps bits travel the same way.
const FLAG_60FPS_STREAM1: u32 = 1;
const FLAG_60FPS_STREAM2: u32 = 2;
/// The host draws no cursor into the video; we show its shapes locally.
const FLAG_NO_CURSOR: u32 = 4;

/// Video offer choices that the client can vary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfferOptions {
    /// Advertise 60 fps (flag bits 0 and 1); false asks for 30.
    pub fps60: bool,
    /// Advertise long-term reference pictures (LTRP): `LTR;` in the HEVC
    /// parameter string and ltrpEnabled (field 7). The host is said to use
    /// the last LTR we acknowledged as the reference for its next P picture
    /// after a loss instead of sending an IDR; that is the reference's
    /// reading of the protocol, not something it has demonstrated, and the
    /// RFC draft lists the LTR semantics as a gap.
    pub ltr: bool,
}

impl Default for OfferOptions {
    fn default() -> Self {
        Self { fps60: true, ltr: true }
    }
}

/// The 0x1c header flags. A separate login session drops the second-stream
/// 60 fps bit, as the native viewer does.
fn stream_flags(alt_session: bool, opts: OfferOptions) -> u32 {
    let mut flags = FLAG_NO_CURSOR;
    if opts.fps60 {
        flags |= FLAG_60FPS_STREAM1;
        if !alt_session {
            flags |= FLAG_60FPS_STREAM2;
        }
    }
    flags
}

/// Audio bitrate tiers Screen Sharing.app advertises in field 9.
const AUDIO_TIERS: [(u64, u64, Option<u64>); 10] = [
    (0, 40_000_000, Some(12288)),
    (0, 6_000_000, Some(131072)),
    (4074, 0, Some(16384)),
    (16, 4100, None),
    (0, 75_000_000, Some(524288)),
    (0, 20_000_000, Some(98304)),
    (4, 6500, None),
    (0, 60_000_000, Some(262144)),
    (1, 299, None),
    (0, 100_000_000, Some(1048576)),
];

/// Minimal protobuf writer: varints and length-delimited fields only.
#[derive(Default)]
struct Pb(Vec<u8>);

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v > 0x7f {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

impl Pb {
    fn int(mut self, field: u64, v: u64) -> Self {
        varint(&mut self.0, field << 3);
        varint(&mut self.0, v);
        self
    }
    fn bytes(mut self, field: u64, v: &[u8]) -> Self {
        varint(&mut self.0, (field << 3) | 2);
        varint(&mut self.0, v.len() as u64);
        self.0.extend_from_slice(v);
        self
    }
    fn raw(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
}

/// Reads protobuf fields, yielding (field, wire type, varint value or bytes).
struct PbReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

enum PbValue<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}

impl<'a> PbReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
}

impl<'a> Iterator for PbReader<'a> {
    type Item = (u64, PbValue<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let tag = self.varint()?;
        let field = tag >> 3;
        match tag & 7 {
            0 => Some((field, PbValue::Int(self.varint()?))),
            2 => {
                let len = self.varint()? as usize;
                let end = self.pos.checked_add(len)?;
                let b = self.buf.get(self.pos..end)?;
                self.pos = end;
                Some((field, PbValue::Bytes(b)))
            }
            1 => {
                self.pos += 8;
                self.next()
            }
            5 => {
                self.pos += 4;
                self.next()
            }
            _ => None,
        }
    }
}

fn endpoint_info() -> Vec<u8> {
    let mut out = vec![0x08, 0x00, 0x10, 0x01];
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "0".into());
    let model = format!("Linux-{}", std::env::consts::ARCH);
    for (tag, s) in [(0x1Au8, model.as_str()), (0x22, "1.0.0"), (0x2A, release.as_str())] {
        let b = &s.as_bytes()[..s.len().min(127)];
        out.push(tag);
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out
}

fn media_blob(mode: i64, session_id: u32, audio: bool, ltr: bool) -> Vec<u8> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let desc = if mode == MODE_VIDEO {
        let entry = |alt: u64| Pb::default().int(1, 1).int(2, alt).int(3, 50115).int(4, 0).0;
        let (e, ea) = (entry(1), entry(2));
        // Counter-intuitively, the bank tagged 100 is the one the host
        // answers with HEVC 4:4:4 and 123 yields H.264; offering both lets
        // the host pick HEVC.
        let bank_123 = Pb::default()
            .int(1, 123)
            .bytes(2, &e)
            .bytes(2, &ea)
            .bytes(2, &e)
            .bytes(2, &ea)
            .bytes(3, if ltr { HEVC_PARAMS } else { HEVC_PARAMS_NO_LTR })
            .int(4, 1)
            .0;
        let bank_100 =
            Pb::default().int(1, 100).bytes(2, &e).bytes(2, &ea).bytes(3, AVC_PARAMS).int(4, 14).0;
        // Field 2 is allowRTCPFB and 7 ltrpEnabled. The reference clears
        // both with LTR off; we keep RTCP feedback allowed so NACKs and
        // keyframe requests are unaffected and only LTR varies.
        let d = Pb::default()
            .int(1, session_id as u64)
            .int(2, 1)
            .bytes(3, &bank_123)
            .bytes(3, &bank_100)
            .int(6, TILES_PER_FRAME)
            .int(7, ltr as u64)
            .int(8, 63)
            .int(9, 1)
            .int(12, 1)
            .0;
        Pb::default().bytes(5, &d).0
    } else {
        let gate = if audio { 24191 } else { 1000 };
        let d = Pb::default()
            .int(1, session_id as u64)
            .int(2, 0)
            .int(3, 0)
            .int(4, gate)
            .int(5, 0)
            .int(6, 0)
            .0;
        Pb::default().bytes(3, &d).0
    };
    let mut tiers = Vec::new();
    for (f1, f2, f3) in AUDIO_TIERS {
        let mut body = Pb::default().int(1, f1).int(2, f2);
        if let Some(f3) = f3 {
            body = body.int(3, f3);
        }
        tiers = Pb(tiers).bytes(9, &body.0).0;
    }
    Pb::default()
        .int(1, 1)
        .int(2, 1)
        .raw(&desc)
        .bytes(6, concat!("macshare ", env!("CARGO_PKG_VERSION")).as_bytes())
        .int(8, 0)
        .raw(&tiers)
        .int(13, timestamp)
        .int(14, 2)
        .int(16, 0)
        .int(18, 1)
        .0
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).expect("in-memory zlib");
    e.finish().expect("in-memory zlib")
}

fn offer_plist(mode: i64, session_id: u32, audio: bool, ltr: bool) -> Vec<u8> {
    let mut dict = plist::Dictionary::new();
    dict.insert("avcMediaStreamOptionRemoteEndpointInfo".into(), plist::Value::Data(endpoint_info()));
    dict.insert("avcMediaStreamNegotiatorMode".into(), plist::Value::Integer(mode.into()));
    dict.insert(
        "avcMediaStreamNegotiatorMediaBlob".into(),
        plist::Value::Data(zlib(&media_blob(mode, session_id, audio, ltr))),
    );
    dict.insert(
        "avcMediaStreamOptionCallID".into(),
        plist::Value::String(uuid::Uuid::new_v4().to_string().to_uppercase()),
    );
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dict)).expect("plist serialization");
    out
}

/// Everything negotiated in one 0x1c: SRTP keys and our SSRCs.
#[derive(Clone)]
pub struct MediaOffer {
    pub audio_key_v: [u8; SRTP_BLOB_LEN],
    pub audio_key_s: [u8; SRTP_BLOB_LEN],
    pub video_key_v: [u8; SRTP_BLOB_LEN],
    pub video_key_s: [u8; SRTP_BLOB_LEN],
    pub video_ssrc: u32,
    pub audio_ssrc: u32,
    alt_session: bool,
    opts: OfferOptions,
    video_offer: Vec<u8>,
    audio_offer: Vec<u8>,
}

impl MediaOffer {
    /// `alt_session` drops the second-stream 60 fps bit, as the native
    /// viewer does for a separate login session.
    pub fn generate(audio: bool, alt_session: bool, opts: OfferOptions) -> Self {
        let key = || {
            let mut k = [0u8; SRTP_BLOB_LEN];
            OsRng.fill_bytes(&mut k);
            k
        };
        let (akv, aks, vkv, vks) = (key(), key(), key(), key());
        let video_ssrc = OsRng.next_u32();
        let audio_ssrc = OsRng.next_u32();
        Self {
            audio_key_v: akv,
            audio_key_s: aks,
            video_key_v: vkv,
            video_key_s: vks,
            video_ssrc,
            audio_ssrc,
            alt_session,
            opts,
            video_offer: offer_plist(MODE_VIDEO, video_ssrc, false, opts.ltr),
            audio_offer: offer_plist(MODE_AUDIO, audio_ssrc, audio, false),
        }
    }

    /// Changes the offer for the next [`message`](Self::message), keeping
    /// the keys and SSRCs, so a mid-session re-offer can renegotiate it.
    pub fn set_options(&mut self, opts: OfferOptions) {
        if opts.ltr != self.opts.ltr {
            self.video_offer = offer_plist(MODE_VIDEO, self.video_ssrc, false, opts.ltr);
        }
        self.opts = opts;
    }

    /// Serializes the 0x1c message. The same message (same keys) is re-sent
    /// after a resize to restart the encoder at the new geometry.
    pub fn message(&self) -> Vec<u8> {
        let a = self.audio_offer.len();
        let v = self.video_offer.len();
        let ms = a + v + 0xD8;
        let mut buf = vec![0u8; ms + 4];
        buf[0] = 0x1C;
        buf[2..4].copy_from_slice(&(ms as u16).to_be_bytes());
        buf[4..6].copy_from_slice(&3u16.to_be_bytes());
        // Stream config flags: 60 fps streams (bits 0, 1) and "do not bake
        // the cursor into the video" (bit 2). Big-endian on the wire: the
        // agent sees the value after an IPC byte swap, so the host's raw
        // little-endian load is misleading.
        buf[6..10].copy_from_slice(&stream_flags(self.alt_session, self.opts).to_be_bytes());
        buf[10..12].copy_from_slice(&(a as u16).to_be_bytes());
        buf[12..14].copy_from_slice(&(v as u16).to_be_bytes());
        buf[0x14..0x24].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        buf[0x24..0x52].copy_from_slice(&self.audio_key_v);
        buf[0x52..0x80].copy_from_slice(&self.audio_key_s);
        buf[0x80..0x80 + a].copy_from_slice(&self.audio_offer);
        let vo = 0x80 + a;
        buf[vo..vo + 0x2E].copy_from_slice(&self.video_key_v);
        buf[vo + 0x2E..vo + 0x5C].copy_from_slice(&self.video_key_s);
        buf[vo + 0x5C..vo + 0x5C + v].copy_from_slice(&self.video_offer);
        buf
    }
}

/// Encoder geometry from the host's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanvasInfo {
    pub width: u32,
    pub height: u32,
    pub tiles: u32,
    /// ltrpEnabled (field 7) as answered, if present.
    pub ltrp: Option<bool>,
}

/// Finds the length of a binary plist starting at `buf[0]` by locating a
/// trailer whose offset table ends exactly where the trailer begins.
fn bplist_len(buf: &[u8]) -> Option<usize> {
    (40..=buf.len()).find(|&end| {
        let t = &buf[end - 32..end];
        if t[..5].iter().any(|&b| b != 0) {
            return false;
        }
        let off_size = t[6] as u64;
        let ref_size = t[7];
        if !(1..=8).contains(&off_size) || !(1..=8).contains(&ref_size) {
            return false;
        }
        let num = u64::from_be_bytes(t[8..16].try_into().unwrap());
        let table = u64::from_be_bytes(t[24..32].try_into().unwrap());
        num.checked_mul(off_size)
            .and_then(|n| n.checked_add(table))
            .is_some_and(|table_end| table_end == (end - 32) as u64)
    })
}

/// Extracts the video canvas from any embedded answer bplist in `data`.
///
/// Returns `Some` with zero dimensions when an answer is present but the
/// encoder has not settled on a canvas yet (the caller re-sends the offer).
pub fn parse_answer(data: &[u8]) -> Option<CanvasInfo> {
    let mut degenerate = None;
    let mut from = 0;
    while let Some(idx) = find(&data[from..], b"bplist").map(|i| i + from) {
        from = idx + 6;
        let Some(len) = bplist_len(&data[idx..]) else { continue };
        let Ok(plist::Value::Dictionary(dict)) = plist::from_bytes(&data[idx..idx + len]) else {
            continue;
        };
        let Some(blob) = dict.get("avcMediaStreamNegotiatorMediaBlob").and_then(|v| v.as_data()) else {
            continue;
        };
        let mut raw = Vec::new();
        if std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(blob), &mut raw).is_err() {
            continue;
        }
        for (field, value) in PbReader::new(&raw) {
            let (5, PbValue::Bytes(video)) = (field, value) else { continue };
            let mut c = CanvasInfo { width: 0, height: 0, tiles: 0, ltrp: None };
            for (f, v) in PbReader::new(video) {
                if let PbValue::Int(v) = v {
                    match f {
                        4 => c.width = v as u32,
                        5 => c.height = v as u32,
                        6 => c.tiles = v as u32,
                        7 => c.ltrp = Some(v != 0),
                        _ => {}
                    }
                }
            }
            if c.width > 0 && c.height > 0 {
                return Some(c);
            }
            degenerate = Some(c);
        }
    }
    degenerate
}

impl CanvasInfo {
    pub fn is_degenerate(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout() {
        let offer = MediaOffer::generate(false, false, OfferOptions::default());
        let m = offer.message();
        let a = u16::from_be_bytes([m[10], m[11]]) as usize;
        let v = u16::from_be_bytes([m[12], m[13]]) as usize;
        assert_eq!(m.len(), a + v + 0xD8 + 4);
        assert_eq!(&m[6..10], &[0, 0, 0, 7]);
        assert_eq!(&m[0x80..0x86], b"bplist");
        assert_eq!(&m[0x80 + a + 0x5C..0x80 + a + 0x5C + 6], b"bplist");
        assert_eq!(&m[0x80 + a..0x80 + a + 46], &offer.video_key_v);
    }

    #[test]
    fn answer_round_trip() {
        // Build an "answer" shaped like ours but with canvas fields filled in.
        let d = Pb::default().int(1, 5).int(4, 2560).int(5, 1440).int(6, 4).int(7, 0).0;
        let blob = Pb::default().int(1, 1).bytes(5, &d).0;
        let mut dict = plist::Dictionary::new();
        dict.insert("avcMediaStreamNegotiatorMediaBlob".into(), plist::Value::Data(zlib(&blob)));
        let mut pl = Vec::new();
        plist::to_writer_binary(&mut pl, &plist::Value::Dictionary(dict)).unwrap();
        let mut msg = vec![0u8, 0, 0, 1, 0xde, 0xad];
        msg.extend_from_slice(&pl);
        msg.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(parse_answer(&msg), Some(CanvasInfo { width: 2560, height: 1440, tiles: 4, ltrp: Some(false) }));
    }

    #[test]
    fn video_ssrc_is_in_blob() {
        let blob = media_blob(MODE_VIDEO, 0xDEADBEEF, false, true);
        let (_, desc) = PbReader::new(&blob).find(|(f, _)| *f == 5).unwrap();
        let PbValue::Bytes(desc) = desc else { panic!() };
        let (f, v) = PbReader::new(desc).next().unwrap();
        assert!(f == 1 && matches!(v, PbValue::Int(0xDEADBEEF)));
    }

    #[test]
    fn fps_flag_bits() {
        let fps = |fps60| OfferOptions { fps60, ..Default::default() };
        // Bit 2 (no cursor) always; bits 0/1 are 60 fps for streams 1/2.
        assert_eq!(stream_flags(false, fps(true)), 7);
        assert_eq!(stream_flags(true, fps(true)), 5);
        assert_eq!(stream_flags(false, fps(false)), 4);
        assert_eq!(stream_flags(true, fps(false)), 4);
        let mut offer = MediaOffer::generate(false, false, OfferOptions::default());
        let keys = (offer.video_key_s, offer.video_ssrc);
        offer.set_options(fps(false));
        let m = offer.message();
        assert_eq!(&m[6..10], &[0, 0, 0, 4]);
        // A re-offer keeps the keys and SSRCs.
        assert_eq!((offer.video_key_s, offer.video_ssrc), keys);
        let alt = MediaOffer::generate(false, true, OfferOptions::default());
        assert_eq!(&alt.message()[6..10], &[0, 0, 0, 5]);
    }

    /// The video description (MediaBlob field 5) of an offer plist.
    fn video_desc(plist_bytes: &[u8]) -> Vec<u8> {
        let plist::Value::Dictionary(d) = plist::from_bytes(plist_bytes).unwrap() else { panic!() };
        let blob = d.get("avcMediaStreamNegotiatorMediaBlob").and_then(|v| v.as_data()).unwrap();
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(blob), &mut raw).unwrap();
        let Some((_, PbValue::Bytes(desc))) = PbReader::new(&raw).find(|(f, _)| *f == 5) else { panic!() };
        desc.to_vec()
    }

    #[test]
    fn ltr_option_in_video_offer() {
        for ltr in [true, false] {
            let mut offer = MediaOffer::generate(false, false, OfferOptions::default());
            offer.set_options(OfferOptions { ltr, ..Default::default() });
            let desc = video_desc(&offer.video_offer);
            let f7 = PbReader::new(&desc).find_map(|(f, v)| match (f, v) {
                (7, PbValue::Int(v)) => Some(v),
                _ => None,
            });
            assert_eq!(f7, Some(ltr as u64));
            assert_eq!(find(&desc, b";LTR;").is_some(), ltr);
            // RTCP feedback stays allowed either way.
            assert!(PbReader::new(&desc).any(|(f, v)| f == 2 && matches!(v, PbValue::Int(1))));
        }
    }

    /// The video description (MediaBlob field 5) of iShareScreen's default
    /// `_build_mediablob(7, ...)`, written out by hand from offers.py.
    #[test]
    fn video_description_matches_reference() {
        fn field(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut v = vec![tag, body.len() as u8];
            v.extend_from_slice(body);
            v
        }
        let res = field(0x12, &[0x08, 1, 0x10, 1, 0x18, 0xc3, 0x87, 3, 0x20, 0]);
        let res_alt = field(0x12, &[0x08, 1, 0x10, 2, 0x18, 0xc3, 0x87, 3, 0x20, 0]);
        let mut bank_123 = vec![0x08, 123];
        for r in [&res, &res_alt, &res, &res_alt] {
            bank_123.extend_from_slice(r);
        }
        bank_123.extend(field(0x1a, b"FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;"));
        bank_123.extend_from_slice(&[0x20, 1]);
        let mut bank_100 = vec![0x08, 100];
        bank_100.extend(res.iter().chain(&res_alt));
        bank_100.extend(field(0x1a, b"FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;"));
        bank_100.extend_from_slice(&[0x20, 14]);

        let mut want = vec![0x08, 5, 0x10, 1];
        want.extend(field(0x1a, &bank_123));
        want.extend(field(0x1a, &bank_100));
        want.extend_from_slice(&[0x30, 4, 0x38, 1, 0x40, 63, 0x48, 1, 0x60, 1]);

        let blob = media_blob(MODE_VIDEO, 5, false, true);
        let (_, desc) = PbReader::new(&blob).find(|(f, _)| *f == 5).unwrap();
        let PbValue::Bytes(desc) = desc else { panic!() };
        assert_eq!(desc, &want[..]);
    }
}
