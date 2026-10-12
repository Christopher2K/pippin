//! Builders for client→server RFB messages and parsers for the server
//! messages that arrive on the encrypted control channel.

use super::auth::ecb_block;
use super::wire::{Cursor, be16, be32};

pub const PROTOCOL_VERSION: &[u8; 12] = b"RFB 003.889\n";

/// Apple's HP-mode encoding list, sent once in plaintext and once encrypted.
pub const HP_ENCODINGS: [i32; 13] =
    [1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110];

pub const ENC_RECORD_KEYS: i32 = 1103;
pub const ENC_CURSOR: i32 = 1104;
pub const ENC_DISPLAY_LAYOUT: i32 = 0x451;
pub const ENC_MEDIA_BLOB: i32 = 1010;
/// Pseudo-encodings whose payload is `u16 len || data` and which we skip.
pub const ENC_SKIPPABLE: [i32; 11] =
    [1010, 1011, 1107, 1109, 1110, 0x3f2, 0x3f3, 0x3ea, 0x453, 0x455, 0x456];

pub const BTN_LEFT: u8 = 1 << 0;
pub const BTN_RIGHT: u8 = 1 << 1;
pub const BTN_MIDDLE: u8 = 1 << 2;
pub const BTN_SCROLL_UP: u8 = 1 << 3;
pub const BTN_SCROLL_DOWN: u8 = 1 << 4;

/// 0x21 ViewerInfo followed by Apple's 12-byte 0x12 follow-up. The 32-byte
/// command mask matches Screen Sharing.app and unlocks clipboard push and
/// heartbeat notifications.
pub fn viewer_info() -> Vec<u8> {
    let mut m = Vec::with_capacity(66 + 12);
    m.extend_from_slice(&[0x21, 0]);
    m.extend_from_slice(&0x3Eu16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    for v in [2u32, 6, 1, 0, 15, 3, 0] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    let mut mask = [0u8; 32];
    mask[0] = 0xb0;
    mask[2] = 0x0c;
    mask[3] = 0x03;
    mask[4] = 0x90;
    mask[10] = 0x40;
    m.extend_from_slice(&mask);
    m.extend_from_slice(&[0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1]);
    m
}

pub fn set_encodings() -> Vec<u8> {
    let mut m = vec![0x02, 0];
    m.extend_from_slice(&(HP_ENCODINGS.len() as u16).to_be_bytes());
    for e in HP_ENCODINGS {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

/// SetEncryption cmd=2: switches the server onto the enc1103 record layer.
pub fn post_encryption_toggle() -> Vec<u8> {
    vec![0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00]
}

/// Geometry for the virtual display we ask the host to create.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DisplayRequest {
    /// Logical (point) size.
    pub width: u32,
    pub height: u32,
    /// Backing pixels per point. 1.0 = flat, 2.0 = Retina.
    pub scale: f64,
}

impl DisplayRequest {
    pub const MAX_BACKING: (u32, u32) = (3840, 2160);

    /// Picks the logical size and scale so the host's backing store matches
    /// `pixels` as closely as its 3840×2160 cap allows.
    pub fn for_pixels(px_w: u32, px_h: u32, scale: f64) -> Self {
        let scale = scale.clamp(1.0, 3.0);
        let (max_w, max_h) = Self::MAX_BACKING;
        let fit = (max_w as f64 / px_w.max(1) as f64)
            .min(max_h as f64 / px_h.max(1) as f64)
            .min(1.0);
        let even = |v: f64| ((v / 2.0).round() as u32 * 2).max(2);
        let width = even(px_w as f64 * fit / scale).max(640);
        let height = even(px_h as f64 * fit / scale).max(360);
        Self { width, height, scale }
    }

    pub fn backing(&self) -> (u32, u32) {
        (
            (self.width as f64 * self.scale).round() as u32,
            (self.height as f64 * self.scale).round() as u32,
        )
    }
}

/// 0x1d SetDisplayConfiguration. Used for the initial virtual display and,
/// identically, for mid-session dynamic resolution changes.
pub fn set_display_configuration(req: &DisplayRequest) -> Vec<u8> {
    const MODES: [(f64, f64); 5] =
        [(1920.0, 1080.0), (1440.0, 900.0), (1920.0, 1080.0), (1440.0, 810.0), (1312.0, 848.0)];
    let mode_count = MODES.len();
    let di_size = 0x9C + 28 * mode_count;
    let mut di = vec![0u8; di_size];
    let put16 = |d: &mut [u8], off: usize, v: u16| d[off..off + 2].copy_from_slice(&v.to_be_bytes());
    let put32 = |d: &mut [u8], off: usize, v: u32| d[off..off + 4].copy_from_slice(&v.to_be_bytes());

    put16(&mut di, 0, di_size as u16);
    let name = b"macshare Virtual Display";
    di[2..2 + name.len()].copy_from_slice(name);
    put32(&mut di, 0x7A, 1); // dynamic resolution
    put32(&mut di, 0x7E, 4); // virtual display
    di[0x82..0x86].copy_from_slice(&369.454_56_f32.to_be_bytes());
    di[0x86..0x8A].copy_from_slice(&207.818_17_f32.to_be_bytes());
    put32(&mut di, 0x8A, DisplayRequest::MAX_BACKING.0);
    put32(&mut di, 0x8E, DisplayRequest::MAX_BACKING.1);
    put16(&mut di, 0x92, 0);
    put16(&mut di, 0x94, 0);
    put32(&mut di, 0x96, 7);
    put16(&mut di, 0x9A, mode_count as u16);

    let sx = req.width as f64 / 1920.0;
    let sy = req.height as f64 / 1080.0;
    for (i, (bw, bh)) in MODES.iter().enumerate() {
        let lw = (bw * sx + 0.5) as u32;
        let lh = (bh * sy + 0.5) as u32;
        let pw = (lw as f64 * req.scale + 0.5) as u32;
        let ph = (lh as f64 * req.scale + 0.5) as u32;
        let m = 0x9C + 28 * i;
        put32(&mut di, m, pw);
        put32(&mut di, m + 4, ph);
        put32(&mut di, m + 8, lw);
        put32(&mut di, m + 12, lh);
        di[m + 16..m + 24].copy_from_slice(&60.0f64.to_be_bytes());
        put32(&mut di, m + 24, 0);
    }

    let mut msg = vec![0x1d, 0];
    msg.extend_from_slice(&((8 + di_size) as u16).to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // version
    msg.extend_from_slice(&1u16.to_be_bytes()); // display count
    msg.extend_from_slice(&0u32.to_be_bytes()); // flags
    msg.extend_from_slice(&di);
    msg
}

pub fn fbu_request(incremental: bool, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
    let mut m = vec![0x03, incremental as u8];
    for v in [x, y, w, h] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m
}

pub fn key_event(down: bool, keysym: u32) -> Vec<u8> {
    let mut m = vec![0x04, down as u8, 0, 0];
    m.extend_from_slice(&keysym.to_be_bytes());
    m
}

/// msg 0x10 HandleEncryptedEventMessage carrying a pointer event, the form
/// Screen Sharing.app uses for every pointer event in HP mode. The block is
/// AES-128-ECB under the record-layer key; byte 10 must be 0xff.
pub fn encrypted_pointer_event(record_key: &[u8; 16], buttons: u8, x: u16, y: u16) -> Vec<u8> {
    let mut block = [0u8; 16];
    block[10] = 0xff;
    block[11] = buttons;
    block[12..14].copy_from_slice(&x.to_be_bytes());
    block[14..16].copy_from_slice(&y.to_be_bytes());
    ecb_block(record_key, &mut block);
    let mut m = vec![0x10, 0];
    m.extend_from_slice(&block);
    m
}

/// One rect from a FramebufferUpdate on the control channel.
#[derive(Debug)]
pub enum Rect<'a> {
    Cursor(CursorRect<'a>),
    Layout(DisplayLayout),
    /// 1010 media blob; carries the 0x1c answer bplist.
    MediaBlob(&'a [u8]),
    RecordKeys(&'a [u8]),
    Skipped(i32),
}

#[derive(Debug)]
pub struct CursorRect<'a> {
    pub hotspot: (u16, u16),
    pub size: (u16, u16),
    pub cache_id: u32,
    /// zlib (sync-flush) BGRA pixmap followed by an 8-bit alpha mask.
    /// Empty means "reuse cache entry `cache_id`".
    pub compressed: &'a [u8],
}

#[derive(Debug, Clone, PartialEq)]
pub struct DisplayLayout {
    pub scaled: (u16, u16),
    pub backing: (u16, u16),
    pub displays: Vec<DisplayRect>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DisplayRect {
    pub id: u32,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

fn parse_layout(p: &[u8]) -> Option<DisplayLayout> {
    if p.len() < 10 {
        return None;
    }
    let scaled = (be16(p, 2), be16(p, 4));
    let backing = (be16(p, 6), be16(p, 8));
    let mut displays = Vec::new();
    if p.len() >= 20 {
        let count = be16(p, 18) as usize;
        for i in 0..count {
            let off = 20 + 56 * i;
            if off + 56 > p.len() {
                break;
            }
            let (y0, x0, y1, x1) =
                (be16(p, off + 28), be16(p, off + 30), be16(p, off + 32), be16(p, off + 34));
            if x1 > x0 && y1 > y0 {
                displays.push(DisplayRect { id: be32(p, off + 16), x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
            }
        }
    }
    Some(DisplayLayout { scaled, backing, displays })
}

/// Walks a FramebufferUpdate (type 0x00). Stops at the first rect whose
/// encoding we cannot size; everything parsed before it is returned.
pub fn parse_fbu(msg: &[u8]) -> Vec<Rect<'_>> {
    let mut rects = Vec::new();
    let mut c = Cursor::at(msg, 2);
    let Some(n) = c.u16() else { return rects };
    for _ in 0..n {
        let Some((f0, f1, f2, f3, enc)) = (|| Some((c.u16()?, c.u16()?, c.u16()?, c.u16()?, c.i32()?)))()
        else {
            break;
        };
        let rect = match enc {
            ENC_CURSOR => {
                let Some((cache_id, len)) = (|| Some((c.u32()?, c.u32()?)))() else { break };
                let Some(data) = c.take(len as usize) else { break };
                Rect::Cursor(CursorRect { hotspot: (f0, f1), size: (f2, f3), cache_id, compressed: data })
            }
            ENC_RECORD_KEYS => match c.take(36) {
                Some(d) => Rect::RecordKeys(d),
                None => break,
            },
            ENC_DISPLAY_LAYOUT | ENC_MEDIA_BLOB => {
                let Some(len) = c.u16() else { break };
                let Some(data) = c.take(len as usize) else { break };
                if enc == ENC_MEDIA_BLOB {
                    Rect::MediaBlob(data)
                } else {
                    match parse_layout(data) {
                        Some(l) => Rect::Layout(l),
                        None => Rect::Skipped(enc),
                    }
                }
            }
            e if ENC_SKIPPABLE.contains(&e) => {
                let Some(len) = c.u16() else { break };
                if c.skip(len as usize).is_none() {
                    break;
                }
                Rect::Skipped(e)
            }
            other => {
                tracing::debug!(encoding = other, "unknown FBU encoding; stopping walk");
                break;
            }
        };
        rects.push(rect);
    }
    rects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_configuration_layout() {
        let req = DisplayRequest { width: 1920, height: 1080, scale: 2.0 };
        let m = set_display_configuration(&req);
        let di_size = 0x9C + 28 * 5;
        assert_eq!(m.len(), 12 + di_size);
        assert_eq!(&m[0..2], &[0x1d, 0]);
        assert_eq!(be16(&m, 2) as usize, 8 + di_size);
        let di = &m[12..];
        assert_eq!(be16(di, 0) as usize, di_size);
        assert_eq!(be32(di, 0x7A), 1);
        assert_eq!(be32(di, 0x7E), 4);
        assert_eq!(be32(di, 0x8A), 3840);
        assert_eq!(be32(di, 0x96), 7);
        assert_eq!(be16(di, 0x9A), 5);
        // First mode is the requested size at 2× backing.
        assert_eq!((be32(di, 0x9C), be32(di, 0xA0), be32(di, 0xA4), be32(di, 0xA8)), (3840, 2160, 1920, 1080));
        assert_eq!(f32::from_be_bytes(di[0x82..0x86].try_into().unwrap()), 369.454_56);
    }

    #[test]
    fn display_request_respects_cap() {
        let r = DisplayRequest::for_pixels(5120, 2880, 1.0);
        let (bw, bh) = r.backing();
        assert!(bw <= 3840 && bh <= 2160, "{bw}x{bh}");
        let r = DisplayRequest::for_pixels(2560, 1440, 2.0);
        assert_eq!((r.width, r.height), (1280, 720));
        assert_eq!(r.backing(), (2560, 1440));
    }

    #[test]
    fn viewer_info_shape() {
        let v = viewer_info();
        assert_eq!(v.len(), 4 + 0x3E + 12);
        assert_eq!(v[0], 0x21);
        assert_eq!(v[34], 0xb0);
    }

    #[test]
    fn fbu_walk() {
        let mut m = vec![0, 0, 0, 3];
        // 1011 skippable
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&1011i32.to_be_bytes());
        m.extend_from_slice(&[0, 2, 0xaa, 0xbb]);
        // 0x451 layout, 20-byte header + one display
        m.extend_from_slice(&[0; 8]);
        m.extend_from_slice(&0x451i32.to_be_bytes());
        let mut p = vec![0u8; 20 + 56];
        p[2..4].copy_from_slice(&1280u16.to_be_bytes());
        p[4..6].copy_from_slice(&720u16.to_be_bytes());
        p[6..8].copy_from_slice(&2560u16.to_be_bytes());
        p[8..10].copy_from_slice(&1440u16.to_be_bytes());
        p[18..20].copy_from_slice(&1u16.to_be_bytes());
        p[20 + 32..20 + 34].copy_from_slice(&1440u16.to_be_bytes());
        p[20 + 34..20 + 36].copy_from_slice(&2560u16.to_be_bytes());
        m.extend_from_slice(&(p.len() as u16).to_be_bytes());
        m.extend_from_slice(&p);
        // cursor cache hit
        m.extend_from_slice(&[0, 4, 0, 5, 0, 16, 0, 16]);
        m.extend_from_slice(&1104i32.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0]);
        let rects = parse_fbu(&m);
        assert_eq!(rects.len(), 3);
        match &rects[1] {
            Rect::Layout(l) => {
                assert_eq!(l.backing, (2560, 1440));
                assert_eq!(l.displays[0].w, 2560);
            }
            r => panic!("{r:?}"),
        }
        match &rects[2] {
            Rect::Cursor(c) => {
                assert_eq!(c.cache_id, 9);
                assert!(c.compressed.is_empty());
                assert_eq!(c.hotspot, (4, 5));
            }
            r => panic!("{r:?}"),
        }
    }
}
