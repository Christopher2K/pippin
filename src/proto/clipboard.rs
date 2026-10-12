//! Apple's rich pasteboard extension.
//!
//! * 0x15 AutoPasteboard (mode 1) subscribes to change notifications, which
//!   arrive as 0x14 MiscStatus with cmd 2.
//! * 0x0b requests the host pasteboard; the host answers with 0x1f.
//! * 0x1f carries a zlib (sync-flush) archive of pasteboard items. It is used
//!   in both directions; inbound it may span several records, and only the
//!   first record carries the 16-byte header.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;

use super::wire::{Cursor, be32};

const HEADER_LEN: usize = 16;
const UTF8_TEXT: &str = "public.utf8-plain-text";
const PNG: &str = "public.png";
const TIFF: &str = "public.tiff";
/// Refuse to inflate pasteboards beyond this size.
const MAX_INFLATED: u64 = 64 << 20;

pub fn enable_auto_pasteboard() -> Vec<u8> {
    vec![0x15, 0, 0, 1, 0, 0, 0, 0]
}

pub fn request_pasteboard() -> Vec<u8> {
    vec![0x0b, 0, 0, 0, 0, 0, 0, 0]
}

/// Builds an outbound 0x1f carrying `text` as `public.utf8-plain-text`.
pub fn send_text(text: &str) -> Vec<u8> {
    send_items(&[(UTF8_TEXT, text.as_bytes())])
}

/// Builds an outbound 0x1f carrying a PNG image as `public.png`.
pub fn send_png(png: &[u8]) -> Vec<u8> {
    send_items(&[(PNG, png)])
}

fn send_items(items: &[(&str, &[u8])]) -> Vec<u8> {
    let size: usize = items.iter().map(|(u, d)| u.len() + d.len() + 16).sum();
    let mut inner = Vec::with_capacity(size + 4);
    inner.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for (uti, data) in items {
        inner.extend_from_slice(&(uti.len() as u32).to_be_bytes());
        inner.extend_from_slice(uti.as_bytes());
        inner.extend_from_slice(&0u32.to_be_bytes()); // reserved
        inner.extend_from_slice(&0u32.to_be_bytes()); // alias count
        inner.extend_from_slice(&(data.len() as u32).to_be_bytes());
        inner.extend_from_slice(data);
    }

    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(&inner).expect("in-memory zlib");
    z.flush().expect("in-memory zlib"); // sync flush, like the host
    let compressed = z.get_ref().clone();

    let mut msg = Vec::with_capacity(HEADER_LEN + compressed.len());
    msg.extend_from_slice(&[0x1f, 0, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    msg.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    msg.extend_from_slice(&compressed);
    msg
}

/// Stitches multi-record 0x1f messages back together.
#[derive(Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    expected: usize,
}

impl Reassembler {
    pub fn in_progress(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Feeds one record body. Returns the complete message once all of its
    /// compressed payload has arrived.
    pub fn feed(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if self.buf.is_empty() {
            if msg.len() < HEADER_LEN || msg[0] != 0x1f {
                return None;
            }
            self.expected = HEADER_LEN + be32(msg, 12) as usize;
        }
        self.buf.extend_from_slice(msg);
        if self.buf.len() >= self.expected {
            let mut full = std::mem::take(&mut self.buf);
            full.truncate(self.expected);
            return Some(full);
        }
        None
    }
}

struct Item {
    uti: String,
    data: Vec<u8>,
}

fn parse_items(raw: &[u8]) -> Option<Vec<Item>> {
    let mut c = Cursor::new(raw);
    if c.remaining() < 4 {
        return Some(Vec::new());
    }
    let count = c.u32()?;
    let mut items = Vec::new();
    for _ in 0..count {
        let n = c.u32()? as usize;
        let uti = String::from_utf8_lossy(c.take(n)?).into_owned();
        c.u32()?; // reserved
        let aliases = c.u32()?;
        for _ in 0..aliases {
            let n = c.u32()? as usize;
            c.skip(n)?;
            let n = c.u32()? as usize;
            c.skip(n)?;
        }
        let n = c.u32()? as usize;
        let data = c.take(n)?.to_vec();
        items.push(Item { uti, data });
    }
    Some(items)
}

fn decode_utf16(data: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>().0.iter()
        .map(|b| if big_endian { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
        .collect();
    String::from_utf16_lossy(&units)
}

/// The most useful flavor of a host pasteboard.
#[derive(Debug, PartialEq)]
pub enum Content {
    Text(String),
    /// Encoded image bytes, still in the host's format.
    Image { tiff: bool, data: Vec<u8> },
}

/// Decodes a complete 0x1f message. Text wins over images, since rich text
/// copies often carry a rendered picture alongside.
pub fn content_from_message(full: &[u8]) -> Option<Content> {
    if full.len() < HEADER_LEN {
        return None;
    }
    let compressed = &full[HEADER_LEN..];
    let mut raw = Vec::new();
    // A sync-flushed stream has no end marker; read until input runs out and
    // keep whatever inflated cleanly.
    let mut dec = flate2::read::ZlibDecoder::new(compressed).take(MAX_INFLATED);
    if let Err(e) = dec.read_to_end(&mut raw)
        && raw.is_empty() {
            tracing::warn!("clipboard inflate failed: {e}");
            return None;
        }
    let mut items = parse_items(&raw)?;
    if let Some(text) = text_from_items(&items) {
        return Some(Content::Text(text));
    }
    for (uti, tiff) in [(PNG, false), (TIFF, true)] {
        if let Some(i) = items.iter().position(|i| i.uti == uti) {
            return Some(Content::Image { tiff, data: items.swap_remove(i).data });
        }
    }
    tracing::debug!(
        utis = ?items.iter().map(|i| i.uti.as_str()).collect::<Vec<_>>(),
        "pasteboard has no text or image flavor"
    );
    None
}

/// Decodes a complete 0x1f message and returns its best text flavor.
#[cfg(test)]
pub fn text_from_message(full: &[u8]) -> Option<String> {
    match content_from_message(full)? {
        Content::Text(t) => Some(t),
        Content::Image { .. } => None,
    }
}

fn text_from_items(items: &[Item]) -> Option<String> {
    if let Some(it) = items.iter().find(|i| i.uti == UTF8_TEXT) {
        return Some(String::from_utf8_lossy(&it.data).into_owned());
    }
    if let Some(it) = items.iter().find(|i| i.uti.starts_with("public.") && i.uti.contains("text")) {
        if it.uti.contains("utf16") {
            return Some(decode_utf16(&it.data, it.uti.contains("external")));
        }
        return Some(String::from_utf8_lossy(&it.data).into_owned());
    }
    if let Some(it) = items.iter().find(|i| i.uti == "com.apple.traditional-mac-plain-text") {
        return Some(it.data.iter().map(|&b| b as char).collect());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_reassembler() {
        let text = "héllo, wörld\n".repeat(400);
        let msg = send_text(&text);
        let mut r = Reassembler::default();
        let mut out = None;
        for chunk in msg.chunks(700) {
            assert!(out.is_none());
            out = r.feed(chunk);
        }
        let full = out.expect("complete");
        assert!(!r.in_progress());
        assert_eq!(text_from_message(&full).as_deref(), Some(text.as_str()));
    }

    #[test]
    fn png_round_trip() {
        let png = vec![0x89, b'P', b'N', b'G', 1, 2, 3];
        let got = content_from_message(&send_png(&png));
        assert_eq!(got, Some(Content::Image { tiff: false, data: png }));
    }

    #[test]
    fn text_beats_image() {
        let msg = send_items(&[(TIFF, b"II*\0"), (UTF8_TEXT, b"hi")]);
        assert_eq!(content_from_message(&msg), Some(Content::Text("hi".into())));
        let msg = send_items(&[(TIFF, b"II*\0"), ("com.example.other", b"x")]);
        assert_eq!(content_from_message(&msg), Some(Content::Image { tiff: true, data: b"II*\0".to_vec() }));
    }

    #[test]
    fn empty_pasteboard() {
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.flush().unwrap();
        let mut msg = vec![0x1f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(&(z.get_ref().len() as u32).to_be_bytes());
        msg.extend_from_slice(z.get_ref());
        assert_eq!(text_from_message(&msg), None);
    }
}
