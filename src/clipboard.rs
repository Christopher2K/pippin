//! Mirrors text and images between the local clipboard and the host
//! pasteboard.
//!
//! Remote changes arrive pushed over the control channel (auto-pasteboard);
//! local changes are found by polling, since neither X11 nor Wayland offer a
//! portable change notification through `arboard`. Text goes through
//! `arboard`; on Wayland images go through `wl-clipboard-rs` directly so PNG
//! bytes pass untouched instead of round-tripping through RGBA. Clipboard
//! contents are never logged.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError};

use crate::proto::clipboard::{Content, send_png, send_text};
use crate::session::{Control, Shared};

const POLL: Duration = Duration::from_millis(500);
/// Larger texts are not mirrored to the host.
const MAX_SEND: usize = 8 << 20;
/// Larger encoded images are not mirrored to the host.
const MAX_SEND_IMAGE: usize = 32 << 20;
const PNG_MIME: &str = "image/png";

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// One clipboard value. Images are always PNG-encoded.
enum Value {
    Text(String),
    Png(Vec<u8>),
}

impl Value {
    fn fingerprint(&self) -> u64 {
        let mut h = DefaultHasher::new();
        match self {
            Value::Text(t) => (0u8, t).hash(&mut h),
            Value::Png(p) => (1u8, p).hash(&mut h),
        }
        h.finish()
    }
}

/// Tracks both sides by fingerprint so a value set by one side isn't echoed
/// back to it.
#[derive(Default)]
struct Mirror {
    /// Last local value seen.
    local: Option<u64>,
    /// Last value exchanged with the host.
    synced: Option<u64>,
}

impl Mirror {
    /// A local value was read. Returns whether to send it to the host.
    fn local_changed(&mut self, fp: u64) -> bool {
        if self.local == Some(fp) {
            return false;
        }
        self.local = Some(fp);
        if self.synced == Some(fp) {
            return false;
        }
        self.synced = Some(fp);
        true
    }

    /// The host sent a value. Returns whether to set it locally.
    fn remote_changed(&mut self, fp: u64) -> bool {
        if self.synced == Some(fp) && self.local == Some(fp) {
            return false;
        }
        self.synced = Some(fp);
        self.local = Some(fp);
        true
    }
}

/// Re-encodes a host TIFF as PNG.
fn tiff_to_png(tiff: &[u8]) -> anyhow::Result<Vec<u8>> {
    let img = image::load_from_memory_with_format(tiff, image::ImageFormat::Tiff)?;
    let mut png = Vec::new();
    img.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)?;
    Ok(png)
}

fn host_value(content: Content) -> Option<Value> {
    match content {
        Content::Text(t) => Some(Value::Text(normalize(&t))),
        Content::Image { tiff: false, data } => Some(Value::Png(data)),
        Content::Image { tiff: true, data } => match tiff_to_png(&data) {
            Ok(png) => Some(Value::Png(png)),
            Err(e) => {
                tracing::warn!("host clipboard image unreadable: {e}");
                None
            }
        },
    }
}

fn is_text_mime(m: &str) -> bool {
    m.starts_with("text/plain") || matches!(m, "UTF8_STRING" | "STRING" | "TEXT")
}

/// The local clipboard.
struct Local {
    // Must outlive any text we set: on Linux this process serves the
    // selection until another client takes it.
    clip: arboard::Clipboard,
    wayland: bool,
}

impl Local {
    fn read(&mut self) -> Option<Value> {
        if !self.wayland {
            if let Ok(t) = self.clip.get_text() {
                return Some(Value::Text(normalize(&t)));
            }
            let img = self.clip.get_image().ok()?;
            let rgba = image::RgbaImage::from_raw(img.width as u32, img.height as u32, img.bytes.into_owned())?;
            let mut png = Vec::new();
            rgba.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).ok()?;
            return Some(Value::Png(png));
        }
        use wl_clipboard_rs::paste::{ClipboardType, MimeType, Seat, get_contents, get_mime_types};
        // Cheap: only lists what the owner offers.
        let mimes = get_mime_types(ClipboardType::Regular, Seat::Unspecified).ok()?;
        if mimes.iter().any(|m| is_text_mime(m)) {
            return self.clip.get_text().ok().map(|t| Value::Text(normalize(&t)));
        }
        if !mimes.contains(PNG_MIME) {
            return None;
        }
        let (mut pipe, _) = get_contents(ClipboardType::Regular, Seat::Unspecified, MimeType::Specific(PNG_MIME)).ok()?;
        let mut png = Vec::new();
        pipe.by_ref().take(MAX_SEND_IMAGE as u64 + 1).read_to_end(&mut png).ok()?;
        Some(Value::Png(png))
    }

    fn write(&mut self, v: &Value) -> anyhow::Result<()> {
        match v {
            Value::Text(t) => self.clip.set_text(t.clone())?,
            Value::Png(png) if self.wayland => {
                use wl_clipboard_rs::copy::{MimeType, Options, Source};
                // Serves the selection from a background thread until replaced.
                Options::new().copy(Source::Bytes(png.clone().into_boxed_slice()), MimeType::Specific(PNG_MIME.into()))?;
            }
            Value::Png(png) => {
                let rgba = image::load_from_memory_with_format(png, image::ImageFormat::Png)?.into_rgba8();
                let (w, h) = rgba.dimensions();
                self.clip.set_image(arboard::ImageData {
                    width: w as usize,
                    height: h as usize,
                    bytes: rgba.into_raw().into(),
                })?;
            }
        }
        Ok(())
    }
}

pub(crate) fn run(shared: Arc<Shared>, control: Arc<Control>, remote: Receiver<Content>) {
    let clip = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("local clipboard unavailable, clipboard sharing disabled: {e}");
            // Keep draining so the control reader never blocks.
            while !shared.is_stopped() {
                let _ = remote.recv_timeout(POLL);
            }
            return;
        }
    };
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let mut local = Local { clip, wayland };
    let mut mirror = Mirror::default();
    // Whatever is on the local clipboard at connect time is not pushed to
    // the host; only later changes are.
    if let Some(v) = local.read() {
        mirror.local = Some(v.fingerprint());
    }

    while !shared.is_stopped() {
        match remote.recv_timeout(POLL) {
            Ok(content) => {
                if let Some(v) = host_value(content)
                    && mirror.remote_changed(v.fingerprint()) {
                        match local.write(&v) {
                            Err(e) => tracing::warn!("setting local clipboard failed: {e}"),
                            Ok(()) => tracing::debug!("local clipboard updated from host"),
                        }
                    }
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let Some(v) = local.read() else { continue };
        let empty = matches!(&v, Value::Text(t) if t.is_empty());
        if empty || !mirror.local_changed(v.fingerprint()) {
            continue;
        }
        match &v {
            Value::Text(t) if t.len() > MAX_SEND => {
                tracing::info!("local clipboard text too large to share ({} bytes)", t.len())
            }
            Value::Png(p) if p.len() > MAX_SEND_IMAGE => {
                tracing::info!("local clipboard image too large to share ({} bytes)", p.len())
            }
            Value::Text(t) => {
                tracing::debug!("sending local clipboard text to host ({} bytes)", t.len());
                control.send(&send_text(t));
            }
            Value::Png(p) => {
                tracing::debug!("sending local clipboard image to host ({} bytes)", p.len());
                control.send(&send_png(p));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(s: &str) -> u64 {
        Value::Text(normalize(s)).fingerprint()
    }

    #[test]
    fn no_echo_in_either_direction() {
        let mut m = Mirror::default();
        assert!(m.remote_changed(fp("a\r\nb")));
        // Our own write read back locally is not re-sent.
        assert!(!m.local_changed(fp("a\nb")));
        assert!(m.local_changed(fp("c")));
        // The host echoing our value back doesn't touch the local clipboard.
        assert!(!m.remote_changed(fp("c")));
        // Polling the same value again sends nothing.
        assert!(!m.local_changed(fp("c")));
    }

    #[test]
    fn text_and_image_fingerprints_differ() {
        assert_ne!(Value::Text("x".into()).fingerprint(), Value::Png(b"x".to_vec()).fingerprint());
    }

    #[test]
    fn host_tiff_becomes_png() {
        let img = image::RgbaImage::from_fn(3, 2, |x, y| image::Rgba([x as u8 * 80, y as u8 * 120, 7, 255]));
        let mut tiff = Vec::new();
        img.write_to(&mut Cursor::new(&mut tiff), image::ImageFormat::Tiff).unwrap();
        let Some(Value::Png(png)) = host_value(Content::Image { tiff: true, data: tiff }) else { panic!("no png") };
        let back = image::load_from_memory_with_format(&png, image::ImageFormat::Png).unwrap().into_rgba8();
        assert_eq!(back, img);
    }
}
