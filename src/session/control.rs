//! Reads and dispatches the encrypted TCP control channel.

use std::collections::HashMap;
use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Result;
use crossbeam_channel::Sender;

use super::{Control, CursorShape, Event, Feedback, KeyframeCause, Shared};
use crate::proto::clipboard::{self, Reassembler};
use crate::proto::messages::{self, CursorRect, DisplayLayout, Rect};
use crate::proto::offers::parse_answer;
use crate::proto::record::{Opened, RecordOpener};

const MAX_CACHED_CURSORS: usize = 64;

pub(super) struct ControlReader {
    shared: Arc<Shared>,
    control: Arc<Control>,
    clipboard_out: Sender<clipboard::Content>,
    feedback: Sender<Feedback>,
    clipboard: Reassembler,
    cursors: HashMap<u32, CursorShape>,
    backing: Option<(u16, u16)>,
}

/// Inflates a cursor bitmap (BGRA pixels followed by an alpha mask) into RGBA.
fn decode_cursor(rect: &CursorRect) -> Option<Vec<u8>> {
    let (w, h) = (rect.size.0 as usize, rect.size.1 as usize);
    let px = w * h;
    let mut raw = Vec::with_capacity(px * 5);
    let mut z = flate2::read::ZlibDecoder::new(rect.compressed).take((px * 5) as u64);
    // Sync-flushed streams end without a trailer; keep what inflated.
    if z.read_to_end(&mut raw).is_err() && raw.len() < px * 5 {
        return None;
    }
    if raw.len() != px * 5 {
        tracing::debug!("cursor payload is {} bytes, expected {}", raw.len(), px * 5);
        return None;
    }
    let (bgra, mask) = raw.split_at(px * 4);
    let mut rgba = Vec::with_capacity(px * 4);
    for (p, &a) in bgra.as_chunks::<4>().0.iter().zip(mask) {
        rgba.extend_from_slice(&[p[2], p[1], p[0], a]);
    }
    Some(rgba)
}

impl ControlReader {
    pub fn new(
        shared: Arc<Shared>,
        control: Arc<Control>,
        clipboard_out: Sender<clipboard::Content>,
        feedback: Sender<Feedback>,
    ) -> Self {
        Self {
            shared,
            control,
            clipboard_out,
            feedback,
            clipboard: Reassembler::default(),
            cursors: HashMap::new(),
            backing: None,
        }
    }

    pub fn run(&mut self, stream: &mut TcpStream, mut opener: RecordOpener) -> Result<()> {
        loop {
            match opener.read(stream) {
                Ok(Opened::Message(msg)) => self.dispatch(&msg),
                Ok(Opened::BadMac) => tracing::debug!("dropped control record with bad MAC"),
                Err(e) if self.shared.stopped() => {
                    tracing::debug!("control reader stopping: {e}");
                    return Ok(());
                }
                Err(e) => {
                    // read_exact turns a FIN into UnexpectedEof; a reset or
                    // TCP_USER_TIMEOUT surfaces as its own error kind.
                    let marker = if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        crate::errors::Failure::HostClosed
                    } else {
                        crate::errors::Failure::ConnectionLost
                    };
                    return Err(anyhow::Error::new(e).context(marker));
                }
            }
        }
    }

    pub fn dispatch(&mut self, msg: &[u8]) {
        if msg.is_empty() {
            return;
        }
        // Continuation records of a multi-record 0x1f carry no type byte.
        if self.clipboard.in_progress() || msg[0] == 0x1f {
            if let Some(full) = self.clipboard.feed(msg)
                && let Some(content) = clipboard::content_from_message(&full) {
                    match &content {
                        clipboard::Content::Text(t) => tracing::debug!("remote clipboard: {} chars", t.chars().count()),
                        clipboard::Content::Image { tiff, data } => {
                            tracing::debug!("remote clipboard: {} image, {} bytes", if *tiff { "tiff" } else { "png" }, data.len())
                        }
                    }
                    let _ = self.clipboard_out.send(content);
                }
            return;
        }
        match msg[0] {
            0x00 => self.framebuffer_update(msg),
            0x14 if msg.len() >= 8 => {
                let cmd = u16::from_be_bytes([msg[6], msg[7]]);
                if cmd == 2 {
                    self.control.send(&clipboard::request_pasteboard());
                }
            }
            0x02 => {} // bell
            other => tracing::debug!("ignoring control message {other:#04x} ({} bytes)", msg.len()),
        }
    }

    fn framebuffer_update(&mut self, msg: &[u8]) {
        let mut saw_cursor = false;
        for rect in messages::parse_fbu(msg) {
            match rect {
                Rect::Cursor(c) => {
                    saw_cursor = true;
                    self.cursor(&c);
                }
                Rect::Layout(l) => self.layout(l),
                Rect::MediaBlob(data) => {
                    if let Some(c) = parse_answer(data).filter(|c| !c.is_degenerate()) {
                        tracing::info!("encoder canvas {}x{} in {} tiles", c.width, c.height, c.tiles);
                        if c.tiles > 0 {
                            self.shared.tiles.store(c.tiles, Ordering::Relaxed);
                        }
                        self.shared.set_canvas(c.width, c.height);
                        self.shared.metrics.set_answer_ltrp(c.ltrp);
                    }
                }
                Rect::RecordKeys(k) => tracing::debug!("ignoring late record-key rect ({} bytes)", k.len()),
                Rect::Skipped(enc) => tracing::trace!("skipped rect encoding {enc}"),
            }
        }
        if saw_cursor {
            // The host re-arms its cursor sender per request; a 1×1 region
            // keeps cursor updates flowing without pulling video over TCP.
            self.control.send(&messages::fbu_request(true, 0, 0, 1, 1));
        }
    }

    fn cursor(&mut self, c: &CursorRect) {
        let shape = if c.compressed.is_empty() {
            // Cache hit: the host sends only the id, with a 0×0 size.
            self.cursors.get(&c.cache_id).cloned().map(|s| CursorShape { fresh: false, ..s })
        } else {
            decode_cursor(c).map(|rgba| {
                let shape = CursorShape {
                    cache_id: c.cache_id,
                    width: c.size.0,
                    height: c.size.1,
                    hotspot: c.hotspot,
                    rgba: Some(Arc::new(rgba)),
                    fresh: true,
                };
                if self.cursors.len() >= MAX_CACHED_CURSORS {
                    self.cursors.clear();
                }
                self.cursors.insert(c.cache_id, shape.clone());
                shape
            })
        };
        let shape = shape.unwrap_or(CursorShape {
            cache_id: c.cache_id,
            width: c.size.0,
            height: c.size.1,
            hotspot: c.hotspot,
            rgba: None,
            fresh: false,
        });
        self.shared.sink.emit(Event::Cursor(shape));
    }

    fn layout(&mut self, l: DisplayLayout) {
        tracing::info!(
            "display layout: {}x{} points, {}x{} pixels, {} display(s)",
            l.scaled.0,
            l.scaled.1,
            l.backing.0,
            l.backing.1,
            l.displays.len()
        );
        // Re-arm the cursor sender at every layout transition.
        self.control.send(&messages::fbu_request(false, 0, 0, 0xffff, 0xffff));
        if l.backing.0 == 0 || l.backing.1 == 0 {
            return;
        }
        let changed = self.backing.is_some_and(|b| b != l.backing);
        self.backing = Some(l.backing);
        if changed {
            // The encoder stops after a geometry change until the media
            // session is offered again.
            tracing::info!("geometry changed; re-offering media session");
            self.shared.touch(&self.shared.renegotiated);
            self.shared.touch(&self.shared.geometry_changed);
            self.control.reoffer();
            let _ = self.feedback.send(Feedback::Keyframe(None, KeyframeCause::Reoffer));
        }
        self.shared.set_canvas(l.backing.0 as u32, l.backing.1 as u32);
    }
}
