//! Mirrors plain text between the local clipboard and the host pasteboard.
//!
//! Remote changes arrive pushed over the control channel (auto-pasteboard);
//! local changes are found by polling, since neither X11 nor Wayland offer a
//! portable change notification through `arboard`. Clipboard contents are
//! never logged.

use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError};

use crate::proto::clipboard::send_text;
use crate::session::{Control, Shared};

const POLL: Duration = Duration::from_millis(500);
/// Larger texts are not mirrored to the host.
const MAX_SEND: usize = 8 << 20;

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// Tracks both sides so a value set by one side isn't echoed back to it.
#[derive(Default)]
struct Mirror {
    /// Last local value seen, normalized.
    local: Option<String>,
    /// Last value exchanged with the host, normalized.
    synced: Option<String>,
}

impl Mirror {
    /// A local value was read. Returns the text to send to the host.
    fn local_changed(&mut self, text: String) -> Option<String> {
        let text = normalize(&text);
        if self.local.as_deref() == Some(&text) {
            return None;
        }
        self.local = Some(text.clone());
        if self.synced.as_deref() == Some(&text) || text.is_empty() {
            return None;
        }
        self.synced = Some(text.clone());
        Some(text)
    }

    /// The host sent a value. Returns the text to set locally.
    fn remote_changed(&mut self, text: String) -> Option<String> {
        let text = normalize(&text);
        if self.synced.as_deref() == Some(&text) && self.local.as_deref() == Some(&text) {
            return None;
        }
        self.synced = Some(text.clone());
        self.local = Some(text.clone());
        Some(text)
    }
}

pub(crate) fn run(shared: Arc<Shared>, control: Arc<Control>, remote: Receiver<String>) {
    // The clipboard object must outlive any text we set: on Linux this
    // process serves the selection until another client takes it.
    let mut clip = match arboard::Clipboard::new() {
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
    let mut mirror = Mirror::default();
    // Whatever is on the local clipboard at connect time is not pushed to
    // the host; only later changes are.
    if let Ok(t) = clip.get_text() {
        mirror.local = Some(normalize(&t));
    }

    while !shared.is_stopped() {
        match remote.recv_timeout(POLL) {
            Ok(text) => {
                if let Some(t) = mirror.remote_changed(text) {
                    if let Err(e) = clip.set_text(t) {
                        tracing::warn!("setting local clipboard failed: {e}");
                    } else {
                        tracing::debug!("local clipboard updated from host");
                    }
                }
                continue;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        match clip.get_text() {
            Ok(text) => {
                if let Some(t) = mirror.local_changed(text) {
                    if t.len() > MAX_SEND {
                        tracing::info!("local clipboard text too large to share ({} bytes)", t.len());
                    } else {
                        tracing::debug!("sending local clipboard to host ({} bytes)", t.len());
                        control.send(&send_text(&t));
                    }
                }
            }
            // Empty or non-text clipboard.
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_echo_in_either_direction() {
        let mut m = Mirror::default();
        assert_eq!(m.remote_changed("a\r\nb".into()).as_deref(), Some("a\nb"));
        // Our own write read back locally is not re-sent.
        assert_eq!(m.local_changed("a\nb".into()), None);
        assert_eq!(m.local_changed("c".into()).as_deref(), Some("c"));
        // The host echoing our value back doesn't touch the local clipboard.
        assert_eq!(m.remote_changed("c".into()), None);
        // Polling the same value again sends nothing.
        assert_eq!(m.local_changed("c".into()), None);
    }
}
