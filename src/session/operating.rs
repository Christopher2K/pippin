//! The operating point: the levers that trade picture quality for
//! robustness on a lossy link, switchable mid-session for experiments.
//!
//! Fast levers take effect at once: `recovery` (the next keyframe request)
//! and `hold` (the next access unit with a gap). Slow ones renegotiate:
//! * `render_scale` asks the host for a display with fewer backing pixels,
//!   the same path as a window resize: SetDisplayConfiguration, the host's
//!   layout answer, a 0x1c re-offer, then a new SSRC group starting with an
//!   IDR (see `ControlReader::layout`).
//! * `fps` and `ltr` change the media offer, so they are applied with a
//!   0x1c re-offer (same keys and SSRCs) on the open connection. The host
//!   restarts its encoder on a re-offer after a resize; whether it also
//!   honours changed flags or LTR in a re-offer without a geometry change is
//!   unverified. If the stream keeps its old rate, `restart` reconnects,
//!   and the new session offers the current operating point from the start.
//!
//! A debug control FIFO (`MACSHARE_CONTROL_FIFO=/path`) takes one command
//! per line; see [`parse_command`].

use std::fmt;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossbeam_channel::Sender;
use parking_lot::Mutex;

use super::{Event, Feedback, KeyframeCause, Shared};
use crate::proto::offers::OfferOptions;
use crate::rtp::assembler::HoldMode;
use crate::rtp::rtcp::Recovery;

/// Offered frame rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Fps {
    #[value(name = "60")]
    Sixty,
    #[value(name = "30")]
    Thirty,
}

impl Fps {
    pub fn value(self) -> u32 {
        match self {
            Fps::Sixty => 60,
            Fps::Thirty => 30,
        }
    }
}

/// Where the client sits between quality and robustness. Held in
/// [`Shared`] and kept across reconnects.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OperatingPoint {
    /// Fraction of the window's pixels the host renders: 1 or 0.5. Slow.
    pub render_scale: f64,
    /// Slow: a re-offer.
    pub fps: Fps,
    /// Fast.
    pub recovery: Recovery,
    /// Fast.
    pub hold: HoldMode,
    /// LTR offered (slow: a re-offer) and LTR acks sent (stop at once).
    pub ltr: bool,
    // A codec lever (--codec hevc|h264) belongs here too; it is slow, and
    // likely needs `restart`, since the decoder has to change with it.
}

impl OperatingPoint {
    pub fn offer_options(&self) -> OfferOptions {
        OfferOptions { fps60: self.fps == Fps::Sixty, ltr: self.ltr }
    }
}

impl fmt::Display for OperatingPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "render_scale {} fps {} recovery {} hold {} ltr {}",
            self.render_scale,
            self.fps.value(),
            self.recovery.name(),
            self.hold.name(),
            if self.ltr { "on" } else { "off" }
        )
    }
}

pub type SharedOp = Arc<Mutex<OperatingPoint>>;

/// One lever setting.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Lever {
    RenderScale(f64),
    Fps(Fps),
    Recovery(Recovery),
    Hold(HoldMode),
    Ltr(bool),
}

impl Lever {
    fn set(self, op: &mut OperatingPoint) {
        match self {
            Lever::RenderScale(v) => op.render_scale = v,
            Lever::Fps(v) => op.fps = v,
            Lever::Recovery(v) => op.recovery = v,
            Lever::Hold(v) => op.hold = v,
            Lever::Ltr(v) => op.ltr = v,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Command {
    Set(Lever),
    /// Ask every tile for a keyframe now (e.g. to measure keyframe size).
    Keyframe,
    /// End the session and reconnect with the current operating point.
    Restart,
}

pub fn parse_on_off(s: &str) -> Result<bool, String> {
    match s {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("expected on or off, got {s:?}")),
    }
}

/// Parses a control line: `render_scale 1|0.5`, `fps 60|30`,
/// `recovery fir|pli|fir+pli`, `hold auto|on|off`, `ltr on|off`,
/// `keyframe` or `restart` (which ends the session like a dropped connection,
/// so it exits under `--no-reconnect`). Blank lines and `#` comments give `Ok(None)`.
pub fn parse_command(line: &str) -> Result<Option<Command>, String> {
    let line = line.split('#').next().unwrap_or_default().trim();
    let mut words = line.split_whitespace();
    let Some(cmd) = words.next() else { return Ok(None) };
    let arg = words.next();
    if words.next().is_some() {
        return Err(format!("too many arguments: {line:?}"));
    }
    let need = |what: &str| arg.ok_or_else(|| format!("{cmd} needs {what}"));
    let lever = match cmd {
        "render_scale" => match need("1 or 0.5")?.parse::<f64>() {
            Ok(v) if v == 1.0 || v == 0.5 => Lever::RenderScale(v),
            _ => return Err("render_scale must be 1 or 0.5".into()),
        },
        "fps" => match need("60 or 30")? {
            "60" => Lever::Fps(Fps::Sixty),
            "30" => Lever::Fps(Fps::Thirty),
            other => return Err(format!("fps must be 60 or 30, got {other:?}")),
        },
        "recovery" => {
            let v = need("fir, pli or fir+pli")?;
            Lever::Recovery(Recovery::parse(v).ok_or_else(|| format!("unknown recovery {v:?}"))?)
        }
        "hold" => {
            let v = need("auto, on or off")?;
            Lever::Hold(HoldMode::parse(v).ok_or_else(|| format!("unknown hold mode {v:?}"))?)
        }
        "ltr" => Lever::Ltr(parse_on_off(need("on or off")?)?),
        "keyframe" | "restart" if arg.is_some() => return Err(format!("{cmd} takes no argument")),
        "keyframe" => return Ok(Some(Command::Keyframe)),
        "restart" => return Ok(Some(Command::Restart)),
        _ => return Err(format!("unknown command {cmd:?}")),
    };
    Ok(Some(Command::Set(lever)))
}

/// Moves the session to `new`: fast levers are read where they're used, so
/// storing them is enough; slow ones start their renegotiation here.
pub(super) fn apply(shared: &Shared, fb: &Sender<Feedback>, new: OperatingPoint) {
    let old = std::mem::replace(&mut *shared.op_handle().lock(), new);
    if old == new {
        return;
    }
    tracing::info!("operating point: {new} (was {old})");
    if new.render_scale != old.render_scale {
        // The window asks for the display; the host's layout answer then
        // triggers the re-offer.
        shared.sink.emit(Event::Reconfigure);
    }
    if new.offer_options() != old.offer_options()
        && let Some(c) = shared.control.get()
    {
        tracing::info!("re-offering media session for the new frame rate / LTR setting");
        c.set_offer_options(new.offer_options());
        shared.touch(&shared.renegotiated);
        c.reoffer();
        let _ = fb.send(Feedback::Keyframe(None, KeyframeCause::Reoffer));
    }
}

fn run_command(shared: &Shared, fb: &Sender<Feedback>, cmd: Command) {
    match cmd {
        Command::Set(lever) => {
            let mut op = shared.op();
            lever.set(&mut op);
            apply(shared, fb, op);
        }
        Command::Keyframe => {
            tracing::info!("control: keyframe requested");
            let _ = fb.send(Feedback::Keyframe(None, KeyframeCause::Other));
        }
        Command::Restart => {
            tracing::info!("control: restarting the session");
            shared.sink.emit(Event::Lost("restart requested on the control FIFO".into()));
        }
    }
}

fn open_fifo(path: &Path) -> std::io::Result<std::fs::File> {
    if !path.exists() {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SAFETY: a valid NUL-terminated path.
        if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    // Read-write, so opening doesn't wait for a writer and the FIFO never
    // reads as closed between writers.
    let f = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open(path)?;
    if !f.metadata()?.file_type().is_fifo() {
        return Err(std::io::Error::other("not a FIFO"));
    }
    Ok(f)
}

/// Reads control commands from the FIFO at `path` until the session stops.
pub(super) fn control_fifo(shared: Arc<Shared>, path: PathBuf, fb: Sender<Feedback>) {
    let mut f = match open_fifo(&path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("MACSHARE_CONTROL_FIFO {}: {e}", path.display());
            return;
        }
    };
    tracing::info!("reading control commands from {}", path.display());
    let mut pending = Vec::new();
    let mut buf = [0u8; 1024];
    while !shared.stopped() {
        let mut pfd = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd; a short timeout so shutdown isn't held up.
        if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
            continue;
        }
        match f.read(&mut buf) {
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                tracing::warn!("control FIFO: {e}");
                return;
            }
        }
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            match parse_command(&String::from_utf8_lossy(&line)) {
                Ok(Some(cmd)) => run_command(&shared, &fb, cmd),
                Ok(None) => {}
                Err(e) => tracing::warn!("control FIFO: {e}"),
            }
        }
        if pending.len() > 4096 {
            pending.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn set(l: Lever) -> Result<Option<Command>, String> {
        Ok(Some(Command::Set(l)))
    }

    #[test]
    fn parses_commands() {
        assert_eq!(parse_command("render_scale 0.5"), set(Lever::RenderScale(0.5)));
        assert_eq!(parse_command("  render_scale   1 \n"), set(Lever::RenderScale(1.0)));
        assert_eq!(parse_command("fps 30"), set(Lever::Fps(Fps::Thirty)));
        assert_eq!(parse_command("fps 60"), set(Lever::Fps(Fps::Sixty)));
        assert_eq!(parse_command("recovery pli"), set(Lever::Recovery(Recovery::Pli)));
        assert_eq!(parse_command("recovery fir+pli"), set(Lever::Recovery(Recovery::FirPli)));
        assert_eq!(parse_command("recovery fir"), set(Lever::Recovery(Recovery::Fir)));
        assert_eq!(parse_command("hold off"), set(Lever::Hold(HoldMode::Off)));
        assert_eq!(parse_command("hold auto # comment"), set(Lever::Hold(HoldMode::Auto)));
        assert_eq!(parse_command("ltr off"), set(Lever::Ltr(false)));
        assert_eq!(parse_command("keyframe"), Ok(Some(Command::Keyframe)));
        assert_eq!(parse_command("restart\r"), Ok(Some(Command::Restart)));
        assert_eq!(parse_command(""), Ok(None));
        assert_eq!(parse_command("   # just a comment"), Ok(None));
    }

    #[test]
    fn rejects_bad_commands() {
        for bad in [
            "render_scale 0.75",
            "render_scale",
            "render_scale x",
            "fps 24",
            "recovery idr",
            "hold maybe",
            "ltr yes",
            "restart now",
            "fps 30 60",
            "warp 9",
        ] {
            assert!(parse_command(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn opens_fifo_without_a_writer() {
        let path = std::env::temp_dir().join(format!("macshare-fifo-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut f = open_fifo(&path).expect("created and opened");
        let mut buf = [0u8; 16];
        assert_eq!(f.read(&mut buf).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        std::fs::OpenOptions::new().write(true).open(&path).unwrap().write_all(b"fps 30\n").unwrap();
        let n = f.read(&mut buf).unwrap();
        assert_eq!(parse_command(std::str::from_utf8(&buf[..n]).unwrap()), set(Lever::Fps(Fps::Thirty)));
        drop(f);
        // A regular file is refused rather than read in a busy loop.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();
        assert!(open_fifo(&path).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn levers_set_their_field() {
        let mut op = OperatingPoint {
            render_scale: 1.0,
            fps: Fps::Sixty,
            recovery: Recovery::FirPli,
            hold: HoldMode::Auto,
            ltr: true,
        };
        let before = op;
        Lever::Hold(HoldMode::Off).set(&mut op);
        Lever::Recovery(Recovery::Pli).set(&mut op);
        assert_eq!(op.offer_options(), before.offer_options());
        Lever::Fps(Fps::Thirty).set(&mut op);
        Lever::RenderScale(0.5).set(&mut op);
        assert_eq!(op.offer_options(), OfferOptions { fps60: false, ltr: true });
        assert_eq!(op.to_string(), "render_scale 0.5 fps 30 recovery pli hold off ltr on");
    }
}
