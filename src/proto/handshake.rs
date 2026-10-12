//! Drives a control connection from TCP connect to a negotiated media
//! session: banner, auth, ClientInit, optional SessionSelect, the plaintext
//! prelude, the switch to the enc1103 record layer, and the 0x1c offer.

use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::auth::{self, AuthError};
use super::messages::{self, DisplayRequest, ENC_RECORD_KEYS};
use super::offers::{CanvasInfo, MediaOffer, parse_answer};
use super::record::{Opened, RecordKeys, RecordOpener, RecordSealer};
use super::wire::{be16, be32, read_vec};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_SELECT_MAGIC: [u8; 4] = [0x00, 0x4a, 0x00, 0x01];
const SESSION_SELECT_WAIT: Duration = Duration::from_secs(60);
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);
const DEGENERATE_RETRIES: u32 = 16;

/// What to do when someone other than the authenticating user owns the
/// host's console.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum SessionMode {
    /// Ask the console user to share their session.
    Share,
    /// Log in to a separate virtual session as the authenticating user.
    Alt,
}

pub struct ConnectParams {
    pub addr: SocketAddrV4,
    pub user: String,
    pub password: String,
    pub session_mode: SessionMode,
    pub display: DisplayRequest,
    pub audio: bool,
}

/// An authenticated, encrypted control connection with media negotiated.
pub struct Negotiated {
    pub stream: TcpStream,
    pub sealer: RecordSealer,
    pub opener: RecordOpener,
    pub record_key: [u8; 16],
    pub offer: MediaOffer,
    pub canvas: Option<CanvasInfo>,
    pub server_size: (u16, u16),
    /// Messages decrypted while waiting for the answer; dispatch these
    /// before reading further from the stream.
    pub pending: Vec<Vec<u8>>,
}

/// Apple's two-TCP convention: a banner-only connection first registers the
/// viewer so the real session survives login/lock transitions.
pub fn warmup(addr: SocketAddrV4) -> Result<()> {
    let mut s = TcpStream::connect_timeout(&addr.into(), Duration::from_secs(10))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    banner(&mut s)?;
    let _ = s.shutdown(std::net::Shutdown::Both);
    std::thread::sleep(Duration::from_millis(1400));
    Ok(())
}

fn banner(s: &mut TcpStream) -> Result<Vec<u8>> {
    let server = read_vec(s, 12)?;
    if !server.starts_with(b"RFB ") {
        bail!("not an RFB server (banner {:?})", String::from_utf8_lossy(&server));
    }
    s.write_all(messages::PROTOCOL_VERSION)?;
    let mut n = [0u8; 1];
    s.read_exact(&mut n)?;
    if n[0] == 0 {
        let len = super::wire::read_u32(s)? as usize;
        let reason = read_vec(s, len.min(4096))?;
        bail!("server refused connection: {}", String::from_utf8_lossy(&reason));
    }
    Ok(read_vec(s, n[0] as usize)?)
}

fn open(addr: SocketAddrV4) -> Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&addr.into(), IO_TIMEOUT)
        .with_context(|| format!("connecting to {addr}"))?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    let types = banner(&mut s)?;
    if !types.contains(&33) {
        bail!("server does not offer Apple auth (security types {types:?})");
    }
    Ok(s)
}

/// Opens a connection and authenticates, preferring SRP and falling back to
/// the RSA1/AES path on a fresh connection when the host lacks SRP.
fn authenticate(p: &ConnectParams) -> Result<(TcpStream, [u8; 16])> {
    let mut s = open(p.addr)?;
    match auth::srp_auth(&mut s, &p.user, &p.password) {
        Ok(key) => {
            tracing::info!("authenticated (SRP)");
            return Ok((s, key));
        }
        Err(e) if matches!(e.downcast_ref::<AuthError>(), Some(AuthError::SrpUnavailable(_))) => {
            tracing::info!("{e}; retrying with legacy auth");
        }
        Err(e) => return Err(e.context("SRP authentication failed")),
    }
    let mut s = open(p.addr)?;
    let key = auth::nonsrp_auth(&mut s, &p.user, &p.password).context("legacy authentication failed")?;
    tracing::info!("authenticated (legacy RSA1)");
    Ok((s, key))
}

fn client_init(s: &mut TcpStream) -> Result<(u16, u16)> {
    s.write_all(&[0xC1])?;
    let head = read_vec(s, 24)?;
    let name_len = be32(&head, 20) as usize;
    let name = read_vec(s, name_len.min(1 << 16))?;
    let size = (be16(&head, 0), be16(&head, 2));
    tracing::info!(
        "server {:?} framebuffer {}x{}",
        String::from_utf8_lossy(&name),
        size.0,
        size.1
    );
    Ok(size)
}

/// Returns true if the host appended a SessionSelect prompt after
/// ServerInit (it does when another user owns the console).
fn session_select_pending(s: &TcpStream) -> Result<bool> {
    s.set_read_timeout(Some(Duration::from_millis(1500)))?;
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut peek = [0u8; 4];
    let result = loop {
        match s.peek(&mut peek) {
            Ok(4) => break Ok(peek == SESSION_SELECT_MAGIC),
            Ok(0) => break Err(anyhow::anyhow!("server closed the connection")),
            Ok(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(_) => break Ok(false),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                break Ok(false);
            }
            Err(e) => break Err(e.into()),
        }
    };
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    result
}

fn session_select(s: &mut TcpStream, p: &ConnectParams, auth_key: &[u8; 16]) -> Result<()> {
    let prompt = read_vec(s, 76)?;
    if prompt[..4] != SESSION_SELECT_MAGIC {
        bail!("malformed SessionSelect prompt");
    }
    let flags = be32(&prompt, 4);
    let console_user = prompt[0xc..]
        .split(|&b| b == 0)
        .next()
        .map(|u| String::from_utf8_lossy(u).into_owned())
        .unwrap_or_default();

    let (cmd, body) = match p.session_mode {
        SessionMode::Share => {
            tracing::info!("{console_user:?} is logged in at the console; asking them to share");
            let mut body = vec![0u8; 72];
            body[0..2].copy_from_slice(&2u16.to_be_bytes());
            let u = console_user.as_bytes();
            let n = u.len().min(72 - 9);
            body[8..8 + n].copy_from_slice(&u[..n]);
            (0u32, body)
        }
        SessionMode::Alt => {
            tracing::info!("{console_user:?} is logged in at the console; opening a separate session");
            let mut body = vec![0u8; 200];
            body[0..2].copy_from_slice(&2u16.to_be_bytes());
            body[6] = 2;
            body[0x48..0x88].copy_from_slice(&auth::ecb_field(auth_key, &p.user));
            body[0x88..0xC8].copy_from_slice(&auth::ecb_field(auth_key, &p.password));
            (2, body)
        }
    };
    if flags >> cmd & 1 == 0 {
        tracing::warn!("host does not advertise SessionSelect cmd {cmd} (flags {flags:#x})");
    }
    let mut msg = (body.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    s.write_all(&msg)?;

    // The acknowledgement content is opaque; consume what arrives.
    s.set_read_timeout(Some(SESSION_SELECT_WAIT))?;
    let mut ack = [0u8; 4096];
    let n = match s.read(&mut ack) {
        Ok(n) => n,
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
            bail!("timed out waiting for the session to be shared or created")
        }
        Err(e) => return Err(e.into()),
    };
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    if n == 0 {
        bail!("host declined the session request");
    }
    Ok(())
}

/// Reads plaintext server messages until the FramebufferUpdate carrying the
/// record-layer keys (encoding 1103). Everything after it is encrypted.
fn read_record_keys(s: &mut TcpStream, auth_key: &[u8; 16]) -> Result<RecordKeys> {
    loop {
        let mut t = [0u8; 1];
        s.read_exact(&mut t)?;
        match t[0] {
            0x14 => {
                read_vec(s, 7)?;
            }
            0x00 => {
                let hdr = read_vec(s, 3)?;
                let n = be16(&hdr, 1);
                let mut keys = None;
                for _ in 0..n {
                    let rect = read_vec(s, 12)?;
                    let enc = be32(&rect, 8) as i32;
                    match enc {
                        ENC_RECORD_KEYS => {
                            let blob = read_vec(s, 36)?;
                            keys = RecordKeys::unwrap(&blob, auth_key);
                        }
                        1010 | 1011 => {
                            let mut len = [0u8; 2];
                            s.read_exact(&mut len)?;
                            read_vec(s, u16::from_be_bytes(len) as usize)?;
                        }
                        other => bail!("unexpected plaintext encoding {other} before record keys"),
                    }
                }
                if let Some(k) = keys {
                    return Ok(k);
                }
            }
            other => bail!(
                "unexpected plaintext message {other:#x} before record keys \
                 (the host may be rate-limiting; wait 10-15 s and retry)"
            ),
        }
    }
}

/// Waits up to `timeout` for at least one byte to be readable.
fn wait_readable(s: &TcpStream, timeout: Duration) -> Result<bool> {
    s.set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
    let mut b = [0u8; 1];
    let r = match s.peek(&mut b) {
        Ok(0) => Err(anyhow::anyhow!("server closed the connection")),
        Ok(_) => Ok(true),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok(false),
        Err(e) => Err(e.into()),
    };
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    r
}

pub fn connect(p: &ConnectParams) -> Result<Negotiated> {
    let (mut s, mut auth_key) = authenticate(p)?;
    let mut server_size = client_init(&mut s)?;

    if session_select_pending(&s)? {
        if p.session_mode == SessionMode::Alt {
            // Screen Sharing.app re-authenticates on a fresh connection
            // before sending encrypted credentials.
            drop(s);
            (s, auth_key) = authenticate(p)?;
            server_size = client_init(&mut s)?;
        }
        session_select(&mut s, p, &auth_key)?;
    }

    s.write_all(&messages::viewer_info())?;
    std::thread::sleep(Duration::from_millis(100));
    s.write_all(&messages::set_display_configuration(&p.display))?;
    s.write_all(&messages::set_encodings())?;

    let keys = read_record_keys(&mut s, &auth_key)?;
    let mut sealer = RecordSealer::new(&keys);
    let mut opener = RecordOpener::new(&keys);
    s.write_all(&messages::post_encryption_toggle())?;
    std::thread::sleep(Duration::from_millis(200));
    tracing::debug!("record layer active");

    let offer = MediaOffer::generate(p.audio, p.session_mode == SessionMode::Alt);
    let offer_msg = offer.message();
    for m in [messages::set_encodings(), offer_msg.clone(), messages::fbu_request(false, 0, 0, 0xffff, 0xffff)] {
        s.write_all(&sealer.seal(&m))?;
    }

    let mut pending = Vec::new();
    let mut canvas = None;
    let mut retries = 0;
    let mut deadline = Instant::now() + ANSWER_TIMEOUT;
    loop {
        let now = Instant::now();
        if now >= deadline || !wait_readable(&s, deadline - now)? {
            if canvas.is_some() && retries < DEGENERATE_RETRIES {
                retries += 1;
                s.write_all(&sealer.seal(&offer_msg))?;
                deadline = Instant::now() + ANSWER_TIMEOUT;
                continue;
            }
            tracing::warn!("no usable media answer; continuing and waiting for video");
            canvas = None;
            break;
        }
        let msg = match opener.read(&mut s)? {
            Opened::Message(m) => m,
            Opened::BadMac => continue,
        };
        match (msg.first(), parse_answer(&msg)) {
            (Some(0x00), Some(c)) if !c.is_degenerate() => {
                tracing::info!("encoder canvas {}x{} in {} tiles", c.width, c.height, c.tiles);
                canvas = Some(c);
                break;
            }
            (Some(0x00), Some(c)) => {
                tracing::debug!("degenerate canvas answer; re-offering");
                canvas = Some(c);
                if retries >= DEGENERATE_RETRIES {
                    canvas = None;
                    break;
                }
                retries += 1;
                std::thread::sleep(Duration::from_millis(200));
                s.write_all(&sealer.seal(&offer_msg))?;
                deadline = Instant::now() + ANSWER_TIMEOUT;
            }
            _ => pending.push(msg),
        }
    }

    Ok(Negotiated {
        stream: s,
        sealer,
        opener,
        record_key: keys.key,
        offer,
        canvas,
        server_size,
        pending,
    })
}
