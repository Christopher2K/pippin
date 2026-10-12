//! A live screen-sharing session: owns the control connection and the media
//! threads, and exposes input/resize/clipboard entry points to the UI.
//!
//! Threads:
//! * `control` connects, then reads the encrypted TCP control channel
//!   (cursor shapes, display layout, clipboard, media answers).
//! * `video-rx` receives SRTP video, assembles access units, maps SSRCs to
//!   tiles and hands work to `decoder`.
//! * `decoder` runs libavcodec and publishes pictures to the [`FrameStore`].
//! * `ctrl-rx` drains the audio/RTCP UDP port and records sender reports.
//! * `feedback` sends RTCP (receiver reports, keyframe requests, NACKs, LTR
//!   acks), the audio keepalive and the cursor poll on a 500 ms tick.
//! * `clipboard` mirrors text between the local and remote pasteboards.

mod control;
mod media;

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, Sender};
use parking_lot::Mutex;

use crate::proto::handshake::{self, ConnectParams, SessionMode};
use crate::proto::messages::{self, DisplayRequest};
use crate::proto::offers::MediaOffer;
use crate::proto::record::RecordSealer;
use crate::video::decoder::Picture;

pub use media::Feedback;

/// Connection settings.
#[derive(Clone)]
pub struct Config {
    pub host: Ipv4Addr,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub session_mode: SessionMode,
    pub hardware_decode: bool,
    /// Software decoder threads; see `DecoderOptions`.
    pub decode_threads: u32,
    pub warmup: bool,
}

/// A cursor shape from the host. `rgba` is `None` when the host referenced
/// a cache entry we never received; the UI then shows its default cursor.
/// Cache hits carry the size and hotspot remembered from the original
/// image, since the host sends them as 0×0.
#[derive(Clone)]
pub struct CursorShape {
    pub cache_id: u32,
    pub width: u16,
    pub height: u16,
    pub hotspot: (u16, u16),
    pub rgba: Option<Arc<Vec<u8>>>,
    /// The image arrived in this message rather than from the cache, so any
    /// cursor the UI built for `cache_id` is stale.
    pub fresh: bool,
}

pub enum Event {
    Connected,
    /// New decoded pictures are waiting in the [`FrameStore`].
    Frame,
    /// Size of the encoded canvas in pixels.
    Canvas { width: u32, height: u32 },
    Cursor(CursorShape),
    Closed(Option<String>),
}

pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, event: Event);
}

/// Latest decoded picture per tile, handed from the decoder to the renderer.
#[derive(Default)]
pub struct FrameStore {
    slots: Mutex<Vec<Option<Picture>>>,
    notified: AtomicBool,
}

impl FrameStore {
    fn put(&self, tile: usize, pic: Picture) -> bool {
        let mut slots = self.slots.lock();
        if slots.len() <= tile {
            slots.resize_with(tile + 1, || None);
        }
        slots[tile] = Some(pic);
        !self.notified.swap(true, Ordering::AcqRel)
    }

    /// Takes every pending picture as `(tile, picture)`.
    pub fn take(&self) -> Vec<(usize, Picture)> {
        self.notified.store(false, Ordering::Release);
        let mut slots = self.slots.lock();
        slots.iter_mut().enumerate().filter_map(|(i, s)| s.take().map(|p| (i, p))).collect()
    }
}

/// The encrypted control-channel writer. The lock keeps record sequence
/// numbers in wire order across threads.
pub struct Control {
    writer: Mutex<(TcpStream, RecordSealer)>,
    record_key: [u8; 16],
    offer: MediaOffer,
}

impl Control {
    pub fn send(&self, msg: &[u8]) {
        let mut w = self.writer.lock();
        let rec = w.1.seal(msg);
        if let Err(e) = w.0.write_all(&rec) {
            tracing::debug!("control send failed: {e}");
        }
    }

    pub fn reoffer(&self) {
        self.send(&self.offer.message());
    }
}

/// Monotonic millisecond clock shared between threads.
struct Clock(Instant);

impl Clock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}

/// State shared by the session threads.
pub struct Shared {
    clock: Clock,
    stop: AtomicBool,
    control: OnceLock<Arc<Control>>,
    sink: Arc<dyn EventSink>,
    pub(crate) frames: Arc<FrameStore>,
    /// Tile count from the latest media answer.
    tiles: AtomicU32,
    last_video_packet: AtomicU64,
    last_frame: AtomicU64,
    /// When the media session was last re-offered (resize).
    renegotiated: AtomicU64,
    tile_ssrcs: Mutex<Vec<u32>>,
    extended_seqs: Mutex<HashMap<u32, u32>>,
    sender_reports: Mutex<HashMap<u32, (u32, Instant)>>,
    canvas: Mutex<Option<(u32, u32)>>,
}

impl Shared {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn since_ms(&self, stamp: &AtomicU64) -> u64 {
        self.clock.now_ms().saturating_sub(stamp.load(Ordering::Relaxed))
    }

    fn touch(&self, stamp: &AtomicU64) {
        stamp.store(self.clock.now_ms(), Ordering::Relaxed);
    }

    fn set_canvas(&self, w: u32, h: u32) {
        let mut c = self.canvas.lock();
        if *c != Some((w, h)) {
            *c = Some((w, h));
            self.sink.emit(Event::Canvas { width: w, height: h });
        }
    }
}

/// Handle used by the UI. Cheap to clone.
#[derive(Clone)]
pub struct Session {
    shared: Arc<Shared>,
    threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Session {
    /// Starts connecting in the background. Progress and failures arrive as
    /// [`Event`]s.
    pub fn start(cfg: Config, display: DisplayRequest, sink: Arc<dyn EventSink>) -> Self {
        let shared = Arc::new(Shared {
            clock: Clock(Instant::now()),
            stop: AtomicBool::new(false),
            control: OnceLock::new(),
            sink,
            frames: Arc::new(FrameStore::default()),
            tiles: AtomicU32::new(crate::proto::offers::TILES_PER_FRAME as u32),
            last_video_packet: AtomicU64::new(0),
            last_frame: AtomicU64::new(0),
            renegotiated: AtomicU64::new(0),
            tile_ssrcs: Mutex::new(Vec::new()),
            extended_seqs: Mutex::new(HashMap::new()),
            sender_reports: Mutex::new(HashMap::new()),
            canvas: Mutex::new(None),
        });
        let threads = Arc::new(Mutex::new(Vec::new()));
        let session = Session { shared: shared.clone(), threads: threads.clone() };
        let main = thread::Builder::new()
            .name("control".into())
            .spawn(move || {
                let result = run(cfg, display, shared.clone(), &threads);
                if !shared.stopped() {
                    let reason = result.err().map(|e| format!("{e:#}"));
                    shared.sink.emit(Event::Closed(reason.or_else(|| Some("connection closed".into()))));
                }
                shared.stop.store(true, Ordering::Release);
            })
            .expect("spawn control thread");
        session.threads.lock().push(main);
        session
    }

    pub fn frames(&self) -> &FrameStore {
        &self.shared.frames
    }

    fn control(&self) -> Option<&Arc<Control>> {
        self.shared.control.get()
    }

    pub fn key(&self, down: bool, keysym: u32) {
        if let Some(c) = self.control() {
            c.send(&messages::key_event(down, keysym));
        }
    }

    /// Pointer position in canvas pixels plus the RFB button mask.
    pub fn pointer(&self, buttons: u8, x: u16, y: u16) {
        if let Some(c) = self.control() {
            c.send(&messages::encrypted_pointer_event(&c.record_key, buttons, x, y));
        }
    }

    /// Asks the host to resize its virtual display.
    pub fn resize(&self, req: DisplayRequest) {
        if let Some(c) = self.control() {
            tracing::info!(
                "requesting {}x{} @{}x (backing {:?})",
                req.width,
                req.height,
                req.scale,
                req.backing()
            );
            c.send(&messages::set_display_configuration(&req));
        }
    }

    pub fn shutdown(&self) {
        if self.shared.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(c) = self.control() {
            // Reset rather than close so the host tears the session down
            // immediately instead of waiting out its own timeouts.
            let w = c.writer.lock();
            let _ = socket2::SockRef::from(&w.0).set_linger(Some(Duration::ZERO));
            let _ = w.0.shutdown(std::net::Shutdown::Both);
        }
        let threads: Vec<_> = self.threads.lock().drain(..).collect();
        for t in threads {
            let _ = t.join();
        }
    }
}

fn bind_udp(port: u16) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    let _ = s.set_recv_buffer_size(8 << 20);
    s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())
        .with_context(|| format!("binding UDP port {port} (is another screen-sharing client running?)"))?;
    if let Ok(n) = s.recv_buffer_size()
        && n < 2 << 20 {
            tracing::warn!(
                "UDP receive buffer is only {n} bytes; raise net.core.rmem_max \
                 (e.g. sysctl -w net.core.rmem_max=33554432) to avoid video loss"
            );
        }
    let s: UdpSocket = s.into();
    s.set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(s)
}

fn spawn(threads: &Mutex<Vec<JoinHandle<()>>>, name: &str, f: impl FnOnce() + Send + 'static) {
    let t = thread::Builder::new().name(name.into()).spawn(f).expect("spawn thread");
    threads.lock().push(t);
}

fn run(cfg: Config, display: DisplayRequest, shared: Arc<Shared>, threads: &Mutex<Vec<JoinHandle<()>>>) -> Result<()> {
    let addr = SocketAddrV4::new(cfg.host, cfg.port);
    let ctrl_dest = SocketAddrV4::new(cfg.host, cfg.port);
    let video_dest = SocketAddrV4::new(cfg.host, cfg.port + 1);

    // The media burst starts right after the answer, so the UDP sockets
    // must exist before the handshake.
    let ctrl_sock = bind_udp(cfg.port)?;
    let video_sock = bind_udp(cfg.port + 1)?;

    if cfg.warmup
        && let Err(e) = handshake::warmup(addr) {
            tracing::warn!("warmup connection failed: {e:#}");
        }

    // Keep the local firewall's return path open for the host's media while
    // negotiating; the host may start streaming at any point.
    let punching = Arc::new(AtomicBool::new(true));
    let punch = {
        let (c, v, flag) = (ctrl_sock.try_clone()?, video_sock.try_clone()?, punching.clone());
        thread::spawn(move || {
            while flag.load(Ordering::Relaxed) {
                let _ = c.send_to(&[0], ctrl_dest);
                let _ = v.send_to(&[0], video_dest);
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let params = ConnectParams {
        addr,
        user: cfg.user.clone(),
        password: cfg.password.clone(),
        session_mode: cfg.session_mode,
        display,
        audio: false,
    };
    let negotiated = handshake::connect(&params);
    punching.store(false, Ordering::Relaxed);
    let _ = punch.join();
    let neg = negotiated?;
    tracing::debug!("server framebuffer {}x{}", neg.server_size.0, neg.server_size.1);

    if let Some(c) = neg.canvas {
        if c.tiles > 0 {
            shared.tiles.store(c.tiles, Ordering::Relaxed);
        }
        shared.set_canvas(c.width, c.height);
    }
    let mut reader = neg.stream.try_clone()?;
    reader.set_read_timeout(None)?;
    let control = Arc::new(Control {
        writer: Mutex::new((neg.stream, neg.sealer)),
        record_key: neg.record_key,
        offer: neg.offer.clone(),
    });
    let _ = shared.control.set(control.clone());

    let (fb_tx, fb_rx): (Sender<Feedback>, Receiver<Feedback>) = crossbeam_channel::unbounded();
    let (dec_tx, dec_rx) = crossbeam_channel::bounded(256);
    let (clip_tx, clip_rx) = crossbeam_channel::unbounded();

    {
        let (shared, fb, sock) = (shared.clone(), fb_tx.clone(), video_sock.try_clone()?);
        let (key, dec_tx) = (neg.offer.video_key_s, dec_tx.clone());
        spawn(threads, "video-rx", move || media::video_rx(shared, sock, key, dec_tx, fb));
    }
    {
        let (shared, fb) = (shared.clone(), fb_tx.clone());
        let opts = crate::video::decoder::DecoderOptions {
            prefer_hw: cfg.hardware_decode,
            threads: cfg.decode_threads,
        };
        spawn(threads, "decoder", move || media::decoder(shared, dec_rx, fb, opts));
    }
    {
        let (shared, sock) = (shared.clone(), ctrl_sock.try_clone()?);
        let key = neg.offer.video_key_s;
        spawn(threads, "ctrl-rx", move || media::ctrl_rx(shared, sock, key));
    }
    {
        let shared = shared.clone();
        let sockets = media::FeedbackSockets { ctrl: ctrl_sock, video: video_sock, ctrl_dest, video_dest };
        let offer = neg.offer.clone();
        spawn(threads, "feedback", move || media::feedback(shared, sockets, offer, fb_rx, dec_tx));
    }
    {
        let (shared, control) = (shared.clone(), control.clone());
        spawn(threads, "clipboard", move || crate::clipboard::run(shared, control, clip_rx));
    }

    // Subscribe to pasteboard changes and prime with the current contents.
    control.send(&crate::proto::clipboard::enable_auto_pasteboard());
    control.send(&crate::proto::clipboard::request_pasteboard());
    shared.sink.emit(Event::Connected);

    let mut rx = control::ControlReader::new(shared.clone(), control, clip_tx, fb_tx);
    for msg in neg.pending {
        rx.dispatch(&msg);
    }
    rx.run(&mut reader, neg.opener)
}

impl Shared {
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped()
    }
}
