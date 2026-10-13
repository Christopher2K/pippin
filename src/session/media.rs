//! UDP media threads: SRTP video receive, HEVC decode and RTCP feedback.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::net::{SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};

use super::{AfterLoss, Event, Shared};
use crate::audio::Player;
use crate::proto::offers::{MediaOffer, SRTP_BLOB_LEN};
use crate::rtp::assembler::{AccessUnit, Assembler, HoldStats, POLL_EVERY, TileMap};
use crate::rtp::srtp::{SrtcpReceiver, SrtcpSender, SrtpReceiver, SrtpSender};
use crate::rtp::stats::{ReceiverStats, VIDEO_CLOCK_HZ};
use crate::rtp::{hevc, rtcp};
use crate::video::decoder::{self, Decoder, DecoderOptions, Picture};

/// Why a keyframe was requested, so the metrics can keep loss recovery
/// apart from requests that are part of a renegotiation or a watchdog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyframeCause {
    /// An access unit came out incomplete (lost packets, hold given up).
    Gap,
    /// The decoder rejected an access unit.
    DecodeError,
    /// A picture decoded with missing references.
    Damaged,
    /// A new SSRC group was adopted.
    Adoption,
    /// The media session was re-offered (resize, operating point).
    Reoffer,
    /// Packets arrive but no pictures come out.
    Stall,
    /// Switched to the next decoder backend.
    HwFallback,
    /// A keyframe arrived without parameter sets, or one was asked for on
    /// the control FIFO.
    Other,
}

impl KeyframeCause {
    pub const ALL: [KeyframeCause; 8] = [
        KeyframeCause::Gap,
        KeyframeCause::DecodeError,
        KeyframeCause::Damaged,
        KeyframeCause::Adoption,
        KeyframeCause::Reoffer,
        KeyframeCause::Stall,
        KeyframeCause::HwFallback,
        KeyframeCause::Other,
    ];

    /// Caused by loss on the link: what loss recovery is measured on.
    pub fn is_loss(self) -> bool {
        matches!(self, KeyframeCause::Gap | KeyframeCause::DecodeError | KeyframeCause::Damaged)
    }

    pub fn name(self) -> &'static str {
        match self {
            KeyframeCause::Gap => "gap",
            KeyframeCause::DecodeError => "decode",
            KeyframeCause::Damaged => "damaged",
            KeyframeCause::Adoption => "adoption",
            KeyframeCause::Reoffer => "reoffer",
            KeyframeCause::Stall => "stall",
            KeyframeCause::HwFallback => "hw_fallback",
            KeyframeCause::Other => "other",
        }
    }
}

/// Requests from the media threads to the feedback sender.
pub enum Feedback {
    /// Ask for an IDR on one tile, or on every tile.
    Keyframe(Option<usize>, KeyframeCause),
    /// Retransmission request: media SSRC and lost sequence numbers.
    Nack(u32, Vec<u16>),
    /// The base tile decoded cleanly up to this DONL.
    LtrAck(u16),
}

pub(super) enum DecoderMsg {
    Au { tile: usize, au: AccessUnit },
    /// Start over from the next IDR.
    Reset(ResetWhy),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResetWhy {
    /// A new SSRC group was adopted: a new stream.
    Adoption,
    /// No pictures for a long time on the same stream.
    Stall,
}

pub(super) struct FeedbackSockets {
    pub ctrl: UdpSocket,
    pub video: UdpSocket,
    pub ctrl_dest: SocketAddrV4,
    pub video_dest: SocketAddrV4,
}

const NACK_MAX_GAP: u16 = 32;
/// Cap on NACKed packets tracked for a retry.
const NACK_PENDING_MAX: usize = 512;
/// Weight of a new round-trip sample in the smoothed estimate.
const RTT_GAIN: f64 = 0.125;
/// Socket read timeout while nothing is pending, as set up in `bind_udp`.
const IDLE_POLL: Duration = Duration::from_millis(100);
const ADOPT_EVERY: Duration = Duration::from_millis(50);
/// No decoded frame for this long allows switching to another SSRC group.
const SWITCH_AFTER_STALL_MS: u64 = 2000;
/// A re-offer allows switching to a new SSRC group for this long.
const SWITCH_AFTER_REOFFER_MS: u64 = 5000;

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted)
}

fn is_rtcp(pkt: &[u8]) -> bool {
    pkt.len() >= 8 && (200..=207).contains(&(pkt[1] & 0x7f))
}

/// Keeps the host's sender reports (for our receiver reports) and folds any
/// report blocks echoing our own SRs into the round-trip estimate.
fn record_sender_reports(shared: &Shared, rtcp: &[u8]) {
    let now = Instant::now();
    {
        let mut srs = shared.sender_reports.lock();
        for (ssrc, mid32) in rtcp::sender_reports(rtcp) {
            srs.insert(ssrc, (mid32, now));
        }
    }
    let Some(ours) = shared.control.get().map(|c| c.video_ssrc) else {
        return;
    };
    let samples = rtcp::round_trips(rtcp, ours, rtcp::ntp_middle_now());
    if samples.is_empty() {
        return;
    }
    let mut rtt = shared.rtt.lock();
    if rtt.is_none() {
        tracing::debug!("round trip {:.1} ms", samples[0].as_secs_f64() * 1000.0);
    }
    for s in samples {
        *rtt = Some(rtt.map_or(s, |r| r.mul_f64(1.0 - RTT_GAIN) + s.mul_f64(RTT_GAIN)));
    }
}

/// Sends access units to the decoder, or stashes those of SSRCs not yet
/// adopted. False once the decoder is gone.
fn route(tiles: &mut TileMap, dec: &Sender<DecoderMsg>, aus: Vec<AccessUnit>) -> bool {
    for au in aus {
        match tiles.tile_of(au.ssrc) {
            Some(tile) => {
                if dec.send(DecoderMsg::Au { tile, au }).is_err() {
                    return false;
                }
            }
            None => tiles.stash(au),
        }
    }
    true
}

/// NACKs each still-missing packet once more `retry` after the first
/// request, and forgets packets once the assembler (holding for `wait`) will
/// have given up on them. Returns how many were retried.
fn retry_nacks(
    nacked: &mut HashMap<(u32, u16), (Instant, bool)>,
    retry: Duration,
    wait: Duration,
    now: Instant,
    fb: &Sender<Feedback>,
) -> u32 {
    let mut again: HashMap<u32, Vec<u16>> = HashMap::new();
    nacked.retain(|&(ssrc, seq), (at, retried)| {
        let age = now.duration_since(*at);
        if age >= wait {
            return false;
        }
        if !*retried && age >= retry {
            *retried = true;
            again.entry(ssrc).or_default().push(seq);
        }
        true
    });
    let mut n = 0;
    for (ssrc, lost) in again {
        tracing::trace!("NACK retry {ssrc:#010x}: {lost:?}");
        n += lost.len() as u32;
        let _ = fb.send(Feedback::Nack(ssrc, lost));
    }
    n
}

/// How long a NACKed packet is watched for, for the metrics and the hold
/// policy: well past any hold, so a host that retransmits late is told
/// apart from one that never does.
const NACK_WATCH: Duration = Duration::from_secs(1);
const NACK_WATCH_MAX: usize = 8192;

/// NACKed packets and when they were first NACKed, kept apart from the
/// hold's retry bookkeeping (which forgets them when the hold ends).
#[derive(Default)]
struct NackWatch {
    sent: HashMap<(u32, u16), Instant>,
}

impl NackWatch {
    fn nacked(&mut self, ssrc: u32, lost: &[u16], now: Instant) {
        for &seq in lost {
            if self.sent.len() >= NACK_WATCH_MAX {
                break;
            }
            self.sent.entry((ssrc, seq)).or_insert(now);
        }
    }

    /// How long ago a packet that just arrived was first NACKed, if it was.
    fn arrived(&mut self, ssrc: u32, seq: u16, now: Instant) -> Option<Duration> {
        self.sent.remove(&(ssrc, seq)).map(|t| now.saturating_duration_since(t))
    }

    fn expire(&mut self, now: Instant) {
        self.sent.retain(|_, t| now.saturating_duration_since(*t) < NACK_WATCH);
    }
}

/// Loss recovery in the video receiver, logged every STATS_EVERY at debug
/// level so the hold can be tuned against a real host.
struct LossStats {
    since: Instant,
    nacked: u32,
    retried: u32,
    holds: HoldStats,
}

impl LossStats {
    fn new() -> Self {
        Self { since: Instant::now(), nacked: 0, retried: 0, holds: HoldStats::default() }
    }

    fn add_holds(&mut self, h: HoldStats) {
        self.holds.started += h.started;
        self.holds.filled += h.filled;
        self.holds.given_up += h.given_up;
        self.holds.donl_backwards += h.donl_backwards;
    }

    fn log_if_due(&mut self, shared: &Shared, asm: &Assembler) {
        if self.since.elapsed() < STATS_EVERY {
            return;
        }
        let holds = self.holds;
        let damaged = shared.recovered_damaged.swap(0, Ordering::Relaxed);
        if self.nacked > 0 || holds.started > 0 || holds.donl_backwards > 0 {
            let rtt = match *shared.rtt.lock() {
                Some(r) => format!("{:.1} ms", r.as_secs_f64() * 1000.0),
                None => "unknown".into(),
            };
            tracing::debug!(
                "loss: {} NACKed, {} retried; holds {} started, {} filled ({damaged} pictures damaged after), \
                 {} given up; DONL backwards {}; rtt {rtt}, hold {} ms{}",
                self.nacked,
                self.retried,
                holds.started,
                holds.filled,
                holds.given_up,
                holds.donl_backwards,
                asm.wait().as_millis(),
                if asm.hold_policy().holding() { "" } else { " (not holding)" },
            );
        }
        *self = Self::new();
    }
}

/// Receives SRTP video, assembles access units and routes them to tiles.
pub(super) fn video_rx(
    shared: Arc<Shared>,
    sock: UdpSocket,
    key: [u8; SRTP_BLOB_LEN],
    dec: Sender<DecoderMsg>,
    fb: Sender<Feedback>,
) {
    let mut srtp = SrtpReceiver::new(&key);
    let srtcp = SrtcpReceiver::new(&key);
    let mut asm = Assembler::default();
    let mut tiles = TileMap::default();
    let mut next_seq: HashMap<u32, u16> = HashMap::new();
    // NACKed packets not yet seen: when first requested, and whether retried.
    let mut nacked: HashMap<(u32, u16), (Instant, bool)> = HashMap::new();
    let mut watch = NackWatch::default();
    // Latest RTP timestamp per tile SSRC, to count the pictures sent.
    let mut last_ts: HashMap<u32, u32> = HashMap::new();
    let mut buf = vec![0u8; 65536];
    let mut last_evict = Instant::now();
    let mut polling = false;
    let mut loss = LossStats::new();
    let mut last_adopt = Instant::now();
    let mut bad = 0u64;
    let mut seen = std::collections::HashSet::new();
    asm.set_hold_mode(shared.op().hold);
    shared.metrics.holding.store(asm.hold_policy().holding(), Ordering::Relaxed);

    while !shared.stopped() {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = &buf[..n];
                if is_rtcp(pkt) {
                    if let Some(data) = srtcp.unprotect(pkt) {
                        record_sender_reports(&shared, &data);
                    }
                } else if let Some(p) = srtp.unprotect(pkt) {
                    let now = Instant::now();
                    shared.touch(&shared.last_video_packet);
                    shared.metrics.video_packets.fetch_add(1, Ordering::Relaxed);
                    shared.metrics.video_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    if seen.insert(p.ssrc) {
                        tracing::debug!("new video SSRC {:#010x} (pt {})", p.ssrc, p.pt);
                    }
                    tiles.count_packet(p.ssrc);
                    if let Some(tile) = tiles.tile_of(p.ssrc) {
                        shared.metrics.tile_packet(tile, shared.clock.now_ms());
                        // A newer RTP timestamp is a new picture from the host.
                        let newer = last_ts.get(&p.ssrc).is_none_or(|&t| (1..0x8000_0000).contains(&p.ts.wrapping_sub(t)));
                        if newer {
                            last_ts.insert(p.ssrc, p.ts);
                            shared.metrics.tile_frame(tile);
                        }
                        nacked.remove(&(p.ssrc, p.seq));
                        if let Some(after) = watch.arrived(p.ssrc, p.seq, now) {
                            // A retransmission, or a late original: either
                            // way the packet NACKed did turn up.
                            shared.metrics.nack_arrived(after);
                            // Only an arrival a hold could have waited for
                            // argues for holding.
                            if after <= asm.wait() {
                                asm.nacked_arrived();
                            }
                        }
                        // Gap detection for NACKs; the assembler deals with order.
                        let expected = *next_seq.entry(p.ssrc).or_insert(p.seq);
                        let gap = p.seq.wrapping_sub(expected);
                        if gap < 0x8000 {
                            // Holes as first seen, before any repair.
                            shared.metrics.tile_holes(tile, gap as u64);
                            if gap > 0 && gap < NACK_MAX_GAP {
                                let lost: Vec<u16> = (0..gap).map(|i| expected.wrapping_add(i)).collect();
                                loss.nacked += lost.len() as u32;
                                shared.metrics.nacked.fetch_add(lost.len() as u64, Ordering::Relaxed);
                                if nacked.len() < NACK_PENDING_MAX {
                                    nacked.extend(lost.iter().map(|&s| ((p.ssrc, s), (now, false))));
                                }
                                watch.nacked(p.ssrc, &lost, now);
                                let _ = fb.send(Feedback::Nack(p.ssrc, lost));
                            }
                            next_seq.insert(p.ssrc, p.seq.wrapping_add(1));
                        }
                        let (index, at) = (srtp.last_index(), shared.clock.0.elapsed());
                        match shared.rx_stats.lock().entry(p.ssrc) {
                            Entry::Occupied(mut e) => e.get_mut().record(index, p.ts, at),
                            Entry::Vacant(e) => {
                                e.insert(ReceiverStats::new(index, p.ts, at));
                            }
                        }
                    }
                    let aus = asm.push(p, now);
                    if !route(&mut tiles, &dec, aus) {
                        return;
                    }
                } else if n > 1 {
                    bad += 1;
                    if bad.is_power_of_two() {
                        tracing::debug!("{bad} undecryptable video packets");
                    }
                }
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                tracing::debug!("video socket: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        let now = Instant::now();
        if now.duration_since(last_evict) >= POLL_EVERY {
            last_evict = now;
            if let Some(rtt) = *shared.rtt.lock() {
                asm.set_rtt(rtt);
            }
            asm.set_hold_mode(shared.op().hold);
            // Given-up access units come out incomplete; the decoder asks
            // for the keyframe.
            if !route(&mut tiles, &dec, asm.evict(now)) {
                return;
            }
            let retried = retry_nacks(&mut nacked, asm.retry_after(), asm.wait(), now, &fb);
            watch.expire(now);
            loss.retried += retried;
            shared.metrics.nack_retries.fetch_add(retried as u64, Ordering::Relaxed);
            let holds = asm.take_stats();
            loss.add_holds(holds);
            shared.metrics.add_holds(holds);
            shared.metrics.holding.store(asm.hold_policy().holding(), Ordering::Relaxed);
            loss.log_if_due(&shared, &asm);
            // Wake often enough to retry and give up on time even if the
            // stream goes quiet, but not while idle.
            let busy = asm.pending() || !nacked.is_empty();
            if busy != polling {
                polling = busy;
                let _ = sock.set_read_timeout(Some(if busy { POLL_EVERY } else { IDLE_POLL }));
            }
        }
        if now.duration_since(last_adopt) >= ADOPT_EVERY {
            last_adopt = now;
            let want = shared.tiles.load(Ordering::Relaxed) as usize;
            let reneg = shared.renegotiated.load(Ordering::Relaxed);
            let allow_switch = tiles.ssrcs().len() != want
                || shared.since_ms(&shared.last_frame) > SWITCH_AFTER_STALL_MS
                || (reneg != 0 && shared.since_ms(&shared.renegotiated) < SWITCH_AFTER_REOFFER_MS);
            if let Some(backlog) = tiles.try_adopt(want, allow_switch) {
                let ssrcs = tiles.ssrcs().to_vec();
                asm.link(&ssrcs);
                srtp.forget(|s| ssrcs.contains(&s));
                next_seq.clear();
                nacked.clear();
                watch = NackWatch::default();
                last_ts.clear();
                *shared.tile_ssrcs.lock() = ssrcs;
                shared.rx_stats.lock().clear();
                shared.renegotiated.store(0, Ordering::Relaxed);
                // Don't let the stall timer immediately allow another switch.
                shared.touch(&shared.last_frame);
                let _ = dec.send(DecoderMsg::Reset(ResetWhy::Adoption));
                for (tile, au) in backlog {
                    let _ = dec.send(DecoderMsg::Au { tile, au });
                }
                let _ = fb.send(Feedback::Keyframe(None, KeyframeCause::Adoption));
            }
        }
    }
}

/// Drains the control/audio UDP port, which carries the host's audio RTP
/// and RTCP muxed together. Audio goes to the player; RTCP is kept for
/// round-trip estimates (ours and the host's via our receiver reports).
pub(super) fn ctrl_rx(
    shared: Arc<Shared>,
    sock: UdpSocket,
    key: [u8; SRTP_BLOB_LEN],
    audio: Option<(Player, [u8; SRTP_BLOB_LEN])>,
) {
    let srtcp = SrtcpReceiver::new(&key);
    let mut audio = audio.and_then(|(player, key)| match AudioRx::new(player, &key) {
        Ok(rx) => Some(rx),
        Err(e) => {
            tracing::warn!("no sound: {e:#}");
            None
        }
    });
    let mut buf = vec![0u8; 65536];
    while !shared.stopped() {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = &buf[..n];
                if is_rtcp(pkt) {
                    if let Some(data) = srtcp.unprotect(pkt) {
                        record_sender_reports(&shared, &data);
                    }
                } else if let Some(a) = audio.as_mut() {
                    a.packet(pkt);
                }
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                tracing::debug!("ctrl socket: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    if let Some(a) = audio {
        a.player.flush();
    }
}

/// Lost audio packets up to this many in a row are concealed by the
/// decoder; longer gaps just go quiet.
const MAX_CONCEAL: u16 = 3;

/// Decrypts and decodes the host's audio stream.
struct AudioRx {
    srtp: SrtpReceiver,
    decoder: crate::audio::aac::Decoder,
    player: Player,
    last_seq: Option<u16>,
    failures: u64,
}

impl AudioRx {
    fn new(player: Player, key: &[u8; SRTP_BLOB_LEN]) -> anyhow::Result<Self> {
        let decoder = crate::audio::aac::Decoder::new()?;
        Ok(Self { srtp: SrtpReceiver::new(key), decoder, player, last_seq: None, failures: 0 })
    }

    fn packet(&mut self, pkt: &[u8]) {
        let Some(rtp) = self.srtp.unprotect(pkt) else { return };
        if rtp.pt != AUDIO_PT {
            return;
        }
        if let Some(last) = self.last_seq {
            let gap = rtp.seq.wrapping_sub(last);
            if gap == 0 || gap > 0x8000 {
                // Duplicate or late: already played past it.
                return;
            }
            for _ in 1..gap.min(MAX_CONCEAL + 1) {
                if let Ok(pcm) = self.decoder.conceal() {
                    self.player.push(pcm);
                }
            }
        }
        self.last_seq = Some(rtp.seq);
        match self.decoder.decode(&rtp.payload) {
            Ok(pcm) => self.player.push(pcm),
            Err(e) => {
                self.failures += 1;
                if self.failures == 1 {
                    tracing::warn!("audio decode failed: {e:#}");
                } else {
                    tracing::trace!("audio decode failed: {e:#}");
                }
            }
        }
    }
}

/// Parameter sets seen in the stream, prepended to every IRAP so the
/// decoder can (re)start from any keyframe.
#[derive(Default)]
struct ParamSets {
    vps: Option<Vec<u8>>,
    sps: Option<Vec<u8>>,
    pps: BTreeMap<u32, Vec<u8>>,
}

impl ParamSets {
    fn absorb(&mut self, nal: &[u8]) {
        match hevc::nal_type(nal) {
            hevc::NAL_VPS => self.vps = Some(nal.to_vec()),
            hevc::NAL_SPS => self.sps = Some(nal.to_vec()),
            hevc::NAL_PPS => {
                if let Some((tiles, wpp)) = hevc::pps_parallelism(nal) {
                    tracing::debug!("PPS: tiles={tiles} wavefront={wpp}");
                }
                if let Some(id) = hevc::pps_id(nal) {
                    self.pps.insert(id, nal.to_vec());
                }
            }
            _ => {}
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        for nal in self.vps.iter().chain(self.sps.iter()).chain(self.pps.values()) {
            push_annexb(out, nal);
        }
    }
}

fn push_annexb(out: &mut Vec<u8>, nal: &[u8]) {
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.extend_from_slice(nal);
}

/// A hardware decoder sometimes accepts packets but never returns pictures
/// (e.g. 4:4:4 on GPUs without support); give up on it after this many
/// access units.
const HW_GRACE_AUS: u32 = 120;
/// The host sends a frame's changed tiles back to back. Decoded pictures are
/// held until input has been idle this long, so siblings still on the wire
/// or in the decoder land in the same presented frame.
const TILE_GATHER: Duration = Duration::from_millis(4);
/// Never hold a picture longer than this, even under a steady stream.
const TILE_GATHER_MAX: Duration = Duration::from_millis(25);

struct DecodeLoop {
    shared: Arc<Shared>,
    opts: DecoderOptions,
    fb: Sender<Feedback>,
    decoder: Decoder,
    params: ParamSets,
    /// SPS the decoder was last started with.
    active_sps: Option<Vec<u8>>,
    /// Decoder-wide, not per tile: the tiles are one coded sequence in one
    /// DPB, fed in cross-SSRC decode order, and a P picture on one tile
    /// references pictures of the others. IDRs come only on the base tile
    /// and reset the DPB for all of them, so per-tile flags for the other
    /// tiles would never clear.
    awaiting_idr: bool,
    pts: i64,
    /// Tile, DONL, whether a hold recovered it, the IRAP epoch and whether
    /// it was fed after a loss (concealed), per decoder input.
    origin: HashMap<i64, (usize, Option<u16>, bool, u64, bool)>,
    /// `--after-loss conceal` only: a loss since the last IRAP, so what is
    /// decoded now is concealed. Never set with `idr`, which gates instead.
    lossy: bool,
    /// IRAPs fed to the decoder so far: a picture from a later epoch than a
    /// loss comes after the keyframe that repaired it.
    epoch: u64,
    /// Tiles whose first access unit after the latest IRAP is still to come
    /// (a bit per tile); its size is part of what the keyframe cost.
    irap_follow: u32,
    fed_without_output: Option<u32>,
    /// No backend could be reopened; the session has been closed.
    dead: bool,
    /// Decoded pictures of the frame being gathered, and when it started.
    batch: Vec<(usize, Picture)>,
    /// Gather tiles into frames; otherwise each picture is shown at once.
    sync_tiles: bool,
    batch_started: Option<Instant>,
    last_input: Instant,
    gather: GatherStats,
    stats: DecodeStats,
    /// MACSHARE_DUMP_HEVC: every access unit fed to the decoder, as Annex B,
    /// for offline analysis (ffmpeg -bsf:v trace_headers) and benchmarks.
    dump: Option<std::io::BufWriter<std::fs::File>>,
}

fn open_dump() -> Option<std::io::BufWriter<std::fs::File>> {
    let path = std::env::var_os("MACSHARE_DUMP_HEVC")?;
    match std::fs::File::create(&path) {
        Ok(f) => {
            tracing::info!("writing decoder input to {}", path.to_string_lossy());
            Some(std::io::BufWriter::new(f))
        }
        Err(e) => {
            tracing::warn!("MACSHARE_DUMP_HEVC: {e}");
            None
        }
    }
}

const STATS_EVERY: Duration = Duration::from_secs(5);

/// Decoder throughput, logged at debug level so slow decoding is visible.
/// Why a gathered frame was presented.
#[derive(Debug, Clone, Copy)]
enum Flush {
    /// Every tile arrived.
    Complete,
    /// A tile came again before the others: the frame was partial.
    Repeat,
    /// Input went quiet: the rest of the tiles didn't change.
    Idle,
    /// Held as long as allowed under a steady stream.
    MaxHold,
}

/// How tile pictures were grouped into presented frames, logged every
/// STATS_EVERY at debug level.
struct GatherStats {
    since: Instant,
    frames: u32,
    tiles: u32,
    by_reason: [u32; 4],
    held: Duration,
    worst: Duration,
}

impl GatherStats {
    fn new() -> Self {
        Self { since: Instant::now(), frames: 0, tiles: 0, by_reason: [0; 4], held: Duration::ZERO, worst: Duration::ZERO }
    }

    fn record(&mut self, why: Flush, tiles: usize, held: Duration) {
        self.frames += 1;
        self.tiles += tiles as u32;
        self.by_reason[why as usize] += 1;
        self.held += held;
        self.worst = self.worst.max(held);
        let elapsed = self.since.elapsed();
        if elapsed >= STATS_EVERY {
            let [complete, repeat, idle, max] = self.by_reason;
            tracing::debug!(
                "present: {:.1} frames/s, {:.2} tiles/frame, held avg {:.1} ms worst {:.1} ms; \
                 complete {complete}, idle {idle}, repeat {repeat}, max-hold {max}",
                self.frames as f64 / elapsed.as_secs_f64(),
                self.tiles as f64 / self.frames as f64,
                self.held.as_secs_f64() * 1000.0 / self.frames as f64,
                self.worst.as_secs_f64() * 1000.0,
            );
            *self = Self::new();
        }
    }
}

struct DecodeStats {
    since: Instant,
    aus: u32,
    slices: u32,
    pictures: u32,
    busy: Duration,
    worst: Duration,
}

impl DecodeStats {
    fn new() -> Self {
        Self { since: Instant::now(), aus: 0, slices: 0, pictures: 0, busy: Duration::ZERO, worst: Duration::ZERO }
    }

    fn record(&mut self, slices: usize, pictures: usize, took: Duration) {
        self.aus += 1;
        self.slices += slices as u32;
        self.pictures += pictures as u32;
        self.busy += took;
        self.worst = self.worst.max(took);
        let elapsed = self.since.elapsed();
        if elapsed >= STATS_EVERY {
            let secs = elapsed.as_secs_f64();
            tracing::debug!(
                "decode: {:.1} AU/s, {:.1} slices/AU, {:.1} pictures/s, avg {:.1} ms, worst {:.1} ms, busy {:.0}%",
                self.aus as f64 / secs,
                self.slices as f64 / self.aus as f64,
                self.pictures as f64 / secs,
                self.busy.as_secs_f64() * 1000.0 / self.aus as f64,
                self.worst.as_secs_f64() * 1000.0,
                self.busy.as_secs_f64() / secs * 100.0,
            );
            *self = Self::new();
        }
    }
}

impl DecodeLoop {
    /// Reopens the decoder on the current backend, or on the ones after it
    /// when `next` is set (the current one can't handle the stream).
    fn restart(&mut self, next: bool) {
        let all = self.opts.candidates();
        let cur = all.iter().position(|&b| b == self.decoder.backend()).unwrap_or(0);
        let from = (cur + next as usize).min(all.len() - 1);
        match Decoder::open_first(&all[from..], &self.opts) {
            Ok(d) => {
                if d.backend() != self.decoder.backend() {
                    tracing::info!("video decoder: {:?}", d.backend());
                }
                self.shared.metrics.set_decoder(d.backend().name());
                self.decoder = d;
            }
            Err(e) => {
                // Even software decoding failed; retrying every AU won't help.
                self.shared.sink.emit(Event::Closed(Some(format!("video decoder: {e:#}"))));
                self.dead = true;
            }
        }
        self.awaiting_idr = true;
        self.origin.clear();
        self.fed_without_output = self.decoder.backend().is_hw().then_some(0);
    }

    fn access_unit(&mut self, tile: usize, au: AccessUnit) {
        for nal in au.nalus.iter().filter(|n| hevc::is_param_set(n)) {
            self.params.absorb(nal);
        }
        let conceal = self.shared.op().after_loss == AfterLoss::Conceal;
        if !conceal && self.lossy {
            // Switched to idr during a loss: drop until the keyframe.
            self.lossy = false;
            self.awaiting_idr = true;
        }
        if !au.complete {
            self.loss_keyframe(tile, self.epoch, KeyframeCause::Gap);
            if !conceal {
                self.awaiting_idr = true;
                return;
            }
            // Concealing: decode the slices that did arrive.
            self.lossy = true;
        }
        if !au.nalus.iter().any(|n| hevc::is_slice(n)) {
            return;
        }
        // Part of a keyframe is not one: it doesn't restart the decoder.
        let irap = au.complete && au.nalus.iter().any(|n| hevc::is_irap(n));
        let bytes: u64 = au.nalus.iter().map(|n| n.len() as u64).sum();
        let m = &self.shared.metrics;
        if irap {
            m.irap_aus.fetch_add(1, Ordering::Relaxed);
            m.irap_bytes.fetch_add(bytes, Ordering::Relaxed);
        } else if au.complete && tile < 32 && self.irap_follow & (1 << tile) != 0 {
            self.irap_follow &= !(1 << tile);
            m.irap_follow_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        if self.awaiting_idr && !irap {
            return;
        }
        let mut annexb = Vec::with_capacity(au.nalus.iter().map(|n| n.len() + 4).sum::<usize>() + 256);
        if irap {
            if self.params.sps.is_none() || self.params.pps.is_empty() {
                // A keyframe without parameter sets cannot start the decoder.
                let _ = self.fb.send(Feedback::Keyframe(Some(tile), KeyframeCause::Other));
                return;
            }
            if self.active_sps.is_some() && self.active_sps != self.params.sps {
                tracing::info!("stream parameters changed; restarting decoder");
                self.restart(false);
            }
            self.active_sps = self.params.sps.clone();
            self.awaiting_idr = false;
            self.lossy = false;
            self.epoch += 1;
            self.irap_follow = follow_mask(self.shared.tiles.load(Ordering::Relaxed) as usize, tile);
            self.params.write(&mut annexb);
        }
        for nal in au.nalus.iter().filter(|n| !(irap && hevc::is_param_set(n))) {
            push_annexb(&mut annexb, nal);
        }

        self.pts += 1;
        self.origin.insert(self.pts, (tile, au.donl, au.recovered, self.epoch, self.lossy));
        let mut pictures = Vec::new();
        if let Some(d) = self.dump.as_mut() {
            let _ = std::io::Write::write_all(d, &annexb);
        }
        let started = Instant::now();
        // Concealed pictures may still be in the decoder after the
        // keyframe that ended the loss was fed.
        let concealed_in_flight = self.origin.values().any(|o| o.4);
        self.decoder.set_lenient(self.lossy || concealed_in_flight);
        let ok = self.decoder.decode(&annexb, self.pts, &mut |p| pictures.push(p));
        let slices = au.nalus.iter().filter(|n| hevc::is_slice(n)).count();
        let took = started.elapsed();
        self.stats.record(slices, pictures.len(), took);
        self.shared.metrics.decoded(took);
        if !ok {
            if conceal {
                self.lossy = true;
            } else {
                self.awaiting_idr = true;
            }
            // A concealed incomplete access unit failing is the same loss,
            // already asked for.
            if au.complete {
                self.loss_keyframe(tile, self.epoch, KeyframeCause::DecodeError);
            }
        }
        let floor = self.pts - 256;
        self.origin.retain(|&p, _| p > floor);

        if let Some(n) = self.fed_without_output.as_mut() {
            if pictures.is_empty() {
                *n += 1;
            } else {
                self.fed_without_output = None;
            }
        }
        let silent = self.fed_without_output.is_some_and(|n| n >= HW_GRACE_AUS);
        if silent || self.decoder.broken() {
            let why = if silent { "produced no pictures" } else { "can't show this stream" };
            tracing::warn!("{:?} decoder {why}; falling back", self.decoder.backend());
            decoder::remember_broken(self.decoder.backend());
            // The old backend's pictures may have another layout than the
            // next one's; mixed in one frame they'd make the renderer
            // rebuild its textures mid-upload. Drop them all.
            self.batch.clear();
            self.batch_started = None;
            self.restart(true);
            let _ = self.fb.send(Feedback::Keyframe(None, KeyframeCause::HwFallback));
            return;
        }
        for p in pictures {
            self.publish(p);
        }
    }

    fn publish(&mut self, pic: Picture) {
        let Some((tile, donl, recovered, epoch, concealed)) = self.origin.remove(&pic.pts) else {
            return;
        };
        self.shared.metrics.picture(tile, epoch, self.shared.clock.now_ms(), Instant::now());
        self.shared.metrics.shown(concealed);
        if pic.damaged {
            if recovered {
                self.shared.recovered_damaged.fetch_add(1, Ordering::Relaxed);
            }
            if self.shared.op().after_loss == AfterLoss::Conceal && epoch == self.epoch {
                // Pictures referencing this one are smeared too (unless a
                // keyframe was fed since).
                self.lossy = true;
            }
            // Repaired by the next IRAP after this picture's, not by the
            // next clean P picture (it may still reference the damage).
            self.loss_keyframe(tile, epoch, KeyframeCause::Damaged);
        } else if let (0, Some(d)) = (tile, donl) {
            let _ = self.fb.send(Feedback::LtrAck(d));
        }
        self.shared.touch(&self.shared.last_frame);
        // A second picture for the same tile means a new frame has begun.
        if self.batch.iter().any(|(t, _)| *t == tile) {
            self.flush(Flush::Repeat);
        }
        self.batch_started.get_or_insert_with(Instant::now);
        self.batch.push((tile, pic));
        if !self.sync_tiles || self.batch.len() >= self.shared.tiles.load(Ordering::Relaxed) as usize {
            self.flush(Flush::Complete);
        }
    }

    /// Asks for a keyframe after a loss seen in IRAP epoch `epoch`; the
    /// first such request opens an outage for the recovery metrics, which
    /// the first picture of a later epoch closes.
    fn loss_keyframe(&mut self, tile: usize, epoch: u64, cause: KeyframeCause) {
        // A loss from before the latest IRAP was already repaired by it.
        if epoch >= self.epoch {
            self.shared.metrics.outage(epoch, Instant::now());
        }
        let _ = self.fb.send(Feedback::Keyframe(Some(tile), cause));
    }

    fn flush(&mut self, why: Flush) {
        let Some(started) = self.batch_started.take() else { return };
        if self.batch.is_empty() {
            return;
        }
        let held = started.elapsed();
        let tiles: Vec<usize> = self.batch.iter().map(|(t, _)| *t).collect();
        tracing::trace!("present tiles {tiles:?} ({why:?}, held {:.1} ms)", held.as_secs_f64() * 1000.0);
        self.gather.record(why, tiles.len(), held);
        self.shared.metrics.presented.fetch_add(1, Ordering::Relaxed);
        if self.shared.frames.put_frame(self.batch.drain(..)) {
            self.shared.sink.emit(Event::Frame);
        }
    }

    /// How long to wait for input before flushing a partial frame.
    fn wait(&self) -> Duration {
        match self.batch_started {
            Some(t) => TILE_GATHER
                .saturating_sub(self.last_input.elapsed())
                .min(TILE_GATHER_MAX.saturating_sub(t.elapsed())),
            None => Duration::from_millis(200),
        }
    }
}

/// The tiles other than `irap_tile` out of `tiles`, as a bit mask.
fn follow_mask(tiles: usize, irap_tile: usize) -> u32 {
    let all = if tiles >= 32 { u32::MAX } else { (1u32 << tiles) - 1 };
    all & !1u32.checked_shl(irap_tile as u32).unwrap_or(0)
}

pub(super) fn decoder(shared: Arc<Shared>, rx: Receiver<DecoderMsg>, fb: Sender<Feedback>, opts: DecoderOptions, sync_tiles: bool) {
    let decoder = match Decoder::new(&opts) {
        Ok(d) => d,
        Err(e) => {
            shared.sink.emit(Event::Closed(Some(format!("video decoder: {e:#}"))));
            return;
        }
    };
    tracing::info!("video decoder: {:?}", decoder.backend());
    shared.metrics.set_decoder(decoder.backend().name());
    let hw = decoder.backend().is_hw();
    let mut st = DecodeLoop {
        shared: shared.clone(),
        opts,
        fb,
        decoder,
        params: ParamSets::default(),
        active_sps: None,
        awaiting_idr: true,
        pts: 0,
        origin: HashMap::new(),
        epoch: 0,
        irap_follow: 0,
        lossy: false,
        fed_without_output: hw.then_some(0),
        batch: Vec::new(),
        sync_tiles,
        batch_started: None,
        last_input: Instant::now(),
        gather: GatherStats::new(),
        stats: DecodeStats::new(),
        dump: open_dump(),
        dead: false,
    };
    while !shared.stopped() && !st.dead {
        match rx.recv_timeout(st.wait()) {
            Ok(DecoderMsg::Au { tile, au }) => {
                st.access_unit(tile, au);
                st.last_input = Instant::now();
                if st.batch_started.is_some_and(|t| t.elapsed() >= TILE_GATHER_MAX) {
                    st.flush(Flush::MaxHold);
                }
            }
            Ok(DecoderMsg::Reset(why)) => {
                if why == ResetWhy::Adoption {
                    // A new stream: an open outage belongs to the old one,
                    // and its recovery would be the adoption's.
                    shared.metrics.end_outage();
                    // New SSRC group: new parameter sets will follow.
                    st.params = ParamSets::default();
                    st.active_sps = None;
                }
                // A stall reset keeps the outage open: the epoch carries on,
                // so the next IRAP still ends it. It keeps the parameter
                // sets too, as the host may send that IDR on the same SSRCs
                // without repeating them; wiping them would refuse every
                // keyframe from then on.
                shared.metrics.shown(false);
                st.irap_follow = 0;
                st.lossy = false;
                st.batch.clear();
                st.batch_started = None;
                st.restart(false);
            }
            Err(RecvTimeoutError::Timeout) => st.flush(Flush::Idle),
            Err(RecvTimeoutError::Disconnected) => return,
        }
        shared.metrics.awaiting_idr.store(st.awaiting_idr, Ordering::Relaxed);
    }
}

const TICK: Duration = Duration::from_millis(500);
const SR_EVERY_TICKS: u64 = 10;
const KEYFRAME_MIN_INTERVAL: Duration = Duration::from_millis(500);
const HEARTBEAT_PAYLOAD: [u8; 4] = [0x00, 0x68, 0x34, 0x00];
const AUDIO_PT: u8 = 101;
/// The encoder goes quiet on a static screen; keyframe requests are
/// pointless (and ignored) then.
const IDLE_AFTER_MS: u64 = 1500;
const STALL_KEYFRAME_MS: u64 = 3000;
const STALL_KEYFRAME_EVERY: Duration = Duration::from_millis(1500);
const STALL_RESET_MS: u64 = 8000;

/// Per-tile packet loss and jitter, logged every STATS_EVERY at debug level
/// so `-v` shows link quality.
struct LinkStats {
    since: Instant,
    /// Expected and received counts per SSRC at the start of the period.
    start: HashMap<u32, (u64, u64)>,
}

impl LinkStats {
    fn new() -> Self {
        Self { since: Instant::now(), start: HashMap::new() }
    }

    /// Takes `(ssrc, expected, received, jitter)` for the tiles with packets.
    fn record(&mut self, tiles: &[u32], now: &[(u32, u64, u64, u32)]) {
        if self.since.elapsed() < STATS_EVERY {
            return;
        }
        let mut parts = Vec::new();
        for (t, ssrc) in tiles.iter().enumerate() {
            let Some(&(_, exp, rcv, jitter)) = now.iter().find(|n| n.0 == *ssrc) else { continue };
            // Stats restart with the SSRC group; count from zero then.
            let (exp0, rcv0) = self.start.get(ssrc).copied().filter(|&(e, _)| e <= exp).unwrap_or((0, 0));
            let (exp, rcv) = (exp - exp0, rcv.saturating_sub(rcv0));
            let loss = if exp == 0 { 0.0 } else { exp.saturating_sub(rcv) as f64 * 100.0 / exp as f64 };
            let jitter_ms = jitter as f64 * 1000.0 / VIDEO_CLOCK_HZ as f64;
            parts.push(format!("{t}: {loss:.1}% {jitter_ms:.1} ms"));
        }
        if !parts.is_empty() {
            tracing::debug!("link: loss/jitter per tile {}", parts.join(", "));
        }
        self.since = Instant::now();
        self.start = now.iter().map(|&(ssrc, e, r, _)| (ssrc, (e, r))).collect();
    }
}

struct FeedbackSender {
    shared: Arc<Shared>,
    s: FeedbackSockets,
    srtcp: SrtcpSender,
    audio: SrtpSender,
    our_ssrc: u32,
    fir_seq: u8,
    last_keyframe: HashMap<usize, Instant>,
    last_ltr: Option<u16>,
    last_stall_keyframe: Option<Instant>,
    stall_reset_done: bool,
    link: LinkStats,
}

impl FeedbackSender {
    fn ctrl(&mut self, rtcp: &[u8]) {
        let pkt = self.srtcp.protect(rtcp);
        if let Err(e) = self.s.ctrl.send_to(&pkt, self.s.ctrl_dest) {
            tracing::debug!("RTCP send: {e}");
        }
    }

    fn keyframe(&mut self, tile: Option<usize>, cause: KeyframeCause) {
        let ssrcs = self.shared.tile_ssrcs.lock().clone();
        let targets: Vec<usize> = match tile {
            Some(t) => vec![t],
            None => (0..ssrcs.len()).collect(),
        };
        let shared = self.shared.clone();
        let metrics = &shared.metrics;
        if self.shared.since_ms(&self.shared.last_video_packet) > IDLE_AFTER_MS {
            let n = targets.iter().filter(|&&t| t < ssrcs.len()).count();
            metrics.keyframes_suppressed.fetch_add(n as u64, Ordering::Relaxed);
            return;
        }
        let kind = self.shared.op().recovery;
        let now = Instant::now();
        for t in targets {
            let Some(&target) = ssrcs.get(t) else { continue };
            if self.last_keyframe.get(&t).is_some_and(|l| now.duration_since(*l) < KEYFRAME_MIN_INTERVAL) {
                metrics.keyframes_suppressed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.last_keyframe.insert(t, now);
            self.fir_seq = self.fir_seq.wrapping_add(1);
            tracing::debug!("keyframe request ({}, {}) for tile {t}", kind.name(), cause.name());
            let pkt = rtcp::recovery_request(kind, self.our_ssrc, target, self.fir_seq);
            self.ctrl(&pkt);
            metrics.keyframe_sent(kind, cause);
        }
    }

    fn handle(&mut self, msg: Feedback) {
        match msg {
            Feedback::Keyframe(t, cause) => self.keyframe(t, cause),
            Feedback::Nack(ssrc, lost) => {
                if let Some(pkt) = rtcp::nack(self.our_ssrc, ssrc, &lost) {
                    self.ctrl(&pkt);
                }
            }
            Feedback::LtrAck(donl) => {
                if self.shared.op().ltr && self.last_ltr != Some(donl) {
                    self.last_ltr = Some(donl);
                    // LTR acks go to the video port, not the control port.
                    let pkt = self.srtcp.protect(&rtcp::ltr_ack(self.our_ssrc, donl));
                    let _ = self.s.video.send_to(&pkt, self.s.video_dest);
                }
            }
        }
    }

    fn tick(&mut self, n: u64, dec: &Sender<DecoderMsg>) {
        let hb = self.audio.protect(AUDIO_PT, &HEARTBEAT_PAYLOAD);
        let _ = self.s.ctrl.send_to(&hb, self.s.ctrl_dest);

        let ssrcs = self.shared.tile_ssrcs.lock().clone();
        let mut link = Vec::with_capacity(ssrcs.len());
        let sources: Vec<rtcp::ReportSource> = {
            let mut stats = self.shared.rx_stats.lock();
            let srs = self.shared.sender_reports.lock();
            ssrcs
                .iter()
                .map(|&ssrc| {
                    let r = stats.get_mut(&ssrc).map(|s| {
                        link.push((ssrc, s.expected(), s.received(), s.jitter()));
                        s.report()
                    });
                    let r = r.unwrap_or_default();
                    rtcp::ReportSource {
                        ssrc,
                        fraction_lost: r.fraction_lost,
                        cumulative_lost: r.cumulative_lost,
                        extended_seq: r.extended_seq,
                        jitter: r.jitter,
                        last_sr: srs.get(&ssrc).map(|&(mid, at)| (mid, at.elapsed().as_secs_f64())),
                    }
                })
                .collect()
        };
        self.link.record(&ssrcs, &link);
        let mut report = Vec::new();
        if n.is_multiple_of(SR_EVERY_TICKS) {
            report.extend(rtcp::empty_sender_report(self.our_ssrc));
        }
        report.extend(rtcp::receiver_report(self.our_ssrc, &sources));
        self.ctrl(&report);

        self.check_stall(dec);

        // Cursor shapes only arrive in answer to update requests.
        if let Some(c) = self.shared.control.get() {
            c.send(&crate::proto::messages::fbu_request(true, 0, 0, 1, 1));
        }
    }

    /// Packets arriving but no pictures coming out means the decoder is
    /// stuck waiting for a keyframe that was lost, or wedged.
    fn check_stall(&mut self, dec: &Sender<DecoderMsg>) {
        let flowing = self.shared.since_ms(&self.shared.last_video_packet) < IDLE_AFTER_MS;
        let stalled = self.shared.since_ms(&self.shared.last_frame);
        if !flowing || stalled < STALL_KEYFRAME_MS || self.shared.tile_ssrcs.lock().is_empty() {
            self.stall_reset_done = false;
            return;
        }
        if self.last_stall_keyframe.is_none_or(|t| t.elapsed() >= STALL_KEYFRAME_EVERY) {
            tracing::debug!("no picture for {stalled} ms; requesting keyframes");
            self.last_stall_keyframe = Some(Instant::now());
            self.keyframe(None, KeyframeCause::Stall);
        }
        if stalled > STALL_RESET_MS && !self.stall_reset_done {
            tracing::warn!("video stalled for {} s; resetting decoder", stalled / 1000);
            self.stall_reset_done = true;
            let _ = dec.send(DecoderMsg::Reset(ResetWhy::Stall));
        }
    }
}

pub(super) fn feedback(
    shared: Arc<Shared>,
    sockets: FeedbackSockets,
    offer: MediaOffer,
    rx: Receiver<Feedback>,
    dec: Sender<DecoderMsg>,
) {
    let mut fs = FeedbackSender {
        shared: shared.clone(),
        s: sockets,
        srtcp: SrtcpSender::new(&offer.video_key_v),
        audio: SrtpSender::new(&offer.audio_key_v, offer.audio_ssrc),
        our_ssrc: offer.video_ssrc,
        fir_seq: 0,
        last_keyframe: HashMap::new(),
        last_ltr: None,
        last_stall_keyframe: None,
        stall_reset_done: false,
        link: LinkStats::new(),
    };
    let mut next_tick = Instant::now();
    let mut n = 0u64;
    while !shared.stopped() {
        let now = Instant::now();
        if now >= next_tick {
            n += 1;
            fs.tick(n, &dec);
            next_tick = now + TICK;
        }
        match rx.recv_timeout(next_tick.saturating_duration_since(Instant::now())) {
            Ok(msg) => fs.handle(msg),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::srtp::RtpPacket;

    #[test]
    fn nack_watch_outlives_holds() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut w = NackWatch::default();
        w.nacked(1, &[5, 6], t0);
        // NACKed again later: the latency counts from the first NACK.
        w.nacked(1, &[6], ms(50));
        assert_eq!(w.arrived(1, 6, ms(400)), Some(Duration::from_millis(400)));
        assert_eq!(w.arrived(1, 6, ms(410)), None);
        assert_eq!(w.arrived(2, 5, ms(410)), None);
        w.expire(ms(999));
        assert_eq!(w.arrived(1, 5, ms(999)), Some(Duration::from_millis(999)));
        w.nacked(1, &[7], t0);
        w.expire(ms(1000));
        assert_eq!(w.arrived(1, 7, ms(1000)), None);
    }

    #[test]
    fn irap_follow_mask() {
        assert_eq!(follow_mask(4, 0), 0b1110);
        assert_eq!(follow_mask(4, 2), 0b1011);
        assert_eq!(follow_mask(1, 0), 0);
        assert_eq!(follow_mask(40, 33), u32::MAX);
    }

    #[test]
    fn retries_each_missing_packet_once() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let (retry, wait) = (Duration::from_millis(11), Duration::from_millis(27));
        let mut nacked = HashMap::from([((1, 5), (t0, false)), ((1, 6), (t0, false)), ((2, 9), (ms(5), false))]);
        assert_eq!(retry_nacks(&mut nacked, retry, wait, ms(10), &tx), 0);
        assert_eq!(retry_nacks(&mut nacked, retry, wait, ms(11), &tx), 2);
        let Ok(Feedback::Nack(1, mut lost)) = rx.try_recv() else { panic!("expected a NACK for SSRC 1") };
        lost.sort_unstable();
        assert_eq!(lost, [5, 6]);
        assert!(rx.try_recv().is_err());
        // Not again; the later one gets its own retry.
        assert_eq!(retry_nacks(&mut nacked, retry, wait, ms(16), &tx), 1);
        let Ok(Feedback::Nack(2, lost)) = rx.try_recv() else { panic!("expected a NACK for SSRC 2") };
        assert_eq!(lost, [9]);
        // Forgotten once the assembler has given up on them.
        retry_nacks(&mut nacked, retry, wait, ms(27), &tx);
        assert_eq!(nacked.keys().collect::<Vec<_>>(), [&(2, 9)]);
        retry_nacks(&mut nacked, retry, wait, ms(32), &tx);
        assert!(nacked.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn given_up_access_unit_reaches_decoder_incomplete() {
        let t0 = Instant::now();
        let mut asm = Assembler::default();
        asm.link(&[7, 8]);
        let mut tiles = TileMap::with_tiles(vec![7, 8]);
        let (tx, rx) = crossbeam_channel::unbounded();
        let p = |seq: u16, ts, marker| RtpPacket { ssrc: 8, seq, ts, marker, pt: 100, payload: vec![2, 1, 0, seq as u8, 0xee] };
        assert!(route(&mut tiles, &tx, asm.push(p(1, 1, true), t0)));
        // Seq 2 is lost and never retransmitted.
        assert!(route(&mut tiles, &tx, asm.push(p(3, 2, true), t0)));
        assert!(route(&mut tiles, &tx, asm.evict(t0 + asm.wait())));
        let got: Vec<(usize, bool, usize)> = rx
            .try_iter()
            .map(|m| match m {
                DecoderMsg::Au { tile, au } => (tile, au.complete, au.nalus.len()),
                DecoderMsg::Reset(_) => panic!("unexpected reset"),
            })
            .collect();
        // The decoder sees it as lost (and then waits for a keyframe, or
        // conceals with the slice that arrived).
        assert_eq!(got, [(1, true, 1), (1, false, 1)]);
    }
}
