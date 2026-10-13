//! UDP media threads: SRTP video receive, HEVC decode and RTCP feedback.

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::net::{SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};

use super::{Event, Shared};
use crate::proto::offers::{MediaOffer, SRTP_BLOB_LEN};
use crate::rtp::assembler::{AccessUnit, Assembler, TileMap};
use crate::rtp::srtp::{SrtcpReceiver, SrtcpSender, SrtpReceiver, SrtpSender};
use crate::rtp::{hevc, rtcp};
use crate::video::decoder::{Backend, Decoder, DecoderOptions, Picture};

/// Requests from the media threads to the feedback sender.
pub enum Feedback {
    /// Ask for an IDR on one tile, or on every tile.
    Keyframe(Option<usize>),
    /// Retransmission request: media SSRC and lost sequence numbers.
    Nack(u32, Vec<u16>),
    /// The base tile decoded cleanly up to this DONL.
    LtrAck(u16),
}

pub(super) enum DecoderMsg {
    Au { tile: usize, au: AccessUnit },
    /// The tile mapping changed; start over from the next IDR.
    Reset,
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
const EVICT_EVERY: Duration = Duration::from_millis(20);
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
    let samples = rtcp::round_trips(rtcp, rtcp::ntp_middle_now());
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

/// NACKs each still-missing packet once more about a round trip after the
/// first request (half the assembler's hold, which allows for two), and
/// forgets packets the assembler will have given up on.
fn retry_nacks(nacked: &mut HashMap<(u32, u16), (Instant, bool)>, wait: Duration, now: Instant, fb: &Sender<Feedback>) {
    let mut retry: HashMap<u32, Vec<u16>> = HashMap::new();
    nacked.retain(|&(ssrc, seq), (at, retried)| {
        let age = now.duration_since(*at);
        if age >= wait {
            return false;
        }
        if !*retried && age >= wait / 2 {
            *retried = true;
            retry.entry(ssrc).or_default().push(seq);
        }
        true
    });
    for (ssrc, lost) in retry {
        tracing::trace!("NACK retry {ssrc:#010x}: {lost:?}");
        let _ = fb.send(Feedback::Nack(ssrc, lost));
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
    let mut buf = vec![0u8; 65536];
    let mut last_evict = Instant::now();
    let mut last_adopt = Instant::now();
    let mut bad = 0u64;
    let mut seen = std::collections::HashSet::new();

    while !shared.stopped() {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = &buf[..n];
                if is_rtcp(pkt) {
                    if let Some(data) = srtcp.unprotect(pkt) {
                        record_sender_reports(&shared, &data);
                    }
                } else if let Some(p) = srtp.unprotect(pkt) {
                    shared.touch(&shared.last_video_packet);
                    if seen.insert(p.ssrc) {
                        tracing::debug!("new video SSRC {:#010x} (pt {})", p.ssrc, p.pt);
                    }
                    tiles.count_packet(p.ssrc);
                    if tiles.tile_of(p.ssrc).is_some() {
                        // Gap detection for NACKs; the assembler deals with order.
                        nacked.remove(&(p.ssrc, p.seq));
                        let expected = *next_seq.entry(p.ssrc).or_insert(p.seq);
                        let gap = p.seq.wrapping_sub(expected);
                        if gap < 0x8000 {
                            if gap > 0 && gap < NACK_MAX_GAP {
                                let lost: Vec<u16> = (0..gap).map(|i| expected.wrapping_add(i)).collect();
                                if nacked.len() < NACK_PENDING_MAX {
                                    let now = Instant::now();
                                    nacked.extend(lost.iter().map(|&s| ((p.ssrc, s), (now, false))));
                                }
                                let _ = fb.send(Feedback::Nack(p.ssrc, lost));
                            }
                            next_seq.insert(p.ssrc, p.seq.wrapping_add(1));
                        }
                        if let Some(ext) = srtp.extended_seq(p.ssrc) {
                            shared.extended_seqs.lock().insert(p.ssrc, ext);
                        }
                    }
                    let aus = asm.push(p, Instant::now());
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
        if now.duration_since(last_evict) >= EVICT_EVERY {
            last_evict = now;
            if let Some(rtt) = *shared.rtt.lock() {
                asm.set_rtt(rtt);
            }
            // Given-up access units come out incomplete; the decoder asks
            // for the keyframe.
            if !route(&mut tiles, &dec, asm.evict(now)) {
                return;
            }
            retry_nacks(&mut nacked, asm.wait(), now, &fb);
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
                srtp.forget(|s| ssrcs.contains(&s));
                next_seq.clear();
                nacked.clear();
                *shared.tile_ssrcs.lock() = ssrcs;
                shared.extended_seqs.lock().clear();
                shared.renegotiated.store(0, Ordering::Relaxed);
                // Don't let the stall timer immediately allow another switch.
                shared.touch(&shared.last_frame);
                let _ = dec.send(DecoderMsg::Reset);
                for (tile, au) in backlog {
                    let _ = dec.send(DecoderMsg::Au { tile, au });
                }
                let _ = fb.send(Feedback::Keyframe(None));
            }
        }
    }
}

/// Drains the control/audio UDP port. Audio is not played; only RTCP is
/// kept, for round-trip estimates (ours and the host's via our receiver
/// reports).
pub(super) fn ctrl_rx(shared: Arc<Shared>, sock: UdpSocket, key: [u8; SRTP_BLOB_LEN]) {
    let srtcp = SrtcpReceiver::new(&key);
    let mut buf = vec![0u8; 65536];
    while !shared.stopped() {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = &buf[..n];
                if is_rtcp(pkt)
                    && let Some(data) = srtcp.unprotect(pkt) {
                        record_sender_reports(&shared, &data);
                    }
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                tracing::debug!("ctrl socket: {e}");
                std::thread::sleep(Duration::from_millis(50));
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

/// CUDA sometimes accepts packets but never returns pictures (e.g. 4:4:4
/// on GPUs without support); give up on it after this many access units.
const CUDA_GRACE_AUS: u32 = 120;
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
    /// Decoder-wide, not per tile: the tiles are pictures of one coded
    /// sequence in one DPB, so a dropped picture leaves a hole in every
    /// later picture's reference set, and an IDR on any tile empties the
    /// DPB for all of them.
    awaiting_idr: bool,
    pts: i64,
    origin: HashMap<i64, (usize, Option<u16>)>,
    fed_without_output: Option<u32>,
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
    fn restart(&mut self, backend: Backend) {
        match Decoder::new(DecoderOptions { prefer_hw: backend == Backend::Cuda, ..self.opts }) {
            Ok(d) => self.decoder = d,
            Err(e) => tracing::error!("restarting decoder: {e:#}"),
        }
        self.awaiting_idr = true;
        self.origin.clear();
        self.fed_without_output = (self.decoder.backend() == Backend::Cuda).then_some(0);
    }

    fn access_unit(&mut self, tile: usize, au: AccessUnit) {
        for nal in au.nalus.iter().filter(|n| hevc::is_param_set(n)) {
            self.params.absorb(nal);
        }
        if !au.complete {
            self.awaiting_idr = true;
            let _ = self.fb.send(Feedback::Keyframe(Some(tile)));
            return;
        }
        if !au.nalus.iter().any(|n| hevc::is_slice(n)) {
            return;
        }
        let irap = au.nalus.iter().any(|n| hevc::is_irap(n));
        if self.awaiting_idr && !irap {
            return;
        }
        let mut annexb = Vec::with_capacity(au.nalus.iter().map(|n| n.len() + 4).sum::<usize>() + 256);
        if irap {
            if self.params.sps.is_none() || self.params.pps.is_empty() {
                // A keyframe without parameter sets cannot start the decoder.
                let _ = self.fb.send(Feedback::Keyframe(Some(tile)));
                return;
            }
            if self.active_sps.is_some() && self.active_sps != self.params.sps {
                tracing::info!("stream parameters changed; restarting decoder");
                self.restart(self.decoder.backend());
            }
            self.active_sps = self.params.sps.clone();
            self.awaiting_idr = false;
            self.params.write(&mut annexb);
        }
        for nal in au.nalus.iter().filter(|n| !(irap && hevc::is_param_set(n))) {
            push_annexb(&mut annexb, nal);
        }

        self.pts += 1;
        self.origin.insert(self.pts, (tile, au.donl));
        let mut pictures = Vec::new();
        if let Some(d) = self.dump.as_mut() {
            let _ = std::io::Write::write_all(d, &annexb);
        }
        let started = Instant::now();
        let ok = self.decoder.decode(&annexb, self.pts, &mut |p| pictures.push(p));
        let slices = au.nalus.iter().filter(|n| hevc::is_slice(n)).count();
        self.stats.record(slices, pictures.len(), started.elapsed());
        if !ok {
            self.awaiting_idr = true;
            let _ = self.fb.send(Feedback::Keyframe(Some(tile)));
        }
        let floor = self.pts - 256;
        self.origin.retain(|&p, _| p > floor);

        if let Some(n) = self.fed_without_output.as_mut() {
            if pictures.is_empty() {
                *n += 1;
                if *n >= CUDA_GRACE_AUS {
                    tracing::warn!("CUDA decoder produced no pictures; switching to software decoding");
                    self.restart(Backend::Software);
                    let _ = self.fb.send(Feedback::Keyframe(None));
                }
            } else {
                self.fed_without_output = None;
            }
        }
        for p in pictures {
            self.publish(p);
        }
    }

    fn publish(&mut self, pic: Picture) {
        let Some((tile, donl)) = self.origin.remove(&pic.pts) else {
            return;
        };
        if pic.damaged {
            let _ = self.fb.send(Feedback::Keyframe(Some(tile)));
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

    fn flush(&mut self, why: Flush) {
        let Some(started) = self.batch_started.take() else { return };
        if self.batch.is_empty() {
            return;
        }
        let held = started.elapsed();
        let tiles: Vec<usize> = self.batch.iter().map(|(t, _)| *t).collect();
        tracing::trace!("present tiles {tiles:?} ({why:?}, held {:.1} ms)", held.as_secs_f64() * 1000.0);
        self.gather.record(why, tiles.len(), held);
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

pub(super) fn decoder(shared: Arc<Shared>, rx: Receiver<DecoderMsg>, fb: Sender<Feedback>, opts: DecoderOptions, sync_tiles: bool) {
    let decoder = match Decoder::new(opts) {
        Ok(d) => d,
        Err(e) => {
            shared.sink.emit(Event::Closed(Some(format!("video decoder: {e:#}"))));
            return;
        }
    };
    tracing::info!("video decoder: {:?}", decoder.backend());
    let cuda = decoder.backend() == Backend::Cuda;
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
        fed_without_output: cuda.then_some(0),
        batch: Vec::new(),
        sync_tiles,
        batch_started: None,
        last_input: Instant::now(),
        gather: GatherStats::new(),
        stats: DecodeStats::new(),
        dump: open_dump(),
    };
    while !shared.stopped() {
        match rx.recv_timeout(st.wait()) {
            Ok(DecoderMsg::Au { tile, au }) => {
                st.access_unit(tile, au);
                st.last_input = Instant::now();
                if st.batch_started.is_some_and(|t| t.elapsed() >= TILE_GATHER_MAX) {
                    st.flush(Flush::MaxHold);
                }
            }
            Ok(DecoderMsg::Reset) => {
                st.batch.clear();
                st.batch_started = None;
                // New SSRC group: new parameter sets will follow.
                st.params = ParamSets::default();
                st.active_sps = None;
                st.restart(st.decoder.backend());
            }
            Err(RecvTimeoutError::Timeout) => st.flush(Flush::Idle),
            Err(RecvTimeoutError::Disconnected) => return,
        }
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
}

impl FeedbackSender {
    fn ctrl(&mut self, rtcp: &[u8]) {
        let pkt = self.srtcp.protect(rtcp);
        if let Err(e) = self.s.ctrl.send_to(&pkt, self.s.ctrl_dest) {
            tracing::debug!("RTCP send: {e}");
        }
    }

    fn keyframe(&mut self, tile: Option<usize>) {
        if self.shared.since_ms(&self.shared.last_video_packet) > IDLE_AFTER_MS {
            return;
        }
        let ssrcs = self.shared.tile_ssrcs.lock().clone();
        let targets: Vec<usize> = match tile {
            Some(t) => vec![t],
            None => (0..ssrcs.len()).collect(),
        };
        let now = Instant::now();
        for t in targets {
            let Some(&target) = ssrcs.get(t) else { continue };
            if self.last_keyframe.get(&t).is_some_and(|l| now.duration_since(*l) < KEYFRAME_MIN_INTERVAL) {
                continue;
            }
            self.last_keyframe.insert(t, now);
            self.fir_seq = self.fir_seq.wrapping_add(1);
            tracing::debug!("keyframe request for tile {t}");
            let pkt = rtcp::keyframe_request(self.our_ssrc, target, self.fir_seq);
            self.ctrl(&pkt);
        }
    }

    fn handle(&mut self, msg: Feedback) {
        match msg {
            Feedback::Keyframe(t) => self.keyframe(t),
            Feedback::Nack(ssrc, lost) => {
                if let Some(pkt) = rtcp::nack(self.our_ssrc, ssrc, &lost) {
                    self.ctrl(&pkt);
                }
            }
            Feedback::LtrAck(donl) => {
                if self.last_ltr != Some(donl) {
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

        let sources: Vec<rtcp::ReportSource> = {
            let ssrcs = self.shared.tile_ssrcs.lock().clone();
            let seqs = self.shared.extended_seqs.lock();
            let srs = self.shared.sender_reports.lock();
            ssrcs
                .iter()
                .map(|&ssrc| rtcp::ReportSource {
                    ssrc,
                    extended_seq: seqs.get(&ssrc).copied().unwrap_or(0),
                    last_sr: srs.get(&ssrc).map(|&(mid, at)| (mid, at.elapsed().as_secs_f64())),
                })
                .collect()
        };
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
            self.keyframe(None);
        }
        if stalled > STALL_RESET_MS && !self.stall_reset_done {
            tracing::warn!("video stalled for {} s; resetting decoder", stalled / 1000);
            self.stall_reset_done = true;
            let _ = dec.send(DecoderMsg::Reset);
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
