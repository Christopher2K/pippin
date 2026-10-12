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
use crate::video::decoder::{Backend, Decoder, Picture};

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

fn record_sender_reports(shared: &Shared, rtcp: &[u8]) {
    let now = Instant::now();
    let mut srs = shared.sender_reports.lock();
    for (ssrc, mid32) in rtcp::sender_reports(rtcp) {
        srs.insert(ssrc, (mid32, now));
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
                        let expected = *next_seq.entry(p.ssrc).or_insert(p.seq);
                        let gap = p.seq.wrapping_sub(expected);
                        if gap < 0x8000 {
                            if gap > 0 && gap < NACK_MAX_GAP {
                                let lost = (0..gap).map(|i| expected.wrapping_add(i)).collect();
                                let _ = fb.send(Feedback::Nack(p.ssrc, lost));
                            }
                            next_seq.insert(p.ssrc, p.seq.wrapping_add(1));
                        }
                        if let Some(ext) = srtp.extended_seq(p.ssrc) {
                            shared.extended_seqs.lock().insert(p.ssrc, ext);
                        }
                    }
                    if let Some(au) = asm.push(p) {
                        match tiles.tile_of(au.ssrc) {
                            Some(tile) => {
                                if dec.send(DecoderMsg::Au { tile, au }).is_err() {
                                    return;
                                }
                            }
                            None => tiles.stash(au),
                        }
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
            for ssrc in asm.evict(now) {
                if let Some(t) = tiles.tile_of(ssrc) {
                    let _ = fb.send(Feedback::Keyframe(Some(t)));
                }
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
                srtp.forget(|s| ssrcs.contains(&s));
                next_seq.clear();
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

/// Drains the control/audio UDP port. Audio is not played; only sender
/// reports are kept for round-trip estimates in our receiver reports.
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

struct DecodeLoop {
    shared: Arc<Shared>,
    fb: Sender<Feedback>,
    decoder: Decoder,
    params: ParamSets,
    /// SPS the decoder was last started with.
    active_sps: Option<Vec<u8>>,
    awaiting_idr: bool,
    pts: i64,
    origin: HashMap<i64, (usize, Option<u16>)>,
    fed_without_output: Option<u32>,
}

impl DecodeLoop {
    fn restart(&mut self, backend: Backend) {
        match Decoder::new(backend == Backend::Cuda) {
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
        let ok = self.decoder.decode(&annexb, self.pts, &mut |p| pictures.push(p));
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
        if self.shared.frames.put(tile, pic) {
            self.shared.sink.emit(Event::Frame);
        }
    }
}

pub(super) fn decoder(shared: Arc<Shared>, rx: Receiver<DecoderMsg>, fb: Sender<Feedback>, prefer_hw: bool) {
    let decoder = match Decoder::new(prefer_hw) {
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
        fb,
        decoder,
        params: ParamSets::default(),
        active_sps: None,
        awaiting_idr: true,
        pts: 0,
        origin: HashMap::new(),
        fed_without_output: cuda.then_some(0),
    };
    while !shared.stopped() {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(DecoderMsg::Au { tile, au }) => st.access_unit(tile, au),
            Ok(DecoderMsg::Reset) => {
                // New SSRC group: new parameter sets will follow.
                st.params = ParamSets::default();
                st.active_sps = None;
                st.restart(st.decoder.backend());
            }
            Err(RecvTimeoutError::Timeout) => {}
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
