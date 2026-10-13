//! Counters for experiments with the operating point, and `--stats-json`:
//! one JSON object per second (JSON lines) describing the link, the loss
//! recovery and what the viewer saw.
//!
//! Fields of each line (counts are for the interval since the previous
//! line, `dt` seconds long, about 1; rates are per second):
//!
//! * `t`: Unix time in seconds at the end of the interval, to line up with
//!   `tc netem` changes. `session_t`: seconds since this session started (a
//!   reconnect starts a new session and a new count).
//! * `op`: the operating point in force at the end of the interval:
//!   `render_scale`, `fps` (what was offered; 60 or 30), `recovery`
//!   (fir, pli or fir+pli), `hold` (the mode: auto, on, off), `holding`
//!   (whether access units with gaps are held right now; auto can switch
//!   it off), `ltr` (LTR offered and acked).
//! * `video_pps`, `video_bytes_ps`: authenticated video RTP packets and
//!   their UDP payload bytes, every SSRC (including ones not adopted).
//! * `tiles`: per adopted tile, `loss_pct` (packets missing over packets
//!   expected in the interval, from the RFC 3550 receiver statistics; a
//!   retransmission or late packet that fills a hole counts as received)
//!   and `jitter_ms` (RFC 3550 interarrival jitter at the end).
//! * `nacks`: packets NACKed for the first time; `nack_retries`: packets
//!   NACKed a second time; `nacked_arrived`: NACKed packets that arrived
//!   after all within the hold window (retransmissions, or late originals).
//!   Zero here with `nacks` > 0 means the host isn't retransmitting.
//! * `holds_started`, `holds_filled`, `holds_given_up`: access units held
//!   for missing packets, and how those holds ended.
//! * `kf_fir`, `kf_pli`, `kf_fir_pli`: keyframe requests sent, by the kind
//!   sent (one per tile request). `kf_suppressed`: requests not sent because
//!   the same tile was asked within 500 ms or the stream was idle.
//! * `irap_aus`, `irap_bytes`: complete IRAP (keyframe) access units that
//!   reached the decoder, and their total size (NAL units, no start codes).
//!   Keyframes lost in transit are not counted.
//! * `recovery_n`, `recovery_p50_ms`, `recovery_max_ms`: for each keyframe
//!   request sent, the time until the next undamaged picture on that tile;
//!   samples are taken when that picture arrives, so they belong to the
//!   interval it arrived in. Requests sent again before recovering each give
//!   a sample, so the max is the first request's (the whole outage). Null
//!   when no request completed in the interval.
//! * `frozen_ms`: time in the interval, sampled every 10 ms, during which
//!   the picture was stuck: the decoder was dropping everything while
//!   waiting for a keyframe and video arrived in the last 1.5 s, or a tile
//!   received packets in the last 100 ms but produced no picture for
//!   100 ms.
//! * `decode_aus`, `decode_avg_ms`, `decode_worst_ms`: access units fed to
//!   the decoder and how long the decode call took.
//! * `presented_fps`: frames handed to the renderer (a frame is one tile
//!   picture, or one gathered set with `--sync-tiles`). The display may
//!   still drop some.
//! * `rtt_ms`: smoothed round trip from host reports echoing our SRs; null
//!   while unknown (the host may never echo them).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use super::Shared;
use crate::rtp::assembler::HoldStats;
use crate::rtp::rtcp::Recovery;
use crate::rtp::stats::VIDEO_CLOCK_HZ;

/// Tiles tracked for freezes; the host uses 4.
pub(super) const MAX_TILES: usize = 16;
const LINE_EVERY: Duration = Duration::from_secs(1);
const SAMPLE_EVERY: Duration = Duration::from_millis(10);
/// A tile with traffic but no picture for this long is frozen.
const FROZEN_AFTER_MS: u64 = 100;
/// Waiting for a keyframe counts as frozen only while video flows.
const FLOWING_MS: u64 = 1500;
/// Recovery samples kept between lines at most.
const MAX_SAMPLES: usize = 4096;

/// Shared counters. Monotonic ones are swapped to zero by the stats writer,
/// its only reader.
#[derive(Default)]
pub(super) struct Metrics {
    pub video_packets: AtomicU64,
    pub video_bytes: AtomicU64,
    pub nacked: AtomicU64,
    pub nack_retries: AtomicU64,
    pub nacked_arrived: AtomicU64,
    pub holds_started: AtomicU64,
    pub holds_filled: AtomicU64,
    pub holds_given_up: AtomicU64,
    pub holding: AtomicBool,
    keyframes: [AtomicU64; 3],
    pub keyframes_suppressed: AtomicU64,
    pub irap_aus: AtomicU64,
    pub irap_bytes: AtomicU64,
    pub decoded_aus: AtomicU64,
    pub decode_ns: AtomicU64,
    pub decode_worst_ns: AtomicU64,
    pub presented: AtomicU64,
    pub awaiting_idr: AtomicBool,
    /// Session clock (ms) of each tile's latest packet and picture.
    tile_packet_ms: [AtomicU64; MAX_TILES],
    tile_picture_ms: [AtomicU64; MAX_TILES],
    recovery: Mutex<RecoveryTracker>,
}

fn kind_index(k: Recovery) -> usize {
    match k {
        Recovery::Fir => 0,
        Recovery::Pli => 1,
        Recovery::FirPli => 2,
    }
}

impl Metrics {
    pub fn add_holds(&self, h: HoldStats) {
        self.holds_started.fetch_add(h.started as u64, Ordering::Relaxed);
        self.holds_filled.fetch_add(h.filled as u64, Ordering::Relaxed);
        self.holds_given_up.fetch_add(h.given_up as u64, Ordering::Relaxed);
    }

    /// A keyframe request went out for `tile`.
    pub fn keyframe_sent(&self, kind: Recovery, tile: usize, at: Instant) {
        self.keyframes[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
        self.recovery.lock().requested(tile, at);
    }

    pub fn decoded(&self, took: Duration) {
        let ns = took.as_nanos() as u64;
        self.decoded_aus.fetch_add(1, Ordering::Relaxed);
        self.decode_ns.fetch_add(ns, Ordering::Relaxed);
        self.decode_worst_ns.fetch_max(ns, Ordering::Relaxed);
    }

    pub fn tile_packet(&self, tile: usize, now_ms: u64) {
        if let Some(t) = self.tile_packet_ms.get(tile) {
            t.store(now_ms, Ordering::Relaxed);
        }
    }

    /// A picture for `tile` was published; `clean` if not damaged.
    pub fn picture(&self, tile: usize, clean: bool, now_ms: u64, at: Instant) {
        if let Some(t) = self.tile_picture_ms.get(tile) {
            t.store(now_ms, Ordering::Relaxed);
        }
        if clean {
            self.recovery.lock().clean(tile, at);
        }
    }

    /// Whether the picture counts as frozen at `now_ms` (see the module
    /// docs), given the session clock of the latest video packet.
    fn frozen(&self, now_ms: u64, last_video_ms: u64) -> bool {
        let ago = |t: u64| now_ms.saturating_sub(t);
        if last_video_ms != 0 && ago(last_video_ms) < FLOWING_MS && self.awaiting_idr.load(Ordering::Relaxed) {
            return true;
        }
        self.tile_packet_ms.iter().zip(&self.tile_picture_ms).any(|(p, q)| {
            let (p, q) = (p.load(Ordering::Relaxed), q.load(Ordering::Relaxed));
            p != 0 && ago(p) < FROZEN_AFTER_MS && ago(q) >= FROZEN_AFTER_MS
        })
    }
}

/// Times from keyframe requests to the next clean picture of their tile.
#[derive(Default)]
struct RecoveryTracker {
    /// Unanswered requests per tile.
    pending: HashMap<usize, Vec<Instant>>,
    samples: Vec<Duration>,
}

impl RecoveryTracker {
    fn requested(&mut self, tile: usize, at: Instant) {
        let p = self.pending.entry(tile).or_default();
        if p.len() < MAX_SAMPLES {
            p.push(at);
        }
    }

    fn clean(&mut self, tile: usize, at: Instant) {
        let Some(p) = self.pending.remove(&tile) else { return };
        for t in p {
            if self.samples.len() < MAX_SAMPLES {
                self.samples.push(at.saturating_duration_since(t));
            }
        }
    }

    /// Count, median and max of the samples since the last call.
    fn take(&mut self) -> (usize, Option<(Duration, Duration)>) {
        let mut s = std::mem::take(&mut self.samples);
        s.sort_unstable();
        (s.len(), s.last().map(|&max| (s[s.len() / 2], max)))
    }
}

/// Formats a float for JSON: finite, at most `digits` decimals.
fn num(v: f64, digits: usize) -> String {
    if v.is_finite() { format!("{v:.digits$}") } else { "null".into() }
}

/// Per-tile loss over the interval, from `(expected, received)` now and at
/// its start.
fn loss_pct(now: (u64, u64), start: Option<(u64, u64)>) -> f64 {
    // Stats restart with a new SSRC group; count from zero then.
    let (e0, r0) = start.filter(|&(e, _)| e <= now.0).unwrap_or((0, 0));
    let exp = now.0 - e0;
    let rcv = now.1.saturating_sub(r0);
    if exp == 0 { 0.0 } else { exp.saturating_sub(rcv) as f64 * 100.0 / exp as f64 }
}

/// The values of one line that don't come from [`Metrics`] counters.
struct LineContext<'a> {
    t: f64,
    session_t: f64,
    dt: f64,
    op: &'a super::OperatingPoint,
    tiles: &'a [(f64, f64)],
    frozen_ms: u64,
    rtt: Option<Duration>,
}

fn line(m: &Metrics, cx: &LineContext) -> String {
    let take = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
    let rate = |n: u64| num(n as f64 / cx.dt, 1);
    let op = cx.op;
    let mut s = String::with_capacity(512);
    let _ = write!(
        s,
        "{{\"t\":{},\"session_t\":{},\"dt\":{},\"op\":{{\"render_scale\":{},\"fps\":{},\"recovery\":\"{}\",\
         \"hold\":\"{}\",\"holding\":{},\"ltr\":{}}}",
        num(cx.t, 3),
        num(cx.session_t, 3),
        num(cx.dt, 3),
        op.render_scale,
        op.fps.value(),
        op.recovery.name(),
        op.hold.name(),
        m.holding.load(Ordering::Relaxed),
        op.ltr,
    );
    let _ = write!(s, ",\"video_pps\":{},\"video_bytes_ps\":{}", rate(take(&m.video_packets)), rate(take(&m.video_bytes)));
    s.push_str(",\"tiles\":[");
    for (i, (loss, jitter)) in cx.tiles.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{{\"loss_pct\":{},\"jitter_ms\":{}}}", num(*loss, 2), num(*jitter, 2));
    }
    s.push(']');
    let _ = write!(
        s,
        ",\"nacks\":{},\"nack_retries\":{},\"nacked_arrived\":{},\"holds_started\":{},\"holds_filled\":{},\
         \"holds_given_up\":{}",
        take(&m.nacked),
        take(&m.nack_retries),
        take(&m.nacked_arrived),
        take(&m.holds_started),
        take(&m.holds_filled),
        take(&m.holds_given_up),
    );
    let [fir, pli, both] = m.keyframes.each_ref().map(take);
    let _ = write!(
        s,
        ",\"kf_fir\":{fir},\"kf_pli\":{pli},\"kf_fir_pli\":{both},\"kf_suppressed\":{},\"irap_aus\":{},\
         \"irap_bytes\":{}",
        take(&m.keyframes_suppressed),
        take(&m.irap_aus),
        take(&m.irap_bytes),
    );
    let ms = |d: Duration| num(d.as_secs_f64() * 1000.0, 1);
    let (n, rec) = m.recovery.lock().take();
    match rec {
        Some((p50, max)) => {
            let _ = write!(s, ",\"recovery_n\":{n},\"recovery_p50_ms\":{},\"recovery_max_ms\":{}", ms(p50), ms(max));
        }
        None => s.push_str(",\"recovery_n\":0,\"recovery_p50_ms\":null,\"recovery_max_ms\":null"),
    }
    let aus = take(&m.decoded_aus);
    let busy = Duration::from_nanos(take(&m.decode_ns));
    let worst = Duration::from_nanos(take(&m.decode_worst_ns));
    let avg = if aus == 0 { "null".into() } else { ms(busy / aus as u32) };
    let _ = write!(
        s,
        ",\"frozen_ms\":{},\"decode_aus\":{aus},\"decode_avg_ms\":{avg},\"decode_worst_ms\":{},\"presented_fps\":{}",
        cx.frozen_ms,
        if aus == 0 { "null".into() } else { ms(worst) },
        rate(take(&m.presented)),
    );
    match cx.rtt {
        Some(r) => {
            let _ = write!(s, ",\"rtt_ms\":{}}}", ms(r));
        }
        None => s.push_str(",\"rtt_ms\":null}"),
    }
    s
}

/// Writes a stats line per second to `path` (appending) until the session
/// stops.
pub(super) fn writer(shared: Arc<Shared>, path: PathBuf) {
    let file = std::fs::OpenOptions::new().create(true).append(true).open(&path);
    let mut out = match file {
        Ok(f) => std::io::BufWriter::new(f),
        Err(e) => {
            tracing::warn!("--stats-json {}: {e}", path.display());
            return;
        }
    };
    tracing::info!("writing stats to {}", path.display());
    let m = &shared.metrics;
    // Drop what accumulated while connecting.
    let _ = line(m, &LineContext { t: 0.0, session_t: 0.0, dt: 1.0, op: &shared.op(), tiles: &[], frozen_ms: 0, rtt: None });
    let mut start: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut since = Instant::now();
    let mut frozen_samples = 0u64;
    while !shared.stopped() {
        std::thread::sleep(SAMPLE_EVERY);
        let now_ms = shared.clock.now_ms();
        if m.frozen(now_ms, shared.last_video_packet.load(Ordering::Relaxed)) {
            frozen_samples += 1;
        }
        let dt = since.elapsed();
        if dt < LINE_EVERY {
            continue;
        }
        since = Instant::now();
        let ssrcs = shared.tile_ssrcs.lock().clone();
        let now: HashMap<u32, (u64, u64, u32)> = {
            let stats = shared.rx_stats.lock();
            ssrcs
                .iter()
                .filter_map(|s| stats.get(s).map(|r| (*s, (r.expected(), r.received(), r.jitter()))))
                .collect()
        };
        let tiles: Vec<(f64, f64)> = ssrcs
            .iter()
            .map(|s| match now.get(s) {
                Some(&(e, r, j)) => (loss_pct((e, r), start.get(s).copied()), j as f64 * 1000.0 / VIDEO_CLOCK_HZ as f64),
                None => (0.0, 0.0),
            })
            .collect();
        start = now.into_iter().map(|(s, (e, r, _))| (s, (e, r))).collect();
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let cx = LineContext {
            t,
            session_t: shared.clock.0.elapsed().as_secs_f64(),
            dt: dt.as_secs_f64(),
            op: &shared.op(),
            tiles: &tiles,
            frozen_ms: (frozen_samples * SAMPLE_EVERY.as_millis() as u64).min(dt.as_millis() as u64),
            rtt: *shared.rtt.lock(),
        };
        frozen_samples = 0;
        let l = line(m, &cx);
        if let Err(e) = writeln!(out, "{l}").and_then(|()| out.flush()) {
            tracing::warn!("--stats-json: {e}");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::assembler::HoldMode;
    use crate::session::{Fps, OperatingPoint};

    #[test]
    fn recovery_latency_per_request() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut r = RecoveryTracker::default();
        r.requested(1, t0);
        r.requested(1, ms(500));
        r.requested(2, ms(100));
        // Another tile's picture doesn't answer tile 1.
        r.clean(0, ms(600));
        r.clean(1, ms(700));
        r.clean(1, ms(800));
        assert_eq!(r.take(), (2, Some((Duration::from_millis(700), Duration::from_millis(700)))));
        assert_eq!(r.take(), (0, None));
        r.clean(2, ms(150));
        assert_eq!(r.take(), (1, Some((Duration::from_millis(50), Duration::from_millis(50)))));
    }

    #[test]
    fn frozen_rules() {
        let m = Metrics::default();
        // Nothing seen yet.
        assert!(!m.frozen(5000, 0));
        m.tile_packet(1, 4950);
        m.tile_picture_ms[1].store(4800, Ordering::Relaxed);
        assert!(m.frozen(5000, 4950));
        m.picture(1, true, 4990, Instant::now());
        assert!(!m.frozen(5000, 4950));
        // Waiting for a keyframe while video flows.
        m.awaiting_idr.store(true, Ordering::Relaxed);
        assert!(m.frozen(5000, 4950));
        // Not on an idle stream.
        assert!(!m.frozen(9000, 4950));
    }

    #[test]
    fn interval_loss() {
        assert_eq!(loss_pct((200, 190), Some((100, 100))), 10.0);
        assert_eq!(loss_pct((100, 100), Some((100, 100))), 0.0);
        // A new SSRC group restarted the counts.
        assert_eq!(loss_pct((10, 9), Some((100, 100))), 10.0);
    }

    #[test]
    fn line_is_json_with_every_field() {
        let m = Metrics::default();
        m.video_packets.store(100, Ordering::Relaxed);
        m.keyframe_sent(Recovery::Pli, 0, Instant::now());
        m.decoded(Duration::from_millis(3));
        let op = OperatingPoint {
            render_scale: 0.5,
            fps: Fps::Thirty,
            recovery: Recovery::Pli,
            hold: HoldMode::Off,
            ltr: false,
        };
        let l = line(
            &m,
            &LineContext {
                t: 1.5,
                session_t: 2.0,
                dt: 2.0,
                op: &op,
                tiles: &[(1.0, 2.5), (0.0, 0.0)],
                frozen_ms: 30,
                rtt: None,
            },
        );
        assert_eq!(
            l,
            "{\"t\":1.500,\"session_t\":2.000,\"dt\":2.000,\"op\":{\"render_scale\":0.5,\"fps\":30,\
             \"recovery\":\"pli\",\"hold\":\"off\",\"holding\":false,\"ltr\":false},\"video_pps\":50.0,\
             \"video_bytes_ps\":0.0,\"tiles\":[{\"loss_pct\":1.00,\"jitter_ms\":2.50},{\"loss_pct\":0.00,\
             \"jitter_ms\":0.00}],\"nacks\":0,\"nack_retries\":0,\"nacked_arrived\":0,\"holds_started\":0,\
             \"holds_filled\":0,\"holds_given_up\":0,\"kf_fir\":0,\"kf_pli\":1,\"kf_fir_pli\":0,\
             \"kf_suppressed\":0,\"irap_aus\":0,\"irap_bytes\":0,\"recovery_n\":0,\"recovery_p50_ms\":null,\
             \"recovery_max_ms\":null,\"frozen_ms\":30,\"decode_aus\":1,\"decode_avg_ms\":3.0,\
             \"decode_worst_ms\":3.0,\"presented_fps\":0.0,\"rtt_ms\":null}"
        );
        // Counters were consumed.
        assert!(line(&m, &LineContext { t: 0.0, session_t: 0.0, dt: 1.0, op: &op, tiles: &[], frozen_ms: 0, rtt: None })
            .contains("\"video_pps\":0.0"));
    }
}
