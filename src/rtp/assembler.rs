//! Groups RTP packets into access units and maps SSRCs to screen tiles.
//!
//! The host splits each frame into N horizontal tiles, each its own SSRC
//! with consecutive SSRC values; the lowest SSRC is the top tile. After a
//! re-negotiation (e.g. a resize) a fresh group of SSRCs appears and the old
//! one goes quiet, so the mapping is re-learned from traffic.
//!
//! An access unit whose marker arrived with packets missing is held for a
//! short wait so NACK retransmissions and reordered packets can fill it,
//! instead of being given up at once (which costs the tile a keyframe).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use super::hevc;
use super::srtp::RtpPacket;

/// A group whose marker hasn't arrived, with no later traffic on its SSRC,
/// is given up after this long without a packet.
const GROUP_TTL: Duration = Duration::from_millis(200);
const FLUSHED_TTL: Duration = Duration::from_secs(2);
/// Hold for missing packets when no round-trip estimate is available.
const DEFAULT_WAIT: Duration = Duration::from_millis(60);
/// Bounds on the hold, whatever the round-trip estimate says.
const MIN_WAIT: Duration = Duration::from_millis(20);
const MAX_WAIT: Duration = Duration::from_millis(300);
/// Added to two round trips (NACK plus one retry) for reordering and host
/// turnaround.
const REORDER_SLACK: Duration = Duration::from_millis(20);
/// Packets this close behind an SSRC's last emitted marker belong to access
/// units already emitted or given up, and are dropped. Further back counts as
/// a sequence jump.
const STALE_SEQS: u16 = 0x1000;
const ADOPT_MIN_PACKETS: u32 = 5;
const INITIAL_SETTLE: Duration = Duration::from_millis(300);
const BACKLOG_AGE: Duration = Duration::from_secs(3);
const BACKLOG_MAX: usize = 4096;

/// One frame's worth of NAL units for one tile.
pub struct AccessUnit {
    pub ssrc: u32,
    pub nalus: Vec<Vec<u8>>,
    pub donl: Option<u16>,
    /// False if packets were lost; only parameter sets are kept then.
    pub complete: bool,
    pub received: Instant,
}

struct Group {
    packets: Vec<(u16, bool, Vec<u8>)>,
    started: Instant,
    last_at: Instant,
    /// Earliest and latest sequence numbers, in wrapping order.
    first: u16,
    last: u16,
    /// Sequence number and arrival of the marker packet.
    marker: Option<(u16, Instant)>,
}

impl Group {
    fn insert(&mut self, seq: u16, marker: bool, payload: Vec<u8>, now: Instant) {
        if self.packets.is_empty() {
            (self.first, self.last) = (seq, seq);
        } else if seq.wrapping_sub(self.first) >= 0x8000 {
            self.first = seq;
        } else if seq.wrapping_sub(self.last) < 0x8000 {
            self.last = seq;
        }
        if marker {
            self.marker = Some((seq, now));
        }
        self.last_at = now;
        self.packets.push((seq, marker, payload));
    }
}

/// What to do with the oldest pending group of an SSRC.
enum Verdict {
    Wait,
    Emit { complete: bool },
}

/// Sorts a group's packets into sequence order, handling 16-bit wrap.
fn ordered(packets: &mut [(u16, bool, Vec<u8>)]) {
    packets.sort_by_key(|p| p.0);
    if packets.len() >= 2 && packets[packets.len() - 1].0.wrapping_sub(packets[0].0) > 0x8000 {
        // The group straddles the wrap: rotate so it starts after the largest gap.
        let (idx, _) = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i, packets[(i + 1) % packets.len()].0.wrapping_sub(p.0)))
            .max_by_key(|&(_, gap)| gap)
            .unwrap();
        packets.rotate_left(idx + 1);
    }
}

/// Access units leave in sequence order per SSRC. When the oldest one is
/// held for missing packets, later ones (even complete) wait behind it: they
/// predict from it, so decoding them first, or giving up on it to release
/// them sooner, would only produce corrupt pictures and a keyframe request
/// anyway. Their extra latency is bounded by the hold.
pub struct Assembler {
    groups: HashMap<(u32, u32), Group>,
    flushed: HashMap<(u32, u32), Instant>,
    last_marker: HashMap<u32, u16>,
    wait: Duration,
}

impl Default for Assembler {
    fn default() -> Self {
        Self { groups: HashMap::new(), flushed: HashMap::new(), last_marker: HashMap::new(), wait: DEFAULT_WAIT }
    }
}

impl Assembler {
    /// How long an access unit with missing packets is held after its marker.
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// Sizes the hold from a round-trip estimate: room for a NACK and one
    /// retry.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.wait = (rtt * 2 + REORDER_SLACK).clamp(MIN_WAIT, MAX_WAIT);
    }

    /// Adds a packet; returns the access units it completes, in order.
    pub fn push(&mut self, pkt: RtpPacket, now: Instant) -> Vec<AccessUnit> {
        let key = (pkt.ssrc, pkt.ts);
        if self.flushed.contains_key(&key) {
            return Vec::new();
        }
        if self.last_marker.get(&pkt.ssrc).is_some_and(|&m| m.wrapping_sub(pkt.seq) < STALE_SEQS) {
            return Vec::new();
        }
        let g = self.groups.entry(key).or_insert_with(|| Group {
            packets: Vec::new(),
            started: now,
            last_at: now,
            first: 0,
            last: 0,
            marker: None,
        });
        if g.packets.iter().any(|p| p.0 == pkt.seq) {
            return Vec::new();
        }
        g.insert(pkt.seq, pkt.marker, pkt.payload, now);
        let mut out = Vec::new();
        // Only a group with its marker can complete; time-based give-ups
        // happen in evict().
        if g.marker.is_some() {
            self.release(pkt.ssrc, now, &mut out);
        }
        out
    }

    /// Gives up on groups that waited too long: their access units come out
    /// incomplete (so the decoder asks for a keyframe), followed by any
    /// complete ones that were queued behind them.
    pub fn evict(&mut self, now: Instant) -> Vec<AccessUnit> {
        let ssrcs: HashSet<u32> = self.groups.keys().map(|k| k.0).collect();
        let mut out = Vec::new();
        for ssrc in ssrcs {
            self.release(ssrc, now, &mut out);
        }
        self.flushed.retain(|_, t| now.duration_since(*t) < FLUSHED_TTL);
        out
    }

    /// The pending group of `ssrc` that comes first in sequence order.
    fn head(&self, ssrc: u32) -> Option<(u32, u32)> {
        self.groups
            .iter()
            .filter(|(k, _)| k.0 == ssrc)
            .reduce(|a, b| if b.1.first.wrapping_sub(a.1.first) >= 0x8000 { b } else { a })
            .map(|(k, _)| *k)
    }

    fn verdict(&self, key: (u32, u32), now: Instant) -> Verdict {
        let g = &self.groups[&key];
        let Some((mseq, marker_at)) = g.marker else {
            // The marker is missing. Once later traffic shows the group's
            // tail was lost, allow the same wait for a retransmission.
            let later = self.groups.iter().filter(|(k, _)| k.0 == key.0 && **k != key).map(|(_, o)| o.started).min();
            let deadline = match later {
                Some(t) => t + self.wait,
                None => g.last_at + GROUP_TTL,
            };
            return if now >= deadline { Verdict::Emit { complete: false } } else { Verdict::Wait };
        };
        if g.last != mseq {
            // A packet after the marker in the same group: no retransmission
            // will make this whole.
            return Verdict::Emit { complete: false };
        }
        let starts_after_prev = self.last_marker.get(&key.0).is_none_or(|&m| g.first == m.wrapping_add(1));
        let contiguous = g.packets.len() == mseq.wrapping_sub(g.first) as usize + 1;
        if starts_after_prev && contiguous {
            Verdict::Emit { complete: true }
        } else if now >= marker_at + self.wait {
            Verdict::Emit { complete: false }
        } else {
            Verdict::Wait
        }
    }

    /// Emits the SSRC's groups in order for as long as the oldest is ready.
    fn release(&mut self, ssrc: u32, now: Instant, out: &mut Vec<AccessUnit>) {
        while let Some(key) = self.head(ssrc) {
            match self.verdict(key, now) {
                Verdict::Wait => break,
                Verdict::Emit { complete } => out.push(self.emit(key, complete, now)),
            }
        }
    }

    fn emit(&mut self, key: (u32, u32), complete: bool, now: Instant) -> AccessUnit {
        let mut g = self.groups.remove(&key).expect("emitted group exists");
        self.flushed.insert(key, now);
        // Without a marker the end is unknown; the next group must start
        // after everything seen so far to count as contiguous.
        self.last_marker.insert(key.0, g.marker.map_or(g.last, |m| m.0));
        ordered(&mut g.packets);
        let refs: Vec<(u16, &[u8])> = g.packets.iter().map(|p| (p.0, p.2.as_slice())).collect();
        let mut nalus = hevc::depayload(&refs);
        if !complete {
            nalus.retain(|n| hevc::is_param_set(n));
        }
        AccessUnit { ssrc: key.0, nalus, donl: hevc::first_donl(&refs), complete, received: g.started }
    }
}


/// Learns which SSRCs carry the active tiles.
#[derive(Default)]
pub struct TileMap {
    tiles: Vec<u32>,
    blacklist: HashSet<u32>,
    counts: HashMap<u32, u32>,
    first_packet: Option<Instant>,
    /// Access units from SSRCs not yet adopted, replayed on adoption so the
    /// parameter sets and IDR at the start of a stream are not lost.
    backlog: VecDeque<AccessUnit>,
}


impl TileMap {
    pub fn tile_of(&self, ssrc: u32) -> Option<usize> {
        self.tiles.iter().position(|&s| s == ssrc)
    }

    pub fn ssrcs(&self) -> &[u32] {
        &self.tiles
    }

    pub fn count_packet(&mut self, ssrc: u32) {
        self.first_packet.get_or_insert_with(Instant::now);
        if !self.blacklist.contains(&ssrc) {
            *self.counts.entry(ssrc).or_default() += 1;
        }
    }

    pub fn stash(&mut self, au: AccessUnit) {
        if self.blacklist.contains(&au.ssrc) {
            return;
        }
        let now = Instant::now();
        while self
            .backlog
            .front()
            .is_some_and(|f| now.duration_since(f.received) > BACKLOG_AGE || self.backlog.len() >= BACKLOG_MAX)
        {
            self.backlog.pop_front();
        }
        self.backlog.push_back(au);
    }

    /// Considers switching to a new SSRC group. `want` is the expected tile
    /// count, and `allow_switch` permits replacing an existing mapping (the
    /// stream stalled or was re-negotiated). On adoption, returns the
    /// backlogged access units of the new group with their tile indexes.
    pub fn try_adopt(&mut self, want: usize, allow_switch: bool) -> Option<Vec<(usize, AccessUnit)>> {
        let want = want.max(1);
        if !self.tiles.is_empty() && !allow_switch {
            return None;
        }
        if self.tiles.is_empty() && self.first_packet.is_some_and(|t| t.elapsed() < INITIAL_SETTLE) {
            return None;
        }
        let mut cands: Vec<u32> = self
            .counts
            .iter()
            .filter(|&(s, &n)| n >= ADOPT_MIN_PACKETS && !self.tiles.contains(s) && !self.blacklist.contains(s))
            .map(|(&s, _)| s)
            .collect();
        cands.sort_unstable();
        let mut runs: Vec<Vec<u32>> = Vec::new();
        for s in cands {
            match runs.last_mut() {
                Some(r) if r.len() < want && s.wrapping_sub(*r.last().unwrap()) == 1 => r.push(s),
                _ => runs.push(vec![s]),
            }
        }
        // Several quality tiers may stream at once; take the busiest group.
        let group = runs
            .into_iter()
            .filter(|r| r.len() == want)
            .max_by_key(|r| r.iter().map(|s| self.counts[s]).sum::<u32>())?;

        tracing::info!(
            "video tiles: {}",
            group.iter().map(|s| format!("{s:#010x}")).collect::<Vec<_>>().join(" ")
        );
        self.blacklist.extend(self.tiles.drain(..));
        self.tiles = group;
        let blacklist = &self.blacklist;
        self.counts.retain(|s, _| !blacklist.contains(s));
        let backlog = std::mem::take(&mut self.backlog);
        Some(
            backlog
                .into_iter()
                .filter_map(|au| self.tile_of(au.ssrc).map(|t| (t, au)))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(ssrc: u32, seq: u16, ts: u32, marker: bool, payload: Vec<u8>) -> RtpPacket {
        RtpPacket { ssrc, seq, ts, marker, pt: 100, payload }
    }

    fn single(t: u8) -> Vec<u8> {
        vec![t << 1, 1, 0, 1, 0xee]
    }

    fn vps() -> Vec<u8> {
        vec![hevc::NAL_VPS << 1, 1, 0, 1, 0xaa]
    }

    fn one(mut aus: Vec<AccessUnit>) -> AccessUnit {
        assert_eq!(aus.len(), 1);
        aus.pop().unwrap()
    }

    #[test]
    fn groups_out_of_order_and_detects_loss() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(a.push(pkt(1, 6, 90, false, single(1)), t0).is_empty());
        // The marker is on seq 5 but seq 6 sorts after it, so the group can
        // never end on its marker: given up at once.
        assert!(!one(a.push(pkt(1, 5, 90, true, single(19)), t0)).complete);

        let mut a = Assembler::default();
        assert!(a.push(pkt(7, 65535, 1, false, single(19)), t0).is_empty());
        let au = one(a.push(pkt(7, 0, 1, true, single(19)), t0));
        assert!(au.complete);
        assert_eq!(au.nalus.len(), 2);
        // Next AU skips seq 1: held for a retransmission, then given up.
        assert!(a.push(pkt(7, 2, 2, true, single(1)), t0).is_empty());
        assert!(a.evict(t0 + a.wait() / 2).is_empty());
        let au = one(a.evict(t0 + a.wait()));
        assert!(!au.complete);
        assert!(au.nalus.is_empty());
    }

    #[test]
    fn late_retransmit_fills_gap() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(3, 9, 0, true, single(19)), t0)).complete);
        assert!(a.push(pkt(3, 10, 1, false, single(1)), t0).is_empty());
        // 11 lost; marker arrives.
        assert!(a.push(pkt(3, 12, 1, true, single(1)), t0).is_empty());
        // A complete AU behind it waits its turn.
        assert!(a.push(pkt(3, 13, 2, false, single(1)), t0).is_empty());
        assert!(a.push(pkt(3, 14, 2, true, single(1)), t0).is_empty());
        let t = t0 + Duration::from_millis(15);
        assert!(a.evict(t).is_empty());
        let aus = a.push(pkt(3, 11, 1, false, single(1)), t);
        assert_eq!(aus.len(), 2);
        assert!(aus.iter().all(|au| au.complete));
        assert_eq!(aus[0].nalus.len(), 3);
        assert_eq!(aus[1].nalus.len(), 2);
        // A duplicate retransmission is ignored.
        assert!(a.push(pkt(3, 11, 1, false, single(1)), t).is_empty());
    }

    #[test]
    fn reordered_packet_after_marker() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(4, 19, 0, true, single(19)), t0)).complete);
        assert!(a.push(pkt(4, 20, 1, false, single(1)), t0).is_empty());
        assert!(a.push(pkt(4, 22, 1, true, single(1)), t0).is_empty());
        let au = one(a.push(pkt(4, 21, 1, false, single(1)), t0));
        assert!(au.complete);
        assert_eq!(au.nalus.len(), 3);
        // The first packet of the next AU arrives after its marker.
        assert!(a.push(pkt(4, 24, 2, true, single(1)), t0).is_empty());
        assert!(one(a.push(pkt(4, 23, 2, false, single(1)), t0)).complete);
        // The lost marker of an AU turns up after the next AU's.
        assert!(a.push(pkt(4, 25, 3, false, single(1)), t0).is_empty());
        assert!(a.push(pkt(4, 27, 4, true, single(1)), t0).is_empty());
        let aus = a.push(pkt(4, 26, 3, true, single(1)), t0);
        assert_eq!(aus.len(), 2);
        assert!(aus.iter().all(|au| au.complete));
    }

    #[test]
    fn gives_up_after_wait() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(5, 99, 0, true, single(19)), t0)).complete);
        assert!(a.push(pkt(5, 100, 1, false, vps()), t0).is_empty());
        assert!(a.push(pkt(5, 102, 1, true, single(1)), t0).is_empty());
        let t1 = t0 + Duration::from_millis(5);
        assert!(a.push(pkt(5, 103, 2, false, single(1)), t1).is_empty());
        assert!(a.push(pkt(5, 104, 2, true, single(1)), t1).is_empty());
        // The held AU comes out incomplete with only its parameter sets (the
        // decoder then asks for a keyframe), followed by the one behind it.
        let aus = a.evict(t0 + a.wait());
        assert_eq!(aus.len(), 2);
        assert!(!aus[0].complete);
        assert_eq!(aus[0].nalus, vec![vec![hevc::NAL_VPS << 1, 1, 0xaa]]);
        assert!(aus[1].complete);
        // The retransmission arriving too late is dropped.
        assert!(a.push(pkt(5, 101, 1, false, single(1)), t0 + a.wait()).is_empty());
        assert!(a.evict(t0 + a.wait() * 4).is_empty());

        // A group whose marker never arrives is given up a wait after later
        // traffic shows it ended.
        let mut a = Assembler::default();
        assert!(a.push(pkt(6, 30, 1, false, single(1)), t0).is_empty());
        assert!(a.push(pkt(6, 33, 2, true, single(1)), t1).is_empty());
        assert!(a.evict(t1 + a.wait() / 2).is_empty());
        let aus = a.evict(t1 + a.wait());
        assert_eq!(aus.len(), 2);
        assert!(aus.iter().all(|au| !au.complete));
    }

    #[test]
    fn fills_gap_across_seq_wrap() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(8, 65533, 0, true, single(19)), t0)).complete);
        assert!(a.push(pkt(8, 65534, 1, false, single(1)), t0).is_empty());
        assert!(a.push(pkt(8, 0, 1, true, single(1)), t0).is_empty());
        let au = one(a.push(pkt(8, 65535, 1, false, single(1)), t0));
        assert!(au.complete);
        assert_eq!(au.nalus.len(), 3);
        assert!(a.push(pkt(8, 1, 2, false, single(1)), t0).is_empty());
        assert!(one(a.push(pkt(8, 2, 2, true, single(1)), t0)).complete);
        // Stale packets from before the last marker are ignored.
        assert!(a.push(pkt(8, 65530, 9, true, single(1)), t0).is_empty());
    }

    #[test]
    fn wait_follows_rtt() {
        let mut a = Assembler::default();
        assert_eq!(a.wait(), DEFAULT_WAIT);
        a.set_rtt(Duration::from_millis(40));
        assert_eq!(a.wait(), Duration::from_millis(100));
        a.set_rtt(Duration::ZERO);
        assert_eq!(a.wait(), MIN_WAIT.max(REORDER_SLACK));
        a.set_rtt(Duration::from_secs(1));
        assert_eq!(a.wait(), MAX_WAIT);
    }

    #[test]
    fn adopts_busiest_consecutive_group() {
        let mut m = TileMap::default();
        m.first_packet = Some(Instant::now() - Duration::from_secs(1));
        for s in [10u32, 11, 12, 13, 50, 51, 52, 53] {
            for _ in 0..if s >= 50 { 20 } else { 6 } {
                m.count_packet(s);
            }
        }
        m.stash(AccessUnit { ssrc: 51, nalus: vec![], donl: None, complete: true, received: Instant::now() });
        let replay = m.try_adopt(4, false).unwrap();
        assert_eq!(m.ssrcs(), &[50, 51, 52, 53]);
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].0, 1);
        assert!(m.try_adopt(4, false).is_none());
        // A switch moves to the other group and blacklists the first.
        assert!(m.try_adopt(4, true).is_some());
        assert_eq!(m.ssrcs(), &[10, 11, 12, 13]);
    }
}
