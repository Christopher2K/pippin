//! Groups RTP packets into access units and maps SSRCs to screen tiles.
//!
//! The host splits each frame into N horizontal tiles, each its own SSRC
//! with consecutive SSRC values; the lowest SSRC is the top tile. After a
//! re-negotiation (e.g. a resize) a fresh group of SSRCs appears and the old
//! one goes quiet, so the mapping is re-learned from traffic.
//!
//! An access unit whose marker arrived with packets missing is held for a
//! short wait so NACK retransmissions and reordered packets can fill it,
//! instead of being given up at once (which costs a keyframe).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use super::srtp::RtpPacket;
use crate::codec::Codec;

/// How often the receiver should call [`Assembler::evict`] (and retry
/// NACKs) while anything is pending.
pub const POLL_EVERY: Duration = Duration::from_millis(5);
/// A group whose marker hasn't arrived, with nothing after it in decode
/// order, is given up after this long without a packet.
const GROUP_TTL: Duration = Duration::from_millis(200);
const FLUSHED_TTL: Duration = Duration::from_secs(2);
/// Round trip assumed until the host reports one.
const DEFAULT_RTT: Duration = Duration::from_millis(25);
/// Host turnaround for a retransmission, plus jitter and reordering.
const TURNAROUND: Duration = Duration::from_millis(10);
/// Upper bound on the hold, whatever the round-trip estimate says. (The
/// floor is two turnarounds plus a poll, 25 ms.)
const MAX_WAIT: Duration = Duration::from_millis(300);
/// A group without its marker, with later traffic in its decode order, that
/// has had no packet for this long lost its tail rather than still arriving.
const QUIET: Duration = Duration::from_millis(10);
/// This many packets in a row behind an SSRC's last marker means its
/// sequence numbers restarted rather than stragglers arriving.
const STALE_RESET: u32 = 256;
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
    /// Complete only because a hold let retransmissions or late packets in.
    pub recovered: bool,
    pub received: Instant,
}

/// Hold outcomes since the last [`Assembler::take_stats`].
#[derive(Default, Clone, Copy)]
pub struct HoldStats {
    pub started: u32,
    pub filled: u32,
    pub given_up: u32,
    /// Complete linked access units whose DONL was behind the previous one
    /// emitted: nonzero means DONL is not one counter across the tiles.
    pub donl_backwards: u32,
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
    /// DONL of the earliest packet: the host's decode order across SSRCs.
    donl: Option<u16>,
    /// Was waited on for missing packets.
    held: bool,
}

impl Group {
    fn new(now: Instant) -> Self {
        Self { packets: Vec::new(), started: now, last_at: now, first: 0, last: 0, marker: None, donl: None, held: false }
    }

    fn insert(&mut self, seq: u16, marker: bool, payload: Vec<u8>, now: Instant, codec: Codec) {
        let earliest = self.packets.is_empty() || seq.wrapping_sub(self.first) >= 0x8000;
        if self.packets.is_empty() || (!earliest && seq.wrapping_sub(self.last) < 0x8000) {
            self.last = seq;
        }
        if earliest {
            self.first = seq;
            self.donl = codec.first_donl(&[(seq, payload.as_slice())]);
        }
        if marker {
            self.marker = Some((seq, now));
        }
        self.last_at = now;
        self.packets.push((seq, marker, payload));
    }

    /// Payloads in sequence order.
    fn payloads(&self) -> Vec<(u16, &[u8])> {
        let mut refs: Vec<(u16, &[u8])> = self.packets.iter().map(|p| (p.0, p.2.as_slice())).collect();
        refs.sort_by_key(|r| r.0.wrapping_sub(self.first));
        refs
    }
}

/// Whether group `a` (of SSRC `sa`) comes before `b` in decode order.
///
/// Within an SSRC that is sequence order. Across SSRCs it is DONL order:
/// Apple numbers access units across all tiles of the coded sequence, and
/// unlike arrival order that survives network reordering and a lost first
/// packet (every packet, FU fragments included, carries the DONL). Equal
/// DONLs fall back to tile order, missing ones (H.264 has none) to arrival.
fn before(sa: u32, a: &Group, sb: u32, b: &Group) -> bool {
    if sa == sb {
        return a.first.wrapping_sub(b.first) >= 0x8000;
    }
    match (a.donl, b.donl) {
        (Some(x), Some(y)) if x != y => x.wrapping_sub(y) >= 0x8000,
        (Some(_), Some(_)) => sa < sb,
        _ => a.started < b.started,
    }
}

/// Whether contiguous payloads that may lack whatever came before them make
/// a decodable IRAP access unit: the first packet starts a NAL, and the
/// first slice is an IRAP slice that begins its picture. Parameter sets
/// before it are kept if present; if they were lost the decoder uses the
/// ones it has, which mid-stream on one SSRC are current (a parameter
/// change comes with a new SSRC group, where nothing precedes the IRAP).
fn whole_irap(codec: Codec, payloads: &[(u16, &[u8])]) -> bool {
    let Some((_, p)) = payloads.first() else { return false };
    if codec.continues_nal(p) {
        return false;
    }
    codec
        .depayload(payloads)
        .iter()
        .find(|n| codec.is_slice(n))
        .is_some_and(|n| codec.is_irap(n) && codec.first_in_picture(n))
}

/// What to do with the first pending group in decode order.
enum Verdict {
    /// Not ready; `holding` if that is for missing packets rather than the
    /// rest of the access unit still arriving.
    Wait { holding: bool },
    Emit { complete: bool },
}

/// Access units leave in decode order: per SSRC, and across the adopted
/// tiles, which share one decoder and reference each other's pictures. When
/// the first one is held for missing packets, later ones (even complete)
/// wait behind it: decoding them first would decode against a missing
/// reference, and giving up on it to release them sooner would cost a
/// keyframe anyway. Their extra latency is bounded by the hold. SSRCs not
/// adopted are ordered on their own and never block the tiles.
pub struct Assembler {
    codec: Codec,
    groups: HashMap<(u32, u32), Group>,
    flushed: HashMap<(u32, u32), Instant>,
    last_marker: HashMap<u32, u16>,
    /// Packets dropped in a row per SSRC for being behind its last marker.
    stale: HashMap<u32, u32>,
    /// The adopted tile SSRCs, ordered together.
    linked: HashSet<u32>,
    rtt: Duration,
    stats: HoldStats,
    /// DONL of the last complete linked access unit emitted.
    last_linked_donl: Option<u16>,
}

impl Default for Assembler {
    fn default() -> Self {
        Self {
            codec: Codec::default(),
            groups: HashMap::new(),
            flushed: HashMap::new(),
            last_marker: HashMap::new(),
            stale: HashMap::new(),
            linked: HashSet::new(),
            rtt: DEFAULT_RTT,
            stats: HoldStats::default(),
            last_linked_donl: None,
        }
    }
}

impl Assembler {
    pub fn new(codec: Codec) -> Self {
        Self { codec, ..Default::default() }
    }

    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// Orders these SSRCs' access units together (the adopted tiles).
    pub fn link(&mut self, ssrcs: &[u32]) {
        self.linked = ssrcs.iter().copied().collect();
        self.last_linked_donl = None;
    }

    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }

    /// When a NACK still unanswered should be sent again: about a round
    /// trip after the first.
    pub fn retry_after(&self) -> Duration {
        self.rtt + TURNAROUND
    }

    /// How long an access unit with missing packets is held after its
    /// marker: room for the NACK, one retry and its answer, plus a poll.
    pub fn wait(&self) -> Duration {
        (self.retry_after() * 2 + POLL_EVERY).min(MAX_WAIT)
    }

    /// Something is in progress, so [`evict`](Self::evict) has work to do.
    pub fn pending(&self) -> bool {
        !self.groups.is_empty()
    }

    pub fn take_stats(&mut self) -> HoldStats {
        std::mem::take(&mut self.stats)
    }

    /// Adds a packet; returns the access units it releases, in decode order.
    pub fn push(&mut self, pkt: RtpPacket, now: Instant) -> Vec<AccessUnit> {
        let key = (pkt.ssrc, pkt.ts);
        if self.flushed.contains_key(&key) {
            return Vec::new();
        }
        if let Some(&m) = self.last_marker.get(&pkt.ssrc)
            && pkt.seq.wrapping_sub(m.wrapping_add(1)) >= 0x8000
        {
            // Behind the last emitted access unit: a straggler for one
            // already emitted or given up.
            let n = self.stale.entry(pkt.ssrc).or_default();
            *n += 1;
            if *n < STALE_RESET {
                return Vec::new();
            }
            self.last_marker.remove(&pkt.ssrc);
        }
        self.stale.remove(&pkt.ssrc);
        let g = self.groups.entry(key).or_insert_with(|| Group::new(now));
        if g.packets.iter().any(|p| p.0 == pkt.seq) {
            return Vec::new();
        }
        g.insert(pkt.seq, pkt.marker, pkt.payload, now, self.codec);
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
    /// that were queued behind them.
    pub fn evict(&mut self, now: Instant) -> Vec<AccessUnit> {
        let mut ssrcs: HashSet<u32> = self.groups.keys().map(|k| k.0).collect();
        if let Some(&any) = ssrcs.iter().find(|s| self.linked.contains(s)) {
            ssrcs.retain(|s| *s == any || !self.linked.contains(s));
        }
        let mut out = Vec::new();
        for ssrc in ssrcs {
            self.release(ssrc, now, &mut out);
        }
        self.flushed.retain(|_, t| now.duration_since(*t) < FLUSHED_TTL);
        out
    }

    fn same_order(&self, a: u32, b: u32) -> bool {
        a == b || (self.linked.contains(&a) && self.linked.contains(&b))
    }

    /// The pending group ordered with `ssrc` that comes first.
    fn head(&self, ssrc: u32) -> Option<(u32, u32)> {
        self.groups
            .iter()
            .filter(|(k, _)| self.same_order(k.0, ssrc))
            .reduce(|a, b| if before(b.0.0, b.1, a.0.0, a.1) { b } else { a })
            .map(|(k, _)| *k)
    }

    fn verdict(&self, key: (u32, u32), now: Instant) -> Verdict {
        let g = &self.groups[&key];
        let Some((mseq, marker_at)) = g.marker else {
            // The marker is missing. Once later traffic shows the group's
            // tail was lost, allow the same wait for a retransmission.
            let later = self
                .groups
                .iter()
                .filter(|(k, _)| **k != key && self.same_order(k.0, key.0))
                .map(|(_, o)| o.started)
                .min();
            let deadline = match later {
                Some(t) => t.max(g.last_at) + self.wait(),
                None => g.last_at + GROUP_TTL,
            };
            if now >= deadline {
                return Verdict::Emit { complete: false };
            }
            // Only a detected gap, or a group gone quiet while later ones
            // arrive, is a hold; otherwise it is still arriving.
            let gap = g.packets.len() != g.last.wrapping_sub(g.first) as usize + 1
                || self.last_marker.get(&key.0).is_some_and(|&m| g.first != m.wrapping_add(1));
            let holding = later.is_some() && (gap || now >= g.last_at + QUIET);
            return Verdict::Wait { holding };
        };
        if g.last != mseq {
            // A packet after the marker in the same group: no retransmission
            // will make this whole.
            return Verdict::Emit { complete: false };
        }
        let contiguous = g.packets.len() == mseq.wrapping_sub(g.first) as usize + 1;
        let starts_after_prev = self.last_marker.get(&key.0).is_none_or(|&m| g.first == m.wrapping_add(1));
        // An IRAP resets the shared DPB, so whatever came before it no
        // longer matters, as long as the access unit itself is whole from
        // its first slice.
        if contiguous && (starts_after_prev || whole_irap(self.codec, &g.payloads())) {
            Verdict::Emit { complete: true }
        } else if now >= marker_at + self.wait() {
            Verdict::Emit { complete: false }
        } else {
            Verdict::Wait { holding: true }
        }
    }

    /// Emits groups in decode order for as long as the first is ready.
    fn release(&mut self, ssrc: u32, now: Instant, out: &mut Vec<AccessUnit>) {
        while let Some(key) = self.head(ssrc) {
            match self.verdict(key, now) {
                Verdict::Wait { holding } => {
                    if let Some(g) = self.groups.get_mut(&key)
                        && holding
                        && !g.held
                    {
                        g.held = true;
                        self.stats.started += 1;
                    }
                    break;
                }
                Verdict::Emit { complete } => out.push(self.emit(key, complete, now)),
            }
        }
    }

    fn emit(&mut self, key: (u32, u32), complete: bool, now: Instant) -> AccessUnit {
        let g = self.groups.remove(&key).expect("emitted group exists");
        self.flushed.insert(key, now);
        if g.held {
            if complete {
                self.stats.filled += 1;
            } else {
                self.stats.given_up += 1;
            }
        }
        // Without a marker the end is unknown; the next group must start
        // after everything seen so far to count as contiguous. Never move
        // backwards.
        let end = g.marker.map_or(g.last, |m| m.0);
        match self.last_marker.get(&key.0) {
            Some(&m) if end.wrapping_sub(m) >= 0x8000 => {}
            _ => {
                self.last_marker.insert(key.0, end);
            }
        }
        let refs = g.payloads();
        let mut nalus = self.codec.depayload(&refs);
        if !complete {
            nalus.retain(|n| self.codec.is_param_set(n));
        }
        let donl = self.codec.first_donl(&refs);
        if complete
            && self.linked.contains(&key.0)
            && let Some(d) = donl
        {
            if self.last_linked_donl.is_some_and(|p| d.wrapping_sub(p) >= 0x8000) {
                self.stats.donl_backwards += 1;
            }
            self.last_linked_donl = Some(d);
        }
        AccessUnit {
            ssrc: key.0,
            nalus,
            donl,
            complete,
            recovered: complete && g.held,
            received: g.started,
        }
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
    #[cfg(test)]
    pub fn with_tiles(tiles: Vec<u32>) -> Self {
        Self { tiles, ..Default::default() }
    }

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
    use crate::rtp::{h264, hevc};

    fn pkt(ssrc: u32, seq: u16, ts: u32, marker: bool, payload: Vec<u8>) -> RtpPacket {
        RtpPacket { ssrc, seq, ts, marker, pt: 100, payload }
    }

    fn single(t: u8) -> Vec<u8> {
        vec![t << 1, 1, 0, 1, 0xee]
    }

    /// A trailing-slice single NAL with this DONL.
    fn slice(donl: u16) -> Vec<u8> {
        let d = donl.to_be_bytes();
        vec![1 << 1, 1, d[0], d[1], 0xee]
    }

    fn vps() -> Vec<u8> {
        vec![hevc::NAL_VPS << 1, 1, 0, 1, 0xaa]
    }

    /// A fragment of an IDR slice; `first` sets first_slice_segment_in_pic.
    fn idr_fu(flags: u8, first: bool) -> Vec<u8> {
        vec![49 << 1, 1, flags | 19, 0, 1, if first { 0x80 } else { 0x40 }, 0xcc]
    }

    fn one(mut aus: Vec<AccessUnit>) -> AccessUnit {
        assert_eq!(aus.len(), 1);
        aus.pop().unwrap()
    }

    fn order(aus: &[AccessUnit]) -> Vec<(u32, bool)> {
        aus.iter().map(|au| (au.ssrc, au.complete)).collect()
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
        assert!(aus[0].recovered && !aus[1].recovered);
        assert_eq!(aus[0].nalus.len(), 3);
        assert_eq!(aus[1].nalus.len(), 2);
        // A duplicate retransmission is ignored.
        assert!(a.push(pkt(3, 11, 1, false, single(1)), t).is_empty());
        let s = a.take_stats();
        assert_eq!((s.started, s.filled, s.given_up), (1, 1, 0));
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
        let s = a.take_stats();
        assert_eq!((s.started, s.filled, s.given_up), (1, 0, 1));

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
    fn far_straggler_does_not_stall() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(2, 10000, 0, true, single(19)), t0)).complete);
        // Far behind the last marker: dropped, not made the head.
        assert!(a.push(pkt(2, 5000, 77, false, single(1)), t0).is_empty());
        assert!(!a.pending());
        assert!(one(a.push(pkt(2, 10001, 1, true, single(1)), t0)).complete);
        // A sequence restart is accepted once it is clearly not stragglers.
        let n = STALE_RESET as u16 - 1;
        for i in 0..n {
            assert!(a.push(pkt(2, 100 + i, 200 + i as u32, true, single(1)), t0).is_empty());
        }
        assert!(one(a.push(pkt(2, 100 + n, 200 + n as u32, true, single(1)), t0)).complete);
    }

    #[test]
    fn irap_after_lost_tail_is_complete() {
        for irap in [true, false] {
            let t0 = Instant::now();
            let mut a = Assembler::default();
            assert!(one(a.push(pkt(9, 9, 0, true, single(1)), t0)).complete);
            // Seq 12, this AU's tail and marker, is lost.
            assert!(a.push(pkt(9, 10, 1, false, single(1)), t0).is_empty());
            assert!(a.push(pkt(9, 11, 1, false, single(1)), t0).is_empty());
            let (p1, p2) = if irap { (idr_fu(0x80, true), idr_fu(0x40, true)) } else { (single(1), single(1)) };
            assert!(a.push(pkt(9, 13, 2, false, p1), t0).is_empty());
            assert!(a.push(pkt(9, 14, 2, true, p2), t0).is_empty());
            let aus = a.evict(t0 + a.wait());
            // The keyframe doesn't start right after a known marker, but it
            // resets the DPB, so it is complete regardless.
            assert_eq!(order(&aus), vec![(9, false), (9, irap)]);
        }
    }

    #[test]
    fn hold_orders_across_linked_tiles() {
        let t0 = Instant::now();
        for fill in [true, false] {
            let mut a = Assembler::default();
            a.link(&[10, 11, 12]);
            // Frame N: tile 10 complete, tile 11 missing seq 2, tile 12 complete.
            assert!(one(a.push(pkt(10, 1, 1, true, slice(100)), t0)).complete);
            assert!(a.push(pkt(11, 1, 1, false, slice(101)), t0).is_empty());
            assert!(a.push(pkt(11, 3, 1, true, slice(101)), t0).is_empty());
            assert!(a.push(pkt(12, 1, 1, true, slice(102)), t0).is_empty());
            // Frame N+1's base tile waits too.
            assert!(a.push(pkt(10, 2, 2, true, slice(103)), t0).is_empty());
            // A stream not adopted is not held up.
            assert!(one(a.push(pkt(99, 1, 1, true, slice(5)), t0)).complete);
            let aus = if fill {
                a.push(pkt(11, 2, 1, false, slice(101)), t0 + Duration::from_millis(10))
            } else {
                assert!(a.evict(t0 + a.wait() / 2).is_empty());
                a.evict(t0 + a.wait())
            };
            assert_eq!(order(&aus), vec![(11, fill), (12, true), (10, true)]);
        }

        // A tile that goes quiet mid-frame (marker lost, nothing after it on
        // its SSRC) is given up once the next tile shows it ended.
        let mut a = Assembler::default();
        a.link(&[10, 11, 12]);
        assert!(a.push(pkt(11, 1, 1, false, slice(101)), t0).is_empty());
        let t1 = t0 + Duration::from_millis(2);
        assert!(a.push(pkt(12, 1, 1, true, slice(102)), t1).is_empty());
        assert!(a.evict(t1 + a.wait() / 2).is_empty());
        assert_eq!(order(&a.evict(t1 + a.wait())), vec![(11, false), (12, true)]);
    }

    #[test]
    fn irap_missing_its_leading_slice_is_not_complete() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(9, 9, 0, true, single(1)), t0)).complete);
        // The IDR's first slice (seq 10-11) is lost; its second slice,
        // seq 12-13, arrives whole.
        assert!(a.push(pkt(9, 12, 1, false, idr_fu(0x80, false)), t0).is_empty());
        assert!(a.push(pkt(9, 13, 1, true, idr_fu(0x40, false)), t0).is_empty());
        assert_eq!(order(&a.evict(t0 + a.wait())), vec![(9, false)]);

        // Same with only the tail of the first slice's fragments.
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(9, 9, 0, true, single(1)), t0)).complete);
        assert!(a.push(pkt(9, 11, 1, false, idr_fu(0, true)), t0).is_empty());
        assert!(a.push(pkt(9, 12, 1, true, idr_fu(0x40, true)), t0).is_empty());
        assert_eq!(order(&a.evict(t0 + a.wait())), vec![(9, false)]);

        // Parameter sets lost but the first slice whole: complete at once.
        let mut a = Assembler::default();
        assert!(one(a.push(pkt(9, 9, 0, true, single(1)), t0)).complete);
        assert!(a.push(pkt(9, 11, 1, false, idr_fu(0x80, true)), t0).is_empty());
        assert!(one(a.push(pkt(9, 12, 1, true, idr_fu(0x40, true)), t0)).complete);
    }

    #[test]
    fn arriving_access_unit_is_not_a_hold() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut a = Assembler::default();
        a.link(&[10, 11]);
        // Tile 10's AU is still arriving when tile 11's starts.
        assert!(a.push(pkt(10, 1, 1, false, slice(100)), t0).is_empty());
        assert!(a.push(pkt(11, 1, 1, false, slice(101)), t0).is_empty());
        assert!(a.push(pkt(10, 2, 1, false, slice(100)), ms(2)).is_empty());
        assert!(a.evict(ms(3)).is_empty());
        let au = one(a.push(pkt(10, 3, 1, true, slice(100)), ms(4)));
        assert!(au.complete && !au.recovered);
        let au = one(a.push(pkt(11, 2, 1, true, slice(101)), ms(4)));
        assert!(au.complete && !au.recovered);
        assert_eq!(a.take_stats().started, 0);

        // Gone quiet with later traffic: its marker was lost, so it is held.
        assert!(a.push(pkt(10, 4, 2, false, slice(102)), ms(10)).is_empty());
        assert!(a.push(pkt(11, 3, 2, true, slice(103)), ms(10)).is_empty());
        assert!(a.evict(ms(15)).is_empty());
        assert_eq!(a.take_stats().started, 0);
        assert!(a.evict(ms(20)).is_empty());
        assert_eq!(a.take_stats().started, 1);
        let aus = a.push(pkt(10, 5, 2, true, slice(102)), ms(25));
        assert_eq!(order(&aus), vec![(10, true), (11, true)]);
        assert!(aus[0].recovered && !aus[1].recovered);
    }

    #[test]
    fn counts_donl_going_backwards() {
        let t0 = Instant::now();
        let mut a = Assembler::default();
        a.link(&[10, 11]);
        assert!(one(a.push(pkt(10, 1, 1, true, slice(500)), t0)).complete);
        assert!(one(a.push(pkt(11, 1, 1, true, slice(501)), t0)).complete);
        assert_eq!(a.take_stats().donl_backwards, 0);
        // A counter per tile would show up as one tile's DONL far behind.
        assert!(one(a.push(pkt(11, 2, 2, true, slice(100)), t0)).complete);
        assert_eq!(a.take_stats().donl_backwards, 1);
        // Unlinked streams don't count.
        assert!(one(a.push(pkt(99, 1, 1, true, slice(1)), t0)).complete);
        assert_eq!(a.take_stats().donl_backwards, 0);
    }

    #[test]
    fn wait_follows_rtt() {
        let mut a = Assembler::default();
        assert_eq!(a.retry_after(), Duration::from_millis(35));
        assert_eq!(a.wait(), Duration::from_millis(75));
        // LAN: retry at 11 ms, answered by ~12 ms; given up at 27 ms.
        a.set_rtt(Duration::from_millis(1));
        assert_eq!(a.retry_after(), Duration::from_millis(11));
        assert_eq!(a.wait(), Duration::from_millis(27));
        a.set_rtt(Duration::ZERO);
        assert_eq!(a.retry_after(), Duration::from_millis(10));
        assert_eq!(a.wait(), Duration::from_millis(25));
        a.set_rtt(Duration::from_millis(100));
        assert_eq!(a.retry_after(), Duration::from_millis(110));
        assert_eq!(a.wait(), Duration::from_millis(225));
        a.set_rtt(Duration::from_millis(200));
        assert_eq!(a.wait(), Duration::from_millis(300));
    }

    /// An H.264 FU-A fragment of a type-1 slice: an I slice that begins
    /// its picture, an I slice that doesn't, or a P slice.
    fn h264_fu(flags: u8, kind: &str) -> Vec<u8> {
        // first_mb_in_slice and slice_type: 0 and 7, 3 and 7, or 0 and 5.
        let header: &[u8] = match kind {
            "I" => &[0b1000_1000],
            "I-later" => &[0b0010_0000, 0b1000_0000],
            _ => &[0b1001_1000],
        };
        let mut v = vec![0x60 | h264::NAL_FU_A, flags | 1];
        v.extend_from_slice(header);
        v.push(0xcc);
        v
    }

    /// Apple's 0x92 decoder configuration with a stand-in SPS and PPS.
    fn h264_config() -> Vec<u8> {
        let mut p = vec![h264::CONFIG_MARKER];
        p.extend_from_slice(b"avc1....avcC");
        p.extend_from_slice(&[1, 0x64, 0, 0x1f, 0xff, 0xe1, 0, 2, 0x67, 0x64, 1, 0, 2, 0x68, 0xeb]);
        p
    }

    #[test]
    fn h264_hold_fills_from_retransmission() {
        let t0 = Instant::now();
        let mut a = Assembler::new(Codec::H264);
        a.link(&[20]);
        let au = one(a.push(pkt(20, 1, 1, true, vec![0x65, 0x88, 0x84]), t0));
        assert!(au.complete && au.donl.is_none());
        // A P slice in three fragments; the middle one is lost, then resent.
        assert!(a.push(pkt(20, 2, 2, false, h264_fu(0x80, "P")), t0).is_empty());
        assert!(a.push(pkt(20, 4, 2, true, h264_fu(0x40, "P")), t0).is_empty());
        assert!(a.evict(t0 + a.wait() / 2).is_empty());
        let au = one(a.push(pkt(20, 3, 2, false, h264_fu(0, "P")), t0 + Duration::from_millis(10)));
        assert!(au.complete && au.recovered && au.donl.is_none());
        assert_eq!(au.nalus, vec![vec![0x61, 0b1001_1000, 0xcc, 0b1001_1000, 0xcc, 0b1001_1000, 0xcc]]);
        let s = a.take_stats();
        assert_eq!((s.started, s.filled, s.given_up, s.donl_backwards), (1, 1, 0, 0));

        // Given up: only the parameter sets from the config packet survive.
        assert!(a.push(pkt(20, 5, 3, false, h264_config()), t0).is_empty());
        assert!(a.push(pkt(20, 7, 3, true, h264_fu(0x40, "P")), t0).is_empty());
        let au = one(a.evict(t0 + a.wait()));
        assert!(!au.complete);
        assert_eq!(au.nalus, vec![vec![0x67, 0x64], vec![0x68, 0xeb]]);
    }

    #[test]
    fn h264_keyframe_after_lost_tail() {
        for (kind, config, whole) in [("I", false, true), ("I", true, true), ("I-later", false, false), ("P", false, false)] {
            let t0 = Instant::now();
            let mut a = Assembler::new(Codec::H264);
            assert!(one(a.push(pkt(9, 9, 0, true, h264_fu(0xc0, "P")), t0)).complete);
            // Seq 11, this AU's tail and marker, is lost.
            assert!(a.push(pkt(9, 10, 1, false, h264_fu(0x80, "P")), t0).is_empty());
            let mut seq = 12;
            if config {
                assert!(a.push(pkt(9, seq, 2, false, h264_config()), t0).is_empty());
                seq += 1;
            }
            assert!(a.push(pkt(9, seq, 2, false, h264_fu(0x80, kind)), t0).is_empty());
            assert!(a.push(pkt(9, seq + 1, 2, true, h264_fu(0x40, kind)), t0).is_empty());
            let aus = a.evict(t0 + a.wait());
            // An intra picture whole from its first slice needs nothing
            // before it.
            assert_eq!(order(&aus), vec![(9, false), (9, whole)], "{kind} config={config}");
            if whole {
                assert_eq!(aus[1].nalus.len(), 1 + 2 * config as usize);
            }
        }
    }

    #[test]
    fn adopts_busiest_consecutive_group() {
        let mut m = TileMap { first_packet: Some(Instant::now() - Duration::from_secs(1)), ..Default::default() };
        for s in [10u32, 11, 12, 13, 50, 51, 52, 53] {
            for _ in 0..if s >= 50 { 20 } else { 6 } {
                m.count_packet(s);
            }
        }
        m.stash(AccessUnit {
            ssrc: 51,
            nalus: vec![],
            donl: None,
            complete: true,
            recovered: false,
            received: Instant::now(),
        });
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
