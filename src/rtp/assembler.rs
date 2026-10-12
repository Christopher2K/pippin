//! Groups RTP packets into access units and maps SSRCs to screen tiles.
//!
//! The host splits each frame into N horizontal tiles, each its own SSRC
//! with consecutive SSRC values; the lowest SSRC is the top tile. After a
//! re-negotiation (e.g. a resize) a fresh group of SSRCs appears and the old
//! one goes quiet, so the mapping is re-learned from traffic.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use super::hevc;
use super::srtp::RtpPacket;

const GROUP_TTL: Duration = Duration::from_millis(200);
const FLUSHED_TTL: Duration = Duration::from_secs(2);
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

#[derive(Default)]
pub struct Assembler {
    groups: HashMap<(u32, u32), Group>,
    flushed: HashMap<(u32, u32), Instant>,
    last_marker: HashMap<u32, u16>,
}

impl Assembler {
    /// Adds a packet; returns the access unit once its marker arrives.
    pub fn push(&mut self, pkt: RtpPacket) -> Option<AccessUnit> {
        let key = (pkt.ssrc, pkt.ts);
        if self.flushed.contains_key(&key) {
            return None;
        }
        let g = self.groups.entry(key).or_insert_with(|| Group { packets: Vec::new(), started: Instant::now() });
        if g.packets.iter().any(|p| p.0 == pkt.seq) {
            return None;
        }
        g.packets.push((pkt.seq, pkt.marker, pkt.payload));
        if !pkt.marker {
            return None;
        }
        let mut g = self.groups.remove(&key)?;
        self.flushed.insert(key, Instant::now());
        ordered(&mut g.packets);

        let contiguous = g.packets.windows(2).all(|w| w[1].0 == w[0].0.wrapping_add(1));
        let ends_on_marker = g.packets.last().is_some_and(|p| p.1);
        let starts_after_prev = self
            .last_marker
            .get(&pkt.ssrc)
            .is_none_or(|&m| g.packets[0].0 == m.wrapping_add(1));
        if let Some(last) = g.packets.iter().rev().find(|p| p.1) {
            self.last_marker.insert(pkt.ssrc, last.0);
        }
        let complete = contiguous && ends_on_marker && starts_after_prev;

        let refs: Vec<(u16, &[u8])> = g.packets.iter().map(|p| (p.0, p.2.as_slice())).collect();
        let mut nalus = hevc::depayload(&refs);
        if !complete {
            nalus.retain(|n| hevc::is_param_set(n));
        }
        Some(AccessUnit { ssrc: pkt.ssrc, nalus, donl: hevc::first_donl(&refs), complete, received: g.started })
    }

    /// Drops groups whose marker never arrived. Returns their SSRCs.
    pub fn evict(&mut self, now: Instant) -> Vec<u32> {
        let mut lost = Vec::new();
        self.groups.retain(|&(ssrc, _), g| {
            let keep = now.duration_since(g.started) < GROUP_TTL;
            if !keep {
                lost.push(ssrc);
            }
            keep
        });
        for ssrc in &lost {
            // The next group cannot be proven contiguous with a lost one.
            self.last_marker.remove(ssrc);
        }
        self.flushed.retain(|_, t| now.duration_since(*t) < FLUSHED_TTL);
        lost
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

    #[test]
    fn groups_out_of_order_and_detects_loss() {
        let mut a = Assembler::default();
        assert!(a.push(pkt(1, 6, 90, false, single(1))).is_none());
        // The marker is on seq 5 but seq 6 sorts after it, so the group does
        // not end on its marker.
        let au = a.push(pkt(1, 5, 90, true, single(19))).unwrap();
        assert!(!au.complete);

        let mut a = Assembler::default();
        assert!(a.push(pkt(7, 65535, 1, false, single(19))).is_none());
        let au = a.push(pkt(7, 0, 1, true, single(19))).unwrap();
        assert!(au.complete);
        assert_eq!(au.nalus.len(), 2);
        // Next AU skips seq 1 -> incomplete, slices dropped.
        let au = a.push(pkt(7, 2, 2, true, single(1))).unwrap();
        assert!(!au.complete);
        assert!(au.nalus.is_empty());
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
