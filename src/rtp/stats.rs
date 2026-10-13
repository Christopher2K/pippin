//! RFC 3550 receiver statistics for one media source: sequence tracking
//! (A.1), loss (A.3) and interarrival jitter (A.8), as reported in RR blocks.
//!
//! Unlike A.1, only unique packets count as received: duplicates and
//! retransmissions of packets already seen are recognized within a window
//! behind the highest sequence number and ignored, and anything older than
//! that (or older than the first packet) is ignored too. Received therefore
//! never exceeds expected and cumulative loss is never negative. A
//! retransmission that fills a hole does count, so loss the NACKs repaired
//! is not reported.

use std::time::Duration;

/// RTP clock of the video streams.
pub const VIDEO_CLOCK_HZ: u64 = 90_000;

/// A forward jump of at least this many sequence numbers is taken as a
/// possible source restart rather than loss (RFC 3550 A.1).
const MAX_DROPOUT: u16 = 3000;
/// Packets up to this far behind the highest sequence number are late or
/// duplicate rather than a restart. Larger than A.1's 100 so a burst of NACK
/// retransmissions isn't mistaken for a new sequence.
const MAX_MISORDER: u16 = 1000;
/// Sequence numbers remembered behind the highest one for duplicate
/// detection; must cover MAX_MISORDER.
const WINDOW: usize = 1024;

/// Largest cumulative loss a report block can carry (24-bit signed).
const MAX_CUMULATIVE_LOST: i64 = 0x7f_ffff;

/// Values for one RR report block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Report {
    /// Lost fraction since the previous report, as a fixed-point /256.
    pub fraction_lost: u8,
    /// Packets lost since the first one, clamped to 0..=0x7fffff.
    pub cumulative_lost: i32,
    pub extended_seq: u32,
    /// Interarrival jitter in RTP timestamp units.
    pub jitter: u32,
}

/// Statistics for one SSRC.
pub struct ReceiverStats {
    /// Highest extended sequence number seen.
    max: i64,
    /// Extended sequence number of the first packet.
    base: i64,
    /// Sequence number after a suspected restart; a packet carrying it
    /// confirms the restart.
    bad_seq: Option<u16>,
    received: u64,
    expected_prior: u64,
    received_prior: u64,
    /// Bit per sequence number in the window behind `max`.
    seen: [u64; WINDOW / 64],
    /// Previous relative transit time, in RTP units.
    transit: Option<u32>,
    /// Jitter ×16 in RTP units (A.8's integer form).
    jitter16: u32,
}

impl ReceiverStats {
    /// Starts tracking at the first packet received.
    pub fn new(seq: u16, ts: u32, arrival: Duration) -> Self {
        let mut s = Self {
            max: 0,
            base: 0,
            bad_seq: None,
            received: 0,
            expected_prior: 0,
            received_prior: 0,
            seen: [0; WINDOW / 64],
            transit: None,
            jitter16: 0,
        };
        s.restart(seq);
        s.update_jitter(ts, arrival);
        s
    }

    fn restart(&mut self, seq: u16) {
        self.max = seq as i64;
        self.base = seq as i64;
        self.bad_seq = None;
        self.received = 1;
        self.expected_prior = 0;
        self.received_prior = 0;
        self.seen = [0; WINDOW / 64];
        self.mark(self.max);
    }

    fn bit(ext: i64) -> (usize, u64) {
        let i = ext.rem_euclid(WINDOW as i64) as usize;
        (i / 64, 1 << (i % 64))
    }

    fn mark(&mut self, ext: i64) {
        let (w, b) = Self::bit(ext);
        self.seen[w] |= b;
    }

    /// Records a packet's sequence number, RTP timestamp and arrival time
    /// (from any fixed origin).
    pub fn record(&mut self, seq: u16, ts: u32, arrival: Duration) {
        let max16 = self.max as u16;
        let ahead = seq.wrapping_sub(max16);
        if ahead == 0 {
            // Duplicate of the highest.
        } else if ahead < MAX_DROPOUT {
            let ext = self.max + ahead as i64;
            // Forget the window slots the new range reuses.
            if ahead as usize >= WINDOW {
                self.seen = [0; WINDOW / 64];
            } else {
                for e in self.max + 1..ext {
                    let (w, b) = Self::bit(e);
                    self.seen[w] &= !b;
                }
            }
            self.max = ext;
            self.bad_seq = None;
            self.mark(ext);
            self.received += 1;
            self.update_jitter(ts, arrival);
        } else if ahead <= u16::MAX - MAX_MISORDER + 1 {
            // A big jump: the sender may have restarted. Believe it once the
            // next packet follows on.
            if self.bad_seq == Some(seq) {
                self.restart(seq);
                self.transit = None;
                self.update_jitter(ts, arrival);
            } else {
                self.bad_seq = Some(seq.wrapping_add(1));
            }
        } else {
            // Late or duplicate. Not used for jitter: a retransmission's
            // transit time says nothing about the path.
            let ext = self.max - max16.wrapping_sub(seq) as i64;
            if ext < self.base {
                return;
            }
            let (w, b) = Self::bit(ext);
            if self.seen[w] & b == 0 {
                self.seen[w] |= b;
                self.received += 1;
            }
        }
    }

    /// A.8, for packets that advance the sequence.
    fn update_jitter(&mut self, ts: u32, arrival: Duration) {
        let arrival = (arrival.as_nanos() * VIDEO_CLOCK_HZ as u128 / 1_000_000_000) as u32;
        let transit = arrival.wrapping_sub(ts);
        if let Some(prev) = self.transit.replace(transit) {
            let d = (transit.wrapping_sub(prev) as i32).unsigned_abs();
            self.jitter16 = self.jitter16.wrapping_add(d).wrapping_sub((self.jitter16 + 8) >> 4);
        }
    }

    pub fn expected(&self) -> u64 {
        (self.max - self.base + 1) as u64
    }

    pub fn received(&self) -> u64 {
        self.received
    }

    pub fn extended_seq(&self) -> u32 {
        self.max as u32
    }

    /// Interarrival jitter in RTP units.
    pub fn jitter(&self) -> u32 {
        self.jitter16 >> 4
    }

    /// Builds a report block and starts the next fraction-lost interval
    /// (A.3).
    pub fn report(&mut self) -> Report {
        let expected = self.expected();
        let lost = expected as i64 - self.received as i64;
        let expected_interval = expected - self.expected_prior;
        let lost_interval = expected_interval as i64 - (self.received - self.received_prior) as i64;
        self.expected_prior = expected;
        self.received_prior = self.received;
        let fraction_lost = if expected_interval == 0 || lost_interval <= 0 {
            0
        } else {
            ((lost_interval << 8) / expected_interval as i64).min(255) as u8
        };
        Report {
            fraction_lost,
            cumulative_lost: lost.clamp(0, MAX_CUMULATIVE_LOST) as i32,
            extended_seq: self.extended_seq(),
            jitter: self.jitter(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn feed(seqs: impl IntoIterator<Item = u16>) -> ReceiverStats {
        let mut it = seqs.into_iter();
        let mut s = ReceiverStats::new(it.next().unwrap(), 0, Duration::ZERO);
        for seq in it {
            s.record(seq, 0, Duration::ZERO);
        }
        s
    }

    #[test]
    fn no_loss() {
        let mut s = feed(100..200);
        let r = s.report();
        assert_eq!((r.fraction_lost, r.cumulative_lost, r.extended_seq), (0, 0, 199));
        assert_eq!(s.expected(), 100);
    }

    #[test]
    fn gaps_and_fraction() {
        // 4 lost out of 16 expected.
        let mut s = feed((0..16).filter(|n| ![3, 4, 9, 12].contains(n)));
        let r = s.report();
        assert_eq!(r.cumulative_lost, 4);
        assert_eq!(r.fraction_lost, 64);
        // Next interval: 8 more, 2 lost.
        for n in (16..24).filter(|n| ![17, 20].contains(n)) {
            s.record(n, 0, Duration::ZERO);
        }
        let r = s.report();
        assert_eq!(r.cumulative_lost, 6);
        assert_eq!(r.fraction_lost, 64);
        // Nothing new: no fraction.
        assert_eq!(s.report().fraction_lost, 0);
    }

    #[test]
    fn late_packet_repairs_loss() {
        let mut s = feed([0, 1, 3, 4]);
        assert_eq!(s.report().cumulative_lost, 1);
        s.record(2, 0, Duration::ZERO);
        let r = s.report();
        assert_eq!(r.cumulative_lost, 0);
        // The interval received more than it expected; fraction stays 0.
        assert_eq!(r.fraction_lost, 0);
    }

    #[test]
    fn duplicates_ignored() {
        let mut s = feed([0, 1, 1, 2, 4, 4, 2, 0]);
        assert_eq!(s.received(), 4);
        let r = s.report();
        assert_eq!(r.cumulative_lost, 1);
        assert_eq!(r.fraction_lost, 51); // 1/5
    }

    #[test]
    fn before_first_packet_ignored() {
        let mut s = feed([10, 11, 9, 12]);
        assert_eq!(s.report().cumulative_lost, 0);
        assert_eq!(s.received(), 3);
    }

    #[test]
    fn wraparound() {
        let seqs = (65530..=65535).chain(0..10).filter(|&n| n != 65535 && n != 2);
        let mut s = feed(seqs);
        let r = s.report();
        assert_eq!(r.extended_seq, 0x1_0009);
        assert_eq!(r.cumulative_lost, 2);
        assert_eq!(s.expected(), 16);
        // A late packet from before the wrap is still recognized.
        s.record(65535, 0, Duration::ZERO);
        assert_eq!(s.report().cumulative_lost, 1);
        // And a duplicate of one is not counted twice.
        s.record(65535, 0, Duration::ZERO);
        assert_eq!(s.report().cumulative_lost, 1);
    }

    #[test]
    fn window_slots_reused_after_gap() {
        // Window slots wrap; marks left by earlier sequence numbers must not
        // make the skipped ones look received.
        let mut s = feed([0, 1, 2]);
        s.record(1500, 0, Duration::ZERO); // clears the whole window
        s.record(1025, 0, Duration::ZERO); // slot of seq 1
        assert_eq!(s.received(), 5);
        let mut s = feed([0, 1, 2, 1000]);
        s.record(1030, 0, Duration::ZERO); // clears slots 1001..1029
        s.record(1025, 0, Duration::ZERO);
        s.record(1026, 0, Duration::ZERO);
        assert_eq!(s.received(), 7);
        assert_eq!(s.report().cumulative_lost, 1031 - 7);
    }

    #[test]
    fn restart_after_big_jump() {
        let mut s = feed([0, 1, 2]);
        s.record(40_000, 0, Duration::ZERO);
        assert_eq!(s.expected(), 3); // one stray packet is ignored
        s.record(40_001, 0, Duration::ZERO);
        let r = s.report();
        assert_eq!(r.extended_seq, 40_001);
        assert_eq!(r.cumulative_lost, 0);
    }

    #[test]
    fn retransmission_burst_is_not_restart() {
        let mut s = feed((0..600).filter(|n| !(100..110).contains(n)));
        for n in 100..110 {
            s.record(n, 0, Duration::ZERO);
        }
        assert_eq!(s.report().cumulative_lost, 0);
        assert_eq!(s.extended_seq(), 599);
    }

    #[test]
    fn cumulative_clamped() {
        let mut s = feed([0]);
        s.received = 0;
        s.max = MAX_CUMULATIVE_LOST + 10;
        assert_eq!(s.report().cumulative_lost, 0x7f_ffff);
    }

    #[test]
    fn jitter_constant_transit_is_zero() {
        // 30 fps: 3000 ticks per frame, arriving exactly 33.33 ms apart.
        let mut s = ReceiverStats::new(0, 1000, Duration::from_millis(50));
        for i in 1..200u32 {
            let at = Duration::from_millis(50) + Duration::from_nanos(i as u64 * 33_333_333);
            s.record(i as u16, 1000 + i * 3000, at);
        }
        assert!(s.jitter() <= 1, "jitter {}", s.jitter());
    }

    #[test]
    fn jitter_varying_transit() {
        // Transit alternates by 10 ms (900 ticks), so |D| is always 900 and
        // the estimate converges on it.
        let mut s = ReceiverStats::new(0, 0, Duration::ZERO);
        for i in 1..500u32 {
            let delay = if i % 2 == 0 { Duration::ZERO } else { MS * 10 };
            s.record(i as u16, i * 3000, Duration::from_nanos(i as u64 * 33_333_333) + delay);
        }
        let j = s.jitter();
        assert!((880..=900).contains(&j), "jitter {j}");
    }
}
