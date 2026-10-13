//! RFC 3550 receiver statistics for one media source: loss (A.3) and
//! interarrival jitter (A.8), as reported in RR blocks.
//!
//! Packets are identified by their SRTP index (ROC << 16 | seq), which the
//! auth tag has already proven, so A.1's restart/dropout heuristics aren't
//! needed: a long outage is plain loss and the extended sequence number
//! never goes backwards.
//!
//! Unlike A.1, only unique packets count as received: duplicates and
//! retransmissions of packets already seen are recognized within a window
//! behind the highest index and ignored, and anything older than that (or
//! older than the first packet) is ignored too. Received therefore never
//! exceeds expected and cumulative loss is never negative. A retransmission
//! that fills a hole does count, so loss the NACKs repaired is not reported.

use std::time::Duration;

/// RTP clock of the video streams.
pub const VIDEO_CLOCK_HZ: u64 = 90_000;

/// Indexes remembered behind the highest one for duplicate detection.
const WINDOW: u64 = 1024;

/// Largest cumulative loss a report block can carry (24-bit signed).
const MAX_CUMULATIVE_LOST: i64 = 0x7f_ffff;

/// A transit-time change larger than this is a timestamp discontinuity
/// (encoder restart, long pause), not jitter; it only resets the baseline.
const MAX_TRANSIT_JUMP: u32 = 10 * VIDEO_CLOCK_HZ as u32;

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
    /// Highest SRTP index seen.
    max: u64,
    /// Index of the first packet.
    base: u64,
    received: u64,
    expected_prior: u64,
    received_prior: u64,
    /// Bit per index in the window behind `max`.
    seen: [u64; WINDOW as usize / 64],
    /// RTP timestamp of the last frame used for jitter.
    jitter_ts: Option<u32>,
    /// Previous relative transit time, in RTP units.
    transit: Option<u32>,
    /// Jitter ×16 in RTP units (A.8's integer form).
    jitter16: u32,
}

impl ReceiverStats {
    /// Starts tracking at the first packet received.
    pub fn new(index: u64, ts: u32, arrival: Duration) -> Self {
        let mut s = Self {
            max: index,
            base: index,
            received: 1,
            expected_prior: 0,
            received_prior: 0,
            seen: [0; WINDOW as usize / 64],
            jitter_ts: None,
            transit: None,
            jitter16: 0,
        };
        s.mark(index);
        s.update_jitter(ts, arrival);
        s
    }

    fn bit(index: u64) -> (usize, u64) {
        let i = (index % WINDOW) as usize;
        (i / 64, 1 << (i % 64))
    }

    fn mark(&mut self, index: u64) {
        let (w, b) = Self::bit(index);
        self.seen[w] |= b;
    }

    /// Records a packet's SRTP index, RTP timestamp and arrival time (from
    /// any fixed origin).
    pub fn record(&mut self, index: u64, ts: u32, arrival: Duration) {
        if index > self.max {
            // Forget the window slots the new range reuses.
            if index - self.max >= WINDOW {
                self.seen = [0; WINDOW as usize / 64];
            } else {
                for i in self.max + 1..index {
                    let (w, b) = Self::bit(i);
                    self.seen[w] &= !b;
                }
            }
            self.max = index;
            self.mark(index);
            self.received += 1;
            self.update_jitter(ts, arrival);
        } else if index >= self.base && self.max - index < WINDOW {
            // Late or duplicate. Not used for jitter: a retransmission's
            // transit time says nothing about the path.
            let (w, b) = Self::bit(index);
            if self.seen[w] & b == 0 {
                self.seen[w] |= b;
                self.received += 1;
            }
        }
    }

    /// A.8, once per frame. A tile's packets share the frame's timestamp but
    /// leave the host as a burst, so their spacing is pacing, not path
    /// jitter; only the first packet of each new timestamp counts (as in
    /// libwebrtc).
    fn update_jitter(&mut self, ts: u32, arrival: Duration) {
        if self.jitter_ts.replace(ts) == Some(ts) {
            return;
        }
        let arrival = (arrival.as_nanos() * VIDEO_CLOCK_HZ as u128 / 1_000_000_000) as u32;
        let transit = arrival.wrapping_sub(ts);
        if let Some(prev) = self.transit.replace(transit) {
            let d = (transit.wrapping_sub(prev) as i32).unsigned_abs();
            if d <= MAX_TRANSIT_JUMP {
                self.jitter16 = self.jitter16.wrapping_add(d).wrapping_sub(self.jitter16.wrapping_add(8) >> 4);
            }
        }
    }

    pub fn expected(&self) -> u64 {
        self.max - self.base + 1
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

    /// Feeds indexes with distinct timestamps and no arrival jitter.
    fn feed(indexes: impl IntoIterator<Item = u64>) -> ReceiverStats {
        let mut it = indexes.into_iter();
        let mut s = ReceiverStats::new(it.next().unwrap(), 0, Duration::ZERO);
        for i in it {
            s.record(i, 0, Duration::ZERO);
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
    fn rollover() {
        let roc = 1u64 << 16;
        let idx = (65530..=65535).chain(roc..roc + 10).filter(|&n| n != 65535 && n != roc + 2);
        let mut s = feed(idx);
        let r = s.report();
        assert_eq!(r.extended_seq, 0x1_0009);
        assert_eq!(r.cumulative_lost, 2);
        assert_eq!(s.expected(), 16);
        // A late packet from before the rollover is still recognized.
        s.record(65535, 0, Duration::ZERO);
        assert_eq!(s.report().cumulative_lost, 1);
        // And a duplicate of one is not counted twice.
        s.record(65535, 0, Duration::ZERO);
        assert_eq!(s.report().cumulative_lost, 1);
    }

    #[test]
    fn window_slots_reused_after_gap() {
        // Window slots wrap; marks left by earlier indexes must not make the
        // skipped ones look received.
        let mut s = feed([0, 1, 2]);
        s.record(1500, 0, Duration::ZERO); // clears the whole window
        s.record(1025, 0, Duration::ZERO); // slot of index 1
        assert_eq!(s.received(), 5);
        let mut s = feed([0, 1, 2, 1000]);
        s.record(1030, 0, Duration::ZERO); // clears slots 1001..1029
        s.record(1025, 0, Duration::ZERO);
        s.record(1026, 0, Duration::ZERO);
        assert_eq!(s.received(), 7);
        assert_eq!(s.report().cumulative_lost, 1031 - 7);
    }

    #[test]
    fn window_boundary() {
        let mut s = feed([0, 2000]);
        s.record(2000 - WINDOW + 1, 0, Duration::ZERO); // last slot in the window
        s.record(2000 - WINDOW, 0, Duration::ZERO); // just outside: ignored
        assert_eq!(s.received(), 3);
        assert_eq!(s.extended_seq(), 2000);
    }

    #[test]
    fn late_retransmissions_are_not_a_restart() {
        // Review repro: two consecutive retransmissions far behind used to
        // look like a sender restart.
        let mut s = feed((0..3000).filter(|n| ![100, 101].contains(n)));
        s.report();
        for i in [100, 101, 3000] {
            s.record(i, 0, Duration::ZERO);
        }
        let r = s.report();
        assert_eq!(r.extended_seq, 3000);
        assert_eq!((r.fraction_lost, r.cumulative_lost), (0, 2));
        // Retransmissions inside the window do repair loss.
        let mut s = feed((0..600).filter(|n| !(100..110).contains(n)));
        for n in 100..110 {
            s.record(n, 0, Duration::ZERO);
        }
        assert_eq!(s.report().cumulative_lost, 0);
        assert_eq!(s.extended_seq(), 599);
    }

    #[test]
    fn long_outage_is_loss() {
        // 5000 packets lost across a rollover: counted, and the extended
        // sequence keeps its cycle count.
        let start = (3u64 << 16) + 65000;
        let mut s = feed(start..start + 10);
        s.report();
        s.record(start + 5010, 0, Duration::ZERO);
        let r = s.report();
        assert_eq!(r.cumulative_lost, 5000);
        assert_eq!(r.fraction_lost, 255);
        assert_eq!(r.extended_seq, (start + 5010) as u32);
        assert!(r.extended_seq > (start + 9) as u32);
    }

    #[test]
    fn cumulative_clamped() {
        let mut s = feed([0]);
        s.record(MAX_CUMULATIVE_LOST as u64 + 10, 0, Duration::ZERO);
        assert_eq!(s.report().cumulative_lost, 0x7f_ffff);
    }

    #[test]
    fn jitter_constant_transit_is_zero() {
        // 30 fps: 3000 ticks per frame, arriving exactly 33.33 ms apart.
        let mut s = ReceiverStats::new(0, 1000, Duration::from_millis(50));
        for i in 1..200u32 {
            let at = Duration::from_millis(50) + Duration::from_nanos(i as u64 * 33_333_333);
            s.record(i as u64, 1000 + i * 3000, at);
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
            s.record(i as u64, i * 3000, Duration::from_nanos(i as u64 * 33_333_333) + delay);
        }
        let j = s.jitter();
        assert!((880..=900).contains(&j), "jitter {j}");
    }

    #[test]
    fn jitter_ignores_frame_burst() {
        // Each frame is 20 packets with one timestamp, spread over 5 ms on
        // arrival; frames themselves arrive on time.
        let mut s = ReceiverStats::new(0, 0, Duration::ZERO);
        let mut index = 0;
        for frame in 1..200u32 {
            let start = Duration::from_nanos(frame as u64 * 33_333_333);
            for p in 0..20u32 {
                index += 1;
                s.record(index, frame * 3000, start + Duration::from_micros(p as u64 * 250));
            }
        }
        assert!(s.jitter() <= 1, "jitter {}", s.jitter());
    }

    #[test]
    fn jitter_skips_timestamp_discontinuity() {
        let mut s = ReceiverStats::new(0, 0, Duration::ZERO);
        // Must not overflow in debug builds either.
        s.jitter16 = u32::MAX - 4;
        s.record(1, 3000, Duration::from_nanos(33_333_333));
        let mut s = ReceiverStats::new(0, 0, Duration::ZERO);
        s.record(1, 0x8000_0000, MS * 33);
        assert_eq!(s.jitter(), 0);
        s.record(2, 0x8000_0000 + 3000, MS * 66 + Duration::from_nanos(666_667));
        assert!(s.jitter() <= 1, "jitter {}", s.jitter());
    }
}
