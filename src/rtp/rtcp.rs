//! RTCP feedback builders (RR, SR, FIR, PLI, NACK, Apple LTR ack) and SR
//! parsing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;
/// Round-trip samples longer than this are taken to be bogus (e.g. a wall
/// clock step between our SR and the report).
const RTT_MAX: Duration = Duration::from_secs(1);

fn ntp_now() -> (u32, u32) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = (d.as_secs() + NTP_EPOCH_OFFSET) as u32;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs, frac as u32)
}

/// Per-source data for a receiver report block (RFC 3550 6.4.1).
#[derive(Default)]
pub struct ReportSource {
    pub ssrc: u32,
    /// Lost fraction since the previous report, fixed point /256.
    pub fraction_lost: u8,
    /// Cumulative packets lost; clamped to the 24-bit signed wire range.
    pub cumulative_lost: i32,
    pub extended_seq: u32,
    /// Interarrival jitter in RTP timestamp units.
    pub jitter: u32,
    /// Middle 32 bits of the last SR's NTP timestamp and seconds since it
    /// arrived.
    pub last_sr: Option<(u32, f64)>,
}

pub fn receiver_report(sender: u32, sources: &[ReportSource]) -> Vec<u8> {
    let rc = sources.len().min(31);
    let mut out = vec![0x80 | rc as u8, 201];
    out.extend_from_slice(&((1 + 6 * rc) as u16).to_be_bytes());
    out.extend_from_slice(&sender.to_be_bytes());
    for s in &sources[..rc] {
        let (lsr, dlsr) = match s.last_sr {
            Some((lsr, age)) => (lsr, (age * 65536.0) as u32),
            None => (0, 0),
        };
        let lost = s.cumulative_lost.clamp(-0x80_0000, 0x7f_ffff) as u32 & 0xff_ffff;
        let loss = (s.fraction_lost as u32) << 24 | lost;
        for v in [s.ssrc, loss, s.extended_seq, s.jitter, lsr, dlsr] {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
    out
}

/// An empty sender report; the host's liveness check wants one periodically.
pub fn empty_sender_report(sender: u32) -> Vec<u8> {
    let (secs, frac) = ntp_now();
    let rtp_ts = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64() * 90_000.0)
        as u64 as u32;
    let mut out = vec![0x80, 200, 0, 6];
    for v in [sender, secs, frac, rtp_ts, 0, 0] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

/// Which keyframe-recovery feedback to send when a tile loses a picture.
///
/// Known about the host (from iShareScreen, the protocol reference):
/// * The native viewer sends only the legacy RFC 2032 FIR (PT 192), and
///   screensharingd answers it with a fresh IDR. It "often ignores" the AVPF
///   FIR (PT 206 FMT 4), so [`Recovery::Fir`] sends both FIR forms.
/// * The reference always sends FIR + PLI + legacy FIR together, so which
///   of them the host acts on has never been measured apart.
///
/// Unknown (to be measured with `--stats-json`):
/// * Whether the host answers a PLI (PT 206 FMT 1) at all, and if so with an
///   IDR or with a P picture predicted from the last long-term reference we
///   acknowledged (see [`ltr_ack`]). RFC 4585 leaves the response to the
///   encoder; with LTR negotiated the cheap answer would be an LTR-referenced
///   P picture instead of a keyframe. The decoder currently drops everything
///   until an IRAP after a loss, so such an answer would not show up as a
///   faster recovery yet.
/// * Whether the compound costs more than a single request (e.g. two IDRs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Recovery {
    /// AVPF FIR and the legacy RFC 2032 FIR.
    Fir,
    /// Picture Loss Indication only.
    Pli,
    /// AVPF FIR + PLI + legacy FIR, as the reference sends.
    #[value(name = "fir+pli")]
    FirPli,
}

impl Recovery {
    pub const ALL: [Recovery; 3] = [Recovery::Fir, Recovery::Pli, Recovery::FirPli];

    pub fn name(self) -> &'static str {
        match self {
            Recovery::Fir => "fir",
            Recovery::Pli => "pli",
            Recovery::FirPli => "fir+pli",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == s)
    }
}

/// AVPF Full Intra Request (RFC 5104 4.3.1.1).
fn fir(out: &mut Vec<u8>, sender: u32, target: u32, fir_seq: u8) {
    out.extend_from_slice(&[0x84, 206, 0, 4]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&target.to_be_bytes());
    out.extend_from_slice(&[fir_seq, 0, 0, 0]);
}

/// Picture Loss Indication (RFC 4585 6.3.1).
fn pli(out: &mut Vec<u8>, sender: u32, target: u32) {
    out.extend_from_slice(&[0x81, 206, 0, 2]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&target.to_be_bytes());
}

/// The legacy RFC 2032 FIR the native viewer sends.
fn legacy_fir(out: &mut Vec<u8>, target: u32) {
    out.extend_from_slice(&[0x80, 192, 0, 1]);
    out.extend_from_slice(&target.to_be_bytes());
}

/// A keyframe request of the given kind, prefixed with an empty RR to form
/// a compound packet.
pub fn recovery_request(kind: Recovery, sender: u32, target: u32, fir_seq: u8) -> Vec<u8> {
    let mut out = receiver_report(sender, &[]);
    if kind != Recovery::Pli {
        fir(&mut out, sender, target, fir_seq);
    }
    if kind != Recovery::Fir {
        pli(&mut out, sender, target);
    }
    if kind != Recovery::Pli {
        legacy_fir(&mut out, target);
    }
    out
}

/// Generic NACK, prefixed with an empty RR.
pub fn nack(sender: u32, media: u32, lost: &[u16]) -> Option<Vec<u8>> {
    let mut seqs = lost.to_vec();
    seqs.sort_unstable();
    seqs.dedup();
    if seqs.is_empty() {
        return None;
    }
    let mut fci = Vec::new();
    let mut i = 0;
    while i < seqs.len() {
        let pid = seqs[i];
        let mut blp = 0u16;
        let mut j = i + 1;
        while j < seqs.len() {
            let diff = seqs[j].wrapping_sub(pid);
            if (1..=16).contains(&diff) {
                blp |= 1 << (diff - 1);
                j += 1;
            } else {
                break;
            }
        }
        fci.extend_from_slice(&pid.to_be_bytes());
        fci.extend_from_slice(&blp.to_be_bytes());
        i = j;
    }
    let mut out = receiver_report(sender, &[]);
    out.extend_from_slice(&[0x81, 205]);
    out.extend_from_slice(&((2 + fci.len() / 4) as u16).to_be_bytes());
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&media.to_be_bytes());
    out.extend_from_slice(&fci);
    Some(out)
}

/// Apple's long-term-reference acknowledgement (APP, subtype 5) carrying the
/// DONL of the last cleanly decoded base-tile frame.
pub fn ltr_ack(sender: u32, donl: u16) -> Vec<u8> {
    let mut out = vec![0x80, 204, 0, 3];
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&5u32.to_be_bytes());
    out.extend_from_slice(&(donl as u32).to_be_bytes());
    out
}

/// Returns `(ssrc, ntp_middle_32)` for each SR in a compound packet.
pub fn sender_reports(data: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let pt = data[pos + 1];
        let len = (u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize + 1) * 4;
        if pos + len > data.len() {
            break;
        }
        if pt == 200 && len >= 28 {
            let p = &data[pos..];
            let ssrc = u32::from_be_bytes(p[4..8].try_into().unwrap());
            let secs = u32::from_be_bytes(p[8..12].try_into().unwrap());
            let frac = u32::from_be_bytes(p[12..16].try_into().unwrap());
            out.push((ssrc, (secs << 16) | (frac >> 16)));
        }
        pos += len;
    }
    out
}

/// Middle 32 bits of the current NTP time, the unit of LSR/DLSR.
pub fn ntp_middle_now() -> u32 {
    let (secs, frac) = ntp_now();
    (secs << 16) | (frac >> 16)
}

/// Round-trip times from the report blocks about `ours` (the SSRC our SRs
/// are sent as) in the SRs and RRs of a compound packet (RFC 3550 6.4.1:
/// A - LSR - DLSR). `now` is [`ntp_middle_now`] at arrival.
pub fn round_trips(data: &[u8], ours: u32, now: u32) -> Vec<Duration> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let p = &data[pos..];
        let len = (u16::from_be_bytes([p[2], p[3]]) as usize + 1) * 4;
        if len > p.len() {
            break;
        }
        let blocks = match p[1] {
            200 => 28,
            201 => 8,
            _ => len,
        };
        let rc = (p[0] & 0x1f) as usize;
        for b in p[..len].get(blocks..).unwrap_or_default().as_chunks::<24>().0.iter().take(rc) {
            let ssrc = u32::from_be_bytes(b[0..4].try_into().unwrap());
            let lsr = u32::from_be_bytes(b[16..20].try_into().unwrap());
            let dlsr = u32::from_be_bytes(b[20..24].try_into().unwrap());
            if ssrc != ours || lsr == 0 {
                continue;
            }
            let rtt = Duration::from_secs_f64(now.wrapping_sub(lsr).wrapping_sub(dlsr) as f64 / 65536.0);
            if rtt <= RTT_MAX {
                out.push(rtt);
            }
        }
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nack_packs_bitmask() {
        let p = nack(1, 2, &[10, 11, 13, 40]).unwrap();
        let fb = &p[8..];
        assert_eq!(&fb[..2], &[0x81, 205]);
        assert_eq!(u16::from_be_bytes([fb[2], fb[3]]), 4);
        assert_eq!(&fb[12..16], &[0, 10, 0b0000_0000, 0b0000_0101]);
        assert_eq!(&fb[16..20], &[0, 40, 0, 0]);
    }

    #[test]
    fn rr_lengths() {
        let rr = receiver_report(9, &[ReportSource { ssrc: 1, extended_seq: 5, ..Default::default() }]);
        assert_eq!(rr.len(), 8 + 24);
        assert_eq!(u16::from_be_bytes([rr[2], rr[3]]), 7);
        let sr = empty_sender_report(9);
        assert_eq!(sr.len(), 28);
        assert_eq!(sender_reports(&sr)[0].0, 9);
    }

    #[test]
    fn rr_block_layout() {
        let src = ReportSource {
            ssrc: 0x1122_3344,
            fraction_lost: 0x40,
            cumulative_lost: 0x01_0203,
            extended_seq: 0x0001_fffe,
            jitter: 0x0000_0384,
            last_sr: Some((0xaabb_ccdd, 1.5)),
        };
        let rr = receiver_report(9, &[src]);
        assert_eq!(&rr[..8], &[0x81, 201, 0, 7, 0, 0, 0, 9]);
        let b = &rr[8..];
        assert_eq!(&b[0..4], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&b[4..8], &[0x40, 0x01, 0x02, 0x03]);
        assert_eq!(&b[8..12], &[0x00, 0x01, 0xff, 0xfe]);
        assert_eq!(&b[12..16], &[0x00, 0x00, 0x03, 0x84]);
        assert_eq!(&b[16..20], &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(&b[20..24], &[0x00, 0x01, 0x80, 0x00]);
    }

    #[test]
    fn rr_cumulative_lost_is_24_bit_signed() {
        let word = |lost| {
            let rr = receiver_report(9, &[ReportSource { fraction_lost: 1, cumulative_lost: lost, ..Default::default() }]);
            [rr[12], rr[13], rr[14], rr[15]]
        };
        assert_eq!(word(-1), [1, 0xff, 0xff, 0xff]);
        assert_eq!(word(i32::MAX), [1, 0x7f, 0xff, 0xff]);
        assert_eq!(word(i32::MIN), [1, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn empty_rr_for_feedback() {
        for kind in Recovery::ALL {
            let p = recovery_request(kind, 9, 2, 1);
            assert_eq!(&p[..8], &[0x80, 201, 0, 1, 0, 0, 0, 9]);
        }
    }

    #[test]
    fn recovery_variants_layout() {
        let rr: &[u8] = &[0x80, 201, 0, 1, 0, 0, 0, 9];
        let fir: &[u8] = &[0x84, 206, 0, 4, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 2, 7, 0, 0, 0];
        let pli: &[u8] = &[0x81, 206, 0, 2, 0, 0, 0, 9, 0, 0, 0, 2];
        let legacy: &[u8] = &[0x80, 192, 0, 1, 0, 0, 0, 2];
        assert_eq!(recovery_request(Recovery::Fir, 9, 2, 7), [rr, fir, legacy].concat());
        assert_eq!(recovery_request(Recovery::Pli, 9, 2, 7), [rr, pli].concat());
        assert_eq!(recovery_request(Recovery::FirPli, 9, 2, 7), [rr, fir, pli, legacy].concat());
        for kind in Recovery::ALL {
            // Each part's length field matches its size, so the compound
            // splits cleanly.
            let p = recovery_request(kind, 9, 2, 7);
            let mut pos = 0;
            while pos < p.len() {
                pos += (u16::from_be_bytes([p[pos + 2], p[pos + 3]]) as usize + 1) * 4;
            }
            assert_eq!(pos, p.len());
            assert_eq!(Recovery::parse(kind.name()), Some(kind));
        }
        assert_eq!(Recovery::parse("idr"), None);
    }

    #[test]
    fn round_trip_from_report_block() {
        // An RR echoing our SR sent at LSR, held 0.25 s by the host, back
        // 0.3 s after we sent it.
        let lsr = 0x1234_0000u32;
        let mut rr = vec![0x81, 201, 0, 7, 0, 0, 0, 9];
        for v in [1u32, 0, 0, 0, lsr, 0x4000] {
            rr.extend_from_slice(&v.to_be_bytes());
        }
        let now = lsr + (0.3 * 65536.0) as u32;
        let rtt = round_trips(&rr, 1, now);
        assert_eq!(rtt.len(), 1);
        assert!((rtt[0].as_secs_f64() - 0.05).abs() < 0.001);
        // About another source, no SR echoed yet, a block that would go back
        // in time, or one implausibly old.
        assert!(round_trips(&rr, 2, now).is_empty());
        assert!(round_trips(&rr[..8], 1, now).is_empty());
        assert!(round_trips(&rr, 1, lsr).is_empty());
        assert!(round_trips(&rr, 1, lsr + 2 * 65536).is_empty());
    }
}
