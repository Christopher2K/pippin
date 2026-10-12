//! RTCP feedback builders (RR, SR, FIR, PLI, NACK, Apple LTR ack) and SR
//! parsing.

use std::time::{SystemTime, UNIX_EPOCH};

const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

fn ntp_now() -> (u32, u32) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = (d.as_secs() + NTP_EPOCH_OFFSET) as u32;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs, frac as u32)
}

/// Per-source data for a receiver report block.
pub struct ReportSource {
    pub ssrc: u32,
    pub extended_seq: u32,
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
        for v in [s.ssrc, 0, s.extended_seq, 0, lsr, dlsr] {
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

/// AVPF FIR + PLI + the legacy RFC 2032 FIR that screensharingd honors most
/// reliably, prefixed with an empty RR to form a compound packet.
pub fn keyframe_request(sender: u32, target: u32, fir_seq: u8) -> Vec<u8> {
    let mut out = receiver_report(sender, &[]);
    out.extend_from_slice(&[0x84, 206, 0, 4]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&target.to_be_bytes());
    out.extend_from_slice(&[fir_seq, 0, 0, 0]);
    out.extend_from_slice(&[0x81, 206, 0, 2]);
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(&target.to_be_bytes());
    out.extend_from_slice(&[0x80, 192, 0, 1]);
    out.extend_from_slice(&target.to_be_bytes());
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
        let rr = receiver_report(9, &[ReportSource { ssrc: 1, extended_seq: 5, last_sr: None }]);
        assert_eq!(rr.len(), 8 + 24);
        assert_eq!(u16::from_be_bytes([rr[2], rr[3]]), 7);
        let sr = empty_sender_report(9);
        assert_eq!(sr.len(), 28);
        assert_eq!(sender_reports(&sr)[0].0, 9);
    }
}
