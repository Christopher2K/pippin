//! Depayloads Apple's H.264 RTP (RFC 6184, non-interleaved mode).
//!
//! Unlike its HEVC, Apple's H.264 carries no decoding-order numbers: single
//! NAL units and FU-A fragments are sent as RFC 6184 defines them. SPS and
//! PPS do not arrive as NAL units either. The host sends them in a packet
//! starting with 0x92 (not a valid NAL header: the forbidden bit is set)
//! that wraps an ISO-BMFF `avc1` sample entry whose `avcC` box holds them;
//! [`depayload`] turns that into ordinary SPS/PPS NAL units.

pub const NAL_SLICE: u8 = 1;
pub const NAL_IDR: u8 = 5;
pub const NAL_SPS: u8 = 7;
pub const NAL_PPS: u8 = 8;
const NAL_STAP_A: u8 = 24;
const NAL_STAP_B: u8 = 25;
pub const NAL_FU_A: u8 = 28;
const NAL_FU_B: u8 = 29;
/// First byte of Apple's decoder-configuration packet.
pub const CONFIG_MARKER: u8 = 0x92;
/// `max_num_ref_frames` written into the SPS; see [`patch_sps_dpb`].
const PATCHED_REF_FRAMES: u32 = 16;
/// Level 6.0, whose DPB limit doesn't cap 16 reference frames.
const PATCHED_LEVEL: u8 = 60;

pub fn nal_type(nal: &[u8]) -> u8 {
    nal[0] & 0x1f
}

pub fn is_param_set(nal: &[u8]) -> bool {
    matches!(nal_type(nal), NAL_SPS | NAL_PPS)
}

/// Coded slices, including data partitions.
pub fn is_slice(nal: &[u8]) -> bool {
    (NAL_SLICE..=NAL_IDR).contains(&nal_type(nal))
}

/// A slice a decoder can start from: an IDR, or an I slice in an ordinary
/// type-1 NAL, which is how Apple's encoder sends most of its keyframes.
pub fn is_keyframe(nal: &[u8]) -> bool {
    match nal_type(nal) {
        NAL_IDR => true,
        NAL_SLICE => {
            let mut r = BitReader::new(unescape(&nal[1..nal.len().min(16)]));
            // first_mb_in_slice, then slice_type: I is 2 or 7.
            r.ue().is_some() && matches!(r.ue(), Some(2 | 7))
        }
        _ => false,
    }
}

/// Whether a slice is the first of its picture: `first_mb_in_slice` is 0,
/// whose ue(v) code is the single bit 1.
pub fn first_in_picture(nal: &[u8]) -> bool {
    nal.len() > 1 && nal[1] & 0x80 != 0
}

/// Reads `pic_parameter_set_id` (the first ue(v) of the PPS RBSP).
pub fn pps_id(nal: &[u8]) -> Option<u32> {
    BitReader::new(unescape(nal.get(1..nal.len().min(8))?)).ue()
}

/// Whether a payload continues a fragmented NAL rather than starting one.
pub fn continues_nal(p: &[u8]) -> bool {
    p.len() >= 2 && matches!(nal_type(p), NAL_FU_A | NAL_FU_B) && p[1] & 0x80 == 0
}

/// Turns one access unit's payloads, sorted by sequence number, into NAL
/// units. A fragmented NAL is emitted only if all of its fragments arrived
/// back to back, so every returned NAL is intact.
pub fn depayload(payloads: &[(u16, &[u8])]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut fu: Option<(Vec<u8>, u16)> = None;
    for &(seq, p) in payloads {
        if p.len() < 2 {
            continue;
        }
        if p[0] == CONFIG_MARKER {
            out.extend(parse_avc_config(p).unwrap_or_default());
            continue;
        }
        match nal_type(p) {
            t @ (NAL_FU_A | NAL_FU_B) => {
                // FU-B has a DON after the FU header.
                let data = if t == NAL_FU_B { 4 } else { 2 };
                if p.len() <= data {
                    fu = None;
                    continue;
                }
                let (start, end) = (p[1] & 0x80 != 0, p[1] & 0x40 != 0);
                if start {
                    let mut nal = vec![(p[0] & 0xe0) | (p[1] & 0x1f)];
                    nal.extend_from_slice(&p[data..]);
                    fu = Some((nal, seq));
                } else if let Some((mut nal, last)) = fu.take()
                    && seq == last.wrapping_add(1)
                {
                    nal.extend_from_slice(&p[data..]);
                    if end {
                        out.push(nal);
                    } else {
                        fu = Some((nal, seq));
                    }
                }
            }
            NAL_STAP_A | NAL_STAP_B => out.extend(aggregated(p)),
            1..=23 => out.push(p.to_vec()),
            _ => {}
        }
    }
    out
}

/// The NAL units of a STAP. STAP-A has none, but iShareScreen skips a
/// 2-byte DON in STAP-A too (it never saw one from Apple), so that layout is
/// accepted when the RFC one doesn't add up.
fn aggregated(p: &[u8]) -> Vec<Vec<u8>> {
    let units = |mut pos: usize| {
        let mut nals = Vec::new();
        while pos < p.len() {
            let size = u16::from_be_bytes([p[pos], *p.get(pos + 1)?]) as usize;
            pos += 2;
            if size == 0 || pos + size > p.len() {
                return None;
            }
            nals.push(p[pos..pos + size].to_vec());
            pos += size;
        }
        Some(nals)
    };
    let (rfc, alt) = if nal_type(p) == NAL_STAP_B { (3, 1) } else { (1, 3) };
    units(rfc).or_else(|| units(alt)).unwrap_or_default()
}

/// SPS and PPS NAL units from Apple's 0x92 configuration packet: the
/// `avcC` box (AVCDecoderConfigurationRecord) inside its `avc1` entry.
pub fn parse_avc_config(p: &[u8]) -> Option<Vec<Vec<u8>>> {
    let find = |from: usize, needle: &[u8]| p.get(from..)?.windows(4).position(|w| w == needle).map(|i| i + from);
    // Anchored on avc1 so "avcC" bytes inside other data can't match first.
    let at = find(find(0, b"avc1").unwrap_or(0), b"avcC")? + 4;
    // version, profile, compatibility, level, length size, SPS count.
    let mut pos = at + 5;
    let mut out = Vec::new();
    for mask in [0x1f, 0xff] {
        let count = p.get(pos)? & mask;
        pos += 1;
        for _ in 0..count {
            let len = u16::from_be_bytes([*p.get(pos)?, *p.get(pos + 1)?]) as usize;
            pos += 2;
            let nal = p.get(pos..pos + len)?;
            pos += len;
            if !nal.is_empty() {
                out.push(nal.to_vec());
            }
        }
    }
    let has = |t| out.iter().any(|n| nal_type(n) == t);
    (has(NAL_SPS) && has(NAL_PPS)).then_some(out)
}

/// Raises the SPS's `max_num_ref_frames` to 16 and its level to 6.0.
///
/// Apple's SPS declares 8 reference frames at level 5.2, but the encoder
/// references up to 9 (7 short-term and 2 long-term). libavcodec keeps only
/// what the SPS allows, and later pictures then miss a reference until the
/// next keyframe. Returns the SPS unchanged if it has anything unexpected
/// (e.g. scaling matrices).
pub fn patch_sps_dpb(sps: &[u8]) -> Vec<u8> {
    patched(sps).unwrap_or_else(|| sps.to_vec())
}

fn patched(sps: &[u8]) -> Option<Vec<u8>> {
    if sps.len() < 4 || nal_type(sps) != NAL_SPS {
        return None;
    }
    let mut r = BitReader::new(unescape(&sps[1..]));
    let profile = r.u(8)?;
    r.u(8)?; // constraint flags
    let level = r.pos;
    r.u(8)?;
    r.ue()?; // seq_parameter_set_id
    if [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].contains(&profile) {
        if r.ue()? == 3 {
            r.u(1)?; // separate_colour_plane_flag
        }
        r.ue()?; // bit_depth_luma_minus8
        r.ue()?; // bit_depth_chroma_minus8
        r.u(1)?; // qpprime_y_zero_transform_bypass_flag
        if r.u(1)? == 1 {
            return None; // seq_scaling_matrix_present_flag
        }
    }
    r.ue()?; // log2_max_frame_num_minus4
    match r.ue()? {
        0 => {
            r.ue()?; // log2_max_pic_order_cnt_lsb_minus4
        }
        1 => {
            r.u(1)?;
            r.ue()?;
            r.ue()?;
            for _ in 0..r.ue()? {
                r.ue()?;
            }
        }
        _ => {}
    }
    let refs_at = r.pos;
    if r.ue()? >= PATCHED_REF_FRAMES {
        return None;
    }
    let mut bits = r.bits();
    bits.splice(refs_at..r.pos, ue_bits(PATCHED_REF_FRAMES));
    for i in 0..8 {
        bits[level + i] = (PATCHED_LEVEL >> (7 - i)) & 1;
    }
    let mut rbsp: Vec<u8> = bits.chunks(8).map(|c| c.iter().enumerate().fold(0, |b, (i, &v)| b | v << (7 - i))).collect();
    // The stop bit moved; drop alignment bytes that are now all zero.
    while rbsp.last() == Some(&0) {
        rbsp.pop();
    }
    let mut out = vec![sps[0]];
    escape(&rbsp, &mut out);
    Some(out)
}

fn ue_bits(v: u32) -> Vec<u8> {
    let code = v + 1;
    let n = 32 - code.leading_zeros();
    let mut bits = vec![0; n as usize - 1];
    bits.extend((0..n).rev().map(|i| ((code >> i) & 1) as u8));
    bits
}

/// Strips emulation-prevention bytes.
fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut zeros = 0;
    for &b in data {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

/// Adds emulation-prevention bytes.
fn escape(rbsp: &[u8], out: &mut Vec<u8>) {
    let mut zeros = 0;
    for &b in rbsp {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
}

struct BitReader {
    data: Vec<u8>,
    pos: usize,
}

impl BitReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    fn u(&mut self, n: usize) -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            let b = (self.data.get(self.pos / 8)? >> (7 - self.pos % 8)) & 1;
            v = (v << 1) | b as u32;
            self.pos += 1;
        }
        Some(v)
    }

    fn ue(&mut self) -> Option<u32> {
        let mut lz = 0;
        while self.u(1)? == 0 {
            lz += 1;
            if lz > 31 {
                return None;
            }
        }
        Some(((1u64 << lz) - 1 + self.u(lz)? as u64) as u32)
    }

    /// Every bit of the data, one per byte.
    fn bits(&self) -> Vec<u8> {
        self.data.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// x264's 1280x720 High-profile SPS and PPS.
    const SPS: [u8; 26] = [
        0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9, 0x40, 0x50, 0x05, 0xbb, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00,
        0x00, 0x03, 0x03, 0x20, 0xf1, 0x83, 0x19, 0x60,
    ];
    const PPS: [u8; 6] = [0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0];

    fn fu(flags: u8, inner: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x60 | NAL_FU_A, flags | inner];
        v.extend_from_slice(data);
        v
    }

    /// An `avc1` sample entry with an `avcC` box, as in Apple's 0x92 packet.
    fn config_packet() -> Vec<u8> {
        let mut p = vec![CONFIG_MARKER, 0, 0, 0, 0x56];
        p.extend_from_slice(b"avc1");
        p.extend_from_slice(&[0; 20]);
        p.extend_from_slice(b"avcC");
        p.extend_from_slice(&[1, 0x64, 0, 0x1f, 0xff, 0xe1]);
        p.extend_from_slice(&(SPS.len() as u16).to_be_bytes());
        p.extend_from_slice(&SPS);
        p.push(1);
        p.extend_from_slice(&(PPS.len() as u16).to_be_bytes());
        p.extend_from_slice(&PPS);
        p.extend_from_slice(&[0xfd, 0xf8, 0xf8, 0]);
        p
    }

    #[test]
    fn depayload_variants() {
        // Single NAL: an IDR slice, no DON.
        let single = vec![0x65, 0x88, 0x84, 0x21];
        // STAP-A with SEI and an access unit delimiter.
        let mut stap = vec![0x18];
        for nal in [&[0x06u8, 5, 1][..], &[0x09, 0xf0]] {
            stap.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            stap.extend_from_slice(nal);
        }
        // FU-A carrying a P slice (type 1, nal_ref_idc 3) in three fragments.
        let (f1, f2, f3) = (fu(0x80, 1, &[0x9a, 2]), fu(0, 1, &[3]), fu(0x40, 1, &[4]));
        let cfg = config_packet();
        let pkts: Vec<(u16, &[u8])> =
            vec![(65533, &cfg), (65534, &single), (65535, &stap), (0, &f1), (1, &f2), (2, &f3)];
        let nals = depayload(&pkts);
        assert_eq!(nals.len(), 6);
        assert_eq!(nals[..2], [SPS.to_vec(), PPS.to_vec()]);
        assert_eq!(nals[2], single);
        assert_eq!(nals[3..5], [vec![0x06, 5, 1], vec![0x09, 0xf0]]);
        assert_eq!(nals[5], vec![0x61, 0x9a, 2, 3, 4]);
        assert!(is_keyframe(&nals[2]) && first_in_picture(&nals[2]));
        assert!(!is_keyframe(&nals[5]) && first_in_picture(&nals[5]));
        assert!(nals[..2].iter().all(|n| is_param_set(n)));
        assert!(is_slice(&nals[5]) && !is_slice(&nals[3]));

        // A lost middle fragment drops the NAL; so does a lost first one.
        assert!(depayload(&[(0, &f1[..]), (2, &f3[..])]).is_empty());
        assert!(depayload(&[(1, &f2[..]), (2, &f3[..])]).is_empty());
        assert!(!continues_nal(&f1) && continues_nal(&f2) && continues_nal(&f3));
        assert!(!continues_nal(&single) && !continues_nal(&cfg));

        // STAP-A with the DON iShareScreen allows for.
        let mut stap_don = vec![0x18, 0, 9];
        stap_don.extend_from_slice(&[0, 3, 0x06, 5, 1]);
        assert_eq!(depayload(&[(0, &stap_don[..])]), vec![vec![0x06, 5, 1]]);
        // FU-B: DON after the FU header.
        let fub = |flags: u8, d: u8| vec![0x60 | NAL_FU_B, flags | 5, 0, 7, d];
        let (b1, b2) = (fub(0x80, 0x88), fub(0x40, 0x99));
        assert_eq!(depayload(&[(4, &b1[..]), (5, &b2[..])]), vec![vec![0x65, 0x88, 0x99]]);
    }

    #[test]
    fn recognises_keyframes() {
        // first_mb_in_slice 0 ("1"), slice_type 7 ("0001000"): an I slice.
        assert!(is_keyframe(&[0x41, 0b1000_1000, 0]));
        // slice_type 2 ("011").
        assert!(is_keyframe(&[0x01, 0b1011_0000]));
        // slice_type 5 (P, "00110").
        assert!(!is_keyframe(&[0x41, 0b1001_1000]));
        // first_mb_in_slice 3 ("00100"), slice_type 7: an I slice, not first.
        let later = [0x41, 0b0010_0000, 0b1000_0000];
        assert!(is_keyframe(&later) && !first_in_picture(&later));
        assert!(!is_keyframe(&SPS) && !is_slice(&SPS));
    }

    #[test]
    fn parses_avc_config() {
        assert_eq!(parse_avc_config(&config_packet()), Some(vec![SPS.to_vec(), PPS.to_vec()]));
        // Truncated, or missing the PPS.
        let p = config_packet();
        assert_eq!(parse_avc_config(&p[..p.len() - 10]), None);
        let mut no_pps = p.clone();
        let at = no_pps.len() - 4 - PPS.len() - 3;
        no_pps[at] = 0;
        assert_eq!(parse_avc_config(&no_pps), None);
        assert_eq!(parse_avc_config(&[CONFIG_MARKER, 1, 2, 3]), None);
        assert_eq!(pps_id(&PPS), Some(0));
        assert_eq!(pps_id(&[0x68, 0b0100_0000]), Some(1));
    }

    #[test]
    fn patches_sps_reference_count() {
        let p = patch_sps_dpb(&SPS);
        assert_ne!(p, SPS);
        let mut r = BitReader::new(unescape(&p[1..]));
        assert_eq!((r.u(8), r.u(8), r.u(8)), (Some(100), Some(0), Some(60)));
        r.ue(); // sps id
        assert_eq!(r.ue(), Some(1)); // chroma_format_idc
        r.ue();
        r.ue();
        r.u(2);
        r.ue(); // log2_max_frame_num_minus4
        assert_eq!(r.ue(), Some(0)); // poc type
        r.ue();
        assert_eq!(r.ue(), Some(16));
        // Already patched: unchanged.
        assert_eq!(patch_sps_dpb(&p), p);
        // Not an SPS: unchanged.
        assert_eq!(patch_sps_dpb(&PPS), PPS);
        // Emulation prevention survives the round trip.
        let mut out = Vec::new();
        escape(&[0, 0, 1, 0, 0, 0, 5], &mut out);
        assert_eq!(out, [0, 0, 3, 1, 0, 0, 3, 0, 5]);
        assert_eq!(unescape(&out), [0, 0, 1, 0, 0, 0, 5]);
        assert_eq!(ue_bits(16), [0, 0, 0, 0, 1, 0, 0, 0, 1]);
        assert_eq!(ue_bits(0), [1]);
    }
}
