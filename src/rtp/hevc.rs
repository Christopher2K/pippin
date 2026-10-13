//! Depayloads Apple's variant of RFC 7798 HEVC RTP.
//!
//! Every payload carries a 2-byte DONL: after the NAL header for single NALs
//! and aggregation packets (once per AP, no DOND between units), and after
//! the FU header in *every* fragmentation unit.

pub const NAL_VPS: u8 = 32;
pub const NAL_SPS: u8 = 33;
pub const NAL_PPS: u8 = 34;
const NAL_AP: u8 = 48;
pub const NAL_FU: u8 = 49;

pub fn nal_type(nal: &[u8]) -> u8 {
    (nal[0] >> 1) & 0x3f
}

pub fn is_irap(nal: &[u8]) -> bool {
    (16..=21).contains(&nal_type(nal))
}

pub fn is_param_set(nal: &[u8]) -> bool {
    matches!(nal_type(nal), NAL_VPS | NAL_SPS | NAL_PPS)
}

pub fn is_slice(nal: &[u8]) -> bool {
    nal_type(nal) <= 31
}

/// Reads `pps_pic_parameter_set_id` (the first ue(v) of the PPS RBSP).
pub fn pps_id(nal: &[u8]) -> Option<u32> {
    let mut rbsp = Vec::with_capacity(8);
    let mut zeros = 0;
    for &b in nal.get(2..)?.iter().take(16) {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        rbsp.push(b);
    }
    let bit = |i: usize| rbsp.get(i / 8).map(|b| (b >> (7 - i % 8)) & 1);
    let mut i = 0;
    let mut lz = 0;
    while bit(i)? == 0 {
        lz += 1;
        i += 1;
        if lz > 31 {
            return None;
        }
    }
    i += 1;
    let mut v = 0u32;
    for _ in 0..lz {
        v = (v << 1) | bit(i)? as u32;
        i += 1;
    }
    Some((1u32 << lz) - 1 + v)
}

/// Within-picture parallelism a PPS enables: `(tiles, wavefront)`. Either
/// lets libavcodec's slice threading split a single-slice picture.
pub fn pps_parallelism(nal: &[u8]) -> Option<(bool, bool)> {
    let mut rbsp = Vec::with_capacity(32);
    let mut zeros = 0;
    for &b in nal.get(2..)?.iter().take(64) {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        rbsp.push(b);
    }
    let mut i = 0usize;
    let mut u = |n: usize| -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | ((rbsp.get(i / 8)? >> (7 - i % 8)) & 1) as u32;
            i += 1;
        }
        Some(v)
    };
    let ue = |u: &mut dyn FnMut(usize) -> Option<u32>| -> Option<u32> {
        let mut lz = 0;
        while u(1)? == 0 {
            lz += 1;
            if lz > 31 {
                return None;
            }
        }
        Some((1u32 << lz) - 1 + u(lz)?)
    };
    ue(&mut u)?; // pps_pic_parameter_set_id
    ue(&mut u)?; // pps_seq_parameter_set_id
    u(1)?; // dependent_slice_segments_enabled_flag
    u(1)?; // output_flag_present_flag
    u(3)?; // num_extra_slice_header_bits
    u(1)?; // sign_data_hiding_enabled_flag
    u(1)?; // cabac_init_present_flag
    ue(&mut u)?; // num_ref_idx_l0_default_active_minus1
    ue(&mut u)?; // num_ref_idx_l1_default_active_minus1
    ue(&mut u)?; // init_qp_minus26 (se; only the length matters)
    u(1)?; // constrained_intra_pred_flag
    u(1)?; // transform_skip_enabled_flag
    if u(1)? == 1 {
        ue(&mut u)?; // diff_cu_qp_delta_depth
    }
    ue(&mut u)?; // pps_cb_qp_offset
    ue(&mut u)?; // pps_cr_qp_offset
    u(1)?; // pps_slice_chroma_qp_offsets_present_flag
    u(1)?; // weighted_pred_flag
    u(1)?; // weighted_bipred_flag
    u(1)?; // transquant_bypass_enabled_flag
    let tiles = u(1)? == 1;
    let wpp = u(1)? == 1;
    Some((tiles, wpp))
}

/// DONL of the first packet of an access unit.
pub fn first_donl(payloads: &[(u16, &[u8])]) -> Option<u16> {
    let (_, p) = payloads.first()?;
    if p.len() < 2 {
        return None;
    }
    let off = if (p[0] >> 1) & 0x3f == NAL_FU { 3 } else { 2 };
    p.get(off..off + 2).map(|d| u16::from_be_bytes([d[0], d[1]]))
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
        match (p[0] >> 1) & 0x3f {
            NAL_AP => {
                let mut pos = 4;
                while pos + 2 <= p.len() {
                    let size = u16::from_be_bytes([p[pos], p[pos + 1]]) as usize;
                    pos += 2;
                    if size == 0 || pos + size > p.len() {
                        break;
                    }
                    out.push(p[pos..pos + size].to_vec());
                    pos += size;
                }
            }
            NAL_FU => {
                if p.len() < 6 {
                    fu = None;
                    continue;
                }
                let hdr = p[2];
                let (start, end, inner) = (hdr & 0x80 != 0, hdr & 0x40 != 0, hdr & 0x3f);
                if start {
                    let mut nal = vec![(p[0] & 0x81) | (inner << 1), p[1]];
                    nal.extend_from_slice(&p[5..]);
                    fu = Some((nal, seq));
                } else if let Some((mut nal, last)) = fu.take()
                    && seq == last.wrapping_add(1) {
                        nal.extend_from_slice(&p[5..]);
                        if end {
                            out.push(nal);
                        } else {
                            fu = Some((nal, seq));
                        }
                    }
            }
            _ => {
                if p.len() >= 4 {
                    let mut nal = p[..2].to_vec();
                    nal.extend_from_slice(&p[4..]);
                    out.push(nal);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depayload_variants() {
        // AP with VPS + SPS (types 32, 33), DONL 0x0007.
        let mut ap = vec![NAL_AP << 1, 1, 0, 7];
        for nal in [[NAL_VPS << 1, 1, 0xaa], [NAL_SPS << 1, 1, 0xbb]] {
            ap.extend_from_slice(&(nal.len() as u16).to_be_bytes());
            ap.extend_from_slice(&nal);
        }
        // FU carrying an IDR (type 19) in three fragments.
        let fu = |flags: u8, data: &[u8]| {
            let mut v = vec![NAL_FU << 1, 1, flags | 19, 0, 7];
            v.extend_from_slice(data);
            v
        };
        let (f1, f2, f3) = (fu(0x80, &[1, 2]), fu(0, &[3]), fu(0x40, &[4]));
        let single = vec![1 << 1, 1, 0, 8, 9, 9];
        let pkts: Vec<(u16, &[u8])> = vec![(65534, &ap), (65535, &f1), (0, &f2), (1, &f3), (2, &single)];
        let nals = depayload(&pkts);
        assert_eq!(nals.len(), 4);
        assert_eq!(nals[0], vec![NAL_VPS << 1, 1, 0xaa]);
        assert_eq!(nals[2], vec![19 << 1, 1, 1, 2, 3, 4]);
        assert!(is_irap(&nals[2]));
        assert_eq!(nals[3], vec![2, 1, 9, 9]);
        assert_eq!(first_donl(&pkts), Some(7));

        // Missing middle fragment drops the NAL.
        let gap: Vec<(u16, &[u8])> = vec![(1, &f1), (3, &f3)];
        assert!(depayload(&gap).is_empty());
    }

    #[test]
    fn reads_pps_parallelism() {
        // x265 4:4:4 PPS with wavefront parallelism on and off.
        assert_eq!(pps_parallelism(&[0x44, 0x01, 0xc1, 0x72, 0x86, 0x0c, 0x46, 0x24]), Some((false, true)));
        assert_eq!(pps_parallelism(&[0x44, 0x01, 0xc1, 0x72, 0x86, 0x0c, 0x42, 0x24]), Some((false, false)));
    }

    #[test]
    fn reads_pps_id() {
        // ue(v) "1" => 0, "010" => 1, "00111" => 6
        assert_eq!(pps_id(&[0x44, 0x01, 0b1000_0000]), Some(0));
        assert_eq!(pps_id(&[0x44, 0x01, 0b0100_0000]), Some(1));
        assert_eq!(pps_id(&[0x44, 0x01, 0b0011_1000]), Some(6));
    }
}
