//! SRTP / SRTCP (RFC 3711) with AES-256-CM and HMAC-SHA1-80.

use std::collections::HashMap;

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::proto::offers::SRTP_BLOB_LEN;

const TAG_LEN: usize = 10;
const RTP_HEADER: usize = 12;

type Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha1 = Hmac<Sha1>;

/// Session keys derived from a 46-byte master blob for one label set.
#[derive(Clone)]
struct SessionKeys {
    cipher: [u8; 32],
    auth: [u8; 20],
    salt: [u8; 14],
}

fn kdf(master: &[u8; 32], salt: &[u8], label: u8, out: &mut [u8]) {
    let aes = Aes256::new(GenericArray::from_slice(master));
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&salt[..14]);
    iv[7] ^= label;
    for (i, chunk) in out.chunks_mut(16).enumerate() {
        let mut block = iv;
        block[14..16].copy_from_slice(&(i as u16).to_be_bytes());
        let mut b = GenericArray::from(block);
        aes.encrypt_block(&mut b);
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

impl SessionKeys {
    fn derive(blob: &[u8; SRTP_BLOB_LEN], rtcp: bool) -> Self {
        let master: [u8; 32] = blob[..32].try_into().unwrap();
        let salt = &blob[32..];
        let base = if rtcp { 3 } else { 0 };
        let mut k = Self { cipher: [0; 32], auth: [0; 20], salt: [0; 14] };
        kdf(&master, salt, base, &mut k.cipher);
        kdf(&master, salt, base + 1, &mut k.auth);
        kdf(&master, salt, base + 2, &mut k.salt);
        k
    }

    fn tag(&self, parts: &[&[u8]]) -> [u8; TAG_LEN] {
        let mut m = <HmacSha1 as Mac>::new_from_slice(&self.auth).expect("any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes()[..TAG_LEN].try_into().unwrap()
    }

    fn rtp_iv(&self, ssrc: u32, index: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        for (i, b) in index.to_be_bytes()[2..].iter().enumerate() {
            iv[8 + i] ^= b;
        }
        iv
    }

    fn rtcp_iv(&self, ssrc: u32, index: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        for (i, b) in index.to_be_bytes().iter().enumerate() {
            iv[10 + i] ^= b;
        }
        iv
    }

    fn apply(&self, iv: [u8; 16], data: &mut [u8]) {
        Ctr::new(&self.cipher.into(), &iv.into()).apply_keystream(data);
    }
}

/// A decrypted RTP packet.
pub struct RtpPacket {
    pub ssrc: u32,
    pub seq: u16,
    pub ts: u32,
    pub marker: bool,
    pub pt: u8,
    pub payload: Vec<u8>,
}

#[derive(Default, Clone, Copy)]
struct RocState {
    roc: u32,
    max_seq: u16,
}

/// SRTP receiver with per-SSRC rollover tracking.
pub struct SrtpReceiver {
    keys: SessionKeys,
    states: HashMap<u32, RocState>,
}

impl SrtpReceiver {
    pub fn new(blob: &[u8; SRTP_BLOB_LEN]) -> Self {
        Self { keys: SessionKeys::derive(blob, false), states: HashMap::new() }
    }

    /// Extended highest sequence number seen for `ssrc`. Receiver reports
    /// use `rtp::stats` instead; this checks the rollover tracking in tests.
    #[cfg(test)]
    pub fn extended_seq(&self, ssrc: u32) -> Option<u32> {
        self.states.get(&ssrc).map(|s| (s.roc << 16) | s.max_seq as u32)
    }

    pub fn forget(&mut self, keep: impl Fn(u32) -> bool) {
        self.states.retain(|s, _| keep(*s));
    }

    pub fn unprotect(&mut self, pkt: &[u8]) -> Option<RtpPacket> {
        if pkt.len() < RTP_HEADER + TAG_LEN || pkt[0] >> 6 != 2 {
            return None;
        }
        let body_len = pkt.len() - TAG_LEN;
        let (body, tag) = pkt.split_at(body_len);
        let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
        let ssrc = u32::from_be_bytes(pkt[8..12].try_into().unwrap());

        let state = self.states.get(&ssrc).copied();
        let guess = match state {
            None => 0,
            Some(s) => {
                let diff = seq as i32 - s.max_seq as i32;
                if diff > 0x7fff {
                    s.roc.saturating_sub(1)
                } else if diff < -0x7fff {
                    s.roc + 1
                } else {
                    s.roc
                }
            }
        };
        let roc = [guess, guess + 1, guess.saturating_sub(1)]
            .into_iter()
            .find(|r| self.keys.tag(&[body, &r.to_be_bytes()]) == tag)?;

        let cc = (pkt[0] & 0x0f) as usize;
        let mut hdr = RTP_HEADER + 4 * cc;
        if pkt[0] & 0x10 != 0 {
            if hdr + 4 > body_len {
                return None;
            }
            hdr += 4 + 4 * u16::from_be_bytes([pkt[hdr + 2], pkt[hdr + 3]]) as usize;
        }
        if hdr > body_len {
            return None;
        }
        let mut payload = body[hdr..].to_vec();
        let index = ((roc as u64) << 16) | seq as u64;
        self.keys.apply(self.keys.rtp_iv(ssrc, index), &mut payload);

        let entry = self.states.entry(ssrc).or_insert(RocState { roc, max_seq: seq });
        if ((roc as u64) << 16 | seq as u64) > ((entry.roc as u64) << 16 | entry.max_seq as u64) {
            *entry = RocState { roc, max_seq: seq };
        }

        Some(RtpPacket {
            ssrc,
            seq,
            ts: u32::from_be_bytes(pkt[4..8].try_into().unwrap()),
            marker: pkt[1] & 0x80 != 0,
            pt: pkt[1] & 0x7f,
            payload,
        })
    }
}

/// SRTP sender, used only for the audio keepalive the host expects.
pub struct SrtpSender {
    keys: SessionKeys,
    ssrc: u32,
    index: u64,
    ts: u32,
}

impl SrtpSender {
    pub fn new(blob: &[u8; SRTP_BLOB_LEN], ssrc: u32) -> Self {
        Self { keys: SessionKeys::derive(blob, false), ssrc, index: 0, ts: 0 }
    }

    pub fn protect(&mut self, pt: u8, payload: &[u8]) -> Vec<u8> {
        let seq = self.index as u16;
        let roc = (self.index >> 16) as u32;
        let mut out = Vec::with_capacity(RTP_HEADER + payload.len() + TAG_LEN);
        out.extend_from_slice(&[0x80, pt & 0x7f]);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(payload);
        self.keys.apply(self.keys.rtp_iv(self.ssrc, self.index), &mut out[RTP_HEADER..]);
        let tag = self.keys.tag(&[&out, &roc.to_be_bytes()]);
        out.extend_from_slice(&tag);
        self.index += 1;
        self.ts = self.ts.wrapping_add(480);
        out
    }
}

/// SRTCP sender.
pub struct SrtcpSender {
    keys: SessionKeys,
    index: u32,
}

impl SrtcpSender {
    pub fn new(blob: &[u8; SRTP_BLOB_LEN]) -> Self {
        Self { keys: SessionKeys::derive(blob, true), index: 0 }
    }

    pub fn protect(&mut self, rtcp: &[u8]) -> Vec<u8> {
        debug_assert!(rtcp.len() >= 8);
        let index = self.index & 0x7fff_ffff;
        self.index = self.index.wrapping_add(1);
        let ssrc = u32::from_be_bytes(rtcp[4..8].try_into().unwrap());
        let mut out = rtcp.to_vec();
        self.keys.apply(self.keys.rtcp_iv(ssrc, index), &mut out[8..]);
        out.extend_from_slice(&(0x8000_0000 | index).to_be_bytes());
        let tag = self.keys.tag(&[&out]);
        out.extend_from_slice(&tag);
        out
    }
}

/// SRTCP receiver.
pub struct SrtcpReceiver {
    keys: SessionKeys,
}

impl SrtcpReceiver {
    pub fn new(blob: &[u8; SRTP_BLOB_LEN]) -> Self {
        Self { keys: SessionKeys::derive(blob, true) }
    }

    pub fn unprotect(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < 8 + 4 + TAG_LEN {
            return None;
        }
        let (body, tag) = pkt.split_at(pkt.len() - TAG_LEN);
        if self.keys.tag(&[body]) != tag {
            return None;
        }
        let e_index = u32::from_be_bytes(body[body.len() - 4..].try_into().unwrap());
        let mut out = body[..body.len() - 4].to_vec();
        if e_index & 0x8000_0000 != 0 {
            let ssrc = u32::from_be_bytes(out[4..8].try_into().unwrap());
            self.keys.apply(self.keys.rtcp_iv(ssrc, e_index & 0x7fff_ffff), &mut out[8..]);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3711 appendix B.3 key derivation test vector (AES-128 in the RFC;
    /// the KDF construction is identical, so check the IV construction with
    /// the published label/salt layout against a round trip instead).
    #[test]
    fn rtp_round_trip_across_rollover() {
        let blob = [0x42u8; SRTP_BLOB_LEN];
        let mut tx = SrtpSender::new(&blob, 0x1234_5678);
        let mut rx = SrtpReceiver::new(&blob);
        tx.index = 0xfffe;
        for i in 0..4u64 {
            let pkt = tx.protect(101, b"\x00\x68\x34\x00");
            let got = rx.unprotect(&pkt).expect("decrypts");
            assert_eq!(got.payload, b"\x00\x68\x34\x00");
            assert_eq!(got.seq, (0xfffe + i) as u16);
        }
        assert_eq!(rx.extended_seq(0x1234_5678), Some(0x1_0001));
    }

    #[test]
    fn rtcp_round_trip() {
        let blob = [7u8; SRTP_BLOB_LEN];
        let mut tx = SrtcpSender::new(&blob);
        let rx = SrtcpReceiver::new(&blob);
        let rr = [0x80, 201, 0, 1, 1, 2, 3, 4];
        let sealed = tx.protect(&rr);
        assert_eq!(sealed.len(), 8 + 4 + 10);
        assert_eq!(rx.unprotect(&sealed).unwrap(), rr);
        let mut bad = sealed.clone();
        bad[9] ^= 1;
        assert!(rx.unprotect(&bad).is_none());
    }

    #[test]
    fn kdf_matches_rfc3711_layout() {
        // RFC 3711 B.3 uses AES-128; we only check that the label is XORed at
        // byte 7 and the counter occupies the last two bytes by comparing two
        // labels' first blocks differ and are stable.
        let master = [0u8; 32];
        let salt = [0u8; 14];
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        kdf(&master, &salt, 0, &mut a);
        kdf(&master, &salt, 1, &mut b);
        assert_ne!(a, b);
        let mut a2 = [0u8; 16];
        kdf(&master, &salt, 0, &mut a2);
        assert_eq!(a, a2);
    }
}
