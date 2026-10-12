//! enc1103: Apple's encrypted RFB record layer.
//!
//! After auth the server sends a 36-byte blob (encoding 1103) holding an
//! AES-128 key and IV, each ECB-wrapped under the auth key. From the
//! PostEncryptionToggle onwards every message in both directions is framed
//! as:
//!
//! ```text
//! u16 BE ciphertext_len || AES-128-CBC( u16 BE len || msg || zero pad || SHA1(u32 BE seq || preceding bytes) )
//! ```
//!
//! Each direction keeps its own CBC chaining state and sequence counter.

use std::io::{self, Read};

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, generic_array::GenericArray};
use sha1::{Digest, Sha1};

const MAC_LEN: usize = 20;
const BLOCK: usize = 16;
/// How far ahead of the expected receive counter a MAC may match. The server
/// occasionally skips counter values.
const RECV_WINDOW: u32 = 6;

type CbcEnc = cbc::Encryptor<Aes128>;
type CbcDec = cbc::Decryptor<Aes128>;

/// Record-layer key material unwrapped from the 1103 blob.
#[derive(Clone)]
pub struct RecordKeys {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

impl RecordKeys {
    /// Unwraps the 36-byte 1103 payload (`u32 generation || ecb(key) || ecb(iv)`).
    pub fn unwrap(blob: &[u8], auth_key: &[u8; 16]) -> Option<Self> {
        if blob.len() < 36 {
            return None;
        }
        let ecb = Aes128::new(GenericArray::from_slice(auth_key));
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&blob[4..20]);
        iv.copy_from_slice(&blob[20..36]);
        ecb.decrypt_block(GenericArray::from_mut_slice(&mut key));
        ecb.decrypt_block(GenericArray::from_mut_slice(&mut iv));
        Some(Self { key, iv })
    }
}

fn mac(seq: u32, data: &[u8]) -> [u8; MAC_LEN] {
    let mut h = Sha1::new();
    h.update(seq.to_be_bytes());
    h.update(data);
    h.finalize().into()
}

/// Outbound half: encrypts messages into wire records.
pub struct RecordSealer {
    cbc: CbcEnc,
    seq: u32,
}

impl RecordSealer {
    pub fn new(keys: &RecordKeys) -> Self {
        Self { cbc: CbcEnc::new(&keys.key.into(), &keys.iv.into()), seq: 0 }
    }

    /// Wraps one message. Panics only if `msg` exceeds the u16 length field,
    /// which no client message comes close to.
    pub fn seal(&mut self, msg: &[u8]) -> Vec<u8> {
        assert!(msg.len() <= u16::MAX as usize, "record too large");
        let pad = (BLOCK - (2 + msg.len() + MAC_LEN) % BLOCK) % BLOCK;
        let ct_len = 2 + msg.len() + pad + MAC_LEN;
        let mut out = Vec::with_capacity(2 + ct_len);
        out.extend_from_slice(&(ct_len as u16).to_be_bytes());
        out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        out.extend_from_slice(msg);
        out.resize(out.len() + pad, 0);
        let tag = mac(self.seq, &out[2..]);
        out.extend_from_slice(&tag);
        for block in out[2..].as_chunks_mut::<BLOCK>().0 {
            self.cbc.encrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        self.seq = self.seq.wrapping_add(1);
        out
    }
}

/// Inbound half: reads and decrypts records from a byte stream.
pub struct RecordOpener {
    cbc: CbcDec,
    seq: u32,
}

/// Result of reading one record.
pub enum Opened {
    /// The decrypted message body.
    Message(Vec<u8>),
    /// The record decrypted but no counter in the window matched its MAC.
    /// The CBC state still advanced, so the stream stays in sync.
    BadMac,
}

impl RecordOpener {
    pub fn new(keys: &RecordKeys) -> Self {
        Self { cbc: CbcDec::new(&keys.key.into(), &keys.iv.into()), seq: 0 }
    }

    /// Blocks until a full record arrives and returns its plaintext.
    pub fn read(&mut self, r: &mut impl Read) -> io::Result<Opened> {
        let mut len = [0u8; 2];
        r.read_exact(&mut len)?;
        let len = u16::from_be_bytes(len) as usize;
        if len == 0 || !len.is_multiple_of(BLOCK) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad record length {len}"),
            ));
        }
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct)?;
        Ok(self.open(ct))
    }

    fn open(&mut self, mut buf: Vec<u8>) -> Opened {
        for block in buf.as_chunks_mut::<BLOCK>().0 {
            self.cbc.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        let expected = self.seq;
        self.seq = self.seq.wrapping_add(1);
        if buf.len() <= MAC_LEN + 2 {
            return Opened::BadMac;
        }
        let (body, tag) = buf.split_at(buf.len() - MAC_LEN);
        let first = expected.saturating_sub(1);
        for seq in first..expected + RECV_WINDOW {
            if mac(seq, body) == tag {
                self.seq = seq.wrapping_add(1);
                let n = (u16::from_be_bytes([body[0], body[1]]) as usize).min(body.len() - 2);
                return Opened::Message(body[2..2 + n].to_vec());
            }
        }
        Opened::BadMac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> RecordKeys {
        RecordKeys { key: [7u8; 16], iv: [9u8; 16] }
    }

    #[test]
    fn round_trip_keeps_chaining_and_counters() {
        let mut tx = RecordSealer::new(&keys());
        let mut rx = RecordOpener::new(&keys());
        let msgs: [&[u8]; 4] = [b"", b"hello", &[0xAB; 33], &[1u8; 300]];
        let mut wire = Vec::new();
        for m in msgs {
            let rec = tx.seal(m);
            assert_eq!((rec.len() - 2) % 16, 0);
            wire.extend_from_slice(&rec);
        }
        let mut cur = io::Cursor::new(wire);
        for m in msgs {
            match rx.read(&mut cur).unwrap() {
                Opened::Message(got) => assert_eq!(got, m),
                Opened::BadMac => panic!("mac mismatch"),
            }
        }
    }

    #[test]
    fn tolerates_skipped_sequence_numbers() {
        let mut tx = RecordSealer::new(&keys());
        let mut rx = RecordOpener::new(&keys());
        tx.seq = 3; // the server skipped three counter values
        let rec = tx.seal(b"skip");
        let mut cur = io::Cursor::new(rec);
        assert!(matches!(rx.read(&mut cur).unwrap(), Opened::Message(m) if m == b"skip"));
        assert_eq!(rx.seq, 4);
    }

    #[test]
    fn unwraps_key_blob() {
        let auth = [3u8; 16];
        let ecb = Aes128::new(GenericArray::from_slice(&auth));
        let mut blob = vec![0u8; 36];
        let mut k = GenericArray::clone_from_slice(&[1u8; 16]);
        let mut v = GenericArray::clone_from_slice(&[2u8; 16]);
        use aes::cipher::BlockEncrypt;
        ecb.encrypt_block(&mut k);
        ecb.encrypt_block(&mut v);
        blob[4..20].copy_from_slice(&k);
        blob[20..36].copy_from_slice(&v);
        let keys = RecordKeys::unwrap(&blob, &auth).unwrap();
        assert_eq!(keys.key, [1u8; 16]);
        assert_eq!(keys.iv, [2u8; 16]);
    }
}
