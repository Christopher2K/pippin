//! RFB security type 33 (0x21): Apple's SRP-4096-SHA512-PBKDF2 exchange and
//! the legacy RSA1 + AES-ECB credential path.
//!
//! Both paths begin with the same "RSA1 init" request that fetches the
//! server's RSA-2048 public key, and both yield a 16-byte AES key that later
//! unwraps the enc1103 record-layer keys.

use std::io::{Read, Write};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Context, Result, bail};
use num_bigint::BigUint;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use super::wire::{Cursor, read_u32, read_vec};

const SRP_MODULUS_LEN: usize = 512;
const SRP_HASH_LEN: u8 = 64;
const SRP_DK_LEN: usize = 128;
const SRP_MAX_ITERATIONS: u64 = 1_000_000;
const RSA_BLOCK_LEN: usize = 256;
const CRED_SLOT_LEN: usize = 64;

/// The server rejected the credentials or answered in a shape that tells us
/// to try the other auth path.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("server did not take the SRP path ({0}-byte challenge)")]
    SrpUnavailable(usize),
    #[error("authentication rejected by server (result {0})")]
    Rejected(u32),
}

/// Requests the server's RSA public key. The leading 0x21 byte doubles as
/// our choice of security type.
fn rsa1_init<S: Read + Write>(sock: &mut S) -> Result<RsaPublicKey> {
    sock.write_all(b"\x21\x00\x00\x00\x0a\x01\x00RSA1\x00\x00\x00\x00")?;
    let len = read_u32(sock)? as usize;
    let pkt = read_vec(sock, len)?;
    let mut c = Cursor::at(&pkt, 2);
    let key_len = c.u32().context("short RSA1 reply")? as usize;
    let der = c.take(key_len).context("truncated RSA1 public key")?;
    RsaPublicKey::from_public_key_der(der).context("parsing server RSA key")
}

fn rsa_encrypt(key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    key.encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
        .context("RSA encrypt")
}

fn aes_ecb_encrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(&key[..16]));
    for block in data.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
}

/// Legacy path: AES-ECB-encrypted credential slots plus the RSA-wrapped AES
/// key. Returns the AES key.
pub fn nonsrp_auth<S: Read + Write>(sock: &mut S, user: &str, password: &str) -> Result<[u8; 16]> {
    let server_key = rsa1_init(sock)?;
    let mut aes_key = [0u8; 16];
    OsRng.fill_bytes(&mut aes_key);

    let mut creds = Vec::with_capacity(2 * CRED_SLOT_LEN);
    for value in [user, password] {
        let mut slot = [0u8; CRED_SLOT_LEN];
        OsRng.fill_bytes(&mut slot);
        let bytes = value.as_bytes();
        let n = bytes.len().min(CRED_SLOT_LEN - 1);
        slot[..n].copy_from_slice(&bytes[..n]);
        slot[n] = 0;
        creds.extend_from_slice(&slot);
    }
    aes_ecb_encrypt(&aes_key, &mut creds);
    let enc_key = rsa_encrypt(&server_key, &aes_key)?;

    let mut blob = Vec::new();
    blob.extend_from_slice(b"\x01\x00RSA1\x00\x01");
    blob.extend_from_slice(&creds);
    blob.extend_from_slice(b"\x00\x01");
    blob.extend_from_slice(&enc_key);
    let mut msg = (blob.len() as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&blob);
    sock.write_all(&msg)?;

    read_vec(sock, 4)?; // padding
    let result = read_u32(sock)?;
    if result != 0 {
        return Err(AuthError::Rejected(result).into());
    }
    Ok(aes_key)
}

struct Challenge {
    n_bytes: Vec<u8>,
    g: BigUint,
    salt: Vec<u8>,
    b_bytes: Vec<u8>,
    iterations: u64,
    cap: Vec<u8>,
}

fn parse_challenge(body: &[u8]) -> Option<Challenge> {
    let mut c = Cursor::at(body, 12);
    if c.u8()? != 0 {
        return None;
    }
    let n_bytes = c.take(SRP_MODULUS_LEN)?.to_vec();
    let g_len = c.u16()? as usize;
    let g = BigUint::from_bytes_be(c.take(g_len)?);
    let salt_len = c.u8()? as usize;
    let salt = c.take(salt_len)?.to_vec();
    let b_len = c.u16()? as usize;
    let b_bytes = c.take(b_len)?.to_vec();
    let iterations = c.u64()?;
    let cap_len = c.u16()? as usize;
    let cap = c.take(cap_len)?.to_vec();
    Some(Challenge { n_bytes, g, salt, b_bytes, iterations, cap })
}

fn pad(v: &BigUint, len: usize) -> Vec<u8> {
    let raw = v.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(raw.len())];
    out.extend_from_slice(&raw);
    out
}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

struct Proof {
    a_pub: Vec<u8>,
    m1: [u8; 64],
    k: [u8; 64],
}

fn solve_srp(ch: &Challenge, password: &str) -> Proof {
    let n = BigUint::from_bytes_be(&ch.n_bytes);
    let g_pad = pad(&ch.g, SRP_MODULUS_LEN);
    let k = BigUint::from_bytes_be(&sha512(&[&ch.n_bytes, &g_pad]));

    let mut a_raw = [0u8; 64];
    OsRng.fill_bytes(&mut a_raw);
    let a = BigUint::from_bytes_be(&a_raw) % (&n - 1u32) + 1u32;
    let a_pub = pad(&ch.g.modpow(&a, &n), SRP_MODULUS_LEN);

    let u = BigUint::from_bytes_be(&sha512(&[&a_pub, &ch.b_bytes]));

    let mut dk = [0u8; SRP_DK_LEN];
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &ch.salt, ch.iterations as u32, &mut dk);
    let inner = sha512(&[b":", &dk]);
    let x = BigUint::from_bytes_be(&sha512(&[&ch.salt, &inner])) % &n;

    let b = BigUint::from_bytes_be(&ch.b_bytes);
    let kgx = (&k * ch.g.modpow(&x, &n)) % &n;
    let base = ((&b + &n) - kgx) % &n;
    let s = base.modpow(&(&a + &u * &x), &n);
    let k_sess = sha512(&[&pad(&s, SRP_MODULUS_LEN)]);

    let h_n = sha512(&[&ch.n_bytes]);
    let h_g = sha512(&[&g_pad]);
    let xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(a, b)| a ^ b).collect();
    let h_empty = sha512(&[]);
    let m1 = sha512(&[&xor, &h_empty, &ch.salt, &a_pub, &ch.b_bytes, &k_sess]);

    Proof { a_pub, m1, k: k_sess }
}

/// SRP-6a against screensharingd. Returns `SHA256(K)[..16]`.
pub fn srp_auth<S: Read + Write>(sock: &mut S, user: &str, password: &str) -> Result<[u8; 16]> {
    let server_key = rsa1_init(sock)?;

    // c2s1: the username rides RSA-encrypted in the "modulus" slot.
    let user_b = user.as_bytes();
    let mut inner = (user_b.len() as u32).to_be_bytes().to_vec();
    inner.extend_from_slice(user_b);
    inner.extend_from_slice(&[0, 0, 0]);
    let mut plain = (inner.len() as u32).to_be_bytes().to_vec();
    plain.extend_from_slice(&inner);
    let enc = rsa_encrypt(&server_key, &plain)?;
    if enc.len() != RSA_BLOCK_LEN {
        bail!("unexpected RSA block size {}", enc.len());
    }
    let mut c2s1 = Vec::with_capacity(654);
    c2s1.extend_from_slice(&650u32.to_be_bytes());
    c2s1.extend_from_slice(&1u16.to_le_bytes());
    c2s1.extend_from_slice(b"RSA1\x00\x02");
    c2s1.extend_from_slice(&(RSA_BLOCK_LEN as u16).to_be_bytes());
    c2s1.extend_from_slice(&enc);
    c2s1.resize(4 + 650, 0);
    sock.write_all(&c2s1)?;

    let len = read_u32(sock)? as usize;
    let body = read_vec(sock, len)?;
    if len < 1000 {
        return Err(AuthError::SrpUnavailable(len).into());
    }
    let ch = parse_challenge(&body).context("malformed SRP challenge")?;
    if ch.iterations > SRP_MAX_ITERATIONS {
        bail!("SRP iteration count {} exceeds cap", ch.iterations);
    }
    tracing::debug!(iterations = ch.iterations, salt = ch.salt.len(), "SRP challenge");

    let proof = solve_srp(&ch, password);

    let mut civ = [0u8; 16];
    OsRng.fill_bytes(&mut civ);
    let mut sd = Vec::new();
    sd.extend_from_slice(&(SRP_MODULUS_LEN as u16).to_be_bytes());
    sd.extend_from_slice(&proof.a_pub);
    sd.push(SRP_HASH_LEN);
    sd.extend_from_slice(&proof.m1);
    sd.extend_from_slice(&(ch.cap.len() as u16).to_be_bytes());
    sd.extend_from_slice(&ch.cap);
    sd.push(16);
    sd.extend_from_slice(&civ);

    let mut pay = Vec::with_capacity(1076);
    pay.extend_from_slice(&1u16.to_le_bytes());
    pay.extend_from_slice(b"RSA1\x00\x02");
    pay.extend_from_slice(&((sd.len() + 4) as u16).to_be_bytes());
    pay.extend_from_slice(&(sd.len() as u32).to_be_bytes());
    pay.extend_from_slice(&sd);
    if pay.len() > 1076 {
        bail!("SRP proof too large ({} bytes)", pay.len());
    }
    pay.resize(1076, 0);
    let mut msg = 1076u32.to_be_bytes().to_vec();
    msg.extend_from_slice(&pay);
    sock.write_all(&msg)?;

    let m2_len = read_u32(sock)? as usize;
    read_vec(sock, m2_len)?;
    let result = read_u32(sock)?;
    if result != 0 {
        return Err(AuthError::Rejected(result).into());
    }
    let digest = Sha256::digest(proof.k);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    Ok(key)
}

/// AES-128-ECB encrypts a zero-padded 64-byte field. Used for SessionSelect
/// cmd=2 credentials.
pub fn ecb_field(key: &[u8; 16], value: &str) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let b = value.as_bytes();
    let n = b.len().min(64);
    buf[..n].copy_from_slice(&b[..n]);
    aes_ecb_encrypt(key, &mut buf);
    buf
}

/// AES-128-ECB encrypts a single block in place.
pub fn ecb_block(key: &[u8; 16], block: &mut [u8; 16]) {
    aes_ecb_encrypt(key, block);
}
