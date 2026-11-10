//! Pure-Rust cryptographic core for VeilProxy. No Python types in this file,
//! so it can be unit-tested with plain `cargo test`.
//!
//! Primitives
//!   * Shamir secret sharing over GF(2^8) (AES polynomial 0x11b), branch-free multiply
//!   * HKDF-SHA256 key derivation (per-session subkeys, key-check value, HMAC tag key)
//!   * AES-256-GCM authenticated encryption with caller-supplied associated data
//!   * Zeroized key custody: the master key lives only inside `Vault`

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
const CT_VERSION: u8 = 1;
const HKDF_SALT: &[u8] = b"veilproxy-v1";
const SHARE_PREFIX: &str = "veil1";

// ---------------------------------------------------------------- GF(2^8)

/// Branch-free multiplication in GF(2^8) modulo x^8+x^4+x^3+x+1.
#[inline]
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        p ^= a & mask;
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & hi);
        b >>= 1;
    }
    p
}

/// Multiplicative inverse via a^254 (the exponent is a public constant).
#[inline]
pub fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u32;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

// ---------------------------------------------------------------- Shamir

pub struct RawShare {
    pub k: u8,
    pub x: u8,
    pub y: Vec<u8>,
}

fn share_crc(k: u8, x: u8, y: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(SHARE_PREFIX.as_bytes());
    h.update([k, x]);
    h.update(y);
    hex::encode(&h.finalize()[..4])
}

pub fn encode_share(s: &RawShare) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        SHARE_PREFIX,
        s.k,
        s.x,
        hex::encode(&s.y),
        share_crc(s.k, s.x, &s.y)
    )
}

pub fn decode_share(text: &str) -> Result<RawShare, String> {
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 5 || parts[0] != SHARE_PREFIX {
        return Err("malformed share (expected veil1:<k>:<x>:<hex>:<crc>)".into());
    }
    let k: u8 = parts[1].parse().map_err(|_| "malformed share: bad threshold".to_string())?;
    let x: u8 = parts[2].parse().map_err(|_| "malformed share: bad index".to_string())?;
    let y = hex::decode(parts[3]).map_err(|_| "malformed share: bad hex payload".to_string())?;
    if x == 0 || k < 2 || y.is_empty() {
        return Err("malformed share: invalid fields".into());
    }
    if share_crc(k, x, &y) != parts[4] {
        return Err("share checksum mismatch (corrupted or mistyped share)".into());
    }
    Ok(RawShare { k, x, y })
}

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
pub fn split(secret: &[u8], n: u8, k: u8) -> Result<Vec<RawShare>, String> {
    if secret.is_empty() {
        return Err("secret must not be empty".into());
    }
    if k < 2 || n < k {
        return Err("require 2 <= threshold <= shares <= 255".into());
    }
    let mut shares: Vec<RawShare> = (1..=n)
        .map(|x| RawShare { k, x, y: Vec::with_capacity(secret.len()) })
        .collect();
    let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
    for &s in secret {
        coeffs[0] = s;
        OsRng.fill_bytes(&mut coeffs[1..]);
        for sh in shares.iter_mut() {
            let mut y = 0u8;
            for c in coeffs.iter().rev() {
                y = gf_mul(y, sh.x) ^ *c; // Horner evaluation
            }
            sh.y.push(y);
        }
    }
    Ok(shares)
}

/// Lagrange interpolation at x = 0. Needs at least the threshold number of shares.
pub fn combine(shares: &[RawShare]) -> Result<Zeroizing<Vec<u8>>, String> {
    if shares.is_empty() {
        return Err("no shares supplied".into());
    }
    let k = shares[0].k;
    let len = shares[0].y.len();
    for s in shares {
        if s.k != k || s.y.len() != len {
            return Err("shares come from different splits".into());
        }
    }
    for (i, a) in shares.iter().enumerate() {
        for b in &shares[i + 1..] {
            if a.x == b.x {
                return Err("duplicate share supplied".into());
            }
        }
    }
    if shares.len() < k as usize {
        return Err(format!("insufficient shares: need {}, got {}", k, shares.len()));
    }
    let used = &shares[..k as usize];
    let mut basis = Zeroizing::new(vec![0u8; used.len()]);
    for (i, si) in used.iter().enumerate() {
        let (mut num, mut den) = (1u8, 1u8);
        for (j, sj) in used.iter().enumerate() {
            if i != j {
                num = gf_mul(num, sj.x);
                den = gf_mul(den, si.x ^ sj.x);
            }
        }
        basis[i] = gf_mul(num, gf_inv(den));
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    for b in 0..len {
        let mut acc = 0u8;
        for (i, si) in used.iter().enumerate() {
            acc ^= gf_mul(si.y[b], basis[i]);
        }
        out[b] = acc;
    }
    Ok(out)
}

pub fn combine_strings(shares: &[String]) -> Result<Zeroizing<Vec<u8>>, String> {
    let raw: Result<Vec<RawShare>, String> = shares.iter().map(|s| decode_share(s)).collect();
    combine(&raw?)
}

// ---------------------------------------------------------------- KDF / MAC / AEAD

pub fn derive(master: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), master);
    let mut okm = Zeroizing::new(vec![0u8; len]);
    hk.expand(info, &mut okm).expect("hkdf output length is valid");
    okm
}

fn info_for(label: &str, session: &str) -> Vec<u8> {
    let mut v = label.as_bytes().to_vec();
    v.push(b'|');
    v.extend_from_slice(session.as_bytes());
    v
}

/// Public verification value for a master key (lets us detect a wrong reconstruction).
pub fn key_check(master: &[u8]) -> String {
    hex::encode(&derive(master, b"keycheck", 16)[..])
}

pub fn seal(master: &[u8], session: &str, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let key = derive(master, &info_for("session", session), KEY_LEN);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad })
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(CT_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(master: &[u8], session: &str, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() < 1 + NONCE_LEN + 16 || blob[0] != CT_VERSION {
        return Err("ciphertext malformed or unsupported version".into());
    }
    let key = derive(master, &info_for("session", session), KEY_LEN);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&blob[1..1 + NONCE_LEN]),
            Payload { msg: &blob[1 + NONCE_LEN..], aad },
        )
        .map_err(|_| "authentication failed (wrong key, wrong context or tampered data)".to_string())?;
    Ok(Zeroizing::new(pt))
}

/// Keyed, session-scoped pseudonym tag (HMAC-SHA256) used to de-duplicate values
/// without storing them in the clear.
pub fn tag(master: &[u8], session: &str, data: &[u8]) -> String {
    let key = derive(master, &info_for("tag", session), KEY_LEN);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("hmac accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

// ---------------------------------------------------------------- Vault

/// Generates a fresh 256-bit master key, splits it, and returns the shares plus the
/// key-check value. The master key is zeroized before this function returns.
pub fn generate(n: u8, k: u8) -> Result<(Vec<String>, String), String> {
    let mut master = Zeroizing::new(vec![0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut master);
    let shares = split(&master, n, k)?;
    Ok((shares.iter().map(encode_share).collect(), key_check(&master)))
}

#[derive(Default)]
pub struct Vault {
    key: Option<Zeroizing<[u8; KEY_LEN]>>,
}

impl Vault {
    pub fn new() -> Self {
        Self { key: None }
    }
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }
    pub fn lock(&mut self) {
        self.key = None; // Zeroizing wipes on drop
    }
    /// Ok(true): unlocked. Ok(false): shares combined but key-check failed.
    /// Err: malformed / insufficient / inconsistent shares.
    pub fn unlock(&mut self, shares: &[String], check: &str) -> Result<bool, String> {
        let secret = combine_strings(shares)?;
        if secret.len() != KEY_LEN {
            return Ok(false);
        }
        let ok: bool = key_check(&secret).as_bytes().ct_eq(check.as_bytes()).into();
        if ok {
            let mut k = Zeroizing::new([0u8; KEY_LEN]);
            k.copy_from_slice(&secret);
            self.key = Some(k);
        }
        Ok(ok)
    }
    fn master(&self) -> Result<&[u8], String> {
        self.key
            .as_ref()
            .map(|k| &k[..])
            .ok_or_else(|| "vault is locked".to_string())
    }
    pub fn seal(&self, session: &str, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        seal(self.master()?, session, pt, aad)
    }
    pub fn open(&self, session: &str, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        open(self.master()?, session, blob, aad)
    }
    pub fn tag(&self, session: &str, data: &[u8]) -> Result<String, String> {
        Ok(tag(self.master()?, session, data))
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn clone_share(s: &RawShare) -> RawShare {
        RawShare { k: s.k, x: s.x, y: s.y.clone() }
    }

    #[test]
    fn gf_known_vectors() {
        assert_eq!(gf_mul(0x57, 0x83), 0xc1); // FIPS-197 example
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }

    #[test]
    fn shamir_every_threshold_subset_reconstructs() {
        let secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
        let sh = split(&secret, 5, 3).unwrap();
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let pick = vec![clone_share(&sh[a]), clone_share(&sh[b]), clone_share(&sh[c])];
                    assert_eq!(&combine(&pick).unwrap()[..], &secret[..]);
                }
            }
        }
    }

    #[test]
    fn shamir_below_threshold_is_rejected() {
        let sh = split(b"hello world 0123", 5, 3).unwrap();
        let two = vec![clone_share(&sh[0]), clone_share(&sh[1])];
        assert!(combine(&two).unwrap_err().contains("insufficient"));
    }

    #[test]
    fn share_strings_roundtrip_and_detect_corruption() {
        let sh = split(&[1, 2, 3, 4], 3, 2).unwrap();
        let s = encode_share(&sh[0]);
        let back = decode_share(&s).unwrap();
        assert_eq!((back.k, back.x, back.y), (2, sh[0].x, sh[0].y.clone()));
        let mut bad = s.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == '0' { '1' } else { '0' });
        assert!(decode_share(&bad).is_err());
    }

    #[test]
    fn vault_unlock_wrong_shares_fails_key_check() {
        let (a, check_a) = generate(5, 3).unwrap();
        let (b, _) = generate(5, 3).unwrap();
        let mut v = Vault::new();
        let mixed = vec![a[0].clone(), a[1].clone(), b[2].clone()];
        assert_eq!(v.unlock(&mixed, &check_a).unwrap(), false);
        assert!(!v.is_unlocked());
        assert!(v.unlock(&a[..2].to_vec(), &check_a).is_err());
        assert_eq!(v.unlock(&vec![a[4].clone(), a[1].clone(), a[2].clone()], &check_a).unwrap(), true);
        assert!(v.is_unlocked());
        v.lock();
        assert!(v.seal("s", b"x", b"").is_err());
    }

    #[test]
    fn aead_roundtrip_binding_and_tamper() {
        let (sh, check) = generate(3, 2).unwrap();
        let mut v = Vault::new();
        assert!(v.unlock(&sh[..2].to_vec(), &check).unwrap());
        let ct = v.seal("sess", b"sk-secret-value", b"sess|[APIKEY_1]").unwrap();
        assert_eq!(&v.open("sess", &ct, b"sess|[APIKEY_1]").unwrap()[..], b"sk-secret-value");
        assert!(v.open("sess", &ct, b"sess|[APIKEY_2]").is_err()); // AAD binding
        assert!(v.open("other", &ct, b"sess|[APIKEY_1]").is_err()); // session isolation
        let mut bad = ct.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(v.open("sess", &bad, b"sess|[APIKEY_1]").is_err()); // tamper
        let ct2 = v.seal("sess", b"sk-secret-value", b"sess|[APIKEY_1]").unwrap();
        assert_ne!(ct, ct2); // fresh nonce
    }

    #[test]
    fn tag_is_deterministic_per_session_and_scoped() {
        let (sh, check) = generate(3, 2).unwrap();
        let mut v = Vault::new();
        v.unlock(&sh[..2].to_vec(), &check).unwrap();
        assert_eq!(v.tag("a", b"x").unwrap(), v.tag("a", b"x").unwrap());
        assert_ne!(v.tag("a", b"x").unwrap(), v.tag("b", b"x").unwrap());
        assert_ne!(v.tag("a", b"x").unwrap(), v.tag("a", b"y").unwrap());
    }
}
