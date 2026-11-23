//! Haraka v2 (Haraka-256/256 and Haraka-512/256) as Burp's Decoder computes it:
//! a byte-exact port of Bouncy Castle's `Haraka256Digest` / `Haraka512Digest`
//! (`HarakaBase.java`, bc-java main, fetched 2026-11-22). No vetted Rust crate
//! implements Haraka, so the AES round and mixing layers are transcribed here
//! and pinned to BC's published known-answer tests.
//!
//! BC parity note: these are fixed-input-length digests. BC throws for input
//! that is not exactly 32 bytes (Haraka-256) or 64 bytes (Haraka-512), and so
//! do we - the Decoder surfaces that as `<error: ...>` rather than inventing a
//! padding Burp would not use.

use crate::haraka_tables::{RC, S};

fn s_box(x: u8) -> u8 {
    S[(x >> 4) as usize][(x & 0x0f) as usize]
}

fn mul_x(p: u8) -> u8 {
    ((p & 0x7f) << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 })
}

/// One AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey) exactly as
/// BC's HarakaBase.aesEnc does it.
fn aes_enc(s: &[u8; 16], rk: &[u8; 16]) -> [u8; 16] {
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = s_box(s[i]);
    }
    let b = [
        b[0], b[5], b[10], b[15], b[4], b[9], b[14], b[3], b[8], b[13], b[2], b[7], b[12], b[1],
        b[6], b[11],
    ];
    let mut out = [0u8; 16];
    for i in 0..4 {
        let a = &b[4 * i..4 * i + 4];
        out[4 * i] = mul_x(a[0]) ^ mul_x(a[1]) ^ a[1] ^ a[2] ^ a[3];
        out[4 * i + 1] = a[0] ^ mul_x(a[1]) ^ mul_x(a[2]) ^ a[2] ^ a[3];
        out[4 * i + 2] = a[0] ^ a[1] ^ mul_x(a[2]) ^ mul_x(a[3]) ^ a[3];
        out[4 * i + 3] = mul_x(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ mul_x(a[3]);
    }
    for i in 0..16 {
        out[i] ^= rk[i];
    }
    out
}

fn mix256(s1: &[[u8; 16]; 2]) -> [[u8; 16]; 2] {
    let mut s2 = [[0u8; 16]; 2];
    s2[0][0..4].copy_from_slice(&s1[0][0..4]);
    s2[0][4..8].copy_from_slice(&s1[1][0..4]);
    s2[0][8..12].copy_from_slice(&s1[0][4..8]);
    s2[0][12..16].copy_from_slice(&s1[1][4..8]);
    s2[1][0..4].copy_from_slice(&s1[0][8..12]);
    s2[1][4..8].copy_from_slice(&s1[1][8..12]);
    s2[1][8..12].copy_from_slice(&s1[0][12..16]);
    s2[1][12..16].copy_from_slice(&s1[1][12..16]);
    s2
}

fn mix512(s1: &[[u8; 16]; 4]) -> [[u8; 16]; 4] {
    let mut s2 = [[0u8; 16]; 4];
    s2[0][0..4].copy_from_slice(&s1[0][12..16]);
    s2[0][4..8].copy_from_slice(&s1[2][12..16]);
    s2[0][8..12].copy_from_slice(&s1[1][12..16]);
    s2[0][12..16].copy_from_slice(&s1[3][12..16]);
    s2[1][0..4].copy_from_slice(&s1[2][0..4]);
    s2[1][4..8].copy_from_slice(&s1[0][0..4]);
    s2[1][8..12].copy_from_slice(&s1[3][0..4]);
    s2[1][12..16].copy_from_slice(&s1[1][0..4]);
    s2[2][0..4].copy_from_slice(&s1[2][4..8]);
    s2[2][4..8].copy_from_slice(&s1[0][4..8]);
    s2[2][8..12].copy_from_slice(&s1[3][4..8]);
    s2[2][12..16].copy_from_slice(&s1[1][4..8]);
    s2[3][0..4].copy_from_slice(&s1[0][8..12]);
    s2[3][4..8].copy_from_slice(&s1[2][8..12]);
    s2[3][8..12].copy_from_slice(&s1[1][8..12]);
    s2[3][12..16].copy_from_slice(&s1[3][8..12]);
    s2
}

/// Haraka-256/256 permutation + feed-forward on one 32-byte block.
pub fn haraka256_256(msg: &[u8; 32]) -> [u8; 32] {
    let mut s: [[u8; 16]; 2] = [
        msg[0..16].try_into().unwrap(),
        msg[16..32].try_into().unwrap(),
    ];
    for r in 0..5 {
        for j in 0..2 {
            s[0] = aes_enc(&s[0], &RC[4 * r + 2 * j]);
            s[1] = aes_enc(&s[1], &RC[4 * r + 2 * j + 1]);
        }
        s = mix256(&s);
    }
    let mut out = [0u8; 32];
    for i in 0..16 {
        out[i] = s[0][i] ^ msg[i];
        out[16 + i] = s[1][i] ^ msg[16 + i];
    }
    out
}

/// Haraka-512/256 permutation + feed-forward on one 64-byte block, truncated
/// the way BC truncates (high halves of lanes 0/1, low halves of lanes 2/3).
pub fn haraka512_256(msg: &[u8; 64]) -> [u8; 32] {
    let mut s: [[u8; 16]; 4] = [
        msg[0..16].try_into().unwrap(),
        msg[16..32].try_into().unwrap(),
        msg[32..48].try_into().unwrap(),
        msg[48..64].try_into().unwrap(),
    ];
    for r in 0..5 {
        for j in 0..2 {
            for (i, block) in s.iter_mut().enumerate() {
                *block = aes_enc(block, &RC[8 * r + 4 * j + i]);
            }
        }
        s = mix512(&s);
    }
    for i in 0..4 {
        for b in 0..16 {
            s[i][b] ^= msg[16 * i + b];
        }
    }
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&s[0][8..16]);
    out[8..16].copy_from_slice(&s[1][8..16]);
    out[16..24].copy_from_slice(&s[2][0..8]);
    out[24..32].copy_from_slice(&s[3][0..8]);
    out
}

/// Burp's HARAKA-256: exactly 32 bytes in, 32 out.
pub fn digest256(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() != 32 {
        return Err(format!(
            "Haraka-256 takes exactly 32 bytes of input, got {} (Bouncy Castle parity)",
            data.len()
        ));
    }
    Ok(haraka256_256(data.try_into().unwrap()).to_vec())
}

/// Burp's HARAKA-512: exactly 64 bytes in, 32 out.
pub fn digest512(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() != 64 {
        return Err(format!(
            "Haraka-512 takes exactly 64 bytes of input, got {} (Bouncy Castle parity)",
            data.len()
        ));
    }
    Ok(haraka512_256(data.try_into().unwrap()).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// BC Haraka256DigestTest: input bytes 00..1f.
    #[test]
    fn haraka256_bc_vector() {
        let msg: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            hex(&digest256(&msg).unwrap()),
            "8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c"
        );
    }

    /// BC Haraka512DigestTest: input bytes 00..3f.
    #[test]
    fn haraka512_bc_vector() {
        let msg: Vec<u8> = (0u8..64).collect();
        assert_eq!(
            hex(&digest512(&msg).unwrap()),
            "be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa"
        );
    }

    /// BC rejects wrong-length input; so do we.
    #[test]
    fn haraka_length_parity() {
        assert!(digest256(b"abc").is_err());
        assert!(digest256(&[0u8; 33]).is_err());
        assert!(digest512(b"abc").is_err());
        assert!(digest512(&[0u8; 63]).is_err());
    }
}
