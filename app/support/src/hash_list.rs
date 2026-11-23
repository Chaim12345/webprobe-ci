//! The Decoder's full "Hash" menu, matching the 82-entry dropdown measured on
//! real Burp Community 2026.11.2 (see `app/docs/` parity notes and the
//! measurements recorded 2026-11-22). Entries are in Burp's exact menu order,
//! including the `OID.`-prefixed and bare-OID alias spellings Bouncy Castle
//! registers (they compute the same digest as their named twin).
//!
//! Most algorithms delegate to vetted crates. Three need special handling:
//! - HARAKA-256/512: no Rust crate exists; ported byte-exact from Bouncy
//!   Castle (the library Burp uses) in `crate::haraka`, including BC's
//!   fixed-input-length behaviour (error unless exactly 32 / 64 bytes).
//! - KECCAK-288: the sha3 crate ships no 288-bit variant; a tiny Keccak
//!   sponge with rate 128 bytes over the `keccak` crate's audited f1600
//!   permutation covers it.
//! - SKEIN-*: the 2017-era `skein-hash` crate (digest 0.9 API, still builds
//!   clean) covers all 13 state/output combinations.

use crate::haraka;

/// One line of Burp's Decoder Hash menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashSpec {
    /// The exact label Burp shows.
    pub label: &'static str,
    pub alg: Alg,
}

/// The algorithm behind a menu entry (aliases share one variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Blake2b(u8), // digest length in bytes: 20, 32, 48, 64
    Blake2s(u8), // 16, 20, 28, 32
    Blake3,
    Kupyna256,
    Kupyna384,
    Kupyna512,
    /// GOST R 34.11-94 with the CryptoPro S-box (BC's default for GOST3411).
    Gost3411,
    Streebog256,
    Streebog512,
    Haraka256,
    Haraka512,
    Keccak224,
    Keccak256,
    Keccak288,
    Keccak384,
    Keccak512,
    Md2,
    Md4,
    Md5,
    ParallelHash128,
    ParallelHash256,
    Ripemd128,
    Ripemd160,
    Ripemd256,
    Ripemd320,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
    Skein256(u8), // digest length in bytes
    Skein512(u8),
    Skein1024(u8),
    Sm3,
    Tiger,
    TupleHash128,
    TupleHash256,
    Whirlpool,
}

/// The full 82-entry menu in the order measured on Burp Community 2026.11.2.
pub const MENU: &[HashSpec] = &[
    HashSpec {
        label: "BLAKE2B-160",
        alg: Alg::Blake2b(20),
    },
    HashSpec {
        label: "BLAKE2B-256",
        alg: Alg::Blake2b(32),
    },
    HashSpec {
        label: "BLAKE2B-384",
        alg: Alg::Blake2b(48),
    },
    HashSpec {
        label: "BLAKE2B-512",
        alg: Alg::Blake2b(64),
    },
    HashSpec {
        label: "BLAKE2S-128",
        alg: Alg::Blake2s(16),
    },
    HashSpec {
        label: "BLAKE2S-160",
        alg: Alg::Blake2s(20),
    },
    HashSpec {
        label: "BLAKE2S-224",
        alg: Alg::Blake2s(28),
    },
    HashSpec {
        label: "BLAKE2S-256",
        alg: Alg::Blake2s(32),
    },
    HashSpec {
        label: "BLAKE3-256",
        alg: Alg::Blake3,
    },
    HashSpec {
        label: "DSTU7564-256",
        alg: Alg::Kupyna256,
    },
    HashSpec {
        label: "DSTU7564-384",
        alg: Alg::Kupyna384,
    },
    HashSpec {
        label: "DSTU7564-512",
        alg: Alg::Kupyna512,
    },
    HashSpec {
        label: "GOST3411",
        alg: Alg::Gost3411,
    },
    HashSpec {
        label: "GOST3411-2012-256",
        alg: Alg::Streebog256,
    },
    HashSpec {
        label: "GOST3411-2012-512",
        alg: Alg::Streebog512,
    },
    HashSpec {
        label: "HARAKA-256",
        alg: Alg::Haraka256,
    },
    HashSpec {
        label: "HARAKA-512",
        alg: Alg::Haraka512,
    },
    HashSpec {
        label: "KECCAK-224",
        alg: Alg::Keccak224,
    },
    HashSpec {
        label: "KECCAK-256",
        alg: Alg::Keccak256,
    },
    HashSpec {
        label: "KECCAK-288",
        alg: Alg::Keccak288,
    },
    HashSpec {
        label: "KECCAK-384",
        alg: Alg::Keccak384,
    },
    HashSpec {
        label: "KECCAK-512",
        alg: Alg::Keccak512,
    },
    HashSpec {
        label: "MD2",
        alg: Alg::Md2,
    },
    HashSpec {
        label: "MD4",
        alg: Alg::Md4,
    },
    HashSpec {
        label: "MD5",
        alg: Alg::Md5,
    },
    // OID spellings, as Bouncy Castle registers them.
    HashSpec {
        label: "OID.1.0.10118.3.0.55",
        alg: Alg::Whirlpool,
    },
    HashSpec {
        label: "OID.1.2.804.2.1.1.1.1.2.2.1",
        alg: Alg::Kupyna256,
    },
    HashSpec {
        label: "OID.1.2.804.2.1.1.1.1.2.2.2",
        alg: Alg::Kupyna384,
    },
    HashSpec {
        label: "OID.1.2.804.2.1.1.1.1.2.2.3",
        alg: Alg::Kupyna512,
    },
    HashSpec {
        label: "OID.2.16.840.1.101.3.4.2.10",
        alg: Alg::Sha3_512,
    },
    HashSpec {
        label: "OID.2.16.840.1.101.3.4.2.11",
        alg: Alg::Shake128,
    },
    HashSpec {
        label: "OID.2.16.840.1.101.3.4.2.12",
        alg: Alg::Shake256,
    },
    HashSpec {
        label: "OID.2.16.840.1.101.3.4.2.7",
        alg: Alg::Sha3_224,
    },
    HashSpec {
        label: "OID.2.16.840.1.101.3.4.2.8",
        alg: Alg::Sha3_256,
    },
    HashSpec {
        label: "OID.2.16.840.1.101.3.4.2.9",
        alg: Alg::Sha3_384,
    },
    HashSpec {
        label: "PARALLELHASH128-256",
        alg: Alg::ParallelHash128,
    },
    HashSpec {
        label: "PARALLELHASH256-512",
        alg: Alg::ParallelHash256,
    },
    HashSpec {
        label: "RIPEMD128",
        alg: Alg::Ripemd128,
    },
    HashSpec {
        label: "RIPEMD160",
        alg: Alg::Ripemd160,
    },
    HashSpec {
        label: "RIPEMD256",
        alg: Alg::Ripemd256,
    },
    HashSpec {
        label: "RIPEMD320",
        alg: Alg::Ripemd320,
    },
    HashSpec {
        label: "SHA-1",
        alg: Alg::Sha1,
    },
    HashSpec {
        label: "SHA-224",
        alg: Alg::Sha224,
    },
    HashSpec {
        label: "SHA-256",
        alg: Alg::Sha256,
    },
    HashSpec {
        label: "SHA-384",
        alg: Alg::Sha384,
    },
    HashSpec {
        label: "SHA-512",
        alg: Alg::Sha512,
    },
    HashSpec {
        label: "SHA-512/224",
        alg: Alg::Sha512_224,
    },
    HashSpec {
        label: "SHA-512/256",
        alg: Alg::Sha512_256,
    },
    HashSpec {
        label: "SHA3-224",
        alg: Alg::Sha3_224,
    },
    HashSpec {
        label: "SHA3-256",
        alg: Alg::Sha3_256,
    },
    HashSpec {
        label: "SHA3-384",
        alg: Alg::Sha3_384,
    },
    HashSpec {
        label: "SHA3-512",
        alg: Alg::Sha3_512,
    },
    HashSpec {
        label: "SHAKE128-256",
        alg: Alg::Shake128,
    },
    HashSpec {
        label: "SHAKE256-512",
        alg: Alg::Shake256,
    },
    HashSpec {
        label: "SKEIN-1024-1024",
        alg: Alg::Skein1024(128),
    },
    HashSpec {
        label: "SKEIN-1024-384",
        alg: Alg::Skein1024(48),
    },
    HashSpec {
        label: "SKEIN-1024-512",
        alg: Alg::Skein1024(64),
    },
    HashSpec {
        label: "SKEIN-256-128",
        alg: Alg::Skein256(16),
    },
    HashSpec {
        label: "SKEIN-256-160",
        alg: Alg::Skein256(20),
    },
    HashSpec {
        label: "SKEIN-256-224",
        alg: Alg::Skein256(28),
    },
    HashSpec {
        label: "SKEIN-256-256",
        alg: Alg::Skein256(32),
    },
    HashSpec {
        label: "SKEIN-512-128",
        alg: Alg::Skein512(16),
    },
    HashSpec {
        label: "SKEIN-512-160",
        alg: Alg::Skein512(20),
    },
    HashSpec {
        label: "SKEIN-512-224",
        alg: Alg::Skein512(28),
    },
    HashSpec {
        label: "SKEIN-512-256",
        alg: Alg::Skein512(32),
    },
    HashSpec {
        label: "SKEIN-512-384",
        alg: Alg::Skein512(48),
    },
    HashSpec {
        label: "SKEIN-512-512",
        alg: Alg::Skein512(64),
    },
    HashSpec {
        label: "SM3",
        alg: Alg::Sm3,
    },
    HashSpec {
        label: "TIGER",
        alg: Alg::Tiger,
    },
    HashSpec {
        label: "TUPLEHASH128-256",
        alg: Alg::TupleHash128,
    },
    HashSpec {
        label: "TUPLEHASH256-512",
        alg: Alg::TupleHash256,
    },
    HashSpec {
        label: "WHIRLPOOL",
        alg: Alg::Whirlpool,
    },
    // Bare-OID aliases (same digests as the OID.-prefixed entries).
    HashSpec {
        label: "1.0.10118.3.0.55",
        alg: Alg::Whirlpool,
    },
    HashSpec {
        label: "1.2.804.2.1.1.1.1.2.2.1",
        alg: Alg::Kupyna256,
    },
    HashSpec {
        label: "1.2.804.2.1.1.1.1.2.2.2",
        alg: Alg::Kupyna384,
    },
    HashSpec {
        label: "1.2.804.2.1.1.1.1.2.2.3",
        alg: Alg::Kupyna512,
    },
    HashSpec {
        label: "2.16.840.1.101.3.4.2.10",
        alg: Alg::Sha3_512,
    },
    HashSpec {
        label: "2.16.840.1.101.3.4.2.11",
        alg: Alg::Shake128,
    },
    HashSpec {
        label: "2.16.840.1.101.3.4.2.12",
        alg: Alg::Shake256,
    },
    HashSpec {
        label: "2.16.840.1.101.3.4.2.7",
        alg: Alg::Sha3_224,
    },
    HashSpec {
        label: "2.16.840.1.101.3.4.2.8",
        alg: Alg::Sha3_256,
    },
    HashSpec {
        label: "2.16.840.1.101.3.4.2.9",
        alg: Alg::Sha3_384,
    },
];

/// Keccak-288 (rate 128 bytes, legacy 0x01 domain suffix), which the sha3
/// crate does not ship, built on the audited `keccak` crate permutation.
fn keccak288(data: &[u8]) -> Vec<u8> {
    const RATE: usize = 128;
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (i, c) in block.chunks(8).enumerate() {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            st[i] ^= u64::from_le_bytes(w);
        }
        keccak::f1600(st);
    };
    let (blocks, rem) = data.as_chunks::<RATE>();
    for c in blocks {
        absorb(&mut st, c);
    }
    let mut last = vec![0u8; RATE];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    absorb(&mut st, &last);
    // 36-byte output fits the single squeeze block.
    let mut out = vec![0u8; 36];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (st[i / 8] >> (8 * (i % 8))) as u8;
    }
    out
}

fn blake2_var(s: bool, out_len: u8, data: &[u8]) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    let mut out = vec![0u8; out_len as usize];
    if s {
        let mut h = blake2::Blake2sVar::new(out_len as usize).expect("valid size");
        h.update(data);
        h.finalize_variable(&mut out).expect("valid size");
    } else {
        let mut h = blake2::Blake2bVar::new(out_len as usize).expect("valid size");
        h.update(data);
        h.finalize_variable(&mut out).expect("valid size");
    }
    out
}

fn skein(state: usize, out_len: u8, data: &[u8]) -> Vec<u8> {
    use skein_hash::digest::generic_array::typenum::{U128, U16, U20, U28, U32, U48, U64};
    use skein_hash::{Digest as _, Skein1024, Skein256, Skein512};
    match (state, out_len) {
        (256, 16) => Skein256::<U16>::digest(data).to_vec(),
        (256, 20) => Skein256::<U20>::digest(data).to_vec(),
        (256, 28) => Skein256::<U28>::digest(data).to_vec(),
        (256, 32) => Skein256::<U32>::digest(data).to_vec(),
        (512, 16) => Skein512::<U16>::digest(data).to_vec(),
        (512, 20) => Skein512::<U20>::digest(data).to_vec(),
        (512, 28) => Skein512::<U28>::digest(data).to_vec(),
        (512, 32) => Skein512::<U32>::digest(data).to_vec(),
        (512, 48) => Skein512::<U48>::digest(data).to_vec(),
        (512, 64) => Skein512::<U64>::digest(data).to_vec(),
        (1024, 48) => Skein1024::<U48>::digest(data).to_vec(),
        (1024, 64) => Skein1024::<U64>::digest(data).to_vec(),
        (1024, 128) => Skein1024::<U128>::digest(data).to_vec(),
        _ => unreachable!("menu only carries the combinations above"),
    }
}

/// Run one menu entry over `data`, returning raw digest bytes.
pub fn digest(spec: &HashSpec, data: &[u8]) -> Result<Vec<u8>, String> {
    use blake2::digest::Digest as _;
    Ok(match spec.alg {
        Alg::Blake2b(n) => blake2_var(false, n, data),
        Alg::Blake2s(n) => blake2_var(true, n, data),
        Alg::Blake3 => blake3::hash(data).as_bytes().to_vec(),
        Alg::Kupyna256 => <kupyna::Kupyna256 as kupyna::digest::Digest>::digest(data).to_vec(),
        Alg::Kupyna384 => <kupyna::Kupyna384 as kupyna::digest::Digest>::digest(data).to_vec(),
        Alg::Kupyna512 => <kupyna::Kupyna512 as kupyna::digest::Digest>::digest(data).to_vec(),
        Alg::Gost3411 => gost94::Gost94CryptoPro::digest(data).to_vec(),
        Alg::Streebog256 => streebog::Streebog256::digest(data).to_vec(),
        Alg::Streebog512 => streebog::Streebog512::digest(data).to_vec(),
        Alg::Haraka256 => haraka::digest256(data)?,
        Alg::Haraka512 => haraka::digest512(data)?,
        Alg::Keccak224 => sha3::Keccak224::digest(data).to_vec(),
        Alg::Keccak256 => sha3::Keccak256::digest(data).to_vec(),
        Alg::Keccak288 => keccak288(data),
        Alg::Keccak384 => sha3::Keccak384::digest(data).to_vec(),
        Alg::Keccak512 => sha3::Keccak512::digest(data).to_vec(),
        Alg::Md2 => md2::Md2::digest(data).to_vec(),
        Alg::Md4 => md4::Md4::digest(data).to_vec(),
        Alg::Md5 => md5::Md5::digest(data).to_vec(),
        Alg::ParallelHash128 => {
            use tiny_keccak::{Hasher as _, ParallelHash};
            let mut h = ParallelHash::v128(&[], 128);
            h.update(data);
            let mut out = vec![0u8; 32];
            h.finalize(&mut out);
            out
        }
        Alg::ParallelHash256 => {
            use tiny_keccak::{Hasher as _, ParallelHash};
            let mut h = ParallelHash::v256(&[], 128);
            h.update(data);
            let mut out = vec![0u8; 64];
            h.finalize(&mut out);
            out
        }
        Alg::Ripemd128 => ripemd::Ripemd128::digest(data).to_vec(),
        Alg::Ripemd160 => ripemd::Ripemd160::digest(data).to_vec(),
        Alg::Ripemd256 => ripemd::Ripemd256::digest(data).to_vec(),
        Alg::Ripemd320 => ripemd::Ripemd320::digest(data).to_vec(),
        Alg::Sha1 => sha1::Sha1::digest(data).to_vec(),
        Alg::Sha224 => sha2::Sha224::digest(data).to_vec(),
        Alg::Sha256 => sha2::Sha256::digest(data).to_vec(),
        Alg::Sha384 => sha2::Sha384::digest(data).to_vec(),
        Alg::Sha512 => sha2::Sha512::digest(data).to_vec(),
        Alg::Sha512_224 => sha2::Sha512_224::digest(data).to_vec(),
        Alg::Sha512_256 => sha2::Sha512_256::digest(data).to_vec(),
        Alg::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
        Alg::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        Alg::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
        Alg::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        Alg::Shake128 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake128::default();
            h.update(data);
            let mut out = vec![0u8; 32];
            h.finalize_xof().read(&mut out);
            out
        }
        Alg::Shake256 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut h = sha3::Shake256::default();
            h.update(data);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            out
        }
        Alg::Skein256(n) => skein(256, n, data),
        Alg::Skein512(n) => skein(512, n, data),
        Alg::Skein1024(n) => skein(1024, n, data),
        Alg::Sm3 => sm3::Sm3::digest(data).to_vec(),
        Alg::Tiger => tiger::Tiger::digest(data).to_vec(),
        Alg::TupleHash128 => {
            use tiny_keccak::{Hasher as _, TupleHash};
            let mut h = TupleHash::v128(&[]);
            h.update(data);
            let mut out = vec![0u8; 32];
            h.finalize(&mut out);
            out
        }
        Alg::TupleHash256 => {
            use tiny_keccak::{Hasher as _, TupleHash};
            let mut h = TupleHash::v256(&[]);
            h.update(data);
            let mut out = vec![0u8; 64];
            h.finalize(&mut out);
            out
        }
        Alg::Whirlpool => whirlpool::Whirlpool::digest(data).to_vec(),
    })
}

/// Digest as lowercase hex, as the Decoder's existing hash ops render.
pub fn digest_hex(spec: &HashSpec, data: &[u8]) -> Result<String, String> {
    Ok(crate::util::hex_encode(&digest(spec, data)?))
}

/// The menu entry with this exact Burp label (for tests and callers that
/// round-trip a label).
pub fn by_label(label: &str) -> Option<&'static HashSpec> {
    MENU.iter().find(|s| s.label == label)
}

#[cfg(test)]
mod tests;
