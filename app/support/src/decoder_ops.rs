// Burp Decoder parity (task F-01): `Op` names one decoder operation, `apply` runs
// it, `pipeline` chains several.  Pure and I/O-free, so every function is directly
// testable.  Base64, hex and HTML entities delegate to `util` (the proxy's own
// codecs — one implementation to keep correct); URL, ASCII hex, ROT13, the digests
// and SmartDecode live here because nothing else needed them.

use crate::hash_list::{self, HashSpec};
use crate::util;

/// One Decoder operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Percent-encode with RFC 3986 unreserved passthrough; decode reads `+` as a space.
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    Base64Encode,
    Base64Decode,
    /// Bytes as `\xNN` escapes (Burp's "ASCII hex").
    AsciiHexEncode,
    AsciiHexDecode,
    HexEncode,
    HexDecode,
    /// Decimal number tokens rewritten in octal (Burp's "Octal", a numeric
    /// radix conversion measured on 2026.11.2: "72 105" -> "110 151").
    OctalEncode,
    OctalDecode,
    /// Decimal number tokens rewritten in binary (Burp's "Binary":
    /// "72 105" -> "1001000 1101001").
    BinaryEncode,
    BinaryDecode,
    /// UTF-8 text -> GZIP bytes -> standard padded base64 text.
    /// Decode expects that base64 representation and rejects non-UTF-8 output.
    /// Raw compressed text from older versions is deliberately not accepted.
    GzipEncode,
    GzipDecode,
    Rot13,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    /// One of the 82 entries of Burp's Decoder Hash menu (parity with real
    /// Burp Community 2026.11.2); see `hash_list::MENU`.
    Hash(&'static HashSpec),
    /// Guess which single encoding layer was applied and undo it.
    SmartDecode,
}

/// Run one operation.  `Err` carries a human-readable reason; nothing panics.
pub fn apply(op: Op, input: &str) -> Result<String, String> {
    match op {
        Op::UrlEncode => Ok(url_encode(input)),
        Op::UrlDecode => Ok(url_decode(input)),
        Op::HtmlEncode => Ok(util::html_encode(input)),
        Op::HtmlDecode => Ok(util::html_decode(input)),
        Op::Base64Encode => Ok(util::b64_encode(input.as_bytes())),
        Op::Base64Decode => base64_decode(input),
        Op::AsciiHexEncode => Ok(ascii_hex_encode(input)),
        Op::AsciiHexDecode => ascii_hex_decode(input),
        Op::HexEncode => Ok(util::hex_encode(input.as_bytes())),
        Op::HexDecode => util::hex_decode(input).map(|b| String::from_utf8_lossy(&b).into_owned()),
        Op::OctalEncode => Ok(octal_encode(input)),
        Op::OctalDecode => octal_decode(input),
        Op::BinaryEncode => Ok(binary_encode(input)),
        Op::BinaryDecode => binary_decode(input),
        Op::GzipEncode => gzip_encode(input),
        Op::GzipDecode => gzip_decode(input),
        Op::Rot13 => Ok(rot13(input)),
        Op::Hash(spec) => hash_list::digest_hex(spec, input.as_bytes()),
        Op::Md5 => Ok(md5_hex(input)),
        Op::Sha1 => Ok(sha1_hex(input)),
        Op::Sha256 => Ok(sha256_hex(input)),
        Op::Sha512 => Ok(sha512_hex(input)),
        Op::SmartDecode => smart_decode(input),
    }
}

/// Apply `ops` in order, left to right, as the Decoder's chain does (F-02); the
/// first failure aborts and names the 1-based step.
pub fn pipeline(input: &str, ops: &[Op]) -> Result<String, String> {
    let mut current = input.to_string();
    for (idx, op) in ops.iter().enumerate() {
        current = apply(*op, &current).map_err(|e| format!("step {} ({op:?}): {e}", idx + 1))?;
    }
    Ok(current)
}

/// The Decoder's Hash dropdown in Burp's measured order (82 entries).
pub fn hash_menu_ops() -> Vec<Op> {
    hash_list::MENU.iter().map(Op::Hash).collect()
}

// ---------- URL ----------

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for b in input.bytes() {
        // RFC 3986 unreserved: the only bytes left as-is.
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decode `%XX` escapes, `+` as a space; a malformed escape is kept verbatim, as
/// Burp does: a body is data, not a syntax error.
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = if bytes[i] == b'%' && i + 2 < bytes.len() {
            match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(hi), Some(lo)) => Some((hi * 16 + lo) as u8),
                _ => None,
            }
        } else {
            None
        };
        match escape {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None if bytes[i] == b'+' => {
                out.push(b' ');
                i += 1;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------- Base64 (strict wrapper around util) ----------

/// `util::b64_decode` skips what it does not recognise — right for a header value,
/// wrong for the Decoder, where `SGVsbG8` (unpadded) must be an error, not a silent
/// short decode.  Validate the shape first, then decode.
fn base64_decode(input: &str) -> Result<String, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(4) {
        return Err(format!(
            "base64 input must be non-empty and a multiple of 4 bytes long (got {})",
            cleaned.len()
        ));
    }
    let body = cleaned.trim_end_matches('=');
    if cleaned.len() - body.len() > 2 {
        return Err("more than two base64 padding characters".into());
    }
    if body.contains('=')
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
    {
        return Err("not a base64 character or misplaced padding".into());
    }
    Ok(String::from_utf8_lossy(&util::b64_decode(&cleaned)?).into_owned())
}

// ---------- ASCII hex ----------

fn ascii_hex_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 4);
    for b in input.bytes() {
        out.push_str(&format!("\\x{b:02x}"));
    }
    out
}

/// Parse `\xNN` escapes; whitespace between them is ignored, anything else errors.
/// Decoded bytes are shown lossily because a String cannot hold them.
fn ascii_hex_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 4);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] != b'\\' || i + 3 >= bytes.len() || !matches!(bytes[i + 1], b'x' | b'X') {
            return Err(format!("expected \\xNN at byte {i}"));
        }
        let hex = |at: usize| {
            (bytes[at] as char)
                .to_digit(16)
                .ok_or_else(|| format!("not a hex digit at byte {at}"))
        };
        out.push((hex(i + 2)? * 16 + hex(i + 3)?) as u8);
        i += 4;
    }
    if out.is_empty() {
        return Err("no \\xNN escapes found".into());
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ---------- Octal / Binary ----------
// Measured against real Burp Community 2026.11.2: these are NUMERIC radix
// conversions over runs of digits in the text, not byte encoders. Everything
// outside a matching digit run is preserved verbatim ("Hi" encodes to "Hi";
// decoding "\\110\\151" keeps the slashes: "\\72\\105").

/// Rewrite every maximal run of digits valid in `radix_in`, converting each
/// run's value to `radix_out` (no padding, no separators). A run whose value
/// overflows u128 is left unchanged, as is all non-run text.
fn convert_digit_runs(input: &str, radix_in: u32, radix_out: u32) -> String {
    let bytes = input.as_bytes();
    let valid = |b: u8| b.is_ascii_digit() && u32::from(b - b'0') < radix_in;
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if !valid(bytes[i]) {
            let start = i;
            while i < bytes.len() && !valid(bytes[i]) {
                i += 1;
            }
            // ASCII digit boundaries are also UTF-8 boundaries. Copy the
            // original slice, never reinterpret individual UTF-8 bytes.
            out.push_str(&input[start..i]);
            continue;
        }
        let start = i;
        while i < bytes.len() && valid(bytes[i]) {
            i += 1;
        }
        let run = &input[start..i];
        match u128::from_str_radix(run, radix_in) {
            Ok(value) => {
                let converted = match radix_out {
                    2 => format!("{value:b}"),
                    8 => format!("{value:o}"),
                    _ => value.to_string(),
                };
                out.push_str(&converted);
            }
            Err(_) => out.push_str(run),
        }
    }
    out
}

fn octal_encode(input: &str) -> String {
    convert_digit_runs(input, 10, 8)
}

fn octal_decode(input: &str) -> Result<String, String> {
    Ok(convert_digit_runs(input, 8, 10))
}

fn binary_encode(input: &str) -> String {
    convert_digit_runs(input, 10, 2)
}

fn binary_decode(input: &str) -> Result<String, String> {
    Ok(convert_digit_runs(input, 2, 10))
}

// ---------- GZIP ----------

/// Largest output a GZIP decode may produce (a zip bomb must not grow without
/// bound; matches the proxy codec's per-body cap of 64 MiB).
const MAX_GZIP_DECODE: u64 = 64 * 1024 * 1024;

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| format!("gzip encode failed: {e}"))?;
    encoder
        .finish()
        .map_err(|e| format!("gzip encode failed: {e}"))
}

fn gzip_encode(input: &str) -> Result<String, String> {
    gzip_compress(input.as_bytes()).map(|compressed| util::b64_encode(&compressed))
}

fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    gzip_decompress_limited(data, MAX_GZIP_DECODE)
}

fn gzip_decompress_limited(data: &[u8], limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    let n = flate2::read::GzDecoder::new(data)
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("not gzip data: {e}"))?;
    if n as u64 > limit {
        return Err("gzip output too large".into());
    }
    Ok(out)
}

/// Decode only standard base64-wrapped GZIP, never legacy lossy binary text.
/// The text panel cannot represent arbitrary bytes, so invalid UTF-8 is an
/// explicit error. The byte codec above remains lossless for arbitrary bytes.
fn gzip_decode(input: &str) -> Result<String, String> {
    use base64::Engine;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("expected base64-encoded GZIP: {e}"))?;
    let out = gzip_decompress(&compressed)?;
    String::from_utf8(out).map_err(|_| "GZIP output is not UTF-8 text".into())
}

// ---------- ROT13 ----------

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

// ---------- Digests ----------
// RFC 1321 (MD5), RFC 3174 (SHA-1), FIPS 180-4 (SHA-256 / SHA-512).  Written out
// rather than pulled from a crate: Cargo.toml carries no digest crate, and one
// small testable implementation beats a new dependency for four fixed vectors.

/// 0x80 terminator, zeros to `block - len_bytes`, then the `len_bytes`-byte
/// big-endian bit length (8 for SHA-1/256, 16 for SHA-512; MD5 pads itself).
fn pad_be(msg: &[u8], block: usize, len_bytes: usize) -> Vec<u8> {
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % block != block - len_bytes {
        data.push(0);
    }
    let bits = (msg.len() as u128).wrapping_mul(8).to_be_bytes();
    data.extend_from_slice(&bits[16 - len_bytes..]);
    data
}

fn md5_hex(input: &str) -> String {
    let mut data = input.as_bytes().to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_le_bytes());
    // K[i] = floor(|sin(i+1)| * 2^32): derived rather than tabulated.
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    // One shift table per round: round `i / 16` uses entries `(i / 16) * 4 ..+ 4`.
    const S: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in data.as_chunks::<64>().0 {
        let m: Vec<u32> = (0..16)
            .map(|i| u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()))
            .collect();
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let sum = a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g]);
            let saved = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(S[(i % 4) + (i / 16) * 4]));
            a = saved;
        }
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
        ];
    }
    // MD5 serialises each state word little-endian.
    h.iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sha1_hex(input: &str) -> String {
    let data = pad_be(input.as_bytes(), 64, 8);
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in data.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5a82_7999),
                1 => (b ^ c ^ d, 0x6ed9_eba1),
                2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
            h[4].wrapping_add(e),
        ];
    }
    h.iter().map(|w| format!("{w:08x}")).collect()
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(input: &str) -> String {
    let data = pad_be(input.as_bytes(), 64, 8);
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in data.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let t2 = s0.wrapping_add((a & b) ^ (a & c) ^ (b & c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
            h[4].wrapping_add(e),
            h[5].wrapping_add(f),
            h[6].wrapping_add(g),
            h[7].wrapping_add(hh),
        ];
    }
    h.iter().map(|w| format!("{w:08x}")).collect()
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

fn sha512_hex(input: &str) -> String {
    let data = pad_be(input.as_bytes(), 128, 16);
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    for block in data.as_chunks::<128>().0 {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let t2 = s0.wrapping_add((a & b) ^ (a & c) ^ (b & c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
            h[4].wrapping_add(e),
            h[5].wrapping_add(f),
            h[6].wrapping_add(g),
            h[7].wrapping_add(hh),
        ];
    }
    h.iter().map(|w| format!("{w:016x}")).collect()
}

// ---------- Smart decode ----------

/// Undo the one encoding layer Smart Decode guesses at.
///
/// Fixed order — URL, HTML, Base64, hex — and a candidate is accepted only when it
/// (a) changes the input and (b) re-encodes to exactly that input, so a plain word
/// is never turned into noise and the input must already be canonical (`a+b` is
/// left alone: URL encoding would have produced `a%20b`).  Hex and Base64
/// candidates must also decode to valid, non-empty UTF-8, which rejects inputs
/// such as `deadbeef` (valid hex, non-text bytes).
fn smart_decode(input: &str) -> Result<String, String> {
    if input.is_empty() {
        return Err("nothing to decode".into());
    }

    let url = url_decode(input);
    if url != input && url_encode(&url) == input {
        return Ok(url);
    }

    let html = util::html_decode(input);
    if html != input && util::html_encode(&html) == input {
        return Ok(html);
    }

    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let b64_shaped = !cleaned.is_empty()
        && cleaned.len().is_multiple_of(4)
        && cleaned
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    if b64_shaped {
        if let Ok(bytes) = util::b64_decode(&cleaned) {
            if let Ok(text) = String::from_utf8(bytes.clone()) {
                if !text.is_empty() && text != input && util::b64_encode(&bytes) == cleaned {
                    return Ok(text);
                }
            }
        }
    }

    if input.len() >= 2
        && input.len().is_multiple_of(2)
        && input.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Ok(bytes) = util::hex_decode(input) {
            if let Ok(text) = String::from_utf8(bytes.clone()) {
                if !text.is_empty()
                    && text != input
                    && util::hex_encode(&bytes) == input.to_ascii_lowercase()
                {
                    return Ok(text);
                }
            }
        }
    }

    Err(format!("no decoder layer recognised in {input:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors_and_rejects() {
        assert_eq!(
            apply(Op::Base64Encode, "Hello, World!").unwrap(),
            "SGVsbG8sIFdvcmxkIQ=="
        );
        assert_eq!(apply(Op::Base64Encode, "a").unwrap(), "YQ==");
        assert_eq!(apply(Op::Base64Encode, "ab").unwrap(), "YWI=");
        assert_eq!(
            apply(Op::Base64Decode, "SGVsbG8sIFdvcmxkIQ==").unwrap(),
            "Hello, World!"
        );
        assert_eq!(apply(Op::Base64Decode, "Y Q = =").unwrap(), "a");
        assert!(
            apply(Op::Base64Decode, "SGVsbG8").is_err(),
            "unpadded length"
        );
        assert!(apply(Op::Base64Decode, "====").is_err(), "only padding");
        assert!(apply(Op::Base64Decode, "").is_err(), "empty input");
        assert!(
            apply(Op::Base64Decode, "not base64!!").is_err(),
            "bad character"
        );
    }

    #[test]
    fn url_encode_and_decode() {
        assert_eq!(apply(Op::UrlEncode, "a b&c=d").unwrap(), "a%20b%26c%3Dd");
        assert_eq!(apply(Op::UrlEncode, "AZaz09-_.~").unwrap(), "AZaz09-_.~");
        assert_eq!(apply(Op::UrlDecode, "a%20b%26c%3Dd").unwrap(), "a b&c=d");
        assert_eq!(apply(Op::UrlDecode, "a+b").unwrap(), "a b");
        assert_eq!(apply(Op::UrlDecode, "%e2%82%ac").unwrap(), "\u{20ac}");
        assert_eq!(apply(Op::UrlDecode, "%zz").unwrap(), "%zz"); // malformed escape kept
    }

    #[test]
    fn html_encode_and_decode() {
        assert_eq!(
            apply(Op::HtmlEncode, "<a href=\"x\">&'").unwrap(),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(apply(Op::HtmlDecode, "&lt;b&gt;").unwrap(), "<b>");
        assert_eq!(apply(Op::HtmlDecode, "&#65;&#x42;").unwrap(), "AB");
        let raw = "Tom & Jerry <3 \"quoted\"";
        assert_eq!(
            apply(Op::HtmlDecode, &apply(Op::HtmlEncode, raw).unwrap()).unwrap(),
            raw
        );
    }

    #[test]
    fn ascii_hex_and_hex() {
        assert_eq!(apply(Op::AsciiHexEncode, "AB").unwrap(), "\\x41\\x42");
        assert_eq!(apply(Op::AsciiHexDecode, "\\x41\\x42").unwrap(), "AB");
        assert_eq!(apply(Op::AsciiHexDecode, "\\x41 \\x42").unwrap(), "AB");
        assert!(apply(Op::AsciiHexDecode, "41").is_err(), "no escapes");
        assert!(apply(Op::AsciiHexDecode, "\\x4").is_err(), "truncated");
        assert!(apply(Op::AsciiHexDecode, "\\xzz").is_err(), "not hex");
        assert_eq!(apply(Op::HexEncode, "AB").unwrap(), "4142");
        assert_eq!(apply(Op::HexDecode, "4142").unwrap(), "AB");
        assert_eq!(apply(Op::HexDecode, "41 42").unwrap(), "AB");
        assert!(apply(Op::HexDecode, "414").is_err(), "odd digit count");
        assert!(apply(Op::HexDecode, "zz").is_err(), "not hex");
    }

    #[test]
    fn rot13_maps_ascii_letters() {
        assert_eq!(apply(Op::Rot13, "Hello, World!").unwrap(), "Uryyb, Jbeyq!");
        assert_eq!(apply(Op::Rot13, "Uryyb, Jbeyq!").unwrap(), "Hello, World!");
        assert_eq!(apply(Op::Rot13, "n").unwrap(), "a");
        assert_eq!(apply(Op::Rot13, "123 !?").unwrap(), "123 !?");
    }

    #[test]
    fn digest_known_vectors() {
        for (op, want) in [
            (Op::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (Op::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                Op::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Op::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ] {
            assert_eq!(apply(op, "abc").unwrap(), want, "{op:?}");
        }
    }

    #[test]
    fn digest_padding_boundaries() {
        // 55/56 straddle the 64-byte block edge, 111/112 the 128-byte one.
        for (op, input, want) in [
            (Op::Md5, String::new(), "d41d8cd98f00b204e9800998ecf8427e"),
            (Op::Sha256, String::new(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (Op::Md5, "a".repeat(55), "ef1772b6dff9a122358552954ad0df65"),
            (Op::Sha256, "a".repeat(56), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (Op::Sha512, "a".repeat(111), "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4be\
                                               ff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2"),
        ] {
            assert_eq!(apply(op, &input).unwrap(), want, "{op:?} len {}", input.len());
        }
    }

    #[test]
    fn smart_decode_picks_one_layer() {
        assert_eq!(apply(Op::SmartDecode, "a%20b").unwrap(), "a b");
        assert_eq!(apply(Op::SmartDecode, "&lt;b&gt;").unwrap(), "<b>");
        assert_eq!(apply(Op::SmartDecode, "SGVsbG8=").unwrap(), "Hello");
        assert_eq!(apply(Op::SmartDecode, "414243").unwrap(), "ABC");
        assert!(apply(Op::SmartDecode, "plain text").is_err());
        assert!(
            apply(Op::SmartDecode, "deadbeef").is_err(),
            "hex of non-UTF-8 bytes"
        );
        assert!(
            apply(Op::SmartDecode, "a+b").is_err(),
            "not canonical URL encoding"
        );
        assert!(apply(Op::SmartDecode, "").is_err());
    }

    #[test]
    fn pipeline_applies_ops_in_order() {
        assert_eq!(
            pipeline("Hello", &[Op::Base64Encode, Op::UrlEncode]).unwrap(),
            "SGVsbG8%3D"
        );
        assert_eq!(
            pipeline("Hello", &[Op::UrlEncode, Op::Base64Encode]).unwrap(),
            "SGVsbG8="
        );
        assert_eq!(pipeline("Hello", &[]).unwrap(), "Hello");
        assert_eq!(
            pipeline(
                "a b",
                &[
                    Op::UrlEncode,
                    Op::Base64Encode,
                    Op::Base64Decode,
                    Op::UrlDecode
                ]
            )
            .unwrap(),
            "a b"
        );
        let err = pipeline("Hello", &[Op::Base64Encode, Op::HexDecode]).unwrap_err();
        assert!(err.starts_with("step 2 ("), "{err}");
    }
}

#[cfg(test)]
mod byte_safe_tests {
    use super::*;

    #[test]
    fn octal_preserves_mixed_utf8() {
        assert_eq!(
            apply(Op::OctalEncode, "שלום 72 café 105 🦀").unwrap(),
            "שלום 110 café 151 🦀"
        );
        assert_eq!(
            apply(Op::OctalDecode, "שלום 110 café 151 🦀").unwrap(),
            "שלום 72 café 105 🦀"
        );
    }

    #[test]
    fn binary_preserves_mixed_utf8() {
        assert_eq!(
            apply(Op::BinaryEncode, "שלום 72 café 105 🦀").unwrap(),
            "שלום 1001000 café 1101001 🦀"
        );
        assert_eq!(
            apply(Op::BinaryDecode, "שלום 1001000 café 1101001 🦀").unwrap(),
            "שלום 72 café 105 🦀"
        );
    }

    #[test]
    fn untouched_utf8_is_byte_identical_for_all_numeric_operations() {
        let text = "שלום café e\u{301} 🦀 ٧٢ １２\0\n";
        for op in [
            Op::OctalEncode,
            Op::OctalDecode,
            Op::BinaryEncode,
            Op::BinaryDecode,
        ] {
            assert_eq!(
                apply(op, text).unwrap().as_bytes(),
                text.as_bytes(),
                "{op:?}"
            );
        }
    }

    #[test]
    fn ascii_radix_compatibility() {
        for (encode, decode, encoded) in [
            (Op::OctalEncode, Op::OctalDecode, "Hi 110\\151-0 377"),
            (
                Op::BinaryEncode,
                Op::BinaryDecode,
                "Hi 1001000\\1101001-0 11111111",
            ),
        ] {
            assert_eq!(apply(encode, "Hi 72\\105-0 255").unwrap(), encoded);
            assert_eq!(apply(decode, encoded).unwrap(), "Hi 72\\105-0 255");
        }
        assert_eq!(apply(Op::OctalDecode, "1789").unwrap(), "1589");
        assert_eq!(apply(Op::BinaryDecode, "10211").unwrap(), "223");
    }

    #[test]
    fn overflowing_digit_runs_and_surrounding_utf8_are_untouched() {
        let text = format!("é{}🦀", "9".repeat(100));
        assert_eq!(apply(Op::OctalEncode, &text).unwrap(), text);
        assert_eq!(apply(Op::BinaryEncode, &text).unwrap(), text);
    }

    #[test]
    fn gzip_codec_roundtrips_empty_non_ascii_and_every_byte() {
        for bytes in [
            Vec::new(),
            "שלום café 🦀".as_bytes().to_vec(),
            (0..=255).collect(),
        ] {
            let compressed = gzip_compress(&bytes).unwrap();
            assert_eq!(gzip_decompress(&compressed).unwrap(), bytes);
        }
    }

    #[test]
    fn gzip_ui_roundtrip_uses_base64_not_lossy_binary_text() {
        for text in ["", "ASCII\0\n", "שלום café 🦀"] {
            let encoded = apply(Op::GzipEncode, text).unwrap();
            let raw = util::b64_decode(&encoded).expect("GZIP UI output must be base64");
            assert_eq!(&raw[..3], &[0x1f, 0x8b, 8]);
            assert_eq!(gzip_decompress(&raw).unwrap(), text.as_bytes());
            assert_eq!(apply(Op::GzipDecode, &encoded).unwrap(), text);
        }
    }

    #[test]
    fn gzip_rejects_invalid_and_truncated_input() {
        assert!(apply(Op::GzipDecode, "%%%not base64%%%").is_err());
        assert!(apply(Op::GzipDecode, &util::b64_encode(b"not gzip")).is_err());
        assert!(apply(Op::GzipDecode, "").is_err());
        let compressed = gzip_compress(b"payload").unwrap();
        assert!(gzip_decompress(&compressed[..compressed.len() - 4]).is_err());
        let mut corrupt = compressed;
        let last = corrupt.len() - 8;
        corrupt[last] ^= 1;
        assert!(gzip_decompress(&corrupt).is_err());
    }

    #[test]
    fn gzip_ui_rejects_non_utf8_instead_of_silently_replacing_bytes() {
        let encoded = util::b64_encode(&gzip_compress(&[0xff, 0xfe, 0]).unwrap());
        assert!(apply(Op::GzipDecode, &encoded).is_err());
    }
}

#[cfg(test)]
mod gzip_contract_tests {
    use super::*;

    #[test]
    fn output_limit_accepts_exact_limit_and_rejects_one_extra_byte() {
        let encoded = gzip_compress(b"12345").unwrap();
        assert_eq!(gzip_decompress_limited(&encoded, 5).unwrap(), b"12345");
        assert_eq!(
            gzip_decompress_limited(&encoded, 4).unwrap_err(),
            "gzip output too large"
        );
        assert_eq!(MAX_GZIP_DECODE, 64 * 1024 * 1024);
    }

    #[test]
    fn externally_encoded_gzip_decodes_and_non_utf8_has_an_explicit_error() {
        use base64::Engine;
        let external = base64::engine::general_purpose::STANDARD
            .encode(gzip_compress("café".as_bytes()).unwrap());
        assert_eq!(apply(Op::GzipDecode, &external).unwrap(), "café");
        let binary = util::b64_encode(&gzip_compress(&[0xff]).unwrap());
        assert_eq!(
            apply(Op::GzipDecode, &binary).unwrap_err(),
            "GZIP output is not UTF-8 text"
        );
        let legacy = String::from_utf8_lossy(&gzip_compress(b"legacy").unwrap()).into_owned();
        assert!(apply(Op::GzipDecode, &legacy)
            .unwrap_err()
            .starts_with("expected base64-encoded GZIP:"));
    }
}
