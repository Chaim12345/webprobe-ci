//! R-09: JWT parsing, attack variants, HMAC, the passive checks and the
//! active check against in-process responders.
//!
//! Independent oracles: the HMAC vectors are RFC 4231 (checked once with
//! Python's hmac module and pasted as constants), the HS256 token is the
//! jwt.io example, signatures in test fixtures come from `ring`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use base64::Engine;

use crate::jwt::{self, Jwt};
use crate::net::{HistEntry, Shared};
use crate::scan::ScanIssue;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn b64(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes)
}

fn unb64(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A compact JWS signed with `ring` (independent of the code under test).
fn sign_hs(alg: &str, key: &[u8], payload: &str) -> String {
    let algo = match alg {
        "HS256" => ring::hmac::HMAC_SHA256,
        "HS384" => ring::hmac::HMAC_SHA384,
        "HS512" => ring::hmac::HMAC_SHA512,
        _ => panic!("alg"),
    };
    let input = format!(
        "{}.{}",
        b64(format!("{{\"alg\":\"{alg}\",\"typ\":\"JWT\"}}")),
        b64(payload)
    );
    let sig = ring::hmac::sign(&ring::hmac::Key::new(algo, key), input.as_bytes());
    format!("{input}.{}", b64(sig.as_ref()))
}

const JWT_IO: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// ------------------------------------------------------------------ parse

#[test]
fn parse_reads_the_jwt_io_example() {
    let t = Jwt::parse(JWT_IO).expect("the jwt.io example parses");
    assert_eq!(t.alg(), "HS256");
    assert_eq!(t.header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
    assert_eq!(t.signing_input(), JWT_IO.rsplit_once('.').unwrap().0);
    assert_eq!(
        String::from_utf8(t.payload()).unwrap(),
        r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#
    );
    assert_eq!(t.raw, JWT_IO);
    // Surrounding whitespace is trimmed.
    assert_eq!(Jwt::parse(&format!("  {JWT_IO}\r\n")).unwrap().raw, JWT_IO);
}

#[test]
fn parse_applies_burps_recognition_rules() {
    // Must start with "e": the same header re-encoded behind a different
    // first character is not a token.
    assert!(Jwt::parse(&format!("A{JWT_IO}")).is_none());
    assert!(Jwt::parse(&format!("E{}", &JWT_IO[1..])).is_none());
    // Minimum length 23: "e30.e30." is {} . {} . "" plus n signature chars.
    let short = format!("e30.e30.{}", "A".repeat(14));
    let exact = format!("e30.e30.{}", "A".repeat(15));
    assert_eq!(short.len(), 22);
    assert_eq!(exact.len(), 23);
    assert!(Jwt::parse(&short).is_none(), "22 characters");
    assert!(Jwt::parse(&exact).is_some(), "23 characters");
    // Four parts are not a JWS.
    assert!(Jwt::parse(&format!("{JWT_IO}.AAAA")).is_none());
}

#[test]
fn parse_rejects_garbage_without_panicking() {
    let json_header = b64(r#"{"alg":"HS256"}"#);
    let cases: Vec<String> = vec![
        String::new(),
        "e".into(),
        ".".into(),
        "..".into(),
        "eyJ!!!.@@@.###_this_is_long_enough".into(),
        // two parts only
        format!("{json_header}.{}", b64("{}")),
        // bad base64 in each of the three parts
        format!("{json_header}.!!!.AAAA_padding_to_be_long"),
        format!("{json_header}.{}.!!!!", b64("{}")),
        format!("e!!!.{}.AAAAAAAAAAAAAAAAAAAAAAAA", b64("{}")),
        // header decodes but is not JSON ("x" encodes to a leading "e")
        format!(
            "{}.{}.AAAAAAAAAAAAAAAA",
            b64("xyz not json at all"),
            b64("{}")
        ),
        // header is JSON but not an object (starts with "e" only for an object, so use a long array token)
        format!("{}.{}.AAAAAAAAAAAAAAAA", b64("[1,2,3]"), b64("{}")),
        // empty header part
        format!(".{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAA", b64("{}")),
        // non-ASCII input
        format!("e{}", "\u{e9}".repeat(30)),
        format!(
            "e{}.{}.\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}",
            b64("{}"),
            b64("{}")
        ),
        "e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".into(),
    ];
    for c in &cases {
        let r = std::panic::catch_unwind(|| Jwt::parse(c));
        assert!(r.is_ok(), "parse panicked on {c:?}");
        // Cases whose header is not "e…" JSON must not parse; the long
        // array case starts with "W" so it is rejected by the prefix rule.
        assert!(r.unwrap().is_none(), "garbage accepted: {c:?}");
    }
}

#[test]
fn header_flags_for_private_jwk() {
    let with = |jwk: &str| {
        let h = b64(format!(r#"{{"alg":"HS256","jwk":{jwk}}}"#));
        Jwt::parse(&format!("{h}.{}.AAAAAAAAAAAAAAAAAAAAAAAA", b64("{}"))).unwrap()
    };
    assert!(with(r#"{"kty":"RSA","n":"x","e":"AQAB","d":"secret"}"#).jwk_has_private_key());
    assert!(with(r#"{"kty":"oct","k":"c2VjcmV0"}"#).jwk_has_private_key());
    assert!(!with(r#"{"kty":"RSA","n":"x","e":"AQAB"}"#).jwk_has_private_key());
    assert!(!Jwt::parse(JWT_IO).unwrap().jwk_has_private_key());
}

// ------------------------------------------------------------------ variants

#[test]
fn corrupt_signature_changes_only_the_signature() {
    let t = Jwt::parse(JWT_IO).unwrap();
    let c = jwt::corrupt_signature(&t);
    let (orig, new): (Vec<&str>, Vec<&str>) = (JWT_IO.split('.').collect(), c.split('.').collect());
    assert_eq!(new.len(), 3);
    assert_eq!(new[0], orig[0], "header untouched");
    assert_eq!(new[1], orig[1], "payload untouched");
    assert_eq!(new[2], "A".repeat(orig[2].len()), "as many A characters");
    assert_ne!(c, JWT_IO);
    assert!(Jwt::parse(&c).is_some(), "still a well-formed token");
}

#[test]
fn none_variants_are_three_unsigned_tokens() {
    let t = Jwt::parse(JWT_IO).unwrap();
    let v = jwt::none_variants(&t);
    assert_eq!(v.len(), 3);
    let algs: Vec<String> = v
        .iter()
        .map(|s| {
            assert!(s.ends_with('.'), "empty signature: {s}");
            let parts: Vec<&str> = s.split('.').collect();
            assert_eq!(parts.len(), 3);
            assert_eq!(
                parts[1],
                JWT_IO.split('.').nth(1).unwrap(),
                "payload untouched"
            );
            assert_eq!(parts[2], "");
            let h: serde_json::Value = serde_json::from_slice(&unb64(parts[0])).unwrap();
            assert_eq!(h["typ"], "JWT", "other header members kept");
            h["alg"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(algs, ["nonE", "None", "none"]);
}

#[test]
fn control_token_blanks_the_payload_to_the_same_length() {
    let t = Jwt::parse(JWT_IO).unwrap();
    let c = jwt::control_token(&t);
    let parts: Vec<&str> = c.split('.').collect();
    assert_eq!(parts[0], JWT_IO.split('.').next().unwrap());
    assert_eq!(
        parts[2],
        JWT_IO.split('.').nth(2).unwrap(),
        "signature unchanged"
    );
    let p = String::from_utf8(unb64(parts[1])).unwrap();
    assert_eq!(p.len(), t.payload().len());
    assert!(
        p.starts_with('{') && p.ends_with('}') && p[1..p.len() - 1].chars().all(|c| c == ' '),
        "{p:?}"
    );
    // Tiny payloads still give "{}"-shaped output and a parseable token.
    let tiny = format!(
        "{}.{}.{}",
        b64(r#"{"alg":"HS256"}"#),
        b64("1"),
        "AAAAAAAAAAAAAAAAAAAAAA"
    );
    let tiny = Jwt::parse(&tiny).unwrap();
    let c = jwt::control_token(&tiny);
    let p = String::from_utf8(unb64(c.split('.').nth(1).unwrap())).unwrap();
    assert_eq!(p, "{}");
}

#[test]
fn header_url_variant_sets_the_header_and_keeps_payload_and_signature() {
    let t = Jwt::parse(JWT_IO).unwrap();
    for name in ["jku", "x5u"] {
        let v = jwt::header_url_variant(&t, name, "https://abc.oast.test/");
        let parts: Vec<&str> = v.split('.').collect();
        let h: serde_json::Value = serde_json::from_slice(&unb64(parts[0])).unwrap();
        assert_eq!(h[name], "https://abc.oast.test/");
        assert_eq!(h["alg"], "HS256");
        assert_eq!(parts[1], JWT_IO.split('.').nth(1).unwrap());
        assert_eq!(parts[2], JWT_IO.split('.').nth(2).unwrap());
    }
}

/// DER of an RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e }) built here,
/// so ring can verify against the key found in the token's own header.
fn rsa_public_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn len(l: usize) -> Vec<u8> {
        if l < 128 {
            vec![l as u8]
        } else if l < 256 {
            vec![0x81, l as u8]
        } else {
            vec![0x82, (l >> 8) as u8, l as u8]
        }
    }
    fn int(v: &[u8]) -> Vec<u8> {
        let mut v = v.to_vec();
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut o = vec![0x02];
        o.extend(len(v.len()));
        o.extend(v);
        o
    }
    let mut body = int(n);
    body.extend(int(e));
    let mut o = vec![0x30];
    o.extend(len(body.len()));
    o.extend(body);
    o
}

#[test]
fn jwk_variant_is_signed_with_the_key_in_its_own_header() {
    let t = Jwt::parse(JWT_IO).unwrap();
    let v = jwt::jwk_variant(&t).expect("the embedded RSA key loads in ring");
    let back = Jwt::parse(&v).expect("the variant is a well-formed token");
    assert_eq!(back.alg(), "RS256");
    let jwk = back
        .header
        .get("jwk")
        .and_then(|j| j.as_object())
        .expect("jwk in the header");
    assert!(
        jwk.get("n")
            .and_then(|n| n.as_str())
            .is_some_and(|n| !n.is_empty()),
        "jwk.n"
    );
    assert_eq!(jwk.get("e").and_then(|e| e.as_str()), Some("AQAB"));
    assert_eq!(jwk.get("kty").and_then(|e| e.as_str()), Some("RSA"));
    assert_eq!(
        back.header.get("kid").and_then(|k| k.as_str()),
        Some(jwt::JWK_KID),
        "kid set when the token had none"
    );
    assert_eq!(
        back.header.get("typ").and_then(|k| k.as_str()),
        Some("JWT"),
        "other header members kept"
    );
    assert_eq!(
        back.payload_b64,
        JWT_IO.split('.').nth(1).unwrap(),
        "payload untouched"
    );
    assert!(
        !back.jwk_has_private_key(),
        "only the public key is embedded"
    );

    let n = unb64(jwk["n"].as_str().unwrap());
    let e = unb64(jwk["e"].as_str().unwrap());
    let der = rsa_public_der(&n, &e);
    let pk =
        ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, der);
    pk.verify(back.signing_input().as_bytes(), &back.signature())
        .expect("signature verifies with the header's public key");
    // And a changed payload does not verify (the check is not vacuous).
    let tampered = format!("{}.{}", back.header_b64, b64("{}"));
    let der = rsa_public_der(&n, &e);
    let pk =
        ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, der);
    assert!(pk.verify(tampered.as_bytes(), &back.signature()).is_err());
}

#[test]
fn jwk_variant_keeps_an_existing_kid() {
    let h = b64(r#"{"alg":"HS256","kid":"mine"}"#);
    let t = Jwt::parse(&format!(
        "{h}.{}.AAAAAAAAAAAAAAAAAAAAAAAA",
        b64(r#"{"a":1}"#)
    ))
    .unwrap();
    let back = Jwt::parse(&jwt::jwk_variant(&t).unwrap()).unwrap();
    assert_eq!(
        back.header.get("kid").and_then(|k| k.as_str()),
        Some("mine")
    );
}

// ------------------------------------------------------------------ HMAC

#[test]
fn hmac_matches_rfc_4231_vectors() {
    // (key, data, SHA-256, SHA-384, SHA-512): RFC 4231 test cases 1, 2 and 6
    // (case 6: a 131-byte key, longer than both block sizes).
    type HmacCase = (
        Vec<u8>,
        &'static [u8],
        &'static str,
        &'static str,
        &'static str,
    );
    let cases: Vec<HmacCase> = vec![
        (
            vec![0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            vec![0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
    ];
    for (i, (key, data, h256, h384, h512)) in cases.iter().enumerate() {
        assert_eq!(
            jwt::hmac_for("HS256", key, data).unwrap(),
            hex(h256),
            "case {i} HS256"
        );
        assert_eq!(
            jwt::hmac_for("HS384", key, data).unwrap(),
            hex(h384),
            "case {i} HS384"
        );
        assert_eq!(
            jwt::hmac_for("HS512", key, data).unwrap(),
            hex(h512),
            "case {i} HS512"
        );
    }
}

#[test]
fn hmac_agrees_with_ring_around_the_block_sizes() {
    for key_len in [0usize, 1, 31, 32, 63, 64, 65, 100, 127, 128, 129, 200] {
        let key: Vec<u8> = (0..key_len).map(|i| (i * 7 + 3) as u8).collect();
        for data_len in [0usize, 1, 55, 56, 64, 111, 112, 128, 500] {
            let data: Vec<u8> = (0..data_len).map(|i| (i * 13 + 1) as u8).collect();
            for (alg, a) in [
                ("HS256", ring::hmac::HMAC_SHA256),
                ("HS384", ring::hmac::HMAC_SHA384),
                ("HS512", ring::hmac::HMAC_SHA512),
            ] {
                let want = ring::hmac::sign(&ring::hmac::Key::new(a, &key), &data);
                assert_eq!(
                    jwt::hmac_for(alg, &key, &data).unwrap(),
                    want.as_ref(),
                    "{alg} key {key_len} data {data_len}"
                );
            }
        }
    }
}

#[test]
fn hmac_for_only_knows_the_three_hs_algorithms() {
    for alg in ["", "none", "RS256", "HS1", "hs256", "HS256 ", "ES256"] {
        assert!(jwt::hmac_for(alg, b"k", b"d").is_none(), "{alg:?}");
    }
}

#[test]
fn jwt_io_example_verifies_against_its_published_secret() {
    let t = Jwt::parse(JWT_IO).unwrap();
    assert_eq!(
        t.signature(),
        unb64("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    );
    assert_eq!(
        jwt::hmac_for(
            "HS256",
            b"your-256-bit-secret",
            t.signing_input().as_bytes()
        )
        .unwrap(),
        t.signature()
    );
    assert_eq!(
        jwt::weak_secret(&t, ["nope", "your-256-bit-secret"]),
        Some("your-256-bit-secret".to_string())
    );
    assert_eq!(jwt::weak_secret(&t, ["nope", "your-256-bit-secreT"]), None);
}

// ------------------------------------------------------------------ weak secret

#[test]
fn weak_secret_finds_the_signing_candidate() {
    let t = Jwt::parse(&sign_hs("HS256", b"secret", r#"{"user":"a"}"#)).unwrap();
    assert_eq!(
        jwt::weak_secret(&t, ["a", "secret"]),
        Some("secret".to_string())
    );
    assert_eq!(jwt::weak_secret(&t, ["a", "b"]), None);
    assert_eq!(jwt::weak_secret(&t, Vec::<&str>::new()), None);
    for alg in ["HS384", "HS512"] {
        let t = Jwt::parse(&sign_hs(alg, b"hunter2", r#"{"user":"a"}"#)).unwrap();
        assert_eq!(
            jwt::weak_secret(&t, ["x", "hunter2"]),
            Some("hunter2".to_string()),
            "{alg}"
        );
    }
    // Block-size edge: a secret longer than the block is hashed first.
    let long = "k".repeat(200);
    let t = Jwt::parse(&sign_hs("HS256", long.as_bytes(), r#"{"user":"a"}"#)).unwrap();
    assert_eq!(jwt::weak_secret(&t, [long.as_str()]), Some(long.clone()));
}

#[test]
fn weak_secret_empty_candidate_is_the_key_zero_byte() {
    let t = Jwt::parse(&sign_hs("HS256", &[0], r#"{"user":"a"}"#)).unwrap();
    assert_eq!(jwt::weak_secret(&t, ["a", ""]), Some(String::new()));
    // HMAC zero-pads the key, so the empty key and [0] sign identically.
    let t = Jwt::parse(&sign_hs("HS256", b"", r#"{"user":"a"}"#)).unwrap();
    assert_eq!(jwt::weak_secret(&t, [""]), Some(String::new()));
}

#[test]
fn weak_secret_ignores_non_hmac_algorithms() {
    // A token that claims RS256 but carries an HMAC signature made with "secret".
    let h = b64(r#"{"alg":"RS256"}"#);
    let input = format!("{h}.{}", b64("{}"));
    let sig = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"secret"),
        input.as_bytes(),
    );
    let t = Jwt::parse(&format!("{input}.{}", b64(sig.as_ref()))).unwrap();
    assert_eq!(jwt::weak_secret(&t, ["secret"]), None);
    for t in jwt::none_variants(&Jwt::parse(JWT_IO).unwrap()) {
        assert_eq!(
            jwt::weak_secret(&Jwt::parse(&t).unwrap(), ["", "secret"]),
            None
        );
    }
}

#[test]
fn secrets_list_loads_without_panicking() {
    let a = jwt::secrets();
    let b = jwt::secrets();
    assert!(std::ptr::eq(a, b), "read once");
}

// ------------------------------------------------------------------ token sources

fn tokens_of(raw: &str) -> Vec<String> {
    let parts = crate::util::parse_http(raw.as_bytes());
    jwt::tokens_in_request(&parts, raw.as_bytes())
        .into_iter()
        .map(|t| t.raw)
        .collect()
}

fn tok(n: u32) -> String {
    sign_hs("HS256", b"k", &format!("{{\"n\":{n}}}"))
}

#[test]
fn tokens_are_found_in_headers_cookies_query_and_form() {
    let (a, b, c, d, e) = (tok(1), tok(2), tok(3), tok(4), tok(5));
    let found = tokens_of(&format!(
        "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer {a}\r\n\r\n"
    ));
    assert_eq!(found, std::slice::from_ref(&a), "Authorization: Bearer");
    let found = tokens_of(&format!(
        "GET /x HTTP/1.1\r\nHost: h\r\nAuthorization: {a}\r\n\r\n"
    ));
    assert_eq!(
        found,
        std::slice::from_ref(&a),
        "Authorization without the scheme"
    );
    let found = tokens_of(&format!(
        "GET /x HTTP/1.1\r\nHost: h\r\nCookie: theme=dark; session={b}; lang=en\r\n\r\n"
    ));
    assert_eq!(found, std::slice::from_ref(&b), "cookie");
    let found = tokens_of(&format!(
        "GET /x?lang=en&jwt={c}&z=1 HTTP/1.1\r\nHost: h\r\n\r\n"
    ));
    assert_eq!(found, std::slice::from_ref(&c), "query parameter");
    let body = format!("user=bob&t={d}");
    let found = tokens_of(&format!("POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
    assert_eq!(found, std::slice::from_ref(&d), "form body");
    let found = tokens_of(&format!("GET /x?a={c} HTTP/1.1\r\nHost: h\r\nX-Custom: {e}\r\nCookie: s={b}\r\nAuthorization: Bearer {a}\r\n\r\n"));
    assert_eq!(found.len(), 4);
    for t in [&a, &b, &c, &e] {
        assert!(found.contains(t));
    }
    // The same token twice is reported once.
    let found = tokens_of(&format!(
        "GET /x?a={a} HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer {a}\r\n\r\n"
    ));
    assert_eq!(found, [a]);
}

#[test]
fn tokens_are_url_decoded_in_parameter_values() {
    let a = tok(7);
    let encoded: String = a
        .chars()
        .map(|c| {
            if c == '.' {
                "%2E".to_string()
            } else {
                c.to_string()
            }
        })
        .collect();
    let found = tokens_of(&format!("GET /x?t={encoded} HTTP/1.1\r\nHost: h\r\n\r\n"));
    assert_eq!(found, [a]);
}

#[test]
fn ordinary_values_are_not_tokens() {
    let raw = "GET /search?q=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee&lang=en&v=e.e.e&w=eyJhbGciOiJub25lIn0 HTTP/1.1\r\n\
        Host: example.com\r\n\
        Accept: text/html,application/xhtml+xml\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n\
        Cookie: a=1; b=eeeeeeeeeeeeeeeeeeeeeeeeee.eeeeeeeeeeeeeeeeeeeeee.eeeeeeeeeeeeeeeeeeee\r\n\
        Referer: https://example.com/eyJhbGciOiJIUzI1NiJ9\r\n\r\n";
    assert!(tokens_of(raw).is_empty(), "{:?}", tokens_of(raw));
    assert!(tokens_of("GET / HTTP/1.1\r\nHost: h\r\n\r\n").is_empty());
}

// ------------------------------------------------------------------ passive checks

fn entry(req: &str, resp: &str) -> HistEntry {
    HistEntry {
        id: 1,
        method: "GET".into(),
        host: "app.test".into(),
        port: 80,
        path: "/x".into(),
        status: "200".into(),
        req_raw: req.as_bytes().to_vec().into(),
        resp_raw: Some(resp.as_bytes().to_vec().into()),
        ..Default::default()
    }
}

const OK_RESP: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";

fn weak(req: &str, candidates: &[&str], dedupe: bool) -> Vec<ScanIssue> {
    let e = entry(req, OK_RESP);
    let resp = e.resp_raw.clone().unwrap();
    let all = |_: &str| true;
    let cx = crate::scan::passive_checks::PassiveCtx::new(&e, &resp, None, &all);
    let mut v = Vec::new();
    crate::scan::passive_checks::jwt_weak_secret_with(
        &cx,
        &mut v,
        candidates.iter().copied(),
        dedupe,
    );
    v
}

#[test]
fn passive_weak_secret_reports_a_token_signed_with_a_listed_secret() {
    let t = sign_hs("HS256", b"secret", r#"{"user":"a"}"#);
    let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {t}\r\n\r\n");
    let v = weak(&req, &["a", "secret"], false);
    assert_eq!(
        v.len(),
        1,
        "{:?}",
        v.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
    assert_eq!(v[0].name, "JWT weak HMAC secret");
    assert_eq!(v[0].sev, "high");
    assert_eq!(v[0].confidence, "Certain");
    assert!(v[0].detail.contains("<b>secret</b>"), "{}", v[0].detail);
    // Burp reads cookies and parameters too.
    let req = format!("GET /x?t={t} HTTP/1.1\r\nHost: app.test\r\nCookie: s={t}\r\n\r\n");
    assert_eq!(
        weak(&req, &["secret"], false).len(),
        1,
        "the same token in two places is one issue"
    );
}

#[test]
fn passive_weak_secret_negatives() {
    let t = sign_hs("HS256", b"correct horse battery staple", r#"{"user":"a"}"#);
    let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {t}\r\n\r\n");
    assert!(
        weak(&req, &["a", "secret", "password"], false).is_empty(),
        "secret not in the list"
    );
    assert!(
        weak(
            "GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n",
            &["secret"],
            false
        )
        .is_empty(),
        "no token"
    );
    // An unsigned token is not an HMAC token.
    let none =
        jwt::none_variants(&Jwt::parse(&sign_hs("HS256", b"secret", "{}")).unwrap()).remove(2);
    let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {none}\r\n\r\n");
    assert!(weak(&req, &["secret", ""], false).is_empty());
}

#[test]
fn passive_weak_secret_html_encodes_the_key() {
    let t = sign_hs("HS256", b"<i>&'", r#"{"user":"a"}"#);
    let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {t}\r\n\r\n");
    let v = weak(&req, &["<i>&'"], false);
    assert_eq!(v.len(), 1);
    assert!(!v[0].detail.contains("<i>"), "{}", v[0].detail);
    assert!(v[0].detail.contains("&lt;i&gt;&amp;"), "{}", v[0].detail);
}

#[test]
fn passive_weak_secret_dedupe_skips_a_token_already_tried() {
    let t = sign_hs("HS256", b"secret", r#"{"user":"dedupe-test-unique-9f3a"}"#);
    let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {t}\r\n\r\n");
    assert_eq!(
        weak(&req, &["secret"], true).len(),
        1,
        "first sighting is checked"
    );
    assert!(
        weak(&req, &["secret"], true).is_empty(),
        "second sighting is skipped"
    );
    assert_eq!(
        weak(&req, &["secret"], false).len(),
        1,
        "without dedupe it is checked again"
    );
}

#[test]
fn passive_checks_are_registered_and_switchable() {
    use crate::scan::passive_checks::{run_passive, PASSIVE_CHECKS};
    for id in [
        "passive.jwt-weak-hmac-secret",
        "passive.jwt-private-key-disclosed",
    ] {
        assert!(PASSIVE_CHECKS.iter().any(|c| c.id == id), "{id} registered");
        assert!(
            crate::scan::check_catalogue().iter().any(|c| c.0 == id),
            "{id} in the scan configuration catalogue"
        );
    }
    // The private-key check needs no secret list, so it exercises the
    // scan-configuration switch end to end. (The weak-secret check reads the
    // user's Burp list through a process-wide OnceLock, which a test cannot
    // set safely.)
    let h = b64(r#"{"alg":"HS256","jwk":{"kty":"RSA","n":"abc","e":"AQAB","d":"privatepart"}}"#);
    let t = format!("{h}.{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAA", b64(r#"{"u":1}"#));
    let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {t}\r\n\r\n");
    let echoed = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{t}",
        t.len()
    );
    let e = entry(&req, &echoed);
    let names = |v: Vec<ScanIssue>| -> Vec<String> { v.into_iter().map(|i| i.name).collect() };
    let on = names(run_passive(&e, &|_| true));
    assert!(
        on.iter().any(|n| n == "JWT private key disclosed"),
        "{on:?}"
    );
    let off = names(run_passive(&e, &|id| {
        id != "passive.jwt-private-key-disclosed"
    }));
    assert!(
        !off.iter().any(|n| n == "JWT private key disclosed"),
        "{off:?}"
    );
    // Through the scan configuration the way the live audit does it.
    let shared = Shared::new();
    let live = names(crate::scan::passive_check_for(&shared, &e));
    assert!(
        live.iter().any(|n| n == "JWT private key disclosed"),
        "{live:?}"
    );
    crate::scan_config::shared_config(&shared)
        .lock()
        .unwrap()
        .disabled_checks
        .insert("passive.jwt-private-key-disclosed".into());
    let live = names(crate::scan::passive_check_for(&shared, &e));
    assert!(
        !live.iter().any(|n| n == "JWT private key disclosed"),
        "{live:?}"
    );
}

#[test]
fn passive_private_key_needs_the_token_echoed_and_a_private_jwk() {
    use crate::scan::passive_checks::run_passive;
    let only = |id: &str| id == "passive.jwt-private-key-disclosed";
    let mk = |jwk: &str| {
        let h = b64(format!(r#"{{"alg":"HS256","jwk":{jwk}}}"#));
        format!("{h}.{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAA", b64(r#"{"u":1}"#))
    };
    let run = |t: &str, body: &str| {
        let req = format!("GET /x HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer {t}\r\n\r\n");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        run_passive(&entry(&req, &resp), &only).len()
    };
    let private = mk(r#"{"kty":"RSA","n":"abc","e":"AQAB","d":"x"}"#);
    let public = mk(r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#);
    assert_eq!(run(&private, &format!("echo: {private}")), 1);
    assert_eq!(run(&private, "no token here"), 0, "private key not echoed");
    assert_eq!(
        run(&public, &format!("echo: {public}")),
        0,
        "public key only"
    );
}

// ------------------------------------------------------------------ active check

#[derive(Clone, Copy, PartialEq, Debug)]
enum App {
    /// Verifies HS256 signatures.
    Proper,
    /// Reads the payload and never looks at the signature.
    IgnoresSignature,
    /// Verifies signatures but also trusts alg "none" with no signature.
    AcceptsNone,
    /// Does not use the token at all.
    Unused,
}

const APP_SECRET: &[u8] = b"a-secret-that-is-in-no-list-0451";
const APP_PAYLOAD: &str = r#"{"sub":"alice","role":"user","iat":1700000000}"#;

fn app_token() -> String {
    sign_hs("HS256", APP_SECRET, APP_PAYLOAD)
}

/// (status, body) for a presented token.
fn verdict(app: App, token: Option<&str>) -> (u16, String) {
    let denied = (401, "invalid token".to_string());
    if app == App::Unused {
        return (200, "welcome page".into());
    }
    let Some(token) = token else { return denied };
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return denied;
    }
    let (Ok(h), Ok(p)) = (B64.decode(parts[0]), B64.decode(parts[1])) else {
        return denied;
    };
    let (Ok(h), Ok(p)) = (
        serde_json::from_slice::<serde_json::Value>(&h),
        serde_json::from_slice::<serde_json::Value>(&p),
    ) else {
        return denied;
    };
    let alg = h["alg"].as_str().unwrap_or("").to_string();
    let verified_hs = || {
        alg == "HS256"
            && B64.decode(parts[2]).is_ok_and(|sig| {
                ring::hmac::verify(
                    &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, APP_SECRET),
                    format!("{}.{}", parts[0], parts[1]).as_bytes(),
                    &sig,
                )
                .is_ok()
            })
    };
    let ok = match app {
        App::Proper => verified_hs(),
        App::IgnoresSignature => true,
        App::AcceptsNone => {
            verified_hs() || (alg.eq_ignore_ascii_case("none") && parts[2].is_empty())
        }
        App::Unused => unreachable!(),
    };
    match (ok, p["sub"].as_str()) {
        (true, Some(sub)) => (200, format!("hello {sub}")),
        _ => denied,
    }
}

/// The token a request carries: cookie `tok`, query `t`, or a Bearer header.
fn presented(head: &str) -> Option<String> {
    let line = head.lines().next().unwrap_or("");
    if let Some(q) = line
        .split(' ')
        .nth(1)
        .and_then(|p| p.split_once('?'))
        .map(|x| x.1)
    {
        for kv in q.split('&') {
            if let Some(v) = kv.strip_prefix("t=") {
                return Some(
                    crate::util::url_decode(v)
                        .trim()
                        .strip_prefix("Bearer ")
                        .map(str::to_string)
                        .unwrap_or_else(|| crate::util::url_decode(v)),
                );
            }
        }
    }
    for l in head.lines() {
        let low = l.to_ascii_lowercase();
        if let Some(c) = low.strip_prefix("cookie:") {
            let _ = c;
            for kv in l[7..].split(';') {
                if let Some(v) = kv.trim().strip_prefix("tok=") {
                    return Some(v.to_string());
                }
            }
        }
        for h in ["authorization:", "x-auth-token:"] {
            if low.starts_with(h) {
                let v = l[h.len()..].trim();
                return Some(v.strip_prefix("Bearer ").unwrap_or(v).to_string());
            }
        }
    }
    None
}

/// A loopback app: one thread per connection, fixed Content-Length bodies,
/// no Date header, nothing random. Returns the port and the heads it saw.
fn responder(app: App) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let log = log.clone();
            std::thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                log.lock().unwrap().push(head.clone());
                let (status, body) = verdict(app, presented(&head).as_deref());
                let reason = if status == 200 { "OK" } else { "Unauthorized" };
                let _ = s.write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            });
        }
    });
    (port, seen)
}

/// Run an active scan restricted to the JWT check; the issues it raised.
fn scan(
    port: u16,
    request_tail: &str,
    path: &str,
    disabled: &[&str],
    oob: Vec<(String, String, String)>,
) -> (std::sync::Arc<Shared>, Vec<ScanIssue>) {
    let shared = Shared::new();
    {
        let cfg_slot = crate::scan_config::shared_config(&shared);
        let mut cfg = cfg_slot.lock().unwrap();
        for (id, _, _) in crate::scan::check_catalogue() {
            if id != "active.jwt" {
                cfg.disabled_checks.insert(id.to_string());
            }
        }
        for d in disabled {
            cfg.disabled_checks.insert((*d).to_string());
        }
    }
    let mut e = entry("", "");
    e.host = "127.0.0.1".into();
    e.port = port;
    e.path = path.into();
    e.req_raw = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{request_tail}\r\n")
        .into_bytes()
        .into();
    crate::scan::start_active_scan(shared.clone(), e, &oob, &[]);
    let t0 = Instant::now();
    while shared.scan.is_busy() {
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "scan did not finish"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let issues = shared.issues.lock().unwrap().clone();
    (shared, issues)
}

fn jwt_issue_names(issues: &[ScanIssue]) -> Vec<String> {
    let mut n: Vec<String> = issues
        .iter()
        .filter(|i| i.name.starts_with("JWT "))
        .map(|i| i.name.clone())
        .collect();
    n.sort();
    n
}

fn cookie_scan(app: App, disabled: &[&str]) -> Vec<ScanIssue> {
    let (port, _) = responder(app);
    scan(
        port,
        &format!("Cookie: tok={}\r\n", app_token()),
        "/me",
        disabled,
        Vec::new(),
    )
    .1
}

#[test]
fn responder_self_check() {
    // The fixtures behave as described, so the scan tests mean something.
    let t = app_token();
    assert_eq!(verdict(App::Proper, Some(&t)).0, 200);
    assert_eq!(
        verdict(
            App::Proper,
            Some(&jwt::corrupt_signature(&Jwt::parse(&t).unwrap()))
        )
        .0,
        401
    );
    assert_eq!(
        verdict(
            App::Proper,
            Some(&jwt::control_token(&Jwt::parse(&t).unwrap()))
        )
        .0,
        401
    );
    assert_eq!(
        verdict(
            App::IgnoresSignature,
            Some(&jwt::corrupt_signature(&Jwt::parse(&t).unwrap()))
        )
        .0,
        200
    );
    assert_eq!(
        verdict(
            App::IgnoresSignature,
            Some(&jwt::control_token(&Jwt::parse(&t).unwrap()))
        )
        .0,
        401
    );
    assert_eq!(
        verdict(
            App::AcceptsNone,
            Some(&jwt::none_variants(&Jwt::parse(&t).unwrap())[2])
        )
        .0,
        200
    );
    assert_eq!(
        verdict(
            App::Proper,
            Some(&jwt::none_variants(&Jwt::parse(&t).unwrap())[2])
        )
        .0,
        401
    );
}

#[test]
fn active_jwt_app_that_verifies_signatures_reports_nothing() {
    let issues = cookie_scan(App::Proper, &[]);
    assert!(
        jwt_issue_names(&issues).is_empty(),
        "{:?}",
        jwt_issue_names(&issues)
    );
}

#[test]
fn active_jwt_app_that_does_not_use_the_token_reports_nothing() {
    // The control token cannot be told from the original: no verdict possible.
    let issues = cookie_scan(App::Unused, &[]);
    assert!(
        jwt_issue_names(&issues).is_empty(),
        "{:?}",
        jwt_issue_names(&issues)
    );
}

#[test]
fn active_jwt_signature_not_verified_is_reported_with_burps_name() {
    let issues = cookie_scan(App::IgnoresSignature, &[]);
    let names = jwt_issue_names(&issues);
    assert!(
        names.iter().any(|n| n == "JWT signature not verified"),
        "{names:?}"
    );
    let i = issues
        .iter()
        .find(|i| i.name == "JWT signature not verified")
        .unwrap();
    assert_eq!(i.sev, "high");
    assert_eq!(i.confidence, "Tentative");
    assert!(
        i.detail.contains("signature of the JWT within the"),
        "{}",
        i.detail
    );
    assert_eq!(
        i.evidence.len(),
        3,
        "attack, original and control exchanges"
    );
    // An app that never checks the signature also trusts none and a foreign JWK.
    assert!(
        names.iter().any(|n| n == "JWT none algorithm supported"),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n == "JWT self-signed JWK header supported"),
        "{names:?}"
    );
}

#[test]
fn active_jwt_issue_is_switchable_by_its_id() {
    let issues = cookie_scan(
        App::IgnoresSignature,
        &["active.jwt.jwt-signature-not-verified"],
    );
    let names = jwt_issue_names(&issues);
    assert!(
        !names.iter().any(|n| n == "JWT signature not verified"),
        "{names:?}"
    );
    assert!(
        names.iter().any(|n| n == "JWT none algorithm supported"),
        "the other issues stay on: {names:?}"
    );
    let issues = cookie_scan(App::IgnoresSignature, &["active.jwt"]);
    assert!(jwt_issue_names(&issues).is_empty(), "the whole check off");
}

#[test]
fn active_jwt_none_algorithm_is_reported_and_only_that() {
    let issues = cookie_scan(App::AcceptsNone, &[]);
    let names = jwt_issue_names(&issues);
    assert!(
        names.iter().any(|n| n == "JWT none algorithm supported"),
        "{names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "JWT signature not verified"),
        "{names:?}"
    );
    assert!(
        !names
            .iter()
            .any(|n| n == "JWT self-signed JWK header supported"),
        "{names:?}"
    );
    let issues = cookie_scan(
        App::AcceptsNone,
        &["active.jwt.jwt-none-algorithm-supported"],
    );
    assert!(jwt_issue_names(&issues).is_empty());
}

#[test]
fn active_jwt_attacks_a_bearer_token_in_a_query_parameter() {
    // applies_to / run strip a "Bearer " prefix from the value.
    let (port, seen) = responder(App::IgnoresSignature);
    let t = app_token();
    let (_, issues) = scan(port, "", &format!("/me?t=Bearer%20{t}"), &[], Vec::new());
    let names = jwt_issue_names(&issues);
    assert!(
        names.iter().any(|n| n == "JWT signature not verified"),
        "{names:?}"
    );
    // The attack kept the prefix.
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|h| h.contains("t=Bearer%20")
                && h.contains(&format!("{}.", Jwt::parse(&t).unwrap().header_b64))),
        "requests carried 'Bearer <token>'"
    );
}

#[test]
fn active_jwt_attacks_a_bearer_token_in_an_x_header() {
    // Header insertion points are the X-* headers, User-Agent and Referer.
    let (port, seen) = responder(App::IgnoresSignature);
    let (_, issues) = scan(
        port,
        &format!("X-Auth-Token: Bearer {}\r\n", app_token()),
        "/me",
        &[],
        Vec::new(),
    );
    let names = jwt_issue_names(&issues);
    assert!(
        names.iter().any(|n| n == "JWT signature not verified"),
        "{names:?}"
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|h| h.to_ascii_lowercase().contains("x-auth-token: bearer ")),
        "requests keep the Bearer prefix"
    );
}

#[test]
fn active_jwt_applies_only_to_points_holding_a_token() {
    let t = app_token();
    let cfg = crate::scan_config::ScanConfig::default();
    let check = crate::scan::checks::JwtAttacks;
    use crate::scan::checks::PointCheck;
    let applies = |req: &str| -> Vec<bool> {
        crate::scan::insertion::audit_points(req, &cfg)
            .iter()
            .map(|ip| check.applies_to(ip))
            .collect()
    };
    let q = applies(&format!(
        "GET /x?a=1&t={t}&b=eyJ HTTP/1.1\r\nHost: h\r\n\r\n"
    ));
    assert_eq!(q.iter().filter(|b| **b).count(), 1, "{q:?}");
    let q = applies(&format!(
        "GET /x?t=Bearer%20{t} HTTP/1.1\r\nHost: h\r\n\r\n"
    ));
    assert_eq!(
        q.iter().filter(|b| **b).count(),
        1,
        "Bearer-prefixed value: {q:?}"
    );
    let q = applies(&format!(
        "GET /x HTTP/1.1\r\nHost: h\r\nCookie: tok={t}\r\n\r\n"
    ));
    assert_eq!(q.iter().filter(|b| **b).count(), 1, "cookie: {q:?}");
    let body = format!("{{\"token\":\"{t}\",\"x\":1}}");
    let q = applies(&format!("POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
    assert!(q.iter().any(|b| *b), "JSON member: {q:?}");
    let q = applies("GET /x?a=1&b=2 HTTP/1.1\r\nHost: h\r\nCookie: s=abc\r\n\r\n");
    assert!(q.iter().all(|b| !b), "ordinary values: {q:?}");
}

// ------------------------------------------------------------------ jku / x5u

fn jwt_point_index(req: &str, name: &str) -> usize {
    crate::scan::insertion::audit_points(req, &Default::default())
        .iter()
        .position(|ip| ip.name == name)
        .expect("insertion point")
}

#[test]
fn active_jwt_jku_and_x5u_send_a_collaborator_url_and_register_the_id() {
    let (port, seen) = responder(App::Proper);
    let req = format!(
        "GET /me HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: tok={}\r\n\r\n",
        app_token()
    );
    let k = jwt_point_index(&req, "tok");
    let oob = vec![
        (
            format!("#{k}:jku"),
            "jkuid".to_string(),
            "jkuid.oast.test".to_string(),
        ),
        (
            format!("#{k}:x5u"),
            "x5uid".to_string(),
            "x5uid.oast.test".to_string(),
        ),
    ];
    let (shared, issues) = scan(
        port,
        &format!("Cookie: tok={}\r\n", app_token()),
        "/me",
        &[],
        oob,
    );
    assert!(
        jwt_issue_names(&issues).is_empty(),
        "nothing reported before an interaction: {:?}",
        jwt_issue_names(&issues)
    );
    let heads = seen.lock().unwrap().clone();
    let header_of = |name: &str| -> Option<serde_json::Value> {
        heads.iter().find_map(|h| {
            let tok = presented(h)?;
            let j = Jwt::parse(&tok)?;
            j.header.get(name).cloned()
        })
    };
    assert_eq!(
        header_of("jku"),
        Some(serde_json::json!("https://jkuid.oast.test/"))
    );
    assert_eq!(
        header_of("x5u"),
        Some(serde_json::json!("https://x5uid.oast.test/"))
    );
    let pending = shared.oob.pending();
    for (id, name) in [
        ("jkuid", "JWT arbitrary jku header supported"),
        ("x5uid", "JWT arbitrary x5u header supported"),
    ] {
        let p = pending
            .iter()
            .find(|p| p.0 == id)
            .unwrap_or_else(|| panic!("{id} registered"));
        assert_eq!(p.2.name, name);
        assert_eq!(p.2.sev, "high");
        assert_eq!(p.2.confidence, "Certain");
    }
    // The per-issue switch keeps the id from being sent.
    let (port, seen) = responder(App::Proper);
    let oob = vec![(
        format!("#{k}:jku"),
        "jkuid".to_string(),
        "jkuid.oast.test".to_string(),
    )];
    let (shared, _) = scan(
        port,
        &format!("Cookie: tok={}\r\n", app_token()),
        "/me",
        &["active.jwt.jwt-arbitrary-jku-header-supported"],
        oob,
    );
    assert!(shared.oob.pending().is_empty());
    assert!(
        !seen.lock().unwrap().iter().any(|h| h.contains("oast")),
        "no jku request when switched off"
    );
}

fn http_interaction(token: &str) -> crate::collaborator::Interaction {
    use crate::collaborator::{HttpInteraction, Interaction, InteractionDetail};
    Interaction {
        id: 1,
        at: 0,
        source: "192.0.2.1".into(),
        token: Some(token.into()),
        detail: InteractionDetail::Http(HttpInteraction {
            method: "GET".into(),
            target: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
        }),
    }
}

#[test]
fn active_jwt_jku_interaction_raises_the_jwt_issue() {
    let (port, _) = responder(App::Proper);
    let req = format!(
        "GET /me HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: tok={}\r\n\r\n",
        app_token()
    );
    let k = jwt_point_index(&req, "tok");
    let oob = vec![(
        format!("#{k}:jku"),
        "jkuid2".to_string(),
        "jkuid2.oast.test".to_string(),
    )];
    let (shared, _) = scan(
        port,
        &format!("Cookie: tok={}\r\n", app_token()),
        "/me",
        &[],
        oob,
    );
    let got = shared.oob.match_interactions(&[http_interaction("jkuid2")]);
    let names: Vec<&str> = got.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        ["JWT arbitrary jku header supported"],
        "the interaction must raise the JWT issue"
    );
    assert_eq!(got[0].sev, "high");
}

#[test]
fn active_jwt_scan_requests_jku_and_x5u_collaborator_slots() {
    let t = app_token();
    let req = format!("GET /me HTTP/1.1\r\nHost: h\r\nCookie: tok={t}\r\n\r\n");
    let k = jwt_point_index(&req, "tok");
    let slots = crate::scan::slots_for(
        req.as_bytes(),
        crate::scan::ScanSpeed::Normal,
        &Default::default(),
    );
    for kind in ["jku", "x5u"] {
        assert!(slots.contains(&format!("#{k}:{kind}")), "no #{k}:{kind} slot, so a real scan never gets a Collaborator payload for it: {slots:?}");
    }
    // A point that holds no token gets none.
    let req = "GET /me?a=1 HTTP/1.1\r\nHost: h\r\n\r\n";
    let slots = crate::scan::slots_for(
        req.as_bytes(),
        crate::scan::ScanSpeed::Normal,
        &Default::default(),
    );
    assert!(
        !slots
            .iter()
            .any(|s| s.ends_with(":jku") || s.ends_with(":x5u")),
        "{slots:?}"
    );
}
