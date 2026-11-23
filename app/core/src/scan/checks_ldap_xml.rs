// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// burp.Zwkf.ZM/ZR: not for boolean literals, and only when every char after
/// the first is a letter, digit, space or one of `'"@.-*`.
pub fn ldap_applicable(value: &str) -> bool {
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
        return false;
    }
    value
        .chars()
        .skip(1)
        .all(|c| c.is_alphanumeric() || " '\"@.-*".contains(c))
}

/// burp.Zsna.ZI: `<prefix>)(<filter>` where the filter is objectClass=*
/// wrapped in `k % 6` negations. Even k always matches (positive), odd k
/// never matches (negative); Burp walks k = 0,2,4,.. and 1,3,5,..
pub fn ldap_payload(prefix: &str, k: usize) -> String {
    let mut f = "objectClass=*".to_string();
    for _ in 0..k % 6 {
        f = format!("!({f})");
    }
    format!("{prefix})({f}")
}

pub struct LdapHit {
    pub positive: String,
    pub negative: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zp7s.Zq: appended to the value (insertion mode 1, base + payload).
pub const XML_INJECTION_PAYLOAD: &str = "]]>><";

/// burp.Zp7s.ZJ, read back from its compiled byte tries (case-insensitive):
/// XML / SOAP markers whose appearance signals the payload reached an XML
/// document the application builds.
pub const XML_INJECTION_MARKERS: [&str; 14] = [
    "xml.",
    "xml&nbsp;",
    "xmlschema",
    "xmlsoap",
    "xmlns:soap",
    "xmlns:xsd",
    "xmlns:xsi",
    "soap ",
    "soap.",
    "soap:",
    "soapenv",
    "soap-env",
    "soap:env",
    "soap:body",
];

/// burp.Zp7s.Zq: repetitions by audit accuracy (1, 2 or 3).
pub fn xml_injection_rounds(a: crate::variations::Accuracy) -> usize {
    match a {
        crate::variations::Accuracy::MinimizeFalseNegatives => 1,
        crate::variations::Accuracy::Normal => 2,
        crate::variations::Accuracy::MinimizeFalsePositives => 3,
    }
}

/// The markers present in a response body, ignoring any that sit inside an
/// ASP.NET __VIEWSTATE value (burp.Zw4k.ZI).
pub fn xml_markers_in(resp: &[u8]) -> Vec<&'static str> {
    let p = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).to_ascii_lowercase();
    let viewstate: Vec<(usize, usize)> = {
        let mut v = Vec::new();
        let mut from = 0;
        while let Some(i) = body[from..].find("__viewstate") {
            let at = from + i;
            if let Some(vs) = body[at..].find("value=\"") {
                let start = at + vs + 7;
                let end = body[start..]
                    .find('"')
                    .map(|e| start + e)
                    .unwrap_or(body.len());
                v.push((start, end));
            }
            from = at + 11;
        }
        v
    };
    XML_INJECTION_MARKERS
        .iter()
        .copied()
        .filter(|m| {
            let mut from = 0;
            while let Some(i) = body[from..].find(m) {
                let at = from + i;
                if !viewstate.iter().any(|(s, e)| at >= *s && at < *e) {
                    return true;
                }
                from = at + 1;
            }
            false
        })
        .collect()
}

/// burp.Zp7s.ZT: applies when the value holds no '<' or '>' (Zp7s.ZQ). Each
/// round appends the payload and keeps only the markers the round's baseline
/// (the original response first, then a fresh one) did not already show; the
/// issue needs new markers in every round.
pub fn run_xml_injection_check<P, B>(
    value: &str,
    baseline: &[u8],
    rounds: usize,
    mut send_payload: P,
    mut send_base: B,
) -> Option<Vec<&'static str>>
where
    P: FnMut(&str) -> Option<Vec<u8>>,
    B: FnMut() -> Option<Vec<u8>>,
{
    if value.contains(['<', '>']) {
        return None;
    }
    let payload = format!("{value}{XML_INJECTION_PAYLOAD}");
    let mut last = Vec::new();
    for round in 0..rounds.max(1) {
        let base = if round == 0 {
            baseline.to_vec()
        } else {
            send_base()?
        };
        let before = xml_markers_in(&base);
        let attack = send_payload(&payload)?;
        let new: Vec<&'static str> = xml_markers_in(&attack)
            .into_iter()
            .filter(|m| !before.contains(m))
            .collect();
        if new.is_empty() {
            return None;
        }
        last = new;
    }
    Some(last)
}

pub fn run_ldap_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    speed: ScanSpeed,
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<LdapHit> {
    if !ldap_applicable(value) {
        return None;
    }
    let random = || {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..10)
            .map(|_| (b'a' + rng.gen_range(0..26)) as char)
            .collect::<String>()
    };
    let variants: Vec<bool> = if speed >= ScanSpeed::Normal {
        vec![true, false]
    } else {
        vec![false]
    };
    for random_prefix in variants {
        let prefix = |r: &dyn Fn() -> String| if random_prefix { r() } else { "*".to_string() };
        let (mut kp, mut kn) = (0usize, 1usize);
        let (mut first_p, mut first_n) = (None, None);
        let sent = std::cell::RefCell::new(&mut send);
        let attrs = crate::variations::differential(
            Some(baseline),
            accuracy,
            || {
                let p = ldap_payload(&prefix(&random), kp);
                kp += 2;
                first_p.get_or_insert_with(|| p.clone());
                (sent.borrow_mut())(&p)
            },
            || {
                let p = ldap_payload(&prefix(&random), kn);
                kn += 2;
                first_n.get_or_insert_with(|| p.clone());
                (sent.borrow_mut())(&p)
            },
        );
        if let Some(attributes) = attrs {
            return Some(LdapHit {
                positive: first_p.unwrap_or_default(),
                negative: first_n.unwrap_or_default(),
                attributes,
            });
        }
    }
    None
}
