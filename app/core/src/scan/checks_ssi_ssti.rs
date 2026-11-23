// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

pub const SSI_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// burp.Zcub.Zy: Caesar shift of the first `len` alphabet chars of `s` by
/// `shift` over the 36-char alphabet.
pub fn ssi_shift(s: &str, shift: usize, len: usize) -> String {
    s.chars()
        .filter_map(|c| SSI_ALPHABET.iter().position(|&a| a == c as u8))
        .take(len)
        .map(|i| SSI_ALPHABET[(i + shift) % SSI_ALPHABET.len()] as char)
        .collect()
}

/// burp.Zxvd.Zu: the SSI echo-based payload. id1/value1 shift by 14/13,
/// id2/value2 by 16/15 (burp.Zcub.Zs). Returns (payload, expected echo).
pub fn ssi_payload(token: &str) -> (String, String) {
    let (id1, v1) = (ssi_shift(token, 14, 10), ssi_shift(token, 13, 10));
    let (id2, v2) = (ssi_shift(token, 16, 10), ssi_shift(token, 15, 10));
    let payload = format!(
        "<!--#set var=\"{id1}\" value=\"{v1}\"--><!--#set var=\"{id2}\" value=\"{v2}\"--><!--#echo var=\"{id1}\"--><!--#echo var=\"{id2}\"-->"
    );
    (payload, format!("{v1}{v2}"))
}

pub struct SsiHit {
    pub payload: String,
}

/// burp.Zexx echo-based SSI: a server that processes SSI emits value1value2
/// as bare text, which the reflected payload never shows contiguously.
pub fn run_ssi_check<F: FnMut(&str) -> Option<String>>(value: &str, mut send: F) -> Option<SsiHit> {
    let token: String = {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10)
            .map(|_| SSI_ALPHABET[g.gen_range(0..26)] as char)
            .collect()
    };
    let (payload, expected) = ssi_payload(&token);
    let body = send(&format!("{value}{payload}"))?;
    if body.contains(&payload) {
        return None;
    }
    body.contains(&expected).then_some(SsiHit { payload })
}

/// A template-injection probe ported from one burp.Znq echo-based detector:
/// `make` builds `<prefix>EXPR<suffix>`, `expected` is the string a vulnerable
/// engine renders between the same prefix and suffix. The literal payload is
/// never equal to `expected` (comment-split or arithmetic), so a plain echo
/// does not match. burp.Ziog(payload, expected).
pub struct SstiProbe {
    pub engine: &'static str,
    pub payload: String,
    pub expected: Vec<String>,
}

/// burp.Znq echo-based detectors (Zsl3, Zhuy, Zieh, Zgok, Zpk0, Zbrp, Ziyq,
/// Zxpo arithmetic; Zp1w, Zpjg, Zi1a identity). Random prefix/suffix and
/// factors per Zg_o.ZP/Zu, so a literal reflection cannot collide.
pub fn ssti_probes(prefix: &str, suffix: &str) -> Vec<SstiProbe> {
    use rand::Rng;
    let mut g = rand::thread_rng();
    let n = |g: &mut rand::rngs::ThreadRng| g.gen_range(100..1000);
    let (a, b, c, d) = (n(&mut g), n(&mut g), n(&mut g), n(&mut g));
    let p = |engine: &'static str, payload: String, expected: Vec<String>| SstiProbe {
        engine,
        payload,
        expected,
    };
    vec![
        p(
            "Freemarker/EL ${}",
            format!("{prefix}${{{a}*{b}}}{suffix}"),
            vec![format!("{prefix}{}{suffix}", a * b)],
        ),
        p(
            "Jinja/Twig {{}}",
            format!("{prefix}{{{{{a}*{b}}}}}{suffix}"),
            vec![format!("{prefix}{}{suffix}", a * b)],
        ),
        p(
            "Spring/Thymeleaf #{}",
            format!("{prefix}#{{{a}*{b}}}{suffix}"),
            vec![format!("{prefix}{}{suffix}", a * b)],
        ),
        p(
            "Struts/OGNL %{}",
            format!("{prefix}%{{{a}*{b}}}{suffix}"),
            vec![format!("{prefix}{}{suffix}", a * b)],
        ),
        p(
            "Angular/other [[]]",
            format!("{prefix}[[{a}*{b}]]{suffix}"),
            vec![format!("{prefix}{}{suffix}", a * b)],
        ),
        p(
            "Smarty {}",
            format!("{prefix}{{{a}*{b}}}{{*commentedout*}}{{{c}*{d}}}{suffix}"),
            vec![format!("{prefix}{}{}{suffix}", a * b, c * d)],
        ),
        p(
            "Twig {{*'*'}}",
            format!("{prefix}{{{{{a}*'{b}'}}}}{{#commentedout#}}{{{{{c}*{d}}}}}{suffix}"),
            vec![
                format!("{prefix}{}{suffix}", c * d),
                format!("{prefix}{}{}{suffix}", a * b, c * d),
            ],
        ),
        p(
            "EL ${''.class}",
            format!("{prefix}${{''.class}}{suffix}"),
            vec![format!("{prefix}class java.lang.String{suffix}")],
        ),
        p(
            "EL ${os.arch}",
            format!("{prefix}${{os.arch}}{suffix}"),
            vec![
                format!("{prefix}amd64{suffix}"),
                format!("{prefix}x86_64{suffix}"),
            ],
        ),
        p(
            "EL ${file.separator}",
            format!("{prefix}${{file.separator}}{suffix}"),
            vec![format!("{prefix}/{suffix}"), format!("{prefix}\\{suffix}")],
        ),
    ]
}

pub struct SstiHit {
    pub engine: &'static str,
    pub payload: String,
}

/// burp.Zi6p echo-based template/code injection: for each detector, send
/// `<prefix>EXPR<suffix>` and report when the rendered `expected` appears in
/// the response while the raw payload does not (so a literal echo is rejected).
pub fn run_ssti_check<F: FnMut(&str) -> Option<String>>(
    value: &str,
    mut send: F,
) -> Option<SstiHit> {
    use rand::Rng;
    let mut g = rand::thread_rng();
    let rnd = |g: &mut rand::rngs::ThreadRng| {
        (0..5)
            .map(|_| (b'a' + g.gen_range(0..26)) as char)
            .collect::<String>()
    };
    let (prefix, suffix) = (rnd(&mut g), rnd(&mut g));
    for probe in ssti_probes(&prefix, &suffix) {
        let Some(body) = send(&format!("{value}{}", probe.payload)) else {
            continue;
        };
        if body.contains(&probe.payload) {
            continue; // literal echo, not evaluation
        }
        if probe.expected.iter().any(|e| body.contains(e)) {
            return Some(SstiHit {
                engine: probe.engine,
                payload: probe.payload,
            });
        }
    }
    None
}
