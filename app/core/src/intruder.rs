//! Intruder engine core: payload positions (C-02), the request matrix of the four
//! attack types (C-01), payload sources (C-03) and payload processing (C-04).
//!
//! Pure and independent of the UI and the network, so the matrix is tested on its
//! own; a runner only has to walk what `requests` returns. Positions are written
//! as `§original§` in the request text, exactly like Burp, and the markers never
//! reach the wire: `Template::render` strips them.
//!
//! Sources turn into plain `Vec<String>` sets (`resolve_sets`), which is exactly
//! what the UI stores and what `requests` consumes, so the new types sit beside
//! the existing API instead of replacing it.

use std::collections::HashSet;

use crate::decoder_ops::{self, Op};
use crate::util;

pub const MARK: char = '§';

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackType {
    /// One set; each position in turn, the others keep their original text.
    Sniper,
    /// One set; the same payload goes into every position at once.
    BatteringRam,
    /// One set per position, walked in lock step; stops at the shortest set.
    Pitchfork,
    /// One set per position; every combination, the last position varying fastest.
    ClusterBomb,
}

impl AttackType {
    pub fn label(self) -> &'static str {
        // Runtime-grounded display strings: burp.Zgu5 enum constants decode to
        // "Sniper attack" / "Battering ram attack" / "Pitchfork attack" /
        // "Cluster bomb attack" (runtime_enums.tsv, runtime.enumConstant:Zgu5).
        match self {
            AttackType::Sniper => "Sniper attack",
            AttackType::BatteringRam => "Battering ram attack",
            AttackType::Pitchfork => "Pitchfork attack",
            AttackType::ClusterBomb => "Cluster bomb attack",
        }
    }

    /// How many payload sets the attack consumes for `positions` positions.
    pub fn sets_needed(self, positions: usize) -> usize {
        match self {
            AttackType::Sniper | AttackType::BatteringRam => 1,
            AttackType::Pitchfork | AttackType::ClusterBomb => positions,
        }
    }
}

/// A request template split at its payload positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Text between positions; always one more entry than `defaults`.
    literals: Vec<String>,
    /// The original text inside each marker pair.
    defaults: Vec<String>,
}

pub struct MarkerSeg {
    pub text: String,
    pub is_marker: bool,
}

pub fn parse_markers(text: &str) -> Vec<MarkerSeg> {
    let mut segs = Vec::new();
    let mut current = String::new();
    let mut in_marker = false;
    for c in text.chars() {
        if c == '§' {
            segs.push(MarkerSeg {
                text: std::mem::take(&mut current),
                is_marker: in_marker,
            });
            in_marker = !in_marker;
        } else {
            current.push(c);
        }
    }
    segs.push(MarkerSeg {
        text: current,
        is_marker: in_marker,
    });
    segs
}

/// Errors from Intruder template/marker handling and payload validation
/// (issue #34). Display text matches the previous `String` messages byte for
/// byte; `From<IntruderError> for String` keeps `?` working in String-typed
/// callers during the gradual conversion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntruderError {
    #[error("unbalanced § marker: a position is never closed")]
    UnbalancedMarker,
    #[error("the selection is outside the request")]
    SelectionOutsideRequest,
    #[error("the selection already contains a position marker")]
    SelectionHasMarker,
    #[error("the selection is inside an existing position")]
    SelectionInsidePosition,
    #[error("No extension payload generator is selected.")]
    NoExtensionGenerator,
    #[error("Bit flipper payload source cannot operate on the base payload position value when using the battering ram attack type.")]
    BitFlipperBaseUnsupported,
    #[error("No bits are selected.")]
    NoBitsSelected,
    #[error("Invalid base string.")]
    InvalidBaseString,
    #[error("Invalid base string")]
    InvalidBase,
    #[error("Base string contains some non-hex characters.")]
    NonHexBase,
    #[error("Invalid block size")]
    InvalidBlockSize,
    #[error("This payload type cannot be used in battering ram attacks")]
    BatteringRamUnsupported,
    #[error("No list items specified.")]
    NoListItems,
    #[error("Cannot copy payload from another position using this attack type.")]
    CopyPayloadWrongAttack,
    #[error("Cannot copy payload from invalid position.")]
    CopyPayloadInvalidPosition,
    #[error("Cannot copy payload from same position.")]
    CopyPayloadSamePosition,
    #[error("Cannot copy payload from another dependent position.")]
    CopyPayloadDependent,
}

impl From<IntruderError> for String {
    fn from(err: IntruderError) -> Self {
        err.to_string()
    }
}

impl Template {
    pub fn parse(text: &str) -> Result<Self, IntruderError> {
        let segments = parse_markers(text);
        if segments.last().is_some_and(|s| s.is_marker) {
            return Err(IntruderError::UnbalancedMarker);
        }
        let mut literals = Vec::new();
        let mut defaults = Vec::new();
        for segment in segments {
            if segment.is_marker {
                defaults.push(segment.text);
            } else {
                literals.push(segment.text);
            }
        }
        Ok(Self { literals, defaults })
    }

    pub fn positions(&self) -> usize {
        self.defaults.len()
    }

    /// The original text inside each marker pair (the base values).
    pub fn position_values(&self) -> &[String] {
        &self.defaults
    }

    /// The request with `values[i]` in position `i`; `None` keeps the original text.
    pub fn render(&self, values: &[Option<&str>]) -> String {
        let mut out = String::new();
        for (i, literal) in self.literals.iter().enumerate() {
            out.push_str(literal);
            if let Some(default) = self.defaults.get(i) {
                out.push_str(values.get(i).copied().flatten().unwrap_or(default));
            }
        }
        out
    }
}

/// One request of an attack and the payload used in each position (`None` where
/// the position kept its original text, which only happens for Sniper).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attack {
    pub payloads: Vec<Option<String>>,
    pub request: String,
}

/// How many requests the attack will make, or `None` when it overflows.
pub fn count(kind: AttackType, positions: usize, set_lens: &[usize]) -> Option<usize> {
    match kind {
        AttackType::Sniper => positions.checked_mul(*set_lens.first()?),
        AttackType::BatteringRam => set_lens.first().copied(),
        AttackType::Pitchfork => set_lens.iter().take(positions).copied().min(),
        AttackType::ClusterBomb => set_lens
            .iter()
            .take(positions)
            .try_fold(1usize, |acc, &n| acc.checked_mul(n)),
    }
}

fn attack(template: &Template, values: &[Option<&str>]) -> Attack {
    Attack {
        payloads: values.iter().map(|v| v.map(str::to_string)).collect(),
        request: template.render(values),
    }
}

/// The full request matrix. `limit` guards against a cluster bomb that would
/// allocate millions of requests before the first one is sent.
pub fn requests(
    template: &Template,
    kind: AttackType,
    sets: &[Vec<String>],
    limit: usize,
) -> Result<Vec<Attack>, String> {
    let n = template.positions();
    if n == 0 {
        return Err("no payload positions: mark at least one with §".into());
    }
    let needed = kind.sets_needed(n);
    if sets.len() < needed {
        return Err(format!(
            "{} needs {needed} payload set(s) for {n} position(s), got {}",
            kind.label(),
            sets.len()
        ));
    }
    if let Some(empty) = sets[..needed].iter().position(|s| s.is_empty()) {
        return Err(format!("payload set {} is empty", empty + 1));
    }
    let lens: Vec<usize> = sets[..needed].iter().map(Vec::len).collect();
    let total =
        count(kind, n, &lens).ok_or_else(|| "the attack is too large to count".to_string())?;
    if total > limit {
        return Err(format!(
            "{} would send {total} requests, over the limit of {limit}",
            kind.label()
        ));
    }

    let mut out = Vec::with_capacity(total);
    match kind {
        AttackType::Sniper => {
            for pos in 0..n {
                for payload in &sets[0] {
                    let mut values: Vec<Option<&str>> = vec![None; n];
                    values[pos] = Some(payload.as_str());
                    out.push(attack(template, &values));
                }
            }
        }
        AttackType::BatteringRam => {
            for payload in &sets[0] {
                out.push(attack(template, &vec![Some(payload.as_str()); n]));
            }
        }
        AttackType::Pitchfork => {
            for (i, _lead) in sets[0].iter().enumerate().take(total) {
                let values: Vec<Option<&str>> = sets.iter().map(|s| Some(s[i].as_str())).collect();
                out.push(attack(template, &values));
            }
        }
        AttackType::ClusterBomb => {
            let mut index = vec![0usize; n];
            for _ in 0..total {
                let values: Vec<Option<&str>> =
                    (0..n).map(|j| Some(sets[j][index[j]].as_str())).collect();
                out.push(attack(template, &values));
                // Odometer: position 1 varies fastest, as Burp iterates all of
                // set 1 for each payload of set 2 (and so on).
                for j in 0..n {
                    index[j] += 1;
                    if index[j] < lens[j] {
                        break;
                    }
                    index[j] = 0;
                }
            }
        }
    }
    Ok(out)
}

// ---------- positions (C-02) ----------

/// Remove every position marker, keeping the original text.
pub fn clear_markers(text: &str) -> String {
    text.chars().filter(|&c| c != MARK).collect()
}

/// Wrap the byte range `start..end` in a position (the editor's selection).
pub fn add_marker(text: &str, start: usize, end: usize) -> Result<String, IntruderError> {
    if start > end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return Err(IntruderError::SelectionOutsideRequest);
    }
    let selected = &text[start..end];
    if selected.contains(MARK) {
        return Err(IntruderError::SelectionHasMarker);
    }
    if text[..start].chars().filter(|&c| c == MARK).count() % 2 == 1 {
        return Err(IntruderError::SelectionInsidePosition);
    }
    Ok(format!(
        "{}{MARK}{selected}{MARK}{}",
        &text[..start],
        &text[end..]
    ))
}

fn mark_pairs(s: &str, sep: char) -> String {
    s.split(sep)
        .map(|piece| match piece.split_once('=') {
            Some((name, value)) => format!("{name}={MARK}{value}{MARK}"),
            None => piece.to_string(),
        })
        .collect::<Vec<_>>()
        .join(&sep.to_string())
}

fn split_eol(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, "\r\n")
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, "\n")
    } else {
        (line, "")
    }
}

/// Burp's "Auto §": mark the value of every query parameter, cookie, form body
/// parameter and JSON scalar. Existing markers are cleared first.
pub fn auto_mark(request: &str) -> String {
    let request = clear_markers(request);
    let split = request
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| request.find("\n\n").map(|i| i + 2))
        .unwrap_or(request.len());
    let (head, body) = request.split_at(split);
    let head_lower = head.to_ascii_lowercase();

    let mut out = String::new();
    for (i, line) in head.split_inclusive('\n').enumerate() {
        let (content, eol) = split_eol(line);
        if i == 0 {
            let mut parts = content.splitn(3, ' ');
            let (method, target, rest) = (parts.next(), parts.next(), parts.next());
            match (method, target, rest) {
                (Some(method), Some(target), Some(rest)) if target.contains('?') => {
                    let (path, query) = target.split_once('?').unwrap_or((target, ""));
                    out.push_str(&format!(
                        "{method} {path}?{} {rest}{eol}",
                        mark_pairs(query, '&')
                    ));
                }
                _ => out.push_str(line),
            }
        } else if content
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("cookie:"))
        {
            out.push_str(&format!(
                "{}{}{eol}",
                &content[..7],
                mark_pairs(&content[7..], ';')
            ));
        } else {
            out.push_str(line);
        }
    }

    let trimmed = body.trim_end_matches(['\r', '\n']);
    let tail = &body[trimmed.len()..];
    if head_lower.contains("application/x-www-form-urlencoded") {
        out.push_str(&mark_pairs(trimmed, '&'));
        out.push_str(tail);
    } else if head_lower.contains("json") {
        let re = regex::Regex::new(
            r#"("(?:[^"\\]|\\.)*"\s*:\s*)(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?|true|false|null))"#,
        )
        .expect("static pattern");
        let marked = re.replace_all(trimmed, |caps: &regex::Captures| match caps.get(2) {
            Some(text) => format!("{}\"{MARK}{}{MARK}\"", &caps[1], text.as_str()),
            None => format!("{}{MARK}{}{MARK}", &caps[1], &caps[3]),
        });
        out.push_str(&marked);
        out.push_str(tail);
    } else {
        out.push_str(body);
    }
    out
}

// ---------- payload sources (C-03) ----------

/// Hard cap on a generated set, so a brute forcer or an open-ended number range
/// cannot exhaust memory before the request limit ever sees it.
pub const MAX_PAYLOADS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberBase {
    Decimal,
    Hex,
}

impl NumberBase {
    fn render(self, magnitude: u64) -> String {
        match self {
            NumberBase::Decimal => magnitude.to_string(),
            NumberBase::Hex => format!("{magnitude:x}"),
        }
    }
}

/// Where a payload set comes from. `generate` is deterministic: the same source
/// always yields the same list, in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadSource {
    /// Payloads from a Montoya extension's generator (registered with
    /// `intruder().registerPayloadGeneratorProvider`): `payloads` are
    /// fetched from the extension when the attack starts.
    Extension {
        provider: String,
        payloads: Vec<String>,
    },
    /// The list as typed, one payload per entry.
    SimpleList { items: Vec<String> },
    /// Lines of a file, read when the set is generated (not when it is edited).
    RuntimeFile { path: String },
    /// An arithmetic run in base 10 or 16, zero-padded to `min_digits`.
    Numbers {
        from: i64,
        to: i64,
        step: i64,
        base: NumberBase,
        min_digits: usize,
        fraction_digits: usize,
    },
    /// Every combination over `charset`, shortest first, charset order preserved.
    BruteForcer {
        charset: String,
        min_len: usize,
        max_len: usize,
    },
    /// Unix timestamps rendered with a strftime subset, UTC only.
    Dates {
        from: u64,
        to: u64,
        step_secs: u64,
        format: String,
    },
    /// The base string repeated and truncated to each length in the range.
    CharacterBlocks {
        base: String,
        min_len: usize,
        max_len: usize,
    },
    /// Empty payloads (the request is sent unchanged `count` times).
    NullPayloads { count: usize },
    /// Each list item in every selected case form, in Burp's option order.
    CaseModification {
        items: Vec<String>,
        no_change: bool,
        lower: bool,
        upper: bool,
        propername: bool,
        proper_name: bool,
    },
    /// The base value with each character position in turn bumped by one.
    CharacterFrobber { base: String },
    /// Burp's custom iterator (burp.Zcce): up to eight positions, each a list
    /// of items written followed by that position's separator; position 1
    /// varies fastest. `lists` and `separators` hold eight entries each.
    CustomIterator {
        lists: Vec<Vec<String>>,
        separators: Vec<String>,
    },
    /// Each list item with every combination of the substitutions applied
    /// (burp.Zcco). `rules` are Burp's 16 one-character from/to slots;
    /// without `case_sensitive` both cases of each "from" match.
    CharacterSubstitution {
        items: Vec<String>,
        rules: Vec<(String, String)>,
        case_sensitive: bool,
    },
    /// Each payload is extracted from the previous response by Grep - Extract
    /// item `extract_index` (burp.Zccc); `initial` goes into the first request.
    /// The runner drives it: `generate` only knows the first payload.
    RecursiveGrep {
        initial: String,
        extract_index: usize,
        stop_on_duplicate: bool,
    },
    /// Each selected bit of each byte flipped in turn (burp.Zcc8). `base` None
    /// means the base value of the payload position; `hex` treats the base as
    /// ASCII hex, flipping bits of the decoded bytes.
    BitFlipper {
        base: Option<String>,
        hex: bool,
        mask: u8,
    },
    /// Usernames derived from "first last" / "first.last@domain" items
    /// (burp.Zccz); `max_per_item` 0 means no limit.
    UsernameGenerator {
        items: Vec<String>,
        max_per_item: usize,
    },
    /// Every distinct ciphertext block inserted at every block boundary
    /// (burp.Zccf). `base` None means the base value of the payload position.
    EcbBlockShuffler {
        base: Option<String>,
        hex: bool,
        block_size: usize,
        extra: Vec<String>,
    },
    /// The payload of another (1-based) position in the same request
    /// (burp.Zccn); only valid for Pitchfork and Cluster bomb.
    CopyOtherPayload { from_position: usize },
    /// Each list item with every `match_char` replaced by each illegal
    /// encoding of `replace_char` (burp.Zccv): overlong UTF-8 up to
    /// `max_bytes`, optional illegal continuation bytes and illegal hex digits,
    /// written as hex (with `%` prefixes by default).
    IllegalUnicode {
        items: Vec<String>,
        match_char: String,
        replace_char: String,
        max_bytes: u8,
        max_encodings: usize,
        illegal_utf8: bool,
        utf8_permute: bool,
        illegal_hex: bool,
        hex_permute: bool,
        percent_prefix: bool,
        lowercase: bool,
    },
}

/// burp.Zccv's static table: for each byte value, every two-character pair
/// over [0-9a-z] whose "hex" value (16 * hi + lo, mod 256) is that byte.
fn illegal_hex_pairs(byte: u8) -> Vec<[u8; 2]> {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    for (i, &hi) in DIGITS.iter().enumerate() {
        for (j, &lo) in DIGITS.iter().enumerate() {
            if ((i * 16 + j) & 255) as u8 == byte {
                out.push([hi, lo]);
            }
        }
    }
    out
}

/// The illegal encodings of byte `c` (burp.Zccv.ZM), in Burp's order and
/// deduplicated, capped at `max` (0 = no cap).
#[allow(clippy::too_many_arguments)]
fn illegal_unicode_encodings(
    c: u8,
    max_bytes: u8,
    illegal_utf8: bool,
    utf8_permute: bool,
    illegal_hex: bool,
    hex_permute: bool,
    percent: bool,
    lowercase: bool,
    max: usize,
) -> Vec<String> {
    // The byte itself, then overlong forms: lead byte, 0x80 fillers and a
    // last continuation byte carrying the low six bits.
    const LEADS: [u8; 7] = [0, 0, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC];
    let mut enc: Vec<Vec<u8>> = vec![vec![c]];
    for (n, &lead) in LEADS
        .iter()
        .enumerate()
        .take(max_bytes.min(6) as usize + 1)
        .skip(2)
    {
        let mut v = vec![lead];
        v.extend(std::iter::repeat_n(0x80, n - 2));
        v.push(0x80 ^ (c & 63));
        enc.push(v);
    }
    let alter = |b: u8, kind: usize| match kind {
        1 => b & 63,
        2 => (b & 63) ^ 64,
        3 => (b & 63) ^ 192,
        _ => b,
    };
    if illegal_utf8 {
        for k in 0..enc.len() {
            let e = enc[k].clone();
            if e.len() <= 1 {
                continue;
            }
            if utf8_permute {
                // Every continuation byte in each of its four top-bit forms,
                // the last byte varying fastest.
                let mut ctr = vec![0usize; e.len() - 1];
                while ctr[0] < 4 {
                    let mut v = e.clone();
                    for (i, &kind) in ctr.iter().enumerate() {
                        v[i + 1] = alter(v[i + 1], kind);
                    }
                    enc.push(v);
                    *ctr.last_mut().unwrap() += 1;
                    for i in (1..ctr.len()).rev() {
                        if ctr[i] > 3 {
                            ctr[i] = 0;
                            ctr[i - 1] += 1;
                        }
                    }
                }
            } else {
                for i in 1..e.len() {
                    for kind in 1..=3 {
                        let mut v = e.clone();
                        v[i] = alter(v[i], kind);
                        enc.push(v);
                    }
                }
            }
        }
    }
    let hex = |b: u8| {
        [
            b"0123456789abcdef"[(b >> 4) as usize],
            b"0123456789abcdef"[(b & 15) as usize],
        ]
    };
    let mut out: Vec<String> = Vec::new();
    let full = |out: &Vec<String>| max != 0 && out.len() >= max;
    let add = |out: &mut Vec<String>, mut bytes: Vec<u8>| {
        if !lowercase {
            bytes.make_ascii_uppercase();
        }
        let s = latin1_string(&bytes);
        if !out.contains(&s) {
            out.push(s);
        }
    };
    let write = |buf: &mut Vec<u8>, pair: [u8; 2]| {
        if percent {
            buf.push(b'%');
        }
        buf.extend_from_slice(&pair);
    };
    for e in &enc {
        if full(&out) {
            break;
        }
        if !illegal_hex {
            let mut buf = Vec::new();
            for &b in e {
                write(&mut buf, hex(b));
            }
            add(&mut out, buf);
        } else if hex_permute {
            let tables: Vec<Vec<[u8; 2]>> = e.iter().map(|&b| illegal_hex_pairs(b)).collect();
            let mut ctr = vec![0usize; e.len()];
            while ctr[0] < tables[0].len() && !full(&out) {
                let mut buf = Vec::new();
                for (i, t) in tables.iter().enumerate() {
                    write(&mut buf, t[ctr[i]]);
                }
                add(&mut out, buf);
                *ctr.last_mut().unwrap() += 1;
                for i in (1..ctr.len()).rev() {
                    if ctr[i] >= tables[i].len() {
                        ctr[i] = 0;
                        ctr[i - 1] += 1;
                    }
                }
            }
        } else {
            for i in 0..e.len() {
                for alt in illegal_hex_pairs(e[i]) {
                    if full(&out) {
                        break;
                    }
                    let mut buf = Vec::new();
                    for (j, &b) in e.iter().enumerate() {
                        write(&mut buf, if j == i { alt } else { hex(b) });
                    }
                    add(&mut out, buf);
                }
            }
        }
    }
    out
}

/// Burp's default character substitutions (burp.Zrvh constructor: the
/// strings "abegiostz" -> "483610572"), padded to its 16 slots.
pub fn default_substitutions() -> Vec<(String, String)> {
    let mut rules: Vec<(String, String)> = "abegiostz"
        .chars()
        .zip("483610572".chars())
        .map(|(f, t)| (f.to_string(), t.to_string()))
        .collect();
    rules.resize(16, (String::new(), String::new()));
    rules
}

/// The substitution table Burp builds in `Zrvh.ZR`: one entry per complete
/// one-character slot, or a lower-case and an upper-case entry when the match
/// is case-insensitive.
fn substitution_table(rules: &[(String, String)], case_sensitive: bool) -> Vec<(char, char)> {
    let mut table = Vec::new();
    for (from, to) in rules {
        let (mut f, mut t) = (from.chars(), to.chars());
        let (Some(a), None, Some(b), None) = (f.next(), f.next(), t.next(), t.next()) else {
            continue;
        };
        if case_sensitive {
            table.push((a, b));
        } else {
            table.push((a.to_ascii_lowercase(), b));
            table.push((a.to_ascii_uppercase(), b));
        }
    }
    table
}

/// How many characters of `item` the table can substitute (k: 2^k variants).
fn substitutable(item: &str, table: &[(char, char)]) -> u32 {
    item.chars()
        .filter(|c| table.iter().any(|(f, _)| f == c))
        .count() as u32
}

/// burp.Zcco.Zt: variant `i` substitutes the j-th substitutable character
/// when bit j of `i` is set, so variant 0 is the item unchanged. The first
/// matching table entry wins.
fn substitution_variants(item: &str, table: &[(char, char)], cap: usize) -> Vec<String> {
    let k = substitutable(item, table);
    let total = if k >= 63 { u64::MAX } else { 1u64 << k };
    let mut out = Vec::new();
    let mut i = 0u64;
    while i < total && out.len() < cap {
        let mut j = 0u32;
        let variant: String = item
            .chars()
            .map(|c| match table.iter().find(|(f, _)| *f == c) {
                None => c,
                Some(&(_, to)) => {
                    let on = j < 64 && (i >> j) & 1 == 1;
                    j += 1;
                    if on {
                        to
                    } else {
                        c
                    }
                }
            })
            .collect();
        out.push(variant);
        i += 1;
    }
    out
}

/// Custom iterator: every combination, position 1 fastest. Each position
/// writes its item (if its list has any) and then its separator. Burp's
/// odometer (burp.Zcce.ZOa) starts position 1 at -1, which skips the first
/// item of position 2 when position 1 is empty; WebProbe walks only the
/// non-empty lists so every combination appears exactly once.
fn custom_iterations(lists: &[Vec<String>], separators: &[String]) -> Vec<String> {
    let lists: Vec<Vec<&String>> = lists
        .iter()
        .map(|l| l.iter().filter(|s| !s.is_empty()).collect())
        .collect();
    let used: Vec<usize> = (0..lists.len()).filter(|&p| !lists[p].is_empty()).collect();
    if used.is_empty() {
        return Vec::new();
    }
    let slots = lists.len().max(separators.len());
    let mut index = vec![0usize; lists.len()];
    let mut out = Vec::new();
    loop {
        if out.len() >= MAX_PAYLOADS {
            return out;
        }
        let mut s = String::new();
        for (p, &idx) in index.iter().enumerate().take(slots) {
            if let Some(item) = lists.get(p).and_then(|l| l.get(idx)) {
                s.push_str(item);
            }
            if let Some(sep) = separators.get(p) {
                s.push_str(sep);
            }
        }
        out.push(s);
        let mut carry = true;
        for &p in &used {
            index[p] += 1;
            if index[p] < lists[p].len() {
                carry = false;
                break;
            }
            index[p] = 0;
        }
        if carry {
            return out;
        }
    }
}

/// Burp's byte view of a string (ISO-8859-1; wider characters become '?').
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| if (c as u32) < 256 { c as u8 } else { b'?' })
        .collect()
}

/// The inverse of `latin1_bytes`: one character per byte. Bytes above 0x7F
/// become U+0080..U+00FF, which the runner sends UTF-8 encoded.
fn latin1_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn hex_pair(bytes: &[u8], at: usize) -> Option<u8> {
    let s = std::str::from_utf8(bytes.get(at..at + 2)?).ok()?;
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

/// burp.Zcc8: byte position outer, selected bits inner (LSB first). In hex
/// mode positions are hex pairs; pairs that are not hex are skipped and the
/// flipped byte is written back as two lower-case hex digits.
fn bit_flips(base: &str, hex: bool, mask: u8) -> Vec<String> {
    let bytes = latin1_bytes(base);
    let positions = if hex { bytes.len() / 2 } else { bytes.len() };
    let mut out = Vec::new();
    for p in 0..positions {
        let decoded = if hex {
            match hex_pair(&bytes, 2 * p) {
                Some(v) => Some(v),
                None => continue,
            }
        } else {
            None
        };
        for bit in 0..8 {
            let b = 1u8 << bit;
            if mask & b == 0 {
                continue;
            }
            let mut v = bytes.clone();
            match decoded {
                Some(d) => {
                    let h = format!("{:02x}", d ^ b);
                    v[2 * p] = h.as_bytes()[0];
                    v[2 * p + 1] = h.as_bytes()[1];
                }
                None => v[p] ^= b,
            }
            out.push(latin1_string(&v));
        }
    }
    out
}

/// One parsed username-generator item (burp.Zccz.ZZU): the first run of
/// letters/digits, then every letter/digit up to '@', then the '@...' suffix.
fn parse_name(item: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let b = item.as_bytes();
    let mut i = 0;
    let mut first = Vec::new();
    while i < b.len() {
        if b[i].is_ascii_alphanumeric() {
            first.push(b[i]);
        } else if !first.is_empty() {
            break;
        }
        i += 1;
    }
    let mut last = Vec::new();
    while i < b.len() {
        if b[i].is_ascii_alphanumeric() {
            last.push(b[i]);
        } else if b[i] == b'@' {
            break;
        }
        i += 1;
    }
    let suffix = b[i.min(b.len())..].to_vec();
    (first, last, suffix)
}

/// burp.Zccz.ZZZ, transcribed: advance the six-counter scheme state
/// [dot, swap, abbreviate, abbreviated side, k4, k5]. False when the item's
/// schemes are exhausted.
fn username_advance(s: &mut [i64; 6], f: i64, l: i64) -> bool {
    let empty = if s[2] == 0 {
        f == 0 || l == 0
    } else if s[3] == 0 {
        s[5] - f == 0 || s[4] == 0
    } else {
        s[4] == 0 || s[5] - l == 0
    };
    s[0] += 1;
    if s[0] == 1 && !empty {
        return true;
    }
    s[0] = 0;
    s[1] += 1;
    if s[1] == 1 && !empty {
        return true;
    }
    s[1] = 0;
    if s[2] == 0 {
        s[2] = 1;
        if !empty {
            return true;
        }
    }
    s[3] += 1;
    if s[3] != 1 || s[4] + s[5] >= f || s[5] > l || (s[4] <= 0 && l - s[5] <= 0) {
        s[4] += 1;
        if s[4] + s[5] < l && s[5] <= f {
            s[3] = 0;
            true
        } else if s[4] + s[5] < f && s[5] <= l {
            s[3] = 1;
            true
        } else {
            s[4] = 0;
            s[5] += 1;
            if s[5] < f && s[5] <= l {
                s[3] = 0;
                true
            } else if s[5] < l && s[5] <= f {
                s[3] = 1;
                true
            } else {
                false
            }
        }
    } else {
        true
    }
}

/// burp.Zccz.Zt's emit step for one state.
fn username_emit(s: &[i64; 6], first: &[u8], last: &[u8], suffix: &[u8]) -> String {
    let (f, l) = (first.len() as i64, last.len() as i64);
    let (nf, nl) = if s[2] == 1 {
        if s[3] == 0 {
            (f - s[5], s[4])
        } else {
            (s[4], l - s[5])
        }
    } else {
        (f, l)
    };
    let take = |v: &[u8], n: i64| v[..(n.clamp(0, v.len() as i64) as usize)].to_vec();
    let (a, b) = if s[1] == 0 {
        (take(first, nf), take(last, nl))
    } else {
        (take(last, nl), take(first, nf))
    };
    let mut out = a;
    if s[0] == 1 {
        out.push(b'.');
    }
    out.extend(b);
    out.extend_from_slice(suffix);
    String::from_utf8_lossy(&out).into_owned()
}

fn usernames(items: &[String], max_per_item: usize) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        let (first, last, suffix) = parse_name(item);
        if first.is_empty() && last.is_empty() {
            continue;
        }
        let mut state = [0i64; 6];
        let mut made = 0usize;
        loop {
            if (max_per_item > 0 && made >= max_per_item) || out.len() >= MAX_PAYLOADS {
                break;
            }
            if made > 0 && !username_advance(&mut state, first.len() as i64, last.len() as i64) {
                break;
            }
            out.push(username_emit(&state, &first, &last, &suffix));
            made += 1;
        }
    }
    out
}

/// burp.Zccf: the sorted distinct blocks of the base and the extra strings,
/// each inserted (not substituted) at every block boundary 0, bs, 2bs ... up
/// to the end of the base; boundary outer, block inner. In hex mode a block
/// is `2 * block_size` hex characters.
fn ecb_shuffles(base: &str, hex: bool, block_size: usize, extra: &[String]) -> Vec<String> {
    let bs = if hex { block_size * 2 } else { block_size };
    if bs == 0 {
        return Vec::new();
    }
    let mut blocks = std::collections::BTreeSet::new();
    for s in std::iter::once(base).chain(extra.iter().map(String::as_str)) {
        let chars: Vec<char> = s.chars().collect();
        for chunk in chars.chunks_exact(bs) {
            blocks.insert(chunk.iter().collect::<String>());
        }
    }
    let chars: Vec<char> = base.chars().collect();
    let mut out = Vec::new();
    let mut offset = 0;
    while offset <= chars.len() {
        let (head, tail): (String, String) = (
            chars[..offset].iter().collect(),
            chars[offset..].iter().collect(),
        );
        for block in &blocks {
            if out.len() >= MAX_PAYLOADS {
                return out;
            }
            out.push(format!("{head}{block}{tail}"));
        }
        offset += bs;
    }
    out
}

/// Burp's case-modification forms (documented: "To Propername" lowers the
/// rest of the word, "To ProperName" keeps it).
fn case_forms(
    item: &str,
    no_change: bool,
    lower: bool,
    upper: bool,
    propername: bool,
    proper_name: bool,
) -> Vec<String> {
    let cap = |rest: String| {
        let mut c = item.chars();
        match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + &rest,
            None => String::new(),
        }
    };
    let tail: String = item.chars().skip(1).collect();
    let mut out: Vec<String> = Vec::new();
    let mut push = |v: String| {
        if !out.contains(&v) {
            out.push(v);
        }
    };
    if no_change {
        push(item.to_string());
    }
    if lower {
        push(item.to_lowercase());
    }
    if upper {
        push(item.to_uppercase());
    }
    if propername {
        push(cap(tail.to_lowercase()));
    }
    if proper_name {
        push(cap(tail.clone()));
    }
    out
}

impl PayloadSource {
    /// Burp's payload-type dropdown entries that WebProbe generates, in
    /// Burp's order (enum burp.Zg3a), each with its default configuration.
    pub fn defaults() -> Vec<PayloadSource> {
        vec![
            PayloadSource::SimpleList { items: Vec::new() },
            PayloadSource::RuntimeFile {
                path: String::new(),
            },
            PayloadSource::CustomIterator {
                lists: vec![Vec::new(); 8],
                separators: vec![String::new(); 8],
            },
            // Zrvh: abegiostz -> 483610572, "Case sensitive match" unticked.
            PayloadSource::CharacterSubstitution {
                items: Vec::new(),
                rules: default_substitutions(),
                case_sensitive: false,
            },
            PayloadSource::CaseModification {
                items: Vec::new(),
                no_change: true,
                lower: true,
                upper: true,
                propername: true,
                proper_name: true,
            },
            // burp.Zb: empty initial payload, stop-on-duplicate off, item 0.
            PayloadSource::RecursiveGrep {
                initial: String::new(),
                extract_index: 0,
                stop_on_duplicate: false,
            },
            // burp.Zrv8: match '*', encode '/', 2 bytes, stop at 1000, % prefix
            // and lower case on, the illegal UTF-8 / hex options off.
            PayloadSource::IllegalUnicode {
                items: Vec::new(),
                match_char: "*".into(),
                replace_char: "/".into(),
                max_bytes: 2,
                max_encodings: 1000,
                illegal_utf8: false,
                utf8_permute: false,
                illegal_hex: false,
                hex_permute: false,
                percent_prefix: true,
                lowercase: true,
            },
            PayloadSource::CharacterBlocks {
                base: "A".into(),
                min_len: 10,
                max_len: 100,
            },
            PayloadSource::Numbers {
                from: 1,
                to: 10,
                step: 1,
                base: NumberBase::Decimal,
                min_digits: 1,
                fraction_digits: 0,
            },
            PayloadSource::Dates {
                from: 1_700_000_000,
                to: 1_700_000_000 + 6 * 86_400,
                step_secs: 86_400,
                format: "%Y-%m-%d".into(),
            },
            PayloadSource::BruteForcer {
                charset: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
                min_len: 4,
                max_len: 4,
            },
            PayloadSource::NullPayloads { count: 10 },
            PayloadSource::CharacterFrobber {
                base: String::new(),
            },
            // burp.Zxnb: base value of the position, literal, all 8 bits.
            PayloadSource::BitFlipper {
                base: None,
                hex: false,
                mask: 0xFF,
            },
            // burp.Zrv6: "Maximum payloads per item" 50.
            PayloadSource::UsernameGenerator {
                items: Vec::new(),
                max_per_item: 50,
            },
            // burp.Zhcf: ASCII hex, block size 8, base value of the position.
            PayloadSource::EcbBlockShuffler {
                base: None,
                hex: true,
                block_size: 8,
                extra: Vec::new(),
            },
            // Burp's list: "Extension-generated" sits before "Copy other payload".
            PayloadSource::Extension {
                provider: String::new(),
                payloads: Vec::new(),
            },
            PayloadSource::CopyOtherPayload { from_position: 1 },
        ]
    }

    /// The encodings of `replace_char` (burp.Zccv.ZH), for the panel's count.
    pub fn illegal_encodings(&self) -> Vec<String> {
        let PayloadSource::IllegalUnicode {
            replace_char,
            max_bytes,
            max_encodings,
            illegal_utf8,
            utf8_permute,
            illegal_hex,
            hex_permute,
            percent_prefix,
            lowercase,
            ..
        } = self
        else {
            return Vec::new();
        };
        let Some(&c) = latin1_bytes(replace_char).first() else {
            return Vec::new();
        };
        illegal_unicode_encodings(
            c,
            *max_bytes,
            *illegal_utf8,
            *utf8_permute,
            *illegal_hex,
            *hex_permute,
            *percent_prefix,
            *lowercase,
            *max_encodings,
        )
    }

    /// burp.Zccv.Zt: every item containing the match character, with each
    /// occurrence replaced by each encoding in turn (at most `max_encodings`
    /// per item); items without the match character are skipped.
    fn illegal_unicode(&self) -> Vec<String> {
        let PayloadSource::IllegalUnicode {
            items,
            match_char,
            max_encodings,
            ..
        } = self
        else {
            return Vec::new();
        };
        let Some(m) = match_char.chars().next() else {
            return Vec::new();
        };
        let encodings = self.illegal_encodings();
        let mut out = Vec::new();
        for item in items.iter().filter(|i| i.contains(m)) {
            for e in encodings.iter().take(if *max_encodings == 0 {
                usize::MAX
            } else {
                *max_encodings
            }) {
                if out.len() >= MAX_PAYLOADS {
                    return out;
                }
                out.push(item.replace(m, e));
            }
        }
        out
    }

    /// True for types whose payloads come from the base value of the payload
    /// position when no specific string is set.
    pub fn uses_position_base(&self) -> bool {
        matches!(
            self,
            PayloadSource::BitFlipper { base: None, .. }
                | PayloadSource::EcbBlockShuffler { base: None, .. }
        )
    }

    /// `generate` with `base` standing in for "base value of payload position".
    pub fn generate_for_base(&self, position_base: &str) -> Vec<String> {
        match self {
            PayloadSource::BitFlipper {
                base: None,
                hex,
                mask,
            } => bit_flips(position_base, *hex, *mask),
            PayloadSource::EcbBlockShuffler {
                base: None,
                hex,
                block_size,
                extra,
            } => ecb_shuffles(position_base, *hex, *block_size, extra),
            other => other.generate(),
        }
    }

    /// Display strings for the payload-type dropdown, as in Burp Intruder.
    pub fn label(&self) -> &'static str {
        match self {
            PayloadSource::SimpleList { .. } => "Simple list",
            PayloadSource::RuntimeFile { .. } => "Runtime file",
            PayloadSource::Numbers { .. } => "Numbers",
            PayloadSource::BruteForcer { .. } => "Brute forcer",
            PayloadSource::Dates { .. } => "Dates",
            PayloadSource::CharacterBlocks { .. } => "Character blocks",
            PayloadSource::NullPayloads { .. } => "Null payloads",
            PayloadSource::Extension { .. } => "Extension-generated",
            PayloadSource::CaseModification { .. } => "Case modification",
            PayloadSource::CharacterFrobber { .. } => "Character frobber",
            PayloadSource::CustomIterator { .. } => "Custom iterator",
            PayloadSource::CharacterSubstitution { .. } => "Character substitution",
            PayloadSource::RecursiveGrep { .. } => "Recursive grep",
            PayloadSource::BitFlipper { .. } => "Bit flipper",
            PayloadSource::UsernameGenerator { .. } => "Username generator",
            PayloadSource::EcbBlockShuffler { .. } => "ECB block shuffler",
            PayloadSource::CopyOtherPayload { .. } => "Copy other payload",
            PayloadSource::IllegalUnicode { .. } => "Illegal Unicode",
        }
    }

    /// The payloads this source produces. Unreadable files and empty alphabets
    /// yield an empty set; nothing here panics or blocks.
    pub fn generate(&self) -> Vec<String> {
        match self {
            PayloadSource::SimpleList { items } => items.clone(),
            PayloadSource::RuntimeFile { path } => match crate::util::read_text_file_capped(
                std::path::Path::new(path),
                crate::util::MAX_TEXT_FILE_BYTES,
            ) {
                Ok(text) => read_payload_lines(&text),
                Err(_) => Vec::new(),
            },
            PayloadSource::Numbers {
                from,
                to,
                step,
                base,
                min_digits,
                fraction_digits,
            } => {
                let step = if *step == 0 { 1 } else { *step };
                number_run(*from, *to, step)
                    .map(|v| format_number(v, *base, *min_digits, *fraction_digits))
                    .collect()
            }
            PayloadSource::BruteForcer {
                charset,
                min_len,
                max_len,
            } => {
                let alphabet: Vec<char> = charset.chars().collect();
                if alphabet.is_empty() || min_len > max_len {
                    return Vec::new();
                }
                let mut out = Vec::new();
                for len in *min_len..=*max_len {
                    let mut index = vec![0usize; len];
                    loop {
                        if out.len() >= MAX_PAYLOADS {
                            return out;
                        }
                        out.push(index.iter().map(|&i| alphabet[i]).collect());
                        // Odometer: the last character varies fastest.
                        let mut j = len;
                        let mut carry = true;
                        while j > 0 && carry {
                            j -= 1;
                            index[j] += 1;
                            if index[j] < alphabet.len() {
                                carry = false;
                            } else {
                                index[j] = 0;
                            }
                        }
                        if carry {
                            break;
                        }
                    }
                }
                out
            }
            PayloadSource::Dates {
                from,
                to,
                step_secs,
                format,
            } => {
                let step = if *step_secs == 0 { 1 } else { *step_secs };
                date_run(*from, *to, step)
                    .map(|t| format_date(t, format))
                    .collect()
            }
            PayloadSource::CharacterBlocks {
                base,
                min_len,
                max_len,
            } => {
                let chars: Vec<char> = base.chars().collect();
                if chars.is_empty() || min_len > max_len {
                    return Vec::new();
                }
                (*min_len..=*max_len)
                    .take(MAX_PAYLOADS)
                    .map(|len| chars.iter().copied().cycle().take(len).collect())
                    .collect()
            }
            PayloadSource::NullPayloads { count } => {
                vec![String::new(); (*count).min(MAX_PAYLOADS)]
            }
            PayloadSource::Extension { payloads, .. } => {
                payloads.iter().take(MAX_PAYLOADS).cloned().collect()
            }
            PayloadSource::CaseModification {
                items,
                no_change,
                lower,
                upper,
                propername,
                proper_name,
            } => items
                .iter()
                .filter(|i| !i.is_empty())
                .flat_map(|i| case_forms(i, *no_change, *lower, *upper, *propername, *proper_name))
                .take(MAX_PAYLOADS)
                .collect(),
            PayloadSource::CharacterFrobber { base } => {
                let chars: Vec<char> = base.chars().collect();
                (0..chars.len())
                    .map(|i| {
                        let mut v = chars.clone();
                        v[i] = char::from_u32(v[i] as u32 + 1).unwrap_or(v[i]);
                        v.into_iter().collect()
                    })
                    .collect()
            }
            PayloadSource::CustomIterator { lists, separators } => {
                custom_iterations(lists, separators)
            }
            PayloadSource::CharacterSubstitution {
                items,
                rules,
                case_sensitive,
            } => {
                let table = substitution_table(rules, *case_sensitive);
                let mut out = Vec::new();
                for item in items.iter().filter(|i| !i.is_empty()) {
                    let room = MAX_PAYLOADS - out.len();
                    if room == 0 {
                        break;
                    }
                    out.extend(substitution_variants(item, &table, room));
                }
                out
            }
            PayloadSource::RecursiveGrep { initial, .. } => vec![initial.clone()],
            PayloadSource::BitFlipper { base, hex, mask } => {
                bit_flips(base.as_deref().unwrap_or(""), *hex, *mask)
            }
            PayloadSource::UsernameGenerator {
                items,
                max_per_item,
            } => {
                let items: Vec<String> = items
                    .iter()
                    .filter(|i| !i.trim().is_empty())
                    .cloned()
                    .collect();
                usernames(&items, *max_per_item)
            }
            PayloadSource::EcbBlockShuffler {
                base,
                hex,
                block_size,
                extra,
            } => {
                let extra: Vec<String> = extra.iter().filter(|e| !e.is_empty()).cloned().collect();
                ecb_shuffles(base.as_deref().unwrap_or(""), *hex, *block_size, &extra)
            }
            // A placeholder: the value is copied from another position when
            // the request matrix is built (`SetSpec::Copy`).
            PayloadSource::CopyOtherPayload { .. } => vec![String::new()],
            PayloadSource::IllegalUnicode { .. } => self.illegal_unicode(),
        }
    }

    /// How many payloads `generate` would return. Cheap except for `RuntimeFile`,
    /// which has to read the file to count its lines.
    pub fn len(&self) -> usize {
        match self {
            PayloadSource::SimpleList { items } => items.len(),
            PayloadSource::RuntimeFile { path } => crate::util::read_text_file_capped(
                std::path::Path::new(path),
                crate::util::MAX_TEXT_FILE_BYTES,
            )
            .map(|text| read_payload_lines(&text).len())
            .unwrap_or(0),
            PayloadSource::Numbers { from, to, step, .. } => {
                number_run(*from, *to, if *step == 0 { 1 } else { *step }).count()
            }
            PayloadSource::BruteForcer {
                charset,
                min_len,
                max_len,
            } => {
                let n = charset.chars().count();
                if n == 0 || min_len > max_len {
                    return 0;
                }
                let mut total = 0usize;
                for len in *min_len..=*max_len {
                    total = total
                        .saturating_add(n.saturating_pow(len as u32))
                        .min(MAX_PAYLOADS);
                }
                total
            }
            PayloadSource::Dates {
                from,
                to,
                step_secs,
                ..
            } => date_run(*from, *to, if *step_secs == 0 { 1 } else { *step_secs }).count(),
            PayloadSource::CharacterBlocks {
                base,
                min_len,
                max_len,
            } => {
                if base.is_empty() || min_len > max_len {
                    0
                } else {
                    (max_len - min_len + 1).min(MAX_PAYLOADS)
                }
            }
            PayloadSource::NullPayloads { count } => (*count).min(MAX_PAYLOADS),
            PayloadSource::Extension { payloads, .. } => payloads.len().min(MAX_PAYLOADS),
            PayloadSource::CaseModification { .. } | PayloadSource::CharacterFrobber { .. } => {
                self.generate().len()
            }
            PayloadSource::CustomIterator { lists, .. } => {
                let mut total = 1usize;
                let mut any = false;
                for l in lists {
                    let n = l.iter().filter(|s| !s.is_empty()).count();
                    if n > 0 {
                        any = true;
                        total = total.saturating_mul(n);
                    }
                }
                if any {
                    total.min(MAX_PAYLOADS)
                } else {
                    0
                }
            }
            PayloadSource::CharacterSubstitution {
                items,
                rules,
                case_sensitive,
            } => {
                let table = substitution_table(rules, *case_sensitive);
                items
                    .iter()
                    .filter(|i| !i.is_empty())
                    .map(|i| {
                        let k = substitutable(i, &table);
                        if k >= 63 {
                            usize::MAX
                        } else {
                            1usize.checked_shl(k).unwrap_or(usize::MAX)
                        }
                    })
                    .fold(0usize, |a, n| a.saturating_add(n))
                    .min(MAX_PAYLOADS)
            }
            // Unknown until the attack runs: one per response.
            PayloadSource::RecursiveGrep { .. } => 1,
            PayloadSource::BitFlipper { base, hex, mask } => {
                let n = latin1_bytes(base.as_deref().unwrap_or("")).len();
                (if *hex { n / 2 } else { n }) * mask.count_ones() as usize
            }
            PayloadSource::UsernameGenerator { .. } => self.generate().len(),
            PayloadSource::EcbBlockShuffler { .. } => self.generate().len(),
            PayloadSource::CopyOtherPayload { .. } => 1,
            PayloadSource::IllegalUnicode { .. } => self.generate().len(),
        }
    }

    /// Whether `generate` would return no payloads.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Burp's per-type validation before an attack starts (the `Zir2`
    /// messages of Zeu8, Zi17, Zsza, Zxfq). `position` is this set's 0-based
    /// index; `sets` the number of payload sets the attack uses.
    pub fn validate(
        &self,
        kind: AttackType,
        position: usize,
        sources: &[PayloadSource],
    ) -> Result<(), IntruderError> {
        match self {
            PayloadSource::Extension { provider, .. } if provider.is_empty() => {
                Err(IntruderError::NoExtensionGenerator)
            }
            PayloadSource::BitFlipper { base, mask, hex } => {
                if kind == AttackType::BatteringRam && base.is_none() {
                    return Err(IntruderError::BitFlipperBaseUnsupported);
                }
                if *mask == 0 {
                    return Err(IntruderError::NoBitsSelected);
                }
                if let Some(b) = base {
                    let n = latin1_bytes(b).len();
                    if (if *hex { n / 2 } else { n }) == 0 {
                        return Err(IntruderError::InvalidBaseString);
                    }
                    if *hex && !b.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(IntruderError::NonHexBase);
                    }
                }
                Ok(())
            }
            PayloadSource::EcbBlockShuffler {
                base, block_size, ..
            } => {
                if *block_size == 0 {
                    return Err(IntruderError::InvalidBlockSize);
                }
                if base.as_deref() == Some("") {
                    return Err(IntruderError::InvalidBase);
                }
                if kind == AttackType::BatteringRam {
                    return Err(IntruderError::BatteringRamUnsupported);
                }
                Ok(())
            }
            PayloadSource::UsernameGenerator { items, .. }
                if items.iter().all(|i| i.trim().is_empty()) =>
            {
                Err(IntruderError::NoListItems)
            }
            PayloadSource::CopyOtherPayload { from_position } => {
                if !matches!(kind, AttackType::Pitchfork | AttackType::ClusterBomb) {
                    return Err(IntruderError::CopyPayloadWrongAttack);
                }
                if *from_position < 1 || *from_position > sources.len() {
                    return Err(IntruderError::CopyPayloadInvalidPosition);
                }
                if from_position - 1 == position {
                    return Err(IntruderError::CopyPayloadSamePosition);
                }
                if matches!(
                    sources[from_position - 1],
                    PayloadSource::CopyOtherPayload { .. }
                ) {
                    return Err(IntruderError::CopyPayloadDependent);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

// ---------- attack plan: sets resolved against the template ----------

/// One payload set as the request matrix consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetSpec {
    /// The same list for whichever position the set feeds.
    List(Vec<String>),
    /// Sniper with a base-value generator: one list per position, generated
    /// from that position's base value (Burp re-runs the generator).
    PerPosition(Vec<Vec<String>>),
    /// Copy other payload: the value of position `.0` (0-based).
    Copy(usize),
    /// Recursive grep: driven by responses (see `RecursiveWalk`).
    Recursive {
        initial: String,
        extract_index: usize,
        stop_on_duplicate: bool,
    },
}

/// Turn the payload sources into the sets the attack consumes, applying
/// Burp's per-type validation. `sources` is one per payload set; only the
/// first `kind.sets_needed(positions)` are used.
pub fn resolve_specs(
    template: &Template,
    kind: AttackType,
    sources: &[PayloadSource],
) -> Result<Vec<SetSpec>, String> {
    let n = template.positions();
    let needed = kind.sets_needed(n).min(sources.len());
    let used = &sources[..needed];
    let mut out = Vec::with_capacity(needed);
    for (i, source) in used.iter().enumerate() {
        source.validate(kind, i, used)?;
        out.push(match source {
            PayloadSource::CopyOtherPayload { from_position } => SetSpec::Copy(from_position - 1),
            PayloadSource::RecursiveGrep {
                initial,
                extract_index,
                stop_on_duplicate,
            } => SetSpec::Recursive {
                initial: initial.clone(),
                extract_index: *extract_index,
                stop_on_duplicate: *stop_on_duplicate,
            },
            s if s.uses_position_base() => match kind {
                AttackType::Sniper => SetSpec::PerPosition(
                    template
                        .position_values()
                        .iter()
                        .map(|b| s.generate_for_base(b))
                        .collect(),
                ),
                _ => SetSpec::List(
                    s.generate_for_base(
                        template
                            .position_values()
                            .get(i)
                            .map(String::as_str)
                            .unwrap_or(""),
                    ),
                ),
            },
            s => SetSpec::List(s.generate()),
        });
    }
    if out
        .iter()
        .filter(|s| matches!(s, SetSpec::Recursive { .. }))
        .count()
        > 1
    {
        return Err("Only one payload set can use recursive grep.".into());
    }
    if kind == AttackType::ClusterBomb && out.iter().any(|s| matches!(s, SetSpec::Recursive { .. }))
    {
        return Err(
            "Recursive grep payloads need a Sniper, Battering ram or Pitchfork attack.".into(),
        );
    }
    Ok(out)
}

fn spec_len(spec: &SetSpec, position: usize) -> Option<usize> {
    match spec {
        SetSpec::List(l) => Some(l.len()),
        SetSpec::PerPosition(v) => v.get(position).map(Vec::len),
        SetSpec::Copy(_) | SetSpec::Recursive { .. } => None,
    }
}

/// The request count for resolved sets: `None` when it overflows or depends
/// on responses (recursive grep). Copy sets neither multiply a Cluster bomb
/// nor cap a Pitchfork.
pub fn count_specs(kind: AttackType, positions: usize, specs: &[SetSpec]) -> Option<usize> {
    if specs.iter().any(|s| matches!(s, SetSpec::Recursive { .. })) {
        return None;
    }
    match kind {
        AttackType::Sniper => match specs.first()? {
            SetSpec::PerPosition(v) => v
                .iter()
                .take(positions)
                .try_fold(0usize, |a, l| a.checked_add(l.len())),
            other => positions.checked_mul(spec_len(other, 0)?),
        },
        AttackType::BatteringRam => spec_len(specs.first()?, 0),
        AttackType::Pitchfork => specs
            .iter()
            .take(positions)
            .enumerate()
            .filter_map(|(i, s)| spec_len(s, i))
            .min(),
        AttackType::ClusterBomb => specs
            .iter()
            .take(positions)
            .enumerate()
            .filter_map(|(i, s)| spec_len(s, i))
            .try_fold(1usize, |a, n| a.checked_mul(n)),
    }
}

/// Fill copy positions from their source position.
fn apply_copies(values: &mut [Option<&str>], specs: &[SetSpec]) {
    for (i, spec) in specs.iter().enumerate() {
        if let SetSpec::Copy(src) = spec {
            if i < values.len() {
                values[i] = values.get(*src).copied().flatten();
            }
        }
    }
}

/// `requests` over resolved sets. Recursive sets are rejected here: they are
/// walked by `RecursiveWalk` instead.
pub fn requests_specs(
    template: &Template,
    kind: AttackType,
    specs: &[SetSpec],
    limit: usize,
) -> Result<Vec<Attack>, String> {
    let n = template.positions();
    if n == 0 {
        return Err("no payload positions: mark at least one with §".into());
    }
    let needed = kind.sets_needed(n);
    if specs.len() < needed {
        return Err(format!(
            "{} needs {needed} payload set(s) for {n} position(s), got {}",
            kind.label(),
            specs.len()
        ));
    }
    let specs = &specs[..needed];
    if specs.iter().any(|s| matches!(s, SetSpec::Recursive { .. })) {
        return Err("recursive grep sets are generated while the attack runs".into());
    }
    for (i, s) in specs.iter().enumerate() {
        let empty = match s {
            SetSpec::List(l) => l.is_empty(),
            SetSpec::PerPosition(v) => v.iter().all(Vec::is_empty),
            _ => false,
        };
        if empty {
            return Err(format!("payload set {} is empty", i + 1));
        }
    }
    let total = count_specs(kind, n, specs)
        .ok_or_else(|| "the attack is too large to count".to_string())?;
    if total > limit {
        return Err(format!(
            "{} would send {total} requests, over the limit of {limit}",
            kind.label()
        ));
    }
    let mut out = Vec::with_capacity(total);
    match kind {
        AttackType::Sniper => {
            for pos in 0..n {
                let list: &[String] = match &specs[0] {
                    SetSpec::PerPosition(v) => v.get(pos).map(Vec::as_slice).unwrap_or(&[]),
                    SetSpec::List(l) => l,
                    _ => &[],
                };
                for payload in list {
                    let mut values: Vec<Option<&str>> = vec![None; n];
                    values[pos] = Some(payload.as_str());
                    out.push(attack(template, &values));
                }
            }
        }
        AttackType::BatteringRam => {
            if let SetSpec::List(l) = &specs[0] {
                for payload in l {
                    out.push(attack(template, &vec![Some(payload.as_str()); n]));
                }
            }
        }
        AttackType::Pitchfork => {
            for i in 0..total {
                let mut values: Vec<Option<&str>> = (0..n)
                    .map(|j| match &specs[j] {
                        SetSpec::List(l) => Some(l[i].as_str()),
                        _ => None,
                    })
                    .collect();
                apply_copies(&mut values, specs);
                out.push(attack(template, &values));
            }
        }
        AttackType::ClusterBomb => {
            let lens: Vec<usize> = (0..n)
                .map(|j| spec_len(&specs[j], j).unwrap_or(1))
                .collect();
            let mut index = vec![0usize; n];
            for _ in 0..total {
                let mut values: Vec<Option<&str>> = (0..n)
                    .map(|j| match &specs[j] {
                        SetSpec::List(l) => Some(l[index[j]].as_str()),
                        _ => None,
                    })
                    .collect();
                apply_copies(&mut values, specs);
                out.push(attack(template, &values));
                // Position 1 fastest (Burp's cluster bomb order).
                for j in 0..n {
                    index[j] += 1;
                    if index[j] < lens[j] {
                        break;
                    }
                    index[j] = 0;
                }
            }
        }
    }
    Ok(out)
}

/// Recursive grep (burp.Zccc / burp.Zwi0): the attack is walked one request
/// at a time, each payload of the recursive set being the Grep - Extract
/// value of the previous response. Sniper walks each position in turn
/// (restarting from the initial payload), Battering ram puts the value in
/// every position, Pitchfork pairs it with the other sets in lock step.
#[derive(Debug, Clone)]
pub struct RecursiveWalk {
    kind: AttackType,
    specs: Vec<SetSpec>,
    rec: usize,
    initial: String,
    extract_index: usize,
    stop_on_duplicate: bool,
    position: usize,
    step: usize,
    next: Option<String>,
    previous: Option<String>,
}

impl RecursiveWalk {
    /// `None` when the specs contain no recursive set.
    pub fn new(kind: AttackType, specs: &[SetSpec]) -> Option<Self> {
        let rec = specs
            .iter()
            .position(|s| matches!(s, SetSpec::Recursive { .. }))?;
        let SetSpec::Recursive {
            initial,
            extract_index,
            stop_on_duplicate,
        } = specs[rec].clone()
        else {
            return None;
        };
        Some(Self {
            kind,
            specs: specs.to_vec(),
            rec,
            next: Some(initial.clone()),
            initial,
            extract_index,
            stop_on_duplicate,
            position: 0,
            step: 0,
            previous: None,
        })
    }

    /// The next request, or `None` when the attack is over.
    pub fn next_attack(&mut self, template: &Template) -> Option<Attack> {
        let n = template.positions();
        if n == 0 {
            return None;
        }
        loop {
            let current = self.next.clone();
            let stop = match &current {
                None => true,
                Some(c) => self.stop_on_duplicate && self.previous.as_ref() == Some(c),
            };
            if stop {
                // Sniper moves on to the next position and restarts the walk.
                if self.kind == AttackType::Sniper && self.position + 1 < n {
                    self.position += 1;
                    self.next = Some(self.initial.clone());
                    self.previous = None;
                    continue;
                }
                return None;
            }
            let payload = current?;
            let mut values: Vec<Option<&str>> = vec![None; n];
            match self.kind {
                AttackType::Sniper => values[self.position] = Some(payload.as_str()),
                AttackType::BatteringRam => {
                    values.iter_mut().for_each(|v| *v = Some(payload.as_str()))
                }
                _ => {
                    for (j, spec) in self.specs.iter().enumerate().take(n) {
                        values[j] = match spec {
                            SetSpec::List(l) => Some(l.get(self.step)?.as_str()),
                            SetSpec::Recursive { .. } if j == self.rec => Some(payload.as_str()),
                            _ => None,
                        };
                    }
                    apply_copies(&mut values, &self.specs);
                }
            }
            let out = attack(template, &values);
            self.previous = Some(payload.clone());
            self.next = None;
            self.step += 1;
            return Some(out);
        }
    }

    /// Feed the Grep - Extract results of the response to the last request.
    /// A missing item or no match ends the walk (Burp's `Zwi0.Zb` stores null).
    pub fn feed(&mut self, extracts: &[Option<String>]) {
        self.next = extracts.get(self.extract_index).cloned().flatten();
    }
}

/// `generate` for every source, in order — the payload sets an attack consumes.
pub fn resolve_sets(sources: &[PayloadSource]) -> Vec<Vec<String>> {
    sources.iter().map(PayloadSource::generate).collect()
}

/// Payload lines: trailing CR stripped, empty lines dropped.
fn read_payload_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .take(MAX_PAYLOADS)
        .map(str::to_string)
        .collect()
}

/// The numbers of a run, capped at `MAX_PAYLOADS`; an empty or inverted range
/// yields nothing. Iterates without materialising, so `len` stays cheap.
fn number_run(from: i64, to: i64, step: i64) -> impl Iterator<Item = i64> {
    let step = step.abs();
    let mut current = from;
    std::iter::from_fn(move || {
        if (step > 0 && current > to) || (step == 0) {
            return None;
        }
        let value = current;
        current = current.saturating_add(step);
        Some(value)
    })
    .take(MAX_PAYLOADS)
}

fn format_number(
    value: i64,
    base: NumberBase,
    min_digits: usize,
    fraction_digits: usize,
) -> String {
    let magnitude = value.unsigned_abs();
    let digits = base.render(magnitude);
    let padded = format!("{digits:0>min_digits$}");
    let mut out = String::new();
    if value < 0 {
        out.push('-');
    }
    out.push_str(&padded);
    if fraction_digits > 0 {
        out.push('.');
        out.extend(std::iter::repeat_n('0', fraction_digits));
    }
    out
}

fn date_run(from: u64, to: u64, step: u64) -> impl Iterator<Item = u64> {
    let mut current = from;
    std::iter::from_fn(move || {
        if current > to {
            return None;
        }
        let value = current;
        current = current.saturating_add(step);
        Some(value)
    })
    .take(MAX_PAYLOADS)
}

/// Days since the Unix epoch to a (year, month, day) civil date (UTC), after
/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// strftime subset for Intruder dates: `%Y %m %d %H %M %S %s`, plus `%%`.
/// Anything else is copied through untouched.
fn format_date(secs: u64, format: &str) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let mut out = String::with_capacity(format.len() + 8);
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{year:04}")),
            Some('m') => out.push_str(&format!("{month:02}")),
            Some('d') => out.push_str(&format!("{day:02}")),
            Some('H') => out.push_str(&format!("{hour:02}")),
            Some('M') => out.push_str(&format!("{minute:02}")),
            Some('S') => out.push_str(&format!("{second:02}")),
            Some('s') => out.push_str(&secs.to_string()),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

// ---------- payload processing (C-04) ----------

/// One rule in an ordered payload-processing pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processor {
    AddPrefix(String),
    AddSuffix(String),
    /// `regex` is a Rust `regex` pattern; `$1`-style group references work.
    MatchReplace {
        regex: String,
        replacement: String,
    },
    /// Character offsets, `-1` = last character, both ends clamped; `end` is
    /// exclusive, so `-3..-1` keeps the last two characters.
    Substring {
        start: i64,
        end: i64,
    },
    Reverse,
    Lowercase,
    Uppercase,
    Base64Encode,
    Base64Decode,
    /// Percent-encode every byte, including unreserved characters.
    UrlEncodeAll,
    /// Percent-encode only the characters that are unsafe in a URL key.
    UrlEncodeKey,
    HtmlEncode,
    HexEncode,
    Md5,
    Sha1,
    Sha256,
    /// Drop the payload from the set when the pattern matches.
    SkipIfMatches {
        regex: String,
    },
    /// Dedupe the set; `max` 0 means unlimited. A set-level rule, so `process`
    /// passes the payload through and `process_set` does the work.
    MakeUnique {
        max: usize,
    },
}

/// Apply `rules` in order to one payload. `None` means a skip rule matched.
/// Invalid regexes and undecodable Base64 leave the payload unchanged instead
/// of failing the whole attack.
pub fn process(payload: &str, rules: &[Processor]) -> Option<String> {
    let mut current = payload.to_string();
    for rule in rules {
        match rule {
            Processor::AddPrefix(prefix) => current = format!("{prefix}{current}"),
            Processor::AddSuffix(suffix) => current = format!("{current}{suffix}"),
            Processor::MatchReplace { regex, replacement } => {
                if let Ok(re) = regex::Regex::new(regex) {
                    current = re.replace_all(&current, replacement.as_str()).into_owned();
                }
            }
            Processor::Substring { start, end } => current = substring(&current, *start, *end),
            Processor::Reverse => current = current.chars().rev().collect(),
            Processor::Lowercase => current = current.to_lowercase(),
            Processor::Uppercase => current = current.to_uppercase(),
            Processor::Base64Encode => current = util::b64_encode(current.as_bytes()),
            Processor::Base64Decode => {
                if let Ok(decoded) = decoder_ops::apply(Op::Base64Decode, &current) {
                    current = decoded;
                }
            }
            Processor::UrlEncodeAll => current = url_encode_all(&current),
            Processor::UrlEncodeKey => current = util::url_encode_key(&current),
            Processor::HtmlEncode => current = util::html_encode(&current),
            Processor::HexEncode => current = util::hex_encode(current.as_bytes()),
            Processor::Md5 => current = digest(Op::Md5, &current),
            Processor::Sha1 => current = digest(Op::Sha1, &current),
            Processor::Sha256 => current = digest(Op::Sha256, &current),
            Processor::SkipIfMatches { regex } => {
                if regex::Regex::new(regex).is_ok_and(|re| re.is_match(&current)) {
                    return None;
                }
            }
            Processor::MakeUnique { .. } => {}
        }
    }
    Some(current)
}

/// Apply the pipeline to a whole set: skip rules drop payloads, and any
/// `MakeUnique` rule dedupes the result (capped by its `max`, 0 = unlimited).
pub fn process_set(set: &[String], rules: &[Processor]) -> Vec<String> {
    let unique = rules.iter().find_map(|rule| match rule {
        Processor::MakeUnique { max } => Some(*max),
        _ => None,
    });
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(set.len());
    for payload in set {
        let Some(value) = process(payload, rules) else {
            continue;
        };
        if unique.is_some() {
            if !seen.insert(value.clone()) {
                continue;
            }
            if let Some(max) = unique.filter(|max| *max > 0) {
                if out.len() >= max {
                    continue;
                }
            }
        }
        out.push(value);
    }
    out
}

fn digest(op: Op, input: &str) -> String {
    decoder_ops::apply(op, input).unwrap_or_else(|_| input.to_string())
}

fn url_encode_all(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        out.push_str(&format!("%{byte:02X}"));
    }
    out
}

fn substring(input: &str, start: i64, end: i64) -> String {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len() as i64;
    let clamp = |index: i64| {
        if index < 0 {
            (len + index).max(0)
        } else {
            index.min(len)
        }
    };
    let (from, to) = (clamp(start), clamp(end));
    if from >= to {
        String::new()
    } else {
        chars[from as usize..to as usize].iter().collect()
    }
}

/// The payload sources an attack uses (the Payloads panel): a "Simple
/// list" takes its items from the set's text, one per line, trimmed, blank
/// lines dropped; every other type is used as configured. A set without a
/// configured type is a simple list (the panel's default).
pub fn effective_sources(set_texts: &[String], sources: &[PayloadSource]) -> Vec<PayloadSource> {
    set_texts
        .iter()
        .enumerate()
        .map(|(i, text)| match sources.get(i) {
            None | Some(PayloadSource::SimpleList { .. }) => PayloadSource::SimpleList {
                items: text
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect(),
            },
            Some(other) => other.clone(),
        })
        .collect()
}

/// Whether counting needs the sets resolved (copy, recursive grep and
/// base-value sets); plain sets count from their length.
fn needs_resolving(s: &PayloadSource) -> bool {
    matches!(
        s,
        PayloadSource::CopyOtherPayload { .. } | PayloadSource::RecursiveGrep { .. }
    ) || s.uses_position_base()
}

/// "Request count:" as Burp's Payloads panel shows it, when it can be told
/// from the set lengths alone: the count, "too many" on overflow, "-" for
/// an invalid set or request, `None` when the sets must be resolved first
/// ([`request_count_resolved`]).
pub fn request_count_fast(
    request: &str,
    kind: AttackType,
    sources: &[PayloadSource],
) -> Option<String> {
    let Ok(template) = Template::parse(request) else {
        return Some("0".into());
    };
    let used = &sources[..kind.sets_needed(template.positions()).min(sources.len())];
    if used.iter().any(needs_resolving) {
        return None;
    }
    if used
        .iter()
        .enumerate()
        .any(|(i, s)| s.validate(kind, i, used).is_err())
    {
        return Some("-".into());
    }
    // Extension payloads are fetched when the attack starts.
    if used
        .iter()
        .any(|s| matches!(s, PayloadSource::Extension { .. }))
    {
        return Some("unknown".into());
    }
    let lens: Vec<usize> = used.iter().map(PayloadSource::len).collect();
    Some(
        count(kind, template.positions(), &lens)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "too many".into()),
    )
}

/// The count after resolving every set: "unknown" with a recursive-grep
/// set (its payloads come from responses), "-" when a set is invalid.
pub fn request_count_resolved(
    request: &str,
    kind: AttackType,
    sources: &[PayloadSource],
) -> String {
    let Ok(template) = Template::parse(request) else {
        return "0".into();
    };
    match resolve_specs(&template, kind, sources) {
        Ok(specs) if specs.iter().any(|s| matches!(s, SetSpec::Recursive { .. })) => {
            "unknown".into()
        }
        Ok(specs) => count_specs(kind, template.positions(), &specs)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "too many".into()),
        Err(_) => "-".into(),
    }
}

/// What the results table does with its row order when it is drawn
/// (`key` = row count, sort column, ascending).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderStep {
    /// Nothing changed.
    Keep,
    /// Rows arrived in a sorted view less than half a second after the last
    /// sort: append them unsorted, sort again soon.
    Append(std::ops::Range<usize>),
    /// Sort (or number-order) all rows now.
    Rebuild,
}

/// Decide the [`OrderStep`] for the results table: an unchanged view keeps
/// its order unless appended rows still wait for a sort; a sorted view that
/// only grew within `recent` appends; anything else rebuilds.
pub fn order_step(
    old: (usize, usize, bool),
    new: (usize, usize, bool),
    recent: bool,
    dirty: bool,
) -> OrderStep {
    if new == old && !(dirty && !recent) {
        return OrderStep::Keep;
    }
    let (old_len, old_col, old_asc) = old;
    let only_grew =
        old_col == new.1 && old_asc == new.2 && new.0 > old_len && old_len != usize::MAX;
    if new.1 != usize::MAX && only_grew && recent {
        OrderStep::Append(old_len..new.0)
    } else {
        OrderStep::Rebuild
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn reqs(attacks: &[Attack]) -> Vec<&str> {
        attacks.iter().map(|a| a.request.as_str()).collect()
    }

    #[test]
    fn parse_splits_positions_and_render_strips_markers() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        assert_eq!(t.positions(), 2);
        assert_eq!(t.render(&[None, None]), "a1b2c");
        assert_eq!(t.render(&[Some("x"), None]), "axb2c");
        assert!(!t.render(&[None, None]).contains(MARK));
    }

    #[test]
    fn unbalanced_marker_is_rejected() {
        assert!(Template::parse("a§1§b§2c").is_err());
    }

    #[test]
    fn sniper_walks_each_position_with_the_others_untouched() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(&t, AttackType::Sniper, &[set(&["x", "y"])], 100).unwrap();
        assert_eq!(reqs(&out), ["axb2c", "ayb2c", "a1bxc", "a1byc"]);
        assert_eq!(out[0].payloads, vec![Some("x".to_string()), None]);
        assert_eq!(count(AttackType::Sniper, 2, &[2]), Some(4));
    }

    #[test]
    fn battering_ram_puts_one_payload_everywhere() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(&t, AttackType::BatteringRam, &[set(&["x", "y"])], 100).unwrap();
        assert_eq!(reqs(&out), ["axbxc", "aybyc"]);
    }

    #[test]
    fn pitchfork_walks_in_lock_step_and_stops_at_the_shortest_set() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(
            &t,
            AttackType::Pitchfork,
            &[set(&["x", "y", "z"]), set(&["1", "2"])],
            100,
        )
        .unwrap();
        assert_eq!(reqs(&out), ["axb1c", "ayb2c"]);
    }

    #[test]
    fn cluster_bomb_tries_every_combination_first_position_fastest() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(
            &t,
            AttackType::ClusterBomb,
            &[set(&["A", "B"]), set(&["1", "2"])],
            100,
        )
        .unwrap();
        assert_eq!(reqs(&out), ["aAb1c", "aBb1c", "aAb2c", "aBb2c"]);

        let t3 = Template::parse("§a§§b§§c§").unwrap();
        let sets = [set(&["1", "2"]), set(&["3", "4"]), set(&["5", "6"])];
        assert_eq!(
            requests(&t3, AttackType::ClusterBomb, &sets, 100)
                .unwrap()
                .len(),
            8
        );
    }

    #[test]
    fn bad_input_is_reported_not_swallowed() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        assert!(
            requests(&t, AttackType::Pitchfork, &[set(&["x"])], 100).is_err(),
            "needs two sets"
        );
        assert!(
            requests(&t, AttackType::Sniper, &[set(&[])], 100).is_err(),
            "empty set"
        );
        assert!(
            requests(
                &t,
                AttackType::ClusterBomb,
                &[set(&["a", "b"]), set(&["c", "d"])],
                3
            )
            .is_err(),
            "over the limit"
        );
        assert!(requests(
            &Template::parse("no positions").unwrap(),
            AttackType::Sniper,
            &[set(&["x"])],
            100
        )
        .is_err());
        assert_eq!(
            count(AttackType::ClusterBomb, 2, &[usize::MAX, 2]),
            None,
            "overflow"
        );
    }

    #[test]
    fn add_and_clear_markers() {
        let text = "GET /a?b=1 HTTP/1.1";
        let marked = add_marker(text, 9, 10).unwrap();
        assert_eq!(marked, "GET /a?b=§1§ HTTP/1.1");
        assert_eq!(clear_markers(&marked), text);
        assert!(
            add_marker(&marked, 9, 12).is_err(),
            "selection contains a marker"
        );
        assert!(
            add_marker(&marked, 11, 12).is_err(),
            "selection sits inside a position"
        );
        assert!(add_marker(text, 5, 99).is_err(), "out of range");
    }

    #[test]
    fn auto_mark_covers_query_cookie_form_and_json() {
        let get = "GET /p?a=1&b=2 HTTP/1.1\r\nHost: h\r\nCookie: s=abc; t=9\r\n\r\n";
        assert_eq!(
            auto_mark(get),
            "GET /p?a=§1§&b=§2§ HTTP/1.1\r\nHost: h\r\nCookie: s=§abc§; t=§9§\r\n\r\n"
        );

        let form =
            "POST /l HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=bob&p=pw";
        assert!(auto_mark(form).ends_with("\r\n\r\nu=§bob§&p=§pw§"));

        let json = "POST /l HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"u\":\"bob\",\"n\":5,\"ok\":true}";
        assert!(auto_mark(json).ends_with("{\"u\":\"§bob§\",\"n\":§5§,\"ok\":§true§}"));

        // Existing markers are replaced, not nested.
        assert_eq!(
            auto_mark("GET /p?a=§1§ HTTP/1.1\r\n\r\n"),
            "GET /p?a=§1§ HTTP/1.1\r\n\r\n"
        );
    }

    // ---------- payload sources (C-03) ----------

    fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("webprobe-intruder-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn simple_list_generates_verbatim_in_order() {
        let source = PayloadSource::SimpleList {
            items: set(&["admin", "root", ""]),
        };
        assert_eq!(source.generate(), ["admin", "root", ""]);
        assert_eq!(source.len(), 3);
    }

    #[test]
    fn runtime_file_reads_lines_skips_blanks_and_trims_cr() {
        let path = temp_file("payloads.txt", "one\r\ntwo\n\nthree\n");
        let source = PayloadSource::RuntimeFile {
            path: path.to_string_lossy().into_owned(),
        };
        assert_eq!(source.generate(), ["one", "two", "three"]);
        assert_eq!(source.len(), 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn runtime_file_missing_is_empty_not_a_panic() {
        let path = std::env::temp_dir().join(format!(
            "webprobe-intruder-{}-missing.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let source = PayloadSource::RuntimeFile {
            path: path.to_string_lossy().into_owned(),
        };
        assert!(source.generate().is_empty());
        assert_eq!(source.len(), 0);
    }

    #[test]
    fn numbers_pad_in_decimal_and_hex() {
        let decimal = PayloadSource::Numbers {
            from: 8,
            to: 10,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 3,
            fraction_digits: 0,
        };
        assert_eq!(decimal.generate(), ["008", "009", "010"]);
        assert_eq!(decimal.len(), 3);

        let hex = PayloadSource::Numbers {
            from: 10,
            to: 12,
            step: 1,
            base: NumberBase::Hex,
            min_digits: 2,
            fraction_digits: 0,
        };
        assert_eq!(hex.generate(), ["0a", "0b", "0c"]);
    }

    #[test]
    fn numbers_handle_fractions_negatives_and_zero_step() {
        let fractional = PayloadSource::Numbers {
            from: 1,
            to: 2,
            step: 0, // rejected, treated as 1
            base: NumberBase::Decimal,
            min_digits: 3,
            fraction_digits: 2,
        };
        assert_eq!(fractional.generate(), ["001.00", "002.00"]);

        let negative = PayloadSource::Numbers {
            from: -2,
            to: 0,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 1,
            fraction_digits: 0,
        };
        assert_eq!(negative.generate(), ["-2", "-1", "0"]);

        let inverted = PayloadSource::Numbers {
            from: 5,
            to: 1,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 1,
            fraction_digits: 0,
        };
        assert!(inverted.generate().is_empty());
    }

    #[test]
    fn null_case_and_frobber_payloads() {
        assert_eq!(
            PayloadSource::NullPayloads { count: 3 }.generate(),
            vec!["", "", ""]
        );
        let c = PayloadSource::CaseModification {
            items: vec!["peTer".into()],
            no_change: true,
            lower: true,
            upper: true,
            propername: true,
            proper_name: true,
        };
        assert_eq!(
            c.generate(),
            vec!["peTer", "peter", "PETER", "Peter", "PeTer"]
        );
        assert_eq!(c.len(), 5);
        let f = PayloadSource::CharacterFrobber { base: "ab1".into() };
        assert_eq!(f.generate(), vec!["bb1", "ac1", "ab2"]);
    }

    #[test]
    fn brute_forcer_is_lexicographic_with_the_charset_as_given() {
        let source = PayloadSource::BruteForcer {
            charset: "ba".into(),
            min_len: 1,
            max_len: 2,
        };
        assert_eq!(source.generate(), ["b", "a", "bb", "ba", "ab", "aa"]);
        assert_eq!(source.len(), 6);
        assert!(PayloadSource::BruteForcer {
            charset: String::new(),
            min_len: 1,
            max_len: 2
        }
        .generate()
        .is_empty());
    }

    #[test]
    fn brute_forcer_caps_total_payloads() {
        let source = PayloadSource::BruteForcer {
            charset: "abcdefghij".into(),
            min_len: 1,
            max_len: 7,
        };
        assert_eq!(source.len(), MAX_PAYLOADS);
        assert_eq!(source.generate().len(), MAX_PAYLOADS);
    }

    #[test]
    fn dates_use_the_strftime_subset_in_utc() {
        let source = PayloadSource::Dates {
            from: 0,
            to: 86_400,
            step_secs: 86_400,
            format: "%Y-%m-%d %H:%M:%S %s".into(),
        };
        assert_eq!(
            source.generate(),
            ["1970-01-01 00:00:00 0", "1970-01-02 00:00:00 86400"]
        );
        assert_eq!(source.len(), 2);

        assert_eq!(
            format_date(1_700_000_000, "%Y/%m/%d %H:%M"),
            "2023/11/14 22:13"
        );
        assert_eq!(format_date(1_700_000_000, "%d%%%q"), "14%%q");
        // A zero step still advances one second instead of looping forever.
        assert_eq!(
            PayloadSource::Dates {
                from: 5,
                to: 6,
                step_secs: 0,
                format: "%s".into()
            }
            .generate(),
            ["5", "6"]
        );
    }

    #[test]
    fn character_blocks_repeat_and_truncate_the_base() {
        let source = PayloadSource::CharacterBlocks {
            base: "ab".into(),
            min_len: 1,
            max_len: 3,
        };
        assert_eq!(source.generate(), ["a", "ab", "aba"]);
        assert_eq!(source.len(), 3);
        assert!(PayloadSource::CharacterBlocks {
            base: String::new(),
            min_len: 1,
            max_len: 3
        }
        .generate()
        .is_empty());
    }

    #[test]
    fn resolve_sets_turns_each_source_into_its_list() {
        let sources = [
            PayloadSource::SimpleList {
                items: set(&["x", "y"]),
            },
            PayloadSource::Numbers {
                from: 1,
                to: 2,
                step: 1,
                base: NumberBase::Decimal,
                min_digits: 1,
                fraction_digits: 0,
            },
        ];
        assert_eq!(
            resolve_sets(&sources),
            vec![set(&["x", "y"]), set(&["1", "2"])]
        );
    }

    // ---------- payload processing (C-04) ----------

    #[test]
    fn prefix_and_suffix_wrap_the_payload() {
        let rules = [
            Processor::AddPrefix("pre".into()),
            Processor::AddSuffix("post".into()),
        ];
        assert_eq!(process("x", &rules).unwrap(), "prexpost");
    }

    #[test]
    fn match_replace_uses_capture_groups() {
        let rules = [Processor::MatchReplace {
            regex: r"(\w+)=(\d+)".into(),
            replacement: "$2=$1".into(),
        }];
        assert_eq!(process("user=123", &rules).unwrap(), "123=user");
        assert_eq!(process("nothing", &rules).unwrap(), "nothing");
    }

    #[test]
    fn invalid_regex_is_skipped_not_fatal() {
        let rules = [
            Processor::MatchReplace {
                regex: "(".into(),
                replacement: "x".into(),
            },
            Processor::SkipIfMatches { regex: "[".into() },
        ];
        assert_eq!(process("keep", &rules).unwrap(), "keep");
    }

    #[test]
    fn substring_counts_from_the_end_and_clamps() {
        assert_eq!(substring("abcdef", -3, -1), "de");
        assert_eq!(substring("abcdef", 0, 3), "abc");
        assert_eq!(substring("abcdef", 2, -1), "cde");
        assert_eq!(substring("abcdef", -100, 2), "ab");
        assert_eq!(substring("abcdef", 10, 20), "");
        assert_eq!(
            process("abcdef", &[Processor::Substring { start: -1, end: 6 }]).unwrap(),
            "f"
        );
    }

    #[test]
    fn case_and_reverse_transform_the_whole_payload() {
        assert_eq!(process("aBc", &[Processor::Reverse]).unwrap(), "cBa");
        assert_eq!(process("aBc", &[Processor::Lowercase]).unwrap(), "abc");
        assert_eq!(process("aBc", &[Processor::Uppercase]).unwrap(), "ABC");
    }

    #[test]
    fn base64_encodes_and_decodes_and_survives_bad_input() {
        assert_eq!(process("hi", &[Processor::Base64Encode]).unwrap(), "aGk=");
        assert_eq!(process("aGk=", &[Processor::Base64Decode]).unwrap(), "hi");
        assert_eq!(process("!!!", &[Processor::Base64Decode]).unwrap(), "!!!");
    }

    #[test]
    fn url_encode_all_differs_from_key_encoding() {
        assert_eq!(
            process("a b", &[Processor::UrlEncodeAll]).unwrap(),
            "%61%20%62"
        );
        assert_eq!(process("a b", &[Processor::UrlEncodeKey]).unwrap(), "a%20b");
    }

    #[test]
    fn html_and_hex_encoding() {
        assert_eq!(
            process("<a&b>", &[Processor::HtmlEncode]).unwrap(),
            "&lt;a&amp;b&gt;"
        );
        assert_eq!(process("hi", &[Processor::HexEncode]).unwrap(), "6869");
    }

    #[test]
    fn hashes_match_known_vectors() {
        assert_eq!(
            process("abc", &[Processor::Md5]).unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            process("abc", &[Processor::Sha1]).unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            process("abc", &[Processor::Sha256]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn skip_rule_drops_the_payload() {
        let rules = [Processor::SkipIfMatches {
            regex: r"\d+".into(),
        }];
        assert_eq!(process("abc123", &rules), None);
        assert_eq!(process("abc", &rules).as_deref(), Some("abc"));
    }

    #[test]
    fn pipeline_order_is_respected() {
        let encode_then_prefix = [Processor::Base64Encode, Processor::AddPrefix("x".into())];
        let prefix_then_encode = [Processor::AddPrefix("x".into()), Processor::Base64Encode];
        assert_eq!(process("hi", &encode_then_prefix).unwrap(), "xaGk=");
        assert_eq!(process("hi", &prefix_then_encode).unwrap(), "eGhp");
        assert_ne!(
            process("hi", &encode_then_prefix).unwrap(),
            process("hi", &prefix_then_encode).unwrap()
        );
    }

    #[test]
    fn make_unique_dedupes_and_caps_the_set() {
        let set = set(&["a", "a", "b", "a", "c"]);
        assert_eq!(
            process_set(&set, &[Processor::MakeUnique { max: 0 }]),
            ["a", "b", "c"]
        );
        assert_eq!(
            process_set(&set, &[Processor::MakeUnique { max: 2 }]),
            ["a", "b"]
        );
    }

    #[test]
    fn process_set_without_make_unique_keeps_duplicates() {
        assert_eq!(process_set(&set(&["a", "a", "b"]), &[]), ["a", "a", "b"]);
    }

    #[test]
    fn process_set_drops_skipped_payloads() {
        let rules = [
            Processor::SkipIfMatches {
                regex: r"^\d".into(),
            },
            Processor::AddPrefix("u_".into()),
        ];
        assert_eq!(
            process_set(&set(&["bob", "1eve", "eve"]), &rules),
            ["u_bob", "u_eve"]
        );
    }

    #[test]
    fn open_ended_number_ranges_stop_at_the_cap() {
        let source = PayloadSource::Numbers {
            from: 0,
            to: i64::MAX,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 1,
            fraction_digits: 0,
        };
        assert_eq!(source.len(), MAX_PAYLOADS);
    }

    #[test]
    fn skip_rules_see_the_value_after_earlier_rules() {
        let rules = [
            Processor::Base64Encode,
            Processor::SkipIfMatches {
                regex: "^aG".into(),
            },
        ];
        assert_eq!(process("hi", &rules), None, "skipped after encoding");
        assert_eq!(
            process(
                "hi",
                &[
                    Processor::SkipIfMatches {
                        regex: "^aG".into()
                    },
                    Processor::Base64Encode
                ]
            )
            .as_deref(),
            Some("aGk="),
            "skip runs before the encoding when listed first"
        );
    }

    #[test]
    fn processed_sets_feed_the_attack_matrix() {
        let template = Template::parse("u=§a§&p=§b§").unwrap();
        let sources = [
            PayloadSource::Numbers {
                from: 1,
                to: 3,
                step: 1,
                base: NumberBase::Decimal,
                min_digits: 2,
                fraction_digits: 0,
            },
            PayloadSource::SimpleList {
                items: set(&["x", "y"]),
            },
        ];
        let rules = [Processor::AddPrefix("v".into())];
        let sets: Vec<Vec<String>> = resolve_sets(&sources)
            .iter()
            .map(|set| process_set(set, &rules))
            .collect();
        assert_eq!(sets, vec![set(&["v01", "v02", "v03"]), set(&["vx", "vy"])]);

        let attacks = requests(&template, AttackType::ClusterBomb, &sets, 100).unwrap();
        assert_eq!(attacks.len(), 6);
        assert_eq!(attacks[0].request, "u=v01&p=vx");
        assert_eq!(attacks[5].request, "u=v03&p=vy");
        assert_eq!(count(AttackType::ClusterBomb, 2, &[3, 2]), Some(6));
    }

    // ---------- C-03 remaining payload types ----------

    fn lists8(parts: &[&[&str]]) -> Vec<Vec<String>> {
        let mut v: Vec<Vec<String>> = parts.iter().map(|p| set(p)).collect();
        v.resize(8, Vec::new());
        v
    }

    #[test]
    fn custom_iterator_varies_position_one_fastest_with_separators() {
        let mut seps = vec![String::new(); 8];
        seps[0] = "-".into();
        let src = PayloadSource::CustomIterator {
            lists: lists8(&[&["a", "b"], &["1", "2"]]),
            separators: seps.clone(),
        };
        assert_eq!(src.generate(), ["a-1", "b-1", "a-2", "b-2"]);
        assert_eq!(src.len(), 4);
        // An empty first position is skipped without losing position 2's
        // first item (Burp's odometer starts at -1 and would skip "x").
        let src = PayloadSource::CustomIterator {
            lists: lists8(&[&[], &["x", "y"]]),
            separators: seps,
        };
        assert_eq!(src.generate(), ["-x", "-y"]);
        assert_eq!(src.len(), 2);
        let none = PayloadSource::CustomIterator {
            lists: lists8(&[]),
            separators: vec![String::new(); 8],
        };
        assert!(none.generate().is_empty());
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn character_substitution_uses_burps_table_and_bit_order() {
        assert_eq!(
            default_substitutions()[..9]
                .iter()
                .map(|(f, t)| format!("{f}{t}"))
                .collect::<Vec<_>>(),
            ["a4", "b8", "e3", "g6", "i1", "o0", "s5", "t7", "z2"]
        );
        assert_eq!(default_substitutions().len(), 16);
        let src = PayloadSource::CharacterSubstitution {
            items: set(&["ab", "", "Be", "xyz"]),
            rules: default_substitutions(),
            case_sensitive: false,
        };
        assert_eq!(
            src.generate(),
            ["ab", "4b", "a8", "48", "Be", "8e", "B3", "83", "xyz", "xy2"]
        );
        assert_eq!(src.len(), 10);
        let cs = PayloadSource::CharacterSubstitution {
            items: set(&["Be"]),
            rules: default_substitutions(),
            case_sensitive: true,
        };
        assert_eq!(cs.generate(), ["Be", "B3"]);
        assert_eq!(cs.len(), 2);
    }

    #[test]
    fn bit_flipper_flips_each_selected_bit_of_each_byte() {
        let all = PayloadSource::BitFlipper {
            base: Some("A".into()),
            hex: false,
            mask: 0xFF,
        };
        assert_eq!(
            all.generate(),
            ["@", "C", "E", "I", "Q", "a", "\u{1}", "\u{C1}"]
        );
        assert_eq!(all.len(), 8);
        let two = PayloadSource::BitFlipper {
            base: Some("AB".into()),
            hex: false,
            mask: 0b11,
        };
        assert_eq!(two.generate(), ["@B", "CB", "AC", "A@"]);
        let hex = PayloadSource::BitFlipper {
            base: Some("41ff".into()),
            hex: true,
            mask: 0b11,
        };
        assert_eq!(hex.generate(), ["40ff", "43ff", "41fe", "41fd"]);
        assert_eq!(hex.len(), 4);
        // Non-hex pairs are skipped.
        let bad = PayloadSource::BitFlipper {
            base: Some("zz41".into()),
            hex: true,
            mask: 1,
        };
        assert_eq!(bad.generate(), ["zz40"]);
        // Base value of the payload position.
        let pos = PayloadSource::BitFlipper {
            base: None,
            hex: false,
            mask: 1,
        };
        assert_eq!(pos.generate_for_base("ab"), ["`b", "ac"]);
        assert_eq!(
            pos.validate(AttackType::BatteringRam, 0, std::slice::from_ref(&pos))
                .unwrap_err(),
            IntruderError::BitFlipperBaseUnsupported
        );
        let none = PayloadSource::BitFlipper {
            base: None,
            hex: false,
            mask: 0,
        };
        assert_eq!(
            none.validate(AttackType::Sniper, 0, std::slice::from_ref(&none)),
            Err(IntruderError::NoBitsSelected)
        );
    }

    #[test]
    fn username_generator_follows_burps_scheme_state_machine() {
        let src = PayloadSource::UsernameGenerator {
            items: set(&["Peter Wiener"]),
            max_per_item: 14,
        };
        assert_eq!(
            src.generate(),
            [
                "PeterWiener",
                "Peter.Wiener",
                "WienerPeter",
                "Wiener.Peter",
                "Peter",
                "Wiener",
                "PeterW",
                "Peter.W",
                "WPeter",
                "W.Peter",
                "PWiener",
                "P.Wiener",
                "WienerP",
                "Wiener.P",
            ]
        );
        let mail = PayloadSource::UsernameGenerator {
            items: set(&["john.smith@example.org"]),
            max_per_item: 2,
        };
        assert_eq!(
            mail.generate(),
            ["johnsmith@example.org", "john.smith@example.org"]
        );
        let single = PayloadSource::UsernameGenerator {
            items: set(&["admin", "  "]),
            max_per_item: 0,
        };
        assert_eq!(single.generate(), ["admin", "a", "ad", "adm", "admi"]);
        // The default cap is 50 per item and the whole scheme ends on its own.
        let full = PayloadSource::UsernameGenerator {
            items: set(&["Peter Wiener"]),
            max_per_item: 50,
        };
        assert_eq!(full.len(), 50);
        let empty = PayloadSource::UsernameGenerator {
            items: Vec::new(),
            max_per_item: 50,
        };
        assert_eq!(
            empty.validate(AttackType::Sniper, 0, &[]),
            Err(IntruderError::NoListItems)
        );
    }

    #[test]
    fn ecb_block_shuffler_inserts_sorted_distinct_blocks_at_each_boundary() {
        let src = PayloadSource::EcbBlockShuffler {
            base: Some("AABBAA".into()),
            hex: false,
            block_size: 2,
            extra: Vec::new(),
        };
        assert_eq!(
            src.generate(),
            [
                "AAAABBAA", "BBAABBAA", "AAAABBAA", "AABBBBAA", "AABBAAAA", "AABBBBAA", "AABBAAAA",
                "AABBAABB"
            ]
        );
        assert_eq!(src.len(), 8);
        let hex = PayloadSource::EcbBlockShuffler {
            base: Some("0011".into()),
            hex: true,
            block_size: 1,
            extra: set(&["22"]),
        };
        assert_eq!(
            hex.generate(),
            [
                "000011", "110011", "220011", "000011", "001111", "002211", "001100", "001111",
                "001122"
            ]
        );
        let src = PayloadSource::EcbBlockShuffler {
            base: None,
            hex: true,
            block_size: 8,
            extra: Vec::new(),
        };
        assert_eq!(
            src.validate(AttackType::BatteringRam, 0, &[]),
            Err(IntruderError::BatteringRamUnsupported)
        );
        let zero = PayloadSource::EcbBlockShuffler {
            base: None,
            hex: true,
            block_size: 0,
            extra: Vec::new(),
        };
        assert_eq!(
            zero.validate(AttackType::Sniper, 0, &[]),
            Err(IntruderError::InvalidBlockSize)
        );
    }

    #[test]
    fn new_types_sit_at_their_burp_positions() {
        let labels: Vec<&str> = PayloadSource::defaults()
            .iter()
            .map(PayloadSource::label)
            .collect();
        assert_eq!(
            labels,
            [
                "Simple list",
                "Runtime file",
                "Custom iterator",
                "Character substitution",
                "Case modification",
                "Recursive grep",
                "Illegal Unicode",
                "Character blocks",
                "Numbers",
                "Dates",
                "Brute forcer",
                "Null payloads",
                "Character frobber",
                "Bit flipper",
                "Username generator",
                "ECB block shuffler",
                "Extension-generated",
                "Copy other payload",
            ]
        );
    }

    #[test]
    fn copy_other_payload_follows_its_source_without_multiplying() {
        let template = Template::parse("a=§1§&b=§2§").unwrap();
        let sources = [
            PayloadSource::SimpleList {
                items: set(&["x", "y"]),
            },
            PayloadSource::CopyOtherPayload { from_position: 1 },
        ];
        let specs = resolve_specs(&template, AttackType::Pitchfork, &sources).unwrap();
        assert_eq!(count_specs(AttackType::Pitchfork, 2, &specs), Some(2));
        let r = requests_specs(&template, AttackType::Pitchfork, &specs, 100).unwrap();
        assert_eq!(reqs(&r), ["a=x&b=x", "a=y&b=y"]);

        let template = Template::parse("§a§§b§§c§").unwrap();
        let sources = [
            PayloadSource::SimpleList {
                items: set(&["x", "y"]),
            },
            PayloadSource::CopyOtherPayload { from_position: 1 },
            PayloadSource::SimpleList {
                items: set(&["1", "2"]),
            },
        ];
        let specs = resolve_specs(&template, AttackType::ClusterBomb, &sources).unwrap();
        assert_eq!(count_specs(AttackType::ClusterBomb, 3, &specs), Some(4));
        let r = requests_specs(&template, AttackType::ClusterBomb, &specs, 100).unwrap();
        assert_eq!(
            reqs(&r),
            ["xx1", "yy1", "xx2", "yy2"],
            "position 1 fastest, the copy follows it"
        );
        assert_eq!(
            r[0].payloads,
            vec![
                Some("x".to_string()),
                Some("x".to_string()),
                Some("1".to_string())
            ]
        );

        let one = Template::parse("§a§").unwrap();
        let copy = [PayloadSource::CopyOtherPayload { from_position: 1 }];
        assert_eq!(
            resolve_specs(&one, AttackType::Sniper, &copy),
            Err("Cannot copy payload from another position using this attack type.".into())
        );
        let two = Template::parse("§a§§b§").unwrap();
        let same = [
            PayloadSource::SimpleList { items: set(&["x"]) },
            PayloadSource::CopyOtherPayload { from_position: 2 },
        ];
        assert_eq!(
            resolve_specs(&two, AttackType::Pitchfork, &same),
            Err("Cannot copy payload from same position.".into())
        );
        let bad = [
            PayloadSource::SimpleList { items: set(&["x"]) },
            PayloadSource::CopyOtherPayload { from_position: 3 },
        ];
        assert_eq!(
            resolve_specs(&two, AttackType::Pitchfork, &bad),
            Err("Cannot copy payload from invalid position.".into())
        );
        let dep = [
            PayloadSource::CopyOtherPayload { from_position: 2 },
            PayloadSource::CopyOtherPayload { from_position: 1 },
        ];
        assert_eq!(
            resolve_specs(&two, AttackType::Pitchfork, &dep),
            Err("Cannot copy payload from another dependent position.".into())
        );
    }

    #[test]
    fn sniper_runs_base_value_generators_per_position() {
        let template = Template::parse("x=§A§&y=§b§").unwrap();
        let sources = [PayloadSource::BitFlipper {
            base: None,
            hex: false,
            mask: 1,
        }];
        let specs = resolve_specs(&template, AttackType::Sniper, &sources).unwrap();
        assert_eq!(count_specs(AttackType::Sniper, 2, &specs), Some(2));
        let r = requests_specs(&template, AttackType::Sniper, &specs, 100).unwrap();
        assert_eq!(reqs(&r), ["x=@&y=b", "x=A&y=c"]);
    }

    #[test]
    fn recursive_grep_feeds_each_extract_into_the_next_request() {
        let template = Template::parse("t=§a§").unwrap();
        let sources = [PayloadSource::RecursiveGrep {
            initial: "i0".into(),
            extract_index: 0,
            stop_on_duplicate: true,
        }];
        let specs = resolve_specs(&template, AttackType::Sniper, &sources).unwrap();
        assert_eq!(count_specs(AttackType::Sniper, 1, &specs), None);
        assert!(requests_specs(&template, AttackType::Sniper, &specs, 100).is_err());
        let mut walk = RecursiveWalk::new(AttackType::Sniper, &specs).unwrap();
        assert_eq!(walk.next_attack(&template).unwrap().request, "t=i0");
        walk.feed(&[Some("t1".into())]);
        assert_eq!(walk.next_attack(&template).unwrap().request, "t=t1");
        walk.feed(&[Some("t1".into())]);
        assert!(
            walk.next_attack(&template).is_none(),
            "duplicate stops the walk"
        );

        // No match ends it too.
        let mut walk = RecursiveWalk::new(AttackType::Sniper, &specs).unwrap();
        walk.next_attack(&template).unwrap();
        walk.feed(&[None]);
        assert!(walk.next_attack(&template).is_none());

        // Pitchfork: a CSRF token walk paired with a password list.
        let template = Template::parse("csrf=§c§&pw=§p§").unwrap();
        let sources = [
            PayloadSource::RecursiveGrep {
                initial: String::new(),
                extract_index: 1,
                stop_on_duplicate: false,
            },
            PayloadSource::SimpleList {
                items: set(&["p1", "p2"]),
            },
        ];
        let specs = resolve_specs(&template, AttackType::Pitchfork, &sources).unwrap();
        let mut walk = RecursiveWalk::new(AttackType::Pitchfork, &specs).unwrap();
        assert_eq!(walk.next_attack(&template).unwrap().request, "csrf=&pw=p1");
        walk.feed(&[None, Some("T1".into())]);
        assert_eq!(
            walk.next_attack(&template).unwrap().request,
            "csrf=T1&pw=p2"
        );
        walk.feed(&[None, Some("T2".into())]);
        assert!(
            walk.next_attack(&template).is_none(),
            "the password list ran out"
        );
        assert!(resolve_specs(&template, AttackType::ClusterBomb, &sources).is_err());
    }

    fn illegal(
        max_bytes: u8,
        utf8: bool,
        utf8_permute: bool,
        hex: bool,
        hex_permute: bool,
        lower: bool,
    ) -> PayloadSource {
        PayloadSource::IllegalUnicode {
            items: set(&["..*etc*", "no-match"]),
            match_char: "*".into(),
            replace_char: "/".into(),
            max_bytes,
            max_encodings: 1000,
            illegal_utf8: utf8,
            utf8_permute,
            illegal_hex: hex,
            hex_permute,
            percent_prefix: true,
            lowercase: lower,
        }
    }

    #[test]
    fn illegal_unicode_follows_burps_encoding_table() {
        // Defaults: the byte and its 2-byte overlong form, items without '*' skipped.
        let d = PayloadSource::defaults()
            .into_iter()
            .find(|s| s.label() == "Illegal Unicode")
            .unwrap();
        assert_eq!(d.illegal_encodings(), ["%2f", "%c0%af"]);
        assert_eq!(
            illegal(2, false, false, false, false, true).generate(),
            ["..%2fetc%2f", "..%c0%afetc%c0%af"]
        );
        assert_eq!(
            illegal(3, false, false, false, false, false).illegal_encodings(),
            ["%2F", "%C0%AF", "%E0%80%AF"]
        );
        // Illegal continuation bytes: 00xxxxxx, 01xxxxxx, 11xxxxxx forms.
        assert_eq!(
            illegal(2, true, false, false, false, true).illegal_encodings(),
            ["%2f", "%c0%af", "%c0%2f", "%c0%6f", "%c0%ef"]
        );
        // Maximized permutations also yield the unchanged form, deduplicated.
        assert_eq!(
            illegal(2, true, true, false, false, true).illegal_encodings(),
            ["%2f", "%c0%af", "%c0%2f", "%c0%6f", "%c0%ef"]
        );
        assert_eq!(
            illegal(3, true, true, false, false, true)
                .illegal_encodings()
                .len(),
            3 + 3 + 15
        );
        // Illegal hex: every [0-9a-z] pair whose 16*hi+lo wraps to 0x2f.
        assert_eq!(
            illegal(1, false, false, true, false, true).illegal_encodings(),
            ["%1v", "%2f", "%hv", "%if", "%xv", "%yf"]
        );
        assert_eq!(illegal_hex_pairs(0x2F).len(), 6);
        let permuted = illegal(2, false, false, true, true, true).illegal_encodings();
        assert_eq!(
            permuted.len(),
            6 + illegal_hex_pairs(0xC0).len() * illegal_hex_pairs(0xAF).len()
        );
        assert_eq!(&permuted[6..8], ["%aw%9v", "%aw%af"]);
        let mut capped = illegal(2, false, false, true, true, true);
        if let PayloadSource::IllegalUnicode { max_encodings, .. } = &mut capped {
            *max_encodings = 4;
        }
        assert_eq!(capped.illegal_encodings().len(), 4);
        assert_eq!(capped.len(), 4);
    }

    #[test]
    fn effective_sources_take_simple_lists_from_the_set_text() {
        let texts = vec![
            " a \n\n b\r\n".to_string(),
            "ignored".to_string(),
            "x\ny".to_string(),
        ];
        let srcs = vec![
            PayloadSource::SimpleList {
                items: vec!["stale".into()],
            },
            PayloadSource::NullPayloads { count: 3 },
        ];
        let v = effective_sources(&texts, &srcs);
        assert_eq!(
            v[0],
            PayloadSource::SimpleList {
                items: vec!["a".into(), "b".into()]
            }
        );
        assert_eq!(v[1], PayloadSource::NullPayloads { count: 3 });
        // A set the panel never configured is a simple list, not dropped.
        assert_eq!(
            v[2],
            PayloadSource::SimpleList {
                items: vec!["x".into(), "y".into()]
            }
        );
    }

    #[test]
    fn request_count_matches_each_attack_type() {
        let req = "GET /?a=§1§&b=§2§ HTTP/1.1\r\nHost: h\r\n\r\n";
        let list = |n: usize| PayloadSource::SimpleList {
            items: (0..n).map(|i| i.to_string()).collect(),
        };
        let two = [list(3), list(4)];
        assert_eq!(
            request_count_fast(req, AttackType::Sniper, &two).as_deref(),
            Some("6"),
            "3 payloads x 2 positions"
        );
        assert_eq!(
            request_count_fast(req, AttackType::BatteringRam, &two).as_deref(),
            Some("3")
        );
        assert_eq!(
            request_count_fast(req, AttackType::Pitchfork, &two).as_deref(),
            Some("3"),
            "shortest set"
        );
        assert_eq!(
            request_count_fast(req, AttackType::ClusterBomb, &two).as_deref(),
            Some("12")
        );
        assert_eq!(
            request_count_fast("GET /§x HTTP/1.1\r\n\r\n", AttackType::Sniper, &two).as_deref(),
            Some("0"),
            "unbalanced markers"
        );
        // Copy and recursive sets need resolving.
        let copy = [
            list(3),
            PayloadSource::CopyOtherPayload { from_position: 1 },
        ];
        assert_eq!(request_count_fast(req, AttackType::Pitchfork, &copy), None);
        assert_eq!(
            request_count_resolved(req, AttackType::Pitchfork, &copy),
            "3"
        );
        let rec = [PayloadSource::RecursiveGrep {
            initial: "x".into(),
            extract_index: 0,
            stop_on_duplicate: false,
        }];
        assert_eq!(
            request_count_resolved(req, AttackType::Sniper, &rec),
            "unknown"
        );
    }

    #[test]
    fn results_order_appends_while_sorted_rows_stream_in() {
        let none = (usize::MAX, usize::MAX, false);
        assert_eq!(
            order_step(none, (5, usize::MAX, true), false, false),
            OrderStep::Rebuild,
            "first draw"
        );
        assert_eq!(
            order_step((5, 2, true), (5, 2, true), true, false),
            OrderStep::Keep
        );
        assert_eq!(
            order_step((5, 2, true), (8, 2, true), true, false),
            OrderStep::Append(5..8),
            "sorted view, just sorted"
        );
        assert_eq!(
            order_step((5, 2, true), (8, 2, true), false, false),
            OrderStep::Rebuild,
            "sort again after half a second"
        );
        assert_eq!(
            order_step((8, 2, true), (8, 2, true), false, true),
            OrderStep::Rebuild,
            "appended rows still to sort"
        );
        assert_eq!(
            order_step((8, 2, true), (8, 2, true), true, true),
            OrderStep::Keep
        );
        assert_eq!(
            order_step((5, 2, true), (5, 3, true), true, false),
            OrderStep::Rebuild,
            "another column"
        );
        assert_eq!(
            order_step((5, usize::MAX, true), (8, usize::MAX, true), true, false),
            OrderStep::Rebuild,
            "unsorted view numbers rows"
        );
    }
}
