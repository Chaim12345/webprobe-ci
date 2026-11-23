//! Burp's response-variation engine, ported from build 52685.
//!
//! Burp's differential checks (LDAP injection, boolean SQL injection, ...)
//! decide "these two kinds of request get different responses" with this
//! machinery, not with a length threshold:
//!
//! * `fingerprint` = burp.Zx33: each response is reduced to integer
//!   attributes (burp.Zb6a). String attributes are java.util.zip.CRC32 over
//!   the low byte of each char (CRC32.update(int) keeps the low 8 bits), as
//!   in burp.Zsgf.ZB.
//! * `Side` = burp.Zr2x: attribute values seeded from one sample; a sample
//!   of the same side removes attributes that changed (ZO), a sample of the
//!   other side removes attributes that are equal (Ze).
//! * `Comparator` = burp.Zsnr: two sides; distinguishable while either side
//!   keeps an attribute (ZK). CREDIT_CARD_COUNT, SOCIAL_SECURITY_NUMBER_COUNT,
//!   EMAIL_ADDRESS_COUNT and JSON_NODE_COUNT are excluded (Zsnr.Zk) and are
//!   not computed here.
//! * `differential` = burp.Zmaq: n rounds (4/6/10 for minimise false
//!   negatives / normal / minimise false positives, Zmaq.ZA; NORMAL is
//!   Burp's default scan_accuracy), alternating which side gets the next
//!   sample, failing as soon as the sides become indistinguishable.
//!
//! The six navigation-model attributes (POTENTIAL_ACTION_COUNT,
//! POTENTIAL_ACTION_TAG_NAMES, ANCHOR_LABELS, INPUT_SUBMIT_LABELS,
//! INPUT_IMAGE_LABELS, NON_HIDDEN_FORM_INPUT_TYPES) come from Burp's
//! browser navigation model (burp.Zxpm implementations over Zb6n); they are
//! approximated from anchors, forms and inputs here.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attr {
    StatusCode,
    EtagHeader,
    LastModifiedHeader,
    ContentType,
    ContentTypeCharset,
    ContentLength,
    CookieNames,
    TagNames,
    TagIds,
    DivIds,
    BodyContent,
    VisibleText,
    WordCount,
    VisibleWordCount,
    Comments,
    InitialContent,
    CanonicalLink,
    PageTitle,
    FirstHeaderTag,
    HeaderTags,
    AnchorLabels,
    InputSubmitLabels,
    ButtonSubmitLabels,
    CssClasses,
    LineCount,
    LimitedBodyContent,
    PotentialActionCount,
    PotentialActionTagNames,
    InputImageLabels,
    ContentLocation,
    Location,
    NonHiddenFormInputTypes,
    ColonCount,
    HeadersNames,
}

pub type Fingerprint = BTreeMap<Attr, i32>;

/// burp.Zsgf: CRC32 fed with the low byte of each char.
#[derive(Default)]
struct Crc(flate2::Crc);

impl Crc {
    fn str(&mut self, s: &str) {
        let b: Vec<u8> = s.chars().map(|c| c as u32 as u8).collect();
        self.0.update(&b);
    }
    fn byte(&mut self, b: u8) {
        self.0.update(&[b]);
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.update(b);
    }
    fn value(&self) -> i32 {
        self.0.sum() as i32
    }
}

fn crc_of(s: &str) -> i32 {
    let mut c = Crc::default();
    c.bytes(s.as_bytes());
    c.value()
}

/// Java's `byte <= 32` on a signed byte: control/space and every byte >= 0x80.
fn java_space(b: u8) -> bool {
    (b as i8) <= 32
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Start(String, Vec<(String, String)>),
    End(String),
    Comment(String),
    Text(String),
    SelfClose(String, Vec<(String, String)>),
}

impl Tok {
    /// burp.Zbpq.ZGU token type codes.
    fn code(&self) -> u8 {
        match self {
            Tok::Start(..) => 0,
            Tok::End(_) => 1,
            Tok::Comment(_) => 2,
            Tok::Text(_) => 3,
            Tok::SelfClose(..) => 4,
        }
    }
    fn name(&self) -> &str {
        match self {
            Tok::Start(n, _) | Tok::End(n) | Tok::SelfClose(n, _) => n,
            _ => "",
        }
    }
    fn attr(&self, key: &str) -> Option<&str> {
        match self {
            Tok::Start(_, a) | Tok::SelfClose(_, a) => {
                a.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
            }
            _ => None,
        }
    }
    fn is_open(&self, name: &str) -> bool {
        matches!(self, Tok::Start(n, _) if n == name)
    }
    fn is_close(&self, name: &str) -> bool {
        matches!(self, Tok::End(n) if n == name)
    }
    fn is_start_or_self(&self) -> bool {
        matches!(self, Tok::Start(..) | Tok::SelfClose(..))
    }
}

fn parse_attrs(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'/' {
            i += 1;
        }
        if ks == i {
            break;
        }
        let key = s[ks..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut val = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                val = s[vs..i].to_string();
                i += 1;
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                val = s[vs..i].to_string();
            }
        }
        out.push((key, val));
    }
    out
}

/// A small HTML tokenizer producing Burp's five token kinds. Script and
/// style bodies are one raw text token.
fn tokenize(html: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = html.len();
    while i < n {
        let Some(lt) = html[i..].find('<').map(|x| x + i) else {
            out.push(Tok::Text(html[i..].to_string()));
            break;
        };
        if lt > i {
            out.push(Tok::Text(html[i..lt].to_string()));
        }
        let rest = &html[lt..];
        if let Some(body) = rest.strip_prefix("<!--") {
            let end = body.find("-->").unwrap_or(body.len());
            out.push(Tok::Comment(body[..end].to_string()));
            i = (lt + end + 7).min(n);
            continue;
        }
        let Some(gt) = rest.find('>') else {
            out.push(Tok::Text(rest.to_string()));
            break;
        };
        let inner = &rest[1..gt];
        i = lt + gt + 1;
        if inner.starts_with('!') || inner.starts_with('?') {
            continue;
        }
        if let Some(name) = inner.strip_prefix('/') {
            out.push(Tok::End(name.trim().to_ascii_lowercase()));
            continue;
        }
        let name_end = inner
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(inner.len());
        let name = inner[..name_end].to_ascii_lowercase();
        if name.is_empty() {
            out.push(Tok::Text(rest[..gt + 1].to_string()));
            continue;
        }
        let attrs = parse_attrs(&inner[name_end..]);
        if inner.trim_end().ends_with('/') {
            out.push(Tok::SelfClose(name, attrs));
        } else {
            let raw = name == "script" || name == "style";
            out.push(Tok::Start(name.clone(), attrs));
            if raw {
                let close = format!("</{name}");
                let lower = html[i..].to_ascii_lowercase();
                let end = lower.find(&close).map(|x| x + i).unwrap_or(n);
                if end > i {
                    out.push(Tok::Text(html[i..end].to_string()));
                }
                i = end;
            }
        }
    }
    out
}

const HEADER_TAGS: [&str; 6] = ["h1", "h2", "h3", "h4", "h5", "h6"];

fn is_header_open(t: &Tok) -> bool {
    matches!(t, Tok::Start(n, _) if HEADER_TAGS.contains(&n.as_str()))
}
fn is_header_close(t: &Tok) -> bool {
    matches!(t, Tok::End(n) if HEADER_TAGS.contains(&n.as_str()))
}

/// burp.Zx33: the response attributes Burp compares.
pub fn fingerprint(resp: &[u8]) -> Fingerprint {
    let mut fp = Fingerprint::new();
    let p = crate::util::parse_http(resp);
    let body = &resp[p.head_len.min(resp.len())..];

    // status (ZY)
    fp.insert(
        Attr::StatusCode,
        p.status.trim().parse::<i32>().unwrap_or(0),
    );

    // headers (Ze): first value of each tracked header, CRC32 of the trimmed value
    let first = |name: &str| {
        p.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    for (name, attr) in [
        ("Location", Attr::Location),
        ("Content-Location", Attr::ContentLocation),
        ("ETag", Attr::EtagHeader),
        ("Last-Modified", Attr::LastModifiedHeader),
    ] {
        if let Some(v) = first(name) {
            fp.insert(attr, crc_of(&v));
        }
    }
    // Content-Length header, else the body length (Zhat)
    let cl = first("Content-Length")
        .map(|v| v.parse::<i32>().unwrap_or(0))
        .unwrap_or(body.len() as i32);
    fp.insert(Attr::ContentLength, cl);
    // Set-Cookie names, sorted and unique (Zhhh); only when there are any
    let cookies: BTreeSet<String> = p
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
        .filter_map(|(_, v)| v.split_once('=').map(|(n, _)| n.trim_start().to_string()))
        .collect();
    if !cookies.is_empty() {
        let mut c = Crc::default();
        cookies.iter().for_each(|n| c.str(n));
        fp.insert(Attr::CookieNames, c.value());
    }
    // header names in order (Zb8s)
    let mut hn = Crc::default();
    p.headers.iter().for_each(|(k, _)| hn.str(k));
    fp.insert(Attr::HeadersNames, hn.value());
    // content type and charset (ZS)
    if let Some(ct) = first("Content-Type") {
        let mut parts = ct.split(';');
        let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        fp.insert(Attr::ContentType, crc_of(&media));
        if let Some(cs) = parts.find_map(|x| {
            x.trim()
                .strip_prefix("charset=")
                .map(|v| v.trim_matches('"').to_ascii_lowercase())
        }) {
            fp.insert(Attr::ContentTypeCharset, crc_of(&cs));
        }
    }
    if let Some(link) = first("Link") {
        if link.to_ascii_lowercase().contains("rel=\"canonical\"")
            || link.to_ascii_lowercase().contains("rel=canonical")
        {
            if let Some(u) = link
                .split('>')
                .next()
                .and_then(|x| x.trim().strip_prefix('<'))
            {
                fp.insert(Attr::CanonicalLink, crc_of(u));
            }
        }
    }

    // raw-body attributes (ZJ)
    let mut bc = Crc::default();
    bc.bytes(body);
    fp.insert(Attr::BodyContent, bc.value());
    let mut lc = Crc::default();
    if body.len() < 2048 {
        lc.bytes(body);
    } else {
        lc.bytes(&body[..1024]);
        lc.bytes(&body[body.len() - 1024..]);
    }
    fp.insert(Attr::LimitedBodyContent, lc.value());
    let mut ic = Crc::default();
    ic.bytes(
        &body[..body
            .iter()
            .position(|b| java_space(*b))
            .unwrap_or(body.len())],
    );
    fp.insert(Attr::InitialContent, ic.value());
    let mut lines = body.iter().filter(|b| **b == b'\n').count() as i32;
    if body.last().is_some_and(|b| *b != b'\n') {
        lines += 1;
    }
    fp.insert(Attr::LineCount, lines);
    let mut words = 0i32;
    let mut in_word = false;
    for b in body {
        if java_space(*b) {
            if in_word {
                words += 1;
                in_word = false;
            }
        } else {
            in_word = true;
        }
    }
    if in_word {
        words += 1;
    }
    fp.insert(Attr::WordCount, words);
    // colons over the whole message (Z_ / Zxqy)
    fp.insert(
        Attr::ColonCount,
        resp.iter().filter(|b| **b == b':').count() as i32,
    );

    // HTML attributes (Zr), only for real markup (Zx33.ZU)
    let html: String = body.iter().map(|b| *b as char).collect();
    let toks = tokenize(&html);
    let markup = !toks.is_empty() && !(toks.len() == 1 && matches!(toks[0], Tok::Text(_)));
    if markup {
        html_attributes(&toks, &mut fp);
    }
    fp
}

fn html_attributes(toks: &[Tok], fp: &mut Fingerprint) {
    let (mut tag_names, mut tag_ids, mut div_ids, mut comments) = (
        Crc::default(),
        Crc::default(),
        Crc::default(),
        Crc::default(),
    );
    let mut classes = BTreeSet::new();
    let (mut title, mut first_h, mut headers, mut vis, mut buttons) = (
        Crc::default(),
        Crc::default(),
        Crc::default(),
        Crc::default(),
        Crc::default(),
    );
    let (mut in_title, mut title_done, mut in_fh, mut fh_done, mut in_h) =
        (false, false, false, false, false);
    let (mut skip_title, mut skip_script, mut vis_words) = (false, false, 0i32);
    let (mut in_form, mut in_button) = (false, false);
    let mut canonical: Option<String> = None;
    // navigation-model approximations (see module docs)
    let (
        mut actions,
        mut action_tags,
        mut anchor_labels,
        mut input_submit,
        mut input_image,
        mut input_types,
    ) = (
        0i32,
        Crc::default(),
        Crc::default(),
        Crc::default(),
        Crc::default(),
        Crc::default(),
    );
    let (mut in_anchor, mut first_anchor_label) = (false, true);

    for t in toks {
        // TAG_NAMES (Zcux): start/end/self-closing tags, name + type code
        if matches!(t, Tok::Start(..) | Tok::End(_) | Tok::SelfClose(..)) {
            tag_names.str(t.name());
            tag_names.byte(t.code());
        }
        if t.is_start_or_self() {
            if let Some(id) = t.attr("id") {
                tag_ids.str(id);
                if t.name() == "div" {
                    div_ids.str(id);
                }
            }
            if let Some(c) = t.attr("class") {
                classes.insert(c.to_string());
            }
            if canonical.is_none()
                && t.name() == "link"
                && matches!(t, Tok::SelfClose(..))
                && t.attr("rel") == Some("canonical")
            {
                canonical = t.attr("href").map(str::to_string);
            }
            match t.name() {
                "a" if t.attr("href").is_some() => {
                    actions += 1;
                    action_tags.str("a");
                }
                "form" => {
                    actions += 1;
                    action_tags.str("form");
                }
                "input" => {
                    let ty = t.attr("type").unwrap_or("text").to_ascii_lowercase();
                    if ty == "submit" {
                        input_submit.str(t.attr("value").unwrap_or(""));
                    }
                    if ty == "image" {
                        let label = t
                            .attr("alt")
                            .filter(|a| !a.trim().is_empty())
                            .or(t.attr("src"))
                            .unwrap_or("");
                        input_image.str(label);
                    }
                    if ty != "hidden" {
                        input_types.str(&ty);
                    }
                }
                _ => {}
            }
        }
        if t.is_open("a") {
            in_anchor = true;
        } else if t.is_close("a") {
            in_anchor = false;
        }
        if let Tok::Comment(c) = t {
            comments.str(c);
        }
        // PAGE_TITLE (Zfhr): text inside the first <title>
        if !title_done {
            if in_title {
                if t.is_close("title") {
                    in_title = false;
                    title_done = true;
                } else if let Tok::Text(x) = t {
                    title.str(x);
                }
            } else if t.is_open("title") {
                in_title = true;
            }
        }
        // FIRST_HEADER_TAG (Zijw) and HEADER_TAGS (Zpov)
        if !fh_done {
            if in_fh {
                if is_header_close(t) {
                    in_fh = false;
                    fh_done = true;
                } else if let Tok::Text(x) = t {
                    first_h.str(x);
                }
            } else if is_header_open(t) {
                in_fh = true;
            }
        }
        if in_h {
            if is_header_close(t) {
                in_h = false;
            } else if let Tok::Text(x) = t {
                headers.str(x);
            }
        } else if is_header_open(t) {
            in_h = true;
        }
        // BUTTON_SUBMIT_LABELS (Zbih): <button type=submit> text inside a form
        if in_form {
            if t.is_close("form") {
                in_form = false;
            } else if in_button {
                if t.is_close("button") {
                    in_button = false;
                } else if let Tok::Text(x) = t {
                    buttons.str(x);
                }
            } else if t.is_open("button") && t.attr("type") == Some("submit") {
                in_button = true;
            }
        } else if t.is_open("form") {
            in_form = true;
        }
        // VISIBLE_TEXT / VISIBLE_WORD_COUNT (Zeso): text outside title/script
        if skip_title {
            if t.is_close("title") {
                skip_title = false;
            }
        } else if skip_script {
            if t.is_close("script") {
                skip_script = false;
            }
        } else if let Tok::Text(x) = t {
            let chars: Vec<char> = x.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                if !chars[i].is_whitespace() {
                    vis.byte(chars[i] as u32 as u8);
                    i += 1;
                } else {
                    vis.byte(32);
                    while i < chars.len() && chars[i].is_whitespace() {
                        i += 1;
                    }
                }
            }
            let mut j = 0;
            while j < chars.len() {
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if j < chars.len() {
                    vis_words += 1;
                }
                while j < chars.len() && !chars[j].is_whitespace() {
                    j += 1;
                }
            }
            if in_anchor {
                if !first_anchor_label {
                    anchor_labels.str(" ");
                }
                anchor_labels.str(x);
                first_anchor_label = false;
            }
        } else if t.is_open("title") {
            skip_title = true;
        } else if t.is_open("script") {
            skip_script = true;
        }
    }
    let mut css = Crc::default();
    classes.iter().for_each(|c| css.str(c));
    for (attr, crc) in [
        (Attr::TagNames, tag_names),
        (Attr::TagIds, tag_ids),
        (Attr::DivIds, div_ids),
        (Attr::Comments, comments),
        (Attr::CssClasses, css),
        (Attr::PageTitle, title),
        (Attr::FirstHeaderTag, first_h),
        (Attr::HeaderTags, headers),
        (Attr::VisibleText, vis),
        (Attr::ButtonSubmitLabels, buttons),
        (Attr::PotentialActionTagNames, action_tags),
        (Attr::AnchorLabels, anchor_labels),
        (Attr::InputSubmitLabels, input_submit),
        (Attr::InputImageLabels, input_image),
        (Attr::NonHiddenFormInputTypes, input_types),
    ] {
        fp.insert(attr, crc.value());
    }
    fp.insert(Attr::VisibleWordCount, vis_words);
    fp.insert(Attr::PotentialActionCount, actions);
    if let Some(c) = canonical {
        let mut x = Crc::default();
        x.str(&c);
        fp.insert(Attr::CanonicalLink, x.value());
    }
}

const ALL: [Attr; 34] = [
    Attr::StatusCode,
    Attr::EtagHeader,
    Attr::LastModifiedHeader,
    Attr::ContentType,
    Attr::ContentTypeCharset,
    Attr::ContentLength,
    Attr::CookieNames,
    Attr::TagNames,
    Attr::TagIds,
    Attr::DivIds,
    Attr::BodyContent,
    Attr::VisibleText,
    Attr::WordCount,
    Attr::VisibleWordCount,
    Attr::Comments,
    Attr::InitialContent,
    Attr::CanonicalLink,
    Attr::PageTitle,
    Attr::FirstHeaderTag,
    Attr::HeaderTags,
    Attr::AnchorLabels,
    Attr::InputSubmitLabels,
    Attr::ButtonSubmitLabels,
    Attr::CssClasses,
    Attr::LineCount,
    Attr::LimitedBodyContent,
    Attr::PotentialActionCount,
    Attr::PotentialActionTagNames,
    Attr::InputImageLabels,
    Attr::ContentLocation,
    Attr::Location,
    Attr::NonHiddenFormInputTypes,
    Attr::ColonCount,
    Attr::HeadersNames,
];

/// burp.Zeua.Za: an attribute that was never set reads as 0.
fn get(fp: &Fingerprint, a: Attr) -> i32 {
    fp.get(&a).copied().unwrap_or(0)
}

/// burp.Zr2x.
#[derive(Clone, Debug)]
struct Side(BTreeMap<Attr, i32>);

impl Side {
    fn seed(fp: &Fingerprint) -> Self {
        Side(ALL.iter().map(|a| (*a, get(fp, *a))).collect())
    }
    /// ZO: same-side sample; drop attributes that changed.
    fn own(&mut self, fp: &Fingerprint) {
        self.0.retain(|a, v| *v == get(fp, *a));
    }
    /// Ze: other-side sample; drop attributes that are equal.
    fn other(&mut self, fp: &Fingerprint) {
        self.0.retain(|a, v| *v != get(fp, *a));
    }
}

/// burp.Zsnr.
#[derive(Clone, Debug)]
pub struct Comparator {
    a: Side,
    b: Side,
}

impl Comparator {
    pub fn new(a: &Fingerprint, b: &Fingerprint) -> Self {
        let mut c = Comparator {
            a: Side::seed(a),
            b: Side::seed(b),
        };
        c.add_a(a);
        c.add_b(b);
        c
    }
    /// Zsnr.Zz
    pub fn add_a(&mut self, fp: &Fingerprint) {
        self.a.own(fp);
        self.b.other(fp);
    }
    /// Zsnr.ZE
    pub fn add_b(&mut self, fp: &Fingerprint) {
        self.b.own(fp);
        self.a.other(fp);
    }
    /// Zsnr.ZK
    pub fn distinguishable(&self) -> bool {
        !self.a.0.is_empty() || !self.b.0.is_empty()
    }
    /// The attributes that still separate the two sides (Zsnr.Ze report).
    pub fn attributes(&self) -> Vec<Attr> {
        let mut v: Vec<Attr> = self.a.0.keys().chain(self.b.0.keys()).copied().collect();
        v.sort();
        v.dedup();
        v
    }
}

/// burp.Zgnf / Zmaq.ZA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accuracy {
    MinimizeFalseNegatives,
    Normal,
    MinimizeFalsePositives,
}

impl Accuracy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Accuracy::MinimizeFalseNegatives,
            2 => Accuracy::MinimizeFalsePositives,
            _ => Accuracy::Normal,
        }
    }
    pub fn rounds(self) -> usize {
        match self {
            Accuracy::MinimizeFalseNegatives => 4,
            Accuracy::Normal => 6,
            Accuracy::MinimizeFalsePositives => 10,
        }
    }
}

/// burp.Zmaq.Zq/ZP: the differential driver. `positive` and `negative`
/// each send the next payload of their kind (callers vary payloads per
/// call, as Burp does) and return the raw response. With a baseline, the
/// baseline seeds the positive side. Returns the distinguishing attributes
/// when the sides stayed distinguishable for every round.
pub fn differential(
    baseline: Option<&[u8]>,
    accuracy: Accuracy,
    mut positive: impl FnMut() -> Option<Vec<u8>>,
    mut negative: impl FnMut() -> Option<Vec<u8>>,
) -> Option<Vec<Attr>> {
    let mut cmp: Option<Comparator> = None;
    let mut flip = false;
    for _ in 0..accuracy.rounds() {
        let ok = match cmp.as_mut() {
            None => {
                let first = match baseline {
                    Some(b) => fingerprint(b),
                    None => fingerprint(&positive()?),
                };
                let mut c = Comparator::new(&first, &fingerprint(&negative()?));
                let ok = c.distinguishable()
                    && (baseline.is_none() || {
                        c.add_a(&fingerprint(&positive()?));
                        c.distinguishable()
                    });
                cmp = Some(c);
                ok
            }
            Some(c) => {
                let mut step = |pos: bool, c: &mut Comparator| -> Option<bool> {
                    if pos {
                        c.add_a(&fingerprint(&positive()?));
                    } else {
                        c.add_b(&fingerprint(&negative()?));
                    }
                    Some(c.distinguishable())
                };
                // Zmaq: Zu ? (ZV && Zn) : (Zn && ZV); ZV = positive, Zn = negative
                let (x, y) = if flip { (true, false) } else { (false, true) };
                step(x, c)? && step(y, c)?
            }
        };
        if !ok {
            return None;
        }
        flip = !flip;
    }
    cmp.map(|c| c.attributes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn crc_matches_java_char_semantics() {
        // java.util.zip.CRC32 over "abc" = 0x352441c2
        let mut c = Crc::default();
        c.str("abc");
        assert_eq!(c.value() as u32, 0x352441c2);
        // a char above 0xFF contributes only its low byte (CRC32.update(int))
        let mut d = Crc::default();
        d.str("\u{0161}");
        let mut e = Crc::default();
        e.byte(0x61);
        assert_eq!(d.value(), e.value());
        assert!(java_space(b' ') && java_space(0xC3) && !java_space(b'a'));
    }

    #[test]
    fn fingerprint_reads_burp_attributes() {
        let r = resp(200, "<html><head><title>Hi there</title></head><body><h1>Top</h1><div id=\"d\" class=\"x\">one two</div><!--c--><form><button type=\"submit\">Go</button></form></body></html>");
        let fp = fingerprint(&r);
        assert_eq!(fp[&Attr::StatusCode], 200);
        assert_eq!(
            fp[&Attr::ContentLength] as usize,
            r.len() - r.windows(4).position(|w| w == b"\r\n\r\n").unwrap() - 4
        );
        assert_eq!(
            fp[&Attr::VisibleWordCount],
            4,
            "Top one two Go (title excluded)"
        );
        assert_ne!(fp[&Attr::PageTitle], 0);
        assert_ne!(fp[&Attr::ButtonSubmitLabels], 0);
        // plain text: no HTML attributes at all
        let t = fingerprint(&resp(200, "just words"));
        assert!(!t.contains_key(&Attr::TagNames));
        assert_eq!(t[&Attr::WordCount], 2);
        assert_eq!(t[&Attr::LineCount], 1);
    }

    #[test]
    fn comparator_follows_zr2x_rules() {
        let a = fingerprint(&resp(200, "<p>found 3 entries</p>"));
        let b = fingerprint(&resp(200, "<p>no entries</p>"));
        let mut c = Comparator::new(&a, &b);
        assert!(c.distinguishable());
        // same pages on both sides: nothing distinguishes them
        let mut same = Comparator::new(&a, &a);
        assert!(!same.distinguishable());
        same.add_b(&b);
        assert!(!same.distinguishable());
        // a second, different positive sample removes attributes that changed
        c.add_a(&fingerprint(&resp(200, "<p>found 4 entries</p>")));
        assert!(
            c.distinguishable(),
            "word count still separates 3 words from 2"
        );
        assert!(c.attributes().contains(&Attr::WordCount));
        assert!(
            !c.a.0.contains_key(&Attr::BodyContent),
            "body varied within the positive side"
        );
        // ...but the negative side's body is still constant and unlike every positive sample
        assert!(c.b.0.contains_key(&Attr::BodyContent));
    }

    #[test]
    fn differential_needs_consistent_separation() {
        let t = || Some(resp(200, "<ul><li>alice</li><li>bob</li></ul>"));
        let f = || Some(resp(200, "<p>none</p>"));
        let attrs = differential(Some(&t().unwrap()), Accuracy::Normal, t, f)
            .expect("true/false differ consistently");
        assert!(attrs.contains(&Attr::TagNames));
        // random noise on one side: no stable distinguishing attribute
        let mut n = 0;
        let noisy = move || {
            n += 1;
            Some(resp(200, &format!("<p>{}</p>", "x ".repeat(n))))
        };
        assert!(differential(None, Accuracy::Normal, noisy, noisy).is_none());
        // a request failure aborts
        assert!(differential(None, Accuracy::Normal, || None, f).is_none());
    }
}
