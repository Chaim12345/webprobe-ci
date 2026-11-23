// Insertion point vocabulary, moved from core insertion.rs (L8, issue #38):
// the kinds, the point type, wording, skip lists and type names. Pure data
// and string logic over support::util, so modules that only name points
// (stored) no longer pull scan into their graph. The builder and payload
// placement stay in core insertion.rs.

use crate::util;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpKind {
    Query,
    Body,
    /// JSON value at a path of object keys / array indices.
    Json(Vec<String>),
    /// multipart/form-data part `index` (0-based); `filename` is set for a
    /// file-upload part (burp.Zsdt / Ziqg, the parts with a filename attribute).
    Multipart {
        index: usize,
        filename: Option<String>,
    },
    /// A cookie in the Cookie header (Zg6r.COOKIE).
    Cookie,
    /// A request header value (Zbg8.HEADER); added when absent (Referer).
    Header,
    /// '/'-separated path segment index (Zg6r.PATH_FOLDER_PARAM).
    PathFolder(usize),
    /// '/'-separated path segment index of the last segment (PATH_FILENAME_PARAM).
    PathFilename(usize),
    /// The whole body of an XML or JSON request (Zbg8.ENTIRE_BODY, Zuq.ZT).
    EntireBody,
    /// Text of an XML element, raw range `start..end` (Zbg8.XML_PARAM from the
    /// request parser, burp.Zhjs: a text token, or the empty value between a
    /// start tag and its end tag).
    XmlParam {
        start: usize,
        end: usize,
    },
    /// A self-closing XML element turned into `<tag>value</tag>`
    /// (Zbg8.XML_PARAM, Zuq.addStandaloneTagInsertionPoint): `close` is
    /// where `/>` starts (spaces before `/` included), `end` is just after
    /// the `>`.
    XmlTag {
        close: usize,
        end: usize,
    },
    /// Value of an XML attribute, raw range `start..end` inside its quotes
    /// (Zbg8.XML_ATTR).
    XmlAttr {
        start: usize,
        end: usize,
    },
    /// Name of an added `1=1` parameter (Zbg8.PARAM_NAME_*, Zuq.Zp).
    ParamName(NameSite),
    /// A Base64 (or Base64url) value decoded from its parent
    /// (Zbg8.BASE64_ENCODED / BASE64URL_ENCODED, Zuq.ZS). Always nested.
    Base64 {
        url: bool,
    },
}

/// Where a parameter-name point adds its `1=1` parameter (Zuq.Zp).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameSite {
    /// `1=1` added to the query string (PARAM_NAME_URL).
    Url,
    /// `1=1` added to a URL-encoded body (PARAM_NAME_BODY_URL_ENCODED).
    Body,
    /// A part named `1` added to a multipart body (PARAM_NAME_BODY_MULTIPART).
    Multipart,
    /// `/1` appended to a `.php` path (Zuq.addPhpFileRequestInsertionPoint,
    /// typed PARAM_NAME_URL).
    PhpPathInfo,
}

/// Burp's point type (burp.Zbg8) of a kind: what the wording (Zsg0), the
/// skip lists (burp.Zsc3.ZQ) and the encoders (burp.Zfw9) key on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointType {
    UrlParam,
    BodyParamUrlEncoded,
    BodyParamMultipart,
    Cookie,
    XmlParam,
    XmlAttr,
    PathFolder,
    PathFilename,
    JsonParam,
    ParamNameUrl,
    ParamNameBodyUrlEncoded,
    ParamNameBodyMultipart,
    Header,
    EntireBody,
    Base64,
    Base64Url,
}

impl IpKind {
    pub fn point_type(&self) -> PointType {
        match self {
            IpKind::Query => PointType::UrlParam,
            IpKind::Body => PointType::BodyParamUrlEncoded,
            IpKind::Json(_) => PointType::JsonParam,
            IpKind::Multipart { .. } => PointType::BodyParamMultipart,
            IpKind::Cookie => PointType::Cookie,
            IpKind::Header => PointType::Header,
            IpKind::PathFolder(_) => PointType::PathFolder,
            IpKind::PathFilename(_) => PointType::PathFilename,
            IpKind::EntireBody => PointType::EntireBody,
            IpKind::XmlParam { .. } | IpKind::XmlTag { .. } => PointType::XmlParam,
            IpKind::XmlAttr { .. } => PointType::XmlAttr,
            IpKind::ParamName(NameSite::Url | NameSite::PhpPathInfo) => PointType::ParamNameUrl,
            IpKind::ParamName(NameSite::Body) => PointType::ParamNameBodyUrlEncoded,
            IpKind::ParamName(NameSite::Multipart) => PointType::ParamNameBodyMultipart,
            IpKind::Base64 { url: false } => PointType::Base64,
            IpKind::Base64 { url: true } => PointType::Base64Url,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InsertionPoint {
    pub kind: IpKind,
    pub name: String,
    /// The base value: decoded for the kinds Burp decodes (form body, XML,
    /// Base64, nested URL parameters); a query or cookie value is kept as
    /// sent (see [`InsertionPoint::decoded_value`]).
    pub value: String,
    /// For a nested point (burp.Zhs3), the point whose decoded value holds it.
    pub parent: Option<Box<InsertionPoint>>,
}

impl InsertionPoint {
    pub fn new(kind: IpKind, name: impl Into<String>, value: impl Into<String>) -> Self {
        InsertionPoint {
            kind,
            name: name.into(),
            value: value.into(),
            parent: None,
        }
    }

    pub fn nested(
        parent: &InsertionPoint,
        kind: IpKind,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        InsertionPoint {
            kind,
            name: name.into(),
            value: value.into(),
            parent: Some(Box::new(parent.clone())),
        }
    }

    /// The base value as Burp's point encoder decodes it (burp.Zr4u runs
    /// the type's Zifl decoder over the raw value): a query parameter or a
    /// cookie URL-decoded, every other kind as stored.
    pub fn decoded_value(&self) -> String {
        match (&self.kind, &self.parent) {
            (IpKind::Query | IpKind::Cookie, None) => util::url_decode(&self.value),
            _ => self.value.clone(),
        }
    }

    /// The content nested points of this one index into: the decoded value,
    /// trimmed (burp.Zuq.ZV: `Zy().trim()`).
    pub fn nested_content(&self) -> String {
        self.decoded_value().trim().to_string()
    }

    /// The points from the outermost to this one (burp.Zhs3.Zn: the parent's
    /// list, then the child's).
    pub fn chain(&self) -> Vec<&InsertionPoint> {
        let mut v = vec![self];
        let mut cur = self;
        while let Some(p) = cur.parent.as_deref() {
            v.push(p);
            cur = p;
        }
        v.reverse();
        v
    }

    /// burp.Zsg0.ZD: "value of the q request parameter", "Base64-decoded
    /// value of the data parameter", "name of an arbitrarily supplied URL
    /// parameter", ...
    pub fn describe(&self) -> String {
        describe_chain(&self.chain(), true, false)
    }

    /// burp.Zsg0.ZD(…, true, true), as Burp's issue texts print it: "value
    /// of the <b>q</b> request parameter".
    pub fn describe_bold(&self) -> String {
        describe_chain(&self.chain(), true, true)
    }

    /// burp.Zsg0.Zj: "q parameter", "sid cookie", "request body", ...;
    /// `bold` wraps the name in `<b>` as Burp's issue texts do.
    pub fn describe_short(&self, bold: bool) -> String {
        describe_chain(&self.chain(), false, bold)
    }

    /// True when Burp's skip_server_side_injection_for_parameters list
    /// matches this point (burp.Ziqf.Zr -> Ze9d.Ze: the point's own type,
    /// name and value; ancestors are not consulted).
    pub fn skips_server_side(&self) -> bool {
        rule_hits(SKIP_SERVER_SIDE, self)
    }
}

// ---------------------------------------------------------------- wording

/// burp.Zsg0.Zy (short form) and Zsg0.ZX (`value_form`) for one point.
pub fn point_label(t: PointType, name: &str, value_form: bool, bold: bool) -> String {
    // Zsg0.Zj(…, html, bold): the name HTML-escaped (Zucz.ZL) inside <b>.
    let n = if bold {
        format!("<b>{}</b>", util::html_encode(name))
    } else {
        name.to_string()
    };
    let named = |what: &str| {
        if value_form {
            format!("value of the {n} {what}")
        } else {
            format!("{n} {what}")
        }
    };
    match t {
        PointType::UrlParam | PointType::BodyParamUrlEncoded | PointType::BodyParamMultipart => {
            if value_form {
                format!("value of the {n} request parameter")
            } else {
                format!("{n} parameter")
            }
        }
        PointType::Cookie => named("cookie"),
        PointType::XmlParam => named("XML parameter"),
        PointType::XmlAttr => named("XML attribute"),
        PointType::Header => named("HTTP header"),
        PointType::JsonParam => named("JSON parameter"),
        PointType::ParamNameUrl => "name of an arbitrarily supplied URL parameter".into(),
        PointType::ParamNameBodyUrlEncoded | PointType::ParamNameBodyMultipart => {
            "name of an arbitrarily supplied body parameter".into()
        }
        // Zsg0 case 13 appends the folder's name (no bold) to the label;
        // WebProbe names folders "URL path folder N" already.
        PointType::PathFolder => {
            let num = name.strip_prefix("URL path folder ").unwrap_or(name);
            if value_form {
                format!("value of the URL path folder {num}")
            } else {
                format!("URL path folder {num}")
            }
        }
        PointType::PathFilename => if value_form {
            "value of the URL path filename"
        } else {
            "URL path filename"
        }
        .into(),
        PointType::EntireBody => if value_form {
            "value of the request body"
        } else {
            "request body"
        }
        .into(),
        PointType::Base64 => "Base64-decoded value".into(),
        PointType::Base64Url => "Base64Url-decoded value".into(),
    }
}

/// burp.Zsg0.ZH: innermost point first; a Base64 level is followed by
/// " of the ", any other by " within the " (", within the " from three
/// levels on).
pub fn describe_chain(chain: &[&InsertionPoint], value_form: bool, bold: bool) -> String {
    let n = chain.len();
    let mut s = String::new();
    for i in (0..n).rev() {
        let t = chain[i].kind.point_type();
        s.push_str(&point_label(
            t,
            &chain[i].name,
            value_form && i == n - 1,
            bold,
        ));
        if n > 1 && i > 0 {
            if matches!(t, PointType::Base64 | PointType::Base64Url) {
                s.push_str(" of the ");
            } else {
                if n > 2 {
                    s.push(',');
                }
                s.push_str(" within the ");
            }
        }
    }
    s
}

// ---------------------------------------------------------------- skip lists

/// The `parameter` of a skip rule (burp.Zsc3.ZQ: the rule's type matched
/// against the point type; `any_parameter` matches every type).
#[derive(Clone, Copy)]
enum RuleParam {
    Any,
    Body,
    Cookie,
    XmlAttr,
}

/// `match_type` of a skip rule on the parameter name (burp.Zsc3.Ze):
/// `is` compares ignoring case; `matches_regex` runs Matcher.find() with
/// CASE_INSENSITIVE|DOTALL (burp.Zx6z, flags 34). Every shipped regex is
/// `<literal>.*`, so find() is "contains the literal, ignoring case".
#[derive(Clone, Copy)]
enum RuleMatch {
    Is(&'static str),
    Contains(&'static str),
}

/// AuditDefaults.json scanner.ignored_insertion_points.skip_all_tests_for_parameters.
const SKIP_ALL: &[(RuleParam, RuleMatch)] = &[
    (RuleParam::XmlAttr, RuleMatch::Is("version")),
    (RuleParam::XmlAttr, RuleMatch::Is("encoding")),
    (RuleParam::XmlAttr, RuleMatch::Is("standalone")),
    (RuleParam::XmlAttr, RuleMatch::Contains("xmlns")),
    (RuleParam::XmlAttr, RuleMatch::Is("xml:lang")),
    (RuleParam::XmlAttr, RuleMatch::Is("lang")),
    (RuleParam::Cookie, RuleMatch::Is("_ga")),
    (RuleParam::Cookie, RuleMatch::Is("_gid")),
    (RuleParam::Cookie, RuleMatch::Is("_gat")),
    (RuleParam::Cookie, RuleMatch::Contains("_ga_")),
    (RuleParam::Cookie, RuleMatch::Contains("_gac_")),
    (RuleParam::Cookie, RuleMatch::Contains("awsalb")),
];

/// AuditDefaults.json scanner.ignored_insertion_points.skip_server_side_injection_for_parameters.
const SKIP_SERVER_SIDE: &[(RuleParam, RuleMatch)] = &[
    (RuleParam::Cookie, RuleMatch::Contains("aspsessionid")),
    (RuleParam::Cookie, RuleMatch::Is("asp.net_sessionid")),
    (RuleParam::Body, RuleMatch::Is("__eventtarget")),
    (RuleParam::Body, RuleMatch::Is("__eventargument")),
    (RuleParam::Body, RuleMatch::Is("__viewstate")),
    (RuleParam::Body, RuleMatch::Is("__eventvalidation")),
    (RuleParam::Any, RuleMatch::Is("jsessionid")),
    (RuleParam::Cookie, RuleMatch::Is("cfid")),
    (RuleParam::Cookie, RuleMatch::Is("cftoken")),
    (RuleParam::Cookie, RuleMatch::Is("PHPSESSID")),
    (RuleParam::Cookie, RuleMatch::Is("session_id")),
];

fn rule_param_matches(param: RuleParam, t: PointType) -> bool {
    match param {
        RuleParam::Any => true,
        // burp.Zr2c: body_parameter covers URL-encoded and multipart body
        // parameters (and multipart attributes), not JSON or XML.
        RuleParam::Body => matches!(
            t,
            PointType::BodyParamUrlEncoded | PointType::BodyParamMultipart
        ),
        RuleParam::Cookie => t == PointType::Cookie,
        RuleParam::XmlAttr => t == PointType::XmlAttr,
    }
}

fn rule_hits(rules: &[(RuleParam, RuleMatch)], p: &InsertionPoint) -> bool {
    let t = p.kind.point_type();
    rules.iter().any(|(param, m)| {
        rule_param_matches(*param, t)
            && match m {
                RuleMatch::Is(x) => p.name.eq_ignore_ascii_case(x),
                RuleMatch::Contains(x) => p
                    .name
                    .to_ascii_lowercase()
                    .contains(&x.to_ascii_lowercase()),
            }
    })
}

/// burp.Zb9c: the skip-all list vetoes a point when it matches the point or
/// any point it is nested in.
pub fn skipped_by_skip_all(p: &InsertionPoint) -> bool {
    p.chain().iter().any(|q| rule_hits(SKIP_ALL, q))
}

// ---------------------------------------------------------------- vetoes

/// The scan configuration's insertion point type of a base point
/// ([`crate::scan_config::INSERTION_TYPES`], burp.Zwez's Zick list); None
/// for kinds that only exist nested (Zick lets every nested point through).
pub fn insertion_type(kind: &IpKind) -> Option<&'static str> {
    match kind {
        IpKind::Query => Some("url"),
        IpKind::Body
        | IpKind::Json(_)
        | IpKind::Multipart { .. }
        | IpKind::XmlParam { .. }
        | IpKind::XmlTag { .. }
        | IpKind::XmlAttr { .. } => Some("body"),
        IpKind::Cookie => Some("cookie"),
        IpKind::Header => Some("header"),
        IpKind::PathFolder(_) => Some("folder"),
        IpKind::PathFilename(_) => Some("filename"),
        IpKind::EntireBody => Some("entire_body"),
        IpKind::ParamName(_) => Some("param_name"),
        IpKind::Base64 { .. } => None,
    }
}
