// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// The first three entries are the SQL probes used by the light active scan;
/// the rest are passive stack-trace / error-message signatures.
pub const ERROR_SIGNATURES: [(&str, &str); 12] = [
    ("SQL syntax", "SQL error message in response"),
    ("SQLite3::", "SQLite error message in response"),
    ("ORA-", "Oracle database error message in response"),
    ("PHP Warning", "PHP runtime warning in response"),
    ("System.Exception", "Server exception message in response"),
    ("Stack Trace", "Stack trace disclosed in response"),
    ("Warning: mysql_", "MySQL warning in response"),
    (
        "Traceback (most recent call last)",
        "Python stack trace disclosed in response",
    ),
    ("at java.", "Java stack trace disclosed in response"),
    (
        "goroutine 1 [running]:",
        "Go stack trace disclosed in response",
    ),
    ("Fatal error:", "PHP fatal error disclosed in response"),
    ("Notice: Undefined", "PHP notice disclosed in response"),
];

pub const SECRET_KEYWORDS: [(&str, &str); 6] = [
    ("password", "Possible credential reference in HTML comment"),
    ("passwd", "Possible credential reference in HTML comment"),
    ("secret", "Possible secret reference in HTML comment"),
    ("api_key", "Possible API key reference in HTML comment"),
    ("apikey", "Possible API key reference in HTML comment"),
    ("TODO:", "Developer note in HTML comment"),
];

/// Largest response body slice inspected by any passive check. Burp also caps
/// the work it does per response; 256 KB keeps huge downloads cheap.
pub const MAX_BODY_SCAN: usize = 256 * 1024;

/// Stable descriptor for one passive check: the report shows name + severity,
/// while `id` and `confidence` stay fixed for tests, exports and dedupe.
#[derive(Clone, Copy)]
pub struct CheckDef {
    pub id: &'static str,
    pub name: &'static str,
    pub sev: &'static str,
    /// Burp vocabulary: Certain | Firm | Tentative.
    pub confidence: &'static str,
}

pub const CH_HSTS: CheckDef = CheckDef {
    id: "passive.hsts-missing",
    name: "Strict transport security not enforced",
    sev: "low",
    confidence: "Certain",
};

pub const CH_CLEARTEXT: CheckDef = CheckDef {
    id: "passive.unencrypted-communications",
    name: "Unencrypted communications",
    sev: "low",
    confidence: "Certain",
};

pub const CH_CSP: CheckDef = CheckDef {
    id: "passive.csp-missing",
    name: "Content security policy (CSP) header not set",
    sev: "low",
    confidence: "Certain",
};

pub const CH_FRAME: CheckDef = CheckDef {
    id: "passive.frame-ancestors-missing",
    name: "Frameable response (potential Clickjacking)",
    sev: "info",
    confidence: "Firm",
};

pub const CH_XCTO: CheckDef = CheckDef {
    id: "passive.x-content-type-options-missing",
    name: "X-Content-Type-Options header missing",
    sev: "low",
    confidence: "Certain",
};

pub const CH_REFERRER: CheckDef = CheckDef {
    id: "passive.referrer-policy-missing",
    name: "Referrer-Policy header not set",
    sev: "low",
    confidence: "Certain",
};

pub const CH_PERMISSIONS: CheckDef = CheckDef {
    id: "passive.permissions-policy-missing",
    name: "Permissions policy header not set",
    sev: "low",
    confidence: "Certain",
};

pub const CH_SERVER: CheckDef = CheckDef {
    id: "passive.server-version",
    name: "Server header discloses version",
    sev: "info",
    confidence: "Firm",
};

pub const CH_XPB: CheckDef = CheckDef {
    id: "passive.x-powered-by",
    name: "X-Powered-By header discloses technology",
    sev: "info",
    confidence: "Firm",
};

pub const CH_ASPNET: CheckDef = CheckDef {
    id: "passive.aspnet-version",
    name: "ASP.NET version disclosure",
    sev: "info",
    confidence: "Certain",
};

pub const CH_COOKIE_HTTPONLY: CheckDef = CheckDef {
    id: "passive.cookie-httponly-missing",
    name: "Cookie without HttpOnly flag set",
    sev: "low",
    confidence: "Firm",
};

pub const CH_COOKIE_SECURE: CheckDef = CheckDef {
    id: "passive.cookie-secure-missing",
    name: "TLS cookie without secure flag set",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_COOKIE_SAMESITE: CheckDef = CheckDef {
    id: "passive.cookie-samesite-missing",
    name: "Cookie without SameSite attribute",
    sev: "low",
    confidence: "Firm",
};

pub const CH_COOKIE_SAMESITE_NONE: CheckDef = CheckDef {
    id: "passive.cookie-samesite-none-insecure",
    name: "SameSite=None cookie without Secure attribute",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CORS_WILDCARD: CheckDef = CheckDef {
    id: "passive.cors-wildcard-origin",
    name: "CORS misconfiguration: wildcard origin",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CORS_WILDCARD_CREDS: CheckDef = CheckDef {
    id: "passive.cors-wildcard-origin-credentials",
    name: "CORS misconfiguration: wildcard origin with credentials",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_CORS_REFLECT: CheckDef = CheckDef {
    id: "passive.cors-reflected-origin",
    name: "CORS misconfiguration: arbitrary origin reflected",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CORS_CREDS: CheckDef = CheckDef {
    id: "passive.cors-reflected-origin-credentials",
    name: "CORS misconfiguration: reflected origin with credentials",
    sev: "high",
    confidence: "Firm",
};

pub const CH_CORS_NULL: CheckDef = CheckDef {
    id: "passive.cors-null-origin",
    name: "CORS misconfiguration: null origin allowed",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_DIR_LISTING: CheckDef = CheckDef {
    id: "passive.directory-listing",
    name: "Directory listing",
    sev: "low",
    confidence: "Firm",
};

pub const CH_GIT: CheckDef = CheckDef {
    id: "passive.git-directory-exposed",
    name: "Exposed .git directory",
    sev: "high",
    confidence: "Certain",
};

pub const CH_ENV: CheckDef = CheckDef {
    id: "passive.env-file-exposed",
    name: "Exposed .env file",
    sev: "high",
    confidence: "Certain",
};

pub const CH_LOGIN_HTTP: CheckDef = CheckDef {
    id: "passive.login-form-http",
    name: "Cleartext submission of password",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_MIXED: CheckDef = CheckDef {
    id: "passive.mixed-content",
    name: "Mixed content",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CACHE: CheckDef = CheckDef {
    id: "passive.cacheable-https-response",
    name: "Cacheable HTTPS response",
    sev: "low",
    confidence: "Tentative",
};

pub const CH_REDIRECT_COOKIE: CheckDef = CheckDef {
    id: "passive.session-cookie-cross-host-redirect",
    name: "Session cookie sent on cross-host redirect",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_AUTOCOMPLETE: CheckDef = CheckDef {
    id: "passive.password-autocomplete",
    name: "Password field with autocomplete enabled",
    sev: "low",
    confidence: "Firm",
};

pub const CH_EMAIL: CheckDef = CheckDef {
    id: "passive.email-disclosed",
    name: "Email addresses disclosed",
    sev: "info",
    confidence: "Certain",
};

pub const CH_PRIVATE_IP: CheckDef = CheckDef {
    id: "passive.private-ip-disclosed",
    name: "Private IP addresses disclosed",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CREDIT_CARD: CheckDef = CheckDef {
    id: "passive.credit-card-disclosed",
    name: "Credit card numbers disclosed",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_OPENAPI_PASSIVE: CheckDef = CheckDef {
    id: "passive.openapi-definition",
    name: "OpenAPI definition found (passive scan check)",
    sev: "info",
    confidence: "Certain",
};

pub const CH_HTML_NO_CHARSET: CheckDef = CheckDef {
    id: "passive.html-no-charset",
    name: "HTML does not specify charset",
    sev: "info",
    confidence: "Certain",
};

pub const CH_HTML_BAD_CHARSET: CheckDef = CheckDef {
    id: "passive.html-unrecognized-charset",
    name: "HTML uses unrecognized charset",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CT_MISSING: CheckDef = CheckDef {
    id: "passive.content-type-missing",
    name: "Content type is not specified",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CT_MULTI: CheckDef = CheckDef {
    id: "passive.content-type-multiple",
    name: "Multiple content types specified",
    sev: "info",
    confidence: "Certain",
};

pub const CH_ROBOTS: CheckDef = CheckDef {
    id: "passive.robots-txt",
    name: "Robots.txt file",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CSRF: CheckDef = CheckDef {
    id: "passive.csrf-form-token-missing",
    name: "CSRF token missing on form with password field",
    sev: "medium",
    confidence: "Firm",
};

/// Every passive check the engine knows, in report order.
pub static PASSIVE_LIBRARY: &[CheckDef] = &[
    CH_HSTS,
    CH_CSP,
    CH_FRAME,
    CH_XCTO,
    CH_REFERRER,
    CH_PERMISSIONS,
    CH_SERVER,
    CH_XPB,
    CH_ASPNET,
    CH_COOKIE_HTTPONLY,
    CH_COOKIE_SECURE,
    CH_COOKIE_SAMESITE,
    CH_COOKIE_SAMESITE_NONE,
    CH_CORS_WILDCARD,
    CH_CORS_WILDCARD_CREDS,
    CH_CORS_REFLECT,
    CH_CORS_CREDS,
    CH_CORS_NULL,
    CH_DIR_LISTING,
    CH_GIT,
    CH_ENV,
    CH_LOGIN_HTTP,
    CH_MIXED,
    CH_CACHE,
    CH_REDIRECT_COOKIE,
    CH_AUTOCOMPLETE,
    CH_EMAIL,
    CH_PRIVATE_IP,
    CH_CREDIT_CARD,
    CH_ROBOTS,
    CH_OPENAPI_PASSIVE,
    CH_HTML_NO_CHARSET,
    CH_HTML_BAD_CHARSET,
    CH_CT_MISSING,
    CH_CT_MULTI,
];

/// burp.Zf9p.ZY: charsets Burp recognizes.
pub const KNOWN_CHARSETS: [&str; 10] = [
    "utf-8",
    "us-ascii",
    "iso8859-1",
    "iso8859-2",
    "iso8859-15",
    "iso-8859-1",
    "iso-8859-2",
    "iso-8859-15",
    "windows-1250",
    "windows-1252",
];

/// burp.Zf9p: content-type and charset statements of one response.
pub fn mime_issues(resp: &[u8]) -> Vec<CheckDef> {
    let p = util::parse_http(resp);
    let status: u16 = p
        .first
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    if (300..400).contains(&status) || status == 204 {
        return Vec::new();
    }
    let body = &resp[p.head_len.min(resp.len())..];
    let cts: Vec<&String> = p
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v)
        .collect();
    let mut out = Vec::new();
    if cts.is_empty() {
        if !body.is_empty() {
            out.push(CH_CT_MISSING);
        }
        return out;
    }
    let essences: std::collections::BTreeSet<String> = cts
        .iter()
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .collect();
    if essences.len() > 1 {
        out.push(CH_CT_MULTI);
    }
    if essences.iter().any(|e| e == "text/html") && !body.is_empty() {
        let mut charsets: Vec<String> = cts
            .iter()
            .flat_map(|v| v.split(';').skip(1))
            .filter_map(|p| {
                p.trim()
                    .strip_prefix("charset=")
                    .or_else(|| p.trim().strip_prefix("Charset="))
                    .map(|c| c.trim_matches('"').to_ascii_lowercase())
            })
            .collect();
        let low = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();
        if let Some(i) = low.find("<meta") {
            for tag in low[i..].split("<meta").skip(1).take(20) {
                let tag = tag.split('>').next().unwrap_or("");
                if let Some(c) = tag.split("charset=").nth(1) {
                    let c = c
                        .trim_start_matches(['"', '\''])
                        .split(['"', '\'', ' ', '/', ';'])
                        .next()
                        .unwrap_or("");
                    if !c.is_empty() {
                        charsets.push(c.to_string());
                    }
                }
            }
        }
        if charsets.is_empty() {
            out.push(CH_HTML_NO_CHARSET);
        } else if charsets
            .iter()
            .any(|c| !KNOWN_CHARSETS.contains(&c.as_str()))
        {
            out.push(CH_HTML_BAD_CHARSET);
        }
    }
    out
}

/// The passive check library (ids, names, severities, confidences).
pub fn check_library() -> &'static [CheckDef] {
    PASSIVE_LIBRARY
}
