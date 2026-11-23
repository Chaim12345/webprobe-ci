// Moved from core scan/issue_types.rs (L8, issue #38): the shared issue
// vocabulary oob and stored name. Pure data, no core deps, so modules that
// only need the types no longer pull scan (and its cycle) into their graph.

use std::sync::Arc;

/// Largest request or response kept as issue evidence; longer messages are
/// truncated to this many bytes.
pub const EVIDENCE_MAX_BYTES: usize = 256 * 1024;

/// One exchange that confirmed an issue: the probe as sent and the response
/// it got (None when the target did not answer, or not known yet). Shared,
/// so cloning an issue does not copy the bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanEvidence {
    pub request: Arc<[u8]>,
    pub response: Option<Arc<[u8]>>,
}

impl ScanEvidence {
    /// A bounded copy: each message is cut at [`EVIDENCE_MAX_BYTES`].
    pub fn new(request: &[u8], response: Option<&[u8]>) -> Self {
        let cap = |b: &[u8]| -> Arc<[u8]> { Arc::from(&b[..b.len().min(EVIDENCE_MAX_BYTES)]) };
        ScanEvidence {
            request: cap(request),
            response: response.map(cap),
        }
    }
}

#[derive(Clone, Default)]
pub struct ScanIssue {
    pub id: u64,
    pub sev: String, // high | medium | low | info (DarkTheme.json ui.issue colors)
    pub name: String,
    pub host: String,
    pub path: String,
    pub detail: String,
    /// Burp lets the user classify an issue as a false positive
    /// (build 52685 burp.Ze1r line 12 returns "False positive").
    pub false_positive: bool,
    /// Burp vocabulary: Certain | Firm | Tentative.
    pub confidence: String,
    /// When the issue was reported (unix seconds), Burp's "Time" column.
    pub ts: u64,
    /// Burp's numeric issue type (KnowledgeBase `typeIndex`) for an issue
    /// name Burp knows, otherwise 0 (see `issue_type_id` in core scan).
    pub type_id: u64,
    /// The exchange(s) that confirmed the issue: the probe and its response
    /// for an active check (several when a control or a retrieval request is
    /// part of the proof), the audited exchange for a passive check. Empty
    /// for issues loaded from a project file and for checks that do not
    /// attach evidence yet.
    pub evidence: Vec<ScanEvidence>,
    /// Burp's pervasive issue identifier (Zu4s.PERVASIVE_ISSUE_IDENTIFIER),
    /// with the variant where Burp keys on it: the value an issue is about
    /// (an SSN, a cookie name, a library and version). Part of the merge
    /// key; empty for issues keyed by location only.
    pub ident: String,
}

impl ScanIssue {
    pub fn with_evidence(mut self, evidence: Vec<ScanEvidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

// ---------------------------------------------------------------- issue types

/// Burp's numeric issue type for every name in kb_issue_names.txt, from the
/// `typeIndex` field of Burp's KnowledgeBase (resources/KnowledgeBase/Issues
/// /*.json of build 52685; the file-name prefix is the same number in hex
/// except for two entries, where the JSON field wins).
pub const KB_ISSUE_TYPES: &[(&str, u64)] = &[
    ("ASP.NET ViewState without MAC enabled", 0x00400600),
    ("ASP.NET debugging enabled", 0x00100800),
    ("ASP.NET tracing enabled", 0x00100280),
    ("Ajax request header manipulation (DOM-based)", 0x00500c00),
    (
        "Ajax request header manipulation (reflected DOM-based)",
        0x00500c01,
    ),
    (
        "Ajax request header manipulation (stored DOM-based)",
        0x00500c02,
    ),
    ("BCheck generated issue", 0x09000000),
    ("Backup file", 0x006000d8),
    ("Bambda generated issue", 0x09000000),
    ("Base64-encoded data in parameter", 0x00700200),
    ("Broken access control", 0x00100850),
    ("Browser cross-site scripting filter disabled", 0x005009b0),
    ("CSS injection (reflected)", 0x00501300),
    ("CSS injection (stored)", 0x00501301),
    ("Cacheable HTTPS response", 0x00700100),
    ("Cleartext submission of password", 0x00300100),
    (
        "Client-side HTTP parameter pollution (reflected)",
        0x00501400,
    ),
    ("Client-side HTTP parameter pollution (stored)", 0x00501401),
    ("Client-side JSON injection (DOM-based)", 0x00200370),
    (
        "Client-side JSON injection (reflected DOM-based)",
        0x00200371,
    ),
    ("Client-side JSON injection (stored DOM-based)", 0x00200372),
    ("Client-side SQL injection (DOM-based)", 0x00200330),
    (
        "Client-side SQL injection (reflected DOM-based)",
        0x00200331,
    ),
    ("Client-side SQL injection (stored DOM-based)", 0x00200332),
    ("Client-side XPath injection (DOM-based)", 0x00200360),
    (
        "Client-side XPath injection (reflected DOM-based)",
        0x00200361,
    ),
    ("Client-side XPath injection (stored DOM-based)", 0x00200362),
    ("Client-side desync", 0x00200141),
    ("Client-side prototype pollution", 0x00200316),
    ("Client-side template injection", 0x00200308),
    (
        "Content security policy: allowlisted script resources",
        0x00200503,
    ),
    ("Content security policy: allows clickjacking", 0x00200507),
    ("Content security policy: allows form hijacking", 0x00200508),
    (
        "Content security policy: allows untrusted script execution",
        0x00200504,
    ),
    (
        "Content security policy: allows untrusted style execution",
        0x00200505,
    ),
    ("Content security policy: malformed syntax", 0x00200506),
    ("Content security policy: not enforced", 0x00200509),
    ("Content type incorrectly stated", 0x00800400),
    ("Content type is not specified", 0x00800500),
    ("Cookie manipulation (DOM-based)", 0x00500b00),
    ("Cookie manipulation (reflected DOM-based)", 0x00500b01),
    ("Cookie manipulation (stored DOM-based)", 0x00500b02),
    ("Cookie scoped to parent domain", 0x00500300),
    ("Cookie without HttpOnly flag set", 0x00500600),
    ("Credit card numbers disclosed", 0x00600500),
    ("Cross-domain POST", 0x00400500),
    ("Cross-domain Referer leakage", 0x00500400),
    ("Cross-domain script include", 0x00500500),
    ("Cross-origin resource sharing", 0x00200600),
    (
        "Cross-origin resource sharing: all subdomains trusted",
        0x00200603,
    ),
    (
        "Cross-origin resource sharing: arbitrary origin trusted",
        0x00200601,
    ),
    (
        "Cross-origin resource sharing: unencrypted origin trusted",
        0x00200602,
    ),
    ("Cross-site request forgery", 0x00200700),
    ("Cross-site scripting (DOM-based)", 0x00200310),
    ("Cross-site scripting (reflected DOM-based)", 0x00200311),
    ("Cross-site scripting (reflected)", 0x00200300),
    ("Cross-site scripting (stored DOM-based)", 0x00200312),
    ("Cross-site scripting (stored)", 0x00200100),
    ("DOM data manipulation (DOM-based)", 0x00501200),
    ("DOM data manipulation (reflected DOM-based)", 0x00501201),
    ("DOM data manipulation (stored DOM-based)", 0x00501202),
    ("Database connection string disclosed", 0x00600080),
    ("Denial of service (DOM-based)", 0x00500d00),
    ("Denial of service (reflected DOM-based)", 0x00500d01),
    ("Denial of service (stored DOM-based)", 0x00500d02),
    ("Directory listing", 0x00600100),
    ("Document domain manipulation (DOM-based)", 0x00501100),
    (
        "Document domain manipulation (reflected DOM-based)",
        0x00501101,
    ),
    (
        "Document domain manipulation (stored DOM-based)",
        0x00501102,
    ),
    ("Duplicate cookies set", 0x00400a00),
    ("Email addresses disclosed", 0x00600200),
    ("Expression Language injection", 0x00100f20),
    ("Extension generated issue", 0x08000000),
    ("External service interaction (DNS)", 0x00300200),
    ("External service interaction (HTTP)", 0x00300210),
    ("External service interaction (SMTP)", 0x00300220),
    ("File path manipulation", 0x00100b00),
    ("File path traversal", 0x00100300),
    ("File upload functionality", 0x00500980),
    ("Flash cross-domain policy", 0x00200400),
    ("Form action hijacking (reflected)", 0x00501500),
    ("Form action hijacking (stored)", 0x00501501),
    ("Frameable response (potential Clickjacking)", 0x005009a0),
    ("GraphQL content type not validated", 0x00200514),
    ("GraphQL endpoint discovered", 0x00200511),
    ("GraphQL endpoint found", 0x00200510),
    ("GraphQL introspection enabled", 0x00200512),
    ("GraphQL suggestions enabled", 0x00200513),
    ("HTML does not specify charset", 0x00800200),
    ("HTML uses unrecognized charset", 0x00800300),
    ("HTML5 storage manipulation (DOM-based)", 0x00500f00),
    (
        "HTML5 storage manipulation (reflected DOM-based)",
        0x00500f01,
    ),
    ("HTML5 storage manipulation (stored DOM-based)", 0x00500f02),
    ("HTML5 web message manipulation (DOM-based)", 0x00500e00),
    (
        "HTML5 web message manipulation (reflected DOM-based)",
        0x00500e01,
    ),
    (
        "HTML5 web message manipulation (stored DOM-based)",
        0x00500e02,
    ),
    ("HTTP PUT method is enabled", 0x00100900),
    ("HTTP TRACE method is enabled", 0x00500a00),
    ("HTTP request smuggling", 0x00200140),
    ("HTTP response header injection", 0x00200200),
    ("Hidden HTTP 2", 0x01000500),
    ("Input returned in response (reflected)", 0x00400c00),
    ("Input returned in response (stored)", 0x00400b00),
    ("JWT arbitrary jku header supported", 0x00200904),
    ("JWT arbitrary x5u header supported", 0x00200905),
    ("JWT none algorithm supported", 0x00200901),
    ("JWT private key disclosed", 0x00600800),
    ("JWT self-signed JWK header supported", 0x00200902),
    ("JWT signature not verified", 0x00200900),
    ("JWT weak HMAC secret", 0x00200903),
    ("JavaScript injection (DOM-based)", 0x00200320),
    ("JavaScript injection (reflected DOM-based)", 0x00200321),
    ("JavaScript injection (stored DOM-based)", 0x00200322),
    ("Json Web Key Set disclosed", 0x00600700),
    ("LDAP injection", 0x00100500),
    ("Link manipulation (DOM-based)", 0x00501000),
    ("Link manipulation (reflected DOM-based)", 0x00501001),
    ("Link manipulation (reflected)", 0x00501003),
    ("Link manipulation (stored DOM-based)", 0x00501002),
    ("Link manipulation (stored)", 0x00501004),
    ("Local file path manipulation (DOM-based)", 0x00200350),
    (
        "Local file path manipulation (reflected DOM-based)",
        0x00200351,
    ),
    (
        "Local file path manipulation (stored DOM-based)",
        0x00200352,
    ),
    ("Long redirection response", 0x00400800),
    ("Manually generated issue", 0x08008000),
    ("Mixed content", 0x01000400),
    ("Multiple content types specified", 0x00800100),
    ("OS command injection", 0x00100100),
    ("Open redirection (DOM-based)", 0x00500110),
    ("Open redirection (reflected DOM-based)", 0x00500111),
    ("Open redirection (reflected)", 0x00500100),
    ("Open redirection (stored DOM-based)", 0x00500112),
    ("Open redirection (stored)", 0x00500101),
    ("OpenAPI definition found (active scan check)", 0x00600900),
    ("OpenAPI definition found (passive scan check)", 0x00600901),
    ("Out-of-band resource load (HTTP)", 0x00100a00),
    ("PHP code injection", 0x00100c00),
    ("Password field with autocomplete enabled", 0x00500800),
    ("Password returned in URL query string", 0x00400400),
    ("Password returned in later response", 0x00400200),
    ("Password submitted using GET method", 0x00400300),
    ("Password value set in cookie", 0x00500900),
    ("Path-relative style sheet import", 0x00200328),
    ("Perl code injection", 0x00100e00),
    ("Private IP addresses disclosed", 0x00600300),
    ("Private key disclosed", 0x00600550),
    ("Python code injection", 0x00100f10),
    (
        "React Server Components remote code execution (React2Shell)",
        0x00100e00,
    ),
    ("Referer-dependent response", 0x00400100),
    ("Request URL override", 0x00400f00),
    ("Robots.txt file", 0x00600600),
    ("Ruby code injection", 0x00100f00),
    ("SMTP header injection", 0x00200800),
    ("SQL injection", 0x00100200),
    ("SQL injection (second order)", 0x00100210),
    ("SQL statement in request parameter", 0x00400480),
    ("SSI injection", 0x00101100),
    ("Serialized object in HTTP message", 0x00400900),
    ("Server-side JavaScript code injection", 0x00100d00),
    ("Server-side template injection", 0x00101080),
    ("Session token in URL", 0x00500700),
    ("Silverlight cross-domain policy", 0x00200500),
    ("Social security numbers disclosed", 0x00600400),
    ("Source code disclosure", 0x006000b0),
    ("Spoofable client IP address", 0x00400110),
    ("Strict transport security not enforced", 0x01000300),
    ("Suspicious input transformation (reflected)", 0x00400d00),
    ("Suspicious input transformation (stored)", 0x00400e00),
    ("TLS certificate", 0x01000100),
    ("TLS cookie without secure flag set", 0x00500200),
    ("Unencrypted communications", 0x01000200),
    ("Unidentified code injection", 0x00101000),
    ("User agent-dependent response", 0x00400120),
    ("Vulnerable JavaScript dependency", 0x00500080),
    ("Web cache deception", 0x00200650),
    ("Web cache poisoning", 0x00200180),
    ("WebSocket URL poisoning (DOM-based)", 0x00200340),
    ("WebSocket URL poisoning (reflected DOM-based)", 0x00200341),
    ("WebSocket URL poisoning (stored DOM-based)", 0x00200342),
    ("XML entity expansion", 0x00400700),
    ("XML external entity injection", 0x00100400),
    ("XML injection", 0x00100700),
    ("XPath injection", 0x00100600),
];

/// Burp's numeric issue type for a KnowledgeBase name (0 when the name is not
/// in Burp's catalogue, such as a WebProbe-only probe).
pub fn issue_type_id(name: &str) -> u64 {
    KB_ISSUE_TYPES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .unwrap_or(0)
}
