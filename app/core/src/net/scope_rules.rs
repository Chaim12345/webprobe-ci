// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

/// Target scope entry. Include=false excludes a matching location.
#[derive(Clone)]
pub struct ScopeRule {
    pub enabled: bool,
    pub include: bool,
    pub pattern: String,
    pub is_regex: bool,
}

impl ScopeRule {
    pub fn include(pattern: impl Into<String>, is_regex: bool) -> Self {
        Self {
            enabled: true,
            include: true,
            pattern: pattern.into(),
            is_regex,
        }
    }
}

/// One session-handling rule. The local implementation supports the original's
/// core actions: set a header, reuse a captured cookie, or run a macro first.
#[derive(Clone)]
pub struct SessionRule {
    pub enabled: bool,
    pub name: String,
    /// One of [`SESSION_ACTIONS`].
    pub action: String,
    pub host_match: String,
    /// The action's argument: `Name: value`, `name=value`, a cookie name, a
    /// macro name, or an extension's session handling action.
    pub value: String,
    /// Tools the rule applies to (Burp's "Tools scope").
    pub tools: Vec<String>,
    /// "check session": the expression looked for in the validation response.
    pub check: String,
    /// "check session": true when finding the expression means the session
    /// is invalid ("Please log in"), false when it means valid.
    pub check_invalid_on_match: bool,
}

/// Burp's default tool scope for a new session rule: everything except the
/// Proxy (which Burp marks "use with caution").
pub const SESSION_DEFAULT_TOOLS: [&str; 5] =
    ["Target", "Scanner", "Repeater", "Intruder", "Sequencer"];

impl SessionRule {
    pub fn new() -> Self {
        Self {
            enabled: true,
            name: "New session rule".into(),
            action: "set header".into(),
            host_match: String::new(),
            value: String::new(),
            tools: SESSION_DEFAULT_TOOLS
                .iter()
                .map(|t| t.to_string())
                .collect(),
            check: String::new(),
            check_invalid_on_match: true,
        }
    }
}

impl Default for SessionRule {
    fn default() -> Self {
        Self::new()
    }
}

/// A reusable raw request executed by session rules and from the Sessions tab.
#[derive(Clone)]
pub struct Macro {
    pub name: String,
    pub request: String,
}
