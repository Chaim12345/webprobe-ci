//! History entry: the shared request/response record. Lives in
//! webprobe-support since L8 (#38) so history-adjacent modules do not
//! depend on net; `webprobe_core::net::HistEntry` re-exports it.

/// One request/response pair in Proxy history.
#[derive(Clone, Default)]
pub struct HistEntry {
    pub id: u64,
    pub ts: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub path: String,
    pub status: String,
    pub resp_len: usize,
    /// Request and response bytes: cheap to clone; Proxy history keeps them
    /// in the on-disk store (`body::spill`).
    pub req_raw: crate::body::Body,
    pub resp_raw: Option<crate::body::Body>,
    pub note: Option<String>,
    /// Burp's row highlight (ui.highlight.0..8 in LightTheme.json).
    pub highlight: Option<u8>,
    /// The live passive audit looked at this item (Dashboard > Audit items).
    pub audited: bool,
    /// Derived once at insert (P-05), so a table frame never recomputes them.
    /// Whether the request carries a query string, body parameters or cookies.
    pub params: bool,
    /// Whether the user edited the message (intercept, match/replace).
    pub edited: bool,
    /// URL file extension (lower case, no dot); empty when there is none.
    pub extension: String,
    /// HTML <title> text, empty for non-HTML responses.
    pub title: String,
    /// Cookies set by the response, "name=value" pairs joined by "; ".
    pub cookies: String,
    /// Listener port the request arrived on.
    pub listener_port: u16,
    /// Upstream IP the host resolved to (history "IP" column, live 52685:
    /// e.g. 104.20.23.154 for example.com); empty when unresolvable.
    pub ip: String,
    /// How many response attributes changed vs. the previous exchange of the
    /// same request location ("Diff count" column, burp.Zxwu.java:56).
    pub diffs: usize,
}

impl HistEntry {
    /// This entry with its bodies in the on-disk store, as Proxy history
    /// keeps every entry (N-06).
    pub fn spilled(mut self) -> Self {
        self.req_raw = crate::body::spill(&self.req_raw);
        self.resp_raw = self.resp_raw.as_ref().map(crate::body::spill);
        self
    }
}
