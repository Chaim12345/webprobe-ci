// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Burp's "other tools ignore streaming responses and close the
/// connection": the sink of a tool (Scanner, Intruder, crawler, ...) other
/// than the Proxy and Repeater, which bring their own.
pub struct ToolSink<'a> {
    shared: &'a Shared,
    url: String,
    settings: crate::streaming::StreamSettings,
}

impl crate::streaming::ResponseSink for ToolSink<'_> {
    fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
        if crate::streaming::decide(&self.url, head, &self.settings)
            == crate::streaming::Decision::Buffered
        {
            return crate::streaming::BodyMode::Buffer;
        }
        let tool = TOOL.with(|t| t.get()).unwrap_or("A tool");
        self.shared.log(&format!(
            "{tool} ignored the streaming response from {} and closed the connection",
            self.url
        ));
        crate::streaming::BodyMode::HeadOnly
    }
    fn wire(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn payload(&mut self, _: &[u8]) {}
    fn end(&mut self, _: bool) {}
}

pub fn tool_sink<'a>(
    shared: &'a Shared,
    host: &str,
    port: u16,
    https: bool,
    request: &[u8],
) -> Option<ToolSink<'a>> {
    let tool = TOOL.with(|t| t.get())?;
    if tool == "Proxy" || tool == "Repeater" {
        return None;
    }
    Some(ToolSink {
        shared,
        url: request_url(host, port, https, request),
        settings: shared.streaming.lock().unwrap().clone(),
    })
}

/// How a sender wants HTTP/2 used on its thread (Repeater's protocol
/// control): `want_h2` Some(true) = HTTP/2 only, Some(false) = HTTP/1
/// only, None = negotiate by ALPN (the Proxy, and Repeater with "Allow
/// HTTP/2 ALPN override"). `strip_connection`: Repeater's "Strip
/// Connection header over HTTP/2" (default on).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Http2Choice {
    pub want_h2: Option<bool>,
    pub strip_connection: bool,
}

/// Restores the thread's previous HTTP/2 choice when dropped.
pub struct Http2Scope(Option<Http2Choice>);

impl Drop for Http2Scope {
    fn drop(&mut self) {
        H2_CHOICE.with(|c| c.set(self.0));
    }
}

/// Use `choice` for sends on this thread until the scope ends.
pub fn http2_scope(choice: Http2Choice) -> Http2Scope {
    Http2Scope(H2_CHOICE.with(|c| c.replace(Some(choice))))
}

/// The protocol the last send on this thread used ("HTTP/1.1"/"HTTP/2").
pub fn last_protocol() -> &'static str {
    LAST_PROTOCOL.with(|p| p.get())
}

/// An HTTP/1.1 request line for a request shown as `HTTP/2` (the
/// listener's h2 requests, Repeater tabs) that goes out over HTTP/1.
pub fn as_http1(req: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let line_end = req.iter().position(|&b| b == b'\n').unwrap_or(req.len());
    let line = &req[..line_end];
    let trimmed = line.strip_suffix(b"\r").unwrap_or(line);
    for v in [b"HTTP/2".as_slice(), b"HTTP/2.0".as_slice()] {
        if trimmed.ends_with(v)
            && trimmed.len() > v.len()
            && trimmed[trimmed.len() - v.len() - 1] == b' '
        {
            let mut out = trimmed[..trimmed.len() - v.len()].to_vec();
            out.extend_from_slice(b"HTTP/1.1");
            out.extend_from_slice(&req[trimmed.len()..]);
            return out.into();
        }
    }
    req.into()
}

/// The request a tool is about to send, with the cookie jar's cookies when
/// the jar's rule covers the tool working on this thread; otherwise as given.
pub fn jar_request<'a>(
    shared: &Shared,
    host: &str,
    https: bool,
    request: &'a [u8],
) -> std::borrow::Cow<'a, [u8]> {
    let Some(tool) = TOOL.with(|t| t.get()) else {
        return request.into();
    };
    let jar = shared.cookie_jar.lock().unwrap();
    if !jar.applies_to(tool) || jar.cookies.is_empty() {
        return request.into();
    }
    jar.apply(request, host, https, util::now_secs()).into()
}

/// The session rules scoped to the tool working on this thread, applied to
/// the request it is about to send.
pub fn session_request<'a>(
    shared: &Shared,
    port: u16,
    https: bool,
    request: std::borrow::Cow<'a, [u8]>,
) -> Result<std::borrow::Cow<'a, [u8]>, String> {
    let Some(tool) = TOOL.with(|t| t.get()) else {
        return Ok(request);
    };
    if shared.session_rules.lock().unwrap().is_empty() {
        return Ok(request);
    }
    apply_session_rules_for(shared, tool, &request, port, https).map(Into::into)
}

/// Post-request macros for the tool working on this thread.
pub fn session_after(shared: &Shared, host: &str) {
    if let Some(tool) = TOOL.with(|t| t.get()) {
        if !shared.session_rules.lock().unwrap().is_empty() {
            // Macros send requests on this thread; each exchange rewrites the
            // "last exchange was reusable" flag the proxy engine reads for the
            // OUTER response. Keep the outer result across them.
            let outer = LAST_EXCHANGE_REUSABLE.with(|c| c.get());
            run_post_request_rules(shared, tool, host);
            LAST_EXCHANGE_REUSABLE.with(|c| c.set(outer));
        }
    }
}

/// Feed a tool's response to the cookie jar when the jar monitors that tool.
pub fn jar_response(shared: &Shared, host: &str, request: &[u8], up: &Upstream) {
    let (Some(tool), Some(resp)) = (TOOL.with(|t| t.get()), up.resp.as_deref()) else {
        return;
    };
    let mut jar = shared.cookie_jar.lock().unwrap();
    if jar.updates_from(tool) {
        let path = util::parse_http(request).path;
        jar.update_from_response(host, &path, resp, util::now_secs());
    }
}

/// One request a tool sent, summarised for the Logger (Burp's Logger lists
/// every tool's traffic, not only the proxy's).
#[derive(Clone, Debug, PartialEq)]
pub struct ToolExchange {
    pub ts: u64,
    pub tool: &'static str,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub method: String,
    pub path: String,
    /// Status code text, empty when no response arrived.
    pub status: String,
    pub req_len: usize,
    pub resp_len: usize,
    /// Response Content-Type without parameters.
    pub mime: String,
    /// The messages, each cut at [`TOOL_LOG_MESSAGE_MAX`] bytes.
    pub request: Arc<[u8]>,
    pub response: Option<Arc<[u8]>>,
}

/// Bytes of each message kept for the Logger's detail pane.
pub const TOOL_LOG_MESSAGE_MAX: usize = 256 * 1024;

/// Unlogged tool exchanges kept while nothing collects them (a headless run).
pub const TOOL_LOG_MAX: usize = 5000;

/// Marks the current thread as working for `tool` until the guard is dropped:
/// every request it sends through `send_raw`/`send_tls_raw` is then recorded
/// in `Shared::tool_log` under that name.
pub fn tool_scope(tool: &'static str) -> ToolScope {
    ToolScope(TOOL.with(|t| t.replace(Some(tool))))
}

pub struct ToolScope(Option<&'static str>);

impl Drop for ToolScope {
    fn drop(&mut self) {
        TOOL.with(|t| t.set(self.0));
    }
}

pub fn log_tool_exchange(
    shared: &Shared,
    host: &str,
    port: u16,
    https: bool,
    request: &[u8],
    up: &Upstream,
) {
    let Some(tool) = TOOL.with(|t| t.get()) else {
        return;
    };
    let first = request.split(|b| *b == b'\n').next().unwrap_or_default();
    let first = String::from_utf8_lossy(first);
    let mut words = first.split_whitespace();
    let method = words.next().unwrap_or_default().to_string();
    let path = words.next().unwrap_or_default().to_string();
    let (status, resp_len, mime) = match &up.resp {
        Some(resp) => {
            let parts = crate::util::parse_http(resp);
            let status =
                String::from_utf8_lossy(resp.split(|b| *b == b'\n').next().unwrap_or_default())
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
            let ct = crate::util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
            (
                status,
                resp.len(),
                ct.split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase(),
            )
        }
        None => (String::new(), 0, String::new()),
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut log = shared.tool_log.lock().unwrap();
    if log.len() >= TOOL_LOG_MAX {
        log.remove(0);
    }
    let keep = |b: &[u8]| -> Arc<[u8]> { Arc::from(&b[..b.len().min(TOOL_LOG_MESSAGE_MAX)]) };
    log.push(ToolExchange {
        ts,
        tool,
        host: host.to_string(),
        port,
        https,
        method,
        path,
        status,
        req_len: request.len(),
        resp_len,
        mime,
        request: keep(request),
        response: up.resp.as_deref().map(keep),
    });
}
