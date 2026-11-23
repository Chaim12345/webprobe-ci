// WebProbe AI: the slot of Burp's AI assistant (Burp AI / "Send to Burp AT").
// Burp's assistant runs on PortSwigger's cloud; WebProbe talks to an
// OpenAI-compatible chat endpoint the user configures (a local model server or
// a hosted API). Nothing is sent until an endpoint is set.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::sync::Mutex;

use crate::net::{self, Shared};
use crate::util;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatMsg {
    pub role: String,
    pub text: String,
}

pub struct AiChat {
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
    pub input: String,
    pub messages: Arc<Mutex<Vec<ChatMsg>>>,
    pub busy: Arc<AtomicBool>,
}

impl Default for AiChat {
    fn default() -> Self {
        Self {
            endpoint: std::env::var("WEBPROBE_AI_ENDPOINT").unwrap_or_default(),
            model: std::env::var("WEBPROBE_AI_MODEL").unwrap_or_else(|_| "default".into()),
            api_key: std::env::var("WEBPROBE_AI_KEY").unwrap_or_default(),
            input: String::new(),
            messages: Arc::new(Mutex::new(Vec::new())),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub const SYSTEM_PROMPT: &str = "You are a web security testing assistant inside an intercepting proxy. Explain HTTP requests and responses, point out security-relevant behaviour, and suggest concrete next tests. Be concise.";

/// The prompt "Send to WebProbe AI" builds from a history item.
pub fn explain_prompt(req: &[u8], resp: Option<&[u8]>) -> String {
    let clip = |b: &[u8]| {
        let s = String::from_utf8_lossy(b);
        if s.len() > 6000 {
            format!(
                "{}\n[... truncated ...]",
                &s[..s
                    .char_indices()
                    .take_while(|(i, _)| *i < 6000)
                    .last()
                    .map(|x| x.0)
                    .unwrap_or(0)]
            )
        } else {
            s.into_owned()
        }
    };
    let mut p = format!(
        "Explain this HTTP exchange and what I should test next.\n\nRequest:\n{}",
        clip(req)
    );
    if let Some(r) = resp {
        p.push_str(&format!("\n\nResponse:\n{}", clip(r)));
    }
    p
}

/// The chat-completions request body.
pub fn request_body(model: &str, history: &[ChatMsg]) -> String {
    let mut msgs = vec![serde_json::json!({"role": "system", "content": SYSTEM_PROMPT})];
    for m in history {
        msgs.push(serde_json::json!({"role": m.role, "content": m.text}));
    }
    serde_json::json!({"model": model, "messages": msgs, "temperature": 0.2}).to_string()
}

/// The assistant text of a chat-completions response body.
pub fn parse_reply(body: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("not JSON: {e}"))?;
    if let Some(t) = v
        .pointer("/choices/0/message/content")
        .and_then(|x| x.as_str())
    {
        return Ok(t.to_string());
    }
    if let Some(e) = v.pointer("/error/message").and_then(|x| x.as_str()) {
        return Err(e.to_string());
    }
    Err("no choices in the response".into())
}

impl AiChat {
    pub fn configured(&self) -> bool {
        self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")
    }

    /// Append the user's message and fetch the reply on a worker thread.
    pub fn send(&mut self, shared: Arc<Shared>, text: String) {
        if text.trim().is_empty() || self.busy.load(Ordering::SeqCst) {
            return;
        }
        self.messages.lock().unwrap().push(ChatMsg {
            role: "user".into(),
            text,
        });
        let history = self.messages.lock().unwrap().clone();
        let (endpoint, model, key) = (
            self.endpoint.clone(),
            self.model.clone(),
            self.api_key.clone(),
        );
        let (msgs, busy) = (Arc::clone(&self.messages), Arc::clone(&self.busy));
        busy.store(true, Ordering::SeqCst);
        crate::util::spawn_contained("ai", move || {
            let reply = complete(&shared, &endpoint, &model, &key, &history);
            let text = match reply {
                Ok(t) => t,
                Err(e) => format!("[error] {e}"),
            };
            msgs.lock().unwrap().push(ChatMsg {
                role: "assistant".into(),
                text,
            });
            busy.store(false, Ordering::SeqCst);
        });
    }
}

fn complete(
    shared: &Shared,
    endpoint: &str,
    model: &str,
    key: &str,
    history: &[ChatMsg],
) -> Result<String, String> {
    let https = endpoint.starts_with("https://");
    let rest = endpoint.split_once("://").map(|x| x.1).unwrap_or(endpoint);
    let (authority, base) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let path = if base.ends_with("/chat/completions") {
        base.to_string()
    } else if base.ends_with("/v1") {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    };
    let (host, port) = net::split_h_p(authority, if https { 443 } else { 80 });
    let body = request_body(model, history);
    let auth = if key.is_empty() {
        String::new()
    } else {
        format!("Authorization: Bearer {key}\r\n")
    };
    let raw = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nAccept: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let up = if https {
        net::send_tls_raw(shared, &host, port, raw.as_bytes())
    } else {
        net::send_raw(shared, &host, port, raw.as_bytes())
    };
    let resp = up
        .resp
        .ok_or_else(|| up.error.unwrap_or_else(|| "no response".into()))?;
    let parts = util::parse_http(&resp);
    let mut b = resp[parts.head_len.min(resp.len())..].to_vec();
    let chunked = util::get_header(&parts.headers, "Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        if let Some((d, _)) = crate::codec::decode_chunked(&b) {
            b = d;
        }
    }
    let status = parts
        .first
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let text = String::from_utf8_lossy(&b).into_owned();
    if !status.starts_with('2') {
        return Err(format!(
            "HTTP {status}: {}",
            parse_reply(&text)
                .err()
                .unwrap_or_else(|| text.chars().take(300).collect())
        ));
    }
    parse_reply(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_and_reply_round_trip() {
        let b = request_body(
            "m",
            &[ChatMsg {
                role: "user".into(),
                text: "hi".into(),
            }],
        );
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["model"], "m");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][1]["content"], "hi");
        assert_eq!(
            parse_reply(r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#)
                .unwrap(),
            "ok"
        );
        assert!(parse_reply(r#"{"error":{"message":"bad key"}}"#)
            .unwrap_err()
            .contains("bad key"));
        assert!(explain_prompt(b"GET / HTTP/1.1", Some(b"HTTP/1.1 200 OK")).contains("Response:"));
    }

    /// Live model: WEBPROBE_AI_ENDPOINT / _MODEL / _KEY. Drives the same path
    /// as the AI tab (AiChat::send on a worker thread, then the reply lands
    /// in the shared message list) with the "Send to WebProbe AI" prompt.
    #[test]
    #[ignore]
    fn live_model_explains_an_exchange() {
        let mut chat = AiChat::default();
        assert!(chat.configured(), "set WEBPROBE_AI_ENDPOINT");
        let shared = Shared::new();
        let prompt = explain_prompt(
            b"GET /rest/products/search?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3001\r\n\r\n",
            Some(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"success\",\"data\":[]}"),
        );
        chat.send(shared, prompt);
        let t0 = std::time::Instant::now();
        while chat.busy.load(Ordering::SeqCst) && t0.elapsed() < std::time::Duration::from_secs(180)
        {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let msgs = chat.messages.lock().unwrap().clone();
        eprintln!(
            "MODEL {} REPLY ({:?}):\n{}",
            chat.model,
            t0.elapsed(),
            msgs.last().map(|m| m.text.as_str()).unwrap_or("")
        );
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].role, "assistant");
        assert!(
            !msgs[1].text.starts_with("[error]") && msgs[1].text.len() > 20,
            "{}",
            msgs[1].text
        );
    }

    /// A fake OpenAI-compatible server answers the chat request.
    #[test]
    fn chat_against_a_local_server() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 65536];
            let n = s.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = r#"{"choices":[{"message":{"content":"It is a GET."}}]}"#;
            write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            req
        });
        let shared = Shared::new();
        let r = complete(
            &shared,
            &format!("http://127.0.0.1:{port}"),
            "m",
            "k",
            &[ChatMsg {
                role: "user".into(),
                text: "x".into(),
            }],
        );
        let req = t.join().unwrap();
        assert_eq!(r.unwrap(), "It is a GET.");
        assert!(
            req.starts_with("POST /v1/chat/completions") && req.contains("Authorization: Bearer k"),
            "{req}"
        );
    }
}
