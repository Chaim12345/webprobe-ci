//! WebSocket match and replace (R-07): Burp's Proxy settings > "WebSocket
//! match and replace rules" (Zcgm; key `proxy.ws_match_replace_rules`,
//! default none; "Only apply to in-scope items" is
//! `proxy.ws_match_replace_disable_out_of_scope`, default off). A rule
//! applies to messages in one direction; its match is a literal string or a
//! regex. Text messages are matched as text; binary messages byte for byte
//! (a literal as its UTF-8 bytes, a regex over the bytes), so a binary
//! payload never goes through a lossy text conversion.

use serde::{Deserialize, Serialize};

/// One rule, under Burp's JSON key names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsRule {
    pub enabled: bool,
    /// "client_to_server" or "server_to_client".
    pub rule_type: String,
    pub string_match: String,
    pub string_replace: String,
    /// Burp's "is_simple_match": true = literal, false = regex.
    #[serde(default = "yes")]
    pub is_simple_match: bool,
    #[serde(default)]
    pub comment: String,
}

fn yes() -> bool {
    true
}

impl WsRule {
    pub fn new(to_server: bool, string_match: &str, string_replace: &str) -> Self {
        WsRule {
            enabled: true,
            rule_type: if to_server {
                "client_to_server"
            } else {
                "server_to_client"
            }
            .into(),
            string_match: string_match.into(),
            string_replace: string_replace.into(),
            is_simple_match: true,
            comment: String::new(),
        }
    }

    pub fn to_server(&self) -> bool {
        self.rule_type == "client_to_server"
    }

    pub fn applies_to(&self, to_server: bool) -> bool {
        self.rule_type == "both" || self.to_server() == to_server
    }

    /// The label Burp's rule table shows for the type.
    pub fn type_label(&self) -> &'static str {
        match self.rule_type.as_str() {
            "client_to_server" => "Client to server",
            "server_to_client" => "Server to client",
            "both" => "Both directions",
            _ => "Unknown",
        }
    }
}

/// Apply the enabled rules for this direction in order; the new payload
/// when any rule changed it. An empty match adds the replacement at the
/// end, as Burp's HTTP rules add a header.
pub fn apply(rules: &[WsRule], to_server: bool, binary: bool, payload: &[u8]) -> Option<Vec<u8>> {
    let mut cur = payload.to_vec();
    for r in rules
        .iter()
        .filter(|r| r.enabled && r.applies_to(to_server))
    {
        cur = if r.string_match.is_empty() {
            let mut v = cur;
            v.extend_from_slice(r.string_replace.as_bytes());
            v
        } else if r.is_simple_match {
            replace_bytes(&cur, r.string_match.as_bytes(), r.string_replace.as_bytes())
        } else if binary {
            match regex::bytes::Regex::new(&r.string_match) {
                Ok(re) => re
                    .replace_all(&cur, r.string_replace.as_bytes())
                    .into_owned(),
                Err(_) => cur,
            }
        } else {
            match regex::Regex::new(&r.string_match) {
                Ok(re) => re
                    .replace_all(&String::from_utf8_lossy(&cur), r.string_replace.as_str())
                    .into_owned()
                    .into_bytes(),
                Err(_) => cur,
            }
        };
    }
    (cur != payload).then_some(cur)
}

fn replace_bytes(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_apply_per_direction_to_text_and_binary() {
        let mut rx = WsRule::new(true, r"id=(\d+)", "id=9$1");
        rx.is_simple_match = false;
        let rules = vec![
            WsRule::new(true, "hello", "HELLO"),
            WsRule::new(false, "x", "y"),
            rx,
        ];
        assert_eq!(
            apply(&rules, true, false, b"hello id=1").unwrap(),
            b"HELLO id=91"
        );
        assert_eq!(
            apply(&rules, false, false, b"hello"),
            None,
            "other direction only"
        );
        let both = vec![WsRule {
            rule_type: "both".into(),
            ..WsRule::new(true, "hello", "HELLO")
        }];
        assert_eq!(apply(&both, true, false, b"hello"), Some(b"HELLO".to_vec()));
        assert_eq!(
            apply(&both, false, false, b"hello"),
            Some(b"HELLO".to_vec())
        );
        // Binary: bytes around the match survive, invalid UTF-8 included.
        let bin = [0xff, b'h', b'e', b'l', b'l', b'o', 0x80, 0x00];
        assert_eq!(
            apply(&rules, true, true, &bin).unwrap(),
            [0xff, b'H', b'E', b'L', b'L', b'O', 0x80, 0x00]
        );
        let mut off = rules.clone();
        off.iter_mut().for_each(|r| r.enabled = false);
        assert_eq!(apply(&off, true, false, b"hello"), None);
        let v = serde_json::to_value(&rules[0]).unwrap();
        for k in [
            "enabled",
            "rule_type",
            "string_match",
            "string_replace",
            "is_simple_match",
            "comment",
        ] {
            assert!(v.get(k).is_some(), "{k}");
        }
    }
}
