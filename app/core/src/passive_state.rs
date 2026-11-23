//! Passive-scan state that spans responses (R-04). Burp keeps it in its
//! per-host state (burp.Zf8t.ZDZ, the `ZE` map of burp.Zirr) for the life
//! of the project; here it lives on `Shared::passive` and is cleared when a
//! project is loaded.
//!
//! What it holds: for each host, the paths forms with password fields post
//! to, the names of those fields, and the last password submitted to each
//! (burp.Zcn0.ZG / Zc / ZW).

use crate::sync::Mutex;
use std::collections::BTreeMap;

/// A password value submitted to a known password field.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Submitted {
    /// The value as sent (raw, not URL-decoded: burp.Zxo6 keeps `Zwwc.ZO`).
    pub value: String,
    /// The request that submitted it, kept as evidence.
    pub request: Vec<u8>,
}

/// host -> form action path -> password field name -> last value.
type Forms = BTreeMap<String, BTreeMap<String, BTreeMap<String, Option<Submitted>>>>;

#[derive(Default)]
pub struct PassiveState {
    forms: Mutex<Forms>,
}

/// burp.Zcn0.storePasswordFieldName(String): a value that is likely a real
/// password: 6 characters or more and not one of Burp's placeholders.
fn password_like(v: &str) -> bool {
    v.len() >= 6 && !["password", "script", "javascript"].contains(&v)
}

impl PassiveState {
    pub fn clear(&self) {
        self.forms.lock().unwrap().clear();
    }

    /// A form posting to `host` `path` has a password field `field`
    /// (burp.Zcn0.ZG): remembered without a value unless already known.
    pub(crate) fn note_password_field(&self, host: &str, path: &str, field: &str) {
        let mut f = self.forms.lock().unwrap();
        f.entry(host.to_string())
            .or_default()
            .entry(path.to_string())
            .or_default()
            .entry(field.to_string())
            .or_insert(None);
    }

    /// A request to `host` `path` with these (name, raw value) parameters
    /// (burp.Zcn0.Zc / ZW): each parameter named like a known password field
    /// records its value when it looks like a password, else clears it.
    /// Returns the passwords this request submitted.
    pub(crate) fn submit(
        &self,
        host: &str,
        path: &str,
        params: &[(String, String)],
        request: &[u8],
    ) -> Vec<Submitted> {
        let mut f = self.forms.lock().unwrap();
        let Some(fields) = f.get_mut(host).and_then(|h| h.get_mut(path)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (name, value) in params {
            if let Some(slot) = fields.get_mut(name) {
                if password_like(value) {
                    let s = Submitted {
                        value: value.clone(),
                        request: request.to_vec(),
                    };
                    *slot = Some(s.clone());
                    out.push(s);
                } else {
                    *slot = None;
                }
            }
        }
        out
    }

    /// Every password submitted earlier on `host`, with the path it was
    /// submitted to (burp.Zcn0.ZQ).
    pub(crate) fn submitted_on(&self, host: &str) -> Vec<(String, Submitted)> {
        let f = self.forms.lock().unwrap();
        f.get(host)
            .map(|paths| {
                paths
                    .iter()
                    .flat_map(|(p, fields)| {
                        fields
                            .values()
                            .flatten()
                            .map(move |s| (p.clone(), s.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_submitted_passwords_per_host_and_path() {
        let s = PassiveState::default();
        assert!(
            s.submit("h", "/login", &[("pw".into(), "hunter22".into())], b"r")
                .is_empty(),
            "unknown field"
        );
        s.note_password_field("h", "/login", "pw");
        assert!(s
            .submit("h", "/login", &[("pw".into(), "short".into())], b"r")
            .is_empty());
        let got = s.submit(
            "h",
            "/login",
            &[
                ("user".into(), "bob".into()),
                ("pw".into(), "hunter22".into()),
            ],
            b"r",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(
            s.submitted_on("h"),
            vec![("/login".to_string(), got[0].clone())]
        );
        s.note_password_field("h", "/login", "pw");
        assert_eq!(
            s.submitted_on("h").len(),
            1,
            "a known field keeps its value"
        );
        assert!(s.submitted_on("other").is_empty());
        s.clear();
        assert!(s.submitted_on("h").is_empty());
    }
}
