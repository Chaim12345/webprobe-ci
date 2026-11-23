// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Client certificate rule for upstream mTLS: presented when `host_pattern`
/// matches the upstream host (exact name or `*.example.com` wildcard).
#[derive(Clone)]
pub struct ClientCertRule {
    pub host_pattern: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Exact host match or `*.suffix` wildcard (wildcard covers exactly one label).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix('*') {
        if let Some(suffix) = rest.strip_prefix('.') {
            let dotted = format!(".{suffix}");
            if let Some(prefix) = host
                .to_ascii_lowercase()
                .strip_suffix(&dotted.to_ascii_lowercase())
            {
                return !prefix.is_empty() && !prefix.contains('.');
            }
        }
    }
    false
}

/// The TLS client config for an upstream host: a per-host client certificate
/// (mTLS) when one is configured, otherwise the shared upstream config.
pub fn tls_client_config(shared: &Shared, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let base = tls_client_config_base(shared, host);
    // A sender that chose the protocol (Repeater) offers only that one.
    match H2_CHOICE.with(|c| c.get()).and_then(|c| c.want_h2) {
        Some(h2) => {
            let mut c = (*base).clone();
            c.alpn_protocols = vec![if h2 {
                b"h2".to_vec()
            } else {
                b"http/1.1".to_vec()
            }];
            Arc::new(c)
        }
        None => base,
    }
}

pub fn tls_client_config_base(shared: &Shared, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let rule = shared
        .client_certs
        .lock()
        .unwrap()
        .iter()
        .find(|r| host_matches(&r.host_pattern, host))
        .cloned();
    if let Some(rule) = rule {
        let roots = shared.tls_roots.lock().unwrap().clone();
        match crate::tls::client_auth_config(&rule.cert_pem, &rule.key_pem, roots) {
            Ok(config) => return config,
            Err(e) => shared.log(&format!("client certificate for {host} ignored: {e}")),
        }
    }
    shared.tls_upstream.clone()
}

/// Which policy won for a host: a matching client-certificate rule that
/// built (its full content is the identity, so a cert or key change is a
/// new identity), or the shared fallback config's Arc identity.
enum TlsIdentity {
    ClientCert(ClientCertRule),
    Fallback(usize),
}

/// One consistent capture of the effective upstream TLS policy for a host:
/// the config a connection is built from plus everything that shapes it
/// (the winning rule's content or the fallback identity, and the root
/// store). The h2 pool key and the connection's TLS config both derive
/// from this snapshot, so a policy mutation can never split the pool key
/// and the connection construction across two different policy states.
///
/// Concurrency guarantee: `client_certs` and `tls_roots` change only under
/// their mutexes, and capture holds both (in the same client_certs ->
/// tls_roots order `tls_client_config_base` uses) while it clones, so the
/// snapshot is a single consistent state. A mutation before capture shows
/// up in the key and the config alike; a mutation after capture changes the
/// NEXT capture's key, so a connection pooled under the old key is never
/// checked out by a request keyed under the new policy.
pub struct EffectiveTlsPolicy {
    config: std::sync::Arc<rustls::ClientConfig>,
    identity: TlsIdentity,
    roots: rustls::RootCertStore,
}

impl EffectiveTlsPolicy {
    pub fn capture(shared: &Shared, host: &str) -> Self {
        let certs = shared.client_certs.lock().unwrap();
        let roots_guard = shared.tls_roots.lock().unwrap();
        let rule = certs
            .iter()
            .find(|r| host_matches(&r.host_pattern, host))
            .cloned();
        let roots = roots_guard.clone();
        drop(roots_guard);
        drop(certs);
        let fallback = || {
            (
                shared.tls_upstream.clone(),
                TlsIdentity::Fallback(std::sync::Arc::as_ptr(&shared.tls_upstream) as usize),
            )
        };
        let (config, identity) = match rule {
            Some(rule) => {
                match crate::tls::client_auth_config(&rule.cert_pem, &rule.key_pem, roots.clone()) {
                    Ok(config) => (config, TlsIdentity::ClientCert(rule)),
                    Err(_) => fallback(),
                }
            }
            None => fallback(),
        };
        Self {
            config,
            identity,
            roots,
        }
    }

    /// The captured config with the sender's protocol choice (a Repeater
    /// ALPN pin) applied, mirroring `tls_client_config`.
    pub fn config_with_sender_choice(&self) -> std::sync::Arc<rustls::ClientConfig> {
        match H2_CHOICE.with(|c| c.get()).and_then(|c| c.want_h2) {
            Some(h2) => {
                let mut c = (*self.config).clone();
                c.alpn_protocols = vec![if h2 {
                    b"h2".to_vec()
                } else {
                    b"http/1.1".to_vec()
                }];
                std::sync::Arc::new(c)
            }
            None => self.config.clone(),
        }
    }

    /// A hash of everything in the snapshot that shapes the TLS connection:
    /// the winning rule's full content or the fallback identity, and every
    /// root's subject, SPKI and name constraints.
    pub fn key_identity(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        match &self.identity {
            TlsIdentity::ClientCert(rule) => {
                1u8.hash(&mut h);
                rule.host_pattern.hash(&mut h);
                rule.cert_pem.hash(&mut h);
                rule.key_pem.hash(&mut h);
            }
            TlsIdentity::Fallback(ptr) => {
                0u8.hash(&mut h);
                ptr.hash(&mut h);
            }
        }
        self.roots.len().hash(&mut h);
        for root in self.roots.roots.iter() {
            root.subject.as_ref().hash(&mut h);
            root.subject_public_key_info.as_ref().hash(&mut h);
            root.name_constraints
                .as_ref()
                .map(AsRef::as_ref)
                .hash(&mut h);
        }
        h.finish()
    }
}
