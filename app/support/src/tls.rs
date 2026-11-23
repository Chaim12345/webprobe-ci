// The proxy's certificate authority and per-host TLS server configurations for
// CONNECT. Like Burp's CA (kept in its user settings), the CA persists across
// restarts so a browser or OS that trusts it keeps trusting it: the key and
// certificate parameters live in ~/.config/webprobe/ca.json (mode 0600; set
// WEBPROBE_CA_DIR to move it). No operating-system trust store is touched.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use crate::sync::Mutex;

use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SerialNumber, PKCS_RSA_SHA256,
};
use rsa::pkcs8::EncodePrivateKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use time::{Duration, OffsetDateTime};

const RSA_BITS: usize = 2048;
const CA_SERIAL_BITS: usize = 32;
const CA_NOT_BEFORE_YEAR: i32 = 2014;
const CA_VALIDITY_YEARS: i32 = 10;
const LEAF_BACKDATE_DAYS: i64 = 14;
const LEAF_VALIDITY_DAYS: i64 = 199;

/// PEM or DER input: the first PEM block's contents, or the bytes as they are.
fn der_of(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    if let (Some(a), Some(b)) = (text.find("-----BEGIN "), text.find("-----END ")) {
        let body_start = text[a..].find('\n').map(|i| a + i + 1).unwrap_or(a);
        // END before the line after BEGIN: not a PEM block (no reversed range).
        let b64: String = text
            .get(body_start..b)
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Ok(d) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
            return d;
        }
    }
    input.to_vec()
}

/// Check that `cert_der` is a CA certificate and `key_pkcs8` its private key.
fn check_ca_pair(cert_der: &[u8], key_pkcs8: &[u8]) -> Result<(Vec<u8>, KeyPair), String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("not an X.509 certificate: {e}"))?;
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|b| b.value.ca);
    if !is_ca {
        return Err(
            "the certificate is not a CA certificate (basicConstraints CA:TRUE missing)".into(),
        );
    }
    let key =
        KeyPair::try_from(key_pkcs8).map_err(|e| format!("private key (PKCS#8 expected): {e}"))?;
    if key.public_key_der() != cert.public_key().raw {
        return Err("the private key does not belong to the certificate".into());
    }
    Ok((cert_der.to_vec(), key))
}

/// Import a CA certificate and its private key (PEM or DER; PKCS#8 key),
/// as Burp's "Import certificate and key". It replaces the saved CA in `dir`
/// and takes effect on the next start. Returns the new CA's SHA-256
/// fingerprint.
pub fn import_ca(dir: &std::path::Path, cert: &[u8], key: &[u8]) -> Result<String, String> {
    let (cert_der, key_der) = (der_of(cert), der_of(key));
    check_ca_pair(&cert_der, &key_der)?;
    let enc = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
    let saved = serde_json::json!({ "imported": true, "cert_der": enc(&cert_der), "key_pkcs8": enc(&key_der) });
    let file = dir.join("ca.json");
    write_private(dir, &file, saved.to_string().as_bytes())
        .map_err(|e| format!("{}: {e}", file.display()))?;
    use sha2::Digest;
    Ok(sha2::Sha256::digest(&cert_der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn generate_rsa_key() -> Result<KeyPair, String> {
    let mut rng = rand::rngs::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, RSA_BITS)
        .map_err(|e| format!("generate RSA key: {e}"))?;
    let der = key
        .to_pkcs8_der()
        .map_err(|e| format!("encode RSA key: {e}"))?;
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(der.as_bytes()),
        &PKCS_RSA_SHA256,
    )
    .map_err(|e| format!("import RSA key: {e}"))
}

fn add_calendar_years(value: OffsetDateTime, years: i32) -> Result<OffsetDateTime, String> {
    let year = value.year() + years;
    value
        .replace_year(year)
        .or_else(|_| value.replace_day(28).and_then(|v| v.replace_year(year)))
        .map_err(|e| format!("set certificate year: {e}"))
}

// burp.Zg88.Z_: set CA notBefore to 2014 only when the current year is later.
fn ca_not_before_year(current_year: i32) -> i32 {
    current_year.min(CA_NOT_BEFORE_YEAR)
}

struct CaSeed {
    serial: u64,
    not_before: i64,
    not_after: i64,
}

/// Where the CA is kept: $WEBPROBE_CA_DIR, else $XDG_CONFIG_HOME/webprobe or
/// ~/.config/webprobe.
pub fn default_ca_dir() -> Option<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("WEBPROBE_CA_DIR") {
        return Some(d.into());
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("webprobe"))
}

/// "Regenerate CA certificate": set the stored CA aside (renamed, not
/// deleted) so the next start creates a new one. Like Burp, the running
/// session keeps the old CA until restart. Returns the backup path.
pub fn retire_ca(dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let file = dir.join("ca.json");
    if !file.exists() {
        return Err(format!("No stored CA at {}", file.display()));
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = dir.join(format!("ca.json.retired-{secs}"));
    std::fs::rename(&file, &backup).map_err(|e| format!("Could not set the CA aside: {e}"))?;
    Ok(backup)
}

/// Write a file only its owner can read (the CA private key is inside).
fn write_private(
    dir: &std::path::Path,
    file: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = file.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
    }
    std::fs::rename(tmp, file)
}

/// Per-host TLS configurations kept in memory at most.
const MAX_CACHED_HOSTS: usize = 4096;

pub struct MitmAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    next_serial: AtomicI32,
    hosts: Mutex<HashMap<String, Arc<ServerConfig>>>,
    /// One key pair for every per-host certificate, made on first use: a
    /// fresh 2048-bit RSA key per host cost a key generation on every new
    /// site (Burp's generated certificates share one key too).
    leaf_key: std::sync::OnceLock<KeyPair>,
}

impl MitmAuthority {
    /// The persistent CA (created on first run), or an in-memory one in tests.
    pub fn new() -> Result<Self, String> {
        if cfg!(test) {
            return Self::load_or_create(None);
        }
        Self::load_or_create(default_ca_dir())
    }

    /// Load the CA saved in `dir`, or create one and save it there.
    pub fn load_or_create(dir: Option<std::path::PathBuf>) -> Result<Self, String> {
        let file = dir.as_ref().map(|d| d.join("ca.json"));
        if let Some(f) = &file {
            if let Ok(text) =
                crate::util::read_text_file_capped(f, crate::util::MAX_TEXT_FILE_BYTES)
            {
                match Self::from_saved(&text) {
                    Ok(ca) => return Ok(ca),
                    Err(e) => {
                        eprintln!("webprobe: ignoring unreadable CA file {}: {e}", f.display())
                    }
                }
            }
        }
        let now = OffsetDateTime::now_utc();
        let mut rng = rand::rngs::OsRng;
        let mut serial_bytes = [0u8; CA_SERIAL_BITS / 8];
        rng.fill_bytes(&mut serial_bytes);
        let seed = CaSeed {
            serial: u64::from(u32::from_be_bytes(serial_bytes)),
            not_before: add_calendar_years(now, ca_not_before_year(now.year()) - now.year())?
                .unix_timestamp(),
            not_after: add_calendar_years(now, CA_VALIDITY_YEARS)?.unix_timestamp(),
        };
        let ca_key = generate_rsa_key()?;
        if let (Some(d), Some(f)) = (&dir, &file) {
            let saved = serde_json::json!({
                "serial": seed.serial,
                "not_before": seed.not_before,
                "not_after": seed.not_after,
                "key_pkcs8": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ca_key.serialize_der()),
            });
            if let Err(e) = write_private(d, f, saved.to_string().as_bytes()) {
                eprintln!(
                    "webprobe: could not save the CA to {}: {e}; it will change on the next start",
                    f.display()
                );
            }
        }
        Self::from_seed(&seed, ca_key)
    }

    fn from_saved(text: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if v["imported"].as_bool() == Some(true) {
            let b64 = |k: &str| {
                base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    v[k].as_str().unwrap_or_default(),
                )
                .map_err(|e| format!("{k}: {e}"))
            };
            return Self::from_imported(&b64("cert_der")?, &b64("key_pkcs8")?);
        }
        let seed = CaSeed {
            serial: v["serial"].as_u64().ok_or("no serial")?,
            not_before: v["not_before"].as_i64().ok_or("no not_before")?,
            not_after: v["not_after"].as_i64().ok_or("no not_after")?,
        };
        let der = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            v["key_pkcs8"].as_str().ok_or("no key")?,
        )
        .map_err(|e| e.to_string())?;
        let key =
            KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der), &PKCS_RSA_SHA256)
                .map_err(|e| format!("CA key: {e}"))?;
        Self::from_seed(&seed, key)
    }

    /// The CA certificate is rebuilt from its saved parameters and key; RSA
    /// PKCS#1 v1.5 signatures are deterministic, so it is byte-identical to
    /// the one a browser or OS was told to trust.
    fn from_seed(seed: &CaSeed, ca_key: KeyPair) -> Result<Self, String> {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "WebProbe Local CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.serial_number = Some(SerialNumber::from(seed.serial));
        params.not_before =
            OffsetDateTime::from_unix_timestamp(seed.not_before).map_err(|e| e.to_string())?;
        params.not_after =
            OffsetDateTime::from_unix_timestamp(seed.not_after).map_err(|e| e.to_string())?;
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| format!("generate CA: {e}"))?;
        let ca_der = ca_cert.der().clone();
        let ca_pem = ca_cert.pem();
        let now = OffsetDateTime::now_utc();
        let leaf_seed = (now.unix_timestamp_nanos() / 1_000_000) as i32;
        Ok(Self {
            ca_cert,
            ca_key,
            ca_der,
            ca_pem,
            next_serial: AtomicI32::new(leaf_seed),
            hosts: Mutex::new(HashMap::new()),
            leaf_key: std::sync::OnceLock::new(),
        })
    }

    /// A CA the user imported: leaf certificates are issued under its own
    /// subject and key, and the original certificate is the one exported
    /// and trusted.
    fn from_imported(cert_der: &[u8], key_pkcs8: &[u8]) -> Result<Self, String> {
        let (_, key) = check_ca_pair(cert_der, key_pkcs8)?;
        let params = CertificateParams::from_ca_cert_der(&CertificateDer::from(cert_der.to_vec()))
            .map_err(|e| format!("CA certificate: {e}"))?;
        let issuer = params
            .self_signed(&key)
            .map_err(|e| format!("CA certificate: {e}"))?;
        let ca_der = CertificateDer::from(cert_der.to_vec());
        let ca_pem = crate::tls::pem_armor(cert_der, "CERTIFICATE");
        let leaf_seed = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i32;
        Ok(Self {
            ca_cert: issuer,
            ca_key: key,
            ca_der,
            ca_pem,
            next_serial: AtomicI32::new(leaf_seed),
            hosts: Mutex::new(HashMap::new()),
            leaf_key: std::sync::OnceLock::new(),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// SHA-256 of the CA certificate, as colon-separated hex (what browsers
    /// show as the certificate fingerprint).
    pub fn ca_fingerprint(&self) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(self.ca_der.as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn ca_der(&self) -> CertificateDer<'static> {
        self.ca_der.clone()
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        self.listener_config(host, false)
    }

    /// The MITM config for a client of the proxy listener: with `http2`
    /// (the listener's "Support HTTP/2" option, Burp default on) ALPN offers
    /// `h2` before `http/1.1`; without, no ALPN (HTTP/1.1).
    pub fn listener_config(&self, host: &str, http2: bool) -> Result<Arc<ServerConfig>, String> {
        // Built under the cache lock: with the shared leaf key a build is one
        // signature, and two connections to a new host no longer both build.
        let key = if http2 {
            format!("{host}\0h2")
        } else {
            host.to_string()
        };
        let mut hosts = self.hosts.lock().unwrap();
        if let Some(config) = hosts.get(&key) {
            return Ok(config.clone());
        }
        let alpn = if http2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            Vec::new()
        };
        let config = self.build_config(host, alpn)?;
        // Bounded: a crawl over many hosts must not grow this forever.
        if hosts.len() >= MAX_CACHED_HOSTS {
            hosts.clear();
        }
        hosts.insert(key, config.clone());
        Ok(config)
    }

    /// A fresh server config (not cached) advertising the given ALPN protocols,
    /// e.g. `h2` for an HTTP/2 upstream test server.
    pub fn server_config_with_alpn(
        &self,
        host: &str,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<ServerConfig>, String> {
        self.build_config(host, alpn)
    }

    /// A server config that requires and verifies client certificates signed by
    /// the given roots (upstream mTLS test servers).
    pub fn server_config_with_client_auth(
        &self,
        host: &str,
        client_roots: RootCertStore,
    ) -> Result<Arc<ServerConfig>, String> {
        use rustls::server::WebPkiClientVerifier;
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|e| format!("configure client verifier: {e}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("invalid host for certificate: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let not_before = OffsetDateTime::now_utc() - Duration::days(LEAF_BACKDATE_DAYS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
        let serial = self
            .next_serial
            .fetch_add(1, Ordering::Relaxed)
            .unsigned_abs();
        params.serial_number = Some(SerialNumber::from(u64::from(serial)));
        let leaf_key = generate_rsa_key()?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign host certificate: {e}"))?;
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key.into())
            .map_err(|e| format!("configure host TLS: {e}"))?;
        Ok(Arc::new(config))
    }

    /// A client certificate signed by this CA, returned as PEM strings
    /// (certificate, PKCS8 private key) for upstream mTLS.
    pub fn client_certificate(&self, common_name: &str) -> Result<(String, String), String> {
        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| format!("invalid client certificate name: {e}"))?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let not_before = OffsetDateTime::now_utc() - Duration::days(LEAF_BACKDATE_DAYS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
        let serial = self
            .next_serial
            .fetch_add(1, Ordering::Relaxed)
            .unsigned_abs();
        params.serial_number = Some(SerialNumber::from(u64::from(serial)));
        let key = generate_rsa_key()?;
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign client certificate: {e}"))?;
        Ok((cert.pem(), pem_armor(&key.serialize_der(), "PRIVATE KEY")))
    }

    fn build_config(&self, host: &str, alpn: Vec<Vec<u8>>) -> Result<Arc<ServerConfig>, String> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("invalid host for certificate: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let not_before = OffsetDateTime::now_utc() - Duration::days(LEAF_BACKDATE_DAYS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
        // Java uses Math.abs(previous), then wrapping increment. rcgen only emits positive serials;
        // unsigned_abs deliberately maps Java's negative MIN_VALUE overflow to +2147483648.
        let serial = self
            .next_serial
            .fetch_add(1, Ordering::Relaxed)
            .unsigned_abs();
        params.serial_number = Some(SerialNumber::from(u64::from(serial)));
        let leaf_key = match self.leaf_key.get() {
            Some(k) => k,
            None => {
                let k = generate_rsa_key()?;
                let _ = self.leaf_key.set(k);
                self.leaf_key.get().ok_or("leaf key unavailable")?
            }
        };
        let leaf = params
            .signed_by(leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign host certificate: {e}"))?;
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key.into())
            .map_err(|e| format!("configure host TLS: {e}"))?;
        config.alpn_protocols = alpn;
        Ok(Arc::new(config))
    }
}

/// TLS to the targets the proxy and tools talk to. Like Burp (which does not
/// validate upstream server certificates by default), any certificate is
/// accepted: self-signed, private-CA, expired or wrong-name servers are
/// exactly what gets tested. The handshake signatures are still checked, so
/// the peer must hold the key of the certificate it presents.
pub fn upstream_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    // Offer HTTP/2 via ALPN; servers without it fall back to HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// TLS to WebProbe's own external services (the public OAST server), which
/// must be the real thing: verified against the WebPKI roots.
pub fn verified_client_config() -> Arc<ClientConfig> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config that presents a client certificate (mTLS) to upstream
/// servers, trusting the given roots.
pub fn pem_armor(der: &[u8], label: &str) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        b64.push(TBL[(n >> 18) as usize & 63] as char);
        b64.push(TBL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            b64.push(TBL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            b64.push(TBL[n as usize & 63] as char);
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn client_auth_config(
    cert_pem: &str,
    key_pem: &str,
    roots: RootCertStore,
) -> Result<Arc<ClientConfig>, String> {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
        let normalized = pem.replace("\\n", "\n");
        let body: String = normalized
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        data_encoding_decode(&body)
    }
    // Minimal PEM-armour decode (base64 body between BEGIN/END lines).
    fn data_encoding_decode(body: &str) -> Result<Vec<u8>, String> {
        const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut lut = [255u8; 256];
        for (i, &c) in TBL.iter().enumerate() {
            lut[c as usize] = i as u8;
        }
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for c in body.bytes() {
            if c == b'=' || c.is_ascii_whitespace() {
                continue;
            }
            let v = lut[c as usize];
            if v == 255 {
                return Err("invalid base64 in PEM body".into());
            }
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        Ok(out)
    }
    let cert_der = pem_to_der(cert_pem)?;
    let key_der = pem_to_der(key_pem)?;
    let key: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![CertificateDer::from(cert_der)], key)
        .map_err(|e| format!("configure client certificate: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    /// An imported CA (certificate + PKCS#8 key, PEM) is used after the next
    /// load: the trusted certificate is the original one, and host
    /// certificates it issues validate against it in a real TLS handshake.
    #[test]
    fn imported_ca_issues_host_certificates_that_chain_to_it() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
        use std::sync::Arc;
        let dir = std::env::temp_dir().join(format!("wp-ca-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Engagement Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();
        // Not a CA, and a key from elsewhere: both refused.
        let leafish = CertificateParams::new(vec!["x.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(super::import_ca(
            &dir,
            leafish.pem().as_bytes(),
            key.serialize_pem().as_bytes()
        )
        .unwrap_err()
        .contains("not a CA"));
        let other = KeyPair::generate().unwrap();
        assert!(
            super::import_ca(&dir, ca.pem().as_bytes(), other.serialize_pem().as_bytes())
                .unwrap_err()
                .contains("does not belong")
        );
        let fp =
            super::import_ca(&dir, ca.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        let auth = super::MitmAuthority::load_or_create(Some(dir.clone())).unwrap();
        assert_eq!(
            auth.ca_der().as_ref(),
            ca.der().as_ref(),
            "the imported certificate is the trusted one"
        );
        assert_eq!(auth.ca_fingerprint(), fp);
        // Handshake: client trusts only the imported CA.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let mut client =
            rustls::ClientConnection::new(client_cfg, "shop.example.test".try_into().unwrap())
                .unwrap();
        let mut server =
            rustls::ServerConnection::new(auth.server_config("shop.example.test").unwrap())
                .unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut buf.as_slice()).unwrap();
            server.process_new_packets().unwrap();
            let mut back = Vec::new();
            server.write_tls(&mut back).unwrap();
            client.read_tls(&mut back.as_slice()).unwrap();
            client
                .process_new_packets()
                .expect("host certificate chains to the imported CA");
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retiring_the_ca_renames_it_and_a_new_one_is_made_on_next_load() {
        let dir = std::env::temp_dir().join(format!(
            "wp-ca-retire-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // Nothing stored yet.
        assert!(super::retire_ca(&dir).is_err());
        let first = super::MitmAuthority::load_or_create(Some(dir.clone()))
            .unwrap()
            .ca_pem()
            .to_string();
        let again = super::MitmAuthority::load_or_create(Some(dir.clone()))
            .unwrap()
            .ca_pem()
            .to_string();
        assert_eq!(first, again, "the stored CA is reused");
        let backup = super::retire_ca(&dir).unwrap();
        assert!(backup.exists() && !dir.join("ca.json").exists());
        let fresh = super::MitmAuthority::load_or_create(Some(dir.clone()))
            .unwrap()
            .ca_pem()
            .to_string();
        assert_ne!(first, fresh, "a new CA after retiring the old one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_persists_byte_identical_across_restarts() {
        let d = std::env::temp_dir().join(format!("wp-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let a = super::MitmAuthority::load_or_create(Some(d.clone())).unwrap();
        let b = super::MitmAuthority::load_or_create(Some(d.clone())).unwrap();
        assert_eq!(a.ca_der(), b.ca_der(), "same CA after a restart");
        assert_eq!(a.ca_pem(), b.ca_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join("ca.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "private key file is owner-only");
        }
        // A leaf issued after the restart chains to the saved CA.
        assert!(b.server_config("example.test").is_ok());
        let _ = std::fs::remove_dir_all(&d);
        let c = super::MitmAuthority::load_or_create(None).unwrap();
        assert_ne!(c.ca_der(), a.ca_der(), "no directory: a fresh in-memory CA");
    }

    use super::{ca_not_before_year, CA_NOT_BEFORE_YEAR};

    #[test]
    fn ca_not_before_uses_original_year_clamp() {
        assert_eq!(ca_not_before_year(2026), CA_NOT_BEFORE_YEAR);
        assert_eq!(ca_not_before_year(2013), 2013);
    }
}
