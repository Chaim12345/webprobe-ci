// The proxy's own setup page (http://webprobe, http://burpsuite) and CA
// downloads, answered by the listener instead of being sent upstream.

/// Hosts answered locally instead of being proxied upstream.
pub const SETUP_HOSTS: [&str; 2] = ["webprobe", "burpsuite"];

/// The page served for `http://webprobe` and `http://burpsuite`.
///
/// Burp's page tells you to download the certificate and explains that the
/// browser must already be proxying through the listener; this keeps that shape
/// (and the same two download formats) without copying its assets.
pub fn setup_page(port: u16) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>WebProbe</title>\
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:44em;margin:3em auto;padding:0 1em;color:#1b1f24}}\
h1{{margin:0 0 .25em}}code,pre{{font-family:ui-monospace,monospace;background:#f2f4f6;padding:.1em .35em;border-radius:3px}}\
pre{{padding:.8em;overflow:auto}}a{{color:#0b5cad}}li{{margin:.35em 0}}</style></head><body>\
<h1>WebProbe proxy</h1>\
<p>Your browser reached WebProbe through its proxy (main listener <code>127.0.0.1:{port}</code>; WebProbe's own browser uses a private listener). \
If you are reading this, the listener is running and your browser is configured correctly.</p>\
<h2>1. Install the CA certificate</h2>\
<p>WebProbe signs the per-host HTTPS certificates with its own CA, kept on this machine (owner-only file) and reused across restarts. \
WebProbe's built-in browser already trusts it. For any other browser or device, trust it once to browse HTTPS without warnings:</p>\
<ul><li><a href=\"/webprobe-ca.pem\">Download the CA certificate (PEM)</a> &mdash; for Firefox, macOS Keychain, Android</li>\
<li><a href=\"/webprobe-ca.der\">Download the CA certificate (DER)</a> &mdash; for Windows, iOS, Java</li></ul>\
<h2>2. Check the listener</h2>\
<p>The listener is on <code>127.0.0.1:{port}</code>. WebProbe's Dashboard shows it as the first checklist step.</p>\
<h2>3. Verify</h2>\
<p>Visit any HTTPS URL. The browser should load it with no security warning, and the request appears in Proxy &gt; HTTP history with the padlock marked.</p>\
<h2>4. Interception</h2>\
<p>Press <code>Ctrl+T</code> to hold messages, <code>Ctrl+F</code> to forward a held request, and <code>Ctrl+K</code> for the command palette.</p>\
<hr><p style=\"color:#666\">Reference documentation for the original tool: \
<a href=\"https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate\">installing a CA certificate</a>, \
<a href=\"https://portswigger.net/burp/documentation/desktop/settings/ui/hotkeys.html\">hotkeys</a>.</p>\
</body></html>"
    )
}

/// True when this request is for the local setup page (or the CA download) and
/// should be answered by the proxy instead of being sent upstream.
pub fn local_response(
    host: &str,
    path: &str,
    port: u16,
    ca_pem: &str,
    ca_der: &[u8],
) -> Option<Vec<u8>> {
    let host = host.split(':').next().unwrap_or(host);
    if !SETUP_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return None;
    }
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let (body, content_type): (Vec<u8>, &str) = match path {
        "/webprobe-ca.pem" => (ca_pem.as_bytes().to_vec(), "application/x-pem-file"),
        "/webprobe-ca.der" | "/cert" | "/burp/cert" => (ca_der.to_vec(), "application/pkix-cert"),
        _ => (setup_page(port).into_bytes(), "text/html; charset=utf-8"),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(&body);
    Some(out)
}
