// Shared networking vocabulary (L8, issue #38): the suite's standard
// timeouts and bounded DNS resolution. Moved from core net::types /
// net::send so modules that only need these (upstream) no longer pull the
// net module (and its cycle) into their graph.

use std::sync::mpsc;
use std::time::Duration;

pub const CONNECT_TIMEOUT_MS: u64 = 120000;

pub const READ_TIMEOUT_MS: u64 = 120000;

pub const DNS_TIMEOUT_MS: u64 = 300000;

/// Resolve a host with the suite's DNS timeout (ProjectDefaults.json: domain_name_resolution_timeout).
pub fn resolve(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    let display = host.to_string();
    let (tx, rx) = mpsc::sync_channel::<Result<Vec<std::net::SocketAddr>, String>>(1);
    let host = host.to_string();
    crate::util::spawn_contained("net", move || {
        let r = match (host.as_str(), port).to_socket_addrs() {
            Ok(it) => Ok(it.collect::<Vec<std::net::SocketAddr>>()),
            Err(e) => Err(format!("dns {host}: {e}")),
        };
        let _ = tx.send(r);
    });
    rx.recv_timeout(Duration::from_millis(timeout_ms))
        .map_err(|_| format!("dns {display}: timed out after {timeout_ms} ms"))?
}
