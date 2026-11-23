// Per-scan-run dedup sets (issue #38), moved from core scan::state so
// net::Shared can hold them without naming scan. Owned by the scan and
// fresh by construction: crawl_and_audit swaps a new one in at run start.

use std::collections::HashSet;

use crate::sync::Mutex;

/// Dedup sets the active checks share for one scan run (and, until the
/// next run starts, the session: standalone audits of an already-probed
/// host stay quiet, matching the old statics).
#[derive(Default)]
pub struct ScanDedup {
    /// Hosts already probed by the per-host OpenAPI check (Burp runs APH_
    /// checks once per host).
    pub openapi_hosts: Mutex<HashSet<String>>,
    /// Hosts already probed by the collaborator-everywhere check
    /// (burp.Zc7h, once per host).
    pub everywhere_hosts: Mutex<HashSet<String>>,
}
