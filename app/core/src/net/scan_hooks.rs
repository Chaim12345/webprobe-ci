// The net -> scan boundary (issue #38): everything the proxy needs from
// the scanner, behind a trait the scan registers at startup. With the
// calls routed through here, net no longer names scan, so a crate
// boundary can sit between them. Unregistered means the feature is off:
// tests and tools that never start the scanner see no live crawl or
// passive audit, exactly as if it were disabled.

use std::sync::{Arc, OnceLock};

use webprobe_support::hist::HistEntry;
use webprobe_support::issues::ScanIssue;

use super::Shared;

/// What net needs from the scanner.
pub trait ScanHooks: Send + Sync {
    /// Links in a proxied response, for the live passive crawl (Dashboard
    /// task 1: same-origin links become unrequested site-map items).
    fn crawl_links(&self, origin: &str, path: &str, resp: &[u8]) -> Vec<String>;
    /// The crawler's unique-location cap (CrawlDefaults.json: 1500).
    fn crawl_max_unique_locations(&self) -> usize;
    /// The live passive audit of one proxied exchange
    /// (AuditDefaults.json: scan_type_passive).
    fn passive_check_live(&self, shared: &Shared, e: &HistEntry) -> Vec<ScanIssue>;
    /// Merge a live passive audit's issues into the issue list.
    fn add_passive_issues(&self, shared: &Shared, issues: Vec<ScanIssue>);
    /// Merge issues into the issue list (extension-reported ones).
    fn add_issues(&self, shared: &Shared, issues: Vec<ScanIssue>);
    /// Burp's numeric issue type for a name, 0 when Burp has no such issue.
    fn issue_type_id(&self, name: &str) -> u64;
}

static SCAN_HOOKS: OnceLock<Arc<dyn ScanHooks>> = OnceLock::new();

/// Register the scanner's hooks; called once at app startup. A second
/// call is ignored (tests share the process).
pub fn set_scan_hooks(hooks: Arc<dyn ScanHooks>) {
    let _ = SCAN_HOOKS.set(hooks);
}

/// The registered scanner hooks, None before registration.
pub fn scan_hooks() -> Option<Arc<dyn ScanHooks>> {
    SCAN_HOOKS.get().map(Arc::clone)
}
