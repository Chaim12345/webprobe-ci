// Per-scan-run state (issue #38): the once-per-host(-and-session) dedup
// sets the active checks share. The sets themselves live in
// webprobe_support::dedup so net::Shared can hold them without naming
// scan; this module keeps the Shared-facing accessor. Fresh by
// construction: crawl_and_audit swaps a new one in at run start, which
// replaces the hand-reset OnceLock statics (reset_openapi_hosts).

use std::sync::Arc;

use crate::net::Shared;

pub use webprobe_support::dedup::ScanDedup;

/// The run's current dedup sets: the ones swapped in when the latest scan
/// run started (Shared::new's until then).
pub fn scan_dedup_of(shared: &Shared) -> Arc<ScanDedup> {
    Arc::clone(&shared.scan_state.lock().unwrap())
}
