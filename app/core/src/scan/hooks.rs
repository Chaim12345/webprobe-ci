// The scanner's side of the net boundary (issue #38): the ScanHooks impl
// the app registers at startup so net's live crawl, live passive audit
// and issue bookkeeping work without net naming scan.

use std::sync::Arc;

use webprobe_support::hist::HistEntry;
use webprobe_support::issues::ScanIssue;

use super::*;
use crate::net::ScanHooks;

struct LiveHooks;

impl ScanHooks for LiveHooks {
    fn crawl_links(&self, origin: &str, path: &str, resp: &[u8]) -> Vec<String> {
        crate::crawl::crawl_links(origin, path, resp)
    }

    fn crawl_max_unique_locations(&self) -> usize {
        CRAWL_MAX_UNIQUE_LOCATIONS
    }

    fn passive_check_live(&self, shared: &Shared, e: &HistEntry) -> Vec<ScanIssue> {
        passive_check_live(shared, e)
    }

    fn add_passive_issues(&self, shared: &Shared, issues: Vec<ScanIssue>) {
        add_passive_issues(shared, issues);
    }

    fn add_issues(&self, shared: &Shared, issues: Vec<ScanIssue>) {
        add_issues(shared, issues);
    }

    fn issue_type_id(&self, name: &str) -> u64 {
        issue_type_id(name)
    }
}

/// Register the scanner with net; call once at app startup before proxy
/// traffic (the live passive crawl and audit run on proxy responses).
/// Browser-driven crawl support, registered by the headless module when a
/// browser driver is linked in. With none registered, a crawl configured
/// for a browser engine falls back to the static crawl, as an engine that
/// is not installed does.
/// The js_crawl op: render a URL with the named engine, returning the
/// pages it found; None when the engine is not installed.
pub type JsCrawl =
    fn(&str, &std::sync::Arc<crate::net::Shared>, &str) -> Option<Result<Vec<String>, String>>;

pub struct BrowserCrawl {
    /// Render `url` with the named engine and return the pages it found;
    /// None when the engine is not installed.
    pub js_crawl: JsCrawl,
    /// The display name of the named engine, when it is installed.
    pub engine_name: fn(&str) -> Option<String>,
}

static BROWSER_CRAWL: std::sync::OnceLock<BrowserCrawl> = std::sync::OnceLock::new();

/// Register the browser crawl driver (app and headless startup).
pub fn register_browser_crawl(bc: BrowserCrawl) {
    let _ = BROWSER_CRAWL.set(bc);
}

/// The registered browser crawl driver, when one is.
pub fn browser_crawl() -> Option<&'static BrowserCrawl> {
    BROWSER_CRAWL.get()
}

/// Register the entry points the task queue runner drives (app and
/// headless startup, next to register_scan_hooks).
pub fn register_task_ops() {
    crate::tasks::register_scan_ops(crate::tasks::ScanOps {
        crawl_and_audit: |shared, urls, audit_only| {
            crate::scan::crawl_and_audit(shared, urls, audit_only)
        },
        start_active_scan: |shared, entry, oob, smtp| {
            crate::scan::start_active_scan(shared, entry, oob, smtp)
        },
        pooled_oob: |shared, req_raw| crate::scan::pooled_oob(shared, req_raw),
        open_stored_batch: |shared| Box::new(crate::scan::StoredBatch::open(shared)),
    });
}

pub fn register_scan_hooks() {
    crate::net::set_scan_hooks(Arc::new(LiveHooks));
}
