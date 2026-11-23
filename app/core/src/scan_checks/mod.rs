// Active-scan check interface and registry.
//
// `start_active_scan` (scan.rs) is a short driver: it fetches the baseline,
// builds a `ScanCtx`, runs every `PointCheck` of `POINT_CHECKS` on each
// insertion point and then every `RequestCheck` of `REQUEST_CHECKS` once.
// Burp models the same split: insertion-point checks (burp.Zi6p, Zp3a, ...)
// versus per-request and per-host checks (burp.Zs6x TRACE, the APH_ OpenAPI
// checks).
//
// Each check wraps one of the pure `run_*_check(value, baseline, ..., send)`
// functions in scan.rs / active_checks.rs / xss.rs / burp_checks.rs without
// changing them. The bodies below are the blocks that used to sit inline in
// `start_active_scan`, in the same order and under the same conditions: the
// order matters because later checks see the state earlier ones leave
// (`sqli_reported`, the stored-echo markers, the Collaborator slots used) and
// it decides which of two duplicate issues is reported first.

// The cache submodule sees the scan module the way it did as an inline
// child of scan_checks.rs: through this glob.
#[allow(unused_imports)]
pub(crate) use super::*;

#[path = "cache_checks.rs"]
pub(crate) mod cache;

mod collaborator_everywhere;
mod context;
mod evidence;
mod graphql;
mod interface;
mod point_checks;
mod request_checks;
mod stored_input;

pub use collaborator_everywhere::*;
pub(crate) use context::*;
pub use evidence::*;
pub use graphql::*;
pub(crate) use interface::*;
pub use point_checks::*;
pub use request_checks::*;
pub use stored_input::*;

#[cfg(test)]
mod graphql_tests;
#[cfg(test)]
mod tests;
