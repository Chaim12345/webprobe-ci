// Split from scan.rs (L5, issue #35): scan is now a module directory.

use crate::net::{self, HistEntry, Shared};
use crate::util;
pub(crate) use insertion::{audit_points, inject, inject_payload, InsertionPoint, IpKind};
#[cfg(test)]
pub(crate) use insertion::{insertion_points, NameSite, SYNTH_REFERER};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Burp active-check families ported for D-02 (PHP echo-based code
/// injection, stored XSS, client-side template injection, the out-of-band
/// half of XML injection): pure functions over send closures.
#[path = "../active_checks.rs"]
pub(crate) mod active_checks;
/// The active-scan check interface (`PointCheck`, `RequestCheck`), the check
/// registries and the scan context `start_active_scan` drives them with.
#[path = "../scan_checks/mod.rs"]
pub(crate) mod checks;
#[path = "../csp.rs"]
pub(crate) mod csp;
/// Insertion points: Burp's point types, builder, vetoes, payload placement
/// and point wording (burp.Zbg8, Zuq, Zwez, Zfw9, Zsg0).
#[path = "../insertion.rs"]
pub(crate) mod insertion;
/// Content security policy issues (burp.Zxr9 / Zupz / Zifp).
#[path = "../passive_pack.rs"]
pub(crate) mod pack;
/// Passive checks, one registered unit each (R-04).
#[path = "../passive_checks.rs"]
pub(crate) mod passive_checks;
#[path = "../retirejs.rs"]
pub(crate) mod retirejs;

mod passive_library;
pub use passive_library::*;

mod issue_types;
pub(crate) use issue_types::mk_point;
pub use issue_types::*;

mod passive_merge;
pub use passive_merge::*;

mod passive_helpers;
pub use passive_helpers::*;

mod passive_entry;
pub use passive_entry::*;

mod engine;
mod hooks;
mod state;
pub use engine::*;
pub use hooks::*;
pub use state::*;

mod checks_header_redirect;
pub use checks_header_redirect::*;

mod checks_traversal;
pub use checks_traversal::*;

mod checks_xxe;
pub use checks_xxe::*;

mod checks_csrf;
pub use checks_csrf::*;

mod checks_link_file;
pub use checks_link_file::*;

mod checks_ssi_ssti;
pub use checks_ssi_ssti::*;

mod checks_sql;
pub use checks_sql::*;

mod checks_ldap_xml;
pub use checks_ldap_xml::*;

mod detect_misc;
pub use detect_misc::*;
pub use webprobe_support::tasks::SmtpOob;

mod request_builders;
pub(crate) use request_builders::reflected_xss_severity;
pub use request_builders::*;

#[cfg(test)]
mod passive_helpers_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod passive_library_tests;
