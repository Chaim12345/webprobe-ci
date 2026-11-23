//! Scan configuration: which audit checks run and which insertion point
//! types they attack (Burp's scan configuration "Issues reported" and
//! "Insertion point types" sections). Everything is on by default.

/// Scanner configuration (J-01). Defaults are Shared's startup values
/// (AuditDefaults.json scan_speed / scan_accuracy "normal").
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectScanner {
    /// 0 fast, 1 normal, 2 thorough.
    #[serde(default = "one_u8")]
    pub speed: u8,
    /// 0 minimise false negatives, 1 normal, 2 minimise false positives.
    #[serde(default = "one_u8")]
    pub accuracy: u8,
    #[serde(default)]
    pub extra_checks: bool,
    /// Check ids switched off in the scan configuration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_checks: Vec<String>,
    /// Insertion point types switched off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_insertion_points: Vec<String>,
    /// Crawl limits (absent: Burp's defaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_max_depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_max_locations: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_robots: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_sitemap: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_max_minutes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl_max_requests: Option<usize>,
    /// R-11: Burp's scanner.issues_reported object when the issue
    /// selection is not "everything" (absent in older projects).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issues_reported: Option<serde_json::Value>,
    /// R-11: the project's scan configuration library entries (Burp JSON,
    /// unknown keys kept).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library: Vec<ProjectLibraryConfig>,
    /// R-11: the library configurations last chosen at scan launch, in
    /// order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library_selection: Vec<String>,
}

/// One project library entry: its name and Burp's JSON for it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectLibraryConfig {
    pub name: String,
    pub config: serde_json::Value,
}

fn one_u8() -> u8 {
    1
}

impl Default for ProjectScanner {
    fn default() -> Self {
        Self {
            speed: 1,
            accuracy: 1,
            extra_checks: false,
            disabled_checks: Vec::new(),
            disabled_insertion_points: Vec::new(),
            crawl_max_depth: None,
            crawl_max_locations: None,
            crawl_robots: None,
            crawl_sitemap: None,
            crawl_engine: None,
            crawl_max_minutes: None,
            crawl_max_requests: None,
            issues_reported: None,
            library: Vec::new(),
            library_selection: Vec::new(),
        }
    }
}

/// The live scan configuration a `Shared` carries (stored in
/// `Shared::tool_state` so net does not name this type). The returned guard
/// shares one mutex across all callers, as the old `Shared::scan_config`
/// field did.
pub fn shared_config(
    shared: &crate::net::Shared,
) -> std::sync::Arc<crate::sync::Mutex<ScanConfig>> {
    shared.tool_state.get_or_insert()
}

use std::collections::BTreeSet;

/// Burp's insertion point types, as (key, label): AuditDefaults.json
/// scanner.insertion_point_types (insert_url_params, insert_body_params,
/// insert_cookies, insert_param_name, insert_http_headers,
/// insert_entire_body, insert_url_path_folders, insert_url_path_filename).
/// A key is stored only when switched off, so a configuration saved before
/// a type existed loads with that type on, as in Burp's defaults.
pub const INSERTION_TYPES: [(&str, &str); 8] = [
    ("url", "URL parameter values"),
    ("body", "Body parameter values"),
    ("cookie", "Cookie parameter values"),
    ("param_name", "Parameter name"),
    ("header", "HTTP headers"),
    ("entire_body", "Entire body"),
    ("folder", "URL path folders"),
    ("filename", "URL path filename"),
];

/// "Use nested insertion points" (AuditDefaults.json
/// scanner.misc_insertion_point_options.use_nested_insertion_points, on by
/// default), kept with the switched-off insertion types under this key.
pub const NESTED_KEY: &str = "nested";
pub const NESTED_LABEL: &str = "Use nested insertion points";

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanConfig {
    /// Check ids (see `scan::check_catalogue`) that do not run.
    pub disabled_checks: BTreeSet<String>,
    /// Insertion point type keys (see [`INSERTION_TYPES`]) not attacked.
    pub disabled_insertion: BTreeSet<String>,
    /// Crawl limits for "Crawl and audit" scans.
    pub crawl: CrawlLimits,
    /// "Issues reported" from the scan configuration library (R-11); None
    /// runs every check, as before the library existed.
    pub issues: Option<webprobe_support::scan_filter::IssueFilter>,
}

/// Burp's crawl settings (CrawlDefaults.json): link depth, unique locations,
/// and whether robots.txt and sitemap.xml are requested.
#[derive(Clone, Debug, PartialEq)]
pub struct CrawlLimits {
    pub max_depth: usize,
    pub max_locations: usize,
    pub robots: bool,
    pub sitemap: bool,
    /// crawl_limits.maximum_crawl_time in minutes (0: no limit).
    pub max_minutes: u64,
    /// crawl_limits.maximum_request_count (0: no limit).
    pub max_requests: usize,
    /// Headless engine for the JavaScript crawl: "" = Chromium over CDP
    /// (the default), or "Lightpanda" / "Obscura" (headless::js_crawl).
    pub engine: String,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        // crawl_optimization.maximum_link_depth = 4,
        // crawl_limits.maximum_unique_locations = 1500,
        // customization.request_robots_txt / request_sitemap = true,
        // crawl_limits.maximum_crawl_time = 150, maximum_request_count = 0.
        Self {
            max_depth: 4,
            max_locations: 1500,
            robots: true,
            sitemap: true,
            max_minutes: 150,
            max_requests: 0,
            engine: String::new(),
        }
    }
}

impl CrawlLimits {
    /// Whether a crawl started at `started` that has made `requests`
    /// requests must stop (maximum crawl time / request count).
    pub fn exhausted(&self, started: std::time::Instant, requests: usize) -> bool {
        (self.max_minutes > 0
            && started.elapsed() >= std::time::Duration::from_secs(self.max_minutes * 60))
            || (self.max_requests > 0 && requests >= self.max_requests)
    }
}

impl ScanConfig {
    pub fn check_enabled(&self, id: &str) -> bool {
        !self.disabled_checks.contains(id)
    }

    /// Whether checks for issue `name` run and report (see
    /// [`webprobe_support::scan_filter::filter_allows`]).
    pub fn issue_allowed(&self, name: &str, active: bool) -> bool {
        self.issues
            .as_ref()
            .is_none_or(|f| webprobe_support::scan_filter::filter_allows(f, name, active))
    }

    pub fn insertion_enabled(&self, key: &str) -> bool {
        !self.disabled_insertion.contains(key)
    }
}

impl ScanConfig {
    /// The configuration a project file holds. Ids and keys are kept as
    /// saved (unknown ones are harmless: nothing asks for them), so a check
    /// or insertion type added later loads switched on; crawl limits out of
    /// range are clamped (depth 1..=50, locations 1..=100000) and missing
    /// ones take Burp's defaults.
    pub fn from_saved(s: &ProjectScanner) -> Self {
        let d = CrawlLimits::default();
        ScanConfig {
            disabled_checks: s.disabled_checks.iter().cloned().collect(),
            disabled_insertion: s.disabled_insertion_points.iter().cloned().collect(),
            crawl: CrawlLimits {
                max_depth: s.crawl_max_depth.unwrap_or(d.max_depth).clamp(1, 50),
                max_locations: s
                    .crawl_max_locations
                    .unwrap_or(d.max_locations)
                    .clamp(1, 100_000),
                robots: s.crawl_robots.unwrap_or(d.robots),
                sitemap: s.crawl_sitemap.unwrap_or(d.sitemap),
                max_minutes: s.crawl_max_minutes.unwrap_or(d.max_minutes),
                max_requests: s.crawl_max_requests.unwrap_or(d.max_requests),
                engine: s.crawl_engine.clone().unwrap_or_default(),
            },
            issues: s.issues_reported.as_ref().and_then(|ir| {
                webprobe_support::scan_filter::IssueFilter::from_tree(
                    &serde_json::json!({"scanner": {"issues_reported": ir}}),
                )
            }),
        }
    }

    /// Write this configuration into a project's scanner section.
    pub fn save_into(&self, s: &mut ProjectScanner) {
        s.disabled_checks = self.disabled_checks.iter().cloned().collect();
        s.disabled_insertion_points = self.disabled_insertion.iter().cloned().collect();
        s.crawl_max_depth = Some(self.crawl.max_depth);
        s.crawl_max_locations = Some(self.crawl.max_locations);
        s.crawl_robots = Some(self.crawl.robots);
        s.crawl_sitemap = Some(self.crawl.sitemap);
        s.crawl_engine = Some(self.crawl.engine.clone()).filter(|e| !e.is_empty());
        s.crawl_max_minutes = Some(self.crawl.max_minutes);
        s.crawl_max_requests = Some(self.crawl.max_requests);
        s.issues_reported = self.issues.as_ref().and_then(|_| {
            webprobe_support::scan_filter::get_path(
                &config_to_tree(self, 1, 1),
                "scanner.issues_reported",
            )
            .cloned()
        });
    }
}

/// Burp's insertion point switches and WebProbe's keys for them
/// ([`INSERTION_TYPES`]).
pub(crate) const INSERTION_KEYS: [(&str, &str); 8] = [
    ("insert_url_params", "url"),
    ("insert_body_params", "body"),
    ("insert_cookies", "cookie"),
    ("insert_param_name", "param_name"),
    ("insert_http_headers", "header"),
    ("insert_entire_body", "entire_body"),
    ("insert_url_path_folders", "folder"),
    ("insert_url_path_filename", "filename"),
];

pub(crate) const SPEEDS: [&str; 3] = ["fast", "normal", "thorough"];
pub(crate) const ACCURACIES: [&str; 3] = [
    "minimise_false_negatives",
    "normal",
    "minimise_false_positives",
];

/// The scan settings WebProbe runs with, as Burp JSON: what a library
/// configuration is overlaid onto (Burp loads a configuration onto the
/// settings being edited) and what "Save" writes.
pub fn config_to_tree(c: &ScanConfig, speed: u8, accuracy: u8) -> serde_json::Value {
    let f = c
        .issues
        .clone()
        .unwrap_or(webprobe_support::scan_filter::IssueFilter {
            types_on: webprobe_support::scan_filter::CAT_PASSIVE
                | webprobe_support::scan_filter::CAT_ACTIVE
                | webprobe_support::scan_filter::CAT_JAVASCRIPT,
            selected: None,
        });
    let mut ipt = serde_json::Map::new();
    for (burp, key) in INSERTION_KEYS {
        ipt.insert(
            burp.into(),
            serde_json::Value::Bool(c.insertion_enabled(key)),
        );
    }
    let selected: Vec<serde_json::Value> = f
        .selected
        .iter()
        .flatten()
        .map(|(id, on)| serde_json::json!({"detection_methods": [], "enabled": on, "type_index": format!("0x{id:08x}")}))
        .collect();
    serde_json::json!({
        "crawler": {
            "crawl_limits": {
                "maximum_crawl_time": c.crawl.max_minutes,
                "maximum_request_count": c.crawl.max_requests,
                "maximum_unique_locations": c.crawl.max_locations,
            },
            "crawl_optimization": {"maximum_link_depth": c.crawl.max_depth},
            "customization": {"request_robots_txt": c.crawl.robots, "request_sitemap": c.crawl.sitemap},
        },
        "scanner": {
            "audit_optimization": {
                "scan_speed": SPEEDS[speed.min(2) as usize],
                "scan_accuracy": ACCURACIES[accuracy.min(2) as usize],
            },
            "issues_reported": {
                "scan_type_passive": f.types_on & webprobe_support::scan_filter::CAT_PASSIVE != 0,
                "scan_type_light_active": f.types_on & webprobe_support::scan_filter::CAT_LIGHT != 0,
                "scan_type_medium_active": f.types_on & webprobe_support::scan_filter::CAT_MEDIUM != 0,
                "scan_type_intrusive_active": f.types_on & webprobe_support::scan_filter::CAT_INTRUSIVE != 0,
                "scan_type_javascript_analysis": f.types_on & webprobe_support::scan_filter::CAT_JAVASCRIPT != 0,
                "select_individual_issues": f.selected.is_some(),
                "selected_issues": selected,
            },
            "insertion_point_types": serde_json::Value::Object(ipt),
            "misc_insertion_point_options": {"use_nested_insertion_points": c.insertion_enabled(NESTED_KEY)},
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProjectScanner;

    #[test]
    fn round_trips_through_a_project_file() {
        let mut c = ScanConfig::default();
        c.disabled_checks.insert("passive.ssn-disclosed".into());
        c.disabled_insertion.insert("header".into());
        c.disabled_insertion.insert(NESTED_KEY.into());
        c.crawl = CrawlLimits {
            max_depth: 7,
            max_locations: 200,
            robots: false,
            sitemap: true,
            max_minutes: 10,
            max_requests: 500,
            engine: "Lightpanda".into(),
        };
        let mut saved = ProjectScanner::default();
        c.save_into(&mut saved);
        let json = serde_json::to_string(&saved).unwrap();
        let back: ProjectScanner = serde_json::from_str(&json).unwrap();
        assert_eq!(ScanConfig::from_saved(&back), c);
    }

    #[test]
    fn old_and_odd_files_load_with_defaults_and_clamps() {
        // A file from before crawl limits and insertion switches existed.
        let old: ProjectScanner = serde_json::from_str(
            r#"{"speed":1,"accuracy":1,"extra_checks":false,"disabled_checks":["active.csrf"]}"#,
        )
        .unwrap();
        let c = ScanConfig::from_saved(&old);
        assert_eq!(c.crawl, CrawlLimits::default());
        assert!(!c.check_enabled("active.csrf"));
        assert!(
            c.check_enabled("passive.vulnerable-js-dependency"),
            "checks added later load on"
        );
        assert!(
            INSERTION_TYPES.iter().all(|(k, _)| c.insertion_enabled(k))
                && c.insertion_enabled(NESTED_KEY)
        );
        let odd = ProjectScanner {
            crawl_max_depth: Some(0),
            crawl_max_locations: Some(10_000_000),
            crawl_engine: Some(String::new()),
            ..ProjectScanner::default()
        };
        let c = ScanConfig::from_saved(&odd);
        assert_eq!(
            (
                c.crawl.max_depth,
                c.crawl.max_locations,
                c.crawl.engine.as_str()
            ),
            (1, 100_000, "")
        );
        let mut back = ProjectScanner::default();
        c.save_into(&mut back);
        assert_eq!(back.crawl_engine, None, "the default engine is not written");
    }
}
