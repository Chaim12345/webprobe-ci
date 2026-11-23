//! R-11: Burp's scan configuration library. Configurations are kept as
//! Burp's own JSON tree (`crawler` / `scanner` / `description`), so every
//! key, including ones WebProbe does not know, is stored and exported
//! unchanged. Burp's 29 built-in configurations are read from the user's
//! Burp install (`paths::Lookup::burp_scan_configs`: an extracted
//! `BuiltInConfigs` directory or burpsuite.jar), never copied into WebProbe.
//!
//! Combining (burp.Zhw5.Zx / Zibv / Zbqe.Zm): Burp's scan launcher loads a
//! library configuration onto the settings being edited; each option model
//! reads its key with the current value as the fallback (for example
//! burp.Zb1q:107 `var1.Zn("scanner.insertion_point_types.insert_http_headers",
//! this.ZpM())`, burp.Zmzw:95-99 for the scan types), so a key the loaded
//! configuration sets replaces the current value and every other key is
//! left alone. Loading several in turn is therefore a per-key overlay in
//! load order, the last one winning (burp.Zxm6.Ze:606-631 is the same rule
//! for trees: replace by key, append new keys). Arrays (selected issues,
//! parameter lists) are single values: a later list replaces the earlier
//! one whole.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::{Map, Value};

use crate::paths::BurpResources;

/// A configuration file larger than this is rejected (Burp's largest
/// built-in, "Audit checks - critical issues only", is about 30 KB).
pub const MAX_CONFIG_BYTES: usize = 1 << 20;

/// One library entry.
#[derive(Clone, Debug, PartialEq)]
pub struct LibraryConfig {
    /// File name without `.json` (Burp's library name, burp.Zb2v / Zsnv).
    pub name: String,
    /// The configuration as Burp's JSON object.
    pub tree: Value,
    /// One of Burp's built-in configurations (read-only in the library).
    pub built_in: bool,
}

impl LibraryConfig {
    /// The library's "Functions" column: whether the configuration has
    /// crawl and/or audit settings.
    pub fn functions(&self) -> (bool, bool) {
        (
            self.tree.get("crawler").is_some(),
            self.tree.get("scanner").is_some(),
        )
    }

    /// Burp's JSON for export (pretty-printed, keys as loaded).
    pub fn to_burp_json(&self) -> String {
        serde_json::to_string_pretty(&self.tree).unwrap_or_else(|_| "{}".into())
    }

    /// The configuration's leaf settings as dotted key paths
    /// (`scanner.issues_reported.scan_type_passive`), `description` left out.
    pub fn setting_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Value::Object(m) = &self.tree {
            for (k, v) in m {
                if k != "description" {
                    leaf_paths(k, v, &mut out);
                }
            }
        }
        out
    }
}

fn leaf_paths(prefix: &str, v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, c) in m {
                leaf_paths(&format!("{prefix}.{k}"), c, out);
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

/// The JSON type a known setting must have.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Bool,
    Int,
    Str,
    List,
    Object,
}

/// Settings whose type is checked on load (a wrong type rejects the file,
/// as Burp's schema would). Every other key is accepted and kept as is.
const TYPED: &[(&str, Kind)] = &[
    ("crawler", Kind::Object),
    ("scanner", Kind::Object),
    ("description", Kind::Object),
    ("crawler.crawl_limits.maximum_crawl_time", Kind::Int),
    ("crawler.crawl_limits.maximum_request_count", Kind::Int),
    ("crawler.crawl_limits.maximum_unique_locations", Kind::Int),
    ("crawler.crawl_optimization.crawl_strategy", Kind::Str),
    ("crawler.crawl_optimization.maximum_link_depth", Kind::Int),
    ("crawler.customization.request_robots_txt", Kind::Bool),
    ("crawler.customization.request_sitemap", Kind::Bool),
    ("scanner.audit_optimization.scan_speed", Kind::Str),
    ("scanner.audit_optimization.scan_accuracy", Kind::Str),
    (
        "scanner.audit_optimization.maximum_crawl_and_audit_time",
        Kind::Int,
    ),
    ("scanner.issues_reported.scan_type_passive", Kind::Bool),
    ("scanner.issues_reported.scan_type_light_active", Kind::Bool),
    (
        "scanner.issues_reported.scan_type_medium_active",
        Kind::Bool,
    ),
    (
        "scanner.issues_reported.scan_type_intrusive_active",
        Kind::Bool,
    ),
    (
        "scanner.issues_reported.scan_type_javascript_analysis",
        Kind::Bool,
    ),
    (
        "scanner.issues_reported.select_individual_issues",
        Kind::Bool,
    ),
    (
        "scanner.issues_reported.scan_only_selected_issues",
        Kind::Bool,
    ),
    ("scanner.issues_reported.selected_issues", Kind::List),
    (
        "scanner.insertion_point_types.insert_url_params",
        Kind::Bool,
    ),
    (
        "scanner.insertion_point_types.insert_body_params",
        Kind::Bool,
    ),
    ("scanner.insertion_point_types.insert_cookies", Kind::Bool),
    (
        "scanner.insertion_point_types.insert_param_name",
        Kind::Bool,
    ),
    (
        "scanner.insertion_point_types.insert_http_headers",
        Kind::Bool,
    ),
    (
        "scanner.insertion_point_types.insert_entire_body",
        Kind::Bool,
    ),
    (
        "scanner.insertion_point_types.insert_url_path_folders",
        Kind::Bool,
    ),
    (
        "scanner.insertion_point_types.insert_url_path_filename",
        Kind::Bool,
    ),
    (
        "scanner.misc_insertion_point_options.use_nested_insertion_points",
        Kind::Bool,
    ),
    (
        "scanner.misc_insertion_point_options.max_insertion_points_per_base_request",
        Kind::Int,
    ),
    (
        "scanner.ignored_insertion_points.skip_all_tests_for_parameters",
        Kind::List,
    ),
    (
        "scanner.ignored_insertion_points.skip_server_side_injection_for_parameters",
        Kind::List,
    ),
];

fn kind_ok(kind: Kind, v: &Value) -> bool {
    match kind {
        Kind::Bool => v.is_boolean(),
        Kind::Int => v.is_i64() || v.is_u64(),
        Kind::Str => v.is_string(),
        Kind::List => v.is_array(),
        Kind::Object => v.is_object(),
    }
}

/// Parse one configuration file (Burp JSON). Rejects: oversize input,
/// invalid JSON, a top level that is not an object, a known setting of the
/// wrong type, and selected-issue entries without a `type_index` Burp could
/// read. Unknown keys are kept.
pub use webprobe_support::scan_filter::*;

pub fn parse_config(name: &str, bytes: &[u8], built_in: bool) -> Result<LibraryConfig, String> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(format!("{name}: larger than {} bytes", MAX_CONFIG_BYTES));
    }
    let tree: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("{name}: not valid JSON ({e})"))?;
    if !tree.is_object() {
        return Err(format!("{name}: a scan configuration is a JSON object"));
    }
    for (path, kind) in TYPED {
        if let Some(v) = get_path(&tree, path) {
            if !kind_ok(*kind, v) {
                return Err(format!(
                    "{name}: {path} has the wrong type (expected {kind:?})"
                ));
            }
        }
    }
    if let Some(Value::Array(items)) = get_path(&tree, "scanner.issues_reported.selected_issues") {
        for (i, it) in items.iter().enumerate() {
            if parse_type_index(it.get("type_index")).is_none() {
                return Err(format!(
                    "{name}: selected_issues[{i}] has no valid type_index"
                ));
            }
        }
    }
    let name = name.trim();
    if name.is_empty() {
        return Err("a scan configuration needs a name".into());
    }
    Ok(LibraryConfig {
        name: name.to_string(),
        tree,
        built_in,
    })
}

/// Loading result: every configuration that parsed, and one message per
/// file that did not (shown in the library, never fatal).
#[derive(Debug, Default)]
pub struct LoadReport {
    pub configs: Vec<LibraryConfig>,
    pub errors: Vec<String>,
}

/// Burp's built-in configurations from `src`, sorted by name.
pub fn load_builtin(src: &BurpResources) -> Result<LoadReport, String> {
    let files = match src {
        BurpResources::Dir(d) => dir_json_files(d)?,
        BurpResources::Jar(j) => jar_files(j, "resources/BuiltInConfigs/")?,
    };
    let mut rep = LoadReport::default();
    for (name, bytes) in files {
        match parse_config(&name, &bytes, true) {
            Ok(c) => rep.configs.push(c),
            Err(e) => rep.errors.push(e),
        }
    }
    rep.configs.sort_by_key(|a| a.name.to_lowercase());
    Ok(rep)
}

/// Burp's default scan settings (Preferences/AuditDefaults.json and
/// CrawlDefaults.json, merged), when `src` has them.
pub fn load_burp_defaults(src: &BurpResources) -> Option<Value> {
    let files: Vec<(String, Vec<u8>)> = match src {
        BurpResources::Dir(d) => {
            let prefs = d.parent()?.join("Preferences");
            ["AuditDefaults", "CrawlDefaults"]
                .iter()
                .filter_map(|n| {
                    read_capped_file(&prefs.join(format!("{n}.json")))
                        .ok()
                        .map(|b| (n.to_string(), b))
                })
                .collect()
        }
        BurpResources::Jar(j) => jar_files(j, "resources/Preferences/")
            .ok()?
            .into_iter()
            .filter(|(n, _)| n == "AuditDefaults" || n == "CrawlDefaults")
            .collect(),
    };
    let mut out = Value::Object(Map::new());
    let mut any = false;
    for (_, b) in files {
        if let Ok(v @ Value::Object(_)) = serde_json::from_slice::<Value>(&b) {
            overlay(&mut out, &v);
            any = true;
        }
    }
    any.then_some(out)
}

/// Overlay `top` onto `base`: objects merge key by key, any other value
/// (including arrays) replaces. `description` is library metadata and is
/// not merged.
pub fn overlay(base: &mut Value, top: &Value) {
    let Value::Object(t) = top else {
        *base = top.clone();
        return;
    };
    if !base.is_object() {
        *base = Value::Object(Map::new());
    }
    let Value::Object(b) = base else { return };
    for (k, v) in t {
        if k == "description" {
            continue;
        }
        match (b.get_mut(k), v) {
            (Some(slot @ Value::Object(_)), Value::Object(_)) => overlay_inner(slot, v),
            _ => {
                b.insert(k.clone(), v.clone());
            }
        }
    }
}

fn overlay_inner(base: &mut Value, top: &Value) {
    if let (Value::Object(b), Value::Object(t)) = (base, top) {
        for (k, v) in t {
            match (b.get_mut(k), v) {
                (Some(slot @ Value::Object(_)), Value::Object(_)) => overlay_inner(slot, v),
                _ => {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
    }
}

/// The settings a scan runs with: `defaults` (Burp's, when found) with
/// each configuration overlaid in order, the last one winning per key.
pub fn combine(defaults: Option<&Value>, configs: &[&LibraryConfig]) -> Value {
    let mut out = defaults
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    for c in configs {
        overlay(&mut out, &c.tree);
    }
    out
}

fn read_capped_file(p: &Path) -> Result<Vec<u8>, String> {
    let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut out = Vec::new();
    f.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(out)
}

/// `(name without .json, bytes)` for each `*.json` in `dir`. Files over the
/// cap are returned truncated past the cap so `parse_config` rejects them.
fn dir_json_files(dir: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "json") && p.is_file() {
            let name = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            match read_capped_file(&p) {
                Ok(b) => out.push((name, b)),
                Err(e) => out.push((name, e.into_bytes())),
            }
        }
    }
    Ok(out)
}

fn le16(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
}

fn le32(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64)
}

/// The `*.json` entries directly under `prefix` in a jar (zip): reads the
/// central directory and only those entries (stored or deflated). Zip64
/// archives are not supported (burpsuite.jar is a plain zip).
fn jar_files(jar: &Path, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let err = |what: &str| format!("{}: {what}", jar.display());
    let mut f = std::fs::File::open(jar).map_err(|e| err(&e.to_string()))?;
    let len = f.metadata().map_err(|e| err(&e.to_string()))?.len();
    let tail_len = len.min(22 + 65_535);
    f.seek(SeekFrom::Start(len - tail_len))
        .map_err(|e| err(&e.to_string()))?;
    let mut tail = vec![0u8; tail_len as usize];
    f.read_exact(&mut tail).map_err(|e| err(&e.to_string()))?;
    let eocd = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| tail[i..i + 4] == *b"PK\x05\x06")
        .ok_or_else(|| err("not a zip file (no end of central directory)"))?;
    let cd_size = le32(&tail, eocd + 12).ok_or_else(|| err("truncated end record"))?;
    let cd_off = le32(&tail, eocd + 16).ok_or_else(|| err("truncated end record"))?;
    if cd_off == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF {
        return Err(err("zip64 archives are not supported"));
    }
    if cd_size > 64 << 20 || cd_off + cd_size > len {
        return Err(err("central directory out of range"));
    }
    f.seek(SeekFrom::Start(cd_off))
        .map_err(|e| err(&e.to_string()))?;
    let mut cd = vec![0u8; cd_size as usize];
    f.read_exact(&mut cd).map_err(|e| err(&e.to_string()))?;
    let mut wanted = Vec::new();
    let mut at = 0usize;
    while at + 46 <= cd.len() && cd[at..at + 4] == *b"PK\x01\x02" {
        let (
            Some(method),
            Some(csize),
            Some(usize_),
            Some(nlen),
            Some(xlen),
            Some(clen),
            Some(loff),
        ) = (
            le16(&cd, at + 10),
            le32(&cd, at + 20),
            le32(&cd, at + 24),
            le16(&cd, at + 28),
            le16(&cd, at + 30),
            le16(&cd, at + 32),
            le32(&cd, at + 42),
        )
        else {
            break;
        };
        let name = String::from_utf8_lossy(cd.get(at + 46..at + 46 + nlen).unwrap_or_default())
            .into_owned();
        if let Some(rest) = name.strip_prefix(prefix) {
            if !rest.contains('/') {
                if let Some(stem) = rest.strip_suffix(".json") {
                    wanted.push((stem.to_string(), method, csize, usize_, loff));
                }
            }
        }
        at += 46 + nlen + xlen + clen;
    }
    let mut out = Vec::new();
    for (stem, method, csize, usize_, loff) in wanted {
        let read = |f: &mut std::fs::File| -> Result<Vec<u8>, String> {
            if csize > MAX_CONFIG_BYTES as u64 * 4 || usize_ > MAX_CONFIG_BYTES as u64 {
                return Ok(vec![b' '; MAX_CONFIG_BYTES + 1]);
            }
            f.seek(SeekFrom::Start(loff)).map_err(|e| e.to_string())?;
            let mut lh = [0u8; 30];
            f.read_exact(&mut lh).map_err(|e| e.to_string())?;
            if lh[..4] != *b"PK\x03\x04" {
                return Err("bad local header".into());
            }
            let skip = le16(&lh, 26).unwrap_or(0) + le16(&lh, 28).unwrap_or(0);
            f.seek(SeekFrom::Current(skip as i64))
                .map_err(|e| e.to_string())?;
            let mut data = vec![0u8; csize as usize];
            f.read_exact(&mut data).map_err(|e| e.to_string())?;
            match method {
                0 => Ok(data),
                8 => {
                    let mut o = Vec::new();
                    flate2::read::DeflateDecoder::new(&data[..])
                        .take(MAX_CONFIG_BYTES as u64 + 1)
                        .read_to_end(&mut o)
                        .map_err(|e| e.to_string())?;
                    Ok(o)
                }
                m => Err(format!("compression method {m} not supported")),
            }
        };
        match read(&mut f) {
            Ok(b) => out.push((stem, b)),
            Err(e) => out.push((stem.clone(), e.to_string().into_bytes())),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- issue selection

/// Selected, enabled issue types no WebProbe check reports (kept in the
/// configuration, listed as not applied).
pub fn filter_unsupported_selection(f: &IssueFilter) -> Vec<u32> {
    let Some(sel) = &f.selected else {
        return Vec::new();
    };
    sel.iter()
        .filter(|(id, on)| **on && !webprobe_support::scan_filter::type_has_checks(**id))
        .map(|(id, _)| *id)
        .collect()
}

// ---------------------------------------------------------------- applying a configuration

/// The settings WebProbe applies. Every other setting a configuration
/// carries is kept and listed by [`not_applied`].
pub const APPLIED: &[&str] = &[
    "crawler.crawl_limits.maximum_crawl_time",
    "crawler.crawl_limits.maximum_request_count",
    "crawler.crawl_limits.maximum_unique_locations",
    "crawler.crawl_optimization.maximum_link_depth",
    "crawler.customization.request_robots_txt",
    "crawler.customization.request_sitemap",
    "scanner.audit_optimization.scan_speed",
    "scanner.audit_optimization.scan_accuracy",
    "scanner.issues_reported.scan_type_passive",
    "scanner.issues_reported.scan_type_light_active",
    "scanner.issues_reported.scan_type_medium_active",
    "scanner.issues_reported.scan_type_intrusive_active",
    "scanner.issues_reported.scan_type_javascript_analysis",
    "scanner.issues_reported.select_individual_issues",
    "scanner.issues_reported.scan_only_selected_issues",
    "scanner.issues_reported.selected_issues",
    "scanner.insertion_point_types.insert_url_params",
    "scanner.insertion_point_types.insert_body_params",
    "scanner.insertion_point_types.insert_cookies",
    "scanner.insertion_point_types.insert_param_name",
    "scanner.insertion_point_types.insert_http_headers",
    "scanner.insertion_point_types.insert_entire_body",
    "scanner.insertion_point_types.insert_url_path_folders",
    "scanner.insertion_point_types.insert_url_path_filename",
    "scanner.misc_insertion_point_options.use_nested_insertion_points",
];

/// Settings decoded from a Burp tree: the scan configuration and the
/// audit speed / accuracy (0..=2, `Shared::scan_speed` / `scan_accuracy`).
#[derive(Clone, Debug, PartialEq)]
pub struct Applied {
    pub config: crate::scan_config::ScanConfig,
    pub speed: u8,
    pub accuracy: u8,
}

/// Decode `tree` (normally [`crate::scan_config::config_to_tree`] of the current settings
/// with library configurations overlaid). Keys WebProbe does not apply
/// are ignored here and reported by [`not_applied`]; `base` supplies what
/// Burp's format has no key for (switched-off WebProbe checks, the crawl
/// engine).
pub fn tree_to_config(tree: &Value, base: &crate::scan_config::ScanConfig) -> Applied {
    let mut c = base.clone();
    let int = |p: &str| get_path(tree, p).and_then(Value::as_u64);
    let flag = |p: &str| get_path(tree, p).and_then(Value::as_bool);
    if let Some(v) = int("crawler.crawl_limits.maximum_crawl_time") {
        c.crawl.max_minutes = v;
    }
    if let Some(v) = int("crawler.crawl_limits.maximum_request_count") {
        c.crawl.max_requests = v as usize;
    }
    if let Some(v) = int("crawler.crawl_limits.maximum_unique_locations") {
        // 0 is "no limit" in Burp; WebProbe's ceiling is 100000.
        c.crawl.max_locations = if v == 0 {
            100_000
        } else {
            (v as usize).clamp(1, 100_000)
        };
    }
    if let Some(v) = int("crawler.crawl_optimization.maximum_link_depth") {
        c.crawl.max_depth = (v as usize).clamp(1, 50);
    }
    if let Some(v) = flag("crawler.customization.request_robots_txt") {
        c.crawl.robots = v;
    }
    if let Some(v) = flag("crawler.customization.request_sitemap") {
        c.crawl.sitemap = v;
    }
    for (burp, key) in crate::scan_config::INSERTION_KEYS {
        if let Some(on) = flag(&format!("scanner.insertion_point_types.{burp}")) {
            if on {
                c.disabled_insertion.remove(key);
            } else {
                c.disabled_insertion.insert(key.to_string());
            }
        }
    }
    if let Some(on) = flag("scanner.misc_insertion_point_options.use_nested_insertion_points") {
        if on {
            c.disabled_insertion.remove(crate::scan_config::NESTED_KEY);
        } else {
            c.disabled_insertion
                .insert(crate::scan_config::NESTED_KEY.to_string());
        }
    }
    c.issues = IssueFilter::from_tree(tree);
    let pick = |p: &str, names: &[&str; 3]| {
        get_path(tree, p)
            .and_then(Value::as_str)
            .and_then(|s| names.iter().position(|n| *n == s))
            .map(|i| i as u8)
    };
    Applied {
        config: c,
        speed: pick(
            "scanner.audit_optimization.scan_speed",
            &crate::scan_config::SPEEDS,
        )
        .unwrap_or(1),
        accuracy: pick(
            "scanner.audit_optimization.scan_accuracy",
            &crate::scan_config::ACCURACIES,
        )
        .unwrap_or(1),
    }
}

/// Load `configs` in order onto the current settings, as Burp's launcher
/// does (see the module comment).
pub fn apply(
    configs: &[&LibraryConfig],
    current: &crate::scan_config::ScanConfig,
    speed: u8,
    accuracy: u8,
) -> Applied {
    let mut tree = crate::scan_config::config_to_tree(current, speed, accuracy);
    for c in configs {
        overlay(&mut tree, &c.tree);
    }
    tree_to_config(&tree, current)
}

/// What `configs` set that WebProbe does not apply, one line per setting:
/// keys outside [`APPLIED`], values WebProbe has no engine for, detection
/// method choices, and selected issue types no WebProbe check reports.
pub fn not_applied(configs: &[&LibraryConfig]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for c in configs {
        for p in c.setting_paths() {
            if !APPLIED.contains(&p.as_str()) {
                add(format!("{p} (not applied by WebProbe)"));
            }
        }
        for (p, names) in [
            (
                "scanner.audit_optimization.scan_speed",
                &crate::scan_config::SPEEDS,
            ),
            (
                "scanner.audit_optimization.scan_accuracy",
                &crate::scan_config::ACCURACIES,
            ),
        ] {
            if let Some(v) = get_path(&c.tree, p).and_then(Value::as_str) {
                if !names.contains(&v) {
                    add(format!(
                        "{p} = {v:?} (unknown value, not applied by WebProbe)"
                    ));
                }
            }
        }
        if let Some(Value::Array(items)) =
            get_path(&c.tree, "scanner.issues_reported.selected_issues")
        {
            let mut methods = false;
            for it in items {
                methods |= it
                    .get("detection_methods")
                    .and_then(Value::as_array)
                    .is_some_and(|m| {
                        m.iter()
                            .any(|d| d.get("enabled").and_then(Value::as_bool) == Some(false))
                    });
            }
            if methods {
                add("scanner.issues_reported.selected_issues: per-issue detection method choices (not applied by WebProbe: checks run all their methods)".into());
            }
        }
        if let Some(f) = IssueFilter::from_tree(&c.tree) {
            let missing = filter_unsupported_selection(&f);
            if !missing.is_empty() {
                let names: Vec<String> = missing
                    .iter()
                    .map(|id| {
                        issue_type_name(*id)
                            .map_or(format!("0x{id:08x}"), |n| format!("{n} (0x{id:08x})"))
                    })
                    .collect();
                add(format!(
                    "selected issue types WebProbe has no check for (kept, not applied): {}",
                    names.join(", ")
                ));
            }
        }
    }
    out
}

/// Burp's name for issue type `id` (the KnowledgeBase names WebProbe knows).
pub fn issue_type_name(id: u32) -> Option<&'static str> {
    webprobe_support::issues::KB_ISSUE_TYPES
        .iter()
        .find(|(_, t)| *t as u32 == id)
        .map(|(n, _)| *n)
}

// ---------------------------------------------------------------- user library and saving

/// Where WebProbe keeps the user's own library entries (one Burp JSON file
/// per configuration): `<data dir>/scan-configs`.
pub fn user_dir() -> std::path::PathBuf {
    crate::paths::Lookup::process()
        .data_dir()
        .join("scan-configs")
}

/// The user's entries in `dir` (none when the directory does not exist).
pub fn load_dir(dir: &Path) -> LoadReport {
    let mut rep = LoadReport::default();
    if !dir.is_dir() {
        return rep;
    }
    match dir_json_files(dir) {
        Ok(files) => {
            for (name, bytes) in files {
                match parse_config(&name, &bytes, false) {
                    Ok(c) => rep.configs.push(c),
                    Err(e) => rep.errors.push(e),
                }
            }
        }
        Err(e) => rep.errors.push(e),
    }
    rep.configs.sort_by_key(|a| a.name.to_lowercase());
    rep
}

/// A file name for library entry `name` (path separators and characters
/// Windows refuses become `_`).
pub fn file_name_for(name: &str) -> String {
    let stem: String = name
        .trim()
        .chars()
        .map(|c| {
            if "/\\:*?\"<>|".contains(c) || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    format!(
        "{}.json",
        if stem.is_empty() || stem == "." || stem == ".." {
            "_".to_string()
        } else {
            stem
        }
    )
}

/// Write `cfg` into `dir` (atomically: temporary file, then rename).
pub fn save_to_dir(dir: &Path, cfg: &LibraryConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(file_name_for(&cfg.name));
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        file_name_for(&cfg.name),
        std::process::id()
    ));
    std::fs::write(&tmp, cfg.to_burp_json())?;
    std::fs::rename(&tmp, &path)
}

/// Remove entry `name` from `dir` (no error when it is already gone).
pub fn delete_from_dir(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(file_name_for(name))) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Write edited settings back into a library entry's tree, keeping it
/// partial as Burp's are: an applied setting is written when the entry
/// already had it or when the editor changed it from `start` (the
/// settings the editor opened with). Unknown keys stay untouched, and
/// selected issues keep their detection methods.
pub fn with_settings(entry: &Value, edited: &Value, start: &Value) -> Value {
    let mut out = if entry.is_object() {
        entry.clone()
    } else {
        Value::Object(Map::new())
    };
    for p in APPLIED {
        let Some(new) = get_path(edited, p) else {
            continue;
        };
        if get_path(entry, p).is_none() && get_path(start, p) == Some(new) {
            continue;
        }
        let mut value = new.clone();
        if *p == "scanner.issues_reported.selected_issues" {
            if let (Value::Array(items), Some(Value::Array(old))) = (&mut value, get_path(entry, p))
            {
                for it in items.iter_mut() {
                    let id = parse_type_index(it.get("type_index"));
                    if let Some(prev) = old
                        .iter()
                        .find(|o| parse_type_index(o.get("type_index")) == id)
                    {
                        if let (Some(m), Value::Object(obj)) =
                            (prev.get("detection_methods"), &mut *it)
                        {
                            obj.insert("detection_methods".into(), m.clone());
                        }
                    }
                }
            }
        }
        set_path(&mut out, p, value);
    }
    out
}

fn set_path(tree: &mut Value, path: &str, value: Value) {
    let mut cur = tree;
    let parts: Vec<&str> = path.split('.').collect();
    for (i, k) in parts.iter().enumerate() {
        if !cur.is_object() {
            *cur = Value::Object(Map::new());
        }
        let Value::Object(m) = cur else { return };
        if i + 1 == parts.len() {
            m.insert(k.to_string(), value);
            return;
        }
        cur = m
            .entry(k.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, json: &str) -> LibraryConfig {
        parse_config(name, json.as_bytes(), false).unwrap()
    }

    #[test]
    fn later_configs_win_per_key_and_lists_replace_whole() {
        let a = cfg(
            "a",
            r#"{"scanner":{"issues_reported":{"scan_type_passive":true,"scan_type_light_active":true,"selected_issues":[{"type_index":"0x00100200","enabled":true}]}}}"#,
        );
        let b = cfg(
            "b",
            r#"{"scanner":{"issues_reported":{"scan_type_light_active":false,"selected_issues":[]}},"crawler":{"crawl_limits":{"maximum_crawl_time":10}}}"#,
        );
        let both = combine(None, &[&a, &b]);
        assert_eq!(
            get_path(&both, "scanner.issues_reported.scan_type_passive"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            get_path(&both, "scanner.issues_reported.scan_type_light_active"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            get_path(&both, "scanner.issues_reported.selected_issues"),
            Some(&Value::Array(vec![]))
        );
        let reversed = combine(None, &[&b, &a]);
        assert_eq!(
            get_path(&reversed, "scanner.issues_reported.scan_type_light_active"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn malformed_configs_are_rejected_and_unknown_keys_kept() {
        assert!(parse_config("x", b"[1]", false).is_err());
        assert!(parse_config("x", b"{", false).is_err());
        assert!(parse_config(
            "x",
            br#"{"scanner":{"issues_reported":{"scan_type_passive":"yes"}}}"#,
            false
        )
        .is_err());
        assert!(parse_config(
            "x",
            br#"{"scanner":{"issues_reported":{"selected_issues":[{"enabled":true}]}}}"#,
            false
        )
        .is_err());
        assert!(parse_config("x", &vec![b' '; MAX_CONFIG_BYTES + 1], false).is_err());
        let c = cfg(
            "x",
            r#"{"scanner":{"future_section":{"k":1}},"other":true}"#,
        );
        let back: Value = serde_json::from_str(&c.to_burp_json()).unwrap();
        assert_eq!(back, c.tree);
    }

    /// Smoke check against the local Burp install (skipped when none):
    /// all 29 built-ins parse from the jar, and from an extracted tree.
    #[test]
    fn builtins_load_from_the_local_burp_install() {
        for src in [
            BurpResources::Jar("/opt/BurpSuite/burpsuite.jar".into()),
            BurpResources::Dir("/root/burp-re/in/extract/resources/BuiltInConfigs".into()),
        ] {
            let present = match &src {
                BurpResources::Jar(p) | BurpResources::Dir(p) => p.exists(),
            };
            if !present {
                continue;
            }
            let rep = load_builtin(&src).unwrap();
            assert!(rep.errors.is_empty(), "{:?}", rep.errors);
            assert_eq!(rep.configs.len(), 29, "{src:?}");
            assert!(rep
                .configs
                .iter()
                .any(|c| c.name == "Audit checks - passive"));
            assert!(load_burp_defaults(&src).is_some_and(|d| get_path(
                &d,
                "crawler.crawl_limits.maximum_crawl_time"
            )
            .is_some()));
        }
    }

    #[test]
    fn passive_only_allows_passive_types_only() {
        let c = cfg(
            "p",
            r#"{"scanner":{"issues_reported":{"scan_type_intrusive_active":false,"scan_type_light_active":false,"scan_type_medium_active":false,"scan_type_passive":true,"scan_type_javascript_analysis":false,"select_individual_issues":false,"selected_issues":[]}}}"#,
        );
        let f = IssueFilter::from_tree(&combine(None, &[&c])).unwrap();
        assert!(!webprobe_support::scan_filter::filter_allows(
            &f,
            "SQL injection",
            true
        ));
        assert!(!webprobe_support::scan_filter::filter_allows(
            &f,
            "Web cache poisoning",
            true
        ));
        assert!(filter_allows(
            &f,
            "Strict transport security not enforced",
            false
        ));
        assert!(!webprobe_support::scan_filter::filter_allows(
            &f,
            "Some WebProbe-only probe",
            true
        ));
        assert_eq!(
            IssueFilter::from_tree(&combine(None, &[])),
            None,
            "defaults allow everything"
        );
    }

    #[test]
    fn applying_overlays_onto_current_settings_and_lists_the_rest() {
        let mut cur = crate::scan_config::ScanConfig::default();
        cur.disabled_checks.insert("active.csrf".into());
        let crawl10 = cfg(
            "Crawl limit - 10 minutes",
            r#"{"crawler":{"crawl_limits":{"maximum_crawl_time":10,"maximum_request_count":0,"maximum_unique_locations":1500}}}"#,
        );
        let fast = cfg(
            "f",
            r#"{"scanner":{"audit_optimization":{"scan_speed":"fast","skip_ineffective_checks":true},"insertion_point_types":{"insert_http_headers":false}},"crawler":{"crawl_optimization":{"crawl_strategy":"fastest"}}}"#,
        );
        let a = apply(&[&crawl10, &fast], &cur, 1, 1);
        assert_eq!(
            (a.config.crawl.max_minutes, a.speed, a.accuracy),
            (10, 0, 1)
        );
        assert!(!a.config.insertion_enabled("header") && a.config.insertion_enabled("url"));
        assert!(
            !a.config.check_enabled("active.csrf"),
            "WebProbe-only settings survive"
        );
        assert_eq!(a.config.issues, None);
        let na = not_applied(&[&crawl10, &fast]);
        assert!(
            na.iter()
                .any(|l| l.starts_with("crawler.crawl_optimization.crawl_strategy")),
            "{na:?}"
        );
        assert!(na
            .iter()
            .any(|l| l.starts_with("scanner.audit_optimization.skip_ineffective_checks")));
        assert!(!na.iter().any(|l| l.contains("maximum_crawl_time")));
        // Round trip: the current settings as a tree decode to themselves.
        let back = tree_to_config(
            &crate::scan_config::config_to_tree(&a.config, a.speed, a.accuracy),
            &a.config,
        );
        assert_eq!(back, a);
    }

    #[test]
    fn saving_edits_keeps_entries_partial_and_unknown_keys() {
        let entry = cfg(
            "Crawl limit - 10 minutes",
            r#"{"description":{"uuid":"x"},"crawler":{"crawl_limits":{"maximum_crawl_time":10},"future":1}}"#,
        );
        let cur = crate::scan_config::ScanConfig::default();
        let start_cfg = apply(&[&entry], &cur, 1, 1);
        let start = crate::scan_config::config_to_tree(&start_cfg.config, 1, 1);
        let mut edited_cfg = start_cfg.config.clone();
        edited_cfg.crawl.max_minutes = 20;
        edited_cfg.disabled_insertion.insert("header".into());
        let out = with_settings(
            &entry.tree,
            &crate::scan_config::config_to_tree(&edited_cfg, 1, 1),
            &start,
        );
        assert_eq!(
            get_path(&out, "crawler.crawl_limits.maximum_crawl_time"),
            Some(&Value::from(20))
        );
        assert_eq!(
            get_path(&out, "scanner.insertion_point_types.insert_http_headers"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            get_path(&out, "scanner.audit_optimization.scan_speed"),
            None,
            "unchanged settings stay out"
        );
        assert_eq!(get_path(&out, "crawler.future"), Some(&Value::from(1)));
        assert_eq!(get_path(&out, "description.uuid"), Some(&Value::from("x")));
        assert_eq!(file_name_for("a/b:c"), "a_b_c.json");
    }
}
