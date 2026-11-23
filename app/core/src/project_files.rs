//! Choosing a project: the recent-projects list and the integrity check run
//! before a project file is opened (Burp's startup wizard shows the recent
//! projects and refuses a damaged file instead of loading half of it).

use std::path::{Path, PathBuf};

/// Projects remembered in the list.
pub const RECENT_MAX: usize = 10;

/// Where the list is kept: `$WEBPROBE_CONFIG_DIR`, else the CA folder's
/// parent (`~/.config/webprobe`).
pub fn recent_file() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("WEBPROBE_CONFIG_DIR") {
        return Some(PathBuf::from(d).join("recent-projects.json"));
    }
    crate::tls::default_ca_dir().map(|d| d.join("recent-projects.json"))
}

/// The list with `path` moved to the front, without duplicates, capped.
pub fn remember(list: &[String], path: &str) -> Vec<String> {
    let mut out = vec![path.to_string()];
    out.extend(list.iter().filter(|p| p.as_str() != path).cloned());
    out.truncate(RECENT_MAX);
    out
}

pub fn load_recent(file: &Path) -> Vec<String> {
    crate::util::read_text_file_capped(file, crate::util::MAX_TEXT_FILE_BYTES)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_recent(file: &Path, list: &[String]) -> Result<(), String> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(file, serde_json::to_string_pretty(list).unwrap_or_default())
        .map_err(|e| e.to_string())
}

/// Record `path` as the most recently used project (best effort).
pub fn note_used(path: &str) {
    if let Some(file) = recent_file() {
        let list = remember(&load_recent(&file), path);
        let _ = save_recent(&file, &list);
    }
}

/// What a project file holds, for the confirmation before opening it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub version: u32,
    pub saved_at: u64,
    pub history: usize,
    pub issues: usize,
    pub repeater_tabs: usize,
    pub bytes: u64,
}

/// Read and validate a project file without touching the running session:
/// the header, version and JSON must all be sound. A damaged file is
/// reported, never half-loaded.
pub fn check(path: &Path) -> Result<Summary, String> {
    let bytes = std::fs::metadata(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?
        .len();
    let data = crate::project::load(path)?;
    Ok(Summary {
        version: data.version,
        saved_at: data.saved_at,
        history: data.history.len(),
        issues: data.issues.len(),
        repeater_tabs: data.repeaters.len(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("wp-project-files-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn recent_list_moves_to_front_dedupes_and_caps() {
        let l = remember(&[], "/a");
        let l = remember(&l, "/b");
        let l = remember(&l, "/a");
        assert_eq!(l, ["/a", "/b"]);
        let mut many = Vec::new();
        for i in 0..15 {
            many = remember(&many, &format!("/p{i}"));
        }
        assert_eq!(many.len(), RECENT_MAX);
        assert_eq!(many[0], "/p14");
        let d = tmp("recent");
        let f = d.join("sub/recent.json");
        assert!(
            load_recent(&f).is_empty(),
            "a missing file is an empty list"
        );
        save_recent(&f, &many).unwrap();
        assert_eq!(load_recent(&f), many);
        std::fs::write(&f, "not json").unwrap();
        assert!(load_recent(&f).is_empty(), "a damaged list is ignored");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn check_summarises_good_files_and_rejects_damaged_ones() {
        let d = tmp("check");
        let good = d.join("good.json");
        let data = crate::project::ProjectData {
            history: vec![crate::project::ProjectHistory::from_entry(
                &crate::net::HistEntry {
                    id: 1,
                    method: "GET".into(),
                    path: "/".into(),
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        crate::project::save(&good, &data).unwrap();
        let s = check(&good).unwrap();
        assert_eq!(
            (s.version, s.history, s.issues),
            (crate::project::PROJECT_VERSION, 1, 0)
        );
        assert!(s.bytes > 0);
        // Truncated, wrong header, missing: all refused with a reason.
        let text = std::fs::read_to_string(&good).unwrap();
        let cut = d.join("cut.json");
        std::fs::write(&cut, &text[..text.len() / 2]).unwrap();
        assert!(check(&cut).is_err());
        let other = d.join("other.json");
        std::fs::write(&other, "SOMETHING ELSE 2\n{}").unwrap();
        assert!(check(&other)
            .unwrap_err()
            .contains("not a WebProbe project file"));
        // Headerless JSON is the older project format and still opens.
        let legacy = d.join("legacy.json");
        std::fs::write(&legacy, "{\"version\":2}").unwrap();
        assert_eq!(check(&legacy).unwrap().history, 0);
        assert!(check(&d.join("missing.json"))
            .unwrap_err()
            .contains("cannot open"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
