//! Installed extensions, remembered across runs like Burp's extension list
//! (user-level, not per project): what to load, in order, and whether it is
//! enabled. Loading happens on a background thread so a slow JVM or a
//! misbehaving extension never stalls start-up or the UI.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::ext_host::LoadedExtension;
use crate::net::Shared;

pub use webprobe_support::ext::{Installed, Kind};

/// Per-call deadline for process extensions.
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(2);

pub fn store_file() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("WEBPROBE_CONFIG_DIR") {
        return Some(PathBuf::from(d).join("extensions.json"));
    }
    crate::tls::default_ca_dir().map(|d| d.join("extensions.json"))
}

pub fn load() -> Vec<Installed> {
    store_file().map(|f| load_from(&f)).unwrap_or_default()
}

pub fn save(list: &[Installed]) -> Result<(), String> {
    save_to(&store_file().ok_or("no config directory")?, list)
}

pub fn load_from(f: &std::path::Path) -> Vec<Installed> {
    crate::util::read_text_file_capped(f, crate::util::MAX_TEXT_FILE_BYTES)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_to(f: &std::path::Path, list: &[Installed]) -> Result<(), String> {
    if let Some(d) = f.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(list).map_err(|e| e.to_string())?;
    std::fs::write(f, json).map_err(|e| format!("{}: {e}", f.display()))
}

/// Split a command line into words: whitespace separates, single or double
/// quotes group, a backslash escapes the next character outside single quotes.
pub fn split_command(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('\''), c) => cur.push(c),
            (_, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                has = true;
            }
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                has = false;
            }
            (_, c) => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Extensions run in the temp directory, so words of the command that name
/// an existing file relative to WebProbe's working directory (a script
/// path, `./run`) are made absolute first; everything else is left alone.
pub fn absolutize(words: Vec<String>) -> Vec<String> {
    words
        .into_iter()
        .map(|w| {
            let p = std::path::Path::new(&w);
            if !w.is_empty()
                && p.is_relative()
                && (w.contains('/') || w.contains('\\') || p.extension().is_some())
                && p.exists()
            {
                std::fs::canonicalize(p)
                    .map(|a| a.to_string_lossy().into_owned())
                    .unwrap_or(w)
            } else {
                w
            }
        })
        .collect()
}

/// Start one extension (blocking: JVM start-up or the process's register).
/// A Java extension is linked to `shared` for `Http.sendRequest` and events,
/// gets the project's saved data, and (`startup`: loaded with WebProbe)
/// opens its window only on demand.
pub fn start(
    item: &Installed,
    shared: &Arc<Shared>,
    startup: bool,
) -> Result<LoadedExtension, String> {
    let mut loaded = match item.kind {
        Kind::Java => {
            let data = crate::ext_host::with_host(shared, |h| {
                h.saved_data.get(item.source.trim()).cloned()
            });
            let opts = crate::ext_host::SidecarOptions {
                startup,
                data,
                ..crate::ext_host::SidecarOptions::for_this_session()
            };
            LoadedExtension::new(crate::ext_host::JavaSidecar::spawn_opts(
                item.source.trim(),
                Some(crate::ext_calls::host_link(shared)),
                opts,
            )?)
        }
        Kind::Process => {
            let words = absolutize(split_command(&item.source));
            let (program, args) = words.split_first().ok_or("empty command")?;
            LoadedExtension::new(crate::ext_process::ProcessExtension::spawn(
                program,
                args,
                HOOK_TIMEOUT,
            )?)
        }
    };
    loaded.enabled = item.enabled;
    loaded.source = Some(item.clone());
    Ok(loaded)
}

/// Load an extension in the background and append it to the host; the
/// outcome goes to the event log, and `done` is called with it.
pub fn start_in_background(
    shared: &Arc<Shared>,
    item: Installed,
    done: impl FnOnce(Result<String, String>) + Send + 'static,
) {
    let shared = Arc::clone(shared);
    crate::util::spawn_contained("ext_store", move || {
        let source = item.source.clone();
        let result = start(&item, &shared, false).map(|ext| {
            crate::ext_host::with_host(&shared, move |host| {
                let name = ext.hooks.extension_name().to_string();
                host.not_loaded.retain(|i| i.source != source);
                host.extensions.push(ext);
                name
            })
        });
        match &result {
            Ok(name) => shared.log(&format!(
                "Extension loaded: {name} ({} {})",
                item.kind.label(),
                item.source
            )),
            Err(e) => shared.log(&format!(
                "Extension failed to load ({} {}): {e}",
                item.kind.label(),
                item.source
            )),
        }
        shared.wake();
        done(result);
    });
}

/// The host's extensions that came from the store, in host order, with
/// their current enabled state (what `save` should write).
pub fn current(shared: &Shared) -> Vec<Installed> {
    crate::ext_host::with_host(shared, |host| {
        host.extensions
            .iter()
            .filter_map(|e| {
                e.source.clone().map(|s| Installed {
                    enabled: e.enabled,
                    ..s
                })
            })
            // Entries that failed to load stay remembered: saving after any other
            // change used to drop them from extensions.json.
            .chain(host.not_loaded.iter().cloned())
            .collect()
    })
}

/// Load every remembered extension, one after another, in order.
pub fn load_all(shared: &Arc<Shared>) {
    let list = load();
    if list.is_empty() {
        return;
    }
    let shared = Arc::clone(shared);
    crate::util::spawn_contained("ext_store", move || {
        for item in list {
            match start(&item, &shared, true) {
                Ok(ext) => {
                    shared.log(&format!(
                        "Extension loaded: {} ({} {})",
                        ext.hooks.extension_name(),
                        item.kind.label(),
                        item.source
                    ));
                    crate::ext_host::with_host(&shared, |h| h.extensions.push(ext));
                }
                // Kept in the list: a failed load is reported, not forgotten.
                Err(e) => {
                    shared.log(&format!(
                        "Extension failed to load ({} {}): {e}",
                        item.kind.label(),
                        item.source
                    ));
                    crate::ext_host::with_host(&shared, |h| h.not_loaded.push(item.clone()));
                }
            }
            shared.wake();
        }
    });
}

/// One catalogue entry (the BApp Store's role for WebProbe extensions):
/// `extensions/catalogue.json` next to the binary or in the source tree.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CatalogueEntry {
    pub name: String,
    pub description: String,
    pub kind: Kind,
    /// Command line (process) or jar path (java); `{dir}` is the catalogue's
    /// directory.
    pub command: String,
    /// Programs the extension needs on PATH (its dependency view).
    #[serde(default)]
    pub requires: Vec<String>,
}

impl CatalogueEntry {
    /// What to install: the command with `{dir}` filled in.
    pub fn installed(&self, dir: &std::path::Path) -> Installed {
        let d = dir.to_string_lossy();
        // A process command is split like a shell line, so the directory is
        // quoted (installations live under paths with spaces); a jar path
        // is used as it is.
        let filled = match self.kind {
            Kind::Process => self
                .command
                .replace("{dir}", &format!("'{}'", d.replace('\'', "'\\''"))),
            Kind::Java => self.command.replace("{dir}", &d),
        };
        Installed {
            kind: self.kind,
            source: filled,
            enabled: true,
        }
    }
}

/// Where the catalogue lives (`paths::extensions_dir`): an override, an
/// `extensions/` directory next to the binary, else the catalogue embedded
/// in the binary, written out to WebProbe's data directory.
pub fn catalogue_dir() -> Option<PathBuf> {
    crate::paths::extensions_dir()
        .ok()
        .map(|d| std::fs::canonicalize(&d).unwrap_or(d))
}

pub fn load_catalogue(dir: &std::path::Path) -> Result<Vec<CatalogueEntry>, String> {
    let text = crate::util::read_text_file_capped(
        &dir.join("catalogue.json"),
        crate::util::MAX_TEXT_FILE_BYTES,
    )
    .map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("catalogue.json: {e}"))
}

/// Whether `program` is runnable: an existing path, or found on PATH.
pub fn program_available(program: &str) -> bool {
    let p = std::path::Path::new(program);
    if p.components().count() > 1 {
        return p.is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(program).is_file()))
}

/// The runtime an installed extension depends on: the process command's
/// program, or java for a Montoya jar.
pub fn runtime_of(item: &Installed) -> String {
    match item.kind {
        Kind::Java => "java".into(),
        Kind::Process => split_command(&item.source)
            .into_iter()
            .next()
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_split_like_a_shell() {
        assert_eq!(
            split_command("python3 -I ext.py"),
            ["python3", "-I", "ext.py"]
        );
        assert_eq!(
            split_command(r#"  "/opt/My Ext/run" --name 'a b' x\ y "" "#),
            ["/opt/My Ext/run", "--name", "a b", "x y", ""]
        );
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn relative_script_paths_are_made_absolute() {
        // Tests run in the crate dir; the example lives one level up.
        let w = absolutize(split_command(
            "python3 -I ../extensions/examples/marker_reflection.py --x 1",
        ));
        assert_eq!(
            &w[..2],
            ["python3", "-I"],
            "a program name on PATH is left alone"
        );
        assert!(
            std::path::Path::new(&w[2]).is_absolute() && w[2].ends_with("marker_reflection.py"),
            "{w:?}"
        );
        assert_eq!(&w[3..], ["--x", "1"]);
    }

    #[test]
    fn catalogue_loads_and_fills_its_directory() {
        let dir = catalogue_dir().expect("source-tree catalogue");
        let cat = load_catalogue(&dir).unwrap();
        assert!(cat.len() >= 3);
        let item = cat
            .iter()
            .find(|c| c.name.starts_with("Security headers"))
            .unwrap()
            .installed(&dir);
        assert_eq!(item.kind, Kind::Process);
        assert!(
            !item.source.contains("{dir}") && item.source.ends_with("examples/security_headers.py"),
            "{}",
            item.source
        );
        // Directories with spaces (and quotes) survive the command split.
        let spaced = CatalogueEntry {
            name: "x".into(),
            description: String::new(),
            kind: Kind::Process,
            command: "python3 -I {dir}/a.py".into(),
            requires: vec![],
        };
        let words = split_command(
            &spaced
                .installed(std::path::Path::new("/opt/Craft Anything/it's"))
                .source,
        );
        assert_eq!(words, ["python3", "-I", "/opt/Craft Anything/it's/a.py"]);
        assert_eq!(runtime_of(&item), "python3");
        assert!(program_available("sh"));
        assert!(!program_available("definitely-not-a-program-xyz"));
    }

    #[test]
    fn list_round_trips_through_the_config_dir() {
        let dir = std::env::temp_dir().join(format!("wp-ext-store-{}", std::process::id()));
        let file = dir.join("extensions.json");
        let list = vec![
            Installed {
                kind: Kind::Process,
                source: "python3 -I a.py".into(),
                enabled: true,
            },
            Installed {
                kind: Kind::Java,
                source: "/x/b.jar".into(),
                enabled: false,
            },
        ];
        save_to(&file, &list).unwrap();
        assert_eq!(load_from(&file), list);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("\"kind\": \"process\""), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
