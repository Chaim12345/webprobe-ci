//! R-16 library interchange. Importing a script never compiles or runs it.
use serde::{Deserialize, Serialize};

pub const MAX_FILE_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Function {
    #[serde(rename = "VIEW_FILTER")]
    ViewFilter,
    #[serde(rename = "CUSTOM_COLUMN")]
    CustomColumn,
}
impl Function {
    pub fn kind(self) -> crate::bambda::Kind {
        match self {
            Self::ViewFilter => crate::bambda::Kind::Filter,
            Self::CustomColumn => crate::bambda::Kind::Column,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::ViewFilter => "View filter",
            Self::CustomColumn => "Custom column",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Location {
    #[serde(rename = "PROXY_HTTP_HISTORY")]
    ProxyHttpHistory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {
    pub id: String,
    pub name: String,
    pub function: Function,
    pub location: Location,
    pub source: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid .bambda YAML: {0}")]
    Yaml(#[from] yaml_serde::Error),
    #[error("Invalid script: {0}")]
    Invalid(&'static str),
    #[error("Library I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("A script with this id already exists. Confirm replacement first.")]
    Conflict,
    #[error("Export destination already exists. Choose a new path.")]
    ExportExists,
}

impl Script {
    pub fn new(name: String, function: Function, source: String) -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        Self {
            id: format!(
                "{}-{}-{}-{}-{}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            ),
            name,
            function,
            location: Location::ProxyHttpHistory,
            source,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if self.id.len() != 36
            || !self.id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err(Error::Invalid("id must be a UUID"));
        }
        if self.name.trim().is_empty() || self.name.chars().count() > 200 {
            return Err(Error::Invalid("name must have 1-200 characters"));
        }
        if self.source.trim().is_empty() || self.source.len() > 128 * 1024 {
            return Err(Error::Invalid("source must have 1-131072 bytes"));
        }
        Ok(())
    }
    pub fn from_yaml(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_FILE_BYTES {
            return Err(Error::Invalid("file exceeds 256 KiB"));
        }
        let script: Self = yaml_serde::from_str(text)?;
        script.validate()?;
        Ok(script)
    }
    pub fn to_yaml(&self) -> Result<String, Error> {
        self.validate()?;
        let yaml = yaml_serde::to_string(self)?;
        if yaml.len() > MAX_FILE_BYTES {
            return Err(Error::Invalid("serialized file exceeds 256 KiB"));
        }
        Ok(yaml)
    }
}

#[derive(Default, Debug)]
pub struct LoadReport {
    pub scripts: Vec<Script>,
    pub errors: Vec<String>,
}

pub struct Store {
    dir: std::path::PathBuf,
}
impl Store {
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }
    pub fn directory(&self) -> &std::path::Path {
        &self.dir
    }
    pub fn load(&self) -> Result<LoadReport, Error> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LoadReport::default()),
            Err(e) => return Err(e.into()),
        };
        let mut report = LoadReport::default();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry.path().extension().is_none_or(|e| e != "bambda")
            {
                continue;
            }
            if report.scripts.len() + report.errors.len() >= 1000 {
                report
                    .errors
                    .push("Only the first 1000 library files were loaded.".into());
                break;
            }
            let result = Script::load(&entry.path());
            match result {
                Ok(script)
                    if entry.path().file_stem().and_then(|s| s.to_str())
                        == Some(script.id.as_str()) =>
                {
                    report.scripts.push(script)
                }
                Ok(_) => report.errors.push(format!(
                    "{}: file name does not match script id",
                    entry.path().display()
                )),
                Err(e) => report
                    .errors
                    .push(format!("{}: {e}", entry.path().display())),
            }
        }
        report.scripts.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        Ok(report)
    }
    /// Atomic store. An existing id is never replaced unless overwrite is true.
    pub fn save(&self, script: &Script, overwrite: bool) -> Result<(), Error> {
        let yaml = script.to_yaml()?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&self.dir)?;
        let destination = self.dir.join(format!("{}.bambda", script.id));
        regular_if_exists(&destination)?;
        atomic_write(&destination, yaml.as_bytes(), overwrite)
    }
    pub fn delete(&self, script: &Script) -> Result<(), Error> {
        script.validate()?;
        let path = self.dir.join(format!("{}.bambda", script.id));
        regular_if_exists(&path)?;
        std::fs::remove_file(path)?;
        Ok(())
    }
}
impl Script {
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        regular_if_exists(path)?;
        let text = crate::util::read_text_file_capped(path, MAX_FILE_BYTES)?;
        Self::from_yaml(&text)
    }
    /// Export never replaces an existing destination silently.
    pub fn export(&self, path: &std::path::Path) -> Result<(), Error> {
        regular_if_exists(path)?;
        match atomic_write(path, self.to_yaml()?.as_bytes(), false) {
            Err(Error::Conflict) => Err(Error::ExportExists),
            other => other,
        }
    }
}

fn atomic_write(destination: &std::path::Path, bytes: &[u8], overwrite: bool) -> Result<(), Error> {
    use std::io::Write;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let temp = parent.join(format!(
        ".write-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let cleanup = Cleanup(temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&cleanup.0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if overwrite {
        std::fs::rename(&cleanup.0, destination)?;
    } else {
        match std::fs::hard_link(&cleanup.0, destination) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(Error::Conflict),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

// Reject devices, FIFOs, sockets, directories and symlinks before opening a
// caller-selected path. This is not a defense against a local filesystem race.
fn regular_if_exists(path: &std::path::Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(Error::Invalid(
            "path must be a regular file, not a device, pipe, directory or symlink",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
