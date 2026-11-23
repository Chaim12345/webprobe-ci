//! Compiled Java Bambda batches, isolated from the UI and proxy threads.
//!
//! Scripts are trusted local Java code, not sandboxed. The JVM has the user's
//! file/network access. A timeout and output/heap caps protect responsiveness,
//! not confidentiality. Call from a worker, never from an egui frame.
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_SOURCE: usize = 128 * 1024;
/// Maximum aggregate raw bytes passed to one JVM batch.
pub const MAX_RAW_BATCH_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Filter,
    Column,
}

#[derive(Clone, Debug, Serialize)]
pub struct Exchange {
    #[serde(serialize_with = "serialize_id")]
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

fn serialize_id<S: serde::Serializer>(id: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_string())
}

#[derive(Debug, Deserialize)]
pub struct RowResult {
    pub id: u64,
    #[serde(default, deserialize_with = "present_value")]
    pub value: Option<serde_json::Value>,
    pub error: Option<String>,
}

fn present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bambda I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bambda compilation failed: {0}")]
    Compile(String),
    #[error("Bambda execution failed: {0}")]
    Execution(String),
    #[error("Bambda deadline exceeded")]
    Timeout,
    #[error("Bambda job cancelled")]
    Cancelled,
    #[error("Bambda limit exceeded: {0}")]
    Limit(&'static str),
}

#[derive(Debug)]
pub struct ChunkedResults {
    pub rows: Vec<RowResult>,
    pub skipped_ids: Vec<u64>,
}

#[derive(Debug)]
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "webprobe-bambda-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "cannot allocate Bambda directory",
        ))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
pub struct Program {
    java: PathBuf,
    classpath: std::ffi::OsString,
    _classes: Scratch,
    cancelled: Arc<AtomicBool>,
}

impl Program {
    /// Compile once per source change. Compilation errors include javac's
    /// diagnostics. No script is run by this operation.
    pub fn compile(
        java: &Path,
        api: &Path,
        kind: Kind,
        source: &str,
        deadline: Duration,
    ) -> Result<Self, Error> {
        Self::compile_cancellable(
            java,
            api,
            kind,
            source,
            deadline,
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Like compile, with a shared cancellation flag checked during compilation
    /// and every evaluation. Set it when a preview is cancelled or its UI closes.
    pub fn compile_cancellable(
        java: &Path,
        api: &Path,
        kind: Kind,
        source: &str,
        deadline: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if source.len() > MAX_SOURCE {
            return Err(Error::Limit("source exceeds 128 KiB"));
        }
        let java = std::fs::canonicalize(java)?;
        let api = std::fs::canonicalize(api)?;
        let classes = Scratch::new()?;
        let classpath = std::env::join_paths([api.as_path(), classes.0.as_path()])
            .map_err(|e| Error::Compile(e.to_string()))?;
        let ty = match kind {
            Kind::Filter => "boolean",
            Kind::Column => "Object",
        };
        let code = format!("import burp.api.montoya.proxy.ProxyHttpRequestResponse;\nimport burp.api.montoya.utilities.Utilities;\nimport burp.api.montoya.http.message.StatusCodeClass;\nimport burp.api.montoya.http.message.params.HttpParameterType;\npublic final class WebProbeUserBambda {{\npublic static {ty} evaluate(ProxyHttpRequestResponse requestResponse, Utilities utilities) throws Exception {{\n{source}\n}}\n}}\n");
        let source_path = classes.0.join("WebProbeUserBambda.java");
        std::fs::write(&source_path, code)?;
        let mut sources = Vec::new();
        for (name, source) in crate::paths::MONTOYA_BRIDGE_SOURCES {
            let path = classes.0.join(name);
            std::fs::write(&path, source)?;
            sources.push(path);
        }
        let runner = classes.0.join("BambdaRunner.java");
        std::fs::write(&runner, include_str!("../../sidecar/BambdaRunner.java"))?;
        sources.push(runner);
        let mut cmd = Command::new(&java);
        cmd.args([
            "-Xmx256m",
            "-m",
            "jdk.compiler/com.sun.tools.javac.Main",
            "-proc:none",
            "-encoding",
            "UTF-8",
            "-cp",
        ])
        .arg(&classpath)
        .arg("-d")
        .arg(&classes.0)
        .arg(source_path)
        .args(sources);
        let (status, _, stderr) = run(cmd, deadline, &cancelled)?;
        if !status.success() {
            return Err(Error::Compile(
                String::from_utf8_lossy(&stderr).into_owned(),
            ));
        }
        Ok(Self {
            java,
            classpath,
            _classes: classes,
            cancelled,
        })
    }

    /// Evaluate at most five rows / 1 MiB per JVM batch. The deadline is per
    /// batch; any failed batch returns an error, never a partial success.
    /// Individually oversized rows are reported explicitly in skipped_ids.
    pub fn evaluate_chunked(
        &self,
        rows: &[Exchange],
        deadline: Duration,
    ) -> Result<ChunkedResults, Error> {
        if rows.len() > 10_000 {
            return Err(Error::Limit("more than 10000 rows"));
        }
        let mut result = ChunkedResults {
            rows: Vec::new(),
            skipped_ids: Vec::new(),
        };
        let mut batch = Vec::new();
        let mut raw_bytes = 0;
        for row in rows {
            let size = row
                .request
                .len()
                .saturating_add(row.response.as_ref().map_or(0, Vec::len))
                .saturating_add(row.host.len());
            if size > MAX_RAW_BATCH_BYTES {
                result.skipped_ids.push(row.id);
                continue;
            }
            if !batch.is_empty() && (batch.len() == 5 || raw_bytes + size > MAX_RAW_BATCH_BYTES) {
                result.rows.extend(self.evaluate(&batch, deadline)?);
                batch.clear();
                raw_bytes = 0;
            }
            raw_bytes += size;
            batch.push(row.clone());
        }
        if !batch.is_empty() {
            result.rows.extend(self.evaluate(&batch, deadline)?);
        }
        Ok(result)
    }

    /// Evaluate a snapshot in a separate JVM, returning one result per row.
    /// The program may be reused across batches. Concurrent calls use separate
    /// input directories and JVMs, so user static state is not shared.
    /// The deadline covers the entire JVM batch, not each individual row.
    pub fn evaluate(&self, rows: &[Exchange], deadline: Duration) -> Result<Vec<RowResult>, Error> {
        if rows.len() > 10_000 {
            return Err(Error::Limit("more than 10000 rows"));
        }
        // Check the raw size before serde can allocate an oversized JSON buffer.
        let raw: usize = rows
            .iter()
            .map(|r| {
                r.request
                    .len()
                    .saturating_add(r.response.as_ref().map_or(0, Vec::len))
                    .saturating_add(r.host.len())
            })
            .try_fold(0usize, |a, b| a.checked_add(b))
            .ok_or(Error::Limit("input size overflow"))?;
        if raw > MAX_RAW_BATCH_BYTES {
            return Err(Error::Limit("batch too large"));
        }
        let input = serde_json::to_vec(rows).map_err(|e| Error::Execution(e.to_string()))?;
        if input.len() > MAX_INPUT {
            return Err(Error::Limit("input exceeds 16 MiB"));
        }
        let scratch = Scratch::new()?;
        let path = scratch.0.join("input.json");
        std::fs::write(&path, input)?;
        let mut cmd = Command::new(&self.java);
        cmd.args(["-Xmx256m", "-Djava.awt.headless=true", "-cp"])
            .arg(&self.classpath)
            .arg("BambdaRunner")
            .arg(path)
            .arg(std::process::id().to_string());
        let (status, out, stderr) = run(cmd, deadline, &self.cancelled)?;
        if !status.success() {
            return Err(Error::Execution(format!(
                "JVM exited with {status}: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        let results: Vec<RowResult> = out
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|line| serde_json::from_slice(line).map_err(|e| Error::Execution(e.to_string())))
            .collect::<Result<_, _>>()?;
        if results.len() != rows.len() || results.iter().zip(rows).any(|(a, b)| a.id != b.id) {
            return Err(Error::Execution(
                "JVM returned an incomplete or reordered batch".into(),
            ));
        }
        Ok(results)
    }
}

fn run(
    mut cmd: Command,
    deadline: Duration,
    cancelled: &AtomicBool,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Error> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    crate::util::own_process_group(&mut cmd);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    for (is_error, pipe) in [
        (false, Box::new(stdout) as Box<dyn Read + Send>),
        (true, Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe
                .take(MAX_OUTPUT as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = tx.send((is_error, result));
        });
    }
    drop(tx);
    let start = Instant::now();
    let mut out = None;
    let mut err = None;
    let mut too_large = false;
    let result = loop {
        while let Ok((is_error, bytes)) = rx.try_recv() {
            match bytes {
                Ok(bytes) if bytes.len() <= MAX_OUTPUT => {
                    if is_error {
                        err = Some(bytes);
                    } else {
                        out = Some(bytes);
                    }
                }
                Ok(_) => {
                    too_large = true;
                    break;
                }
                Err(e) => {
                    crate::util::kill_process_tree(child.id(), None, Duration::from_millis(100));
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e.into());
                }
            }
        }
        if cancelled.load(Ordering::Relaxed) {
            break Err(Error::Cancelled);
        }
        if too_large {
            break Err(Error::Limit("JVM output exceeds 8 MiB"));
        }
        if start.elapsed() >= deadline {
            break Err(Error::Timeout);
        }
        match child.try_wait() {
            Ok(Some(status)) if out.is_some() && err.is_some() => {
                break Ok((status, out.take().unwrap(), err.take().unwrap()))
            }
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    crate::util::kill_process_tree(child.id(), None, Duration::from_millis(100));
    let _ = child.kill();
    let _ = child.wait();
    result
}
