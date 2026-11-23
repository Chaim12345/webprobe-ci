//! The scan task queue (Burp's Dashboard tasks): scans are queued and run one
//! at a time by a single runner thread, and each task can be paused,
//! resumed or cancelled. Unfinished tasks are saved with the project and
//! queued again when it is opened.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use std::any::Any;
use std::sync::OnceLock;

use crate::net::{HistEntry, Shared};

use webprobe_support::tasks::SmtpOob;
pub use webprobe_support::tasks::{ScanTask, TaskKind, TaskState};

/// The scan engine's entry points the task runner drives. scan registers
/// them (scan::register_task_ops) when the engine is linked in; with none
/// registered the runner records the task as done without scanning, as the
/// proxy-only build behaves.
/// OOB payload slots pooled for one request: (point, token, host) triples.
pub type OobSlots = Vec<(String, String, String)>;

/// The start_active_scan op: one request with its prepared payloads.
pub type StartActiveScan = fn(Arc<Shared>, HistEntry, &[(String, String, String)], &[SmtpOob]);

pub struct ScanOps {
    pub crawl_and_audit: fn(&Arc<Shared>, &[String], bool),
    pub start_active_scan: StartActiveScan,
    pub pooled_oob: fn(&Shared, &[u8]) -> OobSlots,
    /// Open the stored-input batch for one task (dropped as the task ends).
    pub open_stored_batch: fn(&Arc<Shared>) -> Box<dyn Any>,
}

static SCAN_OPS: OnceLock<ScanOps> = OnceLock::new();

/// Register the scan engine's task entry points (app and headless startup).
pub fn register_scan_ops(ops: ScanOps) {
    let _ = SCAN_OPS.set(ops);
}

fn scan_ops() -> Option<&'static ScanOps> {
    SCAN_OPS.get()
}

/// Add a scan to the queue and make sure the runner is going. Returns its id.
pub fn enqueue(shared: &Arc<Shared>, name: impl Into<String>, kind: TaskKind) -> u64 {
    let id = shared.next_task_id.fetch_add(1, Ordering::SeqCst);
    let total = match &kind {
        TaskKind::Audit(e) => Some(e.len()),
        TaskKind::Single { .. } => Some(1),
        TaskKind::CrawlAudit { .. } => None,
    };
    shared.tasks.lock().unwrap().push(ScanTask {
        id,
        name: name.into(),
        kind,
        state: TaskState::Queued,
        done: 0,
        total,
        issues_found: 0,
        created: crate::util::now_secs(),
        finished: None,
    });
    ensure_runner(shared);
    shared.wake();
    id
}

fn set_state(shared: &Shared, id: u64, state: TaskState) {
    if let Some(t) = shared.tasks.lock().unwrap().iter_mut().find(|t| t.id == id) {
        t.state = state;
        if !state.is_open() {
            t.finished = Some(crate::util::now_secs());
        }
    }
    shared.wake();
}

fn state_of(shared: &Shared, id: u64) -> Option<TaskState> {
    shared
        .tasks
        .lock()
        .unwrap()
        .iter()
        .find(|t| t.id == id)
        .map(|t| t.state)
}

/// Pause a task: a running one stops sending at its next request.
pub fn pause(shared: &Shared, id: u64) {
    match state_of(shared, id) {
        Some(TaskState::Running) => {
            shared.scan.paused.store(true, Ordering::SeqCst);
            set_state(shared, id, TaskState::Paused);
        }
        Some(TaskState::Queued) => set_state(shared, id, TaskState::Paused),
        _ => {}
    }
}

/// Resume a paused task (a queued-then-paused one goes back in the queue).
pub fn resume(shared: &Shared, id: u64) {
    if state_of(shared, id) == Some(TaskState::Paused) {
        let running = shared.scan.running_task.load(Ordering::SeqCst) == id;
        if running {
            shared.scan.paused.store(false, Ordering::SeqCst);
        }
        set_state(
            shared,
            id,
            if running {
                TaskState::Running
            } else {
                TaskState::Queued
            },
        );
    }
}

/// Cancel a task; a running one is stopped.
pub fn cancel(shared: &Shared, id: u64) {
    let Some(state) = state_of(shared, id) else {
        return;
    };
    if !state.is_open() {
        return;
    }
    if shared.scan.running_task.load(Ordering::SeqCst) == id {
        shared.scan.stop.store(true, Ordering::SeqCst);
        shared.scan.paused.store(false, Ordering::SeqCst);
    }
    set_state(shared, id, TaskState::Cancelled);
}

/// Remove a finished or cancelled task from the list.
pub fn remove(shared: &Shared, id: u64) {
    shared
        .tasks
        .lock()
        .unwrap()
        .retain(|t| t.id != id || t.state.is_open());
    shared.wake();
}

/// Block while the scanner is paused (called before every scanner request).
pub fn wait_while_paused(shared: &Shared) {
    while shared.scan.paused.load(Ordering::SeqCst) && !shared.scan.stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Start the runner thread once per `Shared`.
pub fn ensure_runner(shared: &Arc<Shared>) {
    if shared.task_runner.swap(true, Ordering::SeqCst) {
        return;
    }
    let shared = shared.clone();
    std::thread::Builder::new()
        .name("scan-tasks".into())
        .spawn(move || loop {
            let next = {
                let tasks = shared.tasks.lock().unwrap();
                tasks
                    .iter()
                    .find(|t| t.state == TaskState::Queued)
                    .map(|t| (t.id, t.kind.clone()))
            };
            match next {
                Some((id, kind)) if !shared.scan.is_busy() => run(&shared, id, kind),
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        })
        .expect("scan task runner thread");
}

fn wait_idle(shared: &Shared) {
    shared.scan.wait_idle(None);
}

fn run(shared: &Arc<Shared>, id: u64, kind: TaskKind) {
    let issues_before = shared.issues.lock().unwrap().len();
    shared.scan.running_task.store(id, Ordering::SeqCst);
    shared.scan.stop.store(false, Ordering::SeqCst);
    shared.scan.paused.store(false, Ordering::SeqCst);
    set_state(shared, id, TaskState::Running);
    let _tool = crate::net::tool_scope("Scanner");
    // One stored-input store for the whole task; stage A4 runs as the
    // task ends (scan::StoredBatch).
    let stored = scan_ops().map(|ops| (ops.open_stored_batch)(shared));
    // One (entry, prepared payloads) item per request; plain audits draw
    // their OOB payloads from the pool when they reach it.
    type Prepared = Option<(Vec<(String, String, String)>, Vec<SmtpOob>)>;
    let items: Vec<(HistEntry, Prepared)> = match kind {
        TaskKind::Audit(entries) => entries.into_iter().map(|e| (e, None)).collect(),
        TaskKind::Single { entry, oob, smtp } => vec![(*entry, Some((oob, smtp)))],
        TaskKind::CrawlAudit { urls, audit_only } => {
            if let Some(ops) = scan_ops() {
                (ops.crawl_and_audit)(shared, &urls, audit_only);
            }
            wait_idle(shared);
            Vec::new()
        }
    };
    if !items.is_empty() {
        shared.oob.want(true);
        for (e, prepared) in items {
            wait_while_paused(shared);
            if state_of(shared, id) == Some(TaskState::Cancelled) {
                break;
            }
            let (oob, smtp) = prepared.unwrap_or_else(|| {
                (
                    scan_ops().map_or_else(Vec::new, |ops| (ops.pooled_oob)(shared, &e.req_raw)),
                    Vec::new(),
                )
            });
            // start_active_scan marks the scanner busy before it returns,
            // so waiting for idle cannot miss the scan it just started.
            if let Some(ops) = scan_ops() {
                (ops.start_active_scan)(shared.clone(), e, &oob, &smtp);
            }
            wait_idle(shared);
            // Read the issue count first: `tasks` is never held while
            // `issues` is locked (one lock order everywhere).
            let found = shared
                .issues
                .lock()
                .unwrap()
                .len()
                .saturating_sub(issues_before);
            if let Some(t) = shared.tasks.lock().unwrap().iter_mut().find(|t| t.id == id) {
                // An item cut short by Cancel was not audited.
                if t.state != TaskState::Cancelled {
                    t.done += 1;
                }
                t.issues_found = found;
            }
            shared.wake();
        }
        shared.oob.want(false);
    }
    drop(stored);
    shared.scan.running_task.store(0, Ordering::SeqCst);
    shared.scan.paused.store(false, Ordering::SeqCst);
    let found = shared
        .issues
        .lock()
        .unwrap()
        .len()
        .saturating_sub(issues_before);
    if let Some(t) = shared.tasks.lock().unwrap().iter_mut().find(|t| t.id == id) {
        t.issues_found = found;
        if t.state.is_open() {
            t.state = TaskState::Finished;
            t.finished = Some(crate::util::now_secs());
        }
    }
    shared.log(&format!("Task {id} ended: {found} issue(s)"));
    shared.wake();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A local site whose requests are counted.
    fn origin() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                h.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
            }
        });
        (port, hits)
    }

    fn entry(port: u16, path: &str) -> HistEntry {
        HistEntry {
            id: 1,
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
            req_raw: format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                .into_bytes()
                .into(),
            ..Default::default()
        }
    }

    fn wait_for(shared: &Shared, id: u64, want: TaskState, secs: u64) -> bool {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < Duration::from_secs(secs) {
            if state_of(shared, id) == Some(want) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn tasks_run_in_order_and_can_be_paused_resumed_and_cancelled() {
        crate::scan::register_task_ops();
        let shared = Shared::new();
        let (port, hits) = origin();
        let a = enqueue(
            &shared,
            "first",
            TaskKind::Audit(vec![entry(port, "/a?x=1"), entry(port, "/b?y=2")]),
        );
        let b = enqueue(
            &shared,
            "second",
            TaskKind::Audit(vec![entry(port, "/c?z=3")]),
        );
        // The second waits while the first runs.
        assert!(wait_for(&shared, a, TaskState::Running, 10));
        assert_eq!(state_of(&shared, b), Some(TaskState::Queued));
        // Pause: no further requests reach the site.
        pause(&shared, a);
        std::thread::sleep(Duration::from_millis(400));
        let paused_at = hits.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(800));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            paused_at,
            "no traffic while paused"
        );
        assert_eq!(
            state_of(&shared, b),
            Some(TaskState::Queued),
            "the queue waits behind a paused task"
        );
        resume(&shared, a);
        assert!(
            wait_for(&shared, a, TaskState::Finished, 120),
            "{:?}",
            state_of(&shared, a)
        );
        let t = shared
            .tasks
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == a)
            .cloned()
            .unwrap();
        assert_eq!((t.done, t.total), (2, Some(2)));
        assert!(hits.load(Ordering::SeqCst) > paused_at);
        // The second then runs; cancel it. Its one-request scan can finish
        // before the 50ms poll sees Running on a loaded or fast machine, so
        // wait for it to leave the queue, then cancel it if it is still open.
        let t0 = std::time::Instant::now();
        while state_of(&shared, b) == Some(TaskState::Queued)
            && t0.elapsed() < Duration::from_secs(30)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        match state_of(&shared, b) {
            Some(TaskState::Running) => {
                cancel(&shared, b);
                assert_eq!(state_of(&shared, b), Some(TaskState::Cancelled));
                assert!(wait_for(&shared, b, TaskState::Cancelled, 5));
                // Let the interrupted item wind down: it does not count as audited.
                std::thread::sleep(Duration::from_millis(800));
                assert_eq!(
                    shared
                        .tasks
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|t| t.id == b)
                        .unwrap()
                        .done,
                    0
                );
            }
            // It ran to completion before the cancel landed: the run order
            // and the audit are still proven by its done count. Cancelling
            // a running task is covered by cancel_stops_a_running_task.
            Some(TaskState::Finished) => {
                assert_eq!(
                    shared
                        .tasks
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|t| t.id == b)
                        .unwrap()
                        .done,
                    1
                );
            }
            other => panic!("the second task should be running or finished, got {other:?}"),
        }
        // A cancelled or finished task can be removed; an open one cannot.
        let c = enqueue(&shared, "third", TaskKind::Audit(Vec::new()));
        pause(&shared, c);
        remove(&shared, c);
        remove(&shared, a);
        let ids: Vec<u64> = shared.tasks.lock().unwrap().iter().map(|t| t.id).collect();
        assert!(!ids.contains(&a) && ids.contains(&c) && ids.contains(&b));
    }

    /// Cancelling a running task stops it: the item in flight is not
    /// counted as audited and the items after it never start.
    #[test]
    fn cancel_stops_a_running_task() {
        crate::scan::register_task_ops();
        let shared = Shared::new();
        let (port, _hits) = origin();
        let entries: Vec<HistEntry> = (0..20)
            .map(|i| entry(port, &format!("/item{i}?x=1")))
            .collect();
        let a = enqueue(&shared, "long", TaskKind::Audit(entries));
        assert!(wait_for(&shared, a, TaskState::Running, 30));
        cancel(&shared, a);
        assert_eq!(state_of(&shared, a), Some(TaskState::Cancelled));
        // Let the item in flight wind down; a cancelled item is not counted.
        std::thread::sleep(Duration::from_millis(2500));
        let done = shared
            .tasks
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == a)
            .unwrap()
            .done;
        assert!(
            done < 20,
            "a cancelled task stops before its last item, done={done}"
        );
        std::thread::sleep(Duration::from_millis(1000));
        assert_eq!(
            shared
                .tasks
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.id == a)
                .unwrap()
                .done,
            done,
            "no further items run after a cancel"
        );
    }

    /// A one-request scan started while another task runs waits its turn
    /// instead of being dropped ("a scan is already running"), and is saved
    /// with the project as a plain audit of that request.
    #[test]
    fn single_scan_queues_behind_a_running_task() {
        crate::scan::register_task_ops();
        let shared = Shared::new();
        let (port, hits) = origin();
        let a = enqueue(
            &shared,
            "first",
            TaskKind::Audit(vec![entry(port, "/a?x=1")]),
        );
        assert!(wait_for(&shared, a, TaskState::Running, 10));
        let s = enqueue(
            &shared,
            "single",
            TaskKind::Single {
                entry: Box::new(entry(port, "/only?q=1")),
                oob: Vec::new(),
                smtp: Vec::new(),
            },
        );
        let saved = crate::project::ProjectScanTask::save_all(&shared.tasks.lock().unwrap());
        let single = saved
            .iter()
            .find(|t| t.name == "single")
            .expect("open single task saved");
        assert_eq!((single.entries.len(), single.urls.len()), (1, 0));
        assert!(
            wait_for(&shared, s, TaskState::Finished, 120),
            "{:?}",
            state_of(&shared, s)
        );
        let t = shared
            .tasks
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.id == s)
            .cloned()
            .unwrap();
        assert_eq!((t.done, t.total), (1, Some(1)));
        assert!(hits.load(Ordering::SeqCst) > 0);
    }
}
