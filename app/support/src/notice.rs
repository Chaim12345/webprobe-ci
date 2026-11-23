// Notices raised by engine code (listener failures, scan results, ...).
//
// Engine modules must not depend on the UI, so they push into this
// process-wide queue; the UI (feedback.rs) drains it once per frame and shows
// the entries as toasts.

use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

/// Notices kept while nothing drains the queue; older ones drop off.
const QUEUE_MAX: usize = 16;

static QUEUE: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());

type Waker = std::sync::Arc<dyn Fn() + Send + Sync>;

static WAKER: Mutex<Option<Waker>> = Mutex::new(None);

/// Install the front end's wake-up call: notices are then shown at once.
pub fn set_waker(f: Waker) {
    *WAKER.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
}

/// Raise a notice from anywhere (network threads included).
pub fn toast(level: Level, text: impl Into<String>) {
    let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    q.push((level, text.into()));
    if q.len() > QUEUE_MAX {
        q.remove(0);
    }
    drop(q);
    let waker = WAKER.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(f) = waker {
        f();
    }
}

/// Take everything queued so far, oldest first.
pub fn take_queued() -> Vec<(Level, String)> {
    std::mem::take(&mut *QUEUE.lock().unwrap_or_else(|e| e.into_inner()))
}
