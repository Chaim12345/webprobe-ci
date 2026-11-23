//! Repeater's send state (N-07): whether a send is in flight, its
//! generation, the status line, and tab ids. Kept under one lock so a
//! cancelled or superseded send can never overwrite the state of a newer one.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::sync::Mutex;

struct State {
    busy: bool,
    generation: u64,
    result: String,
    /// The tab the send belongs to.
    tab: u64,
}

pub struct RepeaterRun {
    state: Mutex<State>,
    next_tab: AtomicU64,
}

impl Default for RepeaterRun {
    fn default() -> Self {
        // Tab 1 exists from the start; new tabs count on from 2.
        RepeaterRun {
            state: Mutex::new(State {
                busy: false,
                generation: 0,
                result: String::new(),
                tab: 0,
            }),
            next_tab: AtomicU64::new(2),
        }
    }
}

impl RepeaterRun {
    /// A tab id never used before (ids are never reused, so routing a late
    /// response by id cannot hit another tab).
    pub fn new_tab_id(&self) -> u64 {
        self.next_tab.fetch_add(1, Ordering::SeqCst)
    }

    pub fn is_busy(&self) -> bool {
        self.state.lock().unwrap().busy
    }

    /// The status line under the editors.
    pub fn result(&self) -> String {
        self.state.lock().unwrap().result.clone()
    }

    /// Start a send for `tab`: busy, "sending...", and the generation the
    /// worker must still hold when it finishes.
    pub fn begin(&self, tab: u64) -> u64 {
        let mut s = self.state.lock().unwrap();
        s.busy = true;
        s.generation += 1;
        s.result = "sending...".into();
        s.tab = tab;
        s.generation
    }

    /// Whether `generation` is still the current send (not cancelled or
    /// superseded).
    pub fn is_current(&self, generation: u64) -> bool {
        self.state.lock().unwrap().generation == generation
    }

    /// Finish the send of `generation`: `write` (which puts the response into
    /// its tab and returns the status line) runs only if the send is still
    /// current, under this state's lock, so a Cancel cannot land between the
    /// check and the write. False when it was cancelled or superseded. Never
    /// call another `RepeaterRun` method from `write`.
    pub fn finish_with(&self, generation: u64, write: impl FnOnce() -> String) -> bool {
        let mut s = self.state.lock().unwrap();
        if s.generation != generation {
            return false;
        }
        s.result = write();
        s.busy = false;
        true
    }

    /// Show progress of the send of `generation` (a streaming response so
    /// far): `write` runs only while the send is current, under this state's
    /// lock; the send stays busy. Never call another `RepeaterRun` method
    /// from `write`.
    pub fn finish_partial(&self, generation: u64, write: impl FnOnce()) -> bool {
        let s = self.state.lock().unwrap();
        if s.generation != generation {
            return false;
        }
        write();
        true
    }

    /// Abandon the in-flight send: the tab is free at once and the late
    /// response, if any, never lands. Returns the send's tab, None when
    /// nothing was in flight.
    pub fn cancel(&self) -> Option<u64> {
        let mut s = self.state.lock().unwrap();
        if !s.busy {
            return None;
        }
        s.generation += 1;
        s.busy = false;
        s.result = "Request cancelled".into();
        Some(s.tab)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_send_cannot_finish() {
        let r = RepeaterRun::default();
        let g = r.begin(5);
        assert!(r.is_busy() && r.result() == "sending...");
        assert_eq!(r.cancel(), Some(5));
        assert!(!r.is_busy() && r.result() == "Request cancelled");
        assert!(
            !r.finish_with(g, || unreachable!("a cancelled send writes nothing")),
            "late result dropped"
        );
        assert_eq!(r.result(), "Request cancelled");
        assert_eq!(r.cancel(), None, "nothing in flight");
        let g2 = r.begin(6);
        assert!(r.is_current(g2) && !r.is_current(g));
        assert!(r.finish_with(g2, || "Done".into()));
        assert_eq!(r.result(), "Done");
        assert!(!r.is_busy());
        let (a, b) = (r.new_tab_id(), r.new_tab_id());
        assert!(a >= 2 && b > a);
    }
}
