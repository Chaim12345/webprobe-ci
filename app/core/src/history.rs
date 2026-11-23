//! Proxy history (and the crawl's site map items) as an owned type (N-07).
//!
//! The entries are private: every write goes through a method that moves the
//! bodies into the on-disk store (`HistEntry::spilled`), so a path that
//! forgets to spill no longer compiles. Readers get short, scoped access
//! (`with_rows`, `get`, `snapshot`) and never hold the lock while doing UI or
//! network work.

use crate::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use webprobe_support::hist::HistEntry;

#[derive(Default)]
pub struct ProxyHistory {
    rows: Mutex<Vec<HistEntry>>,
    /// Largest id ever held (0 when empty), maintained on writes so readers
    /// answer "was anything added?" in O(1) instead of scanning every row.
    max_id: AtomicU64,
}

impl ProxyHistory {
    /// Append one entry (bodies spilled).
    pub fn push(&self, e: HistEntry) {
        let e = e.spilled();
        self.max_id.fetch_max(e.id, Ordering::SeqCst);
        self.rows.lock().unwrap().push(e);
    }

    /// Append several entries (bodies spilled), in order.
    pub fn extend(&self, entries: impl IntoIterator<Item = HistEntry>) {
        let entries: Vec<HistEntry> = entries.into_iter().map(HistEntry::spilled).collect();
        for e in &entries {
            self.max_id.fetch_max(e.id, Ordering::SeqCst);
        }
        self.rows.lock().unwrap().extend(entries);
    }

    /// Replace every entry (project load), bodies spilled.
    pub fn replace_all(&self, entries: impl IntoIterator<Item = HistEntry>) {
        let entries: Vec<HistEntry> = entries.into_iter().map(HistEntry::spilled).collect();
        let max = entries.iter().map(|e| e.id).max().unwrap_or(0);
        self.max_id.store(max, Ordering::SeqCst);
        *self.rows.lock().unwrap() = entries;
    }

    pub fn clear(&self) {
        self.rows.lock().unwrap().clear();
        self.max_id.store(0, Ordering::SeqCst);
    }

    /// The largest id in the history (0 when empty), maintained on writes.
    pub fn max_id(&self) -> u64 {
        self.max_id.load(Ordering::SeqCst)
    }

    /// The rows added since a mirror pass, for consumers that copy new
    /// entries out on every frame (the Logger mirror). `cursor` is the row
    /// count mirrored so far and `cursor_id` the id of the row at
    /// `cursor - 1` from that pass; both come from the previous return.
    /// When earlier rows changed since (a deletion, a project load), the
    /// cursor no longer lines up and every row is returned with `resynced`
    /// set. Without a cursor a mirror pass scanned the whole history on
    /// every frame and held the lock while doing it, so proxy threads
    /// stalled behind the UI at large histories.
    pub fn rows_since(&self, cursor: usize, cursor_id: u64) -> (Vec<HistEntry>, usize, u64, bool) {
        let rows = self.rows.lock().unwrap();
        let valid = cursor <= rows.len()
            && (cursor == 0 || rows.get(cursor - 1).map(|e| e.id) == Some(cursor_id));
        let start = if valid { cursor } else { 0 };
        let out: Vec<HistEntry> = rows[start..].to_vec();
        let new_cursor = rows.len();
        let new_cursor_id = rows.last().map(|e| e.id).unwrap_or(0);
        (out, new_cursor, new_cursor_id, !valid)
    }

    pub fn len(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// (number of entries, id of the newest): changes whenever entries are
    /// added or removed, for caches keyed on the history.
    pub fn stamp(&self) -> (usize, u64) {
        let rows = self.rows.lock().unwrap();
        (rows.len(), rows.last().map(|e| e.id).unwrap_or(0))
    }

    /// The entry with `id`.
    pub fn get(&self, id: u64) -> Option<HistEntry> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// The newest entry.
    pub fn last(&self) -> Option<HistEntry> {
        self.rows.lock().unwrap().last().cloned()
    }

    /// Every entry, oldest first. Cheap: bodies are shared handles.
    pub fn snapshot(&self) -> Vec<HistEntry> {
        self.rows.lock().unwrap().clone()
    }

    /// Read access for the length of `f`. Keep `f` short: proxy threads
    /// wait for this lock to record traffic.
    pub fn with_rows<R>(&self, f: impl FnOnce(&[HistEntry]) -> R) -> R {
        f(&self.rows.lock().unwrap())
    }

    /// Keep the entries `keep` accepts; returns how many were removed.
    pub fn retain(&self, keep: impl FnMut(&HistEntry) -> bool) -> usize {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(keep);
        let removed = before - rows.len();
        if removed > 0 {
            let max = rows.iter().map(|e| e.id).max().unwrap_or(0);
            self.max_id.store(max, Ordering::SeqCst);
        }
        removed
    }

    /// Change the entry with `id` in place (notes, highlight); false when
    /// there is none. Bodies set by `f` are spilled.
    pub fn update(&self, id: u64, f: impl FnOnce(&mut HistEntry)) -> bool {
        let mut rows = self.rows.lock().unwrap();
        let Some(e) = rows.iter_mut().find(|e| e.id == id) else {
            return false;
        };
        f(e);
        *e = std::mem::take(e).spilled();
        true
    }

    /// Change every entry `pick` selects; returns how many.
    pub fn update_where(
        &self,
        mut pick: impl FnMut(&HistEntry) -> bool,
        mut f: impl FnMut(&mut HistEntry),
    ) -> usize {
        let mut rows = self.rows.lock().unwrap();
        let mut n = 0;
        for e in rows.iter_mut().filter(|e| pick(e)) {
            f(e);
            *e = std::mem::take(e).spilled();
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_spill_and_reads_are_scoped() {
        let h = ProxyHistory::default();
        let big = vec![b'x'; 4096];
        h.push(HistEntry {
            id: 1,
            resp_raw: Some(big.clone().into()),
            ..Default::default()
        });
        h.extend([
            HistEntry {
                id: 2,
                ..Default::default()
            },
            HistEntry {
                id: 3,
                ..Default::default()
            },
        ]);
        assert_eq!(h.stamp(), (3, 3));
        if cfg!(unix) {
            assert!(
                h.get(1).unwrap().resp_raw.unwrap().is_stored(),
                "pushed bodies are spilled"
            );
        }
        assert!(h.update(2, |e| e.note = Some("n".into())));
        assert!(!h.update(9, |_| {}));
        assert_eq!(h.get(2).unwrap().note.as_deref(), Some("n"));
        assert_eq!(h.update_where(|e| e.id >= 2, |e| e.highlight = Some(1)), 2);
        assert_eq!(h.retain(|e| e.id != 3), 1);
        assert_eq!(
            h.with_rows(|r| r.iter().map(|e| e.id).collect::<Vec<_>>()),
            [1, 2]
        );
        h.replace_all([HistEntry {
            id: 7,
            ..Default::default()
        }]);
        assert_eq!((h.len(), h.last().map(|e| e.id)), (1, Some(7)));
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn max_id_tracks_writes() {
        let h = ProxyHistory::default();
        assert_eq!(h.max_id(), 0);
        h.push(HistEntry {
            id: 3,
            ..Default::default()
        });
        h.extend([
            HistEntry {
                id: 7,
                ..Default::default()
            },
            HistEntry {
                id: 5,
                ..Default::default()
            },
        ]);
        assert_eq!(h.max_id(), 7);
        h.retain(|e| e.id != 7);
        assert_eq!(h.max_id(), 5);
        h.replace_all([HistEntry {
            id: 42,
            ..Default::default()
        }]);
        assert_eq!(h.max_id(), 42);
        h.clear();
        assert_eq!(h.max_id(), 0);
    }

    #[test]
    fn rows_since_returns_only_new_rows_while_the_cursor_lines_up() {
        let h = ProxyHistory::default();
        for id in 1..=5 {
            h.push(HistEntry {
                id,
                ..Default::default()
            });
        }
        let (rows, cursor, cursor_id, resynced) = h.rows_since(0, 0);
        assert!(!resynced);
        assert_eq!(rows.len(), 5);
        assert_eq!(cursor, 5);
        assert_eq!(cursor_id, 5);
        // A pass with no new rows returns nothing and does not resync.
        let (rows, cursor, cursor_id, resynced) = h.rows_since(cursor, cursor_id);
        assert!(!resynced);
        assert!(rows.is_empty());
        // Two new rows: only those come back.
        h.push(HistEntry {
            id: 6,
            ..Default::default()
        });
        h.push(HistEntry {
            id: 7,
            ..Default::default()
        });
        let (rows, cursor, cursor_id, resynced) = h.rows_since(cursor, cursor_id);
        assert!(!resynced);
        assert_eq!(rows.iter().map(|e| e.id).collect::<Vec<_>>(), [6, 7]);
        assert_eq!((cursor, cursor_id), (7, 7));
        // A deletion before the cursor invalidates it: full resync.
        h.retain(|e| e.id != 3);
        let (rows, cursor, _, resynced) = h.rows_since(cursor, cursor_id);
        assert!(resynced);
        assert_eq!(rows.len(), 6);
        assert_eq!(cursor, 6);
        // A project load (replace_all) invalidates it the same way.
        h.replace_all([HistEntry {
            id: 1,
            ..Default::default()
        }]);
        let (rows, cursor, cursor_id, resynced) = h.rows_since(cursor, 7);
        assert!(resynced);
        assert_eq!(rows.len(), 1);
        assert_eq!((cursor, cursor_id), (1, 1));
        // A cursor past the end (history shrunk under it) also resyncs.
        let (_, _, _, resynced) = h.rows_since(99, 1);
        assert!(resynced);
    }

    /// Diagnostic timing for the Logger mirror's history access: the old
    /// per-frame whole-history scan vs one `rows_since` pass at the same
    /// history size. Run with
    /// `cargo test -p webprobe-core benchmark_mirror_history_access -- --ignored --nocapture`.
    #[test]
    #[ignore = "diagnostic timing, not a CI threshold"]
    fn benchmark_mirror_history_access() {
        let h = ProxyHistory::default();
        for id in 1..=100_000u64 {
            h.push(HistEntry {
                id,
                ..Default::default()
            });
        }
        let t0 = std::time::Instant::now();
        let mut newest = 0u64;
        let mut copied = 0usize;
        h.with_rows(|rows| {
            for e in rows.iter() {
                newest = newest.max(e.id);
            }
            for e in rows.iter().filter(|e| e.id > newest.saturating_sub(1)) {
                copied += e.method.len();
            }
        });
        let scan = t0.elapsed();
        let t0 = std::time::Instant::now();
        let (rows, _, _, _) = h.rows_since(99_999, 99_999);
        let incremental = t0.elapsed();
        copied += rows.len();
        eprintln!("100k rows: old two-pass scan {scan:?}, rows_since {incremental:?} ({copied})");
    }
}
