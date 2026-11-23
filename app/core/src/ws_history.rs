//! Proxy WebSockets history (R-07): every message as bytes with its kind
//! (text, binary, ping, pong, close, handshake), owned by one type with
//! private rows. Payloads are `body::Body`, so large ones live in the
//! on-disk store, not in RAM; readers borrow the rows (`with_rows`) or copy
//! one message (`get`), and the view checks a cheap `stamp` instead of
//! cloning the history each frame.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use crate::body::Body;

/// One WebSocket message (or the upgrade handshake) seen by the Proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsEntry {
    pub id: u64,
    pub ts: u64,
    pub host: String,
    /// "client -> server", "server -> client" or "handshake".
    pub direction: String,
    /// "text", "binary", "ping", "pong", "close", "request"/"response"
    /// (handshake), or a note for a frame that was not captured.
    pub opcode: String,
    /// The message bytes, exactly as sent (inflated when the connection
    /// used permessage-deflate).
    pub payload: Body,
    /// The connection the message belongs to (0: unknown, older projects).
    pub socket: u64,
}

impl WsEntry {
    /// The payload as text (lossy for binary data; display only).
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.payload)
    }

    pub fn is_binary(&self) -> bool {
        self.opcode == "binary"
    }
}

/// Keep at most this many rows after each batch eviction. Evicting 1024 at
/// once avoids an O(n) front removal for every message.
pub const MAX_WS_HISTORY_ROWS: usize = 100_000;
const EVICT_BATCH: usize = 1024;

#[derive(Default)]
pub struct WsHistory {
    rows: RwLock<Vec<WsEntry>>,
    stamp: AtomicU64,
    /// Payload bytes kept in memory (not in the body store), for the bound.
    inline_bytes: AtomicU64,
}

fn inline_len(b: &Body) -> u64 {
    if b.is_stored() {
        0
    } else {
        b.len() as u64
    }
}

/// Drop the oldest batch when the bound is exceeded, returning their inline
/// byte count so the memory accounting stays exact.
fn bound_rows(rows: &mut Vec<WsEntry>) -> u64 {
    if rows.len() <= MAX_WS_HISTORY_ROWS + EVICT_BATCH {
        return 0;
    }
    let excess = rows.len() - MAX_WS_HISTORY_ROWS;
    let released = rows
        .iter()
        .take(excess)
        .map(|e| inline_len(&e.payload))
        .sum();
    rows.drain(..excess);
    released
}

impl WsHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a message; its payload moves to the body store when large.
    pub fn push(&self, mut e: WsEntry) {
        e.payload = crate::body::spill(&e.payload);
        self.inline_bytes
            .fetch_add(inline_len(&e.payload), Ordering::Relaxed);
        let mut rows = self.rows.write().unwrap_or_else(|p| p.into_inner());
        rows.push(e);
        let released = bound_rows(&mut rows);
        drop(rows);
        self.inline_bytes.fetch_sub(released, Ordering::Relaxed);
        self.stamp.fetch_add(1, Ordering::SeqCst);
    }

    /// Replace everything (a project was loaded).
    pub fn set_all(&self, rows: Vec<WsEntry>) {
        let rows: Vec<WsEntry> = rows
            .into_iter()
            .map(|mut e| {
                e.payload = crate::body::spill(&e.payload);
                e
            })
            .collect();
        let mut rows = rows;
        bound_rows(&mut rows);
        self.inline_bytes.store(
            rows.iter().map(|e| inline_len(&e.payload)).sum(),
            Ordering::Relaxed,
        );
        *self.rows.write().unwrap_or_else(|p| p.into_inner()) = rows;
        self.stamp.fetch_add(1, Ordering::SeqCst);
    }

    pub fn clear(&self) {
        self.set_all(Vec::new());
    }

    pub fn len(&self) -> usize {
        self.rows.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Changes whenever the history changes: views redo their row list only then.
    pub fn stamp(&self) -> u64 {
        self.stamp.load(Ordering::SeqCst)
    }

    /// Payload bytes held in memory (the rest is in the body store).
    pub fn inline_bytes(&self) -> u64 {
        self.inline_bytes.load(Ordering::Relaxed)
    }

    /// Borrow the rows (oldest first) without copying them.
    pub fn with_rows<R>(&self, f: impl FnOnce(&[WsEntry]) -> R) -> R {
        f(&self.rows.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// One message by id (payload handles are cheap to copy).
    pub fn get(&self, id: u64) -> Option<WsEntry> {
        self.with_rows(|rows| rows.iter().find(|e| e.id == id).cloned())
    }

    /// The messages at these positions (a view's visible window).
    pub fn rows_at(&self, at: &[usize]) -> Vec<WsEntry> {
        self.with_rows(|rows| at.iter().filter_map(|&i| rows.get(i).cloned()).collect())
    }

    /// Positions of the rows `keep` accepts (no payload is copied).
    pub fn positions(&self, mut keep: impl FnMut(&WsEntry) -> bool) -> Vec<usize> {
        self.with_rows(|rows| {
            rows.iter()
                .enumerate()
                .filter(|(_, e)| keep(e))
                .map(|(i, _)| i)
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, payload: Vec<u8>) -> WsEntry {
        WsEntry {
            id,
            ts: 0,
            host: "h".into(),
            direction: "server -> client".into(),
            opcode: "binary".into(),
            payload: payload.into(),
            socket: 1,
        }
    }

    #[test]
    fn a_hundred_thousand_messages_keep_bounded_memory_and_cheap_windows() {
        let h = WsHistory::new();
        let s0 = h.stamp();
        for i in 0..100_000u64 {
            // Every 1000th message is large; the rest are small.
            let len = if i % 1000 == 0 { 64 * 1024 } else { 40 };
            h.push(entry(i, vec![(i % 251) as u8; len]));
        }
        assert_eq!(h.len(), 100_000);
        assert!(h.stamp() > s0);
        // Large payloads went to the body store: only small ones stay inline.
        assert!(h.inline_bytes() <= 100_000 * 256, "{}", h.inline_bytes());
        let big = h.get(5000).unwrap();
        assert!(
            big.payload.is_stored()
                && big.payload.len() == 64 * 1024
                && big.payload.iter().all(|&b| b == (5000 % 251) as u8)
        );
        // A view takes positions (no payload copies) and only its window.
        let even = h.positions(|e| e.id % 2 == 0);
        assert_eq!(even.len(), 50_000);
        let window = h.rows_at(&even[100..140]);
        assert_eq!(window.len(), 40);
        assert_eq!(window[0].id, 200);
    }

    #[test]
    fn old_rows_are_evicted_in_batches_with_exact_inline_accounting() {
        let h = WsHistory::new();
        for i in 0..(MAX_WS_HISTORY_ROWS + EVICT_BATCH + 1) as u64 {
            h.push(entry(i, vec![b'x'; 40]));
        }
        assert_eq!(h.len(), MAX_WS_HISTORY_ROWS);
        assert_eq!(h.inline_bytes(), (MAX_WS_HISTORY_ROWS * 40) as u64);
        assert_eq!(h.with_rows(|rows| rows[0].id), (EVICT_BATCH + 1) as u64);
    }

    #[test]
    fn binary_payloads_keep_their_bytes() {
        let h = WsHistory::new();
        let bytes = vec![0xff, 0xfe, 0x00, 0xc3, 0x28, 0x80];
        h.push(entry(1, bytes.clone()));
        assert_eq!(&*h.get(1).unwrap().payload, bytes.as_slice());
    }
}
