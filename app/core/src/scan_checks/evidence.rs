use std::cell::RefCell;

use super::*;

// ---------------------------------------------------------------- evidence

/// Records every exchange a check sends, keyed by the payload it was built
/// from, so the confirming exchange(s) can be attached to the issue.
#[derive(Default)]
pub(crate) struct Recorder {
    log: RefCell<Vec<(String, ScanEvidence)>>,
}

impl Recorder {
    /// Send `raw` for `key` and keep a bounded copy of the exchange.
    pub(crate) fn send(&self, cx: &ScanCtx, key: &str, raw: &[u8]) -> Option<Vec<u8>> {
        let resp = cx.send(raw);
        self.note(key, raw, resp.as_deref());
        resp
    }

    /// Keep an exchange sent by other means.
    pub(crate) fn note(&self, key: &str, raw: &[u8], resp: Option<&[u8]>) {
        self.log
            .borrow_mut()
            .push((key.to_string(), ScanEvidence::new(raw, resp)));
    }

    fn last_index(&self, key: &str) -> Option<usize> {
        self.log.borrow().iter().rposition(|(k, _)| k == key)
    }

    /// The latest exchange sent for `key`.
    pub(crate) fn last(&self, key: &str) -> Option<ScanEvidence> {
        let i = self.last_index(key)?;
        self.log.borrow().get(i).map(|(_, e)| e.clone())
    }

    /// The exchange sent right after the latest one for `key` (a negative
    /// control or a retrieval request).
    pub(crate) fn next_after(&self, key: &str) -> Option<ScanEvidence> {
        let i = self.last_index(key)?;
        self.log.borrow().get(i + 1).map(|(_, e)| e.clone())
    }

    /// The latest exchange for `key` and every exchange after it.
    pub(crate) fn since_last(&self, key: &str) -> Vec<ScanEvidence> {
        let Some(i) = self.last_index(key) else {
            return Vec::new();
        };
        self.log.borrow()[i..]
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }
}

pub fn evidence(items: impl IntoIterator<Item = Option<ScanEvidence>>) -> Vec<ScanEvidence> {
    items.into_iter().flatten().collect()
}
