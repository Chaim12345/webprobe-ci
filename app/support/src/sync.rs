// Poison-tolerant mutex.
//
// With std's Mutex, a panic on any thread that holds a lock poisons it, and
// every later `.lock().unwrap()` panics too: one failed worker (a scan check,
// a proxy connection) would take the UI thread down with it. The state behind
// these locks is plain data that stays usable after an interrupted update, so
// this wrapper hands the guard out regardless. `lock()` keeps the
// `Result` shape, with an error that cannot occur, so call sites written as
// `.lock().unwrap()` or `if let Ok(g) = m.lock()` work unchanged.

use std::convert::Infallible;
pub use std::sync::MutexGuard;

#[derive(Default)]
pub struct Mutex<T>(std::sync::Mutex<T>);

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex(std::sync::Mutex::new(value))
    }

    pub fn lock(&self) -> Result<MutexGuard<'_, T>, Infallible> {
        Ok(self.0.lock().unwrap_or_else(|poisoned| {
            crate::notice::toast(
                crate::notice::Level::Warn,
                "recovered a poisoned lock: a thread panicked while holding it (state may be partially written)",
            );
            poisoned.into_inner()
        }))
    }

    pub fn into_inner(self) -> Result<T, Infallible> {
        Ok(self.0.into_inner().unwrap_or_else(|poisoned| {
            crate::notice::toast(
                crate::notice::Level::Warn,
                "recovered a poisoned lock while taking ownership: a thread panicked while holding it",
            );
            poisoned.into_inner()
        }))
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::Mutex;
    use std::sync::Arc;

    #[test]
    fn a_panic_while_holding_the_lock_does_not_poison_it() {
        let shared = Arc::new(Mutex::new(vec![1, 2]));
        let worker = shared.clone();
        let result = std::thread::spawn(move || {
            let mut guard = worker.lock().unwrap();
            guard.push(3);
            panic!("worker failed while holding the lock");
        })
        .join();
        assert!(result.is_err(), "the worker must have panicked");
        // std's Mutex would make this unwrap panic; the data is still there.
        assert_eq!(*shared.lock().unwrap(), vec![1, 2, 3]);
        shared.lock().unwrap().push(4);
        assert_eq!(shared.lock().unwrap().len(), 4);
    }
}
