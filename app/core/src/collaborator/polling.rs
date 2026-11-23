//! Abortable scheduling around the synchronous interactsh client.
//!
//! One blocking request at a time, including manual polls and deregistration.
//! Aborting the scheduler cannot stop an OS socket call already in progress,
//! but it prevents publication and new requests. Cleanup waits off the UI
//! thread for the current request's gate, then deregisters the session.

use crate::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

pub(super) struct PollTask {
    task: tokio::task::JoinHandle<()>,
    stop: Arc<AtomicBool>,
    gate: Arc<Mutex<()>>,
    now: Arc<Notify>,
    changed: Arc<Notify>,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl PollTask {
    pub(super) fn start<T, P, F, C, D>(period: D, poll: P, publish: F, cleanup: C) -> Self
    where
        T: Send + 'static,
        P: Fn() -> Result<T, String> + Send + Sync + 'static,
        F: Fn(Result<T, String>) + Send + 'static,
        C: FnOnce() + Send + 'static,
        D: Fn() -> Duration + Send + 'static,
    {
        Self::with_timeout(period, poll, publish, cleanup, Duration::from_secs(30))
    }

    fn with_timeout<T, P, F, C, D>(
        period: D,
        poll: P,
        publish: F,
        cleanup: C,
        timeout: Duration,
    ) -> Self
    where
        T: Send + 'static,
        P: Fn() -> Result<T, String> + Send + Sync + 'static,
        F: Fn(Result<T, String>) + Send + 'static,
        C: FnOnce() + Send + 'static,
        D: Fn() -> Duration + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Mutex::new(()));
        let now = Arc::new(Notify::new());
        let changed = Arc::new(Notify::new());
        let (stop2, gate2, now2, changed2) =
            (stop.clone(), gate.clone(), now.clone(), changed.clone());
        let poll = Arc::new(poll);
        let task = crate::rt::engine().spawn(async move {
            let mut timer = tokio::time::interval(period().max(Duration::from_millis(1)));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = timer.tick() => {},
                    _ = now2.notified() => {},
                    _ = changed2.notified() => {
                        timer = tokio::time::interval_at(
                            tokio::time::Instant::now() + period(),
                            period().max(Duration::from_millis(1)),
                        );
                        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        continue;
                    }
                }
                let (poll, gate, stop) = (poll.clone(), gate2.clone(), stop2.clone());
                let mut request = tokio::task::spawn_blocking(move || {
                    let _guard = gate.lock().unwrap();
                    if stop.load(Ordering::SeqCst) {
                        return None;
                    }
                    Some(poll())
                });
                // Timeout reports a stalled poll, but do not detach it and
                // launch another. An in-progress blocking call is not abortable.
                let outcome = match tokio::time::timeout(timeout, &mut request).await {
                    Ok(result) => result,
                    Err(_) => {
                        publish(Err(format!(
                            "Collaborator poll timed out after {} ms",
                            timeout.as_millis()
                        )));
                        request.await
                    }
                };
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                match outcome {
                    Ok(Some(result)) => publish(result),
                    Ok(None) => break,
                    Err(error) => publish(Err(format!("Collaborator poll worker failed: {error}"))),
                }
                // Keep the old completion-relative spacing; do not catch up
                // missed ticks after a slow server or a manual request.
                timer.reset();
            }
        });
        Self {
            task,
            stop,
            gate,
            now,
            changed,
            cleanup: Some(Box::new(cleanup)),
        }
    }

    pub(super) fn poll_now(&self) {
        // Notify coalesces repeated clicks instead of spawning unbounded I/O.
        self.now.notify_one();
    }

    pub(super) fn interval_changed(&self) {
        self.changed.notify_one();
    }
}

impl Drop for PollTask {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.task.abort();
        let gate = self.gate.clone();
        if let Some(cleanup) = self.cleanup.take() {
            crate::rt::engine().spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = gate.lock().unwrap();
                    cleanup();
                })
                .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn manual_poll_and_interval_change_wake_a_long_timer() {
        let period = Arc::new(AtomicUsize::new(3600));
        let p = period.clone();
        let (tx, rx) = mpsc::channel();
        let task = PollTask::start(
            move || Duration::from_millis(p.load(Ordering::SeqCst) as u64),
            || Ok(()),
            move |r| {
                r.unwrap();
                tx.send(()).unwrap();
            },
            || {},
        );
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        task.poll_now();
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        period.store(10, Ordering::SeqCst);
        task.interval_changed();
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn stop_is_prompt_and_cleanup_waits_for_inflight_io() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let (published_tx, published_rx) = mpsc::channel();
        let (cleaned_tx, cleaned_rx) = mpsc::channel();
        let task = PollTask::start(
            || Duration::from_secs(3600),
            move || {
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                Ok(())
            },
            move |r| {
                published_tx.send(r).unwrap();
            },
            move || {
                cleaned_tx.send(()).unwrap();
            },
        );
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        drop(task);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(cleaned_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        cleaned_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(published_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());
        assert!(started_rx.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn failed_poll_is_reported_then_manual_poll_recovers() {
        let calls = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel();
        let task = PollTask::start(
            || Duration::from_secs(3600),
            move || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err("refused".into())
                } else {
                    Ok(7)
                }
            },
            move |result| {
                tx.send(result).unwrap();
            },
            || {},
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap_err(),
            "refused"
        );
        task.poll_now();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(), 7);
    }
    #[test]
    fn timeout_and_manual_clicks_never_overlap_requests() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let (result_tx, result_rx) = mpsc::channel();
        let task = PollTask::with_timeout(
            || Duration::from_secs(3600),
            move || {
                started_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                Ok(())
            },
            move |r| {
                result_tx.send(r).unwrap();
            },
            || {},
            Duration::from_millis(20),
        );
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..100 {
            task.poll_now();
        }
        let error = result_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(error.contains("timed out"));
        assert!(started_rx.recv_timeout(Duration::from_millis(100)).is_err());
        // Complete the timed-out operation; an active session retains its data.
        release_tx.send(()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        result_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        // Dropping during the next I/O also suppresses its result.
        drop(task);
        release_tx.send(()).unwrap();
        assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());
    }
    #[test]
    fn active_session_publishes_interactions_after_timeout() {
        let (tx, rx) = mpsc::channel();
        let _task = PollTask::with_timeout(
            || Duration::from_secs(3600),
            || {
                std::thread::sleep(Duration::from_millis(80));
                Ok(vec![42])
            },
            move |r| {
                tx.send(r).unwrap();
            },
            || {},
            Duration::from_millis(10),
        );
        assert!(rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err()
            .contains("timed out"));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(),
            vec![42]
        );
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn stopping_idle_task_cleans_up_once_without_another_poll() {
        let (poll_tx, poll_rx) = mpsc::channel();
        let (cleaned_tx, cleaned_rx) = mpsc::channel();
        let task = PollTask::start(
            || Duration::from_secs(3600),
            move || {
                poll_tx.send(()).unwrap();
                Ok(())
            },
            |_| {},
            move || {
                cleaned_tx.send(()).unwrap();
            },
        );
        poll_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(task);
        cleaned_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(poll_rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(cleaned_rx.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn interval_change_during_io_is_applied_after_completion() {
        let period = Arc::new(AtomicUsize::new(3600));
        let p = period.clone();
        let calls = AtomicUsize::new(0);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let task = PollTask::start(
            move || Duration::from_millis(p.load(Ordering::SeqCst) as u64),
            move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                started_tx.send(n).unwrap();
                if n == 0 {
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                }
                Ok(())
            },
            |_| {},
            || {},
        );
        assert_eq!(started_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        period.store(20, Ordering::SeqCst);
        task.interval_changed();
        // Changing settings must not launch overlapping requests.
        assert!(started_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        assert_eq!(started_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        drop(task);
    }

    #[test]
    fn panicking_poll_is_reported_and_next_manual_poll_recovers() {
        let calls = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel();
        let task = PollTask::start(
            || Duration::from_secs(3600),
            move || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("poll worker test failure");
                }
                Ok(42)
            },
            move |result| {
                tx.send(result).unwrap();
            },
            || {},
        );
        assert!(rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err()
            .contains("worker failed"));
        task.poll_now();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(),
            42
        );
    }
}
