//! Async Phase 1 (issue #42): one tokio runtime on its own dedicated
//! thread; the scanner/intruder engine submits futures to it while the UI
//! and proxy code stay synchronous (the bridging pattern,
//! <https://tokio.rs/tokio/topics/bridging>).
//!
//! - [`probe_pool`] builds a `tokio::sync::Semaphore`, the resource pool
//!   bounding in-flight probes: it replaces the ad-hoc per-scan worker
//!   thread counts.
//! - Cancellation is cooperative for started blocking work. Abort can
//!   prevent a queued blocking body from starting, but cannot interrupt one
//!   already running. Existing atomic stop checks end those bodies.
//! - Results flow back over `tokio::sync::mpsc` channels, drained per
//!   frame by the egui side (see `intruder_run::RunState::drain_rows`).
//!
//! Constraints from the issue: `std::sync::Mutex` stays (the critical
//! sections are short and never held across an `.await`, so no
//! `tokio::sync::Mutex` is needed), and extension hooks (BCheck /
//! ext_host closures) run inside `tokio::task::spawn_blocking`, never on
//! a runtime thread.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// The process-wide engine runtime.
pub struct EngineRt {
    handle: tokio::runtime::Handle,
}

static ENGINE: OnceLock<EngineRt> = OnceLock::new();

/// The engine runtime, started on first use and owned by the process (it
/// never shuts down, like the proxy listener).
pub fn engine() -> &'static EngineRt {
    ENGINE.get_or_init(EngineRt::start)
}

impl EngineRt {
    fn start() -> EngineRt {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build the engine runtime");
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("engine-rt".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .expect("spawn the engine runtime thread");
        EngineRt { handle }
    }

    /// Submit a future to the engine runtime.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(future)
    }

    /// Submit a blocking engine body (a scan run) as one runtime task
    /// (issue #42): the body runs in `tokio::task::spawn_blocking`, never
    /// on a runtime thread, so extension hooks (BCheck / ext_host
    /// closures) stay off the runtime too. `stop` mirrors the tool's
    /// existing cancel flag: once it reports true the task's
    /// `JoinHandle` is aborted. Abort may cancel a body that has not started;
    /// it does not interrupt a running blocking body. The wrapper awaits
    /// that body's completion, which depends on its own cooperative stop
    /// checks and any in-flight blocking calls returning. A panic is contained
    /// and raised as a notice (panic policy "contain and continue",
    /// issue #32).
    pub fn spawn_engine<F, S>(&self, name: &'static str, stop: S, f: F)
    where
        F: FnOnce() + Send + 'static,
        S: Fn() -> bool + Send + 'static,
    {
        self.handle.spawn(async move {
            let mut body = tokio::task::spawn_blocking(f);
            loop {
                tokio::select! {
                    r = &mut body => {
                        if let Err(e) = r {
                            if e.is_panic() {
                                crate::notice::toast(
                                    crate::notice::Level::Warn,
                                    format!(
                                        "engine task '{name}' panicked; the thread ended, the session continues"
                                    ),
                                );
                            }
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {
                        if stop() {
                            body.abort();
                            let _ = body.await;
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// One run's probe pool (issue #42): a `tokio::sync::Semaphore` bounding
/// how many probes are in flight at once, replacing the ad-hoc per-scan
/// worker-thread count.
#[derive(Clone)]
pub struct ProbePool {
    sem: Arc<tokio::sync::Semaphore>,
    limit: usize,
}

/// A probe pool with `limit` in-flight slots (never zero).
pub fn probe_pool(limit: usize) -> ProbePool {
    ProbePool {
        sem: Arc::new(tokio::sync::Semaphore::new(limit.max(1))),
        limit: limit.max(1),
    }
}

impl ProbePool {
    /// Wait for a free in-flight slot: a probe task's abort point, so an
    /// aborted probe is cancelled before any side effect.
    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("the probe pool is never closed")
    }

    /// The configured in-flight bound.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The pool caps in-flight probes and every queued probe runs.
    #[test]
    fn probe_pool_caps_in_flight() {
        let pool = probe_pool(3);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));
        let mut set = tokio::task::JoinSet::new();
        let rt = engine();
        let (tx, rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            for _ in 0..20 {
                let (pool, in_flight, max_seen, done) = (
                    pool.clone(),
                    in_flight.clone(),
                    max_seen.clone(),
                    done.clone(),
                );
                set.spawn(async move {
                    let _permit = pool.acquire().await;
                    tokio::task::spawn_blocking(move || {
                        let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(n, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        done.fetch_add(1, Ordering::SeqCst);
                    })
                    .await
                    .unwrap();
                });
            }
            while set.join_next().await.is_some() {}
            tx.send((max_seen, done)).unwrap();
        });
        let (max_seen, done) = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("probes finished");
        assert_eq!(done.load(Ordering::SeqCst), 20, "every probe ran");
        assert!(max_seen.load(Ordering::SeqCst) <= 3, "pool bound held");
    }

    /// The body has definitely started, and must return by observing Stop.
    /// The channel acknowledgement proves early exit, not merely that a late
    /// side effect has not happened yet. Unpark avoids timing-based setup.
    #[test]
    fn started_engine_body_stops_cooperatively_before_its_deadline() {
        let stop = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (ended_tx, ended_rx) = std::sync::mpsc::channel();
        let (poll_stop, body_stop) = (stop.clone(), stop.clone());
        engine().spawn_engine(
            "cooperative-test",
            move || poll_stop.load(Ordering::SeqCst),
            move || {
                started_tx.send(std::thread::current()).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while std::time::Instant::now() < deadline {
                    if body_stop.load(Ordering::SeqCst) {
                        ended_tx.send("cooperative stop").unwrap();
                        return;
                    }
                    std::thread::park_timeout(Duration::from_secs(30));
                }
                let _ = ended_tx.send("natural deadline");
            },
        );
        let body_thread = started_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("body started");
        stop.store(true, Ordering::SeqCst);
        body_thread.unpark();
        assert_eq!(
            ended_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("started body exited early"),
            "cooperative stop"
        );
    }
}
