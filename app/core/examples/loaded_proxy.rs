//! Headless proxy process for load measurement (perf lane, 2026-11-22).
//!
//! Boots the engine's proxy listener on a fresh in-memory project, prints
//! `READY <port>` once the listener accepts connections, then idles until
//! killed. A counting waker stands in for the front end: STATS lines on
//! stderr show how many repaints the engine requested, so wake coalescing
//! is measurable without a UI. The harness in qa/perf-load drives traffic.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use webprobe_core::net::{start_proxy, Shared};

static WAKES: AtomicU64 = AtomicU64::new(0);

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(18080);
    let shared = Shared::new();
    shared.set_waker(Arc::new(|| {
        WAKES.fetch_add(1, Ordering::SeqCst);
    }));
    shared.proxy_port.store(port, Ordering::SeqCst);
    start_proxy(Arc::clone(&shared));
    for _ in 0..500 {
        if shared.listener_running.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !shared.listener_running.load(Ordering::SeqCst) {
        eprintln!("listener failed to start on 127.0.0.1:{port}");
        std::process::exit(1);
    }
    println!("READY {port}");
    let stats = Arc::clone(&shared);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        eprintln!(
            "STATS messages={} wakes={} coalesced={}",
            stats.messages.load(Ordering::SeqCst),
            WAKES.load(Ordering::SeqCst),
            stats.wakes_coalesced.load(Ordering::SeqCst),
        );
    });
    loop {
        std::thread::park();
    }
}
