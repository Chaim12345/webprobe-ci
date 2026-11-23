// Wake coalescing tests (perf lane). Test-only code gated by #[cfg(test)] in
// mod.rs. The clock is passed in with `wake_at`: no sleeps, no shared state
// between tests, no reliance on suite order.
use super::*;

fn counted() -> (Arc<Shared>, Arc<AtomicUsize>) {
    let shared = Shared::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    shared.set_waker(Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    }));
    (shared, calls)
}

fn coalesced(shared: &Shared) -> u64 {
    shared.wakes_coalesced.load(Ordering::SeqCst)
}

#[test]
fn wakes_inside_the_coalescing_window_are_skipped() {
    let (shared, calls) = counted();
    shared.wake();
    shared.wake();
    shared.wake();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a burst coalesces to one");
    assert_eq!(coalesced(&shared), 2);
}

#[test]
fn first_wake_at_clock_zero_is_delivered_once() {
    let (shared, calls) = counted();
    shared.wake_at(0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    shared.wake_at(0);
    shared.wake_at(1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "clock 0 is not 'never woken'"
    );
    assert_eq!(coalesced(&shared), 2);
}

#[test]
fn many_calls_inside_the_window_deliver_one() {
    let (shared, calls) = counted();
    shared.wake_at(1000);
    for t in 1001..1000 + WAKE_COALESCE_MS {
        shared.wake_at(t);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(coalesced(&shared), WAKE_COALESCE_MS - 1);
}

#[test]
fn wake_exactly_at_the_boundary_is_delivered() {
    let (shared, calls) = counted();
    shared.wake_at(1000);
    shared.wake_at(1000 + WAKE_COALESCE_MS - 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one ms short is skipped");
    shared.wake_at(1000 + WAKE_COALESCE_MS);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the boundary delivers");
}

#[test]
fn wake_after_the_window_is_delivered_and_restarts_the_window() {
    let (shared, calls) = counted();
    shared.wake_at(0);
    shared.wake_at(WAKE_COALESCE_MS + 20);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    shared.wake_at(WAKE_COALESCE_MS + 21);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "window restarts at the last delivery"
    );
}

#[test]
fn wake_without_a_waker_is_a_no_op() {
    let shared = Shared::new();
    shared.wake_at(0);
    shared.wake_at(500);
    assert_eq!(coalesced(&shared), 0);
    assert_eq!(
        *shared.last_wake_ms.lock().unwrap(),
        None,
        "no waker: window unclaimed"
    );
}
