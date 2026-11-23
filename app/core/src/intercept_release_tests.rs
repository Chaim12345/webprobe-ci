//! Release of held intercepted messages: `set_intercept(false)`,
//! `intercept_release_all`, `intercept_wait` and the liveness check of held
//! WebSocket messages. Every wait has a deadline.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::net::{
    self, build_ws_frame, parse_ws_frame, ws_relay_chunk_alive, InterceptItem, InterceptKind,
    Shared, WsOut, WsStream,
};

const DEADLINE: Duration = Duration::from_secs(5);

fn held_shared() -> Arc<Shared> {
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared
}

/// Run the relay for one chunk on its own thread; its output arrives on the
/// returned channel.
fn relay(
    shared: &Arc<Shared>,
    wire: Vec<u8>,
    to_server: bool,
    alive: Arc<AtomicBool>,
) -> Receiver<WsOut> {
    let (tx, rx) = mpsc::channel();
    let shared = shared.clone();
    std::thread::spawn(move || {
        let mut st = WsStream::new(&None, 1, None);
        let out = ws_relay_chunk_alive(&shared, "h", &wire, &mut st, to_server, &|| {
            alive.load(Ordering::SeqCst)
        });
        let _ = tx.send(out);
    });
    rx
}

fn always() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(true))
}

fn wait_queue(shared: &Shared, n: usize) {
    let end = Instant::now() + DEADLINE;
    while shared.queue.lock().unwrap().len() != n {
        assert!(
            Instant::now() < end,
            "queue never reached {n} items (has {})",
            shared.queue.lock().unwrap().len()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn out_of(rx: &Receiver<WsOut>) -> WsOut {
    rx.recv_timeout(DEADLINE)
        .expect("the relay did not return after the release")
}

#[test]
fn turning_interception_off_forwards_a_held_ws_message_unchanged() {
    // Invalid UTF-8 in a binary message: the queue shows lossy text, and the
    // release must not turn that into an edit.
    let bin = vec![0xff, 0xfe, 0x00, 0xc3, 0x28, 0x80, b'a'];
    for to_server in [true, false] {
        let shared = held_shared();
        let wire = build_ws_frame(0x82, &bin, to_server);
        let rx = relay(&shared, wire.clone(), to_server, always());
        wait_queue(&shared, 1);
        assert!(
            matches!(shared.queue.lock().unwrap()[0].kind, InterceptKind::WebSocket { to_server: t } if t == to_server)
        );
        // Still held: nothing comes back while interception is on.
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(300)),
            Err(RecvTimeoutError::Timeout)
        ));
        let n = net::set_intercept(&shared, false);
        assert_eq!(n, 1, "one message released");
        let out = out_of(&rx);
        assert_eq!(
            out.forward, wire,
            "forwarded byte for byte (to_server {to_server})"
        );
        assert!(
            shared.queue.lock().unwrap().is_empty(),
            "queue empty after the release"
        );
        assert!(!shared.intercept_on.load(Ordering::SeqCst));
        assert!(
            shared.ws_edited.lock().unwrap().is_empty(),
            "not marked as edited"
        );
        assert_eq!(
            shared.ws_history.len(),
            1,
            "the forwarded message is in the history"
        );
    }
}

#[test]
fn turning_interception_off_forwards_the_current_edited_text() {
    let shared = held_shared();
    let rx = relay(
        &shared,
        build_ws_frame(0x81, b"original", true),
        true,
        always(),
    );
    wait_queue(&shared, 1);
    shared.queue.lock().unwrap()[0].edited = "changed in the editor".into();
    assert_eq!(net::set_intercept(&shared, false), 1);
    let out = out_of(&rx);
    let (op, masked, payload, used) = parse_ws_frame(&out.forward).unwrap();
    assert_eq!(
        (op, masked, payload.as_slice(), used),
        (
            1,
            true,
            b"changed in the editor".as_slice(),
            out.forward.len()
        )
    );
    assert!(shared.queue.lock().unwrap().is_empty());
}

#[test]
fn turning_interception_on_releases_nothing() {
    let shared = held_shared();
    let rx = relay(&shared, build_ws_frame(0x81, b"x", false), false, always());
    wait_queue(&shared, 1);
    assert_eq!(net::set_intercept(&shared, true), 0);
    assert!(shared.intercept_on.load(Ordering::SeqCst));
    assert_eq!(shared.queue.lock().unwrap().len(), 1, "still held");
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(300)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert_eq!(net::intercept_release_all(&shared, false), 1);
    assert_eq!(
        out_of(&rx).forward,
        build_ws_frame(0x81, b"x", false).as_slice()
    );
}

#[test]
fn turning_interception_off_with_nothing_held_is_harmless() {
    let shared = held_shared();
    assert_eq!(net::set_intercept(&shared, false), 0);
    assert_eq!(net::set_intercept(&shared, false), 0);
    assert!(shared.queue.lock().unwrap().is_empty());
}

#[test]
fn several_held_messages_are_all_released_by_one_toggle() {
    let shared = held_shared();
    let mut rxs = Vec::new();
    let mut wires = Vec::new();
    for i in 0..4u8 {
        let to_server = i % 2 == 0;
        let wire = build_ws_frame(0x81, format!("message {i}").as_bytes(), to_server);
        rxs.push(relay(&shared, wire.clone(), to_server, always()));
        wires.push(wire);
    }
    wait_queue(&shared, 4);
    assert_eq!(net::set_intercept(&shared, false), 4);
    for (rx, wire) in rxs.iter().zip(&wires) {
        assert_eq!(&out_of(rx).forward, wire);
    }
    assert!(shared.queue.lock().unwrap().is_empty());
}

#[test]
fn a_held_message_is_dropped_and_dequeued_when_the_connection_is_gone() {
    let shared = held_shared();
    let alive = always();
    let rx = relay(
        &shared,
        build_ws_frame(0x81, b"never delivered", true),
        true,
        alive.clone(),
    );
    wait_queue(&shared, 1);
    // Alive: it keeps waiting through several liveness checks.
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(500)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert_eq!(shared.queue.lock().unwrap().len(), 1);
    alive.store(false, Ordering::SeqCst);
    let out = out_of(&rx);
    assert!(
        out.forward.is_empty(),
        "dropped, not forwarded to a dead peer"
    );
    assert!(!out.closed, "a gone peer is not a protocol error");
    assert!(
        shared.queue.lock().unwrap().is_empty(),
        "the item left the queue"
    );
    assert_eq!(
        shared.ws_history.len(),
        0,
        "a dropped message is not recorded as forwarded"
    );
}

#[test]
fn only_the_item_of_the_dead_connection_leaves_the_queue() {
    let shared = held_shared();
    let dead = Arc::new(AtomicBool::new(true));
    let live = always();
    let rx_dead = relay(
        &shared,
        build_ws_frame(0x81, b"dead", true),
        true,
        dead.clone(),
    );
    wait_queue(&shared, 1);
    let rx_live = relay(&shared, build_ws_frame(0x81, b"live", true), true, live);
    wait_queue(&shared, 2);
    dead.store(false, Ordering::SeqCst);
    assert!(out_of(&rx_dead).forward.is_empty());
    assert_eq!(shared.queue.lock().unwrap().len(), 1);
    assert_eq!(shared.queue.lock().unwrap()[0].edited, "live");
    assert_eq!(net::set_intercept(&shared, false), 1);
    // (The mask key is random per frame: compare the unmasked payload.)
    assert_eq!(
        parse_ws_frame(&out_of(&rx_live).forward).map(|f| f.2),
        Some(b"live".to_vec())
    );
}

#[test]
fn release_all_releases_held_http_and_websocket_items() {
    for drop in [false, true] {
        let shared = held_shared();
        let (tx, http_rx) = mpsc::channel();
        shared.queue.lock().unwrap().push(InterceptItem::new(
            900,
            "h",
            80,
            "GET / HTTP/1.1\r\n\r\n".into(),
            tx,
            InterceptKind::Request { https: false },
        ));
        let (tx, resp_rx) = mpsc::channel();
        shared.queue.lock().unwrap().push(InterceptItem::new(
            901,
            "h",
            80,
            "HTTP/1.1 200 OK\r\n\r\n".into(),
            tx,
            InterceptKind::Response { https: false },
        ));
        let wire = build_ws_frame(0x81, b"ws", false);
        let ws_rx = relay(&shared, wire.clone(), false, always());
        wait_queue(&shared, 3);
        assert_eq!(net::intercept_release_all(&shared, drop), 3);
        assert!(shared.queue.lock().unwrap().is_empty());
        let http = http_rx.recv_timeout(DEADLINE).unwrap();
        let resp = resp_rx.recv_timeout(DEADLINE).unwrap();
        let ws = out_of(&ws_rx);
        if drop {
            assert_eq!((http, resp), (None, None));
            assert!(ws.forward.is_empty());
        } else {
            assert_eq!(http.as_deref(), Some("GET / HTTP/1.1\r\n\r\n"));
            assert_eq!(resp.as_deref(), Some("HTTP/1.1 200 OK\r\n\r\n"));
            assert_eq!(ws.forward, wire);
        }
    }
}

#[test]
fn held_http_and_websocket_items_get_distinct_ids_and_release_the_right_one() {
    let shared = held_shared();
    let (tx, http_rx) = mpsc::channel();
    let http_id = shared.next_queue_item_id();
    shared.queue.lock().unwrap().push(InterceptItem::new(
        http_id,
        "h",
        80,
        "GET / HTTP/1.1\r\n\r\n".into(),
        tx,
        InterceptKind::Request { https: false },
    ));
    let wire = build_ws_frame(0x81, b"ws", false);
    let ws_rx = relay(&shared, wire, false, always());
    wait_queue(&shared, 2);
    let ids: Vec<u64> = shared.queue.lock().unwrap().iter().map(|i| i.id).collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1], "one queue, one id sequence: {ids:?}");
    let ws_id = *ids.iter().find(|&&i| i != http_id).unwrap();
    // Dropping the WebSocket frame must leave the HTTP request held.
    assert!(net::intercept_release(&shared, ws_id, true, None));
    assert!(out_of(&ws_rx).forward.is_empty());
    assert!(http_rx.try_recv().is_err(), "HTTP item still held");
    assert_eq!(shared.queue.lock().unwrap().len(), 1);
    // Forwarding the HTTP request releases only that one.
    assert!(net::intercept_release(&shared, http_id, false, None));
    assert_eq!(
        http_rx.recv_timeout(DEADLINE).unwrap().as_deref(),
        Some("GET / HTTP/1.1\r\n\r\n")
    );
}

#[test]
fn turning_interception_off_forwards_a_held_http_request_through_the_proxy() {
    // A held request goes on to the origin when the toggle goes off.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let (seen_tx, seen_rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = origin.accept() {
            s.set_read_timeout(Some(Duration::from_secs(10))).ok();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = seen_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
            );
        }
    });
    let shared = held_shared();
    let proxy_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    shared.proxy_port.store(proxy_port, Ordering::SeqCst);
    net::start_proxy(shared.clone());
    let end = Instant::now() + DEADLINE;
    while !shared.listener_running.load(Ordering::SeqCst) {
        assert!(Instant::now() < end, "proxy did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    let (done_tx, done_rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        c.write_all(format!("GET http://127.0.0.1:{origin_port}/ping HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        let _ = done_tx.send(String::from_utf8_lossy(&out).into_owned());
    });
    wait_queue(&shared, 1);
    assert!(matches!(
        shared.queue.lock().unwrap()[0].kind,
        InterceptKind::Request { .. }
    ));
    assert!(
        matches!(
            seen_rx.recv_timeout(Duration::from_millis(300)),
            Err(RecvTimeoutError::Timeout)
        ),
        "the origin sees nothing while the request is held"
    );
    assert_eq!(net::set_intercept(&shared, false), 1);
    let reply = done_rx
        .recv_timeout(DEADLINE)
        .expect("the client got no response after the release");
    assert!(
        reply.starts_with("HTTP/1.1 200") && reply.ends_with("pong"),
        "{reply:?}"
    );
    let seen = seen_rx
        .recv_timeout(DEADLINE)
        .expect("the origin never saw the request");
    assert!(seen.starts_with("GET /ping HTTP/1.1"), "{seen:?}");
    assert!(shared.queue.lock().unwrap().is_empty());
}

// ------------------------------------------------------------------ intercept_wait

fn push_item(shared: &Shared, id: u64) -> Receiver<Option<String>> {
    let (tx, rx) = mpsc::channel();
    shared.queue.lock().unwrap().push(InterceptItem::new(
        id,
        "h",
        0,
        "x".into(),
        tx,
        InterceptKind::WebSocket { to_server: true },
    ));
    rx
}

#[test]
fn intercept_wait_returns_the_verdict() {
    let shared = Shared::new();
    let rx = push_item(&shared, 1);
    let item = shared.queue.lock().unwrap().remove(0);
    item.tx.send(Some("edited".into())).unwrap();
    assert_eq!(
        net::intercept_wait(&shared, 1, &rx, &|| true),
        Some("edited".to_string())
    );
    item.tx.send(None).unwrap();
    assert_eq!(
        net::intercept_wait(&shared, 1, &rx, &|| true),
        None,
        "a drop verdict"
    );
}

#[test]
fn intercept_wait_gives_up_when_the_sender_is_gone() {
    let shared = Shared::new();
    let rx = push_item(&shared, 1);
    shared.queue.lock().unwrap().clear(); // drops the item and its sender
    assert_eq!(net::intercept_wait(&shared, 1, &rx, &|| true), None);
}

#[test]
fn intercept_wait_removes_its_item_when_the_connection_is_gone() {
    let shared = Shared::new();
    let rx = push_item(&shared, 1);
    let _other = push_item(&shared, 2);
    assert_eq!(net::intercept_wait(&shared, 1, &rx, &|| false), None);
    let ids: Vec<u64> = shared.queue.lock().unwrap().iter().map(|i| i.id).collect();
    assert_eq!(ids, [2], "only the waiting item is removed");
}

#[test]
fn intercept_wait_wakes_the_ui_when_it_removes_an_item() {
    let shared = Shared::new();
    let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let w = woken.clone();
    *shared.waker.lock().unwrap() = Some(Arc::new(move || {
        w.fetch_add(1, Ordering::SeqCst);
    }));
    let rx = push_item(&shared, 1);
    assert_eq!(net::intercept_wait(&shared, 1, &rx, &|| false), None);
    assert!(
        woken.load(Ordering::SeqCst) >= 1,
        "the table needs a repaint"
    );
}

#[test]
fn intercept_wait_keeps_waiting_while_the_connection_lives_and_a_release_arrives_later() {
    let shared = Shared::new();
    let rx = push_item(&shared, 1);
    let s2 = shared.clone();
    let releaser = std::thread::spawn(move || {
        // Let at least one 200 ms liveness check pass first.
        std::thread::sleep(Duration::from_millis(450));
        net::intercept_release(&s2, 1, false, Some("late edit".into()))
    });
    assert_eq!(
        net::intercept_wait(&shared, 1, &rx, &|| true),
        Some("late edit".to_string())
    );
    assert!(releaser.join().unwrap());
}
