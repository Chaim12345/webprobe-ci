//! R-06 through the real proxy: an in-process loopback server streams
//! events, a raw client reads them through the listener. Ordering, not wall
//! time, proves that bytes pass as they arrive: the server sends the second
//! event only after the client has read the first one.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use crate::net::Shared;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn proxy() -> Arc<Shared> {
    let shared = Shared::new();
    shared.proxy_port.store(free_port(), Ordering::SeqCst);
    crate::net::start_proxy(shared.clone());
    for _ in 0..500 {
        if shared.listener_running.load(Ordering::SeqCst) {
            return shared;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("proxy did not start");
}

/// How the test server frames its stream.
#[derive(Clone, Copy)]
enum Framing {
    Chunked,
    Length,
    Close,
}

/// A one-connection server: sends `head`, then each event when `go` says
/// so, then ends the body. Reports when it is done (or the write failed).
fn server(
    content_type: &'static str,
    framing: Framing,
    events: Vec<Vec<u8>>,
) -> (u16, mpsc::Sender<()>, mpsc::Receiver<bool>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (go, wait) = mpsc::channel::<()>();
    let (done_tx, done) = mpsc::channel::<bool>();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        let total: usize = events.iter().map(Vec::len).sum();
        let framing_header = match framing {
            Framing::Chunked => "Transfer-Encoding: chunked\r\n".to_string(),
            Framing::Length => format!("Content-Length: {total}\r\n"),
            Framing::Close => "Connection: close\r\n".to_string(),
        };
        let head =
            format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n{framing_header}\r\n");
        let mut ok = s.write_all(head.as_bytes()).is_ok();
        for (k, e) in events.iter().enumerate() {
            if k > 0 && wait.recv().is_err() {
                break;
            }
            let bytes = match framing {
                Framing::Chunked => [
                    format!("{:x}\r\n", e.len()).into_bytes(),
                    e.clone(),
                    b"\r\n".to_vec(),
                ]
                .concat(),
                _ => e.clone(),
            };
            ok = ok && s.write_all(&bytes).and_then(|()| s.flush()).is_ok();
        }
        if let Framing::Chunked = framing {
            ok = ok && s.write_all(b"0\r\n\r\n").is_ok();
        }
        let _ = done_tx.send(ok);
    });
    (port, go, done)
}

fn client(shared: &Shared, port: u16, path: &str) -> BufReader<TcpStream> {
    let mut c =
        TcpStream::connect(("127.0.0.1", shared.proxy_port.load(Ordering::SeqCst))).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        c,
        "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )
    .unwrap();
    BufReader::new(c)
}

/// Read lines until one contains `want`; panics after 30 s of silence.
fn read_until(r: &mut BufReader<TcpStream>, want: &str) -> String {
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap() == 0 {
            panic!("closed before {want:?}; got {seen:?}");
        }
        seen.push_str(&line);
        if line.contains(want) {
            return seen;
        }
    }
}

fn history_entry(shared: &Shared, path: &str) -> crate::net::HistEntry {
    for _ in 0..1000 {
        if let Some(e) = shared
            .history
            .with_rows(|rows| rows.iter().find(|e| e.path == path).cloned())
        {
            return e;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{path} never reached history");
}

fn sse(n: usize) -> Vec<Vec<u8>> {
    (1..=n)
        .map(|k| format!("data: event {k}\n\n").into_bytes())
        .collect()
}

#[test]
fn event_stream_reaches_the_client_as_it_arrives_and_history_keeps_it_all() {
    let shared = proxy();
    let (port, go, done) = server("text/event-stream", Framing::Chunked, sse(2));
    let mut c = client(&shared, port, "/sse");
    let t0 = std::time::Instant::now();
    // The second event is not sent yet: the first got here on its own.
    read_until(&mut c, "data: event 1");
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "first event after {:?}",
        t0.elapsed()
    );
    go.send(()).unwrap();
    let rest = read_until(&mut c, "data: event 2");
    assert!(rest.contains("data: event 2"));
    assert!(done.recv_timeout(Duration::from_secs(30)).unwrap());
    let e = history_entry(&shared, "/sse");
    let body = String::from_utf8_lossy(&e.resp_raw.unwrap()).into_owned();
    assert!(
        body.starts_with("HTTP/1.1 200 OK\r\n")
            && body.contains("data: event 1\n\ndata: event 2\n\n"),
        "{body}"
    );
    assert!(
        !body.to_ascii_lowercase().contains("transfer-encoding"),
        "chunk metadata stripped from the stored copy: {body}"
    );
    assert_eq!(e.note.as_deref(), Some("Streaming response"));
}

#[test]
fn url_prefix_streams_length_and_close_delimited_bodies() {
    for (framing, path) in [
        (Framing::Length, "/feed/len"),
        (Framing::Close, "/feed/close"),
    ] {
        let shared = proxy();
        let (port, go, done) = server(
            "application/json",
            framing,
            vec![b"{\"a\":1}\n".to_vec(), b"{\"b\":2}\n".to_vec()],
        );
        shared.streaming.lock().unwrap().urls = vec![format!("http://127.0.0.1:{port}/feed/")];
        let mut c = client(&shared, port, path);
        read_until(&mut c, "{\"a\":1}");
        go.send(()).unwrap();
        read_until(&mut c, "{\"b\":2}");
        assert!(done.recv_timeout(Duration::from_secs(30)).unwrap());
        drop(c);
        let e = history_entry(&shared, path);
        assert!(String::from_utf8_lossy(&e.resp_raw.unwrap()).ends_with("{\"a\":1}\n{\"b\":2}\n"));
    }
}

#[test]
fn streaming_passes_intercept_and_match_replace_and_says_so_once() {
    let shared = proxy();
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared.response_rules.lock().unwrap().enabled = true;
    shared.response_rules.lock().unwrap().content_type_on = false;
    let mut rule = crate::rules::MrRule::new(crate::rules::MrScope::ResponseBody);
    (rule.match_, rule.replacement) = ("event".into(), "CHANGED".into());
    shared.mr_response.lock().unwrap().push(rule);
    // Requests are still intercepted: forward the one that arrives.
    let forwarder = {
        let shared = shared.clone();
        std::thread::spawn(move || {
            for _ in 0..3000 {
                if let Some(item) = shared.queue.lock().unwrap().pop() {
                    let _ = item.tx.send(Some(item.edited.clone()));
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        })
    };
    let (port, go, done) = server("text/event-stream", Framing::Chunked, sse(2));
    let mut c = client(&shared, port, "/held");
    let first = read_until(&mut c, "data: event 1");
    assert!(
        forwarder.join().unwrap(),
        "the request was intercepted as usual"
    );
    assert!(!first.contains("CHANGED"), "streamed unmodified");
    go.send(()).unwrap();
    read_until(&mut c, "data: event 2");
    assert!(done.recv_timeout(Duration::from_secs(30)).unwrap());
    assert!(
        shared.queue.lock().unwrap().is_empty(),
        "the response was not held"
    );
    history_entry(&shared, "/held");
    let events = shared.events.lock().unwrap().clone();
    for reason in ["response interception", "response match and replace rules"] {
        let n = events
            .iter()
            .filter(|l| l.contains("pass straight through") && l.contains(reason))
            .count();
        assert_eq!(n, 1, "{reason}: {events:#?}");
    }
}

#[test]
fn other_content_with_intercept_on_stays_buffered_and_editable() {
    let shared = proxy();
    let (port, _go, done) = server(
        "text/html",
        Framing::Length,
        vec![b"<p>original</p>".to_vec()],
    );
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared.response_rules.lock().unwrap().enabled = true;
    let editor = {
        let shared = shared.clone();
        std::thread::spawn(move || {
            let mut handled = 0;
            for _ in 0..3000 {
                if let Some(item) = shared.queue.lock().unwrap().pop() {
                    let text = item.edited.replace("original", "edited!!");
                    let _ = item.tx.send(Some(text));
                    handled += 1;
                    if handled == 2 {
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let mut c = client(&shared, port, "/page");
    let mut all = String::new();
    // The proxy keeps the connection open for the next request; half-close ends it.
    c.get_ref().shutdown(std::net::Shutdown::Write).unwrap();
    c.read_to_string(&mut all).unwrap();
    editor.join().unwrap();
    assert!(done.recv_timeout(Duration::from_secs(30)).unwrap());
    assert!(all.contains("<p>edited!!</p>"), "{all}");
}

#[test]
fn client_disconnect_closes_the_upstream_stream() {
    let shared = proxy();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, closed) = mpsc::channel::<usize>();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
        // Keep sending until the proxy's side goes away.
        for k in 0..100_000usize {
            let ev = format!("data: {k}\n\n");
            if s.write_all(format!("{:x}\r\n{ev}\r\n", ev.len()).as_bytes())
                .and_then(|()| s.flush())
                .is_err()
            {
                let _ = tx.send(k);
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut c = client(&shared, port, "/endless");
    read_until(&mut c, "data: 0");
    drop(c);
    let sent = closed
        .recv_timeout(Duration::from_secs(60))
        .expect("the proxy closed the upstream connection");
    assert!(sent < 100_000);
    // The cut stream is still recorded.
    let e = history_entry(&shared, "/endless");
    assert!(e.note.unwrap_or_default().contains("client closed it"));
}

#[test]
fn not_stored_keeps_the_head_and_skips_the_body() {
    let shared = proxy();
    shared.streaming.lock().unwrap().store = false;
    let (port, go, done) = server("text/event-stream", Framing::Chunked, sse(2));
    let mut c = client(&shared, port, "/nostore");
    read_until(&mut c, "data: event 1");
    go.send(()).unwrap();
    read_until(&mut c, "data: event 2");
    assert!(done.recv_timeout(Duration::from_secs(30)).unwrap());
    let e = history_entry(&shared, "/nostore");
    let raw = e.resp_raw.unwrap();
    assert!(
        raw.ends_with(b"\r\n\r\n") && !String::from_utf8_lossy(&raw).contains("data:"),
        "{}",
        String::from_utf8_lossy(&raw)
    );
    assert!(
        !String::from_utf8_lossy(&raw)
            .to_ascii_lowercase()
            .contains("transfer-encoding"),
        "a head without its body has no framing"
    );
    assert_eq!(e.note.as_deref(), Some("Streaming response (not stored)"));
}

#[test]
fn a_large_stream_is_recorded_whole_through_the_bounded_tee() {
    let shared = proxy();
    let chunk = vec![b'x'; 64 * 1024];
    let events: Vec<Vec<u8>> = (0..128).map(|_| chunk.clone()).collect();
    let (port, go, done) = server("text/event-stream", Framing::Chunked, events);
    std::thread::spawn(move || while go.send(()).is_ok() {});
    let mut c = client(&shared, port, "/big");
    let mut sink = Vec::new();
    let _ = c.read_to_end(&mut sink);
    assert!(done.recv_timeout(Duration::from_secs(60)).unwrap());
    let e = history_entry(&shared, "/big");
    let raw = e.resp_raw.unwrap();
    assert!(raw.is_stored(), "8 MB recorded file-backed, not in RAM");
    let body = &raw[crate::util::find_head_end(&raw).unwrap()..];
    assert_eq!(body.len(), 128 * 64 * 1024);
}

#[test]
fn other_tools_cut_a_streaming_response_after_its_head() {
    let shared = proxy();
    let (port, _go, _done) = server("text/event-stream", Framing::Chunked, sse(2));
    let _tool = crate::net::tool_scope("Scanner");
    // Event 2 is never released: returning at all proves the head was enough.
    let up = crate::net::send_raw(
        &shared,
        "127.0.0.1",
        port,
        format!("GET /tool HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
    );
    let resp = up.resp.unwrap();
    assert!(
        resp.starts_with(b"HTTP/1.1 200 OK") && resp.ends_with(b"\r\n\r\n"),
        "{}",
        String::from_utf8_lossy(&resp)
    );
    assert!(shared
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains("Scanner ignored the streaming response")));
}

#[test]
fn repeater_shows_a_stream_as_it_arrives() {
    let shared = proxy();
    let (port, go, done) = server("text/event-stream", Framing::Chunked, sse(2));
    let _tool = crate::net::tool_scope("Repeater");
    let (seen_tx, seen) = mpsc::channel::<Vec<u8>>();
    let shown = std::sync::Mutex::new(Vec::<u8>::new());
    let settings = shared.streaming.lock().unwrap().clone();
    let releaser = std::thread::spawn(move || {
        // Release event 2 only after the live view showed event 1.
        loop {
            let so_far = seen.recv_timeout(Duration::from_secs(30)).unwrap();
            if String::from_utf8_lossy(&so_far).contains("event 1") {
                go.send(()).unwrap();
                return;
            }
        }
    });
    let progress = |b: &[u8], restart: bool| {
        let mut all = shown.lock().unwrap();
        if restart {
            all.clear();
        }
        all.extend_from_slice(b);
        let _ = seen_tx.send(all.clone());
    };
    let mut sink = crate::streaming::LiveSink::new(
        &format!("http://127.0.0.1:{port}/rep"),
        settings,
        &|| false,
        &progress,
    );
    let req = format!("GET /rep HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    crate::net::send_raw_with(&shared, "127.0.0.1", port, req.as_bytes(), Some(&mut sink));
    releaser.join().unwrap();
    assert!(sink.complete());
    let whole = sink.into_response().unwrap();
    assert!(String::from_utf8_lossy(&whole).ends_with("data: event 1\n\ndata: event 2\n\n"));
    assert_eq!(
        *shown.lock().unwrap(),
        whole,
        "the live view saw every byte once"
    );
    assert!(done.recv_timeout(Duration::from_secs(30)).unwrap());
}
