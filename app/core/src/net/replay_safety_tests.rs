//! Live origins count connections, received requests and committed effects.
//! Failed sends are not evidence that the origin did not process the request.
use super::*;
use rustls::{RootCertStore, ServerConnection, StreamOwned};
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Copy, PartialEq)]
enum Reply {
    Complete,
    Close,
    Hold,
    PartialWrite,
}

#[derive(Default)]
struct Counts {
    accepted: AtomicUsize,
    requests: AtomicUsize,
    effects: AtomicUsize,
    partial: AtomicUsize,
    stop: AtomicBool,
}

fn response(stream: &mut impl Write) {
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .unwrap();
    stream.flush().unwrap();
}

fn serve(mut stream: impl Read + Write, counts: Arc<Counts>, reply: Reply, connection: usize) {
    loop {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).is_err() {
                return;
            }
            head.push(byte[0]);
            assert!(head.len() < 65536);
        }
        counts.requests.fetch_add(1, Ordering::SeqCst);
        let parts = util::parse_http(&head);
        let length = util::get_header(&parts.headers, "Content-Length")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        if parts.method == "POST" && reply == Reply::PartialWrite {
            // Close after a real prefix of the body, while write_all is still
            // trying to send a body larger than the TCP send buffer.
            stream.read_exact(&mut byte).unwrap();
            counts.partial.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        if parts.method != "POST" {
            response(&mut stream);
            continue;
        }
        assert_eq!(body, b"x=1", "origin must receive the exact effectful body");
        counts.effects.fetch_add(1, Ordering::SeqCst);
        // A replacement send gets an ordinary reply, making an erroneous
        // automatic replay observable as two origin effects, not a timeout.
        if connection > 1 || reply == Reply::Complete {
            response(&mut stream);
            if connection > 1 {
                return;
            }
            continue;
        }
        if reply == Reply::Hold {
            while !counts.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // TLS deliberately closes without close_notify. For cleartext this
        // is EOF; the existing codec returns an incomplete, non-reusable reply.
        return;
    }
}

struct Origin {
    shared: Arc<Shared>,
    port: u16,
    counts: Arc<Counts>,
    thread: Option<std::thread::JoinHandle<()>>,
    tls: bool,
}
impl Origin {
    fn new(tls: bool, reply: Reply) -> Self {
        let mut shared = Shared::new();
        shared.keep_alive.store(true, Ordering::SeqCst);
        shared.h2c_upgrade.store(false, Ordering::SeqCst);
        let server_config = shared.mitm.server_config("localhost").unwrap();
        if tls {
            let mut roots = RootCertStore::empty();
            roots.add(shared.mitm.ca_der()).unwrap();
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::get_mut(&mut shared).unwrap().tls_upstream = Arc::new(config);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let counts = Arc::new(Counts::default());
        let origin_counts = counts.clone();
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut handlers = Vec::new();
            let mut stopped = None;
            loop {
                if origin_counts.stop.load(Ordering::SeqCst) {
                    let since = stopped.get_or_insert_with(Instant::now);
                    // Observe replacement connections even if queued just as
                    // the call returns; no fixed sleep controls the failure.
                    if since.elapsed() > Duration::from_millis(100) {
                        break;
                    }
                }
                assert!(Instant::now() < deadline, "origin fixture timed out");
                match listener.accept() {
                    Ok((tcp, _)) => {
                        tcp.set_read_timeout(Some(Duration::from_millis(800)))
                            .unwrap();
                        tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                        let c = origin_counts.clone();
                        let n = c.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        let config = server_config.clone();
                        handlers.push(std::thread::spawn(move || {
                            if tls {
                                let conn = ServerConnection::new(config).unwrap();
                                serve(StreamOwned::new(conn, tcp), c, reply, n);
                            } else {
                                serve(tcp, c, reply, n);
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
        Self {
            shared,
            port,
            counts,
            thread: Some(thread),
            tls,
        }
    }
    fn send(&self, req: &[u8]) -> Result<Vec<u8>, String> {
        if self.tls {
            send_tls_inner(&self.shared, "localhost", self.port, req, None)
        } else {
            send_inner(&self.shared, "localhost", self.port, req, None)
        }
    }
    fn warm(&self) {
        assert!(self
            .send(b"GET /warm HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap()
            .ends_with(b"ok"));
        let key = ("localhost".to_string(), self.port);
        let pool = if self.tls {
            &self.shared.tls_pool
        } else {
            &self.shared.pool
        };
        let mut pool = pool.lock().unwrap();
        let conn = pool.get_mut(&key).expect("warm response must be pooled");
        conn.set_read_timeout_ms(100).unwrap();
    }
    fn finish(&mut self) {
        self.counts.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
    fn assert_counts(&self, connections: usize, requests: usize, effects: usize) {
        assert_eq!(
            (
                self.counts.accepted.load(Ordering::SeqCst),
                self.counts.requests.load(Ordering::SeqCst),
                self.counts.effects.load(Ordering::SeqCst)
            ),
            (connections, requests, effects),
            "origin (accepted connections, received request heads, committed POST effects)"
        );
        assert_eq!(
            self.shared.conns_opened.load(Ordering::SeqCst),
            connections,
            "client opened connections"
        );
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.counts.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

const POST: &[u8] = b"POST /effect HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nx=1";

#[test]
fn pooled_post_effect_then_close_is_never_replayed() {
    for tls in [false, true] {
        let mut origin = Origin::new(tls, Reply::Close);
        origin.warm();
        let outcome = origin.send(POST);
        origin.finish();
        origin.assert_counts(1, 2, 1);
        assert!(
            outcome.as_ref().map_or(true, |r| r.is_empty()),
            "unexpected reply: {outcome:?}"
        );
    }
}

#[test]
fn pooled_post_unknown_read_outcome_is_never_replayed() {
    for tls in [false, true] {
        let mut origin = Origin::new(tls, Reply::Hold);
        origin.warm();
        let outcome = origin.send(POST);
        origin.finish();
        origin.assert_counts(1, 2, 1);
        assert!(
            outcome.is_err(),
            "a missing response must surface the failure"
        );
    }
}

#[test]
fn pooled_partial_write_is_never_replayed() {
    for tls in [false, true] {
        let mut origin = Origin::new(tls, Reply::PartialWrite);
        origin.warm();
        let size = 8 * 1024 * 1024;
        let mut request =
            format!("POST /partial HTTP/1.1\r\nHost: localhost\r\nContent-Length: {size}\r\n\r\n")
                .into_bytes();
        request.resize(request.len() + size, b'x');
        let outcome = origin.send(&request);
        origin.finish();
        origin.assert_counts(1, 2, 0);
        assert_eq!(origin.counts.partial.load(Ordering::SeqCst), 1);
        assert!(
            outcome.as_ref().is_err_and(|e| e.starts_with("write:")),
            "must fail during the request write: {outcome:?}"
        );
    }
}

#[test]
fn fresh_and_ordinary_reused_posts_still_complete() {
    for tls in [false, true] {
        let mut origin = Origin::new(tls, Reply::Complete);
        assert!(origin.send(POST).unwrap().ends_with(b"ok"));
        assert!(origin.send(POST).unwrap().ends_with(b"ok"));
        origin.finish();
        origin.assert_counts(1, 2, 2);
        assert_eq!(origin.shared.pool_hits.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn h2c_post_effect_then_lost_response_is_never_replayed_plainly() {
    let mut origin = Origin::new(false, Reply::Close);
    origin.shared.h2c_upgrade.store(true, Ordering::SeqCst);
    let outcome = origin.send(POST);
    origin.finish();
    origin.assert_counts(1, 1, 1);
    assert!(outcome.is_err());
}

#[test]
fn intruder_worker_does_not_replay_a_committed_post_after_response_loss() {
    use crate::intruder::{resolve_specs, AttackType, PayloadSource, Template};
    use crate::intruder_run::{self, AttackSettings, RetryConfig};
    for tls in [false, true] {
        let mut origin = Origin::new(tls, Reply::Hold);
        origin.warm();
        let template =
            "POST /effect HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nx=§value§";
        let parsed = Template::parse(template).unwrap();
        let specs = resolve_specs(
            &parsed,
            AttackType::Sniper,
            &[PayloadSource::SimpleList {
                items: vec!["1".into()],
            }],
        )
        .unwrap();
        let mut settings = AttackSettings::default();
        settings.pool.max_concurrent = 1;
        // Old saved/user-selected settings cannot prove a failed send had no
        // origin effect. Exercise the real worker with retries still requested.
        settings.retry = RetryConfig {
            retries: 3,
            pause_ms: 0,
        };
        let run = intruder_run::start(
            origin.shared.clone(),
            template,
            AttackType::Sniper,
            specs,
            ("localhost".into(), origin.port, tls),
            settings,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while run.is_running() {
            assert!(Instant::now() < deadline, "Intruder did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
        origin.finish();
        origin.assert_counts(1, 2, 1);
        let rows = run.snapshot_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].attempts, 1);
        assert!(
            rows[0].error,
            "lost response must remain visible in the result"
        );
    }
}

#[test]
fn failed_session_validation_does_not_resend_the_pending_effectful_request() {
    for (tls, reply) in [
        (false, Reply::Hold),
        (true, Reply::Hold),
        (false, Reply::Close),
        (true, Reply::Close),
    ] {
        let mut origin = Origin::new(tls, reply);
        origin.warm();
        origin
            .shared
            .session_rules
            .lock()
            .unwrap()
            .push(SessionRule {
                name: "validate before send".into(),
                action: "check session".into(),
                tools: vec!["Repeater".into()],
                ..SessionRule::new()
            });
        let _tool = tool_scope("Repeater");
        let request = format!(
            "POST /effect HTTP/1.1\r\nHost: localhost:{}\r\nContent-Length: 3\r\n\r\nx=1",
            origin.port
        );
        let outcome = if tls {
            send_tls_raw(&origin.shared, "localhost", origin.port, request.as_bytes())
        } else {
            send_raw(&origin.shared, "localhost", origin.port, request.as_bytes())
        };
        origin.finish();
        origin.assert_counts(1, 2, 1);
        assert!(outcome.resp.is_none());
        assert!(outcome.error.unwrap().contains("unknown origin outcome"));
    }
}
