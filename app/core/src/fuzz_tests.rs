//! Robustness: every parser in the engine is fed random bytes and mutated
//! valid messages, and must return (an error is fine) without panicking or
//! hanging. Deterministic: the generator is seeded, so a failure reproduces.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Values that break naive length arithmetic.
const NASTY: &[&str] = &[
    "0",
    "-1",
    "18446744073709551615",
    "ffffffffffffffff",
    "FFFFFFFFFFFFFFFFFFFF",
    "99999999999999999999",
    "",
    " ",
    "\0",
    "1e9",
    "0x10",
    "%",
    "%%",
    "%zz",
    "\u{ffff}",
    ";",
    "=",
    "\r\n",
    "\n\n",
];

/// Turn a valid message into a broken one: truncate, flip bytes, splice in
/// nasty values, duplicate parts.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !v.is_empty() => v.truncate(rng.below(v.len())),
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(v.len() + 1);
                let nasty = NASTY[rng.below(NASTY.len())].as_bytes();
                v.splice(i..i, nasty.iter().copied());
            }
            3 if !v.is_empty() => {
                let a = rng.below(v.len());
                let b = (a + rng.below(64)).min(v.len());
                let part = v[a..b].to_vec();
                v.extend_from_slice(&part);
            }
            4 => v.extend(rng.bytes(32)),
            _ => {
                // Replace a number with a nasty value.
                if let Some(i) = v.iter().position(|b| b.is_ascii_digit()) {
                    let j = v[i..]
                        .iter()
                        .position(|b| !b.is_ascii_hexdigit())
                        .map(|k| i + k)
                        .unwrap_or(v.len());
                    let nasty = NASTY[rng.below(NASTY.len())].as_bytes().to_vec();
                    v.splice(i..j, nasty);
                }
            }
        }
    }
    v
}

fn seeds() -> Vec<Vec<u8>> {
    let mut gz = Vec::new();
    {
        let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(b"hello hello hello").unwrap();
        e.finish().unwrap();
    }
    let mut gz_resp = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ".to_vec();
    gz_resp.extend_from_slice(format!("{}\r\n\r\n", gz.len()).as_bytes());
    gz_resp.extend_from_slice(&gz);
    vec![
        b"GET /a/b.php?x=1&y=%41 HTTP/1.1\r\nHost: app.test:8080\r\nCookie: a=1; b=2\r\nUser-Agent: x\r\n\r\n".to_vec(),
        b"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&pass=b".to_vec(),
        b"POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"a\":[1,{\"b\":\"c\"}],\"d\":2}".to_vec(),
        b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=XX\r\nContent-Length: 90\r\n\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhi\r\n--XX--\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: sid=1; Path=/; Max-Age=60\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n".to_vec(),
        gz_resp,
        b"HTTP/1.1 302 Found\r\nLocation: //evil.test/%2e%2e/\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"<?xml version=\"1.0\"?><a x=\"1\"><b>t</b><![CDATA[<c>]]></a>".to_vec(),
    ]
}

/// A stream whose reads return the given bytes and whose writes go nowhere:
/// a hostile HTTP/2 server.
struct Hostile {
    data: Vec<u8>,
    pos: usize,
}

impl Read for Hostile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for Hostile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// HTTP/2 frames: a SETTINGS frame, then random frames with random lengths.
fn h2_frames(rng: &mut Rng) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 4, 0, 0, 0, 0, 0];
    for _ in 0..rng.below(6) {
        let payload = rng.bytes(40);
        let claimed = if rng.below(3) == 0 {
            rng.below(1 << 24)
        } else {
            payload.len()
        };
        out.extend_from_slice(&[(claimed >> 16) as u8, (claimed >> 8) as u8, claimed as u8]);
        out.push(rng.below(12) as u8); // type
        out.push(rng.next() as u8); // flags
        out.extend_from_slice(&(rng.below(8) as u32).to_be_bytes()); // stream
        out.extend_from_slice(&payload);
    }
    out
}

/// The property: no parser panics on 3000 random or mutated inputs
/// (deterministic seed). How fast they run is `fuzzing_stays_fast`.
#[test]
fn parsers_survive_random_and_mutated_input() {
    assert_eq!(fuzz_rounds(3000), 3000);
}

/// Wall-clock guard against a parser going pathological on hostile
/// input. Ignored in the suite: wall time on a loaded box says nothing
/// (run it alone: `cargo test -- --ignored fuzzing_stays_fast`).
#[test]
#[ignore = "wall-clock bound; meaningless under suite load"]
fn fuzzing_stays_fast() {
    let started = Instant::now();
    let cases = fuzz_rounds(3000);
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "fuzzing is too slow: {cases} cases in {:?}",
        started.elapsed()
    );
}

/// Feed `rounds` inputs through every parser; the number of cases run.
fn fuzz_rounds(rounds: usize) -> usize {
    let mut rng = Rng(0x5eed_1234);
    let seeds = seeds();
    let mut cases = 0usize;
    for round in 0..rounds {
        let input = if round % 3 == 0 {
            rng.bytes(300)
        } else {
            let pick = rng.below(seeds.len());
            mutate(&mut rng, &seeds[pick])
        };
        let text = String::from_utf8_lossy(&input).into_owned();
        // HTTP framing and decoding.
        let parts = crate::util::parse_http(&input);
        let _ = crate::util::get_header(&parts.headers, "Content-Length");
        let _ = crate::util::find_head_end(&input);
        let _ = crate::util::origin_form(&input);
        let _ = crate::util::patch_header(&input, "Content-Length", "5");
        let _ = crate::codec::decode_chunked(&input);
        let _ = crate::codec::decode_chunked(&input[parts.head_len.min(input.len())..]);
        let _ = crate::codec::normalize_response(&input);
        let _ = crate::codec::normalize_request(&input);
        let _ = crate::codec::body_complete(&input, "GET");
        let _ = crate::codec::body_complete(&input, "HEAD");
        let _ = crate::codec::response_body_kind(&input, "GET");
        for enc in ["gzip", "deflate", "br", "gzip, br", "identity"] {
            let _ = crate::codec::decode_content(&input, enc);
        }
        // Encodings.
        let _ = crate::util::url_decode(&text);
        let _ = crate::util::html_decode(&text);
        let _ = crate::util::b64_decode(&text);
        let _ = crate::util::hex_decode(&text);
        let _ = crate::util::hex_view(&input, 4096);
        let _ = crate::mime::burp_mime(&text, &input);
        // WebSocket frames.
        let _ = crate::net::parse_ws_frame(&input);
        // Scanner and tools that take user or server data.
        let _ = crate::scan::insertion_points(&text);
        let _ = crate::scan::passive_check(&crate::net::HistEntry {
            req_raw: seeds[0].clone().into(),
            resp_raw: Some(input.clone().into()),
            host: "h".into(),
            path: "/".into(),
            ..Default::default()
        });
        let _ = crate::intruder::Template::parse(&text);
        let _ = crate::macros::parse(&text);
        let _ = crate::macros::extract_value(&input, "csrf");
        let _ = crate::macros::substitute_param(&input, "csrf", "v");
        let mut jar = crate::cookie_jar::CookieJar::default();
        for line in text.lines().take(8) {
            jar.set_cookie("app.test", "/x/y", line, 1_800_000_000);
        }
        let _ = jar.update_from_response("app.test", "/", &input, 1_800_000_000);
        let _ = jar.apply(&input, "app.test", false, 1_800_000_000);
        let _ = crate::cookie_jar::parse_http_date(&text);
        let _ = crate::intercept_rules::extension_of(&text);
        let _ = serde_json::from_str::<crate::project::ProjectData>(&text);
        // HTTP/2 against a hostile server.
        if round % 5 == 0 {
            if let Some(req) = crate::h2::request_from_raw(&seeds[0], "https") {
                let mut s = Hostile {
                    data: h2_frames(&mut rng),
                    pos: 0,
                };
                let _ = crate::h2::exchange(&mut s, &req, None);
            }
            let _ = crate::h2::request_from_raw(&input, "https");
        }
        cases += 1;
    }
    cases
}

#[test]
fn url_decode_keeps_multibyte_text_after_a_percent() {
    assert_eq!(
        crate::util::url_decode("%e2%82%ac and %\u{e9}x %4"),
        "\u{20ac} and %\u{e9}x %4"
    );
    assert_eq!(crate::util::url_decode("a%2Fb%2fc%zz%"), "a/b/c%zz%");
}

#[test]
fn patch_header_handles_empty_and_headerless_messages() {
    assert_eq!(
        crate::util::patch_header(b"", "Content-Length", "0"),
        b"\r\nContent-Length: 0\r\n\r\n".to_vec()
    );
    assert_eq!(
        crate::util::patch_header(
            b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\nbody",
            "Content-Length",
            "4"
        ),
        b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody".to_vec()
    );
}

/// The live proxy against hostile clients: random bytes, truncated and
/// oversized requests, CONNECT followed by garbage TLS records, and a
/// WebSocket upgrade followed by garbage frames. No handler may hang (every
/// connection slot comes back once the clients close) and the proxy still
/// serves a normal request afterwards.
#[test]
fn proxy_survives_malformed_connections() {
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;
    let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let oport = origin.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in origin.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    let shared = crate::net::Shared::new();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    shared.proxy_port.store(port, Ordering::SeqCst);
    crate::net::start_proxy(shared.clone());
    let t0 = std::time::Instant::now();
    while !shared.listener_running.load(Ordering::SeqCst) {
        assert!(t0.elapsed() < Duration::from_secs(5), "proxy did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut rng = Rng(0x5eed_f00d);
    for round in 0..60 {
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
            continue;
        };
        let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
        let payload: Vec<u8> = match round % 6 {
            0 => rng.bytes(2048),
            1 => b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Long: ".iter().copied().chain(std::iter::repeat_n(b'a', 70_000)).collect(),
            2 => {
                let mut v = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n".to_vec();
                // A TLS record header claiming a huge handshake, then noise.
                v.extend_from_slice(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0xff, 0xfb]);
                v.extend(rng.bytes(512));
                v
            }
            3 => format!("GET http://127.0.0.1:{oport}/ HTTP/1.1\r\nHost: 127.0.0.1:{oport}\r\nContent-Length: 999999\r\n\r\nshort").into_bytes(),
            4 => {
                let mut v = format!("GET http://127.0.0.1:{oport}/ws HTTP/1.1\r\nHost: 127.0.0.1:{oport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n").into_bytes();
                v.extend(rng.bytes(300));
                v
            }
            _ => mutate(&mut rng, &seeds()[round % seeds().len()]),
        };
        let _ = s.write_all(&payload);
        let _ = s.shutdown(std::net::Shutdown::Write);
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
        let mut sink = [0u8; 1024];
        let _ = s.read(&mut sink);
    }
    // Every handler finishes once its client is gone.
    let t0 = std::time::Instant::now();
    while shared.active_connections.load(Ordering::SeqCst) > 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "{} connection(s) still held",
            shared.active_connections.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // And the proxy still works.
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(format!("GET http://127.0.0.1:{oport}/after HTTP/1.1\r\nHost: 127.0.0.1:{oport}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    assert!(
        resp.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&resp)
    );
}

/// R-05: the HTTP/2 server role (the browser side of the listener) never
/// panics on random or mutated client frames, valid header blocks among
/// them; every run ends when the input does.
#[test]
fn h2_server_survives_random_and_mutated_frames() {
    struct Io(std::io::Cursor<Vec<u8>>, Vec<u8>);
    impl std::io::Read for Io {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl std::io::Write for Io {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.1.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut rng = Rng(0x5eed_4202);
    let handler: crate::h2_server::Handler = std::sync::Arc::new(|_req, mut out| {
        let _ = std::io::Write::write_all(
            &mut out,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        );
    });
    let block = hpack::Encoder::new().encode(vec![
        (b":method".as_ref(), b"POST".as_ref()),
        (b":scheme".as_ref(), b"https".as_ref()),
        (b":authority".as_ref(), b"h.test".as_ref()),
        (b":path".as_ref(), b"/x".as_ref()),
        (b"cookie".as_ref(), b"a=1".as_ref()),
    ]);
    for round in 0..2000 {
        let mut input = crate::h2::PREFACE.to_vec();
        input.extend(h2_frames(&mut rng));
        if round % 2 == 0 {
            // A plausible request, then mutation of the whole input.
            let mut hb = block.clone();
            if round % 4 == 0 {
                let at = rng.below(hb.len());
                hb[at] = rng.next() as u8;
            }
            let mut f = Vec::new();
            crate::h2::write_frame(&mut f, 0x1, 0x4, 1, &hb).unwrap();
            crate::h2::write_frame(&mut f, 0x0, 0x1, 1, &rng.bytes(64)).unwrap();
            input.extend(f);
        }
        if round % 3 == 0 {
            let at = crate::h2::PREFACE.len() + rng.below(input.len() - crate::h2::PREFACE.len());
            input[at] = rng.next() as u8;
        }
        let mut io = Io(std::io::Cursor::new(input), Vec::new());
        crate::h2_server::serve(&mut io, handler.clone());
    }
}
