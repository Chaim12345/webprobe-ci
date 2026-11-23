// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

#[cfg(test)]
mod repeater_fix_tests {
    use super::*;

    /// Second review, finding 3: several links (and non-ASCII text) neither
    /// hang nor panic.
    #[test]
    fn links_in_response_walks_every_link() {
        let body = "<a href=\"http://a\"> x <a href=\"http://b\"> é <img src=\"https://c/ü\"> <a href=\"/rel\">";
        let e = net::HistEntry {
            resp_raw: Some(format!("HTTP/1.1 200 OK\r\n\r\n{body}").into()),
            ..Default::default()
        };
        assert_eq!(links_in_response(&e), "http://a\nhttp://b\nhttps://c/ü");
    }

    /// Issue #2 item 2: Cancel frees the tab at once and a late response
    /// is dropped (its generation is stale).
    #[test]
    fn cancel_abandons_the_in_flight_send() {
        let sh = net::Shared::new();
        let tab = sh.repeaters.lock().unwrap()[0].id;
        let gen = sh.rep.begin(tab);
        cancel_repeater_send(&sh);
        assert_eq!(
            sh.repeaters.lock().unwrap()[0].result_line,
            "Request cancelled",
            "shown in the tab's status line"
        );
        assert!(!sh.rep.is_busy());
        assert_eq!(sh.rep.result(), "Request cancelled");
        assert!(
            !sh.rep.is_current(gen),
            "the worker sees a stale generation"
        );
        // Cancel with nothing in flight changes nothing.
        cancel_repeater_send(&sh);
        assert_eq!(sh.rep.result(), "Request cancelled");
    }

    fn install_probe_header(sh: &std::sync::Arc<net::Shared>) {
        use webprobe_core::ext_host::{
            self, Annotations, HttpService, LoadedExtension, ProxyAction, ProxyHooks,
        };
        struct AddHeader;
        impl ProxyHooks for AddHeader {
            fn extension_name(&self) -> &str {
                "append probe header"
            }
            fn handle_http_request(
                &self,
                _: &str,
                _: &HttpService,
                req: &mut Vec<u8>,
                _: &mut Annotations,
            ) -> ProxyAction {
                let i = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                req.splice(i..i, b"\r\nX-Parity-Probe: 1".iter().copied());
                ProxyAction::Continue
            }
        }
        ext_host::with_host(sh, |h| h.extensions.push(LoadedExtension::new(AddHeader)));
    }

    /// A handler must not rewrite the editor and feed its own edits back
    /// into the next Send. Exercise the actual asynchronous UI action twice.
    #[test]
    fn repeater_repeat_send_keeps_editor_and_wire_headers_stable() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let origin = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = l.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut req = Vec::new();
                let mut buf = [0; 2048];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).unwrap();
                    assert_ne!(n, 0);
                    req.extend_from_slice(&buf[..n]);
                }
                requests.push(String::from_utf8(req).unwrap());
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
            }
            requests
        });
        let sh = net::Shared::new();
        install_probe_header(&sh);
        let request =
            format!("GET /repeat HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        {
            let mut tabs = sh.repeaters.lock().unwrap();
            tabs[0].request = request.clone();
            tabs[0].host = "127.0.0.1".into();
            tabs[0].port = port;
        }
        let mut app = App::new(sh.clone());
        app.repeater.update_cl = false;
        app.rops.follow = crate::repeater_ops::FollowMode::Never;
        for _ in 0..2 {
            repeater_send(&mut app);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while sh.rep.is_busy() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(!sh.rep.is_busy(), "Repeater send timed out");
            let tabs = sh.repeaters.lock().unwrap();
            assert!(
                tabs[0].result_line.starts_with("Done"),
                "{}",
                tabs[0].result_line
            );
            assert_eq!(
                tabs[0].request, request,
                "handler edits must not replace the editor"
            );
        }
        let requests = origin.join().unwrap();
        for req in &requests {
            assert_eq!(req.matches("X-Parity-Probe: 1").count(), 1, "{req}");
        }
        assert_eq!(requests[0], requests[1]);
    }

    /// Real Burp's Follow Always measurement: header counts are 1 then 2,
    /// but the editor stays on the original request, including on re-send.
    #[test]
    fn repeater_follow_always_keeps_editor_unchanged_and_inherits_handler_headers() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let origin = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for hop in 0..4 {
                let (mut stream, _) = l.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut req = Vec::new();
                let mut buf = [0; 2048];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).unwrap();
                    assert_ne!(n, 0);
                    req.extend_from_slice(&buf[..n]);
                }
                requests.push(String::from_utf8(req).unwrap());
                let response: &[u8] = if hop % 2 == 0 {
                    b"HTTP/1.1 302 Found\r\nLocation: /finish\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                };
                stream.write_all(response).unwrap();
            }
            requests
        });
        let sh = net::Shared::new();
        install_probe_header(&sh);
        let request =
            format!("GET /start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        {
            let mut tabs = sh.repeaters.lock().unwrap();
            tabs[0].request = request.clone();
            tabs[0].host = "127.0.0.1".into();
            tabs[0].port = port;
        }
        let mut app = App::new(sh.clone());
        app.repeater.update_cl = false;
        app.rops.follow = crate::repeater_ops::FollowMode::Always;
        for _ in 0..2 {
            repeater_send(&mut app);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while sh.rep.is_busy() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(!sh.rep.is_busy(), "Repeater send timed out");
            let tabs = sh.repeaters.lock().unwrap();
            assert!(
                tabs[0]
                    .result_line
                    .starts_with("Done (followed 1 redirection)"),
                "{}",
                tabs[0].result_line
            );
            assert_eq!(tabs[0].request.as_bytes(), request.as_bytes());
            assert_eq!((tabs[0].host.as_str(), tabs[0].port), ("127.0.0.1", port));
        }
        let requests = origin.join().unwrap();
        for (i, req) in requests.iter().enumerate() {
            let expected_path = if i % 2 == 0 { "/start" } else { "/finish" };
            assert!(
                req.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
                "{req}"
            );
            assert_eq!(req.matches("X-Parity-Probe: 1").count(), 1 + i % 2, "{req}");
        }
        assert_eq!(requests[0], requests[2]);
        assert_eq!(requests[1], requests[3]);
    }

    /// Stop an automatic cross-origin chain on a relative redirect, then
    /// exercise the real manual Follow path. Editor stays at hop 0 until clicked.
    #[test]
    fn repeater_manual_follow_uses_last_response_origin_and_path() {
        use std::io::{Read, Write};
        fn request(stream: &mut std::net::TcpStream) -> String {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            let mut buf = [0; 2048];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                raw.extend_from_slice(&buf[..n]);
            }
            String::from_utf8(raw).unwrap()
        }
        fn run(mode: crate::repeater_ops::FollowMode) {
            let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (pa, pb) = (
                a.local_addr().unwrap().port(),
                b.local_addr().unwrap().port(),
            );
            let origin_a = std::thread::spawn(move || {
                let (mut stream, _) = a.accept().unwrap();
                let initial = request(&mut stream);
                assert!(initial.starts_with("GET /a/start "));
                assert_eq!(initial.matches("X-Parity-Probe: 1").count(), 1);
                write!(stream, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{pb}/b/step\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            });
            let origin_b = std::thread::spawn(move || {
                let (mut stream, _) = b.accept().unwrap();
                let middle = request(&mut stream);
                assert!(middle.starts_with("GET /b/step "));
                assert_eq!(middle.matches("X-Parity-Probe: 1").count(), 1);
                stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                drop(stream);
                let (mut stream, _) = b.accept().unwrap();
                let final_request = request(&mut stream);
                assert_eq!(final_request.matches("X-Parity-Probe: 1").count(), 2);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
                final_request
            });
            let sh = net::Shared::new();
            install_probe_header(&sh);
            sh.scope
                .lock()
                .unwrap()
                .push(net::ScopeRule::include("/b/step", false));
            let original = format!(
                "GET /a/start HTTP/1.1\r\nHost: 127.0.0.1:{pa}\r\nConnection: close\r\n\r\n"
            );
            {
                let mut tabs = sh.repeaters.lock().unwrap();
                tabs[0].host = "127.0.0.1".into();
                tabs[0].port = pa;
                tabs[0].request = original.clone();
            }
            let mut app = App::new(sh.clone());
            app.repeater.update_cl = false;
            app.rops.follow = mode;
            repeater_send(&mut app);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while sh.rep.is_busy() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(!sh.rep.is_busy());
            {
                let tabs = sh.repeaters.lock().unwrap();
                assert_eq!(tabs[0].request, original);
                assert_eq!(tabs[0].port, pa);
                assert!(tabs[0].result_line.starts_with("Done"));
            }
            assert!(crate::repeater_ops::can_follow(&app));
            assert!(crate::repeater_ops::load_redirect(&mut app));
            {
                let tabs = sh.repeaters.lock().unwrap();
                assert_eq!(tabs[0].port, pb, "manual Follow must use hop 1's origin");
                let expected = if mode == crate::repeater_ops::FollowMode::OnSite {
                    "/b/step"
                } else {
                    "/b/next"
                };
                assert!(
                    tabs[0]
                        .request
                        .starts_with(&format!("GET {expected} HTTP/1.1\r\n")),
                    "{}",
                    tabs[0].request
                );
                if mode == crate::repeater_ops::FollowMode::OnSite {
                    assert!(!tabs[0].request.contains("X-Parity-Probe"));
                }
                assert!(tabs[0]
                    .request
                    .contains(&format!("Host: 127.0.0.1:{pb}\r\n")));
            }
            let clicked_request = sh.repeaters.lock().unwrap()[0].request.clone();
            repeater_send(&mut app);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while sh.rep.is_busy() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(!sh.rep.is_busy());
            assert_eq!(sh.repeaters.lock().unwrap()[0].request, clicked_request);
            origin_a.join().unwrap();
            assert!(origin_b
                .join()
                .unwrap()
                .starts_with("GET /b/next HTTP/1.1\r\n"));
        }
        run(crate::repeater_ops::FollowMode::InScope);
        run(crate::repeater_ops::FollowMode::OnSite);
    }

    /// Issue #2 item 1: tab numbers are never reused, so routing by id can
    /// not hit a different tab after a close.
    #[test]
    fn repeater_tab_ids_are_never_reused() {
        let sh = net::Shared::new();
        let first = sh.repeaters.lock().unwrap()[0].id;
        let a = sh.rep.new_tab_id();
        let b = sh.rep.new_tab_id();
        assert!(a != first && b != a && b != first);
    }
}

#[cfg(test)]
mod suite {
    use super::{history_new_rows, history_view};
    use crate::net::HistEntry;
    use crate::table::TableState;

    fn entry(id: u64, host: &str) -> HistEntry {
        HistEntry {
            id,
            ts: 0,
            method: "GET".to_string(),
            host: host.to_string(),
            port: 80,
            path: "/".to_string(),
            status: "200".to_string(),
            resp_len: 0,
            req_raw: Vec::new().into(),
            resp_raw: None,
            https: false,
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        }
    }

    #[test]
    fn history_view_keeps_every_match_and_new_rows_go_on_top() {
        let history: Vec<_> = (1..=1500u64)
            .map(|id| {
                entry(
                    id,
                    if id == 1 {
                        "old.example"
                    } else {
                        "other.example"
                    },
                )
            })
            .collect();
        // The only match is the oldest entry.
        let (rows, truncated) = history_view(
            &history,
            |e| e.host.contains("old.example"),
            &TableState::new(),
        );
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [1]);
        assert!(!truncated);
        // No cap: all 1500 rows, newest first.
        let (rows, truncated) = history_view(&history, |_| true, &TableState::new());
        assert_eq!(rows.len(), 1500);
        assert!(!truncated);
        assert_eq!(
            (rows.first().unwrap().id, rows.last().unwrap().id),
            (1500, 1)
        );
        // Appended rows, filtered and newest first, are what an incremental
        // update puts on top: the result equals a full rebuild.
        let mut grown = history.clone();
        grown.extend(
            (1501..=1505u64).map(|id| entry(id, if id % 2 == 0 { "old.example" } else { "x" })),
        );
        let keep = |e: &crate::net::HistEntry| e.host.contains("old.example");
        let mut incremental = history_new_rows(&grown, history.len(), keep);
        incremental.extend(history_view(&history, keep, &TableState::new()).0);
        let full = history_view(&grown, keep, &TableState::new()).0;
        assert_eq!(
            incremental.iter().map(|r| r.id).collect::<Vec<_>>(),
            full.iter().map(|r| r.id).collect::<Vec<_>>()
        );
        assert_eq!(
            full.iter().map(|r| r.id).collect::<Vec<_>>(),
            [1504, 1502, 1]
        );
        assert!(history_new_rows(&history, 9999, keep).is_empty());
    }

    #[test]
    fn history_sorts_by_method_before_limiting() {
        let mut history: Vec<_> = (1..=5).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string();
        let mut state = TableState::new();
        state.sort_col = 2; // Method (Burp column order: #, Host, Method, ...)
        state.sort_asc = true;
        let (rows, _) = history_view(&history, |_| true, &state);
        // Ascending by method: GET rows keep newest-first order, POST sorts last.
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[4].method, "POST");
    }

    #[test]
    fn csrf_poc_replays_the_body() {
        let e = crate::net::HistEntry {
            method: "POST".into(),
            host: "h".into(),
            port: 80,
            path: "/change".into(),
            req_raw: b"POST /change HTTP/1.1\r\nHost: h\r\n\r\nemail=a%40b.c&x=1"
                .to_vec()
                .into(),
            ..Default::default()
        };
        let html = crate::ui::csrf_poc_html(&e);
        assert!(
            html.contains("action=\"http://h/change\"")
                && html.contains("name=\"email\" value=\"a@b.c\""),
            "{html}"
        );
    }

    #[test]
    fn add_marker_wraps_the_selection() {
        assert_eq!(
            crate::ui::add_marker("q=apple", (2, 7)),
            "q=\u{00A7}apple\u{00A7}"
        );
        assert_eq!(crate::ui::add_marker("ab", (1, 1)), "a\u{00A7}\u{00A7}b");
    }

    #[test]
    fn tools_get_origin_form_without_proxy_connection() {
        let r = crate::ui::request_for_tools(b"GET http://h:1/a?b=1 HTTP/1.1\r\nHost: h:1\r\nProxy-Connection: Keep-Alive\r\nAccept: */*\r\n\r\n");
        assert_eq!(r, "GET /a?b=1 HTTP/1.1\r\nHost: h:1\r\nAccept: */*\r\n\r\n");
    }

    #[test]
    fn repeater_updates_content_length() {
        let r = crate::ui::update_content_length(
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nabcd",
        );
        assert!(r.contains("Content-Length: 4\r\n"), "{r}");
        let g = crate::ui::update_content_length("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(!g.contains("Content-Length"));
    }

    #[test]
    fn a_sort_sees_the_whole_history() {
        let mut history: Vec<_> = (1..=1500u64).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string(); // the oldest entry
        let mut state = TableState::new();
        state.sort_col = 2; // Method
        state.sort_asc = false; // POST first
        let (rows, truncated) = history_view(&history, |_| true, &state);
        assert!(!truncated);
        assert_eq!(rows.len(), 1500);
        assert_eq!(rows[0].id, 1, "the sort must see the whole list");
    }
}

#[cfg(test)]
mod logger_menu_tests {
    use super::*;

    fn tool_row() -> crate::logger::LogEntry {
        crate::logger::LogEntry {
            id: 7,
            method: "GET".into(),
            host: "example.test".into(),
            port: 8443,
            https: true,
            path: "/a?x=1".into(),
            tool: "Repeater".into(),
            request: Some(std::sync::Arc::from(
                &b"GET /a?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"[..],
            )),
            response: Some(std::sync::Arc::from(&b"HTTP/1.1 200 OK\r\n\r\nhi"[..])),
            ..Default::default()
        }
    }

    /// Logger rows offer the Proxy history Send-to commands (Burp parity).
    #[test]
    fn logger_menu_lists_burp_send_to_actions() {
        let labels: Vec<&str> = LOGGER_MENU.iter().map(|(l, _)| *l).collect();
        for want in [
            "Send to Organizer\tCtrl+O",
            "Send to Repeater\tCtrl+R",
            "Send to Intruder\tCtrl+I",
            "Send to Sequencer",
            "Send to Comparer (request)",
            "Send to Comparer (response)",
            "Add to scope",
            "Scan",
        ] {
            assert!(labels.contains(&want), "missing {want}");
        }
    }

    #[test]
    fn logger_tool_row_sends_to_organizer_repeater_intruder() {
        let mut app = App::new(net::Shared::new());
        let row = tool_row();
        let e = log_row_entry(&app.shared, &row).expect("tool row keeps its message");
        assert!(e.https, "TLS on a non-443 port is kept");
        assert_eq!(e.port, 8443);
        assert_eq!(e.host, "example.test");
        let before = app.shared.organizer.lock().unwrap().len();
        logger_command(&mut app, &e, "organizer");
        assert_eq!(app.shared.organizer.lock().unwrap().len(), before + 1);
        let reps_before = app.shared.repeaters.lock().unwrap().len();
        logger_command(&mut app, &e, "repeater");
        assert_eq!(app.shared.repeaters.lock().unwrap().len(), reps_before + 1);
        assert!(app.tab == Tab::Repeater);
        logger_command(&mut app, &e, "intruder");
        assert!(app.intr_req.starts_with("GET /a?x=1"));
        assert!(app.tab == Tab::Intruder);
        logger_command(&mut app, &e, "cmp_resp");
        assert!(app.comparer.items.last().unwrap().ends_with("hi"));
    }

    #[test]
    fn logger_row_without_retained_message_has_no_entry() {
        let shared = net::Shared::new();
        let mut row = crate::logger::LogEntry {
            hist_id: Some(999_999),
            ..Default::default()
        };
        assert!(log_row_entry(&shared, &row).is_none());
        row.hist_id = None;
        assert!(log_row_entry(&shared, &row).is_none());
    }

    /// Real egui frames: right-click a Logger row and the menu opens with
    /// Burp's Send to Organizer / Repeater entries.
    #[test]
    fn right_click_on_logger_row_opens_the_menu() {
        let mut app = App::new(net::Shared::new());
        app.logger.push(tool_row());
        let ctx = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1200.0, 800.0));
        let mut texts = String::new();
        let frame = |events: Vec<egui::Event>, app: &mut App, texts: &mut String| {
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let out = ctx.run_ui(raw, |ui| {
                egui::CentralPanel::default().show(ui, |ui| logger_view(app, ui));
            });
            texts.clear();
            for cs in &out.shapes {
                if let egui::epaint::Shape::Text(t) = &cs.shape {
                    if t.galley.text() == "GET" {
                        texts.push_str(&{
                            let c = t.visual_bounding_rect().center();
                            format!("@GET {} {}\n", c.x, c.y)
                        });
                    }
                    texts.push_str(t.galley.text());
                    texts.push('\n');
                }
            }
            out.drop_without_applying_deltas();
        };
        frame(vec![], &mut app, &mut texts);
        for _ in 0..3 {
            frame(vec![], &mut app, &mut texts);
        }
        let mut it = texts
            .split("@GET ")
            .nth(1)
            .expect("row painted")
            .split_whitespace();
        let x: f32 = it.next().unwrap().parse().unwrap();
        let y: f32 = it.next().unwrap().parse().unwrap();
        // Click the centre of the painted "GET" cell: the row's own spot.
        {
            let at = egui::pos2(x, y);
            frame(vec![egui::Event::PointerMoved(at)], &mut app, &mut texts);
            let btn = |pressed| egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Secondary,
                pressed,
                modifiers: Default::default(),
            };
            frame(vec![btn(true)], &mut app, &mut texts);
            frame(vec![btn(false)], &mut app, &mut texts);
            for _ in 0..3 {
                frame(vec![], &mut app, &mut texts);
            }
            assert!(
                texts.contains("Send to Organizer"),
                "right-click opens the Logger menu; sel {:?}",
                app.log_sel
            );
        }
        assert!(texts.contains("Send to Repeater"));
        assert!(texts.contains("Copy URL"));
        assert_eq!(app.log_sel, Some(1), "right-click selects the row");
    }
}
