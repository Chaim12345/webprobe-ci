//! First-run setup, verification checklist and sample traffic (M-07).
//!
//! Grounding (Burp build 52685, shipped documentation in
//! `resources/Documentation/burp/documentation/desktop/external-browser-config/`):
//!   * `check-listener.html` — the first step is to check the proxy listener is
//!     running; the default is 127.0.0.1:8080.
//!   * `certificate/index.html` + `proxy-troubleshooting.html` — the CA
//!     certificate is fetched *through the proxy* by visiting `http://burpsuite`;
//!     the browser must already be proxying through Burp. Verification is "visit
//!     an HTTPS URL and get no security warning".
//!   * `check-browser-configuration.html` — "these steps enable you to test
//!     applications that use HTTP; to test HTTPS URLs, install Burp's CA
//!     certificate".
//!   * `certificate/index.html` — most users never do this at all, because the
//!     bundled browser is preconfigured. WebProbe has no bundled browser
//!     (L-05), so the checklist says so instead of pretending otherwise.
//!
//! WebProbe therefore serves its own equivalent page at `http://webprobe` (and
//! answers `http://burpsuite` too, so a tutorial written for Burp still works),
//! with the CA in PEM and DER, exactly where the browser can reach it.

use eframe::egui::{self, RichText, Ui};

use crate::feedback;
use crate::net;
use crate::theme::{self, c};
use crate::App;

#[cfg(test)]
use webprobe_core::setup_page::{local_response, setup_page};

/// A checklist line, derived from live state rather than from a stored flag, so
/// it cannot claim a step is done when it is not.
pub struct Check {
    pub label: String,
    pub detail: String,
    pub done: bool,
}

/// An exchange the proxy really carried. Seeded test rows (the
/// WEBPROBE_SEED_HISTORY hook) carry a tiny counter as their timestamp and
/// must not tick the onboarding steps.
fn is_real(e: &net::HistEntry) -> bool {
    e.ts >= 1_000_000_000
}

/// Real exchanges in history.
pub fn real_count(history: &[net::HistEntry]) -> usize {
    history.iter().filter(|e| is_real(e)).count()
}

/// Real exchanges that were intercepted over TLS.
pub fn real_https_count(history: &[net::HistEntry]) -> usize {
    history.iter().filter(|e| is_real(e) && e.https).count()
}

pub fn checks(app: &App) -> Vec<Check> {
    let port = app
        .shared
        .proxy_port
        .load(std::sync::atomic::Ordering::SeqCst);
    let listening = app
        .shared
        .listener_running
        .load(std::sync::atomic::Ordering::SeqCst);
    let history: Vec<net::HistEntry> = app.shared.history.snapshot();
    let https = real_https_count(&history);
    let waiting = app.shared.count_waiting();

    vec![
        Check {
            label: "Proxy listener is running".into(),
            detail: if listening {
                format!("127.0.0.1:{port}")
            } else {
                format!("not listening on 127.0.0.1:{port}")
            },
            done: listening,
        },
        Check {
            label: "HTTPS interception working".into(),
            // The proxy cannot see whether a browser warned before the user
            // clicked through, so this only claims what it observed.
            detail: if https > 0 {
                format!("{https} HTTPS exchange(s) intercepted and decrypted")
            } else {
                "visit http://webprobe through the proxy, then trust the CA".into()
            },
            done: https > 0,
        },
        Check {
            label: "Traffic is flowing".into(),
            detail: if real_count(&history) == 0 {
                "no requests seen yet".into()
            } else {
                format!("{} request(s) in history", real_count(&history))
            },
            done: real_count(&history) > 0,
        },
        Check {
            label: "Intercept holds messages".into(),
            detail: if app
                .shared
                .intercept_on
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                format!("on; {waiting} held")
            } else {
                "off (Ctrl+T toggles)".into()
            },
            done: app
                .shared
                .intercept_on
                .load(std::sync::atomic::Ordering::SeqCst),
        },
    ]
}

/// The onboarding panel. Returns true when the user dismissed it this frame.
pub fn panel(app: &mut App, ui: &mut Ui) -> bool {
    let checks = checks(app);
    let done = checks.iter().filter(|c| c.done).count();

    let hide = ui
        .horizontal(|ui| {
            ui.label(
                RichText::new("Set up WebProbe")
                    .size(14.0)
                    .strong()
                    .color(c(theme::MONO7)),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!("{}/{} steps done", done, checks.len()))
                    .size(12.0)
                    .color(c(if done == checks.len() {
                        theme::GOOD
                    } else {
                        theme::MONO6
                    })),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.small_button("Hide").clicked()
            })
            .inner
        })
        .inner;

    for check in &checks {
        ui.horizontal(|ui| {
            let (mark, colour) = if check.done {
                ("OK", theme::GOOD)
            } else {
                ("--", theme::MONO4)
            };
            ui.add_sized(
                [26.0, 18.0],
                egui::Label::new(RichText::new(mark).monospace().size(12.0).color(c(colour))),
            );
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(check.label.clone())
                        .size(12.0)
                        .color(c(if check.done {
                            theme::EDITOR_TEXT
                        } else {
                            theme::MONO6
                        })),
                );
                ui.label(
                    RichText::new(check.detail.clone())
                        .size(12.0)
                        .color(c(theme::MONO4)),
                );
            });
        });
    }

    ui.add_space(6.0);
    let port = app
        .shared
        .proxy_port
        .load(std::sync::atomic::Ordering::SeqCst);
    ui.label(
        RichText::new(format!(
            "Point your browser at 127.0.0.1:{port}, then open http://webprobe to download the CA certificate. Burp's own page is http://burpsuite; both are answered locally by the proxy."
        ))
        .size(12.0)
        .color(c(theme::MONO6)),
    );

    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        if ui.button("Send sample traffic").clicked() {
            sample_traffic(&app.shared);
        }
        if ui.button("Copy CA certificate").clicked() {
            ui.ctx().copy_text(app.shared.mitm.ca_pem().to_string());
            feedback::toast(feedback::Level::Info, "CA certificate copied (PEM)");
        }
        if ui.button("Export CA certificate").clicked() {
            export_ca(app);
        }
        ui.hyperlink_to(
            "Install the CA (docs)",
            "https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate",
        );
        ui.hyperlink_to("Proxy listener (docs)", "https://portswigger.net/burp/documentation/desktop/external-browser-config");
    });

    hide
}

fn export_ca(app: &App) {
    let dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let path = dir.join("webprobe-ca.pem");
    match std::fs::write(&path, app.shared.mitm.ca_pem()) {
        Ok(()) => {
            app.shared
                .log(&format!("CA certificate exported to {}", path.display()));
            feedback::toast(
                feedback::Level::Success,
                format!("CA written to {}", path.display()),
            );
        }
        Err(e) => feedback::toast(feedback::Level::Error, format!("CA export failed: {e}")),
    }
}

/// Route one real request through our own listener, so the user can see history,
/// a status line and (with an HTTPS URL) a decrypted exchange. Runs off-thread:
/// the listener answers from its own accept loop.
pub fn sample_traffic(shared: &std::sync::Arc<net::Shared>) {
    sample_traffic_to(shared, "example.com");
}

/// The sample request, sent through the listener to `host` (tests use a local
/// upstream so they never depend on, or send traffic to, the internet).
pub fn sample_traffic_to(shared: &std::sync::Arc<net::Shared>, host: &str) {
    let port = shared.proxy_port.load(std::sync::atomic::Ordering::SeqCst);
    let request = format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WebProbe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    let shared = shared.clone();
    webprobe_core::util::spawn_contained("onboarding", move || {
        let out = crate::send_internal_probe(port, request.as_bytes());
        if out.is_empty() {
            shared.log(&format!(
                "Sample traffic failed: no response from the proxy on 127.0.0.1:{port}"
            ));
            feedback::toast(
                feedback::Level::Error,
                format!("No response from 127.0.0.1:{port}; start the listener first"),
            );
            return;
        }
        let status = String::from_utf8_lossy(&out)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        shared.log(&format!("Sample traffic: {status}"));
        feedback::toast(
            feedback::Level::Success,
            format!("Sample traffic: {status}"),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_rows_do_not_count_as_traffic() {
        let row = |ts: u64, https: bool| net::HistEntry {
            ts,
            https,
            ..Default::default()
        };
        // The seed hook stamps rows 0, 1, 2, ...; real rows carry unix time.
        let history = vec![
            row(0, true),
            row(7, true),
            row(29, false),
            row(1_794_000_000, false),
            row(1_794_000_001, true),
        ];
        assert_eq!(super::real_count(&history), 2);
        assert_eq!(super::real_https_count(&history), 1);
        assert_eq!(super::real_https_count(&history[..3]), 0);
    }

    #[test]
    fn setup_hosts_are_answered_locally() {
        for host in ["webprobe", "burpsuite", "WEBPROBE", "burpsuite:8080"] {
            let r = local_response(host, "/", 8080, "PEM", b"DER").expect(host);
            let text = String::from_utf8_lossy(&r);
            assert!(text.starts_with("HTTP/1.1 200 OK"), "{host}");
            assert!(text.contains("WebProbe proxy"), "{host}");
        }
        assert!(local_response("example.com", "/", 8080, "PEM", b"DER").is_none());
    }

    #[test]
    fn ca_downloads_have_the_right_content_type() {
        let pem = local_response("webprobe", "/webprobe-ca.pem", 8080, "PEM", b"DER").unwrap();
        let text = String::from_utf8_lossy(&pem);
        assert!(text.contains("application/x-pem-file"), "{text}");
        assert!(pem.ends_with(b"PEM"));

        let der = local_response("webprobe", "/webprobe-ca.der", 8080, "PEM", b"DER").unwrap();
        let text = String::from_utf8_lossy(&der);
        assert!(text.contains("application/pkix-cert"), "{text}");
        assert!(der.ends_with(b"DER"));
    }

    #[test]
    fn page_documents_both_paths_and_the_verification_step() {
        let page = setup_page(8080);
        assert!(page.contains("127.0.0.1:8080"));
        assert!(page.contains("/webprobe-ca.pem") && page.contains("/webprobe-ca.der"));
        assert!(page.contains("Ctrl+K"));
        // Burp serves the same page at http://burpsuite, and the port shown must
        // be the listener's, not a hard-coded 8080.
        assert!(setup_page(9090).contains("127.0.0.1:9090"));
    }
    #[test]
    fn sample_traffic_populates_history_through_the_listener() {
        use std::sync::atomic::Ordering;

        let shared = net::Shared::new(); // already an Arc<Shared>
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        shared.proxy_port.store(port, Ordering::SeqCst);
        net::start_proxy(shared.clone());
        for _ in 0..100 {
            if shared.listener_running.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            shared.listener_running.load(Ordering::SeqCst),
            "listener never started"
        );

        // A local upstream: the test must not depend on the internet.
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = upstream.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        sample_traffic_to(&shared, &format!("127.0.0.1:{up_port}"));
        for _ in 0..100 {
            if !shared.history.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let history = shared.history.snapshot();
        assert!(
            !history.is_empty(),
            "sample traffic never reached the proxy"
        );
        assert_eq!(history[0].host, "127.0.0.1");
        assert_eq!(history[0].status, "200");
    }
}
