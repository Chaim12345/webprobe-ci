//! WebProbe without a window: the same engine as the desktop app, driven
//! from the command line.
//!
//!     webprobe-headless proxy [--port N] [--project FILE] [--seconds N]
//!         Run the intercepting proxy (with the live passive scan) and print
//!         one line per exchange. With --project, the history and issues are
//!         saved to FILE when it stops (after N seconds, or on Ctrl+C /
//!         end of standard input).
//!
//!     webprobe-headless scan URL... [--crawl] [--speed fast|normal|thorough]
//!                           [--report FILE.html|FILE.xml]
//!         Audit the given URLs (crawl first with --crawl) and print every
//!         issue as one JSON object per line. --report also writes Burp's
//!         HTML report or XML issue export, by the file's extension.
//!
//! Only point it at hosts you are authorised to test.

use std::io::BufRead;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use webprobe_core::{net, project, scan};
use webprobe_report::report;

fn usage() -> ! {
    eprintln!("usage:\n  webprobe-headless proxy [--port N] [--project FILE] [--seconds N]\n  webprobe-headless scan URL... [--crawl] [--speed fast|normal|thorough] [--report FILE.html|FILE.xml]");
    std::process::exit(2)
}

/// Value of `--name V` in `args`, removing both.
fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        usage();
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    match args.iter().position(|a| a == name) {
        Some(i) => {
            args.remove(i);
            true
        }
        None => false,
    }
}

fn issue_json(i: &scan::ScanIssue) -> String {
    serde_json::json!({
        "name": i.name,
        "severity": i.sev,
        "confidence": i.confidence,
        "host": i.host,
        "path": i.path,
        "type_id": i.type_id,
        "detail": i.detail,
        "evidence": i.evidence.len(),
    })
    .to_string()
}

fn save_project(shared: &net::Shared, path: &str) -> Result<(), String> {
    let data = project::ProjectData {
        history: shared
            .history
            .snapshot()
            .iter()
            .map(project::ProjectHistory::from_entry)
            .collect(),
        issues: shared
            .issues
            .lock()
            .unwrap()
            .iter()
            .map(project::ProjectIssue::from_issue)
            .collect(),
        ..Default::default()
    };
    project::save(std::path::Path::new(path), &data).map_err(String::from)
}

fn proxy(mut args: Vec<String>) {
    let port: u16 = take_opt(&mut args, "--port")
        .map(|p| p.parse().unwrap_or_else(|_| usage()))
        .unwrap_or(8090);
    let project_file = take_opt(&mut args, "--project");
    let seconds: Option<u64> =
        take_opt(&mut args, "--seconds").map(|s| s.parse().unwrap_or_else(|_| usage()));
    if !args.is_empty() {
        usage();
    }
    let shared = net::Shared::new();
    shared.proxy_port.store(port, Ordering::SeqCst);
    net::start_proxy(shared.clone());
    let started = Instant::now();
    while !shared.listener_running.load(Ordering::SeqCst) {
        if started.elapsed() > Duration::from_secs(5) {
            eprintln!("could not listen on 127.0.0.1:{port}");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("proxy listening on 127.0.0.1:{port}");
    // Stop on end of standard input (Ctrl+D, or the parent closing it), and
    // on Ctrl+C / SIGTERM: the run then ends normally, so --project is saved.
    let stdin_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, stdin_closed.clone());
    }
    if seconds.is_none() {
        let flag = stdin_closed.clone();
        webprobe_core::util::spawn_contained("webprobe-headless", move || {
            for _ in std::io::stdin().lock().lines() {}
            flag.store(true, Ordering::SeqCst);
        });
    }
    let mut printed = 0usize;
    loop {
        // Copy the new rows out first: printing to a slow pipe must not hold
        // the history lock every proxy thread needs to record.
        let fresh: Vec<String> = {
            let history = shared.history.snapshot();
            let rows = history
                .iter()
                .skip(printed)
                .map(|e| {
                    format!(
                        "{}\t{}\t{}\t{}\t{}",
                        e.id,
                        e.method,
                        net::history_host(e),
                        e.path,
                        e.status
                    )
                })
                .collect();
            printed = history.len();
            rows
        };
        for row in fresh {
            println!("{row}");
        }
        let done = stdin_closed.load(Ordering::SeqCst)
            || seconds.is_some_and(|s| started.elapsed() >= Duration::from_secs(s));
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let issues = shared.issues.lock().unwrap().clone();
    for i in &issues {
        eprintln!("issue: {}", issue_json(i));
    }
    if let Some(path) = project_file {
        match save_project(&shared, &path) {
            Ok(()) => eprintln!(
                "saved {printed} exchange(s) and {} issue(s) to {path}",
                issues.len()
            ),
            Err(e) => {
                eprintln!("could not save {path}: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn scan_urls(mut args: Vec<String>) {
    let crawl = take_flag(&mut args, "--crawl");
    let report_file = take_opt(&mut args, "--report");
    let speed = match take_opt(&mut args, "--speed").as_deref() {
        None | Some("normal") => 1,
        Some("fast") => 0,
        Some("thorough") => 2,
        Some(_) => usage(),
    };
    if args.is_empty() || args.iter().any(|a| a.starts_with("--")) {
        usage();
    }
    let shared = net::Shared::new();
    shared.scan_speed.store(speed, Ordering::SeqCst);
    let started = Instant::now();
    scan::crawl_and_audit(&shared, &args, !crawl);
    // crawl_and_audit returns once the last item's audit has finished.
    shared.scan.wait_idle(None);
    let issues = shared.issues.lock().unwrap().clone();
    for i in &issues {
        println!("{}", issue_json(i));
    }
    eprintln!(
        "{} issue(s) in {:.1} s",
        issues.len(),
        started.elapsed().as_secs_f32()
    );
    if let Some(path) = report_file {
        let format = if path.to_ascii_lowercase().ends_with(".xml") {
            report::ReportFormat::Xml
        } else {
            report::ReportFormat::Html
        };
        let options = report::ReportOptions {
            format,
            ..Default::default()
        };
        let mut known: Vec<net::HistEntry> = shared.crawl_items.snapshot();
        known.extend(shared.history.snapshot().iter().cloned());
        let chosen = report::select_issues(&issues, &options);
        let kb = report::KnowledgeBase::discover_checked().unwrap_or_else(|missing| {
            eprintln!("{missing}");
            report::KnowledgeBase::default()
        });
        let items = report::build_report_issues(&chosen, &known, &kb);
        let text = report::render(&items, &options, webprobe_core::util::now_secs());
        match std::fs::write(&path, text) {
            Ok(()) => eprintln!("report of {} issue(s) written to {path}", items.len()),
            Err(e) => {
                eprintln!("could not write {path}: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    webprobe_core::scan::register_scan_hooks();
    webprobe_core::scan::register_task_ops();
    webprobe_core::scan::register_type_checks();
    webprobe_core::headless::register_browser_crawl();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    match args.remove(0).as_str() {
        "proxy" => proxy(args),
        "scan" => scan_urls(args),
        _ => usage(),
    }
}
