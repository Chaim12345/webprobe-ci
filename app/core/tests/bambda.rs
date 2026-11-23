//! Public Bambda compilation/evaluation contract, with a real JVM.
use std::{path::PathBuf, time::Duration};
use webprobe_core::bambda::{Exchange, Kind, Program};

fn runtime() -> (PathBuf, PathBuf) {
    let java = std::env::var_os("WEBPROBE_BAMBDA_TEST_JAVA")
        .expect("set WEBPROBE_BAMBDA_TEST_JAVA to a JDK 17+ java launcher");
    let api = std::env::var_os("WEBPROBE_BAMBDA_TEST_API")
        .expect("set WEBPROBE_BAMBDA_TEST_API to montoya-api.jar");
    (java.into(), api.into())
}
fn rows() -> Vec<Exchange> {
    vec![Exchange {
        id: 7, host: "example.test".into(), port: 443, secure: true,
        request: b"GET /private HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        response: Some(b"HTTP/1.1 302 Found\r\nServer: fixture\r\nSet-Cookie: session=test\r\nContent-Length: 0\r\n\r\n".to_vec()),
    }, Exchange {
        id: 8, host: "example.test".into(), port: 443, secure: true,
        request: b"GET /pending HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(), response: None,
    }]
}
const LIMIT: Duration = Duration::from_secs(15);
#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn java_filter_returns_booleans_for_complete_and_pending_exchanges() {
    let (java, api) = runtime();
    let script = r#"if (!requestResponse.hasResponse()) return false;
        var response = requestResponse.response();
        return response.isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION)
            && response.hasCookie("session");"#;
    let p = Program::compile(&java, &api, Kind::Filter, script, LIMIT).unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(true)), "{out:?}");
    assert_eq!(out[1].value, Some(serde_json::json!(false)));
    assert!(out.iter().all(|r| r.error.is_none()));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn java_column_guards_missing_responses_and_reads_headers() {
    let (java, api) = runtime();
    let script = r#"if (!requestResponse.hasResponse()) return "";
        var response = requestResponse.response();
        return response.hasHeader("Server") ? response.headerValue("Server") : "";"#;
    let p = Program::compile(&java, &api, Kind::Column, script, LIMIT).unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!("fixture")));
    assert_eq!(out[1].value, Some(serde_json::json!("")));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn invalid_java_and_wrong_filter_return_type_produce_compile_diagnostics() {
    let (java, api) = runtime();
    for source in ["return missing_symbol;", "return 123;"] {
        let result = Program::compile(&java, &api, Kind::Filter, source, LIMIT);
        assert!(
            matches!(result, Err(webprobe_core::bambda::Error::Compile(message)) if message.contains("error"))
        );
    }
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn row_exception_does_not_hide_later_results_or_corrupt_output() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        r#"System.out.println("not protocol");
        if (requestResponse.id() == 7) throw new IllegalStateException("fixture failure");
        return utilities.base64Utils().encodeToString("ok");"#,
        LIMIT,
    )
    .unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert!(out[0].error.as_ref().unwrap().contains("fixture failure"));
    assert_eq!(out[1].value, Some(serde_json::json!("b2s=")));
    assert!(out[1].error.is_none());
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn looping_java_is_stopped_and_program_can_be_reused() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "if (requestResponse.hasResponse()) { while (true) {} } return 42;",
        LIMIT,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let out = p.evaluate(&rows(), Duration::from_millis(500));
    assert!(matches!(out, Err(webprobe_core::bambda::Error::Timeout)));
    assert!(start.elapsed() < Duration::from_secs(5));
    let out = p.evaluate(&rows()[1..], LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(42)));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn row_identity_is_exact_even_above_javascript_integer_precision() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "return requestResponse.request().path();",
        LIMIT,
    )
    .unwrap();
    let mut input = rows();
    input[0].id = u64::MAX;
    let out = p.evaluate(&input, LIMIT).unwrap();
    assert_eq!(out[0].id, u64::MAX);
    assert_eq!(out[0].value, Some(serde_json::json!("/private")));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn byte_bodies_and_cookie_overloads_keep_the_recorded_values() {
    let (java, api) = runtime();
    let p = Program::compile(&java, &api, Kind::Filter, r#"
        if (!requestResponse.hasResponse()) return false;
        record Wanted(String name, String value, String domain, String path)
            implements burp.api.montoya.http.message.Cookie {
            public java.util.Optional<java.time.ZonedDateTime> expiration() { return java.util.Optional.empty(); }
        }
        var response = requestResponse.response();
        return requestResponse.request().body().getByte(0) == (byte) 255
            && response.hasCookie("session") && !response.hasCookie("Session")
            && response.hasCookie(new Wanted("session", "test", null, null))
            && !response.hasCookie(new Wanted("session", "wrong", null, null));
    "#, LIMIT).unwrap();
    let mut input = rows();
    input[0].request =
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\n".to_vec();
    input[0].request.extend_from_slice(&[255, 0]);
    let out = p.evaluate(&input, LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(true)), "{out:?}");
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn runaway_protocol_output_is_bounded() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        r#"
        var output = new java.io.FileOutputStream(java.io.FileDescriptor.out);
        byte[] buffer = new byte[1024 * 1024];
        while (true) output.write(buffer);
    "#,
        LIMIT,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let out = p.evaluate(&rows(), Duration::from_secs(5));
    assert!(
        matches!(out, Err(webprobe_core::bambda::Error::Limit(_))),
        "{out:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn successful_null_column_is_distinct_from_a_missing_error_value() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "if (requestResponse.hasResponse()) return null; throw new IllegalArgumentException();",
        LIMIT,
    )
    .unwrap();
    let out = p.evaluate(&rows(), LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::Value::Null));
    assert!(out[0].error.is_none());
    assert!(out[1].value.is_none());
    assert!(out[1].error.is_some());
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn raw_batch_limit_is_conservative_for_the_256_mib_heap() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "return requestResponse.request().body().length();",
        LIMIT,
    )
    .unwrap();
    let mut input = rows();
    input.truncate(1);
    input[0].response = None;
    input[0].request = b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
    input[0].request.extend(vec![255; 1024 * 1024]);
    assert!(matches!(
        p.evaluate(&input, LIMIT),
        Err(webprobe_core::bambda::Error::Limit(_))
    ));
    input[0].request = b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
    input[0].request.extend(vec![255; 1024 * 1024 - 1024]);
    let out = p.evaluate(&input, LIMIT).unwrap();
    assert_eq!(out[0].value, Some(serde_json::json!(1024 * 1024 - 1024)));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn chunked_snapshots_do_not_discard_rows_that_only_exceed_the_combined_cap() {
    let (java, api) = runtime();
    let p = Program::compile(
        &java,
        &api,
        Kind::Column,
        "return requestResponse.request().body().length();",
        LIMIT,
    )
    .unwrap();
    let mut input = rows();
    for row in &mut input {
        row.response = None;
        row.request = b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
        row.request.extend(vec![255; 600_000]);
    }
    let mut too_large = input[0].clone();
    too_large.id = 999;
    too_large.request.extend(vec![0; 600_000]);
    input.push(too_large);
    let out = p.evaluate_chunked(&input, LIMIT).unwrap();
    assert_eq!(out.rows.len(), 2);
    assert_eq!(out.skipped_ids, vec![999]);
    assert_eq!(out.rows[0].value, Some(serde_json::json!(600_000)));
    assert_eq!(out.rows[1].value, Some(serde_json::json!(600_000)));
}

#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn preview_cancellation_stops_a_looping_jvm_before_its_deadline() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let (java, api) = runtime();
    let cancel = Arc::new(AtomicBool::new(false));
    let p = Program::compile_cancellable(
        &java,
        &api,
        Kind::Column,
        "while (true) {}",
        LIMIT,
        cancel.clone(),
    )
    .unwrap();
    let trigger = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        cancel.store(true, Ordering::Relaxed);
    });
    let start = std::time::Instant::now();
    let result = p.evaluate(&rows(), LIMIT);
    trigger.join().unwrap();
    assert!(matches!(
        result,
        Err(webprobe_core::bambda::Error::Cancelled)
    ));
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires JDK 17+ and a Montoya API jar; see docs/specs/R-16-bambda-backend.md"]
fn parent_loss_watchdog_stops_an_orphaned_looping_jvm() {
    use std::process::{Command, Stdio};
    const MARKER: &str = "WEBPROBE_BAMBDA_ORPHAN_TEST_MARKER";
    if std::env::var_os(MARKER).is_some() {
        let (java, api) = runtime();
        let p = Program::compile(&java, &api, Kind::Column,
            "java.nio.file.Files.writeString(java.nio.file.Path.of(System.getenv(\"WEBPROBE_BAMBDA_ORPHAN_TEST_MARKER\")), Long.toString(ProcessHandle.current().pid())); while (true) {}", LIMIT).unwrap();
        let _ = p.evaluate(&rows(), Duration::from_secs(60));
        panic!("surrogate parent should be killed while evaluating");
    }
    let dir = std::env::temp_dir().join(format!(
        "wp-orphan-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let marker = dir.join("java-pid");
    struct Cleanup {
        child: std::process::Child,
        dir: PathBuf,
        java_pid: Option<u32>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(pid) = self.java_pid {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "parent_loss_watchdog_stops_an_orphaned_looping_jvm",
            "--ignored",
            "--nocapture",
        ])
        .env(MARKER, &marker)
        .env("TMPDIR", &dir)
        .spawn()
        .unwrap();
    let mut cleanup = Cleanup {
        child,
        dir,
        java_pid: None,
    };
    let start = std::time::Instant::now();
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(&marker) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                break pid;
            }
        }
        assert!(
            cleanup.child.try_wait().unwrap().is_none(),
            "surrogate parent exited before running Java"
        );
        assert!(
            start.elapsed() < Duration::from_secs(25),
            "JVM marker was not written"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    cleanup.java_pid = Some(pid);
    cleanup.child.kill().unwrap();
    cleanup.child.wait().unwrap();
    let start = std::time::Instant::now();
    loop {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Ok(stat)
                if stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X')) =>
            {
                break
            }
            _ => {}
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "orphaned JVM remained running after parent loss"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    cleanup.java_pid = None;
}
