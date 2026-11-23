use webprobe_core::scan::{ScanEvidence, ScanIssue};
use webprobe_report::report::{build_report_issues, select_issues, KnowledgeBase, ReportOptions};

#[test]
fn hardening_report_boundary_keeps_probe_order_and_missing_response() {
    let issues = [ScanIssue {
        name: "SQL injection".into(),
        host: "example.test".into(),
        path: "/search".into(),
        sev: "high".into(),
        confidence: "Firm".into(),
        evidence: vec![
            ScanEvidence::new(
                b"POST /search HTTP/1.1\r\nHost: example.test\r\n\r\nprobe",
                None,
            ),
            ScanEvidence::new(
                b"GET /control HTTP/1.1\r\nHost: example.test\r\n\r\n",
                Some(b""),
            ),
        ],
        ..Default::default()
    }];
    let result = build_report_issues(&issues, &[], &KnowledgeBase::default());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].evidence.len(), 2);
    assert_eq!(result[0].evidence[0].method, "POST");
    assert_eq!(
        result[0].evidence[0].request,
        issues[0].evidence[0].request.as_ref()
    );
    assert!(result[0].evidence[0].response.is_none());
    assert_eq!(result[0].evidence[1].response.as_deref(), Some(&b""[..]));
}

#[test]
fn hardening_report_filter_preserves_order_and_shares_evidence_bytes() {
    let evidence = ScanEvidence::new(b"request", Some(b"response"));
    let issues: Vec<_> = [3, 1, 2]
        .into_iter()
        .map(|id| ScanIssue {
            id,
            sev: if id == 1 { "low" } else { "high" }.into(),
            confidence: "Firm".into(),
            evidence: vec![evidence.clone()],
            ..Default::default()
        })
        .collect();
    let options = ReportOptions {
        severities: [true, false, false, false],
        ..Default::default()
    };
    let selected = select_issues(&issues, &options);
    assert_eq!(
        selected.iter().map(|issue| issue.id).collect::<Vec<_>>(),
        [3, 2]
    );
    assert!(std::sync::Arc::ptr_eq(
        &selected[0].evidence[0].request,
        &evidence.request
    ));
    assert_eq!(issues.len(), 3);
}
