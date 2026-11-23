#[test]
fn hardening_support_reexport_is_the_same_mutex_type() {
    // A copied wrapper rather than a re-export would fail this assignment.
    let support: webprobe_support::sync::Mutex<String> =
        webprobe_core::sync::Mutex::new("kept".into());
    let core: webprobe_core::sync::Mutex<String> = support;
    assert_eq!(core.into_inner().unwrap(), "kept");
}
