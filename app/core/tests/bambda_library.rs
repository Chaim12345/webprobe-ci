use webprobe_core::bambda_library::{Function, Script};

#[test]
fn yaml_round_trip_preserves_identity_function_and_source_without_execution() {
    let yaml = "id: 6620a595-520b-1ba2-2b20-5ea8568fdb89\nname: Test filter\nfunction: VIEW_FILTER\nlocation: PROXY_HTTP_HISTORY\nsource: |+\n  throw new IllegalStateException();\n\n";
    let script = Script::from_yaml(yaml).unwrap();
    assert_eq!(script.id, "6620a595-520b-1ba2-2b20-5ea8568fdb89");
    assert_eq!(script.function, Function::ViewFilter);
    assert_eq!(script.source, "throw new IllegalStateException();\n\n");
    let round_trip = Script::from_yaml(&script.to_yaml().unwrap()).unwrap();
    assert_eq!(round_trip, script);
}

#[test]
fn stored_id_conflict_requires_explicit_replace_and_lists_latest_source() {
    use webprobe_core::bambda_library::{Error, Store};
    let script = Script::new("Stored".into(), Function::ViewFilter, "return true;".into());
    let dir = std::env::temp_dir().join(format!("wp-library-test-{}", script.id));
    let store = Store::new(dir.clone());
    store.save(&script, false).unwrap();
    let mut changed = script.clone();
    changed.source = "return false;".into();
    assert!(matches!(store.save(&changed, false), Err(Error::Conflict)));
    assert_eq!(store.load().unwrap().scripts, vec![script]);
    store.save(&changed, true).unwrap();
    assert_eq!(store.load().unwrap().scripts, vec![changed]);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "no temporary files remain"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unsupported_targets_duplicate_fields_and_path_ids_are_rejected() {
    let script = Script::new("Safe".into(), Function::CustomColumn, "return 1;".into());
    let yaml = script.to_yaml().unwrap();
    for invalid in [
        yaml.replace("CUSTOM_COLUMN", "CUSTOM_ACTION"),
        yaml.replace("PROXY_HTTP_HISTORY", "REPEATER"),
        yaml.replace(&script.id, "../../outside"),
        format!("{yaml}\nname: duplicate\n"),
        format!("{yaml}\nunknown: arbitrary\n"),
        "x".repeat(256 * 1024 + 1),
    ] {
        assert!(Script::from_yaml(&invalid).is_err());
    }
}

#[test]
fn serialization_cannot_create_a_file_larger_than_the_import_limit() {
    let script = Script::new(
        "Control bytes".into(),
        Function::ViewFilter,
        "\u{1}".repeat(100_000),
    );
    assert!(script.to_yaml().is_err());
}

#[test]
fn exported_files_preserve_id_and_never_overwrite_an_existing_destination() {
    let script = Script::new("Export".into(), Function::CustomColumn, "return 42;".into());
    let dir = std::env::temp_dir().join(format!("wp-export-test-{}", script.id));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Export.bambda");
    script.export(&path).unwrap();
    assert_eq!(Script::load(&path).unwrap(), script);
    let mut changed = script.clone();
    changed.name = "Replacement".into();
    assert!(changed.export(&path).is_err());
    assert_eq!(Script::load(&path).unwrap(), script);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "no temporary files remain"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn fifo_paths_are_rejected_before_any_blocking_open() {
    use webprobe_core::bambda_library::Store;
    let script = Script::new("FIFO".into(), Function::ViewFilter, "return true;".into());
    let dir = std::env::temp_dir().join(format!("wp-fifo-test-{}", script.id));
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join(format!("{}.bambda", script.id));
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let (tx, rx) = std::sync::mpsc::channel();
    let path = fifo.clone();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(Script::load(&path).is_err());
    });
    assert!(rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("FIFO import must not block"));
    worker.join().unwrap();
    assert!(script.export(&fifo).is_err());
    let store = Store::new(dir.clone());
    assert!(store.save(&script, true).is_err());
    assert!(store.delete(&script).is_err());
    assert!(!std::fs::symlink_metadata(&fifo)
        .unwrap()
        .file_type()
        .is_file());
    std::fs::remove_dir_all(dir).unwrap();
}
