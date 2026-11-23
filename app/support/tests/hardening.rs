use std::sync::Arc;
use webprobe_support::sync::Mutex;

#[test]
fn hardening_into_inner_recovers_owned_value_after_poison() {
    let value = Mutex::new(vec![1]);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        value.lock().unwrap().push(2);
        let _guard = value.lock().unwrap();
        panic!("poison before ownership transfer");
    }));
    assert!(panic.is_err());
    assert_eq!(value.into_inner().unwrap(), [1, 2]);
}

#[test]
fn hardening_repeated_poison_recovery_keeps_mutations_visible() {
    let value = Arc::new(Mutex::new(Vec::new()));
    for n in 0..3 {
        let worker = value.clone();
        assert!(std::thread::spawn(move || {
            let mut guard = worker.lock().unwrap();
            guard.push(n);
            panic!("worker failure");
        })
        .join()
        .is_err());
        assert_eq!(value.lock().unwrap().len(), n + 1);
    }
    assert_eq!(
        Arc::try_unwrap(value).unwrap().into_inner().unwrap(),
        [0, 1, 2]
    );
}

#[test]
fn hardening_default_and_into_inner_keep_non_copy_values() {
    let value: Mutex<Vec<String>> = Mutex::default();
    value.lock().unwrap().push("owned".into());
    assert_eq!(value.into_inner().unwrap(), ["owned"]);
}
