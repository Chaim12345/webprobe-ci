// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

pub struct LinkManipHit {
    pub payload: String,
    pub target: String,
}

/// burp.Zb_5 reflected link manipulation: inject an absolute URL and report
/// when it becomes a link or redirect target the page points at (value
/// replaced then appended, burp.Zw7s REPLACE/APPEND).
pub fn run_link_manip_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    _value: &str,
    mut send: F,
) -> Option<LinkManipHit> {
    // burp.Zb_5 (LINK_MANIPULATION_REFLECTED): the value is replaced by a
    // random 10-character token, which must come back unmodified inside a
    // URL: a link in the page or the Location / Refresh target (Burp, lab
    // /redirect: "echoed unmodified within the response header Location").
    // Nothing is appended to the original value, so allowlisting redirectors
    // (Juice Shop /redirect) reject the probe as they do Burp's.
    let token: String = {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10)
            .map(|i| {
                if i == 8 {
                    (b'0' + g.gen_range(0..10)) as char
                } else {
                    (b'a' + g.gen_range(0..26)) as char
                }
            })
            .collect()
    };
    let resp = send(&token)?;
    let target = crate::crawl::link_targets(&resp)
        .into_iter()
        .chain(crate::crawl::redirect_targets(&resp))
        .find(|t| t.contains(&token))?;
    Some(LinkManipHit {
        payload: token,
        target,
    })
}

/// burp.Zulm: valid (same-file) and invalid path variants of a path-like
/// value. Templates decoded from Zulm.ZV/Zb (%1=sep, %2=file, %3=random).
pub fn file_path_variants(value: &str) -> Option<(String, Vec<String>, Vec<String>)> {
    let sep = if !value.contains('/') && value.contains('\\') {
        "\\"
    } else {
        "/"
    };
    let cut = value.rfind(['/', '\\']);
    let (dir, file) = match cut {
        Some(i) => (&value[..i + 1], &value[i + 1..]),
        None => ("", value),
    };
    if file.is_empty() {
        return None;
    }
    let r = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..3)
            .map(|_| (b'a' + g.gen_range(0..26)) as char)
            .collect::<String>()
    };
    // Zulm.ZV: redundant paths to the same file (should return the same file).
    let valid = vec![
        format!("{dir}.{sep}{file}"),
        format!("{dir}.{sep}.{sep}{file}"),
        format!("{dir}.{sep}.{sep}.{sep}{file}"),
    ];
    // Zulm.Zb: bogus variants (should not return the same file).
    let invalid = vec![
        format!("{dir}...{sep}{file}"),
        format!("{dir}{}{sep}{file}", r()),
        format!("{dir}{file}{}", r()),
    ];
    Some((dir.to_string(), valid, invalid))
}

pub struct FilePathManipHit {
    pub valid: String,
    pub invalid: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zsl1: for a path-like value, the redundant-path variants (same file)
/// must respond consistently differently from the bogus variants, proving the
/// parameter selects a file. Runs Burp's differential engine (Zmaq).
pub fn run_file_path_manip_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<FilePathManipHit> {
    // Only applies to a value that looks like a path (burp.Zsl1 gate).
    if !value.contains(['/', '\\', '.']) || value.len() < 3 {
        return None;
    }
    let (_, valid, invalid) = file_path_variants(value)?;
    let (vi, ii) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
    let sent = std::cell::RefCell::new(&mut send);
    let attrs = crate::variations::differential(
        Some(baseline),
        accuracy,
        || {
            let p = &valid[vi.get() % valid.len()];
            vi.set(vi.get() + 1);
            (sent.borrow_mut())(p)
        },
        || {
            let p = &invalid[ii.get() % invalid.len()];
            ii.set(ii.get() + 1);
            (sent.borrow_mut())(p)
        },
    )?;
    Some(FilePathManipHit {
        valid: valid[0].clone(),
        invalid: invalid[0].clone(),
        attributes: attrs,
    })
}
