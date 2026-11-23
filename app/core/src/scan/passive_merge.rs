// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// Issue types Burp keys by origin and identifier only, not by path
/// (their text class answers `Zpx3.ZT`: Zwvk, Zwur, Zwf2, Zwv5).
pub const ORIGIN_SCOPED: [&str; 4] = [
    "Social security numbers disclosed",
    "Password returned in later response",
    "Database connection string disclosed",
    "Source code disclosure",
];

/// The identity under which passive issues merge (burp.Zufk.ZL with the
/// issue type's Zpx3): name, host, path (left out for the origin-scoped
/// types) and the pervasive identifier.
pub fn passive_merge_key(i: &ScanIssue) -> String {
    let path = if ORIGIN_SCOPED.contains(&i.name.as_str()) {
        ""
    } else {
        i.path.as_str()
    };
    format!("{}|{}|{}|{}", i.name, i.host, path, i.ident)
}

pub fn add_passive_issues(shared: &Shared, mut issues: Vec<ScanIssue>) {
    // WebProbe-only passive checks (no Burp KnowledgeBase entry) stay off
    // unless Settings > Scanner > "WebProbe extra checks" is on, so the
    // default issue list is the one Burp would produce.
    if !shared.extra_checks.load(Ordering::SeqCst) {
        // Issues extensions report are theirs to name.
        issues.retain(|i| {
            is_burp_issue(&i.name) || i.detail.contains("<p>Reported by the extension ")
        });
    }
    if issues.is_empty() {
        return;
    }
    let mut iss = shared.issues.lock().unwrap();
    let key = passive_merge_key;
    let before = issues.len();
    let mut seen = std::collections::BTreeSet::new();
    issues.retain(|i| seen.insert(key(i)));
    let mut known: std::collections::BTreeSet<String> = iss.iter().map(&key).collect();
    issues.retain(|i| known.insert(key(i)));
    let mut incoming = 0;
    for mut issue in issues {
        if pervasive_merge(&mut iss, &issue) {
            continue;
        }
        issue.id = shared.next_issue_id.fetch_add(1, Ordering::SeqCst);
        iss.push(issue);
        incoming += 1;
    }
    if incoming > 0 {
        shared.log(&format!(
            "Scanner reported {} new issue(s) ({} consolidated)",
            incoming,
            before - incoming
        ));
    }
}

/// Burp's sentence on a pervasive issue merged across locations
/// (burp.Zcro.ZZ for MERGE_SINGLE_IDENTIFIER).
pub const MULTIPLE_LOCATIONS: &str =
    "This issue was found in multiple locations under the reported path.";

/// Locations after which an issue becomes pervasive (burp.Zwgx.ZN7:
/// `ZND() >= 10`).
pub const PERVASIVE_AT: usize = 10;

/// burp.Zsgz.ZC: the common leading path segments of two paths ("/" when
/// either is "/" or the first segments differ).
pub fn common_path(a: &str, b: &str) -> String {
    if a == "/" || b == "/" {
        return "/".into();
    }
    // Java's split drops trailing empty strings.
    fn split(p: &str) -> Vec<&str> {
        let mut v: Vec<&str> = p.split('/').collect();
        while v.len() > 1 && v.last() == Some(&"") {
            v.pop();
        }
        v
    }
    let (x, y) = (split(a), split(b));
    let mut out = String::new();
    for i in 1..x.len().min(y.len()) {
        if x[i] != y[i] {
            return if out.is_empty() { "/".into() } else { out };
        }
        out.push('/');
        out.push_str(x[i]);
    }
    out
}

/// Burp's pervasive-issue handling (burp.Zeb6.Zb when an issue is raised,
/// burp.Zbv8 / Zrh8.ZG when the task's issues are merged): issues of one
/// type on one host with the same pervasive identifier (or none) form a
/// group whose path is the common prefix of their locations (Zs45.ZIL).
/// At the 10th location the group's issues become one issue at the group
/// path, its text ending in [`MULTIPLE_LOCATIONS`]; later locations add
/// nothing. Returns true when `new` was absorbed (not to be added).
pub fn pervasive_merge(iss: &mut Vec<ScanIssue>, new: &ScanIssue) -> bool {
    let same = |i: &ScanIssue| i.name == new.name && i.host == new.host && i.ident == new.ident;
    if iss
        .iter()
        .any(|i| same(i) && i.detail.ends_with(MULTIPLE_LOCATIONS))
    {
        return true;
    }
    let members: Vec<usize> = (0..iss.len()).filter(|&k| same(&iss[k])).collect();
    if members.len() + 1 < PERVASIVE_AT {
        return false;
    }
    let first = members[0];
    let mut rep = iss[first].clone();
    for &k in &members[1..] {
        rep.path = common_path(&rep.path, &iss[k].path);
        for ev in &iss[k].evidence {
            if rep.evidence.len() < PERVASIVE_AT {
                rep.evidence.push(ev.clone());
            }
        }
    }
    rep.path = common_path(&rep.path, &new.path);
    rep.detail.push_str(MULTIPLE_LOCATIONS);
    for &k in members[1..].iter().rev() {
        iss.remove(k);
    }
    iss[first] = rep;
    true
}

#[cfg(test)]
mod id_sequence_tests {
    use super::*;

    #[test]
    fn issue_ids_do_not_consume_history_numbers() {
        let shared = Shared::new();
        let issue = |host: &str| ScanIssue {
            name: "Source code disclosure".into(),
            host: host.into(),
            path: "/a".into(),
            ..Default::default()
        };
        add_passive_issues(&shared, vec![issue("one.test"), issue("two.test")]);
        let ids: Vec<u64> = shared.issues.lock().unwrap().iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![1, 2], "issues number from 1 on their own");
        // The next proxy history row is still #1: no gaps from findings.
        assert_eq!(shared.next_id.load(Ordering::SeqCst), 1);
        // Held intercept items and WebSocket frames have their own sequences.
        assert_eq!(shared.next_queue_id.load(Ordering::SeqCst), 1);
        assert_eq!(shared.next_ws_id.load(Ordering::SeqCst), 1);
    }
}
