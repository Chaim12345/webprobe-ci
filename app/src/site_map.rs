//! Site map helpers: the filter and the issue markers of Target > Site map.

/// Burp's site map filter (the subset WebProbe offers).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SiteFilter {
    /// Kept when the host or path contains it (case-insensitive).
    pub text: String,
    pub in_scope_only: bool,
    pub hide_unrequested: bool,
}

impl SiteFilter {
    /// Whether an item at `origin` + `path` is shown. `in_scope` is only
    /// asked when the scope matters.
    pub fn keeps(&self, origin: &str, path: &str, in_scope: impl FnOnce() -> bool) -> bool {
        let t = self.text.trim().to_lowercase();
        if !t.is_empty() && !origin.to_lowercase().contains(&t) && !path.to_lowercase().contains(&t)
        {
            return false;
        }
        !self.in_scope_only || in_scope()
    }
}

/// The most severe issue (lowest severity index: 0 = High) located at or
/// under `prefix` on `host`, or `None`.
pub fn worst_issue(issues: &[(String, String, usize)], host: &str, prefix: &str) -> Option<usize> {
    let prefix = if prefix.is_empty() { "/" } else { prefix };
    issues
        .iter()
        .filter(|(h, p, _)| h == host && p.starts_with(prefix))
        .map(|(_, _, rank)| *rank)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_text_and_scope() {
        let mut f = SiteFilter::default();
        assert!(f.keeps("http://a.test", "/x", || false));
        f.text = "ADMIN".into();
        assert!(f.keeps("http://a.test", "/admin/users", || false));
        assert!(f.keeps("http://admin.test", "/", || false));
        assert!(!f.keeps("http://a.test", "/public", || true));
        f.text.clear();
        f.in_scope_only = true;
        assert!(f.keeps("http://a.test", "/", || true));
        assert!(!f.keeps("http://a.test", "/", || false));
        // The scope is not consulted when the text already rules an item out.
        f.text = "zzz".into();
        assert!(!f.keeps("http://a.test", "/", || panic!("scope must not be asked")));
    }

    #[test]
    fn worst_issue_takes_the_most_severe_under_a_node() {
        let issues = vec![
            ("a.test".to_string(), "/shop/cart".to_string(), 2),
            ("a.test".to_string(), "/shop/pay".to_string(), 0),
            ("a.test".to_string(), "/blog".to_string(), 3),
            ("b.test".to_string(), "/shop".to_string(), 1),
        ];
        assert_eq!(worst_issue(&issues, "a.test", "/"), Some(0));
        assert_eq!(worst_issue(&issues, "a.test", "/shop/cart"), Some(2));
        assert_eq!(worst_issue(&issues, "a.test", "/blog"), Some(3));
        assert_eq!(worst_issue(&issues, "a.test", "/none"), None);
        assert_eq!(worst_issue(&issues, "b.test", ""), Some(1));
    }
}
