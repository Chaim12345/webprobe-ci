// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

pub fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(i) = authority.rfind(':') {
        if let Ok(p) = authority[i + 1..].parse::<u16>() {
            return (authority[..i].to_string(), p);
        }
    }
    (authority.to_string(), default_port)
}

pub fn host_of(parts: &util::HttpParts, default_port: u16) -> (String, u16) {
    util::get_header(&parts.headers, "Host")
        .map(|h| split_host_port(&h, default_port))
        .unwrap_or_else(|| {
            // no Host header: fall back to the authority embedded in an absolute-form URI
            let p = &parts.path;
            if let Some(rest) = p.strip_prefix("http://") {
                let auth = rest.split(['/', '?']).next().unwrap_or("");
                if !auth.is_empty() {
                    return split_host_port(auth, default_port);
                }
            }
            ("".to_string(), default_port)
        })
}

pub fn path_of(parts: &util::HttpParts) -> String {
    if parts.path.starts_with("http://") {
        // origin-form conversion happens upstream; log absolute form
        if let Some(slash) = parts.path["http://".len()..].find('/') {
            return parts.path["http://".len() + slash..].to_string();
        }
        return "/".into();
    }
    if parts.path.is_empty() {
        "/".into()
    } else {
        parts.path.clone()
    }
}
