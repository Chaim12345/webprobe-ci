// Burp's MIME families (the history "MIME type" column), shared by the
// history filter, the crawler and the scanner.

/// Burp's MIME-type column value (stated/inferred type families as Burp names
/// them: HTML, script, CSS, XML, JSON, text, image formats, app).
pub fn burp_mime(content_type: &str, body: &[u8]) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    let t = ct.split(';').next().unwrap_or("").trim();
    match t {
        "" => {
            let head: String = String::from_utf8_lossy(&body[..body.len().min(256)])
                .trim_start()
                .to_ascii_lowercase();
            if head.starts_with("<!doctype html") || head.starts_with("<html") {
                "HTML"
            } else if head.starts_with('{') || head.starts_with('[') {
                "JSON"
            } else if body.is_empty() {
                ""
            } else {
                "text"
            }
        }
        "text/html" | "application/xhtml+xml" => "HTML",
        "application/json" | "text/json" => "JSON",
        "text/css" => "CSS",
        "text/xml" | "application/xml" => "XML",
        "image/png" => "PNG",
        "image/jpeg" | "image/jpg" => "JPEG",
        "image/gif" => "GIF",
        "image/svg+xml" => "XML",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ICO",
        "application/x-shockwave-flash" => "flash",
        _ if t.contains("javascript") || t.contains("ecmascript") => "script",
        _ if t.ends_with("+json") => "JSON",
        _ if t.ends_with("+xml") => "XML",
        _ if t.starts_with("image/") => "image",
        _ if t.starts_with("text/") => "text",
        _ => "app",
    }
}
