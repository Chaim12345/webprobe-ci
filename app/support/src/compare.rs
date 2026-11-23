//! Comparer: word-, byte- and character-level differences between two items,
//! as in Burp's "Compare ... Words / Bytes" window, where each side is shown
//! with its modified, deleted and added runs highlighted.
//!
//! The diff is Myers' O((N+M)D) algorithm over tokens, after stripping the
//! common prefix and suffix. Very different inputs are capped (`MAX_EDITS`):
//! past it, the rest of the middle is reported as one replaced block rather
//! than spending unbounded time and memory.

use crate::util::html_encode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Words and the runs of whitespace and punctuation between them.
    Words,
    Bytes,
    /// Unicode characters.
    Chars,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Same,
    /// Present on this side only, with a counterpart on the other side
    /// (a replacement): Burp's "Modified".
    Modified,
    /// Present on the left side only.
    Deleted,
    /// Present on the right side only.
    Added,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub kind: Kind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    pub left: Vec<Span>,
    pub right: Vec<Span>,
    /// Number of changed runs (a replacement counts once).
    pub differences: usize,
    /// True when the inputs were too different to diff exactly.
    pub capped: bool,
}

/// Most edits the exact diff explores before giving up on the remainder.
pub const MAX_EDITS: usize = 2000;

/// Split bytes into tokens for `unit`. Every token is a non-empty slice and
/// their concatenation is the input.
pub fn tokens(data: &[u8], unit: Unit) -> Vec<&[u8]> {
    match unit {
        Unit::Bytes => data.chunks(1).collect(),
        Unit::Chars => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < data.len() {
                let len = utf8_len(data[i]).min(data.len() - i).max(1);
                // An invalid sequence is split byte by byte.
                let len = if std::str::from_utf8(&data[i..i + len]).is_ok() {
                    len
                } else {
                    1
                };
                out.push(&data[i..i + len]);
                i += len;
            }
            out
        }
        Unit::Words => {
            let class = |b: u8| -> u8 {
                if b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80 {
                    0
                } else if b.is_ascii_whitespace() {
                    1
                } else {
                    2
                }
            };
            let mut out = Vec::new();
            let mut start = 0;
            for i in 1..=data.len() {
                // Punctuation is one token per character; words and
                // whitespace runs are one token each.
                let boundary =
                    i == data.len() || class(data[i]) != class(data[i - 1]) || class(data[i]) == 2;
                if boundary {
                    out.push(&data[start..i]);
                    start = i;
                }
            }
            out
        }
    }
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Same,
    Del,
    Ins,
}

/// Myers' diff of `a` against `b`; `None` when more than `max_d` edits are needed.
fn myers<T: PartialEq>(a: &[T], b: &[T], max_d: usize) -> Option<Vec<Op>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (n + m) as usize;
    let limit = max.min(max_d);
    let off = max as isize + 1;
    let mut v = vec![0isize; 2 * max + 3];
    // The backtrack at step d reads diagonals -d-1..=d+1, so only that
    // window is kept (cloning the whole array each step cost gigabytes on
    // very different inputs).
    let mut trace: Vec<Vec<isize>> = Vec::new();
    for d in 0..=limit as isize {
        trace.push(v[(off - d - 1) as usize..=(off + d + 1) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let idx = (k + off) as usize;
            let mut x = if k == -d || (k != d && v[idx - 1] < v[idx + 1]) {
                v[idx + 1]
            } else {
                v[idx - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx] = x;
            if x >= n && y >= m {
                // Walk the trace back to the start.
                let mut ops = Vec::new();
                let (mut x, mut y) = (n, m);
                for d in (0..=d).rev() {
                    let w = &trace[d as usize];
                    let at = |k: isize| w[(k + d + 1) as usize];
                    let k = x - y;
                    let prev_k = if k == -d || (k != d && at(k - 1) < at(k + 1)) {
                        k + 1
                    } else {
                        k - 1
                    };
                    let prev_x = at(prev_k);
                    let prev_y = prev_x - prev_k;
                    while x > prev_x && y > prev_y {
                        ops.push(Op::Same);
                        x -= 1;
                        y -= 1;
                    }
                    if d > 0 {
                        ops.push(if x == prev_x { Op::Ins } else { Op::Del });
                    }
                    x = prev_x;
                    y = prev_y;
                }
                ops.reverse();
                return Some(ops);
            }
            k += 2;
        }
    }
    None
}

fn push(spans: &mut Vec<Span>, text: &[u8], kind: Kind) {
    if text.is_empty() {
        return;
    }
    let s = String::from_utf8_lossy(text);
    match spans.last_mut() {
        Some(last) if last.kind == kind => last.text.push_str(&s),
        _ => spans.push(Span {
            text: s.into_owned(),
            kind,
        }),
    }
}

/// Compare two items.
pub fn compare(left: &[u8], right: &[u8], unit: Unit) -> Comparison {
    let a = tokens(left, unit);
    let b = tokens(right, unit);
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let (ops, capped) = match myers(am, bm, MAX_EDITS) {
        Some(ops) => (ops, false),
        None => (
            am.iter()
                .map(|_| Op::Del)
                .chain(bm.iter().map(|_| Op::Ins))
                .collect(),
            true,
        ),
    };
    let mut out = Comparison {
        capped,
        ..Default::default()
    };
    let concat = |t: &[&[u8]]| t.concat();
    push(&mut out.left, &concat(&a[..pre]), Kind::Same);
    push(&mut out.right, &concat(&b[..pre]), Kind::Same);
    // Group consecutive edits; a group with both deletions and insertions is
    // a modification on both sides.
    let (mut i, mut j, mut k) = (0usize, 0usize, 0usize);
    while k < ops.len() {
        if ops[k] == Op::Same {
            push(&mut out.left, am[i], Kind::Same);
            push(&mut out.right, bm[j], Kind::Same);
            i += 1;
            j += 1;
            k += 1;
            continue;
        }
        let (i0, j0) = (i, j);
        while k < ops.len() && ops[k] != Op::Same {
            if ops[k] == Op::Del {
                i += 1;
            } else {
                j += 1;
            }
            k += 1;
        }
        let (dels, ins) = (concat(&am[i0..i]), concat(&bm[j0..j]));
        let (lk, rk) = match (dels.is_empty(), ins.is_empty()) {
            (false, false) => (Kind::Modified, Kind::Modified),
            (false, true) => (Kind::Deleted, Kind::Added),
            _ => (Kind::Deleted, Kind::Added),
        };
        push(&mut out.left, &dels, lk);
        push(&mut out.right, &ins, rk);
        out.differences += 1;
    }
    push(&mut out.left, &concat(&a[a.len() - suf..]), Kind::Same);
    push(&mut out.right, &concat(&b[b.len() - suf..]), Kind::Same);
    out
}

/// A self-contained HTML page showing both sides with the differences
/// highlighted (Comparer's export).
pub fn export_html(c: &Comparison, title: &str) -> String {
    let side = |spans: &[Span]| {
        let mut s = String::new();
        for sp in spans {
            let class = match sp.kind {
                Kind::Same => "",
                Kind::Modified => " class=\"mod\"",
                Kind::Deleted => " class=\"del\"",
                Kind::Added => " class=\"add\"",
            };
            s.push_str(&format!("<span{class}>{}</span>", html_encode(&sp.text)));
        }
        s
    };
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{t}</title><style>body{{font-family:sans-serif}}pre{{white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:12px;margin:0}}td{{vertical-align:top;width:50%;border:1px solid #ccc;padding:6px}}.mod{{background:#9FBBD4}}.del{{background:#EE95A1}}.add{{background:#9BCF88}}</style></head><body><h1>{t}</h1><p>{n} difference(s){cap}. Key: <span class=\"mod\">Modified</span> <span class=\"del\">Deleted</span> <span class=\"add\">Added</span></p><table><tr><td><pre>{l}</pre></td><td><pre>{r}</pre></td></tr></table></body></html>",
        t = html_encode(title),
        n = c.differences,
        cap = if c.capped { " (inputs too different: the middle is shown as one block)" } else { "" },
        l = side(&c.left),
        r = side(&c.right),
    )
}

/// One side of a comparison as Burp's Hex view: lines of
/// `offset  b0 b1 ... b15`, each byte keeping the kind of the span it came
/// from, so the highlights land on the bytes that differ.
pub fn hex_spans(spans: &[Span]) -> Vec<Span> {
    let mut out: Vec<Span> = Vec::new();
    let mut push = |text: String, kind: Kind| match out.last_mut() {
        Some(last) if last.kind == kind => last.text.push_str(&text),
        _ => out.push(Span { text, kind }),
    };
    let mut off = 0usize;
    for sp in spans {
        for &b in sp.text.as_bytes() {
            if off.is_multiple_of(16) {
                push(
                    format!("{}{:08x}  ", if off == 0 { "" } else { "\n" }, off),
                    Kind::Same,
                );
            } else {
                push(" ".into(), Kind::Same);
            }
            push(format!("{b:02x}"), sp.kind);
            off += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {

    #[test]
    fn hex_view_keeps_kinds_on_bytes() {
        let spans = vec![
            Span {
                text: "ab".into(),
                kind: Kind::Same,
            },
            Span {
                text: "Z".into(),
                kind: Kind::Added,
            },
        ];
        let h = hex_spans(&spans);
        let text: String = h.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(text, "00000000  61 62 5a");
        assert_eq!(
            h.last().unwrap(),
            &Span {
                text: "5a".into(),
                kind: Kind::Added
            }
        );
        let long: Vec<Span> = vec![Span {
            text: "x".repeat(17),
            kind: Kind::Same,
        }];
        let t: String = hex_spans(&long).iter().map(|s| s.text.as_str()).collect();
        assert!(t.contains("\n00000010  78"), "{t}");
    }
    use super::*;

    fn kinds(spans: &[Span]) -> Vec<(String, Kind)> {
        spans.iter().map(|s| (s.text.clone(), s.kind)).collect()
    }

    #[test]
    fn tokens_cover_the_input() {
        let s = "GET /a?b=1 HTTP/1.1\r\nHost: x".as_bytes();
        for unit in [Unit::Words, Unit::Bytes, Unit::Chars] {
            assert_eq!(tokens(s, unit).concat(), s);
            assert!(tokens(s, unit).iter().all(|t| !t.is_empty()));
        }
        let w: Vec<String> = tokens(b"user=ann  smith!", Unit::Words)
            .iter()
            .map(|t| String::from_utf8_lossy(t).into_owned())
            .collect();
        assert_eq!(w, ["user", "=", "ann", "  ", "smith", "!"]);
        let c = tokens("a\u{e9}\u{20ac}".as_bytes(), Unit::Chars);
        assert_eq!(c.len(), 3);
        // An invalid byte is a token of its own.
        assert_eq!(tokens(&[b'a', 0xff, b'b'], Unit::Chars).len(), 3);
    }

    #[test]
    fn words_marks_modified_deleted_and_added() {
        let c = compare(
            b"session=abc; role=user; theme=dark",
            b"session=xyz; role=user; theme=dark; lang=en",
            Unit::Words,
        );
        assert_eq!(c.differences, 2);
        assert_eq!(
            kinds(&c.left),
            vec![
                ("session=".into(), Kind::Same),
                ("abc".into(), Kind::Modified),
                ("; role=user; theme=dark".into(), Kind::Same)
            ]
        );
        assert_eq!(
            kinds(&c.right),
            vec![
                ("session=".into(), Kind::Same),
                ("xyz".into(), Kind::Modified),
                ("; role=user; theme=dark".into(), Kind::Same),
                ("; lang=en".into(), Kind::Added)
            ]
        );
        let d = compare(b"a b c", b"a c", Unit::Words);
        assert_eq!(
            kinds(&d.left)
                .iter()
                .filter(|(_, k)| *k == Kind::Deleted)
                .count(),
            1
        );
        assert!(d.right.iter().all(|s| s.kind == Kind::Same));
    }

    #[test]
    fn bytes_and_chars_find_single_changes() {
        let c = compare(
            b"Content-Length: 1234\r\n",
            b"Content-Length: 1284\r\n",
            Unit::Bytes,
        );
        assert_eq!(c.differences, 1);
        assert_eq!(
            c.left
                .iter()
                .find(|s| s.kind == Kind::Modified)
                .unwrap()
                .text,
            "3"
        );
        let e = compare("caf\u{e9}".as_bytes(), "cafe".as_bytes(), Unit::Chars);
        assert_eq!(e.left.last().unwrap().text, "\u{e9}");
        assert_eq!(e.right.last().unwrap().text, "e");
        // Identical inputs: one Same span each, no differences.
        let same = compare(b"x y", b"x y", Unit::Words);
        assert_eq!(
            (same.differences, same.left.len(), same.right.len()),
            (0, 1, 1)
        );
        let empty = compare(b"", b"abc", Unit::Bytes);
        assert_eq!(empty.right[0].kind, Kind::Added);
    }

    #[test]
    fn very_different_inputs_are_capped() {
        let a: Vec<u8> = (0..20_000u32).map(|i| (i % 7) as u8 + b'a').collect();
        let b: Vec<u8> = (0..20_000u32).map(|i| (i % 5) as u8 + b'k').collect();
        let c = compare(&a, &b, Unit::Bytes);
        // The cap is what keeps this fast (work bounded by the cap, not
        // by the input sizes); `very_different_inputs_are_capped_quickly`
        // checks the wall time on its own.
        assert!(c.capped);
        assert_eq!(c.left.iter().map(|s| s.text.len()).sum::<usize>(), a.len());
        assert_eq!(c.right.iter().map(|s| s.text.len()).sum::<usize>(), b.len());
    }

    /// Wall-clock guard; ignored in the suite, where load makes time
    /// meaningless (run alone with --ignored).
    #[test]
    #[ignore = "wall-clock bound; meaningless under suite load"]
    fn very_different_inputs_are_capped_quickly() {
        let a: Vec<u8> = (0..20_000u32).map(|i| (i % 7) as u8 + b'a').collect();
        let b: Vec<u8> = (0..20_000u32).map(|i| (i % 5) as u8 + b'k').collect();
        let t = std::time::Instant::now();
        assert!(compare(&a, &b, Unit::Bytes).capped);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(3),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn export_is_an_escaped_html_page() {
        let c = compare(b"<a>1</a>", b"<a>2</a>", Unit::Words);
        let html = export_html(&c, "Word compare of #1 and #2");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(
            html.contains("<span class=\"mod\">1</span>")
                && html.contains("<span class=\"mod\">2</span>")
        );
        assert!(html.contains("&lt;a&gt;") && !html.contains("<a>"));
        assert!(html.contains("1 difference(s)"));
    }
}
