// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// burp.Ze2s.Zn: SQL error signatures per database, decoded at runtime from
/// Burp's own class. Index 0 is the generic `SQLException`.
pub const SQL_ERRORS: [(&str, &[&str]); 8] = [
    ("Generic", &["SQLException"]),
    (
        "Microsoft SQL Server",
        &[
            "Incorrect syntax near",
            "Unclosed quotation mark",
            ", which was not supplied",
            "Invalid object name",
            "Microsoft OLE DB Provider",
            "ODBC SQL Server Driver",
            "Column name or number of supplied values does not match table definition",
            "Cannot find column",
            "SqlException",
        ],
    ),
    (
        "Oracle",
        &[
            "ODBC driver for Oracle",
            "quoted string not properly terminated",
            "missing right parenthesis",
            "PLS-0",
            "ORA-0",
            "ORA-1",
            "ORA-2",
            "ORA-3",
            "ORA-4",
        ],
    ),
    (
        "MySQL",
        &[
            "You have an error in your SQL syntax",
            "Incorrect column name",
            "Can't find record in",
            "Unknown table",
            "Incorrect column specifier for column",
            "Column count doesn't match value count at row",
            "supplied argument is not a valid MySQL result",
            "MDB2 Error: syntax error",
        ],
    ),
    (
        "PostgreSQL",
        &[
            "unterminated quoted identifier",
            "unterminated quoted string",
            "unterminated string literal",
            "Query failed: ERROR: syntax error",
            "PostgreSQL",
        ],
    ),
    (
        "Microsoft Access",
        &[
            "ODBC Microsoft Access Driver",
            "Syntax error in string in query expression",
        ],
    ),
    (
        "IBM DB2",
        &[
            "CLI Driver",
            "does not have an ending string delimiter",
            "Expected tokens may include:  ",
            "Escape syntax error.  See attached Throwable for details.",
        ],
    ),
    ("ColdFusion", &["Dynamic Page Generation Error"]),
];

/// The first database error signature in `body` that the baseline lacks.
pub fn sql_error_in(body: &str, baseline: &str) -> Option<(usize, &'static str)> {
    for (i, (_, sigs)) in SQL_ERRORS.iter().enumerate() {
        if let Some(sig) = sigs
            .iter()
            .find(|s| body.contains(**s) && !baseline.contains(**s))
        {
            return Some((i, sig));
        }
    }
    None
}

pub struct SqlErrorHit {
    pub database: &'static str,
    pub payload: String,
    pub confirmed: bool,
}

/// burp.Zppj.ZE with the quote series decoded through Burp's own string
/// decoder (Zppj.a): one to four single quotes, and at THOROUGH
/// (MYSQL_SPECIFIC) the backslash-escaped quotes `\'` `\\'` `\\\'` `\\\\'`.
/// Payloads are appended to the value. A database-specific error on the
/// first probe reports (confirmed when the balanced second probe is clean);
/// the generic SQLException needs the full alternation error, clean, error,
/// clean. Mapping Burp's issue flags 16/8 to specific/generic is inferred.
pub fn run_sql_error_check<F: FnMut(&str) -> Option<String>>(
    value: &str,
    baseline: &str,
    speed: ScanSpeed,
    mut send: F,
) -> Option<SqlErrorHit> {
    let (base_status, base_body) = split_resp(baseline);
    let mut series: Vec<[&str; 4]> = vec![["'", "''", "'''", "''''"]];
    if speed >= ScanSpeed::Thorough {
        series.push([r"\'", r"\\'", r"\\\'", r"\\\\'"]);
    }
    for s in series {
        // (database index, signature), database usize::MAX = Burp's "general
        // error" (burp.Zbpt via Zxp6, issue flag 8 -> description flag 64).
        let mut probe = |suffix: &str| {
            send(&format!("{value}{suffix}")).and_then(|raw| {
                let (st, body) = split_resp(&raw);
                sql_error_in(body, base_body).or_else(|| {
                    generic_error_in(st, body, base_status, base_body).map(|w| (usize::MAX, w))
                })
            })
        };
        let Some((db, _)) = probe(s[0]) else { continue };
        let second_clean = probe(s[1]).is_none();
        let hit = |confirmed| SqlErrorHit {
            database: if db == usize::MAX {
                "General"
            } else {
                SQL_ERRORS[db].0
            },
            payload: format!("{value}{}", s[0]),
            confirmed,
        };
        if db != 0 && db != usize::MAX {
            return Some(hit(second_clean));
        }
        if second_clean && probe(s[2]).is_some() && probe(s[3]).is_none() {
            return Some(hit(true));
        }
    }
    None
}

/// (status, body) of a raw response; a bare body string counts as a 200.
pub fn split_resp(raw: &str) -> (u16, &str) {
    if raw.starts_with("HTTP/") {
        let status = raw
            .split_whitespace()
            .nth(1)
            .and_then(|x| x.parse().ok())
            .unwrap_or(0);
        let body = raw
            .find("\r\n\r\n")
            .map(|i| &raw[i + 4..])
            .or_else(|| raw.find("\n\n").map(|i| &raw[i + 2..]))
            .unwrap_or("");
        (status, body)
    } else {
        (200, raw)
    }
}

/// burp.Ze27.Za, runtime-dumped: the "general error" words (case-insensitive).
pub const GENERIC_ERROR_WORDS: [&str; 6] =
    ["error", "exception", "illegal", "invalid", "fail", "stack"];

/// burp.Zbpt.ZJ: a new 5xx status, or a general error word the baseline
/// response did not contain.
pub fn generic_error_in(
    status: u16,
    body: &str,
    base_status: u16,
    base_body: &str,
) -> Option<&'static str> {
    // Without a baseline response there is nothing to compare against.
    if base_status == 0 && base_body.is_empty() {
        return None;
    }
    if (500..600).contains(&status) && !(500..600).contains(&base_status) {
        return Some("HTTP 5xx");
    }
    let low = body.to_ascii_lowercase();
    let base = base_body.to_ascii_lowercase();
    GENERIC_ERROR_WORDS
        .iter()
        .copied()
        .find(|w| low.contains(w) && !base.contains(w))
}

/// burp.Zguq subclasses: the boolean payload shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlBoolShape {
    /// burp.Zguz: `<r>{q} or {q}{n}{q}={q}{v}`
    Or,
    /// burp.Zgut: `<r>{q} or {n}={v}-- `
    OrComment,
    /// burp.Zgua: `{q} and {q}{n}{q}={q}{v}`
    And,
    /// burp.Zgu3: `{q} and {n}={v}-- `
    AndComment,
}

/// burp.Zguq: positive/negative payload generator for one shape and quote.
pub struct SqlBoolGen {
    shape: SqlBoolShape,
    quote: String,
    pos: usize,
    neg: usize,
}

impl SqlBoolGen {
    pub(crate) fn new(shape: SqlBoolShape, quote: &str) -> Self {
        SqlBoolGen {
            shape,
            quote: quote.to_string(),
            pos: 0,
            neg: 0,
        }
    }
    fn render(&self, r: u32, n: u32, v: &str) -> String {
        let q = &self.quote;
        match self.shape {
            SqlBoolShape::Or => format!("{r}{q} or {q}{n}{q}={q}{v}"),
            SqlBoolShape::OrComment => format!("{r}{q} or {n}={v}-- "),
            SqlBoolShape::And => format!("{q} and {q}{n}{q}={q}{v}"),
            SqlBoolShape::AndComment => format!("{q} and {n}={v}-- "),
        }
    }
    /// Zguq.ZS: n in [1000,10000) compared with itself; unquoted, every
    /// fourth (starting with the first) compares with "0n" (still equal).
    pub(crate) fn positive_with(&mut self, r: u32, n: u32) -> String {
        let quoted = !self.quote.is_empty();
        let v = if !quoted && self.pos.is_multiple_of(4) {
            format!("0{n}")
        } else {
            n.to_string()
        };
        self.pos += 1;
        self.render(r, n, &v)
    }
    /// Zguq.ZN: m in [1009,9990) compared with m+k (k in [1,10)); every
    /// fourth (the second, sixth, ...) with m+quote (quoted) or m+"0".
    pub(crate) fn negative_with(&mut self, r: u32, m: u32, k: u32) -> String {
        let v = if self.neg % 4 == 1 {
            if self.quote.is_empty() {
                format!("{m}0")
            } else {
                format!("{m}{}", self.quote)
            }
        } else {
            (m + k).to_string()
        };
        self.neg += 1;
        self.render(r, m, &v)
    }
    pub(crate) fn positive(&mut self) -> String {
        use rand::Rng;
        let mut g = rand::thread_rng();
        let (r, n) = (
            g.gen_range(10_000_000..100_000_000),
            g.gen_range(1000..10000),
        );
        self.positive_with(r, n)
    }
    pub(crate) fn negative(&mut self) -> String {
        use rand::Rng;
        let mut g = rand::thread_rng();
        let (r, m, k) = (
            g.gen_range(10_000_000..100_000_000),
            g.gen_range(1009..9990),
            g.gen_range(1..10),
        );
        self.negative_with(r, m, k)
    }
}

pub struct SqlBoolHit {
    pub positive: String,
    pub negative: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zppj.Zi -> ZL(""), ZL("'"), then the numeric pairs (Zppj.Zh).
/// String pairs are appended to the value (Zx4k mode 1); numeric pairs
/// replace it (mode 0). Each attempt runs Burp's differential engine.
/// The unquoted attempt is gated on Burp's insertion-point predicate
/// (Zgx0.ZO()/Zs(), not decompilable here); WebProbe uses "value is
/// numeric" for it (inferred).
pub fn run_sql_boolean_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    speed: ScanSpeed,
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<SqlBoolHit> {
    let numeric = !value.is_empty() && value.chars().all(|c| c.is_ascii_digit());
    let mut quotes: Vec<&str> = Vec::new();
    if numeric {
        quotes.push("");
    }
    quotes.push("'");
    let mut shapes = vec![SqlBoolShape::Or, SqlBoolShape::OrComment];
    if speed >= ScanSpeed::Normal {
        shapes.extend([SqlBoolShape::And, SqlBoolShape::AndComment]);
    }
    let sent = std::cell::RefCell::new(&mut send);
    for q in quotes {
        for shape in &shapes {
            let gen = std::cell::RefCell::new(SqlBoolGen::new(*shape, q));
            let (fp, fnn) = (
                std::cell::RefCell::new(None::<String>),
                std::cell::RefCell::new(None::<String>),
            );
            let attrs = crate::variations::differential(
                Some(baseline),
                accuracy,
                || {
                    let p = format!("{value}{}", gen.borrow_mut().positive());
                    fp.borrow_mut().get_or_insert_with(|| p.clone());
                    (sent.borrow_mut())(&p)
                },
                || {
                    let p = format!("{value}{}", gen.borrow_mut().negative());
                    fnn.borrow_mut().get_or_insert_with(|| p.clone());
                    (sent.borrow_mut())(&p)
                },
            );
            if let Some(attributes) = attrs {
                return Some(SqlBoolHit {
                    positive: fp.into_inner().unwrap_or_default(),
                    negative: fnn.into_inner().unwrap_or_default(),
                    attributes,
                });
            }
        }
    }
    // burp.Zppj.Zh: numeric pairs replacing the value (Zht3 cycles the lists).
    if speed >= ScanSpeed::Normal {
        const T: [&str; 4] = ["(select abs(1))", "(select 1)", "1", "000001"];
        const F: [&str; 4] = ["(select sba(1))", "(seletc 1)", "0", "100000"];
        let (ip, ineg) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
        let attrs = crate::variations::differential(
            Some(baseline),
            accuracy,
            || {
                let p = T[ip.get() % 4];
                ip.set(ip.get() + 1);
                (sent.borrow_mut())(p)
            },
            || {
                let p = F[ineg.get() % 4];
                ineg.set(ineg.get() + 1);
                (sent.borrow_mut())(p)
            },
        );
        if let Some(attributes) = attrs {
            return Some(SqlBoolHit {
                positive: T[0].into(),
                negative: F[0].into(),
                attributes,
            });
        }
    }
    None
}
