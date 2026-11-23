//! Collaborator ids of the active scan (N-07): the payload pool the front
//! end keeps stocked, the ids each check registered, and the matching of
//! interactions against them. One owner, so registering, pooling and
//! matching go through these methods only.
//! Burp family SCANNER_ACTIVE_CHECKS_EXTERNAL_INTERACTION.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::collaborator::{CollaboratorState, Interaction};
use crate::sync::Mutex;
use webprobe_support::issues::ScanIssue;

/// Pending ids kept at most; the oldest are dropped beyond it (an id that
/// never sees its interaction must not be kept forever).
const MAX_PENDING: usize = 100_000;

/// One id a check embedded.
#[derive(Clone)]
struct Pending {
    id: String,
    /// The interaction that proves the check's own issue ("SMTP", "CNAME",
    /// "DNS"), or None: any interaction, raised per type as External
    /// service interaction.
    kind: Option<&'static str>,
    issue: ScanIssue,
    /// How the payload was delivered, in Burp's words (burp.Zez7.Ze: "<br><br>The
    /// payload <b>…</b> was submitted in the <b>q</b> parameter."), for the
    /// External service interaction text (burp.Zwfn.Zf).
    delivery: String,
}

#[derive(Default)]
pub struct OobState {
    pending: Mutex<Vec<Pending>>,
    /// "id|kind" pairs already raised as External service interaction.
    reported: Mutex<HashSet<String>>,
    /// Highest interaction id already matched.
    seen: AtomicU64,
    /// Pre-minted (id, payload domain) pairs for scans off the UI thread.
    pool: Mutex<Vec<(String, String)>>,
    /// A scan off the UI thread wants payloads.
    wanted: AtomicBool,
    /// A front end with a Collaborator keeps the pool stocked.
    supplier: AtomicBool,
    /// Ids a waiting `take` needs: `refill` stocks at least this many.
    demand: std::sync::atomic::AtomicUsize,
    /// Interactions seen by `match_new` (last 2000), for extensions'
    /// Collaborator clients (Montoya `getAllInteractions`).
    observed: Mutex<Vec<Interaction>>,
}

impl OobState {
    /// Register an id a check embedded; `kind` is the interaction that
    /// proves it (None: any, raised per interaction type).
    pub fn register(&self, id: String, kind: Option<&'static str>, issue: ScanIssue) {
        self.register_delivered(id, kind, issue, String::new());
    }

    /// [`OobState::register`] with Burp's delivery sentence for the
    /// External service interaction issue an interaction of another kind
    /// raises (see [`delivery_sentence`]).
    pub fn register_delivered(
        &self,
        id: String,
        kind: Option<&'static str>,
        issue: ScanIssue,
        delivery: String,
    ) {
        let mut pending = self.pending.lock().unwrap();
        pending.push(Pending {
            id,
            kind,
            issue,
            delivery,
        });
        let excess = pending.len().saturating_sub(MAX_PENDING);
        pending.drain(..excess);
    }

    /// Replace the evidence of a pending id once its probe's response is in.
    pub fn set_evidence(&self, id: &str, evidence: Vec<webprobe_support::issues::ScanEvidence>) {
        if let Some(p) = self
            .pending
            .lock()
            .unwrap()
            .iter_mut()
            .find(|p| p.id == id && p.kind.is_none())
        {
            p.issue.evidence = evidence;
        }
    }

    /// (id, kind, issue) of every pending id, for tests and the Dashboard.
    pub fn pending(&self) -> Vec<(String, Option<&'static str>, ScanIssue)> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|p| (p.id.clone(), p.kind, p.issue.clone()))
            .collect()
    }

    pub fn is_pending_empty(&self) -> bool {
        self.pending.lock().unwrap().is_empty()
    }

    /// This process has a front end that stocks the pool.
    pub fn set_supplier(&self, on: bool) {
        self.supplier.store(on, Ordering::SeqCst);
    }

    /// Ask (or stop asking) the supplier for payloads.
    pub fn want(&self, on: bool) {
        self.wanted.store(on, Ordering::SeqCst);
    }

    pub fn is_wanted(&self) -> bool {
        self.wanted.load(Ordering::SeqCst)
    }

    /// Top the pool up to `high` with `mint` when it is below `low`.
    /// Below `low`, or below what a waiting `take` needs, the pool is
    /// stocked up to the larger of `high` and that need.
    pub fn refill(&self, low: usize, high: usize, mut mint: impl FnMut() -> (String, String)) {
        let need = self.demand.load(Ordering::SeqCst);
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < low || pool.len() < need {
            let target = high.max(need);
            while pool.len() < target {
                pool.push(mint());
            }
        }
    }

    /// Put payloads into the pool directly (tests, headless suppliers).
    pub fn stock(&self, items: impl IntoIterator<Item = (String, String)>) {
        self.pool.lock().unwrap().extend(items);
    }

    pub fn pool_len(&self) -> usize {
        self.pool.lock().unwrap().len()
    }

    /// Take `n` payloads, waiting up to `wait` for a supplier that was asked
    /// to stock enough. Returns what it got: fewer than `n` when the pool
    /// runs short (the caller reports the shortfall).
    pub fn take(&self, n: usize, wait: Duration) -> Vec<(String, String)> {
        let deadline = Instant::now() + wait;
        if self.pool_len() < n {
            // Tell the supplier how many are needed: its low-water refill
            // alone would never stock a request needing more than that.
            self.demand.fetch_max(n, Ordering::SeqCst);
        }
        while self.supplier.load(Ordering::SeqCst)
            && self.is_wanted()
            && self.pool_len() < n
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(25));
        }
        self.demand.store(0, Ordering::SeqCst);
        let mut pool = self.pool.lock().unwrap();
        let k = n.min(pool.len());
        let at = pool.len() - k;
        pool.split_off(at).into_iter().rev().collect()
    }

    /// Match the interactions `collab` recorded since the last call (cheap
    /// every frame: only new ones are looked at). Returns the issues proved.
    pub fn match_new(&self, collab: &CollaboratorState) -> Vec<ScanIssue> {
        let fresh = collab.interactions_since(self.seen.load(Ordering::SeqCst));
        let Some(last) = fresh.last().map(|i| i.id) else {
            return Vec::new();
        };
        self.seen.store(last, Ordering::SeqCst);
        self.observe(&fresh);
        self.match_interactions(&fresh)
    }

    /// Keep interactions for extensions' Collaborator clients.
    pub fn observe(&self, fresh: &[Interaction]) {
        let mut o = self.observed.lock().unwrap();
        o.extend(fresh.iter().cloned());
        let excess = o.len().saturating_sub(2000);
        o.drain(..excess);
    }

    /// The interactions whose payload id is one of `ids`.
    pub fn observed_for(&self, ids: &[String]) -> Vec<Interaction> {
        self.observed
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.token.as_ref().is_some_and(|t| ids.contains(t)))
            .cloned()
            .collect()
    }

    /// Match interactions against the pending ids. A check that names its
    /// own issue (SMTP header injection, XML injection, OS command
    /// injection) waits for one interaction of its kind. The plain
    /// external-interaction probe raises one issue per interaction type, as
    /// Burp does ("External service interaction (DNS)" and "(HTTP)", high,
    /// certain), so its id stays pending until both have been seen.
    pub fn match_interactions(&self, interactions: &[Interaction]) -> Vec<ScanIssue> {
        let mut issues = Vec::new();
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            return issues;
        }
        let mut reported = self.reported.lock().unwrap();
        for it in interactions {
            let Some(token) = &it.token else { continue };
            let kind = it.kind().label();
            // "CNAME": a DNS lookup of type CNAME, which only the injected
            // `nslookup -q=cname` makes (burp.Zing.ZR: DNS and type 5).
            let cname = it.dns().is_some_and(|d| d.qtype == 5);
            let fits = |k: &str| k == kind || (k == "CNAME" && cname);
            let Some(pos) = pending
                .iter()
                .position(|p| &p.id == token && p.kind.is_none_or(fits))
            else {
                // An OS-command id that saw some other interaction (an A
                // lookup, an HTTP fetch): Burp reports External service
                // interaction for it (burp.Zfw7.Zr: not Zing.ZR -> Zuet.ZJ)
                // and keeps waiting for the CNAME.
                if let Some(p) = pending
                    .iter()
                    .find(|p| &p.id == token && p.kind == Some("CNAME"))
                {
                    if (kind == "DNS" || kind == "HTTP")
                        && reported.insert(format!("{token}|{kind}"))
                    {
                        let mut issue = p.issue.clone();
                        issue.name = format!("External service interaction ({kind})");
                        issue.sev = "high".into();
                        issue.confidence = "Certain".into();
                        issue.type_id = 0;
                        issue.detail = interaction_detail(kind, &p.delivery, it);
                        issues.push(issue);
                    }
                }
                continue;
            };
            if pending[pos].kind.is_some() {
                let mut issue = pending.remove(pos).issue;
                issue.detail = format!(
                    "{}<br><br>Collaborator interaction observed: {} (source {}).",
                    issue.detail,
                    it.headline(),
                    it.source
                );
                issues.push(issue);
                continue;
            }
            if !reported.insert(format!("{token}|{kind}")) {
                continue;
            }
            let mut issue = pending[pos].issue.clone();
            issue.name = format!("External service interaction ({kind})");
            issue.sev = "high".into();
            issue.confidence = "Certain".into();
            issue.detail = interaction_detail(kind, &pending[pos].delivery, it);
            issues.push(issue);
            if reported.contains(&format!("{token}|DNS"))
                && reported.contains(&format!("{token}|HTTP"))
            {
                pending.remove(pos);
            }
        }
        issues
    }
}

/// burp.Zez7.Ze, the delivery sentence for a payload: "<br><br>The payload
/// <b>x.oast</b> was submitted in the <b>q</b> parameter." (the point in
/// Zsg0.Zj wording, `point`); `lead` names the payload ("The payload",
/// "The nslookup shell command", ...), `tail` is the payload type's own
/// ending (burp.Zez7.ZC; "." for a plain URL payload).
pub fn delivery_sentence(lead: &str, payload: &str, point: &str, tail: &str) -> String {
    format!(
        "<br><br>{lead} <b>{}</b> was submitted in the {point}{tail}",
        crate::util::html_encode(payload)
    )
}

/// burp.Zwfn.Zf: "It is possible to induce the application to perform
/// server-side DNS lookups of arbitrary domain names." + the delivery +
/// "<br><br>The application performed a DNS lookup of the specified
/// domain." (strings decoded from Zwfn.b / Zuet). WebProbe adds the
/// interaction it saw.
fn interaction_detail(kind: &str, delivery: &str, it: &Interaction) -> String {
    let (can, did) = match kind {
        "DNS" => (
            "perform server-side DNS lookups of arbitrary domain names.",
            "performed a DNS lookup of the specified domain",
        ),
        "HTTP" => (
            "perform server-side HTTP requests to arbitrary domains.",
            "performed an HTTP request to the specified domain",
        ),
        "SMTP" => (
            "send emails via SMTP to arbitrary addresses.",
            "sent an email via SMTP to the specified address",
        ),
        _ => (
            "perform server-side interactions with arbitrary domains.",
            "performed an interaction with the specified domain",
        ),
    };
    format!(
        "It is possible to induce the application to {can}{delivery}<br><br>The application {did}.<br><br>Collaborator interaction: {} (source {}).",
        it.headline(),
        it.source
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_hands_out_what_there_is_and_waits_only_when_asked() {
        let oob = OobState::default();
        oob.stock((0..3).map(|i| (format!("t{i}"), format!("t{i}.oast.test"))));
        let t0 = Instant::now();
        assert_eq!(
            oob.take(5, Duration::from_secs(5)).len(),
            3,
            "short pool: what is there, no wait without a supplier"
        );
        assert!(t0.elapsed() < Duration::from_secs(1));
        oob.set_supplier(true);
        oob.want(true);
        let t0 = Instant::now();
        assert!(oob.take(2, Duration::from_millis(200)).is_empty());
        assert!(
            t0.elapsed() >= Duration::from_millis(150),
            "an asked supplier gets its time"
        );
        let mut n = 0;
        oob.refill(10, 20, || {
            n += 1;
            (format!("m{n}"), format!("m{n}.oast.test"))
        });
        assert_eq!(oob.pool_len(), 20);
        oob.refill(10, 20, || unreachable!("above the low mark: no refill"));
        assert_eq!(oob.take(4, Duration::ZERO).len(), 4);
        // A request needing more than the pool holds (16 of 30): the waiting
        // take's demand makes the next refill stock enough.
        let o2 = std::sync::Arc::new(OobState::default());
        o2.set_supplier(true);
        o2.want(true);
        o2.stock((0..16).map(|i| (format!("s{i}"), String::new())));
        let taker = {
            let o = o2.clone();
            std::thread::spawn(move || o.take(30, Duration::from_secs(5)).len())
        };
        while o2.demand.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut k = 0;
        o2.refill(10, 20, || {
            k += 1;
            (format!("r{k}"), String::new())
        });
        assert_eq!(taker.join().unwrap(), 30, "the demand was stocked");
    }

    #[test]
    fn external_interaction_text_names_the_point_as_burp_does() {
        use crate::collaborator::{DnsInteraction, InteractionDetail};
        let oob = OobState::default();
        let issue = ScanIssue {
            name: "pending".into(),
            ..Default::default()
        };
        let delivery = delivery_sentence("The payload", "abc.oast.test", "<b>q</b> parameter", ".");
        oob.register_delivered("abc".into(), None, issue.clone(), delivery);
        let kept = ScanIssue {
            detail: "The value of the q request parameter: x".into(),
            ..issue
        };
        oob.register_delivered("cmd".into(), Some("CNAME"), kept, delivery_sentence("The nslookup shell command", "nslookup -q=cname cmd.oast", "<b>q</b> parameter", ". This payload is designed to trigger a CNAME DNS lookup if the application is vulnerable to OS command injection."));
        let dns = |token: &str, qtype| Interaction {
            id: 1,
            at: 0,
            source: "192.0.2.1".into(),
            token: Some(token.into()),
            detail: InteractionDetail::Dns(DnsInteraction {
                qname: format!("{token}.oast.test"),
                qtype,
                raw_query: Vec::new(),
            }),
        };
        let got = oob.match_interactions(&[dns("abc", 1)]);
        assert!(
            got[0].detail.starts_with("It is possible to induce the application to perform server-side DNS lookups of arbitrary domain names.<br><br>The payload <b>abc.oast.test</b> was submitted in the <b>q</b> parameter.<br><br>The application performed a DNS lookup of the specified domain."),
            "{}",
            got[0].detail
        );
        // The nslookup id's A lookup (burp.Zfw7.Zr) uses the nslookup wording.
        let got = oob.match_interactions(&[dns("cmd", 1)]);
        assert!(got[0].detail.contains("The nslookup shell command <b>nslookup -q=cname cmd.oast</b> was submitted in the <b>q</b> parameter. This payload is designed"), "{}", got[0].detail);
        // Its CNAME keeps the check's own text and adds the interaction.
        let got = oob.match_interactions(&[dns("cmd", 5)]);
        assert!(
            got[0].detail.starts_with(
                "The value of the q request parameter: x<br><br>Collaborator interaction observed:"
            ),
            "{}",
            got[0].detail
        );
    }
}
