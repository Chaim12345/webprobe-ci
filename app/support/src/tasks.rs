//! Scan-task queue vocabulary shared by the core crates.

use crate::hist::HistEntry;

/// Collaborator ids for Burp's SMTP header injection check on one
/// parameter: `simple` and `enclosed` (burp.Zrok, Zpu2
/// SMTP_HEADER_INJECTION_SIMPLE_PAYLOAD / _ENCLOSED_PAYLOAD), each with the
/// public host its id lives under.
#[derive(Clone, Debug)]
pub struct SmtpOob {
    pub param: String,
    pub simple: (String, String),
    pub enclosed: (String, String),
}

/// What a queued task will do.
#[derive(Clone)]
pub enum TaskKind {
    /// Actively audit these requests.
    Audit(Vec<HistEntry>),
    /// Actively audit one request with Collaborator payloads the caller has
    /// already generated (per-parameter OOB slots and Burp's SMTP header
    /// injection pairs), as the "Do active scan" action does. Saved with a
    /// project as a plain `Audit`: payloads belong to the session.
    Single {
        entry: Box<HistEntry>,
        oob: Vec<(String, String, String)>,
        smtp: Vec<SmtpOob>,
    },
    /// Fetch the URLs, crawl from them unless `audit_only`, audit what is found.
    CrawlAudit { urls: Vec<String>, audit_only: bool },
}

/// Lifecycle state of a queued task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Queued,
    Running,
    Paused,
    Finished,
    Cancelled,
}

impl TaskState {
    pub fn label(self) -> &'static str {
        match self {
            TaskState::Queued => "Waiting to start",
            TaskState::Running => "Running",
            TaskState::Paused => "Paused",
            TaskState::Finished => "Finished",
            TaskState::Cancelled => "Cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            TaskState::Queued | TaskState::Running | TaskState::Paused
        )
    }
}

/// One queued scan task.
#[derive(Clone)]
pub struct ScanTask {
    pub id: u64,
    pub name: String,
    pub kind: TaskKind,
    pub state: TaskState,
    /// Requests audited so far and in all (Audit tasks; a crawl does not
    /// know its total in advance).
    pub done: usize,
    pub total: Option<usize>,
    /// Issues reported while the task ran.
    pub issues_found: usize,
    pub created: u64,
    pub finished: Option<u64>,
}
