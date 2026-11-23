// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

pub fn intercept_request(
    shared: &Shared,
    req: Vec<u8>,
    default_port: u16,
) -> (Option<Vec<u8>>, ReqState) {
    if !shared.intercept_on.load(Ordering::SeqCst) {
        return (Some(req), ReqState::default());
    }
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, default_port);
    {
        let head = parts.head_len.min(req.len());
        let url = history_host(&HistEntry {
            host: host.clone(),
            port,
            https: default_port == 443,
            ..Default::default()
        }) + &path_of(&parts);
        let facts = crate::intercept_rules::Facts {
            in_scope: in_scope(shared, &url),
            domain: host.clone(),
            method: parts.method.clone(),
            extension: crate::intercept_rules::extension_of(&parts.path),
            headers: String::from_utf8_lossy(&req[..head]).into_owned(),
            body: String::from_utf8_lossy(&req[head..]).into_owned(),
            has_parameters: parts.path.contains('?') || req.len() > head,
            url,
        };
        if !crate::intercept_rules::should_intercept(
            &shared.intercept_rules.lock().unwrap(),
            &facts,
        ) {
            return (Some(req), ReqState::default());
        }
    }
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let id = shared.next_queue_item_id();
    let shown = String::from_utf8_lossy(&req).into_owned();
    shared.queue.lock().unwrap().push(InterceptItem::new(
        id,
        &host,
        port,
        shown.clone(),
        tx,
        InterceptKind::Request {
            https: default_port == 443,
        },
    ));
    shared.wake();
    match rx.recv() {
        Ok(Some(edited)) => {
            let (bytes, changed) = forwarded(req, &shown, edited);
            (
                Some(bytes),
                ReqState {
                    edited: changed,
                    held: true,
                },
            )
        }
        Ok(None) => {
            shared.log("Intercepted request dropped");
            (
                None,
                ReqState {
                    edited: false,
                    held: true,
                },
            )
        }
        Err(_) => (
            None,
            ReqState {
                edited: false,
                held: true,
            },
        ),
    }
}

/// Hold a response that the response interception rules select, as Burp
/// does: the user forwards (possibly edited) or drops it.
pub fn intercept_response(
    shared: &Shared,
    resp: Vec<u8>,
    host: &str,
    port: u16,
    https: bool,
    url: &str,
    st: ReqState,
) -> Option<Vec<u8>> {
    if !shared.intercept_on.load(Ordering::SeqCst) {
        return Some(resp);
    }
    let p = util::parse_http(&resp);
    let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
    let status = p.status.split_whitespace().next().unwrap_or("").to_string();
    let rules = shared.response_rules.lock().unwrap().clone();
    if !rules.matches(&ct, &status, st, rules.in_scope && in_scope(shared, url)) {
        return Some(resp);
    }
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let id = shared.next_queue_item_id();
    let shown = String::from_utf8_lossy(&resp).into_owned();
    shared.queue.lock().unwrap().push(InterceptItem::new(
        id,
        host,
        port,
        shown.clone(),
        tx,
        InterceptKind::Response { https },
    ));
    shared.wake();
    match rx.recv() {
        Ok(Some(edited)) => Some(forwarded(resp, &shown, edited).0),
        _ => {
            shared.log("Intercepted response dropped");
            None
        }
    }
}

/// Turn interception on or off. Off releases every held message unchanged
/// (forwarded with its current content), as Burp does when the toggle goes
/// off. The one place the toggle changes (UI, extensions).
pub fn set_intercept(shared: &Shared, on: bool) -> usize {
    shared.intercept_on.store(on, Ordering::SeqCst);
    if on {
        return 0;
    }
    let n = intercept_release_all(shared, false);
    if n > 0 {
        shared.log(&format!(
            "Interception turned off: forwarded {n} held message(s)"
        ));
    }
    n
}

/// Wait for the user's verdict on held message `id`. Returns early (None,
/// and the item leaves the queue) when `alive` says the connection is gone;
/// the toggle going off and shutdown answer through the queue
/// ([`set_intercept`], [`intercept_release_all`]).
pub(crate) fn intercept_wait(
    shared: &Shared,
    id: u64,
    rx: &mpsc::Receiver<Option<String>>,
    alive: &dyn Fn() -> bool,
) -> Option<String> {
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(v) => return v,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !alive() {
                    shared.queue.lock().unwrap().retain(|i| i.id != id);
                    shared.wake();
                    return None;
                }
            }
        }
    }
}

/// Burp's "Forward all" / "Drop all" (burp.Zub8 / Zubj): release every held
/// message at once, each with its current (possibly edited) content.
pub fn intercept_release_all(shared: &Shared, drop: bool) -> usize {
    let items: Vec<_> = shared.queue.lock().unwrap().drain(..).collect();
    let n = items.len();
    for item in items {
        let payload = if drop {
            None
        } else {
            Some(item.edited.clone())
        };
        let _ = item.tx.send(payload);
    }
    n
}

/// Forward (drop=false) or drop (drop=true) the first held intercepted request.
pub fn intercept_forward(shared: &Arc<Shared>, drop: bool) {
    let mut q = shared.queue.lock().unwrap();
    if q.is_empty() {
        return;
    }
    let item = q.remove(0);
    let payload = if drop {
        None
    } else {
        Some(item.edited.clone())
    };
    let _ = item.tx.send(payload);
}

/// Release one held message by id (the row selected in the intercept table):
/// forwarded with `edited` when given (else its stored content), or dropped.
/// False when the message is no longer held.
pub fn intercept_release(shared: &Shared, id: u64, drop: bool, edited: Option<String>) -> bool {
    let item = {
        let mut q = shared.queue.lock().unwrap();
        match q.iter().position(|i| i.id == id) {
            Some(pos) => q.remove(pos),
            None => return false,
        }
    };
    let payload = if drop {
        None
    } else {
        Some(edited.unwrap_or(item.edited))
    };
    let _ = item.tx.send(payload);
    true
}
