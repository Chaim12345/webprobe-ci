// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Requests one Intruder attack will send before the cap kicks in (N-04 guard).
pub const INTRUDER_REQUEST_LIMIT: usize = 100_000;

/// Start an Intruder attack of any type (C-01): the request matrix comes from
/// `intruder::requests`, so Sniper, Battering ram, Pitchfork and Cluster bomb all
/// run through this one runner. `sets` is one payload list per position (Sniper
/// and Battering ram use only the first). Payloads are one per line; the `§`
/// markers never reach the wire (the template strips them).
pub fn start_attack(
    shared: Arc<Shared>,
    template: String,
    kind: crate::intruder::AttackType,
    sets: Vec<Vec<String>>,
    https: bool,
) -> Result<(), NetError> {
    let parsed = crate::intruder::Template::parse(&template)?;
    let rows = crate::intruder::requests(&parsed, kind, &sets, INTRUDER_REQUEST_LIMIT)
        .map_err(NetError::Requests)?;

    let cur = shared.attack.lock().unwrap().clone();
    cur.rows.lock().unwrap().clear();
    cur.done.store(0, Ordering::SeqCst);
    cur.total.store(rows.len(), Ordering::SeqCst);
    cur.stop.store(false, Ordering::SeqCst);
    cur.running.store(true, Ordering::SeqCst);
    shared.log(&format!(
        "Intruder attack started: {} ({}) x {} request(s)",
        kind.label(),
        parsed.positions(),
        rows.len()
    ));

    crate::util::spawn_contained("net", move || {
        for attack in rows {
            if cur.stop.load(Ordering::SeqCst) {
                break;
            }
            let payload = attack
                .payloads
                .iter()
                .filter_map(|p| p.clone())
                .collect::<Vec<_>>()
                .join(", ");
            let parts = util::parse_http(attack.request.as_bytes());
            let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
            if host_header.is_empty() {
                cur.rows.lock().unwrap().push(AttackRow {
                    payload,
                    status: String::new(),
                    len: 0,
                    ms: 0,
                    ok: false,
                    req: attack.request.clone().into_bytes(),
                    resp: None,
                });
                cur.done.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            let (host, port) = split_host_port(&host_header, if https { 443 } else { 80 });
            let t0 = Instant::now();
            let up = if https {
                send_tls_raw(&shared, &host, port, attack.request.as_bytes())
            } else {
                send_raw(&shared, &host, port, attack.request.as_bytes())
            };
            let ms = t0.elapsed().as_millis();
            let req_bytes = attack.request.clone().into_bytes();
            cur.rows.lock().unwrap().push(match up.resp {
                Some(resp) => {
                    let st = util::parse_http(&resp)
                        .first
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_string();
                    AttackRow {
                        payload,
                        status: st,
                        len: resp.len(),
                        ms,
                        ok: true,
                        req: req_bytes,
                        resp: Some(resp),
                    }
                }
                None => AttackRow {
                    payload,
                    status: String::new(),
                    len: 0,
                    ms,
                    ok: false,
                    req: req_bytes,
                    resp: None,
                },
            });
            cur.done.fetch_add(1, Ordering::SeqCst);
            // Gentle pacing so one bad host does not hammer (500 ms default throttle
            // from ProjectDefaults.json resource pool; C-06 turns this into a pool).
            std::thread::sleep(Duration::from_millis(50));
        }
        cur.running.store(false, Ordering::SeqCst);
        shared.log("Intruder attack finished");
    });
    Ok(())
}
