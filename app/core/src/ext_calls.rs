//! What a Montoya extension may ask of WebProbe's engine (R-03 stages 4-5):
//! the `{"type":"call","op":..}` requests of the sidecar bridge. Each op is
//! answered from the engine's own state: proxy history and intercept, the
//! Target scope, the site map, the issue list, Repeater tabs, the
//! Organizer and the session cookie jar. What goes to Intruder, Comparer
//! and Decoder (desktop state) waits in `Shared::tool_sends`.

use std::sync::atomic::Ordering;

use serde_json::{json, Value};

use crate::net::{HistEntry, Shared};
use crate::util;

pub use webprobe_support::ext::ToolSend;

/// The Intruder payload generators of the enabled extensions, by name.
pub fn payload_generators(shared: &Shared) -> Vec<String> {
    let exts = crate::ext_host::active_hooks(shared);
    let mut names: Vec<String> = exts
        .iter()
        .filter_map(|e| e.ui())
        .flat_map(|u| u.generators)
        .collect();
    names.dedup();
    names
}

/// Fetch the payloads of every "Extension-generated" set of an attack on
/// `request` (Burp asks the generator when the attack starts; it gets the
/// base value of the first position).
pub fn fill_extension_payloads(
    shared: &Shared,
    request: &str,
    sources: &mut [crate::intruder::PayloadSource],
) -> Result<(), String> {
    if !sources
        .iter()
        .any(|s| matches!(s, crate::intruder::PayloadSource::Extension { .. }))
    {
        return Ok(());
    }
    let template = crate::intruder::Template::parse(request)?;
    let base = template
        .position_values()
        .first()
        .cloned()
        .unwrap_or_default();
    let exts = crate::ext_host::active_hooks(shared);
    for src in sources.iter_mut() {
        let crate::intruder::PayloadSource::Extension { provider, payloads } = src else {
            continue;
        };
        let ext = exts
            .iter()
            .find(|e| {
                e.ui()
                    .is_some_and(|u| u.generators.iter().any(|g| g == provider))
            })
            .ok_or_else(|| {
                format!("No loaded extension provides the payload generator {provider}")
            })?;
        *payloads = ext.generate_payloads(provider, request.as_bytes(), &base)?;
    }
    Ok(())
}

/// Run each payload set through the extension payload processor chosen
/// for it (`processors[i]` for set i, "" = none), as Burp's "Invoke Burp
/// extension" processing rule: the processor sees each payload with the
/// base value of its position and may change or skip it. Copy-other and
/// recursive-grep sets are made while the attack runs and are not
/// processed.
pub fn apply_extension_processors(
    shared: &Shared,
    template: &crate::intruder::Template,
    specs: &mut [crate::intruder::SetSpec],
    processors: &[String],
) -> Result<(), String> {
    use crate::intruder::SetSpec;
    if processors.iter().all(String::is_empty) {
        return Ok(());
    }
    let exts = crate::ext_host::active_hooks(shared);
    let bases = template.position_values();
    for (spec, name) in specs.iter_mut().zip(processors) {
        if name.is_empty() {
            continue;
        }
        let ext = exts
            .iter()
            .find(|e| {
                e.ui()
                    .is_some_and(|u| u.processors.iter().any(|p| p == name))
            })
            .ok_or_else(|| format!("No loaded extension provides the payload processor {name}"))?;
        match spec {
            SetSpec::List(list) => {
                *list =
                    ext.process_payloads(name, list, bases.first().map_or("", String::as_str))?
            }
            SetSpec::PerPosition(lists) => {
                for (k, list) in lists.iter_mut().enumerate() {
                    *list =
                        ext.process_payloads(name, list, bases.get(k).map_or("", String::as_str))?;
                }
            }
            SetSpec::Copy(_) | SetSpec::Recursive { .. } => {}
        }
    }
    Ok(())
}

fn origin(v: &Value) -> (String, bool) {
    let https = v["secure"].as_bool().unwrap_or(false);
    let host = v["host"].as_str().unwrap_or_default();
    let port = v["port"].as_u64().unwrap_or(if https { 443 } else { 80 });
    let dflt = port == if https { 443 } else { 80 };
    let scheme = if https { "https" } else { "http" };
    (
        if host.is_empty() {
            String::new()
        } else if dflt {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        },
        https,
    )
}

fn entry_json(e: &HistEntry) -> Value {
    let mut v = json!({
        "id": e.id, "request": util::b64_encode(&e.req_raw), "host": e.host, "port": e.port, "secure": e.https,
        "notes": e.note.clone().unwrap_or_default(), "edited": e.edited, "time": e.ts, "listenerPort": e.listener_port,
        "highlight": e.highlight.and_then(|i| crate::ext_host::HIGHLIGHT_COLOURS.get(i as usize).copied()),
    });
    if let Some(r) = &e.resp_raw {
        v["response"] = util::b64_encode(r).into();
    }
    v
}

/// A message an extension handed over, as a history entry.
fn entry_of(v: &Value) -> Option<HistEntry> {
    let req = b64(v, "request")?;
    let parts = util::parse_http(&req);
    let resp = b64(v, "response");
    let mut e = HistEntry {
        method: parts.method.clone(),
        host: v["host"].as_str().unwrap_or_default().to_string(),
        port: v["port"].as_u64().unwrap_or(80) as u16,
        https: v["secure"].as_bool().unwrap_or(false),
        path: parts.path.clone(),
        status: resp
            .as_ref()
            .map(|r| util::parse_http(r).status)
            .unwrap_or_default(),
        resp_len: resp.as_ref().map_or(0, Vec::len),
        req_raw: req.into(),
        resp_raw: resp.map(Into::into),
        ts: util::now_secs(),
        ..Default::default()
    };
    e.id = 0;
    Some(e)
}

fn b64(v: &Value, k: &str) -> Option<Vec<u8>> {
    let s = v[k].as_str()?;
    util::b64_decode(s).ok()
}

/// The host link to a running WebProbe for a sidecar or helper process:
/// sends with net::send_raw / send_tls_raw, events to the event log, engine
/// calls to dispatch. Holds the engine weakly (the engine owns its
/// extensions).
pub fn host_link(shared: &std::sync::Arc<Shared>) -> std::sync::Arc<crate::ext_host::HostLink> {
    let (a, b, c) = (
        std::sync::Arc::downgrade(shared),
        std::sync::Arc::downgrade(shared),
        std::sync::Arc::downgrade(shared),
    );
    std::sync::Arc::new(crate::ext_host::HostLink {
        send: Box::new(move |svc, req| {
            let shared = a.upgrade().ok_or("WebProbe is shutting down")?;
            let up = if svc.secure {
                crate::net::send_tls_raw(&shared, &svc.host, svc.port, req)
            } else {
                crate::net::send_raw(&shared, &svc.host, svc.port, req)
            };
            up.resp
                .ok_or_else(|| up.error.unwrap_or_else(|| "no response".into()))
        }),
        event: Box::new(move |level, msg| {
            if let Some(shared) = b.upgrade() {
                shared.log(&format!("Extension event ({level}): {msg}"));
            }
        }),
        call: Box::new(move |ext, op, args| {
            let shared = c.upgrade().ok_or("WebProbe is shutting down")?;
            dispatch(&shared, ext, op, args)
        }),
    })
}

pub use crate::ext_host::issue_of;

/// Answer one call from the extension `extension`.
pub fn dispatch(shared: &Shared, extension: &str, op: &str, args: &Value) -> Result<Value, String> {
    match op {
        "proxy.history" => Ok(Value::Array(shared.history.with_rows(|rows| rows.iter().map(entry_json).collect()))),
        "proxy.ws-history" => Ok(Value::Array(
            shared.ws_history.with_rows(|rows| rows.iter().map(|w| json!({"id": w.id, "time": w.ts, "host": w.host, "direction": w.direction, "opcode": w.opcode, "payload": w.text(), "bytes": util::b64_encode(&w.payload)})).collect()),
        )),
        "proxy.intercept" => {
            crate::net::set_intercept(shared, args["on"].as_bool().unwrap_or(false));
            shared.wake();
            Ok(Value::Null)
        }
        "proxy.intercept-state" => Ok(shared.intercept_on.load(Ordering::SeqCst).into()),
        "scope.in" => Ok(crate::net::in_scope(shared, args["url"].as_str().unwrap_or_default()).into()),
        "scope.include" | "scope.exclude" => {
            let url = args["url"].as_str().unwrap_or_default().to_string();
            let mut rule = crate::net::ScopeRule::include(url, false);
            rule.include = op == "scope.include";
            shared.scope.lock().unwrap().push(rule);
            shared.wake();
            Ok(Value::Null)
        }
        "sitemap.items" => {
            let mut v: Vec<Value> = shared.history.with_rows(|rows| rows.iter().map(entry_json).collect());
            v.extend(shared.crawl_items.with_rows(|rows| rows.iter().map(entry_json).collect::<Vec<_>>()));
            Ok(Value::Array(v))
        }
        "sitemap.add" => {
            let mut e = entry_of(args).ok_or("no request")?;
            e.id = shared.next_crawl_id.fetch_add(1, Ordering::SeqCst);
            shared.crawl_items.push(e);
            shared.wake();
            Ok(Value::Null)
        }
        "scanner.issues" => Ok(Value::Array(
            shared
                .issues
                .lock()
                .unwrap()
                .iter()
                .map(|i| json!({"name": i.name, "detail": i.detail, "severity": i.sev, "confidence": i.confidence, "baseUrl": format!("https://{}{}", i.host, i.path)}))
                .collect(),
        )),
        "scanner.add-issues" => {
            let issues = args["issues"].as_array().map(|a| a.iter().map(|i| issue_of(i, extension)).collect()).unwrap_or_default();
            crate::scan::add_issues(shared, issues);
            Ok(Value::Null)
        }
        "repeater.send" => {
            let req = b64(args, "request").ok_or("no request")?;
            let id = shared.rep.new_tab_id();
            let name = args["name"].as_str().filter(|n| !n.is_empty()).map(str::to_string).unwrap_or_else(|| id.to_string());
            shared.repeaters.lock().unwrap().push(crate::net::RepTab {
                id,
                name,
                host: args["host"].as_str().unwrap_or_default().to_string(),
                port: args["port"].as_u64().unwrap_or(80) as u16,
                https: args["secure"].as_bool().unwrap_or(false),
                request: String::from_utf8_lossy(&req).into_owned(),
                response: None,
                result_line: String::new(),
                history: Vec::new(),
                response_sources: Vec::new(),
                hist_pos: 0,
            ws: None,
            });
            shared.wake();
            Ok(Value::Null)
        }
        "intruder.send" => {
            let req = b64(args, "request").ok_or("no request")?;
            let (target, https) = origin(args);
            shared.tool_sends.lock().unwrap().push(ToolSend::Intruder { request: String::from_utf8_lossy(&req).into_owned(), target, https });
            shared.wake();
            Ok(Value::Null)
        }
        "comparer.send" | "decoder.send" => {
            let items: Vec<String> = args["items"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(|x| util::b64_decode(x).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).collect()).unwrap_or_default();
            let mut sends = shared.tool_sends.lock().unwrap();
            for item in items {
                sends.push(if op == "decoder.send" { ToolSend::Decoder(item) } else { ToolSend::Comparer(item) });
            }
            drop(sends);
            shared.wake();
            Ok(Value::Null)
        }
        "organizer.send" => {
            let req = b64(args, "request").ok_or("no request")?;
            let resp = b64(args, "response").unwrap_or_default();
            let parts = util::parse_http(&req);
            let name = format!("{} {}", parts.method, parts.path);
            shared.organizer.lock().unwrap().add(&name, "", &String::from_utf8_lossy(&req), &String::from_utf8_lossy(&resp), util::now_secs());
            shared.wake();
            Ok(Value::Null)
        }
        "organizer.items" => Ok(Value::Array(
            shared.organizer.lock().unwrap().list().into_iter().map(|i| {
                let host = i.request.lines().skip(1).take_while(|l| !l.is_empty()).find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string())).unwrap_or_default();
                let (h, port) = match host.rsplit_once(':') {
                    Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
                    _ => (host.clone(), 80),
                };
                let mut v = json!({"id": i.id, "request": util::b64_encode(i.request.as_bytes()), "host": h, "port": port, "secure": port == 443, "notes": i.note});
                if !i.response.is_empty() {
                    v["response"] = util::b64_encode(i.response.as_bytes()).into();
                }
                v
            }).collect(),
        )),
        "cookiejar.cookies" => Ok(Value::Array(
            shared.cookie_jar.lock().unwrap().cookies.iter().map(|c| json!({"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "expires": c.expires})).collect(),
        )),
        "cookiejar.set" => {
            let mut jar = shared.cookie_jar.lock().unwrap();
            let name = args["name"].as_str().unwrap_or_default().to_string();
            let domain = args["domain"].as_str().unwrap_or_default().trim_start_matches('.').to_ascii_lowercase();
            let path = args["path"].as_str().unwrap_or("/").to_string();
            jar.cookies.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
            jar.cookies.push(crate::cookie_jar::Cookie {
                domain,
                host_only: false,
                path,
                name,
                value: args["value"].as_str().unwrap_or_default().to_string(),
                secure: false,
                expires: args["expires"].as_u64(),
            });
            Ok(Value::Null)
        }
        "collab.payload" => {
            shared.oob.want(true);
            let got = shared.oob.take(1, std::time::Duration::from_secs(5));
            let Some((id, payload)) = got.into_iter().next() else {
                return Err("No Collaborator payload is available: configure a Collaborator server in WebProbe's Collaborator tab".into());
            };
            let server = payload.split_once('.').map(|x| x.1.to_string()).unwrap_or_default();
            Ok(json!({"id": id, "payload": payload, "server": server}))
        }
        "collab.interactions" => {
            let ids: Vec<String> = args["ids"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            Ok(Value::Array(shared.oob.observed_for(&ids).iter().map(interaction_json).collect()))
        }
        _ => Err(format!("{op} is not supported by WebProbe")),
    }
}

fn interaction_json(i: &crate::collaborator::Interaction) -> Value {
    use crate::collaborator::InteractionDetail as D;
    let mut v = json!({"id": i.id, "token": i.token, "time": i.at, "client": i.source});
    match &i.detail {
        D::Dns(d) => {
            v["type"] = "DNS".into();
            v["qtype"] = d.qtype.into();
            v["query"] = util::b64_encode(&d.raw_query).into();
        }
        D::Http(h) => {
            v["type"] = "HTTP".into();
            let mut raw = format!("{} {} {}\r\n", h.method, h.target, h.version).into_bytes();
            for (k, val) in &h.headers {
                raw.extend_from_slice(format!("{k}: {val}\r\n").as_bytes());
            }
            raw.extend_from_slice(b"\r\n");
            raw.extend_from_slice(&h.body);
            v["request"] = util::b64_encode(&raw).into();
        }
        D::Smtp(m) => {
            v["type"] = "SMTP".into();
            v["conversation"] = m.conversation.clone().into();
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_reach_the_engine() {
        let shared = crate::net::Shared::new();
        dispatch(&shared, "x", "proxy.intercept", &json!({"on": true})).unwrap();
        assert_eq!(
            dispatch(&shared, "x", "proxy.intercept-state", &json!({})).unwrap(),
            json!(true)
        );
        dispatch(
            &shared,
            "x",
            "scope.include",
            &json!({"url": "http://in.test/"}),
        )
        .unwrap();
        assert_eq!(
            dispatch(
                &shared,
                "x",
                "scope.in",
                &json!({"url": "http://in.test/a"})
            )
            .unwrap(),
            json!(true)
        );
        assert_eq!(
            dispatch(
                &shared,
                "x",
                "scope.in",
                &json!({"url": "http://out.test/a"})
            )
            .unwrap(),
            json!(false)
        );
        let req = util::b64_encode(b"GET /r HTTP/1.1\r\nHost: r.test\r\n\r\n");
        dispatch(&shared, "x", "repeater.send", &json!({"request": req, "host": "r.test", "port": 80, "secure": false, "name": "From ext"})).unwrap();
        assert_eq!(
            shared.repeaters.lock().unwrap().last().unwrap().name,
            "From ext"
        );
        dispatch(
            &shared,
            "x",
            "sitemap.add",
            &json!({"request": req, "host": "r.test", "port": 80, "secure": false}),
        )
        .unwrap();
        assert_eq!(
            dispatch(&shared, "x", "sitemap.items", &json!({}))
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let issue = json!({"name": "Ext issue", "detail": "d", "remediation": "", "baseUrl": "https://r.test:8443/p?q", "severity": "HIGH", "confidence": "CERTAIN", "evidence": []});
        dispatch(
            &shared,
            "Ext One",
            "scanner.add-issues",
            &json!({"issues": [issue]}),
        )
        .unwrap();
        let i = shared.issues.lock().unwrap()[0].clone();
        assert_eq!(
            (
                i.host.as_str(),
                i.path.as_str(),
                i.sev.as_str(),
                i.confidence.as_str()
            ),
            ("r.test", "/p", "high", "Certain")
        );
        assert!(i
            .detail
            .ends_with("<p>Reported by the extension Ext One.</p>"));
        dispatch(&shared, "x", "cookiejar.set", &json!({"name": "sid", "value": "1", "domain": ".r.test", "path": "/", "expires": null})).unwrap();
        assert_eq!(
            dispatch(&shared, "x", "cookiejar.cookies", &json!({})).unwrap()[0]["domain"],
            "r.test"
        );
        assert!(dispatch(&shared, "x", "nope", &json!({}))
            .unwrap_err()
            .contains("not supported by WebProbe"));
    }
}
