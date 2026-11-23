//! "Extensions" in WebProbe's context menus: the items Montoya extensions
//! add (`registerContextMenuItemsProvider`), asked for once when the menu
//! opens and run in the extension's JVM when chosen. Also the "Extension
//! editors" hand-off of a message to extension-provided editors.

use std::cell::RefCell;
use std::sync::Arc;
use webprobe_core::sync::Mutex;

use eframe::egui;
use webprobe_core::ext_host::{MenuContext, MenuItem, MenuMessage, MenuOutcome, ProxyHooks};
use webprobe_core::net::{HistEntry, Shared};

/// The items of one opened menu: asked for on a worker thread (a call into
/// the extension's JVM), `None` until they arrive.
type Found = Vec<(Arc<dyn ProxyHooks>, Vec<MenuItem>)>;
type Slot = Arc<Mutex<Option<Found>>>;

thread_local! {
    /// The menu now open: its key and its items' slot.
    static CACHE: RefCell<Option<(String, Slot)>> = const { RefCell::new(None) };
}

/// Requests an extension action or editor gave back, per target editor
/// (e.g. "Repeater:3"); the editor takes them on a later frame.
static EDITS: Mutex<Vec<(String, Vec<u8>)>> = Mutex::new(Vec::new());

/// The request an extension produced for `target`, if one arrived.
pub fn take_edit(target: &str) -> Option<Vec<u8>> {
    let mut edits = EDITS.lock().unwrap();
    let at = edits.iter().position(|(t, _)| t == target)?;
    Some(edits.remove(at).1)
}

fn put_edit(target: &str, request: Vec<u8>) {
    EDITS.lock().unwrap().push((target.to_string(), request));
}

/// Run `work` (calls into extension JVMs) off the UI thread and repaint
/// when it is done: the UI never waits on a sidecar.
fn off_ui(ctx: &egui::Context, work: impl FnOnce() + Send + 'static) {
    let ctx = ctx.clone();
    webprobe_core::util::spawn_contained("ext_menu", move || {
        work();
        ctx.request_repaint();
    });
}

/// A history entry as a menu message.
pub fn message_of(e: &HistEntry) -> MenuMessage {
    MenuMessage {
        request: e.req_raw.to_vec(),
        response: e.resp_raw.as_ref().map(|r| r.to_vec()),
        service: webprobe_core::ext_host::HttpService::new(&e.host, e.port, e.https),
    }
}

fn key(ctx: &MenuContext) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for m in &ctx.messages {
        m.request.hash(&mut h);
        m.response.hash(&mut h);
    }
    format!(
        "{}|{}|{:?}|{}",
        ctx.tool,
        ctx.invocation,
        ctx.editor,
        h.finish()
    )
}

/// The extensions' items for this menu (asked once per opened menu, on a
/// worker thread); `None` while they are on their way.
fn items(ui: &egui::Ui, shared: &Shared, ctx: &MenuContext) -> Option<Found> {
    let k = key(ctx);
    let slot = CACHE.with(|c| {
        c.borrow()
            .as_ref()
            .filter(|(ck, _)| *ck == k)
            .map(|(_, s)| Arc::clone(s))
    });
    if let Some(slot) = slot {
        return slot.lock().unwrap().clone();
    }
    let exts: Vec<_> = webprobe_core::ext_host::active_hooks(shared)
        .into_iter()
        .filter(|e| e.ui().is_some_and(|u| u.menu_providers > 0))
        .collect();
    let slot: Slot = Arc::new(Mutex::new(None));
    if exts.is_empty() {
        *slot.lock().unwrap() = Some(Vec::new());
    } else {
        let (fill, ctx) = (Arc::clone(&slot), ctx.clone());
        off_ui(ui.ctx(), move || {
            let found: Found = exts
                .into_iter()
                .map(|e| {
                    let items = e.menu_items(&ctx);
                    (e, items)
                })
                .filter(|(_, items)| !items.is_empty())
                .collect();
            *fill.lock().unwrap() = Some(found);
        });
    }
    CACHE.with(|c| *c.borrow_mut() = Some((k, Arc::clone(&slot))));
    let ready = slot.lock().unwrap().clone();
    ready
}

/// Draw "Extensions > <extension> > items". A chosen item runs on a worker
/// thread; a request it sets arrives through [`take_edit`] for `target`
/// (None: the menu's messages are read-only). Nothing is drawn when no
/// extension adds items.
pub fn submenu(ui: &mut egui::Ui, shared: &Shared, ctx: &MenuContext, target: Option<&str>) {
    let Some(found) = items(ui, shared, ctx) else {
        ui.separator();
        ui.add_enabled(false, egui::Button::new("Extensions (loading...)"));
        return;
    };
    if found.is_empty() {
        return;
    }
    ui.separator();
    ui.menu_button("Extensions", |ui| {
        for (ext, items) in &found {
            ui.menu_button(ext.extension_name(), |ui| {
                for it in items {
                    if ui.button(&it.label).clicked() {
                        let (ext, id, target) =
                            (Arc::clone(ext), it.id.clone(), target.map(str::to_string));
                        off_ui(ui.ctx(), move || {
                            let outcome: MenuOutcome = ext.invoke_menu_item(&id);
                            if let (Some(t), Some(r)) = (target, outcome.request) {
                                put_edit(&t, r);
                            }
                        });
                        CACHE.with(|c| *c.borrow_mut() = None);
                        ui.close();
                    }
                }
            });
        }
    });
}

/// "Extension editors" items of a request editor's menu, when a loaded
/// extension provides editors: send the message to them (they show in the
/// extension's window), or take back the request one changed (it arrives
/// through [`take_edit`] for `target`).
pub fn editor_items(
    ui: &mut egui::Ui,
    shared: &Arc<Shared>,
    msg: &MenuMessage,
    tool: &str,
    target: &str,
) {
    let any = webprobe_core::ext_host::active_hooks(shared)
        .iter()
        .any(|e| {
            e.ui()
                .is_some_and(|u| u.request_editors + u.response_editors > 0)
        });
    if !any {
        return;
    }
    ui.menu_button("Extension editors", |ui| {
        if ui
            .button("Open this message in extension editors")
            .clicked()
        {
            let (shared, msg, tool) = (Arc::clone(shared), msg.clone(), tool.to_string());
            off_ui(ui.ctx(), move || {
                crate::feedback::toast(
                    crate::feedback::Level::Info,
                    open_in_editors(&shared, &msg, &tool),
                )
            });
            ui.close();
        }
        if ui
            .button("Use the request edited in an extension editor")
            .clicked()
        {
            let (shared, target) = (Arc::clone(shared), target.to_string());
            off_ui(ui.ctx(), move || match edited_request(&shared) {
                Some(r) => put_edit(&target, r),
                None => crate::feedback::toast(
                    crate::feedback::Level::Info,
                    "No extension editor has changed the request.",
                ),
            });
            ui.close();
        }
    });
}

/// Offer a message to every extension editor; a summary for a toast.
pub fn open_in_editors(shared: &Shared, msg: &MenuMessage, tool: &str) -> String {
    let exts = webprobe_core::ext_host::active_hooks(shared);
    let mut shown = Vec::new();
    let mut idle = 0;
    for e in exts {
        if let Some(u) = e.ui() {
            if u.request_editors + u.response_editors == 0 {
                continue;
            }
            for t in e.open_in_editors(msg, tool) {
                if t.enabled {
                    shown.push(format!("{} ({})", t.caption, e.extension_name()));
                } else {
                    idle += 1;
                }
            }
            if u.headless {
                return "The extension editors cannot be shown: its JVM runs without a display."
                    .into();
            }
        }
    }
    match (shown.is_empty(), idle) {
        (true, 0) => "No loaded extension provides message editors.".into(),
        (true, _) => "No extension editor handles this message.".into(),
        (false, _) => format!("Opened in the extension window: {}", shown.join(", ")),
    }
}

/// The first request an extension editor changed.
pub fn edited_request(shared: &Shared) -> Option<Vec<u8>> {
    let exts = webprobe_core::ext_host::active_hooks(shared);
    exts.iter()
        .filter(|e| e.ui().is_some_and(|u| u.request_editors > 0))
        .find_map(|e| e.edited_request())
}
