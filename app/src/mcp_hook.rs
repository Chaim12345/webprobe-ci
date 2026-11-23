//! UI automation through egui-mcp-server (feature `mcp`).
//!
//! With the feature on, the app runs egui-mcp-client's IPC server so an agent
//! can take screenshots, click, type and read the widget tree (the tree comes
//! from AccessKit). Without it every method is a no-op and the app has no
//! tokio runtime.

use eframe::egui;

#[cfg(feature = "mcp")]
pub struct Mcp {
    client: egui_mcp_client::McpClient,
    rt: std::sync::Arc<tokio::runtime::Runtime>,
    /// Clicks are delivered over several frames (move, press, release) like
    /// a real pointer: a widget must be hovered before it can be pressed, and
    /// table rows ignore a move+press+release that arrives in one frame.
    staged: std::cell::RefCell<std::collections::VecDeque<Vec<egui::Event>>>,
    waker_set: std::cell::Cell<bool>,
    /// When this frame's UI started (get_frame_stats reports build time).
    frame_start: std::cell::Cell<Option<std::time::Instant>>,
}

#[cfg(not(feature = "mcp"))]
pub struct Mcp;

#[cfg(feature = "mcp")]
impl Mcp {
    pub fn start() -> Self {
        let rt = std::sync::Arc::new(
            tokio::runtime::Runtime::new().expect("tokio runtime for egui-mcp"),
        );
        let client = egui_mcp_client::McpClient::new();
        let server = client.clone();
        let path = rt.block_on(client.socket_path());
        rt.spawn(async move {
            if let Err(e) = egui_mcp_client::IpcServer::run(server).await {
                eprintln!("webprobe: egui MCP unavailable on {}: {e}", path.display());
            }
        });
        Mcp {
            client,
            rt,
            staged: Default::default(),
            waker_set: Default::default(),
            frame_start: Default::default(),
        }
    }

    /// Inputs sent by the agent, merged into the frames' input in the order
    /// they were sent, one step per frame (see `steps`).
    pub fn inject(&self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        let inputs = self.rt.block_on(self.client.take_pending_inputs());
        let mut staged = self.staged.borrow_mut();
        for input in inputs {
            staged.extend(steps(input));
        }
        if let Some(events) = staged.pop_front() {
            raw.events.extend(events);
            ctx.request_repaint();
        }
        if !staged.is_empty() {
            ctx.request_repaint();
        }
    }

    /// Mark the start of the frame's UI pass.
    pub fn begin_frame(&self) {
        self.frame_start.set(Some(std::time::Instant::now()));
    }

    /// Per frame: answer screenshot requests, draw requested highlights.
    pub fn frame(&self, ctx: &egui::Context) {
        if let Some(t0) = self.frame_start.take() {
            self.rt.block_on(self.client.record_frame(t0.elapsed()));
        }
        // Event-driven: the IPC server wakes the UI when a request arrives
        // (polling with a 100 ms repaint kept a software-rendered window at
        // ~110% CPU while idle).
        if !self.waker_set.get() {
            let c = ctx.clone();
            self.client
                .set_waker(std::sync::Arc::new(move || c.request_repaint()));
            self.waker_set.set(true);
        }
        if self.rt.block_on(self.client.take_screenshot_request()) {
            let client = self.client.clone();
            let rt = self.rt.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                egui::ScreenshotCallback::new(move |img| {
                    let rgba: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect();
                    let png = compressed_png(img.width() as u32, img.height() as u32, &rgba);
                    let c = client.clone();
                    rt.spawn(async move { c.set_screenshot(png).await });
                }),
            ));
            ctx.request_repaint();
        }
        let highlights = self.rt.block_on(self.client.get_highlights());
        egui_mcp_client::draw_highlights(ctx, &highlights);
    }
}

/// The frames one agent input becomes. Pointer actions are spread over
/// frames like a real pointer (hover, press, release), because a widget must
/// be hovered before it can be pressed and table rows ignore a click that
/// arrives in one frame. Everything shares one queue, so a key sent after a
/// click lands in the field the click focused.
#[cfg(feature = "mcp")]
fn steps(input: egui_mcp_client::PendingInput) -> Vec<Vec<egui::Event>> {
    use egui_mcp_client::PendingInput as P;
    let button = |b: &egui_mcp_client::MouseButton| match b {
        egui_mcp_client::MouseButton::Right => egui::PointerButton::Secondary,
        egui_mcp_client::MouseButton::Middle => egui::PointerButton::Middle,
        _ => egui::PointerButton::Primary,
    };
    let press = |pos, button, pressed| egui::Event::PointerButton {
        pos,
        button,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    match input {
        P::Click { x, y, button: b } => {
            let (pos, b) = (egui::pos2(x, y), button(&b));
            vec![
                vec![egui::Event::PointerMoved(pos)],
                vec![press(pos, b, true)],
                vec![press(pos, b, false)],
            ]
        }
        P::DoubleClick { x, y, button: b } => {
            let (pos, b) = (egui::pos2(x, y), button(&b));
            vec![
                vec![egui::Event::PointerMoved(pos)],
                vec![press(pos, b, true)],
                vec![press(pos, b, false)],
                vec![press(pos, b, true)],
                vec![press(pos, b, false)],
            ]
        }
        P::MoveMouse { x, y } => vec![vec![egui::Event::PointerMoved(egui::pos2(x, y))]],
        P::Drag {
            start_x,
            start_y,
            end_x,
            end_y,
            button: b,
        } => {
            let (a, z, b) = (
                egui::pos2(start_x, start_y),
                egui::pos2(end_x, end_y),
                button(&b),
            );
            let mid = a + (z - a) * 0.5;
            vec![
                vec![egui::Event::PointerMoved(a)],
                vec![press(a, b, true)],
                vec![egui::Event::PointerMoved(mid)],
                vec![egui::Event::PointerMoved(z)],
                vec![press(z, b, false)],
            ]
        }
        P::Scroll {
            x,
            y,
            delta_x,
            delta_y,
        } => vec![
            vec![egui::Event::PointerMoved(egui::pos2(x, y))],
            vec![egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(delta_x, delta_y),
                phase: egui::TouchPhase::Move,
                source: egui::MouseWheelSource::Unknown,
                modifiers: egui::Modifiers::NONE,
            }],
        ],
        P::Keyboard { key } => vec![key_events(&key)],
    }
}

#[cfg_attr(not(feature = "mcp"), allow(dead_code))]
/// Named keys: egui's names plus the X11 / xdotool spellings agents use.
fn named_key(name: &str) -> Option<egui::Key> {
    let lower = name.to_ascii_lowercase();
    let alias = match lower.as_str() {
        "return" | "kp_enter" => "Enter",
        "backspace" | "back_space" => "Backspace",
        "esc" => "Escape",
        "del" => "Delete",
        "ins" => "Insert",
        "up" => "ArrowUp",
        "down" => "ArrowDown",
        "left" => "ArrowLeft",
        "right" => "ArrowRight",
        "page_up" | "prior" | "pgup" => "PageUp",
        "page_down" | "next" | "pgdn" => "PageDown",
        "space" => "Space",
        _ => "",
    };
    if !alias.is_empty() {
        return egui::Key::from_name(alias);
    }
    // Only multi-letter names here: a single character is text.
    if name.chars().count() < 2 {
        return None;
    }
    egui::Key::from_name(name).or_else(|| {
        // Case-insensitive match on egui's own names ("enter", "pageup", "f5").
        egui::Key::ALL
            .iter()
            .copied()
            .find(|k| k.name().eq_ignore_ascii_case(name))
    })
}

/// One `keyboard_input` value as this frame's events:
/// * `ctrl+a`, `shift+Tab`, `ctrl+shift+z`: a key with modifiers
///   (`ctrl`/`control`, `shift`, `alt`, `cmd`/`super`/`meta`);
/// * a key name (`Enter`, `Tab`, `BackSpace`, `ArrowLeft`, `F5`, `space`):
///   that key (space also types a space);
/// * anything else is typed as text, so `a`, `&` or `hello world` type
///   themselves; prefix `text:` to type a word that is also a key name.
#[cfg_attr(not(feature = "mcp"), allow(dead_code))]
pub fn key_events(key: &str) -> Vec<egui::Event> {
    let pressed_and_released = |k: egui::Key, modifiers: egui::Modifiers| {
        [true, false]
            .map(|pressed| egui::Event::Key {
                key: k,
                physical_key: Some(k),
                pressed,
                repeat: false,
                modifiers,
            })
            .to_vec()
    };
    if let Some(text) = key.strip_prefix("text:") {
        return vec![egui::Event::Text(text.to_string())];
    }
    // Modifier combos.
    let combo =
        key.len() > 2 && (key.ends_with("++") || (key.contains('+') && !key.ends_with('+')));
    if combo {
        let (mods, last) = match key.strip_suffix("++") {
            Some(m) => (m, "+"),
            None => key.rsplit_once('+').unwrap_or(("", key)),
        };
        let mut m = egui::Modifiers::NONE;
        let mut ok = !mods.is_empty();
        for part in mods.split('+') {
            match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => {
                    m.ctrl = true;
                    m.command = true;
                }
                "shift" => m.shift = true,
                "alt" | "option" => m.alt = true,
                "cmd" | "command" | "super" | "meta" | "win" => {
                    m.mac_cmd = true;
                    m.command = true;
                }
                _ => ok = false,
            }
        }
        let k = named_key(last).or_else(|| {
            let mut chars = last.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => egui::Key::from_name(&c.to_ascii_uppercase().to_string())
                    .or_else(|| egui::Key::from_name(&c.to_string())),
                _ => None,
            }
        });
        if let (true, Some(k)) = (ok, k) {
            // egui-winit turns these shortcuts into clipboard events.
            if m.command && !m.shift && !m.alt {
                match k {
                    egui::Key::C => return vec![egui::Event::Copy],
                    egui::Key::X => return vec![egui::Event::Cut],
                    _ => {}
                }
            }
            return pressed_and_released(k, m);
        }
    }
    if let Some(k) = named_key(key) {
        let mut events = pressed_and_released(k, egui::Modifiers::NONE);
        if k == egui::Key::Space {
            events.push(egui::Event::Text(" ".into()));
        }
        return events;
    }
    // Text: a single character also presses its key, as a keyboard would.
    let mut events = Vec::new();
    let mut chars = key.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        if let Some(k) = egui::Key::from_name(&c.to_ascii_uppercase().to_string())
            .filter(|_| c.is_ascii_alphanumeric())
        {
            let modifiers = if c.is_ascii_uppercase() {
                egui::Modifiers::SHIFT
            } else {
                egui::Modifiers::NONE
            };
            events.push(egui::Event::Key {
                key: k,
                physical_key: Some(k),
                pressed: true,
                repeat: false,
                modifiers,
            });
            events.push(egui::Event::Text(key.to_string()));
            events.push(egui::Event::Key {
                key: k,
                physical_key: Some(k),
                pressed: false,
                repeat: false,
                modifiers,
            });
            return events;
        }
    }
    vec![egui::Event::Text(key.to_string())]
}

/// A deflate-compressed RGBA PNG. The MCP protocol caps a message at 1 MB;
/// the uncompressed encoder in `util` makes a 1440x900 screenshot ~5 MB.
#[cfg(feature = "mcp")]
pub fn compressed_png(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    use std::io::Write;
    fn crc32(parts: &[&[u8]]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for part in parts {
            for &b in *part {
                c ^= b as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xedb8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
            }
        }
        !c
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
    }
    let mut raw = Vec::with_capacity((w as usize * 4 + 1) * h as usize);
    for row in rgba.chunks(w as usize * 4) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = z.write_all(&raw);
    let idat = z.finish().unwrap_or_default();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &idat);
    chunk(&mut out, b"IEND", &[]);
    out
}

#[cfg(not(feature = "mcp"))]
impl Mcp {
    pub fn start() -> Self {
        Mcp
    }
    pub fn inject(&self, _ctx: &egui::Context, _raw: &mut egui::RawInput) {}
    pub fn begin_frame(&self) {}
    pub fn frame(&self, _ctx: &egui::Context) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(ev: &[egui::Event]) -> String {
        ev.iter()
            .filter_map(|e| {
                if let egui::Event::Text(t) = e {
                    Some(t.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    fn key(ev: &[egui::Event]) -> Option<(egui::Key, egui::Modifiers)> {
        ev.iter().find_map(|e| {
            if let egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } = e
            {
                Some((*key, *modifiers))
            } else {
                None
            }
        })
    }

    #[test]
    fn characters_and_strings_type_text() {
        assert_eq!(text(&key_events("a")), "a");
        assert_eq!(key(&key_events("a")).map(|k| k.0), Some(egui::Key::A));
        assert_eq!(text(&key_events("&")), "&");
        assert_eq!(text(&key_events(" ")), " ");
        assert_eq!(text(&key_events("a b&c")), "a b&c");
        assert_eq!(
            text(&key_events("ampersand")),
            "ampersand",
            "not a key name: typed"
        );
        assert_eq!(text(&key_events("text:Enter")), "Enter");
        assert_eq!(text(&key_events("+")), "+");
    }

    #[test]
    fn key_names_press_keys() {
        for (name, k) in [
            ("Enter", egui::Key::Enter),
            ("Return", egui::Key::Enter),
            ("BackSpace", egui::Key::Backspace),
            ("backspace", egui::Key::Backspace),
            ("Tab", egui::Key::Tab),
            ("End", egui::Key::End),
            ("Page_Up", egui::Key::PageUp),
            ("F5", egui::Key::F5),
            ("left", egui::Key::ArrowLeft),
        ] {
            assert_eq!(key(&key_events(name)).map(|x| x.0), Some(k), "{name}");
            assert_eq!(text(&key_events(name)), "", "{name} types nothing");
        }
        assert_eq!(text(&key_events("space")), " ", "space types a space");
    }

    #[test]
    fn combos_carry_modifiers() {
        let (k, m) = key(&key_events("ctrl+a")).unwrap();
        assert_eq!(k, egui::Key::A);
        assert!(m.ctrl && m.command && !m.shift);
        let (k, m) = key(&key_events("shift+Tab")).unwrap();
        assert_eq!(k, egui::Key::Tab);
        assert!(m.shift);
        assert!(matches!(key_events("ctrl+c")[..], [egui::Event::Copy]));
        assert_eq!(
            key(&key_events("ctrl+shift+z")).map(|x| (x.0, x.1.shift)),
            Some((egui::Key::Z, true))
        );
    }
}
