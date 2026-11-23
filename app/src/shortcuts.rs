//! Keyboard shortcuts and the command palette (M-06).
//!
//! The default table is not invented: it is Burp build 52685's own
//! `resources/Preferences/UserDefaults.json` → `user_options.misc.hotkeys`
//! (50 pairs), joined to the command ids and labels of `burp.Zmcg`
//! (`Zj()` label, `ZB()` id, `Ze()` category). Both were read from
//! `/opt/BurpSuite/burpsuite.jar` and are cited in `mechanics.json`.
//!
//! Burp's shipped documentation (`settings/ui/hotkeys.html`) adds two rules the
//! parser enforces: every hotkey must use Ctrl/Cmd, and modifiers such as Shift
//! are allowed. Duplicate chords are refused the same way Burp's
//! `isKeystrokeDuplicate` does.
//!
//! Hotkeys are user settings, not project settings (Burp's docs say so), so
//! they persist in `~/.config/webprobe/hotkeys.json`.

use eframe::egui::{self, Key, Modifiers, RichText, Ui};
use serde::{Deserialize, Serialize};

use crate::theme::{self, c};

/// How well WebProbe supports a Burp command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// WebProbe dispatches this command itself.
    Wired,
    /// The focused egui text editor already handles it; we must not consume it.
    EditorNative,
    /// Burp command with no WebProbe equivalent yet.
    Missing,
}

pub struct ActionDef {
    pub id: &'static str,
    pub label: &'static str,
    pub category: &'static str,
    pub default: Option<&'static str>,
    pub support: Support,
}

const fn a(
    id: &'static str,
    label: &'static str,
    category: &'static str,
    default: &'static str,
    support: Support,
) -> ActionDef {
    ActionDef {
        id,
        label,
        category,
        default: Some(default),
        support,
    }
}

/// Burp's 50 default hotkeys, in the order the reference file lists them.
pub const ACTIONS: &[ActionDef] = &[
    a(
        "send_to_repeater",
        "Send to Repeater",
        "Send",
        "Ctrl+R",
        Support::Wired,
    ),
    a(
        "send_to_intruder",
        "Send to Intruder",
        "Send",
        "Ctrl+I",
        Support::Wired,
    ),
    a(
        "send_to_organizer",
        "Send to Organizer",
        "Send",
        "Ctrl+O",
        Support::Missing,
    ),
    a(
        "explain_this",
        "Explain selected text",
        "Burp AI",
        "Ctrl+E",
        Support::Missing,
    ),
    a(
        "forward_intercepted_proxy_message",
        "Forward intercepted message",
        "Intercept",
        "Ctrl+F",
        Support::Wired,
    ),
    a(
        "toggle_proxy_interception",
        "Toggle interception on/off",
        "Intercept",
        "Ctrl+T",
        Support::Wired,
    ),
    a(
        "issue_repeater_request",
        "Send Repeater request",
        "Repeater",
        "Ctrl+Space",
        Support::Wired,
    ),
    a(
        "switch_to_dashboard",
        "Go to Dashboard",
        "Switch tab",
        "Ctrl+Shift+D",
        Support::Wired,
    ),
    a(
        "switch_to_target",
        "Go to Target",
        "Switch tab",
        "Ctrl+Shift+T",
        Support::Wired,
    ),
    a(
        "switch_to_proxy",
        "Go to Proxy",
        "Switch tab",
        "Ctrl+Shift+P",
        Support::Wired,
    ),
    a(
        "switch_to_intruder",
        "Go to Intruder",
        "Switch tab",
        "Ctrl+Shift+I",
        Support::Wired,
    ),
    a(
        "switch_to_repeater",
        "Go to Repeater",
        "Switch tab",
        "Ctrl+Shift+R",
        Support::Wired,
    ),
    a(
        "switch_to_logger",
        "Go to Logger",
        "Switch tab",
        "Ctrl+Shift+L",
        Support::Missing,
    ),
    a(
        "switch_to_organizer",
        "Go to Organizer",
        "Switch tab",
        "Ctrl+Shift+O",
        Support::Missing,
    ),
    a(
        "go_to_previous_tab",
        "Go to previous tab",
        "Tabs",
        "Ctrl+Minus",
        Support::Wired,
    ),
    a(
        "go_to_next_tab",
        "Go to next tab",
        "Tabs",
        "Ctrl+Equals",
        Support::Wired,
    ),
    a(
        "open_command_palette",
        "Open command palette",
        "Open",
        "Ctrl+K",
        Support::Wired,
    ),
    a("editor_cut", "Cut", "Edit", "Ctrl+X", Support::EditorNative),
    a(
        "editor_copy",
        "Copy",
        "Edit",
        "Ctrl+C",
        Support::EditorNative,
    ),
    a(
        "editor_copy_prettified",
        "Copy prettified",
        "Edit",
        "Ctrl+Alt+C",
        Support::Missing,
    ),
    a(
        "editor_paste",
        "Paste",
        "Edit",
        "Ctrl+V",
        Support::EditorNative,
    ),
    a(
        "editor_undo",
        "Undo",
        "Edit",
        "Ctrl+Z",
        Support::EditorNative,
    ),
    a(
        "editor_redo",
        "Redo",
        "Edit",
        "Ctrl+Y",
        Support::EditorNative,
    ),
    a(
        "editor_select_all",
        "Select all",
        "Edit",
        "Ctrl+A",
        Support::EditorNative,
    ),
    a(
        "editor_search",
        "Search in editor",
        "Search text",
        "Ctrl+S",
        Support::Missing,
    ),
    a(
        "editor_go_to_previous_search_match",
        "Previous search result in editor",
        "Search text",
        "Ctrl+Comma",
        Support::Missing,
    ),
    a(
        "editor_go_to_next_search_match",
        "Next search result in editor",
        "Search text",
        "Ctrl+Period",
        Support::Missing,
    ),
    a(
        "editor_url_decode",
        "URL-decode",
        "Decode",
        "Ctrl+Shift+U",
        Support::Missing,
    ),
    a(
        "editor_url_encode_key_characters",
        "URL-encode key characters",
        "Encode",
        "Ctrl+U",
        Support::Missing,
    ),
    a(
        "editor_html_decode",
        "HTML-decode",
        "Decode",
        "Ctrl+Shift+H",
        Support::Missing,
    ),
    a(
        "editor_html_encode_key_characters",
        "HTML-encode key characters",
        "Encode",
        "Ctrl+H",
        Support::Missing,
    ),
    a(
        "editor_base64_decode",
        "Base64-decode",
        "Decode",
        "Ctrl+Shift+B",
        Support::Missing,
    ),
    a(
        "editor_base64_encode",
        "Base64-encode",
        "Encode",
        "Ctrl+B",
        Support::Missing,
    ),
    a(
        "editor_backspace_word",
        "Backspace word",
        "Edit",
        "Ctrl+Backspace",
        Support::EditorNative,
    ),
    a(
        "editor_delete_word",
        "Delete word",
        "Edit",
        "Ctrl+Delete",
        Support::EditorNative,
    ),
    a(
        "editor_delete_line",
        "Delete line",
        "Edit",
        "Ctrl+D",
        Support::Missing,
    ),
    a(
        "editor_go_to_previous_word",
        "Go to previous word",
        "Navigate text",
        "Ctrl+Left",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_previous_word_extend_selection",
        "Go to previous word (with text selection)",
        "Navigate text",
        "Ctrl+Shift+Left",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_next_word",
        "Go to next word",
        "Navigate text",
        "Ctrl+Right",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_next_word_extend_selection",
        "Go to next word (with text selection)",
        "Navigate text",
        "Ctrl+Shift+Right",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_previous_paragraph",
        "Go to previous paragraph",
        "Navigate text",
        "Ctrl+Up",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_previous_paragraph_extend_selection",
        "Go to previous paragraph (with text selection)",
        "Navigate text",
        "Ctrl+Shift+Up",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_next_paragraph",
        "Go to next paragraph",
        "Navigate text",
        "Ctrl+Down",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_next_paragraph_extend_selection",
        "Go to next paragraph (with text selection)",
        "Navigate text",
        "Ctrl+Shift+Down",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_start_of_document",
        "Go to start of document",
        "Navigate text",
        "Ctrl+Home",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_start_of_document_extend_selection",
        "Go to start of document (with text selection)",
        "Navigate text",
        "Ctrl+Shift+Home",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_end_of_document",
        "Go to end of document",
        "Navigate text",
        "Ctrl+End",
        Support::EditorNative,
    ),
    a(
        "editor_go_to_end_of_document_extend_selection",
        "Go to end of document (with text selection)",
        "Navigate text",
        "Ctrl+Shift+End",
        Support::EditorNative,
    ),
    a(
        "send_to_burp_at",
        "Send to Burp AI",
        "Burp AI",
        "Ctrl+G",
        Support::Missing,
    ),
    a(
        "open_burp_at",
        "Send to Burp AI",
        "Burp AI",
        "Ctrl+Shift+G",
        Support::Missing,
    ),
];

/// Everything the app may need to know about a key, independent of egui.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chord {
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
    /// Canonical Burp key name: "R", "7", "Minus", "Space", "ArrowLeft" → "Left".
    pub key: String,
}

impl Chord {
    /// "Ctrl+Shift+P", "Ctrl+Minus", "Ctrl+Alt+C" — Burp's own spelling.
    pub fn format(&self) -> String {
        let mut s = String::new();
        if self.ctrl {
            s.push_str("Ctrl+");
        }
        if self.shift {
            s.push_str("Shift+");
        }
        if self.alt {
            s.push_str("Alt+");
        }
        s.push_str(&self.key);
        s
    }

    /// Parse Burp's display spelling. Rejects chords without Ctrl (Burp's docs
    /// state every hotkey must use Cmd/Ctrl) and unknown key names.
    pub fn parse(text: &str) -> Result<Self, String> {
        let parts: Vec<&str> = text
            .split('+')
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        if parts.is_empty() {
            return Err("empty hotkey".to_string());
        }
        let (key, mods) = parts.split_last().unwrap();
        let mut chord = Chord {
            ctrl: false,
            shift: false,
            alt: false,
            key: String::new(),
        };
        for m in mods {
            match m.to_ascii_lowercase().as_str() {
                "ctrl" | "cmd" | "command" | "control" => chord.ctrl = true,
                "shift" => chord.shift = true,
                "alt" | "option" => chord.alt = true,
                _ => return Err(format!("unknown modifier {m}")),
            }
        }
        if !chord.ctrl {
            return Err("hotkeys must include Ctrl (Burp requires Cmd/Ctrl)".to_string());
        }
        chord.key = canonical_key_name(key).ok_or_else(|| format!("unknown key {key}"))?;
        Ok(chord)
    }

    /// The egui key this chord needs, if WebProbe knows it.
    pub fn egui_key(&self) -> Option<Key> {
        key_from_name(&self.key)
    }

    /// Match a live key event against this chord.
    pub fn matches(&self, key: Key, m: &Modifiers) -> bool {
        let live = match Chord::from_egui(key, m) {
            Some(c) => c,
            None => return false,
        };
        &live == self
    }

    /// Build a chord from an egui key press. Returns None for keys Burp has no
    /// name for (or presses without Ctrl, which are text input, not hotkeys).
    pub fn from_egui(key: Key, m: &Modifiers) -> Option<Chord> {
        let name = key_name(key)?;
        // `command` is Ctrl on Linux/Windows and Cmd on macOS, like Burp.
        let ctrl = m.ctrl || m.command;
        Some(Chord {
            ctrl,
            shift: m.shift,
            alt: m.alt,
            key: name.to_string(),
        })
    }
}

fn canonical_key_name(key: &str) -> Option<String> {
    let k = key.trim();
    if k.len() == 1 {
        let ch = k.chars().next().unwrap().to_ascii_uppercase();
        if ch.is_ascii_alphanumeric() {
            return Some(ch.to_string());
        }
    }
    let lower = k.to_ascii_lowercase();
    let name = match lower.as_str() {
        "minus" | "-" => "Minus",
        "equals" | "=" => "Equals",
        "comma" | "," => "Comma",
        "period" | "." => "Period",
        "space" | "spacebar" => "Space",
        "backspace" => "Backspace",
        "delete" | "del" => "Delete",
        "insert" | "ins" => "Insert",
        "home" => "Home",
        "end" => "End",
        "left" | "arrowleft" => "Left",
        "right" | "arrowright" => "Right",
        "up" | "arrowup" => "Up",
        "down" | "arrowdown" => "Down",
        "pageup" => "PageUp",
        "pagedown" => "PageDown",
        "tab" => "Tab",
        "enter" | "return" => "Enter",
        "escape" | "esc" => "Escape",
        "slash" | "/" => "Slash",
        "backslash" | "\\" => "Backslash",
        "semicolon" | ";" => "Semicolon",
        "quote" | "'" => "Quote",
        _ => return None,
    };
    Some(name.to_string())
}

fn key_name(key: Key) -> Option<&'static str> {
    Some(match key {
        Key::A => "A",
        Key::B => "B",
        Key::C => "C",
        Key::D => "D",
        Key::E => "E",
        Key::F => "F",
        Key::G => "G",
        Key::H => "H",
        Key::I => "I",
        Key::J => "J",
        Key::K => "K",
        Key::L => "L",
        Key::M => "M",
        Key::N => "N",
        Key::O => "O",
        Key::P => "P",
        Key::Q => "Q",
        Key::R => "R",
        Key::S => "S",
        Key::T => "T",
        Key::U => "U",
        Key::V => "V",
        Key::W => "W",
        Key::X => "X",
        Key::Y => "Y",
        Key::Z => "Z",
        Key::Num0 => "0",
        Key::Num1 => "1",
        Key::Num2 => "2",
        Key::Num3 => "3",
        Key::Num4 => "4",
        Key::Num5 => "5",
        Key::Num6 => "6",
        Key::Num7 => "7",
        Key::Num8 => "8",
        Key::Num9 => "9",
        Key::Minus => "Minus",
        Key::Equals => "Equals",
        Key::Comma => "Comma",
        Key::Period => "Period",
        Key::Space => "Space",
        Key::Backspace => "Backspace",
        Key::Delete => "Delete",
        Key::Insert => "Insert",
        Key::Home => "Home",
        Key::End => "End",
        Key::ArrowLeft => "Left",
        Key::ArrowRight => "Right",
        Key::ArrowUp => "Up",
        Key::ArrowDown => "Down",
        Key::PageUp => "PageUp",
        Key::PageDown => "PageDown",
        Key::Tab => "Tab",
        Key::Enter => "Enter",
        Key::Escape => "Escape",
        Key::Slash => "Slash",
        Key::Backslash => "Backslash",
        Key::Semicolon => "Semicolon",
        Key::Quote => "Quote",
        _ => return None,
    })
}

fn key_from_name(name: &str) -> Option<Key> {
    Some(match name {
        "A" => Key::A,
        "B" => Key::B,
        "C" => Key::C,
        "D" => Key::D,
        "E" => Key::E,
        "F" => Key::F,
        "G" => Key::G,
        "H" => Key::H,
        "I" => Key::I,
        "J" => Key::J,
        "K" => Key::K,
        "L" => Key::L,
        "M" => Key::M,
        "N" => Key::N,
        "O" => Key::O,
        "P" => Key::P,
        "Q" => Key::Q,
        "R" => Key::R,
        "S" => Key::S,
        "T" => Key::T,
        "U" => Key::U,
        "V" => Key::V,
        "W" => Key::W,
        "X" => Key::X,
        "Y" => Key::Y,
        "Z" => Key::Z,
        "0" => Key::Num0,
        "1" => Key::Num1,
        "2" => Key::Num2,
        "3" => Key::Num3,
        "4" => Key::Num4,
        "5" => Key::Num5,
        "6" => Key::Num6,
        "7" => Key::Num7,
        "8" => Key::Num8,
        "9" => Key::Num9,
        "Minus" => Key::Minus,
        "Equals" => Key::Equals,
        "Comma" => Key::Comma,
        "Period" => Key::Period,
        "Space" => Key::Space,
        "Backspace" => Key::Backspace,
        "Delete" => Key::Delete,
        "Insert" => Key::Insert,
        "Home" => Key::Home,
        "End" => Key::End,
        "Left" => Key::ArrowLeft,
        "Right" => Key::ArrowRight,
        "Up" => Key::ArrowUp,
        "Down" => Key::ArrowDown,
        "PageUp" => Key::PageUp,
        "PageDown" => Key::PageDown,
        "Tab" => Key::Tab,
        "Enter" => Key::Enter,
        "Escape" => Key::Escape,
        "Slash" => Key::Slash,
        "Backslash" => Key::Backslash,
        "Semicolon" => Key::Semicolon,
        "Quote" => Key::Quote,
        _ => return None,
    })
}

pub fn index_of(id: &str) -> Option<usize> {
    ACTIONS.iter().position(|a| a.id == id)
}

/// The user's binding table, aligned with `ACTIONS`.
#[derive(Clone, Debug)]
pub struct Shortcuts {
    pub bindings: Vec<Option<Chord>>,
    /// Most recently run commands, newest first (command palette order).
    pub recents: Vec<usize>,
}

impl Default for Shortcuts {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl Shortcuts {
    pub fn with_defaults() -> Self {
        let bindings = ACTIONS
            .iter()
            .map(|a| a.default.and_then(|d| Chord::parse(d).ok()))
            .collect();
        Self {
            bindings,
            recents: Vec::new(),
        }
    }

    pub fn chord_for(&self, idx: usize) -> Option<&Chord> {
        self.bindings.get(idx).and_then(|b| b.as_ref())
    }

    /// Bind (or unbind) one action. Refuses a chord already used by another
    /// action, mirroring Burp's `isKeystrokeDuplicate`.
    pub fn set(&mut self, idx: usize, chord: Option<Chord>) -> Result<(), String> {
        if idx >= self.bindings.len() {
            return Err("unknown action".to_string());
        }
        if let Some(c) = &chord {
            for (i, b) in self.bindings.iter().enumerate() {
                if i != idx && b.as_ref() == Some(c) {
                    return Err(format!(
                        "{} is already used by {}",
                        c.format(),
                        ACTIONS[i].label
                    ));
                }
            }
        }
        self.bindings[idx] = chord;
        Ok(())
    }

    pub fn reset(&mut self, idx: usize) {
        if let Some(def) = ACTIONS.get(idx) {
            self.bindings[idx] = def.default.and_then(|d| Chord::parse(d).ok());
        }
    }

    pub fn is_default(&self, idx: usize) -> bool {
        let def = ACTIONS
            .get(idx)
            .and_then(|a| a.default)
            .and_then(|d| Chord::parse(d).ok());
        self.bindings.get(idx).cloned().flatten() == def
    }

    /// Actions whose hotkey fires this frame. Only wired commands are consumed,
    /// so Ctrl+C and friends still reach the focused text editor.
    pub fn handle(&mut self, ctx: &egui::Context) -> Vec<usize> {
        let mut out = Vec::new();
        let wired: Vec<usize> = (0..ACTIONS.len())
            .filter(|&i| ACTIONS[i].support == Support::Wired)
            .collect();
        ctx.input_mut(|input| {
            let mut taken = Vec::new();
            for (ev_idx, ev) in input.events.iter().enumerate() {
                let egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } = ev
                else {
                    continue;
                };
                let Some(chord) = Chord::from_egui(*key, modifiers) else {
                    continue;
                };
                if !chord.ctrl {
                    continue;
                }
                if let Some(&action) = wired
                    .iter()
                    .find(|&&i| self.bindings[i].as_ref() == Some(&chord))
                {
                    taken.push(ev_idx);
                    out.push(action);
                }
            }
            for i in taken.into_iter().rev() {
                input.events.remove(i);
            }
        });
        for &a in &out {
            self.note_used(a);
        }
        out
    }

    pub fn note_used(&mut self, idx: usize) {
        self.recents.retain(|&r| r != idx);
        self.recents.insert(0, idx);
        self.recents.truncate(6);
    }

    /// Commands the palette can run, filtered by a case-insensitive query and
    /// ordered recents-first like Burp's palette.
    pub fn palette_rows(&self, query: &str) -> Vec<usize> {
        let q = query.trim().to_ascii_lowercase();
        let mut rows: Vec<usize> = (0..ACTIONS.len())
            .filter(|&i| ACTIONS[i].support == Support::Wired)
            .filter(|&i| {
                q.is_empty()
                    || ACTIONS[i].label.to_ascii_lowercase().contains(&q)
                    || ACTIONS[i].category.to_ascii_lowercase().contains(&q)
                    || ACTIONS[i].id.contains(&q)
            })
            .collect();
        rows.sort_by_key(|&i| {
            let recent = self.recents.iter().position(|&r| r == i);
            (recent.unwrap_or(usize::MAX), ACTIONS[i].label)
        });
        rows
    }

    fn to_saved(&self) -> Saved {
        // Burp's settings file is authoritative: `burp.Zfhv.Zh` clears the
        // registry and applies the stored list, so an action missing from the
        // file has no hotkey. Every action is therefore written out, with an
        // empty string for "unbound", otherwise a user's unbinding would be
        // silently undone on the next start.
        let hotkeys = ACTIONS
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let text = self.bindings[i]
                    .as_ref()
                    .map(|c| c.format())
                    .unwrap_or_default();
                (a.id.to_string(), text)
            })
            .collect();
        Saved { hotkeys }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_saved()).unwrap_or_else(|_| "{}".to_string())
    }

    /// Load bindings from Burp's file shape (`{"hotkeys": [[id, "Ctrl+R"], …]}`).
    /// Stored values replace defaults outright; when two entries claim the same
    /// chord the first one in the file wins (Burp dedupes by keystroke the same
    /// way in `burp.Zfhv.Zh`) and the later one is left unbound rather than
    /// stealing a binding.
    pub fn from_json(text: &str) -> Self {
        let mut s = Self {
            bindings: vec![None; ACTIONS.len()],
            recents: Vec::new(),
        };
        let Ok(saved) = serde_json::from_str::<Saved>(text) else {
            return s;
        };
        for (id, chord) in saved.hotkeys {
            let Some(idx) = index_of(&id) else { continue };
            if chord.trim().is_empty() {
                s.bindings[idx] = None;
                continue;
            }
            let Ok(parsed) = Chord::parse(&chord) else {
                continue;
            };
            if s.set(idx, Some(parsed)).is_err() {
                s.bindings[idx] = None;
            }
        }
        s
    }

    pub fn config_path() -> std::path::PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
            })
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join("webprobe").join("hotkeys.json")
    }

    pub fn load() -> Self {
        match std::fs::read_to_string(Self::config_path()) {
            Ok(text) => Self::from_json(&text),
            Err(_) => Self::with_defaults(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {dir:?}: {e}"))?;
        }
        std::fs::write(&path, self.to_json()).map_err(|e| format!("write {path:?}: {e}"))
    }
}

/// The persisted form. An ordered list of pairs, not a map, so "first binding
/// wins" on a conflicting file matches Burp's file order.
#[derive(Serialize, Deserialize, Default)]
struct Saved {
    hotkeys: Vec<(String, String)>,
}

/// Command palette state (open/query/selection).
#[derive(Default)]
pub struct Palette {
    pub open: bool,
    pub query: String,
    pub sel: usize,
}

/// What the key-capture mode saw this frame.
pub enum Capture {
    Idle,
    Cancelled,
    Chord(Chord),
}

/// Take one key press for the "press a hotkey" capture mode. Consumes every
/// key event, so a plain key can be captured too (then rejected by `set` if it
/// has no Ctrl). Escape cancels.
pub fn capture(ctx: &egui::Context) -> Capture {
    ctx.input_mut(|input| {
        let mut idx = None;
        for (i, ev) in input.events.iter().enumerate() {
            if let egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } = ev
            {
                if *key == Key::Escape {
                    input.events.remove(i);
                    return Capture::Cancelled;
                }
                if let Some(c) = Chord::from_egui(*key, modifiers) {
                    idx = Some((i, c));
                    break;
                }
            }
        }
        match idx {
            Some((i, c)) => {
                input.events.remove(i);
                Capture::Chord(c)
            }
            None => Capture::Idle,
        }
    })
}

/// Draw the command palette. Returns the action chosen this frame.
pub fn palette_ui(
    palette: &mut Palette,
    shortcuts: &mut Shortcuts,
    ctx: &egui::Context,
) -> Option<usize> {
    if !palette.open {
        return None;
    }
    let rows = shortcuts.palette_rows(&palette.query);
    palette.sel = palette.sel.min(rows.len().saturating_sub(1));
    let mut chosen = None;
    let mut close = false;

    // Burp: arrows navigate, Enter runs, Escape closes.
    ctx.input_mut(|i| {
        if i.consume_key(Modifiers::NONE, Key::Escape) {
            close = true;
        }
        if i.consume_key(Modifiers::NONE, Key::ArrowDown) {
            palette.sel = if rows.is_empty() {
                0
            } else {
                (palette.sel + 1).min(rows.len() - 1)
            };
        }
        if i.consume_key(Modifiers::NONE, Key::ArrowUp) {
            palette.sel = palette.sel.saturating_sub(1);
        }
        if i.consume_key(Modifiers::NONE, Key::Enter) {
            if let Some(&a) = rows.get(palette.sel) {
                chosen = Some(a);
            }
        }
    });

    egui::Area::new(egui::Id::unique("command_palette"))
        .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 84.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::popup(ui.style())
                .fill(theme::chrome())
                .stroke(egui::Stroke::new(1.0, theme::line_strong()))
                .show(ui, |ui| {
                    ui.set_width(520.0);
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut palette.query)
                            .hint_text("Search commands…")
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                    if palette.query.is_empty() {
                        edit.request_focus();
                    }
                    ui.add_space(theme::SPACE_XS);
                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
                            if rows.is_empty() {
                                ui.label(
                                    RichText::new("no matching commands")
                                        .size(12.0)
                                        .color(theme::ink_faint()),
                                );
                            }
                            for (row_i, &a) in rows.iter().enumerate() {
                                let def = &ACTIONS[a];
                                let selected = row_i == palette.sel;
                                let hotkey = shortcuts
                                    .chord_for(a)
                                    .map(|ch| ch.format())
                                    .unwrap_or_default();
                                let text = format!("{}  ·  {}", def.label, def.category);
                                let resp = ui.horizontal(|ui| {
                                    let r = ui.selectable_label(
                                        selected,
                                        RichText::new(text).size(12.5).color(if selected {
                                            theme::ink()
                                        } else {
                                            theme::ink_dim()
                                        }),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new(hotkey)
                                                    .monospace()
                                                    .size(12.0)
                                                    .color(theme::ink_faint()),
                                            );
                                        },
                                    );
                                    r
                                });
                                if resp.inner.clicked() {
                                    chosen = Some(a);
                                }
                            }
                        });
                });
        });

    if close {
        palette.open = false;
        palette.query.clear();
        palette.sel = 0;
    }
    if let Some(a) = chosen {
        palette.open = false;
        palette.query.clear();
        palette.sel = 0;
        shortcuts.note_used(a);
    }
    chosen
}

const SUPPORT_HINT: &str = "WebProbe does not have this Burp command yet";

/// Dashboard-side hotkey settings panel. Owns the capture handshake so the
/// table itself stays free of app state.
pub fn settings_panel(app: &mut crate::App, ui: &mut Ui) {
    if let Some(idx) = app.hotkey_capture {
        let label = ACTIONS.get(idx).map(|d| d.label).unwrap_or("command");
        ui.label(
            RichText::new(format!(
                "Press a new hotkey for \u{201c}{label}\u{201d} — Esc cancels."
            ))
            .size(12.0)
            .color(c(theme::ORANGE)),
        );
    }
    let mut notice = app.hotkey_notice.clone();
    let pressed = settings_ui(ui, &mut app.shortcuts, &mut notice);
    app.hotkey_notice = notice;
    if pressed.is_some() {
        app.hotkey_capture = pressed;
    }
    ui.label(
        RichText::new("Hotkeys are user settings: they apply to every project on this machine.")
            .size(12.0)
            .color(theme::ink_hint()),
    );
}

/// Hotkey settings table, grouped by command category. Returns an action index
/// the caller should put into key-capture mode.
pub fn settings_ui(
    ui: &mut Ui,
    shortcuts: &mut Shortcuts,
    notice: &mut Option<String>,
) -> Option<usize> {
    let mut capturing = None;
    ui.label(
        RichText::new("Hotkeys")
            .size(13.0)
            .strong()
            .color(theme::ink()),
    );
    ui.label(
        RichText::new(
            "User settings, like Burp: every hotkey includes Ctrl. Click a hotkey, press the new combination, then Apply. Escape cancels.",
        )
        .size(12.0)
        .color(theme::ink_faint()),
    );
    if let Some(msg) = notice.clone() {
        ui.label(RichText::new(msg).size(12.0).color(c(theme::BAD)));
    }

    // 50 rows would push the rest of the dashboard off-screen, so the table
    // scrolls inside its own frame (Burp's hotkey table lives in Settings and
    // scrolls too).
    egui::Frame::default()
        .fill(theme::chrome())
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(300.0)
                .show(ui, |ui| {
                    let mut category = "";
                    for (idx, def) in ACTIONS.iter().enumerate() {
                        if def.category != category {
                            category = def.category;
                            ui.add_space(theme::SPACE_XS);
                            ui.label(
                                RichText::new(category)
                                    .size(12.0)
                                    .strong()
                                    .color(theme::ink_faint()),
                            );
                        }
                        ui.horizontal(|ui| {
                            let label =
                                RichText::new(def.label)
                                    .size(12.0)
                                    .color(match def.support {
                                        Support::Missing => theme::ink_hint(),
                                        _ => theme::ink_dim(),
                                    });
                            ui.add_sized([300.0, 20.0], egui::Label::new(label).truncate());
                            let shown = shortcuts
                                .chord_for(idx)
                                .map(|ch| ch.format())
                                .unwrap_or_else(|| "(none)".to_string());
                            if ui
                                .add_sized(
                                    [120.0, 20.0],
                                    egui::Button::new(RichText::new(shown).monospace().size(12.0)),
                                )
                                .clicked()
                            {
                                capturing = Some(idx);
                            }
                            // Plain "Clear": the default egui font has no
                            // "✕" glyph, so it would draw as a missing-glyph box.
                            if shortcuts.chord_for(idx).is_some()
                                && ui
                                    .small_button("Clear")
                                    .on_hover_text("Remove this hotkey")
                                    .clicked()
                            {
                                shortcuts.bindings[idx] = None;
                                *notice = None;
                                if let Err(e) = shortcuts.save() {
                                    *notice = Some(e);
                                }
                            }
                            if !shortcuts.is_default(idx) && ui.small_button("Reset").clicked() {
                                shortcuts.reset(idx);
                                *notice = None;
                                if let Err(e) = shortcuts.save() {
                                    *notice = Some(e);
                                }
                            }
                            if def.support == Support::Missing {
                                ui.label(
                                    RichText::new(SUPPORT_HINT)
                                        .size(12.0)
                                        .color(theme::ink_hint()),
                                );
                            }
                        });
                    }
                });
        });
    capturing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_burp_user_defaults() {
        // 50 pairs in UserDefaults.json → user_options.misc.hotkeys.
        assert_eq!(ACTIONS.len(), 50);
        let want = [
            ("send_to_repeater", "Ctrl+R"),
            ("toggle_proxy_interception", "Ctrl+T"),
            ("forward_intercepted_proxy_message", "Ctrl+F"),
            ("issue_repeater_request", "Ctrl+Space"),
            ("open_command_palette", "Ctrl+K"),
            ("go_to_previous_tab", "Ctrl+Minus"),
            ("go_to_next_tab", "Ctrl+Equals"),
            ("editor_copy_prettified", "Ctrl+Alt+C"),
            ("editor_go_to_end_of_document", "Ctrl+End"),
            ("open_burp_at", "Ctrl+Shift+G"),
        ];
        for (id, chord) in want {
            let idx = index_of(id).expect(id);
            assert_eq!(ACTIONS[idx].default, Some(chord), "{id}");
        }
    }

    #[test]
    fn every_default_round_trips_and_uses_ctrl() {
        for def in ACTIONS {
            let text = def.default.expect(def.id);
            let chord = Chord::parse(text).unwrap_or_else(|e| panic!("{}: {e}", def.id));
            assert!(chord.ctrl, "{} must use Ctrl", def.id);
            assert_eq!(chord.format(), text, "{}", def.id);
            assert_eq!(Chord::parse(&chord.format()).unwrap(), chord);
        }
    }

    #[test]
    fn parser_rejects_chords_without_ctrl_and_unknown_keys() {
        assert!(Chord::parse("Shift+P").is_err());
        assert!(Chord::parse("Ctrl+Nope").is_err());
        assert_eq!(
            Chord::parse("cmd+shift+p").unwrap(),
            Chord {
                ctrl: true,
                shift: true,
                alt: false,
                key: "P".into()
            }
        );
    }

    #[test]
    fn duplicate_bindings_are_refused_both_ways() {
        // burp.Zfhv.ZT asserts the chord is free *and* the action has no chord.
        let mut s = Shortcuts::with_defaults();
        let intruder = index_of("send_to_intruder").unwrap();
        let repeater = index_of("send_to_repeater").unwrap();
        let err = s
            .set(intruder, Some(Chord::parse("Ctrl+R").unwrap()))
            .unwrap_err();
        assert!(err.contains("Send to Repeater"), "{err}");
        assert_eq!(s.chord_for(intruder).unwrap().format(), "Ctrl+I");

        // Freeing the chord first makes the move legal, and it leaves exactly
        // one owner.
        s.set(repeater, None).unwrap();
        s.set(intruder, Some(Chord::parse("Ctrl+R").unwrap()))
            .unwrap();
        assert_eq!(s.chord_for(intruder).unwrap().format(), "Ctrl+R");
        assert_eq!(s.chord_for(repeater), None);

        // The other direction: one action cannot hold two chords.
        let other = index_of("switch_to_proxy").unwrap();
        assert!(s
            .set(intruder, Some(Chord::parse("Ctrl+P").unwrap()))
            .is_ok());
        assert_eq!(s.chord_for(intruder).unwrap().format(), "Ctrl+P");
        assert!(ACTIONS[other].default.is_some());
    }

    #[test]
    fn json_round_trip_keeps_custom_bindings() {
        let mut s = Shortcuts::with_defaults();
        let idx = index_of("switch_to_proxy").unwrap();
        s.set(idx, Some(Chord::parse("Ctrl+Alt+P").unwrap()))
            .unwrap();
        let back = Shortcuts::from_json(&s.to_json());
        assert_eq!(back.chord_for(idx).unwrap().format(), "Ctrl+Alt+P");
        // Defaults survive too.
        assert_eq!(
            back.chord_for(index_of("send_to_repeater").unwrap())
                .unwrap()
                .format(),
            "Ctrl+R"
        );
    }

    #[test]
    fn stored_conflicts_do_not_steal_both_bindings() {
        // File order decides; the later duplicate is left unbound.
        let json = r#"{"hotkeys":[["send_to_repeater","Ctrl+R"],["send_to_intruder","Ctrl+R"]]}"#;
        let s = Shortcuts::from_json(json);
        assert_eq!(
            s.chord_for(index_of("send_to_repeater").unwrap())
                .unwrap()
                .format(),
            "Ctrl+R"
        );
        assert_eq!(s.chord_for(index_of("send_to_intruder").unwrap()), None);
    }

    #[test]
    fn an_unbound_action_stays_unbound_after_a_reload() {
        // Burp's file is authoritative (burp.Zfhv.Zh clears then applies), so
        // an empty string has to mean "no hotkey", not "fall back to default".
        let mut s = Shortcuts::with_defaults();
        let idx = index_of("issue_repeater_request").unwrap();
        s.set(idx, None).unwrap();
        let back = Shortcuts::from_json(&s.to_json());
        assert_eq!(back.chord_for(idx), None);
        assert_eq!(
            back.chord_for(index_of("send_to_repeater").unwrap())
                .unwrap()
                .format(),
            "Ctrl+R"
        );
    }

    #[test]
    fn palette_lists_wired_commands_recents_first_and_filters() {
        let mut s = Shortcuts::with_defaults();
        let all = s.palette_rows("");
        assert!(all.iter().all(|&i| ACTIONS[i].support == Support::Wired));
        assert!(!all.contains(&index_of("switch_to_logger").unwrap()));

        let filtered = s.palette_rows("repeater");
        assert!(filtered
            .iter()
            .any(|&i| ACTIONS[i].id == "send_to_repeater"));
        assert!(filtered
            .iter()
            .any(|&i| ACTIONS[i].id == "switch_to_repeater"));

        s.note_used(index_of("switch_to_proxy").unwrap());
        assert_eq!(s.palette_rows("")[0], index_of("switch_to_proxy").unwrap());
    }

    #[test]
    fn reset_restores_the_burp_default() {
        let mut s = Shortcuts::with_defaults();
        let idx = index_of("toggle_proxy_interception").unwrap();
        s.set(idx, Some(Chord::parse("Ctrl+Alt+T").unwrap()))
            .unwrap();
        assert!(!s.is_default(idx));
        s.reset(idx);
        assert!(s.is_default(idx));
        assert_eq!(s.chord_for(idx).unwrap().format(), "Ctrl+T");
    }
}
