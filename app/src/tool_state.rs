//! Tool-owned desktop state. Extracted from `App` without changing defaults.
use crate::{analysis, compare, decoder_ops, net, seq_bits, sync::Mutex, table};
use eframe::egui;
use std::sync::Arc;

pub struct ComparerState {
    /// Comparer items (shown in both tables), selections, comparison window.
    pub items: Vec<String>,
    pub sel1: Option<usize>,
    pub sel2: Option<usize>,
    pub table1: table::TableState,
    pub table2: table::TableState,
    pub paste_pending: bool,
    pub load_path: String,
    pub window: Option<(usize, usize, bool)>,
    /// The token-level comparison shown in the compare window, and the file
    /// its Export button writes.
    pub result: Option<compare::Comparison>,
    /// Comparer result window: Hex view, Sync views, shared scroll offset.
    pub hex: bool,
    pub sync: bool,
    pub scroll: egui::Vec2,
    pub export_path: String,
    /// Which Compare button opened the window (Words, Bytes, Characters).
    pub unit_label: &'static str,
}
impl Default for ComparerState {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            sel1: None,
            sel2: None,
            table1: table::TableState::default(),
            table2: table::TableState::default(),
            paste_pending: false,
            load_path: String::new(),
            window: None,
            result: None,
            hex: false,
            sync: false,
            scroll: egui::Vec2::ZERO,
            export_path: std::env::temp_dir()
                .join("comparer.html")
                .display()
                .to_string(),
            unit_label: "Words",
        }
    }
}

#[derive(Default)]
pub struct DecoderState {
    /// Decoder: the input pane shows hex.
    pub hex: bool,
    /// Decoder stages after the input: (text, hex view).
    pub chain: Vec<(String, bool)>,
    pub input: String,
    pub results: Vec<(String, String)>,
    /// Latest Decoder output (P-07).
    pub output: String,
    pub sel_decode: Option<decoder_ops::Op>,
    pub sel_encode: Option<decoder_ops::Op>,
    pub sel_hash: Option<decoder_ops::Op>,
}

pub struct SequencerState {
    /// Sequencer (Burp layout): sub-tab, requests sent here, token location
    /// (0 cookie, 1 form field, 2 custom regex), live capture state.
    pub sub: usize,
    pub requests: Vec<net::HistEntry>,
    pub req_sel: Option<usize>,
    pub table: table::TableState,
    pub loc: usize,
    pub field: String,
    pub custom: String,
    pub load_path: String,
    pub live_buf: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    pub live_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub mode: usize,
    pub ignore_abnormal: bool,
    /// Live capture: stop after this many tokens; re-analyse as they arrive.
    pub capture_limit: usize,
    pub auto_analyze: bool,
    pub selector: String,
    pub manual: String,
    pub samples: Vec<Vec<u8>>,
    pub stats: Option<analysis::TokenStats>,
    pub report: Option<analysis::SequencerReport>,
    /// Bit-level analysis of `seq_samples` (None below 100 tokens) and the
    /// file its export buttons write to.
    pub bits: Option<seq_bits::BitReport>,
    pub export_path: String,
    pub status: String,
}
impl Default for SequencerState {
    fn default() -> Self {
        Self {
            sub: 0,
            requests: Vec::new(),
            req_sel: None,
            table: table::TableState::default(),
            loc: 0,
            field: String::new(),
            custom: String::new(),
            load_path: String::new(),
            live_buf: None,
            live_stop: None,
            mode: 0,
            ignore_abnormal: true,
            capture_limit: 20_000,
            auto_analyze: true,
            selector: "session".to_string(),
            manual: String::new(),
            samples: Vec::new(),
            stats: None,
            report: None,
            bits: None,
            export_path: std::env::temp_dir()
                .join("sequencer-analysis.csv")
                .display()
                .to_string(),
            status: String::new(),
        }
    }
}

/// Repeater UI only. The separate repeater_ops::State also owns Intercept and
/// WebSocket behavior and is deliberately not folded into this view state.
pub struct RepeaterState {
    pub split: f32,
    pub req_pane: crate::msgpane::PaneState,
    pub resp_pane: crate::msgpane::PaneState,
    pub target_edit: bool,
    pub update_cl: bool,
    pub sel: usize,
    /// Legacy response/request view choices. Kept even though current panes
    /// store their own views, so this structural change removes no state.
    pub view: usize,
    pub req_view: usize,
}
impl Default for RepeaterState {
    fn default() -> Self {
        Self {
            split: 0.5,
            req_pane: crate::msgpane::PaneState {
                view: 1,
                ..Default::default()
            },
            resp_pane: crate::msgpane::PaneState::default(),
            target_edit: false,
            update_cl: true,
            sel: 0,
            view: 0,
            req_view: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RepeaterState;
    #[test]
    fn repeater_defaults_preserve_the_original_app_constructor() {
        let state = RepeaterState::default();
        assert_eq!(state.split, 0.5);
        assert_eq!(state.req_pane.view, 1);
        assert_eq!(state.resp_pane.view, 0);
        assert!(!state.target_edit);
        assert!(state.update_cl);
        assert_eq!(state.sel, 0);
        assert_eq!(state.view, 0);
        assert_eq!(state.req_view, 1);
    }
}
