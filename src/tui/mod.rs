// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Terminal User Interface (TUI) dashboard.
//!
//! Provides a tabbed dashboard using ratatui/crossterm with panels for:
//! - **Dashboard**: At-a-glance status overview with severity counts, monitor status, scan summary
//! - **Alerts**: Critical + Warning alerts only (all sources)
//! - **Commands**: Process/exec monitoring (auditd, behavior, policy, barnacle, falco)
//! - **Network**: Network activity + logins (network, auditd:net_connect, ssh, firewall)
//! - **FIM**: File integrity monitoring (sentinel, samhain, cognitive)
//! - **Scans**: Periodic security scan results (scan:*)
//! - **Config**: Interactive config editor with section sidebar
//!
//! The config editor supports in-place editing of all config fields, bool toggling,
//! sudo-authenticated saves (chattr dance), and action buttons for installing
//! optional tools (Falco, Samhain).
//!
//! The config editor logic is in the [`config_editor`] submodule.

mod config_editor;
#[allow(unused_imports)]
pub use config_editor::{ConfigField, ConfigFocus, FieldType, DropdownState};
use config_editor::get_section_fields;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs},
};
use zeroize::Zeroize;
use std::collections::HashMap;
use std::io;
use tokio::sync::{mpsc, watch};
use std::time::Duration;
use std::path::{Path, PathBuf};

use crate::alerts::{Alert, AlertStore, Severity};
use crate::config::Config;
use crate::response::{PendingStatus, ResponseRequest, SharedPendingActions};
use crate::scanner::SharedScanResults;

// ── Layout constants ──────────────────────────────────────────────────────────
// Task 6.5: Centralized magic numbers for TUI layout dimensions.

/// Number of tabs in the TUI (Dashboard, Alerts, Commands, Network, FIM, Scans, Config).
const TAB_COUNT: usize = 7;

/// Tab indices for semantic access.
const TAB_DASHBOARD: usize = 0;
const TAB_ALERTS: usize = 1;
const TAB_COMMANDS: usize = 2;
const TAB_NETWORK: usize = 3;
const TAB_FIM: usize = 4;
const TAB_SCANS: usize = 5;
const TAB_CONFIG: usize = 6;

/// Height of the tab bar in rows.
const TAB_BAR_HEIGHT: u16 = 3;
/// Height of the footer/status bar in rows.
const FOOTER_HEIGHT: u16 = 1;

/// Dashboard header height (art + pun area).
const DASHBOARD_HEADER_HEIGHT: u16 = 6;
/// Dashboard bottom status bar height.
const DASHBOARD_BOTTOM_HEIGHT: u16 = 3;
/// Dashboard header text column width (when lobster art shown).
const DASHBOARD_HEADER_TEXT_WIDTH: u16 = 54;
/// Dashboard header lobster art column width.
const DASHBOARD_HEADER_ART_WIDTH: u16 = 18;
/// Minimum terminal width to show lobster art in the dashboard header.
const DASHBOARD_ART_MIN_WIDTH: u16 = 72;
/// Dashboard severity counter panel height.
const DASHBOARD_SEVERITY_HEIGHT: u16 = 6;
/// Dashboard monitor status panel height.
const DASHBOARD_MONITOR_HEIGHT: u16 = 9;
/// Number of recent critical alerts to show on the dashboard.
const DASHBOARD_RECENT_CRITS: usize = 5;

/// Sudo popup preferred width.
const SUDO_POPUP_WIDTH: u16 = 60;
/// Sudo popup preferred height.
const SUDO_POPUP_HEIGHT: u16 = 9;
/// Margin subtracted from terminal width for popup clamping.
const POPUP_WIDTH_MARGIN: u16 = 4;
/// Margin subtracted from terminal height for popup clamping.
const POPUP_HEIGHT_MARGIN: u16 = 2;

/// Approval popup preferred width.
const APPROVAL_POPUP_WIDTH: u16 = 70;
/// Approval popup base height (before adding action lines).
const APPROVAL_POPUP_BASE_HEIGHT: u16 = 14;

/// Config editor sidebar width as percentage.
const CONFIG_SIDEBAR_PCT: u16 = 25;
/// Config editor fields panel width as percentage.
const CONFIG_FIELDS_PCT: u16 = 75;

/// Padding subtracted from area width for detail view word-wrap.
const DETAIL_WRAP_PADDING: u16 = 4;

// ── Tab filter configuration ──────────────────────────────────────────────────
// Task 6.2: Single source of truth for per-tab alert filtering.

/// How to filter alerts by source in a list tab.
enum SourceFilter<'a> {
    /// Show all sources (no source filter applied).
    All,
    /// Show only alerts whose source exactly matches one of these strings.
    Exact(&'a [&'a str]),
    /// Show only alerts whose source starts with one of these prefixes.
    Prefix(&'a [&'a str]),
    /// Show alerts matching exact sources OR prefix patterns.
    Mixed { exact: &'a [&'a str], prefix: &'a [&'a str] },
}

impl SourceFilter<'_> {
    /// Test whether an alert's source matches this filter.
    fn matches_source(&self, source: &str) -> bool {
        match self {
            SourceFilter::All => true,
            SourceFilter::Exact(sources) => sources.iter().any(|s| *s == source),
            SourceFilter::Prefix(prefixes) => prefixes.iter().any(|p| source.starts_with(p)),
            SourceFilter::Mixed { exact, prefix } => {
                exact.iter().any(|s| *s == source)
                    || prefix.iter().any(|p| source.starts_with(p))
            }
        }
    }
}

/// Per-tab filter configuration: which sources to show, minimum severity, and display title.
///
/// This is the single source of truth for tab-based alert filtering. It is used by:
/// - `render_alert_list` (rendering)
/// - `on_key` Enter handler (selecting an alert for detail view)
/// - `ui` badge counts (tab bar numbers)
struct TabFilterConfig<'a> {
    source_filter: SourceFilter<'a>,
    min_severity: Option<Severity>,
    title: &'a str,
}

/// Source lists for each tab, defined once and shared by `tab_filter_config` and badge counts.
const CMD_SOURCES: &[&str] = &["auditd", "behavior", "policy", "barnacle", "falco"];
const NET_SOURCES: &[&str] = &["network", "auditd:net_connect", "ssh", "firewall"];
const FIM_EXACT_SOURCES: &[&str] = &["sentinel", "samhain"];
const FIM_PREFIX_SOURCES: &[&str] = &["scan:cognitive"];
const SCAN_PREFIX: &[&str] = &["scan:"];

/// Return the filter configuration for alert-list tabs (1-5).
/// Returns `None` for non-list tabs (0=Dashboard, 6=Config).
fn tab_filter_config(tab: usize) -> Option<TabFilterConfig<'static>> {
    match tab {
        TAB_ALERTS => Some(TabFilterConfig {
            source_filter: SourceFilter::All,
            min_severity: Some(Severity::Warning),
            title: "Alerts (Warning+)",
        }),
        TAB_COMMANDS => Some(TabFilterConfig {
            source_filter: SourceFilter::Exact(CMD_SOURCES),
            min_severity: None,
            title: "Commands",
        }),
        TAB_NETWORK => Some(TabFilterConfig {
            source_filter: SourceFilter::Exact(NET_SOURCES),
            min_severity: None,
            title: "Network",
        }),
        TAB_FIM => Some(TabFilterConfig {
            source_filter: SourceFilter::Mixed {
                exact: FIM_EXACT_SOURCES,
                prefix: FIM_PREFIX_SOURCES,
            },
            min_severity: None,
            title: "File Integrity",
        }),
        TAB_SCANS => Some(TabFilterConfig {
            source_filter: SourceFilter::Prefix(SCAN_PREFIX),
            min_severity: None,
            title: "Security Scans",
        }),
        _ => None,
    }
}

/// Count how many alerts match a given tab's filter (source + severity only, no search/mute).
/// Used by the tab bar badge counts.
fn tab_alert_count(alerts: &[Alert], tab: usize) -> usize {
    match tab_filter_config(tab) {
        Some(cfg) => alerts.iter().filter(|a| {
            cfg.source_filter.matches_source(&a.source)
                && cfg.min_severity.as_ref().map_or(true, |min| a.severity >= *min)
        }).count(),
        None => 0,
    }
}

// ── Input mode dispatch ───────────────────────────────────────────────────────
// Task 6.4: Enum-based input mode for flattened key dispatch.

/// Current input mode, determining which handler processes keyboard events.
///
/// The mode is derived from app state (popup presence, search/detail flags, active tab)
/// rather than stored separately, so it always reflects the true UI state.
enum InputMode {
    /// Sudo password popup is active (password entry or status display).
    SudoPassword,
    /// Response engine approval popup is active.
    ApprovalPrompt,
    /// Search bar is active (typing a search query).
    Searching,
    /// Alert detail view is open (showing a single alert).
    DetailView,
    /// Normal tab interaction (navigation, scrolling, editing).
    TabActive,
}

const PUNS: &[&str] = &[
    "Feeling crabby? That's just good security posture.",
    "This lobster never sleeps. Neither do your attackers.",
    "Shell we check the firewall?",
    "Don't be shellfish with your security budget.",
    "Pinch me, I must be monitoring.",
    "You butter believe this system is locked down.",
    "Claw and order: special monitoring unit.",
    "No phishing allowed in these waters.",
    "Keep your claws off the config files.",
    "This tower is built on a rock... lobster.",
    "Crustacean creation, zero exfiltration.",
    "If the shell fits, monitor it.",
    "Security is no fluke — it's a lobster.",
    "The best defense is a good claw-ffense.",
    "Shrimply the best watchdog around.",
    "Red alert? Must be a lobster thing.",
    "In crust we trust.",
    "Lobster thermidor of threat detection.",
    "Keep calm and claw on.",
    "Every byte you make, I'll be watching you.",
    "Snap, crackle, block.",
    "Gone in 60 seconds? Not on my watch.",
    "Armor plated, barnacle rated.",
    "Zero trust, maximum crust.",
];

#[allow(dead_code)]
pub enum TuiEvent {
    Alert(Alert),
    Tick,
    Quit,
}

/// Main TUI application state.
///
/// Holds the alert store, tab selection, config editor state, and sudo popup state.
/// Updated by `on_key()` handlers and rendered by the `ui()` function.
pub struct App {
    pub alert_store: AlertStore,
    pub selected_tab: usize,
    pub should_quit: bool,
    pub tab_titles: Vec<String>,
    // Config editor state
    pub config: Option<Config>,
    pub config_path: Option<PathBuf>,
    pub config_sections: Vec<String>,
    pub config_selected_section: usize,
    pub config_fields: Vec<ConfigField>,
    pub config_selected_field: usize,
    pub config_focus: ConfigFocus,
    pub config_editing: bool,
    pub config_edit_buffer: String,
    pub config_dropdown: Option<DropdownState>,
    pub config_saved_message: Option<String>,
    // Sudo popup state
    pub sudo_popup: Option<SudoPopup>,
    // Scroll state per tab (tab index -> ListState)
    pub list_states: [ListState; TAB_COUNT], // slots 0 (Dashboard) and 6 (Config) unused
    // Alert detail view
    pub detail_alert: Option<Alert>,
    // Search/filter
    pub search_active: bool,
    pub search_buffer: String,
    pub search_filter: String, // committed search (applied on Enter)
    // Pause alert feed
    pub paused: bool,
    // Cached tool installation status
    pub tool_status_cache: HashMap<String, bool>,
    // Muted sources (alerts from these sources are hidden)
    pub muted_sources: Vec<String>,
    // Response engine integration
    pub pending_actions: SharedPendingActions,
    pub response_tx: Option<mpsc::Sender<ResponseRequest>>,
    pub approval_popup: Option<ApprovalPopup>,
    // Dashboard state
    pub startup_time: std::time::Instant,
    pub scan_results: Option<SharedScanResults>,
    pub pun_index: usize,
    // Live path switching for falco/samhain tailers
    pub falco_path_tx: Option<watch::Sender<PathBuf>>,
    pub samhain_path_tx: Option<watch::Sender<PathBuf>>,
}

/// State for the modal sudo password prompt overlay.
pub struct SudoPopup {
    /// Action to run after successful authentication.
    pub action: String,
    /// Password being typed (shown as dots).
    pub password: String,
    /// Human-readable description of the pending action.
    pub message: String,
    /// Current progress state.
    pub status: SudoStatus,
}

impl Drop for SudoPopup {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Progress state of a sudo authentication attempt.
pub enum SudoStatus {
    /// Waiting for user to type password.
    WaitingForPassword,
    /// Command is executing.
    Running,
    /// Authentication or command failed with an error message.
    Failed(String),
}

/// State for the response engine approval popup.
pub struct ApprovalPopup {
    /// The pending action being reviewed.
    pub action_id: String,
    pub threat_source: String,
    pub threat_message: String,
    pub severity: Severity,
    pub actions_display: Vec<String>,
    pub playbook: Option<String>,
    /// Currently selected: 0 = Approve, 1 = Deny
    pub selected: usize,
    /// Optional message/annotation
    pub message_buffer: String,
    /// Whether the message field is being edited
    pub editing_message: bool,
}

impl App {
    /// Create a new TUI application with default state.
    pub fn new(pending_actions: SharedPendingActions, response_tx: Option<mpsc::Sender<ResponseRequest>>) -> Self {
        Self {
            alert_store: AlertStore::new(500),
            selected_tab: 0,
            should_quit: false,
            tab_titles: vec![
                "Dashboard".into(),
                "Alerts".into(),
                "Commands".into(),
                "Network".into(),
                "FIM".into(),
                "Scans".into(),
                "Config".into(),
            ],
            config: None,
            config_path: None,
            config_sections: vec![
                "general".into(), "slack".into(), "auditd".into(), "network".into(),
                "falco".into(), "samhain".into(), "api".into(), "scans".into(),
                "proxy".into(), "policy".into(), "barnacle".into(), "netpolicy".into(),
                "response".into(), "prompt_firewall".into(),
            ],
            config_selected_section: 0,
            config_fields: Vec::new(),
            config_selected_field: 0,
            config_focus: ConfigFocus::Sidebar,
            config_editing: false,
            config_edit_buffer: String::new(),
            config_dropdown: None,
            config_saved_message: None,
            sudo_popup: None,
            list_states: std::array::from_fn(|_| {
                let mut s = ListState::default();
                s.select(Some(0));
                s
            }),
            detail_alert: None,
            search_active: false,
            search_buffer: String::new(),
            search_filter: String::new(),
            paused: false,
            tool_status_cache: HashMap::new(),
            muted_sources: Vec::new(),
            pending_actions,
            response_tx,
            approval_popup: None,
            startup_time: std::time::Instant::now(),
            scan_results: None,
            pun_index: {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut h = DefaultHasher::new();
                std::time::SystemTime::now().hash(&mut h);
                (h.finish() as usize) % PUNS.len()
            },
            falco_path_tx: None,
            samhain_path_tx: None,
        }
    }

    /// Load configuration from a file and populate the editor fields.
    pub fn load_config(&mut self, path: &Path) -> Result<()> {
        let config = Config::load(path)?;
        self.config = Some(config);
        self.config_path = Some(path.to_path_buf());
        self.refresh_fields();
        Ok(())
    }

    /// Rebuild the field list for the currently selected config section.
    pub fn refresh_fields(&mut self) {
        // Pre-cache tool status before borrowing config
        let _ = self.is_tool_installed("falco");
        let _ = self.is_tool_installed("samhain");
        if let Some(ref config) = self.config {
            let section = &self.config_sections[self.config_selected_section];
            self.config_fields = get_section_fields(config, section, &self.tool_status_cache);
            if self.config_selected_field >= self.config_fields.len() && !self.config_fields.is_empty() {
                self.config_selected_field = 0;
            }
        }
    }

    /// Check and cache whether a tool is installed (runs `which` once per tool).
    pub fn is_tool_installed(&mut self, tool: &str) -> bool {
        if let Some(&cached) = self.tool_status_cache.get(tool) {
            return cached;
        }
        let installed = std::process::Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        self.tool_status_cache.insert(tool.to_string(), installed);
        installed
    }

    /// Invalidate cached tool status (e.g., after installing).
    pub fn invalidate_tool_cache(&mut self) {
        self.tool_status_cache.clear();
    }

    /// Determine the current input mode from application state.
    fn input_mode(&self) -> InputMode {
        if self.sudo_popup.is_some() {
            InputMode::SudoPassword
        } else if self.approval_popup.is_some() {
            InputMode::ApprovalPrompt
        } else if self.search_active {
            InputMode::Searching
        } else if self.detail_alert.is_some() {
            InputMode::DetailView
        } else {
            InputMode::TabActive
        }
    }

    /// Handle a keyboard event, dispatching to the appropriate mode handler.
    pub fn on_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        match self.input_mode() {
            InputMode::SudoPassword => self.on_key_sudo(key),
            InputMode::ApprovalPrompt => self.on_key_approval(key),
            InputMode::Searching => self.on_key_search(key),
            InputMode::DetailView => self.on_key_detail(key),
            InputMode::TabActive => self.on_key_tab(key, modifiers),
        }
    }

    /// Handle keys while the sudo password popup is active.
    fn on_key_sudo(&mut self, key: KeyCode) {
        let popup = match self.sudo_popup {
            Some(ref mut p) => p,
            None => return,
        };
        match &popup.status {
            SudoStatus::WaitingForPassword => {
                match key {
                    KeyCode::Esc => { self.sudo_popup = None; }
                    KeyCode::Enter => {
                        let password = popup.password.clone();
                        let action = popup.action.clone();
                        popup.status = SudoStatus::Running;
                        self.run_sudo_action(&action, &password);
                    }
                    KeyCode::Backspace => { popup.password.pop(); }
                    KeyCode::Char(c) => { popup.password.push(c); }
                    _ => {}
                }
            }
            SudoStatus::Running => {}
            SudoStatus::Failed(_) => {
                // Any key dismisses
                self.sudo_popup = None;
            }
        }
    }

    /// Handle keys while the approval popup is active.
    fn on_key_approval(&mut self, key: KeyCode) {
        let popup = match self.approval_popup {
            Some(ref mut p) => p,
            None => return,
        };
        if popup.editing_message {
            match key {
                KeyCode::Esc => { popup.editing_message = false; }
                KeyCode::Backspace => { popup.message_buffer.pop(); }
                KeyCode::Char(c) => { popup.message_buffer.push(c); }
                KeyCode::Enter => { popup.editing_message = false; }
                _ => {}
            }
            return;
        }
        match key {
            KeyCode::Up | KeyCode::Down => {
                popup.selected = if popup.selected == 0 { 1 } else { 0 };
            }
            KeyCode::Char('m') => {
                popup.editing_message = true;
            }
            KeyCode::Enter => {
                let approved = popup.selected == 0;
                let action_id = popup.action_id.clone();
                let msg = if popup.message_buffer.is_empty() { None } else { Some(popup.message_buffer.clone()) };
                self.approval_popup = None;

                // Send resolution
                if let Some(ref tx) = self.response_tx {
                    let resolve = ResponseRequest::Resolve {
                        id: action_id,
                        approved,
                        by: "admin".to_string(),
                        message: msg,
                        surface: "tui".to_string(),
                    };
                    let _ = tx.try_send(resolve);
                }
            }
            KeyCode::Esc => {
                self.approval_popup = None;
            }
            _ => {}
        }
    }

    /// Handle keys while the search bar is active.
    fn on_key_search(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => {
                self.search_filter = self.search_buffer.clone();
                self.search_active = false;
            }
            KeyCode::Esc => {
                self.search_active = false;
                self.search_buffer.clear();
            }
            KeyCode::Backspace => { self.search_buffer.pop(); }
            KeyCode::Char(c) => { self.search_buffer.push(c); }
            _ => {}
        }
    }

    /// Handle keys while the alert detail view is open.
    fn on_key_detail(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => {
                self.detail_alert = None;
            }
            KeyCode::Char('m') => {
                // Mute/unmute the source of the viewed alert
                if let Some(ref alert) = self.detail_alert {
                    let src = alert.source.clone();
                    if let Some(pos) = self.muted_sources.iter().position(|s| s == &src) {
                        self.muted_sources.remove(pos);
                    } else {
                        self.muted_sources.push(src);
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle keys during normal tab interaction (no popup/overlay active).
    fn on_key_tab(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        // Clear saved message on any keypress
        if self.config_saved_message.is_some() {
            self.config_saved_message = None;
        }

        let is_alert_tab = (TAB_ALERTS..=TAB_SCANS).contains(&self.selected_tab);

        match key {
            KeyCode::Char('q') | KeyCode::Esc if !self.config_editing => {
                // If search filter is active, Esc clears it first
                if !self.search_filter.is_empty() && key == KeyCode::Esc {
                    self.search_filter.clear();
                    self.search_buffer.clear();
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Tab if !self.config_editing => {
                self.selected_tab = (self.selected_tab + 1) % self.tab_titles.len();
            }
            KeyCode::BackTab if !self.config_editing => {
                if self.selected_tab > 0 {
                    self.selected_tab -= 1;
                } else {
                    self.selected_tab = self.tab_titles.len() - 1;
                }
            }
            KeyCode::Right if !self.config_editing && (self.selected_tab != TAB_CONFIG || self.config_focus != ConfigFocus::Fields) => {
                self.selected_tab = (self.selected_tab + 1) % self.tab_titles.len();
                if self.selected_tab == TAB_CONFIG { self.config_focus = ConfigFocus::Sidebar; }
            }
            KeyCode::Left if !self.config_editing && (self.selected_tab != TAB_CONFIG || self.config_focus != ConfigFocus::Fields) => {
                if self.selected_tab > 0 {
                    self.selected_tab -= 1;
                } else {
                    self.selected_tab = self.tab_titles.len() - 1;
                }
                if self.selected_tab == TAB_CONFIG { self.config_focus = ConfigFocus::Sidebar; }
            }
            // Alert list tabs: scroll, select, search, pause
            KeyCode::Up if is_alert_tab => {
                let state = &mut self.list_states[self.selected_tab];
                let i = state.selected().unwrap_or(0);
                state.select(Some(i.saturating_sub(1)));
            }
            KeyCode::Down if is_alert_tab => {
                let state = &mut self.list_states[self.selected_tab];
                let i = state.selected().unwrap_or(0);
                state.select(Some(i + 1)); // ListState clamps to list len during render
            }
            KeyCode::Enter if is_alert_tab => {
                self.open_selected_alert_detail();
            }
            KeyCode::Char('/') if is_alert_tab => {
                self.search_active = true;
                self.search_buffer = self.search_filter.clone();
            }
            KeyCode::Char(' ') if is_alert_tab => {
                self.paused = !self.paused;
            }
            // Config tab specific keys
            _ if self.selected_tab == TAB_CONFIG => config_editor::handle_config_key(self, key, modifiers),
            _ => {}
        }
    }

    /// Open the detail view for the currently selected alert in the active list tab.
    ///
    /// Uses `TabFilterConfig` to apply the same filter as `render_alert_list`,
    /// ensuring the selected index corresponds to the correct alert.
    fn open_selected_alert_detail(&mut self) {
        let tab = self.selected_tab;
        let cfg = match tab_filter_config(tab) {
            Some(c) => c,
            None => return,
        };
        let selected_idx = self.list_states[tab].selected().unwrap_or(0);
        let filtered: Vec<&Alert> = self.filter_alerts_for_tab(&cfg);
        if let Some(alert) = filtered.get(selected_idx) {
            self.detail_alert = Some((*alert).clone());
        }
    }

    /// Filter alerts using the given tab config, respecting muted sources and search filter.
    fn filter_alerts_for_tab<'a>(&'a self, cfg: &TabFilterConfig<'_>) -> Vec<&'a Alert> {
        self.alert_store.alerts()
            .iter()
            .rev()
            .filter(|a| {
                if !cfg.source_filter.matches_source(&a.source) { return false; }
                if let Some(ref min_sev) = cfg.min_severity {
                    if a.severity < *min_sev { return false; }
                }
                if self.muted_sources.contains(&a.source) { return false; }
                if !self.search_filter.is_empty() {
                    let h = a.to_string().to_lowercase();
                    if !h.contains(&self.search_filter.to_lowercase()) { return false; }
                }
                true
            })
            .collect()
    }

    fn run_action(&mut self, action: &str) {
        let needs_sudo = !nix_is_root();
        let description = match action {
            "install_falco" => "Install Falco (apt-get install falco)",
            "install_samhain" => "Install Samhain (apt-get install samhain)",
            _ => return,
        };

        if needs_sudo {
            self.sudo_popup = Some(SudoPopup {
                action: action.to_string(),
                password: String::new(),
                message: description.to_string(),
                status: SudoStatus::WaitingForPassword,
            });
        } else {
            self.run_sudo_action(action, "");
        }
    }

    fn run_sudo_action(&mut self, action: &str, password: &str) {
        // Config save uses direct Command execution (no shell) to prevent path injection.
        // Install actions use shell commands (no user-controlled input).
        if let Some(path) = action.strip_prefix("save_config:") {
            self.run_config_save(path, password);
            return;
        }

        let shell_cmd: &str = match action {
            "install_falco" => "apt-get update -qq && apt-get install -y -qq falco 2>&1 || dnf install -y falco 2>&1 || echo 'INSTALL_FAILED'",
            "install_samhain" => "apt-get update -qq && apt-get install -y -qq samhain 2>&1 || dnf install -y samhain 2>&1 || echo 'INSTALL_FAILED'",
            _ => return,
        };

        let result = if nix_is_root() || password.is_empty() {
            std::process::Command::new("bash")
                .args(["-c", shell_cmd])
                .output()
        } else {
            // Pipe password to sudo -S
            use std::io::Write;
            let mut child = match std::process::Command::new("sudo")
                .args(["-S", "bash", "-c", shell_cmd])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        self.sudo_popup = Some(SudoPopup {
                            action: action.to_string(),
                            password: String::new(),
                            message: String::new(),
                            status: SudoStatus::Failed(format!("Failed to spawn sudo: {}", e)),
                        });
                        return;
                    }
                };
            if let Some(ref mut stdin) = child.stdin {
                let _ = writeln!(stdin, "{}", password);
            }
            child.wait_with_output()
        };

        self.sudo_popup = None;

        match result {
            Ok(output) => {
                let out = String::from_utf8_lossy(&output.stdout);
                let err = String::from_utf8_lossy(&output.stderr);
                if output.status.success() && !out.contains("INSTALL_FAILED") {
                    self.invalidate_tool_cache();
                    self.config_saved_message = Some("Installed! Refresh with Left/Right.".to_string());
                } else if err.contains("incorrect password") || err.contains("Sorry, try again") {
                    self.config_saved_message = Some("Wrong password".to_string());
                } else {
                    self.config_saved_message = Some(format!("Install failed: {}", err.chars().take(80).collect::<String>()));
                }
            }
            Err(e) => {
                self.config_saved_message = Some(format!("{}", e));
            }
        }
        self.refresh_fields();
    }

    /// Execute config save as individual Command calls — no shell interpolation.
    /// This prevents shell injection via crafted config file paths.
    fn run_config_save(&mut self, path: &str, password: &str) {
        let use_sudo = !nix_is_root() && !password.is_empty();
        let tmp = "/tmp/clawtower-config-save.toml";

        // Helper: run a command, optionally wrapped with sudo -S + piped password.
        let run = |prog: &str, args: &[&str]| -> Result<std::process::Output, std::io::Error> {
            if use_sudo {
                use std::io::Write;
                let mut sudo_args = vec!["-S", prog];
                sudo_args.extend_from_slice(args);
                let mut child = std::process::Command::new("sudo")
                    .args(&sudo_args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;
                if let Some(ref mut stdin) = child.stdin {
                    let _ = writeln!(stdin, "{}", password);
                }
                child.wait_with_output()
            } else {
                std::process::Command::new(prog)
                    .args(args)
                    .output()
            }
        };

        // Step 1: chattr -i (ignore errors — file may not have immutable flag)
        let _ = run("chattr", &["-i", path]);

        // Step 2: cp tmp file to destination
        let cp_result = run("cp", &[tmp, path]);
        let ok = match &cp_result {
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr);
                if err.contains("incorrect password") || err.contains("Sorry, try again") {
                    self.sudo_popup = None;
                    self.config_saved_message = Some("Wrong password".to_string());
                    self.refresh_fields();
                    return;
                }
                output.status.success()
            }
            Err(_) => false,
        };

        if !ok {
            self.sudo_popup = None;
            let msg = match cp_result {
                Ok(output) => format!("Config save failed: {}", String::from_utf8_lossy(&output.stderr).chars().take(80).collect::<String>()),
                Err(e) => format!("{}", e),
            };
            self.config_saved_message = Some(msg);
            self.refresh_fields();
            return;
        }

        // Step 3: chattr +i (re-protect)
        let _ = run("chattr", &["+i", path]);

        // Step 4: clean up tmp file
        let _ = run("rm", &["-f", tmp]);

        self.sudo_popup = None;
        self.config_saved_message = Some("Saved!".to_string());
        self.refresh_fields();
        self.notify_path_changes();
    }

    /// Notify falco/samhain tailers if their log path changed in config.
    fn notify_path_changes(&self) {
        if let Some(ref config) = self.config {
            if let Some(ref tx) = self.falco_path_tx {
                let new = PathBuf::from(&config.falco.log_path);
                if *tx.borrow() != new {
                    let _ = tx.send(new);
                }
            }
            if let Some(ref tx) = self.samhain_path_tx {
                let new = PathBuf::from(&config.samhain.log_path);
                if *tx.borrow() != new {
                    let _ = tx.send(new);
                }
            }
        }
    }
}

fn nix_is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn render_alert_list(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    tab_index: usize,
    source_filter: SourceFilter,
    min_severity: Option<Severity>,
    title: &str,
) {
    let alerts = app.alert_store.alerts();
    let filtered: Vec<&Alert> = alerts
        .iter()
        .rev()
        .filter(|a| {
            if !source_filter.matches_source(&a.source) { return false; }
            if let Some(ref min_sev) = min_severity {
                if &a.severity < min_sev { return false; }
            }
            if app.muted_sources.contains(&a.source) {
                return false;
            }
            if !app.search_filter.is_empty() {
                let haystack = a.to_string().to_lowercase();
                if !haystack.contains(&app.search_filter.to_lowercase()) {
                    return false;
                }
            }
            true
        })
        .collect();

    let now = chrono::Local::now();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|alert| {
            let age = now.signed_duration_since(alert.timestamp);
            let age_str = crate::util::format_age_short(age);

            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Blue),
            };
            ListItem::new(format!(
                "{} {} [{}] {}",
                age_str, alert.severity, alert.source, alert.message
            ))
            .style(style)
        })
        .collect();

    let count = items.len();
    let display_title = format!(" {} ({}) ", title, count);
    let pause_indicator = if app.paused { " PAUSED " } else { "" };
    let full_title = format!("{}{}", display_title, pause_indicator);

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(full_title))
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, &mut app.list_states[tab_index]);
}

fn render_dashboard(f: &mut Frame, area: Rect, app: &App) {
    use crate::scanner::ScanStatus;

    // Split into rows: header, middle panels, bottom status
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(DASHBOARD_HEADER_HEIGHT),
            Constraint::Min(0),
            Constraint::Length(DASHBOARD_BOTTOM_HEIGHT),
        ])
        .split(area);

    // --- HEADER: Lobster art + version + pun ---
    let version = format!("ClawTower v{}", env!("CARGO_PKG_VERSION"));
    let pun = PUNS[app.pun_index];

    let header_block = Block::default().borders(Borders::ALL).title(" Dashboard ");
    let header_inner = header_block.inner(rows[0]);
    f.render_widget(header_block, rows[0]);

    let show_lobster = header_inner.width >= DASHBOARD_ART_MIN_WIDTH;

    let text_lines = vec![
        Line::from(Span::styled(&version, Style::default().fg(Color::Cyan).bold())),
        Line::from(Span::styled("OS-level security watchdog for AI agents", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(pun, Style::default().fg(Color::Yellow).italic())),
    ];

    if show_lobster {
        let header_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(DASHBOARD_HEADER_TEXT_WIDTH),
                Constraint::Length(DASHBOARD_HEADER_ART_WIDTH),
                Constraint::Min(0),
            ])
            .split(header_inner);
        f.render_widget(Paragraph::new(text_lines), header_cols[0]);

        let lobster_lines = vec![
            Line::from(Span::styled(" /==g           _", Style::default().fg(Color::Blue))),
            Line::from(Span::styled("//      >>>/---{_", Style::default().fg(Color::Blue))),
            Line::from(Span::styled("`==::[[[[|:     _", Style::default().fg(Color::Blue))),
            Line::from(Span::styled("        >>>/---{_", Style::default().fg(Color::Blue))),
        ];
        f.render_widget(Paragraph::new(lobster_lines), header_cols[1]);
    } else {
        f.render_widget(Paragraph::new(text_lines), header_inner);
    }

    // --- MIDDLE: split into left and right columns ---
    let mid_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    // Left column: severity counters + recent critical alerts
    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(DASHBOARD_SEVERITY_HEIGHT), Constraint::Min(0)])
        .split(mid_cols[0]);

    // Severity counters
    let info_count = app.alert_store.count_by_severity(&Severity::Info);
    let warn_count = app.alert_store.count_by_severity(&Severity::Warning);
    let crit_count = app.alert_store.count_by_severity(&Severity::Critical);

    let severity_lines = vec![
        Line::from(vec![
            Span::styled(format!("  Critical: {}", crit_count), Style::default().fg(Color::Red).bold()),
        ]),
        Line::from(vec![
            Span::styled(format!("  Warning:  {}", warn_count), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(format!("  Info:     {}", info_count), Style::default().fg(Color::Blue)),
        ]),
        Line::from(vec![
            Span::raw(format!("  Total: {} alerts", app.alert_store.alerts().len())),
        ]),
    ];
    let severity_panel = Paragraph::new(severity_lines)
        .block(Block::default().borders(Borders::ALL).title(" Severity "));
    f.render_widget(severity_panel, left_rows[0]);

    // Recent critical alerts
    let now = chrono::Local::now();
    let recent_crits: Vec<&Alert> = app.alert_store.alerts()
        .iter()
        .rev()
        .filter(|a| a.severity == Severity::Critical)
        .take(DASHBOARD_RECENT_CRITS)
        .collect();
    let crit_lines: Vec<Line> = if recent_crits.is_empty() {
        vec![Line::from(Span::styled("  No critical alerts", Style::default().fg(Color::Green)))]
    } else {
        recent_crits.iter().map(|a| {
            let age = now.signed_duration_since(a.timestamp);
            let age_str = crate::util::format_age_compact(age);
            let max_msg = (mid_cols[0].width as usize).saturating_sub(12);
            let msg: String = a.message.chars().take(max_msg).collect();
            Line::from(vec![
                Span::styled(format!(" {:>3} ", age_str), Style::default().fg(Color::DarkGray)),
                Span::styled(msg, Style::default().fg(Color::Red)),
            ])
        }).collect()
    };
    let crits_panel = Paragraph::new(crit_lines)
        .block(Block::default().borders(Borders::ALL).title(" Recent Critical "));
    f.render_widget(crits_panel, left_rows[1]);

    // Right column: monitor status + scan summary
    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(DASHBOARD_MONITOR_HEIGHT), Constraint::Min(0)])
        .split(mid_cols[1]);

    // Monitor status (read from config)
    let monitor_lines = if let Some(ref config) = app.config {
        let status = |enabled: bool| -> Span {
            if enabled {
                Span::styled("ON ", Style::default().fg(Color::Green).bold())
            } else {
                Span::styled("OFF", Style::default().fg(Color::DarkGray))
            }
        };
        vec![
            Line::from(vec![Span::raw("  auditd:   "), status(config.auditd.enabled), Span::raw("  network:  "), status(config.network.enabled)]),
            Line::from(vec![Span::raw("  sentinel: "), status(config.sentinel.enabled), Span::raw("  ssh:      "), status(config.ssh.enabled)]),
            Line::from(vec![Span::raw("  barnacle: "), status(config.barnacle.enabled), Span::raw("  policy:   "), status(config.policy.enabled)]),
            Line::from(vec![Span::raw("  falco:    "), status(config.falco.enabled), Span::raw("  samhain:  "), status(config.samhain.enabled)]),
            Line::from(""),
            Line::from(vec![
                Span::raw("  Feed: "),
                if app.paused {
                    Span::styled("PAUSED", Style::default().fg(Color::Yellow).bold())
                } else {
                    Span::styled("LIVE", Style::default().fg(Color::Green).bold())
                },
            ]),
        ]
    } else {
        vec![Line::from(Span::styled("  Config not loaded", Style::default().fg(Color::DarkGray)))]
    };
    let monitor_panel = Paragraph::new(monitor_lines)
        .block(Block::default().borders(Borders::ALL).title(" Monitors "));
    f.render_widget(monitor_panel, right_rows[0]);

    // Scan summary (from SharedScanResults)
    let scan_lines = if let Some(ref scan_store) = app.scan_results {
        if let Ok(results) = scan_store.try_lock() {
            if results.is_empty() {
                vec![Line::from(Span::styled("  No scan results yet", Style::default().fg(Color::DarkGray)))]
            } else {
                let pass = results.iter().filter(|r| r.status == ScanStatus::Pass).count();
                let warn = results.iter().filter(|r| r.status == ScanStatus::Warn).count();
                let fail = results.iter().filter(|r| r.status == ScanStatus::Fail).count();
                let age_str = if let Some(ts) = results.iter().map(|r| r.timestamp).max() {
                    crate::util::format_age_short(now.signed_duration_since(ts))
                } else { "unknown".to_string() };
                vec![
                    Line::from(vec![
                        Span::styled(format!("  Pass: {}", pass), Style::default().fg(Color::Green)),
                        Span::raw("  "),
                        Span::styled(format!("Warn: {}", warn), Style::default().fg(Color::Yellow)),
                        Span::raw("  "),
                        Span::styled(format!("Fail: {}", fail), Style::default().fg(Color::Red)),
                    ]),
                    Line::from(vec![
                        Span::raw("  Last scan: "),
                        Span::styled(age_str, Style::default().fg(Color::DarkGray)),
                    ]),
                    Line::from(vec![
                        Span::raw(format!("  {} total checks", results.len())),
                    ]),
                ]
            }
        } else {
            vec![Line::from(Span::styled("  Scan data locked", Style::default().fg(Color::DarkGray)))]
        }
    } else {
        vec![Line::from(Span::styled("  Scanner not connected", Style::default().fg(Color::DarkGray)))]
    };
    let scan_panel = Paragraph::new(scan_lines)
        .block(Block::default().borders(Borders::ALL).title(" Last Scan "));
    f.render_widget(scan_panel, right_rows[1]);

    // --- BOTTOM: uptime + version ---
    let uptime = app.startup_time.elapsed();
    let uptime_str = crate::util::format_uptime(uptime);
    let bottom_line = Line::from(vec![
        Span::raw("  Uptime: "),
        Span::styled(uptime_str, Style::default().fg(Color::Cyan)),
        Span::raw("  |  "),
        Span::raw(format!("v{}", env!("CARGO_PKG_VERSION"))),
    ]);
    let bottom = Paragraph::new(bottom_line)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(bottom, rows[2]);
}

fn render_detail_view(f: &mut Frame, area: Rect, alert: &Alert) {
    let now = chrono::Local::now();
    let age = now.signed_duration_since(alert.timestamp);
    let age_str = crate::util::format_age_long(age);

    let severity_style = match alert.severity {
        Severity::Critical => Style::default().fg(Color::Red).bold(),
        Severity::Warning => Style::default().fg(Color::Yellow).bold(),
        Severity::Info => Style::default().fg(Color::Blue).bold(),
    };

    let mut text = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", alert.severity), severity_style),
            Span::raw("  "),
            Span::styled(alert.source.as_str(), Style::default().fg(Color::Cyan).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Timestamp: ", Style::default().fg(Color::DarkGray)),
            Span::raw(alert.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
            Span::styled(format!("  ({})", age_str), Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(Color::DarkGray)),
            Span::raw(alert.source.as_str()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", alert.severity), severity_style),
        ]),
        Line::from(""),
        Line::from(Span::styled("Message:", Style::default().fg(Color::DarkGray))),
        Line::from(""),
    ];

    // Word-wrap the message to fit the area
    let wrap_width = area.width.saturating_sub(DETAIL_WRAP_PADDING) as usize;
    if wrap_width > 0 {
        let msg_lines: Vec<Line> = alert
            .message
            .chars()
            .collect::<Vec<_>>()
            .chunks(wrap_width)
            .map(|chunk| Line::from(format!("  {}", chunk.iter().collect::<String>())))
            .collect();
        text.extend(msg_lines);
    }

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Alert Detail ")
                .border_style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(paragraph, area);
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(TAB_BAR_HEIGHT),
            Constraint::Min(0),
            Constraint::Length(FOOTER_HEIGHT),
        ])
        .split(f.area());

    // Tab bar with dynamic counts — uses tab_alert_count for centralized filtering
    let alerts = app.alert_store.alerts();

    let alerts_cw_count = tab_alert_count(&alerts, TAB_ALERTS);
    let cmd_count = tab_alert_count(&alerts, TAB_COMMANDS);
    let net_count = tab_alert_count(&alerts, TAB_NETWORK);
    let fim_count = tab_alert_count(&alerts, TAB_FIM);
    let scan_count = tab_alert_count(&alerts, TAB_SCANS);

    let pending_count = {
        if let Ok(pending) = app.pending_actions.try_lock() {
            pending.iter().filter(|a| matches!(a.status, PendingStatus::AwaitingApproval)).count()
        } else {
            0
        }
    };

    let alerts_title = if pending_count > 0 {
        format!("Alerts ({}) !{}", alerts_cw_count, pending_count)
    } else {
        format!("Alerts ({})", alerts_cw_count)
    };

    let tab_titles: Vec<Line> = vec![
        Line::from("Dashboard".to_string()),
        Line::from(alerts_title),
        Line::from(format!("Commands ({})", cmd_count)),
        Line::from(format!("Network ({})", net_count)),
        Line::from(format!("FIM ({})", fim_count)),
        Line::from(format!("Scans ({})", scan_count)),
        Line::from("Config".to_string()),
    ];

    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title(" ClawTower "))
        .select(app.selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).bold());
    f.render_widget(tabs, chunks[0]);

    // Content area — detail view overrides tab content
    if let Some(ref alert) = app.detail_alert.clone() {
        render_detail_view(f, chunks[1], alert);
    } else {
        match app.selected_tab {
            TAB_DASHBOARD => render_dashboard(f, chunks[1], app),
            tab @ TAB_ALERTS..=TAB_SCANS => {
                if let Some(cfg) = tab_filter_config(tab) {
                    render_alert_list(
                        f, chunks[1], app, tab,
                        cfg.source_filter, cfg.min_severity, cfg.title,
                    );
                }
            }
            TAB_CONFIG => config_editor::render_config_tab(f, chunks[1], app),
            _ => {}
        }
    }

    // Footer / status bar
    let footer_text = if app.search_active {
        format!(" Search: {}|  (Enter to apply, Esc to cancel)", app.search_buffer)
    } else if app.detail_alert.is_some() {
        " Esc: back | m: mute source".to_string()
    } else {
        match app.selected_tab {
            TAB_DASHBOARD => " Tab: switch | q: quit".to_string(),
            TAB_ALERTS..=TAB_SCANS => {
                let pause = if app.paused { "Space: resume" } else { "Space: pause" };
                let filter = if !app.search_filter.is_empty() {
                    format!(" | Filter: \"{}\" (Esc clears)", app.search_filter)
                } else {
                    String::new()
                };
                format!(" Tab: switch | Up/Dn: scroll | Enter: detail | /: search | {}{} | q: quit", pause, filter)
            }
            TAB_CONFIG => {
                if app.config_dropdown.is_some() {
                    " Up/Dn: select | Enter: confirm | Esc: cancel".to_string()
                } else if app.config_editing {
                    " Enter: confirm | Esc: cancel".to_string()
                } else if app.config_focus == ConfigFocus::Fields {
                    " Up/Dn: navigate | Enter: edit | Backspace: sidebar | Ctrl+S: save | Tab: switch".to_string()
                } else {
                    " Up/Dn: sections | Enter: fields | Left/Right: tabs | Tab: switch | q: quit".to_string()
                }
            }
            _ => String::new(),
        }
    };

    let footer = Paragraph::new(Line::from(footer_text))
        .style(Style::default().fg(Color::DarkGray).bg(Color::Black));
    f.render_widget(footer, chunks[2]);

    // Sudo popup overlay
    if let Some(ref popup) = app.sudo_popup {
        render_sudo_popup(f, f.area(), popup);
    }

    // Approval popup overlay
    if let Some(ref popup) = app.approval_popup {
        render_approval_popup(f, f.area(), popup);
    }
}

fn render_sudo_popup(f: &mut Frame, area: Rect, popup: &SudoPopup) {
    // Center a popup box
    let popup_width = SUDO_POPUP_WIDTH.min(area.width.saturating_sub(POPUP_WIDTH_MARGIN));
    let popup_height = SUDO_POPUP_HEIGHT.min(area.height.saturating_sub(POPUP_HEIGHT_MARGIN));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let lines = match &popup.status {
        SudoStatus::WaitingForPassword => {
            let dots = "*".repeat(popup.password.len());
            vec![
                Line::from(Span::styled("Sudo Authentication Required", Style::default().fg(Color::Yellow).bold())),
                Line::from(""),
                Line::from(Span::raw(&popup.message)),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Password: ", Style::default().fg(Color::Cyan)),
                    Span::styled(format!("{}|", dots), Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(Span::styled("Enter to confirm - Esc to cancel", Style::default().fg(Color::DarkGray))),
            ]
        }
        SudoStatus::Running => {
            vec![
                Line::from(Span::styled("Running...", Style::default().fg(Color::Yellow).bold())),
                Line::from(""),
                Line::from(Span::raw(&popup.message)),
            ]
        }
        SudoStatus::Failed(msg) => {
            vec![
                Line::from(Span::styled("Failed", Style::default().fg(Color::Red).bold())),
                Line::from(""),
                Line::from(Span::raw(msg.as_str())),
                Line::from(""),
                Line::from(Span::styled("Press any key to dismiss", Style::default().fg(Color::DarkGray))),
            ]
        }
    };

    let paragraph = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Authentication "))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(paragraph, popup_area);
}

fn render_approval_popup(f: &mut Frame, area: Rect, popup: &ApprovalPopup) {
    let popup_width = APPROVAL_POPUP_WIDTH.min(area.width.saturating_sub(POPUP_WIDTH_MARGIN));
    let popup_height = (APPROVAL_POPUP_BASE_HEIGHT + popup.actions_display.len() as u16).min(area.height.saturating_sub(POPUP_HEIGHT_MARGIN));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let severity_style = match popup.severity {
        Severity::Critical => Style::default().fg(Color::Red).bold(),
        Severity::Warning => Style::default().fg(Color::Yellow).bold(),
        Severity::Info => Style::default().fg(Color::Blue).bold(),
    };

    let mut lines = vec![
        Line::from(Span::styled(
            format!("{} THREAT DETECTED", popup.severity),
            severity_style,
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&popup.threat_source),
        ]),
        Line::from(vec![
            Span::styled("Threat: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&popup.threat_message),
        ]),
    ];

    if let Some(ref pb) = popup.playbook {
        lines.push(Line::from(vec![
            Span::styled("Playbook: ", Style::default().fg(Color::DarkGray)),
            Span::styled(pb.as_str(), Style::default().fg(Color::Cyan)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Proposed actions:", Style::default().fg(Color::DarkGray))));
    for action in &popup.actions_display {
        lines.push(Line::from(format!("  - {}", action)));
    }

    lines.push(Line::from(""));

    let approve_style = if popup.selected == 0 {
        Style::default().fg(Color::Black).bg(Color::Green).bold()
    } else {
        Style::default().fg(Color::Green)
    };
    let deny_style = if popup.selected == 1 {
        Style::default().fg(Color::Black).bg(Color::Red).bold()
    } else {
        Style::default().fg(Color::Red)
    };

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(" APPROVE ", approve_style),
        Span::raw("    "),
        Span::styled("  DENY  ", deny_style),
    ]));

    lines.push(Line::from(""));

    let msg_display = if popup.editing_message {
        format!("Note: {}|", popup.message_buffer)
    } else if popup.message_buffer.is_empty() {
        "Press 'm' to add a note".to_string()
    } else {
        format!("Note: {}", popup.message_buffer)
    };
    lines.push(Line::from(Span::styled(msg_display, Style::default().fg(Color::DarkGray))));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Up/Dn: select | Enter: confirm | m: add note | Esc: dismiss",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .title(" Action Required ")
            .style(Style::default().bg(Color::Black)));
    f.render_widget(paragraph, popup_area);
}

/// Run the TUI dashboard, blocking until the user quits.
///
/// Drains alerts from the channel, renders the UI at 10fps, and handles keyboard input.
pub async fn run_tui(
    mut alert_rx: mpsc::Receiver<Alert>,
    config_path: Option<PathBuf>,
    pending_actions: SharedPendingActions,
    response_tx: Option<mpsc::Sender<ResponseRequest>>,
    scan_results: Option<SharedScanResults>,
    falco_path_tx: Option<watch::Sender<PathBuf>>,
    samhain_path_tx: Option<watch::Sender<PathBuf>>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(pending_actions, response_tx);
    app.scan_results = scan_results;
    app.falco_path_tx = falco_path_tx;
    app.samhain_path_tx = samhain_path_tx;

    // Load config if provided
    if let Some(path) = config_path {
        if let Err(e) = app.load_config(&path) {
            eprintln!("Failed to load config: {}", e);
        }
    }

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        // Check for keyboard events (non-blocking)
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key.code, key.modifiers);
                }
            }
        }

        // Drain alert channel (skip when paused — alerts buffer in channel)
        if !app.paused {
            while let Ok(alert) = alert_rx.try_recv() {
                app.alert_store.push(alert);
            }
        }

        // Check for new pending actions and show popup
        if app.approval_popup.is_none() {
            if let Ok(pending) = app.pending_actions.try_lock() {
                if let Some(action) = pending.iter().find(|a| matches!(a.status, PendingStatus::AwaitingApproval)) {
                    app.approval_popup = Some(ApprovalPopup {
                        action_id: action.id.clone(),
                        threat_source: action.threat_source.clone(),
                        threat_message: action.threat_message.clone(),
                        severity: action.severity.clone(),
                        actions_display: action.actions.iter().map(|a| a.to_string()).collect(),
                        playbook: action.playbook.clone(),
                        selected: 1, // default to DENY for safety
                        message_buffer: String::new(),
                        editing_message: false,
                    });
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
