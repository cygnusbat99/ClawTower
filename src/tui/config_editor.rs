// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Config editor panel for the TUI.
//!
//! Extracted from the main TUI module. Contains:
//! - Config field types (`ConfigField`, `FieldType`, `ConfigFocus`, `DropdownState`)
//! - Field definition generation (`get_section_fields`)
//! - Field value application (`apply_field_to_config`)
//! - Config tab keyboard handling (`App::handle_config_key`)
//! - Config tab rendering (`render_config_tab`)

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::config::Config;

use super::{App, SudoPopup, SudoStatus};

/// A single editable field in the config editor panel.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ConfigField {
    pub name: String,
    pub value: String,
    pub section: String,
    pub field_type: FieldType,
}

/// Which panel has keyboard focus in the config editor tab.
#[derive(Clone)]
#[derive(PartialEq)]
pub enum ConfigFocus {
    /// Section sidebar: Up/Down navigates, Enter enters fields.
    Sidebar,
    /// Field list: Up/Down navigates, Enter edits, Backspace returns to sidebar.
    Fields,
}

/// Type of a config field, controlling how it's edited (text input, toggle, number, or action button).
#[derive(Clone)]
pub enum FieldType {
    /// Free-form text input.
    Text,
    /// Selectable from a list of valid options (includes booleans).
    Enum(Vec<String>),
    /// Numeric input.
    Number,
    /// Action button — Enter runs the associated command string.
    Action(String),
}

/// State for an active inline dropdown picker overlay.
pub struct DropdownState {
    /// Index of the field this dropdown is attached to.
    pub field_index: usize,
    /// Valid options to choose from.
    pub options: Vec<String>,
    /// Currently highlighted option index.
    pub selected: usize,
}

/// Return the list of editable fields for a given config section.
pub fn get_section_fields(config: &Config, section: &str, tool_cache: &HashMap<String, bool>) -> Vec<ConfigField> {
    match section {
        "general" => vec![
            ConfigField {
                name: "watched_user".to_string(),
                value: config.general.watched_user.clone().unwrap_or_default(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "watched_users".to_string(),
                value: config.general.watched_users.join(","),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "watch_all_users".to_string(),
                value: config.general.watch_all_users.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "min_alert_level".to_string(),
                value: config.general.min_alert_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["info".into(), "warn".into(), "crit".into()]),
            },
            ConfigField {
                name: "log_file".to_string(),
                value: config.general.log_file.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "slack" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.slack.enabled.unwrap_or(false).to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "webhook_url".to_string(),
                value: config.slack.webhook_url.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "backup_webhook_url".to_string(),
                value: config.slack.backup_webhook_url.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "channel".to_string(),
                value: config.slack.channel.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "min_slack_level".to_string(),
                value: config.slack.min_slack_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["info".into(), "warn".into(), "crit".into()]),
            },
        ],
        "auditd" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.auditd.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "log_path".to_string(),
                value: config.auditd.log_path.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "network" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.network.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "log_path".to_string(),
                value: config.network.log_path.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "log_prefix".to_string(),
                value: config.network.log_prefix.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "source".to_string(),
                value: config.network.source.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "falco" => {
            let falco_installed = tool_cache.get("falco").copied().unwrap_or(false);
            let mut fields = vec![
                ConfigField {
                    name: "enabled".to_string(),
                    value: config.falco.enabled.to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
                },
                ConfigField {
                    name: "log_path".to_string(),
                    value: config.falco.log_path.clone(),
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
                ConfigField {
                    name: "status".to_string(),
                    value: if falco_installed { "✅ installed".to_string() } else { "❌ not installed".to_string() },
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
            ];
            if !falco_installed {
                fields.push(ConfigField {
                    name: "▶ Install Falco".to_string(),
                    value: "Press Enter to install".to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Action("install_falco".to_string()),
                });
            }
            fields
        },
        "samhain" => {
            let samhain_installed = tool_cache.get("samhain").copied().unwrap_or(false);
            let mut fields = vec![
                ConfigField {
                    name: "enabled".to_string(),
                    value: config.samhain.enabled.to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
                },
                ConfigField {
                    name: "log_path".to_string(),
                    value: config.samhain.log_path.clone(),
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
                ConfigField {
                    name: "status".to_string(),
                    value: if samhain_installed { "✅ installed".to_string() } else { "❌ not installed".to_string() },
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
            ];
            if !samhain_installed {
                fields.push(ConfigField {
                    name: "▶ Install Samhain".to_string(),
                    value: "Press Enter to install".to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Action("install_samhain".to_string()),
                });
            }
            fields
        },
        "api" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.api.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "bind".to_string(),
                value: config.api.bind.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "port".to_string(),
                value: config.api.port.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
        ],
        "scans" => vec![
            ConfigField {
                name: "interval".to_string(),
                value: config.scans.interval.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
        ],
        "proxy" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.proxy.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "bind".to_string(),
                value: config.proxy.bind.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "port".to_string(),
                value: config.proxy.port.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
        ],
        "policy" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.policy.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "dir".to_string(),
                value: config.policy.dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "barnacle" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.barnacle.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "vendor_dir".to_string(),
                value: config.barnacle.vendor_dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "netpolicy" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.netpolicy.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "mode".to_string(),
                value: config.netpolicy.mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["allow".into(), "deny".into(), "disabled".into()]),
            },
            ConfigField {
                name: "allowed_ports".to_string(),
                value: config.netpolicy.allowed_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "response" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.response.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "timeout_secs".to_string(),
                value: config.response.timeout_secs.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
            ConfigField {
                name: "warning_mode".to_string(),
                value: config.response.warning_mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["gate".into(), "alert_only".into(), "auto_deny".into()]),
            },
            ConfigField {
                name: "playbook_dir".to_string(),
                value: config.response.playbook_dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "deny_message".to_string(),
                value: config.response.deny_message.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "prompt_firewall" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.prompt_firewall.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "tier".to_string(),
                value: config.prompt_firewall.tier.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["1".into(), "2".into(), "3".into()]),
            },
            ConfigField {
                name: "patterns_path".to_string(),
                value: config.prompt_firewall.patterns_path.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        _ => Vec::new(),
    }
}

/// Apply a field value change to the in-memory config.
pub fn apply_field_to_config(config: &mut Config, section: &str, field_name: &str, value: &str) {
    match section {
        "general" => match field_name {
            "watched_user" => config.general.watched_user = if value.is_empty() { None } else { Some(value.to_string()) },
            "watched_users" => config.general.watched_users = value.split(',').filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string()).collect(),
            "watch_all_users" => config.general.watch_all_users = value == "true",
            "min_alert_level" => config.general.min_alert_level = value.to_string(),
            "log_file" => config.general.log_file = value.to_string(),
            _ => {}
        },
        "slack" => match field_name {
            "enabled" => config.slack.enabled = Some(value == "true"),
            "webhook_url" => config.slack.webhook_url = value.to_string(),
            "backup_webhook_url" => config.slack.backup_webhook_url = value.to_string(),
            "channel" => config.slack.channel = value.to_string(),
            "min_slack_level" => config.slack.min_slack_level = value.to_string(),
            _ => {}
        },
        "auditd" => match field_name {
            "enabled" => config.auditd.enabled = value == "true",
            "log_path" => config.auditd.log_path = value.to_string(),
            _ => {}
        },
        "network" => match field_name {
            "enabled" => config.network.enabled = value == "true",
            "log_path" => config.network.log_path = value.to_string(),
            "log_prefix" => config.network.log_prefix = value.to_string(),
            "source" => config.network.source = value.to_string(),
            _ => {}
        },
        "falco" => match field_name {
            "enabled" => config.falco.enabled = value == "true",
            "log_path" => config.falco.log_path = value.to_string(),
            _ => {}
        },
        "samhain" => match field_name {
            "enabled" => config.samhain.enabled = value == "true",
            "log_path" => config.samhain.log_path = value.to_string(),
            _ => {}
        },
        "api" => match field_name {
            "enabled" => config.api.enabled = value == "true",
            "bind" => config.api.bind = value.to_string(),
            "port" => if let Ok(port) = value.parse::<u16>() { config.api.port = port; },
            _ => {}
        },
        "scans" => if field_name == "interval" {
            if let Ok(interval) = value.parse::<u64>() { config.scans.interval = interval; }
        },
        "proxy" => match field_name {
            "enabled" => config.proxy.enabled = value == "true",
            "bind" => config.proxy.bind = value.to_string(),
            "port" => if let Ok(port) = value.parse::<u16>() { config.proxy.port = port; },
            _ => {}
        },
        "policy" => match field_name {
            "enabled" => config.policy.enabled = value == "true",
            "dir" => config.policy.dir = value.to_string(),
            _ => {}
        },
        "barnacle" => match field_name {
            "enabled" => config.barnacle.enabled = value == "true",
            "vendor_dir" => config.barnacle.vendor_dir = value.to_string(),
            _ => {}
        },
        "netpolicy" => match field_name {
            "enabled" => config.netpolicy.enabled = value == "true",
            "mode" => config.netpolicy.mode = value.to_string(),
            "allowed_ports" => {
                config.netpolicy.allowed_ports = value
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();
            },
            _ => {}
        },
        "response" => match field_name {
            "enabled" => config.response.enabled = value == "true",
            "timeout_secs" => if let Ok(t) = value.parse::<u64>() { config.response.timeout_secs = t; },
            "warning_mode" => config.response.warning_mode = value.to_string(),
            "playbook_dir" => config.response.playbook_dir = value.to_string(),
            "deny_message" => config.response.deny_message = value.to_string(),
            _ => {}
        },
        "prompt_firewall" => match field_name {
            "enabled" => config.prompt_firewall.enabled = value == "true",
            "tier" => if let Ok(t) = value.parse::<u8>() { config.prompt_firewall.tier = t; },
            "patterns_path" => config.prompt_firewall.patterns_path = value.to_string(),
            _ => {}
        },
        _ => {}
    }
}

/// Handle keyboard input when the Config tab (tab 6) is active.
///
/// This is called from `App::on_key()` when `self.selected_tab == 6`.
pub fn handle_config_key(app: &mut App, key: KeyCode, modifiers: KeyModifiers) {
    // Handle dropdown if active
    if let Some(ref mut dropdown) = app.config_dropdown {
        match key {
            KeyCode::Up => {
                dropdown.selected = dropdown.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                if dropdown.selected < dropdown.options.len().saturating_sub(1) {
                    dropdown.selected += 1;
                }
            }
            KeyCode::Enter => {
                let value = dropdown.options[dropdown.selected].clone();
                let field_index = dropdown.field_index;
                app.config_dropdown = None;
                if let Some(ref mut config) = app.config {
                    let section = &app.config_sections[app.config_selected_section];
                    let field_name = &app.config_fields[field_index].name;
                    apply_field_to_config(config, section, field_name, &value);
                    app.refresh_fields();
                }
            }
            KeyCode::Esc => {
                app.config_dropdown = None;
            }
            _ => {}
        }
        return;
    }

    if app.config_editing {
        // Handle editing mode
        match key {
            KeyCode::Enter => {
                // Validate before applying
                let field = &app.config_fields[app.config_selected_field];
                let value = &app.config_edit_buffer;

                let valid = match &field.field_type {
                    FieldType::Number => value.parse::<u64>().is_ok(),
                    FieldType::Enum(ref options) => options.contains(&value.to_string()),
                    FieldType::Text => true,
                    FieldType::Action(_) => true,
                };

                if valid {
                    if let Some(ref mut config) = app.config {
                        let section = &app.config_sections[app.config_selected_section];
                        let field = &app.config_fields[app.config_selected_field];
                        apply_field_to_config(config, section, &field.name, &app.config_edit_buffer);
                        app.refresh_fields();
                    }
                    app.config_editing = false;
                    app.config_edit_buffer.clear();
                } else {
                    app.config_saved_message = Some(format!(
                        "❌ Invalid {}: \"{}\"",
                        match &field.field_type {
                            FieldType::Number => "number",
                            FieldType::Enum(_) => "selection",
                            _ => "value",
                        },
                        value
                    ));
                }
            }
            KeyCode::Esc => {
                // Cancel edit
                app.config_editing = false;
                app.config_edit_buffer.clear();
            }
            KeyCode::Backspace => {
                app.config_edit_buffer.pop();
            }
            KeyCode::Char(c) => {
                app.config_edit_buffer.push(c);
            }
            _ => {}
        }
    } else {
        // Ctrl+S save always available
        if key == KeyCode::Char('s') && modifiers == KeyModifiers::CONTROL {
            if let (Some(ref config), Some(ref path)) = (&app.config, &app.config_path) {
                if config.save(path).is_ok() {
                    app.config_saved_message = Some("Saved!".to_string());
                    app.notify_path_changes();
                } else if super::nix_is_root() {
                    // File is likely immutable (chattr +i) — do the chattr dance directly
                    let _ = config.save(&std::path::PathBuf::from("/tmp/clawtower-config-save.toml"));
                    let path_str = path.display().to_string();
                    app.run_sudo_action(&format!("save_config:{}", path_str), "");
                } else {
                    let path_str = path.display().to_string();
                    app.sudo_popup = Some(SudoPopup {
                        action: format!("save_config:{}", path_str),
                        password: String::new(),
                        message: format!("Save config to {}", path_str),
                        status: SudoStatus::WaitingForPassword,
                    });
                    let _ = config.save(&std::path::PathBuf::from("/tmp/clawtower-config-save.toml"));
                }
            }
            return;
        }

        match app.config_focus {
            ConfigFocus::Sidebar => {
                // Sidebar: Up/Down = sections, Enter = go into fields
                // Left/Right = switch tabs (handled by parent on_key)
                match key {
                    KeyCode::Up => {
                        if app.config_selected_section > 0 {
                            app.config_selected_section -= 1;
                            app.config_selected_field = 0;
                            app.refresh_fields();
                        }
                    }
                    KeyCode::Down => {
                        if app.config_selected_section < app.config_sections.len() - 1 {
                            app.config_selected_section += 1;
                            app.config_selected_field = 0;
                            app.refresh_fields();
                        }
                    }
                    KeyCode::Enter => {
                        // Enter the fields panel
                        if !app.config_fields.is_empty() {
                            app.config_focus = ConfigFocus::Fields;
                            app.config_selected_field = 0;
                        }
                    }
                    _ => {}
                }
            }
            ConfigFocus::Fields => {
                // Fields: Up/Down = fields, Enter = edit, Backspace = back to sidebar
                match key {
                    KeyCode::Backspace | KeyCode::Esc => {
                        app.config_focus = ConfigFocus::Sidebar;
                    }
                    KeyCode::Up => {
                        if app.config_selected_field > 0 {
                            app.config_selected_field -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if app.config_selected_field < app.config_fields.len().saturating_sub(1) {
                            app.config_selected_field += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if !app.config_fields.is_empty() {
                            let field = &app.config_fields[app.config_selected_field];
                            match &field.field_type {
                                FieldType::Enum(ref options) => {
                                    let current = &field.value;
                                    let selected = options.iter().position(|o| o == current).unwrap_or(0);
                                    app.config_dropdown = Some(DropdownState {
                                        field_index: app.config_selected_field,
                                        options: options.clone(),
                                        selected,
                                    });
                                }
                                FieldType::Action(action) => {
                                    let action = action.clone();
                                    app.run_action(&action);
                                }
                                _ => {
                                    app.config_editing = true;
                                    app.config_edit_buffer = field.value.clone();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Render the config editor tab (section sidebar + field editor + dropdown overlay).
pub fn render_config_tab(f: &mut Frame, area: Rect, app: &App) {
    if app.config.is_none() {
        let text = vec![
            Line::from(vec![
                Span::styled("No config loaded", Style::default().fg(Color::Red).bold()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("Config file path not provided or failed to load."),
            ]),
        ];
        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" Config Editor "));
        f.render_widget(paragraph, area);
        return;
    }

    // Split into left (sections list, 25%) and right (fields, 75%)
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(super::CONFIG_SIDEBAR_PCT), Constraint::Percentage(super::CONFIG_FIELDS_PCT)])
        .split(area);

    let sidebar_focused = app.config_focus == ConfigFocus::Sidebar;
    let fields_focused = app.config_focus == ConfigFocus::Fields;

    // Left: section list
    let section_items: Vec<ListItem> = app.config_sections.iter().enumerate().map(|(i, s)| {
        let style = if i == app.config_selected_section {
            if sidebar_focused {
                Style::default().fg(Color::Cyan).bold().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Color::Cyan).bold()
            }
        } else {
            Style::default().fg(Color::DarkGray)
        };
        ListItem::new(format!("  {}", s)).style(style)
    }).collect();

    let sidebar_border = if sidebar_focused { Color::Cyan } else { Color::DarkGray };
    let sidebar_title = if sidebar_focused { " Sections (↑↓ Enter) " } else { " Sections " };
    let sections_list = List::new(section_items)
        .block(Block::default().borders(Borders::ALL)
            .border_style(Style::default().fg(sidebar_border))
            .title(sidebar_title));
    f.render_widget(sections_list, chunks[0]);

    // Right: fields for selected section
    let field_items: Vec<ListItem> = app.config_fields.iter().enumerate().map(|(i, field)| {
        let is_selected = i == app.config_selected_field && fields_focused;
        let is_editing = is_selected && app.config_editing;

        let value_display = if is_editing {
            format!("{}▌", app.config_edit_buffer)
        } else {
            field.value.clone()
        };

        let style = if is_selected {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::REVERSED)
        } else if fields_focused {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        ListItem::new(format!("  {}: {}", field.name, value_display)).style(style)
    }).collect();

    let fields_border = if fields_focused { Color::Cyan } else { Color::DarkGray };
    let title = if let Some(ref msg) = app.config_saved_message {
        format!(" {} — {} ", app.config_sections[app.config_selected_section], msg)
    } else if fields_focused {
        format!(" [{}] — Enter to edit, Backspace to go back, Ctrl+S save ", app.config_sections[app.config_selected_section])
    } else {
        format!(" [{}] ", app.config_sections[app.config_selected_section])
    };

    let fields_list = List::new(field_items)
        .block(Block::default().borders(Borders::ALL)
            .border_style(Style::default().fg(fields_border))
            .title(title));
    f.render_widget(fields_list, chunks[1]);

    // Dropdown overlay
    if let Some(ref dropdown) = app.config_dropdown {
        let max_option_len = dropdown.options.iter().map(|o| o.len()).max().unwrap_or(4);
        let dropdown_width = (max_option_len as u16) + 4;
        let dropdown_height = (dropdown.options.len() as u16) + 2;

        // Position: right side of fields panel, at the field's Y offset
        let fields_area = chunks[1]; // the right panel
        let field_y_offset = dropdown.field_index as u16;
        let x = fields_area.x + fields_area.width.saturating_sub(dropdown_width + 1);
        let y = (fields_area.y + 1 + field_y_offset).min(
            fields_area.y + fields_area.height.saturating_sub(dropdown_height + 1)
        );

        let dropdown_area = Rect::new(x, y, dropdown_width, dropdown_height);

        let items: Vec<ListItem> = dropdown.options.iter().enumerate().map(|(i, opt)| {
            let style = if i == dropdown.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!(" {} ", opt)).style(style)
        }).collect();

        let list = List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)));
        f.render_widget(list, dropdown_area);
    }
}
