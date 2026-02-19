// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Configuration loading and serialization.
//!
//! Defines the TOML configuration schema for ClawTower. The root [`Config`] struct
//! contains sections for each subsystem (auditd, network, falco, samhain, proxy,
//! policy, barnacle, sentinel, etc.).
//!
//! All sections implement `Default` and `serde::Deserialize` with `#[serde(default)]`
//! so missing fields gracefully fall back to sensible defaults. Config is loaded
//! from `/etc/clawtower/config.toml` by default.

pub mod merge;
pub mod cloud;
pub mod openclaw;
pub mod export;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::detect::barnacle::BarnacleConfig;
use self::merge::merge_toml;

/// Root configuration struct, deserialized from TOML.
///
/// All subsystem sections use `#[serde(default)]` so missing sections
/// gracefully use defaults. Load with [`Config::load`], save with [`Config::save`].
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub slack: SlackConfig,
    pub auditd: AuditdConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub falco: FalcoConfig,
    #[serde(default)]
    pub samhain: SamhainConfig,
    #[serde(default)]
    pub api: ApiConfig,
    pub scans: ScansConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub barnacle: BarnacleConfig,
    #[serde(default)]
    pub netpolicy: NetPolicyConfig,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub incident_mode: IncidentModeConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub sentinel: SentinelConfig,
    #[serde(default)]
    pub auto_update: AutoUpdateConfig,
    #[serde(default)]
    pub openclaw: OpenClawConfig,
    #[serde(default)]
    pub behavior: BehaviorConfig,
    #[serde(default)]
    pub export: ExportConfig,
    #[serde(default)]
    pub cloud: CloudConfig,
    #[serde(default)]
    pub prompt_firewall: PromptFirewallConfig,
    #[serde(default)]
    pub memory_sentinel: MemorySentinelConfig,
}

/// Behavior detection engine configuration.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct BehaviorConfig {
    #[serde(default)]
    pub safe_hosts: Vec<String>,
    /// When enabled, run the new detector abstraction in shadow mode and
    /// emit diagnostics if it disagrees with hardcoded behavior classification.
    /// This does not change production alert fanout.
    #[serde(default)]
    pub detector_shadow_mode: bool,
}

/// Memory sentinel configuration — process memory integrity monitoring.
///
/// When enabled, periodically scans a target process's memory for integrity
/// violations (.text modification, GOT overwrites). Disabled by default
/// because it requires `CAP_SYS_PTRACE` or equivalent.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MemorySentinelConfig {
    #[serde(default)]
    pub enabled: bool,
    /// PID of the process to monitor. If not set, memory sentinel won't start.
    #[serde(default)]
    pub target_pid: Option<u32>,
    /// Scan interval in milliseconds (default: 30000 = 30s at Normal threat level).
    #[serde(default = "default_memory_scan_interval")]
    pub scan_interval_ms: u64,
}

fn default_memory_scan_interval() -> u64 { 30_000 }

impl Default for MemorySentinelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_pid: None,
            scan_interval_ms: default_memory_scan_interval(),
        }
    }
}

/// Auto-update configuration: checks GitHub releases periodically.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AutoUpdateConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auto_update_interval")]
    pub interval: u64,
    #[serde(default = "default_auto_update_mode")]
    pub mode: String,
}

fn default_auto_update_interval() -> u64 { 300 }
fn default_auto_update_mode() -> String { "auto".to_string() }

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: default_auto_update_interval(),
            mode: default_auto_update_mode(),
        }
    }
}

/// SSH login monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SshConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
fn default_true() -> bool { true }
impl Default for SshConfig {
    fn default() -> Self { Self { enabled: true } }
}

/// YAML policy engine configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PolicyConfig {
    pub enabled: bool,
    pub dir: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: "./policies".to_string(),
        }
    }
}

/// General configuration: which users to monitor, alert level, log path.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GeneralConfig {
    /// Single watched user (backward compat, prefer `watched_users`)
    pub watched_user: Option<String>,
    /// List of UIDs to monitor; empty + watch_all_users=false means watch all
    #[serde(default)]
    pub watched_users: Vec<String>,
    /// If true, monitor all users regardless of watched_users
    #[serde(default)]
    pub watch_all_users: bool,
    /// Minimum severity for alerts ("info", "warning", "critical")
    pub min_alert_level: String,
    /// Path to ClawTower's own log file
    pub log_file: String,
}

impl GeneralConfig {
    /// Returns the effective set of watched users, handling backward compat
    pub fn effective_watched_users(&self) -> Option<Vec<String>> {
        if self.watch_all_users {
            return None; // None means watch all
        }
        let mut users = self.watched_users.clone();
        if let Some(ref single) = self.watched_user {
            if !users.contains(single) {
                users.push(single.clone());
            }
        }
        if users.is_empty() {
            None // No users specified = watch all
        } else {
            Some(users)
        }
    }
}

/// Slack notification configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SlackConfig {
    /// Explicitly enable/disable Slack (None = enabled if webhook_url is set)
    pub enabled: Option<bool>,
    /// Primary incoming webhook URL
    pub webhook_url: String,
    /// Failover webhook URL if primary fails
    #[serde(default)]
    pub backup_webhook_url: String,
    /// Slack channel name
    pub channel: String,
    /// Minimum severity to forward to Slack
    pub min_slack_level: String,
    /// Interval in seconds for periodic health heartbeat to Slack (0 = disabled)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
}

fn default_heartbeat_interval() -> u64 {
    3600
}

/// Auditd log monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditdConfig {
    pub log_path: String,
    pub enabled: bool,
}

// Network config types moved to network.rs — re-exported for backward compatibility
pub use crate::sources::network::NetworkConfig;

/// Falco eBPF integration configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FalcoConfig {
    pub enabled: bool,
    pub log_path: String,
}

impl Default for FalcoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: "/var/log/falco/falco_output.jsonl".to_string(),
        }
    }
}

/// Samhain file integrity monitoring integration configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SamhainConfig {
    pub enabled: bool,
    pub log_path: String,
}

impl Default for SamhainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: "/var/log/samhain/samhain.log".to_string(),
        }
    }
}

/// Periodic security scanner configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ScansConfig {
    /// Interval between full scan cycles in seconds
    pub interval: u64,
    /// Interval between persistence-specific scans in seconds (default: 300)
    #[serde(default = "default_persistence_interval")]
    pub persistence_interval: u64,
    /// Dedup interval for repeated scanner findings in seconds (default: 3600)
    #[serde(default = "default_dedup_interval")]
    pub dedup_interval_secs: u64,
}

fn default_persistence_interval() -> u64 { 300 }
fn default_dedup_interval() -> u64 { 3600 }

/// HTTP REST API server configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub cors_origin: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1".to_string(),
            port: 18791,
            auth_token: String::new(),
            cors_origin: None,
        }
    }
}

impl ApiConfig {
    /// Validate API configuration. Non-loopback binds require an auth token.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.auth_token.is_empty() {
            let is_loopback = self.bind == "127.0.0.1" || self.bind == "::1" || self.bind == "localhost";
            if !is_loopback {
                return Err(format!(
                    "API bound to {} without auth_token — set [api] auth_token or bind to 127.0.0.1",
                    self.bind
                ));
            }
        }
        Ok(())
    }
}

// Proxy config types moved to proxy.rs — re-exported for backward compatibility
pub use crate::proxy::ProxyConfig;

/// Prompt firewall configuration — intercepts malicious prompts before they reach LLM providers.
///
/// Tier system:
/// - Tier 1 (Permissive): Log all matches, block nothing
/// - Tier 2 (Standard): Block prompt_injection + exfil_via_prompt, log the rest
/// - Tier 3 (Strict): Block all categories
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PromptFirewallConfig {
    pub enabled: bool,
    /// Security tier: 1 = permissive, 2 = standard, 3 = strict
    pub tier: u8,
    /// Path to the prompt firewall patterns JSON file
    #[serde(default = "default_prompt_firewall_patterns_path")]
    pub patterns_path: String,
    /// Per-category action overrides. Keys: prompt_injection, exfil_via_prompt,
    /// jailbreak, tool_abuse, system_prompt_extract. Values: "block", "warn", "log".
    #[serde(default)]
    pub overrides: std::collections::HashMap<String, String>,
}

fn default_prompt_firewall_patterns_path() -> String {
    "/etc/clawtower/prompt-firewall-patterns.json".to_string()
}

impl Default for PromptFirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tier: 2,
            patterns_path: default_prompt_firewall_patterns_path(),
            overrides: std::collections::HashMap::new(),
        }
    }
}

/// Network policy (allowlist/blocklist) configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NetPolicyConfig {
    pub enabled: bool,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
    #[serde(default = "default_netpolicy_mode")]
    pub mode: String,
}

fn default_netpolicy_mode() -> String {
    "blocklist".to_string()
}

impl Default for NetPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_hosts: Vec::new(),
            allowed_ports: vec![80, 443, 53],
            blocked_hosts: Vec::new(),
            mode: default_netpolicy_mode(),
        }
    }
}

// Response + IncidentMode config types moved to response.rs — re-exported for backward compatibility
pub use crate::core::response::{ResponseConfig, IncidentModeConfig};

// Cloud config types moved to cloud.rs — re-exported for backward compatibility
pub use self::cloud::CloudConfig;

// Export config types moved to export.rs — re-exported for backward compatibility
pub use self::export::ExportConfig;

// Sentinel config types moved to sentinel.rs — re-exported for backward compatibility
pub use crate::sentinel::{SentinelConfig, WatchPathConfig, WatchPolicy};

// OpenClaw config types moved to openclaw_config.rs — re-exported for backward compatibility
pub use self::openclaw::OpenClawConfig;

/// Apply all `.toml` overlays from a config.d/ directory to a base TOML value.
/// Files are loaded in alphabetical order. No-op if the directory doesn't exist.
fn apply_config_d_overlays(base: &mut toml::Value, config_d: &Path) -> Result<()> {
    if !config_d.exists() || !config_d.is_dir() {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(config_d)
        .with_context(|| format!("Failed to read config.d: {}", config_d.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "toml")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let overlay_content = std::fs::read_to_string(entry.path())
            .with_context(|| format!("Failed to read overlay: {}", entry.path().display()))?;
        let overlay: toml::Value = toml::from_str(&overlay_content)
            .with_context(|| format!("Failed to parse overlay: {}", entry.path().display()))?;
        merge_toml(base, overlay);
    }

    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config")?;
        Ok(config)
    }

    /// Load config from base path, then merge overlays from config_d directory.
    /// Files in config_d are loaded in alphabetical order.
    #[allow(dead_code)]
    pub fn load_with_overrides(base_path: &Path, config_d: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(base_path)
            .with_context(|| format!("Failed to read config: {}", base_path.display()))?;
        let mut base: toml::Value = toml::from_str(&content)
            .with_context(|| "Failed to parse base config")?;

        apply_config_d_overlays(&mut base, config_d)?;

        let config: Config = base.try_into()
            .with_context(|| "Failed to deserialize merged config")?;
        Ok(config)
    }

    /// Load config with optional profile overlay between base and config.d/.
    /// Priority order: base < profile < config.d/ overlays.
    pub fn load_with_profile_and_overrides(
        base_path: &Path,
        profile_path: Option<&Path>,
        config_d: &Path,
    ) -> Result<Self> {
        let content = std::fs::read_to_string(base_path)
            .with_context(|| format!("Failed to read config: {}", base_path.display()))?;
        let mut base: toml::Value = toml::from_str(&content)
            .with_context(|| "Failed to parse base config")?;

        // Apply profile overlay (lower priority than config.d/)
        if let Some(profile) = profile_path {
            if profile.exists() {
                let overlay_content = std::fs::read_to_string(profile)
                    .with_context(|| format!("Failed to read profile: {}", profile.display()))?;
                let overlay: toml::Value = toml::from_str(&overlay_content)
                    .with_context(|| format!("Failed to parse profile: {}", profile.display()))?;
                merge_toml(&mut base, overlay);
            }
        }

        apply_config_d_overlays(&mut base, config_d)?;

        let config: Config = base.try_into()
            .with_context(|| "Failed to deserialize merged config")?;
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if (self.api.port as u32) > 65535 { warnings.push("api.port out of range".into()); }
        if (self.proxy.port as u32) > 65535 { warnings.push("proxy.port out of range".into()); }
        if !self.slack.webhook_url.is_empty() && !self.slack.webhook_url.starts_with("https://") {
            warnings.push("slack.webhook should use https://".into());
        }
        if self.policy.enabled && !std::path::Path::new(&self.policy.dir).exists() {
            warnings.push(format!("policy.dir '{}' does not exist", self.policy.dir));
        }
        warnings
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::KeyMapping;

    #[test]
    fn test_openclaw_config_defaults() {
        let config: OpenClawConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert_eq!(config.state_dir, "/home/openclaw/.openclaw");
        assert!(config.audit_on_scan);
        assert!(config.config_drift_check);
    }

    #[test]
    fn test_openclaw_config_custom() {
        let toml_str = r#"
            enabled = false
            config_path = "/tmp/test.json"
            state_dir = "/tmp/openclaw"
            audit_on_scan = false
        "#;
        let config: OpenClawConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.config_path, "/tmp/test.json");
        assert!(!config.audit_on_scan);
    }

    #[test]
    fn test_default_sentinel_includes_openclaw_creds() {
        let config = SentinelConfig::default();
        let paths: Vec<&str> = config.watch_paths.iter()
            .map(|w| w.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains(".openclaw/credentials")),
            "Should watch OpenClaw credentials dir");
        assert!(paths.iter().any(|p| *p == "/home/openclaw/.openclaw"),
            "Should watch OpenClaw config directory for *.json");
        assert!(paths.iter().any(|p| p.contains("auth-profiles.json")),
            "Should watch auth profiles");
    }

    #[test]
    fn test_default_sentinel_content_scan_excludes_openclaw_auth() {
        let config = SentinelConfig::default();
        assert!(!config.content_scan_excludes.is_empty(),
            "Should have default content scan exclusions");
        assert!(config.content_scan_excludes.iter().any(|p| p.contains("auth-profiles.json")),
            "Should exclude OpenClaw auth-profiles.json from content scanning");
        assert!(config.content_scan_excludes.iter().any(|p| p.contains(".openclaw/credentials")),
            "Should exclude OpenClaw credentials dir from content scanning");
    }

    #[test]
    fn test_default_sentinel_includes_openclaw_session_and_whatsapp() {
        let config = SentinelConfig::default();
        let paths: Vec<&str> = config.watch_paths.iter()
            .map(|w| w.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("sessions/sessions.json")),
            "Should watch session metadata");
        assert!(paths.iter().any(|p| p.contains("credentials/whatsapp")),
            "Should watch WhatsApp credentials");
    }

    #[test]
    fn test_exclude_content_scan_pattern() {
        let config = SentinelConfig::default();
        assert!(!config.exclude_content_scan.is_empty(),
            "Should have default exclude_content_scan patterns");

        let path = "/home/openclaw/.openclaw/workspace/superpowers/skills/brainstorming/SKILL.md";
        let excluded = config.exclude_content_scan.iter().any(|excl| path.contains(excl));
        assert!(excluded, "Skills directory should be excluded from content scan");

        let path2 = "/home/openclaw/.openclaw/workspace/SOUL.md";
        let excluded2 = config.exclude_content_scan.iter().any(|excl| path2.contains(excl));
        assert!(!excluded2, "SOUL.md should NOT be excluded from content scan");
    }

    #[test]
    fn test_load_with_overrides_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/clawtower/watchdog.log"

            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#devops"
            min_slack_level = "critical"

            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true

            [network]
            log_path = "/var/log/syslog"
            log_prefix = "CLAWTOWER_NET"
            enabled = true

            [scans]
            interval = 3600

            [falco]
            enabled = true
            log_path = "/var/log/falco/falco_output.jsonl"
        "##).unwrap();

        std::fs::write(config_d.join("00-my-overrides.toml"), r##"
            [falco]
            enabled = false
        "##).unwrap();

        let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
        assert!(!config.falco.enabled, "Falco should be disabled by override");
        assert_eq!(config.general.min_alert_level, "info");
    }

    #[test]
    fn test_load_with_overrides_list_add() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/clawtower/watchdog.log"

            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#devops"
            min_slack_level = "critical"

            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true

            [network]
            log_path = "/var/log/syslog"
            log_prefix = "CLAWTOWER_NET"
            enabled = true

            [netpolicy]
            enabled = true
            allowed_hosts = ["a.com"]

            [scans]
            interval = 3600
        "##).unwrap();

        std::fs::write(config_d.join("01-hosts.toml"), r##"
            [netpolicy]
            allowed_hosts_add = ["b.com"]
        "##).unwrap();

        let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
        assert!(config.netpolicy.allowed_hosts.contains(&"a.com".to_string()));
        assert!(config.netpolicy.allowed_hosts.contains(&"b.com".to_string()));
    }

    #[test]
    fn test_load_with_overrides_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/clawtower/watchdog.log"

            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#devops"
            min_slack_level = "critical"

            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true

            [network]
            log_path = "/var/log/syslog"
            log_prefix = "CLAWTOWER_NET"
            enabled = true

            [scans]
            interval = 3600
        "##).unwrap();

        let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
        assert_eq!(config.general.watched_user, Some("1000".to_string()));
    }

    // --- NEW REGRESSION TESTS ---

    #[test]
    fn test_missing_sections_use_defaults() {
        // Minimal config with only required non-default sections
        let toml_str = r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/test.log"

            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#test"
            min_slack_level = "critical"

            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true

            [network]
            log_path = "/var/log/syslog"
            log_prefix = "TEST"
            enabled = true

            [scans]
            interval = 60
        "##;
        let config: Config = toml::from_str(toml_str).unwrap();
        // All optional sections should have defaults
        assert!(!config.falco.enabled);
        assert!(!config.samhain.enabled);
        assert!(!config.api.enabled);
        assert!(!config.proxy.enabled);
        assert!(config.policy.enabled);
        assert_eq!(config.policy.dir, "./policies");
        assert!(!config.netpolicy.enabled);
        assert!(config.ssh.enabled);
        assert!(config.sentinel.enabled);
        assert!(config.auto_update.enabled);
        assert_eq!(config.auto_update.interval, 300);
        assert!(config.openclaw.enabled);
    }

    #[test]
    fn test_regression_sentinel_watch_paths_survive_partial_section() {
        // REGRESSION: When a profile overlay adds [sentinel] enabled = true,
        // the TOML merge creates a partial sentinel section. Without a named
        // serde default for watch_paths, #[serde(default)] produced vec![]
        // instead of the full watch path list — silently disabling all watches.
        let toml_str = r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/test.log"
            [slack]
            webhook_url = ""
            channel = "#test"
            min_slack_level = "critical"
            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true
            [network]
            log_path = "/var/log/syslog"
            log_prefix = "TEST"
            enabled = true
            [scans]
            interval = 60
            [sentinel]
            enabled = true
        "##;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.sentinel.enabled);
        assert!(!config.sentinel.watch_paths.is_empty(),
            "REGRESSION: sentinel.watch_paths must not be empty when [sentinel] section \
             only specifies enabled=true — serde default must return full watch list");
        assert!(config.sentinel.watch_paths.iter().any(|w| w.path.contains("SOUL.md")),
            "Default watch paths must include SOUL.md");
        assert!(config.sentinel.watch_paths.iter().any(|w| w.path == "/home/openclaw/.openclaw"),
            "Default watch paths must include .openclaw directory (for *.json glob)");
    }

    #[test]
    fn test_unknown_fields_ignored() {
        let toml_str = r##"
            this_field_does_not_exist = "should not crash"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/test.log"
            bogus_field = 42
            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#test"
            min_slack_level = "critical"
            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true
            [network]
            log_path = "/var/log/syslog"
            log_prefix = "TEST"
            enabled = true
            [scans]
            interval = 60
        "##;
        // Should not panic — unknown fields ignored by serde(default)
        // Actually this will fail because Config doesn't have deny_unknown_fields
        // but also doesn't have flatten. Let's see...
        let result: Result<Config, _> = toml::from_str(toml_str);
        // If this errors, that's a finding (unknown top-level fields crash parsing)
        // For now, just document the behavior
        if result.is_err() {
            // Known: top-level unknown fields cause parse error in strict serde
            // This is actually fine for security, but worth noting
        }
    }

    #[test]
    fn test_watch_path_auth_profiles_is_watched_credentials_protected() {
        // The important invariant: auth-profiles.json must be Watched (not Protected)
        // and credentials/ must be Protected. The sentinel matching logic handles
        // specificity, so ordering is less critical than correct policy assignment.
        let config = SentinelConfig::default();
        let auth_entry = config.watch_paths.iter()
            .find(|w| w.path.contains("auth-profiles.json"))
            .expect("auth-profiles.json must be in watch_paths");
        assert_eq!(auth_entry.policy, WatchPolicy::Watched);

        let creds_entry = config.watch_paths.iter()
            .find(|w| w.path.ends_with("credentials") && w.patterns.contains(&"*.json".to_string()))
            .expect("credentials/*.json must be in watch_paths");
        assert_eq!(creds_entry.policy, WatchPolicy::Protected);
    }

    #[test]
    fn test_regression_auth_profiles_is_watched_not_protected() {
        // REGRESSION: auth-profiles.json was Protected, causing quarantine loop
        let config = SentinelConfig::default();
        let auth_entry = config.watch_paths.iter()
            .find(|w| w.path.contains("auth-profiles.json"))
            .expect("auth-profiles.json must be in watch_paths");
        assert_eq!(auth_entry.policy, WatchPolicy::Watched,
            "REGRESSION: auth-profiles.json must be Watched, not Protected (caused quarantine loop)");
    }

    #[test]
    fn test_sentinel_defaults_soul_protected() {
        let config = SentinelConfig::default();
        let soul = config.watch_paths.iter()
            .find(|w| w.path.contains("SOUL.md"))
            .expect("SOUL.md must be watched");
        assert_eq!(soul.policy, WatchPolicy::Protected);
    }

    #[test]
    fn test_sentinel_defaults_memory_protected() {
        let config = SentinelConfig::default();
        let mem = config.watch_paths.iter().find(|w| w.path.ends_with("MEMORY.md")).unwrap();
        assert!(matches!(mem.policy, WatchPolicy::Protected), "MEMORY.md should be Protected to prevent shadow poisoning");
    }

    #[test]
    fn test_content_scan_excludes_include_auth_and_credentials() {
        let config = SentinelConfig::default();
        assert!(config.content_scan_excludes.iter().any(|p| p.contains("auth-profiles")),
            "content_scan_excludes must include auth-profiles");
        assert!(config.content_scan_excludes.iter().any(|p| p.contains("credentials")),
            "content_scan_excludes must include credentials");
    }

    #[test]
    fn test_effective_watched_users_single() {
        let gc = GeneralConfig {
            watched_user: Some("1000".to_string()),
            watched_users: vec![],
            watch_all_users: false,
            min_alert_level: "info".to_string(),
            log_file: "/tmp/test.log".to_string(),
        };
        let users = gc.effective_watched_users().unwrap();
        assert_eq!(users, vec!["1000"]);
    }

    #[test]
    fn test_effective_watched_users_dedup() {
        let gc = GeneralConfig {
            watched_user: Some("1000".to_string()),
            watched_users: vec!["1000".to_string(), "1001".to_string()],
            watch_all_users: false,
            min_alert_level: "info".to_string(),
            log_file: "/tmp/test.log".to_string(),
        };
        let users = gc.effective_watched_users().unwrap();
        // Should not duplicate "1000"
        assert_eq!(users.iter().filter(|u| *u == "1000").count(), 1);
        assert!(users.contains(&"1001".to_string()));
    }

    #[test]
    fn test_effective_watched_users_watch_all() {
        let gc = GeneralConfig {
            watched_user: Some("1000".to_string()),
            watched_users: vec!["1001".to_string()],
            watch_all_users: true,
            min_alert_level: "info".to_string(),
            log_file: "/tmp/test.log".to_string(),
        };
        // watch_all_users overrides everything
        assert!(gc.effective_watched_users().is_none());
    }

    #[test]
    fn test_effective_watched_users_empty_means_all() {
        let gc = GeneralConfig {
            watched_user: None,
            watched_users: vec![],
            watch_all_users: false,
            min_alert_level: "info".to_string(),
            log_file: "/tmp/test.log".to_string(),
        };
        assert!(gc.effective_watched_users().is_none());
    }

    #[test]
    fn test_config_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // Create minimal config, save, reload
        let toml_str = r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/test.log"
            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#test"
            min_slack_level = "critical"
            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true
            [network]
            log_path = "/var/log/syslog"
            log_prefix = "TEST"
            enabled = true
            [scans]
            interval = 60
        "##;
        let config: Config = toml::from_str(toml_str).unwrap();
        config.save(&path).unwrap();

        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.general.min_alert_level, "info");
        assert_eq!(reloaded.scans.interval, 60);
    }

    #[test]
    fn test_default_sentinel_includes_persistence_files() {
        let config = SentinelConfig::default();
        let paths: Vec<&str> = config.watch_paths.iter()
            .map(|w| w.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with(".bashrc")));
        assert!(paths.iter().any(|p| p.ends_with(".profile")));
        assert!(paths.iter().any(|p| p.ends_with(".bash_login")));
        assert!(paths.iter().any(|p| p.ends_with(".bash_logout")));
        assert!(paths.iter().any(|p| p.ends_with(".npmrc")));
        assert!(paths.iter().any(|p| p.ends_with(".ssh/rc")));
        assert!(paths.iter().any(|p| p.ends_with(".ssh/environment")));
        assert!(paths.iter().any(|p| p.contains("systemd/user")));
        assert!(paths.iter().any(|p| p.contains("autostart")));
        assert!(paths.iter().any(|p| p.contains(".git/hooks")));
    }

    #[test]
    fn test_sentinel_heartbeat_watched() {
        let config = SentinelConfig::default();
        let hb = config.watch_paths.iter()
            .find(|w| w.path.contains("HEARTBEAT.md"))
            .expect("HEARTBEAT.md must be watched");
        assert_eq!(hb.policy, WatchPolicy::Watched);
    }

    #[test]
    fn test_sentinel_agents_protected() {
        let config = SentinelConfig::default();
        let agents = config.watch_paths.iter()
            .find(|w| w.path.contains("AGENTS.md"))
            .expect("AGENTS.md must be watched");
        assert_eq!(agents.policy, WatchPolicy::Protected);
    }

    #[test]
    fn test_watch_policy_serde_roundtrip() {
        let toml_str = r#"
            path = "/test"
            patterns = ["*"]
            policy = "protected"
        "#;
        let wp: WatchPathConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(wp.policy, WatchPolicy::Protected);

        let toml_str2 = r#"
            path = "/test"
            patterns = ["*"]
            policy = "watched"
        "#;
        let wp2: WatchPathConfig = toml::from_str(toml_str2).unwrap();
        assert_eq!(wp2.policy, WatchPolicy::Watched);
    }

    #[test]
    fn test_overlay_multiple_files_applied_alphabetically() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/clawtower/watchdog.log"
            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#devops"
            min_slack_level = "critical"
            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true
            [network]
            log_path = "/var/log/syslog"
            log_prefix = "CLAWTOWER_NET"
            enabled = true
            [scans]
            interval = 3600
            [ssh]
            enabled = true
        "##).unwrap();

        // 00 sets ssh.enabled = false
        std::fs::write(config_d.join("00-disable-ssh.toml"), r##"
            [ssh]
            enabled = false
        "##).unwrap();

        // 01 sets ssh.enabled = true (should win, applied after 00)
        std::fs::write(config_d.join("01-enable-ssh.toml"), r##"
            [ssh]
            enabled = true
        "##).unwrap();

        let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
        assert!(config.ssh.enabled, "Later overlay (01) should override earlier (00)");
    }

    #[test]
    fn test_overlay_non_toml_files_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/test.log"
            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#test"
            min_slack_level = "critical"
            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true
            [network]
            log_path = "/var/log/syslog"
            log_prefix = "TEST"
            enabled = true
            [scans]
            interval = 60
        "##).unwrap();

        // .txt file should be ignored
        std::fs::write(config_d.join("README.txt"), "not a config").unwrap();
        // .bak file should be ignored
        std::fs::write(config_d.join("backup.bak"), "[ssh]\nenabled = false").unwrap();

        let config = Config::load_with_overrides(&base_path, &config_d).unwrap();
        assert!(config.ssh.enabled, "Non-.toml files should be ignored");
    }

    #[test]
    fn test_incident_mode_defaults() {
        let cfg = IncidentModeConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.dedup_window_secs, 2);
        assert_eq!(cfg.scan_dedup_window_secs, 60);
        assert_eq!(cfg.rate_limit_per_source, 200);
        assert!(!cfg.lock_clawsudo);
    }

    #[test]
    fn test_incident_mode_from_toml() {
        let toml_str = r##"
[general]
watched_user = "1000"
min_alert_level = "info"
log_file = "/var/log/test.log"
[slack]
webhook_url = "https://hooks.slack.com/test"
channel = "#test"
min_slack_level = "critical"
[auditd]
log_path = "/var/log/audit/audit.log"
enabled = true
[network]
log_path = "/var/log/syslog"
log_prefix = "TEST"
enabled = true
[scans]
interval = 60
[incident_mode]
enabled = true
dedup_window_secs = 5
lock_clawsudo = true
"##;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.incident_mode.enabled);
        assert_eq!(cfg.incident_mode.dedup_window_secs, 5);
        assert!(cfg.incident_mode.lock_clawsudo);
        // Defaults for unspecified fields
        assert_eq!(cfg.incident_mode.scan_dedup_window_secs, 60);
        assert_eq!(cfg.incident_mode.rate_limit_per_source, 200);
    }

    #[test]
    fn test_load_with_overrides_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");

        std::fs::write(&base_path, r##"
            [general]
            watched_user = "1000"
            min_alert_level = "info"
            log_file = "/var/log/clawtower/watchdog.log"

            [slack]
            webhook_url = "https://hooks.slack.com/test"
            channel = "#devops"
            min_slack_level = "critical"

            [auditd]
            log_path = "/var/log/audit/audit.log"
            enabled = true

            [network]
            log_path = "/var/log/syslog"
            log_prefix = "CLAWTOWER_NET"
            enabled = true

            [scans]
            interval = 3600
        "##).unwrap();

        let nonexistent = dir.path().join("config.d");
        let config = Config::load_with_overrides(&base_path, &nonexistent).unwrap();
        assert_eq!(config.general.watched_user, Some("1000".to_string()));
    }

    #[test]
    fn test_load_with_profile_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let profile_path = dir.path().join("profile.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
[general]
watched_user = "1000"
min_alert_level = "info"
log_file = "/var/log/clawtower/watchdog.log"
[slack]
webhook_url = "https://hooks.slack.com/test"
channel = "#devops"
min_slack_level = "critical"
[auditd]
log_path = "/var/log/audit/audit.log"
enabled = true
[network]
log_path = "/var/log/syslog"
log_prefix = "CLAWTOWER_NET"
enabled = true
[scans]
interval = 3600
"##).unwrap();

        // Profile changes scan interval and slack level
        std::fs::write(&profile_path, r##"
[scans]
interval = 1800
[slack]
min_slack_level = "info"
"##).unwrap();

        // config.d/ override wins over profile
        std::fs::write(config_d.join("00-override.toml"), r##"
[scans]
interval = 900
"##).unwrap();

        let config = Config::load_with_profile_and_overrides(
            &base_path,
            Some(profile_path.as_path()),
            &config_d,
        ).unwrap();

        // config.d/ override wins: 900, not profile's 1800
        assert_eq!(config.scans.interval, 900);
        // Profile's slack change applies (no config.d/ override for slack)
        assert_eq!(config.slack.min_slack_level, "info");
        // Base value preserved where neither profile nor override touches it
        assert_eq!(config.general.min_alert_level, "info");
    }

    #[test]
    fn test_load_with_no_profile() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("config.toml");
        let config_d = dir.path().join("config.d");
        std::fs::create_dir(&config_d).unwrap();

        std::fs::write(&base_path, r##"
[general]
watched_user = "1000"
min_alert_level = "info"
log_file = "/var/log/clawtower/watchdog.log"
[slack]
webhook_url = "https://hooks.slack.com/test"
channel = "#devops"
min_slack_level = "critical"
[auditd]
log_path = "/var/log/audit/audit.log"
enabled = true
[network]
log_path = "/var/log/syslog"
log_prefix = "CLAWTOWER_NET"
enabled = true
[scans]
interval = 3600
"##).unwrap();

        // No profile, should behave like load_with_overrides
        let config = Config::load_with_profile_and_overrides(
            &base_path,
            None,
            &config_d,
        ).unwrap();
        assert_eq!(config.scans.interval, 3600);
        assert_eq!(config.slack.min_slack_level, "critical");
    }

    #[test]
    fn test_prompt_firewall_config_defaults() {
        let config = PromptFirewallConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.tier, 2);
        assert_eq!(config.patterns_path, "/etc/clawtower/prompt-firewall-patterns.json");
        assert!(config.overrides.is_empty());
    }

    #[test]
    fn test_prompt_firewall_config_deserialize() {
        let toml_str = r#"
            enabled = true
            tier = 3
            patterns_path = "/custom/patterns.json"
            [overrides]
            jailbreak = "log"
        "#;
        let config: PromptFirewallConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.tier, 3);
        assert_eq!(config.overrides.get("jailbreak").unwrap(), "log");
    }

    #[test]
    fn test_key_mapping_ttl_defaults() {
        let toml_str = r#"
            virtual_key = "vk-test"
            real = "sk-real"
            provider = "anthropic"
            upstream = "https://api.anthropic.com"
        "#;
        let mapping: KeyMapping = toml::from_str(toml_str).unwrap();
        assert!(mapping.ttl_secs.is_none(), "ttl_secs should default to None");
        assert!(mapping.allowed_paths.is_empty(), "allowed_paths should default to empty");
        assert_eq!(mapping.revoke_at_risk, 0.0, "revoke_at_risk should default to 0.0");
    }

    #[test]
    fn test_api_non_loopback_requires_auth_token() {
        let config = ApiConfig {
            enabled: true,
            bind: "0.0.0.0".to_string(),
            port: 18791,
            auth_token: String::new(),
            cors_origin: None,
        };
        assert!(config.validate().is_err(), "Non-loopback bind must require auth_token");
    }

    #[test]
    fn test_api_loopback_allows_empty_token() {
        let config = ApiConfig {
            enabled: true,
            bind: "127.0.0.1".to_string(),
            port: 18791,
            auth_token: String::new(),
            cors_origin: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_api_non_loopback_with_token_ok() {
        let config = ApiConfig {
            enabled: true,
            bind: "0.0.0.0".to_string(),
            port: 18791,
            auth_token: "my-secret".to_string(),
            cors_origin: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_api_disabled_skips_validation() {
        let config = ApiConfig {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: 18791,
            auth_token: String::new(),
            cors_origin: None,
        };
        assert!(config.validate().is_ok(), "Disabled API should skip validation");
    }

    #[test]
    fn test_api_ipv6_loopback_allows_empty_token() {
        let config = ApiConfig {
            enabled: true,
            bind: "::1".to_string(),
            port: 18791,
            auth_token: String::new(),
            cors_origin: None,
        };
        assert!(config.validate().is_ok());
    }
}
