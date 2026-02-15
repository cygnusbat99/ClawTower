use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::secureclaw::SecureClawConfig;

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
    pub secureclaw: SecureClawConfig,
    #[serde(default)]
    pub netpolicy: NetPolicyConfig,
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub sentinel: SentinelConfig,
    #[serde(default)]
    pub auto_update: AutoUpdateConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AutoUpdateConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auto_update_interval")]
    pub interval: u64,
}

fn default_auto_update_interval() -> u64 { 300 }

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 300,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SshConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
fn default_true() -> bool { true }
impl Default for SshConfig {
    fn default() -> Self { Self { enabled: true } }
}

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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GeneralConfig {
    pub watched_user: Option<String>,  // Keep for backward compat
    #[serde(default)]
    pub watched_users: Vec<String>,
    #[serde(default)]
    pub watch_all_users: bool,
    pub min_alert_level: String,
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SlackConfig {
    pub enabled: Option<bool>,
    pub webhook_url: String,
    #[serde(default)]
    pub backup_webhook_url: String,
    pub channel: String,
    pub min_slack_level: String,
    /// Interval in seconds for periodic health heartbeat to Slack (0 = disabled)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
}

fn default_heartbeat_interval() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditdConfig {
    pub log_path: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NetworkConfig {
    pub log_path: String,
    pub log_prefix: String,
    pub enabled: bool,
    #[serde(default = "default_network_source")]
    pub source: String,
    /// CIDR ranges to never alert on
    #[serde(default = "default_allowlisted_cidrs")]
    pub allowlisted_cidrs: Vec<String>,
    /// Extra ports to never alert on
    #[serde(default = "default_allowlisted_ports")]
    pub allowlisted_ports: Vec<u16>,
}

fn default_network_source() -> String {
    "auto".to_string()
}

pub fn default_allowlisted_cidrs() -> Vec<String> {
    vec![
        "192.168.0.0/16".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "169.254.0.0/16".to_string(),
        "127.0.0.0/8".to_string(),
        "224.0.0.0/4".to_string(),
    ]
}

pub fn default_allowlisted_ports() -> Vec<u16> {
    vec![443, 53, 123, 5353]
}

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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ScansConfig {
    pub interval: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: 18791,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    #[serde(default)]
    pub key_mapping: Vec<KeyMapping>,
    #[serde(default)]
    pub dlp: DlpConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1".to_string(),
            port: 18790,
            key_mapping: Vec::new(),
            dlp: DlpConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct KeyMapping {
    #[serde(alias = "virtual")]
    pub virtual_key: String,
    pub real: String,
    pub provider: String,
    pub upstream: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DlpConfig {
    #[serde(default)]
    pub patterns: Vec<DlpPattern>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
    pub action: String,
}

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
            mode: "blocklist".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SentinelConfig {
    #[serde(default = "default_sentinel_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub watch_paths: Vec<WatchPathConfig>,
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: String,
    #[serde(default = "default_shadow_dir")]
    pub shadow_dir: String,
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
    #[serde(default = "default_scan_content")]
    pub scan_content: bool,
    #[serde(default = "default_max_file_size_kb")]
    pub max_file_size_kb: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WatchPathConfig {
    pub path: String,
    pub patterns: Vec<String>,
    pub policy: WatchPolicy,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WatchPolicy {
    Protected,
    Watched,
}

fn default_sentinel_enabled() -> bool { true }
fn default_quarantine_dir() -> String { "/etc/clawav/quarantine".to_string() }
fn default_shadow_dir() -> String { "/etc/clawav/sentinel-shadow".to_string() }
fn default_debounce_ms() -> u64 { 200 }
fn default_scan_content() -> bool { true }
fn default_max_file_size_kb() -> u64 { 1024 }

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_paths: vec![
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/SOUL.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/AGENTS.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Protected,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/MEMORY.md".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
            ],
            quarantine_dir: default_quarantine_dir(),
            shadow_dir: default_shadow_dir(),
            debounce_ms: default_debounce_ms(),
            scan_content: default_scan_content(),
            max_file_size_kb: default_max_file_size_kb(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config")?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))?;
        Ok(())
    }
}
