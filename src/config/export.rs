// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! SIEM Export Pipeline — syslog CEF, JSON webhook, and rotated file export.
//!
//! Provides three export backends for integrating ClawTower alerts into
//! enterprise SIEM/SOC toolchains:
//!
//! - **Syslog CEF** (Common Event Format): UDP/TCP to Splunk, QRadar, ArcSight
//! - **Webhook**: JSON POST to SOAR platforms, PagerDuty, Tines, custom endpoints
//! - **File**: Rotated JSONL for Splunk forwarder, Fluentd, Filebeat
//!
//! The export pipeline receives alerts via a tokio mpsc channel (teed from the
//! aggregator output) and fans out to all enabled backends.

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::core::alerts::{Alert, Severity};

// ── Config types (moved from config.rs) ──────────────────────────────────────

/// SIEM export pipeline configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExportConfig {
    /// Enable the export pipeline.
    #[serde(default)]
    pub enabled: bool,
    /// Syslog export sub-config.
    #[serde(default)]
    pub syslog: SyslogExportConfig,
    /// Webhook export sub-config.
    #[serde(default)]
    pub webhook: WebhookExportConfig,
    /// File export sub-config (for Splunk forwarder / Fluentd).
    #[serde(default)]
    pub file: FileExportConfig,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            syslog: SyslogExportConfig::default(),
            webhook: WebhookExportConfig::default(),
            file: FileExportConfig::default(),
        }
    }
}

/// Syslog (CEF / RFC 5424) export configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogExportConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Target address (e.g., "udp://siem.corp:514", "tcp://siem.corp:6514")
    #[serde(default = "default_syslog_target")]
    pub target: String,
    /// Format: "cef" (Common Event Format) or "rfc5424"
    #[serde(default = "default_syslog_format")]
    pub format: String,
    /// Minimum severity for syslog export
    #[serde(default = "default_syslog_min_level")]
    pub min_level: String,
}

fn default_syslog_target() -> String { "udp://127.0.0.1:514".to_string() }
fn default_syslog_format() -> String { "cef".to_string() }
fn default_syslog_min_level() -> String { "warning".to_string() }

impl Default for SyslogExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target: default_syslog_target(),
            format: default_syslog_format(),
            min_level: default_syslog_min_level(),
        }
    }
}

/// Webhook (JSON POST) export configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookExportConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Webhook URL to POST alerts to
    #[serde(default)]
    pub url: String,
    /// Authorization header value (e.g., "Bearer <token>")
    #[serde(default)]
    pub auth_header: String,
    /// Number of alerts to batch before flushing
    #[serde(default = "default_webhook_batch")]
    pub batch_size: usize,
    /// Maximum seconds between flushes
    #[serde(default = "default_webhook_flush")]
    pub flush_interval_secs: u64,
}

fn default_webhook_batch() -> usize { 10 }
fn default_webhook_flush() -> u64 { 5 }

impl Default for WebhookExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            auth_header: String::new(),
            batch_size: default_webhook_batch(),
            flush_interval_secs: default_webhook_flush(),
        }
    }
}

/// File export configuration (rotated JSON lines for Splunk forwarder / Fluentd).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileExportConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Output file path
    #[serde(default = "default_file_export_path")]
    pub path: String,
    /// Maximum file size in bytes before rotation
    #[serde(default = "default_file_max_size")]
    pub max_size_bytes: u64,
    /// Number of rotated files to keep
    #[serde(default = "default_file_keep")]
    pub keep_rotated: u32,
}

fn default_file_export_path() -> String { "/var/log/clawtower/export.jsonl".to_string() }
fn default_file_max_size() -> u64 { 50 * 1024 * 1024 } // 50 MB
fn default_file_keep() -> u32 { 5 }

impl Default for FileExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_file_export_path(),
            max_size_bytes: default_file_max_size(),
            keep_rotated: default_file_keep(),
        }
    }
}

/// CEF severity mapping (0-10 scale per ArcSight CEF spec).
fn cef_severity(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 3,
        Severity::Warning => 6,
        Severity::Critical => 9,
    }
}

/// Escape a string for CEF value fields.
/// CEF requires escaping backslash, pipe, and equals in extension values.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', " ")
}

/// Escape a string for CEF header fields (only backslash and pipe).
fn cef_header_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Format an alert as a CEF (Common Event Format) syslog message.
///
/// CEF format: `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions`
///
/// Extensions include: `src`, `msg`, `cat`, and optional `duser` (agent) and
/// `cs1` (skill name).
#[allow(dead_code)]
pub fn format_cef(alert: &Alert, version: &str) -> String {
    let sig_id = cef_header_escape(&alert.source);
    let name = cef_header_escape(
        alert.message.get(..80).unwrap_or(&alert.message),
    );
    let sev = cef_severity(&alert.severity);

    let mut extensions = format!(
        "rt={} src={} msg={} cat={}",
        alert.timestamp.format("%b %d %Y %H:%M:%S"),
        cef_escape(&alert.source),
        cef_escape(&alert.message),
        cef_escape(&alert.source),
    );

    if let Some(ref agent) = alert.agent_name {
        extensions.push_str(&format!(" duser={}", cef_escape(agent)));
    }
    if let Some(ref skill) = alert.skill_name {
        extensions.push_str(&format!(
            " cs1={} cs1Label=SkillName",
            cef_escape(skill)
        ));
    }

    format!(
        "CEF:0|ClawTower|ClawTower|{}|{}|{}|{}|{}",
        version, sig_id, name, sev, extensions
    )
}

/// A serializable alert payload for webhook/file export.
#[derive(Debug, Clone, Serialize)]
pub struct ExportAlert {
    pub timestamp: String,
    pub severity: String,
    pub source: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skill_name: Option<String>,
    pub clawtower_version: String,
    pub hostname: String,
}

#[allow(dead_code)]
impl ExportAlert {
    /// Convert an Alert into an ExportAlert with metadata.
    pub fn from_alert(alert: &Alert, version: &str, hostname: &str) -> Self {
        Self {
            timestamp: alert.timestamp.to_rfc3339(),
            severity: format!("{}", alert.severity),
            source: alert.source.clone(),
            message: alert.message.clone(),
            agent_name: alert.agent_name.clone(),
            skill_name: alert.skill_name.clone(),
            clawtower_version: version.to_string(),
            hostname: hostname.to_string(),
        }
    }

    /// Serialize to a single JSON line (for JSONL file export).
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A batch of alerts for webhook delivery.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub source: String,
    pub hostname: String,
    pub version: String,
    pub alerts: Vec<ExportAlert>,
}

/// Parse a syslog target string into (protocol, host, port).
///
/// Accepts: `udp://host:port`, `tcp://host:port`, `host:port` (defaults to UDP).
#[allow(dead_code)]
pub fn parse_syslog_target(target: &str) -> (String, String, u16) {
    let (proto, rest) = if let Some(stripped) = target.strip_prefix("tcp://") {
        ("tcp".to_string(), stripped)
    } else if let Some(stripped) = target.strip_prefix("udp://") {
        ("udp".to_string(), stripped)
    } else {
        ("udp".to_string(), target)
    };

    let parts: Vec<&str> = rest.rsplitn(2, ':').collect();
    let port = parts.first().and_then(|p| p.parse().ok()).unwrap_or(514);
    let host = if parts.len() > 1 {
        parts[1].to_string()
    } else {
        rest.to_string()
    };

    (proto, host, port)
}

/// File exporter with size-based rotation.
#[allow(dead_code)]
pub struct FileExporter {
    path: String,
    max_size_bytes: u64,
    keep_rotated: u32,
}

#[allow(dead_code)]
impl FileExporter {
    pub fn new(path: &str, max_size_bytes: u64, keep_rotated: u32) -> Self {
        Self {
            path: path.to_string(),
            max_size_bytes,
            keep_rotated,
        }
    }

    /// Write a JSONL line to the export file, rotating if needed.
    pub fn write_line(&self, line: &str) -> std::io::Result<()> {
        // Check if rotation is needed
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() >= self.max_size_bytes {
                self.rotate()?;
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&self.path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", line)
    }

    /// Rotate log files: export.jsonl -> export.jsonl.1 -> ... -> export.jsonl.N
    fn rotate(&self) -> std::io::Result<()> {
        // Remove the oldest rotated file
        let oldest = format!("{}.{}", self.path, self.keep_rotated);
        let _ = std::fs::remove_file(&oldest);

        // Shift existing rotated files
        for i in (1..self.keep_rotated).rev() {
            let from = format!("{}.{}", self.path, i);
            let to = format!("{}.{}", self.path, i + 1);
            if std::path::Path::new(&from).exists() {
                std::fs::rename(&from, &to)?;
            }
        }

        // Move current file to .1
        let first = format!("{}.1", self.path);
        if std::path::Path::new(&self.path).exists() {
            std::fs::rename(&self.path, &first)?;
        }

        Ok(())
    }
}

/// Check if an alert meets the minimum severity threshold for export.
#[allow(dead_code)]
pub fn meets_min_level(alert: &Alert, min_level: &str) -> bool {
    let threshold = Severity::from_str(min_level);
    alert.severity >= threshold
}

/// Build a webhook payload from a batch of alerts.
#[allow(dead_code)]
pub fn build_webhook_payload(
    alerts: &[ExportAlert],
    hostname: &str,
    version: &str,
) -> WebhookPayload {
    WebhookPayload {
        source: "clawtower".to_string(),
        hostname: hostname.to_string(),
        version: version.to_string(),
        alerts: alerts.to_vec(),
    }
}

/// Get the local hostname for export metadata.
#[allow(dead_code)]
pub fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

/// Summary of export pipeline state (for status/health endpoints).
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct ExportStatus {
    pub enabled: bool,
    pub syslog_enabled: bool,
    pub webhook_enabled: bool,
    pub file_enabled: bool,
    pub total_exported: u64,
    pub last_export: Option<DateTime<Local>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::alerts::{Alert, Severity};

    fn test_alert(severity: Severity, source: &str, message: &str) -> Alert {
        Alert::new(severity, source, message)
    }

    #[test]
    fn test_cef_format_critical() {
        let alert = test_alert(
            Severity::Critical,
            "behavior:data_exfiltration",
            "Detected data exfiltration via curl to unknown host",
        );
        let cef = format_cef(&alert, "0.5.0");

        assert!(cef.starts_with("CEF:0|ClawTower|ClawTower|0.5.0|"));
        assert!(cef.contains("|9|")); // Critical = severity 9
        assert!(cef.contains("msg=Detected data exfiltration"));
        assert!(cef.contains("cat=behavior:data_exfiltration"));
    }

    #[test]
    fn test_cef_format_warning() {
        let alert = test_alert(
            Severity::Warning,
            "scan:firewall_status",
            "UFW inactive",
        );
        let cef = format_cef(&alert, "0.5.0");

        assert!(cef.contains("|6|")); // Warning = severity 6
        assert!(cef.contains("scan:firewall_status"));
    }

    #[test]
    fn test_cef_format_info() {
        let alert = test_alert(Severity::Info, "sentinel", "File changed");
        let cef = format_cef(&alert, "0.5.0");

        assert!(cef.contains("|3|")); // Info = severity 3
    }

    #[test]
    fn test_cef_with_agent_and_skill() {
        let alert = test_alert(Severity::Critical, "behavior", "reverse shell")
            .with_agent("openclaw")
            .with_skill("web-scraper");
        let cef = format_cef(&alert, "0.5.0");

        assert!(cef.contains("duser=openclaw"));
        assert!(cef.contains("cs1=web-scraper"));
        assert!(cef.contains("cs1Label=SkillName"));
    }

    #[test]
    fn test_cef_escaping_pipes() {
        let alert = test_alert(
            Severity::Warning,
            "test|source",
            "message with | pipe and = equals",
        );
        let cef = format_cef(&alert, "0.5.0");

        // Header fields should escape pipes
        assert!(cef.contains("test\\|source"));
        // Extension values should escape pipes and equals
        assert!(cef.contains("msg=message with \\| pipe and \\= equals"));
    }

    #[test]
    fn test_export_alert_from_alert() {
        let alert = test_alert(Severity::Warning, "auditd", "suspicious exec")
            .with_agent("openclaw");
        let export = ExportAlert::from_alert(&alert, "0.5.0", "testhost");

        assert_eq!(export.severity, "WARN");
        assert_eq!(export.source, "auditd");
        assert_eq!(export.message, "suspicious exec");
        assert_eq!(export.agent_name, Some("openclaw".to_string()));
        assert!(export.skill_name.is_none());
        assert_eq!(export.clawtower_version, "0.5.0");
        assert_eq!(export.hostname, "testhost");
    }

    #[test]
    fn test_export_alert_json_line() {
        let alert = test_alert(Severity::Info, "sentinel", "file changed");
        let export = ExportAlert::from_alert(&alert, "0.5.0", "host1");
        let json = export.to_json_line();

        assert!(json.contains("\"severity\":\"INFO\""));
        assert!(json.contains("\"source\":\"sentinel\""));
        assert!(json.contains("\"hostname\":\"host1\""));
        // Optional None fields should be absent
        assert!(!json.contains("agent_name"));
    }

    #[test]
    fn test_parse_syslog_target_udp() {
        let (proto, host, port) = parse_syslog_target("udp://siem.corp:514");
        assert_eq!(proto, "udp");
        assert_eq!(host, "siem.corp");
        assert_eq!(port, 514);
    }

    #[test]
    fn test_parse_syslog_target_tcp() {
        let (proto, host, port) = parse_syslog_target("tcp://siem.corp:6514");
        assert_eq!(proto, "tcp");
        assert_eq!(host, "siem.corp");
        assert_eq!(port, 6514);
    }

    #[test]
    fn test_parse_syslog_target_bare() {
        let (proto, host, port) = parse_syslog_target("siem.corp:514");
        assert_eq!(proto, "udp"); // default
        assert_eq!(host, "siem.corp");
        assert_eq!(port, 514);
    }

    #[test]
    fn test_meets_min_level_warning_threshold() {
        let crit = test_alert(Severity::Critical, "test", "crit");
        let warn = test_alert(Severity::Warning, "test", "warn");
        let info = test_alert(Severity::Info, "test", "info");

        assert!(meets_min_level(&crit, "warning"));
        assert!(meets_min_level(&warn, "warning"));
        assert!(!meets_min_level(&info, "warning"));
    }

    #[test]
    fn test_meets_min_level_info_threshold() {
        let info = test_alert(Severity::Info, "test", "info");
        assert!(meets_min_level(&info, "info"));
    }

    #[test]
    fn test_webhook_payload_structure() {
        let alert = test_alert(Severity::Warning, "auditd", "exec detected");
        let export = ExportAlert::from_alert(&alert, "0.5.0", "host1");
        let payload = build_webhook_payload(&[export], "host1", "0.5.0");

        assert_eq!(payload.source, "clawtower");
        assert_eq!(payload.hostname, "host1");
        assert_eq!(payload.version, "0.5.0");
        assert_eq!(payload.alerts.len(), 1);
    }

    #[test]
    fn test_webhook_payload_serializable() {
        let alert = test_alert(Severity::Critical, "behavior", "exfil");
        let export = ExportAlert::from_alert(&alert, "0.5.0", "host1");
        let payload = build_webhook_payload(&[export], "host1", "0.5.0");
        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("\"source\":\"clawtower\""));
        assert!(json.contains("\"hostname\":\"host1\""));
        assert!(json.contains("\"severity\":\"CRIT\""));
    }

    #[test]
    fn test_file_exporter_write_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.jsonl");
        let exporter = FileExporter::new(
            path.to_str().unwrap(),
            1024 * 1024,
            3,
        );

        exporter.write_line(r#"{"test": true}"#).unwrap();
        exporter.write_line(r#"{"test": false}"#).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"test\": true"));
    }

    #[test]
    fn test_file_exporter_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.jsonl");
        let exporter = FileExporter::new(
            path.to_str().unwrap(),
            30, // tiny max size — first line exceeds this, triggering rotation on second write
            3,
        );

        // Write enough to exceed 50 bytes
        exporter.write_line(r#"{"line": 1, "padding": "aaaaaaaaaaaaaaaaaa"}"#).unwrap();
        // This write should trigger rotation
        exporter.write_line(r#"{"line": 2, "padding": "bbbbbbbbbbbbbbbbbb"}"#).unwrap();

        // Rotated file should exist
        let rotated = format!("{}.1", path.display());
        assert!(std::path::Path::new(&rotated).exists());

        // Current file should contain the newest line
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("line\": 2"));
    }

    #[test]
    fn test_export_config_defaults() {
        let config = ExportConfig::default();
        assert!(!config.enabled);
        assert!(!config.syslog.enabled);
        assert!(!config.webhook.enabled);
        assert!(!config.file.enabled);
        assert_eq!(config.syslog.format, "cef");
        assert_eq!(config.webhook.batch_size, 10);
        assert_eq!(config.file.max_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn test_export_status_serializable() {
        let status = ExportStatus {
            enabled: true,
            syslog_enabled: true,
            webhook_enabled: false,
            file_enabled: true,
            total_exported: 42,
            last_export: Some(Local::now()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"total_exported\":42"));
    }
}
