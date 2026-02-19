// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Cloud Management Plane — agent-side uplink for fleet management.
//!
//! Pushes alerts and health telemetry to the ClawTower cloud management plane.
//! Pulls policy updates when enabled. Communication is HTTPS with Ed25519
//! agent authentication. Operates autonomously when cloud is unreachable.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Local};
use crate::core::alerts::Alert;

// ── Config types (moved from config.rs) ──────────────────────────────────────

/// Cloud management plane uplink configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudConfig {
    /// Enable cloud uplink
    #[serde(default)]
    pub enabled: bool,
    /// Cloud management plane endpoint URL
    #[serde(default = "default_cloud_endpoint")]
    pub endpoint: String,
    /// Path to agent Ed25519 private key for authentication
    #[serde(default = "default_agent_key_path")]
    pub agent_key_path: String,
    /// Agent registration ID (auto-generated on first connect)
    #[serde(default)]
    pub agent_id: String,
    /// Telemetry push interval in seconds
    #[serde(default = "default_telemetry_interval")]
    pub telemetry_interval: u64,
    /// Whether to push alerts to cloud
    #[serde(default = "default_true")]
    pub push_alerts: bool,
    /// Whether to pull policy updates from cloud
    #[serde(default)]
    pub pull_policies: bool,
    /// Batch size for alert uploads
    #[serde(default = "default_cloud_batch")]
    pub batch_size: usize,
}

fn default_cloud_endpoint() -> String { "https://api.clawtower.io".to_string() }
fn default_agent_key_path() -> String { "/etc/clawtower/agent-key.pem".to_string() }
fn default_telemetry_interval() -> u64 { 60 }
fn default_cloud_batch() -> usize { 50 }
fn default_true() -> bool { true }

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_cloud_endpoint(),
            agent_key_path: default_agent_key_path(),
            agent_id: String::new(),
            telemetry_interval: default_telemetry_interval(),
            push_alerts: true,
            pull_policies: false,
            batch_size: default_cloud_batch(),
        }
    }
}

/// Registration payload sent to the cloud on first connect.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub hostname: String,
    pub version: String,
    pub os_info: String,
    pub registered_at: DateTime<Local>,
}

/// Health telemetry pushed periodically.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct HealthTelemetry {
    pub agent_id: String,
    pub timestamp: DateTime<Local>,
    pub uptime_secs: u64,
    pub total_alerts: u64,
    pub critical_alerts: u64,
    pub warning_alerts: u64,
    pub monitored_agents: Vec<String>,
    pub incident_mode: bool,
    pub version: String,
}

/// Alert batch payload for cloud upload.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct AlertBatch {
    pub agent_id: String,
    pub batch_id: u64,
    pub alerts: Vec<CloudAlert>,
}

/// Alert representation for cloud upload (serializable subset of Alert).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAlert {
    pub timestamp: String,
    pub severity: String,
    pub source: String,
    pub message: String,
    pub agent_name: Option<String>,
    pub skill_name: Option<String>,
}

impl CloudAlert {
    pub fn from_alert(alert: &Alert) -> Self {
        Self {
            timestamp: alert.timestamp.to_rfc3339(),
            severity: format!("{}", alert.severity),
            source: alert.source.clone(),
            message: alert.message.clone(),
            agent_name: alert.agent_name.clone(),
            skill_name: alert.skill_name.clone(),
        }
    }
}

/// Policy update received from the cloud.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyUpdate {
    pub version: String,
    pub update_type: PolicyUpdateType,
    pub payload: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyUpdateType {
    AgentProfile,
    ClawsudoPolicy,
    IocBundle,
    ExportConfig,
}

/// Cloud uplink client for the agent.
#[allow(dead_code)]
pub struct CloudUplink {
    config: CloudConfig,
    alert_buffer: Vec<CloudAlert>,
    batch_counter: u64,
}

#[allow(dead_code)]
impl CloudUplink {
    pub fn new(config: CloudConfig) -> Self {
        Self {
            config,
            alert_buffer: Vec::new(),
            batch_counter: 0,
        }
    }

    /// Get the registration payload for this agent.
    pub fn registration(&self) -> AgentRegistration {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        AgentRegistration {
            agent_id: self.config.agent_id.clone(),
            hostname,
            version: env!("CARGO_PKG_VERSION").to_string(),
            os_info: std::fs::read_to_string("/etc/os-release")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".to_string()),
            registered_at: Local::now(),
        }
    }

    /// Build a health telemetry payload.
    pub fn health_telemetry(
        &self,
        uptime_secs: u64,
        total_alerts: u64,
        critical_alerts: u64,
        warning_alerts: u64,
        monitored_agents: Vec<String>,
        incident_mode: bool,
    ) -> HealthTelemetry {
        HealthTelemetry {
            agent_id: self.config.agent_id.clone(),
            timestamp: Local::now(),
            uptime_secs,
            total_alerts,
            critical_alerts,
            warning_alerts,
            monitored_agents,
            incident_mode,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Queue an alert for batch upload.
    pub fn queue_alert(&mut self, alert: &Alert) {
        self.alert_buffer.push(CloudAlert::from_alert(alert));
    }

    /// Flush the alert buffer into a batch, returning it if non-empty.
    pub fn flush_batch(&mut self) -> Option<AlertBatch> {
        if self.alert_buffer.is_empty() {
            return None;
        }

        let alerts: Vec<CloudAlert> = self.alert_buffer
            .drain(..self.config.batch_size.min(self.alert_buffer.len()))
            .collect();

        self.batch_counter += 1;

        Some(AlertBatch {
            agent_id: self.config.agent_id.clone(),
            batch_id: self.batch_counter,
            alerts,
        })
    }

    /// Get the cloud endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Check if the uplink is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the number of pending alerts.
    pub fn pending_count(&self) -> usize {
        self.alert_buffer.len()
    }

    /// Serialize a registration payload to JSON.
    pub fn registration_json(&self) -> String {
        serde_json::to_string_pretty(&self.registration()).unwrap_or_default()
    }

    /// Serialize a health telemetry payload to JSON.
    pub fn telemetry_json(&self, telemetry: &HealthTelemetry) -> String {
        serde_json::to_string(telemetry).unwrap_or_default()
    }

    /// Serialize an alert batch to JSON.
    pub fn batch_json(batch: &AlertBatch) -> String {
        serde_json::to_string(batch).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::alerts::{Alert, Severity};

    fn test_config() -> CloudConfig {
        CloudConfig {
            enabled: true,
            endpoint: "https://api.clawtower.io".to_string(),
            agent_key_path: "/etc/clawtower/agent-key.pem".to_string(),
            agent_id: "agent-test-001".to_string(),
            telemetry_interval: 60,
            push_alerts: true,
            pull_policies: false,
            batch_size: 50,
        }
    }

    fn test_alert(severity: Severity, source: &str, message: &str) -> Alert {
        Alert::new(severity, source, message)
    }

    #[test]
    fn test_cloud_config_defaults() {
        let cfg = CloudConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "https://api.clawtower.io");
        assert_eq!(cfg.agent_key_path, "/etc/clawtower/agent-key.pem");
        assert!(cfg.agent_id.is_empty());
        assert_eq!(cfg.telemetry_interval, 60);
        assert!(cfg.push_alerts);
        assert!(!cfg.pull_policies);
        assert_eq!(cfg.batch_size, 50);
    }

    #[test]
    fn test_cloud_alert_from_alert() {
        let alert = test_alert(Severity::Critical, "behavior", "exfil detected")
            .with_agent("openclaw")
            .with_skill("shell-exec");
        let cloud_alert = CloudAlert::from_alert(&alert);
        assert_eq!(cloud_alert.severity, "CRIT");
        assert_eq!(cloud_alert.source, "behavior");
        assert_eq!(cloud_alert.message, "exfil detected");
        assert_eq!(cloud_alert.agent_name, Some("openclaw".to_string()));
        assert_eq!(cloud_alert.skill_name, Some("shell-exec".to_string()));
        // Timestamp should be RFC 3339 formatted
        assert!(cloud_alert.timestamp.contains('T'));
    }

    #[test]
    fn test_cloud_uplink_new() {
        let uplink = CloudUplink::new(test_config());
        assert_eq!(uplink.pending_count(), 0);
        assert!(uplink.is_enabled());
        assert_eq!(uplink.endpoint(), "https://api.clawtower.io");
    }

    #[test]
    fn test_queue_alert() {
        let mut uplink = CloudUplink::new(test_config());
        let alert = test_alert(Severity::Warning, "scanner", "weak firewall");
        uplink.queue_alert(&alert);
        assert_eq!(uplink.pending_count(), 1);
        uplink.queue_alert(&alert);
        assert_eq!(uplink.pending_count(), 2);
    }

    #[test]
    fn test_flush_batch_empty() {
        let mut uplink = CloudUplink::new(test_config());
        assert!(uplink.flush_batch().is_none());
    }

    #[test]
    fn test_flush_batch_with_alerts() {
        let mut uplink = CloudUplink::new(test_config());
        let alert = test_alert(Severity::Info, "sentinel", "file modified");
        uplink.queue_alert(&alert);
        uplink.queue_alert(&alert);
        uplink.queue_alert(&alert);

        let batch = uplink.flush_batch().unwrap();
        assert_eq!(batch.batch_id, 1);
        assert_eq!(batch.alerts.len(), 3);
        assert_eq!(batch.agent_id, "agent-test-001");
        assert_eq!(uplink.pending_count(), 0);

        // Second flush should return None (buffer drained)
        assert!(uplink.flush_batch().is_none());

        // Next batch should increment counter
        uplink.queue_alert(&alert);
        let batch2 = uplink.flush_batch().unwrap();
        assert_eq!(batch2.batch_id, 2);
    }

    #[test]
    fn test_flush_batch_respects_batch_size() {
        let mut config = test_config();
        config.batch_size = 2;
        let mut uplink = CloudUplink::new(config);

        for _ in 0..5 {
            let alert = test_alert(Severity::Info, "auditd", "syscall event");
            uplink.queue_alert(&alert);
        }
        assert_eq!(uplink.pending_count(), 5);

        let batch1 = uplink.flush_batch().unwrap();
        assert_eq!(batch1.alerts.len(), 2);
        assert_eq!(uplink.pending_count(), 3);

        let batch2 = uplink.flush_batch().unwrap();
        assert_eq!(batch2.alerts.len(), 2);
        assert_eq!(uplink.pending_count(), 1);

        let batch3 = uplink.flush_batch().unwrap();
        assert_eq!(batch3.alerts.len(), 1);
        assert_eq!(uplink.pending_count(), 0);
    }

    #[test]
    fn test_registration_payload() {
        let uplink = CloudUplink::new(test_config());
        let reg = uplink.registration();
        assert_eq!(reg.agent_id, "agent-test-001");
        assert_eq!(reg.version, env!("CARGO_PKG_VERSION"));
        // hostname and os_info are system-dependent but should be non-empty strings
        assert!(!reg.version.is_empty());
    }

    #[test]
    fn test_health_telemetry() {
        let uplink = CloudUplink::new(test_config());
        let telemetry = uplink.health_telemetry(
            3600,
            150,
            5,
            20,
            vec!["openclaw".to_string()],
            false,
        );
        assert_eq!(telemetry.agent_id, "agent-test-001");
        assert_eq!(telemetry.uptime_secs, 3600);
        assert_eq!(telemetry.total_alerts, 150);
        assert_eq!(telemetry.critical_alerts, 5);
        assert_eq!(telemetry.warning_alerts, 20);
        assert_eq!(telemetry.monitored_agents, vec!["openclaw".to_string()]);
        assert!(!telemetry.incident_mode);
        assert_eq!(telemetry.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_batch_json_serialization() {
        let mut uplink = CloudUplink::new(test_config());
        let alert = test_alert(Severity::Critical, "behavior", "lateral movement")
            .with_agent("openclaw");
        uplink.queue_alert(&alert);

        let batch = uplink.flush_batch().unwrap();
        let json = CloudUplink::batch_json(&batch);

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["agent_id"], "agent-test-001");
        assert_eq!(parsed["batch_id"], 1);
        assert!(parsed["alerts"].is_array());
        assert_eq!(parsed["alerts"][0]["severity"], "CRIT");
        assert_eq!(parsed["alerts"][0]["source"], "behavior");
        assert_eq!(parsed["alerts"][0]["agent_name"], "openclaw");
    }

    #[test]
    fn test_policy_update_type_deserialization() {
        let json_agent = r#"{"version":"1.0","update_type":"agent_profile","payload":"data"}"#;
        let update: PolicyUpdate = serde_json::from_str(json_agent).unwrap();
        assert!(matches!(update.update_type, PolicyUpdateType::AgentProfile));
        assert_eq!(update.version, "1.0");

        let json_policy = r#"{"version":"2.0","update_type":"clawsudo_policy","payload":"rules"}"#;
        let update: PolicyUpdate = serde_json::from_str(json_policy).unwrap();
        assert!(matches!(update.update_type, PolicyUpdateType::ClawsudoPolicy));

        let json_ioc = r#"{"version":"3.0","update_type":"ioc_bundle","payload":"indicators"}"#;
        let update: PolicyUpdate = serde_json::from_str(json_ioc).unwrap();
        assert!(matches!(update.update_type, PolicyUpdateType::IocBundle));

        let json_export = r#"{"version":"4.0","update_type":"export_config","payload":"cfg"}"#;
        let update: PolicyUpdate = serde_json::from_str(json_export).unwrap();
        assert!(matches!(update.update_type, PolicyUpdateType::ExportConfig));
    }
}
