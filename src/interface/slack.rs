// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Slack webhook notification sender.
//!
//! Sends formatted alerts to Slack via incoming webhooks. Supports primary and
//! backup webhook URLs for failover. Messages use color-coded attachments based
//! on severity. Also sends startup announcements and periodic heartbeat messages.

use anyhow::Result;
use serde_json::json;

use crate::core::alerts::Alert;
use crate::config::SlackConfig;

/// Sends formatted alerts and status messages to Slack via incoming webhooks.
///
/// Supports primary + backup webhook URLs for failover. Automatically disabled
/// if no webhook URL is configured.
pub struct SlackNotifier {
    webhook_url: String,
    backup_webhook_url: String,
    channel: String,
    enabled: bool,
}

impl SlackNotifier {
    pub fn new(config: &SlackConfig) -> Self {
        let explicitly_enabled = config.enabled.unwrap_or(true);
        Self {
            webhook_url: config.webhook_url.clone(),
            backup_webhook_url: config.backup_webhook_url.clone(),
            channel: config.channel.clone(),
            enabled: explicitly_enabled && !config.webhook_url.is_empty(),
        }
    }

    /// Send payload to primary webhook, failover to backup on error
    async fn post_webhook(&self, payload: &serde_json::Value) -> Result<()> {
        let client = reqwest::Client::new();
        let resp = client.post(&self.webhook_url).json(payload).send().await;

        match resp {
            Ok(r) if r.status().is_success() => Ok(()),
            _ => {
                if !self.backup_webhook_url.is_empty() {
                    client.post(&self.backup_webhook_url).json(payload).send().await?;
                    Ok(())
                } else if let Err(e) = resp {
                    Err(e.into())
                } else {
                    anyhow::bail!("Primary webhook failed, no backup configured")
                }
            }
        }
    }

    /// Test the webhook connection by sending a test message.
    #[allow(dead_code)]
    pub async fn test_connection(&self) -> Result<()> {
        if !self.enabled {
            anyhow::bail!("Slack notifications not enabled or webhook URL is empty");
        }

        let payload = json!({
            "channel": self.channel,
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "text": "🛡️ ClawTower webhook test — connection verified!"
        });

        let resp = reqwest::Client::new()
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Slack webhook returned HTTP {}", resp.status());
        }

        Ok(())
    }

    /// Send the startup announcement.
    pub async fn send_startup_message(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let payload = json!({
            "channel": self.channel,
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "text": "🛡️ ClawTower watchdog started — independent monitoring active"
        });

        self.post_webhook(&payload).await
    }

    pub async fn send_heartbeat(&self, uptime_secs: u64, alert_count: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let payload = serde_json::json!({
            "channel": self.channel,
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "text": format!("❤️ ClawTower heartbeat — uptime: {}h {}m, alerts processed: {}",
                uptime_secs / 3600, (uptime_secs % 3600) / 60, alert_count)
        });
        self.post_webhook(&payload).await
    }

    pub async fn send_alert(&self, alert: &Alert) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let color = match alert.severity {
            crate::core::alerts::Severity::Info => "#36a64f",
            crate::core::alerts::Severity::Warning => "#daa520",
            crate::core::alerts::Severity::Critical => "#dc3545",
        };

        let payload = json!({
            "channel": self.channel,
            "username": "ClawTower",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "title": format!("{} ClawTower Alert", alert.severity.emoji()),
                "text": alert.message,
                "fields": [
                    { "title": "Severity", "value": alert.severity.to_string(), "short": true },
                    { "title": "Source", "value": alert.source, "short": true },
                ],
                "ts": alert.timestamp.timestamp()
            }]
        });

        self.post_webhook(&payload).await
    }
}
