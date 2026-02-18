//! Journald-based log monitoring for network and SSH events.
//!
//! Provides two async tail functions:
//! - [`tail_journald_network`]: Tails kernel messages (`journalctl -k`) for iptables
//!   log entries matching a configured prefix.
//! - [`tail_journald_ssh`]: Tails `ssh`/`sshd` unit logs for login successes and failures.
//!
//! Falls back to file-based monitoring when journald is unavailable.
//!
//! Uses [`SafeCommand`] for hardened process execution: absolute path enforcement,
//! environment sanitization, and auto-restart with exponential backoff.

use anyhow::Result;
use serde_json::Value;
use std::path::Path;
use tokio::sync::mpsc;

use crate::alerts::{Alert, Severity};
use crate::network::parse_iptables_line;
use crate::safe_cmd::SafeCommand;

/// Absolute path to journalctl binary.
const JOURNALCTL_PATH: &str = "/usr/bin/journalctl";

/// Check if journald is available on this system.
///
/// Uses an absolute path to avoid PATH injection. Returns `false` if the
/// binary does not exist or if `journalctl --version` fails.
pub fn journald_available() -> bool {
    if !Path::new(JOURNALCTL_PATH).exists() {
        return false;
    }
    std::process::Command::new(JOURNALCTL_PATH)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Tail kernel messages from journald for iptables log entries.
///
/// Spawns `journalctl -k -f -o json --since now` via [`SafeCommand::stream_lines`],
/// which provides auto-restart on exit with exponential backoff and Critical alerts
/// after 5 consecutive failures.
pub async fn tail_journald_network(
    prefix: &str,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    let cmd = SafeCommand::new(JOURNALCTL_PATH)
        .map_err(|e| anyhow::anyhow!(e))?
        .args(&["-k", "-f", "-o", "json", "--since", "now"]);

    // Send startup notification
    let _ = tx.send(Alert::new(
        Severity::Info,
        "network",
        "Network monitor started (journald source)",
    )).await;

    let mut rx = cmd.stream_lines(tx.clone(), "network").await;

    while let Some(line) = rx.recv().await {
        // Parse JSON line from journalctl
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            // The kernel message is in the "MESSAGE" field
            if let Some(message) = json.get("MESSAGE").and_then(|v| v.as_str()) {
                if let Some(alert) = parse_iptables_line(message, prefix) {
                    let _ = tx.send(alert).await;
                }
            }
        }
    }

    Ok(())
}

/// Tail SSH login events from journald.
///
/// Spawns `journalctl -u ssh -u sshd -f -o cat --since now` via
/// [`SafeCommand::stream_lines`], which provides auto-restart on exit with
/// exponential backoff and Critical alerts after 5 consecutive failures.
pub async fn tail_journald_ssh(tx: mpsc::Sender<Alert>) -> Result<()> {
    let cmd = SafeCommand::new(JOURNALCTL_PATH)
        .map_err(|e| anyhow::anyhow!(e))?
        .args(&["-u", "ssh", "-u", "sshd", "-f", "-o", "cat", "--since", "now"]);

    let mut rx = cmd.stream_lines(tx.clone(), "ssh").await;

    while let Some(line) = rx.recv().await {
        let (severity, msg) = if line.contains("Accepted") {
            (Severity::Info, format!("SSH login: {}", line))
        } else if line.contains("Failed password") || line.contains("Failed publickey") {
            (Severity::Warning, format!("SSH failed login: {}", line))
        } else if line.contains("Invalid user") {
            (Severity::Warning, format!("SSH invalid user: {}", line))
        } else {
            continue;
        };
        let _ = tx.send(Alert::new(severity, "ssh", &msg)).await;
    }
    Ok(())
}
