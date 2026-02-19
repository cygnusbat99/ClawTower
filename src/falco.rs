// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Falco eBPF/syscall alert integration.
//!
//! Tails a Falco JSON log file and converts entries into ClawTower alerts.
//! Falco priority levels (EMERGENCY, ALERT, CRITICAL, etc.) are mapped to
//! ClawTower severity levels. Waits for the log file to appear if Falco is not
//! yet running.

use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, watch};

use crate::alerts::{Alert, Severity};
use crate::safe_tail::SafeTailer;

/// Map Falco priority string to our Severity
fn falco_priority_to_severity(priority: &str) -> Severity {
    match priority.to_uppercase().as_str() {
        "EMERGENCY" | "ALERT" | "CRITICAL" => Severity::Critical,
        "ERROR" | "WARNING" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Parse a single Falco JSON log line into an Alert
pub fn parse_falco_line(line: &str) -> Option<Alert> {
    let json: Value = serde_json::from_str(line).ok()?;

    let priority = json.get("priority")?.as_str()?;
    let output = json.get("output")?.as_str()?;
    let rule = json.get("rule").and_then(|v| v.as_str()).unwrap_or("unknown");

    let severity = falco_priority_to_severity(priority);
    let message = format!("[{}] {}", rule, output);

    Some(Alert::new(severity, "falco", &message))
}

/// Tail the Falco JSON log file and send alerts
pub async fn tail_falco_log(
    path: &Path,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    let tailer = SafeTailer::new(path);
    let mut rx = tailer.tail_lines(tx.clone(), "falco").await;

    while let Some(line) = rx.recv().await {
        if let Some(alert) = parse_falco_line(&line) {
            let _ = tx.send(alert).await;
        }
    }

    Ok(())
}

/// Tail the Falco log with live path switching via a watch channel.
///
/// When the path changes (e.g. user edits config in the TUI), the old SafeTailer
/// is dropped and a new one is created for the updated path — no restart required.
pub async fn tail_falco_log_dynamic(
    tx: mpsc::Sender<Alert>,
    mut path_rx: watch::Receiver<PathBuf>,
) -> Result<()> {
    loop {
        let path = path_rx.borrow_and_update().clone();
        let tailer = SafeTailer::new(&path);
        let mut rx = tailer.tail_lines(tx.clone(), "falco").await;

        loop {
            tokio::select! {
                line = rx.recv() => {
                    match line {
                        Some(line) => {
                            if let Some(alert) = parse_falco_line(&line) {
                                let _ = tx.send(alert).await;
                            }
                        }
                        None => break, // tailer died, restart with current path
                    }
                }
                _ = path_rx.changed() => {
                    let _ = tx.send(Alert::new(
                        Severity::Info, "falco",
                        &format!("Log path changed to {}", path_rx.borrow().display()),
                    )).await;
                    break; // drop rx (stops old SafeTailer), loop restarts with new path
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_falco_json() {
        let line = r#"{"output":"12:00:00.000000000: Warning Unexpected process by openclaw user (user=openclaw command=nmap pid=1234 parent=bash container=host)","priority":"Warning","rule":"OpenClaw Unexpected Process","source":"syscall","tags":["openclaw","process"],"time":"2026-02-13T12:00:00.000000000Z"}"#;
        let alert = parse_falco_line(line).unwrap();
        assert_eq!(alert.source, "falco");
        assert_eq!(alert.severity, Severity::Warning);
        assert!(alert.message.contains("OpenClaw Unexpected Process"));
    }

    #[test]
    fn test_parse_falco_critical() {
        let line = r#"{"output":"12:00:00.000000000: Critical Privilege escalation attempt (user=openclaw command=sudo bash)","priority":"Critical","rule":"OpenClaw Privilege Escalation Attempt","source":"syscall","tags":["openclaw"],"time":"2026-02-13T12:00:00.000000000Z"}"#;
        let alert = parse_falco_line(line).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn test_parse_invalid_json() {
        assert!(parse_falco_line("not json at all").is_none());
    }
}
