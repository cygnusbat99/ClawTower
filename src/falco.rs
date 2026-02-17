//! Falco eBPF/syscall alert integration.
//!
//! Tails a Falco JSON log file and converts entries into ClawTower alerts.
//! Falco priority levels (EMERGENCY, ALERT, CRITICAL, etc.) are mapped to
//! ClawTower severity levels. Waits for the log file to appear if Falco is not
//! yet running.

use anyhow::Result;
use serde_json::Value;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::fs::File;
use std::path::Path;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::alerts::{Alert, Severity};

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
    // Wait for log file to appear, but don't wait forever.
    // If Falco isn't installed/running, give up after a few attempts.
    let max_wait_attempts = 3;
    let mut attempts = 0;
    while !path.exists() {
        attempts += 1;
        if attempts > max_wait_attempts {
            let _ = tx.send(Alert::new(
                Severity::Warning,
                "falco",
                &format!(
                    "Falco log not found at {} after {}s — Falco may not be installed. \
                     Disable with falco.enabled=false in config.",
                    path.display(),
                    max_wait_attempts * 30
                ),
            )).await;
            return Ok(());
        }
        let _ = tx.send(Alert::new(
            Severity::Info,
            "falco",
            &format!("Waiting for Falco log at {} (attempt {}/{})...", path.display(), attempts, max_wait_attempts),
        )).await;
        sleep(Duration::from_secs(30)).await;
    }

    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    let _ = tx.send(Alert::new(
        Severity::Info,
        "falco",
        "Falco log monitor started",
    )).await;

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => sleep(Duration::from_millis(500)).await,
            Ok(_) => {
                if let Some(alert) = parse_falco_line(&line) {
                    let _ = tx.send(alert).await;
                }
            }
            Err(e) => {
                let _ = tx.send(Alert::new(
                    Severity::Warning,
                    "falco",
                    &format!("Error reading Falco log: {}", e),
                )).await;
                sleep(Duration::from_secs(5)).await;
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
