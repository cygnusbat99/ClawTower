//! Samhain file integrity monitoring integration.
//!
//! Tails the Samhain log file and converts entries into ClawTower alerts.
//! Samhain severity prefixes (CRIT, ALERT, WARN, NOTICE, INFO) are mapped
//! to ClawTower severity levels. Waits for the log file to appear if Samhain
//! is not yet running.

use anyhow::Result;
use std::path::Path;
use tokio::sync::mpsc;
use tokio::time::Duration;

use crate::alerts::{Alert, Severity};
use crate::safe_match::parse_log_severity;
use crate::safe_tail::SafeTailer;

/// Parse a Samhain log line into an Alert.
/// Samhain log lines look like:
///   CRIT   :  [2026-02-13T12:00:00] path=/etc/passwd (checksum mismatch)
///   WARN   :  [2026-02-13T12:00:00] path=/usr/bin/curl (mtime changed)
///   ALERT  :  [2026-02-13T12:00:00] POLICY CHANGED: /etc/sudoers
pub fn parse_samhain_line(line: &str) -> Option<Alert> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Determine severity from Samhain's level prefix (only checks before first `:` or `]`)
    let severity = match parse_log_severity(line) {
        Some(sev) => sev,
        None => return None, // Skip debug/unknown lines
    };

    // Extract the meaningful part — everything after the timestamp bracket
    let message = if let Some(bracket_end) = line.find(']') {
        line[bracket_end + 1..].trim().to_string()
    } else {
        // No timestamp bracket — use the whole line after severity
        if let Some(colon_pos) = line.find(':') {
            line[colon_pos + 1..].trim().to_string()
        } else {
            line.to_string()
        }
    };

    if message.is_empty() {
        return None;
    }

    Some(Alert::new(severity, "samhain", &message))
}

/// Tail the Samhain log file and send alerts
pub async fn tail_samhain_log(
    path: &Path,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    let tailer = SafeTailer::new(path)
        .retry_interval(Duration::from_secs(60));
    let mut rx = tailer.tail_lines(tx.clone(), "samhain").await;

    while let Some(line) = rx.recv().await {
        if let Some(alert) = parse_samhain_line(&line) {
            let _ = tx.send(alert).await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_crit_line() {
        let line = "CRIT   :  [2026-02-13T12:00:00+0000] path=/etc/shadow checksum mismatch";
        let alert = parse_samhain_line(line).unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.source, "samhain");
        assert!(alert.message.contains("/etc/shadow"));
    }

    #[test]
    fn test_parse_warn_line() {
        let line = "WARN   :  [2026-02-13T12:00:00+0000] path=/usr/bin/curl mtime changed";
        let alert = parse_samhain_line(line).unwrap();
        assert_eq!(alert.severity, Severity::Warning);
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(parse_samhain_line("").is_none());
        assert!(parse_samhain_line("# comment").is_none());
    }

    #[test]
    fn test_parse_info_line() {
        let line = "INFO   :  [2026-02-13T12:00:00+0000] Checking /etc/passwd";
        let alert = parse_samhain_line(line).unwrap();
        assert_eq!(alert.severity, Severity::Info);
    }
}
