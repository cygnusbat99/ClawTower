use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::alerts::{Alert, Severity};

/// Monitor audit log file for tampering indicators
pub async fn monitor_log_integrity(
    log_path: PathBuf,
    tx: mpsc::Sender<Alert>,
    interval_secs: u64,
) {
    let mut last_size: Option<u64> = None;
    let mut last_inode: Option<u64> = None;

    loop {
        match check_log_file(&log_path, &mut last_size, &mut last_inode) {
            Some(alert) => {
                let _ = tx.send(alert).await;
            }
            None => {}
        }
        sleep(Duration::from_secs(interval_secs)).await;
    }
}

fn check_log_file(
    path: &Path,
    last_size: &mut Option<u64>,
    last_inode: &mut Option<u64>,
) -> Option<Alert> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => {
            return Some(Alert::new(
                Severity::Critical,
                "logtamper",
                &format!("Audit log MISSING: {} — possible evidence destruction", path.display()),
            ));
        }
    };

    let current_size = metadata.len();
    let current_inode = metadata.ino();

    // Check for inode change (file was replaced/recreated)
    if let Some(prev_inode) = *last_inode {
        if current_inode != prev_inode {
            *last_inode = Some(current_inode);
            *last_size = Some(current_size);
            return Some(Alert::new(
                Severity::Critical,
                "logtamper",
                &format!(
                    "Audit log REPLACED: {} — inode changed from {} to {} — possible tampering",
                    path.display(), prev_inode, current_inode
                ),
            ));
        }
    }

    // Check for size decrease (file was truncated)
    if let Some(prev_size) = *last_size {
        if current_size < prev_size {
            *last_size = Some(current_size);
            return Some(Alert::new(
                Severity::Critical,
                "logtamper",
                &format!(
                    "Audit log TRUNCATED: {} — size decreased from {} to {} bytes — possible evidence destruction",
                    path.display(), prev_size, current_size
                ),
            ));
        }
    }

    // Update tracking state
    *last_size = Some(current_size);
    *last_inode = Some(current_inode);

    None
}

/// Scanner integration: check audit log health
pub fn scan_audit_log_health(log_path: &Path) -> crate::scanner::ScanResult {
    use crate::scanner::{ScanResult, ScanStatus};

    if !log_path.exists() {
        return ScanResult::new("audit_log", ScanStatus::Fail, "Audit log file does not exist");
    }

    match std::fs::metadata(log_path) {
        Ok(metadata) => {
            use std::os::unix::fs::MetadataExt;
            let size = metadata.len();
            let mode = metadata.mode();

            // Check permissions (should be 600 or 640)
            let world_readable = mode & 0o004 != 0;
            let world_writable = mode & 0o002 != 0;

            if world_writable {
                ScanResult::new("audit_log", ScanStatus::Fail, 
                    &format!("Audit log is world-writable (mode {:o}) — anyone can tamper", mode & 0o777))
            } else if world_readable {
                ScanResult::new("audit_log", ScanStatus::Warn, 
                    &format!("Audit log is world-readable (mode {:o})", mode & 0o777))
            } else if size == 0 {
                ScanResult::new("audit_log", ScanStatus::Warn, "Audit log is empty (0 bytes)")
            } else {
                ScanResult::new("audit_log", ScanStatus::Pass, 
                    &format!("Audit log healthy: {} bytes, mode {:o}", size, mode & 0o777))
            }
        }
        Err(e) => ScanResult::new("audit_log", ScanStatus::Fail, &format!("Cannot stat audit log: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_log_triggers_critical() {
        let mut last_size = Some(1000);
        let mut last_inode = Some(12345);
        let alert = check_log_file(Path::new("/nonexistent/audit.log"), &mut last_size, &mut last_inode);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("MISSING"));
    }

    #[test]
    fn test_first_check_no_alert() {
        // Use /dev/null as a file that exists
        let mut last_size = None;
        let mut last_inode = None;
        let alert = check_log_file(Path::new("/dev/null"), &mut last_size, &mut last_inode);
        assert!(alert.is_none());
        assert!(last_size.is_some());
        assert!(last_inode.is_some());
    }

    #[test]
    fn test_size_decrease_triggers_truncation_alert() {
        let mut last_size = Some(10000);
        let mut last_inode = None;
        // /dev/null has size 0, so this simulates truncation
        let alert = check_log_file(Path::new("/dev/null"), &mut last_size, &mut last_inode);
        // First call sets inode, but since last_inode was None, no inode change alert
        // Size check: 0 < 10000 = truncation
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("TRUNCATED"));
    }

    #[test]
    fn test_scan_audit_log_missing() {
        let result = scan_audit_log_health(Path::new("/nonexistent/audit.log"));
        assert_eq!(result.status, crate::scanner::ScanStatus::Fail);
    }

    #[test]
    fn test_scan_audit_log_exists() {
        // /etc/passwd exists on all Linux systems
        let result = scan_audit_log_health(Path::new("/etc/passwd"));
        // Should pass or warn depending on permissions, but not fail
        assert_ne!(result.status, crate::scanner::ScanStatus::Fail);
    }
}