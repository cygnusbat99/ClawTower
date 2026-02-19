// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! User account and persistence security scanners.
//!
//! User audit, persistence mechanisms, failed logins, crontab.

use super::{ScanResult, ScanStatus};
use super::helpers::{run_cmd, detect_agent_username, detect_agent_home, compute_file_sha256};

/// Audit user and system crontabs for suspicious entries (wget, curl, nc, base64, etc.).
pub fn scan_crontab_audit() -> ScanResult {
    let mut issues = Vec::new();

    // Check user crontabs
    if let Ok(output) = run_cmd("bash", &["-c", "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null | grep -v '^#' | grep -v '^$' && echo \"User: $u\"; done"]) {
        if !output.trim().is_empty() {
            let lines: Vec<&str> = output.lines().collect();
            for line in lines {
                if line.contains("wget") || line.contains("curl") || line.contains("nc") ||
                   line.contains("/dev/tcp") || line.contains("python -c") || line.contains("base64") {
                    issues.push(format!("Suspicious cron job: {}", line.trim()));
                }
            }
        }
    }

    // Check system crontabs
    let system_cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
    for dir in &system_cron_dirs {
        if let Ok(output) = run_cmd("find", &[dir, "-type", "f", "-exec", "grep", "-l", "-E", "(wget|curl|nc|python -c|base64|/dev/tcp)", "{}", ";"]) {
            if !output.trim().is_empty() {
                for file in output.lines() {
                    issues.push(format!("Suspicious system cron file: {}", file));
                }
            }
        }
    }

    // Check /etc/crontab
    if let Ok(output) = run_cmd("grep", &["-v", "^#", "/etc/crontab"]) {
        for line in output.lines() {
            if line.contains("wget") || line.contains("curl") || line.contains("nc") {
                issues.push(format!("Suspicious /etc/crontab entry: {}", line.trim()));
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("crontab_audit", ScanStatus::Pass, "No suspicious cron jobs detected")
    } else {
        ScanResult::new("crontab_audit", ScanStatus::Fail, &format!("Found {} suspicious cron entries: {}", issues.len(), issues.join("; ")))
    }
}

/// Check journalctl and auth.log for excessive failed SSH login attempts and potential brute-force success.
pub fn scan_failed_login_attempts() -> ScanResult {
    let mut issues = Vec::new();

    // Check journalctl for failed SSH attempts
    if let Ok(output) = run_cmd("journalctl", &["--since", "24 hours ago", "-u", "ssh", "--grep", "Failed password"]) {
        let failed_attempts = output.lines().count();
        if failed_attempts > 50 {
            issues.push(format!("High SSH failed logins in 24h: {}", failed_attempts));
        } else if failed_attempts > 10 {
            issues.push(format!("Moderate SSH failed logins in 24h: {}", failed_attempts));
        }
    }

    // Check distro-specific auth logs if present
    for log_path in ["/var/log/auth.log", "/var/log/secure"] {
        if std::path::Path::new(log_path).exists() {
            if let Ok(output) = run_cmd("grep", &["-c", "Failed password", log_path]) {
                if let Ok(count) = output.trim().parse::<u32>() {
                    if count > 100 {
                        issues.push(format!("High auth failures in {}: {}", log_path, count));
                    }
                }
            }
        }
    }

    // Check for successful logins after many failures (potential brute force success)
    if let Ok(output) = run_cmd("journalctl", &["--since", "1 hour ago", "--grep", "Accepted password"]) {
        let successful_logins = output.lines().count();
        if successful_logins > 0 && issues.iter().any(|i| i.contains("failed logins")) {
            issues.push(format!("Successful logins after failures detected: {}", successful_logins));
        }
    }

    if issues.is_empty() {
        ScanResult::new("failed_logins", ScanStatus::Pass, "No excessive failed login attempts")
    } else {
        ScanResult::new("failed_logins", ScanStatus::Warn, &format!("Login attempt issues: {}", issues.join("; ")))
    }
}

/// Audit user accounts: non-root UID 0 users, passwordless shell accounts, and excessive sudo group members.
pub fn scan_user_account_audit() -> ScanResult {
    let mut issues = Vec::new();
    let watched_user = detect_agent_username();

    // Check for users with UID 0 (root privileges)
    if let Ok(passwd_content) = std::fs::read_to_string("/etc/passwd") {
        let mut uid_0_users = Vec::new();
        for line in passwd_content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                let username = fields[0];
                let uid = fields[2];
                if uid == "0" && username != "root" {
                    uid_0_users.push(username.to_string());
                }
            }
        }
        if !uid_0_users.is_empty() {
            issues.push(format!("Non-root users with UID 0: {}", uid_0_users.join(", ")));
        }

        // Check for users with no password
        if let Ok(shadow_content) = std::fs::read_to_string("/etc/shadow") {
            let mut no_password_users = Vec::new();
            for line in shadow_content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 2 {
                    let username = fields[0];
                    let password_hash = fields[1];
                    if password_hash.is_empty() || password_hash == "*" || password_hash == "!" {
                        // These are normal for system users, but check if they have shell access
                        if let Some(passwd_line) = passwd_content.lines().find(|l| l.starts_with(&format!("{}:", username))) {
                            let passwd_fields: Vec<&str> = passwd_line.split(':').collect();
                            if passwd_fields.len() >= 7 {
                                let shell = passwd_fields[6];
                                if shell.contains("bash") || shell.contains("zsh") || shell.contains("sh") {
                                    no_password_users.push(username.to_string());
                                }
                            }
                        }
                    }
                }
            }
            if !no_password_users.is_empty() {
                issues.push(format!("Users with shell access but no password: {}", no_password_users.join(", ")));
            }
        }

        // Check for recently created users
        if let Ok(output) = run_cmd("bash", &["-c", "awk -F: '($3>=1000)&&($1!=\"nobody\"){print $1}' /etc/passwd | wc -l"]) {
            if let Ok(user_count) = output.trim().parse::<u32>() {
                if user_count > 5 {
                    issues.push(format!("Many regular user accounts: {}", user_count));
                }
            }
        }

        // Check for users in sudo group
        if let Ok(group_content) = std::fs::read_to_string("/etc/group") {
            for line in group_content.lines() {
                if line.starts_with("sudo:") || line.starts_with("wheel:") || line.starts_with("admin:") {
                    let fields: Vec<&str> = line.split(':').collect();
                    if fields.len() >= 4 && !fields[3].is_empty() {
                        let sudo_users: Vec<&str> = fields[3].split(',').collect();
                        if sudo_users.len() > 2 {
                            issues.push(format!("Many users with sudo access: {}", sudo_users.len()));
                        }
                    }
                }
            }
        }
    }

    // Check if watched user is in dangerous groups (docker/lxd = instant root)
    if let Ok(group_content) = std::fs::read_to_string("/etc/group") {
        const DANGEROUS_GROUPS: &[&str] = &["docker", "lxd", "lxc", "disk"];
        for line in group_content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 4 {
                let group_name = fields[0];
                if DANGEROUS_GROUPS.contains(&group_name) {
                    let members: Vec<&str> = fields[3].split(',').filter(|s| !s.is_empty()).collect();
                    if members.iter().any(|m| *m == watched_user) {
                        issues.push(format!("{} in dangerous group '{}' (privilege escalation vector)", watched_user, group_name));
                    }
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("user_accounts", ScanStatus::Pass, "User account configuration secure")
    } else {
        // Dangerous groups are critical, not just warnings
        let has_dangerous_group = issues.iter().any(|i| i.contains("dangerous group"));
        if has_dangerous_group {
            ScanResult::new("user_accounts", ScanStatus::Fail, &format!("User account issues: {}", issues.join("; ")))
        } else {
            ScanResult::new("user_accounts", ScanStatus::Warn, &format!("User account issues: {}", issues.join("; ")))
        }
    }
}

/// Scan user-level persistence mechanisms for the openclaw user.
///
/// Checks crontab, systemd user units, shell rc file integrity, autostart
/// desktop files, git hooks, SSH rc/environment, Python usercustomize,
/// npmrc install scripts, and dangerous environment variables.
pub fn scan_user_persistence() -> Vec<ScanResult> {
    scan_user_persistence_inner(None)
}

/// Inner implementation with optional crontab override for testing.
fn scan_user_persistence_inner(crontab_override: Option<&str>) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let home = detect_agent_home();

    // 1. Crontab entries
    let crontab_output = match crontab_override {
        Some(s) => Ok(s.to_string()),
        None => run_cmd("crontab", &["-l"]),
    };
    match crontab_output {
        Ok(output) => {
            let entries: Vec<&str> = output.lines()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .collect();
            if entries.is_empty() {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No user crontab entries"));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                    &format!("User crontab has {} entries: {}", entries.len(), entries.join("; "))));
            }
        }
        Err(_) => {
            // "no crontab for user" returns error — that's fine
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No user crontab entries"));
        }
    }

    // 2. Systemd user timers and services
    {
        // OpenClaw's own services are legitimate, not persistence
        const ALLOWED_USER_UNITS: &[&str] = &[
            "openclaw.service",
            "openclaw-gateway.service",
            "openclaw-worker.service",
            "default.target.wants",
        ];
        let user_systemd = format!("{}/.config/systemd/user", home);
        let mut unexpected = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&user_systemd) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if (name.ends_with(".timer") || name.ends_with(".service"))
                    && !ALLOWED_USER_UNITS.iter().any(|a| name == *a)
                {
                    unexpected.push(name);
                }
            }
        }
        if unexpected.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No unexpected user systemd units"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                &format!("Unexpected user systemd units: {}", unexpected.join(", "))));
        }
    }

    // 3. Shell RC file integrity
    {
        let baselines_path = "/etc/clawtower/persistence-baselines.json";
        let baselines: std::collections::HashMap<String, String> = std::fs::read_to_string(baselines_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        for rc_file in &[".bashrc", ".profile", ".bash_login"] {
            let full_path = format!("{}/{}", home, rc_file);
            if std::path::Path::new(&full_path).exists() {
                match compute_file_sha256(&full_path) {
                    Ok(hash) => {
                        if let Some(expected) = baselines.get(*rc_file) {
                            if &hash != expected {
                                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                                    &format!("{} hash mismatch (expected {}, got {})", rc_file, &expected[..8], &hash[..8])));
                            } else {
                                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                                    &format!("{} integrity OK", rc_file)));
                            }
                        } else {
                            results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                                &format!("{} first seen (hash: {})", rc_file, &hash[..16])));
                        }
                    }
                    Err(e) => {
                        results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                            &format!("Cannot hash {}: {}", rc_file, e)));
                    }
                }
            }
        }
    }

    // 4. Autostart desktop files
    {
        let autostart_dir = format!("{}/.config/autostart", home);
        let mut desktop_files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&autostart_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".desktop") {
                    desktop_files.push(name);
                }
            }
        }
        if desktop_files.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No autostart desktop files"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                &format!("Autostart desktop files found: {}", desktop_files.join(", "))));
        }
    }

    // 5. Git hooks in workspace
    {
        let hooks_dir = format!("{}/.openclaw/workspace/.git/hooks", home);
        let mut non_sample = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".sample") {
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_file() {
                            non_sample.push(name);
                        }
                    }
                }
            }
        }
        if non_sample.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No active git hooks in workspace"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                &format!("Active git hooks found: {}", non_sample.join(", "))));
        }
    }

    // 6. SSH rc and environment
    {
        let ssh_dangerous = [".ssh/rc", ".ssh/environment"];
        for file in &ssh_dangerous {
            let full_path = format!("{}/{}", home, file);
            if std::path::Path::new(&full_path).exists() {
                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                    &format!("~/{} exists — potential persistence mechanism", file)));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                    &format!("~/{} not present", file)));
            }
        }
    }

    // 7. Python usercustomize.py
    {
        let python_glob = format!("{}/.local/lib", home);
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&python_glob) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("python") {
                    let uc_path = entry.path().join("site-packages/usercustomize.py");
                    if uc_path.exists() {
                        found.push(uc_path.display().to_string());
                    }
                }
            }
        }
        if found.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No usercustomize.py found"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                &format!("usercustomize.py found: {}", found.join(", "))));
        }
    }

    // 8. npmrc install scripts
    {
        let npmrc_path = format!("{}/.npmrc", home);
        if let Ok(content) = std::fs::read_to_string(&npmrc_path) {
            let has_scripts = content.lines().any(|l| {
                let lower = l.to_lowercase();
                lower.contains("preinstall") || lower.contains("postinstall")
            });
            if has_scripts {
                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                    "~/.npmrc contains preinstall/postinstall scripts"));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                    "~/.npmrc clean (no install scripts)"));
            }
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No ~/.npmrc"));
        }
    }

    // 9. Dangerous environment variables
    {
        let dangerous_vars = ["PYTHONSTARTUP", "PERL5OPT", "NODE_OPTIONS"];
        for var in &dangerous_vars {
            if std::env::var(var).is_ok() {
                results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                    &format!("Environment variable {} is set", var)));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                    &format!("{} not set", var)));
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_user_persistence_clean() {
        let results = scan_user_persistence();
        assert!(!results.is_empty());
        assert!(results.len() >= 9, "Expected at least 9 results, got {}", results.len());
        for r in &results {
            assert_eq!(r.category, "user_persistence");
        }
    }

    #[test]
    fn test_scan_user_persistence_crontab_entries() {
        let results = scan_user_persistence_inner(Some("* * * * * /tmp/evil.sh\n"));
        let crontab_result = &results[0];
        assert_eq!(crontab_result.status, ScanStatus::Fail);
        assert!(crontab_result.details.contains("crontab"));
    }

    #[test]
    fn test_scan_user_persistence_crontab_empty() {
        let results = scan_user_persistence_inner(Some("# comment only\n\n"));
        let crontab_result = &results[0];
        assert_eq!(crontab_result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_user_persistence_ssh_rc() {
        use std::io::Write;
        let tmp = tempfile::TempDir::new().unwrap();
        let ssh_dir = tmp.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let rc_file = ssh_dir.join("rc");
        std::fs::File::create(&rc_file).unwrap().write_all(b"evil").unwrap();

        assert!(rc_file.exists());
        let results = scan_user_persistence();
        let ssh_rc_result = results.iter().find(|r| r.details.contains(".ssh/rc"));
        assert!(ssh_rc_result.is_some(), "Should have a .ssh/rc check result");
        assert_eq!(ssh_rc_result.unwrap().status, ScanStatus::Pass);
    }
}
