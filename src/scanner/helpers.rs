// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Shared helper functions used across scanner submodules.
//!
//! Extracts common patterns like reading file lines, finalizing scan results
//! from issue lists, and command execution utilities.

use std::process::Command;

use super::{ScanResult, ScanStatus};

/// Default timeout for command execution (30 seconds).
pub const DEFAULT_CMD_TIMEOUT: u64 = 30;

/// Run a command with a timeout, killing it if it exceeds `timeout_secs`.
pub fn run_cmd_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String, String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn {}: {}", cmd, e))?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Read stdout directly from the pipe before wait_with_output
                // (wait_with_output after try_wait can lose buffered data)
                let mut stdout_str = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    use std::io::Read;
                    let _ = stdout.read_to_string(&mut stdout_str);
                }
                let _ = child.wait(); // reap the process
                return Ok(stdout_str);
            }
            Ok(None) => {
                if start.elapsed().as_secs() > timeout_secs {
                    let _ = child.kill();
                    return Err(format!("{} timed out after {}s", cmd, timeout_secs));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(format!("Error waiting for {}: {}", cmd, e)),
        }
    }
}

/// Run a command with the default timeout (30s).
pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    run_cmd_timeout(cmd, args, DEFAULT_CMD_TIMEOUT)
}

/// Run a command, falling back to `sudo` if the initial invocation fails.
pub fn run_cmd_with_sudo(cmd: &str, args: &[&str]) -> Result<String, String> {
    // Try without sudo first
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    // Skip sudo fallback if already root (NoNewPrivileges=yes blocks sudo)
    if unsafe { libc::getuid() } == 0 {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    // Try with sudo
    let mut sudo_args = vec![cmd];
    sudo_args.extend_from_slice(args);
    let output = Command::new("sudo")
        .args(&sudo_args)
        .output()
        .map_err(|e| format!("Failed to run sudo {}: {}", cmd, e))?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check if a command is available on the system PATH.
pub fn command_available(cmd: &str) -> bool {
    match run_cmd("which", &[cmd]) {
        Ok(output) => !output.trim().is_empty(),
        Err(_) => false,
    }
}

/// Detect the AI agent username from environment variables or default to "openclaw".
pub fn detect_agent_username() -> String {
    std::env::var("CLAWTOWER_AGENT_USER")
        .or_else(|_| std::env::var("OPENCLAW_USER"))
        .unwrap_or_else(|_| "openclaw".to_string())
}

/// Look up a user's home directory from /etc/passwd.
pub fn user_home_from_passwd(username: &str) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[0] == username {
            return Some(fields[5].to_string());
        }
    }
    None
}

/// Detect the AI agent's home directory.
pub fn detect_agent_home() -> String {
    let username = detect_agent_username();
    user_home_from_passwd(&username)
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| format!("/home/{}", username))
}

/// Detect the primary system package manager.
pub fn detect_primary_package_manager() -> Option<&'static str> {
    if command_available("apt") {
        Some("apt")
    } else if command_available("dnf") {
        Some("dnf")
    } else if command_available("yum") {
        Some("yum")
    } else if command_available("zypper") {
        Some("zypper")
    } else if command_available("pacman") {
        Some("pacman")
    } else {
        None
    }
}

/// Compute SHA-256 hash of a file, returning the hex-encoded digest.
pub fn compute_file_sha256(path: &str) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    let data = std::fs::read(path).map_err(|e| format!("cannot read: {}", e))?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Read a file and return its lines as a Vec<String>, or an empty vec on failure.
pub fn read_lines_from_file(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|content| content.lines().map(String::from).collect())
        .unwrap_or_default()
}

/// Finalize a scan result from a list of issues.
///
/// - If `issues` is empty, returns `Pass` with "No issues found".
/// - If `issues.len() > warn_threshold`, returns `Fail`.
/// - Otherwise returns `Warn` with the issues joined.
pub fn finalize_scan(category: &str, issues: &[String], warn_threshold: usize) -> ScanResult {
    if issues.is_empty() {
        ScanResult::new(category, ScanStatus::Pass, &format!("No {} issues found", category))
    } else if issues.len() > warn_threshold {
        ScanResult::new(
            category,
            ScanStatus::Fail,
            &format!("{} issues detected: {}", issues.len(), issues.join("; ")),
        )
    } else {
        ScanResult::new(
            category,
            ScanStatus::Warn,
            &format!("{} issue(s): {}", issues.len(), issues.join("; ")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_lines_from_file_nonexistent() {
        let lines = read_lines_from_file("/nonexistent/file/abc123");
        assert!(lines.is_empty());
    }

    #[test]
    fn test_read_lines_from_file_real() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "line1\nline2\nline3").unwrap();
        let lines = read_lines_from_file(path.to_str().unwrap());
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[2], "line3");
    }

    #[test]
    fn test_finalize_scan_no_issues() {
        let result = finalize_scan("test_cat", &[], 5);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_finalize_scan_few_issues() {
        let issues = vec!["issue1".to_string(), "issue2".to_string()];
        let result = finalize_scan("test_cat", &issues, 5);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("issue1"));
    }

    #[test]
    fn test_finalize_scan_many_issues() {
        let issues: Vec<String> = (0..10).map(|i| format!("issue{}", i)).collect();
        let result = finalize_scan("test_cat", &issues, 5);
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_compute_sha256_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world").unwrap();
        let hash = compute_file_sha256(path.to_str().unwrap()).unwrap();
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_compute_sha256_file_not_found() {
        let result = compute_file_sha256("/nonexistent/file/abc123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn test_compute_sha256_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();
        let hash = compute_file_sha256(path.to_str().unwrap()).unwrap();
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_compute_sha256_modified_file_differs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.txt");
        std::fs::write(&path, "original").unwrap();
        let hash1 = compute_file_sha256(path.to_str().unwrap()).unwrap();
        std::fs::write(&path, "modified").unwrap();
        let hash2 = compute_file_sha256(path.to_str().unwrap()).unwrap();
        assert_ne!(hash1, hash2);
    }
}
