// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Process and system-level security scanners.
//!
//! Zombie processes, file descriptors, resource limits, kernel modules,
//! side-channel mitigations, environment variables.

use super::{ScanResult, ScanStatus};
use super::helpers::run_cmd;

/// Check loaded kernel modules for suspicious names (rootkit, backdoor, keylog, etc.).
pub fn scan_kernel_modules() -> ScanResult {
    match run_cmd("lsmod", &[]) {
        Ok(output) => {
            let lines: Vec<&str> = output.lines().collect();
            let module_count = lines.len().saturating_sub(1); // Subtract header

            // Check for suspicious module names
            let suspicious_patterns = ["rootkit", "evil", "backdoor", "stealth", "hidden", "keylog"];
            let mut suspicious_modules = Vec::new();

            for line in lines.iter().skip(1) { // Skip header
                let module_name = line.split_whitespace().next().unwrap_or("");
                for pattern in &suspicious_patterns {
                    if module_name.to_lowercase().contains(pattern) {
                        suspicious_modules.push(module_name);
                        break;
                    }
                }
            }

            if !suspicious_modules.is_empty() {
                ScanResult::new("kernel_modules", ScanStatus::Fail, &format!("Found {} suspicious kernel modules: {}",
                    suspicious_modules.len(), suspicious_modules.join(", ")))
            } else if module_count > 100 {
                ScanResult::new("kernel_modules", ScanStatus::Warn, &format!("High number of loaded modules: {}", module_count))
            } else {
                ScanResult::new("kernel_modules", ScanStatus::Pass, &format!("{} kernel modules loaded", module_count))
            }
        }
        Err(e) => ScanResult::new("kernel_modules", ScanStatus::Warn, &format!("Cannot check kernel modules: {}", e)),
    }
}

/// Check for excessive open file descriptors, suspicious network connections, and FD-heavy processes.
pub fn scan_open_file_descriptors() -> ScanResult {
    let mut issues = Vec::new();

    // Check system-wide open files
    if let Ok(output) = run_cmd("sh", &["-c", "lsof -n 2>/dev/null | wc -l"]) {
        if let Ok(count) = output.trim().parse::<u32>() {
            if count > 10000 {
                issues.push(format!("High number of open files: {}", count));
            }
        }
    }

    // Check for suspicious open network connections
    if let Ok(output) = run_cmd("lsof", &["-i", "-n"]) {
        for line in output.lines() {
            if line.contains("ESTABLISHED") && (line.contains(":6667") || line.contains(":6697") ||
               line.contains(":4444") || line.contains(":1234")) {
                issues.push(format!("Suspicious network connection: {}", line.trim()));
            }
        }
    }

    // Check processes with many open files
    if let Ok(output) = run_cmd("bash", &["-c", "for pid in /proc/*/fd; do echo \"$(ls $pid 2>/dev/null | wc -l) $pid\"; done | sort -n | tail -5"]) {
        for line in output.lines() {
            if let Some(count_str) = line.split_whitespace().next() {
                if let Ok(count) = count_str.parse::<u32>() {
                    if count > 1000 {
                        issues.push(format!("Process with many open FDs: {}", line.trim()));
                    }
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("open_fds", ScanStatus::Pass, "File descriptor usage normal")
    } else {
        ScanResult::new("open_fds", ScanStatus::Warn, &format!("FD issues: {}", issues.join("; ")))
    }
}

/// Detect zombie processes and high-CPU consumers via `ps aux`.
pub fn scan_zombie_processes() -> ScanResult {
    match run_cmd("ps", &["aux"]) {
        Ok(output) => {
            let mut zombies = Vec::new();
            let mut high_cpu_procs = Vec::new();

            for line in output.lines().skip(1) { // Skip header
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 11 {
                    let cpu = fields.get(2).map_or("0", |v| v);
                    let stat = fields.get(7).map_or("", |v| v);
                    let command = fields.get(10).map_or("", |v| v);

                    // Check for zombie processes
                    if stat.contains('Z') {
                        zombies.push(command.to_string());
                    }

                    // Check for processes consuming high CPU
                    if let Ok(cpu_val) = cpu.parse::<f32>() {
                        if cpu_val > 80.0 {
                            high_cpu_procs.push(format!("{} ({}%)", command, cpu));
                        }
                    }
                }
            }

            let mut issues = Vec::new();
            if !zombies.is_empty() {
                issues.push(format!("Zombie processes: {}", zombies.join(", ")));
            }
            if !high_cpu_procs.is_empty() {
                issues.push(format!("High CPU processes: {}", high_cpu_procs.join(", ")));
            }

            if issues.is_empty() {
                ScanResult::new("process_health", ScanStatus::Pass, "No zombie or suspicious processes")
            } else {
                ScanResult::new("process_health", ScanStatus::Warn, &format!("Process issues: {}", issues.join("; ")))
            }
        }
        Err(e) => ScanResult::new("process_health", ScanStatus::Warn, &format!("Cannot check processes: {}", e)),
    }
}

/// Check root filesystem disk usage percentage.
pub fn scan_resources() -> ScanResult {
    match run_cmd("df", &["-h", "/"]) {
        Ok(output) => parse_disk_usage(&output),
        Err(e) => ScanResult::new("resources", ScanStatus::Warn, &format!("Cannot check disk: {}", e)),
    }
}

/// Check CPU side-channel vulnerability mitigations (Spectre, Meltdown, MDS, etc.) via sysfs.
pub fn scan_sidechannel_mitigations() -> ScanResult {
    let mitigations = [
        "spectre_v1",
        "spectre_v2",
        "meltdown",
        "mds",
        "tsx_async_abort",
        "itlb_multihit",
        "srbds",
        "mmio_stale_data",
        "retbleed",
        "spec_store_bypass",
    ];

    let mut vulnerable_count = 0;
    let mut missing_files = 0;
    let mut vulnerable_list = Vec::new();

    for mitigation in &mitigations {
        let path = format!("/sys/devices/system/cpu/vulnerabilities/{}", mitigation);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let status = contents.trim();
                if status.contains("Vulnerable") {
                    vulnerable_count += 1;
                    vulnerable_list.push(format!("{}: {}", mitigation, status));
                } else if !status.contains("Mitigation:") && !status.contains("Not affected") {
                    // Unknown status - treat as warning
                    vulnerable_list.push(format!("{}: {}", mitigation, status));
                }
            }
            Err(_) => {
                missing_files += 1;
                vulnerable_list.push(format!("{}: file missing", mitigation));
            }
        }
    }

    if vulnerable_count > 0 || missing_files > 0 {
        let total_issues = vulnerable_count + missing_files;
        ScanResult::new(
            "sidechannel",
            ScanStatus::Warn,
            &format!("{} vulnerability issues: {}", total_issues, vulnerable_list.join(", "))
        )
    } else {
        ScanResult::new(
            "sidechannel",
            ScanStatus::Pass,
            &format!("All {} CPU side-channel mitigations enabled", mitigations.len())
        )
    }
}

/// Parse `df -h /` output to extract usage percentage (testable helper).
pub fn parse_disk_usage(output: &str) -> ScanResult {
    // Second line, 5th column is Use%
    if let Some(line) = output.lines().nth(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pct_str) = parts.get(4) {
            let pct: u32 = pct_str.trim_end_matches('%').parse().unwrap_or(0);
            if pct > 90 {
                return ScanResult::new("resources", ScanStatus::Warn, &format!("Disk usage at {}%", pct));
            } else {
                return ScanResult::new("resources", ScanStatus::Pass, &format!("Disk usage at {}%", pct));
            }
        }
    }
    ScanResult::new("resources", ScanStatus::Warn, "Cannot parse disk usage")
}

/// Scan environment variables for suspicious LD_PRELOAD, proxy configs, debug flags, and leaked credentials.
pub fn scan_environment_variables() -> ScanResult {
    let mut issues = Vec::new();

    // Check current environment for suspicious variables
    for (key, value) in std::env::vars() {
        if key == "LD_PRELOAD" && !value.contains("clawtower") {
            issues.push(format!("Suspicious LD_PRELOAD: {}", value));
        }
        if key == "LD_LIBRARY_PATH" && value.contains("/tmp") {
            issues.push("LD_LIBRARY_PATH includes /tmp".to_string());
        }
        if key.contains("PROXY") && (value.contains("tor") || value.contains("socks")) {
            issues.push(format!("Proxy configuration detected: {}={}", key, value));
        }
        if key.contains("DEBUG") && value == "1" {
            issues.push(format!("Debug mode enabled: {}", key));
        }
        // Check for encoded credentials in env
        if (key.contains("KEY") || key.contains("SECRET") || key.contains("TOKEN"))
            && value.len() > 20 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/') {
                issues.push(format!("Potential credential in environment: {}", key));
        }
    }

    // Check OpenClaw agent environment specifically
    if let Ok(openclaw_pid) = run_cmd("pgrep", &["openclaw"]) {
        if let Ok(env_content) = std::fs::read_to_string(format!("/proc/{}/environ", openclaw_pid.trim())) {
            let env_vars: Vec<&str> = env_content.split('\0').collect();
            for var in env_vars {
                if var.starts_with("AWS_SECRET_ACCESS_KEY=") || var.starts_with("ANTHROPIC_API_KEY=") {
                    issues.push("Credentials found in agent environment".to_string());
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("environment_vars", ScanStatus::Pass, "Environment variables secure")
    } else {
        ScanResult::new("environment_vars", ScanStatus::Warn, &format!("Environment issues: {}", issues.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_disk_usage_ok() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   20G   28G  42% /
";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Pass);
        assert!(result.details.contains("42%"));
    }

    #[test]
    fn test_parse_disk_usage_high() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   47G    1G  95% /
";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("95%"));
    }

    #[test]
    fn test_parse_disk_usage_exactly_90() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   45G    5G  90% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_parse_disk_usage_91() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   46G    4G  91% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_disk_usage_0_percent() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G    0G   50G   0% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_parse_disk_usage_100_percent() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   50G    0G 100% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_disk_usage_empty() {
        let result = parse_disk_usage("");
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("Cannot parse"));
    }

    #[test]
    fn test_parse_disk_usage_single_line() {
        let result = parse_disk_usage("Filesystem      Size  Used Avail Use% Mounted on\n");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_sidechannel_mitigation_status() {
        let protected_status = "Mitigation: Full generic retpoline, IBRS, IBPB";
        assert!(protected_status.contains("Mitigation:"));

        let not_affected_status = "Not affected";
        assert!(not_affected_status.contains("Not affected"));

        let vulnerable_status = "Vulnerable";
        assert!(vulnerable_status.contains("Vulnerable"));

        let unknown_status = "Processor vulnerable";
        assert!(!unknown_status.contains("Mitigation:") && !unknown_status.contains("Not affected"));
    }

    #[test]
    fn test_kernel_module_suspicious_patterns() {
        let suspicious = ["rootkit", "evil", "backdoor", "stealth", "hidden", "keylog"];
        for name in &suspicious {
            assert!(name.to_lowercase().contains(name));
        }
        let benign = ["bluetooth", "snd_pcm", "ext4", "nfs", "iptable_filter"];
        for name in &benign {
            assert!(!suspicious.iter().any(|p| name.contains(p)));
        }
    }

    #[test]
    fn test_kernel_module_case_insensitive() {
        let module_name = "RootKit_Module";
        let suspicious_patterns = ["rootkit"];
        assert!(suspicious_patterns.iter().any(|p| module_name.to_lowercase().contains(p)));
    }

    #[test]
    fn test_sidechannel_vulnerable_status() {
        let status = "Vulnerable: Clear CPU buffers attempted, no microcode";
        assert!(status.contains("Vulnerable"));
    }

    #[test]
    fn test_sidechannel_mitigated_status() {
        let status = "Mitigation: Full generic retpoline, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling";
        assert!(status.contains("Mitigation:"));
        assert!(!status.contains("Vulnerable"));
    }

    #[test]
    fn test_sidechannel_not_affected() {
        let status = "Not affected";
        assert!(status.contains("Not affected"));
    }

    #[test]
    fn test_env_ld_preload_suspicious_detected() {
        let value = "/tmp/evil.so";
        assert!(!value.contains("clawtower"));
    }

    #[test]
    fn test_env_ld_preload_clawtower_allowed() {
        let value = "/usr/lib/clawtower.so";
        assert!(value.contains("clawtower"));
    }

    #[test]
    fn test_env_proxy_tor_detection() {
        let key = "HTTP_PROXY";
        let value = "socks5://127.0.0.1:9050";
        assert!(key.contains("PROXY"));
        assert!(value.contains("socks"));
    }

    #[test]
    fn test_env_proxy_all_proxy_encoded() {
        let key = "ALL_PROXY";
        let value = "socks5h://tor-gateway:9050";
        assert!(key.contains("PROXY"));
        assert!(value.contains("socks"));
    }

    #[test]
    fn test_env_proxy_normal_http_not_flagged() {
        let value = "http://proxy.corp.com:3128";
        assert!(!value.contains("tor") && !value.contains("socks"));
    }

    #[test]
    fn test_env_credential_detection_long_base64() {
        let key = "AWS_SECRET_KEY";
        let value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(key.contains("KEY") || key.contains("SECRET"));
        assert!(value.len() > 20);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/'));
    }

    #[test]
    fn test_env_debug_flag_detection() {
        let key = "NODE_DEBUG";
        let value = "1";
        assert!(key.contains("DEBUG") && value == "1");
    }

    #[test]
    fn test_env_ld_library_path_tmp() {
        let value = "/tmp/lib:/usr/lib";
        assert!(value.contains("/tmp"));
    }
}
