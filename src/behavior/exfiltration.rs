// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Data exfiltration detection helpers.
//!
//! Hostname extraction from command arguments, safe-host matching
//! for network exfiltration tool analysis, DNS tunneling detection,
//! scripted exfiltration, and data staging patterns.

use crate::alerts::Severity;
use crate::safe_match;
use super::BehaviorCategory;
use super::patterns::{
    EXFIL_COMMANDS, REMOTE_TRANSFER_COMMANDS, DNS_EXFIL_COMMANDS,
    NETWORK_CAPABLE_RUNTIMES, SCRIPTED_EXFIL_PATTERNS,
    CRITICAL_READ_PATHS, AGENT_SENSITIVE_PATHS,
    TUNNEL_CREATION_PATTERNS,
    ENCODING_TOOLS, LARGE_FILE_EXFIL_PATTERNS,
    AWS_CREDENTIAL_PATTERNS, GIT_CREDENTIAL_PATTERNS,
    MEMORY_DUMP_PATTERNS,
};

/// Safe hosts that should not trigger exfiltration alerts for network tools.
pub(crate) const SAFE_HOSTS: &[&str] = &[
    "gottamolt.gg", "mahamedia.us", "localhost", "127.0.0.1",
    "api.anthropic.com", "api.openai.com", "github.com",
    "hooks.slack.com", "registry.npmjs.org",
    "crates.io", "pypi.org", "api.brave.com", "wttr.in",
    "ssm.us-east-1.amazonaws.com",
    "s3.us-east-1.amazonaws.com",
    "ec2.us-east-1.amazonaws.com",
    "sts.amazonaws.com",
    "elasticache.us-east-1.amazonaws.com",
    "rds.us-east-1.amazonaws.com",
    "route53.amazonaws.com",
    "acm.us-east-1.amazonaws.com",
    "cloudfront.amazonaws.com",
];

/// Extract hostnames from a list of command arguments.
///
/// Scans each argument for URL-like patterns (`https://host/...`, `http://host/...`)
/// and bare `host:port` patterns, returning the hostname portions. This is used to
/// check exfiltration tool targets against the safe-hosts list without substring
/// matching the entire command line.
pub(crate) fn extract_hostnames_from_args(args: &[String]) -> Vec<String> {
    let mut hostnames = Vec::new();
    for arg in args {
        // Match URLs: scheme://host[:port][/path...]
        if let Some(rest) = arg.strip_prefix("https://").or_else(|| arg.strip_prefix("http://")) {
            // Host ends at '/', ':', '?', '#', or end-of-string
            let host = rest.split(&['/', ':', '?', '#'][..]).next().unwrap_or("");
            if !host.is_empty() {
                hostnames.push(host.to_lowercase());
            }
        }
        // Also check for bare host:port (e.g., "evil.com:8080")
        else if let Some(colon_pos) = arg.rfind(':') {
            let maybe_host = &arg[..colon_pos];
            let after_colon = &arg[colon_pos + 1..];
            // Only treat as host:port if the part after colon is numeric
            if !maybe_host.is_empty()
                && !maybe_host.contains('/')
                && after_colon.chars().all(|c| c.is_ascii_digit())
            {
                hostnames.push(maybe_host.to_lowercase());
            }
        }
    }
    hostnames
}

/// Check for network exfiltration tools (curl, wget, nc, ncat, netcat, socat, rsync).
///
/// These are unconditionally suspicious unless the target host is in the safe list.
pub(crate) fn check_network_exfil(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
        let hostnames = extract_hostnames_from_args(args);
        let is_safe = hostnames.iter().any(|h| safe_match::is_safe_host(h, SAFE_HOSTS));
        if !is_safe {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }
    None
}

/// Check for remote file transfer tools with remote targets (scp, sftp, ssh with '@').
pub(crate) fn check_remote_transfer(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if REMOTE_TRANSFER_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
        let has_remote = args.iter().skip(1).any(|a| a.contains('@'));
        if has_remote {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }
    None
}

/// Check for DNS exfiltration (dig, nslookup, host, drill, resolvectl).
///
/// Detects TXT record queries, suspiciously long/numerous subdomain labels,
/// and subshell injection in DNS query arguments. Normal DNS lookups are
/// classified as Reconnaissance/Info.
pub(crate) fn check_dns_exfil(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if DNS_EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
        let has_txt = args.iter().skip(1).any(|arg| arg == "TXT" || arg == "txt");
        if has_txt {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
        let suspicious = args.iter().skip(1).any(|arg| {
            let dot_count = arg.matches('.').count();
            let has_long_labels = arg.split('.').any(|label| label.len() > 25);
            let has_subshell = arg.contains('$') || arg.contains('`');
            (dot_count > 4 && has_long_labels) || has_subshell || dot_count > 6
        });
        if suspicious {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
        return Some((BehaviorCategory::Reconnaissance, Severity::Info));
    }
    None
}

/// Check for scripted DNS exfiltration via interpreters (python, node, ruby, perl).
pub(crate) fn check_scripted_dns_exfil(binary: &str, cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    if ["python", "python3", "node", "ruby", "perl"].contains(&binary) {
        let cmd_lower = cmd.to_lowercase();
        if cmd_lower.contains("getaddrinfo") || cmd_lower.contains("dns.resolve") ||
           cmd_lower.contains("socket.gethostbyname") || cmd_lower.contains("resolver") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }
    None
}

/// Check for interpreter credential file access and scripted exfiltration.
///
/// Detects network-capable runtimes (python, node, perl, ruby, php, lua)
/// accessing credential files or using known exfil patterns (http.server,
/// socket.connect, etc.). Also flags inline code execution (-c, -e, --eval).
pub(crate) fn check_interpreter_exfil(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if NETWORK_CAPABLE_RUNTIMES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
        let full_cmd = args.join(" ");
        let all_cred_paths: Vec<&str> = CRITICAL_READ_PATHS.iter()
            .chain(AGENT_SENSITIVE_PATHS.iter())
            .copied()
            .collect();
        for cred_path in &all_cred_paths {
            if full_cmd.contains(cred_path) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
        }

        for pattern in SCRIPTED_EXFIL_PATTERNS {
            if full_cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
        }
        if args.iter().any(|a| a == "-c" || a == "-e" || a == "--eval") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }
    }
    None
}

/// Check for ICMP data exfiltration via ping -p (payload pattern).
pub(crate) fn check_icmp_exfil(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if binary == "ping" && args.iter().any(|a| a == "-p") {
        return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
    }
    None
}

/// Check for git push or git remote add (data exfiltration vectors).
pub(crate) fn check_git_exfil(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if binary == "git" {
        let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
        if sub == "push" {
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }
        if sub == "remote" && args.iter().any(|a| a == "add") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }
    }
    None
}

/// Check for network tunnel creation (ssh -R/-L/-D, chisel, ngrok, socat, etc.).
pub(crate) fn check_tunnel_creation(binary: &str, cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    for pattern in TUNNEL_CREATION_PATTERNS {
        if binary.contains(pattern) || cmd.contains(pattern) {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }
    None
}

/// Check for encoding/obfuscation tools piped to network tools.
pub(crate) fn check_encoding_exfil(binary: &str, cmd: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    for pattern in ENCODING_TOOLS {
        if binary == *pattern && args.len() > 1 {
            if cmd.contains("| curl") || cmd.contains("| wget") || cmd.contains("| nc") ||
               (args.iter().any(|a| a.contains("/proc/")) && cmd.contains("|")) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
            }
        }
    }
    None
}

/// Check for large file exfiltration (tar, zip, 7z, gzip, bzip2 on sensitive dirs).
pub(crate) fn check_large_file_exfil(cmd: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    for pattern in LARGE_FILE_EXFIL_PATTERNS {
        if cmd.contains(pattern) {
            if args.iter().any(|a| a.contains("/etc") || a.contains("/var") || a.contains("/home")) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
            }
        }
    }
    None
}

/// Check for AWS credential theft patterns.
pub(crate) fn check_aws_credential_theft(cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    for pattern in AWS_CREDENTIAL_PATTERNS {
        if cmd.contains(pattern) {
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }
    }
    None
}

/// Check for Git credential exposure patterns.
pub(crate) fn check_git_credential_exposure(cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    for pattern in GIT_CREDENTIAL_PATTERNS {
        if cmd.contains(pattern) {
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }
    }
    None
}

/// Check for memory dump tools (gdb attach, volatility, memdump, etc.).
pub(crate) fn check_memory_dumps(cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    for pattern in MEMORY_DUMP_PATTERNS {
        if cmd.contains(pattern) {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }
    None
}

/// Check for bare base64 invocation (encoding for exfil).
pub(crate) fn check_base64_encoding(binary: &str) -> Option<(BehaviorCategory, Severity)> {
    if binary == "base64" {
        return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
    }
    None
}

/// Check for memory/environ dumping tools (strings, xxd, od on /proc/*/environ|mem|maps).
pub(crate) fn check_memory_environ_dump(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if ["strings", "xxd", "od"].contains(&binary) {
        for arg in args.iter().skip(1) {
            if arg.contains("/proc/") && (arg.contains("/environ") || arg.contains("/mem") || arg.contains("/maps")) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
        }
    }
    None
}
