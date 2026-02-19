// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! CLI subcommand dispatch and helper functions.
//!
//! All non-watchdog subcommands (install, scan, harden, etc.) are handled here.
//! The main module calls [`dispatch_subcommand`] first; if it returns `true`,
//! the process exits without entering the watchdog runtime.

use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn print_help() {
    eprintln!(r#"🛡️  ClawTower — Tamper-proof security watchdog for AI agents

USAGE:
    clawtower [COMMAND] [OPTIONS]

COMMANDS:
    run                  Start the watchdog with TUI dashboard (default)
    run --headless       Start in headless mode (no TUI, log to stderr)
    install [--force]    Bootstrap /etc/clawtower with default config + directories
    status               Show service status and recent alerts
    configure            Interactive configuration wizard
    update               Self-update to latest GitHub release
    scan                 Run a one-shot security scan and exit
    compliance-report    Generate a compliance report (SOC2/NIST/CIS)
    verify-key           Verify admin key from stdin (or --key flag)
    verify-audit [PATH]  Verify audit chain integrity
    setup                Install ClawTower as a system service
    setup --source       Build from source + install
    setup --auto         Install + start service automatically
    harden               Apply tamper-proof "swallowed key" hardening
    generate-key         Generate admin key (called by harden, idempotent)
    setup-apparmor       Install AppArmor profiles (or pam_cap fallback)
    uninstall            Reverse hardening + remove ClawTower (requires admin key)
    profile list         List available deployment profiles
    update-ioc           Update IOC bundles with signature verification
    sync                 Update Barnacle pattern databases
    logs                 Tail the service logs (journalctl)
    help                 Show this help message
    version              Show version info

EXAMPLES:
    clawtower                           Start TUI dashboard
    clawtower run --headless            Run as background daemon
    clawtower run --profile=production  Run with production profile
    clawtower configure                 Set up Slack, watched users, etc.
    clawtower scan                      Quick security scan
    sudo clawtower update               Self-update to latest release
    clawtower update --check            Check for updates without installing
    clawtower setup --source --auto     Full unattended install from source
    clawtower status                    Check if service is running

CONFIG:
    Default config path: /etc/clawtower/config.toml
    Override with:       clawtower run /path/to/config.toml
"#);
}

pub fn print_version() {
    eprintln!("ClawTower v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Tamper-proof security watchdog for AI agents");
    eprintln!("https://github.com/ClawTower/ClawTower");
}

/// Find the scripts directory relative to the binary or fallback locations.
pub fn find_scripts_dir() -> Option<PathBuf> {
    // Check relative to binary location
    if let Ok(exe) = std::env::current_exe() {
        // Binary at /usr/local/bin/clawtower → scripts at source dir
        // Binary at target/release/clawtower → scripts at ../../scripts
        let parent = exe.parent()?;
        let candidate = parent.join("../../scripts");
        if candidate.join("configure.sh").exists() {
            return candidate.canonicalize().ok();
        }
    }
    // Check common locations
    let candidates = [
        PathBuf::from("/home/openclaw/.openclaw/workspace/projects/ClawTower/scripts"),
        PathBuf::from("/home/openclaw/.openclaw/workspace/openclawtower/scripts"),
        PathBuf::from("./scripts"),
        PathBuf::from("/opt/clawtower/scripts"),
    ];
    for c in &candidates {
        if c.join("configure.sh").exists() || c.join("uninstall.sh").exists() {
            return Some(c.clone());
        }
    }
    None
}

fn download_script(name: &str) -> Result<PathBuf> {
    let version = env!("CARGO_PKG_VERSION");
    let tag = format!("v{}", version);
    let url = format!(
        "https://raw.githubusercontent.com/ClawTower/ClawTower/{}/scripts/{}",
        tag, name
    );
    eprintln!("Downloading {} from GitHub ({})...", name, tag);
    let output = std::process::Command::new("curl")
        .args(["-sSL", "-f", "-o", &format!("/tmp/clawtower-{}", name), &url])
        .status()?;
    if !output.success() {
        // Fall back to main branch
        let url_main = format!(
            "https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/{}",
            name
        );
        let output2 = std::process::Command::new("curl")
            .args(["-sSL", "-f", "-o", &format!("/tmp/clawtower-{}", name), &url_main])
            .status()?;
        if !output2.success() {
            anyhow::bail!("Failed to download script '{}' from GitHub", name);
        }
    }
    let path = PathBuf::from(format!("/tmp/clawtower-{}", name));
    Ok(path)
}

fn run_script(name: &str, extra_args: &[String]) -> Result<()> {
    let script = if let Some(scripts_dir) = find_scripts_dir() {
        let s = scripts_dir.join(name);
        if s.exists() { s } else { download_script(name)? }
    } else {
        download_script(name)?
    };
    if !script.exists() {
        anyhow::bail!("Script not found: {}", script.display());
    }
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(&script);
    for arg in extra_args {
        cmd.arg(arg);
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("{} exited with code {}", name, status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Strip the immutable flag (chattr +i) from a file or directory.
/// Three-level fallback:
///   1. Direct ioctl (bypasses AppArmor on /usr/bin/chattr)
///   2. External chattr command (works when AppArmor profiles aren't loaded)
///   3. systemd-run chattr (runs in PID 1's scope, bypasses dropped bounding set)
pub fn strip_immutable_flag(path: &str) {
    use std::os::unix::io::AsRawFd;

    if !Path::new(path).exists() {
        return;
    }

    // Try direct ioctl first
    if let Ok(file) = std::fs::File::open(path) {
        let fd = file.as_raw_fd();
        let mut flags: libc::c_long = 0;
        let ret = unsafe { libc::ioctl(fd, 0x80086601_u64, &mut flags as *mut libc::c_long) };
        if ret == 0 && (flags & 0x10) != 0 {
            flags &= !0x10;
            let ret = unsafe { libc::ioctl(fd, 0x40086602_u64, &flags as *const libc::c_long) };
            if ret == 0 {
                eprintln!("  chattr -i {} (ioctl)", path);
                return;
            }
        } else if ret == 0 {
            // File exists but doesn't have immutable flag — nothing to do
            return;
        }
        drop(file);
    }

    // Fallback: external chattr command
    if let Ok(o) = std::process::Command::new("chattr").args(["-i", path]).output() {
        if o.status.success() {
            eprintln!("  chattr -i {} (cmd)", path);
            return;
        }
    }

    // Final fallback: systemd-run runs in PID 1's scope, which has the full
    // capability bounding set (not affected by pam_cap session restrictions).
    if let Ok(o) = std::process::Command::new("systemd-run")
        .args(["--wait", "--collect", "--quiet", "chattr", "-i", path])
        .output()
    {
        if o.status.success() {
            eprintln!("  chattr -i {} (systemd-run)", path);
            return;
        }
        let stderr = String::from_utf8_lossy(&o.stderr);
        eprintln!("  chattr -i {}: all methods failed ({})", path, stderr.trim());
    }
}

/// Pre-harden cleanup: remove immutable flags and AppArmor profiles that
/// would otherwise block install.sh from modifying protected files.
fn pre_harden_cleanup() {
    eprintln!("[PRE-HARDEN] Stripping immutable flags...");

    // Capability check for diagnostics
    let cap_status = std::process::Command::new("cat")
        .arg("/proc/self/status")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    for line in cap_status.lines() {
        if line.starts_with("Cap") {
            eprintln!("  {}", line);
        }
    }

    // Directories first (must be writable before files inside can be created)
    let all_paths = [
        "/etc/clawtower",
        "/etc/clawtower/config.d",
        "/var/log/clawtower",
        "/usr/local/bin/clawtower",
        "/usr/local/bin/clawsudo",
        "/etc/clawtower/config.toml",
        "/etc/clawtower/admin.key.hash",
        "/etc/clawtower/preload-policy.json",
        "/etc/systemd/system/clawtower.service",
        "/etc/sudoers.d/010_openclaw",
        "/usr/local/lib/clawtower/libclawtower.so",
    ];
    for path in &all_paths {
        strip_immutable_flag(path);
    }
    // Unload AppArmor protection profiles (may fail if profiles can't parse — that's OK)
    let _ = std::process::Command::new("apparmor_parser")
        .args(["-R", "/etc/apparmor.d/etc.clawtower.protect"])
        .output();

    // Clean up stale pam_cap entry that drops CAP_LINUX_IMMUTABLE from all sessions.
    // Use systemd-run so sed can write even if the current session lacks capabilities.
    let pam_auth = "/etc/pam.d/common-auth";
    if let Ok(contents) = std::fs::read_to_string(pam_auth) {
        if contents.contains("pam_cap") {
            let cleaned: String = contents.lines()
                .filter(|line| !line.contains("pam_cap"))
                .collect::<Vec<_>>()
                .join("\n");
            if std::fs::write(pam_auth, format!("{}\n", cleaned)).is_ok() {
                eprintln!("[PRE-HARDEN] Removed stale pam_cap from {}", pam_auth);
            }
        }
    }
}

/// Bootstrap /etc/clawtower with default config and directory structure.
/// With --force, overwrites existing config and policies.
fn run_install(force: bool) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let conf_dir = Path::new("/etc/clawtower");
    let dirs = [
        conf_dir.to_path_buf(),
        conf_dir.join("policies"),
        conf_dir.join("barnacle"),
        conf_dir.join("sentinel-shadow"),
        conf_dir.join("quarantine"),
        PathBuf::from("/var/log/clawtower"),
        PathBuf::from("/var/run/clawtower"),
    ];

    eprintln!("🛡️  ClawTower Install{}", if force { " (--force)" } else { "" });
    eprintln!("====================\n");

    if force {
        // Remove immutable flags so we can overwrite
        let _ = std::process::Command::new("chattr")
            .args(["-i", "-R", conf_dir.to_str().unwrap_or_default()])
            .status();
    }

    // Create directories
    for dir in &dirs {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            eprintln!("  Created {}", dir.display());
        }
    }

    // Restrict sensitive dirs
    for dir_name in &["sentinel-shadow", "quarantine"] {
        let dir = conf_dir.join(dir_name);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }

    // Write default config (embedded at compile time from repo root)
    let config_path = conf_dir.join("config.toml");
    if force || !config_path.exists() {
        fs::write(&config_path, include_str!("../config.toml"))?;
        eprintln!("  Wrote default config to {}", config_path.display());
    } else {
        eprintln!("  Config already exists: {} (use --force to overwrite)", config_path.display());
    }

    // Write default policy
    let default_policy = conf_dir.join("policies/default.yaml");
    if force || !default_policy.exists() {
        // Check if we can find a default.yaml in the source tree
        if let Some(scripts_dir) = find_scripts_dir() {
            let source_policy = scripts_dir.parent()
                .map(|p| p.join("policies/default.yaml"));
            if let Some(ref sp) = source_policy {
                if sp.exists() {
                    fs::copy(sp, &default_policy)?;
                    eprintln!("  Copied default policy to {}", default_policy.display());
                }
            }
        }
    }

    eprintln!("\n✅ ClawTower installed. Next steps:");
    eprintln!("  1. Edit /etc/clawtower/config.toml (set watched_user, Slack webhook, etc.)");
    eprintln!("  2. Run: clawtower configure    (interactive wizard)");
    eprintln!("  3. Run: clawtower              (start the dashboard)");
    eprintln!("  4. Run: clawtower harden       (generates admin key + applies hardening)");

    Ok(())
}

/// Check privileges and re-exec via sudo BEFORE tokio starts.
/// This ensures the password prompt isn't clobbered by async tasks.
pub fn ensure_root() {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("run");

    // Skip for help/version which don't need privileges
    if unsafe { libc::getuid() } != 0
        && !matches!(subcommand, "help" | "--help" | "-h" | "version" | "--version" | "-V")
    {
        eprintln!("🛡️  ClawTower requires root privileges. Escalating via sudo...\n");
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("clawtower"));
        let status = std::process::Command::new("sudo")
            .arg("--")
            .arg(&exe)
            .args(&args[1..])
            .status();
        match status {
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("Failed to escalate privileges: {}", e);
                std::process::exit(1);
            }
        }
    }
}

/// Dispatch CLI subcommands. Returns `Ok(true)` if the subcommand was handled
/// (caller should exit), or `Ok(false)` to continue to watchdog startup.
pub async fn dispatch_subcommand(subcommand: &str, rest_args: &[String], all_args: &[String]) -> Result<bool> {
    match subcommand {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(true)
        }
        "version" | "--version" | "-V" => {
            print_version();
            Ok(true)
        }
        "verify-key" => {
            let key = if let Some(pos) = rest_args.iter().position(|a| a == "--key") {
                rest_args.get(pos + 1).cloned().unwrap_or_default()
            } else {
                let mut key = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut key)
                    .unwrap_or_default();
                key.trim().to_string()
            };
            if key.is_empty() {
                eprintln!("No key provided");
                std::process::exit(1);
            }
            let hash_path = std::path::Path::new("/etc/clawtower/admin.key.hash");
            let hash = match std::fs::read_to_string(hash_path) {
                Ok(h) => h.trim().to_string(),
                Err(e) => {
                    eprintln!("Cannot read {}: {}", hash_path.display(), e);
                    std::process::exit(1);
                }
            };
            if crate::admin::verify_key(&key, &hash) {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        }
        "verify-audit" => {
            let path = all_args.get(2).map(|s| s.as_str());
            crate::audit_chain::run_verify_audit(path)?;
            Ok(true)
        }
        "update" => {
            crate::update::run_update(rest_args)?;
            Ok(true)
        }
        "install" => {
            let force = rest_args.iter().any(|a| a == "--force" || a == "-f");
            run_install(force)?;
            Ok(true)
        }
        "configure" => {
            strip_immutable_flag("/etc/clawtower/config.toml");
            let result = run_script("configure.sh", rest_args);
            let _ = std::process::Command::new("chattr")
                .args(["+i", "/etc/clawtower/config.toml"])
                .status();
            result?;
            Ok(true)
        }
        "setup" => {
            run_script("setup.sh", rest_args)?;
            Ok(true)
        }
        "harden" => {
            pre_harden_cleanup();
            run_script("install.sh", rest_args)?;
            Ok(true)
        }
        "generate-key" => {
            let hash_path = std::path::Path::new("/etc/clawtower/admin.key.hash");
            match crate::admin::generate_and_show_admin_key(hash_path) {
                Ok(_) => Ok(true),
                Err(e) => {
                    eprintln!("Failed to generate admin key: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "setup-apparmor" => {
            let quiet = rest_args.iter().any(|a| a == "--quiet" || a == "-q");
            let result = crate::apparmor::setup(quiet);
            if !result.any_protection() {
                eprintln!("No AppArmor or pam_cap protection could be applied.");
                std::process::exit(1);
            }
            Ok(true)
        }
        "uninstall" => {
            pre_harden_cleanup();
            run_script("uninstall.sh", rest_args)?;
            Ok(true)
        }
        "update-ioc" => {
            crate::barnacle::run_update_ioc(rest_args)?;
            Ok(true)
        }
        "sync" => {
            run_script("sync-barnacle.sh", rest_args)?;
            Ok(true)
        }
        "logs" => {
            let status = std::process::Command::new("journalctl")
                .args(["-u", "clawtower", "-f", "--no-pager"])
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        "status" => {
            let _ = std::process::Command::new("systemctl")
                .args(["status", "clawtower", "--no-pager"])
                .status();
            eprintln!();
            let api_result = std::process::Command::new("curl")
                .args(["-s", "http://localhost:18791/api/security"])
                .output();
            if let Ok(output) = api_result {
                let body = String::from_utf8_lossy(&output.stdout);
                if !body.is_empty() && body.contains("critical") {
                    eprintln!("Alert Summary (from API):");
                    eprintln!("{}", body);
                }
            }
            Ok(true)
        }
        "scan" => {
            let results = crate::scanner::SecurityScanner::run_all_scans();
            eprintln!("🛡️  ClawTower Security Scan");
            eprintln!("========================");
            for r in &results {
                let icon = match r.status {
                    crate::scanner::ScanStatus::Pass => "✅",
                    crate::scanner::ScanStatus::Warn => "⚠️ ",
                    crate::scanner::ScanStatus::Fail => "❌",
                };
                eprintln!("{} [{}] {}: {}", icon, r.status, r.category, r.details);
            }
            let pass_count = results.iter().filter(|r| r.status == crate::scanner::ScanStatus::Pass).count();
            let total = results.len();
            eprintln!();
            eprintln!("Score: {}/{} checks passed", pass_count, total);
            Ok(true)
        }
        "profile" => {
            let sub = rest_args.first().map(|s| s.as_str()).unwrap_or("list");
            match sub {
                "list" => {
                    eprintln!("Available profiles:");
                    let dirs = [
                        PathBuf::from("/etc/clawtower/profiles"),
                        PathBuf::from("profiles"),
                    ];
                    let mut found = false;
                    for dir in &dirs {
                        if let Ok(entries) = std::fs::read_dir(dir) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                                    let name = path.file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("?");
                                    let desc = std::fs::read_to_string(&path).ok()
                                        .and_then(|c| c.lines()
                                            .find(|l| l.starts_with("# ClawTower Profile:"))
                                            .map(|l| l.trim_start_matches("# ClawTower Profile:").trim().to_string()))
                                        .unwrap_or_default();
                                    eprintln!("  {:<25} {}", name, desc);
                                    found = true;
                                }
                            }
                        }
                    }
                    if !found {
                        eprintln!("  (no profiles found in /etc/clawtower/profiles/ or ./profiles/)");
                    }
                    eprintln!();
                    eprintln!("Usage: clawtower run --profile=<name>");
                }
                _ => {
                    eprintln!("Unknown profile subcommand: {}", sub);
                    eprintln!("Usage: clawtower profile list");
                }
            }
            Ok(true)
        }
        "compliance-report" => {
            let framework = rest_args.iter()
                .find_map(|a| a.strip_prefix("--framework="))
                .unwrap_or("soc2");
            let period = rest_args.iter()
                .find_map(|a| a.strip_prefix("--period="))
                .and_then(|p| p.trim_end_matches('d').parse::<u32>().ok())
                .unwrap_or(30);
            let output_format = rest_args.iter()
                .find_map(|a| a.strip_prefix("--format="))
                .unwrap_or("text");
            let output_path = rest_args.iter()
                .find_map(|a| a.strip_prefix("--output="));

            let report = crate::compliance::generate_report(framework, period, &[], &[]);

            let output = match output_format {
                "json" => crate::compliance::report_to_json(&report),
                _ => crate::compliance::report_to_text(&report),
            };

            if let Some(path) = output_path {
                std::fs::write(path, &output)?;
                eprintln!("Report written to {}", path);
            } else {
                println!("{}", output);
            }
            Ok(true)
        }
        _ => Ok(false), // Not a CLI subcommand — continue to watchdog startup
    }
}
