//! AppArmor profile management with pam_cap fallback.
//!
//! Embeds both AppArmor profiles at compile time so they're available even when
//! deploying just the binary (no source tree needed). The `setup()` entry point
//! implements a fallback chain:
//!
//! 1. AppArmor kernel + tools available → write profiles to /etc/apparmor.d/, load them
//! 2. Kernel only (no userspace tools) → try `apt-get install apparmor-utils`, retry
//! 3. AppArmor unavailable → apply pam_cap fallback (drop CAP_LINUX_IMMUTABLE)
//!
//! Called via `clawtower setup-apparmor [--quiet]`.

use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Embedded profiles — compiled into the binary via include_str!().
const PROFILE_OPENCLAW: &str = include_str!("../apparmor/usr.bin.openclaw");
const PROFILE_PROTECT: &str = include_str!("../apparmor/etc.clawtower.protect");

// Destination paths in /etc/apparmor.d/
const DST_OPENCLAW: &str = "/etc/apparmor.d/usr.bin.openclaw";
const DST_PROTECT: &str = "/etc/apparmor.d/etc.clawtower.protect";
const CAPABILITY_CONF: &str = "/etc/security/capability.conf";

/// What level of AppArmor support is available on this system.
#[derive(Debug, PartialEq)]
pub enum AppArmorStatus {
    /// Kernel LSM includes apparmor AND apparmor_parser is installed.
    FullyAvailable,
    /// Kernel has apparmor LSM but no userspace tools (apparmor_parser missing).
    KernelOnly,
    /// AppArmor not present in kernel LSM list.
    Unavailable,
}

impl fmt::Display for AppArmorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullyAvailable => write!(f, "fully available (kernel + tools)"),
            Self::KernelOnly => write!(f, "kernel only (no userspace tools)"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Result of the setup operation — what actions were taken.
#[derive(Debug)]
pub struct SetupResult {
    pub profiles_loaded: Vec<String>,
    pub pam_cap_applied: bool,
    pub warnings: Vec<String>,
}

impl SetupResult {
    fn new() -> Self {
        Self {
            profiles_loaded: Vec::new(),
            pam_cap_applied: false,
            warnings: Vec::new(),
        }
    }

    /// True if at least one protection mechanism was applied.
    pub fn any_protection(&self) -> bool {
        !self.profiles_loaded.is_empty() || self.pam_cap_applied
    }
}

/// Detect AppArmor availability on the running system.
pub fn detect() -> AppArmorStatus {
    // Check kernel LSM list
    let kernel_has_apparmor = fs::read_to_string("/sys/kernel/security/lsm")
        .map(|lsm| lsm.contains("apparmor"))
        .unwrap_or(false);

    if !kernel_has_apparmor {
        return AppArmorStatus::Unavailable;
    }

    // Check for userspace tools
    let has_parser = Command::new("which")
        .arg("apparmor_parser")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_parser {
        AppArmorStatus::FullyAvailable
    } else {
        AppArmorStatus::KernelOnly
    }
}

/// Main entry point: detect, install profiles or fall back to pam_cap.
pub fn setup(quiet: bool) -> SetupResult {
    let mut result = SetupResult::new();
    let log = |msg: &str| {
        if !quiet {
            eprintln!("[AppArmor] {}", msg);
        }
    };

    let status = detect();
    log(&format!("AppArmor status: {}", status));

    match status {
        AppArmorStatus::FullyAvailable => {
            write_and_load_profiles(&mut result, quiet);
        }
        AppArmorStatus::KernelOnly => {
            log("Kernel has AppArmor but userspace tools missing — attempting install...");
            if try_install_apparmor_utils(quiet) {
                log("apparmor-utils installed successfully, loading profiles...");
                write_and_load_profiles(&mut result, quiet);
            } else {
                result.warnings.push(
                    "Could not install apparmor-utils — falling back to pam_cap".into(),
                );
                if !quiet {
                    eprintln!("[AppArmor WARN] {}", result.warnings.last().unwrap());
                }
                setup_pam_cap_fallback(&mut result, quiet);
            }
        }
        AppArmorStatus::Unavailable => {
            log("AppArmor not available in kernel — applying pam_cap fallback");
            setup_pam_cap_fallback(&mut result, quiet);
        }
    }

    if !quiet {
        eprintln!();
        if !result.profiles_loaded.is_empty() {
            eprintln!(
                "[AppArmor] Profiles loaded: {}",
                result.profiles_loaded.join(", ")
            );
        }
        if result.pam_cap_applied {
            eprintln!("[AppArmor] pam_cap fallback applied (capability.conf)");
        }
        if !result.any_protection() {
            eprintln!("[AppArmor WARN] No protection mechanism could be applied");
        }
    }

    result
}

/// Write embedded profiles to /etc/apparmor.d/ and load with apparmor_parser.
fn write_and_load_profiles(result: &mut SetupResult, quiet: bool) {
    let log = |msg: &str| {
        if !quiet {
            eprintln!("[AppArmor] {}", msg);
        }
    };

    // Write and load openclaw restriction profile
    match fs::write(DST_OPENCLAW, PROFILE_OPENCLAW) {
        Ok(()) => {
            log(&format!("Wrote {}", DST_OPENCLAW));
            match Command::new("apparmor_parser")
                .args(["-r", DST_OPENCLAW])
                .output()
            {
                Ok(output) if output.status.success() => {
                    log("Profile usr.bin.openclaw loaded (enforce mode)");
                    result.profiles_loaded.push("usr.bin.openclaw".into());
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let msg = format!(
                        "apparmor_parser failed for usr.bin.openclaw: {}",
                        stderr.trim()
                    );
                    result.warnings.push(msg.clone());
                    if !quiet {
                        eprintln!("[AppArmor WARN] {}", msg);
                    }
                }
                Err(e) => {
                    let msg = format!("Failed to run apparmor_parser: {}", e);
                    result.warnings.push(msg.clone());
                    if !quiet {
                        eprintln!("[AppArmor WARN] {}", msg);
                    }
                }
            }
        }
        Err(e) => {
            let msg = format!("Failed to write {}: {}", DST_OPENCLAW, e);
            result.warnings.push(msg.clone());
            if !quiet {
                eprintln!("[AppArmor WARN] {}", msg);
            }
        }
    }

    // Write and load config protection profile
    match fs::write(DST_PROTECT, PROFILE_PROTECT) {
        Ok(()) => {
            log(&format!("Wrote {}", DST_PROTECT));
            match Command::new("apparmor_parser")
                .args(["-r", DST_PROTECT])
                .output()
            {
                Ok(output) if output.status.success() => {
                    log("Profile etc.clawtower.protect loaded");
                    result.profiles_loaded.push("etc.clawtower.protect".into());
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let msg = format!(
                        "apparmor_parser failed for etc.clawtower.protect: {}",
                        stderr.trim()
                    );
                    result.warnings.push(msg.clone());
                    if !quiet {
                        eprintln!("[AppArmor WARN] {}", msg);
                    }
                }
                Err(e) => {
                    let msg = format!("Failed to run apparmor_parser: {}", e);
                    result.warnings.push(msg.clone());
                    if !quiet {
                        eprintln!("[AppArmor WARN] {}", msg);
                    }
                }
            }
        }
        Err(e) => {
            let msg = format!("Failed to write {}: {}", DST_PROTECT, e);
            result.warnings.push(msg.clone());
            if !quiet {
                eprintln!("[AppArmor WARN] {}", msg);
            }
        }
    }
}

/// Try to install apparmor-utils via apt-get. Returns true on success.
fn try_install_apparmor_utils(quiet: bool) -> bool {
    let apt_args: &[&str] = if quiet {
        &["install", "-y", "-qq", "apparmor-utils"]
    } else {
        &["install", "-y", "apparmor-utils"]
    };

    Command::new("apt-get")
        .args(["update", "-qq"])
        .output()
        .ok();

    Command::new("apt-get")
        .args(apt_args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fallback: write /etc/security/capability.conf to drop CAP_LINUX_IMMUTABLE
/// from the openclaw user, and ensure pam_cap is in the PAM stack.
fn setup_pam_cap_fallback(result: &mut SetupResult, quiet: bool) {
    let log = |msg: &str| {
        if !quiet {
            eprintln!("[AppArmor] {}", msg);
        }
    };

    // Write capability.conf
    let cap_content = "\
# ClawTower: drop dangerous capabilities from openclaw user
!cap_linux_immutable  openclaw
!cap_sys_ptrace       openclaw
!cap_sys_module       openclaw
";

    match fs::write(CAPABILITY_CONF, cap_content) {
        Ok(()) => {
            log(&format!("Wrote {}", CAPABILITY_CONF));
        }
        Err(e) => {
            let msg = format!("Failed to write {}: {}", CAPABILITY_CONF, e);
            result.warnings.push(msg.clone());
            if !quiet {
                eprintln!("[AppArmor WARN] {}", msg);
            }
            return;
        }
    }

    // Ensure pam_cap.so is in the PAM login stack
    let pam_auth = Path::new("/etc/pam.d/common-auth");
    let pam_cap_line = "auth    optional    pam_cap.so";

    let already_configured = fs::read_to_string(pam_auth)
        .map(|contents| contents.contains("pam_cap"))
        .unwrap_or(false);

    if !already_configured {
        // Check if pam_cap.so exists
        let pam_cap_exists = Path::new("/lib/security/pam_cap.so").exists()
            || Path::new("/lib/aarch64-linux-gnu/security/pam_cap.so").exists()
            || Path::new("/lib/x86_64-linux-gnu/security/pam_cap.so").exists();

        if pam_cap_exists {
            if let Ok(mut contents) = fs::read_to_string(pam_auth) {
                contents.push('\n');
                contents.push_str(pam_cap_line);
                contents.push('\n');
                match fs::write(pam_auth, contents) {
                    Ok(()) => log("Added pam_cap.so to /etc/pam.d/common-auth"),
                    Err(e) => {
                        let msg = format!("Failed to update PAM config: {}", e);
                        result.warnings.push(msg.clone());
                        if !quiet {
                            eprintln!("[AppArmor WARN] {}", msg);
                        }
                        return;
                    }
                }
            }
        } else {
            let msg = "pam_cap.so not found — install libpam-cap for capability restrictions";
            result.warnings.push(msg.into());
            if !quiet {
                eprintln!("[AppArmor WARN] {}", msg);
            }
            return;
        }
    } else {
        log("pam_cap already configured in PAM stack");
    }

    result.pam_cap_applied = true;
}

/// Remove AppArmor profiles (for uninstall). Unloads from kernel and deletes files.
#[allow(dead_code)]
pub fn remove_profiles(quiet: bool) {
    let log = |msg: &str| {
        if !quiet {
            eprintln!("[AppArmor] {}", msg);
        }
    };

    for dst in &[DST_OPENCLAW, DST_PROTECT] {
        if Path::new(dst).exists() {
            // Unload from kernel first
            let _ = Command::new("apparmor_parser").args(["-R", dst]).output();
            match fs::remove_file(dst) {
                Ok(()) => log(&format!("Removed {}", dst)),
                Err(e) => {
                    if !quiet {
                        eprintln!("[AppArmor WARN] Failed to remove {}: {}", dst, e);
                    }
                }
            }
        }
    }

    // Also remove the inline profile that install.sh used to create
    let legacy = "/etc/apparmor.d/clawtower.deny-openclaw";
    if Path::new(legacy).exists() {
        let _ = Command::new("apparmor_parser")
            .args(["-R", legacy])
            .output();
        let _ = fs::remove_file(legacy);
        log(&format!("Removed legacy profile {}", legacy));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_profiles_not_empty() {
        assert!(
            !PROFILE_OPENCLAW.is_empty(),
            "openclaw profile should be embedded"
        );
        assert!(
            !PROFILE_PROTECT.is_empty(),
            "protect profile should be embedded"
        );
    }

    #[test]
    fn no_stale_clawav_references() {
        assert!(
            !PROFILE_OPENCLAW.contains("clawav"),
            "openclaw profile still references stale 'clawav' paths"
        );
        assert!(
            !PROFILE_PROTECT.contains("clawav"),
            "protect profile still references stale 'clawav' paths"
        );
    }

    #[test]
    fn openclaw_profile_denies_linux_immutable() {
        assert!(
            PROFILE_OPENCLAW.contains("deny capability linux_immutable"),
            "openclaw profile must deny CAP_LINUX_IMMUTABLE"
        );
    }

    #[test]
    fn protect_profile_covers_key_tools() {
        for tool in &["rm", "mv", "chattr", "cp", "chmod"] {
            assert!(
                PROFILE_PROTECT.contains(&format!("/usr/bin/{}", tool)),
                "protect profile should cover /usr/bin/{}",
                tool
            );
        }
    }

    #[test]
    fn openclaw_profile_denies_clawtower_paths() {
        assert!(PROFILE_OPENCLAW.contains("deny /etc/clawtower/"));
        assert!(PROFILE_OPENCLAW.contains("deny /usr/local/bin/clawtower"));
        assert!(PROFILE_OPENCLAW.contains("deny /var/log/clawtower/"));
    }

    #[test]
    fn setup_result_any_protection() {
        let mut r = SetupResult::new();
        assert!(!r.any_protection());
        r.profiles_loaded.push("test".into());
        assert!(r.any_protection());

        let mut r2 = SetupResult::new();
        r2.pam_cap_applied = true;
        assert!(r2.any_protection());
    }
}
