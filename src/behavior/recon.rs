// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Reconnaissance detection helpers.
//!
//! Environment enumeration, config reads, recon command invocations,
//! and file access patterns indicative of system probing.

use crate::alerts::Severity;
use super::BehaviorCategory;
use super::patterns::{RECON_COMMANDS, RECON_ALLOWLIST, RECON_PATHS};

/// Check for reconnaissance command invocations (EXECVE events).
///
/// Detects commands like `whoami`, `id`, `uname`, `env`, `printenv`,
/// `hostname`, `ifconfig` — unless the full command matches a known-safe
/// allowlist entry (e.g. `ip neigh`, `ip addr`).
///
/// `binary` is the base name of the executed binary. `args` is the full
/// argument vector.
pub(crate) fn check_recon_commands(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    let full_cmd_lower = args.join(" ").to_lowercase();
    let is_allowed = RECON_ALLOWLIST.iter().any(|&a| full_cmd_lower.contains(a));
    if !is_allowed && RECON_COMMANDS.iter().any(|&c| {
        let c_base = c.split_whitespace().next().unwrap_or(c);
        binary.eq_ignore_ascii_case(c_base)
    }) {
        return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
    }
    None
}

/// Check for reading recon-sensitive files (EXECVE events).
///
/// Detects file readers (cat, less, more, head, tail, etc.) accessing
/// paths like `.env`, `.aws/credentials`, `.ssh/config`, `/proc/kallsyms`,
/// etc.
///
/// `binary` is the base name, `args` is the full argument vector.
pub(crate) fn check_recon_file_reads(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if ["cat", "less", "more", "head", "tail", "cp", "dd", "tar", "rsync", "sed", "tee", "scp", "script"].contains(&binary) {
        for arg in args.iter().skip(1) {
            for path in RECON_PATHS {
                if arg.contains(path) {
                    return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                }
            }
        }
    }
    None
}

/// Check for `dd` reading recon-sensitive paths via `if=` argument.
///
/// Returns a Reconnaissance match if the `if=` argument references a
/// recon path (e.g. `/proc/kallsyms`, `.ssh/config`).
pub(crate) fn check_dd_recon(args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    for arg in args.iter() {
        if let Some(path) = arg.strip_prefix("if=") {
            for recon_path in RECON_PATHS {
                if path.contains(recon_path) {
                    return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                }
            }
        }
    }
    None
}
