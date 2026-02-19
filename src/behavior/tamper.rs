// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Security tamper detection helpers.
//!
//! LD_PRELOAD persistence detection, guard library allowlisting,
//! and related tamper-detection utility functions.

use crate::alerts::Severity;
use super::BehaviorCategory;
use super::patterns::{SHELL_PROFILE_PATHS, CLAWTOWER_GUARD_PATHS};

/// Check if a value references ClawTower's own guard library (allowlisted for LD_PRELOAD).
///
/// Uses exact path matching against known install locations rather than substring
/// matching, which could be bypassed by an attacker naming a malicious library
/// something like `/tmp/not-clawtower-evil.so`.
pub(crate) fn is_clawtower_guard(value: &str) -> bool {
    CLAWTOWER_GUARD_PATHS.iter().any(|path| value.contains(path))
}

/// Detect LD_PRELOAD persistence: writing LD_PRELOAD= or export LD_PRELOAD to
/// shell profile/rc files. Returns Critical if detected (unless it's ClawTower's
/// own guard path).
pub fn check_ld_preload_persistence(command: &str, file_path: Option<&str>) -> Option<(BehaviorCategory, Severity)> {
    // Check if command writes LD_PRELOAD to a shell profile
    let has_ld_preload = command.contains("LD_PRELOAD=") || command.contains("export LD_PRELOAD");
    if !has_ld_preload {
        return None;
    }

    // Check if target is a shell profile path
    let targets_profile = if let Some(fp) = file_path {
        SHELL_PROFILE_PATHS.iter().any(|p| fp.contains(p))
    } else {
        // Check if the command itself references a profile path (e.g., echo >> .bashrc)
        SHELL_PROFILE_PATHS.iter().any(|p| command.contains(p))
    };

    if !targets_profile {
        return None;
    }

    // Allow ClawTower's own guard
    if is_clawtower_guard(command) {
        return None;
    }

    Some((BehaviorCategory::SecurityTamper, Severity::Critical))
}

/// Check if a diff/content line contains LD_PRELOAD persistence (for sentinel use).
/// Returns true if the line is suspicious (not a comment, not ClawTower's guard).
pub fn is_ld_preload_persistence_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with("---") || trimmed.starts_with("+++") {
        return false;
    }
    if !(trimmed.contains("LD_PRELOAD=") || trimmed.contains("export LD_PRELOAD")) {
        return false;
    }
    !is_clawtower_guard(trimmed)
}
