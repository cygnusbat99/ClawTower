// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Financial theft detection helpers.
//!
//! Crypto wallet access, private key detection, transaction signing,
//! and crypto CLI tool usage.

use crate::alerts::Severity;
use super::BehaviorCategory;
use super::patterns::{CRYPTO_WALLET_PATHS, CRYPTO_KEY_PATTERNS, CRYPTO_CLI_TOOLS};

/// Check for financial theft patterns in an EXECVE command.
///
/// Detects:
/// - Access to crypto wallet file paths (Critical)
/// - Crypto private key / seed phrase patterns in command text (Critical)
/// - Crypto CLI tool invocations (Warning)
///
/// `cmd` is the full command string, `cmd_lower` is its lowercase form.
pub(crate) fn check_financial_theft(cmd: &str, cmd_lower: &str) -> Option<(BehaviorCategory, Severity)> {
    // Crypto wallet file path access
    for path in CRYPTO_WALLET_PATHS {
        if cmd.contains(path) {
            return Some((BehaviorCategory::FinancialTheft, Severity::Critical));
        }
    }

    // Crypto key / seed phrase patterns (case-insensitive)
    for pattern in CRYPTO_KEY_PATTERNS {
        if cmd_lower.contains(&pattern.to_lowercase()) {
            return Some((BehaviorCategory::FinancialTheft, Severity::Critical));
        }
    }

    // Crypto CLI tool usage
    for tool in CRYPTO_CLI_TOOLS {
        if cmd_lower.starts_with(tool) || cmd_lower.contains(&format!("/{}", tool)) {
            return Some((BehaviorCategory::FinancialTheft, Severity::Warning));
        }
    }

    None
}
