// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Social engineering detection for commands and document content.
//!
//! Detects pipe-to-shell patterns, paste service URLs, password-protected
//! archives, and deceptive prerequisite installations in both command streams
//! and file content (markdown code blocks, inline commands).

use crate::alerts::Severity;
use super::patterns::{SOCIAL_ENGINEERING_PATTERNS, DOCUMENT_SOCIAL_ENGINEERING_PATTERNS};

/// Patterns that indicate piping output to a shell or interpreter.
///
/// Covers standard shells (sh, bash, dash, zsh, ksh), full paths
/// (/bin/sh, /usr/bin/bash, etc.), sudo, and interpreter pipes
/// (perl, python, ruby, node).
const PIPE_TO_SHELL_PATTERNS: &[&str] = &[
    // Standard shells (bare names)
    "| sh", "|sh", "| bash", "|bash", "| sudo", "|sudo",
    "| dash", "|dash", "| zsh", "|zsh", "| ksh", "|ksh",
    // Full paths
    "| /bin/sh", "| /usr/bin/sh",
    "| /bin/bash", "| /usr/bin/bash",
    "| /bin/dash", "| /usr/bin/dash",
    "| /bin/zsh", "| /bin/ksh",
    // Interpreter pipes
    "| perl", "| python", "| ruby", "| node",
];

/// Check a command string for social engineering patterns.
///
/// Returns the first matching pattern's (description, severity), or None.
/// For curl/wget entries, we require both the tool name AND a pipe-to-shell
/// pattern (`| sh`, `| bash`, `| sudo`) to avoid false positives on normal
/// HTTP requests.
pub fn check_social_engineering(cmd: &str) -> Option<(&'static str, Severity)> {
    let cmd_lower = cmd.to_lowercase();

    // First check: curl/wget pipe-to-shell (Critical)
    let has_pipe_to_shell = PIPE_TO_SHELL_PATTERNS.iter().any(|p| cmd_lower.contains(p));

    if has_pipe_to_shell {
        if cmd_lower.contains("curl ") || cmd_lower.contains("curl\t") {
            return Some(("curl piped to shell", Severity::Critical));
        }
        if cmd_lower.contains("wget ") || cmd_lower.contains("wget\t") {
            return Some(("wget piped to shell", Severity::Critical));
        }
    }

    // Check all non-curl/wget patterns via substring matching
    for &(pattern, description, ref severity) in SOCIAL_ENGINEERING_PATTERNS {
        // Skip the curl/wget pipe-to-shell entries (handled above with compound logic)
        if pattern == "curl " || pattern == "wget " {
            continue;
        }
        if cmd_lower.contains(&pattern.to_lowercase()) {
            return Some((description, severity.clone()));
        }
    }

    None
}

/// Check document/file content for social engineering patterns.
///
/// This is the document-level counterpart to [`check_social_engineering`]. It:
/// 1. Extracts code blocks from markdown (lines between ``` fences)
/// 2. Runs each code block line through [`check_social_engineering`]
/// 3. Checks the full content against document-specific patterns (paste URLs, etc.)
///
/// Returns the first match's (description, severity), or None.
pub fn check_social_engineering_content(content: &str) -> Option<(&'static str, Severity)> {
    let content_lower = content.to_lowercase();

    // Phase 1: Extract markdown code blocks and check each line as a command
    let mut in_code_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }
        if in_code_block {
            if let Some(result) = check_social_engineering(trimmed) {
                return Some(result);
            }
        }
    }

    // Phase 2: Check full content against document-specific patterns
    for &(pattern, description, ref severity) in DOCUMENT_SOCIAL_ENGINEERING_PATTERNS {
        if content_lower.contains(&pattern.to_lowercase()) {
            return Some((description, severity.clone()));
        }
    }

    // Phase 3: Check non-code-block lines for inline command patterns
    // (e.g., "Run: base64 -d | sh" without code fences)
    in_code_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }
        if !in_code_block && !trimmed.is_empty() {
            // Check for inline command patterns (base64 pipes, curl pipes)
            if let Some(result) = check_social_engineering(trimmed) {
                return Some(result);
            }
        }
    }

    None
}
