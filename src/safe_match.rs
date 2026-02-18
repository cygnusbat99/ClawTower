//! Boundary-aware string matching utilities for security-critical comparisons.
//!
//! This module provides safe matching functions that prevent substring-based
//! bypass attacks found across multiple ClawTower modules. Every function here
//! enforces proper word/domain boundaries so that an attacker cannot craft
//! hostnames, log fields, or config values that accidentally match a shorter
//! legitimate string.
//!
//! # Functions
//!
//! - [`domain_matches`] — Wildcard and exact domain matching (e.g., `*.anthropic.com`)
//! - [`prefix_matches`] — iptables log prefix matching with boundary awareness
//! - [`parse_audit_field`] — Extracts `key=value` fields from audit log lines
//! - [`is_safe_host`] — Checks a hostname against a list of trusted domains
//! - [`field_exact_match`] — Exact string equality (no substring matching)
//! - [`parse_log_severity`] — Extracts severity from the prefix portion of a log line

use crate::alerts::Severity;

/// Matches a hostname against a domain pattern, supporting wildcard prefixes.
///
/// - Pattern `"*.anthropic.com"` matches `"api.anthropic.com"` and
///   `"deep.sub.anthropic.com"` but NOT `"evilanthropic.com"`.
/// - Pattern `"anthropic.com"` matches exactly `"anthropic.com"` only.
/// - Comparison is case-insensitive.
///
/// # Examples
///
/// ```ignore
/// assert!(domain_matches("api.anthropic.com", "*.anthropic.com"));
/// assert!(!domain_matches("evilanthropic.com", "*.anthropic.com"));
/// assert!(domain_matches("ANTHROPIC.COM", "anthropic.com"));
/// ```
pub fn domain_matches(hostname: &str, pattern: &str) -> bool {
    if hostname.is_empty() || pattern.is_empty() {
        return false;
    }
    let hostname = hostname.to_lowercase();
    let pattern = pattern.to_lowercase();

    // Strip wildcard prefix if present
    let domain = if let Some(stripped) = pattern.strip_prefix("*.") {
        stripped
    } else {
        // Exact match only (no wildcard)
        return hostname == pattern;
    };

    // Wildcard pattern: hostname is exactly the domain, or ends with .domain
    hostname == domain || hostname.ends_with(&format!(".{}", domain))
}

/// Matches an iptables log prefix with word-boundary awareness.
///
/// The prefix must appear at a word boundary — preceded by `[` or start-of-string,
/// and followed by `]`, ` ` (space), or end-of-string.
///
/// # Examples
///
/// ```ignore
/// assert!(prefix_matches("[CLAWTOWER_NET] SRC=...", "CLAWTOWER_NET"));
/// assert!(!prefix_matches("[OPENCLAWTOWER_NET] SRC=...", "CLAWTOWER_NET"));
/// ```
pub fn prefix_matches(line: &str, prefix: &str) -> bool {
    // Search for all occurrences of `prefix` in `line` and check boundaries
    let line_bytes = line.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    let prefix_len = prefix_bytes.len();
    let line_len = line_bytes.len();

    if prefix_len == 0 || prefix_len > line_len {
        return false;
    }

    let mut start = 0;
    while start + prefix_len <= line_len {
        if let Some(pos) = line[start..].find(prefix) {
            let abs_pos = start + pos;
            let end_pos = abs_pos + prefix_len;

            // Check left boundary: start-of-string, `[`, or space
            let left_ok = abs_pos == 0
                || line_bytes[abs_pos - 1] == b'['
                || line_bytes[abs_pos - 1] == b' ';

            // Check right boundary: end-of-string, `]`, or ` `
            let right_ok =
                end_pos == line_len || line_bytes[end_pos] == b']' || line_bytes[end_pos] == b' ';

            if left_ok && right_ok {
                return true;
            }

            // Advance past this occurrence to avoid infinite loop
            start = abs_pos + 1;
        } else {
            break;
        }
    }

    false
}

/// Parses a `key=value` field from an audit log line with word-boundary safety.
///
/// Splits the line on whitespace and finds the first token that starts with
/// `"{field}="`, returning the value portion. This prevents `"uid"` from
/// matching inside `"auid"`.
///
/// # Examples
///
/// ```ignore
/// let line = "type=SYSCALL uid=10 auid=1000 exe=/bin/ls";
/// assert_eq!(parse_audit_field(line, "uid"), Some("10".to_string()));
/// assert_eq!(parse_audit_field(line, "auid"), Some("1000".to_string()));
/// assert_eq!(parse_audit_field(line, "exe"), Some("/bin/ls".to_string()));
/// ```
pub fn parse_audit_field(line: &str, field: &str) -> Option<String> {
    let needle = format!("{}=", field);
    for token in line.split_whitespace() {
        if let Some(value) = token.strip_prefix(&needle) {
            return Some(value.to_string());
        }
    }
    None
}

/// Checks whether a hostname belongs to one of the safe (trusted) domains.
///
/// A hostname is considered safe if it exactly matches a domain in the list,
/// or if it ends with `.{domain}` (i.e., is a subdomain). This prevents
/// suffix-based spoofing like `"anthropic.com.evil.com"`.
///
/// Comparison is case-insensitive.
///
/// # Examples
///
/// ```ignore
/// let safe = &["anthropic.com", "openai.com"];
/// assert!(is_safe_host("api.anthropic.com", safe));
/// assert!(!is_safe_host("api.anthropic.com.evil.com", safe));
/// ```
pub fn is_safe_host(hostname: &str, safe_domains: &[&str]) -> bool {
    let hostname = hostname.to_lowercase();
    for domain in safe_domains {
        let domain = domain.to_lowercase();
        if hostname == domain || hostname.ends_with(&format!(".{}", domain)) {
            return true;
        }
    }
    false
}

/// Exact string equality check — no substring or suffix matching.
///
/// This is a deliberate wrapper to make call sites self-documenting:
/// replacing a `.contains()` with `field_exact_match()` signals that
/// only full equality is acceptable.
///
/// # Examples
///
/// ```ignore
/// assert!(field_exact_match("sandbox.mode", "sandbox.mode"));
/// assert!(!field_exact_match("evil.sandbox.mode", "sandbox.mode"));
/// ```
pub fn field_exact_match(field: &str, pattern: &str) -> bool {
    field == pattern
}

/// Parses a [`Severity`] from the *prefix* portion of a log line only.
///
/// The "prefix" is defined as the text before the first `:` or `]` character.
/// This prevents false matches on severity keywords that appear inside the
/// log message body (e.g., a filename containing "WARN").
///
/// # Recognized keywords (case-insensitive)
///
/// | Keyword              | Severity   |
/// |----------------------|------------|
/// | `CRIT`, `CRITICAL`   | Critical   |
/// | `ALERT`              | Critical   |
/// | `WARN`, `WARNING`    | Warning    |
/// | `NOTICE`, `INFO`     | Info       |
/// | `MARK`               | Info       |
///
/// # Examples
///
/// ```ignore
/// use crate::alerts::Severity;
/// // Picks up CRIT from prefix, ignores WARN in body
/// assert_eq!(
///     parse_log_severity("CRIT: [2026-02-17] file /tmp/WARN_data modified"),
///     Some(Severity::Critical),
/// );
/// ```
pub fn parse_log_severity(line: &str) -> Option<Severity> {
    // Find the prefix: text before the first `:` or `]`
    let prefix_end = line
        .find(':')
        .unwrap_or(line.len())
        .min(line.find(']').unwrap_or(line.len()));

    let prefix = &line[..prefix_end];
    let prefix_upper = prefix.to_uppercase();

    // Check keywords from most to least specific to avoid partial matches.
    // "CRITICAL" must be checked before "CRIT" to avoid false early return,
    // but both map to Critical so order between them doesn't matter functionally.
    if prefix_upper.contains("CRITICAL") || prefix_upper.contains("CRIT") {
        return Some(Severity::Critical);
    }
    if prefix_upper.contains("ALERT") {
        return Some(Severity::Critical);
    }
    if prefix_upper.contains("WARNING") || prefix_upper.contains("WARN") {
        return Some(Severity::Warning);
    }
    if prefix_upper.contains("NOTICE") || prefix_upper.contains("INFO") {
        return Some(Severity::Info);
    }
    if prefix_upper.contains("MARK") {
        return Some(Severity::Info);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::Severity;

    // ───────────────────────────── domain_matches ─────────────────────────────

    #[test]
    fn domain_wildcard_matches_subdomain() {
        assert!(domain_matches("api.anthropic.com", "*.anthropic.com"));
    }

    #[test]
    fn domain_wildcard_matches_deep_subdomain() {
        assert!(domain_matches("deep.sub.anthropic.com", "*.anthropic.com"));
    }

    #[test]
    fn domain_wildcard_matches_bare_domain() {
        // *.anthropic.com should also match anthropic.com itself
        assert!(domain_matches("anthropic.com", "*.anthropic.com"));
    }

    #[test]
    fn domain_wildcard_rejects_evil_prefix() {
        // The critical security test: "evilanthropic.com" must NOT match
        assert!(!domain_matches("evilanthropic.com", "*.anthropic.com"));
    }

    #[test]
    fn domain_wildcard_rejects_suffix_attack() {
        assert!(!domain_matches("anthropic.com.evil.com", "*.anthropic.com"));
    }

    #[test]
    fn domain_exact_matches_same() {
        assert!(domain_matches("anthropic.com", "anthropic.com"));
    }

    #[test]
    fn domain_exact_rejects_subdomain() {
        // Without wildcard, subdomains do NOT match
        assert!(!domain_matches("api.anthropic.com", "anthropic.com"));
    }

    #[test]
    fn domain_exact_rejects_evil_prefix() {
        assert!(!domain_matches("evilanthropic.com", "anthropic.com"));
    }

    #[test]
    fn domain_case_insensitive() {
        assert!(domain_matches("API.ANTHROPIC.COM", "*.anthropic.com"));
        assert!(domain_matches("ANTHROPIC.COM", "anthropic.com"));
        assert!(domain_matches("anthropic.com", "ANTHROPIC.COM"));
    }

    #[test]
    fn domain_empty_inputs() {
        assert!(!domain_matches("", "*.anthropic.com"));
        assert!(!domain_matches("anthropic.com", ""));
        assert!(!domain_matches("", ""));
    }

    #[test]
    fn domain_wildcard_only() {
        // Pattern "*." with empty domain portion — edge case
        assert!(!domain_matches("anything.com", "*."));
    }

    #[test]
    fn domain_unicode_hostname() {
        // Unicode should not cause panics
        assert!(!domain_matches("api.\u{00e9}vil.com", "*.anthropic.com"));
    }

    // ───────────────────────────── prefix_matches ─────────────────────────────

    #[test]
    fn prefix_matches_in_brackets() {
        assert!(prefix_matches("[CLAWTOWER_NET] SRC=192.168.1.1", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_matches_at_start() {
        assert!(prefix_matches("CLAWTOWER_NET something", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_matches_at_start_end_of_string() {
        assert!(prefix_matches("CLAWTOWER_NET", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_rejects_superstring_in_brackets() {
        // OPENCLAWTOWER_NET should NOT match CLAWTOWER_NET
        assert!(!prefix_matches("[OPENCLAWTOWER_NET] SRC=...", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_rejects_superstring_suffix() {
        assert!(!prefix_matches("[CLAWTOWER_NET_DROP] SRC=...", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_rejects_embedded_without_boundary() {
        assert!(!prefix_matches("xxCLAWTOWER_NETyy", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_empty_inputs() {
        assert!(!prefix_matches("", "CLAWTOWER_NET"));
        assert!(!prefix_matches("[CLAWTOWER_NET]", ""));
    }

    #[test]
    fn prefix_matches_bracket_tight() {
        // No space between bracket and prefix
        assert!(prefix_matches("[CLAWTOWER_NET]", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_matches_space_after() {
        assert!(prefix_matches("[CLAWTOWER_NET ", "CLAWTOWER_NET"));
    }

    #[test]
    fn prefix_multiple_occurrences_first_invalid() {
        // First occurrence has bad left boundary, second is good
        assert!(prefix_matches("xCLAWTOWER_NET [CLAWTOWER_NET]", "CLAWTOWER_NET"));
    }

    // ───────────────────────────── parse_audit_field ──────────────────────────

    #[test]
    fn audit_field_uid_not_auid() {
        let line = "type=SYSCALL uid=10 auid=1000 exe=/bin/ls";
        assert_eq!(parse_audit_field(line, "uid"), Some("10".to_string()));
        assert_eq!(parse_audit_field(line, "auid"), Some("1000".to_string()));
    }

    #[test]
    fn audit_field_uid_10_vs_100_vs_1000() {
        let line = "uid=10 something=else";
        assert_eq!(parse_audit_field(line, "uid"), Some("10".to_string()));

        let line = "uid=100 something=else";
        assert_eq!(parse_audit_field(line, "uid"), Some("100".to_string()));

        let line = "uid=1000 something=else";
        assert_eq!(parse_audit_field(line, "uid"), Some("1000".to_string()));
    }

    #[test]
    fn audit_field_not_found() {
        let line = "type=SYSCALL exe=/bin/ls";
        assert_eq!(parse_audit_field(line, "uid"), None);
    }

    #[test]
    fn audit_field_empty_value() {
        let line = "uid= auid=1000";
        assert_eq!(parse_audit_field(line, "uid"), Some("".to_string()));
    }

    #[test]
    fn audit_field_empty_line() {
        assert_eq!(parse_audit_field("", "uid"), None);
    }

    #[test]
    fn audit_field_empty_field_name() {
        // Looking for field "" should match tokens starting with "="
        // This is a degenerate case but should not panic
        let line = "uid=10 =orphan";
        assert_eq!(parse_audit_field(line, ""), Some("orphan".to_string()));
    }

    #[test]
    fn audit_field_no_substring_match() {
        // "id" should not match "uid=10"
        let line = "uid=10 pid=999";
        assert_eq!(parse_audit_field(line, "id"), None);
    }

    #[test]
    fn audit_field_with_equals_in_value() {
        // Value containing '=' should still work (only first '=' is split point)
        let line = "key=value=with=equals other=field";
        assert_eq!(
            parse_audit_field(line, "key"),
            Some("value=with=equals".to_string())
        );
    }

    // ───────────────────────────── is_safe_host ───────────────────────────────

    #[test]
    fn safe_host_exact_match() {
        assert!(is_safe_host("anthropic.com", &["anthropic.com"]));
    }

    #[test]
    fn safe_host_subdomain_match() {
        assert!(is_safe_host("api.anthropic.com", &["anthropic.com"]));
    }

    #[test]
    fn safe_host_deep_subdomain() {
        assert!(is_safe_host("deep.api.anthropic.com", &["anthropic.com"]));
    }

    #[test]
    fn safe_host_rejects_suffix_attack() {
        // anthropic.com.evil.com should NOT be safe
        assert!(!is_safe_host(
            "api.anthropic.com.evil.com",
            &["anthropic.com"]
        ));
    }

    #[test]
    fn safe_host_rejects_evil_prefix() {
        assert!(!is_safe_host("evilanthropic.com", &["anthropic.com"]));
    }

    #[test]
    fn safe_host_case_insensitive() {
        assert!(is_safe_host("API.ANTHROPIC.COM", &["anthropic.com"]));
        assert!(is_safe_host("api.anthropic.com", &["ANTHROPIC.COM"]));
    }

    #[test]
    fn safe_host_multiple_domains() {
        let safe = &["anthropic.com", "openai.com", "github.com"];
        assert!(is_safe_host("api.anthropic.com", safe));
        assert!(is_safe_host("api.openai.com", safe));
        assert!(is_safe_host("raw.githubusercontent.com", &["githubusercontent.com"]));
        assert!(!is_safe_host("evil.com", safe));
    }

    #[test]
    fn safe_host_empty_list() {
        assert!(!is_safe_host("anything.com", &[]));
    }

    #[test]
    fn safe_host_empty_hostname() {
        assert!(!is_safe_host("", &["anthropic.com"]));
    }

    // ───────────────────────────── field_exact_match ──────────────────────────

    #[test]
    fn field_exact_matches_same() {
        assert!(field_exact_match("sandbox.mode", "sandbox.mode"));
    }

    #[test]
    fn field_exact_rejects_prefix() {
        assert!(!field_exact_match("evil.sandbox.mode", "sandbox.mode"));
    }

    #[test]
    fn field_exact_rejects_suffix() {
        assert!(!field_exact_match("sandbox.mode.extra", "sandbox.mode"));
    }

    #[test]
    fn field_exact_rejects_substring() {
        assert!(!field_exact_match("xsandbox.modey", "sandbox.mode"));
    }

    #[test]
    fn field_exact_empty() {
        assert!(field_exact_match("", ""));
        assert!(!field_exact_match("something", ""));
        assert!(!field_exact_match("", "something"));
    }

    // ───────────────────────────── parse_log_severity ─────────────────────────

    #[test]
    fn severity_crit_in_prefix() {
        assert_eq!(
            parse_log_severity("CRIT: [2026-02-17] file /tmp/WARN_data modified"),
            Some(Severity::Critical),
        );
    }

    #[test]
    fn severity_critical_in_prefix() {
        assert_eq!(
            parse_log_severity("CRITICAL: something happened"),
            Some(Severity::Critical),
        );
    }

    #[test]
    fn severity_alert_in_prefix() {
        assert_eq!(
            parse_log_severity("ALERT: intrusion detected"),
            Some(Severity::Critical),
        );
    }

    #[test]
    fn severity_warn_in_prefix() {
        assert_eq!(
            parse_log_severity("WARN: disk space low"),
            Some(Severity::Warning),
        );
    }

    #[test]
    fn severity_warning_in_prefix() {
        assert_eq!(
            parse_log_severity("WARNING: unusual activity"),
            Some(Severity::Warning),
        );
    }

    #[test]
    fn severity_info_in_prefix() {
        assert_eq!(
            parse_log_severity("INFO: service started"),
            Some(Severity::Info),
        );
    }

    #[test]
    fn severity_notice_in_prefix() {
        assert_eq!(
            parse_log_severity("NOTICE: connection accepted"),
            Some(Severity::Info),
        );
    }

    #[test]
    fn severity_mark_in_prefix() {
        assert_eq!(
            parse_log_severity("MARK: heartbeat"),
            Some(Severity::Info),
        );
    }

    #[test]
    fn severity_ignores_body_keywords() {
        // "WARN" in the body (after the first `:`) should be ignored
        assert_eq!(
            parse_log_severity("INFO: the file WARN_flag was accessed"),
            Some(Severity::Info),
        );
    }

    #[test]
    fn severity_ignores_body_after_bracket() {
        // Prefix ends at `]`
        assert_eq!(
            parse_log_severity("[INFO] CRIT happened later"),
            Some(Severity::Info),
        );
    }

    #[test]
    fn severity_no_keyword() {
        assert_eq!(parse_log_severity("some random log line"), None);
    }

    #[test]
    fn severity_empty_line() {
        assert_eq!(parse_log_severity(""), None);
    }

    #[test]
    fn severity_case_insensitive() {
        assert_eq!(
            parse_log_severity("crit: lowercase check"),
            Some(Severity::Critical),
        );
        assert_eq!(
            parse_log_severity("Warn: mixed case"),
            Some(Severity::Warning),
        );
    }

    #[test]
    fn severity_colon_before_bracket() {
        // Colon appears before bracket — prefix is text before colon
        assert_eq!(
            parse_log_severity("WARN: [2026-02-17] event"),
            Some(Severity::Warning),
        );
    }

    #[test]
    fn severity_bracket_before_colon() {
        // Bracket appears before colon — prefix is text before bracket
        assert_eq!(
            parse_log_severity("[CRIT] 2026-02-17: event"),
            Some(Severity::Critical),
        );
    }

    #[test]
    fn severity_keyword_only_in_body() {
        // No keyword in prefix, only in body after `:`
        assert_eq!(
            parse_log_severity("timestamp: CRIT something bad"),
            None,
        );
    }

    #[test]
    fn severity_filename_with_warn_in_body() {
        // Realistic case: file named WARN_data.log mentioned after prefix
        assert_eq!(
            parse_log_severity("CRIT: file /var/log/WARN_data.log was deleted"),
            Some(Severity::Critical),
        );
    }

    #[test]
    fn severity_multiple_keywords_in_prefix_picks_highest() {
        // Both CRIT and WARN in prefix — CRIT is checked first, so Critical wins
        assert_eq!(
            parse_log_severity("CRIT WARN: something"),
            Some(Severity::Critical),
        );
    }
}
