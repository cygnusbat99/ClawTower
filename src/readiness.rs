// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Enterprise readiness gate: startup control score.
//!
//! Computes a 0–100 readiness score from the current config. Below threshold
//! triggers a Critical alert at startup. Checks API security exposure,
//! monitoring coverage, update posture, and alert pipeline health.

use crate::config::Config;

/// Result of the readiness check.
pub struct ReadinessReport {
    pub score: u32,
    pub max_score: u32,
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
}

/// Compute an enterprise readiness score from the current configuration.
///
/// Scoring breakdown (100 total):
/// - API security: 20 points (auth token + loopback binding)
/// - Monitoring coverage: 40 points (sentinel, barnacle, policy, netpolicy)
/// - Update posture: 20 points (auto-update mode)
/// - Alert pipeline: 20 points (Slack + auditd)
pub fn check_readiness(config: &Config) -> ReadinessReport {
    let mut score = 0u32;
    let max_score = 100;
    let mut failures = Vec::new();
    let mut warnings = Vec::new();

    // API security (20 points)
    if config.api.enabled {
        if !config.api.auth_token.is_empty() {
            score += 10;
        } else {
            failures.push("API enabled without auth_token".to_string());
        }
        if config.api.bind == "127.0.0.1" || config.api.bind == "::1" {
            score += 10;
        } else if !config.api.auth_token.is_empty() {
            score += 5;
            warnings.push("API bound to non-loopback with auth".to_string());
        } else {
            failures.push("API bound to non-loopback without auth".to_string());
        }
    } else {
        score += 20; // API disabled = no exposure
    }

    // Monitoring coverage (40 points)
    if config.sentinel.enabled { score += 10; } else { warnings.push("sentinel disabled".to_string()); }
    if config.barnacle.enabled { score += 10; } else { warnings.push("barnacle disabled".to_string()); }
    if config.policy.enabled { score += 10; } else { warnings.push("policy engine disabled".to_string()); }
    if config.netpolicy.enabled { score += 10; } else { warnings.push("netpolicy disabled".to_string()); }

    // Update posture (20 points)
    match config.auto_update.mode.as_str() {
        "check" | "disabled" => score += 20,
        "auto" => { score += 10; warnings.push("auto-update in auto mode".to_string()); }
        _ => score += 15,
    }

    // Alert pipeline (20 points)
    let slack_enabled = config.slack.enabled.unwrap_or(!config.slack.webhook_url.is_empty());
    if slack_enabled { score += 10; } else { warnings.push("slack notifications disabled".to_string()); }
    score += 10; // auditd always enabled

    ReadinessReport { score, max_score, failures, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readiness_score_all_enabled() {
        let mut config = Config::default();
        config.api.enabled = true;
        config.api.auth_token = "secret".to_string();
        config.api.bind = "127.0.0.1".to_string();
        config.sentinel.enabled = true;
        config.barnacle.enabled = true;
        config.policy.enabled = true;
        config.netpolicy.enabled = true;
        config.auto_update.mode = "check".to_string();
        config.slack.enabled = Some(true);
        config.slack.webhook_url = "https://hooks.slack.com/test".to_string();

        let report = check_readiness(&config);
        assert!(report.score >= 80, "Full config should score >= 80, got {}", report.score);
        assert!(report.failures.is_empty(), "No failures expected: {:?}", report.failures);
    }

    #[test]
    fn test_readiness_score_insecure_config() {
        let mut config = Config::default();
        config.api.enabled = true;
        config.api.bind = "0.0.0.0".to_string();
        config.api.auth_token = String::new();

        let report = check_readiness(&config);
        assert!(report.score < 80, "Insecure config should score < 80, got {}", report.score);
        assert!(!report.failures.is_empty(), "Should have failures for insecure API");
    }

    #[test]
    fn test_readiness_api_disabled_full_score() {
        let mut config = Config::default();
        config.api.enabled = false;
        config.sentinel.enabled = true;
        config.barnacle.enabled = true;
        config.policy.enabled = true;
        config.netpolicy.enabled = true;
        config.auto_update.mode = "check".to_string();
        config.slack.enabled = Some(true);
        config.slack.webhook_url = "https://hooks.slack.com/test".to_string();

        let report = check_readiness(&config);
        assert_eq!(report.score, 100, "All enabled + API disabled should be 100");
    }

    #[test]
    fn test_readiness_default_config() {
        let config = Config::default();
        let report = check_readiness(&config);
        // Default config has API disabled (20) + some monitors on + no slack
        assert!(report.score > 0);
        assert!(report.score <= 100);
    }

    #[test]
    fn test_readiness_non_loopback_with_auth() {
        let mut config = Config::default();
        config.api.enabled = true;
        config.api.auth_token = "token".to_string();
        config.api.bind = "0.0.0.0".to_string();

        let report = check_readiness(&config);
        // Should get 5 for non-loopback with auth (not 10 for loopback)
        assert!(report.warnings.iter().any(|w| w.contains("non-loopback")));
        assert!(report.failures.is_empty());
    }
}
