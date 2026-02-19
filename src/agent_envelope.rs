// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Capability Envelope — enforces expected behavior boundaries for AI agents.
//!
//! Each agent profile declares a [`CapabilitiesConfig`] that defines what the agent
//! is *expected* to do. The [`CapabilityMatcher`] checks observed actions against
//! these capabilities. Actions outside the envelope are flagged as violations.
//!
//! This flips the detection model from "match known bad" to "flag anything outside
//! known good" — much harder for an attacker to evade.

use crate::agent_profile::CapabilitiesConfig;
use crate::alerts::Severity;

/// Result of checking an action against a capability envelope.
#[derive(Debug, Clone, PartialEq)]
pub enum EnvelopeResult {
    /// Action is within the agent's declared capabilities
    WithinEnvelope,
    /// Action violates the capability envelope
    Violation {
        reason: String,
        severity: Severity,
    },
    /// No capability envelope defined (agent has no restrictions)
    NoEnvelope,
}

/// Checks observed agent actions against declared capability envelopes.
pub struct CapabilityMatcher<'a> {
    capabilities: &'a CapabilitiesConfig,
    has_restrictions: bool,
}

impl<'a> CapabilityMatcher<'a> {
    /// Create a matcher from an agent's capability config.
    pub fn new(capabilities: &'a CapabilitiesConfig) -> Self {
        // An envelope is "defined" if any restriction is specified
        let has_restrictions = !capabilities.allowed_binaries.is_empty()
            || !capabilities.allowed_syscall_categories.is_empty()
            || !capabilities.allowed_hosts.is_empty()
            || !capabilities.allowed_write_paths.is_empty();

        Self {
            capabilities,
            has_restrictions,
        }
    }

    /// Check if a binary execution is within the envelope.
    pub fn check_binary(&self, binary: &str) -> EnvelopeResult {
        if !self.has_restrictions || self.capabilities.allowed_binaries.is_empty() {
            return EnvelopeResult::NoEnvelope;
        }

        let basename = crate::util::extract_binary_name(binary);

        if self.capabilities.allowed_binaries.iter().any(|b| b == basename) {
            EnvelopeResult::WithinEnvelope
        } else {
            EnvelopeResult::Violation {
                reason: format!("binary '{}' not in capability envelope", basename),
                severity: Severity::Warning,
            }
        }
    }

    /// Check if a network connection to a host is within the envelope.
    pub fn check_host(&self, host: &str) -> EnvelopeResult {
        if !self.has_restrictions || self.capabilities.allowed_hosts.is_empty() {
            return EnvelopeResult::NoEnvelope;
        }

        if self.capabilities.allowed_hosts.iter().any(|h| h == host) {
            EnvelopeResult::WithinEnvelope
        } else {
            EnvelopeResult::Violation {
                reason: format!("host '{}' not in capability envelope", host),
                severity: Severity::Warning,
            }
        }
    }

    /// Check if a file write path is within the envelope.
    pub fn check_write_path(&self, path: &str) -> EnvelopeResult {
        if !self.has_restrictions || self.capabilities.allowed_write_paths.is_empty() {
            return EnvelopeResult::NoEnvelope;
        }

        if self.capabilities.allowed_write_paths.iter().any(|prefix| path.starts_with(prefix)) {
            EnvelopeResult::WithinEnvelope
        } else {
            EnvelopeResult::Violation {
                reason: format!("write to '{}' outside capability envelope", path),
                severity: Severity::Warning,
            }
        }
    }

    /// Check if a container operation is within the envelope.
    pub fn check_container_op(&self, binary: &str) -> EnvelopeResult {
        if !self.has_restrictions {
            return EnvelopeResult::NoEnvelope;
        }

        let basename = crate::util::extract_binary_name(binary);
        let is_container_op = matches!(basename, "docker" | "podman" | "nerdctl" | "containerd");

        if !is_container_op {
            return EnvelopeResult::WithinEnvelope;
        }

        if self.capabilities.allow_containers {
            EnvelopeResult::WithinEnvelope
        } else {
            EnvelopeResult::Violation {
                reason: format!("container operation '{}' not permitted", basename),
                severity: Severity::Critical,
            }
        }
    }

    /// Check if a sudo operation is within the envelope.
    pub fn check_sudo(&self) -> EnvelopeResult {
        if !self.has_restrictions {
            return EnvelopeResult::NoEnvelope;
        }

        if self.capabilities.allow_sudo {
            EnvelopeResult::WithinEnvelope
        } else {
            EnvelopeResult::Violation {
                reason: "sudo not permitted by capability envelope".to_string(),
                severity: Severity::Critical,
            }
        }
    }

    /// Check if a package install operation is within the envelope.
    pub fn check_package_install(&self, binary: &str) -> EnvelopeResult {
        if !self.has_restrictions {
            return EnvelopeResult::NoEnvelope;
        }

        let basename = crate::util::extract_binary_name(binary);
        let is_pkg_install = matches!(
            basename,
            "apt" | "apt-get" | "pip" | "pip3" | "npm" | "yarn" | "cargo" | "gem" | "go"
        );

        if !is_pkg_install {
            return EnvelopeResult::WithinEnvelope;
        }

        if self.capabilities.allow_package_install {
            EnvelopeResult::WithinEnvelope
        } else {
            EnvelopeResult::Violation {
                reason: format!("package install '{}' not permitted", basename),
                severity: Severity::Warning,
            }
        }
    }

    /// Run all applicable checks for a command execution.
    ///
    /// Returns the first violation found, or WithinEnvelope/NoEnvelope.
    pub fn check_command(&self, binary: &str, args: &[String]) -> EnvelopeResult {
        if !self.has_restrictions {
            return EnvelopeResult::NoEnvelope;
        }

        // Check sudo
        let basename = crate::util::extract_binary_name(binary);
        if basename == "sudo" {
            let result = self.check_sudo();
            if matches!(result, EnvelopeResult::Violation { .. }) {
                return result;
            }
        }

        // Check container ops
        let container_result = self.check_container_op(binary);
        if matches!(container_result, EnvelopeResult::Violation { .. }) {
            return container_result;
        }

        // Check package install
        let pkg_result = self.check_package_install(binary);
        if matches!(pkg_result, EnvelopeResult::Violation { .. }) {
            return pkg_result;
        }

        // Check binary allowlist
        let bin_result = self.check_binary(binary);
        if matches!(bin_result, EnvelopeResult::Violation { .. }) {
            return bin_result;
        }

        // Check write paths in args (heuristic: look for file path args)
        for arg in args {
            if arg.starts_with('/') && !arg.starts_with("--") {
                let write_result = self.check_write_path(arg);
                if matches!(write_result, EnvelopeResult::Violation { .. }) {
                    return write_result;
                }
            }
        }

        EnvelopeResult::WithinEnvelope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restricted_capabilities() -> CapabilitiesConfig {
        CapabilitiesConfig {
            allowed_binaries: vec![
                "curl".to_string(),
                "python3".to_string(),
                "node".to_string(),
            ],
            allowed_syscall_categories: vec!["network".to_string(), "filesystem".to_string()],
            allowed_hosts: vec![
                "api.anthropic.com".to_string(),
                "api.github.com".to_string(),
            ],
            allowed_write_paths: vec![
                "/home/openclaw/".to_string(),
                "/tmp/".to_string(),
            ],
            allow_containers: false,
            allow_package_install: false,
            allow_sudo: false,
        }
    }

    fn empty_capabilities() -> CapabilitiesConfig {
        CapabilitiesConfig::default()
    }

    #[test]
    fn test_no_envelope_when_empty() {
        let caps = empty_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        assert_eq!(matcher.check_binary("docker"), EnvelopeResult::NoEnvelope);
        assert_eq!(matcher.check_host("evil.com"), EnvelopeResult::NoEnvelope);
    }

    #[test]
    fn test_allowed_binary() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        assert_eq!(matcher.check_binary("curl"), EnvelopeResult::WithinEnvelope);
        assert_eq!(matcher.check_binary("/usr/bin/curl"), EnvelopeResult::WithinEnvelope);
    }

    #[test]
    fn test_disallowed_binary() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_binary("nmap");
        assert!(matches!(result, EnvelopeResult::Violation { .. }));
        if let EnvelopeResult::Violation { reason, severity } = result {
            assert!(reason.contains("nmap"));
            assert_eq!(severity, Severity::Warning);
        }
    }

    #[test]
    fn test_allowed_host() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        assert_eq!(matcher.check_host("api.anthropic.com"), EnvelopeResult::WithinEnvelope);
    }

    #[test]
    fn test_disallowed_host() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_host("evil.com");
        assert!(matches!(result, EnvelopeResult::Violation { .. }));
    }

    #[test]
    fn test_allowed_write_path() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        assert_eq!(
            matcher.check_write_path("/home/openclaw/workspace/file.txt"),
            EnvelopeResult::WithinEnvelope
        );
    }

    #[test]
    fn test_disallowed_write_path() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_write_path("/etc/passwd");
        assert!(matches!(result, EnvelopeResult::Violation { .. }));
    }

    #[test]
    fn test_container_blocked() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_container_op("docker");
        assert!(matches!(result, EnvelopeResult::Violation { severity: Severity::Critical, .. }));
    }

    #[test]
    fn test_container_allowed() {
        let mut caps = restricted_capabilities();
        caps.allow_containers = true;
        let matcher = CapabilityMatcher::new(&caps);
        assert_eq!(matcher.check_container_op("docker"), EnvelopeResult::WithinEnvelope);
    }

    #[test]
    fn test_sudo_blocked() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_sudo();
        assert!(matches!(result, EnvelopeResult::Violation { severity: Severity::Critical, .. }));
    }

    #[test]
    fn test_package_install_blocked() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_package_install("pip");
        assert!(matches!(result, EnvelopeResult::Violation { .. }));
    }

    #[test]
    fn test_non_package_binary_passes_pkg_check() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        assert_eq!(matcher.check_package_install("curl"), EnvelopeResult::WithinEnvelope);
    }

    #[test]
    fn test_check_command_sudo_violation() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_command("sudo", &["rm".to_string(), "-rf".to_string()]);
        assert!(matches!(result, EnvelopeResult::Violation { severity: Severity::Critical, .. }));
    }

    #[test]
    fn test_check_command_allowed() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_command("curl", &["https://api.anthropic.com".to_string()]);
        assert_eq!(result, EnvelopeResult::WithinEnvelope);
    }

    #[test]
    fn test_check_command_write_path_violation() {
        let caps = restricted_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_command(
            "python3",
            &["-c".to_string(), "open('/etc/crontab','w')".to_string(), "/etc/crontab".to_string()],
        );
        assert!(matches!(result, EnvelopeResult::Violation { .. }));
    }

    #[test]
    fn test_check_command_no_envelope() {
        let caps = empty_capabilities();
        let matcher = CapabilityMatcher::new(&caps);
        let result = matcher.check_command("docker", &["run".to_string(), "evil".to_string()]);
        assert_eq!(result, EnvelopeResult::NoEnvelope);
    }
}
