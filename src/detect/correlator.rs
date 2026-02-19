// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

#![allow(dead_code)]
//! Correlator Engine — the sentinel's brain.
//!
//! Ingests events from all defense layers (LD_PRELOAD, eBPF, seccomp,
//! memory sentinel, process cage), maintains a unified timeline, computes
//! a decaying threat score, drives a state machine, and recommends response
//! actions based on cross-layer correlation patterns.

use std::collections::VecDeque;
use std::time::Instant;

// ── Constants ──────────────────────────────────────────────────────────────

const MAX_TIMELINE: usize = 10_000;
const DECAY_RATE: f64 = 50.0; // points per second

const THRESHOLD_ELEVATED: f64 = 300.0;
const THRESHOLD_CRITICAL: f64 = 600.0;
const THRESHOLD_LOCKDOWN: f64 = 900.0;

/// Bonus score when eBPF sees an exec that LD_PRELOAD didn't report.
const CROSS_LAYER_EXEC_BYPASS_SCORE: f64 = 400.0;

/// Bonus when sensitive reads are followed by network activity.
const CROSS_LAYER_READ_THEN_NETWORK_SCORE: f64 = 300.0;

/// Window for read-then-network correlation (seconds).
const READ_NETWORK_WINDOW_SECS: f64 = 10.0;

// ── Enums ──────────────────────────────────────────────────────────────────

/// Which defense layer produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    LdPreload,
    Ebpf,
    Seccomp,
    MemorySentinel,
    ProcessCage,
}

/// What kind of activity was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Execve,
    OpenFile,
    ReadSensitive,
    Connect,
    Mprotect,
    MemoryViolation,
    Dlopen,
    WriteSocket,
    FrequencyBurst,
    CgroupEscape,
}

/// Actions the sentinel can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Log,
    Alert,
    Elevate,
    Throttle,
    ForceThreatLevel,
    Kill,
    Freeze,
    NetworkIsolate,
    CorruptPayload,
    ForensicDump,
}

// ── Event ──────────────────────────────────────────────────────────────────

/// A unified event from any defense layer.
#[derive(Debug, Clone)]
pub struct Event {
    pub timestamp: Instant,
    pub source: EventSource,
    pub kind: EventKind,
    pub pid: u32,
    pub detail: String,
    pub threat_contribution: f64,
}

// ── ThreatState ────────────────────────────────────────────────────────────

/// State machine for the sentinel's threat assessment.
#[derive(Debug, Clone)]
pub enum ThreatState {
    Normal,
    Elevated {
        since: Instant,
        reason: String,
    },
    Critical {
        since: Instant,
        reason: String,
        actions_taken: Vec<ActionKind>,
    },
    Lockdown {
        since: Instant,
        reason: String,
        frozen: bool,
    },
}

impl ThreatState {
    /// Return the name of the current state for logging.
    pub fn name(&self) -> &'static str {
        match self {
            ThreatState::Normal => "Normal",
            ThreatState::Elevated { .. } => "Elevated",
            ThreatState::Critical { .. } => "Critical",
            ThreatState::Lockdown { .. } => "Lockdown",
        }
    }
}

// ── Correlator ─────────────────────────────────────────────────────────────

/// The correlator engine: ingests events, maintains threat score, drives
/// state transitions, and recommends response actions.
pub struct Correlator {
    pub timeline: VecDeque<Event>,
    pub threat_score: f64,
    pub state: ThreatState,
    last_tick: Instant,
}

impl Correlator {
    /// Create a new correlator with initial time reference.
    pub fn new(now: Instant) -> Self {
        Self {
            timeline: VecDeque::new(),
            threat_score: 0.0,
            state: ThreatState::Normal,
            last_tick: now,
        }
    }

    /// Ingest an event: add to timeline, update score, check patterns,
    /// evaluate state transition.
    pub fn ingest(&mut self, event: Event) {
        // Update score from the event itself.
        self.threat_score += event.threat_contribution;

        // Cross-layer correlation checks.
        self.check_exec_bypass(&event);
        self.check_read_then_network(&event);

        // Add to bounded timeline.
        self.timeline.push_back(event);
        while self.timeline.len() > MAX_TIMELINE {
            self.timeline.pop_front();
        }

        // Evaluate state transition.
        self.evaluate_state_transition();
    }

    /// Apply time-based score decay and potentially de-escalate.
    pub fn tick(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_tick).as_secs_f64();
        self.last_tick = now;

        self.threat_score -= DECAY_RATE * elapsed;
        if self.threat_score < 0.0 {
            self.threat_score = 0.0;
        }

        self.evaluate_state_transition();
    }

    /// Return recommended actions based on the current threat state.
    pub fn recommended_actions(&self) -> Vec<ActionKind> {
        match &self.state {
            ThreatState::Normal => {
                vec![ActionKind::Log]
            }
            ThreatState::Elevated { .. } => {
                vec![
                    ActionKind::Alert,
                    ActionKind::Elevate,
                    ActionKind::ForceThreatLevel,
                ]
            }
            ThreatState::Critical { .. } => {
                vec![
                    ActionKind::Alert,
                    ActionKind::Throttle,
                    ActionKind::Elevate,
                    ActionKind::ForceThreatLevel,
                    ActionKind::ForensicDump,
                    ActionKind::Kill,
                ]
            }
            ThreatState::Lockdown { .. } => {
                vec![
                    ActionKind::ForensicDump,
                    ActionKind::Freeze,
                    ActionKind::NetworkIsolate,
                    ActionKind::CorruptPayload,
                    ActionKind::Alert,
                ]
            }
        }
    }

    // ── Private helpers ────────────────────────────────────────────────

    /// Detect eBPF exec without matching LD_PRELOAD exec (static binary / bypass).
    fn check_exec_bypass(&mut self, event: &Event) {
        if event.source != EventSource::Ebpf || event.kind != EventKind::Execve {
            return;
        }

        // Look for a matching LD_PRELOAD exec for the same pid in the recent timeline.
        let has_preload_exec = self.timeline.iter().rev().any(|e| {
            e.source == EventSource::LdPreload
                && e.kind == EventKind::Execve
                && e.pid == event.pid
        });

        if !has_preload_exec {
            self.threat_score += CROSS_LAYER_EXEC_BYPASS_SCORE;
            #[cfg(not(test))]
            eprintln!(
                "[correlator] Cross-layer: exec by pid {} seen by eBPF but NOT LD_PRELOAD — possible evasion (+{})",
                event.pid, CROSS_LAYER_EXEC_BYPASS_SCORE
            );
        }
    }

    /// Detect sensitive reads followed by network activity within window.
    fn check_read_then_network(&mut self, event: &Event) {
        if event.source != EventSource::Ebpf && event.source != EventSource::LdPreload {
            return;
        }
        if event.kind != EventKind::Connect && event.kind != EventKind::WriteSocket {
            return;
        }

        // Look backwards for recent sensitive reads.
        let has_recent_sensitive_read = self.timeline.iter().rev().any(|e| {
            e.kind == EventKind::ReadSensitive
                && event.timestamp.duration_since(e.timestamp).as_secs_f64()
                    < READ_NETWORK_WINDOW_SECS
        });

        if has_recent_sensitive_read {
            self.threat_score += CROSS_LAYER_READ_THEN_NETWORK_SCORE;
            #[cfg(not(test))]
            eprintln!(
                "[correlator] Cross-layer: network activity after sensitive read — possible exfiltration (+{})",
                CROSS_LAYER_READ_THEN_NETWORK_SCORE
            );
        }
    }

    /// Evaluate whether the threat score warrants a state transition.
    #[allow(unused_variables)]
    fn evaluate_state_transition(&mut self) {
        let score = self.threat_score;
        let now_name = self.state.name();

        let new_state = if score >= THRESHOLD_LOCKDOWN {
            match &self.state {
                ThreatState::Lockdown { .. } => return,
                _ => {
                    let reason = format!("Threat score {:.0} >= {}", score, THRESHOLD_LOCKDOWN);
                    #[cfg(not(test))]
                    eprintln!("[correlator] State transition: {} → Lockdown ({})", now_name, reason);
                    ThreatState::Lockdown {
                        since: Instant::now(),
                        reason,
                        frozen: false,
                    }
                }
            }
        } else if score >= THRESHOLD_CRITICAL {
            match &self.state {
                ThreatState::Critical { .. } | ThreatState::Lockdown { .. } => {
                    // De-escalate from Lockdown to Critical.
                    if matches!(self.state, ThreatState::Lockdown { .. }) {
                        let reason = format!("Threat score decayed to {:.0}", score);
                        #[cfg(not(test))]
                        eprintln!("[correlator] State transition: Lockdown → Critical ({})", reason);
                        ThreatState::Critical {
                            since: Instant::now(),
                            reason,
                            actions_taken: vec![],
                        }
                    } else {
                        return;
                    }
                }
                _ => {
                    let reason = format!("Threat score {:.0} >= {}", score, THRESHOLD_CRITICAL);
                    #[cfg(not(test))]
                    eprintln!("[correlator] State transition: {} → Critical ({})", now_name, reason);
                    ThreatState::Critical {
                        since: Instant::now(),
                        reason,
                        actions_taken: vec![],
                    }
                }
            }
        } else if score >= THRESHOLD_ELEVATED {
            match &self.state {
                ThreatState::Elevated { .. } => return,
                ThreatState::Normal => {
                    let reason = format!("Threat score {:.0} >= {}", score, THRESHOLD_ELEVATED);
                    #[cfg(not(test))]
                    eprintln!("[correlator] State transition: Normal → Elevated ({})", reason);
                    ThreatState::Elevated {
                        since: Instant::now(),
                        reason,
                    }
                }
                _ => {
                    // De-escalate from Critical/Lockdown.
                    let reason = format!("Threat score decayed to {:.0}", score);
                    #[cfg(not(test))]
                    eprintln!("[correlator] State transition: {} → Elevated ({})", now_name, reason);
                    ThreatState::Elevated {
                        since: Instant::now(),
                        reason,
                    }
                }
            }
        } else {
            // Below ELEVATED threshold — de-escalate to Normal.
            if matches!(self.state, ThreatState::Normal) {
                return;
            }
            #[cfg(not(test))]
            eprintln!(
                "[correlator] State transition: {} → Normal (score {:.0})",
                now_name, score
            );
            ThreatState::Normal
        };

        self.state = new_state;
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn make_event(source: EventSource, kind: EventKind, pid: u32, score: f64) -> Event {
        Event {
            timestamp: Instant::now(),
            source,
            kind,
            pid,
            detail: String::new(),
            threat_contribution: score,
        }
    }

    fn make_event_at(
        ts: Instant,
        source: EventSource,
        kind: EventKind,
        pid: u32,
        score: f64,
    ) -> Event {
        Event {
            timestamp: ts,
            source,
            kind,
            pid,
            detail: String::new(),
            threat_contribution: score,
        }
    }

    #[test]
    fn test_normal_to_elevated_to_critical_to_lockdown() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        assert!(matches!(c.state, ThreatState::Normal));

        // Push to Elevated (300+).
        c.ingest(make_event(EventSource::LdPreload, EventKind::OpenFile, 1, 350.0));
        assert!(matches!(c.state, ThreatState::Elevated { .. }));

        // Push to Critical (600+).
        c.ingest(make_event(EventSource::Seccomp, EventKind::Mprotect, 1, 300.0));
        assert!(matches!(c.state, ThreatState::Critical { .. }));

        // Push to Lockdown (900+).
        c.ingest(make_event(EventSource::MemorySentinel, EventKind::MemoryViolation, 1, 400.0));
        assert!(matches!(c.state, ThreatState::Lockdown { .. }));
    }

    #[test]
    fn test_deescalation_via_decay() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Go to Lockdown.
        c.ingest(make_event(EventSource::Ebpf, EventKind::Execve, 1, 0.0));
        // Manually inject LD_PRELOAD exec so cross-layer doesn't fire.
        c.timeline.push_back(make_event(
            EventSource::LdPreload,
            EventKind::Execve,
            1,
            0.0,
        ));
        c.threat_score = 1000.0;
        c.evaluate_state_transition();
        assert!(matches!(c.state, ThreatState::Lockdown { .. }));

        // Decay to Critical range (600-899).
        // 1000 - 50*7 = 650
        c.tick(now + Duration::from_secs(7));
        assert!(
            matches!(c.state, ThreatState::Critical { .. }),
            "Expected Critical, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );

        // Decay to Elevated range (300-599).
        // 650 - 50*3 = 500 → still Critical; need more
        // 650 - 50*5 = 400 → Elevated
        c.tick(now + Duration::from_secs(12));
        assert!(
            matches!(c.state, ThreatState::Elevated { .. }),
            "Expected Elevated, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );

        // Decay to Normal.
        // Need score < 300. 400 - 50*4 = 200.
        c.tick(now + Duration::from_secs(16));
        assert!(
            matches!(c.state, ThreatState::Normal),
            "Expected Normal, got {:?} (score={:.0})",
            c.state.name(),
            c.threat_score
        );
    }

    #[test]
    fn test_cross_layer_exec_bypass() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // eBPF sees exec but no LD_PRELOAD exec in timeline → bypass detection.
        let event = make_event(EventSource::Ebpf, EventKind::Execve, 42, 100.0);
        c.ingest(event);

        // 100 (base) + 400 (cross-layer) = 500 → Elevated.
        assert!(
            c.threat_score >= 500.0,
            "Expected >= 500, got {:.0}",
            c.threat_score
        );
        assert!(matches!(c.state, ThreatState::Elevated { .. }));
    }

    #[test]
    fn test_cross_layer_no_false_positive() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // LD_PRELOAD reports exec first.
        c.ingest(make_event(EventSource::LdPreload, EventKind::Execve, 42, 50.0));
        // Then eBPF reports same pid exec — should NOT trigger bypass.
        c.ingest(make_event(EventSource::Ebpf, EventKind::Execve, 42, 50.0));

        // Total should be just 100, no cross-layer bonus.
        assert!(
            c.threat_score < 200.0,
            "Expected < 200, got {:.0} (false positive!)",
            c.threat_score
        );
    }

    #[test]
    fn test_read_then_network_correlation() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Sensitive read.
        c.ingest(make_event_at(
            now,
            EventSource::LdPreload,
            EventKind::ReadSensitive,
            1,
            100.0,
        ));

        // Network connect within window.
        c.ingest(make_event_at(
            now + Duration::from_secs(3),
            EventSource::Ebpf,
            EventKind::Connect,
            1,
            100.0,
        ));

        // 100 + 100 + 300 (cross-layer) = 500.
        assert!(
            c.threat_score >= 500.0,
            "Expected >= 500, got {:.0}",
            c.threat_score
        );
    }

    #[test]
    fn test_timeline_bounded() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        for i in 0..MAX_TIMELINE + 500 {
            c.ingest(Event {
                timestamp: now + Duration::from_millis(i as u64),
                source: EventSource::LdPreload,
                kind: EventKind::OpenFile,
                pid: 1,
                detail: String::new(),
                threat_contribution: 0.0, // zero to avoid score overflow issues
            });
        }

        assert_eq!(c.timeline.len(), MAX_TIMELINE);
    }

    #[test]
    fn test_threat_score_decay() {
        let now = Instant::now();
        let mut c = Correlator::new(now);
        c.threat_score = 500.0;

        // 2 seconds of decay: 500 - 50*2 = 400.
        c.tick(now + Duration::from_secs(2));
        assert!(
            (c.threat_score - 400.0).abs() < 1.0,
            "Expected ~400, got {:.1}",
            c.threat_score
        );

        // Decay doesn't go below zero.
        c.tick(now + Duration::from_secs(100));
        assert_eq!(c.threat_score, 0.0);
    }

    #[test]
    fn test_recommended_actions_per_state() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Normal.
        let actions = c.recommended_actions();
        assert!(actions.contains(&ActionKind::Log));
        assert!(!actions.contains(&ActionKind::Freeze));

        // Elevated.
        c.state = ThreatState::Elevated {
            since: now,
            reason: "test".into(),
        };
        let actions = c.recommended_actions();
        assert!(actions.contains(&ActionKind::Alert));
        assert!(actions.contains(&ActionKind::Elevate));
        assert!(!actions.contains(&ActionKind::Freeze));

        // Critical.
        c.state = ThreatState::Critical {
            since: now,
            reason: "test".into(),
            actions_taken: vec![],
        };
        let actions = c.recommended_actions();
        assert!(actions.contains(&ActionKind::Throttle));
        assert!(actions.contains(&ActionKind::Kill));
        assert!(actions.contains(&ActionKind::ForensicDump));

        // Lockdown.
        c.state = ThreatState::Lockdown {
            since: now,
            reason: "test".into(),
            frozen: false,
        };
        let actions = c.recommended_actions();
        assert!(actions.contains(&ActionKind::Freeze));
        assert!(actions.contains(&ActionKind::NetworkIsolate));
        assert!(actions.contains(&ActionKind::CorruptPayload));
        assert!(actions.contains(&ActionKind::ForensicDump));
    }

    #[test]
    fn test_event_ingestion_updates_score() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        assert_eq!(c.threat_score, 0.0);

        c.ingest(make_event(EventSource::LdPreload, EventKind::OpenFile, 1, 150.0));
        assert!((c.threat_score - 150.0).abs() < 1.0);

        c.ingest(make_event(EventSource::Seccomp, EventKind::Mprotect, 1, 200.0));
        assert!((c.threat_score - 350.0).abs() < 1.0);
    }

    #[test]
    fn test_rapid_events_cause_escalation() {
        let now = Instant::now();
        let mut c = Correlator::new(now);

        // Rapidly ingest many small events — should escalate through states.
        for _ in 0..10 {
            c.ingest(make_event(EventSource::LdPreload, EventKind::FrequencyBurst, 1, 100.0));
        }

        // 10 * 100 = 1000 → Lockdown.
        assert!(
            matches!(c.state, ThreatState::Lockdown { .. }),
            "Expected Lockdown after rapid events, got {:?}",
            c.state.name()
        );
    }
}
