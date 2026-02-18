# ClawTower Documentation Index

Quick map to every doc in this project. Start with what you need.

## Getting Started

| Document | What's in it |
|----------|-------------|
| [README](../README.md) | Project overview, features, quick start, config basics |
| [INSTALL.md](INSTALL.md) | Full installation walkthrough, hardening steps, systemd setup, uninstall |
| [CONFIGURATION.md](CONFIGURATION.md) | Config layering, overrides, policy customization, field reference |

## Architecture & Internals

| Document | What's in it |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module dependency graph, data flow diagrams, threat model |
| [ALERT-PIPELINE.md](ALERT-PIPELINE.md) | Alert model, aggregator dedup/rate-limiting, Slack/TUI delivery |
| [MONITORING-SOURCES.md](MONITORING-SOURCES.md) | All 9 real-time data sources (auditd, journald, falco, etc.) |
| [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) | All 30+ periodic security scanners — pass/warn/fail conditions |

## Features Deep Dives

| Document | What's in it |
|----------|-------------|
| [SENTINEL.md](SENTINEL.md) | Real-time file integrity: inotify, shadow copies, quarantine, content scanning |
| [POLICIES.md](POLICIES.md) | YAML policy writing for detection rules and clawsudo enforcement |
| [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) | clawsudo gatekeeper, admin key, audit chain, API proxy, LD_PRELOAD guard |
| [API.md](API.md) | HTTP REST API endpoints and response formats |

## Operations & Tuning

| Document | What's in it |
|----------|-------------|
| [DAY1-OPERATIONS.md](DAY1-OPERATIONS.md) | First-day setup checklist, common tasks, troubleshooting |
| [NOISE-ANALYSIS.md](NOISE-ANALYSIS.md) | Analysis of 18h production logs — alert volumes, noise sources, signal quality |
| [TUNING.md](TUNING.md) | Tuning guide — reducing noise, adjusting thresholds, filter recipes |
| [POC-RESULTS.md](POC-RESULTS.md) | Attack simulation POC results — 10 tests, 90% detection rate |

## Design Plans

| Document | What's in it |
|----------|-------------|
| [Runtime Abstraction Phase 1 Design](plans/2026-02-18-runtime-abstraction-phase1-design.md) | Parity-first refactor plan for detector/source abstractions and hardcoding removal |
| [Tinman Coverage Design](plans/2026-02-17-tinman-coverage-design.md) | Gap analysis and design for Tinman eval harness attack coverage |
| [Tinman Coverage Implementation](plans/2026-02-17-tinman-coverage-implementation.md) | Implementation plan for 7 Tinman attack categories |

## For AI Agents / Contributors

| Document | What's in it |
|----------|-------------|
| [CLAUDE.md](../CLAUDE.md) | LLM onboarding — module guide, key patterns, common tasks, glossary |
| [SOURCE-INVENTORY.md](SOURCE-INVENTORY.md) | Complete inventory of all public items (structs, enums, functions) |
| [AUDIT-LOG.md](AUDIT-LOG.md) | Internal documentation audit log (maintainer reference, not user-facing) |

## Suggested Reading Order

**New user?** README → INSTALL.md → CONFIGURATION.md

**Understanding the system?** ARCHITECTURE.md → ALERT-PIPELINE.md → MONITORING-SOURCES.md

**Setting up file protection?** SENTINEL.md → POLICIES.md

**Working on the code?** CLAUDE.md → ARCHITECTURE.md → the relevant feature doc
