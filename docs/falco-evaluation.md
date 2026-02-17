# Falco Integration Evaluation

**Date:** 2026-02-17  
**Status:** Deprecated (disabled by default)  
**Branch:** `chore/falco-evaluation`

## Summary

The Falco integration (`src/falco.rs`) is **deprecated and disabled by default** (`falco.enabled = false`). The code is retained but gated behind the config flag. Users who have Falco installed can still enable it.

## Background

Falco is an eBPF/kernel-module-based runtime security tool that monitors syscalls. ClawTower's integration tails Falco's JSON log output and converts entries to ClawTower alerts.

**Problem:** The integration was configured but never operational — `tail_falco_log()` waited indefinitely for a log file (`/var/log/falco/falco_output.jsonl`) that never appeared because Falco was never installed on the target Pi. This wasted a spawned task and produced misleading "Waiting for Falco log..." messages every 30 seconds forever.

This gap contributed to **Flag 6 (ESCAPE) scoring 0/17** in the Red Lobster v4 pentest — network escape detection had no working monitor.

## Why Deprecate

1. **Redundant coverage.** The iptables log prefix fix (`CLAWTOWER_NET`) and auditd `connect()` syscall monitoring now provide network escape detection. These are lighter-weight and already operational.

2. **Operational overhead on Pi.** Falco requires either a kernel module or eBPF probe. On a Raspberry Pi (aarch64, limited resources), this is significant:
   - Kernel module: requires headers, breaks on kernel updates
   - eBPF: requires kernel ≥4.18 with BTF, higher memory usage
   - Both: additional service to maintain, update, and monitor

3. **No unique detection value.** For ClawTower's threat model (monitoring a single AI agent on a known host), auditd + iptables cover the same syscall and network visibility that Falco would provide, without the extra dependency.

4. **Setup script never ran.** `scripts/setup-falco.sh` exists but was never executed on the target system, confirming Falco was never part of the operational deployment.

## What Changed

- `config.toml`: `falco.enabled = false` (already was — confirmed as correct default)
- `src/falco.rs`: `tail_falco_log()` now gives up after 3 attempts (90s) if the log file doesn't appear, instead of waiting forever. Emits a warning suggesting `falco.enabled=false`.
- `src/main.rs`: Already gates Falco spawn behind `config.falco.enabled` — no change needed.

## If You Want Falco

If you have a use case for Falco (e.g., container monitoring, broader syscall coverage beyond auditd):

1. Run `scripts/setup-falco.sh` as root
2. Set `falco.enabled = true` in `/etc/clawtower/config.toml`
3. Restart ClawTower

The integration code is fully functional — it just needs Falco actually running and producing logs.
