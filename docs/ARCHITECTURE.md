# Architecture

## Module Dependency Graph

```
main.rs
├── config.rs          (Config, all *Config structs)
├── alerts.rs          (Alert, Severity, AlertStore)
├── auditd.rs          (ParsedEvent, parse_to_event, tail functions)
│   ├── behavior.rs    (classify_behavior — uses ParsedEvent)
│   └── policy.rs      (PolicyEngine — uses ParsedEvent)
├── aggregator.rs      (dedup + rate limit, uses Alert, audit_chain, api store)
│   └── audit_chain.rs (AuditChain — SHA-256 hash chain)
├── api.rs             (HTTP server, AlertRingBuffer, SharedAlertStore)
├── slack.rs           (SlackNotifier — independent webhook)
├── tui.rs             (Ratatui dashboard — consumes Alert stream)
├── scanner.rs         (periodic security scans)
├── admin.rs           (Unix socket + Argon2 auth)
├── firewall.rs        (UFW state monitor)
├── network.rs         (iptables log parser)
├── journald.rs        (journalctl -k tail, reuses network parser)
├── falco.rs           (Falco JSON log tail)
├── samhain.rs         (Samhain FIM log tail)
└── proxy.rs           (LLM API proxy with key mapping + DLP)

bin/clawsudo.rs        (standalone binary, own policy loader)
preload/interpose.c    (standalone .so, no Rust dependency)
```

## Data Flow — Alert Pipeline

```
                    ┌─────────────┐
                    │   auditd    │──→ parse_to_event() ──→ behavior.classify_behavior()
                    │  tail loop  │                    └──→ policy.evaluate()
                    └──────┬──────┘                    └──→ event_to_alert()
                           │
  ┌────────────┐    ┌──────▼──────┐    ┌──────────┐
  │  network   │──→ │             │    │          │
  │  falco     │──→ │   raw_tx    │──→ │ Aggreg.  │──→ alert_tx ──→ TUI
  │  samhain   │──→ │  (channel)  │    │          │
  │  firewall  │──→ │             │    │  dedup   │──→ slack_tx ──→ Slack webhook
  │  scanner   │──→ │             │    │  rate    │
  │  admin     │──→ │             │    │  limit   │──→ api_store (ring buffer)
  └────────────┘    └─────────────┘    │          │
                                       │  audit   │──→ audit.chain (append-only file)
                                       │  chain   │
                                       └──────────┘
```

**Three-stage channel pipeline** (all `mpsc::channel`):
1. **Sources → raw_tx/raw_rx** (capacity: 1000) — all sources push raw alerts
2. **Aggregator → alert_tx/alert_rx** (capacity: 1000) — filtered alerts to TUI
3. **Aggregator → slack_tx/slack_rx** (capacity: 100) — alerts meeting min severity to Slack

## Auditd Event Parsing

The auditd parser (`src/auditd.rs`) handles three record types:

1. **EXECVE records** — Contains `argc` and `a0..aN` fields. Args may be hex-encoded (e.g., `a0=2F7573722F62696E2F6375726C` → `/usr/bin/curl`). The parser decodes hex when all characters are hex digits and length is even.

2. **SYSCALL records** — Contains `syscall=<num>`, `success=yes|no`, `uid=<uid>`. Syscall numbers are mapped via a static lookup table for aarch64 (e.g., 221→execve, 56→openat, 203→connect). File paths extracted from `name=` or `exe=` fields.

3. **AVC/Anomaly records** — AppArmor denials (`apparmor="DENIED"`), anomaly events. Always classified as security events.

**User filtering:** SYSCALL records are filtered by `uid=` or `auid=` matching the configured watched user. EXECVE records pass through unfiltered (they follow an already-filtered SYSCALL record in auditd's output).

## Behavior Classification

The behavior engine (`src/behavior.rs`) applies hardcoded rules in priority order:

| Priority | Category | Severity | Triggers |
|----------|----------|----------|----------|
| 1 | SEC_TAMPER | Critical | `ufw disable`, `systemctl stop auditd`, etc. (16 patterns) |
| 2 | DATA_EXFIL | Critical | `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat` |
| 3 | PRIV_ESC | Critical | Read `/etc/shadow`, write `/etc/passwd`, edit `/etc/hosts` |
| 4 | RECON | Warning | `whoami`, `id`, `uname`; reading `.env`, `.ssh/id_rsa`, `.aws/credentials` |

Also checks syscall-level events: `openat` on sensitive paths, `unlinkat` on critical files.

## Aggregator — Dedup and Rate Limiting

The aggregator (`src/aggregator.rs`) sits between all sources and all consumers.

**Deduplication:** Key = `"{source}:{message}"`. If the same key appears within 30 seconds, the duplicate is suppressed.

**Rate limiting:** Per-source, max 20 alerts per 60-second sliding window. Tracked via a vector of timestamps, pruned on each check.

**Critical bypass:** Critical alerts have a tighter dedup window (5 seconds) but are never rate-limited.

**Cleanup:** Every 100 processed alerts, old dedup entries (>90s) and empty rate limit buckets are pruned to prevent unbounded memory growth.

## Hash Chain Verification

Each audit entry in `/var/log/clawav/audit.chain` is a JSON line:

```json
{
  "seq": 42,
  "ts": "2026-02-13T22:00:00Z",
  "severity": "warning",
  "source": "behavior",
  "message": "[BEHAVIOR:RECON] whoami",
  "prev_hash": "abc123...",
  "hash": "def456..."
}
```

**Hash computation:** `SHA-256("{seq}|{ts}|{severity}|{source}|{message}|{prev_hash}")`

**Genesis:** First entry uses `prev_hash = "0000...0000"` (64 zeros).

**Verification** (`clawav verify-audit`): Reads every entry sequentially, verifies:
1. Sequence numbers are contiguous (1, 2, 3, ...)
2. Each entry's `prev_hash` matches the previous entry's `hash`
3. Each entry's `hash` matches the recomputed hash

Any tampering (modified message, deleted entry, reordered entries) breaks the chain.

**Resumption:** When restarting, `AuditChain::new()` reads the last entry to get `last_seq` and `last_hash`, then continues appending.

## Threat Model

| Layer | Defends Against | Mechanism |
|-------|----------------|-----------|
| **auditd** | Unlogged commands | Kernel-level logging, immutable rules (`-e 2`) |
| **behavior engine** | Known attack patterns | Hardcoded classification of exfil/privesc/recon/tamper |
| **policy engine** | Configurable threats | YAML rules with glob matching and whitelists |
| **clawsudo** | Unauthorized privilege use | Policy gate before `sudo`, fail-secure default |
| **LD_PRELOAD** | Syscall execution | Blocks calls at libc level *before* they happen |
| **aggregator** | Alert fatigue | Dedup + rate limiting without suppressing criticals |
| **audit chain** | Log tampering | SHA-256 hash chain, append-only |
| **Slack webhook** | Agent silencing alerts | Independent webhook, not routed through agent |
| **immutable files** | Binary/config modification | `chattr +i` + capability stripping |
| **AppArmor** | Agent accessing watchdog | MAC profile denying `openclaw` user access |
| **systemd hardening** | Service killing | `Restart=always`, `WatchdogSec=30`, sudoers deny |
| **DLP proxy** | Secret leakage via API | Regex scanning of outbound LLM requests |
| **admin key** | Unauthorized management | Argon2 auth, rate limiting, lockout |
