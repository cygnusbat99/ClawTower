# 🛡️ ClawAV

**Tamper-proof, OS-level security watchdog for AI agents.** ClawAV monitors an AI agent's every syscall, network connection, and file access at the kernel level — and cannot be disabled, modified, or silenced by the agent, even under full prompt injection compromise. Once installed, the only way to change it is physical access and a recovery boot.

## Why

AI agents like [OpenClaw](https://github.com/openclaw) run with real OS access — executing commands, reading files, making network requests. A prompt injection attack can weaponize that access: exfiltrating secrets, disabling firewalls, escalating privileges. Traditional security tools trust their operator; ClawAV assumes the operator (the AI) is compromised and builds an independent monitoring layer the agent cannot touch.

## Architecture

```
Agent command → clawsudo (policy gate) → LD_PRELOAD (syscall intercept) → OS
     ↓                                          ↓
auditd logs → EXECVE parser → behavior engine + policy engine → aggregator
     ↓                                                              ↓
hash-chained audit trail                              Slack webhook (independent)
     ↓                                                              ↓
JSON API on LAN (:18791)                              TUI dashboard
```

**Key principle:** Alerts go through an independent Slack webhook — not through the AI agent. If the agent is compromised, alerts still reach the human.

## Components

| Module | File | Description |
|--------|------|-------------|
| **auditd parser** | `src/auditd.rs` | Tails `/var/log/audit/audit.log`, parses EXECVE/SYSCALL records, decodes hex args, maps aarch64 syscall numbers |
| **behavior engine** | `src/behavior.rs` | Hardcoded rules classifying events as DATA_EXFIL, PRIV_ESC, SEC_TAMPER, RECON, or SIDE_CHAN |
| **policy engine** | `src/policy.rs` | YAML-driven rule engine with command, command_contains, file_access, and exclude_args matchers |
| **aggregator** | `src/aggregator.rs` | Deduplication (30s window) and per-source rate limiting (20/min). Critical alerts always pass. |
| **audit chain** | `src/audit_chain.rs` | SHA-256 hash-chained append-only log. Each entry includes hash of previous entry. |
| **clawsudo** | `src/bin/clawsudo.rs` | Sudo proxy with allow/deny/ask enforcement. Fail-secure: no rules = deny all. |
| **LD_PRELOAD** | `src/preload/interpose.c` | Intercepts `execve`, `open`, `openat`, `connect` at libc level before they execute |
| **Slack notifier** | `src/slack.rs` | Independent webhook with primary/backup failover |
| **API server** | `src/api.rs` | JSON API on port 18791 — status, alerts, security posture |
| **TUI dashboard** | `src/tui.rs` | Ratatui terminal UI with 5 tabs: Alerts, Network, Falco, FIM, System |
| **scanner** | `src/scanner.rs` | Periodic checks: firewall, auditd, integrity, updates, SSH, listeners, disk, side-channel mitigations, SecureClaw sync |
| **admin socket** | `src/admin.rs` | Unix socket with Argon2-hashed key auth, rate limiting (3 failures = 1hr lockout) |
| **proxy** | `src/proxy.rs` | Transparent LLM API proxy with virtual→real key mapping and DLP scanning |
| **firewall monitor** | `src/firewall.rs` | Polls UFW every 30s, alerts on any rule change or disablement |
| **network monitor** | `src/network.rs`, `src/journald.rs` | Parses iptables log lines from syslog or journald |
| **Falco** | `src/falco.rs` | Tails Falco JSON output for eBPF behavioral alerts |
| **Samhain** | `src/samhain.rs` | Tails Samhain file integrity monitoring logs |
| **SecureClaw** | `src/secureclaw.rs` | Modular pattern databases for prompt injection, dangerous commands, privacy violations, and supply chain attacks |

**6,400 lines of Rust/C. 109 tests.**

## Quick Start

```bash
# Build
cargo build --release

# Build LD_PRELOAD library
bash scripts/build-preload.sh

# Run in dev mode (uses local config.toml, no installation)
cargo run -- ./config.toml

# Run headless (no TUI, log to stderr)
cargo run -- --headless ./config.toml

# Run tests
cargo test

# Verify audit chain integrity
cargo run -- verify-audit /path/to/audit.chain
```

## Installation

The installer (`scripts/install.sh`) implements the **"Swallowed Key"** pattern — 7 layers of tamper protection that make ClawAV immutable once installed:

| Step | What it does |
|------|-------------|
| 1. System user | Creates `clawav` user with no login shell |
| 2. Binary + config | Installs to `/usr/local/bin/clawav` and `/etc/clawav/` |
| 3. systemd service | `Restart=always`, `WatchdogSec=30`, `NoNewPrivileges=true` |
| 4. Immutable flags | `chattr +i` on binary, config, and service file |
| 5. AppArmor | Denies `openclaw` user access to all ClawAV paths |
| 6. Capability dropping | Strips `CAP_LINUX_IMMUTABLE`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE` from openclaw |
| 7. Kernel hardening | `kernel.modules_disabled=1`, `yama.ptrace_scope=2`, `auditctl -e 2` |

Plus: restricted sudoers (agent can't stop/disable the service), LD_PRELOAD guard installation, and **installer self-destructs** after completion.

```bash
sudo bash scripts/install.sh
```

See [docs/INSTALL.md](docs/INSTALL.md) for the full guide.

## clawsudo — Sudo Proxy

`clawsudo` replaces `sudo` for the AI agent. Every privileged command goes through policy evaluation first.

**Enforcement modes:**
- **allow** — Execute immediately via `sudo`
- **deny** — Block with exit code 77, alert to Slack
- **ask** — Send Slack notification, wait up to 5 minutes for human approval via `touch /tmp/clawsudo-<hash>.approved`

**Fail-secure:** If no policy files are found, ALL commands are denied.

If no rule matches, the command enters `ask` mode (unknown = suspicious).

```yaml
# policies/clawsudo.yaml
rules:
  - name: "allow-apt"
    match:
      command: ["apt", "apt-get"]
    enforcement: allow

  - name: "deny-raw-shell"
    match:
      command: ["bash", "sh", "zsh"]
    enforcement: deny
```

## LD_PRELOAD — Syscall Interception

`libclawguard.so` intercepts libc calls **before they execute** (unlike auditd which logs after):

- **`execve`** — blocks denied binaries (e.g., `bash -c`)
- **`open`/`openat`** — blocks writes to protected paths (e.g., `/etc/shadow`)
- **`connect`** — blocks connections to denied addresses

Policy loaded once at init from `/etc/clawav/preload-policy.json`:
```json
{
  "enabled": true,
  "deny_exec": ["bash -c", "sh -c"],
  "deny_paths_write": ["/etc/shadow", "/etc/passwd", "/etc/clawav"],
  "deny_connect": [],
  "log_file": "/var/log/clawav/preload.log"
}
```

Denied calls return `EACCES` and are logged.

## YAML Policy Engine

Rules are loaded from `policies/*.yaml` and `/etc/clawav/policies/*.yaml`.

```yaml
rules:
  - name: "block-data-exfiltration"
    description: "Block curl/wget to unknown hosts"
    match:
      command: ["curl", "wget", "nc"]          # exact binary name
      exclude_args: ["api.anthropic.com"]       # whitelist
    action: critical

  - name: "deny-shadow-read"
    match:
      file_access: ["/etc/shadow", "/etc/sudoers.d/*"]  # glob patterns
    action: critical

  - name: "deny-firewall-changes"
    match:
      command_contains: ["ufw disable", "iptables -F"]   # substring
    action: critical
```

See [docs/POLICIES.md](docs/POLICIES.md) for the full schema.

## Admin Key

At first run, ClawAV generates a 256-bit key (displayed once, stored as Argon2 hash):

```
╔══════════════════════════════════════════════════════════════╗
║  OCAV-a1b2c3d4e5f6...                                      ║
║  Store in your password manager or write it down.           ║
╚══════════════════════════════════════════════════════════════╝
```

Commands via unix socket (`/var/run/clawav/admin.sock`):
- `status` — Check watchdog state
- `scan` — Trigger manual security scan
- `pause` — Pause monitoring (max 30 minutes, auto-resume)
- `config-update` — Update config (placeholder)

**3 failed auth attempts = 1 hour lockout + CRITICAL Slack alert.**

## JSON API

LAN-only HTTP API on port 18791. No authentication (firewall-restricted to local network).

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML landing page with links |
| `GET /api/status` | System status, uptime, module states |
| `GET /api/alerts` | Last 100 alerts (JSON array) |
| `GET /api/security` | Alert counts by severity and source |

See [docs/API.md](docs/API.md) for examples.

## Configuration

`config.toml` reference:

```toml
[general]
watched_user = "1000"          # UID of the monitored user (backward compat)
watched_users = ["1000", "1001"]  # Monitor multiple users
watch_all_users = false        # Set true to monitor ALL users
min_alert_level = "warning"
log_file = "/var/log/clawav/watchdog.log"

[slack]
webhook_url = "https://hooks.slack.com/..."    # Independent webhook
backup_webhook_url = "https://hooks.slack.com/..."  # Failover
channel = "#devops"
min_slack_level = "warning"    # Only send warning+ to Slack

[auditd]
log_path = "/var/log/audit/audit.log"
enabled = true

[network]
log_path = "/var/log/syslog"
log_prefix = "OPENCLAWAV_NET"
source = "auto"                # "auto", "journald", or "file"
enabled = true

[falco]
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"

[samhain]
enabled = false
log_path = "/var/log/samhain/samhain.log"

[api]
enabled = true
bind = "0.0.0.0"
port = 18791

[scans]
interval = 3600                # Seconds between periodic scans

[secureclaw]
enabled = false                # Enable SecureClaw pattern databases
vendor_dir = "./vendor/secureclaw/secureclaw/skill/configs"  # Path to pattern files

[policy]
enabled = true
dir = "./policies"
```

## SecureClaw Integration

ClawAV integrates with [SecureClaw](https://github.com/adversa-ai/secureclaw) pattern databases to enhance detection capabilities:

- **Prompt injection patterns** - 70+ regex patterns across 7 categories
- **Dangerous commands** - Command patterns with severity levels and actions
- **Privacy rules** - PII detection with configurable actions (block/warn/rewrite)
- **Supply chain IOCs** - Indicators of compromise for malicious packages/skills

### Setup

```bash
# Add as git submodule (already done if you cloned after integration)
git submodule add https://github.com/adversa-ai/secureclaw.git vendor/secureclaw
git submodule update --init

# Enable in config.toml
[secureclaw]
enabled = true

# Sync patterns (run weekly)
./scripts/sync-secureclaw.sh
```

The security scanner checks if SecureClaw patterns are >7 days old and warns accordingly.

## Testing

```bash
cargo test
```

100 tests covering: policy evaluation, behavior classification, audit chain integrity, aggregator dedup/rate-limiting, API ring buffer, clawsudo enforcement, DLP scanning, scanner parsing, and more.

## Security Model

### What it protects against

| Threat | Defense |
|--------|---------|
| Agent runs `curl` to exfil data | Behavior engine (CRITICAL) + policy engine + clawsudo deny |
| Agent reads `/etc/shadow` | Behavior engine + policy engine + LD_PRELOAD deny |
| Agent disables firewall | Behavior engine + policy engine + clawsudo deny + sudoers restrict |
| Agent kills the watchdog | `Restart=always` + systemd WatchdogSec + sudoers deny |
| Agent modifies watchdog binary | `chattr +i` + AppArmor deny + CAP_LINUX_IMMUTABLE dropped |
| Agent loads kernel module | `kernel.modules_disabled=1` |
| Agent ptraces the watchdog | `yama.ptrace_scope=2` + CAP_SYS_PTRACE dropped |
| Agent tampers with audit trail | Hash chain makes modifications detectable |
| Agent compromises Slack integration | ClawAV uses its own independent webhook |
| PII/secrets leaked via LLM API | DLP proxy scans outbound requests (SSN, credit cards, AWS keys) |
| Side-channel attacks (Spectre, Meltdown) | Kernel mitigation scanner + side-channel tool detection + perf_event_open monitoring |
| Attacks targeting other system users | Multi-user monitoring (`watched_users` list or `watch_all_users = true`) |
| Prompt injection / supply chain attacks | SecureClaw pattern databases (70+ injection patterns, supply chain IOCs) |

### What it does NOT protect against

- **Physical access** — by design, physical access is the recovery path
- **Kernel exploits** — a kernel 0-day could bypass all userspace protections
- **Pre-installation compromise** — ClawAV must be installed from a trusted state

## License

MIT
