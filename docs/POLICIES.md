# Policy Writing Guide

ClawAV has two policy systems:

1. **Policy Engine** (`src/policy.rs`) — evaluates auditd events in real-time, generates alerts
2. **clawsudo policies** (`src/bin/clawsudo.rs`) — gates privileged commands with allow/deny/ask enforcement

Both use the same YAML format but clawsudo adds an `enforcement` field.

## YAML Schema

```yaml
rules:
  - name: "rule-name"              # Required. Unique identifier.
    description: "what it does"     # Optional. Human-readable description.
    match:                          # Required. At least one match type.
      command: []                   # Exact binary name match (basename)
      command_contains: []          # Substring match against full command
      file_access: []               # Glob patterns for file paths
      exclude_args: []              # Whitelist — skip match if any appear in args
    action: "critical"              # Required. Severity: "info", "warning", "critical"
    enforcement: "deny"             # Optional (clawsudo only): "allow", "deny", "ask"
```

## Match Types

### `command` — Exact binary name

Matches the basename of the first argument (e.g., `/usr/bin/curl` → `curl`). Case-insensitive.

```yaml
match:
  command: ["curl", "wget", "nc"]
```

### `command_contains` — Substring match

Matches if any pattern appears as a substring of the full command string. Case-insensitive.

```yaml
match:
  command_contains: ["ufw disable", "iptables -F", "systemctl stop auditd"]
```

### `file_access` — Glob patterns

Matches file paths from auditd events (the `name=` field, or arguments starting with `/`). Uses [glob-match](https://crates.io/crates/glob-match) syntax.

```yaml
match:
  file_access: ["/etc/shadow", "/etc/sudoers.d/*", "**/.env", "**/.ssh/id_rsa"]
```

### `exclude_args` — Whitelist

If any of these strings appear in the command or arguments (case-insensitive), the rule does NOT match. Use this to whitelist known-good destinations.

```yaml
match:
  command: ["curl", "wget"]
  exclude_args: ["api.anthropic.com", "api.openai.com", "github.com"]
```

## Action Levels

| Action | Severity | Description |
|--------|----------|-------------|
| `info` | Info | Logged, shown in TUI. Not sent to Slack by default. |
| `warning` | Warning | Sent to Slack (if `min_slack_level` is "warning"). Yellow in TUI. |
| `critical` / `block` | Critical | Always sent to Slack. Red in TUI. Never rate-limited by aggregator. |

## Enforcement Modes (clawsudo only)

| Mode | Behavior |
|------|----------|
| `allow` | Execute immediately via `sudo` |
| `deny` | Block with exit code 77. Send CRITICAL alert to Slack. |
| `ask` | Notify Slack, wait up to 5 minutes for approval (`touch /tmp/clawsudo-<hash>.approved`) |

If `enforcement` is not set, clawsudo infers from `action`: `critical`/`block` → deny, everything else → ask.

## Evaluation Order

**Policy engine:** All rules are evaluated. The highest-severity match wins. If multiple rules match at the same severity, the first match wins.

**clawsudo:** First matching rule wins (short-circuit). If no rule matches, the command enters `ask` mode. If no policy files exist at all, ALL commands are denied (fail-secure).

## Policy File Locations

**Policy engine** loads from (both directories, merged):
- `./policies/` (relative to working directory)
- `/etc/clawav/policies/` (system-installed)

**clawsudo** loads from:
- `/etc/clawav/policies/`
- `./policies/`

## Built-in Policy Files

### `policies/default.yaml` — Monitoring rules

These generate alerts but don't block anything:

| Rule | Matches | Action |
|------|---------|--------|
| `block-data-exfiltration` | curl, wget, nc, ncat, netcat, socat (excluding known APIs) | critical |
| `deny-shadow-read` | /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/* | critical |
| `deny-sensitive-write` | /etc/passwd, /etc/hosts, /etc/crontab, /etc/shadow | critical |
| `deny-firewall-changes` | ufw disable, iptables -F, systemctl stop apparmor, etc. | critical |
| `recon-detection` | whoami, id, uname, env, printenv, hostname, ifconfig | warning |
| `recon-sensitive-files` | **/.env, **/.aws/credentials, **/.ssh/id_rsa, etc. | warning |

### `policies/clawsudo.yaml` — Enforcement rules

| Rule | Matches | Enforcement |
|------|---------|-------------|
| `allow-apt` | apt, apt-get | allow |
| `allow-docker` | docker, docker-compose | allow |
| `allow-systemctl-openclaw` | systemctl restart openclaw, systemctl status | allow |
| `deny-clawav-tamper` | clawav, /etc/clawav, chattr, auditctl -e/-D | deny |
| `deny-firewall-disable` | ufw disable, iptables -F, nft flush | deny |
| `deny-raw-shell` | bash, sh, zsh, dash | deny |
| `deny-dangerous-rm` | rm -rf /etc, rm -rf /usr, rm -rf /var, rm -rf / | deny |

## Adding Custom Rules

Create a new `.yaml` file in the policies directory:

```yaml
# policies/custom.yaml
rules:
  - name: "alert-on-docker-run"
    description: "Flag new container launches"
    match:
      command_contains: ["docker run", "docker exec"]
    action: warning

  - name: "block-outbound-to-pastebin"
    description: "Block data exfil to paste sites"
    match:
      command_contains: ["pastebin.com", "paste.ee", "hastebin.com"]
    action: critical

  - name: "allow-git"
    description: "Let agent use git freely"
    match:
      command: ["git"]
    action: info
    enforcement: allow  # clawsudo only
```

Rules from all `.yaml`/`.yml` files in the policy directories are merged. No restart required for the policy engine (files are loaded at startup), but clawsudo re-reads on each invocation.
