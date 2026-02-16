# Tier 3 Hardening — Based on Red Lobster v3 Findings

**Goal:** Fix remaining bypasses. Target 6/6 flags defended in Red Lobster v4.

**Current score:** 2/6 defended (BLIND ✅, TAMPER ✅), 2/6 partial (ESCALATE, EXFIL), 2/6 bypassed (PERSIST, ESCAPE)

---

## Priority Order (by impact)

### T3.1: Real-Time Persistence Monitoring ⭐ PERSIST flag fix
**Problem:** `scan_user_persistence()` works but runs on 3600s interval — attacker plants and cleans up within window.
**Fix:** Add sentinel file watches on persistence paths:
- `~/.config/systemd/user/` (recursive)
- `~/.bashrc`, `~/.profile`, `~/.bash_login`, `~/.bash_logout`
- `~/.config/autostart/`
- `~/.ssh/rc`, `~/.ssh/environment`
- `~/.npmrc`
- `.git/hooks/` in workspace

On any change → immediate alert (not waiting for scan cycle). Use existing sentinel infrastructure with `WatchPolicy::Watched`.

Also reduce scan interval from 3600s → 300s for persistence checks specifically.

**Files:** `src/config.rs` (add persistence watch paths to sentinel defaults), `src/sentinel.rs`

### T3.2: Script File Network Detection ⭐ ESCAPE + EXFIL flag fix
**Problem:** `python3 script.py` and `node script.js` making HTTP requests are invisible (only `-c`/`-e` caught).
**Fix:** Two approaches:
1. **auditd connect() syscall monitoring** — catches ALL outbound connections regardless of tool:
   ```
   -a always,exit -F arch=b64 -S connect -F uid=1000 -k clawav_net_connect
   ```
   Parse in auditd.rs, extract destination, feed to netpolicy allowlist.
   Filter out: loopback, LAN, known OpenClaw endpoints.

2. **Script file execution tracking** — when python3/node/perl/ruby execute a .py/.js/.pl/.rb file, flag as Warning (execution of script files by network-capable runtimes).

**Files:** `src/auditd.rs`, `src/behavior.rs`, `scripts/setup-auditd.sh`

### T3.3: Safe-Host Allowlist Tightening ⭐ ESCAPE flag fix
**Problem:** `amazonaws.com` is too broad — attacker can exfil to their own S3 bucket.
**Fix:**
- Replace `amazonaws.com` with specific subdomains: `ssm.us-east-1.amazonaws.com`, `s3.us-east-1.amazonaws.com` (only our region)
- Or better: switch to exact endpoint matching for AWS
- Remove any other overly broad entries
- Add `curl` header/param inspection: flag if data is being sent TO a safe host (POST with body, custom headers with file content)

**Files:** `src/behavior.rs` (SAFE_HOSTS constant)

### T3.4: Sentinel Auto-Restore on Deletion ⭐ TAMPER defense-in-depth
**Problem:** fd unlink trick deletes cognitive files; sentinel doesn't restore deleted files.
**Fix:** In sentinel watch loop, detect `Remove` events. If a Protected/Watched file is deleted:
1. Restore from shadow copy
2. Re-establish the watch
3. Fire CRIT alert

**Files:** `src/sentinel.rs`

### T3.5: Shadow/Quarantine Permission Hardening
**Problem:** `/etc/clawav/sentinel-shadow/` and `/etc/clawav/quarantine/` are world-readable — info leak.
**Fix:** `chmod 700` on both directories in install.sh/oneshot-install.sh. Only root (clawav process) needs access.

**Files:** `scripts/install.sh`, `scripts/oneshot-install.sh`

### T3.6: Docker Group Detection (Scanner)
**Problem:** openclaw in docker group = instant root. Currently just relies on manual removal.
**Fix:** Add to scanner: check if watched user is in docker/lxd/disk/adm groups → CRIT alert.
Already have `scan_user_account_audit()` — extend it.

**Files:** `src/scanner.rs`

### T3.7: ICMP/Ping Exfil Detection
**Problem:** `ping -p` with encoded data bypasses network monitoring.
**Fix:** Add `ping` to behavior watchlist when used with `-p` (pattern) flag.

**Files:** `src/behavior.rs`

### T3.8: Git Push Monitoring
**Problem:** `git push` to attacker repo is unmonitored — can exfil entire repos.
**Fix:** Add `git` with `push`/`remote add` subcommands to behavior detection.

**Files:** `src/behavior.rs`

---

## Implementation Order

1. T3.1 (persistence watches) — highest impact, fixes PERSIST flag
2. T3.2 (connect() syscall) — fixes ESCAPE + EXFIL flags
3. T3.3 (safe-host tightening) — quick win for ESCAPE
4. T3.4 (delete restore) — defense-in-depth for TAMPER
5. T3.5 (permissions) — quick fix
6. T3.6 (docker group check) — quick fix for ESCALATE
7. T3.7 (ping -p) — minor
8. T3.8 (git push) — minor

## Estimated Effort
- T3.1-T3.3: ~2 hours (core fixes)
- T3.4-T3.8: ~1 hour (quick wins)
- Testing + Red Lobster v4: ~30 min
