# Installation Guide

## Prerequisites

- **Rust** (stable toolchain) — for building
- **gcc** — for building `libclawguard.so`
- **auditd** — kernel audit framework (`apt install auditd`)
- **ufw** — firewall (`apt install ufw`)
- **AppArmor** (optional but recommended) — MAC profiles
- **libpam-cap** (optional) — for capability restriction via PAM

## Pre-Install Checklist

1. **Build the release binary:**
   ```bash
   cargo build --release
   ```
   Binary will be at `target/release/clawav`

2. **Build the LD_PRELOAD library:**
   ```bash
   bash scripts/build-preload.sh
   ```
   Creates `libclawguard.so` in the project root

3. **Configure `config.toml`:**
   - Set `watched_user` to the UID of your AI agent user
   - Set `slack.webhook_url` to an **independent** Slack webhook (not the agent's)
   - Optionally set `slack.backup_webhook_url` for failover

4. **Ensure auditd is running:**
   ```bash
   sudo systemctl status auditd
   ```

5. **Ensure ufw is active:**
   ```bash
   sudo ufw status
   ```

## Installation

```bash
sudo bash scripts/install.sh
```

### What install.sh Does (Step by Step)

**Step 1 — Create system user:**
```bash
useradd --system --no-create-home --shell /usr/sbin/nologin clawav
```

**Step 2 — Install binary and config:**
- Copies binary to `/usr/local/bin/clawav` (mode 755)
- Copies config to `/etc/clawav/config.toml` (mode 644)
- Creates `/var/log/clawav/` and `/var/run/clawav/`
- Sets ownership: `clawav:clawav` (except `/var/run/clawav/` → `clawav:openclaw` mode 0750)

**Step 3 — Install systemd service:**
Creates `/etc/systemd/system/clawav.service` with:
- `Restart=always`, `RestartSec=5`
- `WatchdogSec=30` (systemd kills and restarts if watchdog not fed)
- `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=true`
- `ReadWritePaths=/var/log/clawav /var/run/clawav /etc/clawav`
- Runs as user `clawav` in `--headless` mode

**Step 4 — Set immutable attributes:**
```bash
chattr +i /usr/local/bin/clawav
chattr +i /etc/clawav/config.toml
chattr +i /etc/systemd/system/clawav.service
```
After this, even root cannot modify these files without first removing the immutable flag — and the agent's `CAP_LINUX_IMMUTABLE` is stripped in step 6.

**Step 5 — AppArmor profile:**
Creates `/etc/apparmor.d/clawav.deny-openclaw` which denies the `openclaw` user access to:
- `/usr/local/bin/clawav`
- `/etc/clawav/**`
- `/var/log/clawav/**`

**Step 6 — Drop capabilities:**
Writes `/etc/security/capability.conf`:
```
!cap_linux_immutable  openclaw
!cap_sys_ptrace       openclaw
!cap_sys_module       openclaw
```
Adds `pam_cap.so` to `/etc/pam.d/common-auth` if available.

**Step 7 — Kernel hardening:**
Creates `/etc/sysctl.d/99-clawav.conf`:
```
kernel.modules_disabled = 1
kernel.yama.ptrace_scope = 2
```
- `modules_disabled=1` — prevents loading kernel modules (irreversible until reboot)
- `ptrace_scope=2` — only root can ptrace (prevents debugging the watchdog)

**Step 8 — Restricted sudoers:**
Creates `/etc/sudoers.d/clawav-deny` denying the `openclaw` user from running:
- `systemctl stop/disable/mask clawav`
- `chattr -i` on any ClawAV files
- `ufw disable`
- `auditctl -e 0` or `auditctl -e 1`

The sudoers file itself is made immutable with `chattr +i`.

**Step 9 — Lock audit rules:**
```bash
auditctl -e 2
```
Makes audit rules immutable until next reboot.

**Step 10 — Start the service.**

**Step 11 — Build and install LD_PRELOAD guard:**
Runs `build-preload.sh` and `enable-preload.sh`:
- Compiles `libclawguard.so` and installs to `/usr/local/lib/clawav/`
- Creates default preload policy at `/etc/clawav/preload-policy.json`
- Adds `Environment=LD_PRELOAD=...` to the systemd service
- Makes `libclawguard.so` immutable

**Step 12 — Self-destruct:**
```bash
rm -f "$SCRIPT_PATH"
```

## Post-Install Verification

```bash
# Check service is running
sudo systemctl status clawav

# Check logs
sudo journalctl -u clawav -f

# Verify immutable flags
lsattr /usr/local/bin/clawav
# Should show: ----i---------e------- /usr/local/bin/clawav

# Test the API
curl http://localhost:18791/api/status

# Verify audit chain
/usr/local/bin/clawav verify-audit
```

## ⚠️ The Admin Key — SAVE IT!

On first run, the service prints a 256-bit admin key to its log output:

```
OCAV-<64 hex characters>
```

**This key is shown exactly once.** It's stored only as an Argon2 hash in `/etc/clawav/admin.key.hash`. You need this key to:
- Check watchdog status remotely
- Trigger manual scans
- Temporarily pause monitoring (max 30 min)

Check `journalctl -u clawav` immediately after install to capture it.

## Recovery Procedure

To modify ClawAV after installation:

1. **Reboot into recovery mode** (physical access required)
2. Mount filesystem read-write
3. Remove immutable flags: `chattr -i /usr/local/bin/clawav /etc/clawav/config.toml /etc/systemd/system/clawav.service`
4. Make changes
5. Re-apply immutable flags: `chattr +i ...`
6. Reboot normally

This is by design — the "swallowed key" pattern means no software-only path can modify the watchdog.

## Uninstall

Requires physical access + recovery boot:

```bash
# In recovery mode:
chattr -i /usr/local/bin/clawav
chattr -i /etc/clawav/config.toml
chattr -i /etc/systemd/system/clawav.service
chattr -i /etc/sudoers.d/clawav-deny
chattr -i /usr/local/lib/clawav/libclawguard.so

systemctl stop clawav
systemctl disable clawav
rm /etc/systemd/system/clawav.service
rm /usr/local/bin/clawav
rm -rf /etc/clawav
rm -rf /var/log/clawav
rm -rf /var/run/clawav
rm /etc/sudoers.d/clawav-deny
rm /etc/apparmor.d/clawav.deny-openclaw
rm /etc/sysctl.d/99-clawav.conf
rm /etc/security/capability.conf
rm -rf /usr/local/lib/clawav

userdel clawav
systemctl daemon-reload

# Revert sysctl (will take effect on next boot):
# Remove kernel.modules_disabled and ptrace_scope from sysctl
```
