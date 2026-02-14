#!/usr/bin/env bash
# ClawAV Swallowed Key Installer
# Once run, ClawAV cannot be stopped/modified without physical access + recovery boot.
# This script self-destructs after successful installation.
set -euo pipefail

SCRIPT_PATH="$(readlink -f "$0")"
BINARY_SRC="$(dirname "$SCRIPT_PATH")/../target/release/clawav"
CONFIG_SRC="$(dirname "$SCRIPT_PATH")/../config.toml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INSTALL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root"
[[ -f "$BINARY_SRC" ]] || die "Binary not found at $BINARY_SRC — run 'cargo build --release' first"
[[ -f "$CONFIG_SRC" ]] || die "Config not found at $CONFIG_SRC"

# ── 1. Create system user ────────────────────────────────────────────────────
log "Creating clawav system user..."
if ! id -u clawav &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin clawav
fi

# ── 2. Install binary and config ─────────────────────────────────────────────
log "Installing binary and config..."
mkdir -p /etc/clawav /var/log/clawav /var/run/clawav
cp "$BINARY_SRC" /usr/local/bin/clawav
chmod 755 /usr/local/bin/clawav
cp "$CONFIG_SRC" /etc/clawav/config.toml
chmod 644 /etc/clawav/config.toml
chown -R clawav:clawav /etc/clawav /var/log/clawav /var/run/clawav
# Allow openclaw group to connect to admin socket dir
chown clawav:openclaw /var/run/clawav
chmod 0750 /var/run/clawav

# ── 3. Install systemd service ───────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/clawav.service <<'EOF'
[Unit]
Description=ClawAV Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=clawav
Group=clawav
ExecStart=/usr/local/bin/clawav --headless /etc/clawav/config.toml
Restart=always
RestartSec=5
WatchdogSec=30
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=true
ReadWritePaths=/var/log/clawav /var/run/clawav /etc/clawav
RuntimeDirectory=clawav
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable clawav

# ── 4. Set immutable attributes ──────────────────────────────────────────────
log "Setting immutable attributes (chattr +i)..."
chattr +i /usr/local/bin/clawav
chattr +i /etc/clawav/config.toml
chattr +i /etc/systemd/system/clawav.service

# ── 5. AppArmor profile ──────────────────────────────────────────────────────
log "Creating AppArmor profile..."
if command -v apparmor_parser &>/dev/null; then
    cat > /etc/apparmor.d/clawav.deny-openclaw <<'APPARMOR'
# AppArmor profile: deny openclaw user access to ClawAV paths
# This is loaded as a hat/profile restricting the openclaw user.

abi <abi/3.0>,

profile clawav.deny-openclaw {
  # Deny openclaw user access to all ClawAV files
  deny /usr/local/bin/clawav rwxmlk,
  deny /etc/clawav/** rwxmlk,
  deny /etc/clawav/ rwxmlk,
  deny /var/log/clawav/** rwxmlk,
  deny /var/log/clawav/ rwxmlk,

  # Allow everything else (this profile is applied to openclaw's shell)
  /** rwxmlk,
}
APPARMOR
    apparmor_parser -r /etc/apparmor.d/clawav.deny-openclaw 2>/dev/null || warn "AppArmor profile load failed (may need reboot)"
else
    warn "AppArmor not available — skipping profile"
fi

# ── 6. Drop capabilities from openclaw user ──────────────────────────────────
log "Dropping dangerous capabilities from openclaw user..."
# capability.conf restricts caps at login
cat > /etc/security/capability.conf <<'CAPCONF'
# Drop dangerous capabilities from openclaw user
!cap_linux_immutable  openclaw
!cap_sys_ptrace       openclaw
!cap_sys_module       openclaw
CAPCONF

# Also ensure pam_cap is in the login stack
if ! grep -q pam_cap /etc/pam.d/common-auth 2>/dev/null; then
    if [ -f /lib/security/pam_cap.so ] || [ -f /lib/aarch64-linux-gnu/security/pam_cap.so ]; then
        echo "auth    optional    pam_cap.so" >> /etc/pam.d/common-auth
    else
        warn "pam_cap.so not found — install libpam-cap for capability restrictions"
    fi
fi

# ── 7. Kernel hardening via sysctl ───────────────────────────────────────────
log "Setting kernel hardening parameters..."
cat > /etc/sysctl.d/99-clawav.conf <<'SYSCTL'
# ClawAV kernel hardening
kernel.modules_disabled = 1
kernel.yama.ptrace_scope = 2
SYSCTL
sysctl -p /etc/sysctl.d/99-clawav.conf 2>/dev/null || warn "Some sysctl params may need reboot"

# ── 8. Restricted sudoers ────────────────────────────────────────────────────
log "Installing sudoers restrictions..."
cat > /etc/sudoers.d/clawav-deny <<'SUDOERS'
# Deny openclaw user from tampering with ClawAV
openclaw ALL=(ALL) !  /usr/bin/systemctl stop clawav, \
                      /usr/bin/systemctl disable clawav, \
                      /usr/bin/systemctl mask clawav, \
                      /usr/bin/chattr -i /usr/local/bin/clawav, \
                      /usr/bin/chattr -i /etc/clawav/*, \
                      /usr/bin/chattr -i /etc/systemd/system/clawav.service, \
                      /usr/sbin/ufw disable, \
                      /usr/sbin/auditctl -e 0, \
                      /usr/sbin/auditctl -e 1
SUDOERS
chmod 0440 /etc/sudoers.d/clawav-deny
# Validate sudoers
visudo -cf /etc/sudoers.d/clawav-deny || die "Invalid sudoers file!"
chattr +i /etc/sudoers.d/clawav-deny

# ── 9. Lock audit rules ─────────────────────────────────────────────────────
log "Locking audit rules (immutable until reboot)..."
if command -v auditctl &>/dev/null; then
    auditctl -e 2 2>/dev/null || warn "Audit rules may already be locked"
else
    warn "auditctl not available — skipping audit lock"
fi

# ── 10. Start the service ────────────────────────────────────────────────────
log "Starting ClawAV service..."
systemctl start clawav || warn "Service start failed — check 'journalctl -u clawav'"

# ── 11. Self-destruct ────────────────────────────────────────────────────────
log "Installation complete!"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ClawAV installed and hardened.                         ║${NC}"
echo -e "${GREEN}║  The swallowed key is now in effect.                        ║${NC}"
echo -e "${GREEN}║                                                             ║${NC}"
echo -e "${GREEN}║  To modify: physical access + recovery boot required.       ║${NC}"
echo -e "${GREEN}║  Admin key will be displayed on first service run.          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── 12. Build and install LD_PRELOAD guard ────────────────────────────────
log "Building and installing LD_PRELOAD syscall interception..."
PRELOAD_SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
if [ -f "$PRELOAD_SCRIPT_DIR/build-preload.sh" ]; then
    bash "$PRELOAD_SCRIPT_DIR/build-preload.sh"
    bash "$PRELOAD_SCRIPT_DIR/enable-preload.sh"
else
    warn "build-preload.sh not found — skipping LD_PRELOAD guard"
fi

log "Self-destructing installer..."
rm -f "$SCRIPT_PATH"
log "Done. Installer deleted."
