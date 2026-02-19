#!/usr/bin/env bash
# ClawTower Setup Script — One-shot install
#
# Usage:
#   sudo bash scripts/setup.sh                    # Install pre-built binaries
#   sudo bash scripts/setup.sh --source           # Build from source + install
#   sudo bash scripts/setup.sh --source --auto    # Full unattended: build + install + start
#
# Reversible. Run `clawtower harden` to lock down, `clawtower uninstall` to remove.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_FROM_SOURCE=false
AUTO_START=false

for arg in "$@"; do
    case "$arg" in
        --source|--build|--from-source)  BUILD_FROM_SOURCE=true ;;
        --auto)                          AUTO_START=true ;;
        --help|-h)
            echo "Usage: sudo bash setup.sh [OPTIONS]"
            echo ""
            echo "  (default)        Install pre-built binaries from target/release/"
            echo "  --source         Build from source (installs Rust if needed)"
            echo "  --auto           Start the service automatically after install"
            echo "  --source --auto  Full unattended: build + install + start"
            echo ""
            exit 0
            ;;
        *) echo "Unknown flag: $arg (try --help)" >&2; exit 1 ;;
    esac
done

# ── Terminal UI ──────────────────────────────────────────────────────────────
if [[ -t 1 ]] || [[ -t 2 ]] || [[ -n "${FORCE_COLOR:-}" ]]; then
    RED='\033[38;5;167m'
    GREEN='\033[38;5;108m'
    AMBER='\033[38;5;179m'
    YELLOW='\033[38;5;179m'
    CYAN='\033[38;5;109m'
    DIM='\033[2m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' AMBER='' YELLOW='' CYAN='' DIM='' BOLD='' NC=''
fi

TERM_WIDTH=$(tput cols 2>/dev/null || echo 72)
[[ "$TERM_WIDTH" -gt 80 ]] && TERM_WIDTH=80

log()  { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${AMBER}▲${NC} $*"; }
info() { echo -e "  ${DIM}·${NC} ${DIM}$*${NC}"; }
die()  { echo -e "\n  ${RED}✗ $*${NC}\n" >&2; exit 1; }

header() {
    local title="$1" subtitle="${2:-}"
    local line
    line=$(printf '─%.0s' $(seq 1 $((TERM_WIDTH - 6))))
    echo ""
    printf "  ${AMBER}╭─${NC} ${BOLD}%s${NC}\n" "$title"
    [[ -n "$subtitle" ]] && printf "  ${AMBER}│${NC}  ${DIM}%s${NC}\n" "$subtitle"
    echo -e "  ${AMBER}╰${line}${NC}"
    echo ""
}

sep() {
    local line
    line=$(printf '─%.0s' $(seq 1 $((TERM_WIDTH - 4))))
    echo -e "  ${DIM}${line}${NC}"
}

if $BUILD_FROM_SOURCE; then
    header "ClawTower Setup" "Mode: build from source"
else
    header "ClawTower Setup" "Mode: install pre-built binaries"
fi
echo -e "  ${DIM}Reversible — use 'clawtower uninstall' to remove.${NC}"
echo ""

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must run as root (sudo bash scripts/setup.sh)"

CLAWTOWER_BIN="$PROJECT_DIR/target/release/clawtower"
CLAWSUDO_BIN="$PROJECT_DIR/target/release/clawsudo"

# ── Build from source (if requested) ─────────────────────────────────────────
if $BUILD_FROM_SOURCE; then
    log "Checking system dependencies..."
    if command -v apt-get &>/dev/null; then
        NEEDED=""
        command -v gcc &>/dev/null || NEEDED="$NEEDED build-essential"
        command -v pkg-config &>/dev/null || NEEDED="$NEEDED pkg-config"
        dpkg -l libssl-dev &>/dev/null 2>&1 || NEEDED="$NEEDED libssl-dev"
        command -v git &>/dev/null || NEEDED="$NEEDED git"
        command -v auditctl &>/dev/null || NEEDED="$NEEDED auditd"
        if [[ -n "$NEEDED" ]]; then
            log "Installing:$NEEDED"
            apt-get update -qq && apt-get install -y -qq $NEEDED
        fi
    elif command -v dnf &>/dev/null; then
        NEEDED=""
        command -v gcc &>/dev/null || NEEDED="$NEEDED gcc"
        command -v pkg-config &>/dev/null || NEEDED="$NEEDED pkg-config"
        command -v git &>/dev/null || NEEDED="$NEEDED git"
        command -v auditctl &>/dev/null || NEEDED="$NEEDED audit"
        [[ -z "$NEEDED" ]] || dnf install -y -q $NEEDED openssl-devel
    elif command -v pacman &>/dev/null; then
        command -v gcc &>/dev/null || pacman -S --noconfirm base-devel
        command -v git &>/dev/null || pacman -S --noconfirm git
    fi

    # Find or install Rust
    export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
    for USER_HOME in /home/*/; do
        [[ -f "${USER_HOME}.cargo/bin/cargo" ]] && export PATH="${USER_HOME}.cargo/bin:$PATH"
    done

    if ! command -v cargo &>/dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>&1 | tail -3
        source "$HOME/.cargo/env" 2>/dev/null || true
        export PATH="$HOME/.cargo/bin:$PATH"
        command -v cargo &>/dev/null || die "Rust installation failed"
    else
        cargo --version &>/dev/null 2>&1 || { rustup default stable 2>/dev/null || rustup toolchain install stable && rustup default stable; }
    fi
    info "Rust: $(rustc --version 2>/dev/null)"

    log "Building ClawTower (this takes ~1 min on Pi, ~10s on desktop)..."
    cd "$PROJECT_DIR"
    cargo build --release 2>&1 | tail -5
    [[ -f "$CLAWTOWER_BIN" ]] || die "Build failed"
    info "Built: clawtower ($(du -h "$CLAWTOWER_BIN" | cut -f1)), clawsudo ($(du -h "$CLAWSUDO_BIN" | cut -f1))"
else
    [[ -f "$CLAWTOWER_BIN" ]] || die "Binary not found at $CLAWTOWER_BIN — build first or use --source"
    info "Using pre-built: clawtower ($(du -h "$CLAWTOWER_BIN" | cut -f1)), clawsudo ($(du -h "$CLAWSUDO_BIN" | cut -f1))"
fi

# ── Install auditd ───────────────────────────────────────────────────────────
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..."
    command -v apt-get &>/dev/null && apt-get update -qq && apt-get install -y -qq auditd
    command -v dnf &>/dev/null && dnf install -y -q audit
fi

# ── Create directories ───────────────────────────────────────────────────────
log "Creating directories..."
mkdir -p /etc/clawtower/policies /var/log/clawtower /var/run/clawtower
mkdir -p /etc/clawtower/shadow /etc/clawtower/sentinel-shadow /etc/clawtower/quarantine
# Ensure agent user can read logs and write to runtime dir
chown -R "${SUDO_USER:-root}:${SUDO_USER:-root}" /var/log/clawtower /var/run/clawtower 2>/dev/null || true

# Harden shadow and quarantine directories (root-only access)
log "Hardening shadow/quarantine permissions..."
chown root:root /etc/clawtower/shadow /etc/clawtower/sentinel-shadow /etc/clawtower/quarantine 2>/dev/null || true
chmod 0700 /etc/clawtower/shadow /etc/clawtower/sentinel-shadow /etc/clawtower/quarantine
# Harden any existing shadow files
find /etc/clawtower/shadow /etc/clawtower/sentinel-shadow -type f -exec chmod 0600 {} \; 2>/dev/null || true

# ── Stop existing service (avoid "Text file busy") ───────────────────────────
if systemctl is-active --quiet clawtower 2>/dev/null; then
    log "Stopping existing ClawTower service..."
    systemctl stop clawtower
    sleep 1
fi

# ── Install binaries ─────────────────────────────────────────────────────────
log "Installing binaries..."
rm -f /usr/local/bin/clawtower /usr/local/bin/clawsudo
cp "$CLAWTOWER_BIN" /usr/local/bin/clawtower
cp "$CLAWSUDO_BIN" /usr/local/bin/clawsudo
chmod 755 /usr/local/bin/clawtower /usr/local/bin/clawsudo

# ── Install config (preserve existing) ───────────────────────────────────────
if [[ -f /etc/clawtower/config.toml ]]; then
    warn "Config exists — keeping /etc/clawtower/config.toml"
else
    log "Installing default config..."
    cp "$PROJECT_DIR/config.toml" /etc/clawtower/config.toml
fi
chmod 644 /etc/clawtower/config.toml

# ── Install policies ─────────────────────────────────────────────────────────
if [[ -d "$PROJECT_DIR/policies" ]]; then
    log "Installing policy files..."
    cp "$PROJECT_DIR/policies/"*.yaml /etc/clawtower/policies/ 2>/dev/null || true
fi

# ── Build LD_PRELOAD guard (source mode only) ────────────────────────────────
if $BUILD_FROM_SOURCE && [[ -f "$SCRIPT_DIR/build-preload.sh" ]]; then
    log "Building LD_PRELOAD guard..."
    bash "$SCRIPT_DIR/build-preload.sh" 2>/dev/null && info "LD_PRELOAD guard built" || warn "LD_PRELOAD build failed (optional)"
fi

# ── Install BarnacleDefense pattern databases ────────────────────────────────
log "Installing BarnacleDefense pattern databases..."
BARNACLE_DIR="/etc/clawtower/barnacle"
mkdir -p "$BARNACLE_DIR"
if [[ -d "$PROJECT_DIR/patterns/barnacle" ]]; then
    cp "$PROJECT_DIR/patterns/barnacle/"*.json "$BARNACLE_DIR/" 2>/dev/null && info "BarnacleDefense: pattern databases installed" || warn "BarnacleDefense pattern copy failed (optional)"
fi

# ── Install systemd service ──────────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/clawtower.service <<'EOF'
[Unit]
Description=ClawTower Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawtower run --headless /etc/clawtower/config.toml
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=15
NoNewPrivileges=true
ReadWritePaths=/var/log/clawtower /var/run/clawtower /etc/clawtower
RuntimeDirectory=clawtower
RuntimeDirectoryMode=0750
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable clawtower

# ── Set up auditd rules ──────────────────────────────────────────────────────
if command -v auditctl &>/dev/null && [[ -f "$SCRIPT_DIR/setup-auditd.sh" ]]; then
    log "Setting up auditd rules..."
    bash "$SCRIPT_DIR/setup-auditd.sh" 2>/dev/null || warn "Auditd setup had issues"
fi

# ── Auto-start ────────────────────────────────────────────────────────────────
if $AUTO_START; then
    log "Starting ClawTower..."
    systemctl restart clawtower
    sleep 2
    if systemctl is-active --quiet clawtower; then
        info "✅ ClawTower is running!"
        echo ""
        journalctl -u clawtower -n 10 --no-pager 2>/dev/null || true
    else
        warn "Service failed to start — check: journalctl -u clawtower -n 20"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
header "ClawTower setup complete"

echo -e "  ${BOLD}Commands${NC}"
echo -e "    ${DIM}clawtower help${NC}             Show all commands"
echo -e "    ${DIM}clawtower configure${NC}        Set up Slack, users, modules"
echo -e "    ${DIM}clawtower scan${NC}             Quick security scan"
echo -e "    ${DIM}clawtower status${NC}           Service status + alerts"
echo -e "    ${DIM}clawtower tui${NC}              Interactive dashboard"
echo -e "    ${DIM}clawtower logs${NC}             Tail live logs"
echo ""
sep
echo ""
echo -e "  ${BOLD}Next steps${NC}"
echo -e "    ${DIM}1.${NC} clawtower configure              ${DIM}Set your Slack webhook${NC}"
echo -e "    ${DIM}2.${NC} sudo systemctl start clawtower   ${DIM}Start monitoring${NC}"
echo -e "    ${DIM}3.${NC} clawtower scan                   ${DIM}Verify security posture${NC}"
echo ""
echo -e "  ${BOLD}Optional${NC}"
echo -e "    ${DIM}clawtower harden${NC}           Lock down ${DIM}(admin key required)${NC}"
echo -e "    ${DIM}clawtower uninstall${NC}        Remove ${DIM}(admin key required)${NC}"
echo ""
