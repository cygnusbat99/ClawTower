#!/usr/bin/env bash
# ClawTower Oneshot Installer — Interactive guided install
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh | sudo bash -s -- --version v0.3.1b
#   curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh | sudo bash -s -- --update
#
set -euo pipefail

REPO="ClawTower/ClawTower"
VERSION="latest"
MODE="install"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --update)   MODE="update"; shift ;;
        --version)  VERSION="$2"; shift 2 ;;
        -*)         echo "Unknown flag: $1" >&2; exit 1 ;;
        *)          VERSION="$1"; shift ;;
    esac
done

# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
HAS_BINARY=false; [[ -f /usr/local/bin/clawtower ]] && HAS_BINARY=true
HAS_CONFIG=false; [[ -f /etc/clawtower/config.toml || -f /etc/clawav/config.toml ]] && HAS_CONFIG=true
HAS_KEY=false;    [[ -f /etc/clawtower/admin.key.hash || -f /etc/clawav/admin.key.hash ]] && HAS_KEY=true
HAD_ADMIN_KEY="$HAS_KEY"

if [[ "$HAS_BINARY" == true && "$HAS_CONFIG" == true && "$HAS_KEY" == true ]]; then
    EXISTING_INSTALL=true
elif [[ "$HAS_BINARY" == true || "$HAS_CONFIG" == true || "$HAS_KEY" == true ]]; then
    EXISTING_INSTALL=partial
else
    EXISTING_INSTALL=false
fi

# Route --update to interactive detection
if [[ "$MODE" == "update" ]]; then
    if [[ "$EXISTING_INSTALL" == true ]]; then
        MODE="upgrade"
    else
        echo -e "\n  \033[38;5;167m✗ ClawTower not fully installed. Run without --update for fresh install.\033[0m\n" >&2
        exit 1
    fi
fi

# ── Terminal UI ──────────────────────────────────────────────────────────────
# 256-color palette with graceful fallback
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

# Section header with rounded border
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

# Danger header — red accent
danger_header() {
    local title="$1" subtitle="${2:-}"
    local line
    line=$(printf '─%.0s' $(seq 1 $((TERM_WIDTH - 6))))
    echo ""
    printf "  ${RED}╭─${NC} ${RED}${BOLD}%s${NC}\n" "$title"
    [[ -n "$subtitle" ]] && printf "  ${RED}│${NC}  ${DIM}%s${NC}\n" "$subtitle"
    echo -e "  ${RED}╰${line}${NC}"
    echo ""
}

# Phase progress bar
phase_bar() {
    local current=$1; shift
    local phases=("$@")
    local i=0
    echo -n "  "
    for p in "${phases[@]}"; do
        if [[ $i -lt $((current - 1)) ]]; then
            echo -en "${GREEN}●${NC} ${DIM}${p}${NC}"
        elif [[ $i -eq $((current - 1)) ]]; then
            echo -en "${AMBER}●${NC} ${BOLD}${p}${NC}"
        else
            echo -en "${DIM}○ ${p}${NC}"
        fi
        [[ $i -lt $((${#phases[@]} - 1)) ]] && echo -en "  ${DIM}─${NC}  "
        ((i++))
    done
    echo -e "\n"
}

# Separator
sep() {
    local line
    line=$(printf '─%.0s' $(seq 1 $((TERM_WIDTH - 4))))
    echo -e "  ${DIM}${line}${NC}"
}

confirm() {
    local prompt="$1"
    local response
    while true; do
        echo -en "  ${AMBER}▸${NC} ${prompt} " > /dev/tty
        read -r response < /dev/tty
        case "$response" in
            [yY]|[yY][eE][sS]) return 0 ;;
            [nN]|[nN][oO]) return 1 ;;
            *) echo -e "    ${DIM}Please answer yes or no.${NC}" > /dev/tty ;;
        esac
    done
}

wait_for_enter() {
    echo -en "  ${AMBER}▸${NC} $1" > /dev/tty
    read -r < /dev/tty
}

[[ $EUID -eq 0 ]] || die "Must run as root (pipe to sudo bash, or run with sudo)"

# ═══════════════════════════════════════════════════════════════════════════════
# SUDOERS INSTALL FUNCTION (shared between fresh install and upgrade)
# ═══════════════════════════════════════════════════════════════════════════════
install_sudoers_allowlist() {
    local agent_user="$1"
    [[ -z "$agent_user" ]] && return 0

    log "Installing Tier 1 hardened sudoers for '$agent_user'..."

    # Remove old deny-list approach if present
    if [[ -f /etc/sudoers.d/clawtower-deny ]]; then
        chattr -i /etc/sudoers.d/clawtower-deny 2>/dev/null || true
        rm -f /etc/sudoers.d/clawtower-deny
        log "Removed old clawtower-deny (consolidated into hardened sudoers)"
    fi

    # Remove old allowlist if present
    if [[ -f /etc/sudoers.d/010_pi-nopasswd ]]; then
        chattr -i /etc/sudoers.d/010_pi-nopasswd 2>/dev/null || true
        rm -f /etc/sudoers.d/010_pi-nopasswd
        log "Removed old 010_pi-nopasswd (replaced by hardened sudoers)"
    fi

    local POLICY_FILE="/etc/sudoers.d/010_openclaw"
    chattr -i "$POLICY_FILE" 2>/dev/null || true

    # Use the hardened template from policies/, substituting agent username
    local SUDOERS_TEMPLATE
    SUDOERS_TEMPLATE="$(dirname "$(realpath "$0")")/../policies/sudoers-openclaw.conf"
    if [[ -f "$SUDOERS_TEMPLATE" ]]; then
        sed "s/^openclaw /${agent_user} /g" "$SUDOERS_TEMPLATE" > "$POLICY_FILE"
    else
        # Inline fallback — hardened Tier 1 sudoers
        cat > "$POLICY_FILE" << POLICYEOF
# ClawTower-hardened sudoers for OpenClaw agent
# Generated by ClawTower installer — do not edit manually

# Read-only system inspection (no shell escape risk)
${agent_user} ALL=(ALL) NOPASSWD: /usr/bin/cat, /usr/bin/ls, /usr/bin/head, /usr/bin/tail, /usr/bin/grep, /usr/bin/find, /usr/bin/stat, /usr/bin/wc, /usr/bin/diff, /usr/bin/file, /usr/bin/readlink, /usr/bin/getent, /usr/bin/id, /usr/bin/whoami, /usr/bin/test, /usr/bin/sort, /usr/bin/uniq, /usr/bin/tr, /usr/bin/cut, /usr/bin/md5sum, /usr/bin/sha256sum, /usr/bin/strings

# System monitoring (read-only, no shell escape)
${agent_user} ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /usr/bin/dmesg, /usr/bin/ss, /usr/sbin/lsof, /usr/bin/lsof, /usr/bin/df, /usr/bin/du, /usr/bin/free, /usr/bin/uptime, /usr/bin/ps, /usr/bin/ip, /usr/sbin/ip

# Systemctl — status/start/restart only (no stop/disable/mask, no systemd-run)
${agent_user} ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/systemctl is-active *, /usr/bin/systemctl show *, /usr/bin/systemctl list-units *, /usr/bin/systemctl list-timers *, /usr/bin/systemctl start *, /usr/bin/systemctl restart *, /usr/bin/systemctl enable *, /usr/bin/systemctl daemon-reload

# Package management (apt has no shell escape)
${agent_user} ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg, /usr/bin/apt-cache

# All other privileged operations go through clawsudo
${agent_user} ALL=(ALL) NOPASSWD: /usr/local/bin/clawsudo *

# Explicit denials — belt and suspenders
${agent_user} ALL=(ALL) !ALL
POLICYEOF
    fi

    chmod 440 "$POLICY_FILE"
    if visudo -cf "$POLICY_FILE"; then
        chattr +i "$POLICY_FILE"
        log "✓ Agent account locked down with Tier 1 hardened sudoers"
    else
        echo "$agent_user ALL=(ALL) NOPASSWD: ALL" > "$POLICY_FILE"
        chmod 440 "$POLICY_FILE"
        warn "Sudoers file had syntax errors — fell back to NOPASSWD:ALL. Agent not locked down!"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE INSTALL DETECTION MENU
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$EXISTING_INSTALL" == "true" && "$MODE" == "install" ]]; then
    CURRENT_VERSION=$(/usr/local/bin/clawtower --version 2>/dev/null || echo "unknown")
    header "ClawTower is already installed" "Current version: $CURRENT_VERSION"
    echo -e "  ${BOLD}1${NC}  ${DIM}Upgrade${NC}         swap binaries, keep config & key"
    echo -e "  ${BOLD}2${NC}  ${DIM}Reconfigure${NC}     re-run config wizard, keep key"
    echo -e "  ${BOLD}3${NC}  ${DIM}Full reinstall${NC}  nuke everything, start fresh"
    echo -e "  ${BOLD}4${NC}  ${DIM}Abort${NC}"
    echo ""
    echo -en "  ${AMBER}▸${NC} Choose [1-4]: " > /dev/tty
    read -r menu_choice < /dev/tty
    case "$menu_choice" in
        1) MODE="upgrade" ;;
        2) MODE="install" ;;  # Continue to full flow (reconfigure)
        3) MODE="install"; HAD_ADMIN_KEY=false ;;  # Full reinstall — treat as fresh
        4) echo "Aborted."; exit 0 ;;
        *) die "Invalid choice" ;;
    esac
elif [[ "$EXISTING_INSTALL" == "partial" && "$MODE" == "install" ]]; then
    echo ""
    warn "Partial ClawTower installation detected (some files missing)."
    echo -e "    ${DIM}Binary${NC}     $([ "$HAS_BINARY" = true ] && echo "${GREEN}✓${NC}" || echo "${RED}✗${NC}")"
    echo -e "    ${DIM}Config${NC}     $([ "$HAS_CONFIG" = true ] && echo "${GREEN}✓${NC}" || echo "${RED}✗${NC}")"
    echo -e "    ${DIM}Admin key${NC}  $([ "$HAS_KEY" = true ] && echo "${GREEN}✓${NC}" || echo "${RED}✗${NC}")"
    echo ""
    if confirm "Proceed with fresh install? (will overwrite existing files) [y/n]"; then
        HAD_ADMIN_KEY=false
    else
        echo "Aborted."
        exit 0
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# UPGRADE MODE
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "upgrade" ]]; then
    header "ClawTower Upgrade"

    CURRENT_VERSION=$(/usr/local/bin/clawtower --version 2>/dev/null || echo "unknown")

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)   ARCH_LABEL="x86_64" ;;
        aarch64|arm64)   ARCH_LABEL="aarch64" ;;
        *)               die "Unsupported architecture: $ARCH" ;;
    esac

    # Resolve version
    if [[ "$VERSION" == "latest" ]]; then
        log "Fetching latest release..."
        VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
        [[ -n "$VERSION" ]] || die "Could not determine latest version"
    fi

    echo -e "  ${DIM}Current${NC}    ${BOLD}$CURRENT_VERSION${NC}"
    echo -e "  ${DIM}Available${NC}  ${BOLD}$VERSION${NC}"
    echo ""

    if ! confirm "Upgrade to $VERSION? [Y/n]"; then
        echo "Aborted."
        exit 0
    fi

    # Download new binaries to temp
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
    log "Downloading clawtower..."
    curl -sSL -f -o "$TMPDIR/clawtower" "$BASE_URL/clawtower-${ARCH_LABEL}-linux" || die "Download failed: $BASE_URL/clawtower-${ARCH_LABEL}-linux"
    log "Downloading clawsudo..."
    curl -sSL -f -o "$TMPDIR/clawsudo" "$BASE_URL/clawsudo-${ARCH_LABEL}-linux" || die "Download failed"
    chmod +x "$TMPDIR/clawtower" "$TMPDIR/clawsudo"

    # Download updated policies
    log "Downloading updated policies..."
    mkdir -p "$TMPDIR/policies"
    curl -sSL -f -o "$TMPDIR/policies/default.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/default.yaml" 2>/dev/null || true

    # Download BarnacleDefense pattern databases
    log "Downloading BarnacleDefense patterns..."
    BARNACLE_BASE="https://raw.githubusercontent.com/$REPO/$VERSION/patterns/barnacle"
    mkdir -p "$TMPDIR/barnacle"
    for pattern in injection-patterns.json dangerous-commands.json privacy-rules.json supply-chain-ioc.json; do
        curl -sSL -f -o "$TMPDIR/barnacle/$pattern" "$BARNACLE_BASE/$pattern" 2>/dev/null && \
            log "  ✓ $pattern" || warn "  ✗ $pattern (non-fatal)"
    done

    # Stop service
    log "Stopping ClawTower service..."
    systemctl stop clawtower 2>/dev/null || true
    sleep 1

    # Remove immutable flags
    log "Removing immutable flags..."
    chattr -i /usr/local/bin/clawtower 2>/dev/null || true
    chattr -i /usr/local/bin/clawsudo 2>/dev/null || true
    chattr -i /usr/local/bin/clawtower-tray 2>/dev/null || true
    chattr -i /etc/clawtower/admin.key.hash 2>/dev/null || true
    chattr -i /etc/sudoers.d/010_pi-nopasswd 2>/dev/null || true

    # Replace binaries
    log "Installing new binaries..."
    cp "$TMPDIR/clawtower" /usr/local/bin/clawtower
    cp "$TMPDIR/clawsudo" /usr/local/bin/clawsudo
    chmod 755 /usr/local/bin/clawtower /usr/local/bin/clawsudo

    # Detect display server for tray install
    CALLING_USER="${SUDO_USER:-$(whoami)}"
    CALLING_HOME=$(eval echo "~$CALLING_USER")
    DISPLAY_SERVER="headless"
    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        DISPLAY_SERVER="wayland"
    elif su -s /bin/sh "$CALLING_USER" -c 'echo $WAYLAND_DISPLAY' 2>/dev/null | grep -q .; then
        DISPLAY_SERVER="wayland"
    elif [[ -n "${DISPLAY:-}" ]]; then
        DISPLAY_SERVER="x11"
    fi

    # Always install/update tray binary on systems with a display server
    TRAY_ARTIFACT="clawtower-tray-${ARCH_LABEL}-linux"
    if [[ "$DISPLAY_SERVER" != "headless" ]]; then
        log "Installing/updating tray binary ($DISPLAY_SERVER detected)..."
        if curl -sSL -f -o "$TMPDIR/clawtower-tray" "$BASE_URL/$TRAY_ARTIFACT" 2>/dev/null; then
            chattr -i /usr/local/bin/clawtower-tray 2>/dev/null || true
            chmod +x "$TMPDIR/clawtower-tray"
            cp "$TMPDIR/clawtower-tray" /usr/local/bin/clawtower-tray
            chmod 755 /usr/local/bin/clawtower-tray
            chattr +i /usr/local/bin/clawtower-tray
            log "✓ Tray binary installed"

            # Ensure autostart entry exists
            AUTOSTART_DIR="$CALLING_HOME/.config/autostart"
            if [[ ! -f "$AUTOSTART_DIR/clawtower-tray.desktop" ]]; then
                mkdir -p "$AUTOSTART_DIR"
                cat > "$AUTOSTART_DIR/clawtower-tray.desktop" <<TRAYEOF
[Desktop Entry]
Type=Application
Name=ClawTower Tray
Exec=/usr/local/bin/clawtower-tray
Icon=security-high
Comment=ClawTower security watchdog tray icon
X-GNOME-Autostart-enabled=true
TRAYEOF
                chown "$CALLING_USER:$(id -gn "$CALLING_USER")" "$AUTOSTART_DIR/clawtower-tray.desktop"
                log "✓ Tray autostart entry created"
            fi
        else
            warn "Tray binary not available in this release — keeping existing"
        fi
    elif [[ -f /usr/local/bin/clawtower-tray ]]; then
        # Headless but tray was previously installed — still update binary
        log "Updating tray binary (headless, but previously installed)..."
        if curl -sSL -f -o "$TMPDIR/clawtower-tray" "$BASE_URL/$TRAY_ARTIFACT" 2>/dev/null; then
            chattr -i /usr/local/bin/clawtower-tray 2>/dev/null || true
            chmod +x "$TMPDIR/clawtower-tray"
            cp "$TMPDIR/clawtower-tray" /usr/local/bin/clawtower-tray
            chmod 755 /usr/local/bin/clawtower-tray
            chattr +i /usr/local/bin/clawtower-tray
            log "✓ Tray binary updated"
        else
            warn "Tray binary not available in this release — keeping existing"
        fi
    fi

    # Update BarnacleDefense patterns
    mkdir -p "/etc/clawtower/barnacle"
    for f in "$TMPDIR"/barnacle/*.json; do
        [[ -f "$f" ]] && cp "$f" "/etc/clawtower/barnacle/"
    done

    # Update default policy
    if [[ -f "$TMPDIR/policies/default.yaml" ]]; then
        cp "$TMPDIR/policies/default.yaml" "/etc/clawtower/policies/default.yaml"
        log "Updated default policy"
    fi

    # Regenerate sudoers allowlist from latest template
    # Check both new and legacy config paths during migration period
    AGENT_USERNAME=$(grep -oP 'watched_user = "\K[^"]+' /etc/clawtower/config.toml 2>/dev/null \
        || grep -oP 'watched_user = "\K[^"]+' /etc/clawav/config.toml 2>/dev/null \
        || echo "")
    # If watched_user is a UID, resolve to username
    if [[ "$AGENT_USERNAME" =~ ^[0-9]+$ ]]; then
        AGENT_USERNAME=$(getent passwd "$AGENT_USERNAME" | cut -d: -f1 || echo "")
    fi
    if [[ -n "$AGENT_USERNAME" ]]; then
        install_sudoers_allowlist "$AGENT_USERNAME"
    fi

    # Service hardening (disable unnecessary network services)
    log "Applying service hardening..."
    if systemctl is-active --quiet rpcbind 2>/dev/null; then
        systemctl stop rpcbind rpcbind.socket 2>/dev/null || true
        systemctl disable rpcbind rpcbind.socket 2>/dev/null || true
        systemctl mask rpcbind rpcbind.socket 2>/dev/null || true
        log "  rpcbind disabled and masked (port 111)"
    else
        log "  rpcbind already inactive"
    fi

    # Remove agent user from docker group (docker group = root)
    if [[ -n "$AGENT_USERNAME" ]] && id -nG "$AGENT_USERNAME" 2>/dev/null | grep -qw docker; then
        gpasswd -d "$AGENT_USERNAME" docker 2>/dev/null || true
        log "  Removed $AGENT_USERNAME from docker group"
    fi

    # Re-set immutable flags
    log "Re-setting immutable flags..."
    chattr +i /usr/local/bin/clawtower
    chattr +i /usr/local/bin/clawsudo
    [[ -f /usr/local/bin/clawtower-tray ]] && chattr +i /usr/local/bin/clawtower-tray
    [[ -f /etc/clawtower/admin.key.hash ]] && chattr +i /etc/clawtower/admin.key.hash

    # Restart service
    log "Starting ClawTower..."
    systemctl start clawtower
    sleep 2

    if systemctl is-active --quiet clawtower; then
        NEW_VERSION=$(/usr/local/bin/clawtower --version 2>/dev/null || echo "$VERSION")
        header "Upgrade complete" "$CURRENT_VERSION → $NEW_VERSION"
        log "Your existing admin key and config are unchanged"
        echo ""
        echo -e "  ${DIM}Status${NC}  systemctl status clawtower"
        echo -e "  ${DIM}Logs${NC}    journalctl -u clawtower -f"
        echo ""
    else
        die "ClawTower failed to start after upgrade — check: journalctl -u clawtower -n 50"
    fi

    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════
phase_bar 1 "Download" "Configure" "Lock Down" "Admin Key"
echo -e "  ${DIM}     /==g           _${NC}"
echo -e "  ${DIM}    //      >>>/---{_${NC}"
echo -e "  ${AMBER}    \`==::[[[[|:${NC}${DIM}     _${NC}"
echo -e "  ${DIM}            >>>\---{_${NC}"
echo ""
header "ClawTower Installer" "OS-level runtime security for AI agents"
echo -e "  This installer will:"
echo -e "  ${DIM}1.${NC} Download binaries + BarnacleDefense patterns"
echo -e "  ${DIM}2.${NC} Configure before anything is locked down"
echo -e "  ${DIM}3.${NC} Lock the installation ${DIM}(immutable — requires recovery to undo)${NC}"
echo ""

if ! confirm "Continue? [y/n]"; then
    echo "Aborted."
    exit 0
fi

# ── Detect architecture ──────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH_LABEL="x86_64" ;;
    aarch64|arm64)   ARCH_LABEL="aarch64" ;;
    *)               die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac
log "Detected architecture: $ARCH_LABEL"

# ── Resolve version ──────────────────────────────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
    log "Fetching latest release..."
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -n "$VERSION" ]] || die "Could not determine latest version. Check https://github.com/$REPO/releases"
fi
log "Installing ClawTower $VERSION"

# ── Download binaries ────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
CLAWTOWER_ARTIFACT="clawtower-${ARCH_LABEL}-linux"
CLAWSUDO_ARTIFACT="clawsudo-${ARCH_LABEL}-linux"

log "Downloading $CLAWTOWER_ARTIFACT..."
curl -sSL -f -o "$TMPDIR/clawtower" "$BASE_URL/$CLAWTOWER_ARTIFACT" || die "Failed to download clawtower binary. Does $VERSION exist? Check: $BASE_URL/$CLAWTOWER_ARTIFACT"

log "Downloading $CLAWSUDO_ARTIFACT..."
curl -sSL -f -o "$TMPDIR/clawsudo" "$BASE_URL/$CLAWSUDO_ARTIFACT" || die "Failed to download clawsudo binary. Check: $BASE_URL/$CLAWSUDO_ARTIFACT"

chmod +x "$TMPDIR/clawtower" "$TMPDIR/clawsudo"

# ── Download config + policies ───────────────────────────────────────────────
log "Downloading default config and policies..."
curl -sSL -f -o "$TMPDIR/config.toml" "https://raw.githubusercontent.com/$REPO/$VERSION/config.toml" || warn "Could not download config.toml"
mkdir -p "$TMPDIR/policies"
curl -sSL -f -o "$TMPDIR/policies/default.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/default.yaml" 2>/dev/null || true
curl -sSL -f -o "$TMPDIR/policies/clawsudo.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/clawsudo.yaml" 2>/dev/null || true

# ── Download BarnacleDefense patterns ─────────────────────────────────────────
log "Downloading BarnacleDefense pattern databases..."
BARNACLE_BASE="https://raw.githubusercontent.com/$REPO/$VERSION/patterns/barnacle"
mkdir -p "$TMPDIR/barnacle"
for pattern in injection-patterns.json dangerous-commands.json privacy-rules.json supply-chain-ioc.json; do
    curl -sSL -f -o "$TMPDIR/barnacle/$pattern" "$BARNACLE_BASE/$pattern" 2>/dev/null && \
        log "  ✓ $pattern" || \
        warn "  ✗ $pattern (non-fatal)"
done

# ── Install dependencies ──────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    PKG_MGR=""
fi

if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..."
    case "$PKG_MGR" in
        apt)    apt-get update -qq && apt-get install -y -qq auditd ;;
        dnf)    dnf install -y -q audit ;;
        pacman) pacman -S --noconfirm audit ;;
        *)      warn "Could not install auditd — install it manually" ;;
    esac
fi

if ! command -v apparmor_parser &>/dev/null; then
    log "Installing AppArmor..."
    case "$PKG_MGR" in
        apt)    apt-get install -y -qq apparmor apparmor-utils ;;
        dnf)    dnf install -y -q apparmor apparmor-utils ;;
        pacman) pacman -S --noconfirm apparmor ;;
        *)      warn "Could not install AppArmor — install it manually" ;;
    esac
fi

# ── Create directories and install files (NOT locked down yet) ────────────────
log "Setting up directories..."
mkdir -p /etc/clawtower/policies /etc/clawtower/barnacle /etc/clawtower/sentinel-shadow /etc/clawtower/quarantine /var/log/clawtower /var/run/clawtower
# Shadow and quarantine dirs should not be world-readable (info leak prevention)
chmod 700 /etc/clawtower/sentinel-shadow /etc/clawtower/quarantine

# Stop existing service if upgrading
if systemctl is-active --quiet clawtower 2>/dev/null; then
    log "Stopping existing ClawTower service..."
    systemctl stop clawtower
    sleep 1
fi

# Remove immutable flags if upgrading
chattr -i /usr/local/bin/clawtower 2>/dev/null || true
chattr -i /usr/local/bin/clawsudo 2>/dev/null || true
chattr -i /etc/clawtower/config.toml 2>/dev/null || true

log "Installing binaries to /usr/local/bin/..."
cp "$TMPDIR/clawtower" /usr/local/bin/clawtower
cp "$TMPDIR/clawsudo" /usr/local/bin/clawsudo
chmod 755 /usr/local/bin/clawtower /usr/local/bin/clawsudo

# ── Detect display server and install tray binary ─────────────────────────────
DISPLAY_SERVER="headless"
CALLING_USER="${SUDO_USER:-$(whoami)}"
CALLING_HOME=$(eval echo "~$CALLING_USER")

# Check for Wayland
if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
    DISPLAY_SERVER="wayland"
elif su -s /bin/sh "$CALLING_USER" -c 'echo $WAYLAND_DISPLAY' 2>/dev/null | grep -q .; then
    DISPLAY_SERVER="wayland"
elif loginctl show-session "$(loginctl list-sessions --no-legend 2>/dev/null | grep "$CALLING_USER" | awk '{print $1}' | head -1)" -p Type 2>/dev/null | grep -qi wayland; then
    DISPLAY_SERVER="wayland"
# Check for X11
elif [[ -n "${DISPLAY:-}" ]]; then
    DISPLAY_SERVER="x11"
elif su -s /bin/sh "$CALLING_USER" -c 'echo $DISPLAY' 2>/dev/null | grep -q .; then
    DISPLAY_SERVER="x11"
fi

log "Detected display server: $DISPLAY_SERVER"

if [[ "$DISPLAY_SERVER" != "headless" ]]; then
    TRAY_ARTIFACT="clawtower-tray-${ARCH_LABEL}-linux"
    log "Downloading tray binary ($DISPLAY_SERVER detected)..."
    if curl -sSL -f -o "$TMPDIR/clawtower-tray" "$BASE_URL/$TRAY_ARTIFACT" 2>/dev/null; then
        chmod +x "$TMPDIR/clawtower-tray"
        chattr -i /usr/local/bin/clawtower-tray 2>/dev/null || true
        cp "$TMPDIR/clawtower-tray" /usr/local/bin/clawtower-tray
        chmod 755 /usr/local/bin/clawtower-tray
        log "✓ Tray binary installed"

        # Create autostart desktop entry
        AUTOSTART_DIR="$CALLING_HOME/.config/autostart"
        mkdir -p "$AUTOSTART_DIR"
        cat > "$AUTOSTART_DIR/clawtower-tray.desktop" <<TRAYEOF
[Desktop Entry]
Type=Application
Name=ClawTower Tray
Exec=/usr/local/bin/clawtower-tray
Icon=security-high
Comment=ClawTower security watchdog tray icon
X-GNOME-Autostart-enabled=true
TRAYEOF
        chown "$CALLING_USER:$(id -gn "$CALLING_USER")" "$AUTOSTART_DIR/clawtower-tray.desktop"
        log "✓ Tray autostart entry created"

        if [[ "$DISPLAY_SERVER" == "x11" ]]; then
            warn "X11 detected — tray uses D-Bus StatusNotifierItem. You may need snixembed or similar SNI bridge."
        fi
    else
        warn "Tray binary not available in this release — skipping (non-fatal)"
    fi
else
    log "Headless system — skipping tray binary"
fi

# Install config (don't overwrite existing)
if [[ ! -f /etc/clawtower/config.toml ]]; then
    [[ -f "$TMPDIR/config.toml" ]] && cp "$TMPDIR/config.toml" /etc/clawtower/config.toml
fi

# Install policies (don't overwrite existing)
for f in "$TMPDIR"/policies/*.yaml; do
    fname=$(basename "$f")
    [[ -f "/etc/clawtower/policies/$fname" ]] || cp "$f" "/etc/clawtower/policies/$fname"
done

# Install BarnacleDefense patterns
for f in "$TMPDIR"/barnacle/*.json; do
    [[ -f "$f" ]] && cp "$f" "/etc/clawtower/barnacle/"
done

# Install systemd service
cat > /etc/systemd/system/clawtower.service <<'EOF'
[Unit]
Description=ClawTower Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawtower --headless --config /etc/clawtower/config.toml
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable clawtower

echo ""
log "Phase 1 complete — files installed ${DIM}(not locked down yet)${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: CONFIGURE
# ═══════════════════════════════════════════════════════════════════════════════
phase_bar 2 "Download" "Configure" "Lock Down" "Admin Key"
header "Configuration"
CONF="/etc/clawtower/config.toml"

# ── Watched User ──────────────────────────────────────────────────────────────
CALLING_USER="${SUDO_USER:-$(whoami)}"
CALLING_UID=$(id -u "$CALLING_USER" 2>/dev/null || echo "1000")
echo -e "  ${BOLD}User to monitor:${NC} $CALLING_USER ${DIM}(UID $CALLING_UID)${NC}"
echo -en "  ${AMBER}▸${NC} Monitor this user? [Y/n] or enter a different UID: " > /dev/tty
read -r user_input < /dev/tty
if [[ -z "$user_input" || "$user_input" =~ ^[yY] ]]; then
    WATCH_UID="$CALLING_UID"
else
    WATCH_UID="$user_input"
fi
sed -i "s/^watched_user = .*/watched_user = \"$WATCH_UID\"/" "$CONF"
log "Watching UID: $WATCH_UID"

# ── Additional Users ──────────────────────────────────────────────────────────
echo ""
echo -en "  ${AMBER}▸${NC} Monitor additional UIDs? ${DIM}(comma-separated, or ENTER to skip)${NC}: " > /dev/tty
read -r extra_uids < /dev/tty
if [[ -n "$extra_uids" ]]; then
    # Build TOML array like ["1000", "1001"]
    UIDS_TOML="[\"$WATCH_UID\""
    IFS=',' read -ra EXTRA <<< "$extra_uids"
    for uid in "${EXTRA[@]}"; do
        uid=$(echo "$uid" | tr -d ' ')
        [[ -n "$uid" ]] && UIDS_TOML+=", \"$uid\""
    done
    UIDS_TOML+="]"
    sed -i "s/^.*watched_users = .*/watched_users = $UIDS_TOML/" "$CONF"
    log "Watching UIDs: $UIDS_TOML"
fi

# ── Slack (Optional) ─────────────────────────────────────────────────────────
sep
echo ""
echo -e "  ${BOLD}Slack Alerts${NC} ${DIM}(optional)${NC}"
echo -e "  ${DIM}ClawTower can send alerts to an independent Slack webhook.${NC}"
echo -en "  ${AMBER}▸${NC} Slack webhook URL ${DIM}(or ENTER to skip)${NC}: " > /dev/tty
read -r slack_url < /dev/tty
if [[ -n "$slack_url" ]]; then
    sed -i "s|^webhook_url = .*|webhook_url = \"$slack_url\"|" "$CONF"
    sed -i "s/^enabled = false/enabled = true/" "$CONF"  # enable slack section
    log "Slack alerts enabled"

    echo -en "  ${AMBER}▸${NC} Slack channel ${DIM}(default: #devops)${NC}: " > /dev/tty
    read -r slack_chan < /dev/tty
    [[ -n "$slack_chan" ]] && sed -i "s|^channel = .*|channel = \"$slack_chan\"|" "$CONF"

    echo -en "  ${AMBER}▸${NC} Backup webhook URL ${DIM}(or ENTER to skip)${NC}: " > /dev/tty
    read -r slack_backup < /dev/tty
    [[ -n "$slack_backup" ]] && sed -i "s|^backup_webhook_url = .*|backup_webhook_url = \"$slack_backup\"|" "$CONF"
else
    log "Slack alerts skipped — alerts go to logs only"
fi

# ── API ───────────────────────────────────────────────────────────────────────
sep
echo ""
echo -e "  ${BOLD}JSON API${NC} ${DIM}(LAN-only status/alerts endpoint)${NC}"
echo -en "  ${AMBER}▸${NC} Enable API on port 18791? [Y/n]: " > /dev/tty
read -r api_input < /dev/tty
if [[ "$api_input" =~ ^[nN] ]]; then
    sed -i '/^\[api\]/,/^$/s/^enabled = true/enabled = false/' "$CONF"
    log "API disabled"
else
    log "API enabled on port 18791"
fi

# ── BarnacleDefense ───────────────────────────────────────────────────────────
sep
echo ""
echo -e "  ${BOLD}BarnacleDefense${NC} ${DIM}(prompt injection + supply chain detection)${NC}"
echo -en "  ${AMBER}▸${NC} Enable BarnacleDefense? [Y/n]: " > /dev/tty
read -r sc_input < /dev/tty
if [[ "$sc_input" =~ ^[nN] ]]; then
    log "BarnacleDefense disabled"
else
    sed -i '/^\[barnacle\]/,/^$/s/^enabled = false/enabled = true/' "$CONF"
    sed -i "s|^vendor_dir = .*|vendor_dir = \"/etc/clawtower/barnacle\"|" "$CONF"
    log "BarnacleDefense enabled"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
sep
echo ""
echo -e "  ${BOLD}Summary${NC}"
echo -e "    ${DIM}Config${NC}       $CONF"
echo -e "    ${DIM}Watched${NC}      UID $WATCH_UID"
if grep -q 'webhook_url = ""' "$CONF" 2>/dev/null || ! grep -q 'webhook_url' "$CONF" 2>/dev/null; then
    echo -e "    ${DIM}Slack${NC}        Disabled ${DIM}(logs only)${NC}"
else
    echo -e "    ${DIM}Slack${NC}        Enabled"
fi
echo ""
echo -e "  ${DIM}You can edit $CONF later (before locking down).${NC}"
echo ""

if ! confirm "Configuration done? Ready to lock down? [y/n]"; then
    echo ""
    echo "  Config saved at /etc/clawtower/config.toml"
    echo "  Binaries installed but NOT locked down."
    echo "  Re-run installer when ready to lock down."
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: LOCK DOWN (SWALLOWED KEY)
# ═══════════════════════════════════════════════════════════════════════════════
phase_bar 3 "Download" "Configure" "Lock Down" "Admin Key"
danger_header "Locking Down" "This is irreversible without recovery mode"

# ── Create human admin account ────────────────────────────────────────────────
echo -e "  ${BOLD}Human Admin Account${NC}"
echo ""
echo -e "  ${DIM}ClawTower locks down the agent's user account (UID $WATCH_UID) so it${NC}"
echo -e "  ${DIM}cannot disable, modify, or bypass the watchdog.${NC}"
echo ""
echo -e "  ${RED}┃${NC} A separate human admin account is ${BOLD}required${NC}."
echo -e "  ${RED}┃${NC} ${DIM}This is the only account that can manage ClawTower after lockdown.${NC}"
echo -e "  ${RED}┃${NC} ${DIM}Without it, you'll need recovery mode (boot from USB).${NC}"
echo ""
echo -e "  ${RED}┃${NC} ${RED}${BOLD}Never share this account's credentials with your AI agent.${NC}"
echo -e "  ${RED}┃${NC} ${DIM}The entire security model depends on this separation.${NC}"
echo ""

AGENT_USERNAME=$(getent passwd "$WATCH_UID" | cut -d: -f1 || echo "")
ADMIN_USERNAME=""

# Check for existing admin accounts (sudo/admin group members that aren't the agent or root)
EXISTING_ADMINS=()
while IFS= read -r user; do
    [[ "$user" == "$AGENT_USERNAME" ]] && continue
    [[ "$user" == "root" ]] && continue
    EXISTING_ADMINS+=("$user")
done < <(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n'; getent group admin 2>/dev/null | cut -d: -f4 | tr ',' '\n')
# Also check for clawtower-created admin sudoers files
for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    if grep -q "ClawTower.*Human admin" "$f" 2>/dev/null; then
        admin_from_file=$(grep -oP '^\w+' "$f" | head -1)
        [[ -n "$admin_from_file" && "$admin_from_file" != "$AGENT_USERNAME" ]] && EXISTING_ADMINS+=("$admin_from_file")
    fi
done
# Deduplicate
EXISTING_ADMINS=($(printf '%s\n' "${EXISTING_ADMINS[@]}" | sort -u))

if [[ ${#EXISTING_ADMINS[@]} -gt 0 ]]; then
    echo -e "  ${GREEN}✓ Found existing admin account(s): ${BOLD}${EXISTING_ADMINS[*]}${NC}"
    echo ""
    echo -en "  ${AMBER}▸${NC} Use existing admin account(s)? [Y/n]: ${NC}" > /dev/tty
    read -r use_existing < /dev/tty
    if [[ ! "$use_existing" =~ ^[nN] ]]; then
        log "Using existing admin account(s): ${EXISTING_ADMINS[*]}"
        ADMIN_USERNAME="${EXISTING_ADMINS[0]}"
        create_admin="n"
    else
        echo -en "  ${AMBER}▸${NC} Create an additional admin account? [Y/n]: ${NC}" > /dev/tty
        read -r create_admin < /dev/tty
    fi
else
    echo -en "  ${AMBER}▸${NC} Create a human admin account? [Y/n]: ${NC}" > /dev/tty
    read -r create_admin < /dev/tty
fi

if [[ "$create_admin" =~ ^[nN] && ${#EXISTING_ADMINS[@]} -eq 0 ]]; then
    echo ""
    warn "No admin account found and none being created."
    echo -en "  ${AMBER}▸${NC} Do you already have a separate admin account? [y/N]: ${NC}" > /dev/tty
    read -r has_admin < /dev/tty
    if [[ ! "$has_admin" =~ ^[yY] ]]; then
        die "Cannot proceed without a human admin account. Re-run the installer and create one."
    fi
fi

if [[ ! "$create_admin" =~ ^[nN] ]]; then
    echo -en "  ${AMBER}▸${NC} Username for admin account: ${NC}" > /dev/tty
    read -r ADMIN_USERNAME < /dev/tty
    [[ -n "$ADMIN_USERNAME" ]] || { warn "No username provided — skipping admin account"; ADMIN_USERNAME=""; }

    if [[ -n "$ADMIN_USERNAME" ]]; then
        if id "$ADMIN_USERNAME" &>/dev/null; then
            log "User '$ADMIN_USERNAME' already exists — adding to sudo group"
            usermod -aG sudo "$ADMIN_USERNAME" 2>/dev/null || true
        else
            log "Creating user '$ADMIN_USERNAME'..."
            useradd -m -s /bin/bash -G sudo "$ADMIN_USERNAME"
        fi

        # Set password
        echo ""
        echo -e "  ${BOLD}Set a password for '${ADMIN_USERNAME}':${NC}" > /dev/tty
        passwd "$ADMIN_USERNAME" < /dev/tty

        # Give full NOPASSWD sudo
        cat > "/etc/sudoers.d/$ADMIN_USERNAME" << SUDOEOF
# ClawTower: Human admin account — full unrestricted sudo access
$ADMIN_USERNAME ALL=(ALL:ALL) NOPASSWD: ALL
SUDOEOF
        chmod 440 "/etc/sudoers.d/$ADMIN_USERNAME"

        # Copy SSH authorized_keys from agent user if they exist
        if [[ -n "$AGENT_USERNAME" && -f "/home/$AGENT_USERNAME/.ssh/authorized_keys" ]]; then
            mkdir -p "/home/$ADMIN_USERNAME/.ssh"
            cp "/home/$AGENT_USERNAME/.ssh/authorized_keys" "/home/$ADMIN_USERNAME/.ssh/authorized_keys"
            chown -R "$ADMIN_USERNAME:$ADMIN_USERNAME" "/home/$ADMIN_USERNAME/.ssh"
            chmod 700 "/home/$ADMIN_USERNAME/.ssh"
            chmod 600 "/home/$ADMIN_USERNAME/.ssh/authorized_keys"
            log "Copied SSH keys from $AGENT_USERNAME → $ADMIN_USERNAME"
        fi

        echo ""
        log "Admin account '${BOLD}$ADMIN_USERNAME${NC}' created with full sudo access"
        echo ""
        echo -e "  ${DIM}Use this account for all system administration.${NC}"
        echo -e "  ${DIM}SSH in as:${NC} ssh ${BOLD}${ADMIN_USERNAME}${NC}@$(hostname)"
        echo ""
        echo -e "  ${RED}┃${NC} ${RED}${BOLD}Never share '${ADMIN_USERNAME}' credentials with your AI agent.${NC}"
        echo -e "  ${RED}┃${NC} ${DIM}The agent cannot know this password or SSH key.${NC}"
        echo -e "  ${RED}┃${NC} ${DIM}This is the foundation of ClawTower's security model.${NC}"
        echo ""
    fi
fi

# ── Install sudoers allowlist for agent ────────────────────────────────────────
if [[ -n "$AGENT_USERNAME" ]]; then
    install_sudoers_allowlist "$AGENT_USERNAME"
fi

# ── Install auditd tamper detection rules ─────────────────────────────────────
if command -v auditctl &>/dev/null; then
    log "Installing auditd tamper detection rules..."
    cat > /etc/audit/rules.d/clawtower.rules << 'AUDITRULES'
# ClawTower tamper detection rules
-w /usr/local/bin/clawtower -p a -k clawtower-tamper
-w /etc/clawtower/ -p wa -k clawtower-config
-w /etc/systemd/system/clawtower.service -p wa -k clawtower-tamper
-w /etc/sudoers.d/clawtower-deny -p wa -k clawtower-tamper
-w /etc/apparmor.d/clawtower.deny-agent -p wa -k clawtower-tamper
AUDITRULES
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        log "ℹ️  Auditd in immutable mode — rules installed, will activate after reboot"
    else
        augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/clawtower.rules 2>/dev/null || true
        log "✓ Auditd tamper detection active"
    fi
fi

# ── Create system user ────────────────────────────────────────────────────────
if ! id -u clawtower &>/dev/null; then
    log "Creating clawtower system user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin clawtower
fi
chown -R clawtower:clawtower /etc/clawtower /var/log/clawtower /var/run/clawtower

# ── Set immutable attributes ─────────────────────────────────────────────────
log "Setting immutable flags (chattr +i)..."
chattr +i /usr/local/bin/clawtower
chattr +i /usr/local/bin/clawsudo
chattr +i /etc/clawtower/config.toml
chattr +i /etc/systemd/system/clawtower.service
[[ -f /usr/local/bin/clawtower-tray ]] && chattr +i /usr/local/bin/clawtower-tray
[[ -f /etc/clawtower/admin.key.hash ]] && chattr +i /etc/clawtower/admin.key.hash
[[ -f /etc/sudoers.d/clawtower-deny ]] && chattr +i /etc/sudoers.d/clawtower-deny

# ── AppArmor profile ─────────────────────────────────────────────────────────
if command -v apparmor_parser &>/dev/null; then
    log "Installing AppArmor profile..."
    cat > /etc/apparmor.d/clawtower.deny-agent <<'APPARMOR'
# Deny AI agent user access to ClawTower paths
/usr/local/bin/clawtower r,
/usr/local/bin/clawsudo r,
deny /etc/clawtower/** w,
deny /var/log/clawtower/** w,
deny /etc/systemd/system/clawtower.service w,
APPARMOR
    apparmor_parser -r /etc/apparmor.d/clawtower.deny-agent 2>/dev/null || warn "AppArmor profile load failed (non-fatal)"
fi

# ── Disable unnecessary services ──────────────────────────────────────────────
log "Disabling unnecessary network services..."
if systemctl is-active --quiet rpcbind 2>/dev/null; then
    systemctl stop rpcbind rpcbind.socket 2>/dev/null || true
    systemctl disable rpcbind rpcbind.socket 2>/dev/null || true
    systemctl mask rpcbind rpcbind.socket 2>/dev/null || true
    log "  rpcbind disabled and masked (port 111)"
else
    log "  rpcbind already inactive"
fi

# ── Kernel hardening ─────────────────────────────────────────────────────────
log "Applying kernel hardening..."
sysctl -w kernel.modules_disabled=1 2>/dev/null || warn "Could not disable module loading"
sysctl -w kernel.yama.ptrace_scope=2 2>/dev/null || warn "Could not set ptrace scope"

# ── Lock audit config ────────────────────────────────────────────────────────
if command -v auditctl &>/dev/null; then
    log "Locking audit configuration..."
    auditctl -e 2 2>/dev/null || warn "Could not lock auditd (may need reboot)"
fi

# ── Start the service ────────────────────────────────────────────────────────
log "Starting ClawTower..."
systemctl start clawtower
sleep 2

if systemctl is-active --quiet clawtower; then
    log "✓ ClawTower is running"
else
    warn "ClawTower did not start — check: journalctl -u clawtower -n 50"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: ADMIN KEY
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$HAD_ADMIN_KEY" == "true" ]]; then
    echo ""
    echo -e "  ${GREEN}✓ Your existing admin key is still valid. No new key was generated.${NC}"
    echo ""
else
    phase_bar 4 "Download" "Configure" "Lock Down" "Admin Key"
    danger_header "Save Your Admin Key" "You will not see it again"

    echo -e "  ${RED}┃${NC} Your admin key was displayed when ClawTower first started."
    echo -e "  ${RED}┃${NC} Check the service logs:"
    echo -e "  ${RED}┃${NC}"
    echo -e "  ${RED}┃${NC}   ${BOLD}sudo journalctl -u clawtower -n 50 | grep OCAV-${NC}"
    echo -e "  ${RED}┃${NC}"
    echo -e "  ${RED}┃${NC} ${DIM}Without this key:${NC}"
    echo -e "  ${RED}┃${NC} ${DIM}  You cannot pause, configure, or manage ClawTower${NC}"
    echo -e "  ${RED}┃${NC} ${DIM}  You cannot update or uninstall it${NC}"
    echo -e "  ${RED}┃${NC} ${DIM}  Your only option is recovery mode (boot from USB)${NC}"
    echo ""

    # Show the key right here if we can find it
    ADMIN_KEY=$(journalctl -u clawtower -n 50 --no-pager 2>/dev/null | grep -oP 'OCAV-[a-f0-9]+' | head -1)
    if [[ -n "$ADMIN_KEY" ]]; then
        sep
        echo ""
        echo -e "  ${DIM}Your admin key:${NC}"
        echo ""
        echo -e "    ${AMBER}${BOLD}$ADMIN_KEY${NC}"
        echo ""
        sep
    fi

    echo ""
    while true; do
        echo -en "  ${RED}▸${NC} Type '${BOLD}I SAVED MY KEY${NC}' to confirm: " > /dev/tty
        read -r response < /dev/tty
        if [[ "$response" == "I SAVED MY KEY" ]]; then
            break
        fi
        echo -e "    ${DIM}You must type exactly: I SAVED MY KEY${NC}" > /dev/tty
    done
fi

header "ClawTower $VERSION installed and locked down"
echo -e "  ${DIM}Binaries${NC}   /usr/local/bin/clawtower, /usr/local/bin/clawsudo"
echo -e "  ${DIM}Config${NC}     /etc/clawtower/config.toml ${DIM}(immutable)${NC}"
echo -e "  ${DIM}Logs${NC}       journalctl -u clawtower -f"
echo -e "  ${DIM}Status${NC}     systemctl status clawtower"
echo -e "  ${DIM}Patterns${NC}   /etc/clawtower/barnacle/"
echo ""
