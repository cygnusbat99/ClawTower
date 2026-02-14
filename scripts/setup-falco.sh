#!/usr/bin/env bash
set -euo pipefail

# ClawAV — Falco Installation for ARM64 (Raspberry Pi 5)
# Installs Falco from official aarch64 tarball, deploys custom rules,
# configures JSON file output for parsing by ClawAV.

FALCO_VERSION="${FALCO_VERSION:-0.42.0}"
FALCO_RULES_SRC="$(dirname "$0")/../rules/openclaw_falco_rules.yaml"
FALCO_RULES_DST="/etc/falco/rules.d/openclaw_rules.yaml"
FALCO_CONFIG="/etc/falco/falco.yaml"
FALCO_OUTPUT_LOG="/var/log/falco/falco_output.jsonl"

echo "=== ClawAV Falco Setup ==="
echo "Falco version: ${FALCO_VERSION}"
echo "Architecture: $(uname -m)"

if [[ "$(uname -m)" != "aarch64" ]]; then
    echo "WARNING: This script is designed for aarch64. Proceeding anyway..."
fi

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Method 1: Try official package repo
install_from_repo() {
    echo "Attempting install from Falco apt repository..."
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
        tee /etc/apt/sources.list.d/falcosecurity.list > /dev/null
    apt-get update -qq
    apt-get install -y falco
}

# Method 2: Install from tarball
install_from_tarball() {
    echo "Installing from official aarch64 tarball..."
    local tmpdir=$(mktemp -d)
    local tarball="falco-${FALCO_VERSION}-aarch64.tar.gz"
    local url="https://download.falco.org/packages/bin/aarch64/${tarball}"
    
    echo "Downloading ${url}..."
    curl -fSL -o "${tmpdir}/${tarball}" "${url}" || {
        echo "ERROR: Failed to download Falco tarball"
        echo "Check https://github.com/falcosecurity/falco/releases for available versions"
        rm -rf "${tmpdir}"
        return 1
    }
    
    echo "Extracting..."
    tar xzf "${tmpdir}/${tarball}" -C /
    rm -rf "${tmpdir}"
}

# Try repo first, fall back to tarball
if ! command -v falco &>/dev/null; then
    install_from_repo 2>/dev/null || {
        echo "Repo install failed, trying tarball..."
        install_from_tarball
    }
else
    echo "Falco already installed: $(falco --version 2>/dev/null || echo 'unknown version')"
fi

# Verify installation
if ! command -v falco &>/dev/null; then
    echo "ERROR: Falco installation failed"
    exit 1
fi

echo "Falco installed: $(falco --version)"

# Create directories
mkdir -p /etc/falco/rules.d
mkdir -p /var/log/falco
mkdir -p "$(dirname "${FALCO_OUTPUT_LOG}")"

# Deploy custom OpenClaw rules
if [[ -f "${FALCO_RULES_SRC}" ]]; then
    cp "${FALCO_RULES_SRC}" "${FALCO_RULES_DST}"
    echo "Custom rules deployed to ${FALCO_RULES_DST}"
else
    echo "WARNING: Custom rules file not found at ${FALCO_RULES_SRC}"
fi

# Configure Falco for JSON file output (for ClawAV parsing)
# Append/update file_output in falco.yaml
if [[ -f "${FALCO_CONFIG}" ]]; then
    # Enable file output in JSON format
    if grep -q "file_output:" "${FALCO_CONFIG}"; then
        sed -i 's/^file_output:.*//' "${FALCO_CONFIG}"
    fi
    
    cat >> "${FALCO_CONFIG}" << EOF

# ClawAV: JSON file output for log parsing
file_output:
  enabled: true
  keep_alive: true
  filename: ${FALCO_OUTPUT_LOG}

json_output: true
json_include_output_property: true
json_include_tags_property: true
EOF
    echo "Falco configured for JSON file output at ${FALCO_OUTPUT_LOG}"
fi

# Create systemd service if not exists
if [[ ! -f /etc/systemd/system/falco.service ]] && [[ ! -f /lib/systemd/system/falco.service ]]; then
    cat > /etc/systemd/system/falco.service << 'EOF'
[Unit]
Description=Falco: Container Native Runtime Security
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/falco --pidfile=/var/run/falco.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi

# Enable and start
systemctl daemon-reload
systemctl enable falco
systemctl restart falco

echo ""
echo "=== Falco Setup Complete ==="
echo "Service status: $(systemctl is-active falco)"
echo "JSON output: ${FALCO_OUTPUT_LOG}"
echo "Custom rules: ${FALCO_RULES_DST}"
echo "Verify rules: falco --validate /etc/falco/rules.d/openclaw_rules.yaml"
