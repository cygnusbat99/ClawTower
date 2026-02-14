#!/usr/bin/env bash
set -euo pipefail

# ClawAV — Samhain FIM Setup for ARM64 (Raspberry Pi 5)
# Compiles Samhain from source and configures file integrity monitoring.

SAMHAIN_VERSION="${SAMHAIN_VERSION:-4.5.2}"
SAMHAIN_SRC_URL="https://la-samhna.de/samhain/samhain-current.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMHAIN_CONFIG_SRC="${SCRIPT_DIR}/../configs/samhainrc"
SAMHAIN_CONFIG_DST="/etc/samhainrc"

echo "=== ClawAV Samhain FIM Setup ==="
echo "Architecture: $(uname -m)"

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Install build dependencies
echo "Installing build dependencies..."
apt-get update -qq
apt-get install -y build-essential autoconf automake libgmp-dev zlib1g-dev

# Check if already installed
if command -v samhain &>/dev/null; then
    echo "Samhain already installed: $(samhain --version 2>&1 | head -1)"
    echo "Reconfiguring..."
else
    # Download and compile from source
    TMPDIR=$(mktemp -d)
    cd "${TMPDIR}"
    
    echo "Downloading Samhain source..."
    curl -fSL -o samhain.tar.gz "${SAMHAIN_SRC_URL}" || {
        echo "ERROR: Failed to download Samhain source"
        echo "Try manually from https://la-samhna.de/samhain/"
        rm -rf "${TMPDIR}"
        exit 1
    }
    
    # Samhain distributes a tar-in-tar (outer tar contains signed inner tar)
    echo "Extracting..."
    tar xzf samhain.tar.gz
    
    # Find the inner tarball
    INNER_TAR=$(find . -name "samhain-*.tar.gz" -not -name "samhain.tar.gz" | head -1)
    if [[ -z "${INNER_TAR}" ]]; then
        # Some versions just have the source directly
        INNER_TAR=$(find . -name "samhain-*" -type d | head -1)
        if [[ -z "${INNER_TAR}" ]]; then
            echo "ERROR: Could not find Samhain source in archive"
            ls -la
            rm -rf "${TMPDIR}"
            exit 1
        fi
        cd "${INNER_TAR}"
    else
        tar xzf "${INNER_TAR}"
        SRCDIR=$(find . -maxdepth 1 -name "samhain-*" -type d | head -1)
        cd "${SRCDIR}"
    fi
    
    echo "Configuring for standalone mode..."
    ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --enable-login-watch \
        --enable-suidcheck \
        --with-log-file=/var/log/samhain/samhain.log \
        --with-data-file=/var/lib/samhain/samhain_file \
        --with-pid-file=/var/run/samhain.pid
    
    echo "Compiling (this may take a few minutes on Pi)..."
    make -j$(nproc)
    
    echo "Installing..."
    make install
    
    cd /
    rm -rf "${TMPDIR}"
fi

# Create directories
mkdir -p /var/log/samhain
mkdir -p /var/lib/samhain
mkdir -p /etc/samhain

# Deploy configuration
if [[ -f "${SAMHAIN_CONFIG_SRC}" ]]; then
    cp "${SAMHAIN_CONFIG_SRC}" "${SAMHAIN_CONFIG_DST}"
    echo "Configuration deployed to ${SAMHAIN_CONFIG_DST}"
else
    echo "WARNING: Config template not found at ${SAMHAIN_CONFIG_SRC}"
fi

# Initialize the database
echo "Initializing file integrity database..."
samhain -t init 2>&1 || {
    echo "WARNING: Database initialization had warnings (this is normal on first run)"
}

echo "Database created at /var/lib/samhain/samhain_file"

# Create systemd service
cat > /etc/systemd/system/samhain.service << 'EOF'
[Unit]
Description=Samhain File Integrity Monitor
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/sbin/samhain -D
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/samhain.pid
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable samhain
systemctl restart samhain || echo "WARNING: Samhain service failed to start (check config)"

echo ""
echo "=== Samhain FIM Setup Complete ==="
echo "Service status: $(systemctl is-active samhain 2>/dev/null || echo 'not running')"
echo "Config: ${SAMHAIN_CONFIG_DST}"
echo "Database: /var/lib/samhain/samhain_file"
echo "Log: /var/log/samhain/samhain.log"
echo ""
echo "To update database after authorized changes:"
echo "  sudo samhain -t update"
echo "To check now:"
echo "  sudo samhain -t check"
