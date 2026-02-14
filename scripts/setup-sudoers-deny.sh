#!/bin/bash
# Block the openclaw user from running sudo commands that could disable ClawAV
set -euo pipefail

DENY_FILE="/etc/sudoers.d/clawav-deny"
AGENT_USER="openclaw"

cat > "$DENY_FILE" << 'EOF'
# ClawAV: Deny agent user from disabling the watchdog
# This file is immutable (chattr +i) — requires admin key to modify

# Block stopping/disabling ClawAV service
openclaw ALL=(ALL) !/usr/bin/systemctl stop clawav, \
                    !/usr/bin/systemctl stop clawav.service, \
                    !/usr/bin/systemctl disable clawav, \
                    !/usr/bin/systemctl disable clawav.service, \
                    !/usr/bin/systemctl mask clawav, \
                    !/usr/bin/systemctl mask clawav.service

# Block modifying ClawAV binary and config
openclaw ALL=(ALL) !/usr/bin/chattr * /usr/local/bin/clawav, \
                    !/usr/bin/chattr * /etc/clawav/*, \
                    !/usr/bin/chattr * /etc/systemd/system/clawav.service

# Block removing/replacing ClawAV files
openclaw ALL=(ALL) !/usr/bin/rm /usr/local/bin/clawav, \
                    !/usr/bin/rm -f /usr/local/bin/clawav, \
                    !/usr/bin/rm -rf /etc/clawav, \
                    !/usr/bin/rm -rf /etc/clawav/*, \
                    !/usr/bin/mv /usr/local/bin/clawav *, \
                    !/usr/bin/cp * /usr/local/bin/clawav, \
                    !/usr/bin/install * /usr/local/bin/clawav

# Block killing ClawAV process directly
openclaw ALL=(ALL) !/usr/bin/kill, \
                    !/usr/bin/killall clawav, \
                    !/usr/bin/pkill clawav
EOF

chmod 440 "$DENY_FILE"
chown root:root "$DENY_FILE"

# Validate syntax
if ! visudo -cf "$DENY_FILE"; then
    echo "ERROR: Invalid sudoers syntax, removing file"
    rm -f "$DENY_FILE"
    exit 1
fi

# Make immutable
chattr +i "$DENY_FILE"

echo "Created and locked $DENY_FILE"
