#!/bin/bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/clawav.rules"

cat > "$RULES_FILE" << 'EOF'
# ClawAV tamper detection rules
# Watch for attribute changes on ClawAV binary (chattr -i attempts)
-w /usr/local/bin/clawav -p a -k clawav-tamper

# Watch for writes/attribute changes to ClawAV config
-w /etc/clawav/ -p wa -k clawav-config

# Watch for changes to the service file
-w /etc/systemd/system/clawav.service -p wa -k clawav-tamper

# Watch for changes to the sudoers deny file
-w /etc/sudoers.d/clawav-deny -p wa -k clawav-tamper

# Watch for changes to AppArmor profile
-w /etc/apparmor.d/clawav.deny-agent -p wa -k clawav-tamper
EOF

# Reload audit rules
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE"

echo "Audit rules installed and loaded"
