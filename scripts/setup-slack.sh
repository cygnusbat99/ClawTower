#!/bin/bash
# Setup Slack webhook for ClawAV independent alerting
# This webhook must be SEPARATE from any OpenClaw Slack integration

set -euo pipefail

CONFIG_FILE="${1:-/etc/clawav/config.toml}"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       ClawAV — Independent Slack Webhook Setup      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  This webhook must be INDEPENDENT of OpenClaw's Slack."
echo "    Create a separate Slack app so alerts work even if"
echo "    OpenClaw is compromised."
echo ""
echo "Steps to create an Incoming Webhook:"
echo "  1. Go to https://api.slack.com/apps"
echo "  2. Click 'Create New App' → 'From scratch'"
echo "  3. Name it 'ClawAV Watchdog' (or similar)"
echo "  4. Select your workspace"
echo "  5. Go to 'Incoming Webhooks' → Toggle ON"
echo "  6. Click 'Add New Webhook to Workspace'"
echo "  7. Choose the channel for alerts (e.g. #devops)"
echo "  8. Copy the webhook URL"
echo ""

read -rp "Paste your webhook URL: " WEBHOOK_URL

if [[ ! "$WEBHOOK_URL" =~ ^https://hooks\.slack\.com/ ]]; then
    echo "ERROR: That doesn't look like a Slack webhook URL"
    exit 1
fi

# Test the webhook
echo "Testing webhook..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d '{"text":"🛡️ ClawAV test message — webhook configured successfully!"}')

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Webhook test successful! Check your Slack channel."
else
    echo "❌ Webhook test failed (HTTP $HTTP_CODE). Check the URL and try again."
    exit 1
fi

# Update config file
if [ -f "$CONFIG_FILE" ]; then
    # Replace the webhook_url line
    sed -i "s|^webhook_url = .*|webhook_url = \"$WEBHOOK_URL\"|" "$CONFIG_FILE"
    # Ensure enabled = true exists in slack section
    if ! grep -q '^enabled = true' "$CONFIG_FILE"; then
        sed -i '/^\[slack\]/a enabled = true' "$CONFIG_FILE"
    fi
    echo "✅ Config updated: $CONFIG_FILE"
else
    echo "⚠️  Config file not found at $CONFIG_FILE"
    echo "    Add this to your config.toml [slack] section:"
    echo "    webhook_url = \"$WEBHOOK_URL\""
    echo "    enabled = true"
fi

echo ""
echo "Done! ClawAV will now send alerts to Slack independently."
