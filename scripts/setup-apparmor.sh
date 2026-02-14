#!/usr/bin/env bash
set -euo pipefail

# ClawAV — AppArmor Profile Setup for OpenClaw Agent
# Installs and enforces the AppArmor profile restricting the openclaw user.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE_SRC="${SCRIPT_DIR}/../apparmor/usr.bin.openclaw"
PROFILE_DST="/etc/apparmor.d/usr.bin.openclaw"

echo "=== ClawAV AppArmor Setup ==="

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Check AppArmor is installed
if ! command -v apparmor_parser &>/dev/null; then
    echo "Installing AppArmor..."
    apt-get update -qq
    apt-get install -y apparmor apparmor-utils
fi

# Check AppArmor is enabled
if ! aa-enabled 2>/dev/null; then
    echo "WARNING: AppArmor is not enabled in the kernel"
    echo "Add 'apparmor=1 security=apparmor' to kernel command line"
    echo "Edit /boot/firmware/cmdline.txt on Raspberry Pi"
    echo ""
    echo "Installing profile anyway..."
fi

# Install profile
if [[ ! -f "${PROFILE_SRC}" ]]; then
    echo "ERROR: Profile not found at ${PROFILE_SRC}"
    exit 1
fi

cp "${PROFILE_SRC}" "${PROFILE_DST}"
echo "Profile installed to ${PROFILE_DST}"

# Parse and load in enforce mode
apparmor_parser -r "${PROFILE_DST}" && {
    echo "Profile loaded in enforce mode"
} || {
    echo "WARNING: Failed to load profile (AppArmor may not be enabled)"
    echo "Profile is installed — it will be loaded on next boot if AppArmor is enabled"
}

# Verify
if command -v aa-status &>/dev/null; then
    echo ""
    echo "AppArmor status:"
    aa-status 2>/dev/null | grep -A5 "enforce" || true
fi

echo ""
echo "=== AppArmor Setup Complete ==="
echo "Profile: ${PROFILE_DST}"
echo "To check status: sudo aa-status"
echo "To set complain mode (testing): sudo aa-complain ${PROFILE_DST}"
echo "To set enforce mode: sudo aa-enforce ${PROFILE_DST}"
