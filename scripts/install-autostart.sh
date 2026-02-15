#!/bin/bash
# Install ClawAV tray autostart for current user
mkdir -p ~/.config/autostart
cp assets/clawav-tray.desktop ~/.config/autostart/
echo "Autostart installed for $(whoami)"
