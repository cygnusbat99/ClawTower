#!/bin/bash
# Install ClawAV polkit policy
sudo cp assets/com.clawav.policy /usr/share/polkit-1/actions/
echo "Polkit policy installed"
