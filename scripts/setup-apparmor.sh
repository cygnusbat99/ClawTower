#!/usr/bin/env bash
# Thin wrapper — delegates to the embedded profiles in the clawtower binary.
# Kept for backwards compatibility with existing documentation/scripts.
exec /usr/local/bin/clawtower setup-apparmor "$@"
