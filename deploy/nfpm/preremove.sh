#!/bin/sh
# Runs before the package is removed: stop and disable the service so removal is clean.
# The config and data dirs are intentionally left in place (removing them would destroy
# the operator's keys, secrets, and state) — delete /etc/mooring and /var/lib/mooring
# by hand if you really want a full wipe.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now mooring >/dev/null 2>&1 || true
fi
