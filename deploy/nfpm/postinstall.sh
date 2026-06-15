#!/bin/sh
# Runs after `apt install helmsman` / `dnf install helmsman`. It creates the service
# account and directories Helmsman needs, but does NOT start the service — the operator
# must first write /etc/helmsman/config.yaml (the master key, login, and IP allowlist
# are generated over SSH; see /usr/share/helmsman/config.example.yaml).
set -e

# Dedicated low-privilege service user, in the docker group so it can talk to Docker.
if ! getent group helmsman >/dev/null 2>&1; then
    groupadd --system helmsman
fi
if ! getent passwd helmsman >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid helmsman helmsman
fi
if getent group docker >/dev/null 2>&1; then
    usermod -aG docker helmsman || true
fi

# Config dir (root-owned, group-readable by the service) and state dir (private).
install -d -o root -g helmsman -m 0750 /etc/helmsman
install -d -o helmsman -g helmsman -m 0700 /var/lib/helmsman

# Pick up the shipped unit.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

cat <<'EOF'

Helmsman installed. Next steps (over SSH):
  1. Generate secrets:   helmsman gen-key ; helmsman hash-password
  2. Write the config:   /etc/helmsman/config.yaml
                         (template at /usr/share/helmsman/config.example.yaml)
  3. Start it:           systemctl enable --now helmsman

Docs: https://github.com/helmsman/helmsman/tree/main/docs
EOF
