# Install Helmsman

> **Getting started, 2 of 3** · [← Introduction](./introduction.md) · Next: [Deploy your first app →](./first-steps.md)

This is the one part you do over SSH. It takes about five minutes: put the program on your server, create your login, and start it. After this, everything happens in the dashboard.

## What you need

- A **Linux server** with `systemd` (any cheap VPS works).
- **Docker** installed, with the Compose plugin (`docker compose`).
- **SSH access** to the server.
- **1 GB of RAM or more** if you want to deploy and build apps on the box. Monitoring and HTTPS run fine on a smaller server.

## 1. Install the program

**Debian / Ubuntu (recommended)** — install from the APT repo and get `apt upgrade` updates:

```bash
curl -fsSL https://apt.helmsman.sh/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/helmsman.gpg
echo "deb [signed-by=/usr/share/keyrings/helmsman.gpg] https://apt.helmsman.sh stable main" | sudo tee /etc/apt/sources.list.d/helmsman.list
sudo apt update && sudo apt install helmsman
```

The package creates the `helmsman` service user and installs the systemd unit; skip the user/dir setup in Step 4. (Fedora/RHEL: a matching `.rpm` is on each [release](https://github.com/daboss2003/helmsman/releases).)

**Any Linux (manual)** — download the binary for your architecture from the [releases page](https://github.com/daboss2003/helmsman/releases) and install it:

```bash
install -m0755 helmsman /usr/local/bin/helmsman
helmsman version
```

## 2. Create your login and encryption key

These commands create the secrets Helmsman needs. You run them over SSH — never in a browser — so your master key and password never travel anywhere they shouldn't. They print what to paste into your config in the next step.

```bash
# A master key that encrypts your stored secrets. Back this up somewhere safe.
helmsman gen-key

# Your dashboard password (you'll be prompted to type it; it's never shown or logged).
helmsman hash-password

# Optional: turn on two-factor sign-in.
helmsman gen-totp
```

> **Keep your master key safe.** It's what unlocks your stored secrets. Save a copy somewhere separate from the server. If you lose it, the encrypted data can't be recovered.

## 3. Write your config file

Create `/etc/helmsman/config.yaml`. This is the only file you edit by hand, and it only holds the essentials: your key, your login, who's allowed to reach the dashboard, and your email for HTTPS certificates.

```yaml
# /etc/helmsman/config.yaml
bind_addr: "127.0.0.1:9000"        # the dashboard is private — only reachable as below

encryption_key: "<paste from gen-key>"

ip_allowlist:                       # who may reach the dashboard (your IP / VPN)
  - "203.0.113.10/32"

auth:
  username: "operator"
  password_hash: "<paste from hash-password>"
  # totp_secret: "<paste from gen-totp>"   # optional two-factor

edge:
  mode: "managed"                   # Helmsman runs the web server + HTTPS for you
  acme_email: "you@example.com"     # used by Let's Encrypt for your certificates

admin:
  hostname: "admin.example.com"     # Helmsman serves the dashboard here over HTTPS,
                                    # behind your ip_allowlist. Point its DNS at this
                                    # server. Omit it and you reach the dashboard over
                                    # an SSH tunnel instead.

data_dir: "/var/lib/helmsman"       # where Helmsman keeps its data
```

> **You don't run a proxy or forward a port.** With `admin.hostname` set, the managed edge serves the dashboard at that address over HTTPS (still behind your IP allowlist). Point the hostname's DNS at your server and that's it. Leave `admin.hostname` out only if you'd rather reach the dashboard over an SSH tunnel.

Helmsman validates this file at startup. If a required value is missing or the file permissions are too open, it stops with a clear message explaining what to fix.

> Everything *else* about your apps lives in the dashboard (or an optional per-app file). This config is just the foundation.

## 4. Start it

Helmsman runs as a normal background service. The repo ships a ready-made service file (`deploy/systemd/helmsman.service`) that runs it locked-down and memory-limited. Set up the service account and start it:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin helmsman
usermod -aG docker helmsman
install -d -o helmsman -g helmsman -m0700 /var/lib/helmsman
install -o root -g helmsman -m0640 config.yaml /etc/helmsman/config.yaml
install -m0644 deploy/systemd/helmsman.service /etc/systemd/system/helmsman.service

systemctl daemon-reload && systemctl enable --now helmsman
systemctl status helmsman
```

That's it. **You won't run any Docker commands** — Helmsman sets up everything it needs to talk to Docker (a locked-down, read-only connection) and runs your HTTPS edge itself. From here on, it's all in the dashboard.

> Changed your mind about who can reach the dashboard, or your password? Edit the config and run `systemctl reload helmsman` — it picks up the change safely, and ignores the edit if it's invalid.

## 5. You're ready

Helmsman is now running and serving HTTPS. Nothing is published yet — that happens when you add an app and give it a domain.

> **Next: [Deploy your first app →](./first-steps.md)**

---

*Want the security and hardening details of the service file (memory caps, sandboxing, network egress lock-down)? See [How it works & why it's safe](./architecture.md). Running your own Docker connection instead of the built-in one? Set `docker.external_proxy: true` — see [the CLI reference](./cli.md).*
