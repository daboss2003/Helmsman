# Installation

> **Getting started · Page 2 of 3** — [← Introduction](./introduction.md) · [Documentation home](./README.md) · Next: [First steps →](./first-steps.md)

This page gets Helmsman running on a host: the binary, the **root of trust** (master key + credentials, generated over SSH), the `config.yaml`, the read-only Docker socket-proxy, and the systemd unit. By the end, Helmsman is serving its loopback admin UI behind automatic HTTPS at the edge.

Everything secret here is generated **on the host over SSH** and read from `/dev/tty` — never passed as a command-line argument or environment variable.

---

## Prerequisites

- A **Linux host** with `systemd`.
- **Docker** with the Compose plugin (`docker compose`).
- **Root/SSH access** to the host.
- For the **write plane** (deploy, on-box builds, setup scripts): **≥ 1 GB RAM**. The managed edge and read-only monitoring run fine on a small VPS. (See the [resource gate](./architecture.md).)

---

## Step 1 — Put the binary on the host

Helmsman is a single static binary. Build it (`go build ./cmd/helmsman`) or download a release, then install it on the host's `PATH`:

```bash
install -m0755 helmsman /usr/local/bin/helmsman
helmsman version
```

---

## Step 2 — Generate the root of trust (over SSH)

These commands print secrets to stdout/tty. Run them in your SSH session and paste the results into `config.yaml` in the next step.

```bash
# The AES-256-GCM master key that encrypts secrets at rest.
helmsman gen-key
# → encryption_key: <base64-key>

# An argon2id hash of your operator password (the password is read from /dev/tty,
# never from argv or the environment).
helmsman hash-password
# → password_hash: $argon2id$v=19$m=8192,t=2,p=1$...

# Optional but recommended: a TOTP secret for 2FA.
helmsman gen-totp
# → totp_secret: ...   (+ an otpauth:// URL to add to your authenticator)
```

> **Keep the key safe.** The master key decrypts every secret Helmsman stores. Back it up out-of-band; if you lose it, encrypted data is unrecoverable. After your first boot, `helmsman verify-key` confirms the configured key still matches the database (Step 6).

---

## Step 3 — Write `config.yaml`

Create `/etc/helmsman/config.yaml`. It is **Tier-1 configuration** — the SSH-only root of trust — so it is owned `root`, group-readable by the service group, and **never group-writable**. Helmsman **refuses to boot** on insecure permissions, an empty allowlist, a wrong-length key, or an invalid auth hash.

```yaml
# /etc/helmsman/config.yaml   (root:helmsman, mode 0640)
bind_addr: "127.0.0.1:9000"        # the admin UI binds loopback ONLY; the edge fronts it

encryption_key: "<from gen-key>"

ip_allowlist:                       # empty = deny-all (fail-closed). NEVER allow-all.
  - "203.0.113.10/32"              # your office/VPN egress IP(s)

auth:
  username: "operator"
  password_hash: "<from hash-password>"
  # totp_secret: "<from gen-totp>"  # optional 2FA

edge:
  mode: "managed"                   # default: Helmsman owns Caddy + HTTPS
  acme_email: "you@example.com"     # required in managed mode (fail-closed if empty)
  acme_ca: "https://acme-v02.api.letsencrypt.org/directory"

data_dir: "/var/lib/helmsman"       # the DB + state live here (mode 0700)
```

The full set of keys (sessions, cookies, monitor cadence, retention, alerting, the resource-gated blocks) is in the [configuration reference](./architecture.md). The defaults are safe; you can grow into them.

> **Tier-1 vs the rest.** `config.yaml` holds only what must never be web-writable: the key, the IP allowlist, the bind address, and auth. Everything app-shaped lives in [`helmsman.yaml`](./definition-file.md) (Tier-3) and the [host file](./host-file.md) (Tier-2). See [the 3-tier model](./host-file.md).

---

## Step 4 — Install the systemd unit and start

Helmsman runs as its **own** systemd unit (not a compose container) so it can never appear in a managed project's container list, and a stack `down` can't take it down. It runs non-root, memory-capped, and heavily sandboxed.

The shipped unit is `deploy/systemd/helmsman.service`. Create the user, state dir, and config, then enable it:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin helmsman
usermod -aG docker helmsman
install -d -o helmsman -g helmsman -m0700 /var/lib/helmsman
install -o root -g helmsman -m0640 config.yaml /etc/helmsman/config.yaml
install -m0644 deploy/systemd/helmsman.service /etc/systemd/system/helmsman.service

systemctl daemon-reload && systemctl enable --now helmsman
systemctl status helmsman
```

Notable hardening in the unit (see the file for the full list): `MemoryMax=192M` (kills inside the cgroup, including forked docker children), `GOMEMLIMIT` under the cap, `NoNewPrivileges`, `ProtectSystem=strict`, a `@system-service` syscall filter, an empty capability set (only the **edge child** gets `CAP_NET_BIND_SERVICE`), and egress `IPAddressDeny=any` so even a perfect RCE can't reach cloud metadata or call home. Tune `IPAddressAllow` to your Docker app subnet + ACME CA range.

> **SIGHUP reloads safely.** `systemctl reload helmsman` hot-swaps the IP allowlist, auth, retention policy, and the API-token CIDR gate — never the key or bind address. A bad edit is rejected and the previous policy is kept (fail-closed).

### You don't run any Docker commands

That's the last setup step. From here you only ever write [`helmsman.yaml`](./definition-file.md) — you never run `docker`, `docker compose`, or `certbot` yourself. In particular:

- **The read-only Docker socket-proxy is managed for you.** Helmsman **never** mounts the raw Docker socket; it reads container state through a read-only, verb-allowlisted proxy on loopback `:2375` (only `CONTAINERS`/`INFO`/`VERSION` are enabled — every write verb is denied). Helmsman **brings this proxy up itself at boot** from an embedded, locked-down compose; you don't start it. (Write-plane actions never use the proxy — Helmsman shells out to `docker compose` for those, gated.)
- **The edge + TLS are managed for you.** The child Caddy and ACME are supervised by Helmsman.

> **Advanced — run your own proxy.** If you'd rather operate the socket-proxy (or a remote Docker endpoint) yourself, set `docker.external_proxy: true` in `config.yaml` and point `docker.proxy_addr` at it; Helmsman then leaves it alone. The reference compose is at `deploy/socket-proxy/docker-compose.yml`.

---

## Step 5 — Verify the key/DB match

Before the next write can touch the database, confirm the configured key actually opens it. This catches a key/DB mismatch *before* it corrupts data:

```bash
helmsman verify-key
```

---

## You're installed

In `managed` mode the child Caddy is now serving HTTPS, but it **proxies to nothing** until you add a route, and exposes **no admin surface** unless you explicitly set `admin.hostname`. That's intentional: nothing is public until you say so.

> **Next: [First steps →](./first-steps.md)** — log in over an SSH tunnel and deploy your first app.

See also: [CLI reference](./cli.md) · [Security model](./security.md) · [Edge & TLS](./edge-and-tls.md)
