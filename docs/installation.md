# Install Helmsman

> **Getting started, 2 of 3** · [← Introduction](./introduction.md) · Next: [Deploy your first app →](./first-steps.md)

This is the one part you do over SSH. It takes about five minutes: put the program on your server, create your login, and start it. After this, everything happens in the dashboard.

## What you need

- A **Linux server** with `systemd` (any cheap VPS works).
- **Docker** installed, with the Compose plugin (`docker compose`).
- **Caddy** — the managed HTTPS edge supervises a child Caddy for `:80`/`:443` + automatic certificates. It isn't bundled (it's third-party, like Docker); `helmsman setup` installs it for you (below), or the `.deb`/`.rpm` pulls it in if you've added Caddy's apt repo.
- **SSH access** to the server.
- **1 GB of RAM or more** if you want to deploy and build apps on the box. Monitoring and HTTPS run fine on a smaller server.

> **Why doesn't Helmsman just install these itself at runtime?** Because the running service is deliberately **unprivileged** — it can't install packages, edit host DNS, or grant capabilities. That's the security model: a compromised dashboard must not be able to either. So prerequisites are a one-time, admin-run, root job — which `helmsman setup` makes a single command (it runs as *you* over SSH, not as the service).

## 1. Install the program

> `apt install helmsman` with nothing else only works for packages that ship in Debian/Ubuntu's own repositories (that's why `apt install python` just works). Helmsman is third-party, so `apt` needs to be told where to find it once — exactly like installing Docker, Chrome, or Tailscale. Pick one:

**Quickest — install the `.deb` directly.** Download the `.deb` for your architecture from the [latest release](https://github.com/daboss2003/Helmsman/releases/latest), then:

```bash
sudo apt install ./helmsman_<version>_linux_amd64.deb
```

`apt` pulls in any dependencies, creates the `helmsman` service user, and installs the systemd unit — so you can **skip Step 4**. To update later, download the newer `.deb` and run the same command.

> **Seeing `N: Download is performed unsandboxed as root … couldn't be accessed by user '_apt' … Permission denied`?** That's a harmless *note*, not a failure. `apt`'s unprivileged sandbox user can't read files in your home directory (it's mode `0750`), so `apt` copies the `.deb` as root and the install completes anyway — confirm with `dpkg -l helmsman`. To avoid the note, install from a path `_apt` can read (download into `/tmp`), or skip the sandbox with `dpkg`:
>
> ```bash
> sudo dpkg -i helmsman_<version>_linux_amd64.deb && sudo apt-get install -f
> ```

**Best for updates — add the signed APT repo (once).** Then `sudo apt upgrade` keeps Helmsman current automatically, and every download is signature-checked:

```bash
curl -fsSL https://daboss2003.github.io/Helmsman/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/helmsman.gpg
echo "deb [signed-by=/usr/share/keyrings/helmsman.gpg] https://daboss2003.github.io/Helmsman stable main" | sudo tee /etc/apt/sources.list.d/helmsman.list
sudo apt update && sudo apt install helmsman
```

(Fedora/RHEL: a matching `.rpm` is on each release — `sudo dnf install ./helmsman_<version>_linux_amd64.rpm` (or `_linux_arm64.rpm`).)

**Any other Linux — the raw binary.** Grab the binary for your architecture from the [releases page](https://github.com/daboss2003/Helmsman/releases) and put it in place (update by replacing the file). With this option you also do Step 4 to create the service:

```bash
install -m0755 helmsman /usr/local/bin/helmsman
helmsman version
```

### Host prerequisites — what's automatic, and the few things you do once

**Most host prep is automatic.** The package's systemd unit + postinstall already create the
runtime dir (`/run/helmsman`) and the writable state dirs, grant the one capability the edge needs
(`CAP_NET_BIND_SERVICE`, so Caddy/nginx bind `:80`/`:443`/`:53` non-root), set a writable `HOME`
and a sane `MemoryMax`, and leave the egress filter off by default. You don't apply drop-ins or
tune the unit.

There are only a **few one-time steps you do by hand** — `helmsman doctor` tells you if any are
missing (it's read-only; run it any time to verify the box):

```bash
helmsman doctor              # read-only: reports anything off + the exact fix
sudo helmsman setup --yes    # installs the Caddy binary — the managed edge needs it
```

That's everything for a normal HTTPS app. Two extras apply **only in specific cases**:

- **A non-HTTP service on a privileged port (a DNS resolver on `:53`, MQTT, …)?** Install the L4
  load balancer's nginx + stream module, and — only if you bind `:53` — free it from
  `systemd-resolved` (Helmsman never rewrites host DNS for you, because getting it wrong takes the
  box's own DNS down):
  ```bash
  sudo helmsman setup --l4 --yes      # nginx + the stream module
  # then, ONLY for a :53 resolver, free the port from systemd-resolved:
  printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
  sudo systemctl restart systemd-resolved
  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf   # the real upstreams — NOT stub-resolv.conf
  getent hosts github.com             # confirm host DNS still resolves
  ```

- **(Recommended) Cap Docker's container logs.** Helmsman *streams* logs (it never buffers them in
  memory or its DB), but Docker's default `json-file` driver keeps every container's stdout on disk
  **forever** — on a small VPS that fills the disk. `helmsman setup` caps it for you (merges a
  `max-size` into `/etc/docker/daemon.json`, preserving your other settings, then restarts Docker).
  That restart **bounces running containers**, so it's a reviewable step in the plan — run `setup`
  *before* you deploy apps and it's a no-op disruption. The equivalent by hand:
  ```json
  { "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
  ```
  then `sudo systemctl restart docker` (or use the self-rotating `local`/`journald` driver).

When `helmsman doctor` is all-green, the host is ready — there's nothing else to tune.

## 2. Create your login and encryption key

These commands create the secrets Helmsman needs. You run them over SSH — never in a browser — so your master key and password never travel anywhere they shouldn't. They print what to paste into your config in the next step.

```bash
# A master key that encrypts your stored secrets. Back this up somewhere safe.
helmsman gen-key

# Your dashboard password (you'll be prompted to type it; it's never shown or logged).
helmsman hash-password

# Optional: turn on two-factor sign-in. Prints a QR code to scan with your
# authenticator app, plus the secret to paste into your config below.
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
  hostname: "admin.example.com"     # the dashboard's address; point its DNS at this server

data_dir: "/var/lib/helmsman"       # where Helmsman keeps its data
```

Set `admin.hostname` to the address you want the dashboard on, and point that hostname's DNS at your server — Helmsman serves it over HTTPS, behind your IP allowlist. (Prefer not to expose it at all? Leave `admin.hostname` out and reach the dashboard over an SSH tunnel instead — see the next guide.)

Helmsman validates this file at startup. If a required value is missing or the file permissions are too open, it stops with a clear message explaining what to fix.

> Everything *else* about your apps lives in the dashboard (or an optional per-app file). This config is just the foundation.

## 4. Start it

Helmsman runs as a normal background service. The repo ships a ready-made service file (`deploy/systemd/helmsman.service`) that runs it locked-down and memory-limited. Set up the service account and start it:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin helmsman
usermod -aG docker helmsman
install -d -o helmsman -g helmsman -m0700 /var/lib/helmsman
install -d -o helmsman -g helmsman -m0700 /var/lib/helmsman-apps   # per-app run dirs
install -d -o helmsman -g helmsman -m0700 /var/lib/caddy           # edge data/cert store
install -o root -g helmsman -m0640 config.yaml /etc/helmsman/config.yaml
install -m0644 deploy/systemd/helmsman.service /etc/systemd/system/helmsman.service

systemctl daemon-reload && systemctl enable --now helmsman
systemctl status helmsman
```

That's it. **You won't run any Docker commands** — Helmsman sets up everything it needs to talk to Docker (a locked-down, read-only connection) and runs your HTTPS edge itself. From here on, it's all in the dashboard.

### Editing the config file (reload vs restart)

`/etc/helmsman/config.yaml` is read at **startup**. After you hand-edit it, Helmsman won't notice the change on its own — you have to tell it to pick it up, and **how depends on what you changed**:

| You changed… | Apply with |
|---|---|
| Who can reach the dashboard (`ip_allowlist`, `trust_proxy`, `trusted_proxies`), your login (`auth.username`, `auth.password_hash`, `auth.totp_secret`), or log retention (`retention.*`) | **`sudo systemctl reload helmsman`** — hot-applied, no downtime |
| **Anything else** — the master `encryption_key`, `bind_addr`, `edge.*` (incl. `l4_enabled`), `admin.hostname`, `github.*`, `alerting.*`, `session.*`, `cookie.*`, `docker.*`, `protected_projects`, … | **`sudo systemctl restart helmsman`** |

The rule of thumb: only the **allowlist + login + retention** are hot-reloadable; **everything else is read once at boot and needs a restart**. A reload that touches a restart-only setting will *silently do nothing* — so when in doubt, `restart` (it briefly drops the dashboard connection; your apps keep running).

> **Reload is safe:** it validates the new file first and **keeps the old config if the edit is invalid**. One side effect to know: enabling/rotating two-factor (`auth.totp_secret`) on reload **logs you out**, so you re-authenticate with the new factor.

(Most *app* settings — env, routes, scaling, self-healing, ops — aren't in this file at all; you manage them in the dashboard, which applies them live. This file is just the bootstrap essentials.)

## 5. You're ready

Helmsman is now running and serving HTTPS. Nothing is published yet — that happens when you add an app and give it a domain.

> **Next: [Deploy your first app →](./first-steps.md)**

---

*Want the security and hardening details of the service file (memory caps, sandboxing, network egress lock-down)? See [How it works & why it's safe](./architecture.md). Running your own Docker connection instead of the built-in one? Set `docker.external_proxy: true` — see [the CLI reference](./cli.md).*
