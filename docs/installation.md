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

### Check + install host prerequisites

Confirm the box has everything the edge needs (Caddy, Docker, working DNS, the
privileged-ports capability), and let Helmsman install what's missing:

```bash
helmsman doctor              # read-only: reports what's missing + the exact fix
sudo helmsman setup          # prints a fix plan (a dry run — changes nothing)
sudo helmsman setup --yes    # applies it: installs Caddy, the caps drop-in, etc.
```

Add `--l4` to also set up the L4 (TCP/UDP) load balancer's nginx + stream module if
you plan to run a non-HTTP service like a DNS resolver. `setup` never touches host DNS
itself — if you bind `:53` it prints the steps to free it from `systemd-resolved`.

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
