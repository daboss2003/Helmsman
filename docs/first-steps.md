# First steps

> **Getting started · Page 3 of 3** — [← Installation](./installation.md) · [Documentation home](./README.md)

Helmsman is installed and serving. This page takes you through your first login and your first deployed app, online with HTTPS. It uses the **dashboard** path (the simplest first run); the equivalent **declarative** path (`helmsman.yaml`) is at the end.

---

## 1. Log in over an SSH tunnel

The admin UI binds **loopback only**. The simplest first login forwards the loopback port over SSH:

```bash
ssh -L 9000:127.0.0.1:9000 operator@your-host
# then open http://127.0.0.1:9000 in your browser
```

Sign in with the `operator` username and the password you hashed during [installation](./installation.md) (plus your TOTP code if you enabled it).

> Later, you can front the dashboard through the edge by setting `admin.hostname` — it stays behind the IP allowlist and HTTPS. The SSH tunnel always remains as the recovery floor.

You'll land on **Overview**: host CPU/memory/disk, a live tile per app, and (once apps exist) their health. Nothing is here yet — let's fix that.

---

## 2. Deploy your first app (dashboard)

Click **New app**. You have two ways in, both of which converge on the *same* validated, gated write path:

- **Guided form (Mode 1)** — fill a typed form; Helmsman generates the compose deterministically from a vetted template. No form input can ever emit `privileged`, `cap_add`, or host namespaces. *Recommended for a new stack.*
- **Paste existing (Mode 2)** — paste an existing `docker-compose.yml`. Helmsman runs it through a **validating importer** (not an interpreter): size-capped, `${VAR}` resolved first, with line-anchored rejections for anything unsafe.

Then:

1. **Validate** — click *Validate* for a dry, read-plane preview. Your bytes go through the **§5.6 chokepoint** (the one validator every path shares) and the edge-conflict gate. Nothing is written. Fix anything it flags.
2. **Commit** — Helmsman writes the app's files atomically and records it as a provisioned app.
3. **Deploy** — click *Deploy*. The write plane runs (`docker compose up/pull`) behind the [resource gate](./architecture.md), one docker child at a time, with the live deploy output streamed to your browser.

When it's up, the app appears on **Overview** with a live health tile and a per-service table (state, health, CPU, memory, restarts, logs).

> **Expose internal ports only.** Your services should `expose` their port to the internal Docker network (e.g. `8080`). They must **not** publish `80`/`443` — the managed edge owns those. Helmsman's validator rejects an app that tries to grab the public ports.

---

## 3. Set a secret

Never put plaintext credentials in compose or env. Helmsman uses **secrets by reference**: you declare a name in config and provide the value out-of-band, encrypted at rest (AES-256-GCM) and shown only via an audited reveal.

**From the dashboard:** open your app → **Env** → add a write-only secret value. It's masked immediately and rendered into the app's live `.env` on the next deploy.

**From the CLI** (values read from the file, never argv):

```bash
helmsman secret import --slug my-app --from ./prod.env
```

The importer classifies each key, **hard-stops** if a value looks like a literal secret that should be by-reference, diffs against what's stored, and ingests by reference. Your uploaded file is an *import source* — never the live file Helmsman runs. See [Env import-and-own](./env-import.md) and [Config files & secrets](./config-files-and-secrets.md).

---

## 4. Put it online with HTTPS

Open **Edge**. Add a route for your app:

- **Hostname** — the public name, e.g. `app.example.com` (point its DNS at the host first).
- **Upstream** — a selector against *this app's* containers, e.g. `web:8080`.

Save. Helmsman re-renders the **whole** edge config from typed structs (you never hand-edit Caddy), reloads the child Caddy, and runs ACME to issue a certificate for the hostname. Within moments `https://app.example.com` is live with a valid cert and HSTS.

> You author *routes*, not Caddy. The operator never writes proxy config — it's derived. See [Edge & TLS](./edge-and-tls.md).

---

## 5. Optional: the declarative path (`helmsman.yaml`)

The dashboard is one front door; the definition file is the other, and they're the *same trust path*. `helmsman.yaml` is the **source of truth** for an app's managed surface — and the **dashboard writes back to it** on every change, so the file and live state never drift.

Author it in your repo and validate it from the CLI (read-plane, safe in CI):

```bash
# Scaffold one from an existing compose:
helmsman init --from-compose ./docker-compose.yml > helmsman.yaml

# Validate it through the same §5.6 + edge-conflict chokepoints (no DB, no writes):
helmsman validate ./helmsman.yaml
```

A minimal example:

```yaml
apiVersion: helmsman/v1
kind: App
metadata:
  slug: my-app                      # immutable after first apply
spec:
  compose:
    inline: |
      services:
        web:
          image: ghcr.io/example/web:1.4.2
          expose: ["8080"]          # internal only; the edge owns 80/443
  env:
    - LOG_LEVEL: "info"
    - DATABASE_URL: "secret: DATABASE_URL"   # by reference
  secrets:
    - name: DATABASE_URL
  edge:
    routes:
      - hostname: "app.example.com"
        upstream: "web:8080"
```

Three rules to internalize: **unknown keys are a hard reject**, **secrets are by reference only** (the file is safe to commit), and a reference resolves **only within its own app's namespace**. Full schema, the 3-way merge, conflict review, and rollback are in the [definition file reference](./definition-file.md).

For repo-backed apps, connect the repo and let Helmsman **auto-fetch** new commits while keeping every **deploy manual and sha-pinned** — see [Git integration & GitOps](./gitops.md).

---

## Where to go from here

You've deployed an app, secured a secret, and put it online with HTTPS. Next, by what you need:

- **Understand the safety guarantees** → [Security model](./security.md) · [Architecture](./architecture.md)
- **Run from a git repo** → [Git integration & GitOps](./gitops.md)
- **Templated config files & certs in the app** → [Config files & secrets](./config-files-and-secrets.md)
- **Keep it healthy under load** → [Scaling & self-healing](./scaling-and-self-healing.md) · [Alerting](./alerting.md)
- **Protect your data** → [Backup & recovery](./backup-and-recovery.md)
- **Run many apps on one host** → [The host file & 3-tier config](./host-file.md)
- **Every command** → [CLI reference](./cli.md)

[← Back to the documentation home](./README.md)
