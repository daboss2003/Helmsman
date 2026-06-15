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

> **From here on, the dashboard is your control surface.** You used SSH once at [install](./installation.md) for the root of trust (the master key + password); day-to-day — apps, secrets, edge routes, repos, scaling, alerts — is all done in the browser. (A couple of advanced/bulk operations have optional CLI equivalents, called out where they apply.)
>
> Later you can front the dashboard through the edge by setting `admin.hostname` (it stays behind the IP allowlist and HTTPS), so you don't even need the tunnel. The SSH tunnel always remains as the recovery floor.

You'll land on **Overview**: host CPU/memory/disk, a live tile per app, and (once apps exist) their health. Nothing is here yet — let's fix that.

---

## 2. Deploy your first app (dashboard)

There are two ways to add an app, and **you never paste raw Docker/compose** — Helmsman *owns* the compose and generates it for you, so a dangerous key (`privileged`, `cap_add`, host namespaces) is literally not expressible:

- **Guided form** — click **New app**, fill a typed form (image, ports, volumes, env). Helmsman generates the compose deterministically from a vetted template. *Recommended for a new stack.*
- **Connect a git repo** — for a repo-backed app, click **Connect repo** instead (see step 5). Helmsman reads the compose from your repository.

This page uses the guided form. Click **New app**, fill it in, then:

1. **Validate** — click *Validate* for a dry, read-plane preview. Your bytes go through the **§5.6 chokepoint** (the one validator every path shares) and the edge-conflict gate. Nothing is written. Fix anything it flags.
2. **Commit** — Helmsman writes the app's files atomically and records it as a provisioned app.
3. **Deploy** — click *Deploy*. The write plane runs (`docker compose up/pull`) behind the [resource gate](./architecture.md), one docker child at a time, with the live deploy output streamed to your browser.

When it's up, the app appears on **Overview** with a live health tile and a per-service table (state, health, CPU, memory, restarts, logs).

> **Expose internal ports only.** Your services should `expose` their port to the internal Docker network (e.g. `8080`). They must **not** publish `80`/`443` — the managed edge owns those. Helmsman's validator rejects an app that tries to grab the public ports.

---

## 3. Set a secret

Never put plaintext credentials in compose or env. Helmsman uses **secrets by reference**: you set a value in the dashboard, it's encrypted at rest (AES-256-GCM), and it's rendered into the app's live `.env` at deploy and shown only via an audited reveal.

Open your app → **Env** → add a write-only secret value. It's masked immediately. Add your literal (non-secret) env there too. That's it — no files, no SSH.

> **Optional — bulk import a `.env` over SSH.** If you already have a big `.env`, `helmsman secret import --slug my-app --from ./prod.env` ingests it (classifying each key, hard-stopping on literal secrets that should be by-reference). It's a convenience for the first big import — the dashboard is the day-to-day surface. See [Env import-and-own](./env-import.md) and [Config files & secrets](./config-files-and-secrets.md).

---

## 4. Put it online with HTTPS

Open **Edge**. Add a route for your app:

- **Hostname** — the public name, e.g. `app.example.com` (point its DNS at the host first).
- **Upstream** — a selector against *this app's* containers, e.g. `web:8080`.

Save. Helmsman re-renders the **whole** edge config from typed structs (you never hand-edit Caddy), reloads the child Caddy, and runs ACME to issue a certificate for the hostname. Within moments `https://app.example.com` is live with a valid cert and HSTS.

> You author *routes*, not Caddy. The operator never writes proxy config — it's derived. See [Edge & TLS](./edge-and-tls.md).

---

## 5. Run from a git repo (connect once — no webhook setup)

For a repo-backed app, click **Connect repo** in the dashboard and give it:

- the **repository URL** and **branch**,
- the **path to your compose** in the repo (e.g. `docker-compose.yml`),
- for a private repo, a **deploy key or token** (the form shows you what it needs).

That's the whole setup. **You don't register a webhook or hand it a config file** — Helmsman checks each connected repo for new commits on its own (it fetches on a cadence in the background). When a new commit lands you see an **"update available"** with a diff; click **Deploy** to ship that exact reviewed commit (sha-pinned). Prefer hands-off? Turn on **auto-deploy** and Helmsman ships clean fast-forward updates for you.

> Want *instant* deploys instead of waiting for the next check? There's an optional webhook you can add — but it's not required; connecting the repo is enough.

This is the "I just connected it online and it works" flow — no SSH, no webhook plumbing.

---

## 6. Optional: author `helmsman.yaml` directly

Everything above is stored in a per-app `helmsman.yaml` that the **dashboard writes for you** — you never have to touch it. But it *is* the source of truth, so you can also author it in your repo and let the dashboard manage it from there (the file and live state never drift; the dashboard writes back on every change).

If you go this route, two read-plane CLI helpers exist (safe in CI, no writes):

```bash
helmsman init --from-compose ./docker-compose.yml > helmsman.yaml  # scaffold one
helmsman validate ./helmsman.yaml                                   # check it
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
