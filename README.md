# Helmsman

> A lightweight, security-first, self-hosted ops dashboard in a single static Go binary.
>
> **Compose runs your containers; Helmsman manages them.**

Helmsman is a single static Go binary (~12–18 MB on disk, ~10–15 MB idle RSS) that gives one operator a CapRover-style dashboard — health, logs, start/stop/redeploy, env and secrets, git deploys, host CPU/RAM/disk — **plus a managed edge** (it owns Caddy and automatic HTTPS for you) **without** a Kubernetes footprint or a heavyweight PaaS's RAM appetite. You point it at one Docker host; an "app" is just a Docker Compose project. Apps that implement Helmsman's versioned [App Ops Interface](./docs/definition-file.md) get rich per-dependency, queue, and snapshot panels; apps that don't fall back to basic Docker-derived health automatically. Its non-negotiable design goal: **hosting Helmsman must never become the thing that gets your server hacked.** Every trade-off below is subordinate to that.

### Features

- **Managed edge out of the box** — Helmsman owns Caddy + Let's Encrypt. You never stand up a proxy, write TLS config, or run certbot. One hostname per app derives the full vhost bundle.
- **Health-driven main view** — rich panels for apps that implement the [Ops Interface](./docs/definition-file.md); container-derived BASIC tiles for everything else, with zero app cooperation required.
- **Lifecycle controls + live logs** — start / stop / restart / redeploy per app or per service, with SSE log and deploy streaming.
- **Encrypted env + secrets** — env blobs, git creds, channel secrets, ops secrets stored AES-256-GCM; the master key lives only in the SSH-edited root-owned config, never in the database, logs, or any web route.
- **Four provisioning modes** — guided form, paste-an-existing-compose, sandboxed setup scripts, and **repo-path GitOps** (point at a `compose_path` in a connected repo).
- **GitOps auto-pull, manual-deploy** — a push fetches and shows you "N commits behind" + a diff; deploying is a deliberate, gated click. No surprise on-box builds.
- **A declarative definition file** — [`helmsman.yaml`](./docs/definition-file.md) is the source of truth for an app's managed surface. The dashboard writes back to it; the CLI applies it without ever opening the UI.
- **Self-healing supervisor** — bounded restart/recreate ladder that pages you (never restart-storms a small box) when it gives up.
- **Optional, pluggable alerting** — built-in engine that defers to apps that already alert, plus never-deferred infra alerts that Helmsman raises about itself. Email, webhook, Telegram, Slack, Discord, ntfy. Zero surface when off.
- **Opt-in auto-scaling** — replica scaling for edge-fronted stateless HTTP services, host-capacity-guarded so it can only ever reduce pressure or refuse.
- **SSH-provisioned auth + IP allowlist** — credentials and the allowlist are set over SSH, never through any web route. argon2id + optional TOTP.
- **SQLite storage, no external services** — `go:embed` ships templates, CSS, JS, and migrations inside the one binary. No `node_modules`, no asset pipeline, no build step.

---

## Documentation

📖 **[Read the full documentation →](./docs/README.md)** — start with the three-page on-ramp:
**[Introduction](./docs/introduction.md) → [Installation](./docs/installation.md) → [First steps](./docs/first-steps.md)**.

The reference pages:

| Document | What it covers |
|---|---|
| [docs/security.md](./docs/security.md) | The threat model, the request pipeline, the §5.6 validator, secrets at rest, the SSRF/XFF invariants, the SBD-1..8 baseline, and the assurance program. |
| [docs/architecture.md](./docs/architecture.md) | Components, runtime placement, data residency, the read/write planes, the one shared reconciler, and the config-file reference. |
| [docs/definition-file.md](./docs/definition-file.md) | The per-app `helmsman.yaml` (`kind: App`) schema, the `spec` projections (incl. generated compose + setup triggers), secrets-by-reference, and the split-plane 3-way sync model. |
| [docs/host-file.md](./docs/host-file.md) | The server-wide host definition (`kind: Host`), the **3-tier config model**, the app registry, and multi-app deploy/setup orchestration. |
| [docs/env-import.md](./docs/env-import.md) | Bringing your `.env`: Helmsman owns the live file, your upload is import-only (values ingested into the encrypted store). |
| [docs/cli.md](./docs/cli.md) | Every CLI subcommand, the root-of-trust commands, read-plane vs write-plane, and the SSH-first flow. |
| [docs/edge-and-tls.md](./docs/edge-and-tls.md) | The managed edge, Caddy + ACME, the three-layer config + read-and-render editor, and cert bindings. |
| [docs/config-files-and-secrets.md](./docs/config-files-and-secrets.md) | Managed config files, selective `{{hm.*}}` templating, and the secret model. |
| [docs/gitops.md](./docs/gitops.md) | The four provisioning modes, repo-path GitOps, auto-pull/manual-deploy, and the git hardening. |
| [docs/scaling-and-self-healing.md](./docs/scaling-and-self-healing.md) | Opt-in auto-scaling + the host-capacity guard, and the self-healing supervisor. |
| [docs/backup-and-recovery.md](./docs/backup-and-recovery.md) | App volume/DB backup + gated restore, and Helmsman's own-state disaster recovery. |
| [docs/alerting.md](./docs/alerting.md) | The alert engine, channels, defer logic, Helmsman-originated infra alerts, and the dead-man's switch. |

> The full internal build plan (every milestone, schema, and red-team finding) lives in [`OPS_DASHBOARD_PLAN.md`](../OPS_DASHBOARD_PLAN.md) at the repo root.

---

## 1. What is Helmsman?

**Compose runs your containers; Helmsman manages them.** Compose is excellent at *bringing a stack up*. It does nothing about TLS, secrets, health visibility, git deploys, alerting, or keeping the edge alive when you `docker compose down` the wrong project. Helmsman is the thin, security-first management layer on top: it watches your Compose projects, fronts them with HTTPS, holds your secrets encrypted, and gives you a dashboard and a CLI — all from one binary you drop on the host.

It is a **generic, reusable tool**. You point it at a Docker host; it is not tied to any one application or repository. An "app" in Helmsman is exactly one Compose project containing N services.

### Feature bullets

- One static binary; trivial deploy; runs as its own `systemd` unit (never a container it could accidentally manage).
- A **health-module-driven** main view (RICH panels) with automatic BASIC fallback.
- Per-app and per-service lifecycle controls, live log streaming, deploy streaming.
- Paste, generate, or repo-point your compose; add env and secrets under Settings; connect a git repo.
- Built-in host RAM / disk / CPU monitoring.
- **Core managed edge** — Helmsman owns Caddy + automatic HTTPS, with an editable, validated Caddy config screen.
- Optional, pluggable alerting and self-healing.
- SQLite storage; SSH-provisioned auth + IP allowlist; **extreme safety** as the paramount requirement.

---

## 2. Why Helmsman, and who it's for

Helmsman is for the **single-host operator** who wants a managed edge, TLS, secrets, and health visibility — *without* a Kubernetes footprint, and without standing up and configuring a reverse proxy or certbot by hand.

You should reach for Helmsman if:

- You run a handful of Docker Compose stacks on **one VPS or bare-metal box** and want them managed, not babysat.
- You want **automatic HTTPS** without writing Caddy/Nginx config or running certbot.
- You want **encrypted secrets** and a clear separation between "containers" and "how they're managed."
- You want the option of **rich health dashboards** for apps that cooperate, and at least basic up/down for everything else.
- You care that the management tool itself is **hardened**, fails closed, and is designed to be survivable even if it is eventually exploited.

You should *not* reach for Helmsman (in v1) if you need a buildpack PaaS (Helmsman deploys an image your CI built; it does not build from source by buildpack), multi-tenant users (it is single-operator, SSH-set creds), or multi-server fan-out (v1 is single-host; the boundaries are forward-compatible with a future Core/Agent split).

**The footprint is the point.** The binary is ~12–18 MB; idle RSS is ~10–15 MB. The always-on edge adds a ~30–40 MB child Caddy **in its own memory-capped slice**. Alerting and setup scripts are optional and add **zero** attack surface when off. A heavyweight PaaS or a Kubernetes control plane wants hundreds of MB before it does anything; Helmsman leaves that RAM for your workloads.

---

## 3. The security-first pitch

Helmsman's design was red-teamed across several passes. The architecture is built around a small number of structural chokepoints, and **everything fails closed** — on any precondition violation it refuses to start or refuses to act, never silently degrading to a less-safe mode. See [./docs/security.md](./docs/security.md) for the complete model; the highlights:

### One validator chokepoint (§5.6)

**Everything** that can reach `docker compose` — whether typed into a form, pasted, generated, produced by a setup script, read from a repo, or applied from a `helmsman.yaml` — passes through **one allowlist validator**. It resolves `${VAR}`/`.env` *first* (validating before interpolation is a known bypass), then rejects any unknown key and the entire dangerous set (`privileged`, `cap_add`, host binds of `/`, `/var/run/docker.sock`, `/etc`, `/proc`, host namespaces, and more). Bind mounts are confined under the app's run directory. Configs are rendered by **marshalling typed structs — never string concatenation.** There is no second, weaker path: the dashboard, the CLI, and SSH are all front-*doors* onto the same reconciler, never new trust *paths*.

### Secrets: master key in the SSH-edited config only

Env blobs, git creds, ops secrets, and channel secrets are encrypted with **AES-256-GCM**. The `encryption_key` lives **only** in `/etc/helmsman/config.yaml` (`0600 root:root`, edited over SSH) — never in the database, never in logs, never in the UI. **No web route reads or writes the master key, the allowlist, the auth hash, or the bind address.** A dedicated `Redacted` type ensures secrets never serialize into logs, errors, `ps` output, or temp files. (Honest trade-off: the reveal-on-click feature *does* put plaintext into your browser for that one POST — it is audited, `no-store`, current-session-only, and stated plainly.)

### The edge is owned safely (the read-and-render model + SBD-1..8)

Because Helmsman owns Caddy, every install is internet-facing — so the edge gets the strongest treatment. The Caddy config you edit is a **declaration of intent that is never executed verbatim**: Helmsman *reads* your input, parses it into the same typed model its own renderer uses, and *re-renders* the document Caddy loads (a **3-layer typed render**: protected base ⊕ app routes ⊕ your additive overlay). If your input **conflicts with anything Helmsman manages, the save is rejected** (fail-to-save on conflict) — never silently merged. A finite, automated **secure-by-default baseline (SBD-1..8)** is proven green on a *fresh install with zero operator config* before any edge-owning release ships: the admin UI is never accidentally public, the Caddy admin API is never public, on-demand TLS is off, only configured app vhosts are served, the edge is network-isolated from the control plane, config is marshalled from typed structs, and the edge can never go down irrecoverably (validate → stage → load with a retained last-known-good and an armed watchdog).

### Read-plane vs write-plane; hardened git

The architecture splits a **hardened-git read-plane** (fetch, diff, status — pure reads, safe even on a tiny box) from a **gated write-plane** (deploy, build, redeploy — behind the resource gate). A git push can *fetch* and show you a diff, but it can **never** reach a build or redeploy on its own. Every git invocation is run config-and-attribute-proof (`GIT_CONFIG_NOSYSTEM`, `core.hooksPath=/dev/null`, `core.symlinks=false`, neutralized filter/textconv drivers, submodules off); file bytes are read via `git cat-file` from the pinned commit's object store, never a working tree that could run smudge filters or hooks.

### Everything fails closed

Empty IP allowlist means **deny-all**, never allow-all. A descriptor an app advertises is **advisory metadata only** and can never move Helmsman's outbound requests off the operator-configured host (the SSRF invariant). The Docker socket is **never** mounted into Helmsman — reads go through a read-only verb-allowlisted `docker-socket-proxy`, writes shell out to `docker compose` with **static argv only** (never a shell, never string interpolation). And the deepest backstop: `systemd` egress allow-listing means even a perfect SSRF or RCE in Helmsman **cannot** reach cloud metadata or call home.

---

## 4. Install & quickstart

### Prerequisites

- A **Linux host** with `systemd`.
- **Docker** with the Compose plugin (`docker compose`).
- Root/SSH access to the host (you provision auth and the master key over SSH — never through a browser).
- For the **write plane** (deploy/redeploy, on-box builds, setup scripts): **≥ 1 GB RAM** (see §9). The managed edge and read-only monitoring run fine on a small VPS.

The quickstart below assumes you have placed the `helmsman` binary somewhere on the host's `PATH` (e.g. `/usr/local/bin/helmsman`). See [./docs/install.md](./README.md) for the systemd unit, the socket-proxy companion, and hardening.

### Step 1 — Generate the master key

```bash
# Run over SSH on the host. Output goes to stdout; never pass keys as argv elsewhere.
helmsman gen-key
# → encryption_key: <base64-key>
```

### Step 2 — Write the config over SSH

Create `/etc/helmsman/config.yaml`, owned `root:root`, mode `0600`. Helmsman **refuses to boot** on insecure perms, an empty allowlist (that would be deny-all anyway), wrong-length keys, or an invalid auth hash.

```yaml
# /etc/helmsman/config.yaml   (0600 root:root)
bind_addr: "127.0.0.1:9000"        # admin UI binds loopback only; the edge fronts it

encryption_key: "<from gen-key>"

ip_allowlist:                       # empty = deny-all (fail-closed); never allow-all
  - "203.0.113.10/32"

auth:
  username: "operator"
  password_hash: "<from hash-password>"   # see Step 3
  # totp_secret: "<from gen-totp>"        # optional

edge:
  mode: "managed"                   # default — Helmsman owns Caddy + HTTPS
  acme_email: "you@example.com"     # fail-closed if empty in managed mode
  acme_ca: "https://acme-v02.api.letsencrypt.org/directory"
  apply_probe_window: "20s"

caddy_editor:
  mode: "strict"                    # strict | review
```

### Step 3 — Hash a password and set first credentials

```bash
helmsman hash-password
# Reads the password from /dev/tty — never from argv or environment.
# → password_hash: $argon2id$v=19$m=8192,t=2,p=1$...
```

Paste the hash into `auth.password_hash` above. Optionally `helmsman gen-totp` to add a TOTP secret. Run `helmsman verify-key` to confirm the key matches the DB before it can corrupt anything on the next write.

### Step 4 — Start Helmsman and log in

Start the `systemd` unit (see [./docs/install.md](./README.md)). In `managed` mode the child Caddy comes up serving HTTPS but **proxies to nothing** until you add a route, and exposes **no admin surface** unless you explicitly set `admin.hostname`. The simplest first login is over an SSH tunnel to the loopback admin port:

```bash
ssh -L 9000:127.0.0.1:9000 operator@your-host
# then browse to http://127.0.0.1:9000 and log in as the operator above
```

### Step 5 — Add your first app

The recommended path is a declarative [`helmsman.yaml`](./docs/definition-file.md) plus `helmsman apply`. A minimal example:

```yaml
# helmsman.yaml
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
          expose: ["8080"]          # internal port only; the edge owns 80/443
  env:
    - LOG_LEVEL: "info"
    - DATABASE_URL: "secret: DATABASE_URL"   # by reference; value set out-of-band
  secrets:
    - name: DATABASE_URL
  edge:
    routes:
      - hostname: "app.example.com"
        upstream: "web:8080"        # a selector against THIS app's containers
```

```bash
helmsman secret set my-app DATABASE_URL   # reads the value from stdin/tty, never argv
helmsman plan  -f helmsman.yaml           # read-plane dry run; masked diff
helmsman apply -f helmsman.yaml           # gated write-plane reconcile
```

Helmsman validates those bytes through the §5.6 chokepoint, provisions env and secrets, brings the app up on its internal port, then wires the edge route and issues TLS for `app.example.com`. You never touched a proxy or certbot.

---

## 5. The Helmsman definition file

`helmsman.yaml` **is the source of truth** for an app's Helmsman-managed surface — and the **dashboard writes back to it** on every settings change, so the file and the live state never drift silently. It is *complementary* to docker-compose: compose describes the containers; `helmsman.yaml` describes how Helmsman manages them. You can author it in your repo and `helmsman apply` it without ever opening the dashboard.

A quick tour of the envelope and `spec` sections:

```yaml
apiVersion: helmsman/v1     # exact-match, fail-closed — an unknown version is rejected
kind: App
metadata:
  slug: my-app              # immutable after first apply
spec:
  compose:        # repo_path or inline  → §5.6 validator
  env:            # non-secret literals, or `secret: NAME` references
  secrets:        # declare NAMES (+ optional generate hint) — never values
  config_files:   # templated files with {{hm.KEY}} bindings
  cert_bindings:  # wire an edge-issued cert into the app, declaratively
  edge:           # routes (Layer-1 input only)
  scaling:        # opt-in replica scaling
  self_healing:   # supervisor policy
  ops_interface:  # the App Ops Interface coordinates
  git:            # repo + auto_deploy (default false)
  resources:      # §9 hints
```

Three rules worth internalizing now: **unknown keys are a hard reject** (so a typo or a smuggled key can't slip through); **secrets are by reference only** (the file is never secret-bearing and is safe to commit to a public repo — values arrive out-of-band); and a secret reference resolves **only within the referencing app's own namespace** (no cross-app secret reads via a committed file). Full schema, the 3-way merge, conflict review, and rollback are in [./docs/definition-file.md](./docs/definition-file.md).

---

## 6. The CLI

The CLI and the dashboard are two thin front-ends producing the **same** typed reconcile request through the **one** §5.6 chokepoint. The only thing the CLI skips is the *web transport* gates (IP allowlist, session, CSRF) because it isn't on the web — it doesn't widen what `apply` is *allowed* to do. Full reference: [./docs/cli.md](./docs/cli.md).

| Command | Plane | One-liner |
|---|---|---|
| `helmsman apply` | write (gated) | Reconcile a `helmsman.yaml` into live state, in dependency order, with whole-app auto-rollback on any step failure. |
| `helmsman plan` | read | Dry-run reconcile; show a masked, in-memory diff. No writes. |
| `helmsman validate` | read | Run a definition (or compose) through the validator and edge-conflict gate without applying. |
| `helmsman status` | read | Show live-vs-declared drift for an app. |
| `helmsman fetch` | read | `git fetch` into the staged ref; compute commits-behind + diff. Touches nothing live. |
| `helmsman promote --sha <40-hex>` | write (gated) | Deploy the exact reviewed commit (the manual, sha-pinned deploy path). |
| `helmsman secret set / rm` | write (gated) | Set or remove a secret value (read from stdin/tty/`--from-file`, never argv). |
| `helmsman def rollback` | write (gated) | Re-derive and re-validate a prior definition version (never a verbatim replay); requires a posture-widening ack if it expands authority. |

**Root-of-trust subcommands** (run over SSH; passwords read from `/dev/tty`, never argv):

| Command | Purpose |
|---|---|
| `helmsman gen-key` | Generate the AES-256-GCM master key. |
| `helmsman hash-password` | Produce an argon2id hash for the config. |
| `helmsman gen-totp` | Generate a TOTP secret. |
| `helmsman verify-key` | Decrypt one column to catch a key/DB mismatch before it corrupts on the next write. |
| `helmsman edge restore-default` | The iron escape hatch — rebuild the protected edge base + admin allowlist from typed structs, drop the overlay, keep app routes. The edge is never irrecoverable; SSH is always the recovery floor. |

---

## 7. The dashboard

The dashboard is server-rendered (`html/template` + htmx + Alpine, ~30 KB of embedded JS; no SPA, no build step) and binds **loopback only**. Reach it over an SSH tunnel, or set `admin.hostname` to front it through the edge behind the IP allowlist.

- **Routes editor** — the default, safe tab: a structured per-app route UI with typed structs and dropdown upstreams. 95% of operators never leave it.
- **Advanced (raw) Caddy editor** — paste or edit raw Caddy config (Caddyfile *or* JSON) as an **additive overlay**. Per the read-and-render model (§3), your text is parsed into the typed model, conflict-checked, validated, and re-marshalled — it can *add*, never redefine, shadow, or weaken what Helmsman owns, and a conflicting save is rejected with a typed error pointing at the offending path. See [./docs/edge.md](./docs/edge-and-tls.md).
- **Stat-only secret panels** — file-mounted secrets (TLS keypairs, credential files) are shown as a **present/missing** panel by `stat` — Helmsman **never reads their contents**. Env-style secrets are masked and write-only, with an audited POST reveal.
- **Writes back to `helmsman.yaml`** — every settings change the dashboard makes is written back to the app's definition file, re-marshalled to canonical YAML, so the file stays the source of truth.

---

## 8. Deployment modes

### Edge mode

One config key, `edge.mode: "managed" | "external"`, **default `managed`**. There is no auto-detection — it is explicit and fail-closed.

- **`managed` (default — the product):** Helmsman supervises a child Caddy that owns `:80/:443`, runs ACME, terminates TLS, and reverse-proxies the admin vhost and each app vhost. From one required field per app — a hostname — Helmsman derives the full vhost bundle. The operator never stands up a proxy, writes TLS config, or runs certbot. The admin UI still binds loopback; only the *child* binds public ports.
- **`external` (narrow advanced escape hatch):** for an operator who insists on fronting Helmsman with their *own* existing proxy. **Config-file-only, not UI-reachable** — you fall into `managed` by doing nothing. Here Helmsman binds loopback only, never opens 80/443, hides the Caddy editor, and emits paste-ready snippets but applies nothing. Boot is *stronger* fail-closed here: it refuses to start unless `trusted_proxies` is a specific edge IP (≤ /24, not a bridge CIDR) **and** a boot probe confirms `:9000` is unreachable off-loopback. Choosing `external` is always a deliberate operator act, never an automatic degrade.

On an undersized box the default **stays** `managed` (the edge runs in its memory-capped slice with a persistent "reduced MemoryMax — consider a larger host" banner). Only a box that *genuinely cannot* host the child boots `external` with a blocking "edge not owned — resource gate" banner.

### Provisioning modes

All four converge on the same stored artifacts and the same §5.6 chokepoint. See [./docs/provisioning.md](./docs/gitops.md).

| Mode | What it is | Notes |
|---|---|---|
| **1 — Guided form** | A typed form → compose generated deterministically from a vetted template via typed structs. | Recommended default for new stacks. No code path can emit `privileged`/`cap_add`/host namespaces; generated YAML is re-validated anyway. |
| **2 — Paste existing** | A *validating importer* (not an interpreter) for an existing compose / Dockerfile. | Size-capped, `${VAR}` resolved first, line-anchored rejections. A pasted Dockerfile is scanned, not built here. |
| **3 — Setup scripts** | Operator-supplied provisioning scripts that bootstrap *app* stacks (files + env + secrets — never the edge). | **OFF by default, ≥ 1 GB.** Designed assuming the script is hostile: a throwaway, no-`docker.sock`, network-restricted, resource-capped jail with one writable mount. Never auto-runs from git/webhook/boot. |
| **4 — Repo-path GitOps** | Connect a repo and point at `compose_path`; Helmsman reads it from the object store. | **Recommended for repo-backed apps.** Auto-fetch + manual-deploy (see below). |

### GitOps: auto-fetch, manual-deploy

For Mode 4, a git event no longer auto-deploys. **Fetch** is automatic and read-plane: a webhook does *only* `git fetch` into a staged ref, computes "N commits behind" + a diff preview, sets `update_available`, and touches nothing live — so a CI push can never trigger a surprise on-box build (the old OOM vector). **Deploy** is manual, write-plane, and fully gated: you click Deploy, the live checkout advances to the **exact reviewed commit**, §5.6 re-validates *those bytes*, and the resource gate runs before `docker compose up/pull/build`. Full auto-deploy-on-push remains an explicit per-app opt-in (`auto_deploy`, default false) that simply auto-clicks the same gated promote path.

---

## 9. The resource gate

Several capabilities are resource-gated as a **safety property, not just performance**. A `docker compose pull` or a sandbox run that OOMs a tiny box can cascade the whole host into a crash-loop — and the proxy serving your dashboard dies first. The defenses: a **global one-docker-child semaphore** (only one docker child ever runs at once), per-process memory caps in **distinct cgroups/slices**, `GOMEMLIMIT` under the systemd cap, swap-disabled sandboxes, and one-service-at-a-time deploys. No plane can OOM-kill the control plane.

The **write plane** (`docker compose up/pull/build`, redeploy), **on-box image builds**, and the **setup-script sandbox** require **≥ 1 GB RAM**. The **always-on edge is part of the baseline** (in its own memory-capped slice), not gated — on a small or near-OOM box, write-plane operations are disabled but the edge keeps serving HTTPS.

| Capability | Min host | Default |
|---|---|---|
| Security spine + read-only health/monitoring | small VPS ok | **on** |
| Write plane (deploy/redeploy), on-box build | ≥ 1 GB | build **off** |
| **Managed edge (owns 80/443 + ACME)** | any (own slice) | **on** |
| Alerting | small VPS ok | **off** until configured |
| Managed config files + cert bindings | ≥ 1 GB | per-app, off |
| Git **auto-fetch** (pull new commits) | small VPS ok (read plane) | **on** for repo apps |
| Git **deploy/build** (manual promote) | ≥ 1 GB | **manual** (auto-deploy opt-in) |
| Self-healing supervisor (restart/recreate) | small VPS ok (watcher) | **on** (rung-2 redeploy ≥ 1 GB) |
| Process-level auto-scaling | guard funds ≥ 2 replicas | **off**, opt-in (`effective_max=1` on a small box) |
| Setup-script execution | ≥ 1 GB | **off** |

A **host-capacity guard** runs every tick on fresh data: on a near-OOM box, auto-scaling collapses to `effective_max = 1` (a permanent no-op that fires a `scale_refused_no_capacity` alert rather than holding silently), and the self-healing ladder tops out at `recreate` then circuit-opens rather than attempting a redeploy it can't fund. See [./docs/scaling.md](./docs/scaling-and-self-healing.md) and [./docs/self-healing.md](./docs/scaling-and-self-healing.md).

---

## 10. Is it safe?

In plain English: Helmsman is **designed to be survivable even if it is exploited**, not merely to avoid bugs. The honest threat picture:

- **Helmsman is in the `docker` group, and that is root-equivalent.** This is the fundamental reason a dashboard compromise *could* become a server compromise. Helmsman shrinks that risk — but does not eliminate it — with a read-only verb-allowlisted socket-proxy (the raw socket is never mounted into Helmsman), allowlist validation on every write, full `systemd` sandboxing, and network egress allow-listing. Hard removal needs the future Core/Agent split.
- **The public edge is the highest-surface feature.** Every install is internet-facing. It is contained by the secure-by-default baseline (SBD-1..8), the structural runtime controls (a pinned dialer that re-resolves and refuses control-plane ports on every connection, an egress firewall that makes those ports *physically unreachable* from the edge, and a unix-socket Caddy admin so there is no TCP `:2019` to reach), plus a negative-from-internet probe that proves the allowlist *blocks* (not just admits) before any apply sticks.
- **The raw Caddy editor is its own risk class** — a linter cannot see Caddy's runtime placeholder/DNS resolution. Helmsman's editor is therefore safe by **structural runtime controls**, not parse-time validation alone, plus the immutable protected base, auto-rollback, and the SSH `restore-default` floor.
- **Every monitored app is assumed eventually hostile.** App responses are untrusted input: size-capped, schema-checked, escaped, never rendered as HTML or eval'd. The descriptor an app advertises can never move Helmsman's outbound, secret-bearing requests off the operator-configured host.
- **The deepest backstop:** even a perfect SSRF or RCE in Helmsman cannot reach cloud metadata or call home, because `systemd` egress allow-listing limits outbound to exactly the edge, the docker-proxy, the internal app net, and the ACME endpoints.

The full threat model, crown-jewel ranking, attacker classes, and the assurance program are in [./docs/security.md](./docs/security.md).

---

## 11. Configuration reference

The authoritative root of trust is `/etc/helmsman/config.yaml` — `0600 root:root`, edited **only over SSH**. **No web route reads or writes auth, the allowlist, the master key, or the bind address.** `SIGHUP` hot-reloads the allowlist and auth (not keys). The key groups (full reference in [./docs/config.md](./docs/architecture.md)):

| Key | Meaning |
|---|---|
| `bind_addr` | The loopback admin bind, e.g. `127.0.0.1:9000`. Helmsman never binds a public port itself. |
| `encryption_key` | The AES-256-GCM master key (from `gen-key`). Never in the DB/logs/UI. |
| `encryption_key_previous` | Optional — used during key rotation. |
| `ip_allowlist` | List of CIDRs allowed to reach the admin plane. **Empty = deny-all** (fail-closed). |
| `trust_proxy` / `trusted_proxies` | Whether to honor XFF, and from which proxy IP(s) (≤ /24, never a bridge CIDR). |
| `auth.username` | The single operator's username. |
| `auth.password_hash` | argon2id hash (from `hash-password`). |
| `auth.totp_secret` | Optional TOTP secret (from `gen-totp`). |
| `edge.mode` | `managed` (default) or `external`. |
| `edge.acme_email` | ACME contact; **fail-closed if empty** in managed mode. |
| `edge.acme_ca` | Pinned single ACME issuer (no fallback). |
| `edge.apply_probe_window` | Health-probe window for an edge apply (default 20s). |
| `edge.l4_enabled` | Opt-in L4 (raw-TCP-by-SNI) routing; requires a custom proxy build (default false). |
| `admin.hostname` | Optional — front the admin UI through the edge (behind the injected allowlist). Unset = SSH-tunnel only. |
| `admin.listen` | Caddy admin API endpoint — a unix socket (preferred) or `127.0.0.1:2019`, never routable. |
| `caddy_editor.mode` | `strict` or `review` (the latter only softens footgun-tier lints, never the control-plane tier). |
| `compose_validation.mode` | `strict` or `review` for paste-import warnings. |
| `setup.enabled` | Setup-script execution (default false; requires the sandbox escape test to pass). |

Tuning for `scaling.*`, `selfheal.*`, and `supervisor.*` (host-capacity reservations, caps, gates) lives **only** in this config — there is intentionally no web route that sets them.

---

## 12. FAQ / Troubleshooting

**Helmsman refuses to start.** It is fail-closed by design. Check, in order: config file perms (`0600 root:root`); an **empty `ip_allowlist`** (that is deny-all and refused); `trust_proxy` on with empty or too-broad `trusted_proxies`; wrong-length keys; an invalid argon2id hash; in managed mode, the admin endpoint reachable off-loopback or missing edge prerequisites (e.g. empty `acme_email`); setup enabled with no working sandbox. The boot error names the exact failing precondition.

**I can't reach the dashboard.** The admin UI binds loopback only. Either tunnel (`ssh -L 9000:127.0.0.1:9000 ...`) or set `admin.hostname` to front it through the edge — and confirm your client IP is in `ip_allowlist`. A non-allowlisted client gets a bare 404 or a dropped connection, by design.

**My app shows BASIC instead of RICH panels.** The app's ops endpoints may be gated behind its own runtime profile (returning 404 otherwise), so the probe misclassifies it. Fix it by exposing a public `/.well-known/ops` *not* behind that gate, enabling the app's ops profile, or setting a per-app `ops_mode: rich` override. See [./docs/ops-interface.md](./docs/definition-file.md).

**My deploy / redeploy is disabled.** The write plane is gated on ≥ 1 GB RAM (a safety gate). On a smaller box the edge and read-only monitoring still work; you'll see the relevant banner. See §9.

**A git push didn't deploy.** That is intended — fetch is automatic, deploy is manual. The app will show `update_available` with a diff; click Deploy (or set `auto_deploy: true` to auto-click the same gated promote path).

**TLS isn't being issued for a hostname.** ACME issues only for hostnames in `app_routes`, and Helmsman validates the hostname **resolves to this box** at issuance time. Confirm the DNS record points at the host and the route exists. On-demand TLS is off by default precisely so a hostile SNI can't make Helmsman burn rate limits on arbitrary certs.

**I lost my master key.** Losing the `encryption_key` **bricks all ciphertext** — there is no recovery. **Back up the config (key) and the DB separately and offsite.** Use `verify-key` to catch a key/DB mismatch before it corrupts on the next write, and `encryption_key_previous` to rotate.

**The edge config is broken / I locked myself out.** The edge is designed never to be irrecoverable: an apply that fails its health probe auto-reverts to the last-known-good. The iron escape hatch over SSH is `helmsman edge restore-default`, which rebuilds the protected base + admin allowlist from typed structs and drops the overlay while keeping app routes. SSH is always the recovery floor.

---

## 13. License, contributing, support

- **License** — see [LICENSE](./LICENSE) in the repository root.
- **Contributing** — see [CONTRIBUTING.md](./CONTRIBUTING.md). Because Helmsman's paramount requirement is safety, any change touching a blast-radius module (the exec wrapper, the SSRF client, the allowlist/XFF derivation, crypto/secret store, the setup sandbox, ACME, or the edge renderer) re-triggers the relevant security gates before merge. Custom lint rules enforce the invariants — among them: no `exec.Command` with request/DB/app-derived args outside the §5.6 validator, no `sh -c`, no un-confined path from external input, no `text/template`/`template.HTML` on app content, and no secret type whose `String()`/`MarshalJSON` isn't redacted.
- **Security reports** — please report vulnerabilities privately per [SECURITY.md](./docs/security.md) rather than opening a public issue.
- **Support** — open a GitHub issue for bugs and feature requests. Start with the [Documentation](#documentation) table and the [FAQ](#12-faq--troubleshooting) above.