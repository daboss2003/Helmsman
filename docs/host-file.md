# The host definition (`kind: Host`) & the 3-tier config model

One server runs many apps. A per-app [`helmsman.yaml`](./definition-file.md) describes *one* app's
managed surface — but it is the wrong place for **server-wide** settings (global defaults, the alert
channels everything shares) and **multi-app coordination** (which apps live here, what order they
deploy in, when each one's setup script runs). Those belong to the *host*, not to any single app.

So Helmsman has a second definition kind — **`kind: Host`** — and a clear **three-tier** split of
where configuration lives. This page covers both.

> **TL;DR.** Server-wide operational settings and the registry of apps live in one
> `/var/lib/helmsman/host.yaml` (`kind: Host`), edited from the dashboard or `helmsman apply --kind
> Host`. Security/identity (the master key, the IP allowlist, the bind address) stays in the
> SSH-only `/etc/helmsman/config.yaml` and is **never** reachable from the web. Each app keeps its own
> `helmsman.yaml`.

---

## 1. The three-tier config model (a security boundary, not tidiness)

| Tier | File | Holds | Who writes it |
|---|---|---|---|
| **1 — security / identity** | `/etc/helmsman/config.yaml` (`0600 root`) | the AES-256-GCM **master key**, the **IP allowlist**, the **bind** address, `edge.mode`, `acme_email`, `acme_ca`, `trusted_proxies`, argon2id/TOTP, and the **security tuning** (memory floors, the one-docker-child semaphore cap, the host-capacity reservation math) | **SSH / root only — never the web** |
| **2 — server-wide operations** | `/var/lib/helmsman/host.yaml` (`0640`) | the **app registry**, **global defaults**, **server-wide alerting** (channels/routes/quiet-hours/maintenance), **cross-app ordering** | dashboard **and** CLI |
| **3 — one app** | `helmsman.yaml` / `canonical.yaml` | that one app's managed surface (compose, env, secrets-by-ref, config files, routes, scaling, …) | dashboard, CLI, **and** the app's repo |

### Why Tier 1 stays separate

Tiers 2 and 3 are **dashboard-writable** and **safe to commit to a repo** — they carry no secret
values (everything is [by reference](./config-files-and-secrets.md)) and they reach Helmsman through
the web plane (behind the IP allowlist + auth + CSRF). Tier 1 is the **root of trust**: it holds the
key that decrypts Tiers 2/3, the allowlist that decides who can even reach the dashboard, and the
bind address. The absolute invariant (see [security.md](./security.md)) is that **no web route ever
reads or writes the master key, the allowlist, or the bind.**

That is enforced *structurally*, not by convention: a host or app spec is **incapable of expressing a
Tier-1 field.** If `encryption_key`, `ip_allowlist`, `bind`, `edge.mode`, `acme_email`,
`trusted_proxies`, or any auth field appears anywhere in a `host.yaml` or `helmsman.yaml`, it is a
hard `additionalProperties:false` reject at parse time, with an error that points you at *"this is
Tier-1 — SSH-edit `/etc/helmsman/config.yaml`."* It's the same class of structural denial as an app
def being unable to grab `:80/:443`. An operator who can edit Tier 1 already holds the master key over
SSH; the dashboard never inherits that authority.

> **Scaling / self-healing knobs are split deliberately.** The app-author/UI-writable subset
> (`enabled`, `service`, `min`, `max`, `target`, `breach_for`, `ladder_max`, `max_attempts`) lives in
> Tier 2/3. The *security* tuning (absolute memory floors, the semaphore cap, the `effective_max`
> collapse threshold, the host-capacity reservation math) is Tier-1 only. See
> [scaling-and-self-healing.md](./scaling-and-self-healing.md).

---

## 2. The `kind: Host` definition

`host.yaml` is a **singleton** per server (a second apply replaces it, never appends). It is parsed
with the exact same discipline as a [`kind: App`](./definition-file.md) file — exact-match
`apiVersion`, one canonical-JSON intermediate, `DisallowUnknownFields` + JSON-Schema
`additionalProperties:false` everywhere, no YAML anchors/merge-keys, no duplicate keys, no implicit
scalar coercion.

```yaml
apiVersion: helmsman/v1
kind: Host
metadata:
  server_id: edge-01           # informational, immutable after first apply
spec:
  apps:                        # the REGISTRY — the only place the set of apps is enumerated
    - slug: broker
      source: { repo: git@github.com:acme/broker.git, ref: refs/heads/main, path: helmsman.yaml }
      enabled: true
    - slug: api
      source: { managed: true }   # the App def is the locally-authored canonical.yaml, no repo
      enabled: true

  defaults:                    # a BASE layer beneath each app's spec (resolved before §5.6)
    self_healing: { enabled: true }
    scaling: { enabled: false }

  alerting:                    # server-wide channels + routing (secrets BY REFERENCE)
    channels:
      - name: ops-email
        kind: email
        config: { to: ops@example.com, smtp_secret: { secret: SMTP_PASS } }   # (_host, SMTP_PASS)
    routes:
      - match: { severity: ">=warning" }
        channels: [ops-email]
    quiet_hours: { tz: UTC, from: "22:00", to: "07:00" }   # suppresses WARNING only
    maintenance_windows: []

  orchestration:
    deploy_order:              # "B's deploy waits until A is healthy" (a partial order)
      - { app: api, depends_on: [broker] }
    on_dependency_failure: halt          # halt | continue-independent (never "ignore")

  setup_orchestration:
    order:                     # cross-app SETUP sequencing under one `helmsman host deploy`
      - { app: broker }
      - { app: api, after: [broker] }
```

### `spec.apps` — the registry

The only place the set of apps on the box is enumerated. Each entry is a `slug` (must match the App
def's `metadata.slug`), a `source` — a `oneOf` of `{repo, ref, path}` (the repo runs the same SSRF
allowlist + git hardening as [gitops.md](./gitops.md): scheme ∈ {https, ssh}, loopback/metadata and
ports `2375/2019/9000` denied; `ref` is fully-qualified and **never** read from a webhook payload;
`path` is read via `git cat-file` from the pinned commit's tree, tree-mode `120000`/`160000` rejected)
or `{managed: true}` (the canonical app def is authored locally, no repo) — and `enabled`.
**Registering an app does not deploy it.**

### `spec.defaults` — inheritance that can tighten but never silently widen

Defaults are projected as a base layer **beneath** each app's own spec, resolved before the
[§5.6 validator](./security.md). Precedence is strict and directional: *built-in default < host
default < per-app field* (the rightmost wins).

A host default may **tighten** a posture (set a floor). It may **never silently widen** an individual
app's posture. *Any* default that — relative to the built-in — enables `auto_deploy`, raises
`scaling.max`/`scaling.min`, adds or widens an `edge.route`, weakens `self_healing`, loosens
`ops_interface`, or changes `git.ref` requires a **per-app, field-named posture-widening
acknowledgement** (the same gate as a definition rollback). `spec.defaults` may not carry
`edge.routes` or `git.ref` at all, and may carry only the Tier-3 subset of scaling/self-healing knobs.
The host↔app merge is the same **field-level 3-way merge** as the app def — both sides changing the
same field is a per-field `host_conflict` review, never last-writer-wins.

### `spec.alerting` — server-wide channels

Server-wide channels, routes, quiet-hours, and maintenance windows, projecting onto the same model as
[alerting.md](./alerting.md) — so you define your email/Slack/etc. **once** instead of per app.
Channel secrets are **by reference** in an isolated **`(_host, name)`** namespace: apps cannot read a
host channel secret, and the host cannot read an app's. `CRITICAL` infra alerts keep
`ignore_quiet_hours`; maintenance windows suppress **WARNING only, never** security/auth alerts — and
a security/auth alert class has a **mandatory, non-removable** paging route that host routes can *add*
destinations to but can never redirect away from or replace.

### `spec.orchestration.deploy_order`

A partial order over registered apps. `depends_on` means *"B's deploy waits until A is healthy"* — a
deploy-time ordering, **not** a runtime network dependency (that stays in compose `depends_on`). A
cycle, or a dependency on an unregistered/disabled slug, is a hard reject. `on_dependency_failure` is
`halt` or `continue-independent` — never a silent "ignore."

---

## 3. Setup-script orchestration (sequence, never automation)

Each app declares its setup trigger in **its own** `spec.setup` (see
[definition-file.md](./definition-file.md)):

```yaml
# in an app's helmsman.yaml
spec:
  setup:
    script_ref: scripts/bootstrap.sh
    trigger: on_first_deploy        # never (default) | on_demand | on_first_deploy | before_each_deploy
    limits: { mem_mb: 256, wall_clock_s: 120, network: none }
    produces:
      secrets: [BROKER_NODE_COOKIE]
      files: [certs/internal.pem]
```

The **trigger is a planner input, never an executor.** It decides whether a setup *step* is included
in a deploy plan — it never makes a deploy happen, and it **never** runs the sandbox from a webhook,
git fetch, auto-deploy, or boot. A deploy reached via an auto path that *would* include setup
**omits** the step and fences into `setup_required` + pages you. (Full sandbox details:
[scaling-and-self-healing.md](./scaling-and-self-healing.md) and the security model in
[security.md](./security.md).)

**Hard rules (don't let "when to run" become "auto-run"):**

- `trigger ∈ {on_first_deploy, before_each_deploy}` together with `git.auto_deploy: true` is a
  **parse-time hard reject.** Auto-deploy advances *code*, never *setup*.
- `on_first_deploy` is **idempotent** on a `setup_runs` row keyed by the **full**
  `script_set_checksum` — the script bytes **plus** its `limits`, `produces`, `trigger`, and
  pinned-sha. Raising a sandbox cap or adding a captured secret changes the checksum and forces a
  fresh, confirm-token-gated run; a trivial no-op edit that doesn't change execution doesn't.
- A script's `produces` land **only** in that app's own `(slug, name)` namespace. There is **no
  implicit cross-app output flow.** If app B legitimately needs a value app A generated, that is an
  **explicit, operator-confirmed, audited copy** into `(B, name)` — never an ambient cross-namespace
  read created by `deploy_order`/`after:`.

### `helmsman host deploy`

The host orchestrator runs a multi-app deploy in `setup_orchestration.order`. It presents **one
ordered plan** but mints a **separate, byte-bound, single-use confirm token per app** whose plan
includes setup. Crucially, each token is minted **lazily** — only after the upstream apps are healthy
and that app's final plan bytes (including any operator-copied inputs) are materialized — and is
**voided on any byte mismatch**, forcing a re-confirm. The orchestrator changes the **sequence** of
operator-confirmed steps; it can never auto-chain B's setup off A's confirm.

Execution: app A's setup runs (confirmed) → captures outputs into `(A, …)` → A becomes healthy → only
then does B's plan finalize and its token mint. On A's failure with `on_dependency_failure: halt`, the
run stops before B ever reaches a confirm.

---

## 4. Storage, versioning, and editing

- Canonical file: `/var/lib/helmsman/host.yaml` (`0640 helmsman:helmsman`) — server-side, **not** in
  any app repo, because it spans apps.
- Three-plane backing for the dashboard↔SSH 3-way merge:
  `/var/lib/helmsman/host/{canonical,working,base}.yaml`, with an HMAC-tracked **`host_versions`**
  history table (mirrors the app `definition_versions`).
- Edited from the **dashboard** *or* `helmsman apply --kind Host --from host.yaml` — both produce the
  **same typed `HostV1` reconcile request** through the **same** reconciler and validation chokepoints
  as everything else (it's a third front *door*, not a new trust *path*; see
  [architecture.md](./architecture.md)).

---

## 5. Worked example — from one stack to many apps

### Today: one Compose project = one app

A stack that today is a single Compose project (an API + a broker + a bundled Caddy + a cert-reload
sidecar, bootstrapped by a `setup-vps.sh`) becomes **one** Helmsman `App`:

- `setup-vps.sh` → the app's `spec.setup` with `trigger: on_first_deploy` (it generates the broker's
  keys/certs and seeds secrets — once, idempotently).
- The bundled **Caddy and cert-reload sidecar are dropped** — Helmsman's edge owns TLS now (see
  [edge-and-tls.md](./edge-and-tls.md)). The broker gets a **`cert_binding`** + a **cert-only** route;
  the API gets a normal reverse-proxy route.
- Secrets that the script generated are declared in the app's `secrets:` by name and provisioned into
  the store; non-secret config arrives via [env import](./env-import.md).

At this scale you may not need a `host.yaml` at all — one app, registered as `{managed: true}`.

### Tomorrow: decomposed into several apps

Split it into `broker` / `api` / `web`, each with its own `helmsman.yaml`, and the **host def** ties
them together:

```yaml
apiVersion: helmsman/v1
kind: Host
metadata: { server_id: edge-01 }
spec:
  apps:
    - { slug: broker, source: { repo: ..., ref: refs/heads/main, path: helmsman.yaml }, enabled: true }
    - { slug: api,    source: { repo: ..., ref: refs/heads/main, path: helmsman.yaml }, enabled: true }
    - { slug: web,    source: { managed: true }, enabled: true }
  defaults:
    self_healing: { enabled: true }
  alerting:
    channels: [ { name: ops, kind: email, config: { to: ops@example.com, smtp_secret: { secret: SMTP_PASS } } } ]
    routes:   [ { match: { severity: ">=warning" }, channels: [ops] } ]
  orchestration:
    deploy_order:
      - { app: api, depends_on: [broker] }     # API waits until the broker is healthy
      - { app: web, depends_on: [api] }
    on_dependency_failure: halt
  setup_orchestration:
    order:
      - { app: broker }                          # broker bootstrap first
      - { app: api, after: [broker] }
```

`helmsman host deploy` then walks broker → api → web, pausing for the per-app confirm where a setup
step is included, and stopping the chain if a dependency never becomes healthy.

---

## See also

- [definition-file.md](./definition-file.md) — the per-app `helmsman.yaml` (`kind: App`).
- [env-import.md](./env-import.md) — bringing your `.env`; Helmsman writes the live one.
- [security.md](./security.md) — the threat model, the §5.6 validator, the Tier-1 structural reject.
- [alerting.md](./alerting.md) — the alert engine the host channels project onto.
- [cli.md](./cli.md) — `apply --kind Host`, `host deploy`, `host plan/status`.
- [README](../README.md) — the project front page.
