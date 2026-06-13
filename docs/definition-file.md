# `helmsman.yaml` — Definition File Reference

The **definition file** (`helmsman.yaml`) is the declarative source of truth for an app's Helmsman-managed surface. It is **complementary to your `docker-compose.yml`**: compose describes the containers; `helmsman.yaml` describes *how Helmsman manages them* — env, secrets (by reference), templated config files, cert bindings, edge routes, scaling, self-healing, ops-interface coordinates, and GitOps behavior.

There are two ways to drive it, and they are **the same trust path**, not two:

- The **dashboard writes back to it** on every settings change.
- A CLI/SSH operator can author and commit it in their repo and run `helmsman apply` **without ever opening the dashboard**.

Both are thin front-ends onto the **one reconciler** and the **one §5.6 allowlist validator** the dashboard uses. The definition file is a new front *door*, never a new trust *path* — nothing in it reaches `docker compose` unvalidated.

> **See also:** [README](../README.md) · [Managed config files](./config-files-and-secrets.md) · [Cert bindings](./edge-and-tls.md) · [GitOps / repo-path apps](./gitops.md) · [Managed edge & routes](./edge-and-tls.md) · [Secrets](./config-files-and-secrets.md) · [Auto-scaling](./scaling-and-self-healing.md) · [Self-healing](./scaling-and-self-healing.md) · [CLI reference](./cli.md)

---

## Table of contents

- [The envelope: `apiVersion` / `kind` / `metadata`](#the-envelope-apiversion--kind--metadata)
- [How parsing works (and what is rejected)](#how-parsing-works-and-what-is-rejected)
- [The `spec` sections](#the-spec-sections)
  - [`compose`](#speccompose)
  - [`env`](#specenv)
  - [`secrets`](#specsecrets)
  - [`config_files`](#specconfig_files)
  - [`cert_bindings`](#speccert_bindings)
  - [`edge.routes`](#specedgeroutes)
  - [`scaling`](#specscaling)
  - [`self_healing`](#specself_healing)
  - [`ops_interface`](#specops_interface)
  - [`git`](#specgit)
  - [`resources`](#specresources)
- [The `{{hm.KEY}}` binding delimiter](#the-hmkey-binding-delimiter)
- [Secrets are by reference only](#secrets-are-by-reference-only)
- [Write-back & sync (split-plane ownership)](#write-back--sync-split-plane-ownership)
- [The apply lifecycle](#the-apply-lifecycle)
- [Worked example A — a stateful broker](#worked-example-a--a-stateful-broker)
- [Worked example B — a stateless API](#worked-example-b--a-stateless-api)
- [Field quick reference](#field-quick-reference)

---

## The envelope: `apiVersion` / `kind` / `metadata`

Every definition file is a Kubernetes-style envelope:

```yaml
apiVersion: helmsman/v1     # exact-match, fail-closed
kind: App                   # the only kind in v1
metadata:
  slug: my-app              # immutable after the first apply
spec:
  # ... the managed surface (see below)
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `apiVersion` | string | yes | **Must be exactly `helmsman/v1`.** See the version gate below. |
| `kind` | string | yes | `App` (the only kind in v1). |
| `metadata.slug` | string | yes | The app identity. `^[a-z][a-z0-9-]{1,30}$`. **Immutable after the first apply** — it becomes the project/run-dir name and the secret namespace key. Changing it is rejected, not silently re-homed. |
| `spec` | object | yes | The managed surface. Each section is a *projection* onto an existing Helmsman artifact (see [The `spec` sections](#the-spec-sections)). |

### The version gate is exact-match and fail-closed

`apiVersion` is matched **exactly**. There is no "best-effort parse of a future version," no minor-version tolerance, no forward-compat guessing:

- `helmsman/v1` → accepted.
- `helmsman/v2`, `helmsman/v1beta1`, `v1`, `helmsman/V1`, anything else → **hard reject at parse**.

**Why so strict (the honest trade-off):** a definition file is an input to a security-sensitive reconciler. A parser that *guesses* at an unknown schema is a parser-differential waiting to happen — the same bytes could mean different things to two versions, and that gap is where a key gets smuggled past validation. Exact-match means an old binary never half-understands a newer file, and a hand-typo never silently lands in a degraded interpretation. If you upgrade the schema, you upgrade the binary; the file says exactly which contract it speaks.

---

## How parsing works (and what is rejected)

`helmsman.yaml` is the canonical name. The loader also accepts `.yml` and `.toml`, but **all three normalize through one canonical JSON intermediate** into a single typed `DefinitionV1`, and the file is always **re-marshalled to canonical YAML** on write-back. The format you author in is an input encoding, never the stored truth.

Hard rejections at parse time (fail-closed, every one is a stop, not a warning):

| Rejected | Why |
|---|---|
| **Unknown key**, anywhere | `DisallowUnknownFields` **plus** an independent JSON-Schema gate with `additionalProperties: false` at every level. A typo is an error, not an ignored field. |
| **YAML anchors / merge keys (`<<`)** | They are a classic way to make two parsers disagree. Banned. |
| **Duplicate keys** | A duplicate is a parser-differential vector. Hard reject. |
| **Implicitly-typed scalars that flip meaning** | Scalars are read as explicitly typed; a `yes`/`on`/`1` cannot quietly become a boolean. |
| Wrong `apiVersion` | See the version gate above. |
| A changed `metadata.slug` after first apply | The slug is immutable. |

After a clean parse, `${VAR}` / `.env` interpolation is **resolved first** (validating before interpolation is a known bypass), then the typed structs fan out into the existing validators. **Nothing reaches `docker compose` before §5.6 has seen the fully-resolved bytes.**

---

## The `spec` sections

Each `spec` section is a **projection onto an existing artifact** — there are no new artifact types. Authoring a section in `helmsman.yaml` is exactly equivalent to filling in the corresponding dashboard panel; both feed the same typed sub-struct.

| Section | Projects onto | Plan ref | Default if omitted |
|---|---|---|---|
| `compose` | the validated compose source | §7.6 | required (repo_path or inline) |
| `env` | the encrypted `env_blob` | §5.5 | empty |
| `secrets` | the AES-256-GCM secret store (names only) | §7.7 | empty |
| `config_files` | managed config files | §7.4 | empty |
| `cert_bindings` | `app_cert_bindings` | §7.5 | empty |
| `edge.routes` | `app_routes` (Layer-1 edge input) | §6 | empty (no public exposure) |
| `scaling` | `scaling_policy` | §8A | disabled (opt-in) |
| `self_healing` | `supervisor_state` policy | §8.5 | on (defaults) |
| `ops_interface` | the ops-interface record | §4 | basic / auto-discover |
| `git` | the GitOps fields on the `apps` row | §7.6 | `auto_deploy: false` |
| `resources` | §0 capacity hints | §0 | none |

### `spec.compose`

Where Helmsman gets the compose bytes. A strict `oneOf` selected by an explicit `source:` (no
inference) — **exactly one** of `generated`, `repo_path`, or `inline`.

```yaml
compose:
  source: generated     # generated | repo_path | inline
```

| `source` | Use when | Notes |
|---|---|---|
| `generated` | **you don't want to hand-write compose/Dockerfile** — declare services in `spec.services` and Helmsman generates the compose. | Requires `spec.services` (and `spec.services` present with `source != generated` is a hard reject). The generator emits only safe keys — see below. |
| `repo_path` | you already have a compose in your repo | `repo_path` (+ optional `dockerfile_path`) read via `git cat-file` from the **pinned commit's object store** — never a working-tree read. All compose-relative paths (build context, `env_file`, `include`/`extends`, binds) canonicalize-then-`Rel`-confine **under the app's checkout subtree**; tree mode `120000`/`160000` on the path rejected. |
| `inline` | you want to paste a compose body in the definition | Validated through the *same* §5.6 chokepoint. |

> A `build: ../../other-app` or an `env_file:` climbing toward Helmsman's config is rejected —
> confinement is to the app's own subtree, never a sibling app or `repos_dir`. A build is always a
> **write-plane, manually-promoted** action (§0 gate); declaring a build never causes one.

### `spec.services` (with `source: generated`)

Declare what you want and Helmsman generates the compose (and a Dockerfile, if you build from
source). You never hand-write either file; the dashboard form is just a view over this section.

```yaml
compose: { source: generated }
services:
  api:
    image: registry.example.com/api:1.4.2   # XOR build:
    ports: { internal: [8080] }             # internal only — NO host-publish field
    env:
      LOG_LEVEL: info
      DB_PASSWORD: { secret: DB_PASSWORD }   # by reference
    healthcheck: { test: ["CMD", "/bin/health"], interval: 10s }   # exec-form only
    restart: unless-stopped
    edge: { route: { hostname: api.example.com, port: 8080, scheme: http } }
  builder-from-source:
    build:
      generate:                              # OR: dockerfile_path: deploy/Dockerfile
        runtime: go                          # curated, digest-pinned bases only
        build_cmd: ["go", "build", "-o", "/app/server", "./cmd/server"]
        run_cmd:   ["/app/server"]
        expose: 8080
        user: app                            # non-root enforced
```

| Field | Notes |
|---|---|
| `image` **XOR** `build` | one of. `build.dockerfile_path` points at an existing Dockerfile (read via `git cat-file`, never written); `build.generate{}` emits a minimal **multi-stage** Dockerfile from a curated digest-pinned base. |
| `ports.internal` | container-internal only. **There is no publish/host-port field** — ingress is *only* an `edge.route`. A value in `{9000, 2019, 2375}` (control-plane ports) is rejected at parse. |
| `env` | literal · `{secret: NAME}` · `{service: NAME}` (intra-project DNS). Secret refs never reach the YAML; they're rendered into the `0600 --env-file` at deploy. |
| `volumes` | a managed named volume, or a bind whose source is `Rel`-confined under run_dir. |
| `healthcheck` / `command` / `entrypoint` | **exec-array form only** (no shell-string smuggling). |
| `depends_on` / `restart` / `resources` / `scaling` / `self_healing` / `edge.route` | siblings only / enum / §0 hints / §8A / §8.5 / a Layer-1 edge route. |

**The dangerous keys simply don't exist in this schema** — `privileged`, `cap_add`, host namespaces,
host binds, any host-publish — so no input can generate them (the generator always emits
`cap_drop:[ALL]` + `no-new-privileges`). And the generated YAML is **still re-run through §5.6**
(defense in depth). `spec.services` is the source of truth; a hand-edit of the generated compose
surfaces `generated_drift` → **regenerate-from-spec** or **detach-to-inline** (a one-way escape hatch
whose bytes go through the **full §5.6 chokepoint as a hard gate** before becoming canonical). See
[gitops.md](./gitops.md) for build gating and [scaling-and-self-healing.md](./scaling-and-self-healing.md)
for whether a generated service is auto-scalable.

### `spec.setup` (when the setup script runs)

A per-app setup-script trigger. **The trigger is a *planner* input, never an *executor*.**

```yaml
setup:
  script_ref: scripts/bootstrap.sh   # or inline:
  trigger: on_first_deploy           # never (default) | on_demand | on_first_deploy | before_each_deploy
  limits: { mem_mb: 256, wall_clock_s: 120, network: none }
  produces:
    secrets: [NODE_COOKIE]
    files: [certs/internal.pem]
```

- A setup script runs **only** inside an operator-initiated, confirm-token-gated deploy — **never**
  from a webhook, git fetch, auto-deploy, or boot. An auto path that *would* include setup **omits**
  it and pages.
- `trigger ∈ {on_first_deploy, before_each_deploy}` together with `git.auto_deploy: true` is a
  **parse-time hard reject**.
- `produces` land **only** in this app's own `(slug, name)` namespace — no implicit cross-app flow;
  cross-app sharing is an explicit, confirmed copy. Cross-app *ordering* lives in the host definition
  ([host-file.md](./host-file.md)).
- `on_first_deploy` is idempotent on a `setup_runs` row keyed by the **full** `script_set_checksum`
  (bytes + `limits` + `produces` + `trigger` + pinned-sha).

> Bringing an existing `.env`? See [env-import.md](./env-import.md) — Helmsman owns the live `.env`
> and ingests your file's values into the encrypted store. Server-wide settings across multiple apps
> live in the host definition: [host-file.md](./host-file.md).

### `spec.env`

Non-secret literals **or** references into the secret store. Maps to the encrypted `env_blob` delivered as a `0600 --env-file` at deploy time (never baked into YAML).

```yaml
env:
  LOG_LEVEL: info                 # a non-secret literal
  REGION: eu-west-1
  DB_PASSWORD: { secret: DB_PASSWORD }   # a reference, resolved from this app's secret namespace
```

| Form | Meaning |
|---|---|
| `KEY: value` | A non-secret literal. The save-time literal lint (see [Secrets are by reference only](#secrets-are-by-reference-only)) **rejects** a value that looks like key material / a token / long base64 — those must be a `secret:` ref. |
| `KEY: { secret: NAME }` | A reference. `NAME` resolves **only within this app's `(slug, NAME)` namespace**. A missing value is a **hard deploy failure**, never an empty string. |

### `spec.secrets`

Declares secret **names** (and an optional generate hint). **It never contains values.** This is what keeps the whole file non-secret-bearing and safe to commit to a public repo.

```yaml
secrets:
  - name: DB_PASSWORD                    # provisioned out-of-band (helmsman secret set / dashboard / SSH)
  - name: NODE_COOKIE
    generate: { type: hex, bytes: 32 }   # mint on explicit operator action only; entropy-floor enforced
  - name: SHARED_AUTH_TOKEN
    generate: { type: base64, bytes: 32 }
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | required | The secret's name within **this app's** namespace. |
| `generate` | object | — | An optional **hint**, not a value. |
| `generate.type` | enum | — | `hex` \| `base64` \| `password` (and similar). Each type has a **hard entropy floor**. |
| `generate.bytes` | int | — | Requested entropy; rejected below the per-type floor. |

Generate semantics (all three are load-bearing):

1. **Hard per-type entropy floor** — a too-small request is rejected, not quietly satisfied.
2. **Mints only on explicit operator action** — declaring a `generate` hint does not auto-create the secret on parse; you opt in to minting it.
3. **Never overwrites an already-provisioned secret** — re-applying a file with a `generate` hint will not rotate a live secret out from under a running app.

### `spec.config_files`

Managed config files (§7.4) — a **third kind** of artifact beside env and file-mounted secrets. A structured template that Helmsman renders **host-side**, filling **only** its own `{{hm.KEY}}` delimiter while the app's own `${…}` placeholders survive byte-identical. The template is encrypted at rest **iff** it is secret-bearing.

```yaml
config_files:
  - path: etc/broker/broker.conf        # rendered destination, confined under run_dir, bind-mounted RO
    template_ref: deploy/broker.conf.tmpl  # template source in the repo (read via cat-file from pinned commit)
    format: ini                          # a hint for preview only — NEVER trusted for a security decision
    bindings:
      NODE_COOKIE: { secret: NODE_COOKIE }
      LISTENER_CRT: { cert: broker-tls.crt }
      PUBLIC_HOST:  { app: public_hostname }
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `path` | string | required | The rendered destination, **relative to the app run_dir**. Re-asserts the full §5.6(d) protected-path landing rejection: `..`/absolute/symlink/NUL/CR-LF rejected; never lands on the proxy data/ACME-key dir, edge binary, socket-proxy, `--env-file`, or Helmsman config/DB/master-key; never a `:80/:443` publish; unique among active config files. |
| `template_ref` | string | — | A repo path to the template, read via `git cat-file` from the **pinned commit**. (Or `template:` inline.) |
| `template` | string | — | Inline template body. |
| `format` | enum | — | `ini`/`conf`/`yaml`/… — used **only** to shape the preview. **CR/LF/NUL hygiene is enforced regardless of `format`** — never trust an attacker-influenced format hint for a security decision. |
| `bindings` | map | — | The **explicit allowlist** of `{{hm.KEY}}` keys this file may resolve. A `{{hm.X}}` resolves only if `X` is here; unknown/dup/malformed → hard error at save **and** at render. |

**Rendered-file behavior (every redeploy):** resolve all bindings → render (single-pass byte scanner) → write atomically → record `rendered_sha256` → bind-mount read-only. A host hand-edit is *detected* (sha mismatch → "host-edited, will be overwritten") — detection only, never auto-merge, never execute. Permissions default to `0640`, and `0600` when secret-bearing — never `0644`. A secret-bearing rendered file joins the read-only file-secret panel and **can never become an edge cert**.

> See [Managed config files](./config-files-and-secrets.md) for the full renderer contract.

### `spec.cert_bindings`

Wires Helmsman's **cert-only / shared-cert** edge pattern (§6) to the app: the edge is the ACME agent for a hostname (which must match one of this app's routes), and the **cert-sync helper** copies the leaf cert + key to a per-consumer `0600` path under the run_dir.

```yaml
cert_bindings:
  - name: broker-tls
    hostname: broker.example.com    # must match one of this app's edge.routes hostnames
    sync_dir: certs/broker          # per-consumer sync dir under run_dir (0600, consumer-uid-owned)
    required: true                  # blocks the consumer's start until the cert exists (no spin-loop)
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | required | Binding name; referenced by `{{hm.cert.<name>.crt|key|ca}}` in a config file. |
| `hostname` | string | required | Must be one of this app's `edge.routes` hostnames. |
| `sync_dir` | string | required | Where the cert-sync helper drops the per-consumer copy, under run_dir. The proxy's own keys are **never** chmod-broadened and the proxy data dir is **never** mounted in. |
| `required` | bool | `false` | When `true`, `docker compose up` of the consumer is **blocked by a hard ordering gate** until the synced files exist. If the cert can't issue, deploy **fails fast with a reason** — the container never polls or waits. |

Renewal re-copies and signals the consumer via static argv. See [Cert bindings](./edge-and-tls.md).

### `spec.edge.routes`

**Layer-1 input only** to the managed edge (§6). Each entry becomes one `app_routes` row, re-rendered into the *whole* proxy document declaratively.

```yaml
edge:
  routes:
    - hostname: api.example.com
      upstream: api            # a SELECTOR against this app's discovered containers — NOT a literal dial target
      upstream_scheme: http
      path_prefix: /
      redirect_http: true
      hsts: true
    - hostname: broker.example.com
      cert_only: true          # edge is ACME agent only; serves no traffic on this host
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `hostname` | string | required | The public vhost. Subject to the §6.2 conflict gate: it may not shadow a managed hostname, the admin vhost, a cert-only hostname, or an auto-scaled pool. |
| `upstream` | string (selector) | — | **A selector resolved against *this app's* discovered containers**, never a literal host:port. Cross-project names are rejected; the pinned-dialer + egress-firewall refuse any resolution to a control-plane port (`9000/2019/2375`), loopback, or metadata. |
| `upstream_scheme` | enum | `http` | `http` \| `https`. |
| `path_prefix` | string | `/` | Combined with hostname for `UNIQUE(hostname, path_prefix)`. |
| `redirect_http` | bool | `true` | HTTP→HTTPS redirect. |
| `hsts` | bool | per-edge | HSTS is only emitted **after** a cert exists. |
| `cert_only` | bool | `false` | The edge is the **ACME agent only** for this hostname (serves no proxy traffic) — pair with a `cert_binding` for a raw-TCP / TLS-terminating-elsewhere service such as a broker. |

The `edge.routes` block is **parsed into the typed edge model and re-marshalled** (read-and-render, never run verbatim). The save fails if it shadows a managed hostname, touches `admin`/`tls.automation`/`pki`, targets `9000/2019/2375`, grabs `:80/:443`, or weakens XFF. **The definition file edits only Layer-1 routes** — never the protected Layer-0 base or the operator's Layer-2 raw overlay. See [Managed edge & routes](./edge-and-tls.md).

### `spec.scaling`

Process-level auto-scaling of **one stateless, edge-fronted HTTP service's replica count** (§8A). **Opt-in; disabled if omitted.**

```yaml
scaling:
  enabled: true
  service: api                       # the one service to scale (must pass candidacy C1-C7)
  min: 1
  max: 4
  per_replica_reservation: 96MiB     # REQUIRED; floored — an implausibly small value is rejected
  target_cpu_percent: 65
  breach_for: 60s
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Opt-in. |
| `service` | string | — | The single service to scale. Must pass the **candidacy gate C1–C7** (edge HTTP upstream, no fixed host port, no exclusive RW volume, not stateful/clustered, no deploy-time identity placeholder, honors the stateless restart contract, explicit opt-in). **Stateful services — databases, brokers — are rejected with a clear reason.** |
| `min` / `max` | int | `1`/`1` | Replica bounds. On a small box `effective_max` **collapses to 1** — scaling becomes a permanent safe no-op and a wanted scale-up fires `scale_refused_no_capacity` rather than queuing a docker child. |
| `per_replica_reservation` | size | **required** | Feeds the host-capacity guard. Floored; if a replica's real RSS exceeds it, Helmsman clamps and alerts. |
| `target_cpu_percent` / `breach_for` | int / dur | — | Signal + sustain window. Hysteresis is up-eager / down-lazy with a ≥ 20-pt dead band. |

> Authoring `scaling` for a stateful service is not a knob you can force — it is rejected at candidacy. Brokers/DBs are precisely the `config_files` / `cert_binding` apps of §7.4, not scaling candidates. See [Auto-scaling](./scaling-and-self-healing.md).

### `spec.self_healing`

The bounded supervisor policy (§8.5). **On by default.** Restarts crashed/stuck services and escalates to a never-deferred Helmsman-originated alert when it gives up.

```yaml
self_healing:
  enabled: true
  ladder_max: recreate     # restart -> recreate -> (redeploy, >=1 GB only)
  max_attempts_per_window: 3
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | Watcher runs on a small box; rung-2 `redeploy` stays ≥ 1 GB. |
| `ladder_max` | enum | `recreate` | The top rung: `restart` \| `recreate` \| `redeploy`. On a small box the ladder structurally tops out at `recreate`, then circuit-opens. |
| `max_attempts_per_window` | int | (tuned) | Anti-flap cap before `CIRCUIT_OPEN` + page. |

The supervisor passes the **four ordered tiny-box gates** before every action and can only reduce pressure or page — never manufacture an OOM. `oom_killed_repeated` short-circuits the ladder. See [Self-healing](./scaling-and-self-healing.md).

### `spec.ops_interface`

The App Ops Interface coordinates (§4) — how Helmsman discovers the app's rich health panels.

```yaml
ops_interface:
  enabled: true
  base_path: /ops          # a RELATIVE path only (^/[A-Za-z0-9._/-]{0,128}$) — never a host/scheme/port
  secret: { secret: OPS_SECRET }   # shared-secret header, by reference (>=16 chars, timing-safe)
  mode: auto               # auto | rich | basic
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | |
| `base_path` | string | — | A **relative path only**. **It can never supply a host, scheme, or port** — every outbound ops call is pinned to the operator-configured container endpoint (`ops_base_url`); the relative path is joined onto that pinned base. This is the §4.1 SSRF invariant: the descriptor cannot move the outbound host. |
| `secret` | ref | — | A `secret:` reference; the header value is resolved from this app's namespace, never sent to the browser. |
| `mode` | enum | `auto` | `auto` (discover) \| `rich` (force the adapter) \| `basic`. |

### `spec.git`

The GitOps fields (§7.6). **Fetch is automatic (read-plane); deploy is manual (write-plane, sha-pinned).** `auto_deploy` defaults to **false**.

```yaml
git:
  ref: refs/heads/main      # fully-qualified; the webhook never reads ref/sha from its payload
  auto_deploy: false        # default false; opt-in only auto-clicks the SAME gated promote path
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `ref` | string | — | A **fully-qualified** git ref. Resolved server-side; a webhook is a trigger only and never reads the ref/sha/repo from its (attacker-influenced) payload. |
| `auto_deploy` | bool | **`false`** | When `true`, a fetch auto-clicks the **same** gated promote path — fail-closed to `update_blocked` + a page on any validation/gate failure, never an unguarded build. |

A push triggers a **fetch only** (`git fetch` → advance `staged_commit` → compute commits-behind + diff → set `update_available`). The live checkout advances only on an explicit, sha-pinned Deploy. See [GitOps](./gitops.md).

### `spec.resources`

§0 capacity hints — advisory inputs to the resource gate and host-capacity guard.

```yaml
resources:
  reservation: 256MiB
  build: false          # never enables a build by itself; a build is always the gated write-plane path
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `reservation` | size | — | Feeds the host-capacity guard's reserve-against-desired math. |
| `build` | bool | `false` | A hint; builds remain ≥ 1 GB write-plane, manually promoted. |

---

## The `{{hm.KEY}}` binding delimiter

Managed config files (`spec.config_files`) are rendered by a **single-pass byte scanner**, not a template engine. It matches **exactly** Helmsman's own namespaced delimiter and **nothing else**:

| Touched (resolved) | Left byte-identical (data) |
|---|---|
| `{{hm.KEY}}` | the app's `${username}`, `${clientid}`, `${topic}` |
| `{{hm.cert.<binding>.crt}}` / `.key` / `.ca` | `$VAR`, `%(name)s`, Go `{{ .Field }}` |
| `{{hm.file.<name>}}` | even `{{hmFoo}}` (no dot) — copied verbatim |

There are **no conditionals, loops, functions, shell, or exec**. A `{{hm.X}}` resolves **only** if `X` is listed in that file's `bindings[]` allowlist; unknown / duplicate / malformed → hard error at save **and** at render. The renderer is **fail-closed, never empty-string** — a missing binding fails the deploy, it does not blank out.

### Binding sources

A binding value names a typed resolver. There are exactly four source kinds:

| Source | Resolves to | Notes |
|---|---|---|
| `env:<KEY>` | a value from `spec.env` | |
| `secret:<NAME>` | a value from the encrypted store | **Marks the whole file secret-bearing** → encrypted at rest, rendered `0600`. |
| `cert:<binding>` | the cert-sync'd path (§7.5) | The synced per-consumer path, so config and files always agree. |
| `app:<field>` | a fixed safe set | `public_hostname` (from the validated route row), the internal upstream URL, the app slug — **never free text**. |

### Rendered-value hygiene

Every resolved value is scrubbed: **NUL is always rejected**, and **CR/LF is rejected in every resolved value regardless of the declared `format`** (a secret with an embedded newline must not inject a second config line). Output is **emitted, never re-scanned** — a secret whose value happens to contain `{{hm.X}}` can never trigger a second substitution pass.

> **Why the app's `${...}` is sacred:** the whole point is that an app keeps its own runtime templating (its entrypoint still expands `${clientid}` at container start). Helmsman fills *only* the deploy-time blanks it owns and gets out of the way. A blanket `envsubst` would clobber the app's own placeholders — which is exactly the bug this design refuses to make.

---

## Secrets are by reference only

**The definition file is never secret-bearing.** Because of that, `canonical.yaml` is stored `0640`, and the file is **safe to commit to a public repo**.

The rules, all enforced:

1. **`spec.secrets` declares names** (and optional generate hints). **It never holds values.**
2. **Every reference resolves within the referencing app's own `(slug, NAME)` namespace.** This applies to `secret:` env, `config_files.bindings[secret:]`, `cert:`, and `ops_interface.secret`.
3. **No cross-app reads.** A name owned by another app resolves as **missing / fail-closed, with zero disclosure** — a committed file cannot exfiltrate another app's secret by guessing its name.
4. **Values arrive only out-of-band:**
   - `helmsman secret set` — reads from **stdin / `/dev/tty` / `--from-file`, never argv** (so a secret never lands in `ps`, shell history, or audit).
   - the dashboard secret panel.
   - the SSH-edited root-owned config.
   …into the AES-256-GCM store under the master key.
5. **The literal-secret lint runs over every value.** A pasted secret — PEM/key material, a token shape, long base64 — in a non-secret-bearing position is **hard-rejected** with a pointer to use a `{{hm.secret:KEY}}` / `{ secret: NAME }` reference instead.
6. **`generate` has a hard entropy floor**, mints **only on explicit operator action**, and **never overwrites an already-provisioned secret**.

> **The honest trade-off:** by-reference-only means the file alone cannot bootstrap a brand-new app end-to-end — you must provision the secret values out-of-band before (or interleaved with) the first apply. That is the deliberate cost of a file you can commit publicly and that can never carry a credential, never leak across apps, and never put a plaintext secret in your git history.

---

## Write-back & sync (split-plane ownership)

The definition file is **both** something the dashboard writes and something you can author in your repo. Reconciling those two writers is done with **split-plane ownership + a field-level 3-way merge** — **last-writer-wins is explicitly rejected.**

### The four planes

| Plane | Path / role | Ownership |
|---|---|---|
| **repo `helmsman.yaml`** | in your connected repo | **desired intent, read-only to Helmsman.** Helmsman **fetches, never pushes** — it holds no git write credential. |
| **`canonical.yaml`** | `/var/lib/helmsman/apps/<slug>/definition/`, `0640`, HMAC-tracked | **last successfully applied = the live source of truth.** |
| **`working.yaml`** | same dir | dashboard pending edits (never live until applied). |
| **`base.yaml`** | same dir | the **3-way ancestor** for the merge. |

A repo definition is adopted **exactly like compose**: read from the **pinned commit tree** via `cat-file`, and it becomes canonical **only through the sha-pinned, §0-gated promote** — **never on fetch.**

### The 3-way merge and the def-state FSM

Per field, against `base`:

- one side changed → take it.
- **both sides changed the same field → a `def_conflict` per-field review.** **Never an auto-merge, never a silent clobber.**

Crucially, even a **non-conflicting repo-side change still requires explicit operator acknowledgement** — a dashboard apply never silently folds in attacker-committed repo changes (e.g. flipping `auto_deploy`, widening `scaling.max`, adding a route).

The def-state FSM mirrors the GitOps FSM (§7.6):

```
up_to_date
  ├─ def_update_available   (repo changed; needs acknowledgement)
  ├─ def_conflict           (both planes changed the same field; per-field review)
  ├─ def_review_required    (force-push / history rewrite on the def's ref)
  ├─ applying
  └─ update_blocked         (a validation/gate failure; stays on the prior def_version)
```

`def_state` lives on the `apps` row; every applied version is recorded in the HMAC-protected `definition_versions` table (`def_sha256`, `resolved_sha256`, `source`, `parent_version_id`, `promoted_commit`). `resolved_sha256` catches a **reference target changing even when the def bytes didn't** — e.g. the repo template behind a `template_ref` was edited.

### Rollback & the iron escape hatch

- **`helmsman apply --from <path>`** (over SSH) re-asserts a known-good definition **even if the DB is wedged** — the recovery floor for the def front-end.
- **`helmsman def rollback`** **re-derives and re-validates** through the full pipeline (HMAC-checked, **never a verbatim replay** of a stored composite). It **requires a posture-widening acknowledgement** if it would *add routes, raise `scaling.max`, enable `auto_deploy`, or disable healing* — you cannot roll *back* into a *wider* posture without saying so explicitly.

---

## The apply lifecycle

`apply` / `plan` / dashboard-save all run the **one reconciler** — one chokepoint, no second trust path:

```
parse → typed DefinitionV1
  → resolve ${VAR}/.env FIRST
  → fan out into the existing typed sub-structs
  → §5.6 allowlist validator
  → §6.2 edge conflict gate         (edge.routes re-marshalled; fail-to-save on shadow/admin/TLS/PKI/:80:443/XFF)
  → secret-literal lint
  → verify required secrets provisioned
  → §0 resource gate + host-capacity guard
  → diff vs SQLite
  → gated write-plane apply, in dependency order:
        env  →  render config files  →  cert-sync (block on required)  →  compose up  →  edge route re-render LAST
  → on ANY step failure: auto-rollback the WHOLE app to the prior def_version  (no partial apply)
```

Properties to rely on:

- **Idempotent.** An `apply` with no changes produces an **empty plan = no-op**. Run it as often as you like.
- **Ordered.** Env first, edge route re-render last (behind the §6.2 atomic-apply + negative-from-internet probe). Cert-sync blocks the consumer's `up` when a binding is `required`.
- **All-or-nothing.** Any step failing rolls the **entire app** back to the prior `def_version`. There is no half-applied state.
- **Same gates, every front-end.** CLI and dashboard produce the *same* typed reconcile request. The **only** thing the CLI skips is the *web transport* gates (IP-allowlist / session / CSRF) — because it is not on the web. **Authority decides who may invoke; it never widens what `apply` may do.** A hostile or typo'd def is still run through the same fail-closed validation.

### The CLI surface

| Read-plane (safe below the §0 1 GB floor) | Write-plane (all §0-gated + one-docker-child semaphore + mem-floor, one service at a time) |
|---|---|
| `validate` | `apply` |
| `plan` / `diff` (masked, in-mem) | `deploy` / `promote --sha` |
| `status` (live-vs-declared drift) | `restart` |
| `fetch` | `def rollback` |
| `secret list` | `secret set` / `secret rm` |
| `logs` | |
| `init --from-compose` (scaffolds a `helmsman.yaml`) | |

> **Trust model:** SSH is the highest tier. An operator who can edit the root-owned config already holds the master key, so `helmsman secret set` grants nothing new — which is *why* the CLI may set secrets but **no web route ever reads the key, allowlist, or bind address.**

---

## Worked example A — a stateful broker

A TLS-terminating MQTT-style broker. It is **stateful**, so scaling is *not* applicable (it would be rejected at candidacy — so we simply do not declare it). It ships a templated config with **deploy-time `{{hm.*}}` blanks mixed with its own `${clientid}` / `${topic}` runtime placeholders**, a **cert binding** for its TLS listener via the edge's cert-only pattern, env + secret refs, and a **cert-only edge route** (the edge is ACME agent only; the broker terminates TLS itself).

```yaml
apiVersion: helmsman/v1            # exact-match; an unknown version is rejected, never best-effort parsed
kind: App
metadata:
  slug: broker                     # immutable after first apply

spec:
  # ---- compose from the pinned commit's tree (Mode 4) ----------------------
  compose:
    repo_path: deploy/docker-compose.yml   # read via `git cat-file`; paths confined to the checkout subtree

  # ---- env: a literal + a secret REFERENCE (value lives only in the store) --
  env:
    BROKER_LOG_LEVEL: warn
    BROKER_ADMIN_PASSWORD: { secret: BROKER_ADMIN_PASSWORD }

  # ---- secrets: NAMES ONLY (never values) ----------------------------------
  secrets:
    - name: BROKER_ADMIN_PASSWORD          # provisioned out-of-band: `helmsman secret set BROKER_ADMIN_PASSWORD`
    - name: NODE_COOKIE
      generate: { type: hex, bytes: 32 }   # mint on explicit action; entropy-floored; never overwrites a live one

  # ---- a templated config file: {{hm.*}} blanks + the app's own ${...} ------
  config_files:
    - path: etc/broker/broker.conf         # rendered RO under run_dir; 0600 because it is secret-bearing
      template_ref: deploy/broker.conf.tmpl
      format: ini                          # PREVIEW hint only — CR/LF/NUL hygiene applies regardless
      bindings:
        NODE_COOKIE:  { secret: NODE_COOKIE }          # secret: => file is secret-bearing => 0600 + encrypted
        ADMIN_PW:     { secret: BROKER_ADMIN_PASSWORD }
        LISTENER_CRT: { cert: broker-tls.crt }         # the cert-sync'd path (see cert_bindings below)
        LISTENER_KEY: { cert: broker-tls.key }
        PUBLIC_HOST:  { app: public_hostname }         # from the validated route row, not free text

  # ---- cert binding: edge issues the cert; cert-sync drops it under run_dir -
  cert_bindings:
    - name: broker-tls
      hostname: broker.example.com         # must match an edge.routes hostname below
      sync_dir: certs/broker               # per-consumer 0600 path; proxy keys never chmod-broadened
      required: true                       # hard ordering gate: `up` blocks until the cert exists; no spin-loop

  # ---- edge: a CERT-ONLY route (edge is ACME agent only; broker serves TLS) -
  edge:
    routes:
      - hostname: broker.example.com
        cert_only: true                    # no proxy traffic on this host; the broker terminates TLS at L4

  # ---- scaling intentionally ABSENT: a broker is stateful => not a candidate -

  self_healing:
    enabled: true
    ladder_max: recreate                   # `recreate` re-runs the template render + cert-sync, healing drift

  resources:
    reservation: 192MiB
```

The corresponding template (`deploy/broker.conf.tmpl`) shows the split clearly — Helmsman fills `{{hm.*}}`; the broker's own entrypoint expands `${clientid}` / `${topic}` at container start, **byte-identical**:

```ini
# === filled by Helmsman at deploy time (its own delimiter) ===
node.cookie       = {{hm.NODE_COOKIE}}
admin.password    = {{hm.ADMIN_PW}}
listener.tls.cert = {{hm.LISTENER_CRT}}
listener.tls.key  = {{hm.LISTENER_KEY}}
advertise.host    = {{hm.PUBLIC_HOST}}

# === left untouched — the broker's OWN runtime placeholders (data to Helmsman) ===
acl.topic.pattern = devices/${clientid}/${topic}
client.id.default = ${clientid}
```

**Preview** masks the secret bindings — e.g. `‹secret:NODE_COOKIE (32 B)›` — so you can confirm the *structure* and that `${clientid}` / `${topic}` survived, while **no secret byte is ever sent to the browser**.

---

## Worked example B — a stateless API

A stateless HTTP API: an edge route, an **opt-in scaling policy**, and a healthcheck driven by self-healing. Secrets are by reference, as always.

```yaml
apiVersion: helmsman/v1
kind: App
metadata:
  slug: web-api                    # immutable after first apply

spec:
  compose:
    repo_path: deploy/docker-compose.yml
    dockerfile_path: deploy/Dockerfile   # a hint only; a build is still the gated, manually-promoted write path

  env:
    LOG_LEVEL: info
    DATABASE_URL: { secret: DATABASE_URL }   # reference; resolved only within (web-api, DATABASE_URL)

  secrets:
    - name: DATABASE_URL                     # `helmsman secret set DATABASE_URL --from-file ./db.url`
    - name: SHARED_AUTH_TOKEN
      generate: { type: base64, bytes: 32 }  # a SHARED auth secret is fine for a stateless service (not an identity)

  # ---- a public edge route; upstream is a SELECTOR against discovered containers
  edge:
    routes:
      - hostname: api.example.com
        upstream: api                        # resolved to this app's container; never a literal dial target
        upstream_scheme: http
        path_prefix: /
        redirect_http: true
        hsts: true

  # ---- opt-in auto-scaling of the one stateless, edge-fronted HTTP service ---
  scaling:
    enabled: true
    service: api                             # must pass candidacy C1-C7; gains a host port/RW vol => scaled back to 1
    min: 1
    max: 4                                    # effective_max collapses to 1 on a near-OOM box (safe no-op + alert)
    per_replica_reservation: 96MiB           # REQUIRED + floored; feeds the host-capacity guard
    target_cpu_percent: 65
    breach_for: 60s

  # ---- healthcheck-driven self-healing (the restart contract for a stateless svc)
  self_healing:
    enabled: true
    ladder_max: recreate
    max_attempts_per_window: 3               # then CIRCUIT_OPEN + a never-deferred Helmsman-originated page

  # ---- rich ops panels via the App Ops Interface ----------------------------
  ops_interface:
    enabled: true
    base_path: /ops                          # RELATIVE only; the descriptor can never move the outbound host
    secret: { secret: OPS_SECRET }
    mode: auto

  git:
    ref: refs/heads/main
    auto_deploy: false                       # default; a push fetches only — deploy stays a manual, sha-pinned promote

  resources:
    reservation: 256MiB
```

This API is a legitimate scaling candidate because every C1–C7 condition holds: it is an edge HTTP upstream with a known internal port, publishes no fixed host port (replicas are internal-port-only), holds no exclusive RW volume, is not stateful, carries no deploy-time *identity* placeholder (a *shared* `SHARED_AUTH_TOKEN` is fine — a per-node cookie would not be), honors a stateless restart contract, and opted in. Compare with [example A](#worked-example-a--a-stateful-broker), where the broker is stateful and scaling is therefore not even authored.

---

## Field quick reference

| Path | Type | Required | Default |
|---|---|---|---|
| `apiVersion` | string (`helmsman/v1`) | yes | — |
| `kind` | string (`App`) | yes | — |
| `metadata.slug` | string (immutable) | yes | — |
| `spec.compose.repo_path` \| `.inline` | string | one of | — |
| `spec.compose.dockerfile_path` | string | no | — |
| `spec.env.<KEY>` | literal \| `{secret: NAME}` | no | — |
| `spec.secrets[].name` | string | yes (per entry) | — |
| `spec.secrets[].generate` | `{type, bytes}` | no | — |
| `spec.config_files[].path` | string (run_dir-rel) | yes | — |
| `spec.config_files[].template_ref` \| `.template` | string | one of | — |
| `spec.config_files[].format` | enum (preview hint) | no | — |
| `spec.config_files[].bindings.<KEY>` | `{env\|secret\|cert\|app: …}` | no | — |
| `spec.cert_bindings[].name` / `.hostname` / `.sync_dir` | string | yes | — |
| `spec.cert_bindings[].required` | bool | no | `false` |
| `spec.edge.routes[].hostname` | string | yes | — |
| `spec.edge.routes[].upstream` | selector | for proxy routes | — |
| `spec.edge.routes[].upstream_scheme` | enum | no | `http` |
| `spec.edge.routes[].path_prefix` | string | no | `/` |
| `spec.edge.routes[].redirect_http` | bool | no | `true` |
| `spec.edge.routes[].hsts` | bool | no | per-edge |
| `spec.edge.routes[].cert_only` | bool | no | `false` |
| `spec.scaling.enabled` | bool | no | `false` |
| `spec.scaling.service` | string | if enabled | — |
| `spec.scaling.min` / `.max` | int | no | `1` / `1` |
| `spec.scaling.per_replica_reservation` | size | **if enabled** | — |
| `spec.self_healing.enabled` | bool | no | `true` |
| `spec.self_healing.ladder_max` | enum | no | `recreate` |
| `spec.ops_interface.enabled` | bool | no | `true` |
| `spec.ops_interface.base_path` | string (relative) | no | — |
| `spec.ops_interface.secret` | `{secret: NAME}` | no | — |
| `spec.ops_interface.mode` | enum | no | `auto` |
| `spec.git.ref` | string (fully-qualified) | no | — |
| `spec.git.auto_deploy` | bool | no | **`false`** |
| `spec.resources.reservation` | size | no | — |

> Unknown keys anywhere are a **hard reject** (`additionalProperties: false`). When in doubt, run `helmsman validate` — it is read-plane and safe on any host.

---

**Related docs:** [README](../README.md) · [Managed config files](./config-files-and-secrets.md) · [Cert bindings](./edge-and-tls.md) · [GitOps / repo-path apps](./gitops.md) · [Managed edge & routes](./edge-and-tls.md) · [Secrets](./config-files-and-secrets.md) · [Auto-scaling](./scaling-and-self-healing.md) · [Self-healing](./scaling-and-self-healing.md) · [CLI reference](./cli.md)