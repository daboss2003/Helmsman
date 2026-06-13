# Helmsman CLI Reference

The `helmsman` binary is both the long-running server (the dashboard + managed edge) **and** a set of operator commands you run over SSH on the host. This page documents every command, what plane it touches (read vs write), how it relates to the dashboard, and the trust and parity guarantees that make the CLI safe to use as a first-class control surface.

> **One-line mental model:** the CLI is not a back door around Helmsman's safety — it is a **second front door** onto the *same* reconciler. Everything you do with `helmsman apply`, `deploy`, `secret set`, etc. passes the **same single compose-validation chokepoint**, the **same edge-conflict gate**, the **same secure-by-default edge baseline**, the **same host-capacity guard**, and the **same fail-closed posture** the web UI does. The only thing the CLI skips is the *web transport* gates (IP allowlist, session, CSRF) — because it isn't on the web.

See also: [README](../README.md) · [Configuration / root of trust](./architecture.md) · [Definition file (`helmsman.yaml`)](./definition-file.md) · [Managed edge](./edge-and-tls.md) · [Security model](./security.md).

---

## Table of contents

- [Conventions](#conventions)
- [The two planes (read vs write)](#the-two-planes-read-vs-write)
- [Shared-core parity (why the CLI is safe)](#shared-core-parity-why-the-cli-is-safe)
- [Trust model (who-may-invoke vs what-apply-may-do)](#trust-model-who-may-invoke-vs-what-apply-may-do)
- [How secret values enter Helmsman](#how-secret-values-enter-helmsman)
- [Command reference](#command-reference)
  - [Root-of-trust commands (SSH only)](#root-of-trust-commands-ssh-only)
  - [Read-plane commands](#read-plane-commands)
  - [Write-plane commands (gated)](#write-plane-commands-gated)
- [End-to-end: a full CLI-first deploy (never opening the dashboard)](#end-to-end-a-full-cli-first-deploy-never-opening-the-dashboard)
- [Exit codes](#exit-codes)

---

## Conventions

- **`helmsman <command>`** — all commands are subcommands of the single static binary. The same binary that systemd runs as the server is what you invoke by hand.
- **Run over SSH on the host.** The CLI is for a single operator who already has shell access to the box. It is **not** exposed over the network, and there is no remote CLI protocol.
- **App targeting.** Commands that act on one app take a `--app <slug>` flag (or, where noted, infer the slug from a `helmsman.yaml` you point at). The slug is **immutable after first apply**.
- **Config & key location.** The root-owned config (`/etc/helmsman/config.yaml`, `0600 root:root`) holds the master key. The CLI reads it the same way the server does; commands that touch secrets need permission to read it (see [Trust model](#trust-model-who-may-invoke-vs-what-apply-may-do)).
- **`-f` / `--from` / `--from-file` / `--sha`** appear on several commands and always mean the same thing across commands.

---

## The two planes (read vs write)

Every command is in exactly one of two planes. **This distinction is a safety property, not a UX nicety** — it is what lets you operate Helmsman on a small or near-OOM host without ever risking the control plane.

| Plane | What it may do | Resource floor | Commands |
|---|---|---|---|
| **Read plane** | Parse, validate, diff, fetch git objects, list, read logs, scaffold — **touches nothing live** (no `docker compose`, no build, no config re-render) | **Safe below the §0 1 GB floor** | `validate`, `plan` / `diff`, `status`, `fetch`, `secret list`, `logs`, `init --from-compose`, `schema` |
| **Write plane** | Mutate the running system — apply a definition, deploy a commit, restart, roll back, set/remove a secret value | **Gated: ≥ 1 GB RAM + global one-docker-child semaphore + memory-headroom floor; one service at a time** | `apply`, `deploy` / `promote --sha`, `restart`, `def rollback`, `secret set` / `secret rm` |
| **Root-of-trust** | Generate/verify the credentials and keys in the SSH-edited config; rebuild the edge base | n/a (local crypto / config) | `hash-password`, `gen-key`, `gen-totp`, `verify-key`, `edge restore-default` |

**Why the floor matters for the write plane.** A `docker compose pull/up/build` on a tiny box can OOM the host and cascade it into a crash-loop — and the edge dies first. So every write-plane command first passes the §0 resource gate for its plane, then must **non-blockingly acquire the global one-docker-child semaphore** (Helmsman never queues docker children — queuing *is* the OOM vector), then clears a **memory-headroom floor**, and only ever acts on **one service at a time**. If any gate fails, the command refuses and tells you why — it never proceeds half-way.

Read-plane commands deliberately have **none** of those costs, so you can `validate`, `plan`, `status`, and `fetch` freely even on an undersized host.

---

## Shared-core parity (why the CLI is safe)

> **This is the load-bearing guarantee of the whole CLI.** Read it before trusting `apply` from a script.

The CLI and the dashboard are **two thin front-ends that produce the exact same typed reconcile request** and push it through the **one** chokepoint. The CLI is **upstream of** that single chokepoint — never *around* it. Concretely, anything you submit via `helmsman apply` is run through, in this order:

1. **Parse → typed `DefinitionV1`** (k8s-style envelope; `apiVersion: helmsman/v1` is exact-match fail-closed; unknown keys are a hard reject via `DisallowUnknownFields` + an independent JSON-Schema gate). All input formats (`.yaml`/`.yml`/`.toml`) normalize through **one canonical JSON intermediate**; YAML anchors, merge keys, and duplicate keys are hard-rejected so a parser differential can't smuggle a key past validation.
2. **Resolve `${VAR}` / `.env` first** (validating *before* interpolation is a known bypass).
3. **§5.6 compose allowlist validator** — the single chokepoint. Reject any unknown top-level/service key and the full dangerous set (`privileged`, `cap_add`, host-namespaces, dangerous binds, `security_opt` unconfined, `devices`, …); bind mounts confined under the app's run dir (canonicalize-then-`Rel`, reject `..`/absolute/symlink-escape).
4. **§6.2 edge-conflict gate** — the `edge.routes` block is parsed into the typed edge model and **re-marshalled (read-and-render, never run verbatim)**. Fail-to-save if it shadows a managed hostname, touches `admin`/`tls.automation`/`pki`, targets `9000/2019/2375`, grabs `:80/:443`, or weakens XFF.
5. **Secret-literal lint** (high-entropy / PEM / token-shape literals are rejected — "use a `secret:` reference").
6. **Verify required secrets are provisioned.**
7. **§0 resource gate + host-capacity guard.**
8. **Diff vs SQLite**, then **gated write-plane apply in dependency order** (env → render config files → cert-sync block-on-required → `compose up` → edge route re-render last, behind the §6.2 atomic-apply + negative-from-internet probe), with **whole-app auto-rollback to the prior `def_version` on any step failure** (no partial apply).

> **The only thing the CLI skips is the *web transport* gates** — the IP allowlist, the session loader, and CSRF/Origin checks — because it is not serving an HTTP request. The validator, the edge gate, the SBD baseline, the host-capacity guard, and the fail-closed posture are **identical** to the dashboard's. There is no "CLI mode" that relaxes a single compose or edge invariant.

A hostile or typo'd definition handed to `helmsman apply` is therefore run through the **same** fail-closed validation as one authored in the UI. The CLI adds **zero** new bytes that reach `docker compose`.

---

## Trust model (who-may-invoke vs what-apply-may-do)

Two ideas, kept strictly separate:

- **Authority decides *who may invoke* a command.** SSH access to the host *is* that authority. The operator who can edit the root-owned `/etc/helmsman/config.yaml` is the **highest trust tier in the system** — they already hold the **master key** (it lives only in that file). 
- **Authority never widens *what `apply` may do*.** Being able to invoke `apply` does not let `apply` do anything the dashboard's apply couldn't. Same validator, same gates, same fail-closed behavior.

A direct consequence — and the reason the CLI is allowed to set secret values at all:

> **`helmsman secret set` grants nothing new.** An operator who can run it already holds the master key. They could decrypt the entire store regardless. So letting the CLI *write* a ciphertext value confers no new capability. This is exactly **why** the CLI may set secrets, while **no web route ever reads the master key, the IP allowlist, or the bind address** — those would hand a lesser tier a capability it does not already have.

This is also why the root-of-trust commands (`hash-password`, `gen-key`, `gen-totp`, `verify-key`, `edge restore-default`) are **SSH-only and have no web equivalent**: they operate on the credentials and keys that define the trust boundary itself.

---

## How secret values enter Helmsman

Secret **values** are handled with one inflexible rule:

> **A secret value never appears in `argv`.** It is read only from **`/dev/tty`** (interactive prompt), **`--from-file <path>`**, or **`--stdin`**. There is no `--value` flag, by design.

Why: anything on the command line is visible in `ps`, the shell history, process accounting, and audit of the invocation. The `Redacted` type guarantees secrets never serialize into logs/errors/temp files at rest; keeping them out of `argv` closes the one channel that bypasses that type.

Other rules that apply to every value you set:

- **By reference only in the definition.** `helmsman.yaml` declares secret *names* (`spec.secrets`) and *references* them (`secret: NAME`); it is **never secret-bearing** and is safe to commit to a public repo. Values arrive out-of-band via `secret set`, the dashboard panel, or the SSH-edited config.
- **Namespaced per app.** A reference resolves **only** within the referencing app's own `(slug, name)` namespace — a name owned by another app resolves as **missing / fail-closed, with zero disclosure**.
- **Literal lint on every value.** The §7.4 high-entropy / PEM / token-shape lint runs over each value; a value that *looks* like it should have been a reference is handled per policy (the definition-side lint hard-rejects pasted secret literals).
- **`generate` hints are conservative.** A `generate:` hint mints a value **only on explicit operator action**, enforces a **hard per-type entropy floor**, and **never overwrites an already-provisioned secret**.

---

## Command reference

For each command: **purpose**, **usage**, **key flags**, **plane**, and an **example**.

---

### Root-of-trust commands (SSH only)

These bootstrap and verify the credentials/keys in `/etc/helmsman/config.yaml`. They are run by hand over SSH; **no web route reads or writes auth, the allowlist, the master key, or the bind address.** Passwords are read from `/dev/tty`, never `argv`.

> **Where the output goes.** These commands print material you paste into the root-owned config file (which you edit over SSH). They do **not** write the config for you — the file is the operator's root-of-trust, edited deliberately. After editing, `SIGHUP` hot-reloads the allowlist + auth (but **not** keys); a key change requires a restart.

#### `helmsman hash-password`

- **Purpose:** produce an **argon2id** hash of the admin password to paste into `config.yaml`. There is no public registration and no web password reset — this is the only way the admin credential is set.
- **Usage:** `helmsman hash-password`
- **Key flags:** none for the secret (the password is read from `/dev/tty`, prompted twice). Optional tuning flags expose the argon2id parameters.
- **Plane:** root-of-trust.
- **Notes:** Argon2id is **tuned small by default** (`m ≈ 8 MiB`, `t = 2`, `p = 1`, verify serialized + rate-limited) so a login attempt can't OOM a tiny box. **Raise `m` on a larger host** for more resistance.

```console
$ helmsman hash-password
New admin password: ********
Confirm password:   ********

# Paste this under auth.password_hash in /etc/helmsman/config.yaml:
$argon2id$v=19$m=8192,t=2,p=1$c29tZXNhbHQ$Rdescbg...
```

#### `helmsman gen-key`

- **Purpose:** generate a fresh **encryption master key** (`encryption_key`) for the AES-256-GCM secret store. Everything at rest — env blobs, git creds, ops secrets, channel secrets — is encrypted under it.
- **Usage:** `helmsman gen-key`
- **Key flags:** none.
- **Plane:** root-of-trust.
- **Critical:** the key lives **only** in the config file, never in the DB/logs/UI. **Back up config (the key) and the DB separately and offsite** — losing the key bricks all ciphertext irrecoverably. Key rotation is done via `encryption_key_previous` (see [config docs](./architecture.md)).

```console
$ helmsman gen-key
# Paste this under encryption_key in /etc/helmsman/config.yaml, then back it up offsite:
hm_key_b64:9f3c1d...== 
```

#### `helmsman gen-totp`

- **Purpose:** generate a **TOTP secret** for the admin's second factor on `POST /login`.
- **Usage:** `helmsman gen-totp`
- **Key flags:** none (prints the secret + an `otpauth://` URI / QR you scan into an authenticator app).
- **Plane:** root-of-trust.

```console
$ helmsman gen-totp
TOTP secret (store under auth.totp_secret): JBSWY3DPEHPK3PXP
otpauth://totp/Helmsman:admin?secret=JBSWY3DPEHPK3PXP&issuer=Helmsman
[QR code rendered to terminal]
```

#### `helmsman verify-key`

- **Purpose:** **catch a key/DB mismatch before it corrupts data.** Decrypts one column from SQLite using the configured `encryption_key` and confirms it round-trips — so you discover a wrong or rotated key **now**, not silently on the next write.
- **Usage:** `helmsman verify-key`
- **Key flags:** none.
- **Plane:** root-of-trust (read-only against the DB + config).
- **When to run it:** after `gen-key`/rotation, after restoring a DB or config from backup, or any time you suspect config and DB drifted apart. This is the antidote to the backup footgun (config and DB are backed up separately).

```console
$ helmsman verify-key
encryption_key: OK (decrypted env_blobs/3 cleanly)
encryption_key_previous: present (rotation in progress)
```

#### `helmsman edge restore-default`

- **Purpose:** the **iron escape hatch** for the managed edge. Rebuilds the protected **Layer 0** base config + the admin IP-allowlist matcher **from typed structs**, **drops the Layer-2 operator overlay**, and **keeps the app routes (Layer 1)** — so the edge is **never irrecoverable** and **SSH is always the recovery floor**.
- **Usage:** `helmsman edge restore-default`
- **Key flags:** none.
- **Plane:** root-of-trust (rewrites the live edge to a known-safe floor).
- **Why it can't make things worse:** the restore **re-derives** the config (Layer 0 from code, Layer 1 from the current `app_routes`); it **never loads a stored `composite_json`**. Even a tampered DB version row can't become a loaded config. Use it if a raw-overlay edit wedged the edge, or if the edge ever fails to come up cleanly.

```console
$ helmsman edge restore-default
Rebuilding Layer 0 (protected base) from typed structs...
Re-deriving Layer 1 from app_routes (3 routes preserved)...
Dropping Layer 2 overlay (1 stored overlay set aside; re-add via the editor).
Validate -> stage -> /load ... OK. Negative-from-internet probe: admin vhost returns 404 from un-allowlisted vantage. OK.
Edge restored to safe default.
```

---

### Read-plane commands

Safe below the §0 1 GB floor. They never touch the live system — no `docker compose`, no build, no config re-render, no working-copy change.

#### `helmsman validate`

- **Purpose:** run a `helmsman.yaml` through the **full §5.6 validator + §6.2 edge gate + secret lint** without writing anything. The fastest way to know a definition is acceptable before you `apply`.
- **Usage:** `helmsman validate -f helmsman.yaml`
- **Key flags:** `-f, --from <path>` (the definition file); `--app <slug>` (optional override / disambiguation).
- **Plane:** read.
- **Notes:** identical validation to what `apply` runs at step 3–5 — so a clean `validate` means `apply` won't be rejected at the chokepoint (it can still legitimately defer at the §0/host-capacity gate at apply time).

```console
$ helmsman validate -f helmsman.yaml
apiVersion helmsman/v1 OK · kind App · slug "billing-api"
compose: 4 services, all keys allowlisted, binds confined under run_dir OK
edge.routes: 1 route -> internal upstream OK (no :80/:443 grab, no control-plane port)
secrets: 2 referenced, both provisioned · 0 literal-secret findings
VALID
```

#### `helmsman plan` / `helmsman diff`

- **Purpose:** show **what `apply` would change** — the reconcile diff of the declared definition vs what's stored in SQLite. Computed **in-memory**, with **secrets masked**.
- **Usage:** `helmsman plan -f helmsman.yaml` (alias: `helmsman diff`)
- **Key flags:** `-f, --from <path>`; `--app <slug>`.
- **Plane:** read.
- **Notes:** an **empty plan means `apply` is a no-op** (`apply` is idempotent). Secret *values* never appear — only that a binding exists / changed (e.g. `‹secret:DB_PASSWORD›`).

```console
$ helmsman plan -f helmsman.yaml
~ env: add KEY "LOG_LEVEL=info"
~ secrets: DB_PASSWORD (provisioned, unchanged)
+ edge.routes: billing.example.com -> billing-api:8080 (HTTPS, redirect, HSTS-after-cert)
~ scaling: unchanged (max=1)
Plan: 2 to change, 1 to add, 0 to remove.
```

#### `helmsman status`

- **Purpose:** show **live-vs-declared drift** for an app — what's actually running vs what the definition says should be, plus the def-state and git-update state.
- **Usage:** `helmsman status --app <slug>`
- **Key flags:** `--app <slug>`.
- **Plane:** read.

```console
$ helmsman status --app billing-api
app billing-api   def_state: up_to_date   update_state: update_available (2 behind)
deployed_commit: 4f1c9ab   staged_commit: 9d20e7c
services:
  api    up (healthy)   1 replica   restarts: 0
edge:    billing.example.com  cert: valid (renews in 41d)
drift:   none (live matches canonical.yaml)
```

#### `helmsman fetch`

- **Purpose:** **read-plane git fetch** — advance the **staged ref** for a repo-backed app, compute commits-behind + a diff preview, and set `update_available`. **Touches nothing live**: no checkout, no re-render, no `docker compose`, no build.
- **Usage:** `helmsman fetch --app <slug>`
- **Key flags:** `--app <slug>`.
- **Plane:** read. (This is *exactly* the work a webhook does — fetch-only, trigger-only — which is why a CI push can never cause a surprise on-box build.)
- **Safety notes:** every git invocation is config-/attribute-proofed (`GIT_CONFIG_NOSYSTEM`, `core.hooksPath=/dev/null`, `core.symlinks=false`, neutralized filter/textconv drivers, submodules off); bytes are read via `git cat-file`, diffs via `--no-textconv --no-ext-diff`. A force-push surfaces as a distinct `history_rewritten` state to acknowledge, never a silent diff.

```console
$ helmsman fetch --app billing-api
Fetching refs/helmsman/staged/billing-api (config-/attribute-proofed)...
staged_commit: 4f1c9ab -> 9d20e7c  (2 commits behind)
update_state: update_available   diff preview ready (helmsman status / dashboard updates view)
No live change. Deploy with: helmsman deploy --app billing-api --sha 9d20e7c
```

#### `helmsman secret list`

- **Purpose:** list the secret **names** declared/provisioned for an app and their status (present / missing). **Never prints values.**
- **Usage:** `helmsman secret list --app <slug>`
- **Key flags:** `--app <slug>`.
- **Plane:** read.

```console
$ helmsman secret list --app billing-api
NAME            STATUS        SIZE   SOURCE
DB_PASSWORD     provisioned   32 B   secret set
HMAC_SIGNING    provisioned   64 B   generate
STRIPE_KEY      MISSING       —      (declared in spec.secrets, no value yet)
```

#### `helmsman logs`

- **Purpose:** stream/read container logs for an app or service (the same log source the dashboard's SSE log view uses, file-pointer-backed — logs are never stored in SQLite).
- **Usage:** `helmsman logs --app <slug> [--service <name>] [-f]`
- **Key flags:** `--app <slug>`; `--service <name>`; `-f, --follow` to tail.
- **Plane:** read.

```console
$ helmsman logs --app billing-api --service api -f
2026-06-13T10:02:11Z api  listening on :8080
2026-06-13T10:02:11Z api  health: all dependencies up
```

#### `helmsman init --from-compose`

- **Purpose:** **scaffold a `helmsman.yaml`** from an existing compose file so you can adopt an app declaratively without hand-writing the envelope. Produces a starting definition you then review, commit, and `apply`.
- **Usage:** `helmsman init --from-compose docker-compose.yml [--slug <slug>]`
- **Key flags:** `--from-compose <path>`; `--slug <slug>` (the immutable app slug; must match `^[a-z][a-z0-9-]{1,30}$`).
- **Plane:** read (writes only the scaffold file you asked for — no live change).
- **Notes:** the scaffold declares secret **names** (by reference), never values; you fill values later with `secret set`.

```console
$ helmsman init --from-compose docker-compose.yml --slug billing-api
Wrote helmsman.yaml (apiVersion: helmsman/v1, kind: App, slug: billing-api)
  spec.compose.repo_path: docker-compose.yml
  spec.secrets: [DB_PASSWORD]   # declared by name; set the value with `helmsman secret set`
Review it, commit it, then: helmsman validate -f helmsman.yaml
```

#### `helmsman schema`

- **Purpose:** print the **JSON Schema for `helmsman.yaml`** (`DefinitionV1`, `additionalProperties:false` everywhere) — useful for editor autocompletion/validation and for understanding the 12 `spec` projections.
- **Usage:** `helmsman schema`
- **Key flags:** none.
- **Plane:** read.

```console
$ helmsman schema > helmsman.schema.json
# Wire it into your editor's YAML language server for inline validation.
```

#### `helmsman env import` (read-plane preview)

- **Purpose:** ingest a `.env`'s **values** into the encrypted store (Helmsman then writes the live `.env` itself). The uploaded/repo file is import-only, never the live file. See [env-import.md](./env-import.md).
- **Usage:** `helmsman env import --slug <s> --from <file>` · `--from-repo <path>` · add `--apply` to commit.
- **Plane:** read for `--dry-run`/default preview (prints a **masked** add/change/unchanged table); **write** with `--apply`.

```console
$ helmsman env import --slug billing-api --from ./.env.production --dry-run
PORT          plain    add
DB_PASSWORD   secret   add   (value hidden)
# repo source is read via git cat-file from the pinned commit:
$ helmsman env import --slug billing-api --from-repo deploy/.env.production --apply
```

#### `helmsman host plan` / `helmsman host status`

- **Purpose:** read-plane dry-run/drift for the **host definition** (`kind: Host`) — the registry, defaults, server-wide alerting, and cross-app ordering. See [host-file.md](./host-file.md).
- **Plane:** read.

---

### Write-plane commands (gated)

All of these pass **identically**: §0 ≥ 1 GB resource gate + non-blocking acquire of the **global one-docker-child semaphore** + memory-headroom floor, and they act **one service at a time**. If a gate isn't satisfied, the command **defers/refuses with a reason** — it never starts a partial change.

#### `helmsman apply`

- **Purpose:** reconcile an app to a declared `helmsman.yaml` — the CLI equivalent of a dashboard "save & apply", through the same reconciler.
- **Usage:** `helmsman apply -f helmsman.yaml`  ·  escape hatch: `helmsman apply --from <path>`
- **Key flags:**
  - `-f, --from <path>` — the definition to apply.
  - `--from <path>` (the **iron escape hatch**) — re-assert a **known-good definition over SSH even if the DB is wedged**.
- **Plane:** write (gated).
- **Behavior:** parse → typed `DefinitionV1` → resolve `${VAR}`/`.env` → **§5.6 validator** → **§6.2 edge gate** → secret lint → verify required secrets → **§0 + host-capacity guard** → diff vs SQLite → **gated apply in dependency order** → **whole-app auto-rollback on any step failure**. `apply` is **idempotent** — an empty plan is a clean no-op.
- **Notes:** `apply` does **not** silently fold in attacker-committed repo changes; a non-conflicting repo-side change still requires explicit acknowledgement (see the 3-way merge in [definition-file docs](./definition-file.md)). On success, `canonical.yaml` becomes the new live source of truth.

```console
$ helmsman apply -f helmsman.yaml
Validating (§5.6 + edge gate + secret lint)... OK
Plan: 2 to change, 1 to add.
§0 gate: host has 2 GB (OK) · semaphore acquired · headroom OK
Applying (one service at a time):
  env -> render config files -> cert-sync -> compose up (api) -> edge re-render (last)
Edge apply: validate -> stage -> /load -> negative-from-internet probe OK
def_version 7 promoted. canonical.yaml updated. DONE.
```

#### `helmsman apply --kind Host`

- **Purpose:** apply the **server-wide host definition** (`kind: Host`) — the app registry, global defaults, server-wide alerting, cross-app ordering. Same reconciler, same gates; structurally cannot express a Tier-1 field. See [host-file.md](./host-file.md).
- **Usage:** `helmsman apply --kind Host --from host.yaml`
- **Plane:** write (gated).

#### `helmsman host deploy`

- **Purpose:** an **orchestrated multi-app deploy** in `setup_orchestration.order`. Presents one ordered plan but mints a **separate, lazily-minted, byte-bound, single-use confirm token per app** whose plan includes a setup step — it changes **sequence, never automation**, and never auto-chains one app's setup off another's confirm.
- **Usage:** `helmsman host deploy` (interactive walk) · `--confirm <token>` per app.
- **Plane:** write (gated).

#### `helmsman setup run`

- **Purpose:** run an app's `spec.setup` script **on demand** (or re-run it) in the sandbox — always behind a **single-use confirm token bound to the full `script_set_checksum`**. Never runs from a webhook/auto-deploy/boot.
- **Usage:** `helmsman setup run --app <slug> [--force]` (`--force` re-runs a satisfied `on_first_deploy`).
- **Plane:** write (gated).

#### `helmsman deploy` / `helmsman promote --sha`

- **Purpose:** the **manual, sha-pinned promote** for a repo-backed app — advance the live checkout to an **exact reviewed commit** and deploy it. This is the **only** build path; a webhook can never reach it.
- **Usage:** `helmsman deploy --app <slug> --sha <40-hex>` (alias: `helmsman promote`)
- **Key flags:** `--app <slug>`; `--sha <commit>` (the exact reviewed 40-hex commit).
- **Plane:** write (gated).
- **Behavior (fenced):** rejects if `staged` moved since you reviewed ("re-review"); **holds the one-docker-child semaphore across checkout → §5.6 (on the pinned commit's bytes, read via `cat-file`) → `compose up/pull/(build)`**; deploys the **validated artifact**, never a re-read live tree (this closes build-smuggled-past-review). A `deploys` row pins the deployed commit; on validation/gate failure the app stays on the old deployment (`update_blocked`), never partial.

```console
$ helmsman deploy --app billing-api --sha 9d20e7c1f0a4b3e8d5c6a7b2e9f0c1d2e3f4a5b6
staged_commit matches reviewed sha. Semaphore acquired (held across deploy).
Reading pinned tree via cat-file · §5.6 on those exact bytes... OK
build_policy: image pre-built off-box (no on-box build) · §0 OK
compose up (api)... healthy. edge re-render OK.
deployed_commit: 4f1c9ab -> 9d20e7c  (source: manual_promote)
```

#### `helmsman restart`

- **Purpose:** restart an app or one of its services through the gated write plane (mirrors the dashboard's restart control + the supervisor's rung-1 action).
- **Usage:** `helmsman restart --app <slug> [--service <name>]`
- **Key flags:** `--app <slug>`; `--service <name>` (omit to restart the project's non-protected services).
- **Plane:** write (gated).
- **Notes:** subject to the **memory-headroom floor** (a restart momentarily runs old+new; below the floor it refuses and tells you, rather than risking an OOM). **Protected edge/cert/socket-proxy services are never targets.**

```console
$ helmsman restart --app billing-api --service api
§0 OK · semaphore acquired · headroom OK (old+new fits)
Restarting service "api" (protected edge excluded)... healthy.
```

#### `helmsman def rollback`

- **Purpose:** roll an app's **definition** back to a prior `def_version`, **re-derived and re-validated** through the full pipeline — never a verbatim replay.
- **Usage:** `helmsman def rollback --app <slug> --version <id>`
- **Key flags:** `--app <slug>`; `--version <id>` (the `definition_versions` row).
- **Plane:** write (gated).
- **Behavior:** the stored version is **HMAC-checked**, then **re-derived + re-validated** through §5.6/§6.2/§0 — a DB tamper can't become a loaded config. If the rollback would **widen posture** — add routes, raise `scaling.max`, enable `auto_deploy`, or disable self-healing — it **requires an explicit posture-widening acknowledgement** before it proceeds.

```console
$ helmsman def rollback --app billing-api --version 5
Version 5 HMAC OK. Re-deriving + re-validating through §5.6/§6.2/§0...
WARNING: rolling back to v5 would re-enable auto_deploy (posture-widening).
Confirm with --ack-widen to proceed.

$ helmsman def rollback --app billing-api --version 5 --ack-widen
Acknowledged. Applying re-validated v5 (gated)... def_version 5 re-promoted.
```

#### `helmsman secret set` / `helmsman secret rm`

- **Purpose:** set or remove a secret **value** in the AES-256-GCM store, by app+name.
- **Usage:**
  - `helmsman secret set --app <slug> --name <NAME>` (value from `/dev/tty` prompt)
  - `helmsman secret set --app <slug> --name <NAME> --from-file <path>`
  - `... --from-file - ` or `--stdin` (value from stdin)
  - `helmsman secret rm --app <slug> --name <NAME>`
- **Key flags:** `--app <slug>`; `--name <NAME>`; `--from-file <path>` / `--stdin`.
- **Plane:** write (gated — but note this writes ciphertext, not a docker child; it does not spin up a container).
- **Hard rules (restated):** the **value never appears in `argv`** — only `/dev/tty`, `--from-file`, or `--stdin`. The value is namespaced to this app's `(slug, name)`; the literal-secret lint runs over it; `set` for a `generate`-hinted name **won't overwrite an already-provisioned secret**. Per the [trust model](#trust-model-who-may-invoke-vs-what-apply-may-do), this **grants nothing new** — the invoker already holds the master key.

```console
$ helmsman secret set --app billing-api --name DB_PASSWORD
Enter value for billing-api/DB_PASSWORD (read from /dev/tty, not argv): ********
Confirm: ********
Stored (AES-256-GCM, 32 B). Literal lint: OK. env_blob v3 created.

# From a file (e.g. a credential file), value never on the command line:
$ helmsman secret set --app billing-api --name STRIPE_KEY --from-file ./stripe.key
Stored (AES-256-GCM, 41 B). Literal lint: OK.

# From stdin in a provisioning script (still never in argv):
$ printf '%s' "$GENERATED" | helmsman secret set --app billing-api --name HMAC_SIGNING --stdin
Stored (AES-256-GCM, 64 B).
```

---

## End-to-end: a full CLI-first deploy (never opening the dashboard)

This is the canonical workflow for an operator who lives in the terminal. **You never open the dashboard.**

**1. Author and commit your declarations in the repo.** Both files live with your code; `helmsman.yaml` references secrets by name and is safe to commit publicly.

```console
# In your app repo, on your workstation:
$ helmsman init --from-compose docker-compose.yml --slug billing-api   # scaffold (or hand-write)
$ git add helmsman.yaml docker-compose.yml
$ git commit -m "Add Helmsman definition + compose"
$ git push
```

**2. On the host, over SSH, provide the secret values out-of-band.** Values never touch `argv`, never go in the committed file.

```console
$ ssh operator@host
host$ helmsman secret set --app billing-api --name DB_PASSWORD          # prompts on /dev/tty
host$ printf '%s' "$STRIPE" | helmsman secret set --app billing-api --name STRIPE_KEY --stdin
host$ helmsman secret list --app billing-api                            # confirm all provisioned
```

**3. Validate → plan → apply** (read-plane checks first, then the one gated write).

```console
host$ helmsman fetch    --app billing-api               # read-plane: advance staged ref
host$ helmsman validate -f helmsman.yaml                # full §5.6 + edge gate + secret lint
host$ helmsman plan     -f helmsman.yaml                # exactly what apply will change (masked)
host$ helmsman apply    -f helmsman.yaml                # the one gated write: reconcile to declared
```

`apply` resolves the compose, runs the chokepoint, deploys in dependency order, and renders the edge route **last** behind the atomic-apply + negative-from-internet probe. On any step failure it auto-rolls the whole app back to the prior `def_version`.

**4. Observe and operate — still in the terminal.**

```console
host$ helmsman status --app billing-api                 # live-vs-declared drift, cert, update state
host$ helmsman logs   --app billing-api --service api -f # tail logs
```

**5. Ship the next commit when CI has built the image.** A push only *fetches*; **you** decide when to deploy, pinning the exact reviewed sha.

```console
host$ helmsman fetch  --app billing-api                                 # "2 commits behind"
host$ helmsman deploy --app billing-api --sha 9d20e7c1f0a4b3e8d5c6a7... # sha-pinned manual promote
```

At no point did you open the dashboard, and at no point did any of these commands bypass a single compose, edge, or secret invariant — they are the same reconciler, driven from the terminal.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (including an idempotent no-op `apply`/`plan` with an empty diff). |
| `1` | **Validation rejection** — the §5.6 validator, §6.2 edge gate, or secret lint refused the input. The error is line-anchored at the offending path. |
| `2` | **Gate deferral** — the §0 resource gate, the one-docker-child semaphore, or the memory-headroom floor was not satisfied; nothing was changed. Retry on a larger host or when load subsides. |
| `3` | **Conflict / re-review required** — e.g. `staged` moved since you reviewed a `--sha`, a def 3-way `def_conflict`, or a posture-widening rollback without `--ack-widen`. |
| `4` | **Config / root-of-trust error** — a key/DB mismatch (`verify-key`), insecure config perms, or a fail-closed boot precondition. |
| `>0` (other) | Unexpected error; the operation auto-rolled back where applicable (no partial apply). |

> **Reminder:** if anything ever wedges the edge, the recovery floor is always one SSH command away — `helmsman edge restore-default` — and a known-good definition is always one away with `helmsman apply --from <path>`. SSH is the ultimate recovery floor.
---

## Day-2 & integration commands (§16 / §17)

### Backup & restore ([backup-and-recovery.md](./backup-and-recovery.md))

| Command | Plane | Notes |
|---|---|---|
| `backup plan --app <slug>` | read | enumerate volumes (from the typed model) + resolve recipes + check destinations |
| `backup list --app <slug>` | read | inventory: artifacts, sizes, `key_id`, verify state |
| `backup verify --app <slug> --run <id>` | read | streaming decrypt + MAC + SHA check — catches the master-key footgun *before* a restore |
| `backup now --app <slug> [--volumes-only\|--recipes-only] [--dest local\|s3\|all]` | write (gated) | one volume/recipe at a time under §0 + semaphore + mem floor |
| `backup now … --no-encrypt` | write (SSH only) | loud ack; **local-only, never offsite/retained**, refused for secret-bearing volumes |
| `backup restore --app <slug> --run <id>` | gated-destructive | prints the plan + the bound operation tuple |
| `backup restore … --confirm <token>` | gated-destructive | single-use token bound to the **full tuple**; quiesce → fresh volume → swap → health → auto-rollback |

### Disk

| Command | Plane | Notes |
|---|---|---|
| `disk reclaim [--images] [--build-cache] [--volume <name> --confirm <token>] [--dry-run]` | write (gated) | runs the denylist server-side (atomic with the prune); `--dry-run` prints what would be removed **and** what the denylist protected and why |

### Scoped API tokens ([security.md](./security.md))

| Command | Plane | Notes |
|---|---|---|
| `token mint --name <l> --scope <s>[,…] --ttl <d> [--token-allowlist <cidr>…] [--rate <rps>:<burst>]` | root-of-trust (SSH) | secret printed **once**; only the hash persists. No web mint. |
| `token list` / `token revoke <id>` / `token rotate <id>` | root-of-trust (SSH) | metadata only; revoke is honored within one tick; rotate grace-windows the old token |

Tokens authenticate the read-mostly **`/api/v1`** JSON API (bearer-only, cookie-rejecting). A token is
*less* privileged than a browser session, its scope has **no Tier-1 symbol**, and it **still passes the
IP allowlist** — the only relaxation is a per-token SSH-minted CIDR set, matched on the unspoofable peer.

### Lifecycle (root-of-trust, SSH only)

| Command | Notes |
|---|---|
| `self-upgrade --to <path-or-channel>` | verify signed digest → candidate `--self-check` (incl. the docker/compose preflight) → DB snapshot → transactional migration → atomic binary swap → optional edge child-Caddy bump; deterministic auto-recovering abort. No web route/API scope. |
| `backup-self [--with-volumes]` | own-state bundle: Tier-1 config+key **offsite-separate** from the DB; HMAC-signed with the distinct `backup_hmac_key` |
| `restore-self --config <ref> --db <ref> --defs <ref> [--volumes <ref>] [--dry-run]` | strict config → verify-bundle → DB → `verify-key` → defs(§5.6) → reconcile → volumes; `--dry-run` rehearses the whole chain |
| `verify-backup <bundle>` | integrity + manifest check, no restore (rehearsal/monitoring) |
