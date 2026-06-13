# Config Files & Secrets

Helmsman manages three distinct kinds of configuration input for an app, plus a strict **secret-by-reference** model that keeps plaintext credentials out of your YAML, your repo, your logs, and your browser. This document explains all three kinds, when to reach for each, how selective host-side templating works (and why it is *not* `envsubst`), and how secrets are provisioned, stored, and previewed.

> If you are coming from a hand-rolled `docker-entrypoint.sh` that `sed`s a config file, bootstraps a credential, and waits for a cert, the [Replacing a bespoke entrypoint](#replacing-a-bespoke-entrypoint-declaratively) section is the fast path — those three imperative jobs become three declarative lines.

**See also:** [README](../README.md) · [Provisioning apps](./gitops.md) · [Managed edge & certs](./edge-and-tls.md) · [The `helmsman.yaml` definition file](./definition-file.md) · [Compose validation](./security.md)

---

## The three kinds of config input

Conflating env vars with file-mounted secrets is a classic footgun, and a templated config file is a *third* thing again. Helmsman treats them as three separate kinds with different storage, different rendering behavior, and different hygiene rules.

| Kind | Holds | Helmsman renders it? | At rest | Mounted as |
|---|---|---|---|---|
| **env** | `KEY=value` pairs | No | Encrypted `env_blob` | `0600 --env-file` |
| **file-mounted secret** | An opaque file (a `.pem`, a keystore, a license blob) | No — Helmsman never reads its contents | Out-of-band on the host; Helmsman keeps a stat-only panel | A bind mount you declare |
| **managed config file** | A **structured template** (config with placeholders) | **Yes — host-side, before `up`** | The template is encrypted *iff* it is secret-bearing | Read-only bind mount, `0640`/`0600` |

### When to use each

**Use an env var when** the value is a flat `KEY=value` that the app already reads from the environment. This is the cheapest, most portable kind. The value lands in an encrypted `env_blob` and is materialized as a `0600 --env-file` at deploy time — it never gets baked into your compose YAML. Non-secret literals and `secret:` references can both live here.

**Use a file-mounted secret when** the app wants an opaque file it will read itself — a TLS keystore, a service-account JSON, a downloaded license — and Helmsman has no business parsing or templating it. Helmsman **never reads the file's contents**; it only stats it for a read-only panel (path, mode, size, mtime). You place the file on the host out-of-band and declare the bind mount. Use this when the payload is binary, large, or simply none of the dashboard's concern.

**Use a managed config file when** the app ships a *structured* config that has deploy-time placeholders Helmsman should fill — a node cookie, a shared auth secret, an internal webhook URL, a dashboard password, the public hostname, the TLS cert paths — **mixed with the app's own runtime placeholders** (`${username}`, `${clientid}`, `${topic}`) that must pass through untouched. This is the kind that replaces a bespoke entrypoint. Helmsman renders it host-side, before `docker compose up`, and bind-mounts the result read-only.

> A managed config file's template is encrypted at rest only when it is **secret-bearing** (when at least one binding resolves a `secret:`). A purely structural template (hostnames, cert paths, internal URLs) is stored unencrypted but still rendered with the same hygiene rules below.

---

## Selective host-side templating

The crux of managed config files — and the thing that makes them safe to drop into a config full of the app's *own* placeholder syntax — is that Helmsman performs **selective** templating, **never a blanket `envsubst`**.

### Helmsman touches only its own namespaced delimiter

The renderer recognizes exactly one family of delimiters:

| Delimiter | Resolves to |
|---|---|
| `{{hm.<key>}}` | A value from this file's `bindings[]` allowlist |
| `{{hm.cert.<binding>.crt}}` / `.key` / `.ca` | A cert path synced by a cert binding (see [Cert bindings](#cert-bindings-edge-cert--app)) |
| `{{hm.file.<name>}}` | The path of another managed file for this app |

**Everything else is data and is copied byte-identical.** The app's `${...}`, `$VAR`, `%(...)s` (Python-style), Go `{{ }}`, and even a near-miss like `{{hmFoo}}` (no dot after `hm`) are all left exactly as written. Your `${username}` survives byte-for-byte.

### It is a single-pass byte scanner, not a template engine

This is a deliberate, load-bearing design choice. The renderer is a **single-pass byte scanner** that matches the literal pattern `{{hm.<key>}}` and nothing more. It is **not** a template engine:

- No conditionals, loops, or functions.
- No shell, no `exec`, no arbitrary evaluation.
- No second pass — see [output is never re-scanned](#rendered-value-hygiene) below.

Because it never runs a general template engine over your file, an attacker who controls part of the config body cannot smuggle in logic, and the app's own template directives can never be misinterpreted as Helmsman's.

> **Why not just `envsubst`?** A blanket substitution would happily eat the app's `${username}` and `${clientid}` placeholders, corrupting the config. The single-pass `{{hm.*}}` scanner is the honest trade-off: Helmsman gives up the convenience of "substitute everything" in exchange for never touching a byte it wasn't explicitly told to.

### The per-file `bindings[]` allowlist

A `{{hm.X}}` resolves **only if `X` is in that file's explicit `bindings[]` allowlist.** There is no implicit lookup against the environment or the secret store. An unknown, duplicate, or malformed `{{hm.*}}` is a **hard error at save time *and* again at render time** — fail-closed, **never** silently substituted with an empty string. A missing `secret:` or `env:` key at render time is a **hard deploy failure**, not an empty value.

This double check (save *and* render) means a template that passed review can't later resolve to nothing because a binding was removed.

---

## The typed resolver

Each binding names a typed source. There are exactly four resolver prefixes — there is no "free text" source:

| Prefix | Resolves to | Notes |
|---|---|---|
| `env:<KEY>` | A value from the app's env blob | |
| `secret:<KEY>` | A value from the **encrypted store**, decrypted in-memory only | Any `secret:` binding marks the whole file **secret-bearing** |
| `cert:<binding>` | The cert-sync'd path for a cert binding | See [Cert bindings](#cert-bindings-edge-cert--app) |
| `app:<field>` | A value from a **fixed safe set** | Not free text — see below |

The `app:<field>` source is restricted to a small fixed set of values Helmsman can vouch for:

- `app:public_hostname` — taken from the **validated route row**, not free text.
- the app's internal upstream URL,
- the app slug.

Because `app:` cannot resolve arbitrary strings, a config template can't be used to inject an attacker-chosen value through the `app:` channel.

---

## Rendered-value hygiene

A resolved value — especially a `secret:` — is treated as **hostile data**, because a credential could contain bytes that would corrupt or extend the config. The renderer enforces the following, and these rules are also re-asserted by the [compose validation chokepoint](./security.md) when the materialized file and its bind mount are validated.

### NUL and CR/LF are rejected — regardless of declared format

- **NUL is always rejected.**
- **CR and LF are rejected in every resolved value, regardless of the operator-declared `format`.**

The reason for the second rule is subtle and important: a secret with an embedded newline could otherwise inject a *second* config line inside the container (e.g. turning `password = {{hm.secret:PW}}` into a password line *plus* an attacker-controlled directive). Helmsman **never trusts an attacker-influenced `format` hint for a security decision** — even if you declare the file's format as something that "allows" newlines, a resolved value still may not carry one.

### Output is never re-scanned

Once a value is emitted, it is **not scanned again.** A secret whose plaintext happens to contain the literal text `{{hm.X}}` can therefore **never trigger a second resolution pass**. There is exactly one pass: scan the template, emit resolved values, done.

### File permissions default to least-privilege

| Condition | Mode |
|---|---|
| Default (non-secret-bearing) | `0640` |
| Secret-bearing (any `secret:` binding) | `0600` |

Rendered files are **never `0644`**. This means that if an operator wrongly pastes a credential as a *literal* into a file that Helmsman doesn't know is secret-bearing, the file is still not world-readable. Files are written atomically: a `.tmp` write, then `fchmod`/`fchown`, then a `rename(2)` into place — so a partially written or wrong-mode file never exists at the final path.

### The literal-secret lint

At save time, a lint scans non-secret-bearing bodies and **hard-rejects** material that looks like a pasted credential — PEM blocks, key material, and long base64 literals. The error directs you to the right tool:

> Use a `{{hm.secret:KEY}}` binding instead of pasting the secret literally.

This catches the most common mistake (pasting a key directly into the template) before it can ever be rendered or mounted. The same literal lint runs over **every value** you provision through `helmsman secret set`, the dashboard, or the definition file — a pasted PEM is rejected there too.

### Lifecycle: re-rendered every deploy, drift detected

- Materialization happens **in the compose-validation chokepoint, before `up`, host-side**: resolve every binding → render → write atomically → record `rendered_sha256` → bind-mount read-only.
- Files are **re-rendered on every redeploy**, so there is no stale drift from an old render.
- A host hand-edit is **detected** by SHA mismatch and surfaced as *"host-edited, will be overwritten."* Detection only — Helmsman **never** auto-merges a hand edit and **never** executes it.
- A secret-bearing rendered file joins the read-only file-secret panel and **can never become an edge cert** — managed config output and edge PKI material are kept strictly separate.

---

## Cert bindings (edge cert → app)

When [Helmsman owns the edge](./edge-and-tls.md), it is the ACME agent for your hostnames. A **cert binding** wires an edge-managed cert to an app declaratively, so the app's config and the files on disk always agree.

How it works:

1. The edge issues/renews the cert for a hostname that matches one of the app's routes.
2. The **cert-sync helper** copies the leaf cert + key to a per-consumer `0600` path under the app's run directory. It **never** chmod-broadens the proxy's own keys and **never** mounts the proxy data directory into the app.
3. `{{hm.cert.<binding>.crt}}` / `.key` / `.ca` inject those **synced** paths into the app's config.

If you set `required: true`, the binding becomes a **hard ordering gate**: `docker compose up` of the consumer is blocked until the synced cert files exist. The container never has to poll or wait for a cert. If the cert can't issue, the deploy **fails fast with a reason** instead of leaving a container in a spin-loop. On renewal, the helper re-copies the files and signals the consumer via static argv.

---

## Replacing a bespoke entrypoint, declaratively

The classic "templated config + custom entrypoint" pattern bundles three imperative jobs into a shell script. Helmsman dissolves all three into declarative config, and the container reverts to its upstream default command.

| Imperative job (old entrypoint) | Declarative replacement |
|---|---|
| Targeted `sed` to fill placeholders | **Host-side `{{hm.*}}` templating** — the container's command goes back to the image default |
| A credential bootstrap (write a secret into a file before start) | A **`kind: bootstrap` config file** bound from a `secret:` resolver |
| A cert-wait loop (`until [ -f cert.pem ]; do sleep …`) | A **cert binding** with `required: true` — a hard ordering gate blocks `up` until the cert exists; no polling, fail-fast if it can't issue |

The win is not just fewer lines of shell. Each of these jobs moves *out* of the (attacker-reachable, hard-to-audit) container entrypoint and *into* a typed, validated, host-side step that the compose-validation chokepoint can reason about.

---

## The secret model

### Secret-by-reference is an invariant

Helmsman's master rule for secrets: **they are always by reference, never by value, in any authoring surface.**

- A `helmsman.yaml` definition file **declares secret names** (and an optional `generate` hint) — **never values.** Because the file is never secret-bearing, its `canonical.yaml` is `0640` and is **safe to commit to a public repo.**
- env entries, `config_files.bindings[secret]`, `cert:` bindings, and an `ops_interface.secret` are all *references* into the store.
- The actual secret value arrives **only out-of-band** (see provisioning below) and lands in the encrypted store.

### Per-`(slug, name)` namespace — no cross-app reads

Every secret reference resolves **only within the referencing app's own `(slug, name)` namespace.** A name owned by another app resolves as **missing / fail-closed, with zero disclosure** — there is no error that leaks the other app's secret's existence or value. This is what makes it safe to commit a definition file: a `secret: SHARED_KEY` reference in app A's committed file can never read app B's `SHARED_KEY`.

### Provisioning: `helmsman secret set` (never argv)

Values are set out-of-band through one of:

- **`helmsman secret set`** — reads the value from **stdin**, `/dev/tty`, or `--from-file`. **Never from `argv`** (so the secret can't land in your shell history, `ps` output, or process listings).
- The **dashboard secret panel**.
- The **SSH-edited root-owned config**.

A `generate` hint (declared in `spec.secrets`) mints a value with a **hard per-type entropy floor**, only on **explicit operator action**, and **never overwrites an already-provisioned secret.**

```bash
# Set a secret from stdin (value never appears in argv or history)
printf '%s' "$NODE_COOKIE" | helmsman secret set my-app NODE_COOKIE

# Or from a file
helmsman secret set my-app TLS_PASSPHRASE --from-file ./passphrase.txt

# List names (never values)
helmsman secret list my-app
```

> **Anti-pattern:** `helmsman secret set my-app NODE_COOKIE "$NODE_COOKIE"` is **not** supported — passing a value as an argument is exactly the leak vector the stdin/`--from-file` interface exists to prevent.

### The encrypted store

Secrets, env blobs, git credentials, ops secrets, and webhook/channel secrets are all encrypted with **AES-256-GCM** under an `encryption_key`. That key lives **only in the SSH-edited, root-owned config file** — never in the database, logs, or UI.

- A dedicated `Redacted` type makes secrets unprintable: its `String()` and `MarshalJSON` return `••••`, so a secret can't accidentally serialize into a log line, an error, `ps` output, or a temp file.
- Key rotation is supported via `encryption_key_previous`.
- **Back up the config (which holds the key) and the database separately and offsite.** Losing the key bricks every ciphertext — there is no recovery path.

> **Honest trade-off — Reveal-on-click.** The dashboard *can* reveal a secret's plaintext on click. It does so over a `POST → text/plain` response with `Cache-Control: no-store`, audited, scoped to the current session, and **never** swapped in via `innerHTML`. Stated plainly: this **does put plaintext into the operator's browser** for that moment. It's a convenience that exists because operators sometimes genuinely need the value, but it is the one place a secret byte intentionally crosses into the UI. Everywhere else — previews, diffs, definition files — secrets stay masked.

### Drift detection

You can ask Helmsman where the live state diverges from what's declared:

- `helmsman status` shows **live-vs-declared drift** for an app.
- For managed config files specifically, every render records a `rendered_sha256`; a host hand-edit is surfaced as *"host-edited, will be overwritten"* (detection only — never an auto-merge).
- `helmsman plan` / `diff` shows the pending change set (masked, computed in-memory) before you apply.

### The masked preview

The config-file preview lets you verify a template **without leaking a single secret byte to the browser.** A `secret:` binding renders as a **masked placeholder** that shows its name and byte length but not its value:

```
‹secret:NODE_COOKIE (32 B)›
```

This is enough to confirm two things at a glance:

1. The **structure** is right — the secret lands where you expect.
2. The app's own `${...}` placeholders **survived** the render untouched.

The same masking applies in `helmsman plan`/`diff` and in the GitOps diff preview — secrets are masked everywhere except the explicit, audited reveal-on-click above.

---

## Worked example: templating a broker config

Suppose your message broker ships this config template, with a mix of values Helmsman should fill and values the app resolves itself at runtime:

**`broker.conf` (template):**

```ini
# --- Helmsman fills these at deploy time (host-side) ---
node.cookie            = {{hm.secret:NODE_COOKIE}}
management.password    = {{hm.secret:DASH_PASSWORD}}
cluster.public_host    = {{hm.app.public_hostname}}
listeners.ssl.certfile = {{hm.cert.broker_edge.crt}}
listeners.ssl.keyfile  = {{hm.cert.broker_edge.key}}

# --- The app's OWN runtime placeholders — copied byte-identical ---
default_user           = ${username}
default_pass           = ${password}
default_vhost          = ${vhost}
mqtt.client_id_prefix  = ${clientid}
log.console.level      = %(LOG_LEVEL)s
```

### Which lines become `{{hm.*}}`, and why

| Line | Treatment | Reason |
|---|---|---|
| `node.cookie` | `{{hm.secret:NODE_COOKIE}}` | A real credential — resolve from the encrypted store; marks the file secret-bearing |
| `management.password` | `{{hm.secret:DASH_PASSWORD}}` | Same — a secret reference |
| `cluster.public_host` | `{{hm.app.public_hostname}}` | The validated public hostname from the app's route row (safe `app:` field) |
| `listeners.ssl.certfile` / `keyfile` | `{{hm.cert.broker_edge.crt}}` / `.key` | The edge-issued cert, synced to a per-consumer `0600` path |
| `${username}` / `${password}` / `${vhost}` / `${clientid}` | **Left byte-identical** | The app's own runtime interpolation — **not** Helmsman's `{{hm.*}}` namespace |
| `%(LOG_LEVEL)s` | **Left byte-identical** | Python-style interpolation the app resolves itself |

### The binding allowlist for this file

Each `{{hm.*}}` must be declared in this file's `bindings[]`. A `{{hm.*}}` not in this list is a hard error at save and at render:

```yaml
config_files:
  - path: ./broker.conf          # confined under the app's run_dir
    template_ref: ./broker.conf.tmpl
    bindings:
      NODE_COOKIE:   { from: "secret:NODE_COOKIE" }
      DASH_PASSWORD: { from: "secret:DASH_PASSWORD" }
    # app:public_hostname and cert:broker_edge resolve via their typed prefixes
cert_bindings:
  - name: broker_edge
    hostname: broker.example.com   # must match one of the app's routes
    required: true                 # blocks `up` until the cert is synced
secrets:
  - name: NODE_COOKIE
    generate: { type: hex, bytes: 32 }   # minted on explicit action, entropy-floored
  - name: DASH_PASSWORD                   # provisioned out-of-band via `helmsman secret set`
```

### The masked preview you'd see

```ini
node.cookie            = ‹secret:NODE_COOKIE (32 B)›
management.password    = ‹secret:DASH_PASSWORD (24 B)›
cluster.public_host    = broker.example.com
listeners.ssl.certfile = /var/lib/helmsman/apps/broker/certs/broker_edge.crt
listeners.ssl.keyfile  = /var/lib/helmsman/apps/broker/certs/broker_edge.key

default_user           = ${username}
default_pass           = ${password}
default_vhost          = ${vhost}
mqtt.client_id_prefix  = ${clientid}
log.console.level      = %(LOG_LEVEL)s
```

Confirm two things from this preview:

1. Both secrets are **masked** (name + byte length, no value) — no secret byte reached your browser.
2. Every `${...}` and `%(...)s` line is **byte-identical** to the template — Helmsman touched only its own `{{hm.*}}` lines.

### What happens at deploy

1. In the compose-validation chokepoint, **before `up`**, Helmsman resolves each binding. `cert_bindings.broker_edge` has `required: true`, so the cert-sync ordering gate holds the broker's `up` until `broker_edge.crt`/`.key` are present (fail-fast with a reason if the cert can't issue).
2. Each resolved value is checked for NUL (always rejected) and CR/LF (rejected regardless of declared format).
3. `broker.conf` is rendered in a single pass, written atomically as `0600` (secret-bearing — it has `secret:` bindings), and bind-mounted **read-only**.
4. `rendered_sha256` is recorded. On the next deploy the file is re-rendered; a host hand-edit in between is reported as *"host-edited, will be overwritten."*

If `NODE_COOKIE` had not been provisioned, the deploy would **fail closed** at materialization — never render an empty cookie.

---

## Quick reference

| You want to… | Use |
|---|---|
| Pass a flat `KEY=value` the app reads from the env | **env** entry (literal or `secret:` ref) |
| Hand the app an opaque file Helmsman shouldn't read | **file-mounted secret** (stat-only panel) |
| Fill placeholders in a structured config, keeping the app's own `${...}` | **managed config file** + `{{hm.*}}` bindings |
| Reference a credential without ever writing its value | a `secret:` binding + `helmsman secret set` |
| Give an app an edge-issued TLS cert | a **cert binding** + `{{hm.cert.<binding>.crt|key}}` |
| Replace a `sed`/bootstrap/cert-wait entrypoint | templating + `kind: bootstrap` + `required: true` cert binding |
| Verify a template without leaking secrets | the **masked preview** / `helmsman plan` |
| See where live state diverges from declared | `helmsman status` (drift) |