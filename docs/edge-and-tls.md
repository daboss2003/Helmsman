# Edge & TLS — the managed edge

Helmsman is internet-facing by default. Every install owns the public ports `:80`/`:443`,
runs ACME/Let's Encrypt for you, terminates TLS, and reverse-proxies the admin UI and each of
your apps. You never stand up a separate proxy, hand-write TLS config, or run `certbot`.

This document explains how that edge works, why it is built the way it is, and how to drive it
safely — including the trade-offs that were made deliberately and what backstops protect you
when a configuration mistake slips through.

> **One-line summary.** From a single required field per app — a hostname — Helmsman derives a
> complete, hardened HTTPS vhost. The admin UI stays on loopback. A supervised, sandboxed child
> Caddy does the public-facing work in its own user, cgroup, and memory-capped slice. What Caddy
> actually runs is always Helmsman's typed render of a protected base plus your routes plus an
> additive overlay — never a config you pasted, loaded verbatim.

**See also:** [README](../README.md) · [Security model](./security.md) ·
[App provisioning](./gitops.md) · [Configuration reference](./architecture.md) ·
[Alerting & self-healing](./alerting.md)

---

## Table of contents

- [Edge modes: `managed` vs `external`](#edge-modes-managed-vs-external)
- [How the edge is owned (process isolation)](#how-the-edge-is-owned-process-isolation)
- [Automatic HTTPS / ACME](#automatic-https--acme)
- [Per-app reverse proxy: routes & upstreams](#per-app-reverse-proxy-routes--upstreams)
- [The three-layer config model](#the-three-layer-config-model)
- [Settings → Caddy: the read-and-render editor](#settings--caddy-the-read-and-render-editor)
- [Fail-to-save on conflict](#fail-to-save-on-conflict)
- [The secure-by-default baseline (SBD-1..8)](#the-secure-by-default-baseline-sbd-18)
- [Non-HTTP services: cert-only / shared-cert](#non-http-services-cert-only--shared-cert)
- [The raw-config caveat — why a linter is not enough](#the-raw-config-caveat--why-a-linter-is-not-enough)
- [Recovery & escape hatches](#recovery--escape-hatches)
- [Configuration reference](#configuration-reference)

---

## Edge modes: `managed` vs `external`

There is exactly **one** config key that decides who owns the edge:

```yaml
edge:
  mode: managed   # "managed" (default) | "external" (advanced escape hatch)
```

There is **no auto-detection**. The choice is explicit and **fail-closed** — if the prerequisites
for the chosen mode are missing, Helmsman refuses to come up rather than guess.

### `managed` (default — the product)

This is the path you get by doing nothing. Helmsman **owns the edge**:

- It supervises a child Caddy that binds the public ports `:80`/`:443`.
- The child runs ACME/Let's Encrypt and terminates TLS.
- The child reverse-proxies the admin vhost to `127.0.0.1:9000` (behind an injected IP-allowlist
  matcher) and each app vhost to its allowlisted internal upstream.
- The admin UI **still** binds loopback `127.0.0.1:9000`. Only the *child* binds public ports.

The operator never stands up a proxy, writes TLS config, or runs certbot. Required config:

| Key | Meaning | If missing |
|---|---|---|
| `edge.acme_email` | Contact for the ACME account | **Fail-closed.** Onboarding refuses to mark setup "complete" and prints the exact CLI line to set it. |
| `edge.acme_ca` | The single, pinned ACME issuer | No fallback issuer is ever used (see [ACME](#automatic-https--acme)). |
| `edge.apply_probe_window` | Health-probe window after an apply | Defaults to `20s`. |
| `caddy_editor.mode` | `strict` or `review` for the raw editor | Defaults to `strict`. |

### `external` (narrow advanced escape hatch)

For an operator who insists on fronting Helmsman with their **own** existing proxy. This is a
deliberate, narrow escape hatch — not an off-switch and not a casual setting.

- **Config-file-only, NOT UI-reachable.** You cannot click your way into `external`; you fall
  into `managed` by doing nothing. Setting `external` is always a deliberate operator act.
- In `external` mode Helmsman **binds loopback only**, never opens `:80`/`:443`, never constructs
  the edge subsystem, and **never grants `CAP_NET_BIND_SERVICE`**.
- The Settings → Caddy editor and the per-app TLS controls are **hidden** — there is no managed
  edge to edit.
- Helmsman emits paste-ready proxy snippets for your front proxy but **applies nothing**.

**Fail-closed boot is stronger here** (this is the most-abused trust seam — the XFF/trusted-proxy
boundary). Helmsman refuses to start in `external` mode unless:

1. `trusted_proxies` is a **specific edge IP** — a prefix no wider than `/24`, and not a Docker
   bridge CIDR; **and**
2. a boot probe confirms `:9000` is **unreachable from a non-loopback interface**.

The emitted snippet bakes in **XFF overwrite** (not append) — an external proxy that *appends*
`X-Forwarded-For` silently breaks the IP allowlist, so Helmsman forces an overwrite. "The operator
chose external" never absolves the allowlist / XFF safety checks.

### Resource behavior: a warning, not a silent mode-switch

On an undersized box the default **stays `managed`** — the edge runs in its own memory-capped slice
with a persistent banner: *"reduced MemoryMax — consider a larger host."* Only a box that
**genuinely cannot** host the child boots `external`, and then it shows a blocking banner:
*"edge not owned — resource gate."* Helmsman never silently degrades you into `external`; choosing it
is always deliberate. (The heavier *write plane* — deploy/build — is separately gated at ≥ 1 GB RAM;
the edge itself is part of the baseline and always serves its minimum-safe config.)

---

## How the edge is owned (process isolation)

The single most load-bearing decision in the edge design: **the TLS terminator runs as a separate,
Helmsman-supervised OS process — a stock Caddy binary — not embedded in-process.**

Helmsman drives the child entirely through Caddy's **admin API on loopback** (preferably a unix
socket), pushing a **full-document JSON config** with a graceful, atomic `/load`. There is no
on-disk config file the proxy auto-loads — **the admin API is the single source of truth.**

### Why a separate process

| Property | What it buys you |
|---|---|
| **Blast radius** | The public-facing HTTP/TLS/ACME/x509 stack parses hostile SNI and traffic in a *different* process, user, and cgroup — not the address space that holds your session secrets and master key. |
| **OOM accounting** | The child gets its own systemd **slice** with its own `MemoryMax` (~96–128 MB). A public-plane traffic spike cannot OOM the control plane. |
| **"Single binary" survives** | Helmsman stays ~12–18 MB. You patch the proxy by swapping one static file and doing a graceful reload — no rebuild of Helmsman. |
| **Crash isolation** | Helmsman supervises with backoff. If the child dies, the admin UI stays up to show you *why*. If Helmsman dies, the child keeps serving. |

### Supervision & capabilities

- The child runs under a **dedicated low-privilege user in its own slice**.
- **`CAP_NET_BIND_SERVICE` is granted to the child only** — never to the Helmsman process, and
  never in `external` mode. That single capability is what lets an unprivileged process bind `:80`
  and `:443`; nothing else in the system needs to be root for the edge to work.
- Helmsman talks to the child over loopback `:2019` (or, preferably, a unix socket) **only**.
- A liveness poll plus crash-loop detection raises a `level=security` audit event.

### Supply-chain hardening of the child binary

The child proxy binary is **root-owned, mode `0755`, on a read-only mount, digest-pinned, and
verified before launch** (Helmsman refuses to start it on a digest mismatch). Its path and data dir
are in the bind-mount **deny set**, so no deploy can overwrite them. The edge runs on **its own
Docker network** that the app network cannot reach — so an in-container ACME client cannot answer
challenges for edge hostnames or reach `:2019` — and `ProtectSystem=strict` keeps the cert/data dir
and Helmsman's own config/key **out of the edge's mount namespace entirely**, so a stray
`file_server` cannot browse them.

---

## Automatic HTTPS / ACME

In `managed` mode every app vhost automatically gets: an ACME-issued certificate, an HTTP→HTTPS
redirect, a reverse-proxy with **`X-Forwarded-For` overwritten to the real TCP peer**, and an edge
header bundle (HSTS is added only *after* a certificate exists). You set a hostname; Helmsman does
the rest.

The ACME behavior is deliberately conservative, because each loose default is a real outage or
abuse class:

- **A single pinned ACME CA, no silent fallback.** `edge.acme_ca` names one issuer and Helmsman
  never falls back to another. A fallback would land certs at a *different* on-disk path and silently
  break shared-volume cert readers — a real outage class.
- **On-demand TLS is OFF by default.** Only hostnames present in your routes get certificates. A
  hostile SNI cannot make Helmsman request arbitrary certs and burn through rate limits. (If
  on-demand is ever enabled via the editor, the renderer **force-rewrites** the `ask` endpoint to a
  fixed Helmsman loopback validator that answers "yes" only for known route/allowlist hostnames,
  plus a rate limit.)
- **Resolves-to-this-box check at issuance.** Helmsman validates that a hostname resolves to this
  box **at issuance time**, not merely when you added the route. A name that no longer points here
  will not silently keep trying.
- **Key custody.** Certificate private keys stay in the proxy's data dir, owned by the proxy user,
  mode `0600`. Helmsman does **not** read HTTP-vhost private keys.

---

## Per-app reverse proxy: routes & upstreams

Routes are stored declaratively in Helmsman's database and reconciled idempotently. The schema is
additive:

```text
app_routes(
  id, app_id, hostname, upstream, upstream_scheme,
  path_prefix, redirect_http, hsts, security_headers, enabled, …,
  UNIQUE(hostname, path_prefix)
)
```

**Reconciliation is declarative and whole-document.** Helmsman holds the desired set in SQLite,
renders the **entire** proxy JSON, and POSTs the whole document to the admin API. It never sends
incremental patches — a full re-render is far easier to keep bug-free.

### The structural backstops that keep the edge out of the control plane

These are not "nice to have." They are the runtime controls that actually stop a misconfigured or
compromised edge from reaching your secrets. Config validation is *necessary but not sufficient*
(see [the raw-config caveat](#the-raw-config-caveat--why-a-linter-is-not-enough)); these are what
make it safe.

- **Custom pinned dialer.** The edge dials every upstream through a dialer that **re-resolves and
  refuses, on every connection**, loopback (`127.0.0.0/8`, `::1`), link-local/metadata
  (`169.254.0.0/16`), and ports `9000`/`2019`/`2375`. The check is enforced on the **resolved
  target**, not the literal config string — so a DNS name (or a DNS-rebind) that points at a
  control-plane port is refused **at dial time**, not just at config time.
- **`upstream` is an allowlist** of discovered app container endpoints. The only loopback target the
  edge may proxy to is the admin vhost → `127.0.0.1:9000` route, which is identity-pinned and
  **never operator- or app-editable**.
- **Egress firewall — the real backstop.** The edge slice's `IPAddressDeny`/firewall makes
  `9000`/`2019`/`2375` and the cloud metadata endpoint **physically unreachable** from the edge. So
  even a config the linter missed, an edge RCE, or an SSRF **cannot** reach the control plane or the
  socket-proxy.
- **Caddy admin on a unix socket** (preferred) so there is no TCP `:2019` to proxy to at all, with
  `enforce_origin:true` and origins pinned to loopback.
- **Config is marshalled from typed structs.** Hostname/path/upstream are charset-validated first.
- **Pooled upstreams (auto-scaling).** An app vhost's upstream may be a *pool* of discovered replica
  endpoints. **Every pool member passes the same allowlist + pinned dialer + egress firewall** — a
  scaled-up replica that mis-resolves to a control-plane port is refused at dial. Pool membership is
  Helmsman-managed state, recomputed from read-only container discovery and re-rendered as the whole
  document.

### Example managed route

A typed route (Tab 1 of the editor; see below) for an HTTP app. You generally never write this by
hand — the structured UI builds it from a hostname and a discovered upstream — but here is what
Helmsman renders on your behalf:

```jsonc
// Layer 1 — one route per app vhost, rendered from app_routes
{
  "match": [{ "host": ["dashboard.example.com"] }],
  "handle": [{
    "handler": "reverse_proxy",
    "upstreams": [{ "dial": "10.89.0.7:8080" }],   // discovered, allowlisted, dialed via the pinned dialer
    "headers": {
      "request": {
        "set": { "X-Forwarded-For": ["{http.request.remote.host}"] }  // OVERWRITE, never append
      }
    }
  }]
}
// Automatic HTTPS (ACME), HTTP→HTTPS redirect, HSTS-after-cert,
// and the edge header bundle are all derived for you — not shown here.
```

---

## The three-layer config model

Everything Caddy runs is the composite of **three typed layers**, where the **highest layer wins in
authoring priority but has the lowest authority**. Higher-numbered layers may *add*; they may never
redefine, shadow, or weaken a lower layer.

| Layer | Source | Editable? | What it contains |
|---|---|---|---|
| **Layer 0 — protected base** | Helmsman code (typed structs) | **No** | The admin block (unix socket, `enforce_origin:true`); the identity-pinned admin→`:9000` route *with* its allowlist matcher; global TLS (pinned ACME CA + email, on-demand off); XFF-overwrite + header bundle; default unmatched-Host = 404/close. |
| **Layer 1 — routes** | `app_routes` (typed structs) | Via the Routes tab | One route per app vhost. |
| **Layer 2 — operator overlay** | Your raw text (Advanced tab) | Yes, **additive only** | Extra vhosts, headers, and matchers on **operator-owned hostnames**. |

Layer 2 is the only thing your raw input actually becomes. It is highest in authoring priority and
**lowest in authority**: it can *add*, never redefine/shadow Layers 0 or 1, and it may **not** speak
about `admin`, `apps.tls.automation`, or `apps.pki` at all. This is the operational meaning of SBD-7
and the SBD-8 recovery guarantee below.

**Minimum-safe protected base** (ships with every install, safe before any route exists): admin on
the unix socket; on-demand off; ACME only for route hostnames; one server on `[:443, :80]` (`:80` =
ACME + redirect only) with `routes:[]` and unmatched-Host = close/404; **no admin vhost unless you
set `admin.hostname`.** A fresh install is a public IP with HTTPS-capable Caddy that *proxies to
nothing and exposes no admin surface* until you add your first route. This base is Layer 0 of the
editor model and the recovery floor for SBD-8.

---

## Settings → Caddy: the read-and-render editor

The editor has **two tabs over one config**:

- **Tab 1 — Routes (default, safe).** The structured per-app route UI: typed structs, dropdown
  upstreams. 95% of operators never leave it.
- **Tab 2 — Advanced (raw).** Paste or edit raw Caddy config — **Caddyfile or JSON** — as an
  **additive overlay**.

> An app's templated config file (managed config files, see [App provisioning](./gitops.md))
> is a **completely different surface** and never mixes with the edge config.

### What "edit the Caddy config" actually means

This is the most important mental model on this page. **The config you paste is a declaration of
desired intent — never an artifact that is executed.**

Helmsman:

1. **Reads** your text,
2. **Parses** it into the same typed model its own renderer uses,
3. **Conflict-checks and validates** the parsed model, and
4. **Re-marshals** that model into the document Caddy loads.

The text is an *input format, never an execution path.* What Caddy runs is **always** Helmsman's
typed render of the composite (Layer 0 ⊕ 1 ⊕ 2). A stored paste is **never loaded verbatim** — every
apply and every restore *re-derives* from typed structs: Layer 0 from code, Layer 1 from the current
`app_routes`, Layer 2 by re-parsing your overlay as untrusted text. So your raw input reduces to
exactly the **Layer-2 additive overlay** — and that overlay can add, never redefine.

### Validation + apply pipeline (fail-closed)

Nothing touches the live proxy until steps 1–2 pass:

1. **Adapt + sandbox.** Caddyfile → JSON via `caddy adapt`, run **inside a network-off, FS-jailed
   sandbox** with `--environ` **stripped** and CWD set to a tmp dir containing only the snippet dir.
   The raw text is **pre-scanned for `import`** and any import outside the snippet dir is rejected
   *before* adapt (the file read happens during adapt). Then `caddy validate` plus a throwaway-Caddy
   dry-load — listeners remapped to ephemeral loopback, control-plane targets remapped to
   **blackhole sinks that fail loudly if dialed.**
2. **Invariant linter** on the parsed **composite** JSON. See [the reject list](#fail-to-save-on-conflict).
3. **Atomic apply + auto-rollback.** Snapshot the current live config (held by Helmsman, not read
   back from a possibly-broken instance) → `/load` the composite (atomic — a bad load leaves the old
   one running) → **health probe within `apply_probe_window`**. The probe includes:
   - a **negative from-internet test** — the admin vhost must return **403/404 from an
     un-allowlisted vantage**, proving the allowlist *blocks*, not just admits;
   - an assertion that **no live route's resolved upstream targets a control-plane port**;
   - an assertion of **no established edge → control-plane / metadata connection**.

   Any failure → **auto-rollback** + `level=security` audit. The operator cannot leave the edge down
   by walking away.
4. **Version history + recovery.** `edge_config_versions` stores all three layers **separately**.
   Restore **re-derives** (Layer 0 from code, Layer 1 from `app_routes`, Layer 2 from the stored
   overlay text *re-validated as untrusted*) — it **never loads a stored `composite_json`**. Version
   rows are HMAC-protected so a DB tamper cannot become a loaded config.

---

## Fail-to-save on conflict

If the pasted config **conflicts with anything Helmsman already manages, the save is rejected** — a
hard, typed error pointing at the offending path. It is **never silently merged or overridden.** This
gate sits **before** the rest of the pipeline (between parse and adapt).

A "conflict" is any construct that would change, shadow, redefine, weaken, or reach something
Helmsman owns. This is the **control-plane reject tier**, and `caddy_editor.mode: review` **cannot
soften it**:

| # | Rejected because it… | Examples |
|---|---|---|
| **1** | …shadows a managed hostname (after lowercase/trailing-dot/IDN canonicalization **and** wildcard-overlap simulation) | A route whose host matcher equals or shadows an app-route vhost (incl. an auto-scaled pool hostname), a cert-only hostname, the admin vhost, or a catch-all/wildcard. |
| **2** | …touches issuance or PKI you don't own | Any `admin` key; any `tls.automation` field (issuer/ca/email/account/on-demand), global *or* per-site; any `apps.pki` key. |
| **3** | …could reach the control plane | Any upstream resolving (at **lint and dial**) to loopback/metadata/`9000`/`2019`/`2375`; any placeholder (`{env.*}` / `{$…}`) in an upstream or admin field; a listener on `80`/`443`/`9000`/`2019`/`2375`. |
| **4** | …rewrites the trust seam | Any `header_up` on `X-Forwarded-For` / `X-Real-IP` / `Forwarded` (XFF is Layer-0-owned). |
| **5** | …executes or reads files it shouldn't | `exec` / `templates` / `respond {file.*}` / `file_server` under a sensitive dir; `import` outside the snippet dir. |

Additional linter REJECTs on the parsed composite (also control-plane tier, never downgradable):
any `on_demand.ask` that is not exactly the typed loopback validator (the renderer **force-rewrites**
it); a missing or non-`127.0.0.1:9000` admin route; the admin allowlist matcher absent, widened, or
**not structurally first**; any `events.exec` / process-spawn; file-read/template-execution
directives (`templates`, `respond {file.*}`, `php_fastcgi`); `file_server`/`root` under any sensitive
dir.

> **Pool membership changes at deploy time.** Because an app's pool membership and hostname candidacy
> can change when you deploy, the **full conflict check (including wildcard overlap) is re-run on
> every Layer-1 change.** A previously-valid wildcard overlay that now overlaps a newly-pooled
> hostname is **stripped fail-closed** — Layer 2 can never shadow a managed pool.

**Footgun-tier** rejects (not control-plane) *may* be downgraded to warn-and-acknowledge under
`caddy_editor.mode: review`. The control-plane tier above never is.

---

## The secure-by-default baseline (SBD-1..8)

Because the edge is always-on, "safe" no longer means *the operator configured it safely* — it means
*the shipped default is provably safe with zero operator action.* Each item is a hard invariant
enforced **in code** (typed structs + render-time checks) and **proven by a per-invariant automated
test on a fresh install.** These are **release-blocking** on the first edge-owning release.

| ID | Invariant | What it guarantees |
|---|---|---|
| **SBD-1** | Admin UI never reachable through the public edge by accident | Admin UI binds `127.0.0.1:9000` only. The edge serves **no admin vhost at all** unless you explicitly set `admin.hostname` (default: reach the UI via SSH tunnel / port-forward). If set, the admin vhost renders with the **IP allowlist as the first matcher, injected from typed config** (not operator text) → upstream `127.0.0.1:9000`. The allowlist cannot be omitted. |
| **SBD-2** | Caddy admin API never public | `admin.listen = unix//run/helmsman/caddy-admin.sock` (preferred) or `127.0.0.1:2019`, never routable; `enforce_origin:true`, origins loopback-only. No public vhost may proxy to `:2019`. |
| **SBD-3** | On-demand TLS off; ACME bounded | Absent from the base. If ever enabled via the editor, the renderer **force-rewrites the `ask` endpoint** to a fixed loopback validator that answers "yes" only for known route/allowlist hostnames, plus a rate limit. ACME issues only for configured app vhosts. |
| **SBD-4** | Only configured app vhosts served; control-plane ports unreachable as upstreams | Exactly the route-derived vhost set (+ optional admin vhost); **no catch-all/wildcard proxy**; no upstream targets `9000`/`2019`/`2375` or any internal port (struct-validated **and** re-checked at render **and** refused at dial); default unmatched-Host = `404`/close, never proxy. |
| **SBD-5** | Network isolation of edge from control plane | The structural backstop — pinned dialer + upstream allowlist + egress firewall + unix-socket admin (see [the backstops](#the-structural-backstops-that-keep-the-edge-out-of-the-control-plane)). |
| **SBD-6** | Egress allow-listing unchanged by always-on | Outbound ops calls stay host-pinned; edge egress is limited to the ACME CA / OCSP / CRL + pinned app hosts. |
| **SBD-7** | Config rendering safety | Proxy config is marshalled from typed structs (never string concat). Operator-pasted input is parsed into the **same typed model and re-marshalled** — paste is an *input format*, not an execution path. |
| **SBD-8** | The edge can never go down irrecoverably | Every apply is validate → stage → load with a retained last-known-good and an armed health-probe watchdog; on failure, **auto-revert**. The typed base config is always loadable as the recovery floor; **SSH is the ultimate recovery floor.** |

---

## Non-HTTP services: cert-only / shared-cert

The edge can be the **ACME agent for a hostname it does not serve traffic for** — for example, an
MQTT-over-TLS broker, where a separate service must terminate TLS itself on its own port. This is a
**per-route choice:**

### `cert-only` / shared-cert (recommended default)

The proxy obtains and renews the certificate for the hostname but serves **no traffic** on that
port. A separate service reads the same cert files and terminates TLS itself.

The hard rule: **never `chmod` the cert dir or keys to broaden access.** A different-uid reader, or a
container that mounts that path, could then read live TLS keys. Instead, Helmsman ships a built-in
**cert-sync helper** that:

- **Copies the leaf cert + key** to a per-consumer path that is **`0600` owned by the consumer uid**
  (or `0640` group-owned), under the consumer's `run_dir`;
- **Watches mtime** and, on renewal, **re-copies and signals/restarts the consumer** using a
  **static argv** — a service name can't inject into the command;
- **Does not** rely on the stock proxy's cert-obtained event hook. That hook needs an unbundled
  plugin; assuming it exists caused a prior outage. Do **not** mount the proxy data dir into any
  monitored app container.

#### `cert_bindings` — wiring a cert to an app declaratively

An `app_cert_bindings` row connects the cert-only pattern to an app: the edge is the ACME agent for
a hostname (matching one of the app's routes), the cert-sync helper copies the leaf cert + key to a
per-consumer `0600` path under the app's `run_dir`, and template placeholders inject those **synced**
paths into the app's config so config and files always agree:

```text
{{hm.cert.<binding>.crt}}   →  /run/helmsman/apps/<app>/certs/<binding>.crt   (0600, consumer-owned)
{{hm.cert.<binding>.key}}   →  /run/helmsman/apps/<app>/certs/<binding>.key
{{hm.cert.<binding>.ca}}    →  the issuing CA chain
```

- `required: true` **blocks the consumer's start** until the cert is present (a hard ordering gate —
  the container never polls or waits; if the cert can't issue, deploy fails fast with a reason rather
  than spin-looping).
- Renewal **re-copies and signals** the consumer via static argv.

See [App provisioning → managed config files](./gitops.md) for how `{{hm.cert.*}}`
placeholders are rendered host-side without ever touching the app's own `${…}` runtime placeholders.

#### Example: cert-only binding for an MQTT-over-TLS broker

```yaml
# In the app's helmsman definition — the edge issues the cert; the broker serves TLS itself.
routes:
  - hostname: mqtt.example.com
    mode: cert-only          # edge is ACME agent only — serves no traffic on this host

cert_bindings:
  - name: mqtt_tls
    hostname: mqtt.example.com
    required: true           # broker will not start until the synced cert exists
    reload:
      # static argv — a service name cannot inject; cert-sync runs this on renewal
      signal: SIGHUP

# The broker's managed config file references the SYNCED paths, never the proxy data dir:
#   listener 8883
#   certfile {{hm.cert.mqtt_tls.crt}}
#   keyfile  {{hm.cert.mqtt_tls.key}}
```

### `tcp-passthrough` / `tcp-terminate` (L4, opt-in, default off)

A layer-4 plugin lets the same proxy route extra TCP ports by SNI. **The cost, stated plainly:** the
L4 plugin is **not** in the stock binary, so enabling it means a **custom build** — which breaks the
"swap one binary" simplicity and makes you own its CVE cadence. It is gated by `edge.l4_enabled`
(**default false**), digest-pinned, and in the SBOM/scan cadence. Prefer `cert-only` + cert-sync
unless you specifically need SNI-routed L4.

---

## The raw-config caveat — why a linter is not enough

> **Be honest with yourself about what static analysis can and cannot catch.**

The obvious design — "adapt the pasted Caddyfile to JSON, then lint the JSON tree" — is
**bypassable**, because **Caddy resolves `{env.*}` placeholders and DNS names at *runtime*, not at
lint time.** A linter sees the literal string `{env.X}` or a hostname — not the `127.0.0.1:9000` it
becomes at dial time.

That is why several constructs are **hard-rejected** in the first place (any placeholder in an
upstream/dial/admin field, any listener on a control-plane port — see [the reject list](#fail-to-save-on-conflict)):
they are *precisely* the ones that defeat static analysis, so Helmsman refuses them outright rather
than pretend to validate them.

And it is why the editor's **real** safety is **structural and runtime**, not the linter:

1. **The pinned dialer** re-resolves and refuses control-plane targets on *every connection* — so a
   DNS name (or a rebind) that the linter saw as innocuous is refused at dial.
2. **The egress firewall** makes the control-plane ports and metadata *physically unreachable* from
   the edge slice — so a config the linter missed simply cannot reach them.
3. **The unix-socket admin** means there is often no TCP `:2019` to proxy to at all.
4. **The negative from-internet probe** after every apply proves the allowlist *blocks* (403/404
   from an un-allowlisted vantage), not just that it admits.
5. **Auto-rollback** reverts any apply whose health probe fails, within `apply_probe_window`.
6. **`helmsman edge restore-default`** (SSH) is the iron floor — see below.

The linter is **defense-in-depth on top of** those controls, not the thing standing between you and a
control-plane breach. Treat the Advanced tab accordingly: it can only *add* to operator-owned
hostnames, and even a perfectly-crafted overlay cannot dial something the firewall has already made
unreachable.

---

## Recovery & escape hatches

The edge is designed so it can **never become irrecoverable**:

- **Atomic load.** A bad `/load` leaves the previous config running — Caddy never serves a partial
  config.
- **Auto-rollback.** A failed health probe within `apply_probe_window` reverts to the retained
  last-known-good automatically. *You cannot leave the edge down by walking away.*
- **Re-derived restore.** Restoring a version re-derives Layer 0 from code, Layer 1 from the current
  `app_routes`, and Layer 2 from the stored overlay text (re-validated as untrusted). It never loads
  a stored composite. HMAC-protected version rows mean a DB tamper cannot become a loaded config.
- **The iron escape hatch (SSH-only):**

  ```bash
  helmsman edge restore-default
  ```

  Rebuilds Layer 0 + the admin allowlist from typed structs, drops the operator overlay, and **keeps
  your app routes.** The edge is never irrecoverable, and **SSH is always the recovery floor** — even
  if the UI itself is unreachable.

---

## Cert lifecycle visibility & ACME rate-limits

A single pinned CA with no fallback means anything that silently stops issuance — expiry, a stalled
renewal, a rate-limit — leaves the edge **serving but degrading invisibly**. So Helmsman makes it
**loud**, reading **leaf x509 metadata only, never a private key** (a lint bans opening any `.key` in
the cert subsystem).

- **Cert inventory** (`cert_inventory` table; read-only `GET /edge/certs`): hostname, issuer,
  `NotAfter`, derived last-renew, SANs, source. Edge-HTTPS leaves are read from the Caddy admin API on
  loopback; cert-only/shared-cert leaves by parsing the synced `.crt` the cert-sync helper placed. A
  cert-scan rides the poll tick — no per-cert goroutine, no reliance on a stock-proxy event hook.
- **Proactive alerts** (never deferred — see [alerting.md](./alerting.md)): `cert_expiring`
  (WARNING ~21 d → CRITICAL ~7 d, *regardless* of whether renewal looks healthy);
  `cert_renew_stalled` (in the renewal window, serial not advancing); **`cert_sync_stale`** — the
  silent MQTT-TLS killer: the edge leaf is fresher than the consumer's synced leaf, so it re-nudges the
  cert-sync helper (the self-healing recreate path) then pages; `cert_anomaly` (issuer ≠ the pinned CA).
- **ACME rate-limit handling.** Helmsman models the CA's weekly per-registered-domain and
  duplicate-cert limits **locally** from its own issuance ledger (`acme_ledger`, bucketed by eTLD+1 via
  an embedded public-suffix list — it never asks the CA). On a 429 / `rateLimited` *or* a local-window
  estimate exceeding the limit → **`cert_rate_limited`** (CRITICAL; the UI shows "retry after …", not a
  silent "still trying") with **capped, jittered, Retry-After-honoring back-off on a *monotonic*
  clock** (so a forward clock-step can't collapse the back-off and hammer the CA — see the clock-skew
  coupling in [security.md](./security.md)) plus a hard floor of one attempt per hostname per
  failed-validation window.
- **Pre-issuance batching.** Bulk-adding vhosts can trip the weekly per-domain limit and brick
  issuance for *every* hostname in that domain. The route-add path groups by registered domain, issues
  up to the safe remaining count now, and **defers the rest as `cert_pending_batch`** — the route is
  still rendered (HTTP→HTTPS works), just cert-pending, so the edge degrades **visibly and partially,
  never silently and totally**. The dry-run surfaces warn before commit, and staging rehearsals are
  ledgered under a separate bucket so they never consume the prod weekly budget.

## Configuration reference

```yaml
edge:
  mode: managed                 # "managed" (default) | "external" (config-file-only escape hatch)
  acme_email: ops@example.com   # REQUIRED in managed mode — fail-closed if empty
  acme_ca: https://acme-v02.api.letsencrypt.org/directory   # single pinned issuer, no fallback
  apply_probe_window: 20s       # health-probe window after each apply (default 20s)
  l4_enabled: false             # layer-4 SNI routing — requires a CUSTOM build; default off

caddy_editor:
  mode: strict                  # "strict" (default) | "review" (footgun-tier rejects may be acked;
                                #   control-plane-tier rejects are NEVER downgradable)

admin:
  # Optional. If unset, the admin UI is reachable only via SSH tunnel / port-forward to 127.0.0.1:9000
  # (the edge serves NO admin vhost — SBD-1). If set, the admin vhost is rendered with the IP
  # allowlist injected as the first matcher.
  hostname: ""

# In external mode ONLY — fail-closed boot requirements:
trusted_proxies:
  - 203.0.113.10/32             # MUST be a specific edge IP, prefix <= /24, not a Docker bridge CIDR
```

| Key | Default | Notes |
|---|---|---|
| `edge.mode` | `managed` | Explicit; no auto-detect. `external` is config-file-only and not UI-reachable. |
| `edge.acme_email` | *(empty)* | **Required** in `managed` mode; onboarding refuses to complete without it. |
| `edge.acme_ca` | *(your CA)* | Single pinned issuer. **No fallback** — a fallback would diverge cert paths and break shared-cert readers. |
| `edge.apply_probe_window` | `20s` | Window for the post-apply health probe (incl. the negative from-internet test) before auto-rollback. |
| `edge.l4_enabled` | `false` | Enabling L4 SNI routing requires a **custom proxy build**; you own its CVE cadence. |
| `caddy_editor.mode` | `strict` | `review` only softens footgun-tier rejects; never the control-plane tier. |
| `admin.hostname` | *(unset)* | When unset, no admin vhost is served at all (SBD-1). |
| `trusted_proxies` | *(none)* | **Required for `external` boot:** a specific edge IP, `≤ /24`, not a bridge CIDR; boot also probes that `:9000` is unreachable from non-loopback. |