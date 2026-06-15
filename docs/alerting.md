# Alerting

> **Scope:** This document describes Helmsman's optional, pluggable alerting engine — how it decides whether to alert at all (or defer to an app that already does), the two distinct alert *origins* (app-domain and Helmsman-originated infra/liveness), the delivery channels, and the safety properties that make alerting trustworthy on a single, possibly small, host.
>
> Alerting is **off until configured**. When off, it has **zero runtime surface** — no goroutines, no outbound calls, no new inbound endpoints. Turning it on never adds required inbound surface: the engine is **read-and-notify only** and performs **zero Docker writes**.

See also: [Helmsman README](../README.md) · [Ops Interface & discovery](./definition-file.md) · [Self-healing supervisor](./scaling-and-self-healing.md) · [Auto-scaling](./scaling-and-self-healing.md) · [Security model](./security.md)

---

## Getting set up

Alerting is **off until you turn it on**. Enable it in `config.yaml` and reload:

```yaml
alerting:
  enabled: true
  quiet_start_hour: 22      # optional: suppress non-critical alerts overnight
  quiet_end_hour: 7
  dead_mans_url: "https://hc-ping.com/your-uuid"   # the heartbeat target (below)
  admin_url: "https://admin.example.com"           # so alerts can link back to the dashboard
```

Everything else is managed on the **Alerts** page in the dashboard — channels, rules, and the list of currently-open alerts. Open problems also roll up onto the **Incidents** screen.

### How an alert reaches you

You add one or more **channels** on the Alerts page, and an alert is delivered to each:

| Channel | Notes |
|---|---|
| **Email** (SMTP) | Sent over TLS, and hardened against header injection (app/host names can't forge headers). The message links back to the dashboard rather than dumping logs. |
| **Webhook** | An HTTP POST with an **HMAC-signed** body, so your receiver can verify the call really came from Helmsman. |
| **Slack** | Incoming webhook / bot. |
| **Discord** | Incoming webhook. |
| **Telegram** | Bot API. |

Sending runs in a **separate, globally rate-limited notifier** — so a hung SMTP server or a slow bot API can never stall monitoring or turn Helmsman into a spam-cannon. Alerts are **deduplicated** (one problem = one page, not a flood) and respect **quiet hours** (non-critical alerts are held overnight; critical ones always page).

### Knowing Helmsman itself is alive (the dead-man's switch)

A dashboard that's down can't alert you that it's down. So Helmsman also runs an **externalized dead-man's switch**: it sends a periodic heartbeat to an outside URL you choose (`dead_mans_url` — e.g. a free [healthchecks.io](https://healthchecks.io) check). As long as Helmsman is healthy, the pings keep coming. If Helmsman — or the whole server — dies, the pings stop, and that outside service pages you. Set it up once and you're covered even for total-host failure.

---

## Table of contents

- [1. The problem alerting solves](#1-the-problem-alerting-solves)
- [2. Architecture at a glance](#2-architecture-at-a-glance)
- [3. App-domain alerting: detect, decide, defer](#3-app-domain-alerting-detect-decide-defer)
  - [3.1 Capability detection](#31-capability-detection)
  - [3.2 The effective-mode table](#32-the-effective-mode-table)
  - [3.3 The down-only safety net](#33-the-down-only-safety-net)
  - [3.4 The built-in evaluator](#34-the-built-in-evaluator)
- [4. Helmsman-originated (infra / liveness) alerts](#4-helmsman-originated-infra--liveness-alerts)
  - [4.1 Why these are never deferred](#41-why-these-are-never-deferred)
  - [4.2 The can't-fix taxonomy](#42-the-cant-fix-taxonomy)
  - [4.3 `host_degraded`: coalescing, never dropping](#43-host_degraded-coalescing-never-dropping)
- [5. The notifier and dead-man's-switch](#5-the-notifier-and-dead-mans-switch)
- [6. Channels](#6-channels)
- [7. Email safety](#7-email-safety)
- [8. Dedupe, quiet hours, and escalation](#8-dedupe-quiet-hours-and-escalation)
- [9. Configuration reference](#9-configuration-reference)
  - [9.1 Channel config](#91-channel-config)
  - [9.2 Rule config](#92-rule-config)
  - [9.3 Routes](#93-routes)
- [10. Operating alerting](#10-operating-alerting)
- [11. Security trade-offs, stated honestly](#11-security-trade-offs-stated-honestly)

---

## 1. The problem alerting solves

You run apps on a single host. Some of those apps already have their own alerting — they page you when a queue backs up or a dependency goes down. Others have **none**. You want one answer to "how do I get alerted about everything?" without:

- **double-paging** for apps that already alert, and
- **silent gaps** for apps that don't, and
- the classic failure where *"the app went dark"* produces **zero** alerts because everything deferred to the now-dead app.

Helmsman ships a built-in alert engine that **fills the gap but defers to apps that already cover themselves** — with one critical exception (the [down-only safety net](#33-the-down-only-safety-net)). It also raises its **own** alerts about the platform — crashed containers, OOM kills, edge/cert failures, a full disk — which are **never** deferred, because an app that is crash-looping cannot be trusted to alert about its own death, and host/edge failures are in no app's domain.

There are therefore **two origins** of alerts, and they behave differently:

| Origin | Raised by | About | Deferrable? | Quiet-hours behavior |
|---|---|---|---|---|
| `app` | The built-in evaluator | An app's own metrics/health | **Yes** — defers to a self-alerting app | Suppressed during quiet hours (unless `critical`) |
| `helmsman_infra` | The supervisor (self-healing) and the scaler | The platform itself: containers, edge, certs, disk, host headroom | **Never** (`defer_to_app` is hard-set `false`) | WARNING infra is suppressed; **CRITICAL infra always pages** |

---

## 2. Architecture at a glance

Alerting is built to be cheap and to **never become the thing that takes the host down**. The design separates the part that *decides* from the part that *sends*.

```
                 poll tick
                    │
        ┌───────────▼───────────────┐
        │  Poller (already running)  │  holds the LATEST snapshot
        │  host + container + health │  (host cpu/mem/disk/swap,
        └───────────┬───────────────┘   container state + restart
                    │ latest snapshot      delta, health indicators)
   ┌────────────────▼────────────────┐
   │  Evaluator goroutine (ONE)       │  ticker-driven, NO network I/O
   │  reads snapshot, runs rules,     │  side-effect-free except SQLite
   │  advances per-(rule,target) FSM  │
   └───────────────┬──────────────────┘
                   │ writes alert_outbox row + signals
   ┌───────────────▼──────────────────┐
   │  Notifier goroutine (separate)    │  globally rate-limited
   │  dedupe + quiet-hours at SEND time│  a hung SMTP/bot cannot stall
   │  encrypted channel configs        │  evaluation or spam the box
   └───────────────┬──────────────────┘
                   │
        ┌──────────▼───────────┐    ┌──────────────────────────────┐
        │  Channels (std-lib)  │    │  Externalized dead-man's-     │
        │  webhook/email/...   │    │  switch: outbound heartbeat,  │
        └──────────────────────┘    │  per-host silence, watchdog   │
                                     └──────────────────────────────┘
```

Key properties, each chosen deliberately:

- **One evaluator goroutine**, ticker-driven, reading the **snapshot the poller already holds**. The evaluator does **no network I/O** — it is fast and side-effect-free apart from SQLite writes. There are **no per-rule goroutines**, no scheduler library, and **no time-series database**.
- **SQLite is the only store.** Alert state is **recovered from SQLite on restart** — a bounce does not re-fire open alerts and does not lose them.
- **The notifier is separate and globally rate-limited.** Notifications **never** run in the evaluator. A hung SMTP server or a slow bot API can stall the notifier, but it can never stall evaluation or turn into a spam-cannon against the box.
- **The dead-man's-switch is externalized**, because a dashboard that is down cannot alert you about being down.

---

## 3. App-domain alerting: detect, decide, defer

### 3.1 Capability detection

Apps advertise self-alerting through the Ops Interface descriptor:

```json
{
  "capabilities": ["...", "alerting"],
  "alerting": {
    "self_managed": true,
    "state_endpoint": "/ops/alerts"
  }
}
```

`state_endpoint` is a **relative path only**. Like every outbound ops/health/alerting call, it is subject to the **SSRF invariant**: the descriptor is advisory metadata and may supply a *relative* path, but it may **never** supply a scheme, host, or port. The path is joined onto the **operator-configured `ops_base_url`** (the app's known container endpoint) — a compromised app cannot redirect Helmsman's authenticated, secret-bearing probes at cloud metadata, the proxy admin API, the socket-proxy, or the admin UI. See [Ops Interface & discovery](./definition-file.md) and [Security model](./security.md).

### 3.2 The effective-mode table

On **each poll**, Helmsman computes an **effective mode per app**. The first matching condition wins:

| Condition | Mode | Meaning |
|---|---|---|
| per-app override `off` | **OFF** | No alerting for this app, period. |
| per-app override `dashboard` | **COVER** | Operator opts in to the built-in engine even though the app self-alerts. |
| per-app override `defer` | **DEFER** | Surface the app's own alert state; do not notify. |
| capability detected **and reachable** | **DEFER** | Surface the app's state, no duplicate notifications. |
| global default `never` | **OFF** | Alerting is globally off. |
| else | **COVER** | The built-in engine evaluates rules for this app. |

- **COVER** = Helmsman's evaluator runs the rules and notifies.
- **DEFER** = Helmsman *surfaces* the app's own alert state in the UI (read from `state_endpoint`) but does **not** send notifications — you rely on the app's own alerting.
- **OFF** = nothing.

### 3.3 The down-only safety net

This is the most important nuance in app-domain alerting.

If an app **advertises** self-alerting but is **unreachable this cycle**, do **not** assume it is silently handling everything — it may be the very thing that died. Helmsman falls through to **COVER for a narrow, safe subset only**:

- container-down,
- health-endpoint-unreachable,
- heartbeat-missing.

It does **not** cover the app's internal threshold alerts (queue depth, dependency latency, error rates) — those belong to the app and Helmsman has no trustworthy signal for them while the app is dark. This closes the classic failure mode where *"the app went dark"* produces zero alerts because everyone deferred to the dead app.

Granularity is **per-rule**, via `defer_when_self_managed`:

| Rule family | Default `defer_when_self_managed` | Behavior |
|---|---|---|
| liveness / heartbeat | **`false`** | **Always cover** — Helmsman always watches liveness. |
| resource / queue / dependency | **`true`** | **Defer when self-managed** — covered only when the app is not self-alerting. |

### 3.4 The built-in evaluator

The evaluator reads the latest poller snapshot and advances a per-`(rule, target)` state machine:

```
ok ──(breach)──► pending ──(breach sustained for `for_seconds`)──► firing
 ▲                  │                                                  │
 │                  └──(breach clears before sustain)──► ok           │
 │                                                                     │
 └────────────── resolved ◄──(clear sustained for clear window)───────┘
```

- **`for_seconds`** is the **sustain window** — anti-flap. A rule must breach continuously for this long before it fires.
- The **clear window** is symmetric — a rule must hold clear before it resolves. This kills the rapid fire/resolve sawtooth.
- **Escalation** bumps the alert *level* if it is still firing and unacked after the escalation interval.

**Metrics available to rules** (all already in the snapshot — the evaluator never reaches out):

- host **CPU / memory / disk / swap** percentages,
- container **state** and **restart-count delta**,
- health indicators — **dependency down, queue backlog, status=error**,
- **heartbeat age**.

---

## 4. Helmsman-originated (infra / liveness) alerts

### 4.1 Why these are never deferred

The §3 logic can defer to an app's own alerting. **Infra/liveness alerts are the opposite — Helmsman raises them itself, about the platform, and they are *never* deferred.**

Two reasons:

1. **An app cannot alert about its own death.** A service that is crash-looping, OOM-killed, or stuck on startup cannot be trusted to page you about it.
2. **Host and edge failures are in no app's domain.** A full disk, a failed ACME renewal, a degraded host — no single app owns these.

The [self-healing supervisor](./scaling-and-self-healing.md) and the [auto-scaler](./scaling-and-self-healing.md) write alert events with:

```
origin:       "helmsman_infra"
defer_to_app:  false        // HARD-SET, not a default
```

The existing evaluator **skips the defer branch** for these and routes them straight to the rate-limited notifier, with **email as a first-class channel**. Dedupe is on `hash(app, service, alert_kind)`. An infra alert **auto-resolves** when the app holds healthy again.

Quiet-hours behavior for infra is asymmetric and deliberate:

> **WARNING infra is quiet-hours-suppressed, but CRITICAL infra *always* pages.** A degraded platform at 3 a.m. is exactly when you need to know.

### 4.2 The can't-fix taxonomy

These are the `alert_kind` values Helmsman raises about itself. They are the things the platform **cannot fix on its own** and must escalate to a human:

| `alert_kind` | Raised when | Typical level |
|---|---|---|
| `crashloop_capped` | The supervisor's remediation ladder hit its attempt cap and the circuit breaker latched open. | CRITICAL |
| `unhealthy_capped` | A container stayed up-but-unhealthy past the cap; remediation gave up. | CRITICAL |
| `stuck_startup` | A service never became healthy within its slow-start watchdog deadline. | CRITICAL |
| `oom_killed_repeated` | Repeated OOM kills (incl. exit-137 / at-limit kills, not just the `OOMKilled` flag). **Short-circuits the ladder** — restarting an OOM-killer on a small box is futile. | CRITICAL |
| `redeploy_failed` | The rung-3 `redeploy` (≥ 1 GB only) failed. | CRITICAL |
| `scale_refused_no_capacity` | The auto-scaler wanted to scale up but the host-capacity budget cannot fund even one more replica. A **first-class alert, not a silent hold**. | WARNING/CRITICAL |
| `edge_down` | The edge proxy slice is down. | CRITICAL |
| `cert_failed` | A required certificate is unavailable. | CRITICAL |
| `acme_failed` | An ACME issuance/renewal failed. | CRITICAL |
| `disk_full` | Host disk crossed the critical threshold. | CRITICAL |
| `host_degraded` | The host as a whole is degraded (see [§4.3](#43-host_degraded-coalescing-never-dropping)). | CRITICAL |
| `low_headroom` | Memory headroom dropped below the floor the supervisor needs to safely act. | WARNING |

**v1-gap additions** (same engine, new kinds — all `origin:helmsman_infra`, `defer_to_app:false`, deduped + auto-resolved; *never* a new notifier/goroutine):

| `alert_kind` | Raised when | Typical level |
|---|---|---|
| `cert_expiring` | A leaf is within `not_after − N` days — **fires regardless of whether renewal looks healthy**, so a quietly-broken auto-renew surfaces with runway. | WARNING → CRITICAL |
| `cert_renew_stalled` | Inside the renewal window but the serial hasn't advanced across N scans ("the renewal that should've happened hasn't"). | CRITICAL |
| `cert_sync_stale` | The edge's leaf is fresher than a cert-only consumer's synced leaf — the **silent MQTT-TLS killer**; re-nudges the sync helper, then pages. | CRITICAL |
| `cert_anomaly` | A scanned leaf's issuer ≠ the pinned CA (mis-issuance / stray fallback). | WARNING |
| `cert_rate_limited` | ACME 429 / `rateLimited`, or the local PSL window estimate is exceeded; the UI shows "retry after …". | CRITICAL |
| `cert_pending_batch` | The pre-issuance guard deferred certs to stay under the CA weekly per-domain limit (route is rendered, cert pending). | WARNING |
| `clock_skew` | A monotonic-divergence step (or trusted-reference confirmation) past threshold; auth/replay/cert protections may be unreliable. | WARNING → CRITICAL (> 60 s) |
| `backup_failed` / `backup_overdue` / `backup_verify_failed` / `backup_dest_unreachable` | A backup run failed / missed its window / won't decrypt+round-trip (the master-key footgun, caught at backup time) / the destination (S3/disk) is unreachable. | CRITICAL / WARNING |
| `restore_failed` | A restore failed (auto-rolled back to the pre-restore volume). **Always pages, even in quiet hours.** | CRITICAL |
| `disk_pressure_critical` | Sub-kind under `disk_full`: > 90 % or projected-full-in-window; arms the remediation FSM. | CRITICAL |
| `self_upgrade_failed` | A self-upgrade aborted (carries the failing step + reason); the box auto-recovered to the old binary. | CRITICAL |
| `preflight_failed` / `engine_api_mismatch` / `compose_v2_missing` / `socket_proxy_not_readonly` | The boot / pre-write-plane preflight failed; the write plane is hard-disabled while the read plane + edge keep serving. `socket_proxy_not_readonly` is `level=security`. | CRITICAL / security |

> **Why "the edge broke" is an alert, not a restart.** A service still waiting on its edge-issued cert enters `WAITING_ON_EDGE` — the supervisor **does not restart it**. If the cert never issues, that surfaces as an `edge/cert/acme` alert, not a futile restart loop. The supervisor never "fixes" what the edge broke. See [self-healing](./scaling-and-self-healing.md).

### 4.3 `host_degraded`: coalescing, never dropping

When the host itself is degraded, many apps fail at once. Paging you once per app is noise — but **dropping** those pages is dangerous. Helmsman threads this needle:

A `host_degraded` **super-alert coalesces** the per-app pages it caused into **one page**, and:

- it **opens and audits every child alert** (they exist in `alert_events` — nothing is silently discarded),
- it **lists every child** in the single page so you can see the blast radius, and
- it **never coalesces an alert that is not plausibly caused by the host condition.**

That last point is a security property, not just a usability one:

> A degraded host **cannot be used as cover to mask a separate compromise alert.** If an auth-failure spike or an allowlist-violation alert fires *during* a host-degraded window, it is **not** folded into the `host_degraded` super-alert — it pages on its own. Coalescing reduces noise; it must never become an attacker's smoke screen.

---

## 5. The notifier and dead-man's-switch

**Notifications never run in the evaluator.** When a rule fires, the evaluator writes an `alert_outbox` row and **signals** the notifier goroutine. That is all.

The **notifier** is a **separate, globally rate-limited** goroutine. It performs dedupe and quiet-hours evaluation **at send time** (critical always pages). Because it is decoupled:

- a hung SMTP server or slow bot API **cannot stall evaluation**, and
- a misbehaving rule **cannot turn the notifier into a spam-cannon** against the box — the global rate limit is the backstop.

**The dead-man's-switch is externalized** — the dashboard cannot alert you about itself being down, so three independent mechanisms exist *outside* the notify path:

1. **Outbound heartbeat ping** to an external cron-monitor URL (e.g. a "dead man's snitch" service). If Helmsman stops pinging, the *external* monitor alerts you.
2. **Per-host silence detection** — if a host stops reporting entirely, that absence is itself a signal.
3. **A self-watchdog** that lets `systemd` restart a stuck evaluator.

**Ack / silence** controls sit in the UI, behind the **IP allowlist + auth** — they are not exposed publicly.

---

## 6. Channels

Channels use the **standard library only** — no heavyweight SDKs. The `Channel` interface is small, and each implementation is intentionally minimal:

| Channel | Transport / notes |
|---|---|
| `webhook` | HTTP POST, **HMAC-signed** body so the receiver can verify authenticity. |
| `email` (SMTP) | SMTP over **TLS**. See [Email safety](#7-email-safety) for the hardening. |
| `telegram` | Bot API. |
| `slack` | Incoming webhook / bot. |
| `discord` | Incoming webhook. |
| `ntfy` | Publish to an ntfy topic. |

Properties common to all channels:

- **Config is encrypted.** Each channel's config JSON is **AES-256-GCM encrypted under the master key**. In the UI it is **masked / write-only** — you can set a token or password but never read it back.
- **"Send test" button.** Every configured channel has a test button that sends a sample notification through the real delivery path, so you find a misconfiguration before an incident does.
- **No template engine.** Message templating is **plain-text / minimal-markdown with fixed defaults**. There is deliberately **no template engine that could execute code** — a templating language is an injection surface, and alerting must not be one.

---

## 7. Email safety

Email gets extra scrutiny because app, service, and host **names flow into messages**, and a compromised app controls its own name. The threat is **SMTP header injection** — a name containing `\r\n` could inject a `Bcc:` header and exfiltrate alert content to an attacker, or forge `From:`/`Subject:`.

Helmsman's defenses:

- **Messages are built via a MIME library**, never by string-concatenating headers.
- **Every interpolated app / service / host name is `CR` / `LF` / `NUL`-stripped** before use, independent of where it came from.
- **Identifiers are never placed in a header.** Attacker-influenced names appear only in the **bounded body**, never in `To`, `From`, `Subject`, `Bcc`, etc.
- The body is a **bounded, fixed-section** layout:

| Section | Content |
|---|---|
| **What failed** | The `alert_kind` and the affected `(app, service)`. |
| **What Helmsman tried** | The remediation steps attempted (for infra alerts), e.g. `restart → recreate → circuit-open`. |
| **Current state** | The FSM/alert state right now. |
| **A few host numbers** | CPU / mem / disk / swap — a handful of figures, not a metrics dump. |
| **A link** | A link to the **loopback admin UI** for the full picture. |

> **Why a link and never an inline log dump:** logs can contain secrets and attacker-controlled content, and an unbounded log dump in an email is both an exfiltration vector and a way to blow past size limits. The email carries enough to triage; the **link** (behind the allowlist + auth) carries the detail.

---

## 8. Dedupe, quiet hours, and escalation

All three happen **at notify time**, in the notifier — not in the evaluator.

**Dedupe.** App-domain alerts dedupe on their `(rule, target)` identity; infra alerts dedupe on `hash(app, service, alert_kind)`. While an alert is open, repeated breaches do not re-page — you get one page, then escalations, then a resolve.

**Quiet hours.** During configured quiet hours, notifications are **suppressed by level and origin**:

| Alert | During quiet hours |
|---|---|
| App-domain, non-critical | **Suppressed** |
| App-domain, **critical** | **Pages** |
| `helmsman_infra`, WARNING | **Suppressed** |
| `helmsman_infra`, **CRITICAL** | **Always pages** |

> The rule is simple: **critical infra always pages.** Quiet hours are for reducing noise, never for muting a platform that is actively failing.

**Escalation.** If an alert is still **firing and unacked** after the escalation interval, its level is bumped and it re-notifies (subject to the rate limit). Acking it stops escalation; silencing it suppresses notifications for a bounded window.

---

## 9. Configuration reference

> Configuration lives in SQLite (`alert_channels`, `alert_rules`, `alert_routes`) and is edited through the UI. The JSON shapes below are illustrative of the fields; secret-bearing values are stored AES-256-GCM-encrypted and shown masked. Use **"Send test"** after any channel change.

### 9.1 Channel config

```json
{
  "channels": [
    {
      "id": "email-primary",
      "type": "email",
      "enabled": true,
      "config": {
        "smtp_host": "smtp.example.net",
        "smtp_port": 587,
        "tls": true,
        "username": "alerts@example.net",
        "password": "********",          // write-only, AES-256-GCM at rest
        "from": "Helmsman <alerts@example.net>",
        "to": ["oncall@example.net"]
      }
    },
    {
      "id": "ops-webhook",
      "type": "webhook",
      "enabled": true,
      "config": {
        "url": "https://hooks.example.net/helmsman",
        "hmac_secret": "********"         // body is HMAC-signed for the receiver
      }
    },
    {
      "id": "telegram-oncall",
      "type": "telegram",
      "enabled": true,
      "config": {
        "bot_token": "********",
        "chat_id": "-1001234567890"
      }
    },
    {
      "id": "ntfy-mobile",
      "type": "ntfy",
      "enabled": true,
      "config": {
        "server": "https://ntfy.sh",
        "topic": "helmsman-myhost-7f3c"
      }
    }
  ]
}
```

> Supported `type` values: `webhook`, `email`, `telegram`, `slack`, `discord`, `ntfy`.

### 9.2 Rule config

```json
{
  "rules": [
    {
      "id": "host-mem-high",
      "scope": "host",
      "metric": "mem_pct",
      "op": ">",
      "threshold": 90,
      "for_seconds": 120,        // sustain window (anti-flap)
      "clear_seconds": 120,      // symmetric clear window
      "level": "warning",
      "escalate_after_seconds": 900,
      "escalate_to": "critical"
    },
    {
      "id": "container-restart-storm",
      "scope": "container",
      "metric": "restart_count_delta",
      "op": ">=",
      "threshold": 3,
      "for_seconds": 60,
      "level": "critical"
    },
    {
      "id": "queue-backlog",
      "scope": "app_health",
      "metric": "queue_backlog",
      "op": ">",
      "threshold": 1000,
      "for_seconds": 300,
      "level": "warning",
      "defer_when_self_managed": true   // resource/queue rule → defers if app self-alerts
    },
    {
      "id": "liveness-heartbeat",
      "scope": "app_health",
      "metric": "heartbeat_age_seconds",
      "op": ">",
      "threshold": 90,
      "for_seconds": 0,
      "level": "critical",
      "defer_when_self_managed": false  // liveness → ALWAYS covered (down-only safety net)
    }
  ]
}
```

Field notes:

| Field | Meaning |
|---|---|
| `scope` | `host`, `container`, or `app_health`. |
| `metric` | One of the snapshot metrics: `cpu_pct`, `mem_pct`, `disk_pct`, `swap_pct`, `state`, `restart_count_delta`, `queue_backlog`, `dependency_down`, `status_error`, `heartbeat_age_seconds`. |
| `for_seconds` | Sustain window before `pending → firing`. `0` fires immediately. |
| `clear_seconds` | Symmetric clear window before `firing → resolved`. |
| `level` | `warning` or `critical` — drives quiet-hours behavior. |
| `escalate_after_seconds` / `escalate_to` | Optional escalation if still firing + unacked. |
| `defer_when_self_managed` | Per-rule defer granularity. **Liveness/heartbeat rules default `false` (always cover); resource/queue/dependency rules default `true`.** |

> **You do not write Helmsman-originated infra rules.** The `helmsman_infra` taxonomy in [§4.2](#42-the-cant-fix-taxonomy) is raised by the supervisor and scaler with `defer_to_app:false` hard-set. You only author `app`-origin rules; you *route* and *quiet-hour* the infra ones.

### 9.3 Routes

Routes map alerts to channels, optionally filtered by origin, level, app, or quiet hours.

```json
{
  "routes": [
    {
      "match": { "origin": "helmsman_infra", "level": "critical" },
      "channels": ["email-primary", "telegram-oncall"],
      "ignore_quiet_hours": true        // CRITICAL infra always pages
    },
    {
      "match": { "origin": "app", "level": "warning" },
      "channels": ["ntfy-mobile"],
      "quiet_hours": { "start": "22:00", "end": "07:00", "tz": "UTC" }
    },
    {
      "match": { "origin": "app" },
      "channels": ["ops-webhook"]
    }
  ]
}
```

---

## 10. Operating alerting

**Turning it on.** Alerting is **off by default** and is a separate, optional package — one config key enables it, and it has **zero runtime surface when off**. With it off there are no alerting goroutines, no outbound calls, and no new inbound endpoints.

**First-run checklist:**

1. Enable alerting (the one config key).
2. Add at least one channel and click **"Send test"** — confirm you actually receive it.
3. Wire the **external dead-man's-switch**: point Helmsman's outbound heartbeat at a cron-monitor URL so *something outside Helmsman* watches Helmsman.
4. Add `app`-origin rules for apps that **don't** self-alert.
5. Set the per-app mode (`off` / `dashboard` / `defer`) for apps that **do** self-alert — usually leave them on auto-detect (`DEFER` when reachable, down-only safety net when not).
6. Route `helmsman_infra` **critical** to a channel that pages, with `ignore_quiet_hours: true`.

**Restarts are safe.** Alert state lives in SQLite and is recovered on boot. A restart does not re-fire open alerts and does not lose them. A crashed deploy's `expected_down` lease is cross-checked against the held write-plane lock and **cleared fail-closed on restart**, so a crash-looping service is never silently left un-paged. See [self-healing](./scaling-and-self-healing.md).

**Acking and silencing.** Ack stops escalation; silence suppresses notifications for a bounded window. Both are behind the IP allowlist + auth.

---

## 11. Security trade-offs, stated honestly

Alerting touches the network and interpolates attacker-influenceable strings, so its trade-offs are explicit:

- **The notifier can be stalled; evaluation cannot.** A hung SMTP server or dead bot API will back up the notifier — that is the *intended* failure mode. Decoupling guarantees a bad channel degrades delivery without ever stalling evaluation or letting a rule spam-cannon the host. The global rate limit caps the blast radius of a misconfigured rule.

- **A self-hosted dashboard cannot reliably alert about its own death.** That is why the dead-man's-switch is **externalized**. If you skip step 3 of the checklist, Helmsman going down is a **silent failure** — the one alert it structurally cannot send is "I am down." Wire the external monitor.

- **Coalescing trades some detail for less noise — but never drops, and never masks.** `host_degraded` folds child pages into one, but it **opens and audits every child** and **refuses to coalesce anything not plausibly caused by the host condition** — so a degraded host can't be turned into cover for a separate compromise alert.

- **Email is deliberately information-poor.** It carries a fixed, bounded summary and a **link**, never an inline log dump. Logs may contain secrets and attacker-controlled content; the email path is hardened (MIME-built, `CR`/`LF`/`NUL`-stripped identifiers, names never in headers) at the cost of putting the full detail behind the loopback admin UI instead of in your inbox.

- **No template engine, by design.** Rich templating is convenient and is an injection surface. Helmsman ships fixed plain-text/minimal-markdown templates and accepts the reduced flexibility.

- **Defer is a trust decision.** When an app self-alerts and is reachable, Helmsman trusts it for its own threshold alerts and only covers liveness. If that app stops alerting *while still reachable*, Helmsman will not notice — defer assumes a *reachable* app is *functioning*. The down-only safety net covers the *unreachable* case, not the *reachable-but-broken-alerting* case.

For the wider security model — the SSRF invariant, the IP allowlist, the master-key encryption, and the supervisor's safety gates — see [Security model](./security.md), [Self-healing supervisor](./scaling-and-self-healing.md), and [Auto-scaling](./scaling-and-self-healing.md).