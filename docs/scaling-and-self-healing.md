# Scaling & Self-Healing

> **Scope:** This document describes Helmsman's two opt-in lifecycle automations — **process-level auto-scaling** (it adjusts the *replica count* of a single container service) and the **self-healing supervisor** (it restarts crashed or stuck services and escalates what it cannot fix). Both share one design principle that is worth stating up front: on a constrained host they are **conservative by construction**. They are wired so that, in the worst case, they *refuse to act and page you* rather than push the box past its limits. Neither can manufacture an out-of-memory (OOM) condition.

> **The one-line mental model.** Auto-scaling adds capacity only when there is provably room for it; self-healing reduces pressure or holds steady but never adds it. When in doubt, both **decline and alert** — a refusal is treated as a first-class signal, not a silent no-op.

See also: [Helmsman README](../README.md) · [Alerting](./alerting.md) · [Managed edge & TLS](./edge-and-tls.md) · [Architecture](./architecture.md) · [Security model](./security.md)

---

## Table of contents

- [0. The resource gate this all lives under](#0-the-resource-gate-this-all-lives-under)
- [1. Two features, one safety philosophy](#1-two-features-one-safety-philosophy)
- [Part I — Auto-scaling](#part-i--auto-scaling)
  - [2. What auto-scaling is (and is not)](#2-what-auto-scaling-is-and-is-not)
  - [3. The candidacy gate (C1–C7)](#3-the-candidacy-gate-c1c7)
  - [4. The controller](#4-the-controller)
  - [5. Hysteresis: not flapping](#5-hysteresis-not-flapping)
  - [6. The host-capacity guard](#6-the-host-capacity-guard)
  - [7. Edge-pool reconciliation](#7-edge-pool-reconciliation)
  - [8. An example scaling policy](#8-an-example-scaling-policy)
- [Part II — Self-healing](#part-ii--self-healing)
  - [9. What the supervisor is](#9-what-the-supervisor-is)
  - [10. The per-service state machine](#10-the-per-service-state-machine)
  - [11. Detection (from already-polled data only)](#11-detection-from-already-polled-data-only)
  - [12. `WAITING_ON_EDGE`: don't fix what the edge broke](#12-waiting_on_edge-dont-fix-what-the-edge-broke)
  - [13. The remediation ladder](#13-the-remediation-ladder)
  - [14. Anti-flap and the circuit breaker](#14-anti-flap-and-the-circuit-breaker)
  - [15. The four tiny-box safety gates](#15-the-four-tiny-box-safety-gates)
  - [16. An example self-healing policy](#16-an-example-self-healing-policy)
- [17. How both features alert](#17-how-both-features-alert)
- [18. Tuning on a small box](#18-tuning-on-a-small-box)
- [19. Security trade-offs, stated honestly](#19-security-trade-offs-stated-honestly)

---

## 0. The resource gate this all lives under

Helmsman treats memory pressure as a **safety property, not a performance footnote**. A `docker compose pull`, an on-box build, or a service restart that OOMs a tiny box can cascade the entire host into a crash-loop — and the first process to die is usually the edge proxy, taking your sites down with it. To prevent that, the **write plane** (anything that runs `docker compose up/pull/build` or redeploys) is gated on a host with **≥ 1 GB RAM**, and several global mechanisms exist so that no single plane can OOM-kill the control plane:

| Mechanism | What it does |
|---|---|
| **Write-plane RAM gate (≥ 1 GB)** | Below it, `docker compose` write operations are disabled. The edge keeps serving — it is part of the baseline, in its own memory-capped slice — but nothing that could OOM the box runs. |
| **One-docker-child semaphore** | A single global lock. **At most one** `docker compose` child process exists at a time, host-wide. Everything that writes acquires it non-blocking. |
| **Per-process memory caps (distinct cgroups/slices)** | The control plane, the edge, and any sandbox each run in their own capped slice. `GOMEMLIMIT` sits under the systemd cap. |
| **One-service-at-a-time deploys** | Deploys are serialized; the box is never asked to materialize several services at once. |

Both features in this document **inherit all of the above**. Scale-up and self-healing remediation **both** pass the §0 write-plane gate plus the one-docker-child semaphore plus a memory-headroom floor, and the auto-scaling capacity guard **collapses to a single replica on a near-OOM box**. The net effect: neither feature can OOM-cascade the control plane.

> If you take one thing from this document: **the gate is the point.** Everything else is how each feature behaves *within* the gate.

---

## 1. Two features, one safety philosophy

|  | Auto-scaling | Self-healing supervisor |
|---|---|---|
| **What it changes** | The *replica count* of one container service | The *running state* of a crashed/stuck service |
| **Direction of pressure** | Can add load (more replicas) | Only reduces pressure or holds steady |
| **Default** | **Off**, opt-in per app+service | **On** (watcher); rung-2 redeploy stays ≥ 1 GB |
| **Min host** | Capacity guard must fund ≥ 2 replicas; otherwise `effective_max = 1` (permanent no-op) | Small VPS is fine — it's a watcher, not a hot loop |
| **Worst case on a tiny box** | Refuses to scale, raises `scale_refused_no_capacity` | Declines to act, raises a can't-fix alert |
| **Polls Docker itself?** | **No** — reads the poller's latest snapshot | **No** — reads the poller's latest snapshot |

The shared philosophy is **refuse rather than queue**. Queuing `docker compose` children *is* the OOM vector on a small host; so when a guard fails, the action is dropped (and re-evaluated next tick), never parked in a backlog. A dropped action that mattered becomes an alert.

---

# Part I — Auto-scaling

## 2. What auto-scaling is (and is not)

Auto-scaling is **opt-in, per app+service**. When you enable it for a service, Helmsman adjusts how many **container replicas** of that one service run, between a floor and a ceiling you declare, based on observed per-replica CPU and memory.

**It scales container replicas. It does not:**

- spin up or tear down **VMs / hosts** — Helmsman is a single-host tool;
- scale a **whole Compose project** — only the one opted-in service;
- touch **stateful** services (databases, brokers, coordination stores) — those are rejected outright (see §3);
- ever **queue** scaling work — if it can't act safely this tick, it skips and re-evaluates next tick.

Because replicas are added with internal-port-only networking and fronted by the managed edge as a load-balanced pool, the only services that *can* be scaled are **stateless, edge-fronted HTTP upstreams**. That constraint is enforced by the candidacy gate.

---

## 3. The candidacy gate (C1–C7)

Before a service is ever considered scalable, it must pass **all seven** candidacy conditions. The **default is NOT scalable**, and candidacy is **re-evaluated on every deploy and every config change** — a service that *gains* a host port or a read-write volume on redeploy **loses candidacy and is scaled back to 1**.

| # | Condition | Why |
|---|---|---|
| **C1** | **Edge HTTP upstream with a known internal port** | Replicas are load-balanced behind the managed edge; Helmsman must know the port to build the pool. |
| **C2** | **Publishes no fixed host port** | Two replicas can't both bind the same host port. Internal-port-only replicas have no such conflict. |
| **C3** | **No exclusive read-write volume** | A second replica writing the same RW volume corrupts state. Stateless replicas share nothing exclusive. |
| **C4** | **Not stateful / clustered** (denylist of DBs, brokers, coordination stores) | These need identity, quorum, or single-writer semantics; replica-count is the wrong knob. |
| **C5** | **No deploy-time *identity* placeholder** | A per-node cookie/name/seed or a host-bound port means each instance is unique — not horizontally cloneable. A *shared* auth secret or a public hostname is fine. |
| **C6** | **Honors a stateless restart contract** | A new replica must be able to start cold and serve without warm-up state or peer coordination. |
| **C7** | **Operator explicitly opts in** | Scaling is never inferred; you turn it on per service. |

**Stateful services are rejected with a clear, specific reason.** A database or a message broker is exactly the kind of app that belongs to the managed config-file / cert-binding workflow — it is **not** a scaling candidate, and Helmsman tells you precisely which condition (C3 RW volume, C4 stateful class, C5 identity placeholder, …) disqualified it. You will never see a vague "can't scale this" — you'll see *why*.

> **Candidacy is a moving target, on purpose.** Because it re-runs on every deploy, you cannot accidentally leave a service scaled-out after a change that makes it unsafe. Add a host port or an exclusive volume in a redeploy and Helmsman drops the service back to a single replica before the next scaling decision.

---

## 4. The controller

Auto-scaling runs as **one evaluator goroutine** over the **poller's latest snapshot**. This is the same pattern the alerting engine uses, and it matters:

- **It never polls Docker itself.** It reads the snapshot the poller already holds. No extra Docker API calls, no per-service goroutines, no scheduler library, no time-series database.
- **Signal:** per-replica **CPU mean** and **memory max**, aggregated across the running replicas of the service. (Memory uses the max so a single hot replica can't be hidden by quiet siblings.)

When the controller decides a change is warranted, the action is **serialized through a strict sequence** so it can never stampede the box:

```
1. §0 resource gate for the write plane ........... pass? ── no ──▶ skip this tick
2. TryAcquire the one-docker-child semaphore ...... got it? ─ no ─▶ skip this tick
3. Per-service rate limit ......................... due? ──── no ──▶ skip this tick
4. static-argv: docker compose up -d --no-deps \
       --no-recreate --scale <svc>=<N>
```

Two details to call out:

- The semaphore is acquired **non-blocking** (`TryAcquire`). If another docker child is already running, the controller **skips this tick** — it does not wait. Waiting would mean two queued children, which is the OOM vector.
- The scale command uses **static argv** — `--scale <svc>=<N>` — with `--no-recreate` so existing replicas are untouched. Replicas are internal-port-only, so adding one can never collide on a host port.

**Scale-down drains first.** When shedding a replica, Helmsman **deregisters it from the edge pool, waits the configured grace period, and *then* reduces the count** — so in-flight requests aren't cut off. The down step is always **1 replica at a time** and **requires all replicas to be healthy** before it proceeds.

---

## 5. Hysteresis: not flapping

A naive autoscaler oscillates: it scales up at a threshold, the per-replica load drops below that same threshold, it scales back down, load rises again, repeat. Helmsman uses **three** independent hysteresis mechanisms, and **all three apply**:

| Mechanism | What it prevents |
|---|---|
| **Time (`breach_for`)** | The breach must *persist* for a sustain window before any action — a momentary spike does nothing. |
| **≥ 20-point dead band** | The down-threshold and up-threshold are separated by at least 20 percentage points. There is no single line to oscillate around. |
| **Asymmetric cooldowns (up-eager, down-lazy)** | Scale-up cooldown is short (ramp fast under load); scale-down cooldown is long (shed slowly, one at a time, only when all-healthy). |

The asymmetry is deliberate: the cost of being **one replica short under load** (dropped requests) is worse than the cost of being **one replica heavy for a while** (a little idle capacity). So Helmsman **ramps fast and sheds slowly**.

```
   load
    ▲
    │            up-threshold ──────────────┐  ramp fast (short cooldown)
    │                                       ▼
    │   ░░░░░░░░░░░░░░░ ≥20pt dead band ░░░░░░░░░░░░
    │                                       ▲
    │          down-threshold ──────────────┘  shed slow (long cooldown,
    │                                            1 at a time, all-healthy)
    └──────────────────────────────────────────────────▶ time
```

---

## 6. The host-capacity guard

This is the **load-bearing safety math**. It runs **every tick on fresh data** and produces a hard ceiling on replicas that the controller may never exceed — no matter what the policy bounds say.

### 6.1 The ceiling

```
effective_max = min(budget_by_mem, budget_by_cpu)
```

Each budget is the **`min` of two numbers**:

1. **The declared-reservation budget** — what the policy says each replica reserves, summed against what the host has declared free for apps.
2. **The measured-free budget** — what the poller actually observes free *right now*.

Taking the `min` of *declared* and *measured* means a host that has declared generous reservations but is *actually* under pressure gets the conservative answer. You can't over-promise your way past reality.

### 6.2 What gets reserved before any replica is funded

The host's free capacity is **not** all available to scaling. Before a single new replica is funded, the guard subtracts:

- **The control plane's** headroom (Helmsman itself must never be starved);
- **The edge's memory-capped slice** (the proxy must keep serving);
- **A safety floor** (a deliberate cushion so the box never runs to zero);
- **All *other* apps' reservations** — not just this app's;
- **All desired-but-not-yet-materialized replicas** — replicas that other scaling decisions have *committed to* but Docker hasn't started yet.

That last point is the one that closes the dangerous multi-service over-commit bug. If two services scale up in the same window, each must reserve against the *other's intent*, not merely against what's currently running. Helmsman therefore:

- **reserves against *desired*, not just observed**, replica counts;
- applies a **post-scale settling freeze** so a just-scaled service isn't immediately re-evaluated against stale "free" memory;
- enforces a **global cross-app budget** so the sum of every app's desired replicas can never exceed the host's funded capacity.

> **Red-team note (TOCTOU over-commit).** Without reserving against *desired* counts, two services could each independently look at the same "free" memory, both decide there's room, and both scale — collectively OOMing the box. The desired-count reservation plus the global cross-app budget makes that arithmetically impossible.

### 6.3 The per-replica reservation is required and floored

A `per_replica_reservation` is **mandatory** for any scalable service. It is also **floored**: an implausibly small value (an attempt to claim a replica costs almost nothing) is **rejected**. And it's enforced at runtime — if a replica's actual resident memory exceeds its reservation, Helmsman **clamps the ceiling and alerts**, rather than letting reality drift past the budget.

### 6.4 What happens when there's no room

| Situation | Result |
|---|---|
| Budget can't fund even one *more* replica | Ceiling = current count. No scale-up. |
| Near-OOM box | **`effective_max = 1` — scaling is a permanent no-op.** |
| Wanted to scale up, but the guard refused | Fires **`scale_refused_no_capacity`** — a **first-class alert**, not a silent hold. |

The last row is the through-line of the whole feature. A refusal to scale on a constrained box is **information you need**, so it's surfaced as a Helmsman-originated infra alert (see [Alerting](./alerting.md)). You find out that your app wanted more capacity and the host couldn't give it — *before* the box falls over, not after.

---

## 7. Edge-pool reconciliation

Because only **edge-fronted HTTP** services scale, every count change is reconciled into the managed edge's upstream pool. After any scale action, Helmsman:

1. **Discovers the live replicas** via the **read-only** socket-proxy (the same read-only Docker access the poller uses — scaling never gets a write path to the socket it doesn't already need).
2. **Builds the upstream pool**, where **each pool member passes the same invariants** every edge upstream must pass:
   - the **upstream allowlist**,
   - the **pinned dialer**,
   - the **egress firewall**.
   A replica that mis-resolves to a control-plane port is **refused at dial** — it never becomes a live upstream.
3. **Updates the vhost** with **least-connections load balancing** plus **active and passive health checks**, so a sick replica is drained from rotation.
4. **Reloads the whole document.** Pool membership is Helmsman-managed Layer-1 state, recomputed from read-only discovery and re-rendered **declaratively as the entire config**, never patched incrementally.

> **The edge stays memory-capped.** Pool changes are **config reloads**, not new processes — the edge's footprint doesn't grow when you scale an upstream from 2 to 6 replicas. The replicas cost memory; the edge re-rendering its routing table does not. See [Managed edge & TLS](./edge-and-tls.md) for the upstream allowlist, pinned dialer, and egress-firewall invariants in full.

---

## 8. An example scaling policy

Auto-scaling is configured per app+service. A policy block looks like this (illustrative shape — see the [definition file](./architecture.md) for the authoritative schema):

```yaml
scaling:
  web:                          # the service name within this app's Compose project
    enabled: true               # C7 — explicit opt-in (default: false / NOT scalable)
    min_replicas: 1
    max_replicas: 6             # a hard upper bound; the host-capacity guard may lower it further

    # --- required, floored: what each replica is allowed to reserve ---
    per_replica_reservation:
      memory: 192Mi             # mandatory; an implausibly small value is rejected
      cpu: 0.25

    # --- signal thresholds (per-replica) ---
    cpu_target_percent:
      up: 75                    # scale up when sustained mean CPU >= 75%
      down: 40                  # scale down when <= 40%  (>= 20pt dead band enforced)
    memory_target_percent:
      up: 80                    # uses per-replica memory MAX, not mean
      down: 50

    # --- hysteresis ---
    breach_for: 90s             # the breach must persist this long before any action
    cooldown:
      up: 60s                   # up-eager
      down: 300s                # down-lazy
    drain_grace: 30s            # scale-down deregisters from the pool, waits, then reduces
```

Notes:

- `enabled: false` (the default) means the service is **not a candidate** regardless of the other fields.
- `max_replicas` is a *ceiling you want*; the **host-capacity guard can always lower it**, down to `effective_max = 1` on a near-OOM box. The policy can never raise the real ceiling above what the host can fund.
- If the service stops satisfying C1–C7 on a future deploy (gains a host port, an RW volume, an identity placeholder…), this policy is **automatically suspended** and the service is scaled back to 1.

---

# Part II — Self-healing

## 9. What the supervisor is

The supervisor is the answer to *"restart the apps that crash, and report what you can't fix."* It is a **bounded** supervisor: it restarts crashed or stuck services, and when it runs out of safe moves it **escalates to a Helmsman-originated alert** rather than thrashing.

It runs as **one goroutine at the tail of each poll tick**, over the latest snapshot. It is **a watcher, not a hot loop** — there are **no per-service timers as goroutines**; backoff "timers" are simply **deadlines stored in the FSM** and checked when the next tick arrives. That's why it's fine on a small VPS: it's nearly free when nothing is wrong.

The supervisor's FSM lives in SQLite (`supervisor_state`), so a restart of Helmsman itself doesn't lose or re-fire in-flight remediation.

---

## 10. The per-service state machine

There is one finite-state machine **per `(app, service)`**:

```
                           ┌───────────────────────────────────────────┐
                           │                                           │
   ┌─────────┐  suspect  ┌─▼───────┐  persists  ┌──────────┐  act   ┌──────────────┐
   │ HEALTHY │──────────▶│ SUSPECT │───────────▶│ DEGRADED │───────▶│ REMEDIATING  │
   └────▲────┘           └────┬────┘            └────┬─────┘        └──────┬───────┘
        │                     │ recovered            │ ladder              │
        │ stabilized          │                      │ exhausted           │ tried a rung
   ┌────┴──────┐              │                  ┌───▼──────────┐          │
   │ RECOVERED │◀─────────────┴──────────────────│ CIRCUIT_OPEN │◀─────────┘ (cap hit /
   └───────────┘   (held healthy a streak)       └──────────────┘            OOM short-circuit)
                                                       │ pages you, stops acting

        ┌────────────────┐
        │ WAITING_ON_EDGE │   the service is waiting on an edge-issued cert, NOT crashing.
        └────────────────┘   Startup deadline suspended; no remediation. (see §12)
```

| State | Meaning |
|---|---|
| `HEALTHY` | Nothing to do. |
| `SUSPECT` | A first sign of trouble (a crash, an unhealthy reading) — watching, not yet acting. |
| `DEGRADED` | The problem has persisted; the service qualifies for remediation. |
| `REMEDIATING` | A ladder rung is being applied (a restart/recreate/redeploy is in flight). |
| `CIRCUIT_OPEN` | The ladder is exhausted or short-circuited. Helmsman **stops acting and pages you.** Latched until you clear it. |
| `RECOVERED` | The service came back and **held healthy a stabilization streak**. From here it returns to `HEALTHY`. |
| `WAITING_ON_EDGE` | The service is blocked on its edge-issued cert, not failing — see §12. |

---

## 11. Detection (from already-polled data only)

The supervisor adds **zero** new probes. Every trigger comes from data the poller already collected:

| Trigger | How it's detected |
|---|---|
| **Crash-loop** | A recurring exit / a climbing `RestartCount`, **cross-checked against `OOMKilled` and exit code 137** (the at-memory-limit kill). |
| **Up-but-unhealthy** | The container is *running* but its health indicator has been failing for **N consecutive intervals**. |
| **Slow-start watchdog** | A service that never reaches healthy within its startup deadline. |

The OOM cross-check matters: a service that is being killed for exceeding its memory limit (`OOMKilled`, or exit-137 / at-limit) is a **different problem** from a service that crashed on a bug. Restarting an OOM-killer on a small box is futile, so it gets special handling (see §14).

---

## 12. `WAITING_ON_EDGE`: don't fix what the edge broke

A subtle failure mode: a service that needs an edge-issued TLS cert may sit "unhealthy" until that cert is issued. If the supervisor treated that as a crash and started restarting, it would be **"fixing" a service whose real fault is the edge it owns** — pointless churn, and it masks the actual problem.

So a service still waiting on its edge-issued cert is moved to **`WAITING_ON_EDGE`**:

- its **startup deadline is suspended** (the slow-start watchdog does not fire);
- **no remediation runs**;
- if the cert **never issues**, that surfaces as an **edge / cert / ACME alert** — the correct owner of the problem — **not** a restart of an innocent service.

### The `expected_down` lease

When the *write plane* is legitimately touching an app (a deploy, a redeploy), the supervisor must not race it by "rescuing" a container that's down on purpose. That's the `expected_down` flag — but it is a **bounded lease**, and it's handled carefully so it can't be abused as a silencer:

- it is **cross-checked against the actually-held write-plane lock** (you can't claim "expected down" without really holding the deploy lock);
- it is **cleared fail-closed on restart** of Helmsman.

> **Red-team note.** A *crashed* deploy must never leave a service silently crash-looping under a stale `expected_down`. Because the lease is bounded, lock-checked, and fail-closed, a deploy that dies mid-flight cannot leave a broken service un-paged — the lease evaporates and the supervisor sees the truth on the next tick.

---

## 13. The remediation ladder

When a service is `DEGRADED`, the supervisor climbs a **bounded ladder**. It applies **one rung per failure window** and **never retries the same rung** within that window — it always moves up, or it circuit-opens.

| Rung | Action | What it does | Availability |
|---|---|---|---|
| **1** | `restart` | `docker compose restart` the service. The cheapest move. | Always |
| **2** | `recreate` | `--force-recreate` — **re-runs the entrypoint and re-renders the host-side templates + cert-sync**, healing config/secret drift that a plain restart wouldn't fix. | Always |
| **3** | `redeploy` | A full redeploy of the service. | **Off by default; ≥ 1 GB.** On a small box it is **structurally unavailable** — the ladder tops out at `recreate`, then circuit-opens. |

The **recreate** rung is the interesting one. A plain `restart` reuses the existing container; `recreate` with `--force-recreate` rebuilds it, which means the **entrypoint runs again, templates are re-rendered, and cert-sync re-runs**. So if the real problem was drifted config or a stale secret, recreate fixes what restart can't.

On a host below 1 GB, **rung 3 simply does not exist** — there is no path by which self-healing can trigger a redeploy that might OOM the box. The ladder is `restart → recreate → CIRCUIT_OPEN`, and the circuit-open pages you.

---

## 14. Anti-flap and the circuit breaker

Bounding the ladder is not enough on its own — a service that restarts, comes up, and dies again would saw back and forth forever. Three mechanisms prevent that:

- **Exponential backoff** — each failed window waits longer than the last before the next attempt.
- **Per-window attempt cap** — a hard limit on how many actions happen in a window.
- **Recovery stabilization** — a recovered service must **hold healthy for a streak** before its attempt budget resets. This is what kills the classic `restart → up → dies` sawtooth: a flap that briefly looks healthy does *not* refill the budget.

### The latching circuit breaker

When the ladder is exhausted (or the cap is hit), the FSM **latches `CIRCUIT_OPEN`**: it **stops acting** and **pages you**. It stays latched until you explicitly clear it — Helmsman will not silently resume hammering a service it already gave up on. (You clear it from the supervisor view in the dashboard once you've addressed the underlying cause.)

### OOM short-circuit

`oom_killed_repeated` — repeated kills detected via `OOMKilled`, exit-137, or at-limit kills, **not just the `OOMKilled` flag** — **short-circuits the entire ladder**. There's no point restarting a process that the kernel is killing for using too much memory on a box that doesn't have it. The supervisor goes straight to circuit-open and pages you. Restarting it would, at best, waste cycles and, at worst, add the very memory pressure that's killing it.

---

## 15. The four tiny-box safety gates

This is the heart of "self-healing can never manufacture an OOM." **Before *every* action**, the supervisor checks **four gates in order**. **All four must pass**, or the action is **deferred** (dropped, re-checked next tick — never queued):

| # | Gate | What it guarantees |
|---|---|---|
| **1** | **§0 resource gate** for the relevant plane | A write-plane action below 1 GB simply isn't available. |
| **2** | **`TryAcquire` the one-docker-child semaphore** (non-blocking) | At most one docker child host-wide. If another is running, **defer** — **never queue** a second docker child. Queuing children *is* the OOM vector. |
| **3** | **Memory-headroom floor** | A restart momentarily runs the **old and new container together**. If that overlap would drop the host below the headroom floor, **don't restart — page instead.** |
| **4** | **Edge protection** | The **edge slice and the control plane are never remediation targets.** Self-healing never restarts the thing that's keeping your sites up or the thing doing the healing. |

The combination is what makes the worst case safe. The most aggressive thing self-healing can do is restart a service — and gate 3 ensures it only does so when there's room for the brief old+new overlap. If there isn't, it **declines and pages you**. Self-healing can therefore only **reduce pressure or hold steady**; it can **never add net memory pressure** and can **never manufacture an OOM**. The worst case is always: *it didn't fix it, and it told you.*

---

## 16. An example self-healing policy

Self-healing is on by default; you tune it per app+service. An illustrative block:

```yaml
self_healing:
  enabled: true                 # on by default (watcher)
  defaults:
    unhealthy_intervals: 3      # N consecutive bad health readings before SUSPECT -> DEGRADED
    slow_start_deadline: 120s   # slow-start watchdog (suspended in WAITING_ON_EDGE)
    ladder:
      restart: true             # rung 1 — always available
      recreate: true            # rung 2 — re-runs entrypoint + template render + cert-sync
      redeploy: false           # rung 3 — OFF by default; requires >= 1 GB; absent on a small box
    anti_flap:
      backoff_base: 15s
      backoff_max: 10m
      attempts_per_window: 3    # per-window cap
      window: 30m
      stabilize_for: 5m         # must hold healthy this long before the budget resets
    memory_headroom_floor: 128Mi  # gate 3 — below this, page instead of restart
  overrides:
    worker:
      unhealthy_intervals: 5    # a noisier service tolerates more bad readings before acting
```

Notes:

- On a host **below 1 GB**, `redeploy` is **structurally unavailable** regardless of this setting — the ladder ends at `recreate`.
- `memory_headroom_floor` is the gate-3 cushion: if a restart's brief old+new overlap would cross it, the supervisor **pages instead of restarting**.
- `stabilize_for` is what prevents flap: a service that bounces up for a few seconds and dies again does **not** get its attempt budget back.

---

## 17. How both features alert

Auto-scaling and self-healing both raise **Helmsman-originated infra alerts**. These are categorically different from app-domain alerts: they are about *the platform*, and they are **never deferred** to an app's own alerting (an app that is crash-looping or OOM-killed cannot be trusted to report its own death). Internally these events carry `origin: "helmsman_infra"` and `defer_to_app: false` (hard-set), and they route straight to the rate-limited notifier.

The relevant **can't-fix taxonomy** entries these two features emit:

| Alert kind | Raised when |
|---|---|
| `scale_refused_no_capacity` | Auto-scaling wanted to scale up but the host-capacity guard refused (a first-class alert, not a silent hold). |
| `crashloop_capped` | The supervisor's ladder/attempt cap was reached on a crash-looping service. |
| `unhealthy_capped` | An up-but-unhealthy service exhausted remediation. |
| `stuck_startup` | The slow-start watchdog gave up (and it wasn't a `WAITING_ON_EDGE` cert wait). |
| `oom_killed_repeated` | Repeated OOM/exit-137 kills short-circuited the ladder. |
| `redeploy_failed` | The rung-3 redeploy (≥ 1 GB hosts) failed. |
| `low_headroom` | The host is too tight for safe remediation. |

WARNING-level infra is quiet-hours-suppressed, but **CRITICAL infra always pages**. See **[Alerting](./alerting.md)** for the full taxonomy, dedupe behavior, the `host_degraded` coalescing rules, channels, and the dead-man's-switch.

---

## 18. Tuning on a small box

A short, practical note for the operator of a constrained host (say, a 512 MB–1 GB VPS):

- **Leave auto-scaling off, or accept it's a no-op.** Below the capacity threshold, the guard sets `effective_max = 1` — scaling becomes a **permanent no-op**, and any wanted scale-up fires `scale_refused_no_capacity`. That alert is *useful information* (your app wants more than this box can give); it's not an error to suppress. If you don't want the noise, don't opt the service in.
- **Keep self-healing on — it's a watcher.** The supervisor is nearly free when nothing's wrong, and on a small box its most aggressive move (a restart) is still guarded by the memory-headroom floor. It will rescue genuine crashes and **page you for the rest**.
- **Expect the ladder to top out at `recreate`.** Rung-3 redeploy is structurally unavailable below 1 GB. If `recreate` doesn't fix a service, you'll get a `CIRCUIT_OPEN` page — that's the intended outcome, not a regression.
- **Set realistic `per_replica_reservation` values *if* you ever scale.** They're floored against implausibly-small claims, and they're what the capacity guard does its arithmetic against. An honest reservation gives you an honest ceiling.
- **Raise the memory-headroom floor if restarts feel risky.** A higher gate-3 floor makes the supervisor more likely to *page instead of restart* — the safe direction on a tight box.
- **Treat refusals as your early-warning system.** A `scale_refused_no_capacity` or `low_headroom` page is the box telling you it's near its limit *before* it falls over. On a small host, that's the most valuable signal these features produce.

> **The whole point on a constrained host:** both features are **conservative by construction**. They will **refuse and alert** rather than push the box past its limits. You can run them on a tiny VPS precisely because the worst they can do is decline and tell you.

---

## 19. Security trade-offs, stated honestly

- **Auto-scaling is off by default — and that's the safe default.** A convenience feature that adds load is exactly the kind of thing that should be opt-in on a single host. You turn it on, per service, with eyes open.
- **A refusal is a feature, not a bug.** `scale_refused_no_capacity` looks like "it didn't do what I asked." It is in fact the capacity guard correctly preventing an over-commit OOM. The alternative — silently scaling and crashing the box — is strictly worse.
- **Self-healing can decline to heal.** On a tight box, the memory-headroom floor (gate 3) and the OOM short-circuit mean the supervisor will sometimes **page instead of restart**. This is intentional: a restart that OOMs the host is not "healing." A page that tells you the truth is.
- **Neither feature gets new powers.** Both read the **read-only** poller snapshot / socket-proxy; both go through the **same** §0 gate and one-docker-child semaphore as a manual deploy; scaled replicas pass the **same** edge upstream allowlist, pinned dialer, and egress firewall as any other upstream. There is **no new trust path** here — only new front-ends onto the existing, gated write plane. See [Security model](./security.md) and [Managed edge & TLS](./edge-and-tls.md).
- **The circuit breaker latches on purpose.** Helmsman would rather **stop and page** than keep hammering a service it has already failed to fix. Auto-clearing a circuit breaker would re-introduce exactly the flap the breaker exists to stop.

---

*Related: [Alerting](./alerting.md) · [Managed edge & TLS](./edge-and-tls.md) · [Architecture](./architecture.md) · [Security model](./security.md) · [Helmsman README](../README.md)*
