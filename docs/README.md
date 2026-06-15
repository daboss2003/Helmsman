# Helmsman Documentation

Helmsman is a **security-first, self-hosted ops dashboard**: a single static Go binary you point at a Docker host. It owns the public edge (Caddy + automatic HTTPS), monitors your apps, and gives you a safe dashboard + CLI to run them — without ever asking you to hand-edit a proxy config, run `certbot`, or paste raw Docker into a browser.

> **The one rule everything else is subordinate to:** *hosting Helmsman must never become the thing that gets your server hacked.* If you read nothing else, read [The security model](./security.md).

---

## Start here

New to Helmsman? Read these three pages in order — they take you from zero to a deployed app.

| # | Page | What you'll do |
|---|------|----------------|
| 1 | [**Introduction**](./introduction.md) | Understand what Helmsman is, who it's for, and the mental model (read vs write plane, the single chokepoint). |
| 2 | [**Installation**](./installation.md) | Put the binary on the host, generate the master key + credentials over SSH, write `config.yaml`, and boot it. |
| 3 | [**First steps**](./first-steps.md) | Log in over an SSH tunnel, deploy your first app, set a secret, and put it online with HTTPS. |

---

## Core concepts

The "how it's built and why it's safe" pages. Read these once and the rest of the docs click into place.

- [**Architecture**](./architecture.md) — the processes that make up a running install, the read-plane / write-plane split, and the single reconciler the dashboard and CLI share.
- [**Security model**](./security.md) — the request pipeline, the §5.6 validation chokepoint, the secrets architecture, the secure-by-default baseline, and the threat model. The long, load-bearing page.
- [**The definition file (`helmsman.yaml`)**](./definition-file.md) — the declarative source of truth for an app's managed surface; complementary to `docker-compose.yml`.
- [**The host definition (`kind: Host`) & 3-tier config**](./host-file.md) — server-wide defaults and multi-app coordination, and the Tier-1/2/3 boundary that decides what the dashboard may write.

---

## Guides

Task-focused pages for the things you'll actually do.

- [**Git integration & GitOps**](./gitops.md) — connect a repo, auto-fetch new commits, and deploy manually and sha-pinned (a CI push can't trigger a surprise build).
- [**Edge & TLS**](./edge-and-tls.md) — the managed edge: how one hostname per app becomes a full HTTPS vhost with ACME, and why you never touch Caddy.
- [**Config files & secrets**](./config-files-and-secrets.md) — the three kinds of config input, selective host-side templating (`{{hm.KEY}}`), and the secret-by-reference model.
- [**Env import-and-own**](./env-import.md) — bring your existing `.env`; Helmsman classifies it, hard-stops on literal secrets, and writes the live file it owns.
- [**Scaling & self-healing**](./scaling-and-self-healing.md) — the two opt-in lifecycle automations, both conservative by construction (they decline-and-alert rather than push a small box over).
- [**Alerting**](./alerting.md) — the optional, pluggable, read-and-notify alert engine (zero runtime surface until configured).
- [**Backup & recovery**](./backup-and-recovery.md) — protecting app *data* (volumes) and recovering Helmsman itself onto a fresh box.

---

## Reference

- [**CLI reference**](./cli.md) — every `helmsman` command, the plane it touches (read vs write), and the trust/parity guarantees.
- [**Definition file reference**](./definition-file.md) — the full `helmsman.yaml` schema, the 3-way merge, conflict review, and rollback.
- [**Configuration / root of trust**](./architecture.md) — `config.yaml` (Tier-1, SSH-only), what's hot-reloadable, and what is deliberately not.

---

## How the docs are organized

Helmsman has **two front doors onto the same engine**: the **dashboard** (a server-rendered web UI, loopback-only) and the **CLI** (operator commands over SSH). They produce the *same* typed reconcile request through the *same* validation chokepoint — so anything you read here applies to both unless a page says otherwise.

A page will tell you which **plane** an action touches:

- **Read plane** — observes and reports. Never mutates Docker. Safe on a tiny VPS. (monitoring, `validate`, `plan`, log streaming, git *fetch*.)
- **Write plane** — mutates live state (`docker compose up/pull/build`, deploys). Gated behind the [resource gate](./architecture.md) (≥ 1 GB RAM) and fail-closed everywhere.

---

*Looking for the project overview, license, and quickstart-in-one-page? See the [top-level README](../README.md). To contribute, see [CONTRIBUTING](../CONTRIBUTING.md).*
