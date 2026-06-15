# Introduction

> **Getting started · Page 1 of 3** — [Documentation home](./README.md) · Next: [Installation →](./installation.md)

Helmsman is a **single static Go binary** that turns a plain Docker host into a managed, internet-facing application platform — with a dashboard, a CLI, automatic HTTPS, monitoring, and lifecycle automation — while holding to one overriding rule:

> **Hosting Helmsman must never become the thing that gets your server hacked.**

Every design decision in this project is subordinate to that requirement. If a feature would widen the attack surface, it is off by default, gated, or simply not expressible.

---

## What Helmsman is

You give Helmsman SSH access to a Linux host running Docker. In return it:

- **Owns the public edge.** It supervises a child Caddy that takes `:80`/`:443`, runs ACME/Let's Encrypt, terminates TLS, and reverse-proxies the admin UI and each of your apps. You never run a separate proxy or `certbot`.
- **Monitors your apps and the host.** A read-only plane polls Docker over a loopback socket-proxy and samples host CPU/memory/disk, surfaced as live health on the dashboard.
- **Deploys and runs apps safely.** A guided form, an importer for existing compose, or a connected git repo — all converging on one validated, gated write path.
- **Manages secrets and config by reference.** Plaintext credentials stay out of your YAML, your repo, your logs, and your browser.
- **Gives you a CLI that is a second front door, not a back door** — the same engine, the same validation chokepoint, minus the web-transport gates.

Helmsman is **generic**: it isn't tied to any framework or project. You point it at a host and it manages whatever you deploy.

---

## What Helmsman is not

- **Not a PaaS that hides your containers.** You still write (or paste, or commit) compose. Helmsman manages *how it's run safely*, not *what* it is.
- **Not a Kubernetes.** It targets the single-host / small-fleet operator who wants safety and ergonomics without an orchestrator.
- **Not a place you paste raw proxy config to the internet.** The operator never hand-authors Caddy; edge config is derived from typed structs. (See [Edge & TLS](./edge-and-tls.md).)

---

## The mental model

Two ideas explain almost everything in these docs.

### 1. The read plane vs the write plane

| | Read plane | Write plane |
|---|---|---|
| **Does** | Observe, report, validate, `git fetch` | `docker compose up/pull/build`, deploy, redeploy |
| **Mutates Docker?** | Never | Yes |
| **Host needs** | A small VPS is fine | **≥ 1 GB RAM** (the [resource gate](./architecture.md)) |
| **Posture** | Always on | Gated, one-docker-child-at-a-time, fail-closed |

A read-plane action can never harm a running app or OOM the box. The write plane is where care concentrates — so that's where the gates are.

### 2. One chokepoint

Every privileged thing — a deploy from the dashboard, a `helmsman apply` from the CLI, an edge route, a config-file render — is forced through **the same typed validation** (the "§5.6 chokepoint") and the **same edge-conflict gate**. There is no second path that skips it. This is why the CLI and the dashboard can both be trusted: they are thin front-ends on one reconciler.

---

## Who it's for

- **Solo operators and small teams** running real apps on one or a few VPSes, who want HTTPS, monitoring, and safe deploys without standing up a platform team.
- **People who care about the blast radius of their tooling.** Helmsman assumes the things it touches (a pasted compose, a connected repo, a restored backup, an inbound request) may be hostile, and is built to fail closed.

If you run a fleet large enough to need a real orchestrator, Helmsman is probably not your tool. For everyone between "a `docker compose up` in an SSH session" and "we adopted Kubernetes," it's built for you.

---

## The security-first pitch, in five points

1. **Fail-closed by default.** Bad config, empty allowlist, wrong-length key, insecure file perms → Helmsman refuses to boot rather than run insecure.
2. **Loopback admin + IP-allowlisted edge.** The dashboard binds `127.0.0.1`; reach it over an SSH tunnel or behind the edge's IP allowlist.
3. **Secrets by reference.** The definition file is never secret-bearing and is safe to commit; values arrive out-of-band and are stored encrypted (AES-256-GCM), shown only via an audited reveal.
4. **A CI push can't deploy itself.** Git is auto-*fetch*, manual-*deploy*, sha-pinned — closing the "a push triggers a surprise on-box build" vector.
5. **An assurance program gates releases.** Static-analysis gates, fuzz targets for every untrusted-input parser, and an authz route-posture gate regenerated from the route table. See [Security model](./security.md).

---

## Where to go next

You now have the model. Time to run it.

> **Next: [Installation →](./installation.md)** — get the binary on a host, generate the root of trust over SSH, and boot Helmsman.

See also: [Architecture](./architecture.md) · [Security model](./security.md) · [CLI reference](./cli.md)
