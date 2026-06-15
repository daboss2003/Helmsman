# Helmsman docs

**Run your apps on your own server — with automatic HTTPS, live monitoring, and one clean dashboard — without the DevOps grind.**

Helmsman is a single small program you install on a Linux server with Docker. It takes over the boring, error-prone parts of self-hosting: it puts your apps online over HTTPS, renews certificates, watches their health, and gives you a dashboard to deploy and manage everything. You configure your apps *in the tool* — you never hand-edit a web-server config or run `certbot`.

It's built for people who want their own server without the stress.

## New here? Start with these

1. **[Introduction](./introduction.md)** — what Helmsman does for you, in two minutes.
2. **[Install it](./installation.md)** — get it running on your server.
3. **[Deploy your first app](./first-steps.md)** — log in, ship an app, put it online with HTTPS.

That's the whole on-ramp. After that, you live in the dashboard.

## Guides

- **[Deploy from a Git repo](./gitops.md)** — connect a repo and Helmsman watches it for new commits. You click Deploy.
- **[Domains, HTTPS & the edge](./edge-and-tls.md)** — how one hostname becomes a live HTTPS site, automatically.
- **[Secrets & config files](./config-files-and-secrets.md)** — keep passwords and API keys safe, and template config files at deploy.
- **[Import an existing `.env`](./env-import.md)** — bring what you already have.
- **[Scaling & self-healing](./scaling-and-self-healing.md)** — keep apps healthy under load, safely.
- **[Alerts](./alerting.md)** — get told when something needs you (off until you turn it on).
- **[Backups & recovery](./backup-and-recovery.md)** — protect your data and recover onto a fresh server.

## Reference

- **[The `helmsman.yaml` file](./definition-file.md)** — the optional config file that describes an app. The dashboard writes it for you; you can also write it yourself.
- **[Running many apps on one server](./host-file.md)** — server-wide settings and coordination.
- **[Command-line reference](./cli.md)** — for installation and the occasional power-user task. You rarely need it.
- **[How it works & why it's safe](./architecture.md)** · **[Security](./security.md)** — the engineering details, if you're curious or evaluating.

---

A quick promise that shapes everything here: **hosting Helmsman should never be the thing that gets your server hacked.** It's secure by default, refuses to start if its setup is unsafe, and never does anything risky behind your back. If that matters to you, the [Security](./security.md) page is worth a read.
