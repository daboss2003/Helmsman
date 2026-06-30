<p align="center"><img src="./assets/logo.svg" width="80" height="80" alt="Mooring"></p>

# Introduction

> **Getting started, 1 of 3** · Next: [Install it →](./installation.md)

Mooring is a self-hosting platform for Docker apps. You install it on a Linux server, open its dashboard in your browser, and from there you connect your apps' repos, give them domains, manage their secrets, and watch their health. Each app is defined by a `mooring.yaml` in its own Git repo — you describe what to run, Mooring runs it. It manages the web server and HTTPS certificates for you, so a plain server becomes a place you can ship to in minutes.

Think of it as your own small Heroku or Netlify, running on a server you own.

## Philosophy

Running apps on your own server usually means stitching together a reverse proxy, TLS certificates, a process manager, log access, and a deploy script — and maintaining all of it. Mooring replaces that with a single program, a dashboard, and one file in your repo. You describe *what* you want to run in a `mooring.yaml`; it handles *how* to run it — including generating and owning the Docker Compose file and Dockerfile so you never write either.

It's designed for a specific person: a developer or small team who wants the control of their own server without the operational overhead. It's not an orchestrator for large clusters — if you need Kubernetes, use Kubernetes. For one server, or a handful, Mooring is meant to be all you need.

## A quick look

You define an app in a `mooring.yaml` at the root of its Git repo, then connect that repo in the dashboard. Here's the whole file for a small web app:

```yaml
apiVersion: mooring/v1
kind: App
metadata:
  slug: my-app
spec:
  compose:
    source: generated
    services:
      web:
        image: ghcr.io/example/web:1.4.2
        ports: [{ internal: 8080 }]
  edge:
    routes:
      - hostname: app.example.com
        service: web
        port: 8080
```

That's a running app with a public HTTPS address. Mooring reads the file, pulls the image, starts it, points `app.example.com` at it, and issues the certificate. The `mooring.yaml` is the single source of truth — to change the app, edit the file and deploy again. See [The `mooring.yaml` file](./definition-file.md) for the full reference.

## What's included

- **A dashboard** to deploy your connected repos, view logs, restart services, and roll back changes.
- **Automatic HTTPS** — declare a domain in `mooring.yaml` and Mooring issues and renews the certificate and routes traffic to it.
- **Git deploys** — connect a repository and Mooring watches it for new commits (fetch-only — it never pushes to your repo).
- **Secrets management** — store credentials encrypted and inject them into your apps at runtime.
- **Health monitoring** — live CPU, memory, and disk for your server and each app.
- **Scaling and self-healing** — optional automation to keep apps responsive and running.

## How you'll work

1. Install Mooring on your server (a one-time setup over SSH).
2. Open the dashboard.
3. Add an app by connecting its Git repo — the `mooring.yaml` in the repo defines it (Mooring scaffolds a starter for the first deploy if the repo has none).
4. Give it a domain (an edge route in the file) and deploy.

---

Ready to set it up?

> **Next: [Install it →](./installation.md)**
