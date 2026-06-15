# Introduction

> **Getting started, 1 of 3** · Next: [Install it →](./installation.md)

Helmsman is a self-hosting platform for Docker apps. You install it on a Linux server, open its dashboard in your browser, and from there you deploy apps, give them domains, manage their settings, and watch their health. It runs the web server and HTTPS certificates for you, so a plain server becomes a place you can ship to in minutes.

Think of it as your own small Heroku or Netlify, running on a server you own.

## Philosophy

Running apps on your own server usually means stitching together a reverse proxy, TLS certificates, a process manager, log access, and a deploy script — and maintaining all of it. Helmsman replaces that with a single program and a dashboard. You describe *what* you want to run; it handles *how* to run it.

It's designed for a specific person: a developer or small team who wants the control of their own server without the operational overhead. It's not an orchestrator for large clusters — if you need Kubernetes, use Kubernetes. For one server, or a handful, Helmsman is meant to be all you need.

## A quick look

Here's the shape of using Helmsman. Deploy an app from the dashboard, or describe it in a small file:

```yaml
apiVersion: helmsman/v1
kind: App
metadata:
  slug: my-app
spec:
  compose:
    inline: |
      services:
        web:
          image: ghcr.io/example/web:1.4.2
          expose: ["8080"]
  edge:
    routes:
      - hostname: "app.example.com"
        upstream: "web:8080"
```

That's a running app with a public HTTPS address. Helmsman pulls the image, starts it, points `app.example.com` at it, and issues the certificate.

## What's included

- **A dashboard** to deploy apps, view logs, restart services, and roll back changes.
- **Automatic HTTPS** — give an app a domain and Helmsman issues and renews the certificate and routes traffic to it.
- **Git deploys** — connect a repository and Helmsman watches it for new commits.
- **Secrets management** — store credentials encrypted and inject them into your apps at runtime.
- **Health monitoring** — live CPU, memory, and disk for your server and each app.
- **Scaling and self-healing** — optional automation to keep apps responsive and running.

## How you'll work

1. Install Helmsman on your server (a one-time setup over SSH).
2. Open the dashboard.
3. Add an app — from a form, or by connecting a Git repo.
4. Give it a domain.

From step 2 on, you work entirely in the dashboard.

---

Ready to set it up?

> **Next: [Install it →](./installation.md)**
