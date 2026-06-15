# Introduction

> **Getting started, 1 of 3** · Next: [Install it →](./installation.md)

Helmsman turns a plain Linux server into a place you can confidently run your apps — with a dashboard, automatic HTTPS, and live health monitoring — without becoming a full-time sysadmin.

You install one small program on a server that has Docker. From then on, you manage everything from a web dashboard: deploy apps, set secrets, point domains at them, watch their health. Helmsman handles the parts people usually get wrong — TLS certificates, reverse proxying, safe deploys — so you don't have to.

## What you get

- **Your apps online, over HTTPS, automatically.** Give an app a domain name and Helmsman issues the certificate, renews it, and routes traffic to it. No proxy config, no `certbot`.
- **A real dashboard.** See every app's health at a glance, view logs, restart a service, roll back a change — all in the browser.
- **Safe deploys.** Deploy from a guided form or straight from a Git repo. Helmsman checks every change before it goes live and can roll back automatically if something fails.
- **Secrets done right.** Store passwords and API keys encrypted, never in plain text in your files or your repo.
- **Peace of mind.** It's locked down by default and won't run anything dangerous on your behalf.

## How it feels to use

1. Install Helmsman on your server (a one-time setup over SSH).
2. Open the dashboard in your browser.
3. Add an app — fill in a short form, or connect a Git repo.
4. Give it a domain. It's live over HTTPS in moments.

After step 1, you don't touch the command line again for day-to-day work. No editing config files on the server, no Docker commands, no certificate wrangling.

## Who it's for

Helmsman is for solo developers and small teams who want to run real apps on their own server (a cheap VPS is fine) and would rather not assemble and babysit a stack of DevOps tools. If you've been doing `docker compose up` over SSH and hand-rolling Nginx and Let's Encrypt, this replaces all of that with something you manage from a browser.

It's **not** trying to be Kubernetes. If you're running a large fleet that needs a full orchestrator, this isn't it. For everyone between "one SSH session" and "we hired a platform team," it's built for you.

## What makes it different

Most self-hosting tools hand you a lot of rope. Helmsman deliberately doesn't:

- **You configure apps through the tool**, not by pasting raw Docker or proxy config. That keeps things simple — and means a typo or a bad snippet can't quietly weaken your server.
- **It's secure by default.** Fresh install, zero tuning: the dashboard is private, traffic is HTTPS, secrets are encrypted, and a risky setting makes it refuse to start rather than run unsafe.
- **Nothing happens behind your back.** A push to your repo never deploys itself unless you explicitly ask it to. You stay in control of what ships and when.

---

> **Next: [Install it →](./installation.md)**
