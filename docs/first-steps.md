# Deploy your first app

> **Getting started, 3 of 3** · [← Install it](./installation.md)

Helmsman is running. Let's get you signed in and ship a real app, online with HTTPS. Everything here happens in the browser.

## 1. Sign in

For safety, the dashboard isn't exposed to the internet. The quickest way to reach it the first time is an SSH tunnel from your computer:

```bash
ssh -L 9000:127.0.0.1:9000 operator@your-server
```

Now open **http://127.0.0.1:9000** and sign in with the username and password you set during install (and your two-factor code if you turned that on).

You'll land on the **Overview**: your server's CPU, memory, and disk, and a tile for each app once you have some.

> **This is your home base from now on.** You used SSH once to install; everything day-to-day — apps, secrets, domains, deploys — is here in the dashboard. Later you can put the dashboard on its own domain so you don't need the tunnel.

## 2. Add an app

Click **New app** and fill in the form: the image to run, which port it listens on, any volumes, and environment values. Helmsman builds everything it needs from that — you don't write or paste Docker config.

Hit **Validate** to preview, then **Deploy**. You'll watch the deploy happen live, and when it's done the app shows up on your Overview with its health, logs, and controls.

> **One thing to know:** your app should listen on an internal port (like `8080`), not try to grab ports 80 or 443. Those belong to Helmsman, which routes public traffic to your app for you. (Got an app in a Git repo instead? Skip to step 5.)

## 3. Add a secret

Don't put passwords or API keys directly in your app's settings. Open your app → **Env**, and add them as secrets. They're encrypted immediately, hidden from view, and injected into your app when it runs. Regular (non-secret) settings go right next to them.

That's all — no files, no SSH.

## 4. Put it online with HTTPS

Open **Edge** and add a route:

- **Domain** — the public address, like `app.example.com` (point its DNS at your server first).
- **App** — which app and port to send traffic to, like `web:8080`.

Save it. Helmsman gets a TLS certificate for that domain, sets up the routing, and within moments **https://app.example.com** is live and secure. You never touched a web-server config or a certificate.

## 5. Deploy from a Git repo

Prefer to ship from a repository? Click **Connect repo** and give it:

- the **repo URL** and **branch**,
- the **path to your compose file** in the repo,
- for a private repo, a **key or token** (the form tells you what it needs).

That's the whole setup — **no webhook to configure, no file to add to your repo.** Helmsman watches the repo for you. When you push a new commit, an **"update available"** appears in the dashboard with a summary of what changed, and you click **Deploy** to ship it.

> **It watches; you decide.** Helmsman never deploys a push on its own — it just tells you there's something new. (If you really want push-to-deploy, it's an opt-in you can turn on. See [Deploy from a Git repo](./gitops.md).)

## You did it

You've deployed an app, secured its secrets, and put it online with HTTPS — all from the browser. Where to next:

- **Ship from Git** → [Deploy from a Git repo](./gitops.md)
- **Templated config files & certificates inside your app** → [Secrets & config files](./config-files-and-secrets.md)
- **Keep apps healthy under load** → [Scaling & self-healing](./scaling-and-self-healing.md) · [Alerts](./alerting.md)
- **Protect your data** → [Backups & recovery](./backup-and-recovery.md)
- **Run several apps on one server** → [Running many apps](./host-file.md)

[← Back to the docs home](./README.md)

---

### Optional: describe an app in a file

Everything you set in the dashboard is saved to a small per-app file (`helmsman.yaml`) that Helmsman manages for you — you never have to open it. But if you like keeping your setup in version control, you can write that file yourself and let the dashboard manage it from there. It looks like this:

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
  env:
    - LOG_LEVEL: "info"
    - DATABASE_URL: "secret: DATABASE_URL"   # the value is set separately, never in the file
  secrets:
    - name: DATABASE_URL
  edge:
    routes:
      - hostname: "app.example.com"
        upstream: "web:8080"
```

Full details — every field, how edits merge, and how to roll back — are in [The `helmsman.yaml` file](./definition-file.md).
