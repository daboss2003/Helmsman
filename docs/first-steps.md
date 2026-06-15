# Deploy your first app

> **Getting started, 3 of 3** · [← Install it](./installation.md)

Helmsman is running. This guide walks through signing in and deploying an app with a public HTTPS address. It all happens in the dashboard.

## Sign in

The dashboard listens on the server's loopback interface. To reach it the first time, forward the port over SSH:

```bash
ssh -L 9000:127.0.0.1:9000 operator@your-server
```

Open **http://127.0.0.1:9000** and sign in with the username and password you set during installation.

You'll arrive at the **Overview** — your server's CPU, memory, and disk, with a tile for each app once you've added some. From here, everything is in the dashboard. (Later, set `admin.hostname` to serve the dashboard on its own domain and skip the tunnel.)

## Add an app

Click **New app** and fill in the form: the image to run, the port it listens on, volumes, and environment values. Helmsman generates the Compose definition from your input.

Click **Validate** to preview, then **Deploy**. The deploy runs live in the page, and the app then appears on your Overview with its health, logs, and controls.

Your app should listen on an internal port such as `8080`. Helmsman owns ports 80 and 443 and routes public traffic to your app.

## Add a secret

Open your app and go to **Env**. Add non-secret values as plain settings, and passwords or API keys as **secrets** — these are encrypted and injected into the app at runtime. Reference a secret from your config by name, and Helmsman supplies the value when the app runs.

## Give it a domain

Open **Edge** and add a route:

- **Domain** — the public address, e.g. `app.example.com` (point its DNS at your server).
- **App** — the app and port to route to, e.g. `web:8080`.

Save it. Helmsman issues a TLS certificate for the domain and configures the routing. Within moments, `https://app.example.com` is live.

## Deploy from a Git repo

To deploy from a repository, you have two options.

**Connect with GitHub.** If GitHub is configured (see [Deploy from a Git repo](./gitops.md)), click **Connect with GitHub**, authorize, and choose a repo from the list. Helmsman creates a deploy key for it.

**Connect any repo.** Click **Connect repo** and provide the URL, branch, the path to your Compose file, and — for a private repo — a key or token.

Once connected, Helmsman watches the repository. When you push a commit, an **update available** notice appears with a summary of the changes. Click **Deploy** to release it.

## Next steps

You've deployed an app, added a secret, and put it online. From here:

- [Deploy from a Git repo](./gitops.md)
- [Secrets & config files](./config-files-and-secrets.md)
- [Scaling & self-healing](./scaling-and-self-healing.md) · [Alerts](./alerting.md)
- [Backups & recovery](./backup-and-recovery.md)
- [Running many apps on one server](./host-file.md)

[← Back to the docs home](./README.md)

---

### Describing an app in a file

What you configure in the dashboard is saved to a per-app `helmsman.yaml`. You can also write this file yourself and keep it in version control — the dashboard keeps it in sync. A minimal example:

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
    - DATABASE_URL: "secret: DATABASE_URL"
  secrets:
    - name: DATABASE_URL
  edge:
    routes:
      - hostname: "app.example.com"
        upstream: "web:8080"
```

See [The `helmsman.yaml` file](./definition-file.md) for the full reference.
