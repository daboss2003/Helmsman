# Deploy from a Git repo

Connect a repository and Helmsman watches it for new commits, shows you what changed, and deploys exactly the commit you reviewed when you click **Deploy**. A push never deploys itself unless you ask it to.

See also: [Deploy your first app](./first-steps.md) · [Secrets & config files](./config-files-and-secrets.md)

---

## Connecting a repository

In the dashboard, click **Connect repo**. Two ways in:

**Connect with GitHub (one click).** If GitHub is set up (see below), click **Connect with GitHub**, authorize, and pick a repo. Helmsman creates a read-only deploy key for it automatically — you copy nothing.

**Connect any repo.** Provide:

- the **repository URL** and **branch**,
- for a **private** repo, a deploy key or access token.

Credentials are stored encrypted and never appear in the UI or logs.

Your repo carries a **`helmsman.yaml`** (see [the definition file](./definition-file.md)) describing the app — its services, build, env, and routes. Helmsman reads it, **generates the `docker-compose.yml` and any Dockerfiles**, and deploys — you never commit a compose file. If the repo has no `helmsman.yaml`, Helmsman scaffolds a sensible default from the stack it detects (e.g. a Node or Go project).

## How updates work

Once connected, **Helmsman checks the repo for new commits on its own** — no webhook to set up, no file to add to your repo. When a new commit lands, the app shows **"update available"** with a summary of what changed (the commits and files).

Click **Deploy** to ship it. Helmsman deploys **exactly the commit you reviewed**, brings the app up, and **rolls back automatically** if anything fails — so a deploy either fully succeeds or leaves the previous version running. There's never a half-deploy.

You'll find this on the app's page (a **Repository & updates** panel) and on the dedicated **Repository** page (with the full diff and history).

> **Want instant deploys?** By default Helmsman checks every couple of minutes. If you want a push to be picked up immediately, you can add an optional **webhook** — but it's not required. And if you want truly hands-off releases, turn on **auto-deploy** (off by default): Helmsman then deploys a new commit for you, through the same checks, when it's a clean fast-forward. The background check on its own only ever *fetches* — it never deploys.

## Why this is safe

- **Nothing deploys until you click** (unless you explicitly turn on auto-deploy). A push to your repo can't trigger a surprise build on your server.
- **Deploys are pinned to the reviewed commit** — what you saw in the diff is exactly what runs.
- **Fetching can't run code.** Helmsman only downloads commits in the background; building and running happen only on the deploy you trigger, and only when the server has the resources for it.
- **Touching a repo is treated as untrusted.** Helmsman generates the compose from your `helmsman.yaml` and validates it before running anything, and a force-push / rewritten history is flagged for you to review rather than deployed silently.

## Connect with GitHub — one-time setup

To offer the one-click flow, whoever installs Helmsman does this once:

1. In GitHub, create an **OAuth App** (Settings → Developer settings → OAuth Apps). Its **Authorization callback URL must match the URL your browser uses to reach the dashboard** — Helmsman derives the callback from `admin.hostname` if set, otherwise from the address you're on:

   | How you reach the dashboard | Set the OAuth App's callback URL to |
   |---|---|
   | A public admin domain (`admin.hostname` set in config) | `https://<admin.hostname>/github/callback` |
   | An **SSH tunnel** to loopback (no `admin.hostname`, the default before you have a domain) | `http://localhost:9000/github/callback` |

   > **You do NOT need a public domain first.** GitHub allows a `localhost` callback, and it works over the SSH tunnel — so you can set GitHub up before pointing a domain at the box. **But the match is strict, and an OAuth App has only ONE callback URL:**
   > - If `admin.hostname` **is set**, Helmsman *always* uses `https://<admin.hostname>/github/callback` — so that domain must be live (its HTTPS working) when you click Connect; the `localhost` callback won't be used even if you're on the tunnel.
   > - If you later add a domain (set `admin.hostname`), **update the OAuth App's callback URL** to the `https://…` form, or Connect will fail with a redirect-URI mismatch.

2. Put the credentials in `config.yaml` and reload:

   ```yaml
   github:
     client_id: "<from the OAuth App>"
     client_secret: "<from the OAuth App>"
   ```

3. Allow the server to reach `github.com` and `api.github.com` if you've locked down outbound network access (the egress filter is off by default).

After that, **Connect with GitHub** appears on the Connect-a-repository page. Operators can disconnect at any time; already-connected repos keep working, because each uses its own deploy key rather than the GitHub login.

## Building images vs pulling them

By default Helmsman **pulls** the images your Compose references — it doesn't build on your server. If your app needs an on-box build, set the build option when connecting the repo; building requires a server with at least 1 GB of RAM.
