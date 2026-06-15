# Deploy from a Git repo

Connect a repository and Helmsman watches it for new commits, shows you what changed, and deploys exactly the commit you reviewed when you click **Deploy**. A push never deploys itself unless you ask it to.

See also: [Deploy your first app](./first-steps.md) · [Secrets & config files](./config-files-and-secrets.md)

---

## Connecting a repository

In the dashboard, click **Connect repo**. Two ways in:

**Connect with GitHub (one click).** If GitHub is set up (see below), click **Connect with GitHub**, authorize, and pick a repo. Helmsman creates a read-only deploy key for it automatically — you copy nothing.

**Connect any repo.** Provide:

- the **repository URL** and **branch**,
- the **path to your Compose file** in the repo (e.g. `docker-compose.yml`),
- for a **private** repo, a deploy key or access token.

Credentials are stored encrypted and never appear in the UI or logs.

## How updates work

Once connected, **Helmsman checks the repo for new commits on its own** — no webhook to set up, no file to add to your repo. When a new commit lands, the app shows **"update available"** with a summary of what changed (the commits and files).

Click **Deploy** to ship it. Helmsman deploys **exactly the commit you reviewed**, brings the app up, and **rolls back automatically** if anything fails — so a deploy either fully succeeds or leaves the previous version running. There's never a half-deploy.

You'll find this on the app's page (a **Repository & updates** panel) and on the dedicated **Repository** page (with the full diff and history).

> **Want instant deploys?** By default Helmsman checks every couple of minutes. If you want a push to be picked up immediately, you can add an optional **webhook** — but it's not required. And if you want truly hands-off releases, turn on **auto-deploy** (off by default): Helmsman then deploys a new commit for you, through the same checks, when it's a clean fast-forward. The background check on its own only ever *fetches* — it never deploys.

## Why this is safe

- **Nothing deploys until you click** (unless you explicitly turn on auto-deploy). A push to your repo can't trigger a surprise build on your server.
- **Deploys are pinned to the reviewed commit** — what you saw in the diff is exactly what runs.
- **Fetching can't run code.** Helmsman only downloads commits in the background; building and running happen only on the deploy you trigger, and only when the server has the resources for it.
- **Touching a repo is treated as untrusted.** Helmsman validates the Compose it pulls before running anything, and a force-push / rewritten history is flagged for you to review rather than deployed silently.

## Connect with GitHub — one-time setup

To offer the one-click flow, whoever installs Helmsman does this once:

1. In GitHub, create an **OAuth App** (Settings → Developer settings → OAuth Apps) with the **Authorization callback URL** set to `https://<your-dashboard>/github/callback`.
2. Put the credentials in `config.yaml` and reload:

   ```yaml
   github:
     client_id: "<from the OAuth App>"
     client_secret: "<from the OAuth App>"
   ```

3. Allow the server to reach `github.com` and `api.github.com` if you've locked down outbound network access.

After that, **Connect with GitHub** appears on the Connect-a-repository page. Operators can disconnect at any time; already-connected repos keep working, because each uses its own deploy key rather than the GitHub login.

## Building images vs pulling them

By default Helmsman **pulls** the images your Compose references — it doesn't build on your server. If your app needs an on-box build, set the build option when connecting the repo; building requires a server with at least 1 GB of RAM.
