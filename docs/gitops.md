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

Either way, **you don't type an app name** — Helmsman reads the repo's helmsman file(s) and takes the app's slug from `metadata.slug`. If the repo has [more than one helmsman file](#several-apps-from-one-repo), you pick which one to deploy next. (Only the scaffold case — a repo with *no* `helmsman.yaml` — asks you for a name.)

Your repo carries a **`helmsman.yaml`** (see [the definition file](./definition-file.md)) describing the app — its services, build, env, edge routes, config files, and cert bindings. **That file is the single source of truth for the app's structure.** Helmsman reads it, **generates the `docker-compose.yml` and any Dockerfiles**, and deploys — you never commit a compose file or a Dockerfile. If the repo has no `helmsman.yaml`, Helmsman scaffolds a sensible default from the stack it detects (e.g. a Node or Go project) so the first deploy still works; commit a real `helmsman.yaml` when you want full control.

### Several apps from one repo

One repo can hold **several helmsman files** — the plain `helmsman.yaml` plus named variants like `helmsman.staging.yaml` and `helmsman.prod.yaml` — and **each one becomes its own deployed app**. When you connect a repo with more than one, Helmsman shows a **chooser**: the plain `helmsman.yaml` is the default, and variants are labelled by the text between `helmsman.` and `.yaml` (`staging`, `prod`, …). Pick one to deploy now; connect the repo again to add another.

Each app's **identity (its slug) comes from that file's `metadata.slug`** — so give each variant a distinct slug (e.g. `myapp-staging`, `myapp-prod`). If the slug you pick already names a connected app, Helmsman just opens it instead of overwriting — connecting never silently repoints an existing app. (Editing a file's `metadata.slug` *after* connecting doesn't rename the app; the slug is fixed at connect.) If your repo only ever has one `helmsman.yaml`, none of this changes anything — you connect and deploy as usual.

To change the app's *shape* — services and edge/L4 routes — **edit `helmsman.yaml` and deploy**; the dashboard then reflects it (read-only for those). The operational pieces are managed in the dashboard: **secret values** and **env** (the file declares secret *names* only), **config files** and **cert bindings** (editable in the dashboard; optionally seeded from the file), the per-service **auto-scaling policy**, and **lifecycle actions** (deploy / restart / scale-now).

## How updates work

Once connected, **Helmsman checks the repo for new commits on its own** — no webhook to set up, no file to add to your repo. When a new commit lands, the app shows **"update available"** with a summary of what changed (the commits and files).

Click **Deploy** to ship it. Helmsman deploys **exactly the commit you reviewed**, brings the app up, and **rolls back automatically** if anything fails — so a deploy either fully succeeds or leaves the previous version running. There's never a half-deploy.

You'll find this on the app's page (a **Repository & updates** panel) and on the dedicated **Repository** page (with the full diff and history).

> **Want instant deploys?** By default Helmsman checks every couple of minutes. If you want a push to be picked up immediately, you can add an optional **webhook** — but it's not required. And if you want truly hands-off releases, turn on **auto-deploy** (off by default): Helmsman then deploys a new commit for you, through the same checks, when it's a clean fast-forward. The background check on its own only ever *fetches* — it never deploys.

## Deleting an app

The app's page has a **Danger zone** with a **Delete** button. Deleting is **permanent and cannot be undone** — it is gated behind re-entering your password (a live session isn't enough) and, because it stops containers, it needs the write plane to be available. When you confirm, Helmsman:

- stops and removes all of the app's **containers, networks, and data volumes** (`docker compose down --volumes`);
- deletes its **run directory** and its **Git object store** (the local repo clone Helmsman fetched);
- erases **all of its state** — env & secrets, config files, cert bindings, edge/L4 routes, auto-scaling, self-healing, and ops — and revokes any API token whose only scope was deploying this app.

What is **not** touched: your own Git repository on GitHub/elsewhere (Helmsman only deletes its local clone), the global GitHub connection, and whole-system **backups** (a backup is a snapshot of all of Helmsman, not one app — restore from one if you delete by mistake). Protected/managed projects (Helmsman's own infrastructure) can't be deleted.

## Why this is safe

- **Nothing deploys until you click** (unless you explicitly turn on auto-deploy). A push to your repo can't trigger a surprise build on your server.
- **Deploys are pinned to the reviewed commit** — what you saw in the diff is exactly what runs.
- **Fetching can't run code.** Helmsman only downloads commits in the background; building and running happen only on the deploy you trigger, and only when the server has the resources for it.
- **Access is fetch-only.** Helmsman reads your repo (with a read-only deploy key over the GitHub flow, or the deploy key / token you supply) and **never pushes to it.** The repo file stays the source of truth; the dashboard reflects what was deployed.
- **Touching a repo is treated as untrusted.** Helmsman generates the compose from your `helmsman.yaml` and validates it before running anything, and a force-push / rewritten history is flagged for you to review rather than deployed silently.

## Connect with GitHub — one-time setup

To offer the one-click flow, whoever installs Helmsman does this once:

1. In GitHub, create an **OAuth App** (Settings → Developer settings → OAuth Apps → **New OAuth App**). You'll see these fields:

   | Field on the GitHub form | What to enter | Does Helmsman use it? |
   |---|---|---|
   | **Application name** | Anything, e.g. `Helmsman`. Shown to you on the authorization screen. | No — cosmetic. |
   | **Homepage URL** | The base URL you use to reach the dashboard — `http://localhost:9000` on the tunnel, or `https://<admin.hostname>` with a domain. GitHub requires *a* valid URL here. | No — cosmetic; never read by Helmsman. |
   | **Application description** | Optional. Leave blank or describe it. | No — cosmetic. |
   | **Authorization callback URL** | **The one that matters** — must match exactly how your browser reaches the dashboard (see the table below). | **Yes** — must match exactly. |
   | **Enable Device Flow** (checkbox) | **Leave it OFF.** | **No** — see note. |

   > **Leave "Enable Device Flow" unchecked.** Helmsman signs you in with the standard browser redirect flow (you click Connect → GitHub → back to the callback URL). Device Flow is a different mechanism for things with no browser (CLIs, TVs); Helmsman never uses it. Turning it on won't break anything, but it adds an unused capability to your app — keep it off.

   The **Authorization callback URL must match the URL your browser uses to reach the dashboard** — Helmsman derives the callback from `admin.hostname` if set, otherwise from the address you're on:

   | How you reach the dashboard | Set the OAuth App's callback URL to |
   |---|---|
   | A public admin domain (`admin.hostname` set in config) | `https://<admin.hostname>/github/callback` |
   | An **SSH tunnel** to loopback (no `admin.hostname`, the default before you have a domain) | `http://localhost:9000/github/callback` |

   > **You do NOT need a public domain first.** GitHub allows a `localhost` callback, and it works over the SSH tunnel — so you can set GitHub up before pointing a domain at the box. **But the match is strict, and an OAuth App has only ONE callback URL:**
   > - If `admin.hostname` **is set**, Helmsman *always* uses `https://<admin.hostname>/github/callback` — so that domain must be live (its HTTPS working) when you click Connect; the `localhost` callback won't be used even if you're on the tunnel.
   > - If you later add a domain (set `admin.hostname`), **update the OAuth App's callback URL** to the `https://…` form, or Connect will fail with a redirect-URI mismatch.

2. Put the credentials in `config.yaml` and **restart** Helmsman:

   ```yaml
   github:
     client_id: "<from the OAuth App>"
     client_secret: "<from the OAuth App>"
   ```

   ```bash
   sudo systemctl restart helmsman
   ```

   > **Restart, not reload.** GitHub credentials are read once at startup, so `systemctl reload` will **not** pick them up — the **Connect with GitHub** button won't appear until you `systemctl restart helmsman`. (See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).)

3. Allow the server to reach `github.com` and `api.github.com` if you've locked down outbound network access (the egress filter is off by default).

After that, **Connect with GitHub** appears on the Connect-a-repository page. Operators can disconnect at any time; already-connected repos keep working, because each uses its own deploy key rather than the GitHub login.

## Building images vs pulling them

By default Helmsman **pulls** the images your Compose references — it doesn't build on your server. If your app needs an on-box build, set the build option when connecting the repo; building requires a server with at least 1 GB of RAM.
