# Git Integration & GitOps

> Point Helmsman at a `compose_path` in your repository and let it watch for new commits — **automatically pulling** them in the background while keeping every deploy **manual, reviewed, and sha-pinned**. This is the recommended way to run a repo-backed app, and it is designed so that *a push from CI can never trigger a surprise build on your box*.

This page covers Helmsman's Git integration end to end: **Mode-4 repo-path provisioning**, the **auto-pull / manual-deploy** model and why it is safer, the **pending-update state machine**, the **webhook**, the **`auto_deploy` opt-in**, the **git-hardening** that makes touching an attacker-controlled repo safe, the **Mode-4 confinement root**, and how all of this composes with the [`helmsman.yaml` definition file](./definition-file.md).

If you have not yet connected a repo, start with [Connecting a repository](#connecting-a-repository) below, then read [How auto-pull / manual-deploy works](#the-auto-pull--manual-deploy-model). For the broader provisioning picture, see the [provisioning modes overview](./gitops.md); for the edge/TLS picture, see the [managed edge docs](./edge-and-tls.md).

---

## Table of contents

- [Why Mode 4 (and why it is the default)](#why-mode-4-and-why-it-is-the-default)
- [Connecting a repository](#connecting-a-repository)
- [The auto-pull / manual-deploy model](#the-auto-pull--manual-deploy-model)
- [The pending-update state machine](#the-pending-update-state-machine)
- [The diff preview](#the-diff-preview)
- [The webhook](#the-webhook)
- [`auto_deploy` — explicit, default-off](#auto_deploy--explicit-default-off)
- [Git hardening (why fetching is safe)](#git-hardening-why-fetching-is-safe)
- [The Mode-4 confinement root](#the-mode-4-confinement-root)
- [How this composes with `helmsman.yaml`](#how-this-composes-with-helmsmanyaml)
- [Field reference](#field-reference)
- [Security trade-offs, stated honestly](#security-trade-offs-stated-honestly)
- [Troubleshooting](#troubleshooting)

---

## Why Mode 4 (and why it is the default)

Helmsman has four input modes for provisioning an app (see [`./provisioning.md`](./gitops.md)):

| Mode | Source of the compose bytes | Notes |
|---|---|---|
| 1 — Guided form | Helmsman generates compose from a vetted template | Recommended for new apps with no repo |
| 2 — Paste | A textarea you paste into | Validating importer, not an interpreter |
| 3 — Setup scripts | A sandboxed provisioning script | Dangerous; off by default; ≥ 1 GB |
| **4 — Repo-path** | **A file path inside your connected git repo** | **Recommended for repo-backed apps** |

**You don't have to paste or generate the compose.** For a repo-backed app, you connect the repo and **point at the file in it**:

- `compose_path` (required) — the path to your compose file inside the repo, e.g. `deploy/docker-compose.yml`.
- `dockerfile_path` (optional) — the path to a Dockerfile if you build on-box.

Helmsman then reads those files **from the repo's object store**, not from a textarea. Mode 4 is **not a fourth parser**: it converges on exactly the same validation chokepoint and the same stored artifacts (a validated compose, an encrypted env blob, file-secret awareness, an ops-interface record) as every other mode. The only thing that changes is the *source* of the compose bytes.

The wizard auto-suggests Mode 4 whenever a repo is connected, and pre-fills candidate paths using `git ls-tree` against the repo's tree (never a filesystem walk).

---

## Connecting a repository

Git connectivity is set up through the credential flow (PAT or deploy key). Credentials are:

- Stored **encrypted** (AES-256-GCM) in the secret store — never in the DB in cleartext, never in the UI, never in logs.
- Passed to `git` via a `PrivateTmp` credential helper — **never in the repo URL argv** — so a credential can never end up in process arguments, audit rows, or `last_fetch_error`.
- Backed by a pinned `known_hosts` for SSH, with an orphan sweep for stray temp artifacts.

### The `git_repo` URL is SSRF-allow-listed

The repository URL you provide is **not** dialed blindly. It is run through the same SSRF allowlist Helmsman applies to every outbound destination (§15):

- **Scheme must be `https` or `ssh`** — nothing else.
- **Loopback, link-local/metadata (`169.254.0.0/16`, `169.254.169.254`), private/CGNAT/ULA ranges, and the control-plane ports `2375` / `2019` / `9000` are denied.**

You cannot point Helmsman's git client at cloud metadata, at the Docker socket-proxy, at Caddy's admin API, or at the admin UI itself.

### Errors are classified, never echoed

Git can fail for many reasons, and its raw stderr is a notorious place for a credential-in-a-URL to leak. Helmsman therefore **classifies** every git error into a small, safe set — `auth`, `host-key`, `network`, `not-found` — and stores *only the classification* in `last_fetch_error`, the audit log, and the UI. **The raw git stderr is never surfaced.**

---

## The auto-pull / manual-deploy model

This is the centerpiece of Helmsman's GitOps design, and it is a deliberate departure from the classic "push triggers a deploy" pipeline. **A git event no longer auto-deploys.** Helmsman decouples *fetch* from *deploy* into two distinct planes:

```
   ┌─────────────────────────── READ PLANE (auto, OOM-safe) ──────────────────────────┐
   │                                                                                   │
   │   push / webhook / poll  ──►  git fetch ──►  advance staged_commit                │
   │                                              compute "N commits behind" + diff     │
   │                                              set update_available                  │
   │                                              (touches NOTHING live)                │
   │                                                                                   │
   └───────────────────────────────────────────────────────────────────────────────────┘
                                          │
                            operator reviews the diff, clicks DEPLOY
                                          │
   ┌─────────────────────── WRITE PLANE (manual, fully gated) ─────────────────────────┐
   │                                                                                   │
   │   advance live checkout to the EXACT reviewed sha                                  │
   │   re-validate THOSE bytes (§5.6 allowlist)                                         │
   │   pass §0 gate + one-docker-child semaphore + mem-headroom floor + build_policy    │
   │   docker compose up / pull / (build)                                               │
   │   pin a `deploys` row at the deployed commit                                       │
   │                                                                                   │
   └───────────────────────────────────────────────────────────────────────────────────┘
```

### Fetch — automatic, read-plane, OOM-safe

A webhook (or a poll) does **only** `git fetch` into a **staged ref**. It then:

- computes "N commits behind",
- builds a diff preview,
- sets `update_available`,
- and **touches nothing live**: no working-copy change, no config re-render, no `docker compose`, no build.

Because fetch is pure read-plane, it is **safe below the §0 1 GB write-plane floor** — it runs even on a small VPS. This is the whole point: **a push from CI can never trigger a surprise on-box build.** The old "auto-redeploy on webhook" pattern carried an OOM vector — a single push could kick off a `docker compose build` or `pull` that OOMs a tiny box and cascades the whole host (the edge dies first). Helmsman closes that vector by making fetch the *only* thing a push can ever cause.

### Deploy — manual, write-plane, fully gated

The operator clicks **Deploy**. **Only here** does:

1. the live checkout advance to the **exact reviewed commit** (the 40-hex sha you reviewed),
2. the §5.6 allowlist validator re-run against *those exact bytes* (read via `git cat-file` from the pinned commit — see [git hardening](#git-hardening-why-fetching-is-safe)),
3. the **§0 write-plane gate** (≥ 1 GB RAM), the **global one-docker-child semaphore**, the **memory-headroom floor**, and the **`build_policy`** check all run, *before*
4. `docker compose up / pull / (build)` runs, one service at a time, and
5. a `deploys` row is written, pinning `deployed_commit` to the validated sha.

The deploy is **fenced** against a moving target: the Deploy action carries the exact reviewed sha, and if `staged_commit` has moved since you reviewed it (a new push landed), Helmsman **rejects the deploy and asks you to re-review**. The one-docker-child semaphore is held across the whole checkout → validate → `up` sequence, and Helmsman deploys the **validated artifact**, never a re-read of the live tree — this closes the "smuggle a build past review" gap.

> ### Why this is safer — in one sentence
> Fetch is read-only and cannot build; deploy is the *only* build path and is gated, sha-pinned, and re-validated — so **no push, webhook, or repo change can ever produce an on-box build or container action you did not explicitly review and click.**

---

## The pending-update state machine

Helmsman tracks two pinned commits per app and a small finite-state machine over them.

| Field | Meaning |
|---|---|
| `deployed_commit` | The commit currently **live** (what `docker compose` is running). |
| `staged_commit` | The **newest fetched** commit, sitting in the staged ref, awaiting your review. |
| `commits_behind` | How many commits `deployed_commit` is behind `staged_commit` ("N commits behind"). |
| `update_state` | The FSM state (below). |
| `last_fetch_at` | Timestamp of the last successful fetch. |
| `last_fetch_error` | The **classified** (not raw) last fetch error, if any. |

### States

```
        ┌──────────────┐   fetch finds new commits   ┌────────────────────┐
        │  up_to_date  │ ──────────────────────────► │  update_available  │
        └──────────────┘                             └────────────────────┘
               ▲                                              │
               │                                       operator clicks Deploy
               │                                              ▼
               │                                       ┌────────────┐
               │       deploy succeeds                 │  deploying │
               └───────────────────────────────────────└────────────┘
                                                              │
                                          validation / gate failure
                                                              ▼
                                                   ┌──────────────────┐
                                                   │  update_blocked  │  (stays on the OLD deployment,
                                                   └──────────────────┘   never a partial deploy)
```

- **`up_to_date`** — `deployed_commit == staged_commit`. Nothing to do.
- **`update_available`** — a fetch advanced `staged_commit` past `deployed_commit`. The UI shows "N commits behind" and a [diff preview](#the-diff-preview). Nothing is live yet.
- **`deploying`** — you clicked Deploy; the gated write-plane promote is in flight.
- **`update_blocked`** — the promote failed validation or a gate (e.g. the §5.6 validator rejected the new bytes, or the §0 gate refused a build on a near-OOM box). The app **stays on the old deployment** — there is never a partial deploy — and Helmsman pages/flags the failure.

A **force-push** (non-fast-forward) is *not* silently treated as an ordinary diff. It is pinned as a distinct **`history_rewritten`** condition that requires explicit acknowledgement before you can act on it, so a rewritten history can never quietly change what you think you are reviewing.

---

## The diff preview

When an app is `update_available`, Helmsman renders a preview of what changed between `deployed_commit` and `staged_commit`: commit messages, authors, changed paths, and content hunks.

**The diff preview is treated as hostile data — full stop.** Your operator session is the most privileged context in the entire system, so the preview is built to be incapable of attacking it:

- **100 % output-encoded as HTML text** — every commit message, author, path, and content line is escaped. Nothing is ever passed through `innerHTML`, an htmx attribute, or a template as markup.
- **`NUL` / `CR` / `LF` / ANSI escape sequences are stripped** — a `<script>` payload, a terminal-escape payload, or a CRLF-injection in a commit message renders **inert**.
- **Hard caps on files, hunk bytes, commit count, and line length** — an attacker-crafted oversized diff **truncates**, it does not OOM your session.
- **`secret:` bindings stay masked** — config-file previews show masked placeholders (e.g. `‹secret:NODE_COOKIE (32 B)›`), never a secret byte (see [`./config-files.md`](./config-files-and-secrets.md)).

In short: reviewing a diff from an attacker-controlled repo is a *read*, and it cannot execute, inject, or exhaust anything.

---

## The webhook (optional)

**You do not need a webhook.** By default Helmsman polls every connected repo on a cadence (`git.poll_interval`, default 2 min), so connecting a repo in the dashboard "just works" — change detection needs no provider setup. The webhook is an **optional** add-on for teams that want *instant* fetches instead of waiting for the next poll: it lets your CI tell Helmsman "there is something new to fetch" without putting Helmsman's admin UI on the public internet.

```
POST /webhook/:token
```

### It is exempt from the IP allowlist — but nothing else

`POST /webhook/:token` is the **one** route exempt from the [IP allowlist](./security.md) (CI egress IPs are unpredictable). To compensate, every other gate is tightened:

| Control | What it does |
|---|---|
| **HMAC, timing-safe** | The request body is HMAC-verified with a high-entropy per-app token. The token is **never logged**. |
| **Provider-agnostic replay protection** | Replay is defeated by a **signed timestamp + nonce inside the HMAC-covered body** — *not* a vendor-specific delivery-id (e.g. a GitHub delivery header) that a generic git host might omit. If no nonce/timestamp can be verified, the webhook is **fetch-only and never auto-deploys**. |
| **Per-token rate limit** | Each token is independently rate-limited. |
| **Single-flight debounce** | Rapid bursts collapse to one fetch. |

### It is a *trigger only* — it never trusts the payload

This is the critical property. **The webhook never reads the ref, sha, or repo from the (attacker-influenced) payload.** A webhook delivery is purely a *signal* that says "go look." Helmsman then, **server-side**:

1. runs `git fetch`,
2. resolves the **configured, fully-qualified `git_ref`** (the one *you* set, not anything in the payload),
3. advances `staged_commit`, computes commits-behind + diff, sets `update_available`, and audits.

That's it. There is **no re-validate, no build, no redeploy** in the webhook path — those live only on the manual Deploy path behind the §0 gate. **A webhook can never reach a build**, which is exactly what removes the surprise-OOM vector. A webhook also **may never trigger setup-script execution** (see [`./setup-scripts.md`](./gitops.md)).

> ### Honest trade-off: the webhook is allowlist-exempt
> Exempting `POST /webhook/:token` from the IP allowlist is a deliberate concession to CI egress unpredictability. It is bounded by HMAC + replay protection + per-token rate limiting, and — most importantly — by the fact that the **worst** a forged-but-somehow-valid webhook could do is cause a *fetch* (read-plane, OOM-safe, touches nothing live). It can never deploy, build, or run a script. If you do not use CI webhooks, you can leave the token unconfigured and rely on polling.

---

## `auto_deploy` — explicit, default-off

If you genuinely want full auto-deploy-on-push (the Netlify-style behavior), Helmsman supports it — but as an **explicit per-app opt-in** (`auto_deploy`, **default `false`**), and it does **not** introduce a second deploy path.

- When `auto_deploy` is enabled, a fetch that produces an `update_available` simply **auto-clicks the same gated promote path** a human would click. It is *not* an unguarded build.
- It runs through the identical sequence: §5.6 re-validation of the exact bytes, §0 write-plane gate, one-docker-child semaphore, memory-headroom floor, `build_policy`.
- On any validation or gate failure it **fails closed to `update_blocked` + a page** — it stays on the old deployment, exactly like a manual deploy, and never falls through to an unguarded build.
- It still requires verifiable replay protection on the triggering webhook; without it, the webhook stays fetch-only regardless of the `auto_deploy` setting.

So `auto_deploy` is best understood as "let Helmsman click Deploy for me," **not** "let a push run arbitrary builds." The safety floor is identical to the manual path.

---

## Git hardening (why fetching is safe)

> ### A connected repo is attacker-controlled, and "fetch runs nothing" is false
> Merely **fetching, diffing, or checking out** a repo can run code via `.gitattributes` `filter`/`textconv` drivers, LFS smudge, `core.fsmonitor` / `core.sshCommand`, hooks, and submodule `ext::` URLs. Helmsman assumes the repo is hostile and proves, by construction, that touching it executes nothing.

**Every** git invocation Helmsman makes is run **config- and attribute-proofed**. None of the host's, the user's, or the repo's own git configuration can influence it:

| Setting | Value | Why |
|---|---|---|
| `GIT_CONFIG_NOSYSTEM` | `1` | Ignore `/etc/gitconfig`. |
| `GIT_CONFIG_GLOBAL` | `/dev/null` | Ignore any global config. |
| `HOME` | empty | No user config picked up. |
| `core.hooksPath` | `/dev/null` | **Hooks cannot run.** |
| `core.fsmonitor` | `false` | No fsmonitor process spawned. |
| **`core.symlinks`** | **`false`** | A tree symlink materializes as plain text, not a traversable link. |
| `protocol.ext.allow` | `never` | No `ext::` transport (RCE vector). |
| `protocol.file.allow` | `never` | No `file://` transport. |
| `submodule.recurse` | `false` | **Submodules are never followed.** |
| `gc.auto` | `0` | No background gc (it could prune a pinned ref). |
| filter / diff / textconv drivers | neutralized | No smudge/clean/textconv code runs. |

### Reads via `cat-file`, diffs via `--no-textconv --no-ext-diff`

Helmsman never reads files out of a working tree (where a smudge filter would fire). It reads **file bytes directly from the object store**:

```
git cat-file blob <sha>:<path>
```

This bypasses the worktree and any smudge entirely. Diffs are produced with `--no-textconv --no-ext-diff`, so no `textconv` or external-diff program can be invoked.

### Tree-mode `120000` / `160000` rejected

For every path component from the repo root down to the target file, Helmsman checks the git **tree mode**:

- mode **`120000`** = a symlink → **rejected**,
- mode **`160000`** = a gitlink (submodule) → **rejected**.

With `core.symlinks=false`, a tree symlink shows up as plain text and `cat-file` returns the *link text* — it never traverses it. Crucially, the **confinement check and the read are done on the same pinned commit's tree** — there is no "lstat a worktree, then reopen" TOCTOU window.

### The validated bytes are exactly what deploys

For a Mode-4 app, §5.6 validation runs on the **exact bytes of the pinned commit being deployed** — read via `cat-file`, with `include` / `extends` / `x-` anchors / `.env` resolved **first**, then the merged document validated. The deploy installs that **validated artifact**, never a re-read of a live tree, so nothing can be smuggled in between review and `up`.

---

## The Mode-4 confinement root

Because a compose file can reference *other* paths (a build context, an `env_file`, an `include`/`extends`, a bind-mount source), an attacker-committed compose could try to climb out of the app's checkout into a sibling app, into `repos_dir`, or into Helmsman's own config.

Helmsman confines all of it. **Every compose-relative path** — build context, `env_file`, `include` / `extends`, bind sources — is resolved from the compose file's directory and must **canonicalize-then-`Rel`-confine under the app's checkout subtree**. Anything that escapes is rejected:

- A `build: ../../other-app` climbing into a sibling app → **rejected**.
- An `env_file:` climbing to Helmsman's config dir → **rejected**.
- `include` / `extends` resolved **first**, with **every** included path confined.
- The build context (when builds are allowed) is the **confined subtree**, never `repos_dir`.
- `ADD <url>` in a Dockerfile → **rejected** (it would fetch from an attacker URL at build time).

This is the same run_dir-confinement discipline the rest of Helmsman uses (see [`./security.md`](./security.md)), applied to the repo checkout subtree as the confinement root.

### Staged is isolated from live

To make rollback safe and keep an in-flight fetch from disturbing the running app:

- each app gets a **dedicated per-app object store**,
- staged commits advance **only** `refs/helmsman/staged/<app>` (there is **no live-branch fetch target**),
- a real `refs/helmsman/deployed/<app>` ref pins `deployed_commit` so `gc` can never prune it — **your rollback target stays valid**.

---

## How this composes with `helmsman.yaml`

Mode 4 governs the **compose** bytes. Helmsman also supports a declarative **`helmsman.yaml` definition file** that describes *how Helmsman manages* the app (env refs, secrets-by-name, config files, edge routes, scaling, healing, `git` settings including `auto_deploy`). The two fit together cleanly. Full details are in [`./definition-file.md`](./definition-file.md); the GitOps-relevant rules are:

- **The repo `helmsman.yaml` is fetch-only desired state.** Helmsman *fetches it, never pushes to it* — it holds **no git write credential**. The repo file is read-only to Helmsman: it expresses *desired intent*.
- It is **read from the pinned commit's tree via `cat-file`**, exactly like the compose — same tree-mode `120000`/`160000` rejection, same hardening.
- A repo definition becomes the live **`canonical.yaml`** (the last-successfully-applied source of truth) **only through the same sha-pinned, §0-gated promote** — **never on fetch**. Fetching a new `helmsman.yaml` sets a `def_update_available` state, mirroring the compose FSM; it does not silently take effect.
- **A non-conflicting repo-side change still requires explicit operator acknowledgement.** A dashboard apply will *never* silently fold in an attacker-committed repo change — e.g. flipping `auto_deploy` from `false` to `true`, widening `scaling`, or adding a route. Where both sides changed the same field, you get a per-field `def_conflict` review, never an auto-merge or silent clobber.

The practical upshot: **a commit to your repo can change Helmsman's desired state, but it can never *enact* it.** Enacting always requires a gated, reviewed, sha-pinned promote that you trigger.

---

## Field reference

These fields live on the `apps` row (and are surfaced in the UI and via `helmsman status`):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `provision_mode` | enum | — | `form` \| `paste` \| `setup_script` \| **`repo_path`** (Mode 4). |
| `compose_path` | path | required (Mode 4) | Path to the compose file inside the repo. |
| `dockerfile_path` | path | optional | Path to a Dockerfile, if you build on-box. |
| `deployed_commit` | 40-hex sha | — | The commit currently live. |
| `staged_commit` | 40-hex sha | — | The newest fetched commit, awaiting review. |
| `update_state` | enum | `up_to_date` | `up_to_date` \| `update_available` \| `deploying` \| `update_blocked`. |
| `commits_behind` | int | `0` | How far `deployed_commit` trails `staged_commit`. |
| `last_fetch_at` | timestamp | — | Last successful fetch. |
| `last_fetch_error` | enum | — | **Classified** error: `auth` \| `host-key` \| `network` \| `not-found` (never raw stderr). |
| `auto_deploy` | bool | **`false`** | Opt-in: auto-click the gated promote on a verified update. |

The `deploys` table records each promote with a `source` of `manual_promote` \| `auto_deploy` \| `rollback` \| `initial`, the validated commit sha, and whether a build ran.

---

## Security trade-offs, stated honestly

The plan makes a few deliberate trade-offs here. They are worth understanding rather than discovering later.

- **The webhook is exempt from the IP allowlist.** This is necessary because CI egress IPs are unpredictable. It is bounded by HMAC + provider-agnostic replay protection + per-token rate limiting, and — decisively — by the fact that a webhook can only ever cause a *fetch*. Even a maximally-abused webhook reaches no build, no deploy, and no setup script.
- **Fetch runs automatically below the 1 GB floor.** This is intentional: fetch is pure read-plane and OOM-safe, so it works on the smallest VPS. The cost is that `staged_commit` can advance without you noticing — which is exactly why nothing happens until you click Deploy.
- **The diff preview puts attacker-authored text in your most privileged session.** That is unavoidable if you want to review changes. Helmsman makes it safe by treating 100 % of that text as hostile data: output-encoded, control-character-stripped, and hard-capped against OOM. It can be *read*, never *executed*.
- **`auto_deploy` exists.** A fully hands-off pipeline is a real operational need, so it is supported — but it is **default-off**, explicit per app, and routed through the identical gated promote, so it cannot become an unguarded build. The safety floor of the automatic path equals the safety floor of the manual path.

Every one of these trade-offs preserves the paramount invariant: **a git push, a webhook, or a repo change can never produce an on-box build or container action you did not explicitly review and trigger.**

---

## Troubleshooting

**The app shows "N commits behind" but nothing is deploying.**
That is the intended behavior. Fetch is automatic; deploy is manual. Review the [diff preview](#the-diff-preview) and click **Deploy**.

**`last_fetch_error: auth` / `host-key` / `network` / `not-found`.**
These are the only four classifications you will see, by design — the raw git stderr is never surfaced (it could leak a credential). Check, respectively: the stored PAT/deploy key; the pinned `known_hosts`; outbound connectivity (and that the repo host is not being blocked by the SSRF allowlist — loopback/metadata/private targets are denied); and the `compose_path`/`git_ref` you configured.

**Deploy is rejected with "staged moved, re-review."**
A new commit landed between your review and your click. Helmsman is fenced against deploying a sha you didn't review. Re-open the diff and Deploy again.

**Deploy lands in `update_blocked`.**
The new bytes failed §5.6 validation or a gate (e.g. the §0 write-plane gate refused a build on a near-OOM box). The app stays on the old deployment. Inspect the audit log for the classified reason, fix the compose in your repo, push, and re-fetch.

**A force-push isn't showing a normal diff.**
A non-fast-forward pins a `history_rewritten` condition that needs explicit acknowledgement before you can act on it — by design, so a rewritten history can't quietly change what you review.

**Helmsman won't connect to my repo URL.**
The `git_repo` URL is SSRF-allow-listed: scheme must be `https` or `ssh`, and loopback / metadata / private / CGNAT / ULA targets and ports `2375`/`2019`/`9000` are denied. A URL pointing at any of those is refused.

---

### See also

- [README](../README.md) — project overview and quick start
- [Provisioning modes](./gitops.md) — Modes 1–4 in context
- [The `helmsman.yaml` definition file](./definition-file.md) — declarative app management, `apply`/`plan`, split-plane ownership
- [Managed edge & TLS](./edge-and-tls.md) — how a deployed app gets a route and a cert
- [Config files & secrets](./config-files-and-secrets.md) — selective templating, masked previews
- [Security model](./security.md) — the IP allowlist, run_dir confinement, SSRF design
- [Setup scripts](./gitops.md) — Mode 3, and why a webhook can never trigger one