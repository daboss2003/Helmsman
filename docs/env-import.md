# Env import-and-own — bring your `.env`, Helmsman writes the live one

> **The one-sentence invariant:** Helmsman **owns** the live `.env`; a `.env` you provide is an
> **import source**, never the file Helmsman runs.

You almost always already have a `.env` — in your repo, in a vault export, or hand-written. Helmsman
lets you bring it. But it does **not** mount your file and run it. Instead it **copies the values in**
(exactly the way a `setup-vps.sh` copies env into place), stores them encrypted, records them in your
[`helmsman.yaml`](./definition-file.md) **by reference**, and thereafter **writes the live `.env`
itself** from its encrypted store. Your uploaded file is read once and shredded.

---

## 1. Own vs. import

### Helmsman owns the live `.env`

The source of truth is the **encrypted store** (see [config-files-and-secrets.md](./config-files-and-secrets.md)
and [security.md](./security.md)):

- non-secret literals live in the per-app **`env_blob`** (still AES-256-GCM at rest);
- secret-shaped values live in the per-**`(slug, name)`** **secret store**, wrapped in `Redacted`.

At **deploy time, inside the §5.6 validator**, Helmsman renders a fresh **`0600 --env-file`**
(service-uid, under the app's run_dir) from the store and hands it to `docker compose`. It is
ephemeral and **re-rendered on every deploy**. Your uploaded file is **never** bind-mounted, never
referenced as `env_file:` in the generated compose, never committed, and never left on disk.

### Why copy-from, not use-in-place

A user `.env` is **hostile data of unknown provenance** carrying plaintext secrets whose path and
permissions aren't Helmsman's to guarantee. Making "the live file is the store render" the rule is
what lets every other guarantee hold: reveal-on-click stays the only audited way to see a value, the
`Redacted` type keeps secrets out of logs, rotation carries its caution, and `${VAR}` is resolved
**once, at §5.6**, where the path is confined under run_dir. If Helmsman ran your file directly, all
of that would be at the mercy of whatever produced it.

---

## 2. The import pipeline

Every stage treats the input as hostile.

1. **Acquire.** An uploaded file is streamed to a **size-capped (~256 KiB) `0600` service-uid staging
   temp** (never world-readable `/tmp`). A repo-pointed source (`spec.env_import.repo_path`) is read
   via **`git cat-file blob <pinned-sha>:<path>`** — no working tree, no smudge, the full git
   hardening of [gitops.md](./gitops.md), tree-mode `120000`/`160000` rejected, path confined under
   the app checkout. The pinned sha is recorded as provenance.
2. **Parse.** A dotenv reader — **not a shell.** `KEY=VALUE`; strips a leading `export `; strips
   full-line and unquoted-trailing `#` comments (a `#` inside quotes is data); supports single/double
   quotes and double-quoted multiline (PEM blocks). It **does not** expand `${VAR}`, `$(...)`, or
   backticks — values are stored **opaque**; `${VAR}` resolution happens once, later, at §5.6. A
   duplicate key is last-wins with a parse warning.
3. **Classify** secret-shaped vs plain, **biased to secret**: the [§7.4 literal-secret lint](./config-files-and-secrets.md)
   (PEM / high-entropy / long-base64 / token-shape / `user:pass@` / JWT) plus name heuristics
   (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY`, `PRIVATE_KEY`, `DSN`, `JWT`, `*_KEY`, …). A positive on
   *either* signal ⇒ secret-shaped. Classification is a **proposal you review**, not a silent
   decision.
4. **Value hygiene.** Keys must match `^[A-Z_][A-Z0-9_]*$` (else reject); **NUL always rejected**;
   **bare CR/LF rejected** in single-line values (they would inject a second `--env-file` line); PEM
   newlines normalized and round-tripped only through the `0600` writer.
5. **Ingest.** Plain → an `env_blob` entry (AES-256-GCM — "plain" means *not a secret reference*, not
   *plaintext at rest*). Secret-shaped → the **`(slug, name)`** store, flagged secret and wrapped in
   `Redacted`; the `env_blob` gets a `secret: NAME` **reference**, never the value. A new `env_blob`
   **version** is created (auditable, reversible).
6. **Populate `helmsman.yaml` by reference**, then re-marshal canonical YAML: a literal becomes
   `env: { KEY: value }`; a secret becomes `secrets: [ - name: KEY ]` **plus** `env: { KEY: { secret:
   KEY } }`. `canonical.yaml` stays **non-secret-bearing → `0640` → commit-safe**.
7. **Shred + audit.** Overwrite-then-unlink the staging temp, zero buffers, drop the parsed plaintext
   map; a repo source needed no checkout (the pinned sha is the provenance). One `env_import` audit
   event records actor, IP, source (`upload` / `repo:<sha>:<path>`), and counts + per-key dispositions
   **by name only, never values.**

Parse / classify / review run on the **read plane** (safe below the [§0 1 GB floor](./architecture.md)).
The store write does **not** redeploy — the live `--env-file` re-renders on the **next** gated deploy.

---

## 3. Re-import is a merge, never a clobber

A second import **diffs against the store** and shows a per-key **add / change / unchanged** review —
computed **without revealing secret values** (a constant-time hash compare for secrets, never a
display):

- **add** → import with its proposed classification.
- **change (plain→plain)** → old→new review.
- **anything touching a secret** → the value is **never displayed**, and the **default action is
  keep**. Replacing a provisioned secret is a **rotation**: it is lifted **out of the bulk "confirm
  merged set"** into its **own per-secret rotation confirm**, carries the rotation caution, and
  creates its own audited secret version. A classification **downgrade** (secret→plain) is treated as
  posture-widening and gets the same explicit confirm.
- **drop** (a key in the store but absent from the file) is **surfaced** ("in store, not in file") but
  **never auto-deleted** — import is additive; deletion is a separate, explicit operation.

Nothing is written until you confirm the merged set.

---

## 4. Safety rules (the red-team fixes)

- **Literal-secret lint is a hard stop.** Any value that import would write as a **plain literal**
  into `canonical.yaml` is run through the same `§7.4` lint that rejects a pasted secret — and your
  review **cannot override it.** A mislabeled secret must never round-trip into git.
- **`Redacted` from parse-time.** Every parsed value is wrapped in `Redacted` *before* classification,
  so a crash can't serialize a pre-classification secret.
- **Orphan-sweep.** A crash between *acquire* and *shred* (the realistic failure mode on a small box)
  would leave a `0600` plaintext temp; a **boot-time and periodic orphan-sweep** shreds any staging
  temp past a short TTL (named alongside the git-credential sweep).
- **Never to the browser.** Secret-shaped values are masked the instant they're classified; the diff
  masks them; the browser never receives a secret byte. Reveal-on-click remains the only audited
  `POST → text/plain, no-store` path.
- **No residue.** The staging temp is shredded; nothing is copied into `run_dir`/`repos_dir`; the live
  `--env-file` is always the store render.
- **Committed secrets are flagged, then fixed.** A repo `.env` that contains real secrets is flagged
  — *"Secrets detected in a committed file. Move these to the Helmsman store and remove them from the
  repo"* — but the values are still ingested into the secret store and the live file still becomes
  Helmsman's render. (Helmsman fixes ownership and warns; it can't rewrite your git history.)
- **Import never deploys.** Importing from a repo path is an **explicit operator action**, never a
  fetch side effect — consistent with the rule that a webhook may never trigger a setup script.

Everything funnels through the **one chokepoint**: the assembled env is materialized into the `0600
--env-file` **inside §5.6**, where `${VAR}`/`.env` are resolved first and the path is confined under
run_dir.

---

## 5. Surfaces

### Dashboard

An **"Import .env"** panel on the app's **Env** tab: parse + classify + hygiene run on the read plane
→ a review screen (secrets masked; a re-import shows add/change/unchanged with keep-default on secret
changes) → confirm → store write + `helmsman.yaml` write-back + audit → shred. The new-app wizard
offers the same as a pre-fill step.

### CLI

```bash
# read-plane: print the masked proposed/diff table, write nothing
helmsman env import --slug broker --from ./.env.production --dry-run

# read a .env that lives in the connected repo (via git cat-file, pinned commit)
helmsman env import --slug broker --from-repo deploy/.env.production --dry-run

# write-plane: run it through the shared reconciler
helmsman env import --slug broker --from ./.env.production --apply
```

It pairs with `helmsman secret set` (values from stdin/`--from-file`, never argv) and `helmsman init
--from-compose`. See [cli.md](./cli.md).

---

## 6. Worked example

A user's `.env`:

```dotenv
# infra
PORT=8080
LOG_LEVEL=info

# credentials
DB_PASSWORD=S3cr3t-w1th-high-entropy-xyz...
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkq...
-----END PRIVATE KEY-----"
```

After `helmsman env import --slug api --from .env --apply`:

- `PORT`, `LOG_LEVEL` → classified **plain** → `env_blob` literals.
- `DB_PASSWORD` (high-entropy + name heuristic) and `JWT_PRIVATE_KEY` (PEM) → classified **secret** →
  the `(api, DB_PASSWORD)` / `(api, JWT_PRIVATE_KEY)` store entries.

The resulting `helmsman.yaml` (commit-safe — no values):

```yaml
spec:
  env:
    PORT: "8080"
    LOG_LEVEL: info
    DB_PASSWORD: { secret: DB_PASSWORD }
    JWT_PRIVATE_KEY: { secret: JWT_PRIVATE_KEY }
  secrets:
    - name: DB_PASSWORD
    - name: JWT_PRIVATE_KEY
```

The uploaded `.env` is shredded. At the next deploy, Helmsman renders a `0600 --env-file` from the
store and hands it to `docker compose`.

---

## See also

- [config-files-and-secrets.md](./config-files-and-secrets.md) — the secret model, managed config files, the literal-secret lint.
- [definition-file.md](./definition-file.md) — the `env` / `secrets` sections this populates by reference.
- [gitops.md](./gitops.md) — how a repo-pointed source is read (`git cat-file`, hardening).
- [security.md](./security.md) — secrets at rest, the §5.6 chokepoint.
- [host-file.md](./host-file.md) — server-wide settings and the 3-tier model.
- [README](../README.md) — the project front page.
