# The Server tab

The **Server** tab (under **System** in the sidebar) is a read-only window into the
host Helmsman runs on — a task-manager-and-file-viewer for your box, plus a tidy-up
for old Helmsman downloads. It is built to **look, not break**: everything is
read-only except one narrow, re-authenticated action (deleting an old `.deb`).

## What it shows

- **Host monitor** — live CPU, load, memory, and disk meters (the same readings the
  Overview charts use), refreshed in place every few seconds.
- **Top processes by memory** — the processes using the most resident memory, with
  PID, name, state, and RSS. This is read-only: Helmsman can't signal or kill
  processes.
- **Disk usage** — how much space Helmsman itself is using, broken down by its data
  directory (database, git deploy history, secrets, state) and its app working dirs
  (repo clones, generated compose/Dockerfile). It also explains where the **build
  caches** live: Helmsman discards its own interrupted-deploy leftovers on boot, but
  **Docker's** build cache, dangling images, and stopped containers accumulate
  separately — check them over SSH with `docker system df` and reclaim with
  `docker system prune`. Helmsman never prunes Docker for you.
- **Helmsman downloads (`.deb`)** — lists the Helmsman release packages you've
  downloaded so you can delete the old ones (see below).
- **Files (read-only)** — an opt-in, allow-listed file viewer (see below).

## Cleaning up old `.deb` downloads

Every time you update Helmsman you download a `helmsman_<version>_linux_<arch>.deb`,
and they pile up. The Server tab can delete the old ones for you — safely:

1. Tell Helmsman where you keep them. In `/etc/helmsman/config.yaml`:

   ```yaml
   server:
     deb_cache_dir: /root/downloads   # the folder you download .deb files into
   ```

   The directory must be **writable by the Helmsman service user**. Note that a
   systemd-sandboxed install only permits writes under its declared paths, so a
   location like `~/Downloads` or `/tmp` may need to be added to the unit's
   `ReadWritePaths` (or just point `deb_cache_dir` somewhere already writable).

2. Reload Helmsman (`sudo systemctl reload helmsman`) and open **Server**. Under
   **Helmsman downloads** you'll see every `helmsman_*_linux_*.deb` in that folder,
   newest first. The **version you're running is marked "in use — kept" and can never
   be deleted.**

3. Click **delete** on an old one. Because this removes a file, it asks for your
   **password** (and your **2FA code** if enabled) — the same re-authentication used
   for deleting an app — behind the same brute-force lockout. Every delete is
   recorded in the **Audit log**.

The cleanup only ever matches files named exactly `helmsman_<version>_linux_(amd64|arm64).deb`
in that one folder. It cannot see or touch anything else, including system packages.

## The read-only file viewer

The file viewer is **off by default**. To turn it on, list the directories you want
to be able to browse:

```yaml
server:
  file_roots:
    - name: app-logs          # a short slug used in the URL
      path: /var/log/myapp
    - name: uploads
      path: /srv/data/uploads
```

Then **Server → Files** lets you browse those directories and read text files inside
them. The viewer is strictly read-only — there is **no** rename, move, write, or
delete of files. Guardrails (all enforced after resolving symlinks):

- **Allow-list only** — nothing outside a declared `file_roots` path is reachable.
  With no roots configured, the viewer is disabled entirely.
- **Secrets are always denied** — Helmsman's data directory (database, git object
  stores, env/secret files), its app working dirs, the config file and its directory,
  and well-known secret locations (`/etc/helmsman`, SSH keys, `/etc/shadow`) are
  refused **even if you accidentally list one as a root**. A root that resolves under
  a denied path is dropped.
- **No traversal, no symlink escape** — `..`, absolute paths, and symlinks whose
  target leaves the root are rejected.
- **Bounded** — listings are capped, file reads are size-capped, and binary files are
  detected and not rendered.
- **Audited** — every file read (and every denial) is written to the Audit log.

## Summary of config keys

```yaml
server:
  deb_cache_dir: /root/downloads   # optional; enables old-.deb cleanup
  file_roots:                      # optional; enables the read-only file viewer
    - name: app-logs
      path: /var/log/myapp
```

Both are optional and default to off. The host monitor, processes, and disk-usage
views need no configuration.
