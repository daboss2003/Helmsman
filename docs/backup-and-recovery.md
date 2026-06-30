# Backups & recovery

Mooring makes your setup reproducible, but two things deserve real backups: **Mooring's own configuration** (every app's settings, secrets, routes, and definitions) and your **apps' data** (their databases and uploaded files). This page covers both, and how to recover onto a fresh server.

See also: [Alerts](./alerting.md) · [Deploy from a Git repo](./gitops.md)

---

## Backing up Mooring

This is the "get everything back on a new server" backup. It captures Mooring's entire state — all your apps' config, definitions, edge routes, and secrets (which stay encrypted) — in one encrypted file.

Open **System → Backups** in the dashboard:

- **Back up now** takes a snapshot. It appears in the list with its date, size, and a checksum.
- **Download** saves the encrypted archive so you can keep it off-site. It's locked with your master key, so it's safe to store anywhere — only someone with that key can read it.
- **Delete** removes a snapshot you no longer need.

> **Keep your master key.** A backup is encrypted with the same master key you generated at install. Store that key somewhere safe and separate from the backups — restoring needs it.

### Restoring Mooring onto a fresh server

Restoring replaces Mooring's database, so it's a deliberate command-line step rather than a dashboard button:

1. Install Mooring on the new server with the **same `encryption_key`** as the original.
2. Stop the service: `systemctl stop mooring`.
3. Restore from your archive:

   ```bash
   mooring restore --from mooring-backup-<id>.mbk --force
   ```

   Mooring decrypts and verifies the archive before swapping it in, and keeps the existing database aside (as a `.pre-restore-*` copy) just in case.
4. Start it again: `systemctl start mooring`.

Your apps' definitions and settings are back; redeploy them and Mooring rebuilds their files and re-issues certificates.

---

## Backing up your apps' data

Mooring's own backup brings back *configuration*, but not the data **inside** your apps — a database's contents, a volume of uploaded files. Those live in Docker volumes and need their own snapshots.

> **Status:** an in-dashboard flow for per-app data-volume backups is on the roadmap. For now, snapshot an app's volumes with your usual Docker volume-backup method, and rely on Mooring's own backup (above) for everything else.

Worth remembering either way:

- **A definition file recreates the app, not its data.** Redeploying gives you a fresh, empty volume — so a database needs its own backup.
- **Keep backups off the server** where you can, so losing the box doesn't lose the backups too.
- **Test a restore occasionally.** A backup you've never restored is a hope, not a plan.
