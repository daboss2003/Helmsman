# APT repository (`apt install helmsman`)

This is how the project hosts a **signed APT repository** so users can install and
auto-update Helmsman with `apt`. GoReleaser already builds the `.deb` packages and
attaches them (plus GPG-signed checksums) to each GitHub release; this step publishes
those `.deb`s into an apt repo.

## What users do

Once the repo is live, installing is three lines:

```bash
# 1. Trust the signing key
curl -fsSL https://apt.helmsman.sh/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/helmsman.gpg

# 2. Add the repo
echo "deb [signed-by=/usr/share/keyrings/helmsman.gpg] https://apt.helmsman.sh stable main" \
  | sudo tee /etc/apt/sources.list.d/helmsman.list

# 3. Install (and `apt upgrade` from then on)
sudo apt update && sudo apt install helmsman
```

## Publishing (maintainers)

The repo is built with [`aptly`](https://www.aptly.info) and signed with the same GPG
key used for release checksums. Run `deploy/apt/publish.sh <version>` after a release:
it downloads that release's `.deb`s, adds them to the `helmsman` aptly repo, publishes
a signed `stable` distribution to `./public/`, and exports the public key to
`./public/gpg.key`. Serve `./public/` from any static host (S3, GitHub Pages, nginx)
at the domain in the snippet above.

Hosting alternatives, if you'd rather not run aptly yourself:

- **deb-s3** — push the `.deb`s straight to an S3 bucket as an apt repo (one command,
  no repo state to keep).
- **Cloudsmith / packagecloud** — managed apt/yum hosting; point users at the URL they
  give you. Lowest effort.

`.rpm` users: the release also ships `.rpm`s; host them as a yum repo with `createrepo`
the same way, or point users at the GitHub release directly.
