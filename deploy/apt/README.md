# APT repository (`apt install mooring`)

This is how the project hosts a **signed APT repository** so users can install and
auto-update Mooring with `apt`. GoReleaser already builds the `.deb` packages and
attaches them (plus GPG-signed checksums) to each GitHub release; this step publishes
those `.deb`s into an apt repo.

## What users do

Once the repo is live, installing is three lines:

```bash
# 1. Trust the signing key
curl -fsSL https://daboss2003.github.io/mooring/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/mooring.gpg

# 2. Add the repo
echo "deb [signed-by=/usr/share/keyrings/mooring.gpg] https://daboss2003.github.io/mooring stable main" \
  | sudo tee /etc/apt/sources.list.d/mooring.list

# 3. Install (and `apt upgrade` from then on)
sudo apt update && sudo apt install mooring
```

## Publishing (maintainers)

The repo is built with [`aptly`](https://www.aptly.info) and signed with the same GPG
key used for release checksums. Run `deploy/apt/publish.sh <version>` after a release:
it downloads that release's `.deb`s, adds them to the `mooring` aptly repo, publishes
a signed `stable` distribution to `./public/`, and exports the public key to
`./public/gpg.key`.

### Hosting on GitHub Pages (this project's setup)

The repo is served at `https://daboss2003.github.io/mooring/` via GitHub Pages.
Publish `./public/` to the `gh-pages` branch:

```bash
GPG_KEY_ID=<your-fingerprint> deploy/apt/publish.sh vX.Y.Z   # writes ./public
cd public
git init -b gh-pages && git remote add origin git@github.com:daboss2003/mooring.git
git add -A && git commit -m "apt repo vX.Y.Z" && git push -f origin gh-pages
```

Then, in the repo's **Settings → Pages**, set the source to the `gh-pages` branch
(root). Pages serves `dists/`, `pool/`, and `gpg.key` at the URL above, which is what
the user snippet points at. (You can automate this as a CI step after release.)

Hosting alternatives, if you'd rather not use Pages/aptly:

- **deb-s3** — push the `.deb`s straight to an S3 bucket as an apt repo (one command,
  no repo state to keep).
- **Cloudsmith / packagecloud** — managed apt/yum hosting; point users at the URL they
  give you. Lowest effort.

`.rpm` users: the release also ships `.rpm`s; host them as a yum repo with `createrepo`
the same way, or point users at the GitHub release directly.
