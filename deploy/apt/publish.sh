#!/usr/bin/env bash
# Build/refresh the signed APT repo from a release's .deb packages.
#
#   deploy/apt/publish.sh v1.2.3
#
# Requires: aptly, gh (GitHub CLI, authenticated), gpg with the signing key present.
# Env: GPG_KEY_ID (the signing key id/fingerprint); REPO defaults to daboss2003/Helmsman.
set -euo pipefail

VERSION="${1:?usage: publish.sh <vX.Y.Z>}"
REPO="${REPO:-daboss2003/Helmsman}"
DIST="${DIST:-stable}"
COMPONENT="${COMPONENT:-main}"
GPG_KEY_ID="${GPG_KEY_ID:?set GPG_KEY_ID to the signing key fingerprint}"
OUT="${OUT:-public}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo ">> downloading ${VERSION} .deb assets from ${REPO}"
gh release download "$VERSION" --repo "$REPO" --pattern '*.deb' --dir "$workdir"

# Create the aptly repo on first run; ignore if it already exists.
aptly repo create -distribution="$DIST" -component="$COMPONENT" helmsman 2>/dev/null || true

echo ">> adding packages"
aptly repo add helmsman "$workdir"/*.deb

echo ">> publishing (signed)"
if aptly publish list | grep -q "$DIST"; then
    aptly publish update -gpg-key="$GPG_KEY_ID" "$DIST"
else
    aptly publish repo -gpg-key="$GPG_KEY_ID" -distribution="$DIST" helmsman
fi

# Export the rendered repo + the public signing key for static hosting.
mkdir -p "$OUT"
rootdir="$(aptly config show | sed -n 's/.*"rootDir": *"\(.*\)".*/\1/p')"
rootdir="${rootdir/#\~/$HOME}"            # aptly prints "~/.aptly" — expand the leading ~
[ -d "$rootdir/public" ] || rootdir="$HOME/.aptly"   # fallback to the default location
rsync -a --delete "$rootdir/public/" "$OUT/"
gpg --armor --export "$GPG_KEY_ID" > "$OUT/gpg.key"

# A small landing page so the Pages root isn't a bare 404 (apt only fetches sub-paths,
# but a human visiting the URL should see install instructions).
cat > "$OUT/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>Helmsman APT repository</title>
<body style="font:16px system-ui;max-width:48rem;margin:3rem auto;padding:0 1rem">
<h1>Helmsman APT repository</h1>
<p>Install on Debian / Ubuntu:</p>
<pre style="background:#f4f4f5;padding:1rem;border-radius:8px;overflow:auto">curl -fsSL https://daboss2003.github.io/Helmsman/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/helmsman.gpg
echo "deb [signed-by=/usr/share/keyrings/helmsman.gpg] https://daboss2003.github.io/Helmsman stable main" | sudo tee /etc/apt/sources.list.d/helmsman.list
sudo apt update &amp;&amp; sudo apt install helmsman</pre>
<p><a href="https://github.com/daboss2003/Helmsman">github.com/daboss2003/Helmsman</a></p>
</body>
HTML

echo ">> done. Serve ./$OUT/ at your apt domain (e.g. https://daboss2003.github.io/Helmsman)."
