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
rsync -a --delete "$(aptly config show | sed -n 's/.*"rootDir": "\(.*\)".*/\1/p')/public/" "$OUT/"
gpg --armor --export "$GPG_KEY_ID" > "$OUT/gpg.key"

echo ">> done. Serve ./$OUT/ at your apt domain (e.g. https://daboss2003.github.io/Helmsman)."
