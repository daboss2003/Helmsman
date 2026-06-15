package definition

import (
	"strings"
	"testing"
)

const goodDef = `apiVersion: helmsman/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    source: generated
    services:
      - name: web
        image: ghcr.io/acme/web:1.2
        port: 8080
        env: [DATABASE_URL]
  secrets:
    - name: DATABASE_URL
  env:
    - name: DATABASE_URL
      secret: DATABASE_URL
  edge:
    routes:
      - hostname: shop.example.com
        service: web
        port: 8080
        hsts: true
`

func TestParseHappyPath(t *testing.T) {
	d, err := Parse([]byte(goodDef))
	if err != nil {
		t.Fatalf("clean definition rejected: %v", err)
	}
	if d.Metadata.Slug != "shop" || d.Spec.Compose.Source != "generated" || len(d.Spec.Compose.Services) != 1 {
		t.Errorf("parsed shape wrong: %+v", d)
	}
}

func TestParseRejectsBadEnvelope(t *testing.T) {
	cases := map[string]string{
		"wrong apiVersion":  strings.Replace(goodDef, "helmsman/v1", "helmsman/v2", 1),
		"future apiVersion": strings.Replace(goodDef, "helmsman/v1", "helmsman/v1beta", 1),
		"wrong kind":        strings.Replace(goodDef, "kind: App", "kind: Host", 1),
		"bad slug":          strings.Replace(goodDef, "slug: shop", "slug: Shop_Bad", 1),
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// The parser-differential defenses: anchors, aliases, merge keys, duplicate keys,
// unknown keys, and a second document are all hard-rejected.
func TestParseRejectsParserDifferentialConstructs(t *testing.T) {
	cases := map[string]string{
		"anchor+alias": `apiVersion: helmsman/v1
kind: App
metadata: &m
  slug: shop
spec:
  compose: { source: inline, inline: "x" }
extra: *m`,
		"merge key": `apiVersion: helmsman/v1
kind: App
metadata:
  slug: shop
  <<: {kind: Host}
spec:
  compose: { source: inline, inline: "x" }`,
		"duplicate key": `apiVersion: helmsman/v1
kind: App
kind: Host
metadata: { slug: shop }
spec:
  compose: { source: inline, inline: "x" }`,
		"unknown key": `apiVersion: helmsman/v1
kind: App
metadata: { slug: shop }
spec:
  compose: { source: inline, inline: "x" }
  danger: true`,
		"second document": goodDef + "\n---\napiVersion: helmsman/v1\nkind: App\nmetadata: {slug: evil}\nspec: {compose: {source: inline, inline: x}}\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected (parser-differential defense)", name)
		}
	}
}

func TestParseComposeOneOf(t *testing.T) {
	bad := map[string]string{
		"generated+path": `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    path: docker-compose.yml
    services: [{name: web, image: nginx, port: 80}]`,
		"repo_path without path": `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: repo_path }`,
		"unknown source": `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: magic }`,
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: oneOf must be rejected", name)
		}
	}
}

func TestParseRejectsControlPlanePortAndBadRefs(t *testing.T) {
	cases := map[string]string{
		"control-plane service port": strings.Replace(goodDef, "port: 8080\n        env", "port: 9000\n        env", 1),
		"undeclared secret ref": `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: inline, inline: "x" }
  env:
    - name: TOK
      secret: NOPE`,
		"edge route literal (no service)": `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: inline, inline: "x" }
  edge:
    routes:
      - hostname: shop.example.com
        port: 8080`,
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// Canonical re-marshal round-trips and re-parses cleanly (write-back is always the
// typed render, never operator bytes).
func TestCanonicalRoundTrip(t *testing.T) {
	d, err := Parse([]byte(goodDef))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Parse(out)
	if err != nil {
		t.Fatalf("canonical form did not re-parse: %v\n%s", err, out)
	}
	if d2.Metadata.Slug != d.Metadata.Slug || d2.Spec.Compose.Source != d.Spec.Compose.Source {
		t.Error("canonical round-trip changed the definition")
	}
}
