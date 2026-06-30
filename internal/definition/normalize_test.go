package definition

import (
	"strings"
	"testing"
)

const goodDef = `apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    source: generated
    services:
      web:
        image: ghcr.io/acme/web:1.2
        ports:
          - internal: 8080
        env:
          DATABASE_URL: { secret: DATABASE_URL }
  secrets:
    - name: DATABASE_URL
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
	web, ok := d.Spec.Compose.Services["web"]
	if !ok || len(web.Ports) != 1 || web.Ports[0].Internal != 8080 {
		t.Errorf("web service not parsed: %+v", web)
	}
	if ev := web.Env["DATABASE_URL"]; ev.Secret != "DATABASE_URL" {
		t.Errorf("per-service secret env not parsed: %+v", web.Env)
	}
}

func TestParseRejectsBadEnvelope(t *testing.T) {
	cases := map[string]string{
		"wrong apiVersion":  strings.Replace(goodDef, "mooring/v1", "mooring/v2", 1),
		"future apiVersion": strings.Replace(goodDef, "mooring/v1", "mooring/v1beta", 1),
		"wrong kind":        strings.Replace(goodDef, "kind: App", "kind: Host", 1),
		"bad slug":          strings.Replace(goodDef, "slug: shop", "slug: Shop_Bad", 1),
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// Parser-differential defenses: anchors, aliases, merge keys, duplicate keys, unknown
// keys, and a second document are hard-rejected (independent of compose content).
func TestParseRejectsParserDifferentialConstructs(t *testing.T) {
	cases := map[string]string{
		"anchor+alias": `apiVersion: mooring/v1
kind: App
metadata: &m
  slug: shop
spec:
  compose: { source: generated, services: {web: {image: nginx:1}} }
extra: *m`,
		"merge key": `apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
  <<: {kind: Host}
spec:
  compose: { source: generated, services: {web: {image: nginx:1}} }`,
		"duplicate key": `apiVersion: mooring/v1
kind: App
kind: Host
metadata: { slug: shop }
spec:
  compose: { source: generated, services: {web: {image: nginx:1}} }`,
		"unknown key": `apiVersion: mooring/v1
kind: App
metadata: { slug: shop }
spec:
  compose: { source: generated, services: {web: {image: nginx:1}} }
  danger: true`,
		"second document": goodDef + "\n---\napiVersion: mooring/v1\nkind: App\nmetadata: {slug: evil}\nspec: {compose: {source: generated, services: {web: {image: nginx:1}}}}\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected (parser-differential defense)", name)
		}
	}
}

// Mooring owns the compose: legacy repo_path/inline, compose.path, an unknown source,
// and a service-less generated compose are all rejected.
func TestParseRejectsLegacyComposeSources(t *testing.T) {
	bad := map[string]string{
		"inline source": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: inline, inline: "services: {}" }`,
		"repo_path source": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: repo_path, path: docker-compose.yml }`,
		"compose.path set": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    path: docker-compose.yml
    services: {web: {image: nginx:1}}`,
		"unknown source": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: magic, services: {web: {image: nginx:1}} }`,
		"no services": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: generated }`,
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected (Mooring owns the compose; generated-only)", name)
		}
	}
}

func TestParseRejectsControlPlanePortAndBadRefs(t *testing.T) {
	cases := map[string]string{
		"control-plane service port": strings.Replace(goodDef, "internal: 8080", "internal: 9000", 1),
		"undeclared secret ref": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: generated
    services:
      web:
        image: nginx:1
        env:
          TOK: { secret: NOPE }`,
		"edge route literal (no service)": `apiVersion: mooring/v1
kind: App
metadata: {slug: shop}
spec:
  compose: { source: generated, services: {web: {image: nginx:1}} }
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

// Canonical re-marshal round-trips and re-parses cleanly.
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
