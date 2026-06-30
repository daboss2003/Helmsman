package compose

import (
	"strings"
	"testing"
)

const runDir = "/var/lib/mooring/apps/shop"

func validate(t *testing.T, yaml string, env Env) Result {
	t.Helper()
	if env == nil {
		env = Env{}
	}
	return ValidateBytes([]byte(yaml), env, runDir, Options{})
}

func mustReject(t *testing.T, yaml string, env Env, wantSubstr string) {
	t.Helper()
	r := validate(t, yaml, env)
	if r.OK() {
		t.Fatalf("expected rejection containing %q, but compose was accepted", wantSubstr)
	}
	if !strings.Contains(r.Error(), wantSubstr) {
		t.Fatalf("error %q does not contain %q", r.Error(), wantSubstr)
	}
}

func TestValidComposePasses(t *testing.T) {
	y := `
services:
  web:
    image: nginx:1.27
    ports: ["8080:80"]
    environment:
      LOG_LEVEL: info
    volumes:
      - ./data:/data
      - app_data:/var/lib/app
    depends_on: [db]
    restart: unless-stopped
  db:
    image: postgres:16
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  app_data:
  db_data:
`
	if r := validate(t, y, nil); !r.OK() {
		t.Fatalf("valid compose rejected: %s", r.Error())
	}
}

func TestUnknownTopLevelKeyRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: nginx\nbogus_top: 1\n", nil, "unknown top-level key")
}

func TestUnknownServiceKeyRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: nginx\n    totally_unknown: x\n", nil, "is not allowed")
}

func TestDangerousKeysRejected(t *testing.T) {
	cases := map[string]string{
		"privileged: true":                       "privileged",
		"cap_add: [NET_ADMIN]":                   "cap_add",
		"devices: [\"/dev/sda:/dev/sda\"]":       "devices",
		"sysctls: {net.ipv4.ip_forward: 1}":      "sysctls",
		"security_opt: [\"seccomp:unconfined\"]": "security_opt",
		"network_mode: host":                     "network_mode",
		"pid: host":                              "pid namespace",
		"ipc: host":                              "ipc namespace",
		"userns_mode: host":                      "userns_mode",
		"cgroup_parent: /x":                      "cgroup_parent",
		"volumes_from: [other]":                  "volumes_from",
		"extends: {service: base}":               "extends",
	}
	for frag, want := range cases {
		y := "services:\n  web:\n    image: nginx\n    " + frag + "\n"
		mustReject(t, y, nil, want)
	}
}

func TestDockerSocketBindRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n", nil, "forbidden host path")
}

func TestSensitivePathBindsRejected(t *testing.T) {
	for _, p := range []string{"/etc", "/", "/proc", "/sys", "/var/lib/docker"} {
		y := "services:\n  web:\n    image: x\n    volumes:\n      - " + p + ":/mnt\n"
		mustReject(t, y, nil, "forbidden host path")
	}
}

func TestBindTraversalRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n    volumes:\n      - ../../../etc:/mnt\n", nil, "escapes the app directory")
}

func TestAbsoluteBindOutsideRunDirRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n    volumes:\n      - /opt/other:/mnt\n", nil, "escapes the app directory")
}

func TestRelativeBindUnderRunDirAllowed(t *testing.T) {
	if r := validate(t, "services:\n  web:\n    image: x\n    volumes:\n      - ./data/sub:/data\n", nil); !r.OK() {
		t.Errorf("relative bind under run_dir rejected: %s", r.Error())
	}
}

func TestNamedVolumeAllowed(t *testing.T) {
	if r := validate(t, "services:\n  web:\n    image: x\n    volumes:\n      - mydata:/data\nvolumes:\n  mydata:\n", nil); !r.OK() {
		t.Errorf("named volume rejected: %s", r.Error())
	}
}

// The classic bypass: validating BEFORE interpolation would miss a ${VAR} that
// expands to a dangerous bind. We resolve first, so it's caught (plan §5.6).
func TestInterpolationResolvedBeforeValidation(t *testing.T) {
	y := "services:\n  web:\n    image: x\n    volumes:\n      - ${SOCK}:/sock\n"
	mustReject(t, y, Env{"SOCK": "/var/run/docker.sock"}, "forbidden host path")

	y2 := "services:\n  web:\n    image: x\n    volumes:\n      - ${DATADIR}/data:/data\n"
	mustReject(t, y2, Env{"DATADIR": "/etc"}, "forbidden host path") // /etc/data is under /etc

	y3 := "services:\n  web:\n    image: x\n    volumes:\n      - ${DATADIR}/data:/data\n"
	mustReject(t, y3, Env{"DATADIR": "/opt/elsewhere"}, "escapes the app directory")
}

func TestEnvFileConfinement(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n    env_file: /etc/shadow\n", nil, "env_file")
	if r := validate(t, "services:\n  web:\n    image: x\n    env_file: ./.env\n", nil); !r.OK() {
		t.Errorf("env_file under run_dir rejected: %s", r.Error())
	}
}

func TestInvalidYAMLRejected(t *testing.T) {
	mustReject(t, "services: [this is: not valid: mapping", nil, "invalid YAML")
}

func TestNoServicesRejected(t *testing.T) {
	mustReject(t, "volumes:\n  x:\n", nil, "no services")
}

// review #1 (CRITICAL): YAML aliases must not bypass bind confinement.
func TestAliasedVolumeBindRejected(t *testing.T) {
	mustReject(t, "x-s: &v \"/var/run/docker.sock:/sock\"\nservices:\n  web:\n    image: x\n    volumes:\n      - *v\n", nil, "forbidden host path")
	mustReject(t, "x-m: &m {type: bind, source: /etc, target: /e}\nservices:\n  web:\n    image: x\n    volumes:\n      - *m\n", nil, "forbidden host path")
	mustReject(t, "x-p: &p /var/run/docker.sock\nservices:\n  web:\n    image: x\n    volumes:\n      - {type: bind, source: *p, target: /s}\n", nil, "forbidden host path")
}

// review #2 (CRITICAL): top-level configs/secrets file: + volume driver_opts binds.
func TestTopLevelFileAndVolumeBindsRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n    configs: [c]\nconfigs:\n  c:\n    file: /etc/shadow\n", nil, "forbidden host path")
	mustReject(t, "services:\n  web:\n    image: x\n    secrets: [s]\nsecrets:\n  s:\n    file: /var/run/docker.sock\n", nil, "forbidden host path")
	mustReject(t, "services:\n  web:\n    image: x\n    volumes: [\"v:/host\"]\nvolumes:\n  v:\n    driver_opts: {type: none, o: bind, device: /}\n", nil, "forbidden host path")
}

// review #3 (HIGH): a long-form volume with a host-path source is confined
// regardless of the declared type.
func TestLongFormTypeHintIgnoredForHostSource(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n    volumes:\n      - {type: volume, source: /etc, target: /e}\n", nil, "forbidden host path")
}

// review #6 (HIGH): a multi-document stream is rejected.
func TestMultiDocumentRejected(t *testing.T) {
	mustReject(t, "services:\n  web:\n    image: x\n---\nservices:\n  evil:\n    image: y\n    privileged: true\n", nil, "single YAML document")
}

// review #17: a bind into a Mooring-protected dir is rejected.
func TestProtectedHostPathRejected(t *testing.T) {
	r := ValidateBytes([]byte("services:\n  web:\n    image: x\n    volumes:\n      - /var/lib/mooring:/data\n"),
		Env{}, "/srv/app", Options{ProtectedPaths: []string{"/var/lib/mooring", "/etc/mooring"}})
	if r.OK() {
		t.Error("bind into a protected Mooring dir was accepted")
	}
}

// Edge-collision (plan §5.6 (a)): an app may never publish host :80/:443.
func TestRejectsReservedHostPorts(t *testing.T) {
	reject := []string{`"80:8080"`, `"443:8080"`, `"127.0.0.1:80:8080"`, `"0.0.0.0:443:443"`, `"80-90:8080"`}
	for _, p := range reject {
		y := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - " + p + "\n"
		if ValidateBytes([]byte(y), Env{}, "/srv/app", Options{}).OK() {
			t.Errorf("ports entry %s should be rejected (edge owns 80/443)", p)
		}
	}
	allow := []string{`"8080:80"`, `"8080:8080"`, `"127.0.0.1:8443:443"`, `"9000"`}
	for _, p := range allow {
		y := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - " + p + "\n"
		if !ValidateBytes([]byte(y), Env{}, "/srv/app", Options{}).OK() {
			t.Errorf("ports entry %s should be allowed (host port not 80/443)", p)
		}
	}
}

// Long-form ports: published 443 is rejected; a high published port is allowed.
func TestRejectsReservedHostPortsLongForm(t *testing.T) {
	bad := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - target: 8080\n        published: 443\n"
	if ValidateBytes([]byte(bad), Env{}, "/srv/app", Options{}).OK() {
		t.Error("long-form published:443 should be rejected")
	}
	ok := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - target: 8080\n        published: 8443\n"
	if !ValidateBytes([]byte(ok), Env{}, "/srv/app", Options{}).OK() {
		t.Error("long-form published:8443 should be allowed")
	}
}

// IPv6 host-IP short form must not let a :80/:443 publish slip past checkPorts.
func TestRejectsReservedHostPortsIPv6(t *testing.T) {
	bad := `"[::1]:443:8080"`
	y := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - " + bad + "\n"
	if ValidateBytes([]byte(y), Env{}, "/srv/app", Options{}).OK() {
		t.Error("IPv6 host-IP :443 publish should be rejected")
	}
	ok := `"[::1]:8443:8080"`
	y2 := "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - " + ok + "\n"
	if !ValidateBytes([]byte(y2), Env{}, "/srv/app", Options{}).OK() {
		t.Error("IPv6 host-IP :8443 publish should be allowed")
	}
}

// §5.6 build-context confinement: a Mooring-generated build directive (context "."
// + a run_dir-relative Dockerfile) passes; an abs/traversing context or Dockerfile is
// rejected so a build can't read or send host files outside the app's checkout.
func TestBuildContextConfinement(t *testing.T) {
	ok := []string{
		"services:\n  web:\n    build:\n      context: .\n      dockerfile: .mooring/Dockerfile.web\n",
		"services:\n  web:\n    build: ./sub\n",
	}
	for _, y := range ok {
		if r := ValidateBytes([]byte(y), Env{}, "/srv/app", Options{}); !r.OK() {
			t.Errorf("a confined build context must pass: %v\n%s", r.Violations, y)
		}
	}
	bad := map[string]string{
		"abs context":          "services:\n  web:\n    build:\n      context: /etc\n",
		"traversal context":    "services:\n  web:\n    build:\n      context: ../../etc\n",
		"traversal dockerfile": "services:\n  web:\n    build:\n      context: .\n      dockerfile: ../../../etc/passwd\n",
		"short traversal":      "services:\n  web:\n    build: ../../etc\n",
		"docker.sock context":  "services:\n  web:\n    build: /var/run\n",
	}
	for name, y := range bad {
		if ValidateBytes([]byte(y), Env{}, "/srv/app", Options{}).OK() {
			t.Errorf("%s: build context must be rejected", name)
		}
	}
}
