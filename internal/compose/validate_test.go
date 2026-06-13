package compose

import (
	"strings"
	"testing"
)

const runDir = "/var/lib/helmsman/apps/shop"

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

// review #17: a bind into a Helmsman-protected dir is rejected.
func TestProtectedHostPathRejected(t *testing.T) {
	r := ValidateBytes([]byte("services:\n  web:\n    image: x\n    volumes:\n      - /var/lib/helmsman:/data\n"),
		Env{}, "/srv/app", Options{ProtectedPaths: []string{"/var/lib/helmsman", "/etc/helmsman"}})
	if r.OK() {
		t.Error("bind into a protected Helmsman dir was accepted")
	}
}
