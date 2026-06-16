package compose

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Violation is one rejected construct, line-anchored where possible.
type Violation struct {
	Service string
	Key     string
	Message string
	Line    int
}

func (v Violation) String() string {
	loc := ""
	if v.Line > 0 {
		loc = fmt.Sprintf(" (line %d)", v.Line)
	}
	if v.Service != "" {
		return fmt.Sprintf("service %q: %s%s", v.Service, v.Message, loc)
	}
	return v.Message + loc
}

// Result is the validation outcome.
type Result struct {
	Violations []Violation
}

// OK reports whether the compose document is safe to hand to docker compose.
func (r Result) OK() bool { return len(r.Violations) == 0 }

// Error renders all violations as one message.
func (r Result) Error() string {
	if r.OK() {
		return ""
	}
	parts := make([]string, len(r.Violations))
	for i, v := range r.Violations {
		parts[i] = v.String()
	}
	return "compose rejected:\n  - " + strings.Join(parts, "\n  - ")
}

// allowedTopLevel are the only permitted top-level keys (plan §5.6 step 2).
var allowedTopLevel = map[string]bool{
	"version": true, "name": true, "services": true,
	"networks": true, "volumes": true, "configs": true, "secrets": true,
}

// allowedServiceKeys is the allowlist of safe service keys. Anything not here is
// rejected — so privileged/cap_add/devices/etc. are denied simply by absence.
var allowedServiceKeys = map[string]bool{
	"image": true, "build": true, "command": true, "entrypoint": true,
	"environment": true, "env_file": true, "expose": true, "ports": true,
	"depends_on": true, "restart": true, "healthcheck": true, "networks": true,
	"labels": true, "deploy": true, "working_dir": true, "user": true,
	"hostname": true, "domainname": true, "dns": true, "dns_search": true,
	"dns_opt": true, "extra_hosts": true, "stop_grace_period": true,
	"stop_signal": true, "tty": true, "stdin_open": true, "init": true,
	"read_only": true, "shm_size": true, "logging": true, "profiles": true,
	"pull_policy": true, "platform": true, "secrets": true, "configs": true,
	"volumes": true, "mem_limit": true, "mem_reservation": true, "cpus": true,
	"cpu_shares": true, "cpu_count": true, "cpuset": true, "ulimits": true,
	"cap_drop": true, "links": true, "container_name": true, "scale": true,
	"annotations": true, "mac_address": true, "oom_score_adj": true, "isolation": true,
}

// dangerousKeys map a known-dangerous key to a specific reason (better UX than
// the generic "unknown key" for the constructs operators most often reach for).
var dangerousKeys = map[string]string{
	"privileged":          "privileged containers are forbidden",
	"cap_add":             "cap_add is forbidden (escalates container capabilities)",
	"devices":             "devices are forbidden (host device access)",
	"device_cgroup_rules": "device_cgroup_rules are forbidden",
	"cgroup_parent":       "cgroup_parent is forbidden",
	"cgroup":              "cgroup is forbidden",
	"sysctls":             "sysctls are forbidden",
	"security_opt":        "security_opt is forbidden (can disable confinement)",
	"network_mode":        "network_mode is forbidden (use `networks:` instead; host/container modes are unsafe)",
	"pid":                 "pid namespace sharing is forbidden",
	"ipc":                 "ipc namespace sharing is forbidden",
	"uts":                 "uts namespace sharing is forbidden",
	"userns_mode":         "userns_mode is forbidden",
	"runtime":             "runtime override is forbidden",
	"group_add":           "group_add is forbidden",
	"volumes_from":        "volumes_from is forbidden (use named volumes)",
	"external_links":      "external_links are forbidden",
	"extends":             "extends is not supported yet; inline the service",
	"tmpfs":               "service-level tmpfs is forbidden",
	"pid_mode":            "pid_mode is forbidden",
	"privileged_mode":     "privileged_mode is forbidden",
}

// sensitivePaths can never be a bind source, even relative to run_dir.
var sensitivePaths = []string{
	"/", "/etc", "/proc", "/sys", "/dev", "/boot", "/root",
	"/var/run/docker.sock", "/run/docker.sock", "/var/lib/docker", "/var/run",
}

// ValidateBytes runs the full §5.6 validation on a compose document. env is used
// for ${VAR} resolution (built from the app's .env, never Helmsman's env);
// runDir is the app's run directory that bind mounts must stay under.
// Options carry extra, deployment-specific inputs to the validator.
type Options struct {
	// ProtectedPaths are additional absolute host paths that must never be a bind
	// source (e.g. Helmsman's data dir and config dir, holding the DB + master
	// key). Joined with the built-in sensitivePaths set (review #17).
	ProtectedPaths []string
}

// ValidateBytes runs the full §5.6 validation on a compose document. env is used
// for ${VAR} resolution (built from the app's .env, never Helmsman's env);
// runDir is the app's run directory that bind mounts must stay under.
func ValidateBytes(raw []byte, env Env, runDir string, opts Options) Result {
	var res Result
	add := func(v Violation) { res.Violations = append(res.Violations, v) }

	// Step 1: resolve ${VAR}/.env BEFORE parsing (plan §5.6).
	resolved := Interpolate(string(raw), env)

	// Decode and reject a multi-document stream (compose is single-document, and
	// validating only the first doc while compose reads more is a bypass, #6).
	dec := yaml.NewDecoder(strings.NewReader(resolved))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		add(Violation{Message: "invalid YAML: " + err.Error()})
		return res
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		add(Violation{Message: "compose must be a single YAML document (multi-document streams are rejected)"})
		return res
	}

	// Resolve ALL YAML aliases in place so anchored constructs cannot smuggle a
	// bind/key past the node walk (critical review #1).
	resolveAliases(&doc, 0)

	if len(doc.Content) == 0 {
		add(Violation{Message: "empty compose document"})
		return res
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		add(Violation{Message: "compose root must be a mapping"})
		return res
	}

	runDirClean := filepath.Clean(runDir)
	conf := confiner{runDir: runDirClean, protected: opts.ProtectedPaths}

	var servicesNode, configsNode, secretsNode, volumesNode *yaml.Node
	for _, kv := range pairs(root) {
		key := kv.key.Value
		if strings.HasPrefix(key, "x-") {
			continue // extension fields are allowed and ignored
		}
		if !allowedTopLevel[key] {
			add(Violation{Key: key, Message: "unknown top-level key " + quote(key), Line: kv.key.Line})
			continue
		}
		switch key {
		case "services":
			servicesNode = kv.val
		case "configs":
			configsNode = kv.val
		case "secrets":
			secretsNode = kv.val
		case "volumes":
			volumesNode = kv.val
		}
	}

	// Top-level configs/secrets `file:` and named-volume host binds are real bind
	// surfaces too (critical review #2).
	for _, v := range checkTopLevelFileRefs(configsNode, "configs", conf) {
		add(v)
	}
	for _, v := range checkTopLevelFileRefs(secretsNode, "secrets", conf) {
		add(v)
	}
	for _, v := range checkTopLevelVolumes(volumesNode, conf) {
		add(v)
	}

	if servicesNode == nil {
		add(Violation{Message: "no services defined"})
		return res
	}
	if servicesNode.Kind != yaml.MappingNode {
		add(Violation{Message: "services must be a mapping"})
		return res
	}

	for _, svc := range pairs(servicesNode) {
		name := svc.key.Value
		if svc.val.Kind != yaml.MappingNode {
			add(Violation{Service: name, Message: "service must be a mapping", Line: svc.val.Line})
			continue
		}
		for _, field := range pairs(svc.val) {
			k := field.key.Value
			if strings.HasPrefix(k, "x-") {
				continue
			}
			if reason, bad := dangerousKeys[k]; bad {
				add(Violation{Service: name, Key: k, Message: reason, Line: field.key.Line})
				continue
			}
			if !allowedServiceKeys[k] {
				add(Violation{Service: name, Key: k, Message: "key " + quote(k) + " is not allowed", Line: field.key.Line})
				continue
			}
			switch k {
			case "volumes":
				for _, v := range checkVolumes(name, field.val, conf) {
					add(v)
				}
			case "env_file":
				for _, v := range checkEnvFiles(name, field.val, conf) {
					add(v)
				}
			case "ports":
				for _, v := range checkPorts(name, field.val) {
					add(v)
				}
			case "build":
				for _, v := range checkBuild(name, field.val, conf) {
					add(v)
				}
			}
		}
	}
	return res
}

// checkBuild confines a service's `build:` context (and Dockerfile) under run_dir,
// the same canonicalize-then-Rel discipline as bind mounts. Short form is a scalar
// context; long form is {context, dockerfile, ...}. The Dockerfile is resolved
// relative to the context, so context/dockerfile must also stay under run_dir — this
// blocks a build that reads or sends host files outside the app's checkout (plan §5.6).
func checkBuild(svc string, node *yaml.Node, c confiner) []Violation {
	var vs []Violation
	bad := func(line int, msg string) {
		vs = append(vs, Violation{Service: svc, Key: "build", Message: msg, Line: line})
	}
	switch node.Kind {
	case yaml.ScalarNode: // short form: build: <context>
		if msg := c.bind(node.Value); msg != "" {
			bad(node.Line, msg)
		}
	case yaml.MappingNode:
		context, dockerfile := ".", ""
		ctxLine, dfLine := node.Line, node.Line
		for _, f := range pairs(node) {
			switch f.key.Value {
			case "context":
				if f.val.Value != "" {
					context = f.val.Value
				}
				ctxLine = f.val.Line
			case "dockerfile":
				dockerfile = f.val.Value
				dfLine = f.val.Line
			}
		}
		if msg := c.bind(context); msg != "" {
			bad(ctxLine, msg)
		}
		if dockerfile != "" {
			// The Dockerfile path is relative to the context; confine context/dockerfile.
			if msg := c.bind(filepath.Join(context, dockerfile)); msg != "" {
				bad(dfLine, "build dockerfile "+quote(dockerfile)+": "+msg)
			}
		}
	default:
		bad(node.Line, "build must be a context path or a mapping")
	}
	return vs
}

// resolveAliases replaces every YAML alias node with a deep copy of its target,
// so downstream validation sees real content, never an unexpanded *anchor.
func resolveAliases(n *yaml.Node, depth int) {
	if n == nil || depth > 100 { // depth cap guards against pathological nesting
		return
	}
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		*n = *n.Alias
	}
	for _, c := range n.Content {
		resolveAliases(c, depth+1)
	}
}

type kvPair struct{ key, val *yaml.Node }

// pairs returns the key/value node pairs of a mapping node.
func pairs(m *yaml.Node) []kvPair {
	var out []kvPair
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, kvPair{key: m.Content[i], val: m.Content[i+1]})
	}
	return out
}

// confiner decides whether a bind source is safe: confined under run_dir and
// clear of sensitive + Helmsman-owned paths, evaluated on the symlink-resolved
// path (best-effort) so an existing symlink can't escape (review #5/#10). NOTE:
// a symlink created BETWEEN validation and `docker compose` (TOCTOU, review #14)
// and an attacker-forged run_dir/config_files label (review #8/#11) are NOT fully
// closed here; the durable fix is the M6/M8 model (Helmsman-owned run_dir +
// cat-file reads of the pinned commit, plan §5.6(e)).
type confiner struct {
	runDir    string
	protected []string
}

func (c confiner) bind(src string) string {
	if strings.HasPrefix(src, "~") {
		return "bind source " + quote(src) + " uses a home (~) path; binds must stay under the app directory"
	}
	resolved := src
	if !filepath.IsAbs(src) {
		resolved = filepath.Join(c.runDir, src)
	}
	resolved = filepath.Clean(resolved)
	real := evalExisting(resolved)
	realRunDir := evalExisting(filepath.Clean(c.runDir))

	forbidden := func() string {
		return "bind source " + quote(src) + " resolves to a forbidden host path " + quote(resolved)
	}
	if resolved == "/" || real == "/" {
		return forbidden()
	}
	if strings.HasSuffix(resolved, "/docker.sock") || strings.HasSuffix(real, "/docker.sock") {
		return forbidden()
	}
	denied := append(append([]string{}, sensitivePaths...), c.protected...)
	for _, sp := range denied {
		sp = filepath.Clean(sp)
		if sp == "" || sp == "/" {
			continue
		}
		if pathConflicts(resolved, sp) || pathConflicts(real, sp) {
			return forbidden()
		}
	}
	rel, err := filepath.Rel(realRunDir, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "bind source " + quote(src) + " escapes the app directory (resolved " + quote(real) + ")"
	}
	return ""
}

// checkVolumes confines every bind mount under runDir (plan §5.6 step 4).
func checkVolumes(svc string, node *yaml.Node, c confiner) []Violation {
	var vs []Violation
	if node.Kind != yaml.SequenceNode {
		return []Violation{{Service: svc, Key: "volumes", Message: "volumes must be a list", Line: node.Line}}
	}
	for _, entry := range node.Content {
		switch entry.Kind {
		case yaml.ScalarNode: // short form "source:target[:mode]"
			src := shortVolumeSource(entry.Value)
			if isBindSource(src) {
				if msg := c.bind(src); msg != "" {
					vs = append(vs, Violation{Service: svc, Key: "volumes", Message: msg, Line: entry.Line})
				}
			}
		case yaml.MappingNode: // long form {type, source, target}
			var src string
			for _, f := range pairs(entry) {
				if f.key.Value == "source" {
					src = f.val.Value
				}
			}
			// Type-agnostic: if the source looks like a host path, confine it
			// regardless of the declared `type` — never trust an attacker hint for
			// a security decision (review #3).
			if isBindSource(src) {
				if msg := c.bind(src); msg != "" {
					vs = append(vs, Violation{Service: svc, Key: "volumes", Message: msg, Line: entry.Line})
				}
			}
		default: // fail closed on any unrecognized node kind (review #7)
			vs = append(vs, Violation{Service: svc, Key: "volumes", Message: "unsupported volume entry", Line: entry.Line})
		}
	}
	return vs
}

func checkEnvFiles(svc string, node *yaml.Node, c confiner) []Violation {
	var vs []Violation
	check := func(p string, line int) {
		if msg := c.bind(p); msg != "" {
			vs = append(vs, Violation{Service: svc, Key: "env_file", Message: "env_file " + msg, Line: line})
		}
	}
	switch node.Kind {
	case yaml.ScalarNode:
		check(node.Value, node.Line)
	case yaml.SequenceNode:
		for _, e := range node.Content {
			switch e.Kind {
			case yaml.ScalarNode:
				check(e.Value, e.Line)
			case yaml.MappingNode:
				for _, f := range pairs(e) {
					if f.key.Value == "path" {
						check(f.val.Value, e.Line)
					}
				}
			default:
				vs = append(vs, Violation{Service: svc, Key: "env_file", Message: "unsupported env_file entry", Line: e.Line})
			}
		}
	}
	return vs
}

// checkTopLevelFileRefs scans top-level configs:/secrets: `file:` refs, which are
// real host-file bind surfaces mounted into services (critical review #2).
func checkTopLevelFileRefs(node *yaml.Node, kind string, c confiner) []Violation {
	var vs []Violation
	if node == nil || node.Kind != yaml.MappingNode {
		return vs
	}
	for _, entry := range pairs(node) {
		name := entry.key.Value
		if entry.val.Kind != yaml.MappingNode {
			continue
		}
		for _, f := range pairs(entry.val) {
			if f.key.Value == "file" && f.val.Kind == yaml.ScalarNode {
				if msg := c.bind(f.val.Value); msg != "" {
					vs = append(vs, Violation{Key: kind, Message: kind + " " + quote(name) + " " + msg, Line: f.val.Line})
				}
			}
		}
	}
	return vs
}

// checkTopLevelVolumes scans named-volume driver_opts host binds (e.g.
// {type: none, o: bind, device: /}) that become host binds when mounted by name
// (critical review #2).
func checkTopLevelVolumes(node *yaml.Node, c confiner) []Violation {
	var vs []Violation
	if node == nil || node.Kind != yaml.MappingNode {
		return vs
	}
	for _, entry := range pairs(node) {
		name := entry.key.Value
		if entry.val.Kind != yaml.MappingNode {
			continue
		}
		for _, f := range pairs(entry.val) {
			if f.key.Value == "driver_opts" && f.val.Kind == yaml.MappingNode {
				var device string
				for _, o := range pairs(f.val) {
					if o.key.Value == "device" {
						device = o.val.Value
					}
				}
				if device != "" && isBindSource(device) {
					if msg := c.bind(device); msg != "" {
						vs = append(vs, Violation{Key: "volumes", Message: "volume " + quote(name) + " device " + msg, Line: f.val.Line})
					}
				}
			}
		}
	}
	return vs
}

func shortVolumeSource(s string) string {
	// "source:target[:mode]" — but Windows paths have colons; for our purposes a
	// leading "/" or "./"/"../" or a name before the first ":" is the source.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return "" // anonymous volume (no source)
}

// isBindSource reports whether a volume source is a host path (bind), as opposed
// to a named volume (a bare name with no slash).
func isBindSource(src string) bool {
	if src == "" {
		return false
	}
	return strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") ||
		strings.HasPrefix(src, "~") || strings.Contains(src, "/")
}

// evalExisting resolves symlinks on the longest existing prefix of p, rejoining
// the non-existing tail, so an existing symlink in the path is followed even when
// the final target doesn't exist yet (review #5/#10).
func evalExisting(p string) string {
	p = filepath.Clean(p)
	suffix := ""
	cur := p
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			if suffix == "" {
				return real
			}
			return filepath.Join(real, suffix)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p // nothing along the path existed
		}
		suffix = filepath.Join(filepath.Base(cur), suffix)
		cur = parent
	}
}

// under reports whether x is within y (x == y or x is a descendant of y).
func under(x, y string) bool {
	if x == y {
		return true
	}
	return strings.HasPrefix(x, y+string(filepath.Separator))
}

// pathConflicts reports whether a and b are the same, or one contains the other.
func pathConflicts(a, b string) bool { return under(a, b) || under(b, a) }

func quote(s string) string { return "\"" + s + "\"" }

// reservedHostPorts belong to the managed edge — an app may NEVER publish them
// (plan §5.6 edge-collision (a): the edge owns 80/443; declare an internal port +
// an edge route instead).
var reservedHostPorts = map[int]bool{80: true, 443: true}

// checkPorts rejects any service publishing a reserved host port (80/443). It
// parses both the short form ("80:8080", "127.0.0.1:443:8080", "80-90:...") and
// the long mapping form ({published, target, ...}).
func checkPorts(svc string, node *yaml.Node) []Violation {
	var vs []Violation
	if node.Kind != yaml.SequenceNode {
		return []Violation{{Service: svc, Key: "ports", Message: "ports must be a list", Line: node.Line}}
	}
	reject := func(line int) {
		vs = append(vs, Violation{Service: svc, Key: "ports", Line: line,
			Message: "publishing host port 80/443 is forbidden — the managed edge owns them; declare an internal port and add an edge route"})
	}
	for _, entry := range node.Content {
		switch entry.Kind {
		case yaml.ScalarNode:
			if p, ok := shortFormHostPort(entry.Value); ok && reservedHostPorts[p] {
				reject(entry.Line)
			}
		case yaml.MappingNode:
			for _, kv := range pairs(entry) {
				if kv.key.Value == "published" {
					if p := startPort(kv.val.Value); reservedHostPorts[p] {
						reject(entry.Line)
					}
				}
			}
		}
	}
	return vs
}

// shortFormHostPort extracts the HOST port from a short-form ports entry, or
// ok=false when the entry publishes nothing (bare container port). Forms:
// "c", "h:c", "ip:h:c" (h/c may be ranges → start of range).
func shortFormHostPort(s string) (int, bool) {
	s = strings.TrimSpace(strings.Trim(s, `"'`))
	if s == "" {
		return 0, false
	}
	// Strip a trailing "/proto".
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// Strip a bracketed IPv6 host-IP prefix "[....]:" so the colon-split below
	// sees only "host:container" (a naive split on a raw IPv6 would slip a :80
	// publish past the check).
	if strings.HasPrefix(s, "[") {
		if j := strings.IndexByte(s, ']'); j >= 0 {
			s = strings.TrimPrefix(s[j+1:], ":")
		}
	}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		return 0, false // container-only, no host publish
	case 2:
		return startPort(parts[0]), true // host:container
	case 3:
		return startPort(parts[1]), true // ip:host:container
	}
	return 0, false
}

// startPort parses a port or the start of a "N-M" range.
func startPort(s string) int {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s = s[:i]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// SortViolations orders violations by line for stable display.
func (r *Result) SortViolations() {
	sort.SliceStable(r.Violations, func(i, j int) bool { return r.Violations[i].Line < r.Violations[j].Line })
}
