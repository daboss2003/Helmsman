package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// cmd_doctor.go is the host-prerequisites helper. Helmsman's RUNTIME service is
// deliberately unprivileged — it can't install packages, edit host DNS, or grant
// capabilities (that's the security model: a compromised dashboard must not be able
// to either). So prerequisites are an explicit, admin-run, root, install-time job —
// which this makes one command instead of a scavenger hunt:
//
//	helmsman doctor   — read-only: report what's missing + the exact fix (any user).
//	helmsman setup    — print a fix PLAN (dry run); `--yes` applies it (root, apt).
//
// `setup` only performs SAFE, idempotent, well-understood mutations (install Caddy /
// nginx+stream, apply the caps drop-in). It NEVER auto-rewrites host DNS or frees
// :53 — that broke a box once already — it prints those steps for you to run.
const (
	caddyKeyURL   = "https://dl.cloudsmith.io/public/caddy/stable/gpg.key"
	caddyKeyPath  = "/usr/share/keyrings/caddy-stable-archive-keyring.asc"
	caddyListPath = "/etc/apt/sources.list.d/caddy-stable.list"
	caddySources  = "deb [signed-by=" + caddyKeyPath + "] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n"
	capsSrc       = "/usr/share/helmsman/systemd/helmsman-privileged-ports.conf"
	capsDst       = "/etc/systemd/system/helmsman.service.d/helmsman-privileged-ports.conf"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	l4 := fs.Bool("l4", false, "also check the L4 (nginx stream) prerequisites")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		fmt.Println("helmsman doctor: host checks run on Linux only.")
		return nil
	}
	rep := preflight(*l4)
	rep.print(os.Stdout)
	if rep.hasFail() {
		fmt.Println("\nRun `sudo helmsman setup` to review a fix plan, then `sudo helmsman setup --yes` to apply it.")
	} else {
		fmt.Println("\nAll required prerequisites are present.")
	}
	return nil
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "apply the changes (default: print the plan only)")
	l4 := fs.Bool("l4", false, "also install the L4 prerequisites (nginx + stream module)")
	restart := fs.Bool("restart", false, "restart the helmsman service after applying")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("setup runs on Linux only")
	}
	if !have("apt-get") {
		fmt.Println("helmsman setup auto-installs via apt (Debian/Ubuntu). On other distros, install")
		fmt.Println("Caddy (and nginx + the stream module for L4) per docs/installation.md, then `helmsman doctor`.")
		return nil
	}
	if *yes && os.Geteuid() != 0 {
		return fmt.Errorf("applying changes needs root — run: sudo helmsman setup --yes")
	}

	preflight(*l4).print(os.Stdout)

	steps := plan(*yes, *l4, *restart)
	if len(steps) == 0 {
		fmt.Println("\nNothing to install — all prerequisites are already in place.")
		printDNSGuidance(*l4)
		return nil
	}
	fmt.Printf("\nPlan — %d step(s):\n", len(steps))
	for i, s := range steps {
		fmt.Printf("  %d. %s\n", i+1, s.desc)
	}
	if !*yes {
		fmt.Println("\nThis was a DRY RUN — nothing changed. Re-run as `sudo helmsman setup --yes` to apply.")
		printDNSGuidance(*l4)
		return nil
	}
	fmt.Println("\nApplying:")
	for i, s := range steps {
		fmt.Printf("\n  %d. %s\n", i+1, s.desc)
		if err := s.do(); err != nil {
			return fmt.Errorf("step %q failed: %w", s.desc, err)
		}
	}
	fmt.Println("\nDone.")
	printDNSGuidance(*l4)
	return nil
}

// step is one planned host mutation; do() prints the action and (when apply) runs it.
type step struct {
	desc string
	do   func() error
}

// plan builds the ordered fix steps for whatever is missing. apply=false makes each
// do() print-only, so the SAME list drives the dry run and the real run.
func plan(apply, l4, restart bool) []step {
	var steps []step
	if !have("caddy") {
		steps = append(steps,
			step{"add the Caddy apt repo + signing key", func() error { return writeCaddyRepo(apply) }},
			step{"apt-get update", func() error { return run(apply, "apt-get", "update") }},
			step{"install caddy", func() error { return run(apply, "apt-get", "install", "-y", "caddy") }},
			step{"disable the distro caddy.service (Helmsman supervises its own child)", func() error { return run(apply, "systemctl", "disable", "--now", "caddy") }},
		)
	}
	if l4 && !have("nginx") {
		steps = append(steps,
			step{"install nginx + the stream module", func() error { return run(apply, "apt-get", "install", "-y", "nginx", "libnginx-mod-stream") }},
			step{"disable the distro nginx.service (Helmsman supervises its own child)", func() error { return run(apply, "systemctl", "disable", "--now", "nginx") }},
		)
	}
	if !fileExists(capsDst) {
		steps = append(steps,
			step{"grant the edge/L4 children CAP_NET_BIND_SERVICE (systemd drop-in)", func() error { return installCapsDropin(apply) }},
			step{"systemctl daemon-reload", func() error { return run(apply, "systemctl", "daemon-reload") }},
		)
	}
	if restart {
		steps = append(steps, step{"restart the helmsman service", func() error { return run(apply, "systemctl", "restart", "helmsman") }})
	}
	return steps
}

// --- checks ---

type result struct{ name, state, detail, fix string }

type report struct{ results []result }

func (r *report) add(x result) { r.results = append(r.results, x) }
func (r report) hasFail() bool {
	for _, x := range r.results {
		if x.state == "fail" {
			return true
		}
	}
	return false
}

func (r report) print(w io.Writer) {
	icon := map[string]string{"ok": "✓", "warn": "!", "fail": "✗"}
	for _, x := range r.results {
		fmt.Fprintf(w, "  %s %-16s %s\n", icon[x.state], x.name, x.detail)
		if x.state != "ok" && x.fix != "" {
			fmt.Fprintf(w, "      → %s\n", x.fix)
		}
	}
}

func preflight(l4 bool) report {
	var r report
	r.add(checkBinary("caddy", "managed HTTPS edge (:80/:443 + ACME)", "sudo helmsman setup --yes"))
	r.add(checkBinary("docker", "container read/write plane", "install Docker + the compose plugin"))
	r.add(checkDNS())
	r.add(checkCaps())
	if l4 {
		r.add(checkBinary("nginx", "L4 (TCP/UDP) load balancer", "sudo helmsman setup --l4 --yes"))
		r.add(checkStreamModule())
		r.add(checkResolvedStub())
	}
	return r
}

func checkBinary(bin, what, fix string) result {
	if p, err := exec.LookPath(bin); err == nil {
		return result{bin, "ok", "found at " + p + " — " + what, ""}
	}
	return result{bin, "fail", "MISSING — " + what, fix}
}

func checkDNS() result {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, "github.com"); err != nil {
		return result{"dns", "fail", "name resolution is broken (" + err.Error() + ")",
			"check /etc/resolv.conf has a working nameserver — see installation docs"}
	}
	return result{"dns", "ok", "host name resolution works", ""}
}

func checkCaps() result {
	if fileExists(capsDst) {
		return result{"net-bind cap", "ok", "privileged-ports drop-in is installed", ""}
	}
	return result{"net-bind cap", "warn", "no CAP_NET_BIND_SERVICE drop-in — the edge/L4 can't bind <1024",
		"sudo helmsman setup --yes (installs the drop-in)"}
}

func checkStreamModule() result {
	if m, _ := filepath.Glob("/etc/nginx/modules-enabled/*stream*.conf"); len(m) > 0 {
		return result{"nginx stream", "ok", "stream module is enabled", ""}
	}
	return result{"nginx stream", "warn", "stream module not found in /etc/nginx/modules-enabled/",
		"sudo apt install libnginx-mod-stream (else nginx rejects the L4 config)"}
}

func checkResolvedStub() result {
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil && strings.Contains(string(b), "127.0.0.53") {
		return result{"port 53", "warn", "systemd-resolved holds 127.0.0.53:53 — collides with a DNS l4_route",
			"free :53 before deploying a :53 resolver (printed below / see L4 docs)"}
	}
	return result{"port 53", "ok", "no systemd-resolved stub on 127.0.0.53", ""}
}

// --- actions ---

func run(apply bool, name string, arg ...string) error {
	fmt.Printf("       $ %s %s\n", name, strings.Join(arg, " "))
	if !apply {
		return nil
	}
	cmd := exec.Command(name, arg...) // fixed binary + args; no shell (SEC-1)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func writeCaddyRepo(apply bool) error {
	fmt.Printf("       write %s (Caddy signing key, fetched over HTTPS)\n", caddyKeyPath)
	fmt.Printf("       write %s\n", caddyListPath)
	if !apply {
		return nil
	}
	key, err := httpGet(caddyKeyURL)
	if err != nil {
		return fmt.Errorf("fetch Caddy signing key: %w", err)
	}
	if err := writeRootFile(caddyKeyPath, key); err != nil {
		return err
	}
	return writeRootFile(caddyListPath, []byte(caddySources))
}

func installCapsDropin(apply bool) error {
	fmt.Printf("       install %s → %s\n", capsSrc, capsDst)
	if !apply {
		return nil
	}
	b, err := os.ReadFile(capsSrc)
	if err != nil {
		return fmt.Errorf("read %s (is the helmsman package installed?): %w", capsSrc, err)
	}
	return writeRootFile(capsDst, b)
}

func writeRootFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func printDNSGuidance(l4 bool) {
	if !l4 {
		return
	}
	fmt.Println("\nDNS resolver on :53? systemd-resolved holds 127.0.0.53:53 by default. `setup` does")
	fmt.Println("NOT touch host DNS (rewriting it unattended is too risky) — if you bind :53, run:")
	fmt.Println("  printf '[Resolve]\\nDNSStubListener=no\\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf")
	fmt.Println("  sudo systemctl restart systemd-resolved")
	fmt.Println("  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf   # NOT stub-resolv.conf")
}

func have(bin string) bool     { _, err := exec.LookPath(bin); return err == nil }
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
