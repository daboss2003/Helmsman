// Command helmsman is the single static binary: the admin server and the
// root-of-trust CLI (plan §2, §5.1). Subcommands that read secrets read them
// from /dev/tty, never from argv or the environment.
package main

import (
	"fmt"
	"os"
)

const usage = `helmsman — lightweight, security-first self-hosted ops dashboard

Usage:
  helmsman <command> [flags]

Server:
  serve            Load config, open the DB, and run the loopback admin server.

Definition file (helmsman.yaml — same validation as the dashboard):
  validate         Parse + validate a helmsman.yaml through the §5.6/§6.2 chokepoints
                   (read-only, no DB — safe in CI).
  init             Scaffold a helmsman.yaml from an existing compose (--from-compose).

Root of trust (run over SSH; secrets read from /dev/tty, never argv):
  gen-key          Generate the AES-256-GCM master key (base64).
  hash-password    Produce an argon2id hash for auth.password_hash.
  gen-totp         Generate a TOTP secret (+ otpauth URL).
  verify-key       Confirm the configured key matches the DB before it corrupts.

Other:
  version          Print version information.
  help             Show this help.

Flags:
  --config PATH    Config file (default /etc/helmsman/config.yaml).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "validate":
		err = cmdValidate(args)
	case "init":
		err = cmdInit(args)
	case "gen-key":
		err = cmdGenKey(args)
	case "hash-password":
		err = cmdHashPassword(args)
	case "gen-totp":
		err = cmdGenTOTP(args)
	case "verify-key":
		err = cmdVerifyKey(args)
	case "version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "helmsman: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "helmsman %s: %v\n", cmd, err)
		os.Exit(1)
	}
}
