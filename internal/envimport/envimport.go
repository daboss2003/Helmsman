// Package envimport is the env import-and-own pipeline (plan §7.9). A user-provided
// .env is an IMPORT SOURCE only — its values are copied into the encrypted store and
// the uploaded file is never the live file (Helmsman renders a fresh 0600 --env-file
// from the store at every deploy). Every stage treats the input as hostile: parse
// (a dotenv reader, not a shell) → hygiene (key charset, NUL reject) → classify
// (biased to secret) → the §7.4 literal-secret HARD STOP → ingest by reference.
// Values are wrapped in secret.Redacted from parse-time so they never leak.
package envimport

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/daboss2003/Helmsman/internal/cfgfile"
	"github.com/daboss2003/Helmsman/internal/compose"
	"github.com/daboss2003/Helmsman/internal/secret"
)

// maxImportBytes caps an uploaded .env (a decode-bomb defence).
const maxImportBytes = 256 << 10

// importKeyRe is the §7.9 import key grammar — UPPER_SNAKE only.
var importKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// secretKeyHint biases classification toward "secret" by NAME (a value that doesn't
// look high-entropy but whose key says SECRET/TOKEN/etc. is still treated as secret).
var secretKeyHint = regexp.MustCompile(`(SECRET|TOKEN|PASSWORD|PASSWD|_PASS|PRIVATE|CREDENTIAL|APIKEY|API_KEY|_KEY|AUTH|SALT|SEED|DSN|CONNECTION_STRING|ACCESS_KEY)`)

// Entry is one classified, hygiene-checked env var. Value is Redacted from parse.
type Entry struct {
	Key    string
	Value  secret.Redacted
	Secret bool // classified secret-shaped (→ the encrypted store, by reference)
}

// Parse runs the acquire→parse→hygiene→classify pipeline over imported .env bytes.
// Classification is BIASED TO SECRET: a value is secret if the §7.4 literal-secret
// lint flags it OR its key looks secret-y. The result is safe to diff/ingest; values
// never appear in errors (only key names).
func Parse(raw []byte) ([]Entry, error) {
	if len(raw) > maxImportBytes {
		return nil, fmt.Errorf("import too large (%d bytes, max %d)", len(raw), maxImportBytes)
	}
	env := compose.ParseEnvFile(raw) // dotenv, not a shell; ${VAR} kept opaque
	out := make([]Entry, 0, len(env))
	for k, v := range env {
		if !importKeyRe.MatchString(k) {
			return nil, fmt.Errorf("env key %q is invalid (must match ^[A-Z_][A-Z0-9_]*$)", k)
		}
		if strings.ContainsRune(v, 0) {
			return nil, fmt.Errorf("env value for %q contains a NUL byte", k)
		}
		_, lintSecret := cfgfile.LiteralSecretLint([]byte(v))
		out = append(out, Entry{
			Key:    k,
			Value:  secret.New(v),
			Secret: lintSecret || secretKeyHint.MatchString(k),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ValidateForIngest is the §7.4 literal-secret HARD STOP — override-proof. Before any
// entry is written, every PLAIN entry is re-linted; a secret-shaped value classified
// (or forced by an operator) as plain is rejected, so a mislabeled secret can never
// round-trip into a committable plain literal / canonical.yaml.
func ValidateForIngest(entries []Entry) error {
	for _, e := range entries {
		if e.Secret {
			continue
		}
		if reason, isSecret := cfgfile.LiteralSecretLint([]byte(e.Value.Reveal())); isSecret {
			return fmt.Errorf("%s looks like a secret (%s) and cannot be stored as a plain literal — it must be a secret (this cannot be overridden)", e.Key, reason)
		}
	}
	return nil
}
