package envimport

import "sort"

// Re-import is a MERGE/DIFF, never a clobber (plan §7.9). The categories are computed
// WITHOUT revealing any secret value (only key names surface). A change that ROTATES
// a live secret or DOWNGRADES a secret to a plain literal is lifted out of the bulk
// confirm into its own per-secret confirm (Rotations) — a higher-friction action.

// Current is the backend's view of one already-stored entry (the caller resolves the
// value from the encrypted store; it never leaves the backend).
type Current struct {
	Value  string
	Secret bool
}

// DiffResult buckets an import against the current store, by key name only.
type DiffResult struct {
	Added     []string // new keys
	Changed   []string // existing PLAIN keys whose value changed
	Unchanged []string // identical keys
	Rotations []string // a secret whose value changed, OR a secret→plain downgrade — needs a per-secret confirm
}

// NeedsRotationConfirm reports whether the import touches any live secret in a way
// that requires the separate per-secret confirmation.
func (d DiffResult) NeedsRotationConfirm() bool { return len(d.Rotations) > 0 }

// Diff compares imported entries against the current store. Value comparison happens
// here (backend-side); only key names are returned.
func Diff(current map[string]Current, imported []Entry) DiffResult {
	var d DiffResult
	for _, e := range imported {
		cur, exists := current[e.Key]
		switch {
		case !exists:
			d.Added = append(d.Added, e.Key)
		case cur.Value == e.Value.Reveal() && cur.Secret == e.Secret:
			d.Unchanged = append(d.Unchanged, e.Key)
		case cur.Secret && !e.Secret:
			// secret → plain downgrade: a live secret would stop being protected.
			d.Rotations = append(d.Rotations, e.Key)
		case cur.Secret && cur.Value != e.Value.Reveal():
			// rotating a live secret value.
			d.Rotations = append(d.Rotations, e.Key)
		default:
			// a plain value changed (or plain→secret upgrade) — ordinary change.
			d.Changed = append(d.Changed, e.Key)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Changed)
	sort.Strings(d.Unchanged)
	sort.Strings(d.Rotations)
	return d
}
