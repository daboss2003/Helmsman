package definition

import (
	"encoding/json"
	"sort"
	"strings"
)

// Field-level 3-way merge (plan §7.7). Last-writer-wins is explicitly REJECTED: the
// repo helmsman.yaml is desired intent, canonical.yaml is the live source of truth,
// and base is the common ancestor. Per field:
//   - both sides agree → take it (no-op or same change);
//   - only the LOCAL side (dashboard/canonical) changed → take it;
//   - only the REPO side changed → take it, but it REQUIRES operator acknowledgement
//     (a dashboard apply never silently folds in attacker-committed repo changes);
//   - both changed the same field differently → a CONFLICT (never auto-merged).
//
// The merge runs over the canonical JSON flattened to leaf field paths (arrays are
// compared whole, at their path), so a smuggled change can't hide below the diff.

// Conflict is one field both sides changed differently.
type Conflict struct {
	Path  string
	Base  string
	Local string
	Repo  string
}

// MergeResult is the outcome of a 3-way merge.
type MergeResult struct {
	merged      map[string]string
	Conflicts   []Conflict // both sides changed → must be resolved, never auto-merged
	RepoChanges []string   // fields the repo changed (and local didn't) → require ack
}

// Clean reports whether the merge can be applied without operator intervention
// (no conflicts AND no unacknowledged repo-side changes).
func (m MergeResult) Clean() bool { return len(m.Conflicts) == 0 && len(m.RepoChanges) == 0 }

// Merge3 performs the field-level 3-way merge of the local (canonical/dashboard) and
// repo definitions against their common ancestor base.
func Merge3(base, local, repo *Definition) (MergeResult, error) {
	bm, err := flattenDef(base)
	if err != nil {
		return MergeResult{}, err
	}
	lm, err := flattenDef(local)
	if err != nil {
		return MergeResult{}, err
	}
	rm, err := flattenDef(repo)
	if err != nil {
		return MergeResult{}, err
	}

	paths := map[string]bool{}
	for p := range bm {
		paths[p] = true
	}
	for p := range lm {
		paths[p] = true
	}
	for p := range rm {
		paths[p] = true
	}

	res := MergeResult{merged: map[string]string{}}
	for p := range paths {
		b, l, r := bm[p], lm[p], rm[p]
		switch {
		case l == r:
			setIfPresent(res.merged, p, l) // agree (incl. both-deleted ⇒ absent)
		case l == b:
			// only the repo side changed → take it, but flag for acknowledgement.
			setIfPresent(res.merged, p, r)
			res.RepoChanges = append(res.RepoChanges, p)
		case r == b:
			setIfPresent(res.merged, p, l) // only the local side changed → take it
		default:
			res.Conflicts = append(res.Conflicts, Conflict{Path: p, Base: b, Local: l, Repo: r})
		}
	}
	sort.Strings(res.RepoChanges)
	sort.Slice(res.Conflicts, func(i, j int) bool { return res.Conflicts[i].Path < res.Conflicts[j].Path })
	return res, nil
}

// Definition reassembles the merged field map back into a typed Definition. It is
// only meaningful when the merge is Clean() (a conflicted merge has no single result).
func (m MergeResult) Definition() (*Definition, error) {
	return unflattenDef(m.merged)
}

// flattenDef marshals a definition to canonical JSON and flattens it to
// path→json-leaf (objects recurse; arrays/scalars are whole leaves). An empty/absent
// value simply has no entry.
func flattenDef(d *Definition) (map[string]string, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	out := map[string]string{}
	flattenJSON("", v, out)
	return out, nil
}

func flattenJSON(prefix string, v any, out map[string]string) {
	if v == nil {
		return // a null (e.g. a nil pointer field) is treated as ABSENT, not a leaf —
		// so a nil pointer and an unset object compare equal (no phantom path).
	}
	if m, ok := v.(map[string]any); ok && len(m) > 0 {
		for k, val := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flattenJSON(p, val, out)
		}
		return
	}
	// arrays, scalars, and empty objects are whole leaves.
	b, _ := json.Marshal(v)
	out[prefix] = string(b)
}

func unflattenDef(m map[string]string) (*Definition, error) {
	root := map[string]any{}
	for path, val := range m {
		var v any
		if err := json.Unmarshal([]byte(val), &v); err != nil {
			return nil, err
		}
		setPath(root, strings.Split(path, "."), v)
	}
	b, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	var d Definition
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// setIfPresent records a merged field only when it is present (a non-empty value);
// an absent field ("") is simply left out so it never reaches unflatten as bad JSON.
func setIfPresent(m map[string]string, path, val string) {
	if val != "" {
		m[path] = val
	}
}

func setPath(root map[string]any, keys []string, v any) {
	cur := root
	for i, k := range keys {
		if i == len(keys)-1 {
			cur[k] = v
			return
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[k] = next
		}
		cur = next
	}
}
