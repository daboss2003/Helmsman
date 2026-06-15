package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
)

// denylist.go is the §16.2 prune-safety analog of the §5.6 allowlist: it is computed
// FRESH from live state and is FAIL-CLOSED — only the provably-safe COMPLEMENT may be
// pruned. The caller resolves LiveState atomically under the held one-docker-child
// semaphore (no deploy interleaves) and never trusts `dangling=true` to be safe.

// LiveState is the fresh-from-live view the prune denylist resolves against. All
// image identities are RESOLVED DIGESTS (never tags), so a rollback image can't be
// pruned just because it's currently dangling/untagged.
type LiveState struct {
	ProtectedImages  map[string]bool // child-proxy / edge / socket-proxy images
	ReferencedImages map[string]bool // referenced by any app's DEPLOYED or ROLLBACK compose
	InUseImages      map[string]bool // images of running containers
	ProtectedVolumes map[string]bool // edge/ACME/control-plane volumes
	SoleDataVolumes  map[string]bool // a volume that is an app's ONLY data store
	BackedUpVolumes  map[string]bool // verified present in backup_inventory
}

// PruneImageSafe reports whether an image (by resolved digest) may be pruned. It
// denies anything provably unsafe; everything else is the safe complement.
func PruneImageSafe(digest string, s LiveState) (bool, string) {
	if digest == "" {
		return false, "unresolved image digest — refusing to prune"
	}
	// Fail-closed: an unresolved LiveState (nil maps — e.g. the docker list failed)
	// must NOT let everything fall into the safe-complement branch. The caller MUST
	// populate every map (even empty) only after a successful, atomic resolve.
	if s.ProtectedImages == nil || s.ReferencedImages == nil || s.InUseImages == nil {
		return false, "live state not fully resolved — refusing to prune (fail-closed)"
	}
	switch {
	case s.ProtectedImages[digest]:
		return false, "protected control-plane image (child-proxy/edge/socket-proxy)"
	case s.ReferencedImages[digest]:
		return false, "referenced by a deployed or rollback compose (by resolved digest)"
	case s.InUseImages[digest]:
		return false, "in use by a running container"
	default:
		return true, ""
	}
}

// PruneVolumeSafe reports whether a volume may be removed. A sole-data volume may be
// removed ONLY if it is verified present in backup_inventory ("back it up first").
func PruneVolumeSafe(name string, s LiveState) (bool, string) {
	if name == "" {
		return false, "empty volume name"
	}
	if s.ProtectedVolumes == nil || s.SoleDataVolumes == nil || s.BackedUpVolumes == nil {
		return false, "live state not fully resolved — refusing to prune (fail-closed)"
	}
	switch {
	case s.ProtectedVolumes[name]:
		return false, "protected volume (edge/ACME/control-plane)"
	case s.SoleDataVolumes[name] && !s.BackedUpVolumes[name]:
		return false, "an app's only data store and not in backup_inventory — back it up first"
	default:
		return true, ""
	}
}

// RestoreTuple binds the FULL restore operation (plan §7.10): plaintext + ciphertext
// digests, the resolved target volumes, the service-binding set, and the member
// sizes. The confirm token is hash(tuple); it is re-derived under the held
// write-plane lock at execute and VOIDED on any drift (not just archive bytes), so a
// swapped archive / re-pointed target / changed size invalidates the confirmation.
func RestoreTuple(plaintextSHA, ciphertextSHA string, targetVolumes, bindings []string, sizes []int64) string {
	tv := append([]string{}, targetVolumes...)
	bn := append([]string{}, bindings...)
	sort.Strings(tv)
	sort.Strings(bn)
	h := sha256.New()
	w := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	w("v1")
	w("pt:" + plaintextSHA)
	w("ct:" + ciphertextSHA)
	for _, v := range tv {
		w("vol:" + v)
	}
	for _, b := range bn {
		w("bind:" + b)
	}
	for _, sz := range sizes {
		w("sz:" + strconv.FormatInt(sz, 10))
	}
	return hex.EncodeToString(h.Sum(nil))
}
