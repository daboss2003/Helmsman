//go:build !unix

package store

// umask is a no-op on non-unix platforms (Mooring targets Linux/systemd; this
// keeps `go build` green on dev machines that aren't unix).
func umask(mask int) int { return 0 }
