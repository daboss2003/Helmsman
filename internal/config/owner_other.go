//go:build !unix

package config

import "io/fs"

// fileOwner cannot determine ownership on non-unix platforms; callers fail closed
// (Mooring targets Linux/systemd).
func fileOwner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}
