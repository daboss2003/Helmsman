//go:build unix

package store

import "syscall"

// umask sets the process umask and returns the previous value. On unix this
// keeps SQLite's -wal/-shm side files from being group/world readable.
func umask(mask int) int { return syscall.Umask(mask) }
