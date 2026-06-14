//go:build unix

package web

import "syscall"

// oNoFollow makes an open() fail if the final path component is a symlink, so a
// fixed-path read cannot be redirected by a symlink swapped in after a stat
// (TOCTOU). 0 on platforms without it.
const oNoFollow = syscall.O_NOFOLLOW
