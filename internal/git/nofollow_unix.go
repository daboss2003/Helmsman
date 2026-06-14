//go:build unix

package git

import "syscall"

// oNoFollow makes OpenFile refuse to follow a symlink at the final path component
// (defense against a pre-existing symlink at an extraction target).
const oNoFollow = syscall.O_NOFOLLOW
