//go:build !unix

package web

// oNoFollow is unavailable off-unix; the Lstat pre-check is the guard there.
const oNoFollow = 0
