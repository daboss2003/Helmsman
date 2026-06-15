// Package backup is the app data backup/restore core (plan §7.10, §16). The docker
// orchestration (throwaway RO backup containers, DB-dump sidecars) is write-plane;
// THIS file is the security-critical, I/O-streaming crypto + the hostile-input
// hardening (restore.go) + the prune denylist (denylist.go), all pure/streaming and
// exhaustively testable.
//
// stream.go is the chunked AES-256-GCM pipeline: tar → gzip → THIS → sink. It never
// buffers the whole stream in RSS (works on a tiny box), and the chunk chaining
// makes tampering, REORDERING, and TRUNCATION all detectable — a silently-truncated
// or shuffled backup must never restore as "success".
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	chunkSize   = 64 << 10 // plaintext bytes per chunk
	nonceLen    = 12
	tagLen      = 16
	streamIDLen = 16        // random per-backup id, authenticated into every chunk's AAD
	magic       = "HMBK1\n" // format magic + version
)

// ErrCorrupt means the stream failed authentication (tamper / wrong key / reorder /
// truncation) — fail-closed, never a partial restore.
var ErrCorrupt = errors.New("backup: stream is corrupt or tampered")

// Encrypt reads plaintext from src and writes the chunked, authenticated stream to
// dst. maxBytes caps the plaintext (0 = no cap); exceeding it errors rather than
// writing an unbounded archive. The AAD of each chunk binds its INDEX and a final
// flag, so a decryptor detects a dropped, duplicated, or reordered chunk.
func Encrypt(dst io.Writer, src io.Reader, key []byte, maxBytes int64) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(dst, magic); err != nil {
		return err
	}
	// A random per-backup stream id, written in the header and authenticated into
	// EVERY chunk's AAD, so a chunk from one backup can't be spliced into another
	// (same key, same index) and still authenticate.
	streamID := make([]byte, streamIDLen)
	if _, err := rand.Read(streamID); err != nil {
		return err
	}
	if _, err := dst.Write(streamID); err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	var idx uint64
	var total int64
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			total += int64(n)
			if maxBytes > 0 && total > maxBytes {
				return fmt.Errorf("backup: source exceeds the %d-byte cap", maxBytes)
			}
		}
		final := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if rerr != nil && !final {
			return rerr
		}
		if err := writeChunk(dst, aead, buf[:n], streamID, idx, final); err != nil {
			return err
		}
		if final {
			return nil
		}
		idx++
	}
}

// Decrypt reads the chunked stream from src, authenticates every chunk IN ORDER, and
// writes the plaintext to dst. It returns ErrCorrupt on any auth failure, a
// missing/early final chunk (truncation), or extra data after the final chunk.
func Decrypt(dst io.Writer, src io.Reader, key []byte) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	hdr := make([]byte, len(magic))
	if _, err := io.ReadFull(src, hdr); err != nil || string(hdr) != magic {
		return ErrCorrupt
	}
	streamID := make([]byte, streamIDLen)
	if _, err := io.ReadFull(src, streamID); err != nil {
		return ErrCorrupt
	}
	var idx uint64
	for {
		pt, final, err := readChunk(src, aead, streamID, idx)
		if err != nil {
			return err
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		if final {
			// Nothing may follow the final chunk (a trailing forged chunk is an attack).
			if _, err := src.Read(make([]byte, 1)); err != io.EOF {
				return ErrCorrupt
			}
			return nil
		}
		idx++
	}
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("backup: key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds the stream id + chunk index + final flag, so reorder, truncation, AND
// cross-stream splice (a chunk from another backup) are all detected.
func aad(streamID []byte, idx uint64, final bool) []byte {
	a := make([]byte, len(streamID)+9)
	copy(a, streamID)
	binary.BigEndian.PutUint64(a[len(streamID):len(streamID)+8], idx)
	if final {
		a[len(streamID)+8] = 1
	}
	return a
}

func writeChunk(dst io.Writer, aead cipher.AEAD, pt, streamID []byte, idx uint64, final bool) error {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, pt, aad(streamID, idx, final))
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(ct)))
	if _, err := dst.Write(lenbuf[:]); err != nil {
		return err
	}
	if _, err := dst.Write(nonce); err != nil {
		return err
	}
	_, err := dst.Write(ct)
	return err
}

func readChunk(src io.Reader, aead cipher.AEAD, streamID []byte, idx uint64) (pt []byte, final bool, err error) {
	var lenbuf [4]byte
	if _, err := io.ReadFull(src, lenbuf[:]); err != nil {
		return nil, false, ErrCorrupt // a stream that ends before a final chunk is truncated
	}
	clen := binary.BigEndian.Uint32(lenbuf[:])
	if clen < tagLen || clen > chunkSize+tagLen {
		return nil, false, ErrCorrupt
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, false, ErrCorrupt
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(src, ct); err != nil {
		return nil, false, ErrCorrupt
	}
	// Try final=false first, then final=true — the AAD flag distinguishes them, and
	// GCM auth tells us which (an attacker can't flip the flag without failing both).
	if p, e := aead.Open(nil, nonce, ct, aad(streamID, idx, false)); e == nil {
		return p, false, nil
	}
	if p, e := aead.Open(nil, nonce, ct, aad(streamID, idx, true)); e == nil {
		return p, true, nil
	}
	return nil, false, ErrCorrupt
}
