package backup

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func key32() []byte { k := make([]byte, 32); rand.Read(k); return k }

func roundtrip(t *testing.T, plain []byte) {
	t.Helper()
	k := key32()
	var enc bytes.Buffer
	if err := Encrypt(&enc, bytes.NewReader(plain), k, 0); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(enc.Bytes()), k); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), plain) {
		t.Errorf("round-trip mismatch (len %d → %d)", len(plain), dec.Len())
	}
}

func TestStreamRoundTripSizes(t *testing.T) {
	for _, n := range []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 7} {
		buf := make([]byte, n)
		rand.Read(buf)
		roundtrip(t, buf)
	}
}

func encrypted(t *testing.T, plain []byte, k []byte) []byte {
	t.Helper()
	var enc bytes.Buffer
	if err := Encrypt(&enc, bytes.NewReader(plain), k, 0); err != nil {
		t.Fatal(err)
	}
	return enc.Bytes()
}

func TestStreamWrongKeyFails(t *testing.T) {
	blob := encrypted(t, []byte("hello world"), key32())
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(blob), key32()); err != ErrCorrupt {
		t.Errorf("wrong key must fail with ErrCorrupt, got %v", err)
	}
}

func TestStreamTamperDetected(t *testing.T) {
	k := key32()
	blob := encrypted(t, bytes.Repeat([]byte("A"), 1000), k)
	blob[len(blob)/2] ^= 0xff // flip a byte in the ciphertext
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(blob), k); err != ErrCorrupt {
		t.Errorf("a tampered byte must fail, got %v", err)
	}
}

func TestStreamTruncationDetected(t *testing.T) {
	k := key32()
	// Multi-chunk so dropping the tail removes the FINAL chunk.
	blob := encrypted(t, bytes.Repeat([]byte("B"), 3*chunkSize), k)
	truncated := blob[:len(blob)-chunkSize] // drop ~the last chunk
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(truncated), k); err != ErrCorrupt {
		t.Errorf("a truncated stream must fail (missing final chunk), got %v", err)
	}
}

func TestStreamReorderDetected(t *testing.T) {
	k := key32()
	plain := bytes.Repeat([]byte("C"), 2*chunkSize) // exactly 2 full chunks + a final empty
	var enc bytes.Buffer
	if err := Encrypt(&enc, bytes.NewReader(plain), k, 0); err != nil {
		t.Fatal(err)
	}
	// Parse the two non-final chunks and swap them, then decrypt → index AAD mismatch.
	b := enc.Bytes()
	header := b[:len(magic)+streamIDLen] // magic + stream id
	rest := b[len(header):]
	c0, n0 := splitChunk(rest)
	c1, _ := splitChunk(rest[n0:])
	var swapped bytes.Buffer
	swapped.Write(header)
	swapped.Write(c1)
	swapped.Write(c0)
	swapped.Write(rest[n0+len(c1):]) // the final chunk untouched
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(swapped.Bytes()), k); err != ErrCorrupt {
		t.Errorf("reordered chunks must fail (index AAD), got %v", err)
	}
}

// splitChunk returns the bytes of one framed chunk (4 len + nonce + ct) and its size.
func splitChunk(b []byte) ([]byte, int) {
	clen := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	total := 4 + nonceLen + clen
	return b[:total], total
}

// Cross-stream splice: a chunk from backup A spliced into backup B (SAME key, same
// index) must fail — the per-backup stream id is authenticated into each chunk's AAD.
func TestStreamCrossSpliceDetected(t *testing.T) {
	k := key32()
	plain := bytes.Repeat([]byte("D"), 2*chunkSize)
	a := encrypted(t, plain, k) // backup A
	b := encrypted(t, plain, k) // backup B (different random stream id)
	// Replace B's first chunk with A's first chunk.
	hdr := len(magic) + streamIDLen
	aRest, bRest := a[hdr:], b[hdr:]
	aC0, _ := splitChunk(aRest)
	bC0, bN0 := splitChunk(bRest)
	_ = bC0
	var spliced bytes.Buffer
	spliced.Write(b[:hdr]) // B's header (B's stream id)
	spliced.Write(aC0)     // A's first chunk
	spliced.Write(bRest[bN0:])
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(spliced.Bytes()), k); err != ErrCorrupt {
		t.Errorf("a chunk spliced from another backup must fail (stream-id AAD), got %v", err)
	}
}

func TestStreamSizeCap(t *testing.T) {
	if err := Encrypt(&bytes.Buffer{}, bytes.NewReader(bytes.Repeat([]byte("x"), 5000)), key32(), 1000); err == nil {
		t.Error("exceeding the size cap must error")
	}
}

func TestStreamTrailingDataRejected(t *testing.T) {
	k := key32()
	blob := encrypted(t, []byte("short"), k)
	blob = append(blob, 0x00, 0x01) // forge bytes after the final chunk
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(blob), k); err != ErrCorrupt {
		t.Errorf("data after the final chunk must fail, got %v", err)
	}
}
