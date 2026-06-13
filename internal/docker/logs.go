package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// streamClient is a no-overall-timeout client for following log streams (the
// short per-request Timeout on the read client would cut a `follow` stream off).
// Lifetime is bound by the caller's context.
func (c *Client) streamClient() *http.Client {
	return &http.Client{Transport: c.hc.Transport}
}

const (
	maxLogLineBytes  = 8 << 10 // truncate pathological lines
	maxLogFrameBytes = 1 << 20 // sanity cap on a single stdcopy frame
)

// StreamLogs follows a container's logs through the read-only socket-proxy (read
// plane — no docker child, no semaphore), demultiplexing the stdcopy framing and
// invoking onLine per (truncated) line until ctx is done or the stream ends.
func (c *Client) StreamLogs(ctx context.Context, id string, tail int, follow bool, onLine func(string)) error {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("timestamps", "0")
	if tail <= 0 || tail > 5000 {
		tail = 500
	}
	q.Set("tail", strconv.Itoa(tail))
	if follow {
		q.Set("follow", "1")
	}
	reqURL := c.base + "/containers/" + url.PathEscape(id) + "/logs?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: logs status %d", resp.StatusCode)
	}
	return demuxLogs(resp.Body, onLine)
}

// demuxLogs reads the Docker multiplexed log stream (8-byte stdcopy headers) and
// emits whole lines. Falls back to raw line reading if the stream isn't framed
// (a TTY container). Bounded line + frame sizes guard against a hostile stream.
func demuxLogs(r io.Reader, onLine func(string)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	emit := newLineEmitter(onLine)

	header := make([]byte, 8)
	for {
		_, err := io.ReadFull(br, header)
		if err != nil {
			emit.flush()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		// Framed iff stream byte ∈ {0,1,2} and the 3 reserved bytes are zero.
		if header[0] > 2 || header[1]|header[2]|header[3] != 0 {
			// Not framed (TTY): treat the 8 bytes + the rest as raw text.
			emit.write(header)
			_ = emitRaw(br, emit)
			return nil
		}
		size := int64(binary.BigEndian.Uint32(header[4:8]))
		// Emit at most maxLogFrameBytes of the frame, but ALWAYS consume the full
		// declared size so the next 8 bytes are a real header — clamping the read
		// would desync the framing (review #20).
		emitN := size
		if emitN > maxLogFrameBytes {
			emitN = maxLogFrameBytes
		}
		if _, err := io.CopyN(emit, br, emitN); err != nil {
			emit.flush()
			if err == io.EOF {
				return nil
			}
			return err
		}
		if rest := size - emitN; rest > 0 {
			if _, err := io.CopyN(io.Discard, br, rest); err != nil {
				emit.flush()
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
}

func emitRaw(br *bufio.Reader, emit *lineEmitter) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			emit.write(buf[:n])
		}
		if err != nil {
			emit.flush()
			return err
		}
	}
}

// lineEmitter accumulates bytes and emits whole lines, truncating any line longer
// than maxLogLineBytes.
type lineEmitter struct {
	onLine func(string)
	buf    strings.Builder
	trunc  bool
}

func newLineEmitter(onLine func(string)) *lineEmitter { return &lineEmitter{onLine: onLine} }

// Write satisfies io.Writer so io.CopyN can target the emitter.
func (e *lineEmitter) Write(p []byte) (int, error) { e.write(p); return len(p), nil }

func (e *lineEmitter) write(p []byte) {
	for _, b := range p {
		if b == '\n' {
			e.flush()
			continue
		}
		if e.buf.Len() >= maxLogLineBytes {
			e.trunc = true
			continue
		}
		e.buf.WriteByte(b)
	}
}

func (e *lineEmitter) flush() {
	if e.buf.Len() == 0 && !e.trunc {
		return
	}
	line := e.buf.String()
	if e.trunc {
		line += "…"
	}
	if e.onLine != nil {
		e.onLine(strings.TrimRight(line, "\r"))
	}
	e.buf.Reset()
	e.trunc = false
}
