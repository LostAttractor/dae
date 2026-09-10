// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type relayReadFunc func([]byte) (int, error)

func (f relayReadFunc) Read(p []byte) (int, error) { return f(p) }

type relayWriteFunc func([]byte) (int, error)

func (f relayWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestCopyRelayAdaptsToTraffic(t *testing.T) {
	bulk := bytes.Repeat([]byte("bulk"), 64<<10)
	chunks := append([][]byte{bulk}, bytes.Split(bytes.Repeat([]byte("small,"), 20), []byte(","))...)
	var got, want bytes.Buffer
	for _, chunk := range chunks {
		want.Write(chunk)
	}
	var initial, largest, last int
	err := copyRelay(&got, relayReadFunc(func(p []byte) (int, error) {
		if initial == 0 {
			initial = len(p)
		}
		largest = max(largest, len(p))
		last = len(p)
		for len(chunks) > 0 && len(chunks[0]) == 0 {
			chunks = chunks[1:]
		}
		if len(chunks) == 0 {
			return 0, io.EOF
		}
		n := copy(p, chunks[0])
		chunks[0] = chunks[0][n:]
		return n, nil
	}))
	if err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("relay changed payload: error=%v, got %d bytes, want %d", err, got.Len(), want.Len())
	}
	if initial != 8<<10 || largest != 32<<10 || last != initial {
		t.Fatalf("buffer sizes: initial=%d, bulk=%d, after small reads=%d", initial, largest, last)
	}
}

func TestCopyRelayIOResults(t *testing.T) {
	failure := errors.New("connection failed")
	for _, test := range []struct {
		name     string
		readErr  error
		written  int
		writeErr error
		want     error
	}{
		{"EOF with data", io.EOF, 3, nil, nil},
		{"read error with data", failure, 3, nil, failure},
		{"short write", io.EOF, 2, nil, io.ErrShortWrite},
		{"write error", io.EOF, 2, failure, failure},
		{"write error before read error", io.ErrUnexpectedEOF, 0, failure, failure},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			err := copyRelay(relayWriteFunc(func(p []byte) (int, error) {
				if string(p) != "abc" {
					t.Fatalf("forwarded %q, want abc", p)
				}
				return test.written, test.writeErr
			}), relayReadFunc(func(p []byte) (int, error) {
				reads++
				if reads > 1 {
					t.Fatal("read again after EOF or error")
				}
				return copy(p, "abc"), test.readErr
			}))
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}
