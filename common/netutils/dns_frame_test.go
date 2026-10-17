// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/daeuniverse/dae/common/consts"
)

type fragmentWriter struct {
	bytes.Buffer
	limit int
}

func (w *fragmentWriter) Write(p []byte) (int, error) {
	return w.Buffer.Write(p[:min(len(p), w.limit)])
}

func TestDNSFramePreservesEmptyOpaqueAndMaximumMessages(t *testing.T) {
	for _, size := range []int{0, 3, consts.MaxDnsMessageSize} {
		wire := bytes.Repeat([]byte{0xa5}, size)
		writer := &fragmentWriter{limit: 7}
		if err := WriteDNSFrame(writer, wire); err != nil {
			t.Fatal(err)
		}
		got, err := ReadDNSFrame(iotest.OneByteReader(&writer.Buffer))
		if err != nil || !bytes.Equal(got, wire) || writer.Len() != 0 {
			t.Fatalf("frame size %d: got %d bytes, remaining %d, error %v", size, len(got), writer.Len(), err)
		}
	}
}

func TestDNSFrameRejectsOversizeAndTruncatedIO(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDNSFrame(&buffer, make([]byte, consts.MaxDnsMessageSize+1)); err == nil || buffer.Len() != 0 {
		t.Fatal("oversized frame was written")
	}
	if err := WriteDNSFrame(&fragmentWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer returned %v", err)
	}
	for _, wire := range [][]byte{nil, {0}, {0, 2, 1}} {
		if _, err := ReadDNSFrame(bytes.NewReader(wire)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated frame %x returned %v", wire, err)
		}
	}
}
