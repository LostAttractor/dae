// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestCopyRelaySmuxFrames(t *testing.T) {
	_, reader, writer := relaySmuxOutbound(t)
	payload := make([]byte, 1<<20+17)
	for i := range payload {
		payload[i] = byte(i*17 + i/251)
	}
	done := make(chan error, 1)
	go func() {
		// The stream response, then the payload in frames.
		_, err := writer.Write(append([]byte{0}, payload...))
		_ = writer.Close()
		done <- err
	}()
	var received bytes.Buffer
	if err := copyRelay(&received, reader); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("smux relay changed the payload: got %d bytes, want %d", received.Len(), len(payload))
	}
}

// Exercise partial and full frame consumption. Both must return the pooled
// receive buffers rather than allocate for every data frame.
func BenchmarkSmuxReceive(b *testing.B) {
	for _, size := range []int{8 << 10, 32 << 10} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			_, reader, writer := relaySmuxOutbound(b)
			payload := make([]byte, 32<<10)
			done := make(chan struct{})
			go func() {
				defer close(done)
				if _, err := writer.Write([]byte{0}); err != nil {
					return
				}
				for {
					if _, err := writer.Write(payload); err != nil {
						return
					}
				}
			}()
			b.Cleanup(func() { _ = writer.Close(); <-done })
			buffer := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := io.ReadFull(reader, buffer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
