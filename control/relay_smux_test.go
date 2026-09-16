// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/xtaci/smux"
)

func relaySmuxPair(t testing.TB) (reader, writer *smux.Stream, closeSessions func()) {
	t.Helper()
	left, right := net.Pipe()
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	client, err := smux.Client(left, config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := smux.Server(right, config)
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	closeSessions = func() {
		_ = client.Close()
		_ = server.Close()
	}
	t.Cleanup(closeSessions)
	reader, err = client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	writer, err = server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	return reader, writer, closeSessions
}

func TestCopyRelaySmuxFrames(t *testing.T) {
	reader, writer, _ := relaySmuxPair(t)
	payload := make([]byte, 1<<20+17)
	for i := range payload {
		payload[i] = byte(i*17 + i/251)
	}
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(payload)
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

// Exercise partial and full frame consumption. Both must return the original
// receive buffers to smux's pool rather than allocate for every data frame.
func BenchmarkSmuxReceive(b *testing.B) {
	for _, size := range []int{8 << 10, 32 << 10} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			reader, writer, closeSessions := relaySmuxPair(b)
			payload := make([]byte, 32<<10)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					if _, err := writer.Write(payload); err != nil {
						return
					}
				}
			}()
			b.Cleanup(func() { closeSessions(); <-done })
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
