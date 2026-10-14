// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func BenchmarkRelayIdleMemory(b *testing.B) {
	for _, directions := range []int{100, 1000} {
		for _, bulk := range []bool{false, true} {
			b.Run(fmt.Sprintf("directions=%d/after_bulk=%t", directions, bulk), func(b *testing.B) {
				var bufferBytes, heapBytes int64
				// Each iteration measures a complete fixed-size population. N changes the
				// number of samples, never the number of simultaneously retained buffers.
				for b.Loop() {
					ready, release := make(chan int), make(chan struct{})
					var before, held runtime.MemStats
					runtime.GC()
					runtime.GC() // Clear both generations of sync.Pool.
					runtime.ReadMemStats(&before)
					var workers sync.WaitGroup
					for range directions {
						workers.Go(func() {
							reads := 0
							_ = copyRelay(io.Discard, relayReadFunc(func(p []byte) (int, error) {
								if bulk && reads < 2 {
									reads++
									return len(p), nil
								}
								ready <- len(p)
								<-release
								return 0, io.EOF
							}))
						})
					}
					for range directions {
						bufferBytes += int64(<-ready)
					}
					runtime.GC()
					runtime.GC() // Clear both generations of sync.Pool.
					runtime.ReadMemStats(&held)
					heapBytes += int64(held.HeapAlloc) - int64(before.HeapAlloc)
					close(release)
					workers.Wait()
				}
				b.ReportMetric(0, "ns/op")
				b.ReportMetric(float64(directions), "directions")
				b.ReportMetric(float64(bufferBytes)/float64(b.N*directions), "buffer-B/direction")
				b.ReportMetric(float64(heapBytes)/float64(b.N*directions), "heap-B/direction")
			})
		}
	}
}

func BenchmarkCopyRelay(b *testing.B) {
	for _, size := range []int{1024, 32 << 10, 1 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if err := copyRelay(io.Discard, bytes.NewReader(payload)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRelayDirectionTCP(b *testing.B) {
	pair := func() (*net.TCPConn, *net.TCPConn) {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			b.Fatal(err)
		}
		defer listener.Close()
		client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = client.Close() })
		server, err := listener.AcceptTCP()
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = server.Close() })
		return client, server
	}
	sourcePeer, source := pair()
	destinationPeer, destination := pair()
	payload := bytes.Repeat([]byte("x"), 64<<10)
	got := make([]byte, len(payload))
	writeDone, relayDone := make(chan error, 1), make(chan error, 1)
	var counted uint64
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	go func() {
		defer sourcePeer.CloseWrite()
		for range b.N {
			if _, err := sourcePeer.Write(payload); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	go func() {
		defer destination.CloseWrite()
		relayDone <- relayEndpointDirection(
			&relayEndpoint{conn: destination, origin: netproxy.OriginTarget},
			&relayEndpoint{conn: source, origin: netproxy.OriginCaller},
			func(n uint64) { counted += n },
		)
	}()
	for range b.N {
		if _, err := io.ReadFull(destinationPeer, got); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-writeDone; err != nil {
		b.Fatal(err)
	}
	if err := <-relayDone; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	if want := uint64(b.N) * uint64(len(payload)); counted != want {
		b.Fatalf("counted %d bytes, want %d", counted, want)
	}
}
