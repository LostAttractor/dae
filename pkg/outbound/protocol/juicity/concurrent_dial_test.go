package juicity

import (
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

func TestConcurrentHealthyDials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		server, e := listener.Accept(ctx)
		if e == nil {
			<-ctx.Done()
			server.CloseWithError(0, "")
		}
	}()
	d, err := NewDialer(loopbackPacketParent{}, protocol.Header{ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"juicity-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var admitted, rejected atomic.Int32
	start := make(chan struct{})
	for range 32 {
		wg.Go(func() {
			<-start
			c, err := d.DialContext(ctx, "tcp", "example.test:443")
			if c != nil {
				admitted.Add(1)
				c.Close()
			}
			if common.IsCapacityError(err) {
				rejected.Add(1)
			} else if err != nil {
				t.Errorf("unexpected: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if rejected.Load() != 0 {
		t.Fatalf("healthy pool rejected concurrent work: admitted=%d rejected=%d state=%+v", admitted.Load(), rejected.Load(), d.Snapshot())
	}
}
