// SPDX-License-Identifier: AGPL-3.0-only

package juicity

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

func TestAuthenticationContinuesAfterConnectWithoutStreamCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", recoveryTLS(t), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	d, err := NewDialer(loopbackPacketParent{}, protocol.Header{
		ProxyAddress: listener.Addr().String(), User: "00000000-0000-0000-0000-000000000000", Password: "test", Feature1: "bbr",
		TlsConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"juicity-test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// The authentication worker is still waiting for requests when Connect returns.
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(0, "test complete")
	stream, err := server.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, make([]byte, 2+16+32)); err != nil {
		t.Fatal(err)
	}
	if err := d.clientRing.Allocate(ctx, false, func(_ context.Context, client *clientImpl) error {
		client.QuicConfig.CapabilityCallback(quic.StreamTypeBidi, 0)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	metadata := &Metadata{Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "example.test", Port: 53}, Network: "udp"}
	if _, err := d.clientRing.DialContext(ctx, metadata); !common.IsCapacityError(err) {
		t.Fatalf("stream reservation ignored: %v", err)
	}
	auth, err := d.clientRing.DialAuth(ctx, metadata)
	if err != nil {
		t.Fatalf("asynchronous auth consumed stream reservation: %v", err)
	}
	defer auth.lease.Invalidate(io.EOF)
	var want bytes.Buffer
	want.Write(auth.IV)
	want.Write(auth.Psk)
	if err := metadata.appendTo(&want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, want.Len())
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatal("continuing authentication was not written on the established stream")
	}
}
