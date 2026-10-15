package juicity

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

type recoveryTestParent struct {
	calls int
	err   error
}

func (p *recoveryTestParent) DialContext(context.Context, string, string) (net.Conn, error) {
	p.calls++
	return nil, p.err
}
func (p *recoveryTestParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	p.calls++
	return nil, p.err
}

func TestRecoveryRejectsUnreadyDialWithoutWaiting(t *testing.T) {
	want := errors.New("parent transport unavailable")
	parent := &recoveryTestParent{err: want}
	d, err := NewDialer(parent, protocol.Header{ProxyAddress: "127.0.0.1:443", User: "00000000-0000-0000-0000-000000000000", Feature1: "bbr", TlsConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.DialContext(context.Background(), "tcp", "example.test:80"); !errors.Is(err, netproxy.ErrNotConnected) {
		t.Fatalf("unready dial returned %v", err)
	}
	if parent.calls != 0 {
		t.Fatalf("unready data-plane dial attempted recovery: calls=%d", parent.calls)
	}
	if err := d.Connect(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Connect returned %v", err)
	}
	if d.Snapshot().State != netproxy.SessionDisconnected {
		t.Fatalf("failed connect state: %+v", d.Snapshot())
	}
	if parent.calls != 1 {
		t.Fatalf("Connect attempts=%d", parent.calls)
	}
}
