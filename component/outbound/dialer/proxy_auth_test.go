package dialer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/daeuniverse/dae/common"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	proxyhttp "github.com/daeuniverse/outbound/protocol/http"
)

type authProxyParent struct{}

func (authProxyParent) DialContext(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		http.ReadRequest(bufio.NewReader(s))
		io.WriteString(s, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	}()
	return c, nil
}
func (authProxyParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected")
}
func TestProxyAuthFailureBlocksRetry(t *testing.T) {
	u, _ := url.Parse("http://bad:password@proxy.test:8080")
	layer, err := proxyhttp.BuildHTTPProxy(u, new(D.ExtraOption), authProxyParent{})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()
	d := newTestDialer(t, layer.Data)
	c := newConnectivityChecker(d.pathRuntime, func(ctx context.Context, n *common.NetworkType) (bool, error) {
		if n.Index() != common.NetworkTCP4 {
			return false, netproxy.UnsupportedTunnelTypeError
		}
		conn, err := d.DialContext(ctx, "tcp", "192.0.2.1:53")
		if conn != nil {
			conn.Close()
		}
		return false, err
	})
	defer c.stopRetries()
	result := c.performAttempt(context.Background(), checkAttempt{kind: checkInitial})
	c.cancel = func() {}
	c.finish(result)
	c.dispatch()
	state := d.RuntimeStatus()
	if c.cancel != nil || state.Recovery.Phase != RecoveryBlocked || !state.Recovery.RetryAt.IsZero() || c.blockedBy != "auth" || state.Failure == nil || state.Failure.Reason != netproxy.ReasonAuth {
		t.Fatalf("407 not surfaced/blocked: blocked=%q retry_pending=%v failure=%+v probes=%+v", c.blockedBy, !c.supportAt.IsZero(), state.Failure, result.probes)
	}
}

func TestStreamAuthenticationDistinguishesProxyAndTarget(t *testing.T) {
	for _, origin := range []netproxy.FailureOrigin{netproxy.OriginPeer, netproxy.OriginTarget} {
		t.Run(string(origin), func(t *testing.T) {
			d := newTestDialer(t, authProxyParent{})
			prepareRecoveryDialer(d)
			failure := netproxy.WrapFailure(errors.New("authentication rejected"), netproxy.Failure{
				Scope: netproxy.ScopeStream, Layer: netproxy.LayerH2, Origin: origin, Reason: netproxy.ReasonAuth,
			})
			d.ReportDataPlaneError(failure)
			if requested := d.connectivityCheckRequested(); requested != (origin == netproxy.OriginPeer) {
				t.Fatalf("data-plane confirmation requested = %v", requested)
			}
			calls := 0
			c := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) {
				calls++
				return false, failure
			})
			defer c.stopRetries()
			result := c.performAttempt(context.Background(), d.beginConnectivityCheck(checkHealth))
			c.cancel = func() {}
			finishCheck(c, result)
			if origin == netproxy.OriginPeer {
				if calls != 1 || c.blockedBy != "auth" || !d.RuntimeStatus().Recovery.RetryAt.IsZero() {
					t.Fatalf("proxy credentials retried: calls=%d, state=%+v", calls, d.RuntimeStatus())
				}
			} else if calls != 2 || c.blockedBy != "" || c.healthAt.IsZero() {
				t.Fatalf("target rejection blocked node recovery: calls=%d, state=%+v", calls, d.RuntimeStatus())
			}
		})
	}
}
