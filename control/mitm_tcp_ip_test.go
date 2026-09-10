// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"golang.org/x/sys/unix"
)

// Supply only the original tuples through a private BPF map. Sniffing,
// admission, TLS certificate verification and the relay are production code.
func TestMITMTCPIPScopeKernelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF map tests")
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	mapSpec := spec.Maps["routing_tuples_map"]
	mapSpec.Pinning = ebpf.PinNone
	tuples, err := ebpf.NewMap(mapSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer tuples.Close()
	authority, roots := mitmQUICTestAuthority(t)
	for _, test := range []struct {
		name, destination, sni       string
		scope                        plugin.Scope
		h2, excluded, ssh, intercept bool
	}{
		{name: "IPv4 TLS 1.2", destination: "192.0.2.20:8443", scope: plugin.Scope{{Host: "192.0.2.20", Ports: []uint16{8443}}}, intercept: true},
		{name: "IPv6 TLS 1.3 h2", destination: "[2001:db8::20]:8443", scope: plugin.Scope{{Host: "2001:db8::20", Ports: []uint16{8443}}}, h2: true, intercept: true},
		{name: "wrong port", destination: "192.0.2.20:443", scope: plugin.Scope{{Host: "192.0.2.20", Ports: []uint16{8443}}}},
		{name: "unrelated IP", destination: "192.0.2.21:8443", scope: plugin.Scope{{Host: "192.0.2.20", Ports: []uint16{8443}}}},
		{name: "domain scope only", destination: "192.0.2.20:8443", scope: plugin.Scope{{Host: "service.example", Ports: []uint16{8443}}}},
		{name: "existing SNI", destination: "192.0.2.20:8443", scope: plugin.Scope{{Host: "192.0.2.20", Ports: []uint16{8443}}}, sni: "outside.example"},
		{name: "excluded client", destination: "192.0.2.20:8443", scope: plugin.Scope{{Host: "192.0.2.20", Ports: []uint16{8443}}}, excluded: true},
		{name: "non TLS", destination: "192.0.2.20:8443", scope: plugin.Scope{{Host: "192.0.2.20", Ports: []uint16{8443}}}, ssh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var bypassDials atomic.Int32
			extension := &controlTestPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: test.scope}}},
				handle: func(*plugin.Exchange, plugin.Handler) (*http.Response, error) {
					return &http.Response{StatusCode: 403, Header: make(http.Header), Body: http.NoBody}, nil
				},
			}
			plane, _, param := newHTTPRequestRouteTestWithAuthority(t, "", extension,
				func(context.Context, string, string) (net.Conn, error) {
					bypassDials.Add(1)
					return nil, errors.New("test raw connection bypass")
				}, authority)
			plane.soMarkFromDae = 37 // Keep marked direct on the fixture dialer.
			plane.sniffingTimeout = time.Second
			plane.core.bpf = &bpfState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{RoutingTuplesMap: tuples}}}
			if test.excluded {
				plane.mitmClients = clientmatch.Matcher{}
			}
			src, dst := param.Src, netip.MustParseAddrPort(test.destination)
			key := bpfTuplesKey{Sport: common.Htons(src.Port()), Dport: common.Htons(dst.Port()), L4proto: unix.IPPROTO_TCP}
			key.Sip.U6Addr8, key.Dip.U6Addr8 = src.Addr().As16(), dst.Addr().As16()
			if err := tuples.Update(key, bpfRoutingResult{Outbound: uint8(consts.OutboundDirect), CaptureFlags: captureHTTP, Mark: 37}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			served := make(chan error, 1)
			go func() {
				relay, err := plane.prepareTCPRelay(context.Background(), &mitmTupleConn{Conn: server, source: src, destination: dst})
				if relay != nil {
					err = relay.run()
				}
				served <- err
			}()
			if test.ssh {
				_, _ = io.WriteString(client, "SSH-2.0-test\r\n")
			} else {
				cfg := &tls.Config{RootCAs: roots, ServerName: test.sni, MaxVersion: tls.VersionTLS12}
				if test.h2 {
					cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
				}
				transport := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: test.h2,
					DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
				}
				response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("https://" + dst.String() + "/blocked")
				if test.intercept {
					if err != nil {
						t.Errorf("literal IP request bypassed MITM: %v", err)
					} else {
						if response.StatusCode != http.StatusForbidden || response.TLS.ServerName != "" {
							t.Errorf("expected local rejection without SNI: %+v", response)
						}
						if test.h2 && response.ProtoMajor != 2 {
							t.Errorf("expected HTTP/2: %s", response.Proto)
						}
						_, _ = io.Copy(io.Discard, response.Body)
						_ = response.Body.Close()
					}
				} else if err == nil {
					_ = response.Body.Close()
					t.Error("out-of-scope connection entered MITM")
				}
				transport.CloseIdleConnections()
			}
			_ = client.Close()
			select {
			case err := <-served:
				if test.intercept && err != nil {
					t.Error(err)
				}
			case <-time.After(time.Second):
				t.Fatal("relay did not close")
			}
			if got := bypassDials.Load(); (got == 0) != test.intercept {
				t.Fatalf("raw bypass dials=%d, intercept=%v", got, test.intercept)
			}
		})
	}
}

type mitmTupleConn struct {
	net.Conn
	source, destination netip.AddrPort
}

func (c *mitmTupleConn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.destination) }
func (c *mitmTupleConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.source) }
