// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

var mitmTestClients = []string{"-02:00:00:00:00:02", "02:00:00:00:00:01", "10.0.0.0/24"}

func mitmClientTestHost(t *testing.T, authority *mitmca.Authority, upstreamTLS *tls.Config, observe func()) *mitm.Host {
	t.Helper()
	extension := mitmRoutingPlugin("example.com")
	extension.handle = func(e *plugin.Exchange, next plugin.Handler) (*http.Response, error) {
		if observe != nil {
			observe()
		}
		response, err := next(e)
		if err == nil {
			response.Header.Set("X-Dae-Mitm", "selected")
		}
		return response, err
	}
	host, err := mitm.New(mitm.Options{Authority: authority, UpstreamTLSConfig: upstreamTLS}, mitm.Instance{ID: "test", Type: "test", Plugin: extension})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return host
}

func mitmClientLogHook(t *testing.T) *logtest.Hook {
	t.Helper()
	logger := log.StandardLogger()
	hooks, level := logger.ReplaceHooks(make(log.LevelHooks)), logger.GetLevel()
	hook := logtest.NewGlobal()
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		logger.ReplaceHooks(hooks)
		logger.SetLevel(level)
	})
	return hook
}

func TestMITMClientGateUsesRoutingMetadata(t *testing.T) {
	for _, test := range []struct {
		name, source, host string
		mac                [6]byte
		port               uint16
		want, bypass       bool
	}{
		{name: "allowed MAC outside IP range", source: "192.0.2.1:12345", mac: [6]byte{2, 0, 0, 0, 0, 1}, want: true},
		{name: "excluded MAC before allowed IP", source: "10.0.0.3:12345", mac: [6]byte{2, 0, 0, 0, 0, 2}, bypass: true},
		{name: "unknown MAC falls through to IP", source: "10.0.0.3:12345", want: true},
		{name: "unknown MAC without matching IP", source: "192.0.2.1:12345", bypass: true},
		{name: "mapped IPv4 source", source: "[::ffff:10.0.0.3]:12345", want: true},
		{name: "other hostname", source: "10.0.0.3:12345", host: "outside.example"},
		{name: "other port", source: "10.0.0.3:12345", port: 8443},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.host == "" {
				test.host = "example.com"
			}
			if test.port == 0 {
				test.port = 443
			}
			hook := mitmClientLogHook(t)
			store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			clients, err := clientmatch.Parse(mitmTestClients)
			if err != nil {
				t.Fatal(err)
			}
			plane := &ControlPlane{mitmHost: mitmClientTestHost(t, &mitmca.Authority{}, nil, nil), settings: store, mitmClients: clients}
			result := &bpfRoutingResult{Mac: test.mac, Mark: 37, Must: 1}
			beforeResult := *result
			source := netip.MustParseAddrPort(test.source)
			destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), test.port)
			if got := plane.mitmMode(test.host, source, destination, result) != mitm.HTTPBypass; got != test.want {
				t.Fatalf("client gate = %v, want %v", got, test.want)
			}
			if *result != beforeResult {
				t.Fatal("client gate changed the selected route or ingress metadata")
			}
			entry := hook.LastEntry()
			if (entry != nil) != test.bypass {
				t.Fatalf("bypass log = %+v, want present=%v", entry, test.bypass)
			}
			if test.bypass {
				if entry.Message != "MITM bypassed for client" || entry.Level != log.DebugLevel {
					t.Fatalf("bypass log = %+v", entry)
				}
				mac := "unknown"
				if test.mac != [6]byte{} {
					mac = net.HardwareAddr(test.mac[:]).String()
				}
				for field, want := range map[string]string{
					"event": "mitm_bypass", "reason": "client_not_allowed", "host": test.host,
					"port": fmt.Sprint(test.port), "source": common.ConvergeAddrPort(source).String(), "mac": mac,
				} {
					if got := fmt.Sprint(entry.Data[field]); got != want {
						t.Errorf("bypass field %s = %q, want %q", field, got, want)
					}
				}
			}
		})
	}
}

type mitmClientDialer struct {
	mu       sync.Mutex
	upstream string
	block    bool
	targets  []string
}

func (d *mitmClientDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, target)
	d.mu.Unlock()
	if d.block {
		return nil, fmt.Errorf("selected block outbound")
	}
	if network != "tcp" || target != "198.51.100.1:443" {
		return nil, fmt.Errorf("selected outbound received unexpected target %s %s", network, target)
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.upstream)
}

func (*mitmClientDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (d *mitmClientDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.targets)
}

func mitmClientTestPlane(t *testing.T, host *mitm.Host, upstream string) (*ControlPlane, []*mitmClientDialer) {
	t.Helper()
	registry, _ := newTestRegistry(10, time.Minute)
	t.Cleanup(func() { _ = registry.Close() })
	store, err := settings.Open(filepath.Join(t.TempDir(), "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	clients, err := clientmatch.Parse(mitmTestClients)
	if err != nil {
		t.Fatal(err)
	}
	plane := &ControlPlane{core: &controlPlaneCore{domainRegistry: registry}, mitmHost: host, settings: store, mitmClients: clients, sniffVerifyMode: consts.SniffVerifyMode_None}
	var transports []*mitmClientDialer
	global := &dialer.GlobalOption{}
	for _, name := range []string{"direct", "block", "proxy"} {
		transport := &mitmClientDialer{upstream: upstream, block: name == "block"}
		transports = append(transports, transport)
		d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: transport}), global, &dialer.Property{Name: name, Link: "test://mitm-client/" + name}, false, name)
		group := outbound.NewDialerGroup(global, name, outbound.GroupKindSingleAlwaysAlive, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, func(bool, *common.NetworkType) error { return nil })
		plane.outbounds = append(plane.outbounds, group)
		t.Cleanup(func() { _ = group.Close() })
	}
	// Substitute only the socket-opening implementation of the existing marked
	// direct path, so this test does not need SO_MARK privileges.
	marked := &mitmClientDialer{upstream: upstream}
	plane.markedDirectDialers.Store(uint32(37), marked)
	return plane, append(transports, marked)
}

func TestMITMClientTLSBypassReplaysClientHello(t *testing.T) {
	for _, test := range []struct {
		name, source string
		mac          [6]byte
		outbound     consts.OutboundIndex
		selected     bool
	}{
		{name: "excluded direct client without dae CA", source: "192.0.2.5:12345", outbound: consts.OutboundDirect},
		{name: "excluded MAC with allowed IP keeps proxy", source: "10.0.0.5:12345", mac: [6]byte{2, 0, 0, 0, 0, 2}, outbound: consts.OutboundUserDefinedMin},
		{name: "allowed MAC uses dae CA and marked direct", source: "192.0.2.5:12345", mac: [6]byte{2, 0, 0, 0, 0, 1}, outbound: consts.OutboundDirect, selected: true},
		{name: "unknown MAC reaches later IP allowance", source: "[::ffff:10.0.0.5]:12345", outbound: consts.OutboundUserDefinedMin, selected: true},
		{name: "unknown MAC without IP allowance bypasses", source: "192.0.2.5:12345", outbound: consts.OutboundUserDefinedMin},
		{name: "allowed client cannot bypass block", source: "10.0.0.5:12345", mac: [6]byte{2, 0, 0, 0, 0, 1}, outbound: consts.OutboundBlock},
	} {
		t.Run(test.name, func(t *testing.T) {
			hook := mitmClientLogHook(t)
			requests := make(chan string, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				requests <- r.Method + " " + r.URL.RequestURI() + " " + r.Host + " " + r.Header.Get("X-Client") + " " + string(body)
				_, _ = io.WriteString(w, "upstream response")
			}))
			t.Cleanup(upstream.Close)
			upstreamTLS := upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			if upstreamTLS.InsecureSkipVerify {
				t.Fatal("test must verify the upstream certificate")
			}
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
			if err := mitmca.Generate(certPath, keyPath, "selected client CA", time.Hour); err != nil {
				t.Fatal(err)
			}
			authority, err := mitmca.Load(certPath, keyPath)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := mitmca.ReadCertificate(certPath)
			if err != nil {
				t.Fatal(err)
			}
			trace := new(atomic.Int32)
			host := mitmClientTestHost(t, authority, upstreamTLS, func() { trace.Add(1) })
			plane, dialers := mitmClientTestPlane(t, host, upstream.Listener.Addr().String())
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			clientSocket, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = clientSocket.Close() })
			serverSocket, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			_ = listener.Close()
			finished := make(chan error, 1)
			// Inject only the kernel-provided tuple/MAC/result. Domain sniffing,
			// routing, the production client gate, and tcpRelay.run are real.
			go func() {
				finished <- func() error {
					sniffer := sniffing.NewConnSniffer(serverSocket, 2*time.Second)
					defer sniffer.Close()
					domain, err := sniffer.SniffTcp()
					if err != nil || domain != "example.com" {
						return fmt.Errorf("sniffed ClientHello host %q: %w", domain, err)
					}
					src := netip.MustParseAddrPort(test.source)
					dst := netip.MustParseAddrPort("198.51.100.1:443")
					result := &bpfRoutingResult{Outbound: uint8(test.outbound), Mark: 37, Mac: test.mac}
					option, planner, release, err := plane.prepareHTTPRoute(context.Background(), domain, &RouteParam{
						routingResult: result, Domain: domain, Src: src, Dest: dst,
						networkType: common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
					})
					if err != nil {
						return err
					}
					selected := planner != nil
					if selected != test.selected || result.Mark != 37 || option.Outbound != plane.outbounds[test.outbound] || option.DialTarget != dst.String() {
						return fmt.Errorf("gate changed route: selected=%v option=%+v mark=%d", selected, option, result.Mark)
					}
					path, fallback := option.trafficAttribution()
					relay := &tcpRelay{lConn: sniffer, dialer: option.Dialer, statsPath: path, fallback: fallback, dst: dst, domain: domain}
					if selected {
						relay.mitmRelease = release
						relay.mitmHost, relay.mitmPlanner = host, planner
					} else {
						relay.rConn, err = option.dialerForConnection().DialContext(context.Background(), "tcp", option.DialTarget)
						if err != nil {
							return err
						}
					}
					return relay.run()
				}()
			}()
			waited := false
			wait := func() error {
				waited = true
				select {
				case err := <-finished:
					return err
				case <-time.After(5 * time.Second):
					return fmt.Errorf("client relay did not finish")
				}
			}
			t.Cleanup(func() {
				_ = clientSocket.Close()
				_ = serverSocket.Close()
				if !waited {
					if err := wait(); err != nil {
						t.Errorf("relay cleanup: %v", err)
					}
				}
			})
			roots := upstreamTLS.RootCAs
			if test.selected {
				roots = x509.NewCertPool()
				roots.AddCert(ca)
			}
			client := tls.Client(clientSocket, &tls.Config{ServerName: "example.com", RootCAs: roots})
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			err = client.Handshake()
			if test.outbound == consts.OutboundBlock {
				if err == nil {
					t.Fatal("blocked client completed TLS")
				}
				if err := wait(); err == nil || !strings.Contains(err.Error(), "selected block outbound") {
					t.Fatalf("block was not retained: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				state := client.ConnectionState()
				if test.selected {
					if err := state.PeerCertificates[0].CheckSignatureFrom(ca); err != nil {
						t.Fatalf("selected client did not receive the dae CA certificate: %v", err)
					}
				} else if !bytes.Equal(state.PeerCertificates[0].Raw, upstream.Certificate().Raw) {
					t.Fatal("bypassed client did not receive the original upstream certificate")
				}
				if _, err := io.WriteString(client, "POST /path?original=1 HTTP/1.1\r\nHost: example.com\r\nX-Client: untouched\r\nContent-Length: 11\r\nConnection: close\r\n\r\nclient-body"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "upstream response" || (response.Header.Get("X-Dae-Mitm") == "selected") != test.selected {
					t.Fatalf("wrong plugin treatment: body=%q headers=%v err=%v", body, response.Header, err)
				}
				// Drain close_notify before closing the raw socket: unread TLS
				// records make an ordinary TCP Close send an unintended RST.
				if _, err := io.Copy(io.Discard, client); err != nil {
					t.Fatal(err)
				}
				_ = clientSocket.(*net.TCPConn).CloseWrite()
				if err := wait(); err != nil {
					t.Fatal(err)
				}
				select {
				case request := <-requests:
					if request != "POST /path?original=1 example.com untouched client-body" {
						t.Fatalf("upstream request changed: %q", request)
					}
				default:
					t.Fatal("upstream did not receive the request")
				}
			}
			selectedDialer := int(test.outbound)
			if test.outbound == consts.OutboundDirect {
				selectedDialer = 3
			}
			for i, d := range dialers {
				want := 0
				if i == selectedDialer {
					want = 1
				}
				if got := d.calls(); got != want {
					t.Errorf("dialer %d calls=%d, want %d", i, got, want)
				}
			}
			if got := trace.Load(); (got == 1) != test.selected || got > 1 {
				t.Errorf("plugin calls=%d, selected=%v", got, test.selected)
			}
			wantBypass := !test.selected && test.outbound != consts.OutboundBlock
			bypassed := false
			for _, entry := range hook.AllEntries() {
				if entry.Message == "MITM bypassed for client" && entry.Data["event"] == "mitm_bypass" {
					bypassed = true
				}
			}
			if bypassed != wantBypass {
				t.Errorf("bypass log present=%v, want %v", bypassed, wantBypass)
			}
			select {
			case extra := <-requests:
				t.Errorf("unexpected upstream request: %q", extra)
			default:
			}
		})
	}
}
