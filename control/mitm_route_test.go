// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestRouteDialOptionUsesAdmittedPolicy(t *testing.T) {
	plane, _, original := newHTTPRequestRouteTest(t, "l4proto(tcp,udp) -> proxy", new(controlTestPlugin), nil)
	for _, test := range []struct {
		name            string
		override, useIP bool
		udp, rewritten  bool
		wantCalls       int
		wantName        bool
	}{
		{"remote name", true, false, false, false, 1, true},
		{"admitted IP policy", true, true, false, false, 1, false},
		{"override disabled", false, true, false, false, 0, false},
		{"UDP keeps IP", true, true, true, false, 0, false},
		{"rewritten target", true, true, false, true, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			param, identity := *original, *original.routingResult
			param.routingResult = &identity
			plane.dialTargetOverride = test.override
			if test.udp {
				param.networkType = *common.NetworkUDP4.NetworkType()
			}
			if test.rewritten {
				param.destination = param.Dest
			}
			calls := 0
			option, err := plane.routeDialOption(t.Context(), &param, func(name string) bool {
				calls++
				if name != param.Domain {
					t.Fatalf("policy hostname = %q, want %q", name, param.Domain)
				}
				return test.useIP
			})
			want := param.Dest.String()
			if test.wantName {
				want = "original.example:80"
			}
			if err != nil || option.DialTarget != want || calls != test.wantCalls {
				t.Fatalf("route=%+v policy calls=%d err=%v, want %s/%d", option, calls, err, want, test.wantCalls)
			}
		})
	}
}

func TestPrepareHTTPRouteWithoutHost(t *testing.T) {
	plane, _, original := newHTTPRequestRouteTest(t, "l4proto(tcp) -> proxy", new(controlTestPlugin), nil)
	plane.mitmHost = nil
	plane.dialTargetOverride = true
	ctx := t.Context()
	route := func(prepare bool) {
		param, identity := *original, *original.routingResult
		param.routingResult = &identity
		var option *DialOption
		var err error
		if prepare {
			var intercepted *mitmRoute
			option, intercepted, err = plane.prepareHTTPRoute(ctx, param.Domain, &param)
			if intercepted != nil {
				intercepted.Release()
				t.Fatal("hostless route retained a MITM admission")
			}
		} else {
			option, err = plane.routeDialOption(ctx, &param, func(string) bool { return false })
		}
		if err != nil || option == nil || option.Outbound.Name != "proxy" || option.DialTarget != "original.example:80" {
			t.Fatalf("hostless route: %+v %v", option, err)
		}
	}
	ordinary := testing.AllocsPerRun(20, func() { route(false) })
	prepared := testing.AllocsPerRun(20, func() { route(true) })
	if prepared > ordinary {
		t.Fatalf("hostless preparation added allocations: ordinary=%v prepared=%v", ordinary, prepared)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, intercepted, err := plane.prepareHTTPRoute(ctx, original.Domain, original); !errors.Is(err, context.Canceled) || intercepted != nil {
		intercepted.Release()
		t.Fatalf("hostless preparation ignored cancellation: %v", err)
	}
}

func TestPrepareHTTPRouteWithoutHostHonorsHandoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		plane, _, param := newHTTPRequestRouteTest(t, "", rewriteTestPlugin(t, nil), nil)
		next := plane.mitmHost
		plane.mitmHost = nil
		handoff := plane.pauseMITM(&plane.planeHTTP)
		result := make(chan error, 1)
		go func() {
			_, route, err := plane.prepareHTTPRoute(t.Context(), param.Domain, param)
			defer route.Release()
			if err == nil && (route == nil || route.admission.Host() != next) {
				err = errors.New("hostless fast path skipped the successor admission")
			}
			result <- err
		}()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("hostless route skipped pending handoff: %v", err)
		default:
		}
		plane.mitmMu.Lock()
		plane.mitmHost = next
		plane.mitmMu.Unlock()
		handoff.complete(nil)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

func TestPrepareHTTPRouteReleasesUntransferredAdmission(t *testing.T) {
	for _, outcome := range []string{"bypass", "blocked", "canceled"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				routing := ""
				if outcome == "blocked" {
					routing = "l4proto(tcp) -> block"
				}
				plane, _, param := newHTTPRequestRouteTest(t, routing, mitmRoutingPlugin("original.example"), nil)
				if outcome == "bypass" {
					param.Domain = "outside.example"
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if outcome == "canceled" {
					cancel()
				}
				option, intercepted, err := plane.prepareHTTPRoute(ctx, param.Domain, param)
				if intercepted != nil {
					intercepted.Release()
					t.Fatal("non-MITM or failed preparation transferred ownership")
				}
				switch outcome {
				case "bypass":
					if err != nil || option == nil {
						t.Fatalf("bypass route: %+v, %v", option, err)
					}
				case "blocked":
					if _, ok := errors.AsType[*routeBlocked](err); !ok {
						t.Fatalf("blocked preparation: %v", err)
					}
				case "canceled":
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled preparation: %v", err)
					}
				}
				started := time.Now()
				if err := plane.MITMHost().Close(); err != nil {
					t.Fatal(err)
				}
				if time.Since(started) != 0 {
					t.Fatal("untransferred admission delayed host cleanup")
				}
			})
		})
	}
}

func TestMITMRouteOwnershipAcrossReloads(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		t.Run(fmt.Sprintf("inspect=%t", inspect), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				extension := func() *controlTestPlugin {
					p := mitmRoutingPlugin("original.example")
					p.plan.Scopes[0].PreserveRoute = inspect
					p.handle = func(e *plugin.Exchange, _ plugin.Handler) (*plugin.Response, error) {
						return e.NewResponse(&http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}), nil
					}
					return p
				}
				unexpectedDial := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("local response must not dial upstream")
				})
				plane, _, original := newHTTPRequestRouteTest(t, "", extension(), unexpectedDial)
				plane.ctx, plane.tcpSetupCtx = t.Context(), t.Context()
				plane.core.bpf = &BPFState{}
				transport := netproxy.NewRuntime(netproxy.Layer{Data: unexpectedDial})
				global := new(dialer.GlobalOption)
				d := dialer.NewDialer(transport, global, &dialer.Property{Name: "direct"}, false, "")
				group := outbound.NewDialerGroup(global, "direct", outbound.GroupKindSingleAlwaysAlive,
					[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
				t.Cleanup(func() { _ = group.Close() })
				plane.outbounds[0] = group
				if err := plane.MITMHost().Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				instances := make(map[*pluginhost.Instance]struct{})
				budget := netproxy.NewPacketBudget(1)
				for round := range 16 {
					before := plane.MITMHost()
					instances[before.Instances()[0]] = struct{}{}
					param, identity := *original, *original.routingResult
					param.routingResult = &identity
					if round%4 >= 2 {
						param.networkType = *common.NetworkUDP4.NetworkType()
					}
					option, intercepted, err := plane.prepareHTTPRoute(t.Context(), param.Domain, &param)
					if err != nil || intercepted == nil || (option != nil) != inspect || (intercepted.releaseDialer != nil) != inspect {
						intercepted.Release()
						t.Fatalf("round %d: option=%+v interception=%+v err=%v", round, option, intercepted, err)
					}
					var releases atomic.Int32
					releaseDialer := intercepted.releaseDialer
					intercepted.releaseDialer = func() {
						releases.Add(1)
						if releaseDialer != nil {
							releaseDialer()
						}
					}
					switch round % 4 {
					case 0, 1:
						server, client := net.Pipe()
						done := make(chan error, 1)
						relay := &tcpRelay{lConn: server, domain: param.Domain, dst: param.Dest, mitm: intercepted}
						go func() { done <- relay.run() }()
						if round%4 == 0 {
							if _, err := fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: original.example\r\nConnection: close\r\n\r\n"); err != nil {
								t.Fatal(err)
							}
							response, err := http.ReadResponse(bufio.NewReader(client), nil)
							if err != nil {
								t.Fatal(err)
							}
							_ = response.Body.Close()
							if response.StatusCode != http.StatusNoContent {
								t.Fatalf("unexpected local response: %d", response.StatusCode)
							}
						}
						_ = client.Close()
						if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
							t.Fatal(err)
						}
					case 2:
						bridge, err := plane.newMITMQUIC(t.Context(), budget, &param, intercepted, nil)
						if err != nil {
							t.Fatal(err)
						}
						_ = bridge.Close()
					case 3:
						held, err := budget.Open(t.Context(), "", func(context.Context, string) (net.PacketConn, error) { return newTestPacketConn(false), nil })
						if err != nil {
							t.Fatal(err)
						}
						bridge, err := plane.newMITMQUIC(t.Context(), budget, &param, intercepted, nil)
						_ = held.Close()
						if !errors.Is(err, netproxy.ErrPacketCapacity) || bridge != nil {
							t.Fatalf("capacity rejection: %v, %v", bridge, err)
						}
					}
					var next *mitm.Host
					if round%5 == 0 {
						next, err = before.PrepareSuccessor()
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = next.Close() })
					} else {
						next = controlTestHost(t, extension(), nil)
					}
					dnsDone := make(chan error, 1)
					go func() {
						dnsDone <- plane.processDNS(t.Context(), &plugin.DNSExchange{}, routingResult{}, false,
							func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) { return nil, nil },
							func([]byte) error { return nil })
					}()
					replaced := make(chan error, 1)
					go func() { replaced <- plane.ReplaceMITM(PreparedMITM{Host: next}, nil) }()
					select {
					case err := <-replaced:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(2 * handoffLifetime):
						intercepted.Release()
						<-replaced
						t.Fatal("route ownership leaked across replacement")
					}
					if err := <-dnsDone; err != nil {
						t.Fatalf("round %d: concurrent DNS admission failed: %v", round, err)
					}
					plane.retiredHosts.Wait()
					if got := releases.Load(); got != 1 {
						intercepted.Release()
						t.Fatalf("round %d: release called %d times", round, got)
					}
				}
				instances[plane.MITMHost().Instances()[0]] = struct{}{}
				if err := plane.MITMHost().Close(); err != nil {
					t.Fatal(err)
				}
				for instance := range instances {
					if instance.Retain() {
						_ = instance.Release()
						t.Fatal("retired plugin instance is still retained")
					}
				}
				_ = group.Close()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := transport.Wait(ctx); err != nil {
					t.Fatalf("retired dialer is still retained: %v", err)
				}
			})
		})
	}
}
