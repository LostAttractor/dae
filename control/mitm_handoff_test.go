// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/pluginctx"
)

type handoffHTTPPlugin struct{ *reloadStatePlugin }

func (*handoffHTTPPlugin) Plan() plugin.Plan {
	return plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "original.example", Ports: []uint16{80}}}}}}
}

func (*handoffHTTPPlugin) Wrap(_ plugin.Flow, _ plugin.Handler) plugin.Handler {
	return func(exchange *plugin.Exchange) (*plugin.Response, error) {
		return exchange.NewResponse(&http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}), nil
	}
}

func TestMITMHandoffWaitsAndCancelsAdmission(t *testing.T) {
	for _, protocol := range []string{"dns", "tcp", "quic"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var store atomic.Int32
				before := &reloadStatePlugin{store: &store, started: make(chan struct{})}
				plane, _, param := newHTTPRequestRouteTest(t, "", &handoffHTTPPlugin{before}, nil)
				plane.ctx, plane.tcpSetupCtx = t.Context(), t.Context()
				plane.core.bpf = &BPFState{}
				first := plane.MITMHost()
				if err := first.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				<-before.started
				before.state.Store(2)
				after := &reloadStatePlugin{store: &store, started: make(chan struct{})}
				next := controlTestHost(t, &handoffHTTPPlugin{after}, nil)
				admitted, finish := make(chan struct{}), make(chan struct{})
				finishRequest := sync.OnceFunc(func() { close(finish) })
				t.Cleanup(finishRequest)
				oldRequest := make(chan error, 1)
				go func() {
					_, err := first.HandleDNS(t.Context(), &plugin.DNSExchange{}, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
						close(admitted)
						<-finish
						return nil, nil
					}, func(*plugin.DNSResponse) error { return nil })
					oldRequest <- err
				}()
				<-admitted
				replaced := make(chan error, 1)
				go func() { replaced <- plane.ReplaceMITM(PreparedMITM{Host: next}, nil) }()
				synctest.Wait()
				if admission, err := first.Admit(); !errors.Is(err, net.ErrClosed) {
					admission.Release()
					t.Fatalf("old host did not enter drain: %v", err)
				}
				request := func(ctx context.Context) error {
					if protocol == "dns" {
						return plane.processDNS(ctx, &plugin.DNSExchange{}, routingResult{}, false, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
							if plane.MITMHost() != next || !before.closed.Load() {
								return nil, errors.New("DNS ran before successor publication")
							}
							return nil, nil
						}, func([]byte) error { return nil })
					}
					flow := *param
					if protocol == "quic" {
						flow.networkType = *common.NetworkUDP4.NetworkType()
					}
					_, intercepted, err := plane.prepareHTTPRoute(ctx, flow.Domain, &flow)
					if err != nil {
						return err
					}
					if intercepted == nil || intercepted.admission.Host() != next || !before.closed.Load() {
						intercepted.Release()
						return errors.New("connection selected a retired host")
					}
					if protocol == "quic" {
						bridge, err := plane.newMITMQUIC(ctx, nil, &flow, intercepted, nil)
						if err != nil {
							return err
						}
						return bridge.Close()
					}
					defer intercepted.Release()
					server, client := net.Pipe()
					defer client.Close()
					served := make(chan error, 1)
					go func() {
						served <- intercepted.admission.ServeConn(server, plugin.Flow{Host: flow.Domain, Port: flow.Dest.Port()}, intercepted.planner)
					}()
					if _, err := fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: original.example\r\nConnection: close\r\n\r\n"); err != nil {
						return err
					}
					response, err := http.ReadResponse(bufio.NewReader(client), nil)
					if err != nil {
						return err
					}
					_ = response.Body.Close()
					_ = client.Close()
					if response.StatusCode != http.StatusNoContent {
						return fmt.Errorf("successor response status = %d", response.StatusCode)
					}
					return <-served
				}
				pending := make(chan error, 1)
				go func() { pending <- request(t.Context()) }()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				canceled := make(chan error, 1)
				go func() { canceled <- request(ctx) }()
				synctest.Wait()
				select {
				case err := <-pending:
					t.Fatalf("request did not wait for handoff: %v", err)
				default:
				}
				cancel()
				if err := <-canceled; !errors.Is(err, context.Canceled) {
					t.Fatalf("waiting request ignored cancellation: %v", err)
				}
				finishRequest()
				if err := <-oldRequest; err != nil {
					t.Fatal(err)
				}
				if err := <-replaced; err != nil {
					t.Fatal(err)
				}
				if err := <-pending; err != nil {
					t.Fatal(err)
				}
				<-after.started
				if after.state.Load() != 2 {
					t.Fatal("successor did not restore the final state")
				}
			})
		})
	}
}

func TestMITMHandoffPreservesAcceptedDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := controlTestHost(t, new(controlTestPlugin), nil)
		next := controlTestHost(t, new(controlTestPlugin), nil)
		plane := &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{}}, ctx: t.Context(), mitmHost: first}
		admission, err := plane.admitMITM(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer admission.Release()
		replaced := make(chan error, 1)
		go func() { replaced <- plane.ReplaceMITM(PreparedMITM{Host: next}, nil) }()
		synctest.Wait()
		if _, err := admission.HandleDNS(t.Context(), &plugin.DNSExchange{}, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
			return nil, nil
		}, func(*plugin.DNSResponse) error { return nil }); err != nil {
			t.Fatalf("drain rejected already accepted DNS work: %v", err)
		}
		admission.Release()
		if err := <-replaced; err != nil {
			t.Fatal(err)
		}
	})
}

func TestMITMHandoffFailureReleasesWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failure := errors.New("final flush failed")
		var store atomic.Int32
		p := &reloadStatePlugin{store: &store, started: make(chan struct{}), closeErr: failure}
		first := controlTestHost(t, p, nil)
		next := controlTestHost(t, new(controlTestPlugin), nil)
		plane := &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{}}, ctx: t.Context(), mitmHost: first}
		admission, err := plane.admitMITM(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer admission.Release()
		replaced := make(chan error, 1)
		go func() { replaced <- plane.ReplaceMITM(PreparedMITM{Host: next}, nil) }()
		synctest.Wait()
		waiting := make(chan error, 1)
		go func() {
			admitted, err := plane.admitMITM(t.Context())
			admitted.Release()
			waiting <- err
		}()
		synctest.Wait()
		admission.Release()
		if err := <-replaced; !errors.Is(err, failure) {
			t.Fatalf("replacement error = %v", err)
		}
		if err := <-waiting; !errors.Is(err, failure) {
			t.Fatalf("waiting request error = %v", err)
		}
		if admitted, err := plane.admitMITM(t.Context()); !errors.Is(err, failure) {
			admitted.Release()
			t.Fatalf("failed handoff accepted later work: %v", err)
		}
	})
}

type handoffTestLink struct{ link.Link }

func (handoffTestLink) Close() error { return nil }

func TestPublishKeepsMITMInstancesWithRoutingGeneration(t *testing.T) {
	for _, rebuild := range []bool{false, true} {
		t.Run(fmt.Sprintf("rebuild=%t", rebuild), func(t *testing.T) {
			plan := plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: plugin.Scope{{Host: "original.example", Ports: []uint16{80}}}}}}
			old, _, original := newHTTPRequestRouteTest(t, "l4proto(tcp) -> proxy", &controlTestPlugin{plan: plan}, nil)
			plan.RequiredOutbounds = []string{"new-policy"}
			next, _, _ := newHTTPRequestRouteTest(t, "l4proto(tcp) -> direct", &controlTestPlugin{plan: plan}, nil)
			next.outbounds = append(next.outbounds, downloadTestGroup(t, "new-policy", nil))
			if !rebuild {
				var err error
				next.mitmHost, err = old.mitmHost.PrepareSuccessor()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = next.mitmHost.Close() })
			}
			source, err := network.NewInterfaceManager()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = source.Close() })
			runtime := NewRuntime()
			// Existing attachments keep publication entirely in userspace.
			runtime.kernelLinks.exitLink = handoffTestLink{}
			runtime.kernelLinks.netnsLinks = []link.Link{handoffTestLink{}}
			for generation, plane := range []*ControlPlane{old, next} {
				registry, _ := newTestRegistry(16, time.Hour)
				t.Cleanup(func() { _ = registry.Close() })
				plane.ctx, plane.cancel = context.WithCancel(t.Context())
				closed, cancel := context.WithCancel(t.Context())
				scope := source.NewScope()
				t.Cleanup(func() { _ = scope.Close() })
				plane.core = &controlPlaneCore{kernelLinks: &runtime.kernelLinks,
					bpf: &BPFState{bpfObjects: new(bpfObjects), Runtime: runtime}, domainRegistry: registry,
					closed: closed, close: cancel, ifmgr: scope, hostBinder: &hostBinder{kernelLinks: &runtime.kernelLinks}}
				plane.planeTraffic = newPlaneTraffic(plane.ctx, &runtime.tcpConnections, runtime.udpEndpoints)
				plane.dnsRelay = newDNSRelay()
				plane.cleanups.add(plane.dnsRelay.Close)
				plane.routingGeneration = uint32(generation + 1)
			}
			runtime.current, runtime.planes[1] = old, old
			t.Cleanup(func() { _ = runtime.Close() })
			if err := old.mitmHost.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Publish(next, false); err != nil {
				t.Fatal(err)
			}
			for _, protocol := range []string{"tcp", "quic", "dns"} {
				t.Run(protocol, func(t *testing.T) {
					if protocol == "dns" {
						called := false
						err := old.processDNS(t.Context(), &plugin.DNSExchange{}, routingResult{}, false, func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
							called = true
							return nil, nil
						}, func([]byte) error { return nil })
						if rebuild && (!errors.Is(err, net.ErrClosed) || called) || !rebuild && (err != nil || !called) {
							t.Fatalf("old DNS admission: called=%t err=%v", called, err)
						}
						return
					}
					param, identity := *original, *original.routingResult
					param.routingResult = &identity
					if protocol == "quic" {
						param.networkType = *common.NetworkUDP4.NetworkType()
					}
					_, route, err := old.prepareHTTPRoute(t.Context(), param.Domain, &param)
					defer route.Release()
					if rebuild {
						if !errors.Is(err, net.ErrClosed) || route != nil {
							var planningErr error
							if route != nil {
								request := httptest.NewRequestWithContext(pluginctx.WithHTTPPolicy(t.Context(), "new-policy"), "GET", "http://original.example/", nil)
								_, planningErr = route.planner(request)
							}
							t.Fatalf("old generation admitted rebuilt plugin: route=%v err=%v policy=%v", route != nil, err, planningErr)
						}
					} else if err != nil || route == nil || route.admission.Host() != old.mitmHost {
						t.Fatalf("reused instances lost their old-generation host: route=%v err=%v", route != nil, err)
					}
				})
			}
			param, identity := *original, *original.routingResult
			param.routingResult = &identity
			_, route, err := next.prepareHTTPRoute(t.Context(), param.Domain, &param)
			if err != nil || route == nil {
				t.Fatalf("new-generation admission: %v", err)
			}
			defer route.Release()
			request := httptest.NewRequestWithContext(pluginctx.WithHTTPPolicy(t.Context(), "new-policy"), "GET", "http://original.example/", nil)
			if _, err := route.planner(request); err != nil {
				t.Fatalf("new generation lost its new policy: %v", err)
			}
		})
	}
}

func TestAbortInterruptsAlreadyDrainingRetiredHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := controlTestHost(t, new(controlTestPlugin), nil)
		plane := newLifecycleTestControlPlane(t, new(UdpEndpointPool))
		plane.core = &controlPlaneCore{bpf: &BPFState{}}
		plane.mitmHost = first
		admitted := make(chan struct{})
		requestDone := make(chan error, 1)
		go func() {
			_, err := first.HandleDNS(t.Context(), &plugin.DNSExchange{}, func(ctx context.Context, _ *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				close(admitted)
				<-ctx.Done()
				return nil, ctx.Err()
			}, func(*plugin.DNSResponse) error { return nil })
			requestDone <- err
		}()
		<-admitted
		shared, err := first.PrepareSuccessor()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = shared.Close() })
		if err := plane.ReplaceMITM(PreparedMITM{Host: shared}, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(handoffLifetime)
		synctest.Wait()
		started := time.Now()
		plane.interruptSetups()
		plane.retiredHosts.Wait()
		if elapsed := time.Since(started); elapsed != 0 {
			t.Fatalf("abort waited for an already draining host: %v", elapsed)
		}
		if err := <-requestDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("old request did not observe abort: %v", err)
		}
	})
}
