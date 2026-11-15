// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	dns "github.com/miekg/dns"
)

func TestIdentityHonorsScriptTimeout(t *testing.T) {
	for _, phase := range []string{"http-request", "http-response", "dns"} {
		for _, trace := range []bool{false, true} {
			for _, explicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/trace=%t/explicit=%t", phase, trace, explicit), func(t *testing.T) {
					rules := "[Script]\njob=type=" + phase + ",pattern=.,script-path=job.js"
					if phase == "dns" {
						rules = "[Host]\nidentity.example=script:job\n[Script]\njob=type=dns,script-path=job.js"
					}
					m := moduleScopeModule(t, "identity", "identity.example", rules, map[string]string{"job": `$done();`})
					e := moduleScopeEngine(t, m)
					const budget = 50 * time.Millisecond
					if explicit {
						m.Scripts[0].Timeout = budget
					} else {
						e.options.ScriptTimeout = budget
					}
					e.options.IsolateLAN = true
					devices := newTestDevices()
					entered := make(chan time.Time, 1)
					devices.identify = func(ctx context.Context, _ netip.Addr, mac [6]byte) [6]byte {
						deadline, _ := ctx.Deadline()
						entered <- deadline
						<-ctx.Done()
						if phase != "dns" {
							return [6]byte{}
						}
						return mac
					}
					e.options.Devices = devices
					if trace {
						e.options.Logger = new(proxyTraceCapture).logger()
					} else {
						e.options.Logger = nil
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					done := make(chan error, 1)
					go func() {
						if phase == "dns" {
							request := hostDNSRequest(t, "identity.example.", dns.TypeA)
							request.SourceOrigin, request.SourceMAC = plugin.SourceLAN, testDeviceMAC
							request.Source = netip.MustParseAddrPort("192.0.2.1:12345")
							key := dnsScriptKey(&m.Scripts[0], request)
							key.scope, key.generation = testDeviceScope, e.options.Runtime.data.generation.Load()
							e.dnsCache.put(key, []netip.Addr{netip.MustParseAddr("192.0.2.80")}, 60, time.Now())
							_, err := e.WrapDNS(nil)(ctx, request)
							done <- err
							return
						}
						flow := plugin.Flow{Host: "identity.example", Port: 443, SourceOrigin: plugin.SourceLAN,
							Source: netip.MustParseAddrPort("192.0.2.1:12345"), SourceMAC: testDeviceMAC}
						next := func(exchange *plugin.Exchange) (*plugin.Response, error) {
							return exchange.NewResponse(&http.Response{StatusCode: http.StatusOK, Request: exchange.Request.Head, Header: make(http.Header), Body: http.NoBody}), nil
						}
						request := plugin.NewRequest(httptest.NewRequestWithContext(ctx, "GET", "https://identity.example/", nil), e.options.BodyMemory)
						response, err := e.Wrap(flow, e.Wrap(flow, next))(&plugin.Exchange{Request: request})
						if response != nil {
							response.Close()
						}
						request.Body().Close()
						done <- err
					}()
					select {
					case deadline := <-entered:
						if deadline.IsZero() || time.Until(deadline) > budget {
							cancel()
							<-done
							t.Fatalf("identity did not receive the script deadline: %v", deadline)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("identity query did not start")
					}
					select {
					case err := <-done:
						if phase == "dns" {
							if !errors.Is(err, context.DeadlineExceeded) {
								t.Fatalf("identity timeout returned %v (or a cached DNS answer)", err)
							}
						} else {
							// HTTP script failures preserve transparent forwarding.
							if err != nil {
								t.Fatal(err)
							}
						}
					case <-time.After(2 * time.Second):
						cancel()
						<-done
						t.Fatal("identity query outlived the script deadline")
					}
					registry := surgeRegistry(t, e)
					outcome := "failed"
					if phase == "dns" {
						outcome = "skipped"
						if got := surgeMetric(t, registry, "surge_processing_skips_total", map[string]string{"stage": "dns", "reason": "timeout"}).GetCounter().GetValue(); got != 1 {
							t.Fatalf("identity timeout counted %v DNS skips", got)
						}
					}
					if got := surgeMetric(t, registry, "surge_scripts_total", map[string]string{"phase": phase, "result": outcome}).GetCounter().GetValue(); got != 1 {
						t.Fatalf("identity timeout counted %v script outcomes", got)
					}
					if len(entered) != 0 {
						t.Fatal("exchange retried a failed identity query")
					}
					if len(e.slots) != 0 {
						t.Fatalf("identity timeout retained %d execution slots", len(e.slots))
					}
				})
			}
		}
	}
}
