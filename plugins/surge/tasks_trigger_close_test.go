// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/apiserver"
)

type triggerCloseDevices struct {
	*testDeviceService
	calls                             atomic.Uint32
	ready, entered, canceled, release chan struct{}
}

func (s *triggerCloseDevices) MITMEnabled(ctx context.Context) ([][6]byte, error) {
	if s.calls.Add(1) == 1 {
		close(s.ready)
		return [][6]byte{testDeviceMAC}, nil
	}
	close(s.entered)
	select {
	case <-ctx.Done():
		close(s.canceled)
	case <-s.release:
		return nil, context.Canceled
	}
	<-s.release
	return nil, ctx.Err()
}

func TestScriptAPIAdmissionCancellationReleasesGeneration(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name := "request cancellation"
		if timeout {
			name = "admission timeout"
		}
		t.Run(name, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
				e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
				e.options.ScriptTimeout = time.Second
				entered := make(chan struct{})
				devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(testDeviceMAC)}
				devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
					if call == 1 {
						return [][6]byte{testDeviceMAC}, nil
					}
					close(entered)
					<-ctx.Done()
					return nil, errors.New("query socket closed")
				}
				e.options.Devices = devices
				host := startCronTestHost(t, e, http.DefaultClient)
				server := new(apiserver.Server)
				server.SetHandler(apiserver.NewHandler(apiserver.Options{APIKey: "secret", Scripts: host}))
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				r := httptest.NewRequest("POST", "http://192.0.2.1:8081/api/plugins/test/scripts/run", strings.NewReader(`{"script":"job","mac":"`+testDeviceName+`"}`))
				r = r.WithContext(context.WithValue(ctx, http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8081}))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Dae-API", "1")
				r.Header.Set("Authorization", "Bearer secret")
				response := httptest.NewRecorder()
				returned := make(chan struct{})
				go func() { server.ServeHTTP(response, r); close(returned) }()
				<-entered
				if timeout {
					time.Sleep(time.Second)
				} else {
					cancel()
				}
				synctest.Wait()
				select {
				case <-returned:
				default:
					t.Fatal("canceled admission still holds the API generation")
				}
				if response.Code != http.StatusServiceUnavailable {
					t.Fatalf("cancellation response: %d %s", response.Code, response.Body)
				}
				drained := make(chan struct{})
				go func() { server.SetHandler(nil); close(drained) }()
				synctest.Wait()
				select {
				case <-drained:
				default:
					t.Fatal("API drain waited for the still-active worker")
				}
				status := deviceTaskStatus(t, e, testDeviceMAC)
				if status.Runs != 0 || status.LastError != "" || status.State != "ready" || !status.LastStartedAt.IsZero() || len(e.Status().Modules[0].Warnings) != 0 || devices.active.Load() != 0 {
					t.Fatalf("admission cancellation changed history or device health: %+v", status)
				}
			})
		})
	}
}

func TestTaskTriggerRechecksAdmission(t *testing.T) {
	for _, change := range []string{"request", "worker", "generation", "busy"} {
		t.Run(change, func(t *testing.T) {
			runtimeFakeClockTest(t, func(t *testing.T) {
				module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
				e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
				entered, release := make(chan struct{}), make(chan struct{})
				devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(testDeviceMAC)}
				devices.query = func(_ context.Context, call int) ([][6]byte, error) {
					if call == 2 {
						close(entered)
						<-release
					}
					return [][6]byte{testDeviceMAC}, nil
				}
				e.options.Devices = devices
				host := startCronTestHost(t, e, http.DefaultClient)
				e.slots <- struct{}{}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				request := api.ScriptRunRequest{Script: "job", MAC: testDeviceName}
				triggered := make(chan error, 1)
				go func() { _, err := e.TriggerScript(ctx, request); triggered <- err }()
				<-entered
				want, runs := error(context.Canceled), uint64(0)
				switch change {
				case "request":
					cancel()
				case "worker":
					host.StopWorkers()
				case "generation":
					e.tasks.mu.Lock()
					previous := e.tasks.ctx
					e.tasks.ctx = context.WithValue(previous, struct{}{}, "successor")
					e.tasks.mu.Unlock()
					defer func() { e.tasks.mu.Lock(); e.tasks.ctx = previous; e.tasks.mu.Unlock() }()
					want = plugin.ErrScriptInactive
				case "busy":
					if _, err := host.TriggerScript(t.Context(), "test", request); err != nil {
						t.Fatal(err)
					}
					want, runs = plugin.ErrScriptBusy, 1
				}
				synctest.Wait()
				close(release)
				if err := <-triggered; !errors.Is(err, want) {
					t.Fatalf("admission after %s: %v, want %v", change, err, want)
				}
				if status := deviceTaskStatus(t, e, testDeviceMAC); status.Runs != runs || status.LastError != "" {
					t.Fatalf("rejected admission changed task history: %+v", status)
				}
				<-e.slots
			})
		})
	}
}

func TestTaskTriggerAdmissionBudgetIsSeparate(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		module := cronModule(t, "[Script]\njob=type=generic,timeout=1,script-path=job.js")
		e := cronTestEngine(t, module, map[string]string{"job": `setTimeout(() => $done(), 750);`}, 1)
		devices := &taskDiscoveryDevices{testDeviceService: newTestDevices(testDeviceMAC)}
		devices.query = func(ctx context.Context, call int) ([][6]byte, error) {
			if call == 2 {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) != time.Second {
					t.Error("admission did not inherit the script timeout")
				}
				time.Sleep(750 * time.Millisecond)
			}
			return [][6]byte{testDeviceMAC}, nil
		}
		e.options.Devices = devices
		host := startCronTestHost(t, e, http.DefaultClient)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		started := time.Now()
		response, err := host.TriggerScript(ctx, "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName})
		cancel()
		if err != nil || response.Run != 1 || response.Status.LastStartedAt.Sub(started) != 750*time.Millisecond {
			t.Fatalf("admission counted discovery as execution: %+v %v", response, err)
		}
		synctest.Wait()
		time.Sleep(750 * time.Millisecond)
		synctest.Wait()
		if status := deviceTaskStatus(t, e, testDeviceMAC); status.Runs != 1 || status.LastResult != "success" || status.LastDurationMS != 750 {
			t.Fatalf("accepted task inherited admission context/budget: %+v", status)
		}
	})
}

func TestHostCloseJoinsDeviceTrigger(t *testing.T) {
	module := cronModule(t, "[Script]\njob=type=generic,script-path=job.js")
	e := cronTestEngine(t, module, map[string]string{"job": `$done();`}, 1)
	devices := &triggerCloseDevices{testDeviceService: newTestDevices(), ready: make(chan struct{}), entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	e.options.Devices = devices
	host, err := mitm.New(mitm.Options{HTTPClient: http.DefaultClient}, mitm.Instance{ID: "test", Type: "surge", Plugin: e})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	defer close(devices.release)
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-devices.ready
	triggered := make(chan error, 1)
	go func() {
		_, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: "job", MAC: testDeviceName})
		triggered <- err
	}()
	<-devices.entered
	closed := make(chan error, 1)
	go func() { closed <- host.Close() }()
	select {
	case <-devices.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("host close could not cancel the device query")
	}
	select {
	case <-closed:
		t.Fatal("host close did not wait for device query cleanup")
	default:
	}
	devices.release <- struct{}{}
	if err := <-triggered; err == nil {
		t.Fatal("canceled device trigger was accepted")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
