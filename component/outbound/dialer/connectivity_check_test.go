/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type blockingFailConnectDialer struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (d *blockingFailConnectDialer) Alive() bool { return true }

func (d *blockingFailConnectDialer) Connect() error {
	if d.calls.Add(1) == 1 {
		close(d.started)
	}
	<-d.release
	return errors.New("connect failed")
}

func (d *blockingFailConnectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *blockingFailConnectDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type failOnceConnectDialer struct {
	calls atomic.Int32
}

func (d *failOnceConnectDialer) Alive() bool { return true }

func (d *failOnceConnectDialer) Connect() error {
	if d.calls.Add(1) == 1 {
		return errors.New("connect failed")
	}
	return nil
}

func (d *failOnceConnectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *failOnceConnectDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type statusRecordingGroup struct {
	notified chan stats.Availability
}

var testDialerSequence atomic.Uint64

func (g *statusRecordingGroup) NotifyStatusChange(d *Dialer) {
	select {
	case g.notified <- stats.GetNode(d.StatsKey()):
	default:
	}
}

func (g *statusRecordingGroup) GetEmaAlpha() float64 { return 0.5 }

func (g *statusRecordingGroup) GetTimeoutPenalty() time.Duration { return time.Minute }

func newTestDialer(t *testing.T, transport netproxy.Dialer) *Dialer {
	t.Helper()
	id := testDialerSequence.Add(1)
	return NewDialer(transport, &GlobalOption{}, &Property{Property: D.Property{
		Name: t.Name(),
		Link: fmt.Sprintf("test://%s/%d", t.Name(), id),
	}}, true)
}

func TestRunCheckLoopPublishesConsecutiveFailure(t *testing.T) {
	transport := &blockingFailConnectDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	close(transport.release)
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 3)}
	d.RegisterDialerGroup(group)

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(nil)
	}()
	d.NotifyCheck()
	timeout := time.After(time.Second)

waitForFailure:
	for {
		select {
		case avail := <-group.notified:
			if avail.ChecksFailed == 1 {
				break waitForFailure
			}
		case <-timeout:
			t.Fatal("consecutive failure was not published")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	avail := stats.GetNode(d.StatsKey())
	if avail.ChecksTotal != 1 || avail.ChecksFailed != 1 {
		t.Fatalf("consecutive failure was not recorded once: %+v", avail)
	}
	if avail.LastFailureStartedAt.IsZero() {
		t.Fatalf("consecutive failure should start a failure episode: %+v", avail)
	}
	if got := transport.calls.Load(); got != 2 {
		t.Fatalf("Connect calls = %d, want 2", got)
	}
}

func TestInitialCheckPublishesFailedConnect(t *testing.T) {
	transport := &blockingFailConnectDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	close(transport.release)
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 1)}
	d.RegisterDialerGroup(group)

	done := make(chan struct{})
	go func() {
		d.runInitialCheck(nil)
		close(done)
	}()
	select {
	case avail := <-group.notified:
		if avail.ChecksFailed != 1 {
			t.Fatalf("notification observed %d failed checks, want 1", avail.ChecksFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("initial failed Connect did not publish the dialer state")
	}
	if avail := stats.GetNode(d.StatsKey()); avail.ChecksTotal != 1 || avail.ChecksFailed != 1 {
		t.Fatalf("initial failed Connect was not recorded: %+v", avail)
	}
	d.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("initial check did not stop after cancellation")
	}
}

func TestInitialCheckDoesNotConnectAfterCancellation(t *testing.T) {
	transport := &failOnceConnectDialer{}
	d := newTestDialer(t, transport)
	d.cancel()

	if opt := d.runInitialCheck(nil); opt != nil {
		t.Fatal("canceled initial check unexpectedly selected an option")
	}
	if got := transport.calls.Load(); got != 0 {
		t.Fatalf("Connect calls after cancellation = %d, want 0", got)
	}
	if avail := stats.GetNode(d.StatsKey()); avail.Seen {
		t.Fatalf("canceled initial check should not be recorded: %+v", avail)
	}
}

func TestRunCheckLoopIgnoresTransientFailure(t *testing.T) {
	transport := &failOnceConnectDialer{}
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 2)}
	d.RegisterDialerGroup(group)
	checkOpt := &CheckOption{
		networkType: common.IndexToNetworkType(0),
		CheckFunc: func(*common.NetworkType) (bool, error) {
			return true, nil
		},
	}

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(checkOpt)
	}()
	d.NotifyCheck()
	timeout := time.After(time.Second)

waitForRetry:
	for {
		select {
		case avail := <-group.notified:
			if avail.Alive && avail.ChecksTotal == 1 {
				break waitForRetry
			}
		case <-timeout:
			t.Fatal("successful immediate retry was not published")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	avail := stats.GetNode(d.StatsKey())
	if !avail.Alive || avail.ChecksTotal != 1 || avail.ChecksFailed != 0 || avail.ChecksSinceAlive != 1 {
		t.Fatalf("transient failure should only publish the successful retry: %+v", avail)
	}
	if got := transport.calls.Load(); got != 2 {
		t.Fatalf("Connect calls = %d, want 2", got)
	}
	latency, ok := d.LatencyStats(group)
	if !ok || latency.Avg10HasFailure {
		t.Fatalf("transient failure should not enter avg10: %+v, ok=%v", latency, ok)
	}
}

func TestRunCheckLoopDoesNotPublishAfterClose(t *testing.T) {
	transport := &blockingFailConnectDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	group := &statusRecordingGroup{notified: make(chan stats.Availability, 2)}
	d.RegisterDialerGroup(group)

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheckLoop(nil)
	}()
	d.NotifyCheck()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("Connect did not start")
	}
	select {
	case <-group.notified:
	case <-time.After(time.Second):
		t.Fatal("transport disconnect was not published before Connect")
	}

	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case <-d.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the dialer")
	}
	close(transport.release)

	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the in-flight Connect finished")
	}
	if got := transport.calls.Load(); got != 1 {
		t.Fatalf("Connect calls after cancellation = %d, want 1", got)
	}
	if avail := stats.GetNode(d.StatsKey()); avail.Seen {
		t.Fatalf("canceled Connect should not be recorded: %+v", avail)
	}
	select {
	case <-group.notified:
		t.Fatal("canceled Connect unexpectedly published its result")
	default:
	}
}

func TestRunCheckLoopDoesNotStartQueuedCheckAfterClose(t *testing.T) {
	transport := &failOnceConnectDialer{}
	d := newTestDialer(t, transport)
	d.CheckInterval = time.Hour
	d.CheckIntervalMax = time.Hour
	d.NotifyCheck()
	d.cancel()

	d.runCheckLoop(nil)

	if got := transport.calls.Load(); got != 0 {
		t.Fatalf("Connect calls after cancellation = %d, want 0", got)
	}
}
