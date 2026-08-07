/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
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

func TestRunCheckStopsRetryingConnectAfterClose(t *testing.T) {
	transport := &blockingFailConnectDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	d := NewDialer(transport, &GlobalOption{}, &Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, true)

	d.checkWG.Add(1)
	go func() {
		defer d.checkWG.Done()
		d.runCheck(nil)
	}()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("Connect did not start")
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
}
