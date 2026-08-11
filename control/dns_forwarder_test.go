/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
)

var errTLSTestDialReleased = errors.New("test dial released")

type concurrentTLSTestDialer struct {
	entered chan struct{}
	release chan struct{}
}

type pipeTLSTestDialer struct {
	server chan net.Conn
	wrap   func(net.Conn) net.Conn
}

type retryTCPTestDialer struct {
	mu       sync.Mutex
	calls    int
	firstErr error
	server   chan net.Conn
}

type blockingPacketTestDialer struct {
	mu       sync.Mutex
	calls    int
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (d *pipeTLSTestDialer) Alive() bool    { return true }
func (d *pipeTLSTestDialer) Connect() error { return nil }
func (d *pipeTLSTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *pipeTLSTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	d.server <- server
	if d.wrap != nil {
		client = d.wrap(client)
	}
	return client, nil
}

func (d *retryTCPTestDialer) Alive() bool    { return true }
func (d *retryTCPTestDialer) Connect() error { return nil }
func (d *retryTCPTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *retryTCPTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	if call == 1 {
		return nil, d.firstErr
	}
	client, server := net.Pipe()
	d.server <- server
	return client, nil
}

func (d *blockingPacketTestDialer) Alive() bool    { return true }
func (d *blockingPacketTestDialer) Connect() error { return nil }
func (d *blockingPacketTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (d *blockingPacketTestDialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	if d.canceled != nil {
		close(d.canceled)
	}
	if d.release != nil {
		<-d.release
	}
	return nil, ctx.Err()
}

func (d *blockingPacketTestDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *concurrentTLSTestDialer) Alive() bool    { return true }
func (d *concurrentTLSTestDialer) Connect() error { return nil }
func (d *concurrentTLSTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *concurrentTLSTestDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.entered <- struct{}{}
	select {
	case <-d.release:
		return nil, errTLSTestDialReleased
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func waitForDoTLSExchange(t *testing.T, forwarder *DoTLS) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		forwarder.mu.Lock()
		active := len(forwarder.exchanges) != 0
		forwarder.mu.Unlock()
		if active {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("DoT exchange was not registered")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDoTLSAllowsConcurrentExchanges(t *testing.T) {
	transport := &concurrentTLSTestDialer{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(transport.release)
		}
	}()
	forwarder := &DoTLS{
		dialArgument: dialArgument{Dialer: &dialer.Dialer{Dialer: transport}},
		state:        newDNSForwarderState(context.Background()),
	}
	defer forwarder.Close()

	done := make(chan error, 2)
	go func() {
		done <- forwarder.ForwardDNS(context.Background(), testDNSQuery("one.example.", dnsmessage.TypeA, 1))
	}()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("first DoT exchange did not start dialing")
	}
	go func() {
		done <- forwarder.ForwardDNS(context.Background(), testDNSQuery("two.example.", dnsmessage.TypeA, 2))
	}()
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("second DoT exchange was serialized behind the first")
	}

	close(transport.release)
	released = true
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if !errors.Is(err, errTLSTestDialReleased) {
				t.Fatalf("ForwardDNS returned %v, want %v", err, errTLSTestDialReleased)
			}
		case <-time.After(time.Second):
			t.Fatal("DoT exchange did not return after dial release")
		}
	}
}

func TestDNSForwardersRejectUnsupportedQueriesBeforeDial(t *testing.T) {
	forwarders := []struct {
		name              string
		forwarder         DnsForwarder
		allowZoneTransfer bool
	}{
		{name: "DoH", forwarder: &DoH{}, allowZoneTransfer: true},
		{name: "DoQ", forwarder: &DoQ{}},
		{name: "DoT", forwarder: &DoTLS{}},
		{name: "TCP", forwarder: &DoTCP{}},
		{name: "UDP", forwarder: &DoUDP{}},
	}
	signatures := map[string]dnsmessage.RR{
		"TSIG": &dnsmessage.TSIG{Hdr: dnsmessage.RR_Header{Rrtype: dnsmessage.TypeTSIG}},
		"SIG(0)": &dnsmessage.SIG{RRSIG: dnsmessage.RRSIG{Hdr: dnsmessage.RR_Header{
			Rrtype: dnsmessage.TypeSIG,
		}}},
	}
	for _, forwarder := range forwarders {
		t.Run(forwarder.name, func(t *testing.T) {
			for name, signature := range signatures {
				t.Run(name, func(t *testing.T) {
					query := testDNSQuery("example.com.", dnsmessage.TypeA, 1)
					query.Extra = append(query.Extra, signature)
					if err := forwarder.forwarder.ForwardDNS(context.Background(), query); err == nil {
						t.Fatal("signed query unexpectedly reached the dial path")
					}
				})
			}
			if forwarder.allowZoneTransfer {
				return
			}
			for _, qtype := range []uint16{dnsmessage.TypeAXFR, dnsmessage.TypeIXFR} {
				t.Run(dnsmessage.Type(qtype).String(), func(t *testing.T) {
					query := testDNSQuery("example.com.", qtype, 1)
					if err := forwarder.forwarder.ForwardDNS(context.Background(), query); err == nil {
						t.Fatal("zone transfer unexpectedly reached the dial path")
					}
				})
			}
		})
	}
}

func TestDNSForwarderOperationErrorPriority(t *testing.T) {
	wantOperationErr := errors.New("operation failed")

	callerCtx, cancelCaller := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelCaller()
	closedState := newDNSForwarderState(context.Background())
	closedState.close()
	operationCtx, cancelOperation := context.WithCancel(context.Background())
	cancelOperation()
	if err := dnsForwarderOperationError(callerCtx, closedState, operationCtx, wantOperationErr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller priority error = %v, want context deadline", err)
	}

	if err := dnsForwarderOperationError(context.Background(), closedState, operationCtx, wantOperationErr); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("state priority error = %v, want net.ErrClosed", err)
	}

	stateParent, cancelState := context.WithCancel(context.Background())
	activeState := newDNSForwarderState(stateParent)
	cancelState()
	if err := dnsForwarderOperationError(context.Background(), activeState, operationCtx, wantOperationErr); !errors.Is(err, context.Canceled) {
		t.Fatalf("state context priority error = %v, want context cancellation", err)
	}

	activeState = newDNSForwarderState(context.Background())
	if err := dnsForwarderOperationError(context.Background(), activeState, operationCtx, wantOperationErr); !errors.Is(err, context.Canceled) {
		t.Fatalf("operation context priority error = %v, want context cancellation", err)
	}
	if err := dnsForwarderOperationError(context.Background(), activeState, context.Background(), wantOperationErr); !errors.Is(err, wantOperationErr) {
		t.Fatalf("operation error = %v, want %v", err, wantOperationErr)
	}
}

func TestDoTLSCloseWaitsForExchange(t *testing.T) {
	transport := &pipeTLSTestDialer{server: make(chan net.Conn, 1)}
	forwarder := &DoTLS{
		dialArgument: dialArgument{Dialer: &dialer.Dialer{Dialer: transport}},
		state:        newDNSForwarderState(context.Background()),
	}
	forwarder.Upstream.Hostname = "resolver.example"
	requestDone := make(chan error, 1)
	go func() {
		requestDone <- forwarder.ForwardDNS(context.Background(), testDNSQuery("example.com.", dnsmessage.TypeA, 1))
	}()
	server := <-transport.server
	defer server.Close()
	waitForDoTLSExchange(t, forwarder)

	closeDone := make(chan error, 1)
	go func() { closeDone <- forwarder.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoT Close did not wait for and stop the active exchange")
	}
	select {
	case err := <-requestDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed DoT exchange error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoT request remained blocked after Close")
	}
}

func TestDoTLSCallerCancellationStopsExchange(t *testing.T) {
	transport := &pipeTLSTestDialer{server: make(chan net.Conn, 1)}
	forwarder := &DoTLS{
		dialArgument: dialArgument{Dialer: &dialer.Dialer{Dialer: transport}},
		state:        newDNSForwarderState(context.Background()),
	}
	forwarder.Upstream.Hostname = "resolver.example"
	ctx, cancel := context.WithCancel(context.Background())
	requestDone := make(chan error, 1)
	go func() {
		requestDone <- forwarder.ForwardDNS(ctx, testDNSQuery("example.com.", dnsmessage.TypeA, 1))
	}()
	server := <-transport.server
	defer server.Close()
	waitForDoTLSExchange(t, forwarder)
	cancel()
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled DoT exchange error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not stop the synchronous DoT exchange")
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDoTLSCancellationDoesNotWaitForBlockingClose(t *testing.T) {
	closeRelease := make(chan struct{})
	closeStarted := make(chan struct{})
	transport := &pipeTLSTestDialer{
		server: make(chan net.Conn, 1),
		wrap: func(conn net.Conn) net.Conn {
			return &blockingDNSCloseConn{Conn: conn, closeStarted: closeStarted, closeRelease: closeRelease}
		},
	}
	forwarder := &DoTLS{
		dialArgument: dialArgument{Dialer: &dialer.Dialer{Dialer: transport}},
		state:        newDNSForwarderState(context.Background()),
	}
	forwarder.Upstream.Hostname = "resolver.example"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- forwarder.ForwardDNS(ctx, testDNSQuery("example.com.", dnsmessage.TypeA, 1))
	}()
	server := <-transport.server
	defer server.Close()
	cancel()
	<-closeStarted
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ForwardDNS error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ForwardDNS waited for blocking Close")
	}
	close(closeRelease)
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDNSForwarderBoundsBlockedRetirement(t *testing.T) {
	oldClient, oldServer := net.Pipe()
	defer oldServer.Close()
	blocked := &blockingDNSCloseConn{
		Conn: oldClient, closeStarted: make(chan struct{}), closeRelease: make(chan struct{}),
	}
	oldManager := NewDnsManager(blocked)
	oldClose := make(chan error, 1)
	go func() { oldClose <- oldManager.Close() }()
	<-blocked.closeStarted

	currentClient, currentServer := net.Pipe()
	defer currentServer.Close()
	currentManager := NewDnsManager(currentClient)
	forwarder := &DoTCP{
		state:      newDNSForwarderState(context.Background()),
		dnsManager: currentManager,
		retiring:   oldManager,
	}
	if forwarder.allowIdleClose(currentManager) {
		t.Fatal("current manager retired while an older transport close was still blocked")
	}

	close(blocked.closeRelease)
	if err := <-oldClose; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !oldManager.closeComplete() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !forwarder.allowIdleClose(currentManager) {
		t.Fatal("current manager stayed pinned after the older transport closed")
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDNSForwarderRetriesDialBeforeOccupyingRetiringSlot(t *testing.T) {
	oldClient, oldServer := net.Pipe()
	defer oldServer.Close()
	blocked := &blockingDNSCloseConn{
		Conn: oldClient, closeStarted: make(chan struct{}), closeRelease: make(chan struct{}),
	}
	oldManager := NewDnsManager(blocked)
	oldClose := make(chan error, 1)
	go func() { oldClose <- oldManager.Close() }()
	<-blocked.closeStarted

	wantErr := errors.New("temporary dial failure")
	transport := &retryTCPTestDialer{firstErr: wantErr, server: make(chan net.Conn, 1)}
	forwarder := &DoTCP{
		state:      newDNSForwarderState(context.Background()),
		dnsManager: oldManager,
		dialArgument: dialArgument{
			Dialer: &dialer.Dialer{Dialer: transport},
		},
	}
	if _, err := forwarder.getManager(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("first replacement dial returned %v, want %v", err, wantErr)
	}
	manager, err := forwarder.getManager(context.Background())
	if err != nil {
		t.Fatalf("temporary dial failure made the forwarder unrecoverable: %v", err)
	}
	if manager == oldManager {
		t.Fatal("replacement dial returned the retired manager")
	}
	server := <-transport.server
	defer server.Close()

	close(blocked.closeRelease)
	if err := <-oldClose; err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDNSForwarderRecoversAfterTransportCloseError(t *testing.T) {
	oldClient, oldServer := net.Pipe()
	defer oldServer.Close()
	wantErr := errors.New("old transport close failed")
	oldManager := NewDnsManager(&dnsCloseErrorConn{Conn: oldClient, err: wantErr})
	if err := oldManager.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("old manager Close returned %v, want %v", err, wantErr)
	}
	if !oldManager.closeComplete() {
		t.Fatal("close error prevented manager completion")
	}

	transport := &pipeTLSTestDialer{server: make(chan net.Conn, 1)}
	forwarder := &DoTCP{
		state:      newDNSForwarderState(context.Background()),
		dnsManager: oldManager,
		dialArgument: dialArgument{
			Dialer: &dialer.Dialer{Dialer: transport},
		},
	}
	manager, err := forwarder.getManager(context.Background())
	if err != nil {
		t.Fatalf("transport close error made the forwarder unrecoverable: %v", err)
	}
	if manager == oldManager {
		t.Fatal("replacement returned the completed manager")
	}
	server := <-transport.server
	defer server.Close()
	if err := forwarder.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("forwarder Close lost retired transport error: %v", err)
	}
}

func TestDoQCoalescesBlockedConnectionDials(t *testing.T) {
	transport := &blockingPacketTestDialer{
		entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}),
	}
	forwarder := &DoQ{
		state: newDNSForwarderState(context.Background()),
		dialArgument: dialArgument{
			Dialer: &dialer.Dialer{Dialer: transport},
		},
	}
	results := make(chan error, 2)
	go func() {
		_, err := forwarder.getConn(context.Background())
		results <- err
	}()
	<-transport.entered
	go func() {
		_, err := forwarder.getConn(context.Background())
		results <- err
	}()

	deadline := time.Now().Add(time.Second)
	for transport.callCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if calls := transport.callCount(); calls != 1 {
		t.Fatalf("concurrent DoQ requests started %d connection dials, want 1", calls)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- forwarder.Close() }()
	<-transport.canceled
	select {
	case err := <-closeDone:
		t.Fatalf("DoQ Close returned before its shared dial exited: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(transport.release)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("blocked DoQ dial returned %v after Close", err)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked DoQ dial did not stop after Close")
		}
	}
}
