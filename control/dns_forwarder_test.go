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

func TestDoTLSCloseWaitsForExchange(t *testing.T) {
	transport := &pipeTLSTestDialer{server: make(chan net.Conn, 1)}
	forwarder := &DoTLS{
		dialArgument: dialArgument{Dialer: &dialer.Dialer{Dialer: transport}},
		state:        newDNSForwarderState(context.Background()),
		exchanges:    make(map[*dnsTLSExchange]struct{}),
	}
	forwarder.Upstream.Hostname = "resolver.example"
	requestDone := make(chan error, 1)
	go func() {
		requestDone <- forwarder.ForwardDNS(context.Background(), testDNSQuery("example.com.", dnsmessage.TypeA, 1))
	}()
	server := <-transport.server
	defer server.Close()
	deadline := time.Now().Add(time.Second)
	for {
		forwarder.mu.Lock()
		active := len(forwarder.exchanges)
		forwarder.mu.Unlock()
		if active != 0 || time.Now().After(deadline) {
			if active == 0 {
				t.Fatal("DoT exchange was not registered")
			}
			break
		}
		time.Sleep(time.Millisecond)
	}

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
		if err == nil {
			t.Fatal("closed DoT exchange unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DoT request remained blocked after Close")
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
	forwarder := &managedDNSForwarder{
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
	forwarder := &managedDNSForwarder{
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
	forwarder := &managedDNSForwarder{
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
