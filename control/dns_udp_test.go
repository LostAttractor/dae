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

	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
)

type directDnsTestDialer struct{}

type blockingDnsTestDialer struct {
	started chan struct{}
}

func (directDnsTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
func (directDnsTestDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", address)
}

func (d blockingDnsTestDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d blockingDnsTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestDoUDPCloseClosesActiveConnections(t *testing.T) {
	client1, server1 := net.Pipe()
	defer server1.Close()
	client2, server2 := net.Pipe()
	defer server2.Close()
	d := &DoUDP{
		connections: map[net.Conn]struct{}{client1: {}, client2: {}},
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for i, server := range []net.Conn{server1, server2} {
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := server.Read(make([]byte, 1)); err == nil {
			t.Fatalf("active connection %d remained open", i)
		}
	}
	if err := d.ForwardDNS(context.Background(), testQuery("example.com.", dnsmessage.TypeA, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed forwarder error = %v, want net.ErrClosed", err)
	}
}

func TestDoUDPTracksConnectionUntilAsyncCloseFinishes(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &blockingDNSCloseConn{
		Conn: client, closeStarted: make(chan struct{}), closeRelease: make(chan struct{}),
	}
	d := &DoUDP{connections: map[net.Conn]struct{}{conn: {}}}
	d.releaseConnection(conn)
	<-conn.closeStarted
	d.mu.Lock()
	_, tracked := d.connections[conn]
	d.mu.Unlock()
	if !tracked {
		t.Fatal("connection was untracked before Close completed")
	}
	close(conn.closeRelease)
	deadline := time.Now().Add(time.Second)
	for {
		d.mu.Lock()
		_, tracked = d.connections[conn]
		d.mu.Unlock()
		if !tracked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("closed connection remained tracked")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDoUDPUsesDistinctSocketsForConcurrentQueries(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	forwarder := &DoUDP{dialArgument: dialArgument{
		Dialer: &componentdialer.Dialer{Dialer: directDnsTestDialer{}},
		Target: server.LocalAddr().(*net.UDPAddr).AddrPort(),
	}}
	defer forwarder.Close()

	ports := make(chan int, 2)
	go func() {
		type request struct {
			msg  dnsmessage.Msg
			addr *net.UDPAddr
		}
		requests := make([]request, 0, 2)
		for len(requests) < 2 {
			buf := make([]byte, 65535)
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Msg
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}
			ports <- addr.Port
			requests = append(requests, request{msg: msg, addr: addr})
		}
		for _, request := range requests {
			payload, err := answerHandler(&request.msg).Pack()
			if err == nil {
				_, _ = server.WriteToUDP(payload, request.addr)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			msg := testQuery("example.com.", dnsmessage.TypeA, id)
			if err := forwarder.ForwardDNS(context.Background(), msg); err != nil {
				t.Error(err)
				return
			}
			if msg.Id != id {
				t.Errorf("client transaction ID = %d, want %d", msg.Id, id)
			}
		}(uint16(i + 1))
	}
	wg.Wait()
	first, second := <-ports, <-ports
	if first == second {
		t.Fatalf("concurrent UDP queries reused source port %d", first)
	}
}

func TestDoUDPCloseCancelsInProgressDial(t *testing.T) {
	started := make(chan struct{})
	forwarder := &DoUDP{dialArgument: dialArgument{
		Dialer: &componentdialer.Dialer{Dialer: blockingDnsTestDialer{started: started}},
	}}
	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- forwarder.ForwardDNS(context.Background(), testQuery("example.com.", dnsmessage.TypeA, 1))
	}()
	<-started
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-forwardDone:
		if err == nil {
			t.Fatal("forwarding unexpectedly succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and wait for the in-progress dial")
	}
}
