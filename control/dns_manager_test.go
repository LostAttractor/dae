/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func testQuery(name string, qtype uint16, id uint16) *dnsmessage.Msg {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(dnsmessage.Fqdn(name), qtype)
	// miekg/dns SetQuestion assigns a random Id; set ours after it.
	msg.Id = id
	msg.RecursionDesired = true
	return msg
}

func answerHandler(req *dnsmessage.Msg) *dnsmessage.Msg {
	resp := new(dnsmessage.Msg)
	resp.SetReply(req)
	resp.Answer = []dnsmessage.RR{testARecord(req.Question[0].Name, "1.2.3.4")}
	return resp
}

// serveUDP answers datagrams until the listener is closed.
func serveUDP(ln *net.UDPConn, handler func(*dnsmessage.Msg) *dnsmessage.Msg) {
	for {
		buf := make([]byte, 65535)
		n, addr, err := ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var req dnsmessage.Msg
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}
		resp := handler(&req)
		if resp == nil {
			continue
		}
		data, err := resp.Pack()
		if err != nil {
			continue
		}
		_, _ = ln.WriteToUDP(data, addr)
	}
}

func testUDPSocketPair(t *testing.T) (client net.Conn, server *net.UDPConn) {
	t.Helper()
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	client, err = net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, server
}

func TestDnsManagerResolveUDP(t *testing.T) {
	client, server := testUDPSocketPair(t)
	go serveUDP(server, answerHandler)

	m := NewDnsManager(client, false)
	defer m.Close()

	msg := testQuery("example.com.", dnsmessage.TypeA, 1234)
	if err := m.Resolve(msg); err != nil {
		t.Fatal(err)
	}
	if !msg.Response {
		t.Errorf("expected a response message")
	}
	if msg.Id != 1234 {
		t.Errorf("client transaction ID should be restored: got %v", msg.Id)
	}
	if !cacheIncludesA([]*DnsCache{{Answer: msg.Answer[0]}}, "1.2.3.4") {
		t.Errorf("unexpected answer: %v", msg.Answer)
	}
}

func TestDnsManagerConcurrentQueriesShareOneConnection(t *testing.T) {
	client, server := testUDPSocketPair(t)

	var mu sync.Mutex
	wireIds := map[uint16]bool{}
	go serveUDP(server, func(req *dnsmessage.Msg) *dnsmessage.Msg {
		mu.Lock()
		wireIds[req.Id] = true
		mu.Unlock()
		return answerHandler(req)
	})

	m := NewDnsManager(client, false)
	defer m.Close()

	// Two in-flight queries reusing the same client transaction ID: the
	// manager must give them distinct on-the-wire IDs.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := testQuery("example.com.", dnsmessage.TypeA, 42)
			if err := m.Resolve(msg); err != nil {
				t.Error(err)
				return
			}
			if msg.Id != 42 {
				t.Errorf("client transaction ID should be restored: got %v", msg.Id)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(wireIds) != 2 {
		t.Errorf("in-flight queries should get distinct wire IDs: got %v", wireIds)
	}
}

func TestDnsManagerTimeoutIsTimeoutError(t *testing.T) {
	client, _ := testUDPSocketPair(t) // server never answers

	m := NewDnsManager(client, false)
	defer m.Close()
	m.timeout = 50 * time.Millisecond

	err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 1))
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("timeout must surface as net.Error with Timeout()==true (got %v)", err)
	}
	if !m.IsClosed() {
		t.Error("timed-out manager should be closed so the next query re-dials")
	}
}

func TestDnsManagerContextCancellation(t *testing.T) {
	client, _ := testUDPSocketPair(t)
	m := NewDnsManager(client, false)
	m.timeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.ResolveContext(ctx, testQuery("example.com.", dnsmessage.TypeA, 2)) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ResolveContext error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ResolveContext did not stop after cancellation")
	}
}

func TestDnsManagerCaseInsensitiveQuestionMatch(t *testing.T) {
	client, server := testUDPSocketPair(t)
	go serveUDP(server, func(req *dnsmessage.Msg) *dnsmessage.Msg {
		resp := answerHandler(req)
		// Some upstreams echo the question with randomized case.
		resp.Question[0].Name = strings.ToUpper(resp.Question[0].Name)
		return resp
	})

	m := NewDnsManager(client, false)
	defer m.Close()

	if err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 7)); err != nil {
		t.Fatalf("0x20-randomized question case should still match: %v", err)
	}
}

func TestDnsManagerDropsMismatchedResponse(t *testing.T) {
	client, server := testUDPSocketPair(t)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Msg
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			// First send a response to a *different* question under the same
			// transaction ID; it must be dropped.
			wrong := answerHandler(&req)
			wrong.Question[0].Name = "other.example."
			if data, err := wrong.Pack(); err == nil {
				_, _ = server.WriteToUDP(data, addr)
			}
			if data, err := answerHandler(&req).Pack(); err == nil {
				_, _ = server.WriteToUDP(data, addr)
			}
		}
	}()

	m := NewDnsManager(client, false)
	defer m.Close()
	m.timeout = 2 * time.Second

	msg := testQuery("example.com.", dnsmessage.TypeA, 9)
	if err := m.Resolve(msg); err != nil {
		t.Fatal(err)
	}
	if msg.Question[0].Name != "example.com." {
		t.Errorf("mismatched response was delivered: %v", msg.Question[0].Name)
	}
}

func TestDnsManagerDropsNonResponseAndWrongClass(t *testing.T) {
	client, server := testUDPSocketPair(t)
	go serveUDP(server, func(req *dnsmessage.Msg) *dnsmessage.Msg {
		query := req.Copy()
		if data, err := query.Pack(); err == nil {
			_, _ = server.WriteToUDP(data, client.LocalAddr().(*net.UDPAddr))
		}
		wrongClass := answerHandler(req)
		wrongClass.Question[0].Qclass = dnsmessage.ClassCHAOS
		if data, err := wrongClass.Pack(); err == nil {
			_, _ = server.WriteToUDP(data, client.LocalAddr().(*net.UDPAddr))
		}
		return answerHandler(req)
	})

	m := NewDnsManager(client, false)
	defer m.Close()
	m.timeout = 2 * time.Second

	msg := testQuery("example.com.", dnsmessage.TypeA, 10)
	if err := m.Resolve(msg); err != nil {
		t.Fatal(err)
	}
	if !msg.Response || msg.Question[0].Qclass != dnsmessage.ClassINET {
		t.Fatalf("invalid message was delivered: %+v", msg)
	}
}

func TestDnsManagerAcceptsHeaderOnlyError(t *testing.T) {
	client, server := testUDPSocketPair(t)
	go serveUDP(server, func(req *dnsmessage.Msg) *dnsmessage.Msg {
		return &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{
			Id:       req.Id,
			Response: true,
			Rcode:    dnsmessage.RcodeRefused,
		}}
	})
	m := NewDnsManager(client, false)
	defer m.Close()
	msg := testQuery("example.com.", dnsmessage.TypeA, 11)
	if err := m.Resolve(msg); err != nil {
		t.Fatal(err)
	}
	if msg.Rcode != dnsmessage.RcodeRefused || len(msg.Question) != 1 {
		t.Fatalf("unexpected header-only error response: %+v", msg)
	}
}

func readStreamFrame(r io.Reader) (*dnsmessage.Msg, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	msg := new(dnsmessage.Msg)
	if err := msg.Unpack(buf); err != nil {
		return nil, err
	}
	return msg, nil
}

func TestDnsManagerResolveStreamWritesOnce(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	frames := make(chan *dnsmessage.Msg, 4)
	go func() {
		for {
			req, err := readStreamFrame(serverConn)
			if err != nil {
				close(frames)
				return
			}
			frames <- req
			resp := answerHandler(req)
			data, err := resp.Pack()
			if err != nil {
				continue
			}
			frame := make([]byte, 2+len(data))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(data)))
			copy(frame[2:], data)
			if _, err := serverConn.Write(frame); err != nil {
				return
			}
		}
	}()

	m := NewDnsManager(clientConn, true)
	defer m.Close()
	// Shorter than DefaultDNSRetryInterval: any retransmission would show up
	// as a second frame before the timeout.
	m.timeout = 500 * time.Millisecond

	msg := testQuery("example.com.", dnsmessage.TypeA, 77)
	if err := m.Resolve(msg); err != nil {
		t.Fatal(err)
	}
	if msg.Id != 77 {
		t.Errorf("client transaction ID should be restored: got %v", msg.Id)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("unexpected answer: %v", msg.Answer)
	}

	// Drain the one legitimate query frame, then assert no retransmission
	// shows up before the (shorter than the retry interval) timeout.
	select {
	case <-frames:
	default:
		t.Fatal("the server should have received exactly one frame")
	}
	select {
	case extra := <-frames:
		if extra != nil {
			t.Errorf("stream queries must not be retransmitted; got an extra frame")
		}
	case <-time.After(200 * time.Millisecond):
	}
}

func TestDnsManagerStreamWriteHonorsTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	m := NewDnsManager(clientConn, true)
	m.timeout = 50 * time.Millisecond

	started := time.Now()
	err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 88))
	if err == nil {
		t.Fatal("blocked stream write unexpectedly succeeded")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("blocked stream write should report a timeout, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked stream write ignored query timeout: %v", elapsed)
	}
	if !m.IsClosed() {
		t.Fatal("manager with an interrupted stream frame must be closed")
	}
}

func TestDnsManagerIdleReapingWaitsForPendingQuery(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	m := newDnsManager(clientConn, true, 500*time.Millisecond, 50*time.Millisecond)
	defer m.Close()

	go func() {
		req, err := readStreamFrame(serverConn)
		if err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
		data, err := answerHandler(req).Pack()
		if err != nil {
			return
		}
		frame := make([]byte, 2+len(data))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(data)))
		copy(frame[2:], data)
		_, _ = serverConn.Write(frame)
	}()

	if err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 89)); err != nil {
		t.Fatalf("idle reaper interrupted a pending query: %v", err)
	}
}

func TestDnsManagerIdleReapingSerializesWithAdmission(t *testing.T) {
	for i := 0; i < 100; i++ {
		clientConn, serverConn := net.Pipe()
		m := newDnsManager(clientConn, true, time.Second, time.Hour)

		start := make(chan struct{})
		var admitted bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			admitted = m.beginQuery()
		}()
		go func() {
			defer wg.Done()
			<-start
			m.reapIdle()
		}()
		close(start)
		wg.Wait()

		if admitted {
			if m.IsClosed() {
				t.Fatal("idle reaper closed a newly admitted query")
			}
			m.endQuery()
		}
		_ = m.Close()
		_ = serverConn.Close()
	}
}

func TestDnsManagerSiblingResponseClearsStaleState(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	m := newDnsManager(clientConn, true, time.Second, time.Hour)
	defer m.Close()

	if !m.beginQuery() || !m.beginQuery() {
		t.Fatal("open manager rejected a query")
	}
	m.markStale()
	m.endQuery()
	if m.ctx.Err() != nil {
		t.Fatal("one timed-out query closed a manager with a pending sibling")
	}
	if m.beginQuery() {
		t.Fatal("stale manager admitted a replacement query")
	}
	m.recordResponse()
	m.endQuery()
	if m.IsClosed() {
		t.Fatal("a successful sibling did not clear the manager's stale state")
	}
}

func TestDnsManagerObsoleteIdleCallbackPreservesActivity(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	m := newDnsManager(clientConn, true, time.Second, time.Hour)
	defer m.Close()
	m.idleTimer.Stop()

	m.recordResponse()
	m.reapIdle()
	if m.IsClosed() {
		t.Fatal("obsolete idle callback closed a recently active manager")
	}
}

func TestDnsManagerObsoleteIdleCallbackDoesNotRearmAfterClose(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	m := newDnsManager(clientConn, true, time.Second, time.Hour)
	m.idleTimer.Stop()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	m.recordResponse()
	m.reapIdle()
	if m.idleTimer.Stop() {
		t.Fatal("obsolete idle callback rearmed the timer after Close")
	}
}

func TestDoUDPCloseClosesRetiredManagers(t *testing.T) {
	client1, server1 := net.Pipe()
	defer server1.Close()
	client2, server2 := net.Pipe()
	defer server2.Close()
	retired := newDnsManager(client1, false, time.Second, time.Hour)
	current := newDnsManager(client2, false, time.Second, time.Hour)
	d := &DoUDP{
		dnsManager:  current,
		dnsManagers: map[*DnsManager]struct{}{retired: {}, current: {}},
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if retired.ctx.Err() == nil || current.ctx.Err() == nil {
		t.Fatal("forwarder Close did not close every owned manager")
	}
	if _, err := d.getManager(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed forwarder getManager error = %v, want net.ErrClosed", err)
	}
}

func TestDnsManagerCloseFailsInFlightResolve(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	m := NewDnsManager(clientConn, true)

	errCh := make(chan error, 1)
	go func() {
		msg := testQuery("example.com.", dnsmessage.TypeA, 5)
		errCh <- m.Resolve(msg)
	}()
	// Let Resolve park waiting for a response that will never come.
	time.Sleep(50 * time.Millisecond)
	_ = m.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Errorf("in-flight Resolve should fail after Close")
		}
	case <-time.After(2 * time.Second):
		t.Errorf("in-flight Resolve should be unblocked by Close")
	}
}
