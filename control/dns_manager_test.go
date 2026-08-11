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
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

type singleWriterConn struct {
	net.Conn
	active     atomic.Int32
	concurrent atomic.Bool
}

func (c *singleWriterConn) Write(p []byte) (int, error) {
	if c.active.Add(1) != 1 {
		c.concurrent.Store(true)
	}
	defer c.active.Add(-1)
	time.Sleep(5 * time.Millisecond)
	return c.Conn.Write(p)
}

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

func TestDnsManagerConcurrentQueriesShareOneConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	var mu sync.Mutex
	wireIds := map[uint16]bool{}
	go func() {
		for i := 0; i < 2; i++ {
			req, err := readStreamFrame(server)
			if err != nil {
				return
			}
			mu.Lock()
			wireIds[req.Id] = true
			mu.Unlock()
			if err := writeStreamFrame(server, answerHandler(req)); err != nil {
				return
			}
		}
	}()

	trackedClient := &singleWriterConn{Conn: client}
	m := NewDnsManager(trackedClient)
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
	if trackedClient.concurrent.Load() {
		t.Error("manager wrote concurrent DNS frames to one connection")
	}
}

func TestDnsManagerWireIdsAreNotSequential(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	wireIds := make(chan uint16, 16)
	go func() {
		for i := 0; i < cap(wireIds); i++ {
			req, err := readStreamFrame(server)
			if err != nil {
				return
			}
			wireIds <- req.Id
			if err := writeStreamFrame(server, answerHandler(req)); err != nil {
				return
			}
		}
	}()
	m := NewDnsManager(client)
	defer m.Close()

	for i := 0; i < cap(wireIds); i++ {
		if err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, uint16(i))); err != nil {
			t.Fatal(err)
		}
	}
	previous := <-wireIds
	allSequential := true
	for i := 1; i < cap(wireIds); i++ {
		current := <-wireIds
		if current != previous+1 {
			allSequential = false
		}
		previous = current
	}
	if allSequential {
		t.Fatal("DNS transaction IDs followed a predictable incrementing sequence")
	}
}

func TestDnsManagerTimeoutIsTimeoutError(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { _, _ = readStreamFrame(server) }()

	m := NewDnsManager(client)
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

func TestDnsManagerCaseInsensitiveQuestionMatch(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		req, err := readStreamFrame(server)
		if err != nil {
			return
		}
		resp := answerHandler(req)
		// Some upstreams echo the question with randomized case.
		resp.Question[0].Name = strings.ToUpper(resp.Question[0].Name)
		_ = writeStreamFrame(server, resp)
	}()

	m := NewDnsManager(client)
	defer m.Close()

	if err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 7)); err != nil {
		t.Fatalf("0x20-randomized question case should still match: %v", err)
	}
}

func TestDnsManagerDropsMismatchedResponse(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		req, err := readStreamFrame(server)
		if err != nil {
			return
		}
		wrong := answerHandler(req)
		wrong.Question[0].Name = "other.example."
		_ = writeStreamFrame(server, wrong)
		_ = writeStreamFrame(server, answerHandler(req))
	}()

	m := NewDnsManager(client)
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
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		req, err := readStreamFrame(server)
		if err != nil {
			return
		}
		query := req.Copy()
		_ = writeStreamFrame(server, query)
		wrongClass := answerHandler(req)
		wrongClass.Question[0].Qclass = dnsmessage.ClassCHAOS
		_ = writeStreamFrame(server, wrongClass)
		_ = writeStreamFrame(server, answerHandler(req))
	}()

	m := NewDnsManager(client)
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
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		req, err := readStreamFrame(server)
		if err != nil {
			return
		}
		response := &dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{
			Id:       req.Id,
			Response: true,
			Rcode:    dnsmessage.RcodeRefused,
		}}
		payload, err := response.Pack()
		if err != nil {
			return
		}
		frame := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
		copy(frame[2:], payload)
		_, _ = server.Write(frame)
	}()
	m := NewDnsManager(client)
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

func writeStreamFrame(w io.Writer, msg *dnsmessage.Msg) error {
	payload, err := msg.Pack()
	if err != nil {
		return err
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	_, err = w.Write(frame)
	return err
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

	m := NewDnsManager(clientConn)
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

	m := NewDnsManager(clientConn)
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
	m := newDnsManager(clientConn, 500*time.Millisecond, 50*time.Millisecond)
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
		m := newDnsManager(clientConn, time.Second, time.Hour)

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

func TestDnsManagerRetiredStateIsMonotonic(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	m := newDnsManager(clientConn, time.Second, time.Hour)
	defer m.Close()

	if !m.beginQuery() {
		t.Fatal("open manager rejected a query")
	}
	m.retire()
	m.recordResponse()
	if !m.IsClosed() {
		t.Fatal("sibling response revived a retired manager")
	}
	if m.beginQuery() {
		t.Fatal("retired manager admitted a new query")
	}
	m.endQuery()
}

func TestDnsManagerRetireBlocksNewIdReservations(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	m := newDnsManager(client, time.Second, time.Hour)
	defer m.Close()

	first := &dnsPendingQuery{
		ch:    make(chan *dnsmessage.Msg, 1),
		query: testQuery("example.com.", dnsmessage.TypeA, 1),
	}
	wireId, err := m.reserveQuery(first, 7)
	if err != nil {
		t.Fatal(err)
	}
	m.retire()
	m.recvMap.Delete(wireId)
	second := &dnsPendingQuery{
		ch:    make(chan *dnsmessage.Msg, 1),
		query: testQuery("example.com.", dnsmessage.TypeA, 2),
	}
	if _, err := m.reserveQuery(second, wireId); !errors.Is(err, errDnsManagerUnavailable) {
		t.Fatalf("reservation after retire error = %v, want errDnsManagerUnavailable", err)
	}
	m.endQuery()
}

func TestDnsManagerParentCancellationRetiresConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	written := make(chan struct{})
	go func() {
		_, _ = readStreamFrame(server)
		close(written)
	}()
	m := NewDnsManager(client)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.ResolveContext(ctx, testQuery("example.com.", dnsmessage.TypeA, 12)) }()
	<-written
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveContext error = %v, want context.Canceled", err)
	}
	if !m.IsClosed() {
		t.Fatal("caller cancellation did not retire a sent exchange")
	}
}

func TestDnsManagerParentDeadlineRetiresSilentConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { _, _ = readStreamFrame(server) }()
	m := NewDnsManager(client)
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := m.ResolveContext(ctx, testQuery("example.com.", dnsmessage.TypeA, 14))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveContext error = %v, want context.DeadlineExceeded", err)
	}
	if !m.IsClosed() {
		t.Fatal("deadline did not retire a silent manager")
	}
}

func TestDnsManagerPreCanceledContextDoesNotWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	m := NewDnsManager(client)
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.ResolveContext(ctx, testQuery("example.com.", dnsmessage.TypeA, 13)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveContext error = %v, want context.Canceled", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("pre-canceled query wrote to the connection")
	}
}

func TestDnsManagerCloseBeforeWriteIsUnavailable(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	m := NewDnsManager(client)
	m.writeMu.Lock()

	query := testQuery("example.com.", dnsmessage.TypeSOA, 1)
	query.Opcode = dnsmessage.OpcodeNotify
	result := make(chan error, 1)
	go func() { result <- m.Resolve(query) }()
	deadline := time.Now().Add(time.Second)
	for {
		m.stateMu.Lock()
		pending := m.pending
		m.stateMu.Unlock()
		if pending != 0 {
			break
		}
		if time.Now().After(deadline) {
			m.writeMu.Unlock()
			t.Fatal("query was not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	m.startClose()
	m.writeMu.Unlock()

	if err := <-result; !errors.Is(err, errDnsManagerUnavailable) {
		t.Fatalf("unsent NOTIFY returned %v, want manager unavailable", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.waitClosed(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDnsManagerObsoleteIdleCallbackPreservesActivity(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	m := newDnsManager(clientConn, time.Second, time.Hour)
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
	m := newDnsManager(clientConn, time.Second, time.Hour)
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

func TestShouldRetryDnsManager(t *testing.T) {
	query := testQuery("example.com.", dnsmessage.TypeA, 1)
	update := query.Copy()
	update.Opcode = dnsmessage.OpcodeUpdate
	tests := []struct {
		name string
		err  error
		msg  *dnsmessage.Msg
		want bool
	}{
		{name: "unavailable query", err: errDnsManagerUnavailable, msg: query, want: true},
		{name: "unavailable update", err: errDnsManagerUnavailable, msg: update, want: true},
		{name: "interrupted query", err: errDnsExchangeInterrupted, msg: query, want: true},
		{name: "interrupted update", err: errDnsExchangeInterrupted, msg: update, want: false},
		{name: "unclassified closed", err: net.ErrClosed, msg: query, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRetryDnsManager(tt.err, tt.msg); got != tt.want {
				t.Fatalf("shouldRetryDnsManager() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDnsManagerCloseFailsInFlightResolve(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	m := NewDnsManager(clientConn)

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

type dnsWriteErrorConn struct {
	net.Conn
	err error
}

type dnsCloseErrorConn struct {
	net.Conn
	err error
}

func (c *dnsCloseErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

func (c *dnsWriteErrorConn) Write([]byte) (int, error) { return 0, c.err }

type blockingDNSWriteConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockingDNSCloseConn struct {
	net.Conn
	closeStarted chan struct{}
	closeRelease chan struct{}
	once         sync.Once
}

func (c *blockingDNSCloseConn) Close() error {
	c.once.Do(func() { close(c.closeStarted) })
	<-c.closeRelease
	return c.Conn.Close()
}

func (c *blockingDNSWriteConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return 0, net.ErrClosed
}

func TestDnsManagerReturnsTerminalWriteError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	wantErr := errors.New("upstream write failed")
	m := NewDnsManager(&dnsWriteErrorConn{Conn: clientConn, err: wantErr})
	defer m.Close()

	err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 5))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve returned %v, want terminal write error %v", err, wantErr)
	}
	if !m.canReplace() {
		t.Fatal("manager was not immediately replaceable after its write returned")
	}
}

func TestDnsManagerCloseReturnsTransportError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	wantErr := errors.New("transport close failed")
	m := NewDnsManager(&dnsCloseErrorConn{Conn: clientConn, err: wantErr})
	if err := m.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close returned %v, want %v", err, wantErr)
	}
}

func TestDnsManagerDoesNotReplaceWhileStreamWriteIsStuck(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	conn := &blockingDNSWriteConn{
		Conn: clientConn, started: make(chan struct{}), release: make(chan struct{}),
	}
	m := NewDnsManager(conn)
	m.timeout = 20 * time.Millisecond
	err := m.Resolve(testQuery("example.com.", dnsmessage.TypeA, 5))
	if err == nil {
		t.Fatal("stuck stream write unexpectedly succeeded")
	}
	<-conn.started
	if m.canReplace() {
		t.Fatal("closed manager became replaceable while its transport write was still blocked")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- m.Close() }()
	select {
	case err := <-closeResult:
		t.Fatalf("Close returned while the transport write was still blocked: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(conn.release)
	deadline := time.Now().Add(time.Second)
	for !m.canReplace() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !m.canReplace() {
		t.Fatal("manager did not become replaceable after the blocked write exited")
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
}

func TestDnsManagerCanceledCanReplaceWhileTransportCloseIsStuck(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	conn := &blockingDNSCloseConn{
		Conn: clientConn, closeStarted: make(chan struct{}), closeRelease: make(chan struct{}),
	}
	m := NewDnsManager(conn)
	closeResult := make(chan error, 1)
	go func() { closeResult <- m.Close() }()
	<-conn.closeStarted
	if !m.canReplace() {
		t.Fatal("canceled manager remained unavailable while transport close was blocked")
	}
	close(conn.closeRelease)
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
}

func TestDnsManagerIdleRetirementCanReplaceWhileTransportCloseIsStuck(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	conn := &blockingDNSCloseConn{
		Conn: clientConn, closeStarted: make(chan struct{}), closeRelease: make(chan struct{}),
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(conn.closeRelease) })
	m := NewDnsManager(conn)
	m.idleTimeout = 20 * time.Millisecond
	m.resetIdleTimer()

	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("idle manager did not start closing its transport")
	}
	if !m.IsClosed() {
		t.Fatal("idle manager was not retired")
	}
	if !m.canReplace() {
		t.Fatal("idle manager remained unavailable while transport close was blocked")
	}
	releaseOnce.Do(func() { close(conn.closeRelease) })
	<-m.closeDone
	<-m.runDone
}
