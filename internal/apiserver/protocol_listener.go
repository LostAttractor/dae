// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// protocolListener delivers HTTP connections and concrete *tls.Conn values to
// one http.Server. Classification happens outside Accept, so an idle peer cannot
// hold up other API connections. Pending classification is bounded and canceled
// along with the underlying listener.
type protocolListener struct {
	net.Listener
	tls     *tls.Config
	ready   chan net.Conn
	closed  chan struct{}
	done    chan struct{}
	slots   chan struct{}
	once    sync.Once
	workers sync.WaitGroup
	mu      sync.Mutex
	pending map[net.Conn]struct{}
	err     error
}

func newProtocolListener(listener net.Listener, configuration *tls.Config) *protocolListener {
	l := &protocolListener{Listener: listener, tls: configuration, ready: make(chan net.Conn),
		closed: make(chan struct{}), done: make(chan struct{}), slots: make(chan struct{}, 128), pending: make(map[net.Conn]struct{})}
	go l.run()
	return l
}

func (l *protocolListener) run() {
	defer close(l.done)
	defer l.workers.Wait()
	var retry time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			// Preserve net/http's retry behavior for transient resource failures.
			if temporary, ok := errors.AsType[net.Error](err); ok && temporary.Temporary() {
				retry = min(max(5*time.Millisecond, retry*2), time.Second)
				timer := time.NewTimer(retry)
				select {
				case <-timer.C:
					continue
				case <-l.closed:
					timer.Stop()
					return
				}
			}
			l.stop(err)
			return
		}
		retry = 0
		select {
		case l.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		l.mu.Lock()
		select {
		case <-l.closed:
			l.mu.Unlock()
			_ = conn.Close()
			<-l.slots
			return
		default:
			l.pending[conn] = struct{}{}
		}
		l.mu.Unlock()
		l.workers.Go(func() { l.classify(conn) })
	}
}

func (l *protocolListener) classify(conn net.Conn) {
	defer func() {
		l.mu.Lock()
		delete(l.pending, conn)
		l.mu.Unlock()
		<-l.slots
	}()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var classified net.Conn = &protocolConn{Conn: conn, reader: reader}
	if first[0] == 0x16 { // TLS Handshake record; crypto/tls validates the rest.
		classified = tls.Server(classified, l.tls)
	}
	select {
	case l.ready <- classified:
	case <-l.closed:
		_ = conn.Close()
	}
}

func (l *protocolListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case <-l.closed:
		l.mu.Lock()
		defer l.mu.Unlock()
		return nil, l.err
	}
}

func (l *protocolListener) stop(err error) {
	l.once.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.err = err
		close(l.closed)
		_ = l.Listener.Close()
		for conn := range l.pending {
			_ = conn.Close()
		}
	})
}

func (l *protocolListener) Close() error {
	l.stop(net.ErrClosed)
	<-l.done
	return nil
}

type protocolConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *protocolConn) Read(data []byte) (int, error) { return c.reader.Read(data) }
