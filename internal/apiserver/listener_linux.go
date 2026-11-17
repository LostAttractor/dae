// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/internal/handoff"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Each socket is bound to its ingress interface, rather than merely to a LAN
// address that Linux could also accept through another interface.
type interfaceListener struct {
	active   *InterfaceUpdate
	pending  *InterfaceUpdate
	address  *net.TCPAddr
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	changes  chan struct{}
	retry    *time.Timer
	backoff  time.Duration
	sockets  map[int]*interfaceSocket
}

// InterfaceUpdate reserves additions without accepting from them until Commit.
// The listener owns the active generation; Rollback only releases additions.
type InterfaceUpdate struct {
	listener *interfaceListener
	scope    *network.InterfaceScope
	patterns []string
	binding  string
}

type interfaceSocket struct {
	net.Listener
	serving     bool
	done        chan struct{}
	connections map[*interfaceConn]struct{}
}
type interfaceConn struct {
	net.Conn
	owner  *interfaceListener
	socket *interfaceSocket
}

func (c *interfaceConn) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.socket.connections, c)
	c.owner.mu.Unlock()
	return err
}

// Caller holds mu. Closing the underlying connections avoids reentering mu.
func (s *interfaceSocket) close() {
	close(s.done)
	_ = s.Listener.Close()
	for c := range s.connections {
		_ = c.Conn.Close()
	}
	clear(s.connections)
}

func InterfaceBinding(address string, patterns []string) string {
	patterns = slices.Clone(patterns)
	slices.Sort(patterns)
	return "lan " + address + " " + strings.Join(slices.Compact(patterns), "\x00")
}
func ListenInterfaces(address string, patterns []string, manager *network.InterfaceManager) (*Server, error) {
	server, update, err := PrepareInterfaces(nil, address, patterns, manager)
	if err != nil {
		return nil, err
	}
	update.Commit()
	return server, nil
}

// PrepareInterfaces reuses only the same LAN endpoint. Other binding changes
// must reserve a separate listener successfully before the old one is retired.
func PrepareInterfaces(current *Server, address string, patterns []string, manager *network.InterfaceManager) (*Server, *InterfaceUpdate, error) {
	if len(patterns) == 0 || manager == nil {
		return nil, nil, fmt.Errorf("a port-only api.listen requires global.lan_interface")
	}
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, nil, err
	}
	var listener *interfaceListener
	if current != nil && current.interfaces != nil && current.interfaces.address.String() == addr.String() {
		listener = current.interfaces
	} else {
		listener = newInterfaceListener(addr)
	}
	update, err := listener.prepare(address, patterns, manager)
	if err != nil {
		return nil, nil, err
	}
	if current == nil || current.interfaces != listener {
		current = serveListener(listener, listener, "tcp", nil)
		current.interfaces = listener
		current.binding = update.binding
	}
	return current, update, nil
}

func newInterfaceListener(addr *net.TCPAddr) *interfaceListener {
	return &interfaceListener{changes: make(chan struct{}, 1), address: addr, incoming: make(chan net.Conn), done: make(chan struct{}), sockets: make(map[int]*interfaceSocket)}
}

// InterfaceFiles duplicates the currently bound sockets under the topology lock.
func (s *Server) InterfaceFiles() (map[int]*os.File, error) {
	if s.interfaces == nil {
		return nil, nil
	}
	l := s.interfaces
	l.mu.Lock()
	defer l.mu.Unlock()
	files := make(map[int]*os.File, len(l.sockets))
	for index, sock := range l.sockets {
		file, err := handoff.DupSocket(sock.Listener.(*net.TCPListener), "management")
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, err
		}
		files[index] = file
	}
	return files, nil
}

// RestoreInterfaces keeps reservations idle until the new configuration selects them.
func RestoreInterfaces(address string, files map[int]*os.File) (*Server, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	l := newInterfaceListener(addr)
	for index, file := range files {
		bound, err := unix.GetsockoptInt(int(file.Fd()), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
		if err != nil || bound != index || index <= 0 {
			l.Close()
			return nil, errors.Join(errors.New("inherited API interface differs"), err)
		}
		raw, err := net.FileListener(file)
		if err != nil {
			l.Close()
			return nil, err
		}
		tcp, ok := raw.(*net.TCPListener)
		if !ok || tcp.Addr().(*net.TCPAddr).Port != addr.Port || !tcp.Addr().(*net.TCPAddr).IP.IsUnspecified() {
			raw.Close()
			l.Close()
			return nil, errors.New("inherited LAN API endpoint differs")
		}
		l.sockets[index] = newInterfaceSocket(tcp)
	}
	s := serveListener(l, l, "tcp", nil)
	s.interfaces = l
	return s, nil
}

func (l *interfaceListener) prepare(address string, patterns []string, manager *network.InterfaceManager) (*InterfaceUpdate, error) {
	update := &InterfaceUpdate{listener: l, scope: manager.NewScope(), patterns: slices.Clone(patterns), binding: InterfaceBinding(address, patterns)}
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		_ = update.scope.Close()
		return nil, net.ErrClosed
	default:
	}
	if l.pending != nil {
		l.mu.Unlock()
		_ = update.scope.Close()
		return nil, fmt.Errorf("LAN API listener update already pending")
	}
	l.pending = update
	l.mu.Unlock()
	update.scope.SetChangeCallback(func() {
		if err := update.refresh(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.WithError(err).Error("Could not update LAN API listener")
		}
	})
	for _, pattern := range patterns {
		if err := update.scope.RegisterWithPatternSync(pattern, nil, nil, nil); err != nil {
			update.Rollback()
			return nil, err
		}
	}
	if err := update.refresh(); err != nil {
		update.Rollback()
		return nil, err
	}
	return update, nil
}

func (u *InterfaceUpdate) refresh() error {
	l := u.listener
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		return net.ErrClosed
	default:
	}
	if l.active != u && l.pending != u {
		return nil
	}
	return l.reconcile()
}

// Caller holds mu. Snapshot the union so overlapping patterns and queued rename
// callbacks cannot remove a socket still selected by the active generation.
func (l *interfaceListener) reconcile() error {
	wanted := make(map[int]netlink.Link)
	serving := make(map[int]bool)
	for _, generation := range []*InterfaceUpdate{l.pending, l.active} {
		if generation == nil {
			continue
		}
		for _, link := range generation.scope.MatchingLinks(generation.patterns) {
			index := link.Attrs().Index
			wanted[index] = link
			serving[index] = generation == l.active
		}
	}
	for index, socket := range l.sockets {
		if link := wanted[index]; link == nil || link.Attrs().MasterIndex != 0 || socket.serving && !serving[index] {
			// A pending socket may already be in the candidate datapath snapshot.
			l.notifyChanges()
			socket.close()
			delete(l.sockets, index)
		}
	}
	var result error
	var retry bool
	for index, link := range wanted {
		socket := l.sockets[index]
		if socket == nil {
			var err error
			socket, err = l.listen(link)
			if err != nil {
				result = errors.Join(result, err)
				retry = retry || serving[index] && (errors.Is(err, unix.EADDRINUSE) || errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.ENOMEM))
				continue
			}
			l.sockets[index] = socket
		}
		if serving[index] && !socket.serving {
			socket.serving = true
			l.notifyChanges()
			go l.accept(index, socket)
		}
	}
	if retry && l.retry == nil {
		l.backoff = min(max(100*time.Millisecond, l.backoff*2), 5*time.Second)
		l.retry = time.AfterFunc(l.backoff, func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.retry = nil
			if l.active != nil {
				_ = l.reconcile()
			}
		})
	} else if !retry {
		l.backoff = 0
	}
	return result
}

func (l *interfaceListener) notifyChanges() {
	select {
	case l.changes <- struct{}{}:
	default:
	}
}

func (s *Server) InterfaceChanges() <-chan struct{} {
	if s == nil || s.interfaces == nil {
		return nil
	}
	return s.interfaces.changes
}

// InterfaceIndices selects only sockets actually reserved for the candidate or serving generation.
func (s *Server) InterfaceIndices(candidate *InterfaceUpdate) []uint32 {
	if s == nil || s.interfaces == nil {
		return nil
	}
	l := s.interfaces
	l.mu.Lock()
	defer l.mu.Unlock()
	var indices []uint32
	if candidate != nil {
		for _, link := range candidate.scope.MatchingLinks(candidate.patterns) {
			if index := link.Attrs().Index; l.sockets[index] != nil && link.Attrs().MasterIndex == 0 {
				indices = append(indices, uint32(index))
			}
		}
	} else {
		for index, socket := range l.sockets {
			if socket.serving {
				indices = append(indices, uint32(index))
			}
		}
	}
	return indices
}

func (u *InterfaceUpdate) Commit() {
	if u == nil {
		return
	}
	l := u.listener
	l.mu.Lock()
	if l.pending != u {
		l.mu.Unlock()
		return
	}
	previous := l.active
	l.active, l.pending = u, nil
	// Initial reservations already succeeded; only subsequent hotplug can fail.
	err := l.reconcile()
	l.mu.Unlock()
	if previous != nil {
		_ = previous.scope.Close()
	}
	if err != nil {
		log.WithError(err).Error("Could not update LAN API listener")
	}
}

func (u *InterfaceUpdate) Rollback() {
	if u == nil {
		return
	}
	l := u.listener
	l.mu.Lock()
	if l.pending != u {
		l.mu.Unlock()
		return
	}
	l.pending = nil
	for index, socket := range l.sockets {
		if !socket.serving {
			socket.close()
			delete(l.sockets, index)
		}
	}
	l.mu.Unlock()
	_ = u.scope.Close()
}

func (l *interfaceListener) listen(link netlink.Link) (*interfaceSocket, error) {
	// Local TCP delivery uses the master, whose ingress scope is wider than this port.
	if link.Attrs().MasterIndex != 0 {
		return nil, fmt.Errorf("port-only api.listen cannot bind enslaved interface %s; use an explicit API IP address or select the master as lan_interface", link.Attrs().Name)
	}
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, link.Attrs().Index)
		}); controlErr != nil {
			return controlErr
		}
		return err
	}}
	config.SetMultipathTCP(false)
	listener, err := config.Listen(context.Background(), "tcp", l.address.String())
	if err != nil {
		return nil, fmt.Errorf("API on %s: %w", link.Attrs().Name, err)
	}
	return newInterfaceSocket(listener), nil
}

func newInterfaceSocket(listener net.Listener) *interfaceSocket {
	return &interfaceSocket{Listener: listener, done: make(chan struct{}), connections: make(map[*interfaceConn]struct{})}
}

func (l *interfaceListener) accept(index int, socket *interfaceSocket) {
	var retry time.Duration
	for {
		conn, err := socket.Accept()
		if err != nil {
			switch retryTemporaryAccept(err, &retry, socket.done, l.done) {
			case acceptRetry:
				continue
			case acceptCanceled:
				return
			}
			if !errors.Is(err, net.ErrClosed) {
				log.WithError(err).Error("LAN API accept failed")
			}
			return
		}
		retry = 0
		l.mu.Lock()
		if l.sockets[index] != socket {
			l.mu.Unlock()
			_ = conn.Close()
			return
		}
		tracked := &interfaceConn{Conn: conn, owner: l, socket: socket}
		socket.connections[tracked] = struct{}{}
		l.mu.Unlock()
		select {
		case l.incoming <- tracked:
		case <-socket.done:
			_ = tracked.Close()
			return
		case <-l.done:
			_ = tracked.Close()
			return
		}
	}
}
func (l *interfaceListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn := <-l.incoming:
		return conn, nil
	}
}
func (l *interfaceListener) Addr() net.Addr { return l.address }
func (l *interfaceListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.mu.Lock()
		if l.retry != nil {
			l.retry.Stop()
		}
		active, pending := l.active, l.pending
		l.active, l.pending = nil, nil
		for _, socket := range l.sockets {
			socket.close()
		}
		clear(l.sockets)
		l.mu.Unlock()
		// Scope cancellation joins callbacks that also acquire mu.
		for _, generation := range []*InterfaceUpdate{active, pending} {
			if generation != nil {
				_ = generation.scope.Close()
			}
		}
	})
	return nil
}
