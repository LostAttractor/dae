// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/component/network"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type acceptFuncListener struct {
	net.Listener
	accept func() (net.Conn, error)
}

func (l acceptFuncListener) Accept() (net.Conn, error) { return l.accept() }

func TestLANListenerRecoversFromTemporaryAcceptErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts []time.Time
		var peers []net.Conn
		socket := &interfaceSocket{connections: make(map[*interfaceConn]struct{})}
		socket.Listener = acceptFuncListener{accept: func() (net.Conn, error) {
			attempts = append(attempts, time.Now())
			switch len(attempts) {
			case 11, 13:
				conn, peer := net.Pipe()
				peers = append(peers, peer)
				return conn, nil
			case 14:
				return nil, net.ErrClosed
			default:
				err := []error{syscall.EMFILE, syscall.ENFILE, os.ErrDeadlineExceeded}[(len(attempts)-1)%3]
				return nil, &net.OpError{Op: "accept", Net: "tcp", Err: err}
			}
		}}
		listener := &interfaceListener{incoming: make(chan net.Conn), done: make(chan struct{}), sockets: map[int]*interfaceSocket{1: socket}}
		finished := make(chan struct{})
		go func() { listener.accept(1, socket); close(finished) }()
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
		}
		<-finished
		for _, peer := range peers {
			peer.Close()
		}
		for i := 1; i <= 10; i++ {
			if delay := attempts[i].Sub(attempts[i-1]); delay <= 0 || delay > time.Second {
				t.Fatalf("retry %d delay = %v", i, delay)
			}
		}
		if attempts[10].Sub(attempts[9]) != time.Second || attempts[12].Sub(attempts[11]) != 5*time.Millisecond {
			t.Fatal("backoff did not cap or reset after a successful accept")
		}
	})
}

func TestLANListenerCloseInterruptsAcceptBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		socket := &interfaceSocket{Listener: acceptFuncListener{accept: func() (net.Conn, error) {
			return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
		}}}
		listener := &interfaceListener{done: make(chan struct{})}
		finished := make(chan struct{})
		go func() { listener.accept(1, socket); close(finished) }()
		synctest.Wait()
		start := time.Now()
		close(listener.done)
		<-finished
		if time.Since(start) != 0 {
			t.Fatal("shutdown waited for the backoff timer")
		}
	})
}

func TestLANListenerBindsInterfaceAndRetiresItsConnections(t *testing.T) {
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	listener := &interfaceListener{address: &net.TCPAddr{}, incoming: make(chan net.Conn), done: make(chan struct{}), sockets: make(map[int]*interfaceSocket)}
	defer listener.Close()
	update, err := listener.prepare(":0", []string{"lo"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	update.Commit()
	socket := listener.sockets[link.Attrs().Index]
	raw, err := socket.Listener.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var index int
	if err := raw.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX) }); err != nil {
		t.Fatal(err)
	}
	if err != nil || index != link.Attrs().Index {
		t.Fatalf("socket interface: %d %v", index, err)
	}
	peer, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socket.Addr().(*net.TCPAddr).Port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	update, err = listener.prepare(":0", []string{"dae-test-absent-*"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	update.Commit()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err = peer.Read(make([]byte, 1))
	if timeout, ok := errors.AsType[net.Error](err); err == nil || ok && timeout.Timeout() {
		t.Fatalf("removed interface kept its connection: %v", err)
	}
	update, err = listener.prepare(":0", []string{"lo"}, manager)
	if err != nil {
		t.Fatal("interface could not return:", err)
	}
	update.Commit()
}

func TestLANListenerNeverFallsBackToAllInterfaces(t *testing.T) {
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	address := fmt.Sprintf(":%d", occupied.Addr().(*net.TCPAddr).Port)
	// A wildcard fallback would fail because this port is already reserved.
	server, err := ListenInterfaces(address, []string{"dae-test-absent-*"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if _, err := ListenInterfaces(address, nil, manager); err == nil {
		t.Fatal("LAN binding accepted no interfaces")
	}
}

func TestLANListenerPreparedSocketsWaitForCommit(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint("commit=", commit), func(t *testing.T) {
			manager, err := network.NewInterfaceManager()
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			listener := &interfaceListener{address: &net.TCPAddr{}, incoming: make(chan net.Conn), done: make(chan struct{}), sockets: make(map[int]*interfaceSocket)}
			defer listener.Close()
			update, err := listener.prepare(":0", []string{"lo"}, manager)
			if err != nil {
				t.Fatal(err)
			}
			defer update.Rollback()
			link, err := netlink.LinkByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			listener.mu.Lock()
			socket := listener.sockets[link.Attrs().Index]
			serving := socket.serving
			listener.mu.Unlock()
			if serving {
				t.Fatal("prepared socket started accepting")
			}
			peer, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socket.Addr().(*net.TCPAddr).Port), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			accepted := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					_, err = conn.Write([]byte("ready"))
					conn.Close()
				}
				accepted <- err
			}()
			peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			buffer := make([]byte, len("ready"))
			if _, err := peer.Read(buffer); err == nil {
				t.Fatal("candidate delivered a connection before commit")
			} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
				t.Fatalf("prepared socket closed early: %v", err)
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			if commit {
				update.Commit()
				if _, err := io.ReadFull(peer, buffer); err != nil || string(buffer) != "ready" {
					t.Fatalf("committed socket did not deliver: %q, %v", buffer, err)
				}
				if err := <-accepted; err != nil {
					t.Fatal(err)
				}
			} else {
				update.Rollback()
				if _, err := peer.Read(buffer); err == nil {
					t.Fatal("rolled-back socket delivered a connection")
				} else if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
					t.Fatal("rollback kept its reserved socket")
				}
				listener.Close()
				if err := <-accepted; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("rollback delivered to Accept: %v", err)
				}
			}
		})
	}
}

func testAPIDummy(t *testing.T, name string) netlink.Link {
	t.Helper()
	link := &netlink.Dummy{Name: name}
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("requires CAP_NET_ADMIN in an isolated network namespace")
		}
		t.Fatal(err)
	}
	created, err := netlink.LinkByName(name)
	if err != nil {
		_ = netlink.LinkDel(link)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(created) })
	return created
}

func TestLANListenerReloadPreservesOverlapAndRollsBackAdditions(t *testing.T) {
	added := testAPIDummy(t, "dae-api-added")
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	reservation, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	address := fmt.Sprintf(":%d", reservation.Addr().(*net.TCPAddr).Port)
	reservation.Close()
	server, err := ListenInterfaces(address, []string{"lo"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "active") }))
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	listener := server.interfaces
	listener.mu.Lock()
	original := listener.sockets[loopback.Attrs().Index]
	listener.mu.Unlock()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	check := func() {
		t.Helper()
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", original.Addr().(*net.TCPAddr).Port))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "active" {
			t.Fatalf("active listener changed: %q, %v", body, err)
		}
	}
	binding := server.Binding()
	for _, commit := range []bool{false, true} {
		next, update, err := PrepareInterfaces(server, address, []string{"l*", added.Attrs().Name}, manager)
		if err != nil {
			t.Fatal(err)
		}
		if next != server || server.Binding() != binding {
			t.Fatal("prepare replaced the server or published the binding")
		}
		listener.mu.Lock()
		kept, candidate := listener.sockets[loopback.Attrs().Index], listener.sockets[added.Attrs().Index]
		serving := candidate.serving
		listener.mu.Unlock()
		if kept != original || serving {
			t.Fatal("prepare replaced overlap or activated an addition")
		}
		check()
		if commit {
			update.Commit()
			if server.Binding() != InterfaceBinding(address, []string{"l*", added.Attrs().Name}) {
				t.Fatal("commit did not publish binding")
			}
		} else {
			update.Rollback()
			select {
			case <-candidate.done:
			default:
				t.Fatal("rollback kept the addition")
			}
			if server.Binding() != binding {
				t.Fatal("rollback changed binding")
			}
		}
		check()
		listener.mu.Lock()
		kept = listener.sockets[loopback.Attrs().Index]
		listener.mu.Unlock()
		if kept != original {
			t.Fatal("transaction replaced overlap")
		}
	}
	// A failure after reserving another interface must clean up that reservation.
	failed := testAPIDummy(t, "dae-api-failed")
	binding = server.Binding()
	if _, _, err := PrepareInterfaces(server, address, []string{failed.Attrs().Name, "["}, manager); err == nil {
		t.Fatal("invalid pattern accepted")
	}
	listener.mu.Lock()
	pending, leaked := listener.pending, listener.sockets[failed.Attrs().Index]
	listener.mu.Unlock()
	if pending != nil || leaked != nil || server.Binding() != binding {
		t.Fatal("failed preparation leaked candidate state")
	}
	check()
	occupied, err := listener.listen(failed)
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.close()
	if _, _, err := PrepareInterfaces(server, address, []string{"lo", failed.Attrs().Name}, manager); err == nil {
		t.Fatal("occupied added interface accepted")
	}
	listener.mu.Lock()
	pending, leaked = listener.pending, listener.sockets[failed.Attrs().Index]
	kept := listener.sockets[loopback.Attrs().Index]
	listener.mu.Unlock()
	if pending != nil || leaked != nil || kept != original || server.Binding() != binding {
		t.Fatal("bind failure changed the active listener")
	}
	check()
}

func TestLANListenerHotplugUsesCommittedPatterns(t *testing.T) {
	link := testAPIDummy(t, "dae-api-before")
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server, err := ListenInterfaces(":0", []string{"dae-api-*", "dae-api-before"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_, update, err := PrepareInterfaces(server, ":0", []string{"dae-api-after"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	update.Commit()
	waitSocket := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			server.interfaces.mu.Lock()
			exists := server.interfaces.sockets[link.Attrs().Index] != nil
			server.interfaces.mu.Unlock()
			if exists == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("socket presence = %v, want %v", exists, want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitSocket(false)
	if err := netlink.LinkSetName(link, "dae-api-after"); err != nil {
		t.Fatal(err)
	}
	waitSocket(true)
	if err := netlink.LinkSetName(link, "dae-api-before"); err != nil {
		t.Fatal(err)
	}
	waitSocket(false)
	if err := netlink.LinkSetName(link, "dae-api-after"); err != nil {
		t.Fatal(err)
	}
	waitSocket(true)
	if err := netlink.LinkDel(link); err != nil {
		t.Fatal(err)
	}
	waitSocket(false)
}

func TestLANListenerCloseJoinsCallbacksWithoutHoldingLock(t *testing.T) {
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	server, err := ListenInterfaces(":0", []string{"dae-test-absent-*"}, manager)
	if err != nil {
		t.Fatal(err)
	}
	listener := server.interfaces
	entered, release, registered := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		registered <- listener.active.scope.RegisterWithPatternSync("lo", func(netlink.Link) error {
			close(entered)
			<-release
			listener.mu.Lock()
			listener.mu.Unlock()
			return nil
		}, nil, nil)
	}()
	<-entered
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	<-listener.done
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked while joining an interface callback")
	}
	if err := <-registered; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
