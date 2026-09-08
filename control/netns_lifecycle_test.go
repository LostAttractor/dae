package control

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestDaeNetnsCloseWaitsForCallbacksAndReleasesHandles(t *testing.T) {
	host, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netns.Get()
	if err != nil {
		host.Close()
		t.Fatal(err)
	}
	// Both handles reference the existing namespace. No named namespace or
	// network interface is created or removed by this lifecycle test.
	ns := &DaeNetns{hostNs: host, daeNs: peer}
	ns.setupDone.Store(true)
	defer ns.Close()
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	callbackDone := make(chan error, 1)
	go func() {
		_, err := ns.With(func() (struct{}, error) {
			close(started)
			<-release
			return struct{}{}, nil
		})
		callbackDone <- err
	}()
	select {
	case <-started:
	case err := <-callbackDone:
		if errors.Is(err, unix.EPERM) {
			t.Skip("switching network namespaces requires privileges")
		}
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("namespace callback did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- ns.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned while a callback used its namespace: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-callbackDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	for _, fd := range []netns.NsHandle{host, peer} {
		var stat unix.Stat_t
		if err := unix.Fstat(int(fd), &stat); !errors.Is(err, unix.EBADF) {
			t.Fatalf("namespace handle %d was not closed: %v", fd, err)
		}
	}
	if err := ns.Setup(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed namespace accepted setup: %v", err)
	}
}
