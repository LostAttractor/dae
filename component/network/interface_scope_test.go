// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func scopeTestSource(t *testing.T) *InterfaceManager {
	t.Helper()
	return testInterfaceSource(t, &InterfaceManager{listLinks: func() ([]netlink.Link, error) { return nil, nil }})
}

func TestInterfaceScopesKeepSiblingSubscriptions(t *testing.T) {
	source := scopeTestSource(t)
	first, second := source.NewScope(), source.NewScope()
	t.Cleanup(func() { first.Close(); second.Close() })
	var a, b, resets, changes atomic.Int32
	if err := first.RegisterWithPatternSync("test*", nil, func(netlink.Link) { a.Add(1) }, nil); err != nil {
		t.Fatal(err)
	}
	if err := second.RegisterSync("test0", nil, func(netlink.Link) { b.Add(1) }, nil); err != nil {
		t.Fatal(err)
	}
	first.SetChangeCallback(func() { a.Add(100) })
	second.SetChangeCallback(func() { changes.Add(1) })
	second.SetResetCallback(func() { resets.Add(1) })
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 7, Name: "test0"}}
	source.handleLinkUpdate(netlink.LinkUpdate{Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK}, Link: link})
	source.replaceLinks([]netlink.Link{link})
	if a.Load() != 0 || b.Load() != 2 || changes.Load() != 2 || resets.Load() != 1 {
		t.Fatalf("scope isolation failed: first=%d second=%d change=%d reset=%d", a.Load(), b.Load(), changes.Load(), resets.Load())
	}
	if second.NameByIndex(7) != "test0" || source.isStopped() {
		t.Fatal("scope lost shared source")
	}
	if err := first.RegisterSync("test0", nil, nil, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed scope registered: %v", err)
	}
	second.Close()
	if len(source.callbacks) != 0 || len(source.scopes) != 0 {
		t.Fatal("retired scope retained callbacks")
	}
}

func TestInterfaceScopeCloseJoinsInitialRegistration(t *testing.T) {
	source := scopeTestSource(t)
	source.listLinks = func() ([]netlink.Link, error) {
		return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "test0", Index: 1}}}, nil
	}
	scope := source.NewScope()
	started, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	registered := make(chan error, 1)
	go func() {
		registered <- scope.RegisterSync("test0", func(netlink.Link) error { close(started); <-release; return nil }, nil, nil)
	}()
	<-started
	closed := make(chan struct{})
	go func() { scope.Close(); close(closed) }()
	<-scope.stop
	select {
	case <-closed:
		t.Fatal("scope closed before its initial callback finished")
	case <-time.After(10 * time.Millisecond):
	}
	unblock()
	if err := <-registered; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("registration outlived scope: %v", err)
	}
	<-closed
	if len(source.callbacks) != 0 {
		t.Fatal("in-flight registration leaked")
	}
}

func TestInterfaceScopeRejectsFailedRegistration(t *testing.T) {
	source := scopeTestSource(t)
	source.listLinks = func() ([]netlink.Link, error) { return nil, errors.New("temporary dump failure") }
	scope := source.NewScope()
	if err := scope.RegisterWithPatternSync("test*", nil, nil, nil); err == nil {
		t.Fatal("missing initial dump error")
	}
	scope.Close()
	if len(source.callbacks) != 0 {
		t.Fatal("failed initial dump leaked a registration")
	}
}
