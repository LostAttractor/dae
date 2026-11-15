// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/common/consts"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func deviceTestPlane(t *testing.T, rules []string, overrides map[[6]byte]bool) *ControlPlane {
	t.Helper()
	matcher, err := clientmatch.Parse(rules)
	if err != nil {
		t.Fatal(err)
	}
	host, err := mitm.New(mitm.Options{Authority: new(localca.Authority)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return &ControlPlane{planeHTTP: planeHTTP{mitmEnabled: true, mitmHost: host, httpClients: httpClientAdmission{policy: matcher.Compile(overrides)}}}
}

func deviceTestRuntime(plane *ControlPlane, neighbors []netlink.Neigh) *Runtime {
	r := &Runtime{current: plane}
	r.kernelLinks.hostTCXLinks = []hostTCXLink{{linkIndex: 1, role: hostTCXLanIngress}, {linkIndex: 9, role: hostTCXWanIngress}}
	r.clientNetlink = &clientNetlink{
		links: func() ([]netlink.Link, error) {
			return []netlink.Link{
				&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "lan", MasterIndex: 2}},
				&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "bridge"}},
				&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 9, Name: "wan"}},
			}, nil
		},
		routes: func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
			return []netlink.Route{{Type: unix.RTN_UNICAST, LinkIndex: 2}}, nil
		},
		neighbors: func(index, family int) ([]netlink.Neigh, error) {
			if index == 2 {
				return neighbors, nil
			}
			return nil, nil
		},
		neighbor: func(_ context.Context, index int, source netip.Addr) (*netlink.Neigh, error) {
			for i := range neighbors {
				if neighbors[i].LinkIndex == index && neighbors[i].IP.Equal(source.AsSlice()) {
					return &neighbors[i], nil
				}
			}
			return nil, unix.ENOENT
		},
	}
	return r
}

func deviceTestNeighbor(ip string, mac [6]byte) netlink.Neigh {
	return netlink.Neigh{LinkIndex: 2, IP: net.ParseIP(ip), HardwareAddr: net.HardwareAddr(mac[:]), State: netlink.NUD_STALE}
}

func TestDeviceServiceMITMTargets(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	other := [6]byte{2, 0, 0, 0, 0, 2}
	v4, v6 := deviceTestNeighbor("192.0.2.10", mac), deviceTestNeighbor("2001:db8::10", mac)
	for _, tc := range []struct {
		name      string
		rules     []string
		overrides map[[6]byte]bool
		neighbors []netlink.Neigh
		want      [][6]byte
	}{
		{"offline true override", nil, map[[6]byte]bool{mac: true}, nil, [][6]byte{mac}},
		{"false override", []string{"all"}, map[[6]byte]bool{mac: false}, []netlink.Neigh{v4, v6}, nil},
		{"all discovers LAN", []string{"all"}, nil, []netlink.Neigh{v4}, [][6]byte{mac}},
		{"all cannot invent devices", []string{"all"}, nil, nil, nil},
		{"multiple addresses deduplicate", []string{"all"}, nil, []netlink.Neigh{v4, v6, v4}, [][6]byte{mac}},
		{"one admitted address is sufficient", []string{"-192.0.2.0/24", "all"}, nil, []netlink.Neigh{v4, v6}, [][6]byte{mac}},
		{"MAC exclusion precedes IP", []string{"-02:00:00:00:00:01", "192.0.2.0/24", "all"}, nil, []netlink.Neigh{v4}, nil},
		{"IP exclusion precedes MAC", []string{"-192.0.2.0/24", "02:00:00:00:00:01"}, nil, []netlink.Neigh{v4}, nil},
		{"MAC precedes IP exclusion", []string{"02:00:00:00:00:01", "-192.0.2.0/24"}, nil, []netlink.Neigh{v4}, [][6]byte{mac}},
		{"IP precedes MAC exclusion", []string{"192.0.2.0/24", "-02:00:00:00:00:01"}, nil, []netlink.Neigh{v4}, [][6]byte{mac}},
		{"offline static MAC", []string{"02:00:00:00:00:01"}, nil, nil, [][6]byte{mac}},
		{"offline IP exclusion unknown", []string{"-192.0.2.0/24", "02:00:00:00:00:01", "all"}, nil, nil, nil},
		{"offline override survives IP exclusion", []string{"-192.0.2.0/24", "all"}, map[[6]byte]bool{mac: true}, nil, [][6]byte{mac}},
		{"stable order", []string{"all"}, nil, []netlink.Neigh{deviceTestNeighbor("192.0.2.11", other), v4}, [][6]byte{mac, other}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := deviceTestRuntime(deviceTestPlane(t, tc.rules, tc.overrides), tc.neighbors)
			got, err := r.MITMEnabled(t.Context())
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("MITMEnabled = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestDeviceServiceConfiguredRoutingCandidates(t *testing.T) {
	mac, member := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	_, matcher := buildClientMatcher(t, clientRule("known", false, "direct"), &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{Name: consts.Function_Mac, Params: []*config_parser.Param{{Val: "02:00:00:00:00:01"}}}},
		Outbound:     config_parser.Function{Name: "direct"},
	})
	if err := matcher.SetClientMembers("known", [][6]byte{member}, false); err != nil {
		t.Fatal(err)
	}
	plane := deviceTestPlane(t, []string{"all"}, nil)
	plane.routingState = matcher.routingState
	r := deviceTestRuntime(plane, nil)
	got, err := r.MITMEnabled(t.Context())
	if err != nil || !slices.Equal(got, [][6]byte{mac, member}) {
		t.Fatalf("routing candidates = %v, %v", got, err)
	}
	if err := matcher.SetClientMembers("known", nil, false); err != nil {
		t.Fatal(err)
	}
	got, err = r.MITMEnabled(t.Context())
	if err != nil || !slices.Equal(got, [][6]byte{mac}) {
		t.Fatalf("removed member remains = %v, %v", got, err)
	}
	blocked, _ := clientmatch.Parse([]string{"-192.0.2.0/24", "all"})
	plane.httpClients.policy = blocked.Compile(nil)
	got, err = r.MITMEnabled(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("unknown IP bypassed exclusion = %v, %v", got, err)
	}
}

func TestDeviceServiceFiltersNeighborStateAndTopology(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, state := range []int{netlink.NUD_NONE, netlink.NUD_FAILED, netlink.NUD_INCOMPLETE} {
		neighbor := deviceTestNeighbor("192.0.2.10", mac)
		neighbor.State = state
		r := deviceTestRuntime(deviceTestPlane(t, []string{"all"}, nil), []netlink.Neigh{neighbor})
		got, err := r.MITMEnabled(t.Context())
		if err != nil || len(got) != 0 {
			t.Fatalf("unresolved neighbor = %v, %v", got, err)
		}
	}
	proxy := deviceTestNeighbor("192.0.2.10", mac)
	proxy.Flags = netlink.NTF_PROXY
	r := deviceTestRuntime(deviceTestPlane(t, []string{"all"}, nil), []netlink.Neigh{proxy})
	original := r.clientNetlink.neighbors
	r.clientNetlink.neighbors = func(index, family int) ([]netlink.Neigh, error) {
		if index == 9 {
			t.Fatal("queried WAN neighbors")
		}
		return original(index, family)
	}
	got, err := r.MITMEnabled(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("proxy neighbor = %v, %v", got, err)
	}
}

func TestDeviceServiceCurrentPolicyAndAvailability(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	plane := deviceTestPlane(t, nil, map[[6]byte]bool{mac: true})
	r := deviceTestRuntime(plane, nil)
	var provider plugin.DeviceService = r
	got, err := provider.MITMEnabled(t.Context())
	if err != nil || !slices.Equal(got, [][6]byte{mac}) {
		t.Fatalf("initial = %v, %v", got, err)
	}
	plane.mitmEnabled = false
	got, err = provider.MITMEnabled(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("global disabled = %v, %v", got, err)
	}
	plane.mitmEnabled = true
	plane.mitmHost = nil
	got, err = provider.MITMEnabled(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("authority unavailable = %v, %v", got, err)
	}
	r.current = deviceTestPlane(t, nil, map[[6]byte]bool{mac: false})
	got, err = provider.MITMEnabled(t.Context())
	if err != nil || len(got) != 0 {
		t.Fatalf("reload retained old plane = %v, %v", got, err)
	}
	matcher, _ := clientmatch.Parse(nil)
	r.current.httpClients.policy = matcher.Compile(map[[6]byte]bool{mac: true})
	got, err = provider.MITMEnabled(t.Context())
	if err != nil || !slices.Equal(got, [][6]byte{mac}) {
		t.Fatalf("published override = %v, %v", got, err)
	}
	r.current = nil
	if _, err := provider.MITMEnabled(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed = %v", err)
	}
}

func TestDeviceServiceErrorsAndRetirement(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	plane := deviceTestPlane(t, nil, map[[6]byte]bool{mac: true})
	for _, links := range []bool{true, false} {
		r := deviceTestRuntime(plane, nil)
		failure := errors.New("netlink unavailable")
		if links {
			r.clientNetlink.links = func() ([]netlink.Link, error) { return nil, failure }
		} else {
			r.clientNetlink.neighbors = func(int, int) ([]netlink.Neigh, error) { return nil, failure }
		}
		if got, err := r.MITMEnabled(t.Context()); got != nil || !errors.Is(err, failure) {
			t.Fatalf("query failure = %v, %v", got, err)
		}
	}
	r := deviceTestRuntime(plane, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.MITMEnabled(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %v", err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	r.clientNetlink.neighbors = func(int, int) ([]netlink.Neigh, error) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		return nil, nil
	}
	go func() { _, err := r.MITMEnabled(t.Context()); done <- err }()
	<-entered
	if !r.mu.TryLock() {
		close(release)
		t.Fatal("netlink holds Runtime.mu")
	}
	r.current = nil
	r.mu.Unlock()
	retired := make(chan struct{})
	go func() { plane.workerRoundTrips.Wait(); close(retired) }()
	select {
	case <-retired:
		close(release)
		t.Fatal("query lost its retirement lease")
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("query leaked retirement lease")
	}
}

func TestDeviceServiceIdentifyRejectsUntrustedObservation(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	source := netip.MustParseAddr("192.0.2.10")
	neighbor := deviceTestNeighbor(source.String(), mac)
	for _, neighbors := range [][]netlink.Neigh{nil, {deviceTestNeighbor("192.0.2.11", mac)}, {deviceTestNeighbor(source.String(), [6]byte{2, 0, 0, 0, 0, 2})}} {
		r := deviceTestRuntime(&ControlPlane{}, neighbors)
		if got := r.Identify(t.Context(), source, mac); got != [6]byte{} {
			t.Fatalf("untrusted observation identified as %x", got)
		}
	}
	r := deviceTestRuntime(&ControlPlane{}, []netlink.Neigh{neighbor})
	r.kernelLinks.hostTCXLinks = nil
	if got := r.Identify(t.Context(), source, mac); got != [6]byte{} {
		t.Fatalf("unattached LAN identified as %x", got)
	}
	r = deviceTestRuntime(&ControlPlane{}, []netlink.Neigh{neighbor})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := r.Identify(ctx, source, mac); got != [6]byte{} {
		t.Fatal("cancelled identification succeeded")
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	links := r.clientNetlink.links
	r.clientNetlink.links = func() ([]netlink.Link, error) {
		cancel()
		return links()
	}
	r.clientNetlink.routes = func(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
		t.Fatal("cancelled identification queried another netlink source")
		return nil, nil
	}
	if got := r.Identify(ctx, source, mac); got != [6]byte{} {
		t.Fatal("identification ignored cancellation during topology query")
	}
	r.current = nil
	if got := r.Identify(t.Context(), source, mac); got != [6]byte{} {
		t.Fatal("retired runtime identified a device")
	}
}

// Inspect only this process's route sockets without creating links, addresses or neighbors.
func deviceTestRouteSockets(t *testing.T) map[int]string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	sockets := make(map[int]string)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil || domain != unix.AF_NETLINK {
			continue
		}
		protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil {
			t.Fatal(err)
		}
		if protocol != unix.NETLINK_ROUTE {
			continue
		}
		identity, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		sockets[fd] = identity
	}
	return sockets
}

func deviceTestNetlink(t *testing.T, ctx context.Context) (clientNetlink, func(), int) {
	t.Helper()
	before := deviceTestRouteSockets(t)
	n, cleanup, err := new(Runtime).deviceNetlink(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	fd := -1
	var identity string
	for candidate, socket := range deviceTestRouteSockets(t) {
		if before[candidate] == socket {
			continue
		}
		if fd != -1 {
			t.Fatal("device query created more than one route socket")
		}
		fd, identity = candidate, socket
	}
	if fd == -1 {
		t.Fatal("device query did not create a private route socket")
	}
	return n, func() {
		cleanup()
		if socket, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil && socket == identity {
			t.Error("device query leaked its route socket")
		}
	}, fd
}

func deviceTestBlockNetlink(t *testing.T, fd int) {
	t.Helper()
	// Drop replies only on the private test socket so the real query waits in Go netpoll.
	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceServiceNetlinkLifecycle(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	r := deviceTestRuntime(deviceTestPlane(t, nil, map[[6]byte]bool{mac: true}), nil)
	r.clientNetlink = nil
	before := deviceTestRouteSockets(t)
	if got, err := r.MITMEnabled(t.Context()); err != nil || !slices.Equal(got, [][6]byte{mac}) {
		t.Fatalf("real MITM query = %v, %v", got, err)
	}
	if got := r.Identify(t.Context(), netip.MustParseAddr("127.0.0.1"), mac); got != [6]byte{} {
		t.Fatalf("loopback identified as %x", got)
	}
	if after := deviceTestRouteSockets(t); !maps.Equal(before, after) {
		t.Fatalf("normal queries changed live route sockets: before %v, after %v", before, after)
	}
}

func TestDeviceServiceNetlinkCancellation(t *testing.T) {
	for _, method := range []string{"identify links", "identify routes", "identify neighbors", "MITM links", "MITM neighbors"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			n, cleanup, fd := deviceTestNetlink(t, ctx)
			defer cleanup()
			deviceTestBlockNetlink(t, fd)

			mac := [6]byte{2, 0, 0, 0, 0, 1}
			plane := deviceTestPlane(t, []string{"all"}, nil)
			r := deviceTestRuntime(plane, []netlink.Neigh{deviceTestNeighbor("192.0.2.10", mac)})
			entered := make(chan struct{})
			switch method {
			case "identify links", "MITM links":
				r.clientNetlink.links = func() ([]netlink.Link, error) {
					close(entered)
					return n.links()
				}
			case "identify routes":
				r.clientNetlink.routes = func(ip net.IP, options *netlink.RouteGetOptions) ([]netlink.Route, error) {
					close(entered)
					return n.routes(ip, options)
				}
			case "identify neighbors":
				socket, err := nl.GetNetlinkSocketAt(-1, -1, unix.NETLINK_ROUTE)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(socket.Close)
				deviceTestBlockNetlink(t, socket.GetFd())
				r.clientNetlink.neighbor = func(ctx context.Context, index int, source netip.Addr) (*netlink.Neigh, error) {
					close(entered)
					return queryClientNeighbor(ctx, socket, index, source)
				}
			case "MITM neighbors":
				r.clientNetlink.neighbors = func(index, family int) ([]netlink.Neigh, error) {
					close(entered)
					return n.neighbors(index, family)
				}
			}
			done := make(chan error, 1)
			go func() {
				if method == "MITM links" || method == "MITM neighbors" {
					_, err := r.MITMEnabled(ctx)
					done <- err
					return
				}
				if got := r.Identify(ctx, netip.MustParseAddr("192.0.2.10"), mac); got != [6]byte{} {
					done <- errors.New("cancelled identification succeeded")
					return
				}
				done <- ctx.Err()
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("query did not reach netlink")
			}
			select {
			case err := <-done:
				t.Fatalf("query returned before cancellation: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if !r.mu.TryLock() {
				t.Fatal("blocked netlink query holds Runtime.mu")
			}
			r.current = nil
			r.mu.Unlock()
			retired := make(chan struct{})
			go func() { plane.workerRoundTrips.Wait(); close(retired) }()
			select {
			case <-retired:
				t.Fatal("blocked query lost its retirement lease")
			default:
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled query = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt netlink receive")
			}
			select {
			case <-retired:
			case <-time.After(time.Second):
				t.Fatal("cancelled query leaked its retirement lease")
			}
			// Queries after close must fail rather than silently create a global socket.
			if _, err := n.links(); err == nil {
				t.Fatal("closed reader fell back to a global socket")
			}
		})
	}
}

func TestDeviceNetlinkDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	n, cleanup, fd := deviceTestNetlink(t, ctx)
	defer cleanup()
	deviceTestBlockNetlink(t, fd)
	r := deviceTestRuntime(deviceTestPlane(t, []string{"all"}, nil), nil)
	r.clientNetlink = &n
	done := make(chan error, 1)
	go func() { _, err := r.MITMEnabled(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expired query = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt netlink receive")
	}
}

func TestDeviceNetlinkIndependentCallsAndCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first, cleanupFirst, fd := deviceTestNetlink(t, ctx)
	defer cleanupFirst()
	second, cleanupSecond, _ := deviceTestNetlink(t, t.Context())
	defer cleanupSecond()
	deviceTestBlockNetlink(t, fd)
	done := make(chan error, 1)
	go func() { _, err := first.links(); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("filtered query did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	secondDone := make(chan error, 1)
	go func() { _, err := second.links(); secondDone <- err }()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("independent query failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("one query blocked another query's socket")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt netlink receive")
	}
	if _, err := second.links(); err != nil {
		t.Fatalf("cancellation closed another query's socket: %v", err)
	}
	cleanupSecond()
	if _, err := second.links(); err == nil {
		t.Fatal("normal cleanup left its socket open")
	}
}

func TestDeviceNetlinkCloseRace(t *testing.T) {
	for range 32 {
		ctx, cancel := context.WithCancel(t.Context())
		n, cleanup, _ := deviceTestNetlink(t, ctx)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, action := range []func(){
			func() {
				for range 8 {
					_, _ = n.links()
					_, _ = n.routes(net.ParseIP("127.0.0.1"), nil)
					_, _ = n.neighbors(0, netlink.FAMILY_ALL)
				}
			},
			cancel,
			cleanup,
			cleanup,
		} {
			wg.Go(func() { <-start; action() })
		}
		close(start)
		wg.Wait()
		cleanup()
	}
}

func TestDeviceServiceCancellationPrecedesNetlinkError(t *testing.T) {
	for _, method := range []string{"links", "neighbors"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r := deviceTestRuntime(deviceTestPlane(t, []string{"all"}, nil), nil)
			failure := errors.New("closed netlink socket")
			if method == "links" {
				r.clientNetlink.links = func() ([]netlink.Link, error) { cancel(); return nil, failure }
			} else {
				r.clientNetlink.neighbors = func(int, int) ([]netlink.Neigh, error) { cancel(); return nil, failure }
			}
			if got, err := r.MITMEnabled(ctx); got != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation was hidden by socket error: %v, %v", got, err)
			}
		})
	}
}

func TestDeviceServiceIdentifyDirectLANOnly(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	for _, tc := range []struct {
		name, source string
		route        netlink.Route
		want         bool
	}{
		{"direct LAN", "192.0.2.10", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 2}, true},
		{"downstream router", "192.0.2.10", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 2, Gw: net.ParseIP("192.0.2.1")}, false},
		{"direct WAN", "192.0.2.10", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 9}, false},
		{"router itself", "192.0.2.10", netlink.Route{Type: unix.RTN_LOCAL, LinkIndex: 2}, false},
		{"link local scope", "fe80::10%bridge", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 2}, true},
		{"numeric link local scope", "fe80::10%2", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 2}, true},
		{"missing link local scope", "fe80::10", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 2}, false},
		{"other link local scope", "fe80::10%wan", netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 9}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := netip.MustParseAddr(tc.source)
			r := deviceTestRuntime(&ControlPlane{}, []netlink.Neigh{deviceTestNeighbor(source.WithZone("").String(), mac)})
			r.clientNetlink.neighbors = func(int, int) ([]netlink.Neigh, error) {
				t.Fatal("identifying one client dumped the neighbor table")
				return nil, nil
			}
			r.clientNetlink.routes = func(_ net.IP, options *netlink.RouteGetOptions) ([]netlink.Route, error) {
				if source.Zone() != "" && options.OifIndex != 2 {
					t.Fatalf("zone lost: %d", options.OifIndex)
				}
				return []netlink.Route{tc.route}, nil
			}
			want := [6]byte{}
			if tc.want {
				want = mac
			}
			if got := r.Identify(t.Context(), source, mac); got != want {
				t.Fatalf("Identify = %x, want %x", got, want)
			}
		})
	}
}
