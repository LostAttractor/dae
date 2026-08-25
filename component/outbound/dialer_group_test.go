/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	log "github.com/sirupsen/logrus"
)

var testNetworkType = &common.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
}

type fakeDialer struct{}

func (fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (fakeDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}

type toggleDialer struct {
	once  sync.Once
	state *netproxy.StateBroadcaster
}

func (d *toggleDialer) initialize() {
	d.once.Do(func() { d.state = netproxy.NewStateBroadcaster(netproxy.SessionDisconnected) })
}
func (d *toggleDialer) setConnected(connected bool) {
	d.initialize()
	state := netproxy.SessionDisconnected
	if connected {
		state = netproxy.SessionConnected
	}
	d.state.Transition(state, nil)
}
func (d *toggleDialer) Connect(context.Context) error {
	d.setConnected(true)
	return nil
}
func (d *toggleDialer) Snapshot() netproxy.StateEvent {
	d.initialize()
	return d.state.Snapshot()
}
func (d *toggleDialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	d.initialize()
	return d.state.WatchState(ctx)
}
func (d *toggleDialer) Close() error {
	d.initialize()
	d.state.Transition(netproxy.SessionClosed, nil)
	return nil
}
func (d *toggleDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (d *toggleDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}

type blockingCheckDialer struct {
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	servers []net.Conn
}

func (d *blockingCheckDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.servers = append(d.servers, server)
	d.mu.Unlock()
	d.once.Do(func() { close(d.started) })
	return client, nil
}
func (d *blockingCheckDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (d *blockingCheckDialer) closeServers() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, server := range d.servers {
		_ = server.Close()
	}
}

func newTestOption() *dialer.GlobalOption {
	return &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.google:53", "8.8.8.8", "2001:4860:4860::8888"}},
		CheckInterval:     15 * time.Second,
	}
}

func newTestDialer(option *dialer.GlobalOption, name string) *dialer.Dialer {
	return dialer.NewDialer(netproxy.NewRuntime(fakeDialer{}), option, &dialer.Property{Property: D.Property{
		Name: name,
		Link: "test://" + name,
	}}, true)
}

// simulateCheck simulates a connectivity check round of the dialer: it marks
// the supported state, feeds the latency/alive result to registered groups
// and notifies selectors.
func simulateCheck(d *dialer.Dialer, ok bool, latency time.Duration) {
	d.SetSupported(testNetworkType, true)
	var err error
	if !ok {
		err = fmt.Errorf("simulated check failure")
	}
	d.Update(ok, latency, testNetworkType, err)
	d.NotifyStatusChange()
}

func newTestGroup(option *dialer.GlobalOption, dialers []*dialer.Dialer, annotations []*dialer.Annotation, policy dialer.DialerSelectionPolicy) *DialerGroup {
	return NewDialerGroup(option, "test-group", GroupKindNormal, dialers, annotations, policy,
		func(bool, *common.NetworkType) error { return nil })
}

func emptyAnnotations(n int) []*dialer.Annotation {
	annotations := make([]*dialer.Annotation, n)
	for i := range annotations {
		annotations[i] = &dialer.Annotation{}
	}
	return annotations
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
		newTestDialer(option, "node2"),
	}
	fixedIndex := 1
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		})
	for i, d := range dialers {
		simulateCheck(d, true, time.Duration(100+i)*time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		d, err := g.Select(testNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fatalf("dialers[%v] expected, but got %v", fixedIndex, d.Name)
		}
	}

	fixedIndex = 0
	g.selectionPolicy.FixedIndex = fixedIndex
	for i := 0; i < 10; i++ {
		d, err := g.Select(testNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fatalf("dialers[%v] expected, but got %v", fixedIndex, d.Name)
		}
	}
}

func TestDialerGroup_Select_Fixed_NotAlive(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
	}
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 1,
		})
	simulateCheck(dialers[0], true, 100*time.Millisecond)
	simulateCheck(dialers[1], false, 0)

	// The fixed dialer is not alive: selection must fail even if other
	// dialers are alive.
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("ErrNoAliveDialer expected, but got %v", err)
	}

	// It recovers once the fixed dialer is alive again.
	simulateCheck(dialers[1], true, 100*time.Millisecond)
	d, err := g.Select(testNetworkType)
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[1] {
		t.Fatalf("dialers[1] expected, but got %v", d.Name)
	}
}

func TestDialerGroup_Select_Fixed_UnknownSupport(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, "node0")
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed})
	defer g.Close()

	// Connectivity through another mode proves the node is alive, while the
	// requested mode remains unknown rather than conclusively unsupported.
	d.Update(true, 100*time.Millisecond, common.IndexToNetworkType(1), nil)
	d.NotifyStatusChange()
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("unknown mode returned %v", err)
	}

	d.SetSupported(testNetworkType, true)
	d.NotifyStatusChange()
	if selected, err := g.Select(testNetworkType); err != nil || selected != d {
		t.Fatalf("confirmed mode returned %v, %v", selected, err)
	}
}

func TestDialerGroupNodeHealthAppliesToAllModes(t *testing.T) {
	policies := []dialer.DialerSelectionPolicy{
		{Policy: consts.DialerSelectionPolicy_Fixed},
		{Policy: consts.DialerSelectionPolicy_Random},
		{Policy: consts.DialerSelectionPolicy_MinLastLatency},
	}
	for _, policy := range policies {
		t.Run(string(policy.Policy), func(t *testing.T) {
			option := newTestOption()
			d := newTestDialer(option, fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()))
			var networkAvailable [4]bool
			g := NewDialerGroup(option, "test-group", GroupKindNormal, []*dialer.Dialer{d}, emptyAnnotations(1), policy,
				func(available bool, networkType *common.NetworkType) error {
					networkAvailable[common.NetworkTypeToIndex(networkType)] = available
					return nil
				})
			defer g.Close()

			otherNetwork := common.IndexToNetworkType(1)
			networks := []*common.NetworkType{testNetworkType, otherNetwork}
			for _, networkType := range networks {
				d.SetSupported(networkType, true)
			}
			d.Update(true, time.Millisecond, testNetworkType, nil)
			d.NotifyStatusChange()

			for _, networkType := range networks {
				if selected, err := g.Select(networkType); err != nil || selected != d {
					t.Fatalf("initial selection for %s = %v, %v", networkType, selected, err)
				}
			}
			if !networkAvailable[0] || !networkAvailable[1] || !g.Available() {
				t.Fatal("group did not publish initial availability")
			}

			d.Update(false, 0, testNetworkType, errors.New("node health check failed"))
			d.NotifyStatusChange()
			for _, networkType := range networks {
				if _, err := g.Select(networkType); !errors.Is(err, ErrNoAliveDialer) {
					t.Fatalf("failed node returned for %s: %v", networkType, err)
				}
				if got := d.SupportState(networkType); got != dialer.NetworkSupportConfirmed {
					t.Fatalf("node failure changed %s support to %s", networkType, got)
				}
			}
			if networkAvailable[0] || networkAvailable[1] || g.Available() {
				t.Fatal("group remained available after node failure")
			}

			d.Update(true, time.Millisecond, testNetworkType, nil)
			d.NotifyStatusChange()
			for _, networkType := range networks {
				if selected, err := g.Select(networkType); err != nil || selected != d {
					t.Fatalf("recovered selection for %s = %v, %v", networkType, selected, err)
				}
			}
			if !networkAvailable[0] || !networkAvailable[1] || !g.Available() {
				t.Fatal("group did not publish recovery")
			}
			availability := d.RuntimeStatus(g).Availability
			if !availability.Alive || availability.ChecksFailed != 1 {
				t.Fatalf("recovered availability = %+v", availability)
			}
		})
	}
}

func TestDialerGroupAvailabilityIsPerNetwork(t *testing.T) {
	policies := []dialer.DialerSelectionPolicy{
		{Policy: consts.DialerSelectionPolicy_Fixed},
		{Policy: consts.DialerSelectionPolicy_Random},
		{Policy: consts.DialerSelectionPolicy_MinLastLatency},
	}
	for _, policy := range policies {
		t.Run(string(policy.Policy), func(t *testing.T) {
			option := newTestOption()
			d := newTestDialer(option, t.Name())
			var changes [4]bool
			g := NewDialerGroup(option, "test-group", GroupKindNormal,
				[]*dialer.Dialer{d}, emptyAnnotations(1), policy,
				func(available bool, networkType *common.NetworkType) error {
					changes[common.NetworkTypeToIndex(networkType)] = available
					return nil
				})
			t.Cleanup(func() { _ = g.Close() })

			// Aggregate node health alone cannot make an unknown mode routable.
			d.Update(true, time.Millisecond, nil, nil)
			d.NotifyStatusChange()
			if g.Available() {
				t.Fatal("healthy group became available before capability confirmation")
			}
			if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("unknown capability selected a dialer: %v", err)
			}

			d.SetSupported(testNetworkType, true)
			d.NotifyStatusChange()
			if selected, err := g.Select(testNetworkType); err != nil || selected != d {
				t.Fatalf("confirmed capability returned %v, %v", selected, err)
			}
			if !changes[common.NetworkTypeToIndex(testNetworkType)] || !g.Available() {
				t.Fatal("confirmed network did not become available")
			}
			for i := 1; i < len(changes); i++ {
				if changes[i] {
					t.Fatalf("network %d inherited another mode's availability", i)
				}
			}

			d.Update(false, 0, nil, errors.New("lost"))
			d.NotifyStatusChange()
			if g.Available() {
				t.Fatal("unhealthy group remained available")
			}
			for i, available := range changes {
				if available {
					t.Fatalf("unhealthy group left network %d available", i)
				}
			}
		})
	}
}

func TestDialerGroupRetriesFailedAvailabilityPublication(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, t.Name())
	d.SetSupported(testNetworkType, true)
	var attempts atomic.Int32
	g := NewDialerGroup(option, t.Name(), GroupKindNormal,
		[]*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(_ bool, networkType *common.NetworkType) error {
			if common.NetworkTypeToIndex(networkType) != common.NetworkTypeToIndex(testNetworkType) {
				return nil
			}
			if attempts.Add(1) == 1 {
				return errors.New("publish failed")
			}
			return nil
		})
	t.Cleanup(func() { _ = g.Close() })

	d.Update(true, time.Millisecond, testNetworkType, nil)
	d.NotifyStatusChange()
	if g.Available() {
		t.Fatal("failed publication committed availability")
	}
	d.NotifyStatusChange()
	if !g.Available() {
		t.Fatal("unchanged health did not retry availability publication")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("publication attempts = %d, want 2", got)
	}
}

func TestDialerGroupCloseRejectsSelection(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, t.Name())
	d.SetSupported(testNetworkType, true)
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed})
	t.Cleanup(d.RetireTransport)
	d.Update(true, time.Millisecond, testNetworkType, nil)
	d.NotifyStatusChange()
	if _, err := g.Select(testNetworkType); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Select(testNetworkType); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Select after Close error = %v, want net.ErrClosed", err)
	}
}

func TestAlwaysAliveGroupStartsAvailable(t *testing.T) {
	g := NewDialerGroup(newTestOption(), t.Name(), GroupKindAlwaysAlive, nil, nil,
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed}, nil)
	t.Cleanup(func() { _ = g.Close() })
	if !g.Available() {
		t.Fatal("always-alive group started unavailable")
	}
}

func TestAlwaysAliveGroupSeedsCachedSelectors(t *testing.T) {
	policies := []dialer.DialerSelectionPolicy{
		{Policy: consts.DialerSelectionPolicy_Random},
		{Policy: consts.DialerSelectionPolicy_MinLastLatency},
	}
	for _, policy := range policies {
		t.Run(string(policy.Policy), func(t *testing.T) {
			option := newTestOption()
			d := dialer.NewDialer(netproxy.NewRuntime(fakeDialer{}), option, &dialer.Property{Property: D.Property{
				Name: t.Name(),
				Link: "test://" + t.Name(),
			}}, false)
			g := NewDialerGroup(option, t.Name(), GroupKindAlwaysAlive,
				[]*dialer.Dialer{d}, emptyAnnotations(1), policy, nil)
			t.Cleanup(func() {
				_ = g.Close()
				d.RetireTransport()
			})
			if selected, err := g.Select(testNetworkType); err != nil || selected != d {
				t.Fatalf("Select = %v, %v", selected, err)
			}
		})
	}
}

func TestFixedSelectorRejectsNegativeIndex(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, t.Name())
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: -1})
	t.Cleanup(func() { _ = g.Close() })
	simulateCheck(d, true, time.Millisecond)
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("negative fixed index returned %v, want ErrNoAliveDialer", err)
	}
}

func TestLatencyTablePrintedAtStartupAndOnReselection(t *testing.T) {
	option := newTestOption()
	first := newTestDialer(option, "first")
	second := newTestDialer(option, "second")
	g := newTestGroup(option, []*dialer.Dialer{first, second}, emptyAnnotations(2),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency})
	t.Cleanup(func() { _ = g.Close() })

	logger := log.StandardLogger()
	previousOutput := logger.Out
	var output bytes.Buffer
	logger.SetOutput(&output)
	t.Cleanup(func() { logger.SetOutput(previousOutput) })
	countTables := func() int {
		return strings.Count(output.String(), "Group 'test-group' [tcp4]:")
	}

	simulateCheck(first, true, 20*time.Millisecond)
	simulateCheck(second, true, 10*time.Millisecond)
	if got := countTables(); got != 0 {
		t.Fatalf("latency tables before startup completion = %d, want 0", got)
	}

	g.PrintLatency()
	if got := countTables(); got != 1 {
		t.Fatalf("startup tcp4 latency tables = %d, want 1", got)
	}

	output.Reset()
	simulateCheck(first, true, time.Millisecond)
	if got := countTables(); got != 1 {
		t.Fatalf("latency tables after reselection = %d, want 1", got)
	}

	output.Reset()
	simulateCheck(first, true, 2*time.Millisecond)
	if got := countTables(); got != 0 {
		t.Fatalf("latency tables without reselection = %d, want 0", got)
	}
}

func TestLatencySelectorIgnoresUnknownUntilConfirmed(t *testing.T) {
	option := newTestOption()
	option.CheckTolerance = time.Second
	unknown := newTestDialer(option, "unknown")
	confirmed := newTestDialer(option, "confirmed")
	g := newTestGroup(option, []*dialer.Dialer{unknown, confirmed}, emptyAnnotations(2),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency})
	defer g.Close()

	otherNetwork := common.IndexToNetworkType(1)
	unknown.SetSupported(otherNetwork, true)
	unknown.Update(true, time.Millisecond, otherNetwork, nil)
	unknown.NotifyStatusChange()
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("unknown dialer returned %v", err)
	}

	confirmed.SetSupported(testNetworkType, true)
	confirmed.Update(true, 500*time.Millisecond, testNetworkType, nil)
	confirmed.NotifyStatusChange()
	if selected, err := g.Select(testNetworkType); err != nil || selected != confirmed {
		t.Fatalf("selection after confirmation = %v, %v; want confirmed dialer", selected, err)
	}
}

func TestDialerWithoutHealthCheckHasConfirmedSupport(t *testing.T) {
	d := dialer.NewDialer(netproxy.NewRuntime(fakeDialer{}), newTestOption(), &dialer.Property{Property: D.Property{
		Name: "always-supported",
		Link: "test://always-supported",
	}}, false)
	defer d.Close()
	for i := 0; i < 4; i++ {
		networkType := common.IndexToNetworkType(i)
		if !d.ConfirmedSupport(networkType) {
			t.Fatalf("network %v is not confirmed", networkType)
		}
	}
}

func TestDialerGroup_Select_Fixed_NegativeIndex(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, "node0")
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: -1,
		})
	simulateCheck(d, true, 100*time.Millisecond)
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("expected ErrNoAliveDialer, got %v", err)
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {
	option := newTestOption()
	dialers := make([]*dialer.Dialer, 0, 10)
	for i := 0; i < 10; i++ {
		dialers = append(dialers, newTestDialer(option, fmt.Sprintf("node%v", i)))
	}
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		})

	// Test 1000 times.
	for i := 0; i < 1000; i++ {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			simulateCheck(d, alive, latency)
			if alive && (jMinLatency == -1 || latency < minLatency) {
				jMinLatency = j
				minLatency = latency
			}
		}
		d, err := g.Select(testNetworkType)
		if jMinLatency == -1 {
			// All dialers are dead.
			if !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("ErrNoAliveDialer expected, but got %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_MinAvg10(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
	}
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinAverage10Latencies,
		})

	// node0 has low last latency but high average; node1 has stable low
	// average. The min_avg10 policy should stick to node1.
	for i := 0; i < 10; i++ {
		simulateCheck(dialers[0], true, 500*time.Millisecond)
		simulateCheck(dialers[1], true, 100*time.Millisecond)
	}
	simulateCheck(dialers[0], true, 10*time.Millisecond)
	d, err := g.Select(testNetworkType)
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[1] {
		t.Fatalf("dialers[1] expected, but got %v", d.Name)
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {
	option := newTestOption()
	dialers := make([]*dialer.Dialer, 0, 5)
	for i := 0; i < 5; i++ {
		dialers = append(dialers, newTestDialer(option, fmt.Sprintf("node%v", i)))
	}
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		})
	for i, d := range dialers {
		simulateCheck(d, true, time.Duration(100+i)*time.Millisecond)
	}
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select(testNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {
	option := newTestOption()
	dialers := make([]*dialer.Dialer, 0, 5)
	for i := 0; i < 5; i++ {
		dialers = append(dialers, newTestDialer(option, fmt.Sprintf("node%v", i)))
	}
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		})
	zeroTarget := 3
	for i, d := range dialers {
		simulateCheck(d, i != zeroTarget, 100*time.Millisecond)
	}
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select(testNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}

func TestDialerGroup_Select_NoAliveDialer(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
	}
	g := newTestGroup(option, dialers, emptyAnnotations(len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		})
	for _, d := range dialers {
		simulateCheck(d, false, 0)
	}
	if _, err := g.Select(testNetworkType); !errors.Is(err, ErrNoAliveDialer) {
		t.Fatalf("ErrNoAliveDialer expected, but got %v", err)
	}
}

func TestDialerGroupInitialUnavailableIsSilent(t *testing.T) {
	logger := log.StandardLogger()
	previousOutput := logger.Out
	var output bytes.Buffer
	logger.SetOutput(&output)
	t.Cleanup(func() { logger.SetOutput(previousOutput) })

	g := &DialerGroup{Name: t.Name()}
	g.publishAvailable(false)
	if strings.Contains(output.String(), "Group is unavailable") {
		t.Fatalf("initial unavailable state was logged:\n%s", output.String())
	}
	g.publishAvailable(true)
	if !strings.Contains(output.String(), "Group is available") {
		t.Fatalf("availability transition was not logged:\n%s", output.String())
	}
}

func TestDialerGroupInitializeConnectivity(t *testing.T) {
	option := newTestOption()
	seen := 0
	g := NewDialerGroup(option, "empty", GroupKindNormal, nil, nil,
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random},
		func(available bool, _ *common.NetworkType) error {
			if available {
				t.Fatal("empty group initialized alive")
			}
			seen++
			return nil
		})

	g.InitializeConnectivity()
	g.InitializeConnectivity()
	if seen != 4 {
		t.Fatalf("availability callbacks = %d, want 4", seen)
	}
}

func TestDialerGroupSelectInvalidatesDisconnectedTransport(t *testing.T) {
	for _, policy := range []consts.DialerSelectionPolicy{
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_Random,
	} {
		t.Run(string(policy), func(t *testing.T) {
			option := newTestOption()
			transport := new(toggleDialer)
			transport.setConnected(true)
			d := dialer.NewDialer(netproxy.NewRuntime(transport), option, &dialer.Property{Property: D.Property{
				Name: "node0",
				Link: "test://node0",
			}}, true)
			g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
				dialer.DialerSelectionPolicy{Policy: policy})
			t.Cleanup(func() { _ = g.Close() })
			simulateCheck(d, true, time.Millisecond)
			transport.setConnected(false)

			done := make(chan error, 1)
			go func() {
				_, err := g.Select(testNetworkType)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNoAliveDialer) {
					t.Fatalf("Select error = %v, want ErrNoAliveDialer", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Select looped on a disconnected transport")
			}
		})
	}
}

func TestDialerGroupSessionDisconnectPublishesState(t *testing.T) {
	for _, policy := range []consts.DialerSelectionPolicy{
		consts.DialerSelectionPolicy_Fixed,
		consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_Random,
	} {
		t.Run(string(policy), func(t *testing.T) {
			option := newTestOption()
			transport := new(toggleDialer)
			transport.setConnected(true)
			d := dialer.NewDialer(netproxy.NewRuntime(transport), option, &dialer.Property{Property: D.Property{
				Name: "node0",
				Link: "test://node0",
			}}, true)
			changes := make(chan struct {
				available bool
				network   int
			}, 16)
			g := NewDialerGroup(option, "test-group", GroupKindNormal,
				[]*dialer.Dialer{d}, emptyAnnotations(1),
				dialer.DialerSelectionPolicy{Policy: policy},
				func(available bool, networkType *common.NetworkType) error {
					changes <- struct {
						available bool
						network   int
					}{available: available, network: common.NetworkTypeToIndex(networkType)}
					return nil
				})
			t.Cleanup(func() {
				_ = g.Close()
				d.RetireTransport()
			})
			simulateCheck(d, true, time.Millisecond)
			for {
				select {
				case change := <-changes:
					if change.network == common.NetworkTypeToIndex(testNetworkType) && change.available {
						goto connected
					}
				case <-time.After(time.Second):
					t.Fatal("group did not publish its connected state")
				}
			}

		connected:
			for len(changes) > 0 {
				<-changes
			}
			transport.setConnected(false)
			deadline := time.After(time.Second)
			for {
				select {
				case change := <-changes:
					if change.network == common.NetworkTypeToIndex(testNetworkType) {
						if change.available {
							t.Fatal("disconnect published alive")
						}
						goto disconnected
					}
				case <-deadline:
					t.Fatal("session disconnect did not reach the group callback")
				}
			}
		disconnected:
			if d.Alive() {
				t.Fatal("session disconnect left node usable")
			}
		})
	}
}

func TestDialerGroup_Select_AnnotationAddLatency(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
	}
	annotations := emptyAnnotations(len(dialers))
	// node1 has lower raw latency, but the +1s latency offset should make
	// node0 win.
	annotations[1].AddLatency = time.Second
	g := newTestGroup(option, dialers, annotations,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		})
	simulateCheck(dialers[0], true, 300*time.Millisecond)
	simulateCheck(dialers[1], true, 100*time.Millisecond)
	d, err := g.Select(testNetworkType)
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[0] {
		t.Fatalf("dialers[0] expected, but got %v", d.Name)
	}
}

func TestDialerGroup_Select_AnnotationPriority(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
	}
	annotations := emptyAnnotations(len(dialers))
	// node1 has higher latency but higher priority.
	annotations[1].Priority = 1
	g := newTestGroup(option, dialers, annotations,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		})
	simulateCheck(dialers[0], true, 100*time.Millisecond)
	simulateCheck(dialers[1], true, 300*time.Millisecond)
	d, err := g.Select(testNetworkType)
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[1] {
		t.Fatalf("dialers[1] expected, but got %v", d.Name)
	}
}

func TestDialerGroup_CheckAsyncAnnotation(t *testing.T) {
	option := newTestOption()
	dialers := []*dialer.Dialer{
		newTestDialer(option, "node0"),
		newTestDialer(option, "node1"),
	}
	annotations := emptyAnnotations(len(dialers))
	annotations[1].CheckAsync = true
	g := newTestGroup(option, dialers, annotations,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		})
	defer g.Close()
	if dialers[0].CheckAsync() {
		t.Errorf("node0 should not be marked check_async")
	}
	if !dialers[1].CheckAsync() {
		t.Errorf("node1 should be marked check_async")
	}
}

func TestDialerRuntimeStatusConcurrentUpdate(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, t.Name())
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinMovingAverageLatencies})
	defer g.Close()
	d.SetSupported(testNetworkType, true)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			d.Update(i%2 == 0, time.Duration(i+1)*time.Millisecond, testNetworkType, errors.New("test"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = d.RuntimeStatus(g)
		}
	}()
	wg.Wait()

	if snapshot := d.RuntimeStatus(g); !snapshot.HasLatency {
		t.Fatalf("runtime snapshot should contain the recorded latency")
	}
}

func TestFixedSelectorConcurrentNotifications(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, t.Name())
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed})
	defer g.Close()

	// Prepare the first state transition without notifying the selector. All
	// goroutines below will therefore contend on its initially empty state.
	d.SetSupported(testNetworkType, true)
	d.Update(true, time.Millisecond, testNetworkType, nil)

	const workers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 20; j++ {
				d.NotifyStatusChange()
			}
		}()
	}
	close(start)
	wg.Wait()

	if selected := g.SelectedDialer(testNetworkType); selected != d {
		t.Fatalf("selected dialer = %v, want %v", selected, d)
	}
}

func TestScopedDialerSharesTransportWithDistinctIdentity(t *testing.T) {
	option := newTestOption()
	base := newTestDialer(option, t.Name())
	clone := base.CloneForStatsScope("override-group")
	defer base.Close()
	defer clone.Close()

	if base.Dialer != clone.Dialer {
		t.Fatal("group-specific checker did not share its underlying transport")
	}
	if base.StatsKey() == clone.StatsKey() || base.StatsID() == clone.StatsID() {
		t.Fatalf("group-specific checker clone must have a distinct stats identity")
	}
}

func TestDialerCloseRejectsLaterUpdates(t *testing.T) {
	option := newTestOption()
	d := newTestDialer(option, t.Name())
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency})

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d.Update(true, 10*time.Millisecond, testNetworkType, nil)
	if snapshot := d.RuntimeStatus(g); snapshot.HasLatency || snapshot.Availability.Seen {
		t.Fatalf("closed dialer accepted a status update: %+v", snapshot)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDialerCloseWaitsForAndCancelsHealthCheck(t *testing.T) {
	option := newTestOption()
	blocking := &blockingCheckDialer{started: make(chan struct{})}
	d := dialer.NewDialer(netproxy.NewRuntime(blocking), option, &dialer.Property{Property: D.Property{
		Name: t.Name(), Link: "test://" + t.Name(),
	}}, true)
	d.SetCheckAsync(true)
	g := newTestGroup(option, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency})
	defer blocking.closeServers()

	d.ActivateCheck(new(sync.WaitGroup))
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("health check did not start")
	}

	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and join the health check")
	}
	if snapshot := d.RuntimeStatus(g); snapshot.Availability.Seen {
		t.Fatalf("canceled check wrote availability after close: %+v", snapshot.Availability)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNextHopDialerIdentityIncludesEffectivePath(t *testing.T) {
	option := newTestOption()
	s := &DialerSet{
		option:       option,
		nodeInfosMap: make(map[dialer.Property]*NodeInfo),
	}
	source := &NodeInfo{
		Link: "source-link",
		Property: &dialer.Property{Property: D.Property{
			Name: "source", Protocol: "source-proto", Address: "source-address", Link: "source-link",
		}},
	}
	nextHop := &NodeInfo{
		Link: "next-hop-link",
		Property: &dialer.Property{Property: D.Property{
			Name: "next-hop", Protocol: "next-proto", Address: "next-address", Link: "next-hop-link",
		}},
	}

	d, err := s.createNextHopDialer(source, nextHop)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if want := "source-link->next-hop-link"; d.Property.Link != want {
		t.Fatalf("effective property link = %q, want %q", d.Property.Link, want)
	}
	if want := dialer.ComposeStatsIdentity("next-hop", "source-link", "next-hop-link"); d.Property.StatsIdentity != want {
		t.Fatalf("effective stats identity = %q, want %q", d.Property.StatsIdentity, want)
	}
}
