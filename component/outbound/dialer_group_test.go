/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

var testNetworkType = &common.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
}

type fakeDialer struct{}

func (fakeDialer) Alive() bool { return true }
func (fakeDialer) Connect() error {
	return nil
}
func (fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (fakeDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}

type blockingCheckDialer struct {
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	servers []net.Conn
}

func (d *blockingCheckDialer) Alive() bool    { return true }
func (d *blockingCheckDialer) Connect() error { return nil }
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
	return dialer.NewDialer(fakeDialer{}, option, &dialer.Property{Property: D.Property{
		Name: name,
		Link: "test://" + name,
	}}, true)
}

// simulateCheck simulates a connectivity check round of the dialer: it marks
// the supported state, feeds the latency/alive result to registered groups
// and notifies selectors.
func simulateCheck(d *dialer.Dialer, ok bool, latency time.Duration) {
	d.SetSupported(testNetworkType, ok)
	var err error
	if !ok {
		err = fmt.Errorf("simulated check failure")
	}
	d.Update(ok, latency, testNetworkType, err)
	d.NotifyStatusChange()
}

func newTestGroup(option *dialer.GlobalOption, dialers []*dialer.Dialer, annotations []*dialer.Annotation, policy dialer.DialerSelectionPolicy) *DialerGroup {
	return NewDialerGroup(option, "test-group", GroupKindNormal, dialers, annotations, policy,
		func(alive bool, networkType *common.NetworkType) {})
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			d.SetSupported(testNetworkType, i%2 == 0)
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
	d := dialer.NewDialer(blocking, option, &dialer.Property{Property: D.Property{
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
