// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestAuthorityChainsEvictLeastRecentlyUsed(t *testing.T) {
	builds := make(map[string]int)
	chainFor := new(Host).chainsForFlow(plugin.Flow{Host: "original.example"}, func(flow plugin.Flow) plugin.Handler {
		builds[flow.Host]++
		return func(e *plugin.Exchange) (*plugin.Response, error) {
			return nil, fmt.Errorf("%s", flow.Host)
		}
	})
	check := func(host string) {
		t.Helper()
		_, err := chainFor(plugin.Flow{Host: host})(nil)
		if err == nil || err.Error() != host {
			t.Fatalf("wrong authority chain for %s: %v", host, err)
		}
	}
	for i := range 32 {
		check(fmt.Sprintf("%d.example", i))
	}
	check("0.example")
	check("new.example")
	check("new.example")
	check("0.example")
	check("original.example")
	if builds["new.example"] != 1 || builds["0.example"] != 1 || builds["original.example"] != 1 {
		t.Fatalf("active authority was rebuilt: %v", builds)
	}
	check("1.example")
	if builds["1.example"] != 2 {
		t.Fatalf("least recently used chain was retained: %v", builds)
	}
}

func TestAuthorityChainConstructionDoesNotBlockOtherHosts(t *testing.T) {
	gate, started := make(chan struct{}), make(chan struct{}, 8)
	unblock := sync.OnceFunc(func() { close(gate) })
	var builds atomic.Int32
	chainFor := new(Host).chainsForFlow(plugin.Flow{Host: "original.example"}, func(flow plugin.Flow) plugin.Handler {
		if flow.Host == "slow.example" {
			builds.Add(1)
			started <- struct{}{}
			<-gate
		}
		return func(*plugin.Exchange) (*plugin.Response, error) { return nil, nil }
	})
	var workers sync.WaitGroup
	defer func() { unblock(); workers.Wait() }()
	for range 8 {
		workers.Go(func() { chainFor(plugin.Flow{Host: "slow.example"}) })
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("chain construction did not start")
	}
	ready := make(chan struct{})
	workers.Go(func() {
		chainFor(plugin.Flow{Host: "other.example"})
		close(ready)
	})
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("one authority blocked another authority's chain")
	}
	unblock()
	workers.Wait()
	if builds.Load() != 1 {
		t.Fatalf("concurrent requests rebuilt one authority %d times", builds.Load())
	}
}
