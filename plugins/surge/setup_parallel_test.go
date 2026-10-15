// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestPrepareModulesConcurrencyAndOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active, peak atomic.Int32
		conf, services := moduleLoadingFixture(12, func(req *http.Request) error {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			delay := time.Millisecond
			if req.URL.Path == "/0.sgmodule" {
				delay *= 10
			}
			time.Sleep(delay)
			return nil
		})
		modules, err := prepareModules(t.Context(), conf, services)
		if err != nil {
			t.Fatal(err)
		}
		if got := peak.Load(); got != maxConcurrentModuleLoads {
			t.Fatalf("concurrency = %d, want %d", got, maxConcurrentModuleLoads)
		}
		for i, module := range modules {
			if module.Name != fmt.Sprintf("module-%d", i) || len(module.Scripts) != 1 {
				t.Fatalf("module %d changed order or lost its script: %+v", i, module)
			}
		}
		if active.Load() != 0 {
			t.Fatal("download outlived preparation")
		}
	})
}

func TestPrepareModulesCancelsDownloads(t *testing.T) {
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprint(parentCancel), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var active, requests atomic.Int32
				failure := errors.New("module download failed")
				conf, services := moduleLoadingFixture(12, func(req *http.Request) error {
					active.Add(1)
					requests.Add(1)
					defer active.Add(-1)
					if req.URL.Path == "/0.sgmodule" {
						time.Sleep(time.Millisecond)
						if parentCancel {
							cancel()
						} else {
							return failure
						}
					}
					<-req.Context().Done()
					return req.Context().Err()
				})
				modules, err := prepareModules(ctx, conf, services)
				if modules != nil || err == nil {
					t.Fatalf("partial modules published: %v, %v", modules, err)
				}
				if !parentCancel && !strings.Contains(err.Error(), failure.Error()) {
					t.Fatalf("lost original error: %v", err)
				}
				if parentCancel && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
				if active.Load() != 0 || requests.Load() != maxConcurrentModuleLoads {
					t.Fatalf("active=%d, requests=%d", active.Load(), requests.Load())
				}
			})
		})
	}
}
