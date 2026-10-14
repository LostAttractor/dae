// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"os"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/surge/internal/jq"
)

func init() {
	if slices.Equal(os.Args[1:], []string{"plugins", "surge", "__jq-worker"}) {
		if err := jq.Run(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func testJQPool(t *testing.T) *jq.Pool {
	t.Helper()
	pool, release, err := jq.Acquire()
	if err != nil {
		t.Skipf("jq cgroup unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	})
	return pool
}
