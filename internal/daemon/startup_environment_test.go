// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestReplacementEnvironmentKeepsDaemonValues(t *testing.T) {
	t.Setenv("PATH", "/daemon/tools")
	t.Setenv("NOTIFY_SOCKET", "@daemon-notifications")
	t.Setenv("DAE_LOCATION_CACHE", "/daemon/cache")
	t.Setenv(replacementEnv, "obsolete-exec")
	t.Setenv(preflightEnv, "obsolete-preflight")
	before := os.Environ()
	for _, marker := range []string{replacementEnv, preflightEnv} {
		t.Run(marker, func(t *testing.T) {
			var want []string
			for _, entry := range before {
				key, _, _ := strings.Cut(entry, "=")
				if key != replacementEnv && key != preflightEnv {
					want = append(want, entry)
				}
			}
			want = append(want, marker+"=73")
			got := replacementEnvironment(marker, 73)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Fatal("replacement changed ordinary environment values or kept stale descriptors")
			}
			if !slices.Equal(os.Environ(), before) {
				t.Fatal("building the exec environment changed the serving process")
			}
		})
	}
}
