// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import "testing"

func TestCacheDirectoryDefaults(t *testing.T) {
	for _, test := range []struct {
		name, cache, want string
	}{
		{name: "default", want: "/var/lib/dae"},
		{name: "custom", cache: "/new/state", want: "/new/state"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DAE_LOCATION_CACHE", test.cache)
			if got := cacheDirectory(); got != test.want {
				t.Fatalf("cache directory = %q, want %q", got, test.want)
			}
		})
	}
}
