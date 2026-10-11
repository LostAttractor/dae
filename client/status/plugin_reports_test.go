// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
)

func TestCoreStatusTreatsPluginReportsAsOpaque(t *testing.T) {
	withoutStatusColors(t)
	withStatusTerminalWidth(t, 0)
	snapshot := &api.StatusSnapshot{StartedAt: time.Now()}
	for _, render := range []func(*strings.Builder){
		func(out *strings.Builder) { Print(out, snapshot, false) },
		func(out *strings.Builder) { Print(out, snapshot, true) },
		func(out *strings.Builder) { PrintRecent(out, snapshot) },
	} {
		snapshot.Plugins = nil
		var before, after strings.Builder
		render(&before)
		snapshot.Plugins = []api.PluginInstanceStatus{{
			ID: "custom", Type: "custom", State: "active",
			Details: []byte(`{"enabled":true,"runtimes":"plugin-private-schema"}`),
		}}
		render(&after)
		if after.String() != before.String() {
			t.Fatalf("plugin report changed core status:\n%s", after.String())
		}
	}
}
