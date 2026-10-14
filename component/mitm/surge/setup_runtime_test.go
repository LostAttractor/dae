// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestPrepareWithoutScriptsNeedsNoRuntime(t *testing.T) {
	for name, module := range map[string]*Module{
		"empty":    {},
		"rewrite":  {URLRewrites: []URLRewrite{{Type: "reject"}}},
		"dns-host": {DNSHosts: []HostEntry{{}}},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := prepare(t.Context(), Config{
				Store: true, NodePath: filepath.Join(t.TempDir(), "absent-node"),
				MemoryLimit: defaultMemoryLimit, MaxBodySize: defaultMaxBodySize,
				MaxConcurrentScripts: defaultMaxConcurrentScripts, ScriptTimeout: DefaultScriptTimeout,
			}, plugin.Services{Prepared: []*Module{module}, BodyMemory: testBodyMemory}, "test")
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if e.options.Runtime != nil || len(e.Status().Runtimes) != 0 {
				t.Fatal("script-free instance prepared a JavaScript runtime")
			}
		})
	}
}
