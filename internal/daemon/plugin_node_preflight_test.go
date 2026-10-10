//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestNodeRuntimePreflightBeforeStartup(t *testing.T) {
	for _, test := range []struct {
		name, contents, want string
		mode                 os.FileMode
	}{
		{name: "missing from PATH", want: "find executable"},
		{name: "missing configured path", want: "find executable"},
		{name: "not executable", contents: "unused", mode: 0600, want: "find executable"},
		{name: "unsupported runtime", contents: "#!/bin/sh\nprintf 'unsupported Node option' >&2\nexit 1\n", mode: 0700, want: "Node.js 22.13+"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir, bin := t.TempDir(), t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", dir)
			t.Setenv("PATH", bin)
			path := filepath.Join(bin, "custom-node")
			if test.contents != "" {
				if err := os.WriteFile(path, []byte(test.contents), test.mode); err != nil {
					t.Fatal(err)
				}
			}
			var setting string
			if test.name != "missing from PATH" {
				setting = fmt.Sprintf("node_path: '%s'", path)
			}
			conf := mitmConfigForTest(t, `mitm { enabled:true ca_cert:absent.pem ca_key:absent.key }
plugins { surge { `+setting+` module { 'https://invalid.example/module' } } }`)
			err := Run(conf, nil, map[string]plugin.Definition{"surge": surge.Plugin}, &netutils.InternalResolver{}, Options{})
			if err == nil || !strings.Contains(err.Error(), "plugins.surge preflight") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startup did not reject Node.js before kernel and resource preparation: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("Node.js preflight wrote resource files: %v %v", entries, err)
			}
		})
	}
}

func TestNodeRuntimePreflightUsesConfiguredPath(t *testing.T) {
	path, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	conf := mitmConfigForTest(t, fmt.Sprintf(`plugins { surge { node_path: '%s' module { 'file:absent.sgmodule' } } }`, path))
	plugins, err := configurePlugins(conf, map[string]plugin.Definition{"surge": surge.Plugin})
	if err != nil {
		t.Fatal(err)
	}
	if err := plugins.Preflight(t.Context()); err != nil {
		t.Fatalf("configured Node.js path should work without PATH lookup or module loading: %v", err)
	}
}
