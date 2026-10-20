//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/plugins/surge"
)

func TestScriptRuntimeFailureRejectsPreparation(t *testing.T) {
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
			for name, contents := range map[string]string{
				"local.sgmodule": "[Script]\ncheck=type=dns,pattern=.,script-path=local.js\n",
				"local.js":       "$done({});",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			conf := mitmConfigForTest(t, `plugins { surge { `+setting+` module { 'file:local.sgmodule' } } }`)
			host, err := loadTestMITM(t.Context(), conf, http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
			if host != nil {
				host.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("script runtime failure did not reject preparation: %v", err)
			}
		})
	}
}

func TestScriptFreeModuleWithoutNode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	t.Setenv("PATH", t.TempDir())
	if err := os.WriteFile(filepath.Join(dir, "local.sgmodule"), []byte("[Host]\nexample.test = 192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conf := mitmConfigForTest(t, fmt.Sprintf(`plugins { surge { node_path:'%s' module { 'file:local.sgmodule' } } }`, filepath.Join(dir, "absent-node")))
	definitions := map[string]plugin.Definition{"surge": surge.Plugin}
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		t.Fatal(err)
	}
	if err := plugins.Preflight(t.Context()); err != nil {
		t.Fatal(err)
	}
	host, err := loadTestMITM(t.Context(), conf, http.DefaultClient, http.DefaultClient, definitions)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
}
