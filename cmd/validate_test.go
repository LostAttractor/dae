// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestValidateUsesStartupChecks(t *testing.T) {
	for _, test := range []struct {
		name, global, sections, wantError string
		preflightError                    bool
	}{
		{name: "unknown plugin", sections: `plugins { absent {} }`, wantError: "not compiled"},
		{name: "plugin settings", sections: `plugins { fixture { unknown: private-value } }`, wantError: "unknown setting"},
		{name: "invalid target", global: `api_port: 2023 api_mitm_test_ipv4: invalid`, sections: `mitm { enabled: true }`, wantError: "api_mitm_test_ipv4"},
		{name: "unpaired certificate", sections: `certificate { ca_cert: absent.pem }`, wantError: "configured together"},
		{name: "runtime preflight", sections: `plugins { fixture {} }`, preflightError: true, wantError: "runtime unavailable"},
		{name: "valid", global: `api_port: 2023`, sections: `mitm { enabled: true } plugins { fixture {} }`},
		{name: "disabled plugin", sections: `plugins { absent { enabled: false } }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", cache)
			path := filepath.Join(t.TempDir(), "config.dae")
			content := "global { " + test.global + " }\nrouting { fallback: direct }\n" + test.sections
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			definitions := map[string]plugin.Definition{"fixture": {
				Configure: func(spec plugin.Spec) (plugin.Factory, error) {
					err := plugin.DecodeSettings(spec.Config, &struct{}{})
					return func(context.Context, plugin.Services) (plugin.Plugin, error) {
						t.Error("validation prepared plugin resources")
						return nil, nil
					}, err
				},
				Preflight: func(context.Context, plugin.Spec) error {
					if test.preflightError {
						return errors.New("runtime unavailable")
					}
					return nil
				},
			}}
			command := newValidateCommand(definitions)
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs([]string{"--config", path})
			err := command.ExecuteContext(t.Context())
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("want error containing %q without configuration values, got %v", test.wantError, err)
			}
			if entries, err := os.ReadDir(cache); err != nil || len(entries) != 0 {
				t.Fatalf("validation wrote daemon resources: %v, %v", entries, err)
			}
		})
	}
}
