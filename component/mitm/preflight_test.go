// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestLoadPreflightsEveryInstanceBeforeSetup(t *testing.T) {
	for _, test := range []struct {
		name string
		last plugin.Definition
		want string
	}{
		{name: "unavailable", want: "not compiled"},
		{name: "bad settings", last: plugin.Definition{Validate: func(plugin.Spec) error { return errors.New("bad setting") }}, want: "bad setting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			setup := func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error) {
				calls++
				return &testPlugin{}, nil
			}
			definitions := map[string]plugin.Definition{"first": {Setup: setup}}
			if test.last.Validate != nil {
				test.last.Setup = setup
				definitions["last"] = test.last
			}
			host, err := Load(t.Context(), definitions, []plugin.Spec{{ID: "first", Type: "first"}, {ID: "last", Type: "last"}}, Options{}, plugin.Services{})
			if host != nil {
				host.Close()
				t.Fatal("invalid configuration constructed a host")
			}
			if calls != 0 || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("setup calls=%d error=%v", calls, err)
			}
		})
	}
}
