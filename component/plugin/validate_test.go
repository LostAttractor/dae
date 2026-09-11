// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateSpecsChecksTypesBeforeValidators(t *testing.T) {
	called := false
	definitions := map[string]Definition{
		"known": {
			Setup:    func(context.Context, Spec, Services) (Plugin, error) { t.Fatal("preflight ran setup"); return nil, nil },
			Validate: func(Spec) error { called = true; return nil },
		},
		"incomplete": {},
	}
	err := ValidateSpecs(definitions, []Spec{{ID: "first", Type: "known"}, {ID: "missing", Type: "unavailable"}, {ID: "nil_setup", Type: "incomplete"}})
	if err == nil || called || !strings.Contains(err.Error(), "plugins.missing") || !strings.Contains(err.Error(), "plugins.nil_setup") {
		t.Fatalf("type preflight: called=%v error=%v", called, err)
	}
}

func TestValidateSpecsReportsInstanceErrorsWithoutSetup(t *testing.T) {
	invalid := errors.New("invalid configuration")
	var order []string
	setup := func(context.Context, Spec, Services) (Plugin, error) { t.Fatal("preflight ran setup"); return nil, nil }
	definitions := map[string]Definition{
		"checked": {Setup: setup, Validate: func(spec Spec) error { order = append(order, spec.ID); return invalid }},
		"legacy":  {Setup: setup},
	}
	err := ValidateSpecs(definitions, []Spec{{ID: "first", Type: "checked"}, {ID: "middle", Type: "legacy"}, {ID: "last", Type: "checked"}})
	if !errors.Is(err, invalid) || strings.Join(order, ",") != "first,last" || !strings.Contains(err.Error(), "plugins.first") || !strings.Contains(err.Error(), "plugins.last") {
		t.Fatalf("validation: order=%v error=%v", order, err)
	}
	if err := ValidateSpecs(definitions, []Spec{{ID: "legacy", Type: "legacy"}}); err != nil {
		t.Fatal(err)
	}
}
