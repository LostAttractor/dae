// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/resource"
)

func TestRequirementExpressions(t *testing.T) {
	env := map[string]string{"SYSTEM": "linux", "LANGUAGE": "zh-CN", "DEVICE_NAME": "router-01"}
	for _, test := range []struct {
		expression string
		want       bool
	}{
		{`SYSTEM='linux'`, true},
		{`SYSTEM='iOS' || SYSTEM='linux' && LANGUAGE='en'`, false},
		{`(SYSTEM='iOS' OR SYSTEM='linux') AND NOT (LANGUAGE='en')`, true},
		{`!(SYSTEM<>'linux') && 20<=100`, true},
		{`'20'<'100'`, false},
		{`LANGUAGE BEGINSWITH 'zh' AND DEVICE_NAME ENDSWITH '01'`, true},
		{`DEVICE_NAME LIKE 'router-??' AND DEVICE_NAME CONTAINS '-'`, true},
		{`DEVICE_NAME MATCHES 'router-[0-9]+'`, true},
		{`CORE_VERSION>=999`, true},
		{`NOT (CORE_VERSION>=999)`, true},
		{`CORE_VERSION>=999 AND SYSTEM='linux'`, true},
		{`CORE_VERSION>=999 OR SYSTEM='iOS'`, false},
		{`SYSTEM='iOS' AND CORE_VERSION>=999`, false},
		{`SYSTEM='linux' OR NOT (CORE_VERSION<20)`, true},
	} {
		got, err := evaluateRequirement(test.expression, env)
		if err != nil || got != test.want {
			t.Errorf("%s: %t %v, want %t", test.expression, got, err, test.want)
		}
	}
	for _, expression := range []string{`CORE_VERSION>=`, `CORE_VERSION INVALID 20`, `SYSTEM='linux' || MISSING=1`, `SYSTEM=`, `(SYSTEM='linux'`, `SYSTEM='linux' extra`, `SYSTEM MATCHES '['`} {
		if _, err := evaluateRequirement(expression, env); err == nil {
			t.Errorf("invalid/unsupported expression accepted: %s", expression)
		}
	}
}

func BenchmarkRequirementExpressions(b *testing.B) {
	env := map[string]string{"SYSTEM": "linux", "LANGUAGE": "zh-CN"}
	const expression = `CORE_VERSION>=20 AND (SYSTEM='linux' OR SYSTEM='iOS') AND NOT LANGUAGE='en'`
	b.ReportAllocs()
	for b.Loop() {
		matched, err := evaluateRequirement(expression, env)
		if err != nil || !matched {
			b.Fatalf("requirement: %t, %v", matched, err)
		}
	}
}

func TestModuleConditionalLinesAndComments(t *testing.T) {
	module, err := Parse(`[MITM] // hosts
hostname = example.com # comment
[Script]
// ordinary comment
#!REQUIREMENT SYSTEM='linux' request=type=http-request,pattern=.,script-path=https://example.com/a.js # comment
response=type=http-response,pattern=.,script-path=b.js //!REQUIREMENT SYSTEM='iOS'
[Rule]
DOMAIN,mac.example,REJECT #!MACOS-ONLY
DOMAIN,ios.example,REJECT #!REQUIREMENT SYSTEM='iOS'
#!REQUIREMENT "SYSTEM='linux' AND LANGUAGE!='never'" DOMAIN,linux.example,DIRECT
DOMAIN,unknown.example,REJECT #!REQUIREMENT MISSING>=20
[Map Local]
. data-type=text data="keep # ; // inside" # comment
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(module.Scripts) != 1 || module.Scripts[0].Path != "https://example.com/a.js" || len(module.Rules) != 1 || module.Rules[0].Policy != "DIRECT" {
		t.Fatalf("conditions changed effective declarations: %+v", module)
	}
	if len(module.Hostnames) != 1 || module.Hostnames[0] != "example.com" || string(module.MapLocals[0].Body) != "keep # ; // inside" {
		t.Fatalf("comments corrupted directive values: %+v", module)
	}
	if !strings.Contains(strings.Join(module.Warnings, "\n"), `unsupported variable "MISSING"`) {
		t.Fatalf("unsupported condition not reported: %v", module.Warnings)
	}
}

func TestDisabledModuleDoesNotLoadDependencies(t *testing.T) {
	for _, condition := range []string{"#!system=ios", "#!requirement=SYSTEM='macOS'", "#!requirement=MISSING>=20"} {
		module, err := loadModuleContents(t.Context(), condition+`
#!arguments=required
[MITM]
hostname = {{{required}}}
[Script]
script=type=generic,script-path=missing.js
`, "/module.sgmodule", nil, func(resource.Source, *time.Duration) (string, error) {
			t.Fatal("disabled module loaded a dependency")
			return "", nil
		})
		if err != nil || module.Status().State != "disabled" || len(module.Hostnames)+len(module.TaskScripts) != 0 {
			t.Fatalf("disabled module: %+v, %v", module, err)
		}
	}
}
