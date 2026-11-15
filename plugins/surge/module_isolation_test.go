// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestModuleIsolationRejectsInvalidDescriptors(t *testing.T) {
	for _, setting := range []string{
		"isolate_lan: secret-invalid-value",
		"isolate_lan: name(secret-invalid-value)",
		"isolate_lan: true isolate_lan: false",
		"isolate_lan: true [other: true]",
		"isolate_lan {}",
		"script: value",
		"script {}",
		"script {name: job}",
		"script {isolate_lan: false}",
		"script {name: '' isolate_lan: false}",
		"script {name: '  ' isolate_lan: false}",
		"script {name: job isolate_lan: secret-invalid-value}",
		"script {name: job isolate_lan: true isolate_lan: false}",
		"script {name: job name: other isolate_lan: false}",
		"script {name: job isolate_lan: false unknown: true}",
		"script {name: job isolate_lan: false unknown {}}",
		"script {name: job [other: true] isolate_lan: false}",
		"script {name: name(job) isolate_lan: false}",
		"script {name: job isolate_lan: false} script {name: job isolate_lan: false}",
	} {
		t.Run(setting, func(t *testing.T) {
			sections, err := config_parser.Parse("surge {module {test {link: 'file:test' " + setting + "}}}")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseConfig(sections[0]); err == nil || strings.Contains(err.Error(), "secret-invalid-value") {
				t.Fatalf("invalid descriptor accepted or disclosed its value: %v", err)
			}
		})
	}
	sections, err := config_parser.Parse("surge {module {'file:test'} isolate_lan: invalid}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig(sections[0]); err == nil {
		t.Fatal("accepted invalid instance isolation")
	}
}

func TestModuleIsolationDescriptorRoundTrip(t *testing.T) {
	for _, source := range []ModuleSource{
		{Name: "test", Link: "file:test", IsolateLANSet: true},
		{Name: "test", Link: "file:test", IsolateLAN: true, IsolateLANSet: true},
		{Name: "test", Link: "file:test", ScriptIsolation: map[string]bool{"demo.request": false}},
		{Name: "test", Link: "file:test", IsolateLANSet: true,
			Arguments: map[string]string{"option": "false"}, ScriptIsolation: map[string]bool{
				"中文 脚本": true, `a.'"\`: false, "line\nbreak": true,
			}},
	} {
		formatted, err := FormatModuleSource(source)
		if err != nil {
			t.Fatal(err)
		}
		sections, err := config_parser.Parse("surge {" + formatted + "}")
		if err != nil {
			t.Fatal(err)
		}
		conf, err := ParseConfig(sections[0])
		if err != nil || len(conf.Modules) != 1 || !reflect.DeepEqual(conf.Modules[0], source) {
			t.Fatalf("descriptor changed after formatting: %+v %+v %v\n%s", source, conf, err, formatted)
		}
		again, err := FormatModuleSource(conf.Modules[0])
		if err != nil || formatted != again {
			t.Fatalf("unstable descriptor formatting: %v", err)
		}
	}
	for _, source := range []ModuleSource{
		{Link: "file:test", IsolateLANSet: true},
		{Link: "file:test", ScriptIsolation: map[string]bool{"job": false}},
		{Name: "test", Link: "file:test", ScriptIsolation: map[string]bool{" ": false}},
	} {
		if _, err := FormatModuleSource(source); err == nil {
			t.Fatalf("formatted invalid descriptor: %+v", source)
		}
	}
}

func TestModuleIsolationBindsResolvedScriptNames(t *testing.T) {
	for _, test := range []struct {
		contents, name, wantError string
		arguments                 map[string]string
	}{
		{"[Script]\njob=type=generic,script-path=test.js", "missing", "unknown", nil},
		{"[Script]\njob=type=http-request,pattern=.,script-path=a.js\njob=type=dns,script-path=b.js", "job", "ambiguous", nil},
		{"[Script]\njob=type=http-request,pattern=.,script-path=a.js\njob=type=generic,script-path=b.js", "job", "ambiguous", nil},
		{"[Script]\njob=type=generic,enable=false,script-path=test.js", "job", "unknown", nil},
		{"#!arguments=script:before\n[Script]\n{{{script}}}=type=generic,script-path=test.js", "after", "", map[string]string{"script": "after"}},
		{"#!arguments=script:before\n[Script]\n{{{script}}}=type=generic,script-path=test.js", "before", "unknown", map[string]string{"script": "after"}},
		{"[Script]\n中文 脚本.v1=type=generic,script-path=test.js", "中文 脚本.v1", "", nil},
	} {
		module, err := Parse(test.contents, test.arguments)
		if err != nil {
			t.Fatal(err)
		}
		err = applyModuleIsolation(module, ModuleSource{ScriptIsolation: map[string]bool{test.name: false}})
		if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
			t.Fatalf("name=%q error=%v want=%q", test.name, err, test.wantError)
		}
	}
	duplicate := "[Script]\njob=type=http-request,pattern=.,script-path=a.js\njob=type=dns,script-path=b.js"
	module, err := Parse(duplicate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyModuleIsolation(module, ModuleSource{IsolateLANSet: true}); err != nil {
		t.Fatalf("module policy rejected native duplicate names: %v", err)
	}
	for _, isolated := range []bool{true, false} {
		module, err := Parse("[Script]\njob=type=generic,script-path=test.js", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyModuleIsolation(module, ModuleSource{ScriptIsolation: map[string]bool{"job": isolated}}); err != nil {
			t.Fatal(err)
		}
		if module.TaskScripts[0].IsolateLAN != isolated || !module.TaskScripts[0].IsolateLANSet {
			t.Fatal("same-name script crossed module boundary")
		}
	}
}
