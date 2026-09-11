// SPDX-License-Identifier: AGPL-3.0-only

package surge_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/spf13/cobra"
)

func runSurgeConfigure(input io.Reader, args ...string) (output, prompts string, err error) {
	command := &cobra.Command{Use: "surge"}
	command.AddCommand(surge.Commands(plugin.CommandServices{BaseDir: os.Getenv("DAE_LOCATION_CACHE")})...)
	var stdout, stderr bytes.Buffer
	command.SetIn(input)
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs(append([]string{"configure"}, args...))
	err = command.Execute()
	return stdout.String(), stderr.String(), err
}

func parseSurgeConfigureOutput(t *testing.T, output string) []surge.ModuleSource {
	t.Helper()
	if !strings.HasPrefix(strings.TrimSpace(output), "module {") {
		t.Fatalf("stdout does not start with a module section:\n%s", output)
	}
	sections, err := config_parser.Parse("global {}\nmitm { surge {\n" + output + "\n} }\nrouting { fallback: direct }")
	if err != nil {
		t.Fatalf("generated configuration cannot be parsed: %v\n%s", err, output)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("generated configuration is invalid: %v\n%s", err, output)
	}
	s, err := surge.ParseConfig(conf.MITM.Plugins[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	return s.Modules
}

func TestSurgeConfigureInteractiveArguments(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	t.Chdir(t.TempDir())
	const contents = `#!name=YouTube 参数示例
#!desc=模块说明
#!arguments=屏蔽上传按钮:true,字幕翻译语言:off,空值:original,必填,特殊字符:original
#!arguments-desc=功能设置\n按需要填写。
[MITM]
hostname=example.test
`
	if err := os.WriteFile(filepath.Join(dir, "youtube.sgmodule"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	const source = "file:youtube.sgmodule"
	const specialValue = `  C:\path\file "双引号" '单引号' =,#[]{}  `
	// Defaults, an explicit empty value, a retried required answer, and a final
	// answer without a newline must all retain their distinct meanings.
	input := "\nzh-CN\n\"\"\n\nrequired-value\n" + specialValue
	output, prompts, err := runSurgeConfigure(strings.NewReader(input), source, "--name", "youtube")
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, prompts)
	}
	want := []surge.ModuleSource{{
		Name: "youtube", Link: source,
		Arguments: map[string]string{
			"字幕翻译语言": "zh-CN",
			"空值":     "",
			"必填":     "required-value",
			"特殊字符":   specialValue,
		},
	}}
	if got := parseSurgeConfigureOutput(t, output); !reflect.DeepEqual(got, want) {
		t.Fatalf("configured sources = %#v, want %#v", got, want)
	}
	for _, text := range []string{"YouTube 参数示例", "模块说明", "功能设置\n按需要填写。"} {
		if !strings.Contains(prompts, text) {
			t.Errorf("metadata %q is missing from stderr:\n%s", text, prompts)
		}
	}
	previous := -1
	for _, name := range []string{"屏蔽上传按钮", "字幕翻译语言", "空值", "必填", "特殊字符"} {
		position := strings.Index(prompts, name)
		if position <= previous {
			t.Fatalf("argument %q was not prompted in declaration order:\n%s", name, prompts)
		}
		previous = position
	}
	if strings.Count(prompts, "必填") < 2 {
		t.Fatalf("blank required answer did not produce another prompt:\n%s", prompts)
	}
}

func TestSurgeConfigureWithoutArgumentsUsesAbsoluteSource(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "absent-cache")
	t.Setenv("DAE_LOCATION_CACHE", cacheDir)
	path := filepath.Join(t.TempDir(), "plain.sgmodule")
	if err := os.WriteFile(path, []byte("#!name=Plain module\n[MITM]\nhostname=example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := "file://" + path
	output, prompts, err := runSurgeConfigure(strings.NewReader(""), source, "--name", "plain")
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, prompts)
	}
	want := []surge.ModuleSource{{Name: "plain", Link: source}}
	if got := parseSurgeConfigureOutput(t, output); !reflect.DeepEqual(got, want) {
		t.Fatalf("configured sources = %#v, want %#v", got, want)
	}
	if strings.Contains(output, "arguments {") || strings.Contains(output, "plain {") {
		t.Fatalf("module without arguments did not use the short form:\n%s", output)
	}
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Fatalf("configure created the cache directory: %v", err)
	}
}

func TestSurgeConfigureFetchesOnlyModuleWithoutCaching(t *testing.T) {
	for _, scheme := range []string{"http", "http-file"} {
		t.Run(scheme, func(t *testing.T) {
			cacheDir := filepath.Join(t.TempDir(), "absent-cache")
			t.Setenv("DAE_LOCATION_CACHE", cacheDir)
			var moduleRequests, dependencyRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/module.sgmodule" {
					dependencyRequests.Add(1)
					http.Error(w, "dependencies must not be downloaded", http.StatusInternalServerError)
					return
				}
				moduleRequests.Add(1)
				fmt.Fprint(w, `#!name=Remote module
#!arguments=enabled:true
[Script]
test=type=http-request,pattern=^https://example\.test/,script-path=/script.js
`)
			}))
			defer server.Close()
			source := strings.Replace(server.URL, "http://", scheme+"://", 1) + "/module.sgmodule"
			output, prompts, err := runSurgeConfigure(strings.NewReader("\n"), source, "--name", "remote")
			if err != nil {
				t.Fatalf("configure: %v\n%s", err, prompts)
			}
			want := []surge.ModuleSource{{Name: "remote", Link: source}}
			if strings.Contains(output, "arguments {") || strings.Contains(output, "remote {") {
				t.Fatalf("inherited defaults did not use the short form:\n%s", output)
			}
			if got := parseSurgeConfigureOutput(t, output); !reflect.DeepEqual(got, want) {
				t.Fatalf("configured sources = %#v, want %#v", got, want)
			}
			if moduleRequests.Load() != 1 || dependencyRequests.Load() != 0 {
				t.Fatalf("requests: module=%d, dependencies=%d", moduleRequests.Load(), dependencyRequests.Load())
			}
			if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
				t.Fatalf("configure created the cache directory: %v", err)
			}
		})
	}
}

func TestSurgeConfigureInheritsUpdatedDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	const contents = `#!arguments=language:en
[Script]
test=type=http-response,pattern=.,script-path=test.js,argument={{{language}}}
`
	if err := os.WriteFile(filepath.Join(dir, "module.sgmodule"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, input, want string
	}{
		{name: "inherit", input: "\n", want: "fr"},
		{name: "explicit current default", input: "en\n", want: "en"},
		{name: "explicit empty", input: "\"\"\n", want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, _, err := runSurgeConfigure(strings.NewReader(test.input), "file:module.sgmodule")
			if err != nil {
				t.Fatal(err)
			}
			sources := parseSurgeConfigureOutput(t, output)
			updated := strings.Replace(contents, "language:en", "language:fr", 1)
			module, err := surge.Parse(updated, sources[0].Arguments)
			if err != nil {
				t.Fatal(err)
			}
			if module.Scripts[0].Argument != test.want {
				t.Fatalf("argument after default changed = %q, want %q", module.Scripts[0].Argument, test.want)
			}
		})
	}
}

func TestSurgeConfigureRejectsIncompleteOrInvalidModuleWithoutOutput(t *testing.T) {
	for _, test := range []struct {
		name, contents, input string
	}{
		{name: "empty module"},
		{name: "HTML response", contents: "<!DOCTYPE html><html><body>Unavailable</body></html>"},
		{name: "standalone script", contents: "#!/usr/bin/env node\nconsole.log('test');"},
		{
			name:     "EOF before all answers",
			contents: "#!arguments=first:true,second:false\n[MITM]\nhostname=example.test\n",
			input:    "false\n",
		},
		{
			name:     "invalid module after answers",
			contents: "#!arguments=first:true\n[MITM]\nhostname={{{undeclared}}}\n",
			input:    "\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", dir)
			if err := os.WriteFile(filepath.Join(dir, "test.sgmodule"), []byte(test.contents), 0600); err != nil {
				t.Fatal(err)
			}
			output, prompts, err := runSurgeConfigure(strings.NewReader(test.input), "file:test.sgmodule", "--name", "test")
			if err == nil {
				t.Fatalf("configure succeeded unexpectedly:\n%s\n%s", output, prompts)
			}
			if output != "" {
				t.Fatalf("failed configure wrote to stdout:\n%s", output)
			}
		})
	}
}

func TestSurgeConfigureRejectsInvalidNameBeforeFetch(t *testing.T) {
	output, _, err := runSurgeConfigure(strings.NewReader(""), "file:unused", "--name", "invalid-name")
	if err == nil || !strings.Contains(err.Error(), "--name must start with an ASCII letter") || output != "" {
		t.Fatalf("invalid name: error=%v, stdout=%q", err, output)
	}
}
