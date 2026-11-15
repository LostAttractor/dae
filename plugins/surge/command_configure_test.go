// SPDX-License-Identifier: AGPL-3.0-only

package surge_test

import (
	"bytes"
	"context"
	"errors"
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
	"testing/iotest"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/plugins/surge"
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
	sections, err := config_parser.Parse("global {}\nplugins { surge {\n" + output + "\n} }\nrouting { fallback: direct }")
	if err != nil {
		t.Fatalf("generated configuration cannot be parsed: %v\n%s", err, output)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("generated configuration is invalid: %v\n%s", err, output)
	}
	s, err := surge.ParseConfig(conf.Plugins[0].Config)
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

func TestSurgeConfigureFetchesScriptsWithoutCaching(t *testing.T) {
	for _, scheme := range []string{"http"} {
		t.Run(scheme, func(t *testing.T) {
			cacheDir := filepath.Join(t.TempDir(), "absent-cache")
			t.Setenv("DAE_LOCATION_CACHE", cacheDir)
			var moduleRequests, dependencyRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/script.js" {
					dependencyRequests.Add(1)
					fmt.Fprint(w, `$done({});`)
					return
				}
				if r.URL.Path != "/module.sgmodule" {
					t.Errorf("unexpected resource request: %s", r.URL.Path)
					http.NotFound(w, r)
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
			if moduleRequests.Load() != 1 || dependencyRequests.Load() != 1 {
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
	if err := os.WriteFile(filepath.Join(dir, "test.js"), []byte(`$done({});`), 0600); err != nil {
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

func configureModuleFile(t *testing.T, contents string, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, source := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "module.sgmodule")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return "file:" + path
}

func TestSurgeConfigureStorageIsolation(t *testing.T) {
	source := configureModuleFile(t, `[Script]
plain=type=http-request,pattern=.,script-path=plain.js
reader=type=dns,script-path=reader.js
writer=type=generic,script-path=writer.js
`, map[string]string{
		"plain.js":  `$done({});`,
		"reader.js": `$persistentStore.read("key"); var $persistentStore; $persistentStore.read("key"); $done({});`,
		"writer.js": `$persistentStore.write("value", "key"); $done();`,
	})
	output, prompts, err := runSurgeConfigure(strings.NewReader("share\nlist\n1\nisolate\n2\nshare\n\n"), source)
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, prompts)
	}
	want := []surge.ModuleSource{{Name: "module", Link: source, IsolateLANSet: true, ScriptIsolation: map[string]bool{"reader": true, "writer": false}}}
	if got := parseSurgeConfigureOutput(t, output); !reflect.DeepEqual(got, want) {
		t.Fatalf("isolation = %#v, want %#v", got, want)
	}
	if !strings.Contains(prompts, `1  "reader" (dns)`) || !strings.Contains(prompts, `2  "writer" (generic)`) || strings.Contains(prompts, `"plain" (http-request)`) {
		t.Fatalf("storage-only script selection: %s", prompts)
	}
	if strings.Count(prompts, "Warning: sharing") != 1 || strings.Contains(output, "Warning:") {
		t.Fatalf("sharing warning must appear once on stderr: %s\n%s", prompts, output)
	}
}

func TestSurgeConfigureIsolationChoices(t *testing.T) {
	for _, test := range []struct {
		name, input  string
		isolate, set bool
		scripts      map[string]bool
	}{
		{"inherit", "\n\n", false, false, nil},
		{"module isolate", "isolate\n\n", true, true, nil},
		{"module share", "share\n\n", false, true, nil},
		{"script share", "\n1\nshare\n\n", false, false, map[string]bool{"job": false}},
		{"explicit same value", "isolate\n1\nisolate\n\n", true, true, map[string]bool{"job": true}},
		{"keep script value", "share\n1\nisolate\n1\n\n\n", false, true, map[string]bool{"job": true}},
		{"remove override", "\n1\nshare\n1\ninherit\n\n", false, false, nil},
		{"retry", "wrong\ninherit\n0\n99\nwrong\n1\nwrong\nshare\n\n", false, false, map[string]bool{"job": false}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := configureModuleFile(t, "[Script]\njob=type=generic,script-path=job.js", map[string]string{"job.js": `$persistentStore.read("key");`})
			output, prompts, err := runSurgeConfigure(strings.NewReader(test.input), source)
			if err != nil {
				t.Fatalf("configure: %v\n%s", err, prompts)
			}
			want := []surge.ModuleSource{{Name: "module", Link: source, IsolateLAN: test.isolate, IsolateLANSet: test.set, ScriptIsolation: test.scripts}}
			if got := parseSurgeConfigureOutput(t, output); !reflect.DeepEqual(got, want) {
				t.Fatalf("configured isolation = %#v, want %#v", got, want)
			}
			if !test.set && len(test.scripts) == 0 && strings.Contains(output, "module {\n  module {") {
				t.Fatalf("inherited settings did not use shorthand: %s", output)
			}
		})
	}
}

func TestSurgeConfigureSkipsUnconfirmedStorage(t *testing.T) {
	for _, test := range []struct {
		name, directive, script string
		warning                 bool
	}{
		{"plain", "job=type=generic,script-path=job.js", `$done();`, false},
		{"comment", "job=type=generic,script-path=job.js", `// $persistentStore.read("key");`, false},
		{"string", "job=type=generic,script-path=job.js", `const text = '$persistentStore.write("v", "k")';`, false},
		{"shadowed", "job=type=generic,script-path=job.js", `function f($persistentStore) { $persistentStore.read("key"); }`, false},
		{"alias", "job=type=generic,script-path=job.js", `const s = $persistentStore; s.read("key");`, false},
		{"unsupported storage", "job=type=generic,script-path=job.js", `$prefs.valueForKey("key");`, false},
		{"invalid syntax", "job=type=generic,script-path=job.js", `const = ;`, true},
		{"disabled", "job=type=generic,enable=false,script-path=missing.js", "", false},
		{"condition excluded", "job=type=generic,script-path=missing.js //!REQUIREMENT SYSTEM='iOS'", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := configureModuleFile(t, "[Script]\n"+test.directive, map[string]string{"job.js": test.script})
			output, prompts, err := runSurgeConfigure(strings.NewReader(""), source)
			if err != nil {
				t.Fatalf("configure: %v\n%s", err, prompts)
			}
			if strings.Contains(prompts, "Module isolation [") || strings.Contains(prompts, "Script override [") || strings.Contains(output, "isolate_lan") {
				t.Fatalf("unconfirmed script prompted for isolation: %s\n%s", prompts, output)
			}
			if strings.Contains(prompts, "could not be analyzed") != test.warning {
				t.Fatalf("analysis warning mismatch: %s", prompts)
			}
			if got := parseSurgeConfigureOutput(t, output); !reflect.DeepEqual(got, []surge.ModuleSource{{Name: "module", Link: source}}) {
				t.Fatalf("unconfirmed script changed defaults: %#v", got)
			}
		})
	}
}

func TestSurgeConfigureIsolationUsesResolvedNames(t *testing.T) {
	source := configureModuleFile(t, "#!arguments=name:before,value:original\n[Script]\n{{{name}}}=type=generic,script-path=job.js,argument={{{value}}}", map[string]string{"job.js": `$persistentStore.read("key");`})
	name := `quoted "name"`
	output, prompts, err := runSurgeConfigure(strings.NewReader(name+"\ncancel\ninherit\nlist\n1\nshare\n\n"), source)
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, prompts)
	}
	got := parseSurgeConfigureOutput(t, output)[0]
	if !reflect.DeepEqual(got.ScriptIsolation, map[string]bool{name: false}) || got.Arguments["name"] != name || got.Arguments["value"] != "cancel" {
		t.Fatalf("resolved arguments or script name changed: %#v", got)
	}
}

func TestSurgeConfigureIsolationDoesNotHideNameAmbiguity(t *testing.T) {
	source := configureModuleFile(t, `[Script]
dup=type=http-request,pattern=.,script-path=storage.js
dup=type=generic,script-path=plain.js
unique=type=cron,cronexp="0 * * * *",script-path=storage.js
`, map[string]string{"storage.js": `$persistentStore.read("key");`, "plain.js": `$done();`})
	output, prompts, err := runSurgeConfigure(strings.NewReader("\nlist\n1\n2\nshare\n\n"), source)
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, prompts)
	}
	if !strings.Contains(prompts, "ambiguous") || !reflect.DeepEqual(parseSurgeConfigureOutput(t, output)[0].ScriptIsolation, map[string]bool{"unique": false}) {
		t.Fatalf("filtered directory lost name ambiguity: %s\n%s", prompts, output)
	}
	for _, kind := range []string{"dns", "generic"} {
		t.Run(kind, func(t *testing.T) {
			source := configureModuleFile(t, "[Script]\ndup=type=http-request,pattern=.,script-path=storage.js\ndup=type="+kind+",script-path=storage.js", map[string]string{"storage.js": `$persistentStore.read("key");`})
			output, prompts, err := runSurgeConfigure(strings.NewReader("share"), source)
			if err != nil {
				t.Fatalf("configure: %v\n%s", err, prompts)
			}
			got := parseSurgeConfigureOutput(t, output)[0]
			if !got.IsolateLANSet || got.IsolateLAN || len(got.ScriptIsolation) != 0 || strings.Contains(prompts, "Script override [") {
				t.Fatalf("ambiguous scripts did not retain module-only policy: %#v\n%s", got, prompts)
			}
		})
	}
}

func TestSurgeConfigureIsolationFailureHasNoOutput(t *testing.T) {
	source := configureModuleFile(t, "[Script]\njob=type=generic,script-path=job.js", map[string]string{"job.js": `$persistentStore.read("key");`})
	for _, input := range []string{"", "\n", "\n1\n", "cancel", "\ncancel", "\n1\ncancel", "bad\n", "\n1\nbad\n"} {
		t.Run(fmt.Sprintf("input=%q", input), func(t *testing.T) {
			output, _, err := runSurgeConfigure(strings.NewReader(input), source)
			if err == nil || output != "" {
				t.Fatalf("incomplete isolation accepted: output=%q error=%v", output, err)
			}
		})
	}
	readErr := fmt.Errorf("injected input failure")
	output, _, err := runSurgeConfigure(iotest.ErrReader(readErr), source)
	if !errors.Is(err, readErr) || output != "" {
		t.Fatalf("input error was hidden: output=%q error=%v", output, err)
	}
}

func TestSurgeConfigureScriptResourcesUseFinalLocationAndDeduplicate(t *testing.T) {
	var scripts, other atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/module.sgmodule":
			http.Redirect(w, r, "/nested/module.sgmodule", http.StatusFound)
		case "/nested/module.sgmodule":
			fmt.Fprint(w, `[Script]
a=type=http-request,pattern=.,script-path=script.js
b=type=generic,script-path=script.js
[Map Local]
. data-type=file data=unrequested.json
`)
		case "/nested/script.js":
			scripts.Add(1)
			fmt.Fprint(w, `$persistentStore.read("key");`)
		default:
			other.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	output, prompts, err := runSurgeConfigure(strings.NewReader("\nlist\n\n"), server.URL+"/module.sgmodule")
	if err != nil {
		t.Fatalf("configure: %v\n%s", err, prompts)
	}
	if scripts.Load() != 1 || other.Load() != 0 || !strings.Contains(prompts, `"a"`) || !strings.Contains(prompts, `"b"`) {
		t.Fatalf("unexpected dependency requests or directory: scripts=%d other=%d\n%s", scripts.Load(), other.Load(), prompts)
	}
	if got := parseSurgeConfigureOutput(t, output)[0]; got.Link != server.URL+"/module.sgmodule" || got.IsolateLANSet {
		t.Fatalf("redirect replaced source or inheritance: %#v", got)
	}
}

func TestSurgeConfigureScriptReadFailureHasNoOutput(t *testing.T) {
	for _, failure := range []string{"missing", "HTML", "too large", "local reference"} {
		t.Run(failure, func(t *testing.T) {
			var scriptRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/module.sgmodule" {
					path := "script.js"
					if failure == "local reference" {
						path = "file:script.js"
					}
					fmt.Fprintf(w, "[Script]\njob=type=generic,script-path=%s", path)
					return
				}
				scriptRequests.Add(1)
				switch failure {
				case "HTML":
					fmt.Fprint(w, "<!DOCTYPE html><html><body>Not a script</body></html>")
				case "too large":
					w.Header().Set("Content-Length", fmt.Sprint(surge.MaxScriptBytes+1))
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			output, _, err := runSurgeConfigure(strings.NewReader(""), server.URL+"/module.sgmodule")
			if err == nil || output != "" || failure == "local reference" && scriptRequests.Load() != 0 {
				t.Fatalf("read failure accepted: requests=%d output=%q error=%v", scriptRequests.Load(), output, err)
			}
		})
	}
}

func TestSurgeConfigureScriptReadCancellation(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/module.sgmodule" {
			fmt.Fprint(w, "[Script]\njob=type=generic,script-path=script.js")
			return
		}
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := &cobra.Command{Use: "surge"}
	command.AddCommand(surge.Commands(plugin.CommandServices{})...)
	var output, prompts bytes.Buffer
	command.SetIn(strings.NewReader(""))
	command.SetOut(&output)
	command.SetErr(&prompts)
	command.SetArgs([]string{"configure", server.URL + "/module.sgmodule"})
	result := make(chan error, 1)
	go func() { result <- command.ExecuteContext(ctx) }()
	select {
	case <-entered:
		cancel()
	case <-ctx.Done():
		t.Fatal("script request did not start")
	}
	if err := <-result; !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("canceled read: output=%q error=%v", output.String(), err)
	}
}

func TestSurgeConfigureRejectsInvalidNameBeforeFetch(t *testing.T) {
	output, _, err := runSurgeConfigure(strings.NewReader(""), "file:unused", "--name", "invalid-name")
	if err == nil || !strings.Contains(err.Error(), "--name must start with an ASCII letter") || output != "" {
		t.Fatalf("invalid name: error=%v, stdout=%q", err, output)
	}
}
