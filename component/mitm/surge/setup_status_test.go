// SPDX-License-Identifier: AGPL-3.0-only
package surge

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

func TestLoadHostModuleWithoutCA(t *testing.T) {
	dir := t.TempDir()
	const source = `[General]
use-local-host-item-for-proxy = true
[Host]
192.0.2.1 = 198.51.100.1,198.51.100.2
`
	path := filepath.Join(dir, "host.sgmodule")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	conf := Config{
		Modules:       []ModuleSource{{Link: "file://" + path}},
		ScriptTimeout: time.Second, MemoryLimit: 16 << 20, MaxBodySize: 1 << 20, MaxConcurrentScripts: 1,
	}
	engine, err := prepare(t.Context(), conf, plugin.Services{BodyMemory: testBodyMemory, BaseDir: dir, PrepareClient: http.DefaultClient, Logger: log.NewEntry(log.StandardLogger())}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if engine.Status().Modules[0].HostMappings != 1 || len(engine.Plan().Destinations) != 1 || len(engine.Status().Modules[0].Warnings) != 0 {
		t.Fatalf("Host-only module failed to load or display mappings: %+v", engine.Status())
	}
	mitmPath := filepath.Join(dir, "mitm.sgmodule")
	if err := os.WriteFile(mitmPath, []byte(source+"\n[MITM]\nhostname=example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conf.Modules[0].Link = "file://" + mitmPath
	engine, err = prepare(t.Context(), conf, plugin.Services{BodyMemory: testBodyMemory, BaseDir: dir, PrepareClient: http.DefaultClient, Logger: log.NewEntry(log.StandardLogger())}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "surge", Plugin: engine}); err == nil || !strings.Contains(err.Error(), "ca_cert") {
		t.Fatalf("MITM must still require a CA: %v", err)
	}
}

func TestLoadDNSHostWithoutCompatibilityWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.sgmodule")
	if err := os.WriteFile(path, []byte("[Host]\nexample.com = 192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	logger := log.New()
	logger.SetOutput(&output)
	conf := Config{
		Modules:       []ModuleSource{{Name: "host-compatibility", Link: "file://" + path}},
		ScriptTimeout: time.Second, MemoryLimit: 16 << 20, MaxBodySize: 1 << 20, MaxConcurrentScripts: 1,
	}
	engine, err := prepare(t.Context(), conf, plugin.Services{BodyMemory: testBodyMemory, BaseDir: dir, PrepareClient: http.DefaultClient, Logger: log.NewEntry(logger)}, "test")
	if err != nil {
		t.Fatal(err)
	}
	status := engine.Status().Modules[0]
	if status.HostMappings != 1 || len(engine.Plan().Destinations) != 0 || len(engine.Plan().DNS) != 1 || len(status.Warnings) != 0 {
		t.Fatalf("DNS Host plan: %+v", status)
	}
	if strings.Contains(output.String(), "level=warning") {
		t.Fatalf("supported Host emitted a warning: %s", output.String())
	}
}

func TestLoadSurgeTraceParametersAndFailureSummary(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := mitmca.Generate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), "status test", time.Hour); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"module.sgmodule": `[MITM]
hostname=example.test
[Script]
test=type=http-request,pattern=.,script-path=test.js,script-update-interval=bad,debug=bad,enable=false,full-header-mode=bad,unknown-option=true
`,
		"test.js": `$done({});`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	conf := Config{
		Modules:       []ModuleSource{{Name: "ready", Link: "file:module.sgmodule"}},
		ScriptTimeout: time.Second, MemoryLimit: 16 << 20,
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 1,
	}
	logger := log.StandardLogger()
	oldOutput, oldLevel, oldFormatter := logger.Out, logger.GetLevel(), logger.Formatter
	t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetLevel(oldLevel); logger.SetFormatter(oldFormatter) })
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.TextFormatter{DisableQuote: true, DisableTimestamp: true})
	for _, level := range []log.Level{log.InfoLevel, log.TraceLevel} {
		output.Reset()
		logger.SetLevel(level)
		engine, err := prepare(context.Background(), conf, plugin.Services{BodyMemory: testBodyMemory, BaseDir: dir, PrepareClient: http.DefaultClient, Logger: log.NewEntry(log.StandardLogger())}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if status := engine.Status(); len(status.Modules) != 1 || status.Modules[0].Scripts != 1 || len(status.Modules[0].Warnings) != 1 {
			t.Fatalf("ignored options changed loading or warnings: %+v", status)
		}
		for _, parameter := range []string{"script-update-interval", "debug", "enable", "full-header-mode"} {
			if got := strings.Contains(output.String(), `parameter "`+parameter+`"`); got != (level == log.TraceLevel) {
				t.Errorf("%s diagnostic at %s: %s", parameter, level, output.String())
			}
		}
		if !strings.Contains(output.String(), "unknown-option") {
			t.Fatalf("unknown option warning disappeared: %s", output.String())
		}
		output.Reset()
		engine.traceRequest(httptest.NewRequest(http.MethodGet, "http://example.test/", nil), "request_begin")
		if got := strings.Contains(output.String(), "request_begin"); got != (level == log.TraceLevel) {
			t.Fatalf("automatic request events at %s: %s", level, output.String())
		}
	}
	output.Reset()
	logger.SetLevel(log.DebugLevel)
	conf.Modules = append(conf.Modules,
		ModuleSource{Name: "broken", Link: "file:missing.sgmodule"},
		ModuleSource{Name: "later", Link: "file:module.sgmodule"},
	)
	if _, err := prepare(context.Background(), conf, plugin.Services{BodyMemory: testBodyMemory, BaseDir: dir, PrepareClient: http.DefaultClient, Logger: log.NewEntry(log.StandardLogger())}, "test"); err == nil {
		t.Fatal("missing module did not fail loading")
	}
	for _, want := range []string{"Surge module load status", "ready", "loaded", "broken", "failed", "later", "not loaded"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("failure summary missing %q:\n%s", want, output.String())
		}
	}
}
