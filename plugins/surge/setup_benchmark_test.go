// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

func moduleLoadingFixture(count int, wait func(*http.Request) error) (Config, plugin.Services) {
	conf := Config{}
	for i := range count {
		conf.Modules = append(conf.Modules, ModuleSource{Name: fmt.Sprintf("module-%d", i), Link: fmt.Sprintf("https://modules.example/%d.sgmodule", i)})
	}
	logger := log.New()
	logger.SetOutput(io.Discard)
	return conf, plugin.Services{
		Logger: log.NewEntry(logger),
		PrepareClient: &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if err := wait(req); err != nil {
				return nil, err
			}
			contents := "[Script]\ntest=type=http-request,pattern=.,script-path=script.js\n"
			if strings.HasSuffix(req.URL.Path, ".js") {
				contents = "$done({});"
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(contents)), Request: req}, nil
		})},
	}
}

func BenchmarkPrepareModules(b *testing.B) {
	conf, services := moduleLoadingFixture(12, func(req *http.Request) error {
		timer := time.NewTimer(5 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-req.Context().Done():
			return req.Context().Err()
		}
	})
	b.ReportAllocs()
	for b.Loop() {
		modules, err := prepareModules(b.Context(), conf, services)
		if err != nil {
			b.Fatal(err)
		}
		if len(modules) != len(conf.Modules) {
			b.Fatal(len(modules))
		}
	}
}
