// SPDX-License-Identifier: AGPL-3.0-only
package apiserver

import (
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"
	"sync"
)

// Recording every blocking and contention event costs a few percent of CPU,
// so each runs only while a delta profile of it is captured.
var contentionProfiles = map[string]*profileWindows{
	"/debug/pprof/block": {record: runtime.SetBlockProfileRate},
	"/debug/pprof/mutex": {record: func(rate int) { runtime.SetMutexProfileFraction(rate) }},
}

// profileWindows counts the captures of one profile in progress.
type profileWindows struct {
	mu     sync.Mutex
	active int
	record func(rate int)
}

func (p *profileWindows) open() (done func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active++
	if p.active == 1 {
		p.record(1)
	}
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.active--
		if p.active == 0 {
			p.record(0)
		}
	}
}

var profiles = func() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("POST /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cancellation or server shutdown ends the capture; snapshots do not sample.
		if profile := contentionProfiles[r.URL.Path]; profile != nil && r.FormValue("seconds") != "" {
			defer profile.open()()
		}
		mux.ServeHTTP(w, r)
	})
}()

func monitoringPath(path string) bool {
	return path == "/metrics" || strings.HasPrefix(path, "/debug/pprof/")
}

// PrepareMonitoring authorizes while the server holds the plane lock. The
// returned handler owns only process-lifetime state and runs after unlocking.
func (s *Handler) PrepareMonitoring(w http.ResponseWriter, r *http.Request) (http.Handler, bool) {
	if !monitoringPath(r.URL.Path) {
		return nil, false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !s.prepareRequest(w, r) {
		return nil, true
	}
	if r.Method == http.MethodOptions {
		s.preflight(w, r)
		return nil, true
	}
	policy := accessAdmin
	if r.URL.Path == "/metrics" {
		policy = accessUser
	}
	if _, ok := s.authorize(w, r, policy); !ok {
		return nil, true
	}
	if policy == accessUser && s.options.Metrics != nil {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			apiError(w, 405, "method not allowed")
			return nil, true
		}
		return s.options.Metrics, true
	}
	if policy == accessAdmin && s.options.Pprof {
		return profiles, true
	}
	http.NotFound(w, r)
	return nil, true
}
