// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed index.html style.css app.js
var assets embed.FS

// Handler serves the management page and its static resources.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var file, contentType string
		switch r.URL.Path {
		case "/":
			file, contentType = "index.html", "text/html; charset=utf-8"
		case "/style.css":
			file, contentType = "style.css", "text/css; charset=utf-8"
		case "/app.js":
			file, contentType = "app.js", "text/javascript; charset=utf-8"
		default:
			http.NotFound(w, r)
			return
		}
		body, _ := assets.ReadFile(file)
		w.Header().Set("Content-Type", contentType)
		http.ServeContent(w, r, file, time.Time{}, bytes.NewReader(body))
	})
}
