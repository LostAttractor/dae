// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// These names follow Vite's content-hashed JS/CSS output convention.
var immutableAsset = regexp.MustCompile(`^assets/[^/]+-[A-Za-z0-9_-]{8}\.(js|css)$`)

// serveAsset leaves directories, redirects and missing files to FileServerFS.
func serveAsset(files fs.FS, w http.ResponseWriter, r *http.Request) bool {
	if strings.HasSuffix(r.URL.Path, "/index.html") || (r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/")) {
		return false
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	file, err := files.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	content, ok := file.(io.ReadSeeker)
	if !ok {
		return false
	}

	w.Header().Add("Vary", "Accept-Encoding")
	gzipQuality, identityQuality := encodingQualities(strings.Join(r.Header.Values("Accept-Encoding"), ","))
	compressed := false
	if gzipQuality > 0 && gzipQuality >= identityQuality {
		if zipped, err := files.Open(name + ".gz"); err == nil {
			defer zipped.Close()
			zipInfo, err := zipped.Stat()
			reader, seekable := zipped.(io.ReadSeeker)
			// An external bundle can be edited without restarting dae. Do not
			// serve a sidecar older than its source file.
			if err == nil && zipInfo.Mode().IsRegular() && seekable && !zipInfo.ModTime().Before(info.ModTime()) {
				content = reader
				compressed = true
			}
		}
	}
	if !compressed && identityQuality == 0 {
		http.Error(w, "no acceptable content encoding", http.StatusNotAcceptable)
		return true
	}
	if immutableAsset.MatchString(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		// Both representations have the same decoded content. A weak tag
		// supports revalidation without promising identical compressed bytes.
		w.Header().Set("ETag", `W/"`+path.Base(name)+`"`)
	}
	if compressed {
		w.Header().Set("Content-Encoding", "gzip")
		// ServeContent must infer the media type from the original name,
		// rather than sniffing the compressed bytes.
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)
		// Send the complete compressed representation rather than wrapping
		// compressed ranges in an uncompressed multipart body.
		if r.Header.Get("Range") != "" {
			r = r.Clone(r.Context())
			r.Header.Del("Range")
			r.Header.Del("If-Range")
		}
	}
	http.ServeContent(w, r, name, info.ModTime(), content)
	return true
}

func encodingQualities(header string) (gzip, identity float64) {
	qualities := make(map[string]float64)
	for entry := range strings.SplitSeq(header, ",") {
		coding, params, _ := strings.Cut(entry, ";")
		quality := 1.0
		for param := range strings.SplitSeq(params, ";") {
			key, value, _ := strings.Cut(strings.TrimSpace(param), "=")
			if strings.EqualFold(strings.TrimSpace(key), "q") {
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil || !(parsed >= 0 && parsed <= 1) {
					quality = 0
				} else {
					quality = parsed
				}
			}
		}
		qualities[strings.ToLower(strings.TrimSpace(coding))] = quality
	}
	gzip, present := qualities["gzip"]
	if !present {
		gzip = qualities["*"]
	}
	identity, present = qualities["identity"]
	if !present {
		identity = 1
		if wildcard, exists := qualities["*"]; exists && wildcard == 0 {
			identity = 0
		}
	}
	return gzip, identity
}
