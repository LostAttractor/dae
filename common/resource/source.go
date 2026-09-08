// SPDX-License-Identifier: AGPL-3.0-only

// Package resource resolves and reads configured HTTP and local file sources.
// Content validation and persistent cache management belong to its callers.
package resource

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Source struct {
	// Location is an HTTP(S) URL without a fragment, or an absolute file path.
	Location string
	// Persistent records the -file suffix; it does not change how Read works.
	Persistent bool
	// Relative records whether a local source was declared with a relative path.
	Relative bool
}

func (s Source) Remote() bool {
	return strings.HasPrefix(s.Location, "http://") || strings.HasPrefix(s.Location, "https://")
}

func supportedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "http-file", "https-file", "file":
		return true
	default:
		return false
	}
}

// Split separates an optional name from a source. A supported source after the
// first colon takes precedence, allowing names such as "file" and "http";
// otherwise file:relative remains an unnamed local source.
func Split(raw string) (name, link string) {
	before, after, found := strings.Cut(raw, ":")
	if !found || strings.HasPrefix(after, "//") {
		return "", raw
	}
	if scheme, _, found := strings.Cut(after, ":"); found && supportedScheme(scheme) {
		return before, after
	}
	if supportedScheme(before) {
		return "", raw
	}
	return before, after
}

// Parse accepts explicit HTTP(S), HTTP(S)-file and file: sources. Relative file
// paths use baseDir; bare paths and file URLs with an authority are rejected.
func Parse(raw, baseDir string) (Source, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Source{}, fmt.Errorf("invalid resource source: %w", RedactError(err))
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "http-file", "https-file":
		if u.Opaque != "" || u.Hostname() == "" {
			return Source{}, errors.New("HTTP resource URL requires // and a host")
		}
		persistent := strings.HasSuffix(u.Scheme, "-file")
		u.Scheme = strings.TrimSuffix(u.Scheme, "-file")
		u.Fragment, u.RawFragment = "", ""
		return Source{Location: u.String(), Persistent: persistent}, nil
	case "file":
		if u.Host != "" || u.User != nil {
			return Source{}, errors.New("file resource URL cannot have a host or user information; use file:relative/path or file:///absolute/path")
		}
		if u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
			return Source{}, errors.New("file resource URL cannot have a query or fragment")
		}
		path := u.Path
		if u.Opaque != "" {
			path, err = url.PathUnescape(u.Opaque)
			if err != nil {
				return Source{}, fmt.Errorf("invalid file resource path: %w", err)
			}
		}
		if path == "" || strings.ContainsRune(path, 0) {
			return Source{}, errors.New("file resource URL requires a nonempty path without NUL bytes")
		}
		relative := !filepath.IsAbs(path)
		if relative {
			path = filepath.Join(baseDir, path)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return Source{}, err
		}
		return Source{Location: path, Relative: relative}, nil
	default:
		return Source{}, errors.New("resource source must use http://, https://, http-file://, https-file://, file:relative/path or file:///absolute/path")
	}
}

// Resolve resolves a module dependency against its final URL or absolute local
// path. A remote module can never introduce a local file dependency.
func Resolve(baseLocation, reference string) (Source, error) {
	base := Source{Location: baseLocation}
	if base.Remote() {
		if strings.Contains(reference, "\\") {
			return Source{}, errors.New("remote resource references cannot contain backslashes")
		}
		baseURL, err := url.Parse(baseLocation)
		if err != nil {
			return Source{}, RedactError(err)
		}
		ref, err := url.Parse(reference)
		if err != nil {
			return Source{}, RedactError(err)
		}
		var resolved Source
		if ref.Scheme != "" {
			resolved, err = Parse(reference, "")
		} else {
			resolved, err = Parse(baseURL.ResolveReference(ref).String(), "")
		}
		if err != nil {
			return Source{}, err
		}
		if !resolved.Remote() {
			return Source{}, errors.New("remote resource references cannot read local files")
		}
		if baseURL.Scheme == "https" && !strings.HasPrefix(resolved.Location, "https://") {
			return Source{}, errors.New("HTTPS resource references cannot downgrade to HTTP")
		}
		return resolved, nil
	}
	if !filepath.IsAbs(baseLocation) {
		return Source{}, errors.New("local resource base must be an absolute path")
	}
	ref, err := url.Parse(reference)
	if err != nil {
		return Source{}, RedactError(err)
	}
	if ref.Scheme != "" {
		return Parse(reference, filepath.Dir(baseLocation))
	}
	if reference == "" || filepath.IsAbs(reference) {
		return Source{}, errors.New("local resource references require a relative path or an explicit source URL")
	}
	return Source{Location: filepath.Join(filepath.Dir(baseLocation), reference), Relative: true}, nil
}

// RedactURL hides remote credentials, path tokens, queries and fragments while
// keeping local paths visible in filesystem diagnostics.
func RedactURL(raw string) string {
	name, link := Split(raw)
	u, err := url.Parse(link)
	redacted := "<invalid>"
	if err == nil {
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "http-file", "https-file":
			redacted = u.Scheme + "://" + u.Host
		case "file":
			u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
			redacted = u.String()
		}
	}
	if name != "" {
		return name + ":" + redacted
	}
	return redacted
}

var remoteURLPattern = regexp.MustCompile(`(?i)https?(?:-file)?://(?:\\.|[^\s"<>])+`)

// RedactText removes remote URL secrets from a diagnostic message.
func RedactText(message string) string {
	return remoteURLPattern.ReplaceAllStringFunc(message, RedactURL)
}

type redactedError struct {
	message string
	cause   error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

// RedactError keeps error identity for errors.Is/As while removing remote URL
// secrets from its printable message, including nested transport errors.
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	// url.Error quotes the full URL, which can contain spaces or escaped
	// quotes. Redact that complete value before scanning ordinary message text.
	var redactURLs func(error)
	redactURLs = func(cause error) {
		if urlErr, ok := cause.(*url.Error); ok {
			message = strings.ReplaceAll(message, strconv.Quote(urlErr.URL), strconv.Quote(RedactURL(urlErr.URL)))
		}
		switch wrapped := cause.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapped.Unwrap() {
				redactURLs(child)
			}
		case interface{ Unwrap() error }:
			redactURLs(wrapped.Unwrap())
		}
	}
	redactURLs(err)
	return &redactedError{
		message: RedactText(message),
		cause:   err,
	}
}
