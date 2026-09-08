// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSourceSyntax(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct {
		raw        string
		location   string
		persistent bool
		relative   bool
	}{
		{"http://example.com/source#fragment", "http://example.com/source", false, false},
		{"https://user:password@example.com/source?token=value#fragment", "https://user:password@example.com/source?token=value", false, false},
		{"http-file://example.com/source", "http://example.com/source", true, false},
		{"https-file://example.com/source", "https://example.com/source", true, false},
		{"HTTPS://example.com/source", "https://example.com/source", false, false},
		{"file:nodes.sub", filepath.Join(dir, "nodes.sub"), false, true},
		{"file:sub/nodes%20with%20spaces%252F.sub", filepath.Join(dir, "sub/nodes with spaces%2F.sub"), false, true},
		{"file:../nodes.sub", filepath.Join(filepath.Dir(dir), "nodes.sub"), false, true},
		{"file:///var/lib/dae/nodes%20with%20spaces.sub", "/var/lib/dae/nodes with spaces.sub", false, false},
		{"file:/var/lib/dae/nodes.sub", "/var/lib/dae/nodes.sub", false, false},
	} {
		t.Run(test.raw, func(t *testing.T) {
			got, err := Parse(test.raw, dir)
			if err != nil {
				t.Fatal(err)
			}
			want := Source{Location: test.location, Persistent: test.persistent, Relative: test.relative}
			if got != want {
				t.Fatalf("Parse() = %#v, want %#v", got, want)
			}
			if got.Remote() != strings.HasPrefix(test.location, "http") {
				t.Fatalf("unexpected Remote() for %#v", got)
			}
		})
	}
	for _, raw := range []string{
		"nodes.sub", "/var/lib/dae/nodes.sub", "//example.com/nodes.sub", "",
		"ftp://example.com/nodes.sub", "https:opaque", "http:///nodes.sub",
		"file://relative/nodes.sub", "file://localhost/nodes.sub", "file://user:password@host/nodes.sub",
		"file:", "file://", "file:relative?query", "file:relative?", "file:relative#fragment", "file:relative#",
		"file:relative%zz", "file:relative%00", "file:///absolute%00",
	} {
		t.Run("reject "+raw, func(t *testing.T) {
			if got, err := Parse(raw, dir); err == nil {
				t.Fatalf("accepted %q as %#v", raw, got)
			}
		})
	}
}

func TestSplitRecognizesOpaqueFileSources(t *testing.T) {
	for _, test := range []struct{ raw, name, link string }{
		{"file:local.sub", "", "file:local.sub"},
		{"file:notes:old.sub", "", "file:notes:old.sub"},
		{"file:./http:notes.sub", "", "file:./http:notes.sub"},
		{"file:http%3Anotes.sub", "", "file:http%3Anotes.sub"},
		{"local:file:local.sub", "local", "file:local.sub"},
		{"local:file:///absolute.sub", "local", "file:///absolute.sub"},
		{"https-file://example.com/sub", "", "https-file://example.com/sub"},
		{"office:https-file://example.com/sub", "office", "https-file://example.com/sub"},
		{"ss://node", "", "ss://node"},
	} {
		name, link := Split(test.raw)
		if name != test.name || link != test.link {
			t.Errorf("Split(%q) = (%q, %q), want (%q, %q)", test.raw, name, link, test.name, test.link)
		}
	}
}

func TestSplitAllowsSourceSchemesAsNames(t *testing.T) {
	for _, wantName := range []string{"file", "http", "https", "http-file", "https-file"} {
		for _, wantLink := range []string{
			"http://example.com/sub", "https://example.com/sub",
			"http-file://example.com/sub", "https-file://example.com/sub",
			"file:nodes.sub", "file:///etc/dae/nodes.sub",
			"https:invalid-opaque", "HTTP://example.com/sub",
		} {
			raw := wantName + ":" + wantLink
			name, link := Split(raw)
			if name != wantName || link != wantLink {
				t.Errorf("Split(%q) = (%q, %q), want (%q, %q)", raw, name, link, wantName, wantLink)
			}
		}
	}
}

func TestResolveDependencies(t *testing.T) {
	for _, test := range []struct {
		base, reference, want string
		persistent            bool
	}{
		{"https://example.com/final/module.sgmodule", "../script.js#name", "https://example.com/script.js", false},
		{"https://example.com/final/module.sgmodule", "/script.js", "https://example.com/script.js", false},
		{"https://example.com/final/module.sgmodule", "//cdn.example/script.js", "https://cdn.example/script.js", false},
		{"http://example.com/module", "https-file://cdn.example/script.js", "https://cdn.example/script.js", true},
		{"http://example.com/module", "http://cdn.example/script.js", "http://cdn.example/script.js", false},
		{"/etc/dae/modules/module.sgmodule", "../script.js", "/etc/dae/script.js", false},
		{"/etc/dae/modules/module.sgmodule", "file:script%20name.js", "/etc/dae/modules/script name.js", false},
		{"/etc/dae/modules/module.sgmodule", "file:///run/dae/script.js", "/run/dae/script.js", false},
		{"/etc/dae/modules/module.sgmodule", "http-file://example.com/script.js", "http://example.com/script.js", true},
	} {
		got, err := Resolve(test.base, test.reference)
		if err != nil || got.Location != test.want || got.Persistent != test.persistent {
			t.Errorf("Resolve(%q, %q) = %#v, %v; want %q persistent=%v", test.base, test.reference, got, err, test.want, test.persistent)
		}
	}
	for _, test := range []struct{ base, reference string }{
		{"https://example.com/module", "http://example.com/script.js"},
		{"https://example.com/module", "http-file://example.com/script.js"},
		{"http://example.com/module", "file:script.js"},
		{"https://example.com/module", "file:///etc/passwd"},
		{"http://example.com/module", `sub\script.js`},
		{"http://example.com/module", "ftp://example.com/script.js"},
		{"/etc/dae/module", "/etc/dae/script.js"},
		{"/etc/dae/module", ""},
		{"module.sgmodule", "script.js"},
	} {
		if got, err := Resolve(test.base, test.reference); err == nil {
			t.Errorf("accepted Resolve(%q, %q) = %#v", test.base, test.reference, got)
		}
	}
}

func TestResourceDiagnosticsRedactRemoteSecrets(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"office:https-file://user:password@example.com:8443/path-token?query-token#fragment", "office:https-file://example.com:8443"},
		{"file:https://user:password@example.com/path-token?query-token#fragment", "file:https://example.com"},
		{"http:https-file://user:password@example.com/path-token?query-token#fragment", "http:https-file://example.com"},
		{"file:file:nodes.sub", "file:file:nodes.sub"},
		{"file:local%20nodes.sub", "file:local%20nodes.sub"},
		{"local:file:///etc/dae/nodes.sub?secret#fragment", "local:file:///etc/dae/nodes.sub"},
	} {
		if got := RedactURL(test.raw); got != test.want {
			t.Errorf("RedactURL(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
	cause := &url.Error{Op: "Get", URL: "https://user:password@example.com/path-token?query-token", Err: context.Canceled}
	err := RedactError(fmt.Errorf("request failed: %w", cause))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("redaction lost error identity: %v", err)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatal("redaction lost wrapped URL error")
	}
	for _, secret := range []string{"user", "password", "path-token", "query-token"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("redacted diagnostic contains %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "request failed:") {
		t.Fatalf("redaction lost surrounding context: %v", err)
	}
	for _, raw := range []string{
		`https://example.com/path'with\"quote-secret?token-secret`,
		"https://example.com/path with space-secret?token-secret",
	} {
		for _, cause := range []error{
			&url.Error{Op: "Get", URL: raw, Err: context.Canceled},
			errors.Join(errors.New("download failed"), fmt.Errorf("mirror: %w", &url.Error{Op: "Get", URL: raw, Err: context.Canceled})),
		} {
			err := RedactError(cause)
			if strings.Contains(err.Error(), "secret") || !errors.Is(err, context.Canceled) {
				t.Fatalf("quoted URL leaked or cancellation was lost: %v", err)
			}
		}
	}
}
