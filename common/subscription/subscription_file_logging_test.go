// SPDX-License-Identifier: AGPL-3.0-only

package subscription

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRedactURLPreservesLocalFilePaths(t *testing.T) {
	for _, test := range []struct{ source, want string }{
		{"flowercloud:file:///run/secrets/dae/subscription/flowercloud", "flowercloud:file:///run/secrets/dae/subscription/flowercloud"},
		{"local:file:secrets/nodes.sub?token=private#fragment", "local:file:secrets/nodes.sub"},
		{"file://user:password@/run/secrets/nodes%20name.sub?token=private#fragment", "file:///run/secrets/nodes%20name.sub"},
		{"file:///run/secrets/nodes%0A.sub", "file:///run/secrets/nodes%0A.sub"},
	} {
		if got := RedactURL(test.source); got != test.want {
			t.Errorf("RedactURL(%q) = %q, want %q", test.source, got, test.want)
		}
	}
}

func TestRelativeSubscriptionOpenErrorIdentifiesComponent(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "regular file", true: "symbolic link"}[symlink], func(t *testing.T) {
			dir := t.TempDir()
			component := filepath.Join(dir, "parent")
			if symlink {
				if err := os.Symlink(t.TempDir(), component); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(component, []byte("not a directory"), 0600); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse("file:parent/nodes.sub")
			if err != nil {
				t.Fatal(err)
			}
			_, err = ResolveFile(u, dir)
			if pathErr, ok := errors.AsType[*os.PathError](err); !ok || pathErr.Path != component || !errors.Is(err, unix.ENOTDIR) {
				t.Fatalf("open error = %v, want ENOTDIR identifying %s", err, component)
			}
			if strings.Contains(err.Error(), "symbolic links are not allowed") != symlink {
				t.Fatalf("open error misidentifies the failing component: %v", err)
			}
		})
	}
}
