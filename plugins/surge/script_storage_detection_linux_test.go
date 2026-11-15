// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dop251/goja/parser"
	"golang.org/x/sys/unix"
)

func TestScriptStorageSourceMapNoFileIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.map")
	if err := os.WriteFile(path, []byte(`{"version":3,"sources":[],"names":[],"mappings":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	source := "$persistentStore.read();\n//# sourceMappingURL=file://" + path
	if got, err := scriptUsesPersistentStore(source); err != nil || !got {
		t.Fatalf("detection = %t, %v; want true, nil", got, err)
	}
	buffer := make([]byte, 4096)
	if n, err := unix.Read(fd, buffer); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("detector opened a source map: event bytes=%d, error=%v", n, err)
	}
	// Positive control: the same parser without the disabling option does open the file.
	if _, err := parser.ParseFile(nil, "", source, 0); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Read(fd, buffer); err != nil || n == 0 {
		t.Fatalf("source-map open was not observed: event bytes=%d, error=%v", n, err)
	}
}
