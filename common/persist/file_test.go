// SPDX-License-Identifier: AGPL-3.0-only

package persist

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceFileUsesHeldDirectoryAndCleansFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := os.Rename(path, path+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(t.Context(), dir, "value", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(t.Context(), dir, "value", []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(path+"-held", "value"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("replacement permissions: %v %v", info, err)
	}
	data, err := os.ReadFile(filepath.Join(path+"-held", "value"))
	if err != nil || string(data) != "new" {
		t.Fatalf("replacement contents: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(path, "value")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("used replaced directory path: %v", err)
	}
	if err := os.Mkdir(filepath.Join(path+"-held", "blocked"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(t.Context(), dir, "blocked", []byte("rejected")); err == nil {
		t.Fatal("replaced a directory")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := ReplaceFile(ctx, dir, "value", []byte("canceled")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "../escape", "/absolute"} {
		if err := ReplaceFile(t.Context(), dir, name, nil); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("name %q: %v", name, err)
		}
	}
	entries, err := os.ReadDir(path + "-held")
	if err != nil || len(entries) != 2 {
		t.Fatalf("temporary files survived: %v %v", entries, err)
	}
	data, err = os.ReadFile(filepath.Join(path+"-held", "value"))
	if err != nil || string(data) != "new" {
		t.Fatalf("failed write changed visible data: %q %v", data, err)
	}
}
