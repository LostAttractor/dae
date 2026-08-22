package cmd

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveDirectory(t *testing.T) {
	source := t.TempDir()
	content := []byte("network status")
	if err := os.WriteFile(filepath.Join(source, "status.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(t.TempDir(), "sysdump.tar.gz")
	if err := archiveDirectory(source, destination); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)

	if _, err := tarReader.Next(); err != nil {
		t.Fatal(err)
	}
	header, err := tarReader.Next()
	if err != nil {
		t.Fatal(err)
	}
	wantName := filepath.ToSlash(filepath.Join(filepath.Base(source), "status.txt"))
	if header.Name != wantName {
		t.Fatalf("archive entry name = %q, want %q", header.Name, wantName)
	}
	got, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("archive content = %q, want %q", got, content)
	}
}
