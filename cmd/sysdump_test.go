package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestSysdumpReturnsFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if sysdumpCmd.RunE == nil {
		t.Fatal("sysdump does not propagate command failures")
	}
	if err := sysdumpCmd.RunE(sysdumpCmd, nil); err == nil {
		t.Fatal("sysdump succeeded without a writable temporary directory")
	}
}

func TestSysdumpPreservesPartialArchiveOnCollectorFailure(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", t.TempDir()) // The optional firewall tools are unavailable.
	var output bytes.Buffer
	err := dumpNetworkInfo(&output)
	if err == nil || !strings.Contains(err.Error(), "nftables") || !strings.Contains(err.Error(), "iptables") {
		t.Fatalf("collector failures did not reach the caller: %v", err)
	}
	archives, err := filepath.Glob(filepath.Join(dir, "dae-sysdump.*.tar.gz"))
	if err != nil || len(archives) != 1 || !strings.Contains(output.String(), filepath.Base(archives[0])) {
		t.Fatalf("partial dump was not saved: archives=%v output=%q err=%v", archives, output.String(), err)
	}
	file, err := os.Open(archives[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	for {
		header, err := archive.Next()
		if err != nil {
			t.Fatalf("partial archive has no interface data: %v", err)
		}
		if filepath.Base(header.Name) == "interfaces.txt" && header.Size > 0 {
			break
		}
	}
}
