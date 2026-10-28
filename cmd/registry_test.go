// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/control"
)

func emptyRegistryStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	base := binary.LittleEndian.AppendUint64([]byte("DAEREGB\x01"), 7)
	base = binary.LittleEndian.AppendUint32(base, crc32.Checksum(base, crc32.MakeTable(crc32.Castagnoli)))
	if err := os.WriteFile(filepath.Join(dir, "domain-registry.base"), base, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRegistryDumpCommand(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		dir := emptyRegistryStore(t)
		command := newRegistryCommand()
		args := []string{"dump"}
		if explicit {
			t.Setenv("DAE_LOCATION_CACHE", filepath.Join(t.TempDir(), "unused"))
			args = append(args, dir)
		} else {
			t.Setenv("DAE_LOCATION_CACHE", dir)
		}
		command.SetArgs(args)
		var output bytes.Buffer
		command.SetOut(&output)
		if err := command.ExecuteContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		var dump control.DomainRegistryDump
		if err := json.Unmarshal(output.Bytes(), &dump); err != nil {
			t.Fatal(err)
		}
		if dump.Epoch != "0000000000000007" || len(dump.Records) != 0 || len(dump.Warnings) != 1 || !bytes.Contains(output.Bytes(), []byte("\n  \"epoch\"")) || !bytes.HasSuffix(output.Bytes(), []byte("\n")) {
			t.Fatalf("unexpected JSON: %s", &output)
		}
	}
}

type registryFailingWriter struct{}

func (registryFailingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRegistryDumpOutputError(t *testing.T) {
	command := newRegistryCommand()
	command.SetArgs([]string{"dump", emptyRegistryStore(t)})
	command.SetOut(registryFailingWriter{})
	command.SetErr(io.Discard)
	if err := command.ExecuteContext(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error = %v", err)
	}
}

func TestRegistryDumpRejectsExtraArguments(t *testing.T) {
	command := newRegistryCommand()
	command.SetArgs([]string{"dump", "one", "two"})
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	if err := command.ExecuteContext(t.Context()); err == nil {
		t.Fatal("accepted multiple registry directories")
	}
}
