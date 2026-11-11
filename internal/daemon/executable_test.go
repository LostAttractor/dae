// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementUsesExecutableContents(t *testing.T) {
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	copy, err := os.Create(filepath.Join(t.TempDir(), "dae"))
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if _, err := io.Copy(copy, self); err != nil {
		t.Fatal(err)
	}
	if replace, err := needsReplacement(copy, false); err != nil || replace {
		t.Fatalf("identical contents: %v, %v", replace, err)
	}
	if replace, err := needsReplacement(copy, true); err != nil || !replace {
		t.Fatalf("forced: %v, %v", replace, err)
	}
	// The version string remains identical, while the ELF contents differ.
	if _, err := copy.Write([]byte("different build")); err != nil {
		t.Fatal(err)
	}
	if replace, err := needsReplacement(copy, false); err != nil || !replace {
		t.Fatalf("different contents: %v, %v", replace, err)
	}
	if replace, err := needsReplacement(nil, false); err != nil || replace {
		t.Fatalf("config-only: %v, %v", replace, err)
	}
}
