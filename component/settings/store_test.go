// SPDX-License-Identifier: AGPL-3.0-only

package settings

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestStorePersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	path := filepath.Join(dir, "runtime-state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	for _, err := range []error{s.SetMITM(mac, nil), s.SetSelection("proxy", ""), s.SetMembership("gaming", mac, false)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("reading or clearing absent settings created the directory: %v", err)
	}

	disabled := false
	for _, err := range []error{
		s.SetMITM(mac, &disabled), s.SetSelection("proxy", "node-id"),
		s.SetMembership("gaming", mac, true), s.SetMembership("streaming", mac, true),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if enabled, exists := s.MITM(mac); enabled || !exists {
		t.Fatal("explicit false MITM preference was lost")
	}
	if s.Selection("proxy") != "node-id" {
		t.Fatal("selector choice was lost")
	}
	if !slices.Equal(s.Members("gaming"), [][6]byte{mac}) || !slices.Equal(s.Members("streaming"), [][6]byte{mac}) {
		t.Fatal("membership in multiple sets was lost")
	}
	for path, want := range map[string]os.FileMode{dir: 0700, path: 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s permissions = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	for _, err := range []error{s.SetMITM(mac, nil), s.SetSelection("proxy", ""), s.SetMembership("gaming", mac, false)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if enabled, exists := s.MITM(mac); enabled || exists || s.Selection("proxy") != "" {
		t.Fatal("reset MITM or selector override survived reopening")
	}
	if len(s.Members("gaming")) != 0 || !slices.Equal(s.Members("streaming"), [][6]byte{mac}) {
		t.Fatal("leaving one set changed another membership")
	}
}

func TestStoreSaveFailurePreservesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	enabled, disabled := true, false
	for _, err := range []error{s.SetMITM(mac, &enabled), s.SetSelection("proxy", "original"), s.SetMembership("gaming", mac, true)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	// A directory makes atomic replacement fail even when tests run as root.
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	assertOriginal := func(store *Store) {
		t.Helper()
		if got, exists := store.MITM(mac); !got || !exists {
			t.Fatal("failed save changed the MITM preference")
		}
		if store.Selection("proxy") != "original" || !slices.Equal(store.Members("gaming"), [][6]byte{mac}) {
			t.Fatal("failed save changed the selection or membership")
		}
	}
	for _, change := range []func() error{
		func() error { return s.SetMITM(mac, &disabled) },
		func() error { return s.SetSelection("proxy", "replacement") },
		func() error { return s.SetMembership("gaming", mac, false) },
	} {
		if err := change(); err == nil {
			t.Fatal("saving over a directory succeeded")
		}
		assertOriginal(s)
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".runtime-state-*"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("failed save left temporary files: %v, %v", temps, err)
	}
	reopened, err := Open(path + ".original")
	if err != nil {
		t.Fatal(err)
	}
	assertOriginal(reopened)
}

func TestStoreRejectsInvalidState(t *testing.T) {
	document := func(selectors, clients, mitm string) string {
		return fmt.Sprintf(`{"selectors":%s,"clients":%s,"mitm":%s}`, selectors, clients, mitm)
	}
	tests := map[string]string{
		"missing objects":   `{}`,
		"empty selection":   document(`{"proxy":""}`, `{}`, `{}`),
		"null members":      document(`{}`, `{"gaming":null}`, `{}`),
		"empty set name":    document(`{}`, `{"":[]}`, `{}`),
		"duplicate members": document(`{}`, `{"gaming":["02:00:00:00:00:01","02:00:00:00:00:01"]}`, `{}`),
		"null preference":   document(`{}`, `{}`, `{"02:00:00:00:00:01":null}`),
		"zero MAC":          document(`{}`, `{}`, `{"00:00:00:00:00:00":true}`),
		"multicast MAC":     document(`{}`, `{"gaming":["01:00:00:00:00:01"]}`, `{}`),
		"noncanonical MAC":  document(`{}`, `{}`, `{"02:AA:BB:CC:DD:EE":true}`),
		"long MAC":          document(`{}`, `{"gaming":["02:aa:bb:cc:dd:ee:ff:01"]}`, `{}`),
		"oversize":          strings.Repeat(" ", maxFileSize+1),
	}
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil {
				t.Fatalf("accepted invalid state (length %d): %.100s", len(data), data)
			}
		})
	}
}

func TestStoreRejectsInvalidUpdates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	s, err := Open(filepath.Join(dir, "runtime-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	for _, mac := range [][6]byte{{}, {1, 0, 0, 0, 0, 1}} {
		if err := s.SetMITM(mac, &enabled); err == nil {
			t.Errorf("accepted invalid MITM MAC %x", mac)
		}
		if err := s.SetMembership("gaming", mac, true); err == nil {
			t.Errorf("accepted invalid member MAC %x", mac)
		}
	}
	for _, err := range []error{
		s.SetSelection("", ""), s.SetMembership("", [6]byte{2}, false),
		s.SetSelection("oversize", strings.Repeat("x", maxFileSize)),
	} {
		if err == nil {
			t.Fatal("accepted invalid settings")
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("invalid update created a directory: %v", err)
	}
}

func TestStoreDeviceLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	initial := Snapshot{Selectors: map[string]string{}, Clients: map[string][]string{"gaming": {}}, MITM: map[string]bool{}}
	for i := range maxClients {
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&255)
		initial.MITM[mac] = true
		initial.Clients["gaming"] = append(initial.Clients["gaming"], mac)
	}
	write := func() {
		t.Helper()
		data, err := json.Marshal(initial)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	existing, extra := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 16, 0}
	if err := s.SetMITM(existing, &disabled); err != nil {
		t.Fatalf("cannot update at capacity: %v", err)
	}
	if err := s.SetMembership("gaming", existing, true); err != nil {
		t.Fatalf("cannot repeat membership at capacity: %v", err)
	}
	if err := s.SetMITM(extra, &disabled); err == nil {
		t.Fatal("accepted an MITM device beyond capacity")
	}
	if err := s.SetMembership("gaming", extra, true); err == nil {
		t.Fatal("accepted a set member beyond capacity")
	}
	if _, exists := s.MITM(extra); exists || slices.Contains(s.Members("gaming"), extra) {
		t.Fatal("rejected device was added to active state")
	}
	initial.MITM[macString(extra)] = true
	write()
	if _, err := Open(path); err == nil {
		t.Fatal("opened a file beyond MITM capacity")
	}
	delete(initial.MITM, macString(extra))
	initial.Clients["gaming"] = append(initial.Clients["gaming"], macString(extra))
	write()
	if _, err := Open(path); err == nil {
		t.Fatal("opened a file beyond client set capacity")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() {
			mac := [6]byte{2, 0, 0, 0, 0, byte(i)}
			enabled := i%2 == 1
			for _, err := range []error{s.SetMITM(mac, &enabled), s.SetSelection(fmt.Sprintf("group-%d", i), fmt.Sprintf("node-%d", i)), s.SetMembership("shared", mac, true)} {
				if err != nil {
					t.Error(err)
					return
				}
			}
			s.MITM(mac)
			s.Selection("group-0")
			s.Members("shared")
		})
	}
	workers.Wait()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	members := s.Members("shared")
	if len(members) != 8 {
		t.Fatalf("concurrent membership updates lost devices: %v", members)
	}
	for i := range 8 {
		mac := [6]byte{2, 0, 0, 0, 0, byte(i)}
		if enabled, exists := s.MITM(mac); enabled != (i%2 == 1) || !exists {
			t.Errorf("concurrent writer %d lost its MITM preference", i)
		}
		if s.Selection(fmt.Sprintf("group-%d", i)) != fmt.Sprintf("node-%d", i) || !slices.Contains(members, mac) {
			t.Errorf("concurrent writer %d lost its selector or membership", i)
		}
	}
}
