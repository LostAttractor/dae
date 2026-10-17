// SPDX-License-Identifier: AGPL-3.0-only

// Package settings persists API choices independently of the configuration file.
package settings

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"

	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/common/selector"
	"golang.org/x/sys/unix"
)

const (
	maxClients  = 4096
	maxFileSize = 1 << 20
)

// Snapshot contains validated file contents. Reload callbacks must treat it as read-only.
type Snapshot struct {
	Selectors map[string]*selector.Path `json:"selectors"`
	Clients   map[string][]string       `json:"clients"`
	MITM      map[string]bool           `json:"mitm"`
}

// Store is shared by active and candidate control planes. Opening an absent
// file does not create its directory; only successful changes write state.
type Store struct {
	mu          sync.RWMutex
	path        string
	state       Snapshot
	syncDir     func(string) error
	pendingSync bool
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("runtime settings path is empty")
	}
	value, err := readState(path)
	if os.IsNotExist(err) {
		value = Snapshot{Selectors: map[string]*selector.Path{}, Clients: map[string][]string{}, MITM: map[string]bool{}}
	} else if err != nil {
		return nil, err
	}
	return &Store{path: path, state: value, syncDir: persist.SyncDir}, nil
}

func readState(path string) (Snapshot, error) {
	var value Snapshot
	f, _, err := fileio.OpenRegular(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	data, err := fileio.ReadBounded(context.Background(), f, maxFileSize)
	if errors.Is(err, fileio.ErrTooLarge) {
		return Snapshot{}, fmt.Errorf("runtime settings exceed %d bytes", maxFileSize)
	}
	if err != nil {
		return Snapshot{}, err
	}
	// JSON null must not become an explicit false runtime preference.
	booleans := json.UnmarshalFunc(func(data []byte, value *bool) error {
		if string(data) == "null" {
			return fmt.Errorf("runtime preference must be true or false")
		}
		return json.Unmarshal(data, value)
	})
	if err := json.Unmarshal(data, &value, json.RejectUnknownMembers(true), json.WithUnmarshalers(booleans)); err != nil {
		return Snapshot{}, fmt.Errorf("decode runtime settings: %w", err)
	}
	if err := value.validate(); err != nil {
		return Snapshot{}, err
	}
	return value, nil
}

// Reload publishes edits only after apply succeeds. Missing files keep the
// current state. The callback runs under the store lock and must not call Store methods.
func (s *Store) Reload(apply func(previous, next Snapshot) error) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := readState(s.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if reflect.DeepEqual(s.state, next) {
		return false, nil
	}
	if err := apply(s.state, next); err != nil {
		return false, err
	}
	s.state = next
	return true, nil
}

// Update serializes an API edit with file reloads and persistence. apply uses
// persist after preparing the live changes and rolls them back on any error.
// If a later kernel commit fails, Update also restores the saved preferences.
// Neither callback may call Store methods while this lock is held.
func (s *Store) Update(edit func(*Snapshot) error, apply func(previous, next Snapshot, persist func() error) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state
	next := Snapshot{Selectors: maps.Clone(previous.Selectors), Clients: maps.Clone(previous.Clients), MITM: maps.Clone(previous.MITM)}
	for name, path := range next.Selectors {
		next.Selectors[name] = path.Clone()
	}
	for name, members := range next.Clients {
		next.Clients[name] = slices.Clone(members)
	}
	if err := edit(&next); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	if reflect.DeepEqual(previous, next) {
		if s.pendingSync {
			return s.syncPublished()
		}
		return nil
	}
	if apply == nil {
		return s.save(next)
	}
	written := false
	persistNext := func() error {
		err := s.save(next)
		written = written || persist.Published(err)
		return err
	}
	if err := apply(previous, next, persistNext); err != nil {
		if written {
			if restoreErr := s.save(previous); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore runtime settings: %w", restoreErr))
			}
		}
		return err
	}
	return nil
}

func macString(mac [6]byte) string { return net.HardwareAddr(mac[:]).String() }
func validateMAC(text string) error {
	mac, err := macaddr.ParseClient(text)
	if err != nil || macString(mac) != text {
		return fmt.Errorf("invalid client MAC %q: expected a canonical unicast Ethernet address", text)
	}
	return nil
}

// Both file and API edits validate a complete proposed state before publication.
func (s Snapshot) validate() error {
	if s.Selectors == nil || s.Clients == nil || s.MITM == nil {
		return fmt.Errorf("runtime settings require selectors, clients and mitm objects")
	}
	if len(s.MITM) > maxClients {
		return fmt.Errorf("MITM preferences exceed %d devices", maxClients)
	}
	for mac := range s.MITM {
		if err := validateMAC(mac); err != nil {
			return err
		}
	}
	for group, path := range s.Selectors {
		if group == "" {
			return fmt.Errorf("selector name must not be empty")
		}
		if err := path.Validate(); err != nil {
			return fmt.Errorf("selector %q: %w", group, err)
		}
	}
	for name, members := range s.Clients {
		if name == "" {
			return fmt.Errorf("client set name must not be empty")
		}
		if members == nil {
			return fmt.Errorf("client set %q must be an array", name)
		}
		if len(members) > maxClients {
			return fmt.Errorf("client set %q exceeds %d devices", name, maxClients)
		}
		seen := make(map[string]bool, len(members))
		for _, mac := range members {
			if err := validateMAC(mac); err != nil {
				return err
			}
			if seen[mac] {
				return fmt.Errorf("duplicate client MAC %q", mac)
			}
			seen[mac] = true
		}
	}
	return nil
}

func (s *Store) Selection(group string) *selector.Path {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Selectors[group].Clone()
}

func (s *Store) Members(name string) [][6]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Members(name)
}

func (s Snapshot) Members(name string) [][6]byte {
	members := make([][6]byte, 0, len(s.Clients[name]))
	for _, text := range s.Clients[name] {
		mac, _ := macaddr.ParseClient(text) // Stored addresses have already been validated.
		members = append(members, mac)
	}
	return members
}

func (s *Store) MITM(mac [6]byte) (enabled, exists bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enabled, exists = s.state.MITM[macString(mac)]
	return
}

// MITMOverrides returns a detached policy input for preparation and publication.
func (s *Store) MITMOverrides() map[[6]byte]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.MITMOverrides()
}

func (s Snapshot) MITMOverrides() map[[6]byte]bool {
	values := make(map[[6]byte]bool, len(s.MITM))
	for text, enabled := range s.MITM {
		mac, _ := macaddr.ParseClient(text) // Snapshot validation owns canonical identities.
		values[mac] = enabled
	}
	return values
}

// The caller holds mu. Readers only see the next state after atomic replacement.
func (s *Store) save(next Snapshot) error {
	data, err := json.Marshal(&next, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxFileSize {
		return fmt.Errorf("runtime settings exceed %d bytes", maxFileSize)
	}
	dir := filepath.Dir(s.path)
	if err := persist.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), dir)
	defer directory.Close()
	if err := persist.ReplaceFile(context.Background(), directory, filepath.Base(s.path), data); err != nil {
		return err
	}

	s.state = next
	s.pendingSync = true
	return s.syncPublished()
}

func (s *Store) syncPublished() error {
	err := s.syncDir(filepath.Dir(s.path))
	s.pendingSync = err != nil
	return persist.AfterPublish(err)
}
