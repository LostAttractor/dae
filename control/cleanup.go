// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"slices"
)

// Owners serialize registration and draining. Userspace and kernel resources
// have separate lifetimes, but both release in reverse acquisition order.
type cleanupStack struct{ funcs []func() error }

func (s *cleanupStack) add(cleanup func() error) { s.funcs = append(s.funcs, cleanup) }

func (s *cleanupStack) take() []func() error {
	cleanups := s.funcs
	s.funcs = nil
	slices.Reverse(cleanups)
	return cleanups
}

func (s *cleanupStack) close() (err error) {
	for _, cleanup := range s.take() {
		err = errors.Join(err, cleanup())
	}
	return err
}
