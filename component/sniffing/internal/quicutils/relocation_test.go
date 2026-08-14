/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"bytes"
	"errors"
	"testing"
)

func TestLinearLocatorAcrossCryptoFrames(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 3, Data: []byte("defgh")},
	})

	got, err := locator.Range(1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("bcdefg")) {
		t.Fatalf("unexpected range: %q", got)
	}
}

func TestLinearLocatorSliceUsesExclusiveEnd(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 3, Data: []byte("defgh")},
	})

	sliced, err := locator.Slice(1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if sliced.Len() != 6 {
		t.Fatalf("unexpected slice length: %d", sliced.Len())
	}
	got, err := sliced.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("bcdefg")) {
		t.Fatalf("unexpected slice: %q", got)
	}
}

func TestLinearLocatorRejectsMissingCrypto(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 4, Data: []byte("efgh")},
	})

	_, err := locator.Range(1, 7)
	if !errors.Is(err, ErrMissingCrypto) {
		t.Fatalf("expected ErrMissingCrypto, got %v", err)
	}
}

func TestLinearLocatorCanStartAfterMissingCrypto(t *testing.T) {
	frames := []*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 4, Data: []byte("ef")},
	}

	t.Run("range", func(t *testing.T) {
		got, err := NewLinearLocator(frames).Range(4, 6)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("ef")) {
			t.Fatalf("unexpected range: %q", got)
		}
	})
	t.Run("at", func(t *testing.T) {
		got, err := NewLinearLocator(frames).At(4)
		if err != nil {
			t.Fatal(err)
		}
		if got != 'e' {
			t.Fatalf("unexpected byte: %q", got)
		}
	})
	t.Run("slice", func(t *testing.T) {
		locator, err := NewLinearLocator(frames).Slice(4, 6)
		if err != nil {
			t.Fatal(err)
		}
		got, err := locator.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("ef")) {
			t.Fatalf("unexpected slice: %q", got)
		}
	})
}

func TestLinearLocatorAcceptsRetransmittedCrypto(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 0, Data: []byte("abc")},
		{UpperAppOffset: 3, Data: []byte("def")},
	})

	got, err := locator.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Fatalf("unexpected reassembled crypto: %q", got)
	}
}

func TestLinearLocatorAcceptsOverlappingCrypto(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abcd")},
		{UpperAppOffset: 2, Data: []byte("cdef")},
		{UpperAppOffset: 6, Data: []byte("gh")},
	})

	got, err := locator.Range(1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("bcdefgh")) {
		t.Fatalf("unexpected reassembled crypto: %q", got)
	}
}

func TestLinearLocatorContainedCryptoDoesNotShrinkLength(t *testing.T) {
	locator := NewLinearLocator([]*CryptoFrameOffset{
		{UpperAppOffset: 0, Data: []byte("abcdef")},
		{UpperAppOffset: 2, Data: []byte("cd")},
	})

	if locator.Len() != 6 {
		t.Fatalf("unexpected locator length: %d", locator.Len())
	}
	got, err := locator.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Fatalf("unexpected reassembled crypto: %q", got)
	}
}
