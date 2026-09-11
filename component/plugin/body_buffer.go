// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"
	"io"
	"sync"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

// SnapshotBody lends immutable bytes and restores consumed input, including a
// partial prefix on failure. The caller closes the view; forwarding owns the
// replacement body. Only untouched, complete snapshots can be shared.
func SnapshotBody(body *io.ReadCloser, limit int64, budget *membuffer.Budget) (*membuffer.View, error) {
	if *body == nil {
		return (&membuffer.Buffer{Budget: budget, Limit: limit}).View(), nil
	}
	cached := membuffer.Snapshot(*body)
	if cached != nil {
		if cached.Budget() == budget {
			if int64(len(cached.Bytes())) <= limit {
				return cached, nil
			}
			cached.Close()
			return nil, membuffer.ErrTooLarge
		}
		cached.Close()
	}
	original := *body
	view, err := membuffer.Read(original, limit, budget)
	if view == nil {
		return nil, err
	}
	prefix := view.Open()
	var replay io.Reader = prefix
	if err != nil {
		var tail io.Reader = original
		if !errors.Is(err, membuffer.ErrTooLarge) && !errors.Is(err, membuffer.ErrBudgetExhausted) {
			tail = readError{err}
		}
		replay = io.MultiReader(prefix, tail)
	}
	*body = &replayBody{Reader: replay, prefix: prefix, source: original, complete: err == nil}
	if err != nil {
		view.Close()
		return nil, err
	}
	return view, nil
}

type readError struct{ err error }

func (e readError) Read([]byte) (int, error) { return 0, e.err }

type replayBody struct {
	io.Reader
	prefix   *membuffer.Reader
	source   io.ReadCloser
	complete bool
	once     sync.Once
	err      error
}

func (b *replayBody) Close() error {
	b.once.Do(func() { _ = b.prefix.Close(); b.err = b.source.Close() })
	return b.err
}

// Snapshot exposes only a complete, untouched prefix. A partial snapshot still
// depends on its source and cannot provide an independent retry cursor.
func (b *replayBody) Snapshot() *membuffer.View {
	if !b.complete {
		return nil
	}
	return b.prefix.Snapshot()
}
