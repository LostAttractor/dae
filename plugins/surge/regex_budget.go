// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"iter"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

const (
	regexTimeout        = 50 * time.Millisecond
	regexWorkLimit      = 250 * time.Millisecond
	regexOperationLimit = 4096
)

var errRegexBudget = errors.New("Surge regular expression budget exhausted")

type regexBudgetKey struct{}
type regexBudget struct {
	mu         sync.Mutex
	spent      time.Duration
	operations int
	err        error
}

func withRegexBudget(ctx context.Context) context.Context {
	if ctx.Value(regexBudgetKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, regexBudgetKey{}, new(regexBudget))
}

func regexBudgetFor(ctx context.Context) *regexBudget {
	if b, ok := ctx.Value(regexBudgetKey{}).(*regexBudget); ok {
		return b
	}
	return new(regexBudget)
}

func regexBudgetError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b, ok := ctx.Value(regexBudgetKey{}).(*regexBudget); ok {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.err
	}
	return nil
}

// Charge only time inside the regex engine, across both HTTP directions. The
// per-pattern timeout also bounds the final operation's possible overrun.
func (b *regexBudget) run[T any](ctx context.Context, run func() (T, error)) (value T, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return value, err
	}
	if b.err != nil {
		return value, b.err
	}
	if b.operations >= regexOperationLimit || b.spent >= regexWorkLimit {
		b.err = errRegexBudget
		return value, b.err
	}
	b.operations++
	started := time.Now()
	value, err = run()
	b.spent += time.Since(started)
	if err != nil {
		// A timed-out condition is unknown, not a definite miss. Stop the pass
		// so later rules cannot turn an expensive reject into an implicit allow.
		b.err = errors.Join(errRegexBudget, err)
	} else if b.spent >= regexWorkLimit {
		b.err = errRegexBudget
	}
	return value, b.err
}

// All replacement loops use this iterator, so every FindNextMatch consumes
// the same request budget rather than renewing the per-pattern timeout alone.
func (b *regexBudget) matches(ctx context.Context, pattern *regexp2.Regexp, text []rune, count int) iter.Seq2[*regexp2.Match, error] {
	return func(yield func(*regexp2.Match, error) bool) {
		match, err := b.run(ctx, func() (*regexp2.Match, error) { return pattern.FindRunesMatch(text) })
		for {
			if err != nil {
				yield(nil, err)
				return
			}
			if match == nil || !yield(match, nil) {
				return
			}
			count--
			if count == 0 {
				return
			}
			match, err = b.run(ctx, func() (*regexp2.Match, error) { return pattern.FindNextMatch(match) })
		}
	}
}

func compilePattern(pattern string) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = regexTimeout
	return re, nil
}

func matchPattern(ctx context.Context, pattern *regexp2.Regexp, value string) bool {
	if pattern == nil {
		return false
	}
	matched, err := regexBudgetFor(ctx).run(ctx, func() (bool, error) { return pattern.MatchString(value) })
	return err == nil && matched
}
