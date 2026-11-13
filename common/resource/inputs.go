// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"reflect"
	"sync"
	"time"
)

// These errors are fatal even for optional inputs. An ordinary recorded load
// failure is neither: it reproduces the original decision to skip that input.
var (
	ErrInputRecording = errors.New("resource input recording failed")
	ErrInputReplay    = errors.New("resource input replay failed")
)

// MaxInputBytes bounds one immutable input or complete resource group. Live
// loaders passed to ReadInput must also bound their own temporary allocations.
const MaxInputBytes = 128 << 20

// MaxInputArchiveBytes includes the header, bounded index, raw bytes and digest.
const MaxInputArchiveBytes = 512 << 20

const (
	maxInputsBody  = MaxInputArchiveBytes - inputsFramingSize
	maxInputIndex  = 16 << 20
	maxInputKeys   = 4096
	maxInputReads  = 65536
	maxGroupReads  = 4096
	maxInputString = 4096

	inputBytes = 1
	inputRead  = 2
	inputGroup = 3
)

type inputKey struct {
	kind           uint8
	namespace, key string
}

type inputError struct {
	message string
	code    uint8
}

// Zero means success; one is a failure without a portable error identity.
var inputErrorCauses = []error{nil, nil, context.Canceled, context.DeadlineExceeded, fs.ErrNotExist, fs.ErrPermission, fs.ErrExist, fs.ErrInvalid}

func savedInputError(err error) inputError {
	if err == nil {
		return inputError{}
	}
	e := inputError{message: RedactError(err).Error(), code: 1}
	for i, cause := range inputErrorCauses[2:] {
		if errors.Is(err, cause) {
			e.code = uint8(i + 2)
			break
		}
	}
	return e
}

func (e inputError) err() error {
	if e.code == 0 {
		return nil
	}
	cause := inputErrorCauses[e.code]
	if e.code >= 4 {
		// os.IsNotExist/IsPermission only unwrap the standard filesystem wrappers.
		return &fs.PathError{Op: e.message, Err: cause}
	}
	return &redactedError{message: e.message, cause: cause}
}

type inputReadRecord struct {
	source      Source
	maxBytes    int64
	userAgent   string
	interval    time.Duration
	hasInterval bool
	result      Result
	err         inputError
}

func newInputRead(source Source, options ReadOptions) inputReadRecord {
	r := inputReadRecord{source: source, maxBytes: options.MaxBytes, userAgent: options.UserAgent}
	if options.RefreshInterval != nil {
		r.hasInterval, r.interval = true, *options.RefreshInterval
	}
	return r
}

func (r inputReadRecord) matches(source Source, options ReadOptions) bool {
	want := newInputRead(source, options)
	return r.source == want.source && r.maxBytes == want.maxBytes && r.userAgent == want.userAgent && r.interval == want.interval && r.hasInterval == want.hasInterval
}

// Account for the exact binary index representation, including length prefixes.
func (r inputReadRecord) indexSize() int64 {
	return 51 + int64(len(r.source.Location)+len(r.userAgent)+len(r.result.Location)+len(r.err.message))
}

type inputEntry struct {
	key                 inputKey
	maxBytes            int64
	err, refresh, write inputError
	reads               []inputReadRecord
	ready               chan struct{}
}

func (e *inputEntry) indexSize() int64 {
	n := int64(36 + len(e.key.namespace) + len(e.key.key) + len(e.err.message) + len(e.refresh.message) + len(e.write.message))
	for _, r := range e.reads {
		n += r.indexSize()
	}
	return n
}

// Inputs holds one initialization operation's immutable inputs, not runtime state.
// Obtain it through WithInputRecording or DecodeInputs. Parallel loads are safe;
// the first load of an identity wins, and subsequent loads reuse its result.
// Encode only after all initialization callers have returned.
type Inputs struct {
	mu         sync.Mutex
	entries    map[inputKey]*inputEntry
	derived    map[derivedInputKey]*derivedInput
	bytes      int64
	indexBytes int64
	reads      int
	pending    int
	err        error
	ctx        context.Context
}

type derivedInputKey struct {
	name   string
	kind   reflect.Type
	replay bool
}

type derivedInput struct {
	ready chan struct{}
	value any
	err   error
}

// DeriveInput reuses decoder state for frozen inputs within one operation.
// build must read only through input-bound readers. Published data must remain
// immutable; private bookkeeping must synchronize its own access. The helper
// does not make arbitrary T values immutable. Derived values are not encoded
// and are released with Inputs; builders and their contexts are not retained.
// Without an input binding, build runs directly without memoization.
func DeriveInput[T any](ctx context.Context, key string, build func(context.Context) (T, error)) (value T, err error) {
	if err := ctx.Err(); err != nil {
		return value, err
	}
	b, ok := boundInputs(ctx)
	if !ok {
		value, err = build(ctx)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return value, err
	}
	fatal := ErrInputRecording
	if b.replay {
		fatal = ErrInputReplay
	}
	if b.inputs == nil {
		return value, fmt.Errorf("%w: no input recording", fatal)
	}
	s := b.inputs
	identity := derivedInputKey{name: key, kind: reflect.TypeFor[T](), replay: b.replay}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return value, fmt.Errorf("%w: %w", fatal, err)
	}
	d, exists := s.derived[identity]
	if !exists {
		if key == "" || len(key) > maxInputString || len(s.derived) >= maxInputKeys {
			s.mu.Unlock()
			err := fmt.Errorf("%w: derived input key or count limit exceeded", fatal)
			if !b.replay {
				err = s.fail(err)
			}
			return value, err
		}
		if s.derived == nil {
			s.derived = make(map[derivedInputKey]*derivedInput)
		}
		d = &derivedInput{ready: make(chan struct{})}
		s.derived[identity] = d
		s.pending++
	}
	s.mu.Unlock()
	if !exists {
		value, err = build(ctx)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if !b.replay && (errors.Is(err, ErrInputRecording) || errors.Is(err, ErrInputReplay)) {
			err = s.fail(err)
		}
		d.value, d.err = new(value), err
		s.mu.Lock()
		s.pending--
		close(d.ready)
		s.mu.Unlock()
	} else {
		select {
		case <-ctx.Done():
			return value, ctx.Err()
		case <-d.ready:
		}
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	s.mu.Lock()
	failed := s.err
	s.mu.Unlock()
	if failed != nil {
		return value, fmt.Errorf("%w: %w", fatal, failed)
	}
	return *d.value.(*T), d.err
}

type inputContextKey struct{}
type inputBinding struct {
	inputs *Inputs
	replay bool
}

// WithInputRecording binds a new, short-lived input recording to ctx. Do not
// propagate this context to runtime workers or mutable persistence operations.
func WithInputRecording(ctx context.Context) (context.Context, *Inputs) {
	inputs := &Inputs{entries: make(map[inputKey]*inputEntry), ctx: ctx}
	return context.WithValue(ctx, inputContextKey{}, inputBinding{inputs: inputs}), inputs
}

// WithInputReplay binds strict replay. A nil or incomplete recording never falls
// back to live I/O. The caller must discard this context after initialization.
func WithInputReplay(ctx context.Context, inputs *Inputs) context.Context {
	return context.WithValue(ctx, inputContextKey{}, inputBinding{inputs: inputs, replay: true})
}

// HasInputs reports an explicit recording or replay binding. Callers that use
// mmap or streaming normally can select bounded byte loading only for this scope.
func HasInputs(ctx context.Context) bool {
	_, ok := boundInputs(ctx)
	return ok
}

func boundInputs(ctx context.Context) (inputBinding, bool) {
	b, ok := ctx.Value(inputContextKey{}).(inputBinding)
	return b, ok
}

func withoutInputs(ctx context.Context) context.Context {
	return context.WithValue(ctx, inputContextKey{}, false)
}

func (s *Inputs) fail(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = fmt.Errorf("%w: %w", ErrInputRecording, err)
	}
	return s.err
}

func (s *Inputs) reserve(data, index int64, reads int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if index > maxInputIndex-s.indexBytes || data+index > maxInputsBody-s.bytes-s.indexBytes || reads > maxInputReads-s.reads {
		s.err = fmt.Errorf("%w: input byte, index or count limit exceeded", ErrInputRecording)
		return s.err
	}
	s.bytes += data
	s.indexBytes += index
	s.reads += reads
	return nil
}

func (s *Inputs) discard(reads []inputReadRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range reads {
		s.bytes -= int64(len(r.result.Data))
		s.indexBytes -= r.indexSize()
		s.reads--
	}
}

func (b inputBinding) entry(ctx context.Context, key inputKey, maxBytes int64) (*inputEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	fatal := ErrInputRecording
	if b.replay {
		fatal = ErrInputReplay
	}
	if b.inputs == nil {
		return nil, false, fmt.Errorf("%w: no input recording", fatal)
	}
	s := b.inputs
	s.mu.Lock()
	if s.err != nil {
		err := fmt.Errorf("%w: %w", fatal, s.err)
		s.mu.Unlock()
		return nil, false, err
	}
	if e, ok := s.entries[key]; ok {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-e.ready:
		}
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		s.mu.Lock()
		failed := s.err
		s.mu.Unlock()
		if failed != nil {
			return nil, false, fmt.Errorf("%w: %w", fatal, failed)
		}
		if e.maxBytes != maxBytes {
			return nil, false, fmt.Errorf("%w: input interpretation changed", ErrInputReplay)
		}
		return e, false, nil
	}
	if b.replay {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("%w: input identity is missing", ErrInputReplay)
	}
	e := &inputEntry{key: key, maxBytes: maxBytes, ready: make(chan struct{})}
	if maxBytes <= 0 || maxBytes > MaxInputBytes || len(key.key) == 0 || len(key.key) > maxInputString || len(key.namespace) > maxInputString || len(s.entries) >= maxInputKeys || e.indexSize() > maxInputIndex-s.indexBytes || e.indexSize() > maxInputsBody-s.bytes-s.indexBytes {
		s.mu.Unlock()
		return nil, false, s.fail(errors.New("input key, index or count limit exceeded"))
	}
	s.entries[key] = e
	s.indexBytes += e.indexSize()
	s.pending++
	s.mu.Unlock()
	return e, true, nil
}

func (s *Inputs) finish(e *inputEntry, err error, status CacheStatus) error {
	var captureErr error
	for _, cause := range []error{err, status.RefreshError, status.WriteError} {
		if errors.Is(cause, ErrInputRecording) || errors.Is(cause, ErrInputReplay) {
			captureErr = s.fail(cause)
		}
	}
	e.err, e.refresh, e.write = savedInputError(err), savedInputError(status.RefreshError), savedInputError(status.WriteError)
	for _, diagnostic := range []inputError{e.err, e.refresh, e.write} {
		if len(diagnostic.message) > maxInputString {
			captureErr = s.fail(errors.New("input diagnostic exceeds the length limit"))
			break
		}
	}
	if captureErr == nil {
		captureErr = s.reserve(0, int64(len(e.err.message)+len(e.refresh.message)+len(e.write.message)), 0)
	}
	s.mu.Lock()
	s.pending--
	close(e.ready)
	s.mu.Unlock()
	return captureErr
}

func (s *Inputs) capture(e *inputEntry, source Source, opts ReadOptions, result Result, err error) error {
	r := newInputRead(source, opts)
	r.result, r.err = result, savedInputError(err)
	if len(e.reads) >= maxGroupReads || len(source.Location) > maxInputString || len(opts.UserAgent) > maxInputString || len(result.Location) > maxInputString || len(r.err.message) > maxInputString {
		return s.fail(errors.New("input read count or string limit exceeded"))
	}
	total := int64(len(result.Data))
	for _, previous := range e.reads {
		total += int64(len(previous.result.Data))
	}
	if total > MaxInputBytes || e.key.kind != inputGroup && total > e.maxBytes {
		return s.fail(errors.New("input exceeds the group byte limit"))
	}
	if err := s.reserve(int64(len(result.Data)), r.indexSize(), 1); err != nil {
		return err
	}
	r.result.Data = bytes.Clone(result.Data)
	e.reads = append(e.reads, r)
	return nil
}

// ReadInput records one immutable byte input under a caller-defined stable key.
// Without an input binding it calls live directly; strict replay never calls live.
// Keys must include every option affecting interpretation. Data may be mutated by
// the caller without modifying the recording. Each input is limited to 128 MiB.
func ReadInput(ctx context.Context, key string, live func(context.Context) ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, ok := boundInputs(ctx)
	if !ok {
		data, err := live(ctx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return data, err
	}
	e, record, err := b.entry(ctx, inputKey{kind: inputBytes, key: key}, MaxInputBytes)
	if err != nil {
		return nil, err
	}
	if !record {
		data := bytes.Clone(e.reads[0].result.Data)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return data, e.err.err()
	}
	data, liveErr := live(ctx)
	if err := ctx.Err(); err != nil {
		liveErr = err
	}
	captureErr := b.inputs.capture(e, Source{}, ReadOptions{}, Result{Data: data}, nil)
	finishErr := b.inputs.finish(e, liveErr, CacheStatus{})
	if err := errors.Join(captureErr, finishErr); err != nil {
		return nil, err
	}
	return data, liveErr
}

func readInputResource(ctx context.Context, b inputBinding, client *http.Client, source Source, opts ReadOptions) (Result, error) {
	e, record, err := b.entry(ctx, inputKey{kind: inputRead, key: source.Location}, opts.MaxBytes)
	if err != nil {
		return Result{}, err
	}
	if !record {
		if !e.reads[0].matches(source, opts) {
			return Result{}, fmt.Errorf("%w: resource read interpretation changed", ErrInputReplay)
		}
		result := e.reads[0].result
		result.Data = bytes.Clone(result.Data)
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return result, e.err.err()
	}
	result, liveErr := Read(withoutInputs(ctx), client, source, opts)
	if err := ctx.Err(); err != nil {
		liveErr = err
	}
	captureErr := b.inputs.capture(e, source, opts, result, liveErr)
	finishErr := b.inputs.finish(e, liveErr, CacheStatus{})
	if err := errors.Join(captureErr, finishErr); err != nil {
		return Result{}, err
	}
	return result, liveErr
}

func (c Cache) loadInputs[T any](ctx context.Context, b inputBinding, client *http.Client, opts LoadOptions, load func(ReadFunc) (T, error)) (value T, status CacheStatus, err error) {
	e, record, err := b.entry(ctx, inputKey{kind: inputGroup, namespace: c.Namespace, key: opts.Key}, opts.MaxBytes)
	if err != nil {
		return value, status, err
	}
	if !record {
		return c.replayInputs(ctx, e, load)
	}
	var captureErr error
	value, status, err = c.load(withoutInputs(ctx), client, opts, func(read ReadFunc) (T, error) {
		// A fresh attempt rejected by validation must never leak into fallback.
		b.inputs.discard(e.reads)
		e.reads = nil
		return load(func(source Source, options ReadOptions) (Result, error) {
			if captureErr != nil {
				return Result{}, captureErr
			}
			if options.MaxBytes > MaxInputBytes {
				captureErr = b.inputs.fail(errors.New("input read byte limit exceeds 128 MiB"))
				return Result{}, captureErr
			}
			result, readErr := read(source, options)
			captureErr = b.inputs.capture(e, source, options, result, readErr)
			if captureErr != nil {
				return Result{}, captureErr
			}
			return result, readErr
		})
	})
	finishErr := b.inputs.finish(e, err, status)
	if fatal := errors.Join(captureErr, finishErr); fatal != nil {
		return value, status, fatal
	}
	return value, status, err
}

func (c Cache) replayInputs[T any](ctx context.Context, e *inputEntry, load func(ReadFunc) (T, error)) (value T, status CacheStatus, err error) {
	status = CacheStatus{RefreshError: e.refresh.err(), WriteError: e.write.err()}
	session := refreshSession(ctx)
	checks := make(map[string]refreshCheck)
	snapshot := &cacheSnapshot{Version: 1, Key: e.key.key, Resources: make(map[string]Result)}
	for _, r := range e.reads {
		if !r.source.Remote() {
			continue
		}
		interval := session.interval
		if r.hasInterval {
			interval = r.interval
		}
		checks[r.source.Location] = (refreshCheck{interval: interval}).reschedule(e.err.code != 0 || e.refresh.code != 0)
		if r.err.code == 0 {
			snapshot.Resources[r.source.Location] = r.result
		}
	}
	if err := ctx.Err(); err != nil {
		return value, status, err
	}
	groupKey := c.Namespace + "\x00" + e.key.key
	if e.err.code != 0 {
		session.stage(groupKey, nil, checks, false)
		return value, status, e.err.err()
	}
	used := make([]bool, len(e.reads))
	remaining := len(e.reads)
	var mismatch error
	value, err = load(func(source Source, options ReadOptions) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		// Group traversal may use maps; only repeated reads of the same input
		// depend on order, not independent resources within the accepted group.
		for i, r := range e.reads {
			if used[i] || !r.matches(source, options) {
				continue
			}
			used[i], remaining = true, remaining-1
			r.result.Data = bytes.Clone(r.result.Data)
			return r.result, r.err.err()
		}
		mismatch = fmt.Errorf("%w: group resource is missing or its interpretation changed", ErrInputReplay)
		return Result{}, mismatch
	})
	if ctx.Err() != nil {
		return value, status, ctx.Err()
	}
	if mismatch != nil {
		return value, status, mismatch
	}
	if err != nil {
		return value, status, fmt.Errorf("%w: accepted input no longer validates: %w", ErrInputReplay, err)
	}
	if remaining != 0 {
		return value, status, fmt.Errorf("%w: accepted group has unused inputs", ErrInputReplay)
	}
	session.stage(groupKey, snapshot, checks, status.RefreshError != nil)
	return value, status, nil
}
