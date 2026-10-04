// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Cache stores complete validated resource groups. An empty Dir disables all
// cache access. Callers supply their routed HTTP client and content validation.
type Cache struct{ Dir string }

type LoadOptions struct {
	// Key includes the source and all options affecting interpretation.
	Key             string
	MaxBytes        int64 // Total remote payload size, before JSON encoding.
	RefreshDeadline time.Time
	Timeout         time.Duration // Per-resource timeout, zero uses the client/context.
}

type CacheStatus struct {
	// A non-nil RefreshError means the last complete cache was used successfully.
	RefreshError error
	WriteError   error
}

type ReadFunc func(Source, ReadOptions) (Result, error)

type cacheSnapshot struct {
	Version   int               `json:"version"`
	Key       string            `json:"key"`
	Resources map[string]Result `json:"resources"`
}

// Load first executes load using fresh resources. Only a successfully validated
// group is published. On failure it reruns load using the previous remote group
// exclusively; local files are always current. It never mixes remote revisions.
// load must be safe to retry and must not modify the returned byte slices.
func (c Cache) Load[T any](ctx context.Context, client *http.Client, opts LoadOptions, load func(ReadFunc) (T, error)) (value T, status CacheStatus, err error) {
	defer func() { err = RedactError(err) }()
	if err := ctx.Err(); err != nil {
		return value, status, err
	}
	if opts.MaxBytes <= 0 || opts.MaxBytes > 128<<20 {
		return value, status, errors.New("resource group byte limit must be between 1 and 128 MiB")
	}
	refreshCtx := ctx
	if !opts.RefreshDeadline.IsZero() {
		var cancel context.CancelFunc
		refreshCtx, cancel = context.WithDeadline(ctx, opts.RefreshDeadline)
		defer cancel()
	}
	read := func(source Source, options ReadOptions) (Result, error) {
		readCtx := ctx
		if source.Remote() {
			readCtx = refreshCtx
		}
		if opts.Timeout > 0 {
			var cancel context.CancelFunc
			readCtx, cancel = context.WithTimeout(readCtx, opts.Timeout)
			defer cancel()
		}
		return Read(readCtx, client, source, options)
	}
	candidate := cacheSnapshot{Version: 1, Key: opts.Key, Resources: make(map[string]Result)}
	var total int64
	value, freshErr := load(func(source Source, options ReadOptions) (Result, error) {
		if previous, ok := candidate.Resources[source.Location]; ok {
			return boundedCachedResult(previous, options)
		}
		result, err := read(source, options)
		if err == nil && source.Remote() {
			total += int64(len(result.Data))
			if total > opts.MaxBytes || len(candidate.Resources) >= 4096 {
				return Result{}, errors.New("resource group exceeds its size or count limit")
			}
			candidate.Resources[source.Location] = result
		}
		return result, err
	})
	if ctx.Err() != nil {
		return value, status, ctx.Err()
	}
	if freshErr == nil {
		if c.Dir != "" && len(candidate.Resources) != 0 {
			status.WriteError = RedactError(c.write(ctx, opts, &candidate))
		}
		return value, status, ctx.Err()
	}
	if c.Dir == "" {
		return value, status, freshErr
	}
	previous, cacheErr := c.read(ctx, opts)
	if ctx.Err() != nil {
		return value, status, ctx.Err()
	}
	if cacheErr != nil {
		return value, status, fmt.Errorf("resource refresh failed: %w; cached fallback unavailable: %v", freshErr, cacheErr)
	}
	value, cacheErr = load(func(source Source, options ReadOptions) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if !source.Remote() {
			return read(source, options)
		}
		result, ok := previous.Resources[source.Location]
		if !ok {
			return Result{}, errors.New("resource is not present in the last complete cache")
		}
		return boundedCachedResult(result, options)
	})
	if ctx.Err() != nil {
		return value, status, ctx.Err()
	}
	if cacheErr != nil {
		return value, status, fmt.Errorf("resource refresh failed: %w; cached fallback unusable: %v", freshErr, cacheErr)
	}
	status.RefreshError = RedactError(freshErr)
	return value, status, nil
}

func boundedCachedResult(result Result, opts ReadOptions) (Result, error) {
	if opts.MaxBytes <= 0 || int64(len(result.Data)) > opts.MaxBytes {
		return Result{}, errors.New("cached resource exceeds the resource byte limit")
	}
	return result, nil
}

func cacheName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (c Cache) read(ctx context.Context, opts LoadOptions) (*cacheSnapshot, error) {
	dir, err := openCacheDir(c.Dir, false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	data, err := readCacheFile(ctx, dir, cacheName(opts.Key), opts.MaxBytes*4/3+8<<20)
	if err != nil {
		return nil, err
	}
	var snapshot cacheSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, errors.New("invalid resource cache JSON")
	}
	if snapshot.Version != 1 || snapshot.Key != opts.Key || len(snapshot.Resources) > 4096 {
		return nil, errors.New("resource cache version, identity or count is invalid")
	}
	var total int64
	for raw, result := range snapshot.Resources {
		source, err := Parse(raw, "")
		if err != nil || !source.Remote() || source.Location != raw {
			return nil, errors.New("invalid resource cache source")
		}
		location, err := Resolve(raw, result.Location)
		if err != nil || location.Location != result.Location {
			return nil, errors.New("invalid resource cache response location")
		}
		total += int64(len(result.Data))
		if total > opts.MaxBytes {
			return nil, errors.New("resource cache exceeds the group byte limit")
		}
	}
	return &snapshot, ctx.Err()
}

func (c Cache) write(ctx context.Context, opts LoadOptions, snapshot *cacheSnapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if int64(len(data)) > opts.MaxBytes*4/3+8<<20 {
		return errors.New("encoded resource cache exceeds the size limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := openCacheDir(c.Dir, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	return writeCacheFile(ctx, dir, cacheName(opts.Key), data)
}

// Prune removes only this cache namespace's inactive, hash-named snapshots.
func (c Cache) Prune(keys []string) error {
	if c.Dir == "" {
		return nil
	}
	dir, err := openCacheDir(c.Dir, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	active := make(map[string]bool, len(keys))
	for _, key := range keys {
		active[cacheName(key)] = true
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		stem, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || len(stem) != sha256.Size*2 || active[entry.Name()] {
			continue
		}
		if _, err := hex.DecodeString(stem); err != nil {
			continue
		}
		if err := unix.Unlinkat(int(dir.Fd()), entry.Name(), 0); err != nil {
			return err
		}
	}
	return dir.Sync()
}
