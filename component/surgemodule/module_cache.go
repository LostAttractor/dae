// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/resource"
)

const (
	moduleCacheVersion = 1
	// JSON represents binary payloads as base64. Allow bounded metadata in
	// addition to the existing raw module and dependency size limits.
	maxModuleCacheBytes     = (MaxModuleBytes+MaxModuleScriptBytes)*4/3 + 8<<20
	maxModuleCacheResources = 4096
)

type moduleCachedResource struct {
	Location string `json:"location"`
	Data     []byte `json:"data"`
}

type moduleCacheSnapshot struct {
	Version   int                             `json:"version"`
	Source    string                          `json:"source"`
	Arguments map[string]string               `json:"arguments,omitempty"`
	Module    *moduleCachedResource           `json:"module,omitempty"`
	Resources map[string]moduleCachedResource `json:"resources"`
}

func isRemoteModuleSource(raw string) bool {
	source, err := resource.Parse(raw, "")
	return err == nil && source.Remote() && !source.Persistent && source.Location == raw
}

func validCachedLocation(source, location string) bool {
	return isRemoteModuleSource(location) &&
		(!strings.HasPrefix(source, "https://") || strings.HasPrefix(location, "https://"))
}

func moduleCachePath(dir, source string, arguments map[string]string) string {
	// JSON sorts map keys, so equivalent overrides share a cache regardless of
	// declaration order. Treat an empty map and omitted overrides identically.
	if len(arguments) == 0 {
		arguments = nil
	}
	identity, _ := json.Marshal(struct {
		Source    string
		Arguments map[string]string
	}{source, arguments})
	sum := sha256.Sum256(identity)
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

func checkModuleCacheDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("module cache directory must be a real directory")
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("module cache directory must not be writable by group or others")
	}
	return nil
}

func readModuleCache(ctx context.Context, dir, identity string, arguments map[string]string, cacheModule bool) (*moduleCacheSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkModuleCacheDirectory(dir); err != nil {
		return nil, err
	}
	path := moduleCachePath(dir, identity, arguments)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxModuleCacheBytes {
		return nil, errors.New("module cache must be a private regular file within the cache size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > maxModuleCacheBytes {
		return nil, errors.New("module cache changed while it was opened")
	}
	reader := io.LimitReader(common.NewContextReader(ctx, f), maxModuleCacheBytes+1)
	var snapshot moduleCacheSnapshot
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode module cache: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("module cache contains trailing data")
	}
	if err := validateModuleCache(&snapshot, identity, arguments, cacheModule); err != nil {
		return nil, err
	}
	return &snapshot, ctx.Err()
}

func validateModuleCache(snapshot *moduleCacheSnapshot, identity string, arguments map[string]string, cacheModule bool) error {
	if snapshot.Version != moduleCacheVersion || snapshot.Source != identity || !maps.Equal(snapshot.Arguments, arguments) {
		return errors.New("module cache version, source, or arguments do not match")
	}
	if cacheModule {
		if snapshot.Module == nil || len(snapshot.Module.Data) > MaxModuleBytes || !validCachedLocation(identity, snapshot.Module.Location) {
			return errors.New("module cache has an invalid remote module resource")
		}
	} else if snapshot.Module != nil {
		return errors.New("dependency cache must not replace the module file")
	}
	if len(snapshot.Resources) > maxModuleCacheResources {
		return errors.New("module cache contains too many resources")
	}
	total := 0
	for source, resource := range snapshot.Resources {
		if !isRemoteModuleSource(source) || !validCachedLocation(source, resource.Location) || len(resource.Data) > MaxScriptBytes {
			return errors.New("module cache contains an invalid remote dependency")
		}
		total += len(resource.Data)
		if total > MaxModuleScriptBytes {
			return errors.New("module cache dependencies exceed the module resource size limit")
		}
	}
	return nil
}

func writeModuleCache(ctx context.Context, dir string, snapshot *moduleCacheSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateModuleCache(snapshot, snapshot.Source, snapshot.Arguments, snapshot.Module != nil); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := checkModuleCacheDirectory(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".module-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := json.NewEncoder(f).Encode(snapshot); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxModuleCacheBytes {
		return errors.New("module cache exceeds the cache size limit")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), moduleCachePath(dir, snapshot.Source, snapshot.Arguments)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
