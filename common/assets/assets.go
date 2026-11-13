/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package assets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/common/resource"

	"github.com/adrg/xdg"
	log "github.com/sirupsen/logrus"
)

const CacheTimeout = 5 * time.Second

type CacheItem struct {
	Filename string
	Path     string

	CacheDeadline time.Time
}

type LocationFinder struct {
	mu         sync.Mutex
	m          map[string]CacheItem
	externDirs []string
}

func NewLocationFinder(externDirPath []string) *LocationFinder {
	return &LocationFinder{
		mu:         sync.Mutex{},
		m:          map[string]CacheItem{},
		externDirs: externDirPath,
	}
}

func (c *LocationFinder) GetLocationAsset(filename string) (string, error) {
	return c.GetLocationAssetContext(context.Background(), filename)
}

// GetLocationAssetContext freezes selection before callers read the chosen asset.
func (c *LocationFinder) GetLocationAssetContext(ctx context.Context, filename string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !resource.HasInputs(ctx) {
		path, err := c.findLocationAsset(filename)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return path, err
	}
	paths := append([]string{filename}, c.externDirs...)
	for _, path := range paths {
		if strings.ContainsRune(path, 0) {
			return "", fmt.Errorf("asset path contains NUL: %w", fs.ErrInvalid)
		}
	}
	// Linux paths are arbitrary bytes except NUL, which separates tuple members.
	key := "assets/location:" + strings.Join(paths, "\x00")
	data, err := resource.ReadInput(ctx, key, func(context.Context) ([]byte, error) {
		path, err := c.findLocationAsset(filename)
		return []byte(path), err
	})
	return string(data), err
}

func (c *LocationFinder) findLocationAsset(filename string) (path string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Search cache.
	if item, ok := c.m[filename]; ok && time.Now().Before(item.CacheDeadline) {
		return item.Path, nil
	}
	defer func() {
		if err == nil {
			c.m[filename] = CacheItem{
				Filename:      filename,
				Path:          path,
				CacheDeadline: time.Now().Add(CacheTimeout),
			}
			time.AfterFunc(CacheTimeout, func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				if item, ok := c.m[filename]; ok && time.Now().After(item.CacheDeadline) {
					delete(c.m, filename)
				}
			})
		}
	}()

	// Search dirs.
	var searchDirs []string
	folder := consts.AppName
	// check if DAE_LOCATION_ASSET is set
	location := os.Getenv("DAE_LOCATION_ASSET")
	if location != "" {
		// add DAE_LOCATION_ASSET to search path
		searchDirs = append(searchDirs, location)
		// add /etc/dae to search path
		searchDirs = append(searchDirs, c.externDirs...)
		searchDirs = append(
			searchDirs,
			filepath.Join("/usr/local/share", folder),
			filepath.Join("/usr/share", folder),
		)
	} else {
		// add /etc/dae to search path
		searchDirs = append(searchDirs, c.externDirs...)
		xdgDirs := append([]string{xdg.DataHome}, xdg.DataDirs...)
		for i := range xdgDirs {
			xdgDirs[i] = filepath.Join(xdgDirs[i], folder)
		}
		searchDirs = append(searchDirs, xdgDirs...)
	}
	log.Tracef(`Search "%v" in [%v]`, filename, strings.Join(searchDirs, ", "))
	for _, searchDir := range searchDirs {
		searchPath := filepath.Join(searchDir, filename)
		if _, err = os.Stat(searchPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", err
		}
		log.Debugf(`Found "%v" at %v`, filename, searchPath)
		// return the first path that exists
		return searchPath, nil
	}
	return "", fmt.Errorf("%v: %w in [%v]", filename, os.ErrNotExist, strings.Join(searchDirs, ", "))
}

// ReadFileContext records asset bytes only during initialization input capture.
// Ordinary reads retain their existing semantics and callers may keep mmap/seek.
func ReadFileContext(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !resource.HasInputs(ctx) {
		return os.ReadFile(path)
	}
	return resource.ReadInput(ctx, "assets/file:"+path, func(ctx context.Context) ([]byte, error) {
		file, info, err := fileio.OpenRegular(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if info.Size() > resource.MaxInputBytes {
			return nil, fmt.Errorf("%w: asset %q exceeds %d bytes", resource.ErrInputRecording, path, resource.MaxInputBytes)
		}
		data, err := fileio.ReadBounded(ctx, file, resource.MaxInputBytes)
		if errors.Is(err, fileio.ErrTooLarge) {
			return nil, fmt.Errorf("%w: asset %q: %w", resource.ErrInputRecording, path, err)
		}
		return data, err
	})
}
