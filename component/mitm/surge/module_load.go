// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/resource"
)

type LoadOptions struct {
	BaseDir   string
	CacheDir  string
	Arguments map[string]string
	// RefreshDeadline only bounds remote refresh attempts. Cached resources
	// remain available until the caller's context itself is canceled.
	RefreshDeadline time.Time
}

const (
	MaxModuleBytes       = 4 << 20
	MaxScriptBytes       = 16 << 20
	MaxModuleScriptBytes = 64 << 20
	resourceTimeout      = 30 * time.Second
	moduleLoadTimeout    = 2 * time.Minute
)

// Load applies the source's explicit persistence policy. A persistent remote
// module refreshes and falls back as one complete snapshot. Other modules always
// use their current contents; only dependencies marked http(s)-file may fall back.
func Load(ctx context.Context, raw string, client *http.Client, options LoadOptions) (*Module, error) {
	source, err := resource.Parse(raw, options.BaseDir)
	if err != nil {
		return nil, err
	}
	m, snapshot, refreshErr := refreshModule(ctx, source, client, options)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if refreshErr != nil {
		if !source.Persistent {
			return nil, fmt.Errorf("load module: %w", refreshErr)
		}
		// A persistent module rolls back as a whole. Never mix the old module
		// text with dependencies from an incomplete refresh.
		previous, err := readFallbackCache(ctx, source, options, refreshErr)
		if err != nil {
			return nil, err
		}
		m, err = loadModuleContents(ctx, string(previous.Module.Data), previous.Module.Location, options.Arguments, func(dependency resource.Source, _ bool) (string, error) {
			cached, ok := previous.Resources[dependency.Location]
			if !ok {
				return "", errors.New("dependency is not present in the last complete module cache")
			}
			return string(cached.Data), nil
		})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("module refresh failed: %w; cached module could not be loaded: %v", refreshErr, err)
		}
		moduleCacheWarning(m, fmt.Sprintf("module refresh failed; using the last complete local cache: %v", refreshErr))
		m.cacheState = "cached"
	} else if options.CacheDir != "" && (snapshot.Module != nil || len(snapshot.Resources) != 0) {
		if err := writeModuleCache(ctx, options.CacheDir, snapshot); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			moduleCacheWarning(m, fmt.Sprintf("module loaded successfully, but its local cache could not be updated: %v", err))
		}
	}
	m.source = resource.RedactURL(raw)
	return m, nil
}

// refreshModule builds a complete candidate without changing the saved cache.
// Nonpersistent modules may reuse only explicitly persistent dependencies.
func refreshModule(ctx context.Context, source resource.Source, client *http.Client, options LoadOptions) (*Module, *moduleCacheSnapshot, error) {
	deadline := time.Now().Add(moduleLoadTimeout)
	if !options.RefreshDeadline.IsZero() && options.RefreshDeadline.Before(deadline) {
		deadline = options.RefreshDeadline
	}
	refreshCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	readCurrent := func(source resource.Source, limit int64) (resource.Result, error) {
		resourceCtx := ctx
		if source.Remote() {
			resourceCtx = refreshCtx
		}
		resourceCtx, cancel := context.WithTimeout(resourceCtx, resourceTimeout)
		defer cancel()
		return resource.Read(resourceCtx, client, source, resource.ReadOptions{MaxBytes: limit})
	}
	current, err := readCurrent(source, MaxModuleBytes)
	if err != nil {
		return nil, nil, err
	}
	snapshot := &moduleCacheSnapshot{
		Version: moduleCacheVersion, Source: source.Location, Arguments: options.Arguments,
		Resources: make(map[string]moduleCachedResource),
	}
	if source.Persistent {
		snapshot.Module = &moduleCachedResource{Location: current.Location, Data: current.Data}
	}
	// Deduplicate downloads by location. Keep errors too: a later ordinary
	// HTTP reference must not reuse an explicitly persistent reference's cache.
	type download struct {
		result resource.Result
		err    error
	}
	downloads := make(map[string]download)
	var previous *moduleCacheSnapshot
	var warnings []string
	readDependency := func(dependency resource.Source, script bool) (string, error) {
		fetched, ok := downloads[dependency.Location]
		if !ok {
			fetched.result, fetched.err = readCurrent(dependency, MaxScriptBytes)
			if fetched.err == nil && script && dependency.Remote() && moduleLooksLikeHTML(string(fetched.result.Data)) {
				fetched.err = errors.New("remote source returned an HTML document instead of JavaScript")
			}
			downloads[dependency.Location] = fetched
		}
		current, err := fetched.result, fetched.err
		if err != nil && !source.Persistent && dependency.Persistent {
			if previous == nil {
				var cacheErr error
				previous, cacheErr = readFallbackCache(ctx, source, options, err)
				if cacheErr != nil {
					return "", cacheErr
				}
			}
			cached, ok := previous.Resources[dependency.Location]
			if !ok {
				return "", fmt.Errorf("dependency refresh failed: %w; dependency is not present in the local cache", err)
			}
			warnings = append(warnings, fmt.Sprintf("dependency %s refresh failed; using its local cache: %v", dependency.Location, err))
			current, err = resource.Result{Data: cached.Data, Location: cached.Location}, nil
		}
		if err != nil {
			return "", err
		}
		if dependency.Remote() && (source.Persistent || dependency.Persistent) {
			snapshot.Resources[dependency.Location] = moduleCachedResource{Location: current.Location, Data: current.Data}
		}
		return string(current.Data), nil
	}
	m, err := loadModuleContents(ctx, string(current.Data), current.Location, options.Arguments, readDependency)
	if err != nil {
		return nil, nil, err
	}
	if len(warnings) != 0 {
		m.cacheState = "cached dependencies"
		for _, warning := range warnings {
			moduleCacheWarning(m, warning)
		}
	}
	return m, snapshot, nil
}

func readFallbackCache(ctx context.Context, source resource.Source, options LoadOptions, refreshErr error) (*moduleCacheSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.CacheDir == "" {
		return nil, refreshErr
	}
	snapshot, err := readModuleCache(ctx, options.CacheDir, source.Location, options.Arguments, source.Persistent)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, refreshErr
	}
	if err != nil {
		return nil, fmt.Errorf("module refresh failed: %w; local cache unavailable: %v", refreshErr, err)
	}
	return snapshot, nil
}

func moduleCacheWarning(m *Module, warning string) {
	m.Warnings = append(m.Warnings, resource.RedactText(warning))
}

func loadModuleContents(ctx context.Context, contents, location string, arguments map[string]string, read func(resource.Source, bool) (string, error)) (*Module, error) {
	m, err := Parse(contents, arguments)
	if err != nil {
		return nil, err
	}
	if m.Name == "" {
		if parsed, err := url.Parse(location); err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
			m.Name = filepath.Base(parsed.Path)
		} else {
			m.Name = filepath.Base(location)
		}
	}
	cache := make(map[resource.Source]string)
	var loadedBytes int
	counted := make(map[string]bool)
	loadResource := func(path resource.Source, script bool) (string, error) {
		if contents, ok := cache[path]; ok {
			return contents, nil
		}
		contents, err := read(path, script)
		if err != nil {
			return "", err
		}
		if !counted[path.Location] {
			loadedBytes += len(contents)
			counted[path.Location] = true
		}
		if loadedBytes > MaxModuleScriptBytes {
			return "", fmt.Errorf("module dependencies exceed %d total bytes", MaxModuleScriptBytes)
		}
		cache[path] = contents
		return contents, nil
	}
	for i := range m.Scripts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		script := &m.Scripts[i]
		path, err := resource.Resolve(location, script.Path)
		if err != nil {
			return nil, fmt.Errorf("script %q: %w", script.Name, err)
		}
		contents, err := loadResource(path, true)
		if err != nil {
			return nil, fmt.Errorf("load script %q: %w", script.Name, err)
		}
		if path.Remote() && moduleLooksLikeHTML(contents) {
			return nil, fmt.Errorf("load script %q: remote source returned an HTML document instead of JavaScript", script.Name)
		}
		script.Source = contents
	}
	mapBodies := make(map[resource.Source][]byte)
	for i := range m.MapLocals {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rule := &m.MapLocals[i]
		if rule.DataType != "file" {
			continue
		}
		path, err := resource.Resolve(location, rule.Data)
		if err != nil {
			return nil, fmt.Errorf("Map Local data: %w", err)
		}
		if body, ok := mapBodies[path]; ok {
			rule.Body = body
			continue
		}
		contents, err := loadResource(path, false)
		if err != nil {
			return nil, fmt.Errorf("load Map Local data: %w", err)
		}
		rule.Body = []byte(contents)
		mapBodies[path] = rule.Body
	}
	return m, nil
}

// The parser deliberately warns about unsupported sections. Require a module
// marker first so that an HTTP 200 plain-text error cannot replace its cache.
// Metadata-only modules can intentionally disable all of their directives.
func hasModuleSyntax(contents string) bool {
	for _, line := range strings.Split(strings.TrimPrefix(contents, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#!") && strings.Contains(line, "=") || strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			return true
		}
	}
	return false
}

func moduleLooksLikeHTML(contents string) bool {
	contents = strings.TrimSpace(strings.TrimPrefix(contents, "\ufeff"))
	for strings.HasPrefix(contents, "<!--") {
		end := strings.Index(contents, "-->")
		if end < 0 {
			return false
		}
		contents = strings.TrimSpace(contents[end+3:])
	}
	contents = strings.ToLower(contents[:min(len(contents), 32)])
	for _, prefix := range []string{"<!doctype html", "<html", "<head", "<body", "<title"} {
		if strings.HasPrefix(contents, prefix) && (len(contents) == len(prefix) || strings.ContainsRune(" \t\r\n>/", rune(contents[len(prefix)]))) {
			return true
		}
	}
	return false
}
