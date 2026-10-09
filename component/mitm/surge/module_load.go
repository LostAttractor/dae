// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
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

// Load validates a module and its dependencies as one resource cache group.
// Local modules always use current contents, including during cache fallback.
func Load(ctx context.Context, raw string, client *http.Client, options LoadOptions) (*Module, error) {
	source, err := resource.Parse(raw, options.BaseDir)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(moduleLoadTimeout)
	if !options.RefreshDeadline.IsZero() && options.RefreshDeadline.Before(deadline) {
		deadline = options.RefreshDeadline
	}
	// Deterministic map encoding makes equivalent overrides share a snapshot.
	key, err := json.Marshal(struct {
		Source    string
		Arguments map[string]string `json:",omitempty"`
	}{source.Location, options.Arguments}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	cache := resource.Cache{Dir: options.CacheDir}
	m, status, err := cache.Load(ctx, client, resource.LoadOptions{
		Key: string(key), MaxBytes: MaxModuleBytes + MaxModuleScriptBytes,
		RefreshDeadline: deadline, Timeout: resourceTimeout,
	}, func(read resource.ReadFunc) (*Module, error) {
		digest := sha256.New()
		readResource := func(source resource.Source, options resource.ReadOptions) (resource.Result, error) {
			result, err := read(source, options)
			if err == nil {
				fmt.Fprintf(digest, "%d:%s%d:%s%d:", len(source.Location), source.Location, len(result.Location), result.Location, len(result.Data))
				digest.Write(result.Data)
			}
			return result, err
		}
		current, err := readResource(source, resource.ReadOptions{MaxBytes: MaxModuleBytes})
		if err != nil {
			return nil, err
		}
		module, err := loadModuleContents(ctx, string(current.Data), current.Location, options.Arguments, func(dependency resource.Source, interval *time.Duration) (string, error) {
			result, err := readResource(dependency, resource.ReadOptions{MaxBytes: MaxScriptBytes, RefreshInterval: interval})
			return string(result.Data), err
		})
		if err == nil {
			digest.Write([]byte(module.requirementKey))
			module.contentKey = fmt.Sprintf("%x", digest.Sum(nil))
		}
		return module, err
	})
	if err != nil {
		return nil, fmt.Errorf("load module: %w", err)
	}
	if status.RefreshError != nil {
		m.cacheState = "cached"
		if !source.Remote() {
			m.cacheState = "cached dependencies"
		}
		moduleCacheWarning(m, fmt.Sprintf("module refresh failed; using the last complete resource cache: %v", status.RefreshError))
	}
	if status.WriteError != nil {
		moduleCacheWarning(m, fmt.Sprintf("module loaded successfully, but its resource cache could not be updated: %v", status.WriteError))
	}
	m.source = resource.RedactURL(raw)
	return m, nil
}

func moduleCacheWarning(m *Module, warning string) {
	m.Warnings = append(m.Warnings, resource.RedactText(warning))
}

func loadModuleContents(ctx context.Context, contents, location string, arguments map[string]string, read moduleResourceReader) (*Module, error) {
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
	read = cacheModuleResources(ctx, read)
	if err := m.loadScriptSources(location, read); err != nil {
		return nil, err
	}
	if err := m.loadHostSets(location, read); err != nil {
		return nil, err
	}
	if err := m.loadMapLocalFiles(location, read); err != nil {
		return nil, err
	}
	return m, nil
}

// The parser deliberately warns about unsupported sections. Require a module
// marker first so that an HTTP 200 plain-text error cannot replace its cache.
// Metadata-only modules can intentionally disable all of their directives.
func hasModuleSyntax(contents string) bool {
	for line := range strings.SplitSeq(strings.TrimPrefix(contents, "\ufeff"), "\n") {
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
