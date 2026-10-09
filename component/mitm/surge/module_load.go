// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
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
		module, err := loadModuleContents(ctx, string(current.Data), current.Location, options.Arguments, func(dependency resource.Source) (string, error) {
			result, err := readResource(dependency, resource.ReadOptions{MaxBytes: MaxScriptBytes})
			return string(result.Data), err
		})
		if err == nil {
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

func loadModuleContents(ctx context.Context, contents, location string, arguments map[string]string, read func(resource.Source) (string, error)) (*Module, error) {
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
	cache := make(map[string]string)
	var loadedBytes int
	loadResource := func(path resource.Source) (string, error) {
		if contents, ok := cache[path.Location]; ok {
			return contents, nil
		}
		contents, err := read(path)
		if err != nil {
			return "", err
		}
		loadedBytes += len(contents)
		if loadedBytes > MaxModuleScriptBytes {
			return "", fmt.Errorf("module dependencies exceed %d total bytes", MaxModuleScriptBytes)
		}
		cache[path.Location] = contents
		return contents, nil
	}
	for _, scripts := range [][]Script{m.Scripts, m.TaskScripts} {
		for i := range scripts {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			script := &scripts[i]
			path, err := resource.Resolve(location, script.Path)
			if err != nil {
				return nil, fmt.Errorf("script %q: %w", script.Name, err)
			}
			contents, err := loadResource(path)
			if err != nil {
				return nil, fmt.Errorf("load script %q: %w", script.Name, err)
			}
			if path.Remote() && moduleLooksLikeHTML(contents) {
				return nil, fmt.Errorf("load script %q: remote source returned an HTML document instead of JavaScript", script.Name)
			}
			script.Source = contents
			script.Path = path.Location
		}
	}
	for i := range m.DNSHosts {
		host := &m.DNSHosts[i]
		if host.SetKind == "" {
			continue
		}
		path, err := resource.Resolve(location, host.SetSource)
		if err != nil {
			return nil, err
		}
		contents, err := loadResource(path)
		if err != nil {
			return nil, fmt.Errorf("load Host %s: %w", host.SetKind, err)
		}
		for line := range strings.SplitSeq(contents, "\n") {
			line = strings.TrimSpace(trimModuleRuleComment(line))
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			var fields []string
			if host.SetKind == "DOMAIN-SET" {
				kind := "DOMAIN"
				if after, ok := strings.CutPrefix(line, "."); ok {
					kind, line = "DOMAIN-SUFFIX", after
				}
				fields = []string{kind, line}
			} else {
				fields, err = splitModuleRuleFields(line)
				if err != nil {
					return nil, err
				}
			}
			clauses, _, err := parseModuleRuleExpression(fields, 0, false)
			if errors.Is(err, errUnsupportedModuleRule) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("Host set: %w", err)
			}
			host.Rules = append(host.Rules, ModuleRule{clauses: clauses})
		}
	}
	mapBodies := make(map[string][]byte)
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
		if body, ok := mapBodies[path.Location]; ok {
			rule.Body = body
			continue
		}
		contents, err := loadResource(path)
		if err != nil {
			return nil, fmt.Errorf("load Map Local data: %w", err)
		}
		rule.Body = []byte(contents)
		mapBodies[path.Location] = rule.Body
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
