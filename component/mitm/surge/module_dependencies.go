// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/resource"
)

type moduleResourceReader func(resource.Source, *time.Duration) (string, error)

// Each resolved dependency is read once per module, including local files.
// All dependency kinds share the same total size and cancellation boundary.
func cacheModuleResources(ctx context.Context, read moduleResourceReader) moduleResourceReader {
	cache := make(map[string]string)
	var loadedBytes int
	return func(path resource.Source, interval *time.Duration) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if contents, ok := cache[path.Location]; ok {
			return contents, nil
		}
		contents, err := read(path, interval)
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
}

func (m *Module) loadScriptSources(location string, read moduleResourceReader) error {
	intervals := make(map[string]time.Duration)
	for _, scripts := range [][]Script{m.Scripts, m.TaskScripts} {
		for i := range scripts {
			script := &scripts[i]
			path, err := resource.Resolve(location, script.Path)
			if err != nil {
				return fmt.Errorf("script %q: %w", script.Name, err)
			}
			script.Path = path.Location
			interval, exists := intervals[script.Path]
			if !exists || interval == 0 || script.UpdateInterval > 0 && script.UpdateInterval < interval {
				intervals[script.Path] = script.UpdateInterval
			}
		}
	}
	for _, scripts := range [][]Script{m.Scripts, m.TaskScripts} {
		for i := range scripts {
			script := &scripts[i]
			path := resource.Source{Location: script.Path}
			contents, err := read(path, new(intervals[script.Path]))
			if err != nil {
				return fmt.Errorf("load script %q: %w", script.Name, err)
			}
			if path.Remote() && moduleLooksLikeHTML(contents) {
				return fmt.Errorf("load script %q: remote source returned an HTML document instead of JavaScript", script.Name)
			}
			script.Source = contents
		}
	}
	return nil
}

func (m *Module) loadHostSets(location string, read moduleResourceReader) error {
	for i := range m.DNSHosts {
		host := &m.DNSHosts[i]
		if host.SetKind == "" {
			continue
		}
		path, err := resource.Resolve(location, host.SetSource)
		if err != nil {
			return err
		}
		contents, err := read(path, nil)
		if err != nil {
			return fmt.Errorf("load Host %s: %w", host.SetKind, err)
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
					return err
				}
			}
			clauses, _, err := parseModuleRuleExpression(fields, 0, false)
			if errors.Is(err, errUnsupportedModuleRule) {
				continue
			}
			if err != nil {
				return fmt.Errorf("Host set: %w", err)
			}
			host.Rules = append(host.Rules, ModuleRule{clauses: clauses})
		}
	}
	return nil
}

func (m *Module) loadMapLocalFiles(location string, read moduleResourceReader) error {
	mapBodies := make(map[string][]byte)
	for i := range m.MapLocals {
		rule := &m.MapLocals[i]
		if rule.DataType != "file" {
			continue
		}
		path, err := resource.Resolve(location, rule.Data)
		if err != nil {
			return fmt.Errorf("Map Local data: %w", err)
		}
		if body, ok := mapBodies[path.Location]; ok {
			rule.Body = body
			continue
		}
		contents, err := read(path, nil)
		if err != nil {
			return fmt.Errorf("load Map Local data: %w", err)
		}
		rule.Body = []byte(contents)
		mapBodies[path.Location] = rule.Body
	}
	return nil
}
