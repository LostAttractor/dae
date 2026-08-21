/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

var (
	ErrCircularInclude = fmt.Errorf("circular include is not allowed")
)

const (
	maxConfigFileSize   = 4 * 1024 * 1024
	maxMergedConfigSize = 16 * 1024 * 1024
	maxConfigFiles      = 1024
	maxIncludeDepth     = 32
)

type Merger struct {
	entry             string
	entryDir          string
	entryToSectionMap map[string]map[string][]*config_parser.Item
	mergedBytes       int64
	initErr           error
}

func NewMerger(entry string) *Merger {
	entry, err := filepath.Abs(entry)
	if err == nil {
		entry = filepath.Clean(entry)
	}
	return &Merger{
		entry:             entry,
		entryDir:          filepath.Dir(entry),
		entryToSectionMap: map[string]map[string][]*config_parser.Item{},
		initErr:           err,
	}
}

func (m *Merger) Merge() (sections []*config_parser.Section, entries []string, err error) {
	if m.initErr != nil {
		return nil, nil, fmt.Errorf("failed to resolve config entry path: %w", m.initErr)
	}
	opener, err := newSecureFileOpener(m.entryDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize config file opener for %v: %w", m.entryDir, err)
	}
	defer opener.Close()
	m.mergedBytes = 0

	err = m.dfsMerge(opener, m.entry, "", 0)
	if err != nil {
		return nil, nil, err
	}
	entries, err = common.MapKeys(m.entryToSectionMap)
	if err != nil {
		return nil, nil, err
	}
	return m.convertMapToSections(m.entryToSectionMap[m.entry]), entries, nil
}

func relativePathWithin(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("file is out of scope: %v", rel)
	}
	return rel, nil
}

func (m *Merger) relativeEntryPath(entry string) (string, error) {
	return relativePathWithin(m.entryDir, entry)
}

func (m *Merger) readEntry(opener *secureFileOpener, entry string) (err error) {
	// Check circular include.
	_, exist := m.entryToSectionMap[entry]
	if exist {
		return ErrCircularInclude
	}
	if len(m.entryToSectionMap) == maxConfigFiles {
		return fmt.Errorf("configuration includes more than %d files", maxConfigFiles)
	}

	// Check filename
	if !strings.HasSuffix(entry, ".dae") {
		return fmt.Errorf("invalid config filename %v: must has suffix .dae", entry)
	}
	var f *os.File
	if entry == m.entry {
		// The entry is explicitly selected by the user and may itself be a
		// symlink managed by systems such as NixOS. Includes remain confined to
		// the lexical entry directory below.
		f, err = openConfigEntry(entry)
	} else {
		f, err = opener.Open(entry)
	}
	if err != nil {
		return fmt.Errorf("failed to securely open config file %v: %w", entry, err)
	}
	defer f.Close()
	// Check file access.
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("config is not a regular file: %v", entry)
	}
	if fi.Mode()&0037 > 0 {
		return fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0777, entry)
	}
	// Read and parse.
	if fi.Size() > maxConfigFileSize {
		return fmt.Errorf("config file %v exceeds %d bytes", entry, maxConfigFileSize)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigFileSize+1))
	if err != nil {
		return err
	}
	if len(b) > maxConfigFileSize {
		return fmt.Errorf("config file %v exceeds %d bytes", entry, maxConfigFileSize)
	}
	m.mergedBytes += int64(len(b))
	if m.mergedBytes > maxMergedConfigSize {
		return fmt.Errorf("merged configuration exceeds %d bytes", maxMergedConfigSize)
	}
	entrySections, err := config_parser.Parse(string(b))
	if err != nil {
		return fmt.Errorf("failed to parse config file %v:\n%w", entry, err)
	}
	m.entryToSectionMap[entry] = m.convertSectionsToMap(entrySections)
	return nil
}

func unsqueezeEntries(patternEntries []string, limit int) (unsqueezed []string, err error) {
	if limit < 0 {
		return nil, fmt.Errorf("configuration includes more than %d files", maxConfigFiles)
	}
	unsqueezed = make([]string, 0, min(len(patternEntries), limit))
	for _, pattern := range patternEntries {
		files, err := globConfigFiles(pattern, limit-len(unsqueezed))
		if err != nil {
			return nil, err
		}
		unsqueezed = append(unsqueezed, files...)
	}
	if len(unsqueezed) == 0 {
		unsqueezed = nil
	}
	return unsqueezed, nil
}

func globConfigFiles(pattern string, limit int) ([]string, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(pattern)
	remainder := strings.TrimPrefix(pattern, volume)
	base := volume
	if filepath.IsAbs(pattern) {
		base += string(filepath.Separator)
		remainder = strings.TrimLeft(remainder, string(filepath.Separator))
	}
	parts := strings.Split(remainder, string(filepath.Separator))
	matches := make([]string, 0, min(limit, len(parts)))

	var walk func(string, int) error
	walk = func(path string, part int) error {
		if part == len(parts) {
			if !strings.HasSuffix(path, ".dae") {
				return nil
			}
			fi, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if !fi.Mode().IsRegular() {
				return nil
			}
			if len(matches) == limit {
				return fmt.Errorf("configuration includes more than %d files", maxConfigFiles)
			}
			matches = append(matches, path)
			return nil
		}

		component := parts[part]
		if !strings.ContainsAny(component, `*?[\`) {
			return walk(filepath.Join(path, component), part+1)
		}
		dir := path
		if dir == "" {
			dir = "."
		}
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			return nil
		}
		f, err := os.Open(dir)
		if err != nil {
			return nil
		}
		defer f.Close()
		for {
			entries, readErr := f.ReadDir(128)
			for _, entry := range entries {
				matched, matchErr := filepath.Match(component, entry.Name())
				if matchErr != nil {
					return matchErr
				}
				if matched {
					if err := walk(filepath.Join(path, entry.Name()), part+1); err != nil {
						return err
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return nil
			}
		}
		return nil
	}

	if err := walk(base, 0); err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

func (m *Merger) dfsMerge(opener *secureFileOpener, entry string, fatherEntry string, depth int) (err error) {
	if depth > maxIncludeDepth {
		return fmt.Errorf("configuration include depth exceeds %d at %v", maxIncludeDepth, entry)
	}
	// Read entry and check circular include.
	if err = m.readEntry(opener, entry); err != nil {
		if errors.Is(err, ErrCircularInclude) {
			return fmt.Errorf("%w: %v -> %v -> ... -> %v", err, fatherEntry, entry, fatherEntry)
		}
		return err
	}
	sectionMap := m.entryToSectionMap[entry]
	// Extract childEntries.
	includes := sectionMap["include"]
	var patterEntries = make([]string, 0, len(includes))
	for _, include := range includes {
		switch v := include.Value.(type) {
		case *config_parser.Param:
			nextEntry := v.String(true, false)
			if !filepath.IsAbs(nextEntry) {
				nextEntry = filepath.Join(m.entryDir, nextEntry)
			}
			nextEntry = filepath.Clean(nextEntry)
			if _, err := m.relativeEntryPath(nextEntry); err != nil {
				return fmt.Errorf("invalid include path %v in %v: %w", nextEntry, entry, err)
			}
			patterEntries = append(patterEntries, nextEntry)
		default:
			return fmt.Errorf("unsupported include grammar in %v: %v", entry, include.String(false, false))
		}
	}
	// DFS and merge children recursively.
	childEntries, err := unsqueezeEntries(patterEntries, maxConfigFiles-len(m.entryToSectionMap))
	if err != nil {
		return err
	}
	for _, nextEntry := range childEntries {
		nextEntry = filepath.Clean(nextEntry)
		if err = m.dfsMerge(opener, nextEntry, entry, depth+1); err != nil {
			return err
		}
	}
	/// Merge into father. Do not need to retrieve sectionMap again because go map is a reference.
	if fatherEntry == "" {
		// We are already on the top.
		return nil
	}
	fatherSectionMap := m.entryToSectionMap[fatherEntry]
	for sec := range sectionMap {
		items := m.mergeItems(fatherSectionMap[sec], sectionMap[sec])
		fatherSectionMap[sec] = items
	}
	return nil
}

func (m *Merger) convertSectionsToMap(sections []*config_parser.Section) (sectionMap map[string][]*config_parser.Item) {
	sectionMap = make(map[string][]*config_parser.Item)
	for _, sec := range sections {
		items, ok := sectionMap[sec.Name]
		if ok {
			sectionMap[sec.Name] = m.mergeItems(items, sec.Items)
		} else {
			sectionMap[sec.Name] = sec.Items
		}
	}
	return sectionMap
}

func (m *Merger) convertMapToSections(sectionMap map[string][]*config_parser.Item) (sections []*config_parser.Section) {
	sections = make([]*config_parser.Section, 0, len(sectionMap))
	for name, items := range sectionMap {
		sections = append(sections, &config_parser.Section{
			Name:  name,
			Items: items,
		})
	}
	return sections
}

func (m *Merger) mergeItems(to, from []*config_parser.Item) (items []*config_parser.Item) {
	items = make([]*config_parser.Item, len(to)+len(from))
	copy(items, to)
	copy(items[len(to):], from)
	return items
}
