// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"fmt"
	"strings"
)

// Metadata describes a module without parsing its directives or loading any of
// its dependencies. Arguments retain the order of their declarations.
type Metadata struct {
	Name                 string
	Description          string
	ArgumentsDescription string
	Arguments            []Argument
}

// Argument declares a text parameter. An empty default and an omitted default
// differ: the latter requires the user to provide a value, which may be empty.
type Argument struct {
	Name       string
	Default    string
	HasDefault bool
}

// ReadMetadata reads the module's #!name, #!desc, #!arguments, and
// #!arguments-desc fields. The argument description is a single piece of display
// text; it does not declare per-argument types or choices.
func ReadMetadata(contents string) (Metadata, error) {
	if len(contents) > MaxModuleBytes {
		return Metadata{}, fmt.Errorf("module exceeds %d bytes", MaxModuleBytes)
	}
	if moduleLooksLikeHTML(contents) {
		return Metadata{}, errors.New("source returned an HTML document instead of a Surge module")
	}
	if !hasModuleSyntax(contents) {
		return Metadata{}, errors.New("source contains no Surge sections or metadata; provide a module source, not a standalone script")
	}
	var metadata Metadata
	declared := make(map[string]bool)
	for i, line := range strings.Split(strings.TrimPrefix(contents, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "#!name":
			metadata.Name = value
		case "#!desc":
			metadata.Description = strings.ReplaceAll(value, `\n`, "\n")
		case "#!arguments-desc":
			metadata.ArgumentsDescription = strings.ReplaceAll(value, `\n`, "\n")
		case "#!arguments":
			if value == "" {
				continue
			}
			for field := range strings.SplitSeq(value, ",") {
				name, defaultValue, hasDefault := strings.Cut(field, ":")
				name, defaultValue = strings.TrimSpace(name), strings.TrimSpace(defaultValue)
				if name == "" || strings.ContainsAny(name, "{}\r\n\x00") {
					return Metadata{}, fmt.Errorf("module line %d: invalid module argument %q", i+1, field)
				}
				if declared[name] {
					return Metadata{}, fmt.Errorf("module line %d: duplicate module argument %q", i+1, name)
				}
				if err := validateArgumentValue(name, defaultValue); err != nil {
					return Metadata{}, fmt.Errorf("module line %d: %w", i+1, err)
				}
				declared[name] = true
				metadata.Arguments = append(metadata.Arguments, Argument{Name: name, Default: defaultValue, HasDefault: hasDefault})
			}
		}
	}
	return metadata, nil
}

// resolveArguments distinguishes an absent override from an explicit empty
// value, and leaves all text unchanged for Surge's literal substitution.
func (m Metadata) resolveArguments(overrides map[string]string) (map[string]string, error) {
	values := make(map[string]string, len(m.Arguments))
	for _, argument := range m.Arguments {
		value, overridden := overrides[argument.Name]
		if !overridden {
			if !argument.HasDefault {
				return nil, fmt.Errorf("module argument %q requires a value", argument.Name)
			}
			value = argument.Default
		}
		if err := validateArgumentValue(argument.Name, value); err != nil {
			return nil, err
		}
		values[argument.Name] = value
	}
	for name := range overrides {
		if _, declared := values[name]; !declared {
			return nil, fmt.Errorf("unknown module argument override %q", name)
		}
	}
	return values, nil
}

func validateArgumentValue(name, value string) error {
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("module argument %q contains a newline or NUL", name)
	}
	return nil
}
