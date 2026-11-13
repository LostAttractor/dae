// SPDX-License-Identifier: AGPL-3.0-only

package config

import "context"

// Load merges includes and validates a complete configuration without creating
// daemon resources.
func Load(path string) (*Config, []string, error) {
	return LoadContext(context.Background(), path)
}

// LoadContext loads configuration using the operation's recorded or replayed inputs.
func LoadContext(ctx context.Context, path string) (*Config, []string, error) {
	sections, includes, err := NewMerger(path).MergeContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	conf, err := New(sections)
	if err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}
