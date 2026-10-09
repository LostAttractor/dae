// SPDX-License-Identifier: AGPL-3.0-only

package config

// Load merges includes and validates a complete configuration without creating
// daemon resources.
func Load(path string) (*Config, []string, error) {
	sections, includes, err := NewMerger(path).Merge()
	if err != nil {
		return nil, nil, err
	}
	conf, err := New(sections)
	if err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}
