// SPDX-License-Identifier: AGPL-3.0-only

package config

// Certificate selects a daemon-wide identity independently of interception.
// Empty paths use the persistent managed CA.
type Certificate struct {
	CACert string `mapstructure:"ca_cert"`
	CAKey  string `mapstructure:"ca_key"`
}
