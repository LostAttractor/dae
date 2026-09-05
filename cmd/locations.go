// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import "os"

const defaultCacheDirectory = "/var/lib/dae"

// Directory resolution never creates files or directories. Each writer creates
// only the state it needs; loading configuration must not create /etc/dae.
func cacheDirectory() string {
	if dir := os.Getenv("DAE_LOCATION_CACHE"); dir != "" {
		return dir
	}
	return defaultCacheDirectory
}
