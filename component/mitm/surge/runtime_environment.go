// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"cmp"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

func scriptEnvironment() map[string]string {
	language := cmp.Or(os.Getenv("LC_ALL"), os.Getenv("LC_MESSAGES"), os.Getenv("LANG"), "en")
	language, _, _ = strings.Cut(language, ".")
	language, _, _ = strings.Cut(language, "@")
	if language == "C" || language == "POSIX" {
		language = "en"
	}
	model := runtime.GOARCH
	for _, path := range []string{"/sys/devices/virtual/dmi/id/product_name", "/proc/device-tree/model"} {
		if data, err := os.ReadFile(path); err == nil && len(data) != 0 {
			model = strings.Trim(strings.TrimSpace(string(data)), "\x00")
			break
		}
	}
	env := map[string]string{
		"system": runtime.GOOS, "language": strings.ReplaceAll(language, "_", "-"), "device-model": model,
		"surge-version": "", "surge-build": "", "dae-runtime": "quickjs",
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		env["dae-version"] = build.Main.Version
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" {
				env["dae-build"] = setting.Value
			}
		}
	}
	return env
}
