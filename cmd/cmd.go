/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/spf13/cobra"
)

var (
	Version = "unknown"
	rootCmd = &cobra.Command{
		Use:     "dae [flags] [command [argument ...]]",
		Short:   "dae is a high-performance transparent proxy solution.",
		Long:    `dae is a high-performance transparent proxy solution.`,
		Version: Version,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
)

func init() {
	http.DefaultClient.Timeout = 30 * time.Second
	config.Version = Version
	rootCmd.Version = strings.Join([]string{
		Version,
		fmt.Sprintf("go runtime %v %v/%v", runtime.Version(), runtime.GOOS, runtime.GOARCH),
		"Copyright (c) 2022-2025 @daeuniverse",
		"License GNU AGPLv3 <https://github.com/daeuniverse/dae/blob/main/LICENSE>",
	}, "\n")
}

// Execute runs the process CLI. Plugin selection is captured by its run command
// and carried through startup and reload, without a global plugin registry.
func Execute() error {
	definitions := compiledPlugins()
	var connection cli.Connection
	services := plugin.CommandServices{BaseDir: common.CacheDirectory(), Status: connection.MITM, TriggerScript: connection.TriggerScript}
	mitm := newMITMCommand(definitions, services)
	plugins := newPluginsCommand(definitions, services)
	connection.Bind(plugins.PersistentFlags())
	rootCmd.AddCommand(newRunCommand(definitions), mitm, plugins)
	return rootCmd.Execute()
}
