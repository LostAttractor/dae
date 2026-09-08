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
	"github.com/daeuniverse/dae/common/json"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/config"
	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
	"github.com/spf13/cobra"
)

const (
	AbortFile = "/var/run/dae.abort"
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
	jsoniter.RegisterTypeDecoder("bool", &json.FuzzyBoolDecoder{})
	extra.RegisterFuzzyDecoders()
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
	definitions := compiledMITMPlugins()
	setups := make(map[string]plugin.Setup, len(definitions))
	for name, definition := range definitions {
		setups[name] = definition.Setup
	}
	var connection cli.Connection
	mitm := newMITMCommand(definitions, plugin.CommandServices{BaseDir: cacheDirectory(), Status: connection.MITM})
	connection.Bind(mitm.PersistentFlags())
	rootCmd.AddCommand(newRunCommand(setups), mitm)
	return rootCmd.Execute()
}
