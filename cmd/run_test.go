// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import "testing"

func TestRunArgumentsAfterConfigRepair(t *testing.T) {
	for _, configArg := range [][]string{{"-c", "config"}, {"--config=config"}, {"-cconfig"}} {
		t.Run(configArg[0], func(t *testing.T) {
			command := newRunCommand(nil)
			args := append([]string{"--disable-sudo", "--disable-timestamp=false", "--logfile=--config", "--logfile-maxsize=17"}, configArg...)
			args = append(args, "--")
			if err := command.ParseFlags(args); err != nil {
				t.Fatal(err)
			}
			cfgFile = "repaired config.dae"
			launch := commandArguments(command)
			if launch[0] != "run" {
				t.Fatalf("subcommand: %v", launch)
			}
			candidate := newRunCommand(nil)
			if err := candidate.ParseFlags(launch[1:]); err != nil {
				t.Fatal(err)
			}
			if cfgFile != "repaired config.dae" || !disableAuthSudo || disableTimestamp || logFile != "--config" || logFileMaxSize != 17 {
				t.Fatalf("candidate arguments changed effective options: %v", launch)
			}
		})
	}
}
