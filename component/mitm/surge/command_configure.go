// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/spf13/cobra"
)

func Commands(services plugin.CommandServices) []*cobra.Command {
	var name string
	configure := &cobra.Command{
		Use: "configure <source>", Short: "Choose module arguments and print a configuration fragment.",
		Long: `Read a Surge module URL or file: source and prompt for its declared arguments.
Only the module text is downloaded; scripts are not downloaded or executed.
Prompts go to stderr. Place the generated module section inside plugins.surge in your config.
Daemon resource caching follows global.resource_cache; relative file: paths
use DAE_LOCATION_CACHE or /var/lib/dae. This command does not write cache files.`,
		Args: cobra.ExactArgs(1), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(name) {
				return fmt.Errorf("--name must start with an ASCII letter or underscore and contain only ASCII letters, digits, or underscores")
			}
			source, err := resource.Parse(args[0], services.BaseDir)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 30 * time.Second}
			result, err := resource.Read(cmd.Context(), client, source, resource.ReadOptions{MaxBytes: MaxModuleBytes})
			if err != nil {
				return fmt.Errorf("read module: %w", err)
			}
			contents := string(result.Data)
			metadata, err := ReadMetadata(contents)
			if err != nil {
				return err
			}
			arguments, err := promptModuleArguments(cmd.InOrStdin(), cmd.ErrOrStderr(), metadata)
			if err != nil {
				return err
			}
			if _, err := Parse(contents, arguments); err != nil {
				return err
			}
			module := ModuleSource{Name: name, Link: strings.TrimSpace(args[0]), Arguments: arguments}
			output, err := FormatModuleSource(module)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Place this module section inside plugins.surge (or another Surge plugin instance) in your configuration:")
			_, err = fmt.Fprint(cmd.OutOrStdout(), output)
			return err
		},
	}
	configure.Flags().StringVar(&name, "name", "module", "Module name in the generated configuration")
	return []*cobra.Command{cli.NewSurgeStatusCommand(services.Status), configure}
}

func promptModuleArguments(input io.Reader, output io.Writer, metadata Metadata) (map[string]string, error) {
	for _, description := range []string{metadata.Name, metadata.Description, metadata.ArgumentsDescription} {
		if description != "" {
			fmt.Fprintln(output, description)
		}
	}
	if len(metadata.Arguments) == 0 {
		fmt.Fprintln(output, "This module declares no arguments.")
		return nil, nil
	}
	fmt.Fprintln(output, `Press Enter to inherit the module default without an override; type "" for an empty value. Other input is used verbatim.`)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), MaxModuleBytes)
	values := make(map[string]string, len(metadata.Arguments))
	for _, argument := range metadata.Arguments {
		for {
			if argument.HasDefault {
				fmt.Fprintf(output, "%s [default: %q]: ", argument.Name, argument.Default)
			} else {
				fmt.Fprintf(output, "%s [required]: ", argument.Name)
			}
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return nil, fmt.Errorf("read argument %q: %w", argument.Name, err)
				}
				return nil, fmt.Errorf("input ended before argument %q was configured", argument.Name)
			}
			value := scanner.Text()
			if value == "" {
				if argument.HasDefault {
					break
				}
				fmt.Fprintln(output, `A value is required; type "" to set an empty value.`)
				continue
			}
			if value == `""` {
				value = ""
			}
			values[argument.Name] = value
			break
		}
	}
	return values, nil
}
