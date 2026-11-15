// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	surgeclient "github.com/daeuniverse/dae/plugins/surge/client"
	"github.com/daeuniverse/dae/plugins/surge/internal/jq"
	"github.com/spf13/cobra"
)

func Commands(services plugin.CommandServices) []*cobra.Command {
	var name string
	configure := &cobra.Command{
		Use: "configure <source>", Short: "Choose module arguments and storage isolation, then print a configuration fragment.",
		Long: `Read a Surge module URL or file: source and prompt for its declared arguments.
Read its enabled scripts without executing them. Offer module and script isolation
settings only for statically recognized $persistentStore.read/write calls.
Aliases and dynamic access may remain unconfirmed; existing isolation defaults are unchanged.
Prompts go to stderr. Place the generated module section inside a Surge plugin instance.
This command does not read or modify existing configuration or stored script data.
Relative file: paths use DAE_LOCATION_CACHE or /var/lib/dae. No cache files are written.`,
		Args: cobra.ExactArgs(1), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(name) {
				return fmt.Errorf("--name must start with an ASCII letter or underscore and contain only ASCII letters, digits, or underscores")
			}
			source, err := resource.Parse(args[0], services.BaseDir)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: resourceTimeout}
			result, err := resource.Read(cmd.Context(), client, source, resource.ReadOptions{MaxBytes: MaxModuleBytes})
			if err != nil {
				return fmt.Errorf("read module: %w", err)
			}
			contents := string(result.Data)
			metadata, err := ReadMetadata(contents)
			if err != nil {
				return err
			}
			scanner := bufio.NewScanner(cmd.InOrStdin())
			scanner.Buffer(make([]byte, 4096), MaxModuleBytes)
			arguments, err := promptModuleArguments(scanner, cmd.ErrOrStderr(), metadata)
			if err != nil {
				return err
			}
			parsed, err := Parse(contents, arguments)
			if err != nil {
				return err
			}
			// Resource deadlines must not include time spent answering prompts.
			ctx, cancel := context.WithTimeout(cmd.Context(), moduleLoadTimeout)
			err = parsed.loadScriptSources(result.Location, cacheModuleResources(ctx, func(path resource.Source, _ *time.Duration) (string, error) {
				result, err := resource.Read(ctx, client, path, resource.ReadOptions{MaxBytes: MaxScriptBytes})
				return string(result.Data), err
			}))
			cancel()
			if err != nil {
				return err
			}
			module := ModuleSource{Name: name, Link: strings.TrimSpace(args[0]), Arguments: arguments}
			if err := promptModuleIsolation(scanner, cmd.ErrOrStderr(), parsed, &module); err != nil {
				return err
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			if err := applyModuleIsolation(parsed, module); err != nil {
				return err
			}
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
	worker := &cobra.Command{Use: "__jq-worker", Hidden: true, Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return jq.Run(cmd.InOrStdin(), cmd.OutOrStdout()) },
	}
	return append(surgeclient.Commands(services.Status, services.TriggerScript, services.MigrateScriptStore), configure, worker)
}

func promptModuleArguments(scanner *bufio.Scanner, output io.Writer, metadata Metadata) (map[string]string, error) {
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

func promptModuleIsolation(scanner *bufio.Scanner, output io.Writer, parsed *Module, source *ModuleSource) error {
	type entry struct {
		kind  string
		count int
		uses  bool
	}
	byName := make(map[string]entry)
	checked := make(map[string]bool)
	for _, scripts := range [][]Script{parsed.Scripts, parsed.TaskScripts} {
		for _, script := range scripts {
			uses, ok := checked[script.Path]
			if !ok {
				var err error
				uses, err = scriptUsesPersistentStore(script.Source)
				if err != nil {
					uses = false
					fmt.Fprintf(output, "Warning: storage use in script %q could not be analyzed: %v\n", script.Name, err)
				}
				checked[script.Path] = uses
			}
			item := byName[script.Name]
			item.kind, item.count, item.uses = script.Type, item.count+1, item.uses || uses
			byName[script.Name] = item
		}
	}
	var names []string
	unique := false
	for name, item := range byName {
		if item.uses {
			names = append(names, name)
			unique = unique || item.count == 1
		}
	}
	if len(names) == 0 {
		fmt.Fprintln(output, "No supported persistent-storage calls were confirmed; isolation settings are omitted.")
		return nil
	}
	slices.Sort(names)
	fmt.Fprintln(output, "Storage calls were found statically; aliases and dynamic access may remain unconfirmed. Local execution always stays local.")
	fmt.Fprintln(output, "Module inheritance uses the instance setting, which this command does not read. A module override applies to every script, including unconfirmed ones.")
	warned := false
	warnSharing := func(isolate, set bool) {
		if set && !isolate && !warned {
			fmt.Fprintln(output, "Warning: sharing lets LAN clients and local execution use the same script state, including cookies/tokens. Existing data is not migrated, merged or deleted.")
			warned = true
		}
	}
	var err error
	source.IsolateLAN, source.IsolateLANSet, err = promptIsolationPolicy(scanner, output, "Module isolation", source.IsolateLAN, source.IsolateLANSet)
	if err != nil {
		return err
	}
	warnSharing(source.IsolateLAN, source.IsolateLANSet)
	if !unique {
		fmt.Fprintln(output, "No unambiguous storage-using script names are available for individual overrides.")
		return nil
	}
	for {
		fmt.Fprint(output, "Script override [Enter=done, list, <number>, cancel]: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("read script selection: %w", err)
			}
			return fmt.Errorf("input ended before script isolation was configured")
		}
		answer := strings.TrimSpace(scanner.Text())
		switch answer {
		case "":
			return nil
		case "cancel":
			return context.Canceled
		case "list":
			for i, name := range names {
				policy := "inherit"
				if isolate, set := source.ScriptIsolation[name]; set {
					policy = "share"
					if isolate {
						policy = "isolate"
					}
				}
				if byName[name].count != 1 {
					policy = "ambiguous name; module policy only"
				}
				fmt.Fprintf(output, "%d  %q (%s) [%s]\n", i+1, name, byName[name].kind, policy)
			}
			continue
		}
		index, err := strconv.Atoi(answer)
		if err != nil || index < 1 || index > len(names) {
			fmt.Fprintln(output, "Choose a listed script number, list, cancel, or press Enter to finish.")
			continue
		}
		name := names[index-1]
		if byName[name].count != 1 {
			fmt.Fprintf(output, "Script name %q is ambiguous; only the module policy can apply to it.\n", name)
			continue
		}
		isolate, set := source.ScriptIsolation[name]
		isolate, set, err = promptIsolationPolicy(scanner, output, fmt.Sprintf("Policy for %q (inherit from module)", name), isolate, set)
		if err != nil {
			return err
		}
		if set {
			if source.ScriptIsolation == nil {
				source.ScriptIsolation = make(map[string]bool)
			}
			source.ScriptIsolation[name] = isolate
		} else {
			delete(source.ScriptIsolation, name)
		}
		warnSharing(isolate, set)
	}
}

func promptIsolationPolicy(scanner *bufio.Scanner, output io.Writer, label string, isolate, set bool) (bool, bool, error) {
	current := "inherit"
	if set {
		current = "share"
		if isolate {
			current = "isolate"
		}
	}
	for {
		fmt.Fprintf(output, "%s [inherit/isolate/share, Enter=%s, cancel]: ", label, current)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return false, false, fmt.Errorf("read isolation policy: %w", err)
			}
			return false, false, fmt.Errorf("input ended before isolation policy was configured")
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "":
			return isolate, set, nil
		case "inherit":
			return false, false, nil
		case "isolate":
			return true, true, nil
		case "share":
			return false, true, nil
		case "cancel":
			return false, false, context.Canceled
		default:
			fmt.Fprintln(output, "Choose inherit, isolate, share, or cancel.")
		}
	}
}
