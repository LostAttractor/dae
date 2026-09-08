//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)
// +build trace
// +build amd64 arm64 riscv64 loong64 ppc64 ppc64le

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os/signal"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/trace"
	"github.com/spf13/cobra"
)

var (
	IPv4, IPv6 bool
	L4Proto    string
	Port       int
	OutputFile string
	DropOnly   bool
)

func init() {
	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "To trace traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			if IPv4 && IPv6 {
				return fmt.Errorf("IPv4 and IPv6 cannot be set at the same time")
			}
			if !IPv4 && !IPv6 {
				IPv4 = true
			}
			IPVersion := 4
			if IPv6 {
				IPVersion = 6
			}

			var L4ProtoNo uint16
			switch L4Proto {
			case "tcp":
				L4ProtoNo = syscall.IPPROTO_TCP
			case "udp":
				L4ProtoNo = syscall.IPPROTO_UDP
			default:
				return fmt.Errorf("unknown L4 protocol %q; use tcp or udp", L4Proto)
			}
			if err := internal.AutoSu(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			if err := trace.ReadKallsyms(); err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return trace.StartTrace(ctx, IPVersion, L4ProtoNo, Port, DropOnly, OutputFile)
		},
	}

	traceCmd.PersistentFlags().BoolVarP(&IPv4, "ipv4", "4", false, "Capture IPv4 traffic")
	traceCmd.PersistentFlags().BoolVarP(&IPv6, "ipv6", "6", false, "Capture IPv6 traffic")
	traceCmd.PersistentFlags().StringVarP(&L4Proto, "l4-proto", "p", "tcp", "Layer 4 protocol")
	traceCmd.PersistentFlags().IntVarP(&Port, "port", "P", 80, "Port")
	traceCmd.PersistentFlags().BoolVarP(&DropOnly, "drop-only", "", false, "only trace the dropped package")
	traceCmd.PersistentFlags().StringVarP(&OutputFile, "output", "o", "/dev/stdout", "Output file")

	rootCmd.AddCommand(traceCmd)
}
