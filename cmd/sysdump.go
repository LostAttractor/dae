/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	sysdumpCmd = &cobra.Command{
		Use:   "sysdump",
		Short: "To dump up system network config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return dumpNetworkInfo(cmd.OutOrStdout())
		},
	}
)

func dumpNetworkInfo(out io.Writer) error {
	tempDir, err := os.MkdirTemp("", "sysdump")
	if err != nil {
		return fmt.Errorf("create sysdump directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Preserve the available diagnostics even when one collector fails.
	collectErr := errors.Join(dumpRouting(tempDir), dumpNetInterfaces(tempDir),
		dumpSysctl(tempDir), dumpNetfilter(tempDir), dumpIPTables(tempDir))

	tarFile := fmt.Sprintf("dae-sysdump.%d.tar.gz", time.Now().Unix())
	if err := archiveDirectory(tempDir, tarFile); err != nil {
		return errors.Join(collectErr, fmt.Errorf("create sysdump archive: %w", err))
	}

	_, err = fmt.Fprintf(out, "System network information saved to %s\n", tarFile)
	return errors.Join(collectErr, err)
}

func archiveDirectory(source, destination string) error {
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(output)
	tarWriter := tar.NewWriter(gzipWriter)

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name, err := filepath.Rel(filepath.Dir(source), path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(name)
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		return errors.Join(copyErr, file.Close())
	})

	return errors.Join(err, tarWriter.Close(), gzipWriter.Close(), output.Close())
}

// Translate scope enum into semantic words
func scopeToString(scope netlink.Scope) string {
	switch scope {
	case unix.RT_SCOPE_UNIVERSE:
		return "universe"
	case unix.RT_SCOPE_SITE:
		return "site"
	case unix.RT_SCOPE_LINK:
		return "link"
	case unix.RT_SCOPE_HOST:
		return "host"
	case unix.RT_SCOPE_NOWHERE:
		return "nowhere"
	default:
		return "unknown"
	}
}

// Translate protocol enum into semantic words
func protocolToString(proto netlink.RouteProtocol) string {
	switch proto {
	case unix.RTPROT_BABEL:
		return "babel"
	case unix.RTPROT_BGP:
		return "bgp"
	case unix.RTPROT_BIRD:
		return "bird"
	case unix.RTPROT_BOOT:
		return "boot"
	case unix.RTPROT_DHCP:
		return "dhcp"
	case unix.RTPROT_DNROUTED:
		return "dnrouted"
	case unix.RTPROT_EIGRP:
		return "eigrp"
	case unix.RTPROT_GATED:
		return "gated"
	case unix.RTPROT_ISIS:
		return "isis"
	case unix.RTPROT_KERNEL:
		return "kernel"
	case unix.RTPROT_MROUTED:
		return "mrouted"
	case unix.RTPROT_MRT:
		return "mrt"
	case unix.RTPROT_NTK:
		return "ntk"
	case unix.RTPROT_OSPF:
		return "ospf"
	case unix.RTPROT_RA:
		return "ra"
	case unix.RTPROT_REDIRECT:
		return "redirect"
	case unix.RTPROT_RIP:
		return "rip"
	case unix.RTPROT_STATIC:
		return "static"
	case unix.RTPROT_UNSPEC:
		return "unspec"
	case unix.RTPROT_XORP:
		return "xorp"
	case unix.RTPROT_ZEBRA:
		return "zebra"
	default:
		return "unknown"
	}
}

// Translate route.type enum into semantic words
func typeToString(typ int) string {
	switch typ {
	case unix.RTN_UNSPEC:
		return "unspec"
	case unix.RTN_UNICAST:
		return "unicast"
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_ANYCAST:
		return "anycast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	case unix.RTN_THROW:
		return "throw"
	case unix.RTN_NAT:
		return "nat"
	case unix.RTN_XRESOLVE:
		return "xresolve"
	default:
		return "unknown"
	}
}

func dumpRouting(outputDir string) error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("get routing table: %w", err)
	}

	var buffer bytes.Buffer
	var linkErrors []error
	buffer.WriteString("Routing:\n")
	for _, route := range routes {
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			linkErrors = append(linkErrors, fmt.Errorf("get routing interface %d: %w", route.LinkIndex, err))
			continue
		}
		ifaceName := link.Attrs().Name

		routeStr := ""
		if route.Dst == nil {
			routeStr += "default"
		} else {
			routeStr += route.Dst.String()
		}

		if route.Gw != nil {
			routeStr += fmt.Sprintf(" via %s", route.Gw.String())
		}

		routeStr += fmt.Sprintf(" dev %s", ifaceName)

		if route.Scope != 0 {
			routeStr += fmt.Sprintf(" scope %s", scopeToString(route.Scope))
		}

		if route.Protocol != 0 {
			routeStr += fmt.Sprintf(" proto %s", protocolToString(route.Protocol))
		}

		if route.Type != 0 {
			routeStr += fmt.Sprintf(" type %s", typeToString(route.Type))
		}

		if route.Flags != 0 {
			routeStr += fmt.Sprintf(" flags %d", route.Flags)
		}

		buffer.WriteString(routeStr + "\n")
	}
	return errors.Join(errors.Join(linkErrors...), os.WriteFile(filepath.Join(outputDir, "routing.txt"), buffer.Bytes(), 0644))
}

func dumpNetInterfaces(outputDir string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("get network interfaces: %w", err)
	}

	var buffer bytes.Buffer
	buffer.WriteString("Network Interfaces:\n")
	for _, iface := range interfaces {
		buffer.WriteString(fmt.Sprintf("Name: %s, MTU: %d, HardwareAddr: %s, Flags: %v\n",
			iface.Name, iface.MTU, iface.HardwareAddr, iface.Flags))
		for _, addr := range iface.Addrs {
			buffer.WriteString(fmt.Sprintf("  Address: %s\n", addr.Addr))
		}
	}

	return os.WriteFile(filepath.Join(outputDir, "interfaces.txt"), buffer.Bytes(), 0644)
}

func dumpSysctl(outputDir string) error {
	sysctlPath := "/proc/sys/net"
	var buffer bytes.Buffer
	var readErrors []error

	err := filepath.Walk(sysctlPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			readErrors = append(readErrors, err)
			return nil
		}

		if !info.IsDir() {
			value, err := os.ReadFile(path)
			if err != nil {
				readErrors = append(readErrors, err)
				return nil
			}

			relativePath := strings.TrimPrefix(path, sysctlPath+"/")
			buffer.WriteString(fmt.Sprintf("%-60s = %s\n", relativePath, string(value)))
		}
		return nil
	})

	return errors.Join(err, errors.Join(readErrors...), os.WriteFile(filepath.Join(outputDir, "sysctl.txt"), buffer.Bytes(), 0644))
}

func dumpNetfilter(outputDir string) error {
	cmd := exec.Command("nft", "list", "ruleset")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("get nftables ruleset: %w", err)
	}

	return os.WriteFile(filepath.Join(outputDir, "nftables.txt"), output, 0644)
}

func dumpIPTables(outputDir string) error {
	var errs []error
	for _, tool := range []string{"iptables", "ip6tables"} {
		output, err := exec.Command(tool+"-save", "-c").CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Errorf("get %s rules: %w", tool, err))
			continue
		}
		errs = append(errs, os.WriteFile(filepath.Join(outputDir, tool+".txt"), output, 0644))
	}
	return errors.Join(errs...)
}

func init() {
	rootCmd.AddCommand(sysdumpCmd)
}
