/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

func formatUptime(duration time.Duration) string {
	if duration <= 0 {
		return "-"
	}
	duration = duration.Truncate(time.Second)
	days := int(duration / (24 * time.Hour))
	duration -= time.Duration(days) * 24 * time.Hour
	hours := int(duration / time.Hour)
	duration -= time.Duration(hours) * time.Hour
	minutes := int(duration / time.Minute)
	duration -= time.Duration(minutes) * time.Minute
	seconds := int(duration / time.Second)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

func formatAgo(timestamp *time.Time) string {
	if timestamp == nil {
		return "-"
	}
	duration := time.Since(*timestamp)
	if duration < time.Second {
		return "just now"
	}
	return formatUptime(duration) + " ago"
}

func formatRatio(ratio float64) string {
	return fmt.Sprintf("%.1f%%", ratio*100)
}

func formatAvailability(ratio float64, failed, total int64) string {
	if total == 0 {
		return formatRatio(ratio)
	}
	return fmt.Sprintf("%s (%d/%d)", formatRatio(ratio), failed, total)
}

func shouldEnableColors() bool {
	forceColor := os.Getenv("FORCE_COLOR")
	if forceColor != "" && forceColor != "0" && forceColor != "false" {
		return true
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}
	if noColor := os.Getenv("NO_COLOR"); noColor != "" && noColor != "0" {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

var colorsEnabled = shouldEnableColors()

const (
	healthyUpRatio  = 0.99
	degradedUpRatio = 0.9
	fastLatencyMs   = 200
	slowLatencyMs   = 500
	ampleUsageRatio = 0.7
	tightUsageRatio = 0.9
)

func colorize(value string, colors ...text.Color) string {
	if !colorsEnabled {
		return value
	}
	return text.Escape(value, text.Colors(colors).EscapeSeq())
}

func colorHealth(health control.HealthStatus) string {
	switch health {
	case control.HealthHealthy:
		return colorize(string(health), text.FgGreen)
	case control.HealthWarning:
		return colorize(string(health), text.FgYellow)
	case control.HealthDegraded:
		return colorize(string(health), text.FgRed)
	default:
		panic(fmt.Sprintf("invalid health status %q", health))
	}
}

func colorNodeHealth(health control.NodeHealthState) string {
	switch health {
	case "":
		return "-"
	case control.NodeHealthHealthy:
		return colorize(string(health), text.FgGreen)
	case control.NodeHealthUnknown, control.NodeHealthConfirming:
		return colorize(string(health), text.FgYellow)
	case control.NodeHealthUnhealthy:
		return colorize(string(health), text.FgRed)
	default:
		panic(fmt.Sprintf("invalid node health status %q", health))
	}
}

func colorNetworkSupport(support control.NetworkSupportStatus) string {
	switch support {
	case "":
		return "-"
	case control.NetworkSupportConfirmed:
		return colorize(string(support), text.FgGreen)
	case control.NetworkSupportUnknown, control.NetworkSupportUnsupported:
		return colorize(string(support), text.FgRed)
	default:
		panic(fmt.Sprintf("invalid network support status %q", support))
	}
}

func colorSelected(value string, selected bool) string {
	if !selected {
		return value
	}
	return colorize(value, text.FgCyan)
}

func colorRatio(ratio float64, value string) string {
	switch {
	case ratio >= healthyUpRatio:
		return colorize(value, text.FgGreen)
	case ratio >= degradedUpRatio:
		return colorize(value, text.FgYellow)
	default:
		return colorize(value, text.FgRed)
	}
}

func colorLatency(latencyMs float64, value string) string {
	switch {
	case latencyMs < fastLatencyMs:
		return colorize(value, text.FgGreen)
	case latencyMs < slowLatencyMs:
		return colorize(value, text.FgYellow)
	default:
		return colorize(value, text.FgRed)
	}
}

func colorUsage(ratio float64, value string) string {
	switch {
	case ratio < ampleUsageRatio:
		return colorize(value, text.FgGreen)
	case ratio < tightUsageRatio:
		return colorize(value, text.FgYellow)
	default:
		return colorize(value, text.FgRed)
	}
}

func formatGroupConnectivityState(connectivity *control.GroupConnectivityStatus) string {
	if connectivity == nil {
		return colorize("N/A", text.FgHiBlack)
	}
	switch connectivity.State {
	case control.GroupConnectivityAvailable:
		return colorize("UP", text.FgGreen)
	case control.GroupConnectivityUnavailable:
		return colorize("DOWN", text.FgRed)
	case control.GroupConnectivityChecking:
		return colorize("CHECKING", text.FgYellow)
	default:
		return string(connectivity.State)
	}
}

func networkSupport(networks []control.NodeNetworkStatus) string {
	var supported []string
	for _, network := range networks {
		if network.SupportState == control.NetworkSupportConfirmed {
			supported = append(supported, network.Network)
		}
	}
	return compactNetworks(supported)
}

func compactNetworks(networks []string) string {
	remaining := make(map[string]bool, len(networks))
	for _, network := range networks {
		remaining[network] = true
	}
	if len(remaining) == 0 {
		return "-"
	}
	if len(remaining) == 4 && remaining["tcp4"] && remaining["tcp6"] && remaining["udp4"] && remaining["udp6"] {
		return "all"
	}

	parts := make([]string, 0, len(remaining))
	consumePair := func(label, first, second string) {
		if remaining[first] && remaining[second] {
			parts = append(parts, label)
			delete(remaining, first)
			delete(remaining, second)
		}
	}
	consumePair("all tcp", "tcp4", "tcp6")
	consumePair("all udp", "udp4", "udp6")
	consumePair("all ipv4", "tcp4", "udp4")
	consumePair("all ipv6", "tcp6", "udp6")
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		if remaining[network] {
			parts = append(parts, network)
			delete(remaining, network)
		}
	}
	for _, network := range networks {
		if remaining[network] {
			parts = append(parts, network)
			delete(remaining, network)
		}
	}
	return strings.Join(parts, ",")
}

func selectedNetworks(nodeIndex int, networks []control.NetworkStatus) (string, bool) {
	var selected []string
	for _, network := range networks {
		if network.Selected != nil && network.Selected.Index == nodeIndex {
			selected = append(selected, network.Network)
		}
	}
	if len(selected) == 0 {
		return "-", false
	}
	return compactNetworks(selected), true
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func formatAgoWithChecks(timestamp *time.Time, checks int64) string {
	formatted := formatAgo(timestamp)
	if timestamp == nil || checks <= 0 {
		return formatted
	}
	return fmt.Sprintf("%s (+%d chk)", formatted, checks)
}

func formatFailure(failure *control.FailureStatus) string {
	if failure == nil {
		return "-"
	}
	duration := time.Duration(failure.DurationMs) * time.Millisecond
	durationText := "0s"
	if duration > 0 {
		durationText = formatUptime(duration)
	}
	return fmt.Sprintf("%s / %s", formatAgo(&failure.StartedAt), durationText)
}

func formatConnCounts(active, total int64) string {
	return fmt.Sprintf("%d/%d", active, total)
}

func formatBytes(bytes uint64) string {
	if bytes == 0 {
		return "0"
	}
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}

	value := float64(bytes) / 1024
	unit := "K"
	for _, nextUnit := range []string{"M", "G", "T", "P", "E"} {
		if value < 1024 {
			break
		}
		value /= 1024
		unit = nextUnit
	}
	format := "%.2f%s"
	if value >= 100 {
		format = "%.0f%s"
	} else if value >= 10 {
		format = "%.1f%s"
	}
	return fmt.Sprintf(format, value, unit)
}

func hasTrafficRate(traffic control.TrafficStatus) bool {
	return traffic.UploadBytesPerSecond != 0 || traffic.DownloadBytesPerSecond != 0
}

func formatTrafficRateCell(traffic control.TrafficStatus) string {
	if !hasTrafficRate(traffic) {
		return "-"
	}
	return fmt.Sprintf(
		"%s/%s",
		formatBytes(traffic.UploadBytesPerSecond),
		formatBytes(traffic.DownloadBytesPerSecond),
	)
}

func formatTrafficRate(traffic control.TrafficStatus) string {
	return formatTrafficRateCell(traffic) + " U/D"
}

func hasTrafficTotal(traffic control.TrafficStatus) bool {
	return traffic.UploadBytes != 0 || traffic.DownloadBytes != 0
}

func formatTrafficTotalCell(traffic control.TrafficStatus) string {
	if !hasTrafficTotal(traffic) {
		return "-"
	}
	return fmt.Sprintf(
		"%s/%s",
		formatBytes(traffic.UploadBytes),
		formatBytes(traffic.DownloadBytes),
	)
}

func formatTrafficTotal(traffic control.TrafficStatus) string {
	return formatTrafficTotalCell(traffic) + " U/D"
}

func formatTrafficSummary(traffic control.TrafficStatus) string {
	if !hasTrafficRate(traffic) && !hasTrafficTotal(traffic) {
		return ""
	}
	return "rate " + formatTrafficRate(traffic) + ", total " + formatTrafficTotal(traffic)
}

func formatTrafficSummarySuffix(traffic control.TrafficStatus) string {
	summary := formatTrafficSummary(traffic)
	if summary == "" {
		return ""
	}
	return ", " + summary
}
