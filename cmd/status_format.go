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

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

type healthStatus string

const (
	healthHealthy  healthStatus = "healthy"
	healthWarning  healthStatus = "warning"
	healthDegraded healthStatus = "degraded"

	nodeHealthUnknown    = "unknown"
	nodeHealthHealthy    = "healthy"
	nodeHealthConfirming = "confirming"
	nodeHealthUnhealthy  = "unhealthy"
)

func groupHealth(group control.GroupStatus) healthStatus {
	if !group.ChecksConnectivity || group.Connectivity == stats.GroupStateAvailable {
		return healthHealthy
	}
	if group.Connectivity == stats.GroupStateChecking || !group.Critical {
		return healthWarning
	}
	return healthDegraded
}

func statusHealth(groups []control.GroupStatus) healthStatus {
	health := healthHealthy
	for _, group := range groups {
		switch groupHealth(group) {
		case healthDegraded:
			return healthDegraded
		case healthWarning:
			health = healthWarning
		}
	}
	return health
}

func nodeHealth(status control.NodeStatus) string {
	if !status.ChecksConnectivity {
		return nodeHealthUnknown
	}
	if status.ConfirmingFailure {
		return nodeHealthConfirming
	}
	if !status.Availability.Seen {
		return nodeHealthUnknown
	}
	if status.Healthy {
		return nodeHealthHealthy
	}
	return nodeHealthUnhealthy
}

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

func formatAgo(timestamp time.Time) string {
	if timestamp.IsZero() {
		return "-"
	}
	duration := time.Since(timestamp)
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

func colorHealth(health healthStatus) string {
	switch health {
	case healthHealthy:
		return colorize(string(health), text.FgGreen)
	case healthWarning:
		return colorize(string(health), text.FgYellow)
	case healthDegraded:
		return colorize(string(health), text.FgRed)
	default:
		return emptyDash(string(health))
	}
}

func colorNodeHealth(health string) string {
	switch health {
	case "":
		return "-"
	case nodeHealthHealthy:
		return colorize(health, text.FgGreen)
	case nodeHealthUnknown, nodeHealthConfirming:
		return colorize(health, text.FgYellow)
	case nodeHealthUnhealthy:
		return colorize(health, text.FgRed)
	default:
		return health
	}
}

func colorNetworkSupport(support dialer.NetworkSupportState) string {
	switch support {
	case "":
		return "-"
	case dialer.NetworkSupportConfirmed:
		return colorize(string(support), text.FgGreen)
	case dialer.NetworkSupportUnknown, dialer.NetworkSupportUnsupported:
		return colorize(string(support), text.FgRed)
	default:
		return string(support)
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

func formatGroupConnectivityState(group control.GroupStatus) string {
	if !group.ChecksConnectivity {
		return colorize("N/A", text.FgHiBlack)
	}
	switch group.Connectivity {
	case stats.GroupStateAvailable:
		return colorize("UP", text.FgGreen)
	case stats.GroupStateUnavailable:
		return colorize("DOWN", text.FgRed)
	case stats.GroupStateChecking:
		return colorize("CHECKING", text.FgYellow)
	default:
		return string(group.Connectivity)
	}
}

func networkMask(support control.NetworkValues[dialer.NetworkSupportState]) uint8 {
	var mask uint8
	for index, state := range support {
		if state == dialer.NetworkSupportConfirmed {
			mask |= 1 << index
		}
	}
	return mask
}

func compactNetworks(mask uint8) string {
	switch mask {
	case 0:
		return "-"
	case 0b1111:
		return "all"
	case 0b0011:
		return "all tcp"
	case 0b1100:
		return "all udp"
	case 0b0101:
		return "all ipv4"
	case 0b1010:
		return "all ipv6"
	}
	parts := make([]string, 0, common.NetworkTypeCount)
	for index := common.NetworkIndex(0); index < common.NetworkTypeCount; index++ {
		if mask&(1<<index) != 0 {
			parts = append(parts, index.String())
		}
	}
	return strings.Join(parts, ",")
}

func selectedNetworks(nodeID string, selected control.NetworkValues[string]) (string, bool) {
	if nodeID == "" {
		return "-", false
	}
	var mask uint8
	for index, selectedID := range selected {
		if selectedID == nodeID {
			mask |= 1 << index
		}
	}
	return compactNetworks(mask), mask != 0
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func formatAgoWithChecks(timestamp time.Time, checks int64) string {
	formatted := formatAgo(timestamp)
	if timestamp.IsZero() || checks <= 0 {
		return formatted
	}
	return fmt.Sprintf("%s (+%d chk)", formatted, checks)
}

func formatFailure(startedAt time.Time, duration time.Duration) string {
	if startedAt.IsZero() {
		return "-"
	}
	durationText := "0s"
	if duration > 0 {
		durationText = formatUptime(duration)
	}
	return fmt.Sprintf("%s / %s", formatAgo(startedAt), durationText)
}

func formatConnCounts(value stats.PathStats) string {
	return fmt.Sprintf("%d/%d", value.ActiveConnections, value.TotalConnections)
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

func hasTrafficRate(value stats.PathStats) bool {
	return value.UploadBytesPerSecond != 0 || value.DownloadBytesPerSecond != 0
}

func formatTrafficRateCell(value stats.PathStats) string {
	if !hasTrafficRate(value) {
		return "-"
	}
	return fmt.Sprintf("%s/%s", formatBytes(value.UploadBytesPerSecond), formatBytes(value.DownloadBytesPerSecond))
}

func formatTrafficRate(value stats.PathStats) string {
	return formatTrafficRateCell(value) + " U/D"
}

func hasTrafficTotal(value stats.PathStats) bool {
	return value.UploadBytes != 0 || value.DownloadBytes != 0
}

func formatTrafficTotalCell(value stats.PathStats) string {
	if !hasTrafficTotal(value) {
		return "-"
	}
	return fmt.Sprintf("%s/%s", formatBytes(value.UploadBytes), formatBytes(value.DownloadBytes))
}

func formatTrafficTotal(value stats.PathStats) string {
	return formatTrafficTotalCell(value) + " U/D"
}

func formatTrafficSummary(value stats.PathStats) string {
	if !hasTrafficRate(value) && !hasTrafficTotal(value) {
		return ""
	}
	return "rate " + formatTrafficRate(value) + ", total " + formatTrafficTotal(value)
}

func formatTrafficSummarySuffix(value stats.PathStats) string {
	summary := formatTrafficSummary(value)
	if summary == "" {
		return ""
	}
	return ", " + summary
}
