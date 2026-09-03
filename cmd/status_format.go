/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"math/bits"
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
	if !group.ChecksConnectivity {
		return healthHealthy
	}
	if group.Connectivity == stats.GroupStateAvailable {
		for network := common.NetworkIndex(0); network < common.NetworkTypeCount; network++ {
			if groupNetworkSupport(group.Nodes, network) == dialer.NetworkSupportConfirmed && !groupNetworkRoutable(group, network) {
				return healthWarning
			}
		}
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

var getStatusTerminalWidth = func() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 0
	}
	return width
}

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
	case dialer.NetworkSupportUnknown:
		return colorize(string(support), text.FgYellow)
	case dialer.NetworkSupportUnsupported:
		return colorize(string(support), text.FgHiBlack)
	default:
		return string(support)
	}
}

func colorSelected(value string, selected bool) string {
	if !selected {
		return value
	}
	return colorize(value, text.FgCyan, text.Bold)
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

func nodeNetworks(status control.NodeStatus, selected control.NetworkValues[string]) (string, bool) {
	var support, selection uint8
	for network, state := range status.Support {
		if state == dialer.NetworkSupportConfirmed {
			support |= 1 << network
		}
		if status.ID != "" && selected[network] == status.ID {
			selection |= 1 << network
		}
	}
	base := compactNetworks(support)
	if selection == 0 {
		return base, false
	}
	selectionText := "*"
	if selection != support {
		parts := make([]string, 0, common.NetworkTypeCount)
		for index := common.NetworkIndex(0); index < common.NetworkTypeCount; index++ {
			if selection&(1<<index) != 0 {
				parts = append(parts, index.String()+"*")
			}
		}
		selectionText = strings.Join(parts, ",")
	}
	return colorSelected(base+"("+selectionText+")", true), true
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
	formatted := fmt.Sprintf("%d/%d", value.ActiveConnections, value.TotalConnections)
	if value.FallbackConnections > 0 {
		formatted += fmt.Sprintf(" (fb %d)", value.FallbackConnections)
	}
	return formatted
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

func formatBitRateParts(bytesPerSecond uint64) (string, string) {
	if bytesPerSecond == 0 {
		return "0", "bps"
	}
	value := float64(bytesPerSecond) * 8
	unit := "bps"
	for _, nextUnit := range []string{"Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps"} {
		if value < 1000 {
			break
		}
		value /= 1000
		unit = nextUnit
	}
	format := "%.2f"
	if value >= 100 {
		format = "%.0f"
	} else if value >= 10 {
		format = "%.1f"
	}
	return fmt.Sprintf(format, value), unit
}

func formatBitRatePair(average, maximum uint64) string {
	averageValue, averageUnit := formatBitRateParts(average)
	maximumValue, maximumUnit := formatBitRateParts(maximum)
	if averageUnit == maximumUnit {
		return averageValue + "/" + maximumValue + averageUnit
	}
	return averageValue + averageUnit + "/" + maximumValue + maximumUnit
}

func trafficMaximum(values []uint64) uint64 {
	var maximum uint64
	for _, value := range values {
		maximum = max(maximum, value)
	}
	return maximum
}

func trafficAverage(values []uint64) uint64 {
	if len(values) == 0 {
		return 0
	}
	var high, low uint64
	for _, value := range values {
		var carry uint64
		low, carry = bits.Add64(low, value, 0)
		high += carry
	}
	average, _ := bits.Div64(high, low, uint64(len(values)))
	return average
}

var trafficSparklineGlyphs = []rune("▁▂▃▄▅▆▇█")

func trafficSpeedColor(bytesPerSecond uint64) text.Color {
	switch {
	case bytesPerSecond >= 100_000_000/8:
		return text.FgRed
	case bytesPerSecond >= 10_000_000/8:
		return text.FgYellow
	case bytesPerSecond > 0:
		return text.FgGreen
	default:
		return text.FgHiBlack
	}
}

func trafficSparkline(values []uint64, scale uint64) string {
	var line strings.Builder
	if padding := max(stats.TrafficHistorySampleCount-len(values), 0); padding > 0 {
		line.WriteString(colorize(strings.Repeat(".", padding), text.FgHiBlack))
	}
	for _, value := range values {
		level := 0
		if value > 0 && scale > 0 {
			level = 1 + int(float64(value)*6/float64(scale))
			level = min(level, 7)
		}
		line.WriteString(colorize(string(trafficSparklineGlyphs[level]), trafficSpeedColor(value)))
	}
	return line.String()
}

func hasTrafficHistory(value stats.PathStats) bool {
	return len(value.History.UploadBytesPerSecond) > 0
}

func formatTrafficSparklineCell(value stats.PathStats) string {
	upload := value.History.UploadBytesPerSecond
	download := value.History.DownloadBytesPerSecond
	if !hasTrafficHistory(value) {
		return "-"
	}
	scale := max(trafficMaximum(upload), trafficMaximum(download))
	return "↑" + trafficSparkline(upload, scale) + " ↓" + trafficSparkline(download, scale)
}

func formatTrafficCell(value stats.PathStats) string {
	upload := value.History.UploadBytesPerSecond
	download := value.History.DownloadBytesPerSecond
	if !hasTrafficHistory(value) {
		return "-"
	}
	uploadMax := trafficMaximum(upload)
	downloadMax := trafficMaximum(download)
	scale := max(uploadMax, downloadMax)
	return fmt.Sprintf(
		"↑%s %s ↓%s %s",
		trafficSparkline(upload, scale),
		formatBitRatePair(trafficAverage(upload), uploadMax),
		trafficSparkline(download, scale),
		formatBitRatePair(trafficAverage(download), downloadMax),
	)
}

func formatTrafficTotalCell(value stats.PathStats) string {
	if value.UploadBytes == 0 && value.DownloadBytes == 0 {
		return "-"
	}
	return fmt.Sprintf("↑%s ↓%s", formatBytes(value.UploadBytes), formatBytes(value.DownloadBytes))
}

func formatTrafficSummary(value stats.PathStats) string {
	var parts []string
	if traffic := formatTrafficCell(value); traffic != "-" {
		parts = append(parts, "1m "+traffic)
	}
	if total := formatTrafficTotalCell(value); total != "-" {
		parts = append(parts, "total "+total)
	}
	return strings.Join(parts, " · ")
}
