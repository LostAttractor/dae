package outbound

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

func saturatingDurationAdd(a, b time.Duration) time.Duration {
	if b > 0 && a > time.Duration(math.MaxInt64)-b {
		return time.Duration(math.MaxInt64)
	}
	if b < 0 && a < time.Duration(math.MinInt64)-b {
		return time.Duration(math.MinInt64)
	}
	return a + b
}

type Selector interface {
	Select(networkType *common.NetworkType) *dialer.Dialer
	SelectedDialer(networkType *common.NetworkType) *dialer.Dialer
	NotifyStatusChange(dialer *dialer.Dialer)
	PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{}))
}

func logDialerAliveTransition(g *DialerGroup, d *dialer.Dialer, previous, current bool) bool {
	if previous == current {
		return current
	}
	fields := log.Fields{"dialer": d.Name, "group": g.Name}
	if current {
		log.WithFields(fields).Warn("[NOT ALIVE --> ALIVE]")
	} else {
		log.WithFields(fields).Info("[ALIVE --> NOT ALIVE]")
	}
	return current
}

func isDialerAlive(d *dialer.Dialer, networkType *common.NetworkType) bool {
	alive, support := d.SelectionState(networkType)
	return alive && support == dialer.NetworkSupportConfirmed
}

func preferredAliveDialers(dialers []*dialer.Dialer, networkType *common.NetworkType) []*dialer.Dialer {
	confirmed := make([]*dialer.Dialer, 0, len(dialers))
	for _, d := range dialers {
		if isDialerAlive(d, networkType) {
			confirmed = append(confirmed, d)
		}
	}
	return confirmed
}

func printDialerLatency(g *DialerGroup, d *dialer.Dialer, networkType *common.NetworkType, logfn func(args ...interface{})) {
	var builder strings.Builder
	if networkType != nil {
		builder.WriteString(fmt.Sprintf("Group '%v' [%v]:\n", g.Name, networkType.String()))
	} else {
		builder.WriteString(fmt.Sprintf("Group '%v':\n", g.Name))
	}
	if !isDialerAlive(d, networkType) {
		builder.WriteString("\t<Not Alive>\n")
		logfn(strings.TrimSuffix(builder.String(), "\n"))
		return
	}
	tag := ""
	if d.SubscriptionTag != "" {
		tag = fmt.Sprintf(" [%v]", d.SubscriptionTag)
	}
	latency := "Always Alive"
	if d.ChecksConnectivity() {
		latency = common.ShowDuration(0)
		if stats, ok := d.LatencyStats(g); ok {
			latency = common.ShowDuration(stats.Last)
		}
	}
	builder.WriteString(fmt.Sprintf("%4d.%v %v: %v\n", 1, tag, d.Name, latency))
	logfn(strings.TrimSuffix(builder.String(), "\n"))
}
