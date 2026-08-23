package outbound

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

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
