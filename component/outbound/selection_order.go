package outbound

import (
	"cmp"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

func compareCandidates(a, b selectorCandidate) int {
	if a.degraded != b.degraded {
		if a.degraded {
			return 1
		}
		return -1
	}
	return cmp.Or(cmp.Compare(b.priority, a.priority), cmp.Compare(a.sortingLatency, b.sortingLatency))
}

func (s *automaticSelection) logSelection(oldDialer, newDialer *dialer.Dialer, networkType *common.NetworkType) {
	oldName := "<nil>"
	newName := "<nil>"
	if oldDialer != nil {
		oldName = oldDialer.Name
	}
	if newDialer != nil {
		newName = newDialer.Name
	}
	fields := log.Fields{
		"node":          newName,
		"previous_node": oldName,
		"group":         s.g.Name,
		"network":       networkType.String(),
		"policy":        s.g.selectionPolicy.Policy,
	}
	if newDialer != nil {
		if candidate, ok := s.g.candidate(newDialer, networkType); ok {
			fields["latency"] = candidate.latency.String()
			fields["selection_score"] = candidate.sortingLatency.String()
			fields["priority"] = candidate.priority
			fields["degraded"] = candidate.degraded
		}
	}
	if oldDialer == nil {
		delete(fields, "previous_node")
		log.WithFields(fields).Info("Group selected node")
	} else {
		log.WithFields(fields).Info("Group changed node")
	}
}
