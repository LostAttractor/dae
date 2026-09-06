package mitm

// InstanceStatus intentionally excludes plugin configuration and credentials.
type InstanceStatus struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	State            string `json:"state"`
	Scopes           int    `json:"scopes"`
	DestinationRules int    `json:"destination_rules"`
}

func (h *Host) Status() []InstanceStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := "prepared"
	if h.cancel != nil {
		state = "active"
	}
	if h.closed {
		state = "draining"
	}
	result := make([]InstanceStatus, 0, len(h.instances))
	for _, p := range h.instances {
		result = append(result, InstanceStatus{ID: p.ID, Type: p.Type, State: state, Scopes: len(p.plan.Scopes), DestinationRules: len(p.plan.Destinations)})
	}
	return result
}
