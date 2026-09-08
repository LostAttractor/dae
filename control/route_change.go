package control

import (
	"errors"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

var errRouteChanged = netproxy.WrapFailure(errors.New("device routing changed"), netproxy.Failure{Origin: netproxy.OriginLocalCleanup})

type deviceRoute struct {
	epoch uint64
	lease *netproxy.Lease
}

// Shared across control-plane reloads. Device policies only abort; resource
// draining remains the responsibility of the independent outbound lease.
type deviceRoutes struct {
	mu      sync.Mutex
	devices map[[6]byte]*deviceRoute
	outer   *ebpf.Map
}

func (d *deviceRoutes) device(mac [6]byte) *deviceRoute {
	if d.devices == nil {
		d.devices = make(map[[6]byte]*deviceRoute)
	}
	if d.devices[mac] == nil {
		d.devices[mac] = &deviceRoute{}
	}
	return d.devices[mac]
}

func (d *deviceRoutes) acquire(result *bpfRoutingResult) (*netproxy.Lease, error) {
	if result.Mac == [6]byte{} {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	device := d.device(result.Mac)
	if result.RouteEpoch != device.epoch {
		return nil, errRouteChanged
	}
	if device.lease == nil {
		device.lease = netproxy.NewLease(netproxy.NewResourceRef())
	}
	return device.lease, nil
}

// Build both replacements before changing live settings. Swapping the inner
// map publishes all affected MACs together, including a file reload that edits
// several sets. Holding mu also excludes userspace route registration.
func (d *deviceRoutes) table(changed map[[6]byte]bool, updating bool) (*ebpf.Map, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 6, ValueSize: 16, MaxEntries: 65536})
	if err != nil {
		return nil, err
	}
	for mac, device := range d.devices {
		state := bpfDeviceRouteState{Epoch: device.epoch}
		if changed[mac] {
			if updating {
				state.Updating = 1
			} else {
				state.Epoch++
			}
		}
		if state.Epoch == 0 && state.Updating == 0 {
			continue
		}
		if err := m.Update(mac, state, ebpf.UpdateAny); err != nil {
			m.Close()
			return nil, err
		}
	}
	return m, nil
}

// apply must restore its settings/matchers if it returns an error. commit runs
// only after all fallible application work succeeds. On a failed map swap the
// caller rolls back the settings while the old generations remain usable.
func (d *deviceRoutes) change(changed map[[6]byte]bool, apply func(commit func() error) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for mac := range changed {
		d.device(mac)
	}
	var previous *ebpf.Map
	if err := d.outer.Lookup(uint32(0), &previous); err != nil {
		return err
	}
	defer previous.Close()
	gate, err := d.table(changed, true)
	if err != nil {
		return err
	}
	defer gate.Close()
	next, err := d.table(changed, false)
	if err != nil {
		return err
	}
	defer next.Close()
	if err := d.outer.Update(uint32(0), gate, ebpf.UpdateAny); err != nil {
		return err
	}
	if err := apply(func() error { return d.outer.Update(uint32(0), next, ebpf.UpdateAny) }); err != nil {
		return errors.Join(err, d.outer.Update(uint32(0), previous, ebpf.UpdateAny))
	}
	for mac := range changed {
		device := d.device(mac)
		device.epoch++
		device.lease.Abort(errRouteChanged)
		device.lease = nil
		log.WithFields(log.Fields{"event": "route_change", "reason": "client_membership", "mac": net.HardwareAddr(mac[:]).String(), "epoch": device.epoch}).Info("Closing device connections after client membership changed")
	}
	return nil
}

func (c *ControlPlane) changeDeviceRoutes(changed map[[6]byte]bool, apply func(commit func() error) error) error {
	if !c.closeOnRouteChange || len(changed) == 0 {
		return apply(func() error { return nil })
	}
	return c.deviceRoutes.change(changed, apply)
}
