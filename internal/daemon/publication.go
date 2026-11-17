// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
)

// preparedPlane owns a candidate and any newly opened API listener until
// publication. The currently serving listener is borrowed and survives rejection.
type preparedPlane struct {
	plane       *control.ControlPlane
	api         *apiserver.Server
	previousAPI *apiserver.Server
	apiUpdate   *apiserver.InterfaceUpdate
}

func (a *application) refreshAPIRouting(ctx context.Context) error {
	if err := a.plane.SetAPIInterfaces(a.managementAPI.InterfaceIndices(nil)); err != nil {
		return err
	}
	return a.plane.RefreshAPIRouting(ctx)
}

func (p *preparedPlane) closeAPI() {
	p.apiUpdate.Rollback()
	if p.api != p.previousAPI {
		p.api.Close()
	}
}

func (p *preparedPlane) discard() error {
	p.closeAPI()
	return p.plane.Close()
}

func (a *application) preparePlane(ctx context.Context, conf *config.Config, inputs *controlInputs, load func(*http.Client) (control.PreparedMITM, error)) (*preparedPlane, error) {
	return a.assemblePlane(ctx, conf, inputs, load)
}

func (a *application) assemblePlane(ctx context.Context, conf *config.Config, inputs *controlInputs, load func(*http.Client) (control.PreparedMITM, error)) (*preparedPlane, error) {
	plane, err := newControlPlane(ctx, a.datapath, conf, inputs, a.settings, load)
	if err != nil {
		return nil, fmt.Errorf("prepare control plane: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, plane.Close())
	}
	plane.SetPluginConfiguration(conf.Plugins, slices.Sorted(maps.Keys(a.definitions)))
	manager, err := a.datapath.Interfaces()
	if err != nil {
		return nil, errors.Join(err, plane.Close())
	}
	api, update, err := prepareAPIServer(a.managementAPI, conf.API, conf.Global.LanInterface, manager, a.staging)
	if err != nil {
		return nil, errors.Join(err, plane.Close())
	}
	p := &preparedPlane{plane: plane, api: api, previousAPI: a.managementAPI, apiUpdate: update}
	if err := plane.SetAPIInterfaces(api.InterfaceIndices(update)); err != nil {
		return nil, errors.Join(err, p.discard())
	}
	return p, nil
}

// publishPlane adopts both resources only after successful routing publication.
// Rejection leaves the old generation usable. Partial activation is terminal:
// Runtime retains the resources needed to finish shutting down that generation.
func (a *application) publishPlane(candidate *preparedPlane, abort bool) error {
	if err := a.datapath.Publish(candidate.plane, abort); err != nil {
		candidate.closeAPI()
		if errors.Is(err, control.ErrPublicationRejected) {
			return errors.Join(err, candidate.plane.Close())
		}
		return &activationError{err}
	}
	if !a.staging {
		candidate.apiUpdate.Commit()
	}
	a.plane = candidate.plane
	if a.managementAPI != candidate.api {
		a.managementAPI.Close()
	}
	a.managementAPI = candidate.api
	return nil
}
