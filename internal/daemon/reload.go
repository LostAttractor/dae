// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"reflect"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/mitm/certtest"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/pkg/logger"
	log "github.com/sirupsen/logrus"
)

// application owns the accepted configuration and the services selected by it.
// Its event loop serializes reloads; API writers drain only at publication.
type application struct {
	options                 Options
	conf                    *config.Config
	inputs                  *controlInputs
	plane                   *control.ControlPlane
	datapath                *control.Runtime
	settings                *settings.Store
	definitions             map[string]plugin.Definition
	resolver                *netutils.InternalResolver
	workerClient            *http.Client
	geoDirs                 []string
	localAPI, managementAPI *apiserver.Server
	progress                func(string)
	resources               resource.RefreshStore
	refreshes               *resourceRefresher
}

// A failed attachment replacement is distinct from a rejected candidate.
type activationError struct{ error }

func (a *application) report(message string) {
	if a.progress != nil {
		a.progress(message)
	}
}

func (a *application) publishAPI() {
	if tests := a.plane.CertificateTests(); tests != nil {
		tests.Invalidate()
	}
	handler := a.plane.APIHandler(a.options.Version, a.refreshes)
	a.localAPI.SetHandler(handler)
	var targets []netip.AddrPort
	var secure apiserver.TLSHandler
	if tests := a.plane.CertificateTests(); tests != nil {
		targets = tests.Targets()
		secure = certtest.Endpoint{Service: tests}
	}
	a.managementAPI.SetHandlers(daemonAPIHandler(handler, targets...), secure)
}

func (a *application) accept(conf *config.Config, inputs *controlInputs, server netip.AddrPort, routingChanged bool) {
	if routingChanged || a.conf.Global.DNSResolver != conf.Global.DNSResolver {
		a.resolver.Configure(server, a.plane.DNSResolverDialer())
	}
	if a.conf.Global.LogLevel != conf.Global.LogLevel {
		logger.SetLogger(conf.Global.LogLevel, a.options.DisableTimestamp, nil)
	}
	if a.conf.Global.APIKey != conf.Global.APIKey {
		a.plane.SetAPIKey(conf.Global.APIKey)
	}
	reconfigureObservabilityServers(conf.Global.PprofPort, conf.Global.MetricsPort)
	a.conf, a.inputs = conf, inputs
	pruneSubscriptions(conf, filepath.Dir(a.options.ConfigFile))
	stats.DefaultStore.RecordReload()
}

func (a *application) reload(ctx context.Context, suspend, abort bool) (string, error) {
	next, includes, err := LoadReloadConfig(a.options.ConfigFile, a.conf, suspend)
	if err != nil {
		return "", fmt.Errorf("load configuration: %w", err)
	}
	log.WithField("files", includes).Debug("Loaded configuration files")
	return a.apply(ctx, next, suspend, abort, false)
}

// Automatic and API refreshes use the accepted configuration. Only reload reads
// configuration edits from disk. All publication paths share this transaction.
func (a *application) apply(ctx context.Context, next *config.Config, suspend, abort, dueOnly bool) (result string, err error) {
	ctx, refresh := a.resources.Begin(ctx, next.Global.ResourceUpdateInterval, dueOnly)
	defer func() {
		if count := refresh.Fallbacks(); err == nil && count > 0 {
			result += fmt.Sprintf("; %d resource groups kept previous contents", count)
		}
	}()
	plugins, err := configurePlugins(next, a.definitions)
	if err != nil {
		return "", fmt.Errorf("configure plugins: %w", err)
	}
	server, err := netutils.ParseDNSServer(next.Global.DNSResolver)
	if err != nil {
		return "", err
	}
	if next.Global.TproxyPort != a.conf.Global.TproxyPort {
		return "", fmt.Errorf("tproxy_port (%v -> %v) cannot be changed by reload; restart dae to apply it", a.conf.Global.TproxyPort, next.Global.TproxyPort)
	}
	oldMark, nextMark := common.EffectiveSoMarkFromDae(a.conf.Global.SoMarkFromDae), common.EffectiveSoMarkFromDae(next.Global.SoMarkFromDae)
	if oldMark != nextMark {
		return "", fmt.Errorf("so_mark_from_dae (%#x -> %#x) cannot be changed by reload; restart dae to apply it", oldMark, nextMark)
	}
	a.report("Refreshing configuration resources...")
	inputs := a.inputs
	if !suspend {
		inputs, err = loadControlInputs(ctx, next, true, a.geoDirs, a.options.ConfigFile, a.inputs)
		if err != nil {
			return "", fmt.Errorf("refresh resources: %w", err)
		}
	}
	previous := a.plane.MITMHost()
	var prepared control.PreparedMITM
	load := func(client *http.Client) (control.PreparedMITM, error) {
		return loadMITM(ctx, next, client, a.workerClient, plugins, previous, a.geoDirs)
	}
	takePrepared := func(*http.Client) (control.PreparedMITM, error) {
		host := prepared
		prepared = control.PreparedMITM{}
		return host, nil
	}
	defer func() {
		if prepared.Host != nil {
			_ = prepared.Host.Close()
		}
	}()

	paused := false
	if suspend {
		prepared, err = a.plane.PrepareMITMSuccessor()
		if err != nil {
			return "", err
		}
		load = takePrepared
	}
	defer func() {
		if paused {
			a.publishAPI()
		}
	}()
	pauseAPI := func() {
		a.localAPI.SetHandler(nil)
		a.managementAPI.SetHandler(nil)
		paused = true
	}
	routingUnchanged := !suspend && !abort && sameControlConfig(a.conf, next) && a.inputs.equal(inputs)
	if routingUnchanged {
		routingUnchanged, err = a.plane.APIRoutingCurrent()
		if err != nil {
			return "", fmt.Errorf("refresh API routing: %w", err)
		}
	}
	if routingUnchanged {
		client, closeClient := a.plane.NewPreparationClient()
		prepared, err = load(client)
		closeClient()
		if err != nil {
			return "", fmt.Errorf("refresh plugins: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		unchanged := previous.SameRuntime(prepared.Host)
		if a.plane.CanReplaceMITM(prepared) {
			if !unchanged || a.conf.Global.APIKey != next.Global.APIKey {
				pauseAPI()
			}
			if !unchanged {
				if err := a.plane.ReplaceMITM(prepared); err != nil {
					return "", err
				}
				prepared = control.PreparedMITM{} // The plane now owns this host.
			}
			result := "Updated runtime services"
			if unchanged && reflect.DeepEqual(a.conf, next) {
				result = "No changes"
			}
			a.accept(next, inputs, server, false)
			refresh.Commit()
			return result, nil
		}
		load = takePrepared
	}

	a.report("Preparing affected services and routing...")
	candidate, err := newControlPlane(ctx, a.datapath, next, inputs, a.settings, load)
	if err != nil {
		return "", fmt.Errorf("prepare control plane: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", errors.Join(err, candidate.Close())
	}
	api, err := prepareAPIServer(a.managementAPI, next.Global.APIPort)
	if err != nil {
		return "", errors.Join(err, candidate.Close())
	}
	a.report("Publishing replacement routing...")
	pauseAPI()
	if err := a.datapath.Publish(candidate, abort); err != nil {
		if api != a.managementAPI {
			api.Close()
		}
		if errors.Is(err, control.ErrPublicationRejected) {
			return "", errors.Join(err, candidate.Close())
		}
		paused = false // Partially replaced attachments require terminal shutdown.
		return "", &activationError{err}
	}
	a.plane = candidate
	if a.managementAPI != api {
		a.managementAPI.Close()
	}
	a.managementAPI = api
	a.accept(next, inputs, server, true)
	if !suspend {
		refresh.Commit()
	}
	logStartupNodeStatus(candidate.GroupsStatus())
	return "Updated routing and affected services", nil
}
