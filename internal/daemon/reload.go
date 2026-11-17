// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
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
	staging                 bool
	beginShutdown           func()
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
	operations              *operations
	certificates            *certificates
}

// A failed attachment replacement is distinct from a rejected candidate.
type activationError struct{ error }

func (e *activationError) Unwrap() error { return e.error }

func (a *application) report(message string) {
	if a.progress != nil {
		a.progress(message)
	}
}

func (a *application) publishAPI() {
	if tests := a.plane.MITMTests(); tests != nil {
		tests.Invalidate()
	}
	handler := a.apiHandler()
	a.localAPI.SetLocalServices(apiserver.LocalServices{Operations: a.operations, Metrics: metricsHandler, Pprof: a.conf.API.Pprof})
	a.localAPI.SetHandler(handler)
	var targets []netip.AddrPort
	if tests := a.plane.MITMTests(); tests != nil {
		targets = tests.Targets()
	}
	a.managementAPI.Configure(daemonAPIHandler(handler, a.conf.API.Web, targets...), a.certificates.Authority(), filepath.Join(common.CacheDirectory(), "api-tls"))
}

func (a *application) accept(conf *config.Config, inputs *controlInputs, server netip.AddrPort, routingChanged bool) {
	a.datapath.RefreshTCPIdleTimeouts()
	if routingChanged || a.conf.Global.DNSResolver != conf.Global.DNSResolver {
		a.resolver.Configure(server, a.plane.DNSResolverDialer())
	}
	if a.conf.Global.LogLevel != conf.Global.LogLevel {
		logger.SetLogger(conf.Global.LogLevel, a.options.DisableTimestamp, nil)
	}
	a.plane.SetPluginConfiguration(conf.Plugins, slices.Sorted(maps.Keys(a.definitions)))
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
	// What dae learned about nodes lasts until the user reloads, also when
	// nothing changed. Resource refreshes keep it.
	a.datapath.RelearnNodes()
	return a.apply(ctx, next, suspend, abort, false)
}

// Automatic and API refreshes use the accepted configuration. Only reload reads
// configuration edits from disk. All publication paths share this transaction.
func (a *application) apply(ctx context.Context, next *config.Config, suspend, abort, dueOnly bool) (result string, err error) {
	loadCtx, refresh := a.resources.Begin(ctx, next.Global.ResourceUpdateInterval, dueOnly)
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
	if err := a.conf.Global.CheckReload(next.Global); err != nil {
		return "", err
	}
	if err := a.datapath.CheckSocketMark(next.Global.SoMarkFromDae); err != nil {
		return "", err
	}
	if !suspend {
		if err := plugins.Preflight(ctx); err != nil {
			return "", err
		}
	}
	certificates := a.certificates
	if !suspend {
		certificates, err = prepareCertificates(next, a.certificates)
		if err != nil {
			return "", err
		}
	}
	inputs := a.inputs
	if !suspend {
		a.report("Refreshing configuration resources...")
		inputs, err = loadControlInputs(loadCtx, next, true, a.geoDirs, a.options.ConfigFile, a.inputs)
		if err != nil {
			return "", fmt.Errorf("refresh resources: %w", err)
		}
	}
	previous := a.plane.MITMHost()
	var prepared control.PreparedMITM
	load := func(client *http.Client) (control.PreparedMITM, error) {
		return loadMITM(loadCtx, next, certificates.Authority(), client, a.workerClient, plugins, previous, a.geoDirs, a.datapath)
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
		a.report("Preparing to suspend traffic interception...")
		prepared, err = a.plane.PrepareMITMSuccessor()
		if err != nil {
			return "", err
		}
		load = takePrepared
	}
	defer func() {
		if _, fatal := errors.AsType[*activationError](err); paused && !fatal {
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
		if err := a.refreshAPIRouting(ctx); err != nil {
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
		if result, err := a.replaceServices(ctx, next, inputs, server, certificates, &prepared, pauseAPI); result != "" || err != nil {
			if err == nil {
				refresh.Commit()
			}
			return result, err
		}
		load = takePrepared
	}

	a.report("Preparing affected services and routing...")
	candidate, err := a.preparePlane(ctx, next, inputs, load)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", errors.Join(err, candidate.discard())
	}
	a.report("Publishing replacement routing...")
	if !paused {
		pauseAPI()
	}
	if err := a.publishPlane(candidate, abort); err != nil {
		return "", err
	}
	a.setCertificates(certificates)
	a.accept(next, inputs, server, true)
	if !suspend {
		refresh.Commit()
	}
	logStartupNodeStatus(a.plane.GroupsStatus())
	if suspend {
		return "Suspended traffic interception", nil
	}
	return "Updated routing and affected services", nil
}

// replaceServices returns an empty result when changed plugin capture rules
// require a new control plane. Otherwise it commits the in-place service update.
func (a *application) replaceServices(ctx context.Context, next *config.Config, inputs *controlInputs, server netip.AddrPort, certificates *certificates, prepared *control.PreparedMITM, pauseAPI func()) (string, error) {
	if !a.plane.CanReplaceMITM(*prepared) {
		return "", nil
	}
	if err := prepared.Build(ctx); err != nil {
		return "", err
	}
	unchanged := a.plane.MITMHost().SameRuntime(prepared.Host)
	if !unchanged || a.certificates != certificates || !reflect.DeepEqual(a.conf.API, next.API) {
		pauseAPI()
	}
	if !unchanged {
		if err := a.plane.ReplaceMITM(*prepared, next.Plugins); err != nil {
			if errors.Is(err, control.ErrPublicationRejected) {
				return "", err
			}
			return "", &activationError{err}
		}
		*prepared = control.PreparedMITM{} // The plane now owns this host.
	}
	result := "Updated runtime services"
	if unchanged && a.certificates == certificates && reflect.DeepEqual(a.conf, next) {
		result = "No changes"
	}
	a.setCertificates(certificates)
	a.accept(next, inputs, server, false)
	if unchanged {
		prepared.Host.CommitResources()
	}
	return result, nil
}
