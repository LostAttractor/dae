import { Tab, TabList } from "@astryxdesign/core/TabList";
import { useEffect, useLayoutEffect, useState } from "react";
import { createView } from "./react-view.js";
import { bytes, TrafficPanel } from "./traffic.jsx";
import { UpdatedAt } from "./updated.jsx";

function GroupEntry({ group }) {
  const [open, setOpen] = useState(false);
  return <details className="status-entry" data-name={group.name} open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary><strong>{group.name}</strong><span className="count">{group.nodes.length} node{group.nodes.length === 1 ? "" : "s"}</span>
      <span className="status-entry-description">{group.policy || group.target_kind} · {group.connectivity || "No connectivity checks"}</span>
      <span className="status-entry-metrics">
        <span><small>Active</small><strong>{group.stats.active_connections}</strong></span>
        <span><small>Uploaded</small><strong>{bytes(group.stats.upload_bytes)}</strong></span>
        <span><small>Downloaded</small><strong>{bytes(group.stats.download_bytes)}</strong></span>
      </span>
    </summary>
    <div className="status-nodes">{open && group.nodes.map((node, index) => <p className="muted" key={index}>
      <span className="status-node-name">{node.name}</span>
      <span>{node.checks_connectivity ? node.healthy ? "Healthy" : "Unavailable" : "Not monitored"}</span>
      <span>{node.stats.active_connections} active</span>
    </p>)}</div>
  </details>;
}

function ConnectionDetails({ snapshot, global, prefix }) {
  const uptime = Math.max(0, Math.floor((Date.now() - Date.parse(snapshot.started_at)) / 60000));
  return <details className="connection-details">
    <summary>Connection Details</summary>
    <dl className="traffic-totals">
      <div><dt>Total connections</dt><dd>{(snapshot.stats.total_connections ?? 0).toLocaleString()}</dd></div>
      <div><dt>Uploaded</dt><dd>{bytes(snapshot.stats.upload_bytes)}</dd></div>
      <div><dt>Downloaded</dt><dd>{bytes(snapshot.stats.download_bytes)}</dd></div>
    </dl>
    <p className="muted">{global
      ? `Uptime ${Math.floor(uptime / 1440)}d ${Math.floor(uptime / 60) % 24}h ${uptime % 60}m · ${snapshot.direct_fallback_connections} direct fallback connections`
      : `Since daemon start ${new Date(snapshot.started_at).toLocaleString()}`}</p>
    {global ? <>
      <div id={`${prefix}-groups`} className="status-details" tabIndex="0" role="region" aria-label="Outbounds and nodes">
        {snapshot.groups.map(group => <GroupEntry key={group.name} group={group} />)}
        {!snapshot.groups.length && <p className="muted">No outbounds available.</p>}
      </div>
      {snapshot.tables.length > 0 && <details><summary>Domain Tables</summary>
        {snapshot.tables.map(table => <p key={table.name}>{table.name}: {table.used.toLocaleString()} / {table.limit ? table.limit.toLocaleString() : "unbounded"}</p>)}
      </details>}
      {snapshot.plugins?.length > 0 && <details><summary>Plugins</summary>
        {snapshot.plugins.map(plugin => <p key={plugin.id}>{plugin.id} · {plugin.type} · {plugin.state}</p>)}
      </details>}
    </> : <div id="device-outbounds">
      {snapshot.outbounds.map(outbound => <div className="outbound-entry" key={outbound.name}><strong>{outbound.name}</strong>
        <dl className="outbound-stats">
          <div><dt>Active</dt><dd>{outbound.stats.active_connections}</dd></div>
          <div><dt>Uploaded</dt><dd>{bytes(outbound.stats.upload_bytes)}</dd></div>
          <div><dt>Downloaded</dt><dd>{bytes(outbound.stats.download_bytes)}</dd></div>
        </dl>
      </div>)}
      {!snapshot.outbounds.length && <p className="muted">No attributed upstream connections yet.</p>}
    </div>}
  </details>;
}

function useWide(query) {
  const [media] = useState(() => matchMedia(query));
  const [wide, setWide] = useState(media.matches);
  useEffect(() => {
    const update = () => setWide(media.matches);
    media.addEventListener("change", update);
    update();
    return () => media.removeEventListener("change", update);
  }, [media]);
  return wide;
}

function ScopeStatus({ state, scope, prefix = scope, visible, labelledBy }) {
  return <div id={`${prefix}-status`} className="status-scope-panel" role={labelledBy ? "tabpanel" : "region"}
    aria-labelledby={labelledBy || `${prefix}-heading`}>
    <h3 id={`${prefix}-heading`}>{scope === "global" ? "All devices" : "This device"}</h3>
    <div id={`${prefix}-traffic`}>
      {state.snapshot && visible ? <TrafficPanel stats={state.snapshot.stats} /> : !state.snapshot && <p className="muted">{state.message}</p>}
      {state.snapshot && <ConnectionDetails snapshot={state.snapshot} global={scope === "global"} prefix={prefix} />}
    </div>
    <p className="status-updated">{state.error || (state.updatedAt != null && <UpdatedAt timestamp={state.updatedAt} />)}</p>
  </div>;
}

function Status({ device, global, visible }) {
  const wide = useWide("(min-width: 1024px)");
  const [scope, setScope] = useState("device");
  const hasGlobal = Boolean(global.snapshot);
  useLayoutEffect(() => { if (!hasGlobal) setScope("device"); }, [hasGlobal]);
  return <>
    <h2 id="traffic-title">Status</h2>
    <div id="traffic-content">
      {!wide && <TabList className="scope-tabs" value={scope} onChange={setScope} role="tablist" aria-label="Traffic scope" hasDivider>
        <Tab id="device-tab" value="device" label="This device" panelId="device-status" onFocus={() => setScope("device")} />
        <Tab id="global-tab" value="global" label="All devices" panelId="global-status" aria-disabled={!hasGlobal}
          onFocus={() => { if (hasGlobal) setScope("global"); }} title={!hasGlobal ? global.message : undefined} />
      </TabList>}
      <div className={`status-grid${wide && hasGlobal ? " status-grid-both" : ""}`}>
        <div hidden={!wide && scope !== "device"}>
          <ScopeStatus state={device} scope="device" visible={visible && (wide || scope === "device")} labelledBy={!wide ? "device-tab" : undefined} />
        </div>
        <div hidden={!hasGlobal || (!wide && scope !== "global")}>
          <ScopeStatus state={global} scope="global" visible={visible && hasGlobal && (wide || scope === "global")} labelledBy={!wide ? "global-tab" : undefined} />
        </div>
      </div>
      <p className="traffic-note">Userspace upstream traffic only. Kernel-direct traffic and local responses are not counted.</p>
    </div>
  </>;
}

function GlobalStatus({ state, visible }) {
  return <>
    <h2 id="managed-global-traffic-title">Global status</h2>
    <ScopeStatus state={state} scope="global" prefix="managed-global" visible={visible} />
    <p className="traffic-note">Userspace upstream traffic only. Kernel-direct traffic and local responses are not counted.</p>
  </>;
}

// Both presentations consume the existing snapshots. No additional polling or
// counters are introduced by showing both scopes or switching Manage sections.
export function createStatus(overviewContainer, globalContainer) {
  const renderOverview = createView(overviewContainer), renderGlobal = createView(globalContainer);
  let device = { snapshot: null, message: "Loading traffic…" };
  let global = { snapshot: null, message: "Login required to view all devices." };
  let page, section;
  const updateOverview = () => renderOverview(<Status device={device} global={global} visible={page === "overview"} />);
  const updateGlobal = () => renderGlobal(<GlobalStatus state={global} visible={page === "manage" && section === "status"} />);
  const snapshotState = (snapshot) => ({ snapshot, updatedAt: Date.now() });
  return {
    setView: (nextPage, nextSection) => {
      if (page === nextPage && section === nextSection) return;
      page = nextPage; section = nextSection; updateOverview(); updateGlobal();
    },
    setDevice: (snapshot) => { device = snapshotState(snapshot); updateOverview(); },
    setGlobal: (snapshot) => { global = snapshotState(snapshot); updateOverview(); updateGlobal(); },
    clearGlobal: (message) => { global = { snapshot: null, message }; updateOverview(); updateGlobal(); },
    deviceError: (message, clear) => {
      device = { ...device, ...(clear ? { snapshot: null, message } : {}), error: "Device update failed · Retrying" };
      updateOverview();
    },
    globalError: () => { global = { ...global, error: "Global update failed · Retrying" }; updateOverview(); updateGlobal(); },
  };
}
