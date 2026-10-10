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

function ConnectionDetails({ snapshot, global }) {
  const uptime = Math.max(0, Math.floor((Date.now() - Date.parse(snapshot.started_at)) / 60000));
  return <details className="connection-details">
    <summary>Connection Details</summary>
    <p className="muted">{global
      ? `Uptime ${Math.floor(uptime / 1440)}d ${Math.floor(uptime / 60) % 24}h ${uptime % 60}m · ${snapshot.direct_fallback_connections} direct fallback connections`
      : `Since daemon start ${new Date(snapshot.started_at).toLocaleString()}`}</p>
    {global ? <>
      <div id="global-groups" className="status-details" tabIndex="0" role="region" aria-label="Outbounds and nodes">
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

function Status({ device, global, visible }) {
  const [scope, setScope] = useState("device");
  const [media] = useState(() => matchMedia("(min-width: 1024px)"));
  const [wide, setWide] = useState(media.matches);
  const [expanded, setExpanded] = useState(null);
  const open = expanded ?? wide;
  useEffect(() => {
    const update = () => setWide(media.matches);
    media.addEventListener("change", update);
    update();
    return () => media.removeEventListener("change", update);
  }, [media]);
  const hasGlobal = Boolean(global.snapshot);
  useLayoutEffect(() => { if (!hasGlobal) setScope("device"); }, [hasGlobal]);
  function navigate(event) {
    if (!hasGlobal || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === "Home" ? "device" : event.key === "End" ? "global" : scope === "device" ? "global" : "device";
    setScope(next);
    event.currentTarget.querySelector(`#${next}-tab`).focus();
  }
  return <>
    <div className="card-heading">
      <h2 id="traffic-title">Traffic</h2>
      <button id="status-toggle" type="button" aria-expanded={open} aria-controls="traffic-content" onClick={() => setExpanded(!open)}>{open ? "Hide" : "Show"}</button>
    </div>
    <div id="traffic-content" hidden={!open}>
      <div className="scope-tabs" role="tablist" aria-label="Traffic scope" onKeyDown={navigate}>
        {[["device", "This Device"], ["global", "All Devices"]].map(([key, label]) => <button key={key} id={`${key}-tab`} type="button" role="tab"
          aria-selected={scope === key} aria-controls={`${key}-status`} tabIndex={scope === key ? 0 : -1}
          disabled={key === "global" && !hasGlobal} title={key === "global" && !hasGlobal ? global.message : undefined}
          onClick={() => setScope(key)}>{label}</button>)}
      </div>
      {Object.entries({ device, global }).map(([key, state]) => <div key={key} id={`${key}-status`} role="tabpanel" aria-labelledby={`${key}-tab`} hidden={scope !== key} tabIndex="0">
        <div id={`${key}-traffic`}>
          {state.snapshot && scope === key && open && visible ? <TrafficPanel stats={state.snapshot.stats} /> : !state.snapshot && <p className="muted">{state.message}</p>}
        </div>
        {state.snapshot && <ConnectionDetails snapshot={state.snapshot} global={key === "global"} />}
        {state.snapshot && <p className="traffic-note">Shows upstream connections handled by dae in userspace. Kernel-direct traffic and local responses are not counted.</p>}
        <p className="status-updated">{state.error || (state.updatedAt != null && <UpdatedAt timestamp={state.updatedAt} />)}</p>
      </div>)}
    </div>
  </>;
}

export function createStatus(container) {
  const render = createView(container);
  let device = { snapshot: null, message: "Loading traffic…" };
  let global = { snapshot: null, message: "Login required to view all devices." };
  let visible = false;
  const update = () => render(<Status device={device} global={global} visible={visible} />);
  const snapshotState = (snapshot) => ({ snapshot, updatedAt: Date.now() });
  update();
  return {
    setVisible: (next) => { if (visible !== next) { visible = next; update(); } },
    setDevice: (snapshot) => { device = snapshotState(snapshot); update(); },
    setGlobal: (snapshot) => { global = snapshotState(snapshot); update(); },
    clearGlobal: (message) => { global = { snapshot: null, message }; update(); },
    deviceError: (message, clear) => {
      device = { ...device, ...(clear ? { snapshot: null, message } : {}), error: "Device update failed · Retrying" };
      update();
    },
    globalError: () => { global = { ...global, error: "Global update failed · Retrying" }; update(); },
  };
}
