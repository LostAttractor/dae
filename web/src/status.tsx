import type { ReactNode } from "react";
import type { Page, DeviceStatus, GlobalStatus, GroupStatus, PathStats } from "./types.ts";
interface ScopeState<T> { snapshot: T | null; message?: string; tone?: "warning" | "error"; updatedAt?: number; error?: string }
import { TabList } from "@astryxdesign/core/TabList";
import { Tab } from "./native-controls.tsx";
import { Collapsible } from "@astryxdesign/core/Collapsible";
import { Banner } from "@astryxdesign/core/Banner";
import { Icon } from "@astryxdesign/core/Icon";
import { useEffect, useLayoutEffect, useState } from "react";
import { createView } from "./react-view.ts";
import { bytes } from "./traffic-data.ts";
import { TrafficPanel } from "./traffic.tsx";
import { UpdatedAt } from "./updated.tsx";

function ConnectionMetrics({ stats, total = false }: { stats: PathStats; total?: boolean }) {
  return <dl className="connection-metrics">
    <div><dt>{total ? "Total connections" : "Active connections"}</dt><dd>{(total ? stats.total_connections ?? 0 : stats.active_connections ?? 0).toLocaleString()}</dd></div>
    <div><dt>Uploaded</dt><dd>{bytes(stats.upload_bytes)}</dd></div>
    <div><dt>Downloaded</dt><dd>{bytes(stats.download_bytes)}</dd></div>
  </dl>;
}

function StatusSection({ title, count, className, children }: { title: string; count?: number; className: string; children: ReactNode }) {
  return <Collapsible className={`status-section ${className}`} defaultIsOpen={false} chevronPosition="start"
    trigger={<span className="status-section-label"><span>{title}</span>{count != null && <span className="count">{count}</span>}</span>}>
    {children}
  </Collapsible>;
}

function GroupEntry({ group }: { group: GroupStatus }) {
  const [open, setOpen] = useState(false);
  return <Collapsible className="status-entry" data-name={group.name} isOpen={open} onOpenChange={setOpen} chevronPosition="start"
    trigger={<span className="status-section-label"><strong>{group.name}</strong><span className="count">{group.nodes.length} node{group.nodes.length === 1 ? "" : "s"}</span></span>}>
    <div className="status-group-details">
      <p className="status-entry-description">{group.policy || group.target_kind} · {group.connectivity || "No connectivity checks"}</p>
      <ConnectionMetrics stats={group.stats} />
      {open && (group.nodes.length ? <div className="status-node-section">
        <h4>Nodes</h4>
        <div className="status-nodes" tabIndex={0} role="region" aria-label={`${group.name} nodes`}>
          <ul>{group.nodes.map((node, index) => <li key={index}>
            <span className="status-node-name">{node.name}</span>
            <span className="status-node-state">{node.checks_connectivity ? node.healthy ? "Healthy" : "Unavailable" : "Not monitored"}</span>
            <span className="status-node-count">{node.stats.active_connections} active</span>
          </li>)}</ul>
        </div>
      </div> : <p className="muted">No nodes in this group.</p>)}
    </div>
  </Collapsible>;
}

function StatusDetails({ snapshot, global, prefix }: { prefix: string } & ({ snapshot: GlobalStatus; global: true } | { snapshot: DeviceStatus; global: false })) {
  const uptime = Math.max(0, Math.floor((Date.now() - Date.parse(snapshot.started_at)) / 60000));
  return <div className="status-sections">
    <StatusSection className="connection-details" title="Connection statistics">
      <ConnectionMetrics stats={snapshot.stats} total />
      <dl className="status-facts">
        <div><dt>{global ? "Uptime" : "Since daemon start"}</dt><dd>{global
          ? `${Math.floor(uptime / 1440)}d ${Math.floor(uptime / 60) % 24}h ${uptime % 60}m`
          : new Date(snapshot.started_at).toLocaleString()}</dd></div>
        {global && <div><dt>Direct fallback connections</dt><dd>{snapshot.direct_fallback_connections}</dd></div>}
      </dl>
    </StatusSection>
    <StatusSection className="outbounds-section" title="Outbounds" count={global ? snapshot.groups.length : snapshot.outbounds.length}>
      {global ? <div id={`${prefix}-groups`} className="status-groups">
        {snapshot.groups.map(group => <GroupEntry key={group.name} group={group} />)}
        {!snapshot.groups.length && <p className="muted">No outbounds available.</p>}
      </div> : <div id="device-outbounds" className="status-groups">
        {snapshot.outbounds.map(outbound => <div className="outbound-entry" key={outbound.name}>
          <h4>{outbound.name}</h4><ConnectionMetrics stats={outbound.stats} />
        </div>)}
        {!snapshot.outbounds.length && <p className="muted">No attributed upstream connections yet.</p>}
      </div>}
    </StatusSection>
    {global && <>
      <StatusSection className="tables-section" title="Domain Tables" count={snapshot.tables.length}>
        <dl className="status-records">{snapshot.tables.map(table => <div key={table.name}>
          <dt>{table.name}</dt><dd>{table.used.toLocaleString()} / {table.limit ? table.limit.toLocaleString() : "unbounded"} entries</dd>
        </div>)}</dl>
        {!snapshot.tables.length && <p className="muted">No domain tables configured.</p>}
      </StatusSection>
      <StatusSection className="plugins-section" title="Plugins" count={snapshot.plugins?.length || 0}>
        <dl className="status-records">{snapshot.plugins?.map(plugin => <div key={plugin.id}>
          <dt>{plugin.id}</dt><dd className="status-record-meta"><span>{plugin.type}</span><span>{plugin.state}</span></dd>
        </div>)}</dl>
        {!snapshot.plugins?.length && <p className="muted">No plugins loaded.</p>}
      </StatusSection>
    </>}
  </div>;
}

function useWide(query: string) {
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

function ScopeStatus({ state, scope, visible, labelledBy }: { state: ScopeState<DeviceStatus | GlobalStatus>; scope: "device" | "global"; visible: boolean; labelledBy?: string }) {
  const prefix = scope;
  return <div id={`${prefix}-status`} className="status-scope-panel" role={labelledBy ? "tabpanel" : "region"}
    aria-labelledby={labelledBy || `${prefix}-heading`}>
    <h3 id={`${prefix}-heading`}>{scope === "global" ? "All devices" : "This device"}</h3>
    <div id={`${prefix}-traffic`}>
      {state.snapshot && visible ? <TrafficPanel stats={state.snapshot.stats} /> : !state.snapshot && (state.tone
        ? <Banner status={state.tone} title={state.message} /> : <p className="muted">{state.message}</p>)}
      {state.snapshot && ("groups" in state.snapshot ? <StatusDetails snapshot={state.snapshot} global prefix={prefix} /> : <StatusDetails snapshot={state.snapshot} global={false} prefix={prefix} />)}
    </div>
    <p className={`status-updated${state.error ? " inline-notice" : ""}`} data-tone={state.error ? "error" : undefined}>
      {state.error ? <><Icon icon="error" size="sm" /><span>{state.error}</span></> : state.updatedAt != null && <UpdatedAt timestamp={state.updatedAt} />}
    </p>
  </div>;
}

function Status({ device, global, visible }: { device: ScopeState<DeviceStatus>; global: ScopeState<GlobalStatus>; visible: boolean }) {
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

// Both scopes consume the existing snapshots without additional polling or counters.
export function createStatus(overviewContainer: HTMLElement) {
  const renderOverview = createView(overviewContainer);
  let device: ScopeState<DeviceStatus> = { snapshot: null, message: "Loading traffic…" };
  let global: ScopeState<GlobalStatus> = { snapshot: null, message: "Login required to view all devices." };
  let page: Page | undefined;
  const updateOverview = () => renderOverview(<Status device={device} global={global} visible={page === "overview"} />);
  const snapshotState = <T,>(snapshot: T): ScopeState<T> => ({ snapshot, updatedAt: Date.now() });
  return {
    setView: (nextPage: Page) => {
      if (page === nextPage) return;
      page = nextPage; updateOverview();
    },
    setDevice: (snapshot: DeviceStatus) => { device = snapshotState(snapshot); updateOverview(); },
    setGlobal: (snapshot: GlobalStatus) => { global = snapshotState(snapshot); updateOverview(); },
    clearGlobal: (message: string) => { global = { snapshot: null, message }; updateOverview(); },
    deviceUnavailable: (message: string) => { device = { snapshot: null, message, tone: "warning" }; updateOverview(); },
    deviceError: (message: string, clear: boolean) => {
      device = clear ? { snapshot: null, message, tone: "error" } : { ...device, error: "Device update failed · Retrying" };
      updateOverview();
    },
    globalError: () => { global = { ...global, error: "Global update failed · Retrying" }; updateOverview(); },
  };
}
