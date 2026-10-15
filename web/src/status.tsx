import type { ReactNode } from "react";
import type { Page, DeviceStatus, GlobalStatus, GroupStatus, PathStats } from "./types.ts";
interface ScopeState<T> { snapshot: T | null; message?: string; tone?: "warning" | "error"; updatedAt?: number; error?: string }
import { LayerCard } from "@cloudflare/kumo/components/layer-card";
import { Tabs } from "@cloudflare/kumo/components/tabs";
import { useEffect, useLayoutEffect, useState } from "react";
import { createView } from "./react-view.ts";
import { Disclosure } from "./disclosure.tsx";
import { inset } from "./setting.tsx";
import { cardTitle, framedList, groupLabel } from "./ui.ts";
import { InlineNotice, StatusBanner } from "./notice.tsx";
import { bytes } from "./traffic-data.ts";
import { TrafficPanel } from "./traffic.tsx";
import { nodeHealthLabels } from "./health.ts";
import { UpdatedAt } from "./updated.tsx";

const muted = "text-kumo-subtle";

function ConnectionMetrics({ stats, total = false }: { stats: PathStats; total?: boolean }) {
  const metrics = [
    [total ? "Total connections" : "Active connections", (total ? stats.total_connections ?? 0 : stats.active_connections ?? 0).toLocaleString()],
    ["Uploaded", bytes(stats.upload_bytes)],
    ["Downloaded", bytes(stats.download_bytes)],
  ];
  return <dl className="connection-metrics grid grid-cols-[repeat(auto-fit,minmax(min(100%,6.5rem),1fr))] gap-x-4 gap-y-3">
    {metrics.map(([label, value]) => <div key={label}><dt className="text-sm text-kumo-subtle">{label}</dt><dd className="mt-0.5 font-medium tabular-nums">{value}</dd></div>)}
  </dl>;
}

function StatusSection({ title, count, className, children }: { title: string; count?: number; className: string; children: ReactNode }) {
  return <Disclosure className={`status-section border-t border-kumo-hairline ${className}`} title={title} meta={count}>{children}</Disclosure>;
}

function Records({ entries }: { entries: [string, ReactNode][] }) {
  return <dl className="status-records divide-y divide-kumo-hairline">{entries.map(([name, detail]) => <div key={name} className="grid gap-0.5 py-2.5 first:pt-0 last:pb-0">
    <dt className="font-medium">{name}</dt><dd className="flex flex-wrap gap-x-3 gap-y-1 text-sm text-kumo-subtle tabular-nums">{detail}</dd>
  </div>)}</dl>;
}

function GroupEntry({ group }: { group: GroupStatus }) {
  const [open, setOpen] = useState(false);
  return <Disclosure className="status-entry px-4" name={group.name} isOpen={open} onOpenChange={setOpen}
    title={<strong className="font-medium">{group.name}</strong>} meta={`${group.nodes.length} node${group.nodes.length === 1 ? "" : "s"}`}>
    <p className="status-entry-description text-sm text-kumo-subtle">{group.policy || group.target_kind} · {group.health}</p>
    <ConnectionMetrics stats={group.stats} />
    {open && (group.nodes.length ? <div className="status-node-section border-t border-kumo-hairline pt-3">
      <h4 className="mb-2 text-sm font-medium">Nodes</h4>
      <div className="status-nodes max-h-80 overflow-y-auto overscroll-contain pr-2 [scrollbar-gutter:stable] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-kumo-brand" tabIndex={0} role="region" aria-label={`${group.name} nodes`}>
        <ul className="divide-y divide-kumo-hairline">{group.nodes.map((node, index) => <li key={index} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-0.5 py-2.5 text-sm">
          <span className="status-node-name col-span-full font-medium">{node.name}</span>
          <span className="status-node-state text-kumo-subtle">{nodeHealthLabels[node.health]}</span>
          <span className="status-node-count tabular-nums">{node.stats.active_connections} active</span>
        </li>)}</ul>
      </div>
    </div> : <p className={muted}>No nodes in this group.</p>)}
  </Disclosure>;
}

function StatusDetails({ snapshot, global, prefix }: { prefix: string } & ({ snapshot: GlobalStatus; global: true } | { snapshot: DeviceStatus; global: false })) {
  const uptime = Math.max(0, Math.floor((Date.now() - Date.parse(snapshot.started_at)) / 60000));
  return <div className="status-sections mt-4 border-b border-kumo-hairline">
    <StatusSection className="connection-details" title="Connection statistics">
      <ConnectionMetrics stats={snapshot.stats} total />
      <dl className="status-facts grid gap-2 border-t border-kumo-hairline pt-4 text-sm">
        <div className="flex flex-wrap justify-between gap-x-4 gap-y-1"><dt className="text-kumo-subtle">{global ? "Uptime" : "Observed since"}</dt><dd className="tabular-nums">{global
          ? `${Math.floor(uptime / 1440)}d ${Math.floor(uptime / 60) % 24}h ${uptime % 60}m`
          : snapshot.started_at.startsWith("0001-") ? "No traffic observed" : new Date(snapshot.started_at).toLocaleString()}</dd></div>
        {global && <div className="flex flex-wrap justify-between gap-x-4 gap-y-1"><dt className="text-kumo-subtle">Direct fallback connections</dt><dd className="tabular-nums">{snapshot.direct_fallback_connections}</dd></div>}
      </dl>
    </StatusSection>
    <StatusSection className="outbounds-section" title="Outbounds" count={global ? snapshot.groups.length : snapshot.outbounds.length}>
      {global ? <div id={`${prefix}-groups`} className={`status-groups ${framedList} empty:hidden`}>
        {snapshot.groups.map(group => <GroupEntry key={group.name} group={group} />)}
      </div> : <div id="device-outbounds" className={`status-groups ${framedList} empty:hidden`}>
        {snapshot.outbounds.map(outbound => <div className="outbound-entry px-4 py-3" key={outbound.name}>
          <h4 className="mb-2 font-medium">{outbound.name}</h4><ConnectionMetrics stats={outbound.stats} />
        </div>)}
      </div>}
      {global ? !snapshot.groups.length && <p className={muted}>No outbounds available.</p>
        : !snapshot.outbounds.length && <p className={muted}>No attributed upstream connections yet.</p>}
    </StatusSection>
    {global && <>
      <StatusSection className="tables-section" title="Domain Tables" count={snapshot.tables.length}>
        <Records entries={snapshot.tables.map(table => [table.name, `${table.used.toLocaleString()} / ${table.limit ? table.limit.toLocaleString() : "unbounded"} entries`])} />
        {!snapshot.tables.length && <p className={muted}>No domain tables configured.</p>}
      </StatusSection>
      <StatusSection className="plugins-section" title="Plugins" count={snapshot.plugins?.length || 0}>
        <p className="buffer-memory text-sm text-kumo-subtle">Body buffers (process): {bytes(snapshot.buffer_memory.used)} / {bytes(snapshot.buffer_memory.limit)}; peak: {bytes(snapshot.buffer_memory.peak)}; denied: {snapshot.buffer_memory.denied.toLocaleString()}</p>
        <Records entries={(snapshot.plugins || []).map(plugin => [plugin.id, <><span>{plugin.type}</span><span>{plugin.state}</span></>])} />
        {!snapshot.plugins?.length && <p className={muted}>No plugins loaded.</p>}
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
  return <div id={`${prefix}-status`} className="status-scope-panel min-w-0" role={labelledBy ? "tabpanel" : "region"}
    aria-labelledby={labelledBy || `${prefix}-heading`}>
    <h3 id={`${prefix}-heading`} className={labelledBy ? "sr-only" : groupLabel}>{scope === "global" ? "All devices" : "This device"}</h3>
    <div id={`${prefix}-traffic`}>
      {state.snapshot && visible ? <TrafficPanel stats={state.snapshot.stats} /> : !state.snapshot && (state.tone
        ? <StatusBanner tone={state.tone} title={state.message || ""} /> : <p className={muted}>{state.message}</p>)}
      {state.snapshot && ("groups" in state.snapshot ? <StatusDetails snapshot={state.snapshot} global prefix={prefix} /> : <StatusDetails snapshot={state.snapshot} global={false} prefix={prefix} />)}
    </div>
    <div className="status-updated mt-3 text-xs text-kumo-subtle empty:hidden">
      {state.error ? <InlineNotice tone="error">{state.error}</InlineNotice> : state.updatedAt != null && <UpdatedAt timestamp={state.updatedAt} />}
    </div>
  </div>;
}

function Status({ device, global, visible }: { device: ScopeState<DeviceStatus>; global: ScopeState<GlobalStatus>; visible: boolean }) {
  const wide = useWide("(min-width: 1024px)");
  const [scope, setScope] = useState("device");
  const hasGlobal = Boolean(global.snapshot);
  useLayoutEffect(() => { if (!hasGlobal) setScope("device"); }, [hasGlobal]);
  return <LayerCard render={<section aria-labelledby="traffic-title" />} className="status-card min-w-0">
    <LayerCard.Secondary><h2 id="traffic-title" className={cardTitle}>Status</h2></LayerCard.Secondary>
    <LayerCard.Primary id="traffic-content" className="gap-0 p-4 md:p-5">
      {!wide && <Tabs className="scope-tabs mb-4" variant="underline" value={scope} activateOnFocus
        onValueChange={next => { if (next === "device" || hasGlobal) setScope(next); }} tabs={[
          { value: "device", label: "This device", className: inset, render: <button type="button" id="device-tab" aria-controls="device-status" /> },
          { value: "global", label: "All devices", className: inset, render: <button type="button" id="global-tab" aria-controls="global-status" aria-disabled={!hasGlobal} title={!hasGlobal ? global.message : undefined} /> },
        ]} />}
      <div className={`status-grid grid gap-5 ${wide && hasGlobal ? "[&>div+div]:border-t [&>div+div]:border-kumo-hairline [&>div+div]:pt-5" : ""}`}>
        <div hidden={!wide && scope !== "device"}>
          <ScopeStatus state={device} scope="device" visible={visible && (wide || scope === "device")} labelledBy={!wide ? "device-tab" : undefined} />
        </div>
        <div hidden={!hasGlobal || (!wide && scope !== "global")}>
          <ScopeStatus state={global} scope="global" visible={visible && hasGlobal && (wide || scope === "global")} labelledBy={!wide ? "global-tab" : undefined} />
        </div>
      </div>
      <p className="traffic-note mt-4 text-xs text-kumo-subtle">Userspace upstream traffic only. Kernel-direct traffic and local responses are not counted.</p>
    </LayerCard.Primary>
  </LayerCard>;
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
