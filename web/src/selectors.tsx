import { nodeHealthLabels } from "./health.ts";
import type { KeyboardEvent } from "react";
import type { APIRequest, RunAction, SelectorNode, SelectorState, Page, SettingSection } from "./types.ts";

interface SelectorActions { run: RunAction; request: APIRequest; refresh: () => Promise<unknown> }
interface SelectorControls extends SelectorActions { update: (selector: SelectorState) => void; layer: HTMLElement }
import { Badge } from "@cloudflare/kumo/components/badge";
import { Button } from "@cloudflare/kumo/components/button";
import { Empty } from "@cloudflare/kumo/components/empty";
import { InputGroup } from "@cloudflare/kumo/components/input-group";
import { Popover } from "@cloudflare/kumo/components/popover";
import { CaretUpDownIcon, CheckIcon, MagnifyingGlassIcon, XIcon } from "@phosphor-icons/react";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { byId } from "./dom.ts";
import { createView } from "./react-view.ts";
import { InlineNotice, StatusBanner } from "./notice.tsx";
import { floating, framed } from "./ui.ts";

const healthLabels = { empty: "No selected node", ...nodeHealthLabels };
const healthVariants = { empty: "secondary", unknown: "secondary", healthy: "success", confirming: "warning", unhealthy: "error" } as const;
const healthState = (node?: SelectorNode) => node?.health ?? "empty";
const latencyLabel = (node?: SelectorNode) => typeof node?.latency_ms === "number" && Number.isFinite(node.latency_ms) ? `${Math.round(node.latency_ms)} ms` : "";
const checkedLabel = (node?: SelectorNode) => node?.checked_at ? `Last tested ${new Date(node.checked_at).toLocaleString()}` : "";
const monitoringLabel = (node: SelectorNode) => node.tracking ? "Monitoring" : "On demand";
const nodeCount = (count: number) => `${count} node${count === 1 ? "" : "s"}`;
const meta = "text-sm font-normal text-kumo-subtle";

function Health({ node }: { node?: SelectorNode }) {
  const state = healthState(node);
  return <><Badge className="node-health" variant={healthVariants[state]}>{healthLabels[state]}</Badge>
    <span className={`node-latency tabular-nums empty:hidden ${meta}`}>{node?.checking ? "Testing…" : latencyLabel(node)}</span></>;
}

function Selector({ selector, actions, compact = false }: { selector: SelectorState; actions: SelectorControls; compact?: boolean }) {
  const id = useId();
  const picker = useRef<HTMLButtonElement>(null), search = useRef<HTMLInputElement>(null), list = useRef<HTMLDivElement>(null);
  // The popup spans the picker and its Test button, leaving room for node names.
  const control = useRef<HTMLDivElement>(null), focused = useRef<HTMLElement | null>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const filter = query.trim().toLocaleLowerCase();
  const visible = open ? selector.nodes.filter(node => node.name.toLocaleLowerCase().includes(filter)) : [];
  const selected = selector.nodes.find(node => node.id === selector.node_id);
  const Heading = compact ? "h4" : "h3";
  const name = selected?.name || "Select a node";
  const saved = selector.saved_selection;
  const fallback = saved && saved.status !== "matched";

  // Polling can replace the focused candidate; keep focus inside the popup.
  useLayoutEffect(() => {
    if (open && focused.current && document.activeElement === document.body &&
      (!focused.current.isConnected || focused.current.matches(":disabled") || !focused.current.checkVisibility())) {
      search.current?.focus({ preventScroll: true });
    }
  }, [selector, open, query]);

  async function save(method: "PUT" | "DELETE", body: { node_id: string } | undefined, success: string) {
    const saved = await actions.run(async () => {
      actions.update(await actions.request<SelectorState>(`/api/selectors/${encodeURIComponent(selector.name)}`, method, body));
      setOpen(false);
    }, success);
    if (saved) picker.current?.focus();
  }

  async function probe(nodeID?: string) {
    const queued = await actions.run(async () => {
      await actions.request("/api/probes", "POST", { outbound: selector.name, node_id: nodeID });
      await actions.refresh();
    }, `${selector.name}: tests queued. Results update automatically.`, "Queuing connectivity tests…");
    if (queued) {
      const candidate = [...(list.current?.querySelectorAll<HTMLElement>(":scope > .selector-node") || [])].find(node => node.dataset.node === nodeID);
      const target = open ? candidate?.querySelector<HTMLButtonElement>(".select-node") ?? search.current : picker.current;
      target?.focus({ preventScroll: true });
    }
  }

  function navigate(event: KeyboardEvent<HTMLDivElement>) {
    if (!(event.target instanceof HTMLElement)) return;
    const fromSearch = event.target === search.current;
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    if (fromSearch && (event.key === "Home" || event.key === "End")) return;
    const rows = [...list.current!.querySelectorAll<HTMLElement>(".selector-node:not([hidden])")];
    if (!rows.length) return;
    const index = rows.indexOf(event.target.closest<HTMLElement>(".selector-node")!);
    let next = index + (event.key === "ArrowDown" ? 1 : -1);
    if (event.key === "Home") next = 0;
    if (event.key === "End" || (fromSearch && event.key === "ArrowUp")) next = rows.length - 1;
    event.preventDefault();
    rows[Math.max(0, Math.min(rows.length - 1, next))].querySelector<HTMLButtonElement>(".select-node")!.focus();
  }

  return <section className={`selector-row min-w-0 ${framed}${selector.track_all ? " tracking-all" : ""}${compact ? " selector-compact" : ""}`} data-group={selector.name} aria-labelledby={id}>
    <div className="selector-heading mb-2.5 flex flex-wrap items-start gap-2">
      <div className="selector-identity flex min-w-0 flex-auto flex-wrap items-center gap-x-3 gap-y-1">
        <Heading id={id} className="selector-name min-w-0 text-base font-semibold">{selector.name}</Heading>
        <div className="selected-status flex flex-wrap items-center gap-2">{<Health node={selected} />}</div>
      </div>
      <div className="selector-meta flex flex-wrap items-center gap-2">
        <span className={`node-count count whitespace-nowrap ${meta}`}>{nodeCount(selector.nodes.length)}</span>
        {fallback ? <InlineNotice className="selection-source selection-warning text-sm" tone="warning" title={`Saved: ${saved.name}`}>Saved choice {saved.status} · Temporary fallback</InlineNotice>
          : <span className="selection-source" hidden={!selector.default_node_id && !saved} title={saved ? `Saved: ${saved.name}` : ""}><Badge variant="secondary">{selector.overridden ? "Custom" : "Default"}</Badge></span>}
      </div>
    </div>
    <div ref={control} className={`selector-control grid gap-2 ${compact || selector.track_all ? "grid-cols-1" : "grid-cols-[minmax(0,1fr)_auto]"}`}>
      <Popover open={open} onOpenChange={next => {
        if (next) {
          setQuery("");
          // On short viewports, such as with a keyboard open, give the list the space below the picker.
          const rect = picker.current!.getBoundingClientRect();
          if (Math.max(rect.top, innerHeight - rect.bottom) < 240) picker.current!.scrollIntoView({ block: "start" });
        }
        setOpen(next);
      }} onOpenChangeComplete={opened => {
        // The list height is final once the popup is positioned; then center the selected node.
        const row = opened && [...list.current?.querySelectorAll<HTMLElement>(":scope > .selector-node") || []].find(node => node.dataset.node === selector.node_id);
        if (row) row.scrollIntoView({ block: "center" });
      }}>
        {/* The picker chooses one value, so its trigger matches Kumo's Select trigger. */}
        <Popover.Trigger render={<Button ref={picker} type="button" className="node-picker w-full min-w-0 justify-between bg-kumo-control font-normal disabled:bg-kumo-control/50" disabled={!selector.nodes.length}
          aria-label={`${selector.name}: ${name}`} />}>
          <span className="selected-name min-w-0 truncate">{name}</span><CaretUpDownIcon className="shrink-0 text-kumo-subtle" size={16} aria-hidden />
        </Popover.Trigger>
        <Popover.Content container={actions.layer} anchor={control} side="bottom" align="start" sideOffset={6} positionMethod="fixed"
          className={`node-popover [&>[data-side]]:hidden max-h-[min(var(--available-height),28rem)] w-[min(var(--anchor-width),calc(100vw-24px))] gap-0 overflow-hidden p-1.5 text-base outline-0 ${floating}`}>
          <Popover.Title className="sr-only">Select a node in {selector.name}</Popover.Title>
          <div className="flex min-h-0 flex-col" onKeyDown={navigate} onFocusCapture={(event) => { focused.current = event.target instanceof HTMLElement ? event.target : null; }}>
            <InputGroup className="node-search w-full flex-none">
              <InputGroup.Addon><MagnifyingGlassIcon aria-hidden /></InputGroup.Addon>
              <InputGroup.Input ref={search} role="searchbox" aria-label={`Search nodes in ${selector.name}`} placeholder="Search nodes…" autoComplete="off" spellCheck={false}
                value={query} onChange={(event) => { setQuery(event.target.value); list.current!.scrollTop = 0; }} />
              {query && <InputGroup.Addon align="end" className="pr-1">
                <InputGroup.Button shape="square" icon={XIcon} aria-label="Clear search" onClick={() => { setQuery(""); search.current!.focus(); }} />
              </InputGroup.Addon>}
            </InputGroup>
            <p className="node-results mx-2 mt-2 mb-1 flex-none text-xs text-kumo-subtle" role="status">{filter ? `${visible.length} of ${selector.nodes.length} nodes` : nodeCount(visible.length)}</p>
            <div ref={list} className="node-list grid min-h-0 gap-0.5 overflow-y-auto overscroll-contain [scrollbar-gutter:stable]">{open && selector.nodes.map(node => <NodeOption key={node.id} node={node} selector={selector}
              hidden={!node.name.toLocaleLowerCase().includes(filter)} onProbe={() => probe(node.id)} onSelect={() => {
                if (node.id === selector.node_id && selector.saved_selection?.status === "matched") {
                  setOpen(false); picker.current!.focus();
                } else save("PUT", { node_id: node.id }, `${selector.name}: selection saved.`);
              }} />)}</div>
            <p className="no-nodes px-2 py-3 text-kumo-subtle" hidden={visible.length !== 0}>No matching nodes.</p>
          </div>
        </Popover.Content>
      </Popover>
      <Button className="test-selected" type="button" hidden={compact || selector.track_all} disabled={!selected || selected.checking}
        aria-label={`Test selected node in ${selector.name}`} onClick={() => probe(selector.node_id)}>Test selected</Button>
    </div>
    {!compact && selected && (!selector.track_all || selected.checked_at) && <div className="selector-monitoring mt-2.5 flex flex-wrap items-center gap-2">
      {!selector.track_all && <Badge className="node-monitoring" variant="secondary">{monitoringLabel(selected)}</Badge>}
      <span className={`node-checked empty:hidden max-[420px]:basis-full ${meta}`}>{checkedLabel(selected)}</span>
    </div>}
    {!compact && <div className="selector-actions mt-3 flex flex-wrap items-center gap-2 [&:not(:has(>:not([hidden])))]:hidden">
      <span className="tracking-status text-kumo-subtle" title="All nodes are monitored automatically" hidden={!selector.track_all}>Monitoring all nodes</span>
      <div className="selector-buttons button-row flex flex-wrap gap-2" hidden={selector.track_all && !selector.default_node_id}>
        <Button className="test-all" type="button" hidden={selector.track_all} disabled={!selector.nodes.length || selector.nodes.every(node => node.checking)}
          aria-label={`Test all nodes in ${selector.name}`} onClick={() => probe()}>Test All</Button>
        <Button className="reset" type="button" hidden={!selector.default_node_id} disabled={!selector.overridden}
          onClick={() => save("DELETE", undefined, `${selector.name}: reset to default.`)}>Use default</Button>
      </div>
    </div>}
  </section>;
}

function NodeOption({ node, selector, hidden, onProbe, onSelect }: { node: SelectorNode; selector: SelectorState; hidden: boolean; onProbe: () => void; onSelect: () => void }) {
  const selected = node.id === selector.node_id;
  return <div className="selector-node grid grid-cols-[minmax(0,1fr)_auto] items-stretch rounded-md [contain-intrinsic-size:auto_64px] [content-visibility:auto] hover:bg-kumo-tint has-[.select-node:focus-visible]:outline-2 has-[.select-node:focus-visible]:-outline-offset-2 has-[.select-node:focus-visible]:outline-kumo-brand has-[.select-node[aria-pressed=true]]:bg-kumo-info-tint" data-node={node.id} hidden={hidden}>
    <button className="select-node grid min-h-14 min-w-0 cursor-pointer grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2 gap-y-0.5 rounded-l-md px-2.5 py-2 text-left font-medium text-kumo-default outline-none disabled:cursor-default" type="button" aria-pressed={selected} onClick={onSelect}
      title={`${node.name}${node.id === selector.default_node_id ? " · Default" : ""}\n${monitoringLabel(node)}${node.checked_at ? ` · ${checkedLabel(node)}` : ""}`}
      aria-label={`${selected ? "Selected" : "Select"} ${node.name}, ${healthLabels[healthState(node)]} ${latencyLabel(node)}`.trim()}>
      <span className="node-name truncate">{node.name}</span>
      <span className="node-check col-start-2 row-span-2 w-4 text-kumo-link" aria-hidden="true">{selected && <CheckIcon size={14} weight="bold" />}</span>
      <span className="node-status col-start-1 flex flex-wrap items-center gap-2"><Health node={node} /></span>
    </button>
    <Button className="test-node mr-2 min-w-16 self-center" type="button" hidden={selector.track_all} disabled={node.checking} aria-label={`Test ${node.name}`} onClick={onProbe}>Test</Button>
  </div>;
}

export function createSelectors(overviewContainer: HTMLElement, settingContainer: HTMLElement, actions: SelectorActions) {
  const renderOverview = createView(overviewContainer), renderSetting = createView(settingContainer);
  let selectors: SelectorState[] | null = null, message: string | null = null;
  let view: "overview" | "selector" | null = "overview";
  const controls = { ...actions, layer: byId("popup-layer"), update: (updated: SelectorState) => show((selectors || []).map(selector => selector.name === updated.name ? updated : selector)) };
  function render() {
    const content = selectors ? selectors.length
      ? selectors.map(selector => <Selector key={selector.name} selector={selector} actions={controls} compact={view === "overview"} />)
      : <Empty size="sm" title="No outbound groups" />
      : message && <StatusBanner tone="error" title={message} />;
    renderOverview(view === "overview" ? content : null);
    renderSetting(view === "selector" ? content : null);
  }
  function show(next: SelectorState[]) {
    selectors = next;
    message = null;
    render();
  }
  return {
    show,
    setView: (page: Page, section?: SettingSection) => {
      const next = page === "overview" ? "overview" : page === "setting" && section === "selector" ? "selector" : null;
      if (view === next) return;
      view = next;
      render();
    },
    clear: () => { selectors = null; message = null; render(); },
    error: (text: string) => { selectors = null; message = text; render(); },
  };
}
