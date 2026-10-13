import type { KeyboardEvent } from "react";
import type { APIRequest, RunAction, SelectorNode, SelectorState, Page, SettingSection } from "./types.ts";

interface SelectorActions { run: RunAction; request: APIRequest; refresh: () => Promise<unknown> }
interface SelectorControls extends SelectorActions { update: (selector: SelectorState) => void }
import { Button, Badge, TextInput } from "./native-controls.tsx";
import { Banner } from "@astryxdesign/core/Banner";
import { Icon } from "@astryxdesign/core/Icon";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { createView } from "./react-view.ts";

const healthLabels = { empty: "No selected node", checking: "Testing…", unknown: "Not tested", healthy: "Available", unavailable: "Unavailable" };
function healthState(node?: SelectorNode) {
  if (!node) return "empty";
  if (node.checking) return "checking";
  if (!node.tested) return "unknown";
  return node.healthy ? "healthy" : "unavailable";
}
const latencyLabel = (node?: SelectorNode) => typeof node?.latency_ms === "number" && Number.isFinite(node.latency_ms) ? `${Math.round(node.latency_ms)} ms` : "";
const checkedLabel = (node?: SelectorNode) => node?.checked_at ? `Last tested ${new Date(node.checked_at).toLocaleString()}` : "";
const monitoringLabel = (node: SelectorNode) => node.tracking ? "Monitoring" : "On demand";
const nodeCount = (count: number) => `${count} node${count === 1 ? "" : "s"}`;

function Health({ node }: { node?: SelectorNode }) {
  const state = healthState(node);
  return <><Badge className="node-health" variant={state === "unavailable" ? "error" : "neutral"} label={healthLabels[state]} />
    <span className="node-latency">{latencyLabel(node)}</span></>;
}

// Popover geometry follows the visible viewport, including a mobile keyboard.
function positionPopover(menu: HTMLDivElement) {
  const rect = menu.parentElement!.getBoundingClientRect();
  const viewport = window.visualViewport;
  const left = viewport?.offsetLeft ?? 0, top = viewport?.offsetTop ?? 0;
  const width = viewport?.width ?? window.innerWidth, height = viewport?.height ?? window.innerHeight;
  const above = Math.max(0, Math.min(rect.top - top - 18, height - 24));
  const below = Math.max(0, Math.min(top + height - rect.bottom - 18, height - 24));
  const down = below >= Math.min(360, above);
  const menuWidth = Math.min(rect.width, width - 24);
  const available = Math.max(above, below) < 160 ? height - 24 : down ? below : above;
  menu.style.width = `${menuWidth}px`;
  menu.style.maxHeight = `${available}px`;
  menu.style.left = `${Math.max(left + 12, Math.min(rect.left, left + width - menuWidth - 12))}px`;
  const menuHeight = menu.getBoundingClientRect().height;
  const desiredTop = down ? rect.bottom + 6 : rect.top - menuHeight - 6;
  menu.style.top = `${Math.max(top + 12, Math.min(desiredTop, top + height - menuHeight - 12))}px`;
}

function Selector({ selector, actions, compact = false }: { selector: SelectorState; actions: SelectorControls; compact?: boolean }) {
  const id = useId();
  const picker = useRef<HTMLButtonElement>(null), menu = useRef<HTMLDivElement>(null), search = useRef<HTMLInputElement>(null), list = useRef<HTMLDivElement>(null);
  const focused = useRef<HTMLElement | null>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const filter = query.trim().toLocaleLowerCase();
  const visible = open ? selector.nodes.filter(node => node.name.toLocaleLowerCase().includes(filter)) : [];
  const selected = selector.nodes.find(node => node.id === selector.node_id);
  const Heading = compact ? "h4" : "h3";
  const name = selected?.name || "Select a node";
  const saved = selector.saved_selection;
  const fallback = saved && saved.status !== "matched";
  const isOpen = () => menu.current?.matches(":popover-open");

  useLayoutEffect(() => {
    if (!isOpen()) return;
    positionPopover(menu.current!);
    if (focused.current && document.activeElement === document.body &&
      (!focused.current.isConnected || focused.current.matches(":disabled") || !focused.current.checkVisibility())) {
      search.current!.focus({ preventScroll: true });
    }
  }, [selector, open, query]);

  useEffect(() => {
    if (!open) return;
    const reposition = (event: Event) => {
      if (isOpen() && !(event?.type === "scroll" && event.target instanceof Node && menu.current!.contains(event.target))) positionPopover(menu.current!);
    };
    window.addEventListener("resize", reposition);
    window.visualViewport?.addEventListener("resize", reposition);
    window.visualViewport?.addEventListener("scroll", reposition);
    document.addEventListener("scroll", reposition, true);
    return () => {
      window.removeEventListener("resize", reposition);
      window.visualViewport?.removeEventListener("resize", reposition);
      window.visualViewport?.removeEventListener("scroll", reposition);
      document.removeEventListener("scroll", reposition, true);
    };
  }, [open]);

  async function save(method: "PUT" | "DELETE", body: { node_id: string } | undefined, success: string) {
    const saved = await actions.run(async () => {
      actions.update(await actions.request<SelectorState>(`/api/selectors/${encodeURIComponent(selector.name)}`, method, body));
      if (isOpen()) menu.current!.hidePopover();
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
      const target = isOpen() ? candidate?.querySelector<HTMLButtonElement>(".select-node") ?? search.current : picker.current;
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

  return <section className={`selector-row${selector.track_all ? " tracking-all" : ""}${compact ? " selector-compact" : ""}`} data-group={selector.name} aria-labelledby={id}>
    <div className="selector-heading">
      <div className="selector-identity">
        <Heading id={id} className="selector-name">{selector.name}</Heading>
        <div className="selected-status status-row"><Health node={selected} /></div>
      </div>
      <div className="selector-meta status-row">
        <span className="node-count count">{nodeCount(selector.nodes.length)}</span>
        {fallback ? <span className="selection-source selection-warning inline-notice" data-tone="warning" title={`Saved: ${saved.name}`}><Icon icon="warning" size="sm" /><span>Saved choice {saved.status} · Temporary fallback</span></span>
          : <Badge className="selection-source" hidden={!selector.default_node_id && !saved} title={saved ? `Saved: ${saved.name}` : ""} label={selector.overridden ? "Custom" : "Default"} />}
      </div>
    </div>
    <div className="selector-control">
      <Button label={name} ref={picker} className="node-picker" type="button" aria-haspopup="dialog" aria-expanded={open}
        aria-controls={`${id}-nodes`} popoverTarget={`${id}-nodes`} isDisabled={!selector.nodes.length} title={name} aria-label={`${selector.name}: ${name}`}>
        <span className="selected-name">{name}</span><span className="picker-arrow" aria-hidden="true" />
      </Button>
      <Button label="Test selected" className="test-selected" type="button" hidden={compact || selector.track_all} isDisabled={!selected || selected.checking}
        aria-label={`Test selected node in ${selector.name}`} onClick={() => probe(selector.node_id)} />
      <div ref={menu} id={`${id}-nodes`} className="node-popover" popover="auto" role="dialog" aria-label={`Select a node in ${selector.name}`}
        onBeforeToggle={(event) => {
          if (event.newState === "open") {
            // Native popover opening needs the candidates committed for sizing.
            flushSync(() => { setQuery(""); setOpen(true); });
          } else setOpen(false);
        }}
        onToggle={() => {
          if (!isOpen()) return;
          positionPopover(menu.current!);
          search.current!.focus({ preventScroll: true });
          const row = [...list.current!.querySelectorAll<HTMLElement>(":scope > .selector-node")].find(node => node.dataset.node === selector.node_id);
          if (row) row.scrollIntoView({ block: "nearest" });
          else list.current!.scrollTop = 0;
        }} onKeyDown={navigate} onFocusCapture={(event) => { focused.current = event.target instanceof HTMLElement ? event.target : null; }}>
        <TextInput ref={search} className="node-search" label={`Search nodes in ${selector.name}`} isLabelHidden startIcon="search" hasClear
          role="searchbox" placeholder="Search nodes…" autoComplete="off" spellCheck={false} width="100%"
          value={query} onChange={(value) => { setQuery(value); list.current!.scrollTop = 0; }} />
        <p className="node-results" role="status">{filter ? `${visible.length} of ${selector.nodes.length} nodes` : nodeCount(visible.length)}</p>
        <div ref={list} className="node-list">{open && selector.nodes.map(node => <NodeOption key={node.id} node={node} selector={selector}
          hidden={!node.name.toLocaleLowerCase().includes(filter)} onProbe={() => probe(node.id)} onSelect={() => {
            if (node.id === selector.node_id && selector.saved_selection?.status === "matched") {
              menu.current!.hidePopover(); picker.current!.focus();
            } else save("PUT", { node_id: node.id }, `${selector.name}: selection saved.`);
          }} />)}</div>
        <p className="no-nodes muted" hidden={visible.length !== 0}>No matching nodes.</p>
      </div>
    </div>
    {!compact && selected && (!selector.track_all || selected.checked_at) && <div className="selector-monitoring status-row">
      <Badge className="node-monitoring" hidden={selector.track_all} label={monitoringLabel(selected)} />
      <span className="node-checked">{checkedLabel(selected)}</span>
    </div>}
    {!compact && <div className="selector-actions">
      <span className="tracking-status muted" title="All nodes are monitored automatically" hidden={!selector.track_all}>Monitoring all nodes</span>
      <div className="selector-buttons button-row" hidden={selector.track_all && !selector.default_node_id}>
        <Button label="Test All" className="test-all" type="button" hidden={selector.track_all} isDisabled={!selector.nodes.length || selector.nodes.every(node => node.checking)}
          aria-label={`Test all nodes in ${selector.name}`} onClick={() => probe()} />
        <Button label="Use default" className="reset" type="button" hidden={!selector.default_node_id} isDisabled={!selector.overridden}
          onClick={() => save("DELETE", undefined, `${selector.name}: reset to default.`)} />
      </div>
    </div>}
  </section>;
}

function NodeOption({ node, selector, hidden, onProbe, onSelect }: { node: SelectorNode; selector: SelectorState; hidden: boolean; onProbe: () => void; onSelect: () => void }) {
  const selected = node.id === selector.node_id;
  return <div className="selector-node" data-node={node.id} hidden={hidden}>
    <Button label={node.name} variant="ghost" className="select-node" type="button" aria-pressed={selected} onClick={onSelect}
      title={`${node.name}${node.id === selector.default_node_id ? " · Default" : ""}\n${monitoringLabel(node)}${node.checked_at ? ` · ${checkedLabel(node)}` : ""}`}
      aria-label={`${selected ? "Selected" : "Select"} ${node.name}, ${healthLabels[healthState(node)]} ${latencyLabel(node)}`.trim()}>
      <span className="node-name">{node.name}</span><span className="node-check" aria-hidden="true">{selected ? "✓" : ""}</span>
      <span className="node-status status-row"><Health node={node} /></span>
    </Button>
    <Button label="Test" className="test-node" type="button" hidden={selector.track_all} isDisabled={node.checking} aria-label={`Test ${node.name}`} onClick={onProbe} />
  </div>;
}

export function createSelectors(overviewContainer: HTMLElement, settingContainer: HTMLElement, actions: SelectorActions) {
  const renderOverview = createView(overviewContainer), renderSetting = createView(settingContainer);
  let selectors: SelectorState[] | null = null, message: string | null = null;
  let view: "overview" | "selector" | null = "overview";
  const controls = { ...actions, update: (updated: SelectorState) => show((selectors || []).map(selector => selector.name === updated.name ? updated : selector)) };
  function render() {
    const content = selectors ? selectors.length
      ? selectors.map(selector => <Selector key={selector.name} selector={selector} actions={controls} compact={view === "overview"} />)
      : <EmptyState isCompact title="No outbound groups" />
      : message && <Banner status="error" title={message} />;
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
