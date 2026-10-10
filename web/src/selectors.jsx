import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { createView } from "./react-view.js";

const healthLabels = { empty: "No selected node", checking: "Testing…", unknown: "Not tested", healthy: "Available", unavailable: "Unavailable" };
function healthState(node) {
  if (!node) return "empty";
  if (node.checking) return "checking";
  if (!node.tested) return "unknown";
  return node.healthy ? "healthy" : "unavailable";
}
const latencyLabel = (node) => Number.isFinite(node?.latency_ms) ? `${Math.round(node.latency_ms)} ms` : "";
const checkedLabel = (node) => node?.checked_at ? `Last tested ${new Date(node.checked_at).toLocaleString()}` : "";
const monitoringLabel = (node) => node.tracking ? "Monitoring" : "On demand";
const nodeCount = (count) => `${count} node${count === 1 ? "" : "s"}`;

function Health({ node }) {
  const state = healthState(node);
  return <><span className="node-health badge" data-tone={state === "unavailable" ? "error" : "neutral"}>{healthLabels[state]}</span>
    <span className="node-latency">{latencyLabel(node)}</span></>;
}

// Popover geometry follows the visible viewport, including a mobile keyboard.
function positionPopover(menu) {
  const rect = menu.parentElement.getBoundingClientRect();
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

function Selector({ selector, actions }) {
  const id = useId();
  const picker = useRef(null), menu = useRef(null), search = useRef(null), list = useRef(null);
  const focused = useRef(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const filter = query.trim().toLocaleLowerCase();
  const visible = open ? selector.nodes.filter(node => node.name.toLocaleLowerCase().includes(filter)) : [];
  const selected = selector.nodes.find(node => node.id === selector.node_id);
  const name = selected?.name || "Select a node";
  const saved = selector.saved_selection;
  const fallback = saved && saved.status !== "matched";
  const isOpen = () => menu.current?.matches(":popover-open");

  useLayoutEffect(() => {
    if (!isOpen()) return;
    positionPopover(menu.current);
    if (focused.current && document.activeElement === document.body &&
      (!focused.current.isConnected || focused.current.matches(":disabled") || !focused.current.checkVisibility())) {
      search.current.focus({ preventScroll: true });
    }
  }, [selector, open, query]);

  useEffect(() => {
    if (!open) return;
    const reposition = (event) => {
      if (isOpen() && !(event?.type === "scroll" && event.target instanceof Node && menu.current.contains(event.target))) positionPopover(menu.current);
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

  async function save(method, body, success) {
    const saved = await actions.run(async () => {
      actions.update(await actions.request(`/api/selectors/${encodeURIComponent(selector.name)}`, method, body));
      if (isOpen()) menu.current.hidePopover();
    }, success);
    if (saved) picker.current?.focus();
  }

  async function probe(nodeID) {
    const queued = await actions.run(async () => {
      await actions.request("/api/probes", "POST", { outbound: selector.name, node_id: nodeID });
      await actions.refresh();
    }, `${selector.name}: tests queued. Results update automatically.`, "Queuing connectivity tests…");
    if (queued) {
      const candidate = [...(list.current?.children || [])].find(node => node.dataset.node === nodeID);
      const target = isOpen() ? candidate?.querySelector(".select-node") ?? search.current : picker.current;
      target?.focus({ preventScroll: true });
    }
  }

  function navigate(event) {
    const fromSearch = event.target === search.current;
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    if (fromSearch && (event.key === "Home" || event.key === "End")) return;
    const rows = [...list.current.querySelectorAll(".selector-node:not([hidden])")];
    if (!rows.length) return;
    const index = rows.indexOf(event.target.closest(".selector-node"));
    let next = index + (event.key === "ArrowDown" ? 1 : -1);
    if (event.key === "Home") next = 0;
    if (event.key === "End" || (fromSearch && event.key === "ArrowUp")) next = rows.length - 1;
    event.preventDefault();
    rows[Math.max(0, Math.min(rows.length - 1, next))].querySelector(".select-node").focus();
  }

  return <section className={`selector-row${selector.track_all ? " tracking-all" : ""}`} data-group={selector.name} aria-labelledby={id}>
    <div className="selector-heading">
      <h3 id={id} className="selector-name">{selector.name}</h3>
      <span className="node-count count">{nodeCount(selector.nodes.length)}</span>
      <span className="selection-source badge" hidden={!selector.default_node_id && !saved} title={saved ? `Saved: ${saved.name}` : ""}>
        {fallback ? `Saved choice ${saved.status} · Temporary fallback` : selector.overridden ? "Custom" : "Default"}
      </span>
    </div>
    <div className="selector-control">
      <button ref={picker} className="node-picker" type="button" aria-haspopup="dialog" aria-expanded={open}
        aria-controls={`${id}-nodes`} popoverTarget={`${id}-nodes`} disabled={!selector.nodes.length} title={name} aria-label={`${selector.name}: ${name}`}>
        <span className="selected-name">{name}</span><span className="picker-arrow" aria-hidden="true" />
      </button>
      <button className="test-selected" type="button" hidden={selector.track_all} disabled={!selected || selected.checking}
        aria-label={`Test selected node in ${selector.name}`} onClick={() => probe(selector.node_id)}>Test</button>
      <div ref={menu} id={`${id}-nodes`} className="node-popover" popover="auto" role="dialog" aria-label={`Select a node in ${selector.name}`}
        onBeforeToggle={(event) => {
          if (event.newState === "open") {
            // Native popover opening needs the candidates committed for sizing.
            flushSync(() => { setQuery(""); setOpen(true); });
          } else setOpen(false);
        }}
        onToggle={() => {
          if (!isOpen()) return;
          positionPopover(menu.current);
          search.current.focus({ preventScroll: true });
          const row = [...list.current.children].find(node => node.dataset.node === selector.node_id);
          if (row) row.scrollIntoView({ block: "nearest" });
          else list.current.scrollTop = 0;
        }} onKeyDown={navigate} onFocusCapture={(event) => { focused.current = event.target; }}>
        <input ref={search} className="node-search" type="search" placeholder="Search nodes…" autoComplete="off" spellCheck={false}
          aria-label={`Search nodes in ${selector.name}`} value={query} onInput={(event) => { setQuery(event.currentTarget.value); list.current.scrollTop = 0; }} />
        <p className="node-results" role="status">{filter ? `${visible.length} of ${selector.nodes.length} nodes` : nodeCount(visible.length)}</p>
        <div ref={list} className="node-list">{open && selector.nodes.map(node => <NodeOption key={node.id} node={node} selector={selector}
          hidden={!node.name.toLocaleLowerCase().includes(filter)} onProbe={() => probe(node.id)} onSelect={() => {
            if (node.id === selector.node_id && selector.saved_selection?.status === "matched") {
              menu.current.hidePopover(); picker.current.focus();
            } else save("PUT", { node_id: node.id }, `${selector.name}: selection saved.`);
          }} />)}</div>
        <p className="no-nodes muted" hidden={visible.length !== 0}>No matching nodes.</p>
      </div>
    </div>
    <div className="selected-status status-row"><Health node={selected} />
      <span className="node-monitoring badge" hidden={!selected || selector.track_all}>{selected ? monitoringLabel(selected) : ""}</span>
      <span className="node-checked">{checkedLabel(selected)}</span>
    </div>
    <div className="selector-actions">
      <span className="tracking-status badge" title="All nodes are monitored automatically" hidden={!selector.track_all}>Monitoring all nodes</span>
      <div className="selector-buttons button-row" hidden={selector.track_all && !selector.default_node_id}>
        <button className="test-all" type="button" hidden={selector.track_all} disabled={!selector.nodes.length || selector.nodes.every(node => node.checking)}
          aria-label={`Test all nodes in ${selector.name}`} onClick={() => probe()}>Test All</button>
        <button className="reset" type="button" hidden={!selector.default_node_id} disabled={!selector.overridden}
          onClick={() => save("DELETE", undefined, `${selector.name}: reset to default.`)}>Use default</button>
      </div>
    </div>
  </section>;
}

function NodeOption({ node, selector, hidden, onProbe, onSelect }) {
  const selected = node.id === selector.node_id;
  return <div className="selector-node" data-node={node.id} hidden={hidden}>
    <button className="select-node" type="button" aria-pressed={selected} onClick={onSelect}
      title={`${node.name}${node.id === selector.default_node_id ? " · Default" : ""}\n${monitoringLabel(node)}${node.checked_at ? ` · ${checkedLabel(node)}` : ""}`}
      aria-label={`${selected ? "Selected" : "Select"} ${node.name}, ${healthLabels[healthState(node)]} ${latencyLabel(node)}`.trim()}>
      <span className="node-name">{node.name}</span><span className="node-check" aria-hidden="true">{selected ? "✓" : ""}</span>
      <span className="node-status status-row"><Health node={node} /></span>
    </button>
    <button className="test-node" type="button" hidden={selector.track_all} disabled={node.checking} aria-label={`Test ${node.name}`} onClick={onProbe}>Test</button>
  </div>;
}

export function createSelectors(container, actions) {
  const render = createView(container);
  let selectors = [];
  const controls = { ...actions, update: (updated) => show(selectors.map(selector => selector.name === updated.name ? updated : selector)) };
  function show(next) {
    selectors = next;
    render(next.length ? next.map(selector => <Selector key={selector.name} selector={selector} actions={controls} />) : <p className="muted">No outbound groups with node selection are configured.</p>);
  }
  return {
    show,
    clear: () => { selectors = []; render(null); },
    error: (text) => { selectors = []; render(<p className="muted">{text}</p>); },
  };
}
