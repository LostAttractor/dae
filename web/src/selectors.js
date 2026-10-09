import { template } from "./dom.js";

let sequence = 0;
const healthLabels = { empty: "No selected node", checking: "Testing…", unknown: "Not tested", healthy: "Available", unavailable: "Unavailable" };

function healthState(node) {
  if (!node) return "empty";
  if (node.checking) return "checking";
  if (!node.tested) return "unknown";
  return node.healthy ? "healthy" : "unavailable";
}

const latencyLabel = (node) => Number.isFinite(node?.latency_ms) ? `${Math.round(node.latency_ms)} ms` : "";

function renderHealth(element, node) {
  const state = healthState(node);
  const health = element.querySelector(".node-health");
  health.textContent = healthLabels[state];
  health.dataset.tone = state === "unavailable" ? "error" : "neutral";
  element.querySelector(".node-latency").textContent = latencyLabel(node);
}

function checkedLabel(node) {
  return node?.checked_at ? `Last tested ${new Date(node.checked_at).toLocaleString()}` : "";
}

const monitoringLabel = (node) => node.tracking ? "Monitoring" : "On demand";

// Fit the popup around its control, using the visible viewport when a mobile
// keyboard is open. The candidate list supplies its own bounded scroll area.
function positionPopover(menu) {
  const rect = menu.parentElement.getBoundingClientRect();
  const viewport = window.visualViewport;
  const left = viewport?.offsetLeft ?? 0;
  const top = viewport?.offsetTop ?? 0;
  const width = viewport?.width ?? window.innerWidth;
  const height = viewport?.height ?? window.innerHeight;
  const above = Math.max(0, Math.min(rect.top - top - 18, height - 24));
  const below = Math.max(0, Math.min(top + height - rect.bottom - 18, height - 24));
  const down = below >= Math.min(360, above);
  const menuWidth = Math.min(rect.width, width - 24);
  // If the control is offscreen or the keyboard leaves little room, use the
  // visible viewport instead of clipping the search field or the candidates.
  const available = Math.max(above, below) < 160 ? height - 24 : down ? below : above;
  menu.style.width = `${menuWidth}px`;
  menu.style.maxHeight = `${available}px`;
  menu.style.left = `${Math.max(left + 12, Math.min(rect.left, left + width - menuWidth - 12))}px`;
  const menuHeight = menu.getBoundingClientRect().height;
  const desiredTop = down ? rect.bottom + 6 : rect.top - menuHeight - 6;
  menu.style.top = `${Math.max(top + 12, Math.min(desiredTop, top + height - menuHeight - 12))}px`;
}

export function selectorRow(selector, { run, request, refresh }) {
  const row = template("selector-template");
  row.dataset.group = selector.name;
  const heading = row.querySelector(".selector-name");
  heading.textContent = selector.name;
  heading.id = `selector-${++sequence}`;
  row.setAttribute("aria-labelledby", heading.id);
  const picker = row.querySelector(".node-picker");
  const menu = row.querySelector(".node-popover");
  const list = row.querySelector(".node-list");
  const search = row.querySelector(".node-search");
  const results = row.querySelector(".node-results");
  const testSelected = row.querySelector(".test-selected");
  const testAll = row.querySelector(".test-all");
  const reset = row.querySelector(".reset");
  const nodes = new Map();
  const isOpen = () => menu.matches(":popover-open");
  menu.id = `${heading.id}-nodes`;
  menu.setAttribute("aria-label", `Select a node in ${selector.name}`);
  picker.setAttribute("popovertarget", menu.id);
  picker.setAttribute("aria-controls", menu.id);
  search.setAttribute("aria-label", `Search nodes in ${selector.name}`);

  async function save(method, body, success) {
    const saved = await run(async () => {
      row.update(await request(`/api/selectors/${encodeURIComponent(selector.name)}`, method, body));
      if (isOpen()) menu.hidePopover();
    }, success);
    if (saved) picker.focus();
  }

  async function probe(nodeID) {
    const queued = await run(async () => {
      await request("/api/probes", "POST", { outbound: selector.name, node_id: nodeID });
      await refresh();
    }, `${selector.name}: tests queued. Results update automatically.`, "Queuing connectivity tests…");
    if (queued) {
      const target = isOpen() ? nodes.get(nodeID)?.querySelector(".select-node") ?? search : picker;
      target.focus({ preventScroll: true });
    }
  }

  reset.onclick = () => save("DELETE", undefined, `${selector.name}: reset to default.`);
  testSelected.onclick = () => probe(selector.node_id);
  testSelected.setAttribute("aria-label", `Test selected node in ${selector.name}`);
  testAll.onclick = () => probe();
  testAll.setAttribute("aria-label", `Test all nodes in ${selector.name}`);

  function filter() {
    const query = search.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const node of selector.nodes) {
      const element = nodes.get(node.id);
      element.hidden = !node.name.toLocaleLowerCase().includes(query);
      if (!element.hidden) visible++;
    }
    row.querySelector(".no-nodes").hidden = visible !== 0;
    const summary = query ? `${visible} of ${selector.nodes.length} nodes` : `${visible} node${visible === 1 ? "" : "s"}`;
    // The live region should announce search results, not repeat them on every poll.
    if (results.textContent !== summary) results.textContent = summary;
  }
  search.oninput = () => { filter(); list.scrollTop = 0; };

  function renderNodes() {
    const focused = list.contains(document.activeElement) ? document.activeElement : null;
    const present = new Set(selector.nodes.map((node) => node.id));
    for (const [id, element] of nodes) {
      if (!present.has(id)) { element.remove(); nodes.delete(id); }
    }
    let index = 0;
    for (const node of selector.nodes) {
      let element = nodes.get(node.id);
      if (!element) {
        element = template("selector-node-template");
        element.querySelector(".test-node").onclick = () => probe(node.id);
        element.querySelector(".select-node").onclick = () => {
          if (node.id === selector.node_id && selector.saved_selection?.status === "matched") {
            menu.hidePopover();
            picker.focus();
          } else {
            save("PUT", { node_id: node.id }, `${selector.name}: selection saved.`);
          }
        };
        nodes.set(node.id, element);
      }
      const selected = node.id === selector.node_id;
      element.querySelector(".node-name").textContent = node.name;
      element.querySelector(".node-check").textContent = selected ? "✓" : "";
      renderHealth(element, node);
      const test = element.querySelector(".test-node");
      test.disabled = node.checking;
      test.hidden = selector.track_all;
      test.setAttribute("aria-label", `Test ${node.name}`);
      const select = element.querySelector(".select-node");
      select.setAttribute("aria-pressed", String(selected));
      select.title = `${node.name}${node.id === selector.default_node_id ? " · Default" : ""}\n${monitoringLabel(node)}${node.checked_at ? ` · ${checkedLabel(node)}` : ""}`;
      select.setAttribute("aria-label", `${selected ? "Selected" : "Select"} ${node.name}, ${healthLabels[healthState(node)]} ${latencyLabel(node)}`.trim());
      // Update in place, but also follow configuration reordering. Unchanged
      // elements are never detached, preserving focus and search while polling.
      if (list.children[index] !== element) list.insertBefore(element, list.children[index] ?? null);
      index++;
    }
    filter();
    if (focused && document.activeElement !== focused) {
      const target = focused.isConnected && !focused.disabled && focused.checkVisibility() ? focused : search;
      target.focus({ preventScroll: true });
    }
  }

  menu.addEventListener("beforetoggle", (event) => {
    picker.setAttribute("aria-expanded", String(event.newState === "open"));
    if (event.newState === "open") {
      search.value = "";
      renderNodes();
    }
  });
  menu.addEventListener("toggle", () => {
    if (isOpen()) {
      positionPopover(menu);
      const selected = nodes.get(selector.node_id);
      if (selected) selected.scrollIntoView({ block: "nearest" });
      else list.scrollTop = 0;
    } else {
      // Closed selectors do not retain thousands of hidden candidate controls.
      list.replaceChildren();
      nodes.clear();
    }
  });
  menu.onkeydown = (event) => {
    const fromSearch = event.target === search;
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    if (fromSearch && (event.key === "Home" || event.key === "End")) return;
    const visible = [...list.querySelectorAll(".selector-node:not([hidden])")];
    if (!visible.length) return;
    const index = visible.indexOf(event.target.closest(".selector-node"));
    let next = index + (event.key === "ArrowDown" ? 1 : -1);
    if (event.key === "Home") next = 0;
    if (event.key === "End" || (fromSearch && event.key === "ArrowUp")) next = visible.length - 1;
    next = Math.max(0, Math.min(visible.length - 1, next));
    event.preventDefault();
    visible[next].querySelector(".select-node").focus();
  };

  row.update = (updated) => {
    selector = updated;
    row.classList.toggle("tracking-all", selector.track_all);
    const source = row.querySelector(".selection-source");
    const saved = selector.saved_selection;
    const fallback = saved && saved.status !== "matched";
    source.hidden = !selector.default_node_id && !saved;
    source.textContent = fallback ? `Saved choice ${saved.status} · Temporary fallback` : selector.overridden ? "Custom" : "Default";
    source.title = saved ? `Saved: ${saved.name}` : "";
    row.querySelector(".node-count").textContent = `${selector.nodes.length} node${selector.nodes.length === 1 ? "" : "s"}`;
    const node = selector.nodes.find((candidate) => candidate.id === selector.node_id);
    const name = node ? node.name : "Select a node";
    row.querySelector(".selected-name").textContent = name;
    picker.title = name;
    picker.setAttribute("aria-label", `${selector.name}: ${name}`);
    picker.disabled = !selector.nodes.length;
    testSelected.disabled = !node || node.checking;
    testSelected.hidden = selector.track_all;
    const summary = row.querySelector(".selected-status");
    renderHealth(summary, node);
    const monitoring = summary.querySelector(".node-monitoring");
    monitoring.hidden = !node || selector.track_all;
    monitoring.textContent = node ? monitoringLabel(node) : "";
    summary.querySelector(".node-checked").textContent = checkedLabel(node);
    row.querySelector(".tracking-status").hidden = !selector.track_all;
    reset.hidden = !selector.default_node_id;
    row.querySelector(".selector-buttons").hidden = selector.track_all && !selector.default_node_id;
    reset.disabled = !selector.overridden;
    testAll.disabled = !selector.nodes.length || selector.nodes.every((candidate) => candidate.checking);
    testAll.hidden = selector.track_all;
    if (isOpen()) { renderNodes(); positionPopover(menu); }
  };
  row.update(selector);
  return row;
}

function repositionNodePickers() {
  for (const menu of document.querySelectorAll(".node-popover:popover-open")) positionPopover(menu);
}
window.addEventListener("resize", repositionNodePickers);
window.visualViewport?.addEventListener("resize", repositionNodePickers);
window.visualViewport?.addEventListener("scroll", repositionNodePickers);
document.addEventListener("scroll", (event) => {
  if (!(event.target instanceof Element) || !event.target.closest(".node-popover")) repositionNodePickers();
}, true);
