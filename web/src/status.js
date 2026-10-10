import { byId } from "./dom.js";

export function bytes(value = 0) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toLocaleString(undefined, { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function groupEntry(name) {
  const entry = element("details", undefined, "status-entry");
  entry.dataset.name = name;
  const summary = element("summary");
  const count = element("span", undefined, "count");
  const metrics = element("span", undefined, "status-entry-metrics");
  summary.append(element("strong", name), count, metrics);
  const list = element("div", undefined, "status-nodes");
  entry.append(summary, list);
  let nodes = [];
  const renderNodes = () => {
    if (!entry.open) { list.replaceChildren(); return; }
    nodes.forEach((node, index) => {
      let line = list.children[index];
      if (!line) { line = element("p", undefined, "muted"); list.append(line); }
      const text = `${node.name} · ${node.checks_connectivity ? node.healthy ? "Healthy" : "Unavailable" : "Not monitored"} · ${node.stats.active_connections} active`;
      if (line.textContent !== text) line.textContent = text;
    });
    while (list.children.length > nodes.length) list.lastElementChild.remove();
  };
  entry.addEventListener("toggle", renderNodes);
  entry.update = (group) => {
    nodes = group.nodes;
    count.textContent = `${nodes.length} node${nodes.length === 1 ? "" : "s"}`;
    metrics.textContent = `${group.policy || group.target_kind} · ${group.connectivity || "No connectivity checks"} · ${group.stats.active_connections} active · ↑ ${bytes(group.stats.upload_bytes)} · ↓ ${bytes(group.stats.download_bytes)}`;
    renderNodes();
  };
  return entry;
}

function renderGroups(groups) {
  const list = byId("global-groups");
  const entries = new Map([...list.children].map((entry) => [entry.dataset.name, entry]));
  const focused = list.contains(document.activeElement) ? document.activeElement : null;
  groups.forEach((group, index) => {
    const entry = entries.get(group.name) || groupEntry(group.name);
    entries.delete(group.name);
    entry.update(group);
    if (list.children[index] !== entry) list.insertBefore(entry, list.children[index] ?? null);
  });
  for (const entry of entries.values()) entry.remove();
  if (focused?.isConnected && document.activeElement !== focused) focused.focus({ preventScroll: true });
}

function traffic(container, stats) {
  const history = stats.history || {};
  const metrics = element("dl", undefined, "traffic-metrics");
  for (const [label, value] of [
    ["Active connections", stats.active_connections], ["Total connections", stats.total_connections],
    ["Uploaded", bytes(stats.upload_bytes)], ["Downloaded", bytes(stats.download_bytes)],
    ["Upload rate", `${bytes(history.upload_bytes_per_second?.at(-1))}/s`],
    ["Download rate", `${bytes(history.download_bytes_per_second?.at(-1))}/s`],
  ]) {
    const metric = element("div");
    metric.append(element("dt", label), element("dd", value ?? 0));
    metrics.append(metric);
  }
  const chart = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  chart.setAttribute("viewBox", "0 0 300 64");
  chart.setAttribute("preserveAspectRatio", "none");
  chart.setAttribute("role", "img");
  chart.setAttribute("aria-label", "Recent upload and download rates, five-second samples, up to one minute");
  chart.classList.add("traffic-chart");
  const values = [history.upload_bytes_per_second || [], history.download_bytes_per_second || []];
  const max = Math.max(1, ...values.flat());
  values.forEach((samples, direction) => {
    const line = document.createElementNS(chart.namespaceURI, "polyline");
    line.setAttribute("points", samples.map((value, i) => `${(12 - samples.length + i) * 300 / 11},${60 - value / max * 56}`).join(" "));
    line.classList.add(direction ? "download-line" : "upload-line");
    chart.append(line);
  });
  byId(container).replaceChildren(metrics, chart, element("p", "Recent minute · Upload (dashed) / Download (solid) · 5-second samples", "muted chart-caption"));
}

export function renderDeviceStatus(snapshot) {
  traffic("device-traffic", snapshot.stats);
  byId("device-stats-note").textContent = `Userspace upstream traffic only · Since daemon start ${new Date(snapshot.started_at).toLocaleString()}. Kernel passthrough and local responses are excluded.`;
  byId("device-outbounds").replaceChildren(...snapshot.outbounds.map((outbound) => element("p",
    `${outbound.name} · ${outbound.stats.active_connections} active · ↑ ${bytes(outbound.stats.upload_bytes)} · ↓ ${bytes(outbound.stats.download_bytes)}`)));
  if (!snapshot.outbounds.length) byId("device-outbounds").append(element("p", "No attributed upstream connections yet.", "muted"));
  byId("device-status-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

export function clearGlobalStatus(text = "Login required to view global status.") {
  byId("global-status-locked").hidden = false;
  byId("global-status-locked").textContent = text;
  byId("global-status-content").hidden = true;
  for (const id of ["global-traffic", "global-groups", "global-tables", "global-plugins"]) byId(id).replaceChildren();
  byId("global-runtime").textContent = "";
}

export function renderGlobalStatus(snapshot) {
  byId("global-status-locked").hidden = true;
  byId("global-status-content").hidden = false;
  const uptime = Math.max(0, Math.floor((Date.now() - Date.parse(snapshot.started_at)) / 1000));
  byId("global-runtime").textContent = `${snapshot.version} · Uptime ${Math.floor(uptime / 86400)}d ${Math.floor(uptime / 3600) % 24}h ${Math.floor(uptime / 60) % 60}m · ${snapshot.direct_fallback_connections} direct fallback connections`;
  traffic("global-traffic", snapshot.stats);
  renderGroups(snapshot.groups);
  byId("global-tables").replaceChildren(...snapshot.tables.map((table) => element("p", `${table.name}: ${table.used.toLocaleString()} / ${table.limit ? table.limit.toLocaleString() : "unbounded"}`)));
  byId("global-plugins").replaceChildren(...(snapshot.plugins || []).map((plugin) => element("p", `${plugin.id} · ${plugin.type} · ${plugin.state}`)));
  byId("global-status-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
}
