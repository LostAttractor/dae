import { useLayoutEffect, useRef, useState } from "react";
import { request } from "./api.js";
import { createView } from "./react-view.js";
import { useRequest } from "./use-request.js";
import { Explanation } from "./trace.jsx";
import { Disclosure } from "./disclosure.jsx";

const fields = {
  flow: ["Destination", "https://example.com or 203.0.113.10:443", "Where would this connection go?"],
  dns: ["DNS name", "example.com", "How would DNS plugins handle this question?"],
  domain: ["Domain", "example.com", "Which domain-to-IP records does dae already know?"],
  outbound: ["Outbound group", "proxy", "Which nodes are available in this outbound group?"],
  plugins: ["Request URL", "https://example.com/path", "Which HTTP plugins would handle this request?"],
};

function parseTarget(value) {
  if (/^https?:\/\//i.test(value)) {
    const url = new URL(value), host = url.hostname.replace(/^\[|\]$/g, "");
    const ip = host.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(host);
    return { destination: ip ? { ip: host } : {}, http: { url: value, method: "GET" } };
  }
  const matched = value.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
  if (!matched) throw new Error("Enter an IP:port, domain:port, or HTTP(S) URL.");
  const host = matched[1] || matched[2], port = Number(matched[3]);
  if (port < 1 || port > 65535) throw new Error("Port must be in 1..65535.");
  const address = host.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(host) ? { ip: host } : { domain: host };
  return { destination: { ...address, port } };
}

function Diagnostics({ allowed, comparisonRequest, deviceKey }) {
  const [kind, setKind] = useState("flow");
  const [scope, setScope] = useState("self");
  const [comparison, setComparison] = useState(null);
  const target = useRef(null), formRef = useRef(null), cachedIP = useRef(null);
  const explanation = useRequest(), context = useRequest();
  const flow = kind === "flow" || kind === "plugins", dns = kind === "dns";
  const [label, placeholder, question] = fields[kind];

  useLayoutEffect(() => {
    if (!allowed && scope === "manual") { setScope("self"); explanation.reset(); }
  }, [allowed, scope, explanation.reset]);

  useLayoutEffect(() => {
    explanation.reset(); context.reset(); setComparison(null);
  }, [deviceKey, explanation.reset, context.reset]);

  useLayoutEffect(() => {
    if (!comparisonRequest) return;
    setComparison(comparisonRequest);
    setKind("flow"); setScope("self"); explanation.reset();
    target.current.closest("section").scrollIntoView({ block: "start" });
    target.current.focus({ preventScroll: true });
  }, [comparisonRequest, explanation.reset]);

  async function showContext() {
    const operation = context.start();
    try { operation.resolve(await request("/api/device/context")); }
    catch (error) { operation.reject(error); }
  }

  function editField(name) {
    const input = formRef.current.elements[name];
    const details = input.closest("details");
    if (details) details.open = true;
    input.focus();
    input.scrollIntoView({ block: "center" });
  }

  function useIP(ip) {
    formRef.current.elements.ip.value = ip;
    cachedIP.current = ip;
    formRef.current.requestSubmit();
  }

  function changeInput(event) {
    if (event.target.name === "target" && cachedIP.current) {
      if (formRef.current.elements.ip.value === cachedIP.current) formRef.current.elements.ip.value = "";
      cachedIP.current = null;
    }
    if (event.target.name === "ip") cachedIP.current = null;
    explanation.reset();
  }

  async function explain(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const operation = explanation.start();
    try {
      if (scope === "manual" && !allowed) throw new Error("Administrator access is required for manual identity.");
      const value = form.get("target").trim();
      const payload = { kind, context: {}, flow: { destination: {}, protocol: dns ? "udp" : form.get("protocol") }, detail: "predicates" };
      if (kind === "outbound") payload.outbound = value;
      else if (dns) payload.dns = { name: value, type: form.get("qtype") };
      else if (kind === "domain") payload.flow.destination.domain = value;
      else Object.assign(payload.flow, parseTarget(value));
      const ip = form.get("ip").trim(), sni = form.get("sni").trim();
      if (ip && !dns && kind !== "outbound") payload.flow.destination.ip = ip;
      if (sni && flow) payload.flow.sni = sni;
      const overrides = JSON.parse(form.get("overrides") || "{}");
      if (typeof overrides !== "object" || overrides === null || Array.isArray(overrides)) throw new Error("Advanced request must be a JSON object.");
      Object.assign(payload, overrides);
      if (comparison) payload.compare = { ...payload.compare, client_sets: { ...payload.compare?.client_sets, ...comparison.sets } };
      const response = await request(scope === "self" ? "/api/device/diagnostics/explain" : "/api/diagnostics/explain", "POST", payload);
      operation.resolve({ response, kind: payload.kind, target: value });
    } catch (error) { operation.reject(error); }
  }

  return <>
    <form id="diagnostic-form" ref={formRef} onSubmit={explain} onInput={changeInput}>
      <div className="diagnostic-mode">
        <label>What to check<select id="diagnostic-kind" value={kind} onChange={(event) => { setKind(event.target.value); explanation.reset(); }}>
          <option value="flow">Connection routing</option><option value="dns">DNS policy</option><option value="domain">Cached domain records</option><option value="outbound">Outbound nodes</option><option value="plugins">HTTP plugins</option>
        </select></label>
        <p className="muted">{question}</p>
      </div>
      <div className={`diagnostic-target-row${!flow && !dns ? " single-field" : ""}`}>
        <label><span id="diagnostic-target-label">{label}</span><input ref={target} id="diagnostic-target" name="target" placeholder={placeholder} aria-describedby="diagnostic-target-hint" autoCapitalize="none" spellCheck={false} required /></label>
        <label id="diagnostic-protocol-field" hidden={!flow}>Transport<select id="diagnostic-protocol" name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
        <label id="diagnostic-qtype-field" hidden={!dns}>Question type<select id="diagnostic-qtype" name="qtype"><option>A</option><option>AAAA</option><option>CNAME</option><option>HTTPS</option><option>TXT</option></select></label>
      </div>
      <p id="diagnostic-target-hint" className="field-hint">{kind === "flow" ? "Enter an IP:port, hostname:port or URL. For a hostname, supply the destination IP below to check its kernel route; this check does not resolve DNS." : kind === "dns" ? "Evaluates DNS policy without sending a DNS query." : kind === "plugins" ? "Checks plugin rules without fetching the URL or running scripts." : kind === "domain" ? "Reads existing records without refreshing DNS." : "Reads the current node selection and health without probing nodes."}</p>
      <div className="diagnostic-fields diagnostic-address" id="diagnostic-flow-fields" hidden={dns || kind === "outbound"}>
        <label id="diagnostic-ip-field">Destination IP <span className="field-hint">{kind === "flow" ? "Needed to check routing for a hostname" : "Optional · filter by IP"}</span><input id="diagnostic-ip" name="ip" placeholder="203.0.113.10" autoCapitalize="none" spellCheck={false} /></label>
      </div>
      <Disclosure className="diagnostic-advanced" title="Advanced context" meta="Optional">
        <label className="diagnostic-identity" id="diagnostic-sni-field" hidden={!flow}>TLS hostname (SNI)<span className="field-hint">Optional · override the hostname supplied by the URL</span><input id="diagnostic-sni" name="sni" placeholder="example.com" autoCapitalize="none" spellCheck={false} /></label>
        <label className="diagnostic-identity">Test as<select id="diagnostic-scope" value={scope} onChange={(event) => { setScope(event.target.value); explanation.reset(); }}>
          <option value="self">This device</option><option id="diagnostic-manual" value="manual" disabled={!allowed}>Custom identity (administrator)</option>
        </select></label>
        <p className="muted">{'JSON fields override the request. For example: {"context":{"source_port":40000,"dscp":0}}. Manual identity also accepts source_ip, mac, interface, origin and policy. Omitted fields remain unknown.'}</p>
        <textarea id="diagnostic-overrides" name="overrides" rows="6" spellCheck={false} aria-label="Advanced diagnostic request JSON" defaultValue="{}" />
        <button id="diagnostic-context" type="button" onClick={showContext} disabled={context.pending}>Show inherited context</button>
        <pre id="diagnostic-context-view" className="code-block">{context.pending ? "Loading context…" : context.error || context.value?.fields.map(field => `${field.name}: ${field.value} [${field.source}]`).join("\n")}</pre>
      </Disclosure>
      <div className="diagnostic-actions">
        <div className="diagnostic-comparison"><span id="diagnostic-comparison" className="muted">{comparison?.label || "Current settings"}</span>
          <span className="field-hint">· {scope === "self" ? "This device" : "Custom identity"}</span>
          <button id="diagnostic-clear-comparison" type="button" hidden={!comparison} onClick={() => { setComparison(null); explanation.reset(); }}>Clear comparison</button>
        </div>
        <button id="diagnostic-run" type="submit" disabled={explanation.pending}>{explanation.pending ? "Checking…" : "Run check"}</button>
      </div>
    </form>
    <div id="diagnostic-result" aria-live="polite" aria-busy={explanation.pending}>
      {explanation.pending && <p className="diagnostic-progress">Checking the current rules…</p>}
      {explanation.error && <p className="notice">{explanation.error}</p>}
      {explanation.value && <Explanation {...explanation.value} onEdit={editField} onUseIP={useIP} />}
    </div>
  </>;
}

export function createDiagnostics(container) {
  const render = createView(container);
  let allowed = false, comparisonRequest = null, deviceKey = "";
  const update = () => render(<Diagnostics allowed={allowed} comparisonRequest={comparisonRequest} deviceKey={deviceKey} />);
  update();
  return {
    setAccess: (next) => { if (allowed !== next) { allowed = next; update(); } },
    setDevice: (next) => { if (deviceKey !== next) { deviceKey = next; update(); } },
    compare: (set) => {
      comparisonRequest = { sets: { [set.name]: !set.joined }, label: `${set.joined ? "Leave" : "Join"} ${set.description || set.name}` };
      update();
    },
  };
}
