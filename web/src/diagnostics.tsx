import type { FormEvent } from "react";
import type { ClientSetState, DeviceContext, DiagnosticFlow, DiagnosticKind, ExplainRequest, ExplainResponse } from "./types.ts";
import { formControl, formValue } from "./dom.ts";
interface Comparison { sets: Record<string, boolean>; label: string }
interface ExplanationView { response: ExplainResponse; kind?: DiagnosticKind; target: string }
import { Button } from "@astryxdesign/core/Button";
import { Banner } from "@astryxdesign/core/Banner";
import { Field } from "@astryxdesign/core/Field";
import { createRef, useImperativeHandle, useLayoutEffect, useRef, useState, type Ref } from "react";
import { flushSync } from "react-dom";
import { request } from "./api.ts";
import { createView } from "./react-view.ts";
import { useRequest } from "./use-request.ts";
import { Explanation } from "./trace.tsx";
import { Disclosure } from "./disclosure.tsx";

const fields = {
  flow: ["Destination", "https://example.com or 203.0.113.10:443"],
  dns: ["DNS name", "example.com"],
  domain: ["Domain", "example.com"],
  outbound: ["Outbound group", "proxy"],
  plugins: ["Request URL", "https://example.com/path"],
};

function parseTarget(value: string): DiagnosticFlow {
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

interface DiagnosticActions { invalidate: () => void }

function Diagnostics({ allowed, comparisonRequest, deviceKey, ref }: { allowed: boolean; comparisonRequest: Comparison | null; deviceKey: string; ref: Ref<DiagnosticActions> }) {
  const [kind, setKind] = useState<DiagnosticKind>("flow");
  const [scope, setScope] = useState<"self" | "manual">("self");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const target = useRef<HTMLInputElement>(null), formRef = useRef<HTMLFormElement>(null), cachedIP = useRef<string | null>(null);
  const explanation = useRequest<ExplanationView>(), context = useRequest<DeviceContext>();
  const flow = kind === "flow" || kind === "plugins", dns = kind === "dns";
  const [label, placeholder] = fields[kind];

  useImperativeHandle(ref, () => ({ invalidate() {
    explanation.reset(); context.reset(); setComparison(null);
  } }), [explanation.reset, context.reset]);

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
    target.current!.closest("section")!.scrollIntoView({ block: "start" });
    target.current!.focus({ preventScroll: true });
  }, [comparisonRequest, explanation.reset]);

  async function showContext() {
    const operation = context.start();
    try { operation.resolve(await request<DeviceContext>("/api/device/context")); }
    catch (error) { operation.reject(error); }
  }

  function editField(name: string) {
    const input = formControl(formRef.current!, name);
    if (input.closest(".diagnostic-advanced")) flushSync(() => setAdvancedOpen(true));
    input.focus();
    input.scrollIntoView({ block: "center" });
  }

  function useIP(ip: string) {
    formControl(formRef.current!, "ip").value = ip;
    cachedIP.current = ip;
    formRef.current!.requestSubmit();
  }

  function changeInput(event: FormEvent<HTMLFormElement>) {
    if (!(event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement || event.target instanceof HTMLTextAreaElement)) return;
    if (event.target.name === "target" && cachedIP.current) {
      if (formControl(formRef.current!, "ip").value === cachedIP.current) formControl(formRef.current!, "ip").value = "";
      cachedIP.current = null;
    }
    if (event.target.name === "ip") cachedIP.current = null;
    explanation.reset();
  }

  async function explain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const operation = explanation.start();
    try {
      if (scope === "manual" && !allowed) throw new Error("Administrator access is required for manual identity.");
      const value = formValue(form, "target").trim();
      const payload: ExplainRequest = { kind, context: {}, flow: { destination: {}, protocol: dns || formValue(form, "protocol") === "udp" ? "udp" : "tcp" }, detail: "predicates" };
      if (kind === "outbound") payload.outbound = value;
      else if (dns) payload.dns = { name: value, type: formValue(form, "qtype") };
      else if (kind === "domain") payload.flow.destination.domain = value;
      else Object.assign(payload.flow, parseTarget(value));
      const ip = formValue(form, "ip").trim(), sni = formValue(form, "sni").trim();
      if (ip && !dns && kind !== "outbound") payload.flow.destination.ip = ip;
      if (sni && flow) payload.flow.sni = sni;
      const overrides: unknown = JSON.parse(formValue(form, "overrides") || "{}");
      if (typeof overrides !== "object" || overrides === null || Array.isArray(overrides)) throw new Error("Advanced request must be a JSON object.");
      Object.assign(payload, overrides);
      if (comparison) payload.compare = { ...payload.compare, client_sets: { ...payload.compare?.client_sets, ...comparison.sets } };
      const response = await request<ExplainResponse>(scope === "self" ? "/api/device/diagnostics/explain" : "/api/diagnostics/explain", "POST", payload);
      operation.resolve({ response, kind: payload.kind, target: value });
    } catch (error) { operation.reject(error); }
  }

  return <>
    <form id="diagnostic-form" ref={formRef} onSubmit={explain} onInput={changeInput}>
      <div className="diagnostic-mode">
        <Field label="What to check" inputID="diagnostic-kind"><select id="diagnostic-kind" value={kind} onChange={(event) => { if (Object.hasOwn(fields, event.target.value)) setKind(event.target.value as DiagnosticKind); explanation.reset(); }}>
          <option value="flow">Connection routing</option><option value="dns">DNS policy</option><option value="domain">Cached domain records</option><option value="outbound">Outbound nodes</option><option value="plugins">HTTP plugins</option>
        </select></Field>
      </div>
      <div className={`diagnostic-target-row${!flow && !dns ? " single-field" : ""}`}>
        <Field label={label} labelID="diagnostic-target-label" inputID="diagnostic-target"><input ref={target} id="diagnostic-target" name="target" placeholder={placeholder} aria-describedby="diagnostic-target-hint" autoCapitalize="none" spellCheck={false} required /></Field>
        <Field id="diagnostic-protocol-field" hidden={!flow} label="Transport" inputID="diagnostic-protocol"><select id="diagnostic-protocol" name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></Field>
        <Field id="diagnostic-qtype-field" hidden={!dns} label="Question type" inputID="diagnostic-qtype"><select id="diagnostic-qtype" name="qtype"><option>A</option><option>AAAA</option><option>CNAME</option><option>HTTPS</option><option>TXT</option></select></Field>
      </div>
      <p id="diagnostic-target-hint" className="field-hint">{kind === "flow" ? "Enter an IP:port, hostname:port or URL. For a hostname, supply the destination IP below to check its kernel route; this check does not resolve DNS." : kind === "dns" ? "Evaluates DNS policy without sending a DNS query." : kind === "plugins" ? "Checks plugin rules without fetching the URL or running scripts." : kind === "domain" ? "Reads existing records without refreshing DNS." : "Reads the current node selection and health without probing nodes."}</p>
      <div className="diagnostic-fields diagnostic-address" id="diagnostic-flow-fields" hidden={dns || kind === "outbound"}>
        <Field id="diagnostic-ip-field" label="Destination IP" inputID="diagnostic-ip" descriptionID="diagnostic-ip-hint"
          description={kind === "flow" ? "Needed to check routing for a hostname" : "Optional · filter by IP"}>
          <input id="diagnostic-ip" name="ip" placeholder="203.0.113.10" autoCapitalize="none" spellCheck={false} aria-describedby="diagnostic-ip-hint" />
        </Field>
      </div>
      <Disclosure className="diagnostic-advanced" title="Advanced context" meta="Optional" isOpen={advancedOpen} onOpenChange={setAdvancedOpen}>
        <Field className="diagnostic-identity" id="diagnostic-sni-field" hidden={!flow} label="TLS hostname (SNI)" inputID="diagnostic-sni"
          description="Optional · override the hostname supplied by the URL" descriptionID="diagnostic-sni-hint">
          <input id="diagnostic-sni" name="sni" placeholder="example.com" autoCapitalize="none" spellCheck={false} aria-describedby="diagnostic-sni-hint" />
        </Field>
        <Field className="diagnostic-identity" label="Test as" inputID="diagnostic-scope"><select id="diagnostic-scope" value={scope} onChange={(event) => { setScope(event.target.value === "manual" ? "manual" : "self"); explanation.reset(); }}>
          <option value="self">This device</option><option id="diagnostic-manual" value="manual" disabled={!allowed}>Custom identity (administrator)</option>
        </select></Field>
        <p className="muted">{'JSON fields override the request. For example: {"context":{"source_port":40000,"dscp":0}}. Manual identity also accepts source_ip, mac, interface, origin and policy. Omitted fields remain unknown.'}</p>
        <Field label="Advanced diagnostic request JSON" inputID="diagnostic-overrides">
          <textarea id="diagnostic-overrides" name="overrides" rows={6} spellCheck={false} defaultValue="{}" />
        </Field>
        <Button label="Show inherited context" id="diagnostic-context" type="button" onClick={showContext} isDisabled={context.pending} />
        <pre id="diagnostic-context-view" className="code-block">{context.pending ? "Loading context…" : context.error || context.value?.fields.map(field => `${field.name}: ${field.value} [${field.source}]`).join("\n")}</pre>
      </Disclosure>
      <div className="diagnostic-actions">
        <div className="diagnostic-comparison"><span id="diagnostic-comparison" className="muted">{comparison?.label || "Current settings"}</span>
          <span className="field-hint">· {scope === "self" ? "This device" : "Custom identity"}</span>
          <Button label="Clear comparison" id="diagnostic-clear-comparison" type="button" hidden={!comparison} onClick={() => { setComparison(null); explanation.reset(); }} />
        </div>
        <Button label={explanation.pending ? "Checking…" : "Run check"} variant="primary" id="diagnostic-run" type="submit" isDisabled={explanation.pending} />
      </div>
    </form>
    <div id="diagnostic-result" aria-live="polite" aria-busy={explanation.pending}>
      {explanation.pending && <p className="diagnostic-progress">Checking the current rules…</p>}
      {explanation.error && <Banner status="error" title="Could not complete the check" description={explanation.error} />}
      {explanation.value && <Explanation {...explanation.value} onEdit={editField} onUseIP={useIP} />}
    </div>
  </>;
}

export function createDiagnostics(container: HTMLElement) {
  const render = createView(container);
  const actions = createRef<DiagnosticActions>();
  let allowed = false, deviceKey = "";
  let generation = 0;
  let comparisonRequest: Comparison | null = null;
  const update = () => render(<Diagnostics ref={actions} allowed={allowed} comparisonRequest={comparisonRequest} deviceKey={JSON.stringify([generation, deviceKey])} />);
  update();
  return {
    setAccess: (next: boolean) => { if (allowed !== next) { allowed = next; update(); } },
    setDevice: (next: string) => { if (deviceKey !== next) { deviceKey = next; update(); } },
    setGeneration: (next: number) => { if (generation !== next) { generation = next; update(); } },
    invalidate: () => actions.current?.invalidate(),
    compare: (set: ClientSetState) => {
      comparisonRequest = { sets: { [set.name]: !set.joined }, label: `${set.joined ? "Leave" : "Join"} ${set.description || set.name}` };
      update();
    },
  };
}
