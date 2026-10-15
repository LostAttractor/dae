import type { FormEvent } from "react";
import type { ClientSetState, DeviceContext, DiagnosticFlow, DiagnosticKind, ExplainRequest, ExplainResponse } from "./types.ts";
import { formControl, formValue } from "./dom.ts";
interface Comparison { sets: Record<string, boolean>; label: string }
interface ExplanationView { response: ExplainResponse; kind?: DiagnosticKind; target: string }
import { Button } from "@cloudflare/kumo/components/button";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Input, InputArea } from "@cloudflare/kumo/components/input";
import { Select } from "@cloudflare/kumo/components/select";
import { createRef, useImperativeHandle, useLayoutEffect, useRef, useState, type Ref } from "react";
import { flushSync } from "react-dom";
import { request } from "./api.ts";
import { createView } from "./react-view.ts";
import { useRequest } from "./use-request.ts";
import { Explanation } from "./trace.tsx";
import { Disclosure } from "./disclosure.tsx";
import { StatusBanner } from "./notice.tsx";
import { codeBlock } from "./ui.ts";

const kinds: Record<DiagnosticKind, string> = { flow: "Connection routing", dns: "DNS policy", domain: "Cached domain records", outbound: "Outbound nodes", plugins: "HTTP plugins" };
const hint = "text-sm text-kumo-subtle";
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

function Diagnostics({ comparisonRequest, deviceKey, ref }: { comparisonRequest: Comparison | null; deviceKey: string; ref: Ref<DiagnosticActions> }) {
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
      <div className="diagnostic-mode mb-4 max-w-sm">
        <Select label="What to check" className="w-full" value={kind} items={kinds} render={<button type="button" id="diagnostic-kind" />}
          onValueChange={(value) => { if (typeof value === "string" && Object.hasOwn(fields, value)) setKind(value as DiagnosticKind); explanation.reset(); }} />
      </div>
      <div className={`diagnostic-target-row mb-4 grid gap-3 sm:gap-4 ${!flow && !dns ? "grid-cols-1" : "sm:grid-cols-[minmax(0,1fr)_9rem]"}`}>
        <Input ref={target} id="diagnostic-target" name="target" label={label} placeholder={placeholder} aria-describedby="diagnostic-target-hint" autoCapitalize="none" spellCheck={false} required className="w-full" />
        <div id="diagnostic-protocol-field" hidden={!flow}>
          <Select label="Transport" name="protocol" className="w-full" defaultValue="tcp" items={{ tcp: "TCP", udp: "UDP" }} onValueChange={() => explanation.reset()} render={<button type="button" id="diagnostic-protocol" />} />
        </div>
        <div id="diagnostic-qtype-field" hidden={!dns}>
          <Select label="Question type" name="qtype" className="w-full" defaultValue="A" items={{ A: "A", AAAA: "AAAA", CNAME: "CNAME", HTTPS: "HTTPS", TXT: "TXT" }} onValueChange={() => explanation.reset()} render={<button type="button" id="diagnostic-qtype" />} />
        </div>
      </div>
      <p id="diagnostic-target-hint" className={`field-hint -mt-2 mb-4 ${hint}`}>{kind === "flow" ? "Enter an IP:port, hostname:port or URL. For a hostname, supply the destination IP below to check its kernel route; this check does not resolve DNS." : kind === "dns" ? "Evaluates DNS policy without sending a DNS query." : kind === "plugins" ? "Checks plugin rules without fetching the URL or running scripts." : kind === "domain" ? "Reads existing records without refreshing DNS." : "Reads the current node selection and health without probing nodes."}</p>
      <div className="diagnostic-fields diagnostic-address mb-4 max-w-xl" id="diagnostic-flow-fields" hidden={dns || kind === "outbound"}>
        <Input id="diagnostic-ip" name="ip" label="Destination IP" description={kind === "flow" ? "Needed to check routing for a hostname" : "Optional · filter by IP"}
          placeholder="203.0.113.10" autoCapitalize="none" spellCheck={false} className="w-full" />
      </div>
      <Disclosure className="diagnostic-advanced border-t border-kumo-hairline" title="Advanced context" meta="Optional" isOpen={advancedOpen} onOpenChange={setAdvancedOpen}>
        <div className="diagnostic-identity max-w-sm" id="diagnostic-sni-field" hidden={!flow}>
          <Input id="diagnostic-sni" name="sni" label="TLS hostname (SNI)" description="Optional · override the hostname supplied by the URL" placeholder="example.com" autoCapitalize="none" spellCheck={false} className="w-full" />
        </div>
        <div className="diagnostic-identity max-w-sm">
          <Select label="Test as" className="w-full" value={scope} render={<button type="button" id="diagnostic-scope" />}
            items={{ self: "This device", manual: "Custom identity" }}
            onValueChange={(value) => { setScope(value === "manual" ? "manual" : "self"); explanation.reset(); }} />
        </div>
        <p className={` ${hint}`}>{'JSON fields override the request. For example: {"context":{"source_port":40000,"dscp":0}}. Manual identity also accepts source_ip, mac, interface, origin and policy. Omitted fields remain unknown.'}</p>
        <InputArea id="diagnostic-overrides" name="overrides" label="Advanced diagnostic request JSON" rows={6} spellCheck={false} defaultValue="{}" className="w-full resize-y font-mono text-sm" />
        <Button id="diagnostic-context" type="button" onClick={showContext} disabled={context.pending}>Show inherited context</Button>
        <pre id="diagnostic-context-view" className={`${codeBlock} whitespace-pre-line empty:hidden`}>{context.pending ? "Loading context…" : context.error || context.value?.fields.map(field => `${field.name}: ${field.value} [${field.source}]`).join("\n")}</pre>
      </Disclosure>
      <div className="diagnostic-actions flex flex-wrap items-center justify-between gap-3 border-t border-kumo-hairline pt-4">
        <div className="diagnostic-comparison flex min-w-0 flex-wrap items-center gap-2"><span className={hint}><span id="diagnostic-comparison">{comparison?.label || "Current settings"}</span>
          {" "}· {scope === "self" ? "This device" : "Custom identity"}</span>
          <Button id="diagnostic-clear-comparison" type="button" hidden={!comparison} onClick={() => { setComparison(null); explanation.reset(); }}>Clear comparison</Button>
        </div>
        <Button variant="primary" id="diagnostic-run" type="submit" className="ml-auto min-w-32 justify-center" disabled={explanation.pending}>{explanation.pending ? "Checking…" : "Run check"}</Button>
      </div>
    </form>
    <div id="diagnostic-result" aria-live="polite" aria-busy={explanation.pending}>
      {explanation.pending && <p className="diagnostic-progress mt-5">Checking the current rules…</p>}
      {explanation.error && <StatusBanner tone="error" title="Could not complete the check" description={explanation.error} />}
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
  const update = () => render(allowed
    ? <Diagnostics ref={actions} comparisonRequest={comparisonRequest} deviceKey={JSON.stringify([generation, deviceKey])} />
    : <Banner className="my-3" role="status" title="Administrator access required" description="Log in to inspect routing rules, DNS records and outbound nodes." />);
  update();
  return {
    setAccess: (next: boolean) => { if (allowed !== next) { allowed = next; comparisonRequest = null; update(); } },
    setDevice: (next: string) => { if (deviceKey !== next) { deviceKey = next; update(); } },
    setGeneration: (next: number) => { if (generation !== next) { generation = next; update(); } },
    invalidate: () => actions.current?.invalidate(),
    compare: (set: ClientSetState) => {
      if (!allowed) return;
      comparisonRequest = { sets: { [set.name]: !set.joined }, label: `${set.joined ? "Leave" : "Join"} ${set.description || set.name}` };
      update();
    },
  };
}
