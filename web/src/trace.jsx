import { useId, useState } from "react";
import { Disclosure } from "./disclosure.jsx";

const words = (value = "") => value.replaceAll("_", " ");
const reasons = {
  terminal_decision: "This rule determines the route at this stage.",
  predicate_match: "The conditions match.", predicate_miss: "The conditions do not match.",
  missing_context: "More information is needed to evaluate this rule.",
  earlier_terminal_rule: "An earlier rule already determined the route.",
  outbound_unavailable: "Skipped because the outbound is unavailable.",
  not_bound_to_active_policy: "This rule is not part of the active policy.",
  different_ingress_policy: "This rule belongs to another ingress policy.",
  remaining_predicates_and_rule_order: "Other conditions and earlier rules still affect the outcome.",
  no_active_plugins: "No plugins are active.", http_disabled: "HTTP interception is disabled.",
  client_not_allowed: "HTTPS modules are disabled for this device.",
  script_execution_required: "The script must run before its effect can be known. This check does not run scripts.",
};
const reasonText = (reason) => reasons[reason] || words(reason);
const statusText = (step) => ({ selected: "Selected", conditional: "Uncertain", not_reached: "Not reached", inactive: "Inactive", skipped: "Skipped", unknown: "Unknown", error: "Error" }[step.status] || (step.match === "miss" ? "No match" : step.match === "match" ? "Matched" : "Unknown"));

export function TraceSteps({ steps = [] }) {
  return <div className="trace-steps">{steps.map((step, index) => <details key={`${step.id || step.expression}:${index}`}>
    <summary className="trace-step-summary"><span className="trace-status" data-status={step.status}>{statusText(step)}</span><span className="trace-expression">{step.expression}</span></summary>
    <div className="trace-step-content">
      <p>{reasonText(step.reason)}</p>
      <p className="muted">Stage: {words(step.stage)}{step.parent ? ` · Policy: ${step.parent}` : ""}</p>
      <p className="code-block">{step.expression}</p>
      {step.outbound && <p>Outbound: {step.outbound} · mark {step.mark || 0} · must {String(Boolean(step.must))}</p>}
      {step.targets?.length > 0 && <p>Targets: {step.targets.join(", ")}</p>}
      {(step.sources || []).map((source, index) => <p key={index} className="code-block">{source.file || "configuration"}:{source.line || 0}:{source.column || 0} {source.expression}</p>)}
      {(step.conditions || []).map((condition, index) => <div key={index} className="trace-condition">
        <strong>{condition.expression}: {words(condition.match)}</strong>
        <p className="muted">{words(condition.status)} · {reasonText(condition.reason)}</p>
        <p className="code-block">{`Actual: ${condition.actual || "—"}\nExpected: ${condition.expected || "—"}`}</p>
      </div>)}
    </div>
  </details>)}</div>;
}

function RuleTrace({ steps }) {
  const [filter, setFilter] = useState("all");
  const filters = {
    all: ["All rules", () => true],
    selected: ["Selected", step => step.status === "selected"],
    matched: ["Matched", step => ["evaluated", "selected"].includes(step.status) && step.match === "match"],
    uncertain: ["Uncertain", step => ["conditional", "unknown"].includes(step.status)],
    inactive: ["Inactive / not reached", step => ["inactive", "not_reached"].includes(step.status)],
  };
  const filtered = steps.filter(filters[filter][1]);
  return <Disclosure className="trace-disclosure trace-rule-list" title="Rule trace" meta={`${steps.length} rule${steps.length === 1 ? "" : "s"}`}>
    <label className="trace-filter"><span>Show</span><select value={filter} onChange={event => setFilter(event.target.value)}>
      {Object.entries(filters).map(([key, [label, match]]) => <option key={key} value={key}>{label} ({steps.filter(match).length})</option>)}
    </select></label>
    <div className="trace-scroll" tabIndex={0} role="region" aria-label="Rule trace"><TraceSteps steps={filtered} />{!filtered.length && <p className="muted">No rules in this category.</p>}</div>
  </Disclosure>;
}

function outcome(result, kind) {
  const decision = result.decision;
  if (!decision.complete) return [decision.missing?.includes("destination.ip") ? "Destination IP needed" : "Cannot determine the result yet", decision.missing?.length ? "Some information needed by the rules is missing. Complete it below and run the check again." : "The result depends on runtime behavior or a choice that this read-only check cannot make."];
  switch (decision.verdict) {
    case "kernel_direct": return ["Direct in the kernel", "This connection passes through the kernel without a userspace handoff."];
    case "drop": return ["Connection blocked", "The current rules or outbound availability policy block this connection."];
    case "userspace": return [decision.outbound === "direct" ? "Direct through userspace" : decision.outbound ? `Routed via ${decision.outbound}` : "Handled in userspace", "The connection is handed to dae in userspace."];
    case "local_response": return ["Answered locally", "A plugin provides a local response."];
    case "analysis": {
      if (kind === "domain") return [result.domains?.length ? `${result.domains.length} cached domain records` : "No cached domain records", "The details show each record's source and kernel presence. No DNS lookup is sent."];
      if (kind === "outbound") {
        const group = result.outbounds?.[0], selected = group?.nodes?.filter(node => node.selected) || [];
        return [!group?.available ? "Outbound unavailable" : group.random ? "Node chosen at connection time" : selected.length === 1 ? `Selected node: ${selected[0].name}` : "Outbound available", "Selection and availability reflect the current snapshot. No connection test is sent."];
      }
      const disabled = result.steps?.find(step => ["no_active_plugins", "http_disabled", "client_not_allowed"].includes(step.reason));
      return [disabled ? reasonText(disabled.reason) : kind === "dns" ? "DNS policy evaluated" : "HTTP plugins evaluated", "Review the matching rules below. This analysis alone does not determine the connection route."];
    }
    default: return ["Result undetermined", "Review the details for the available evidence."];
  }
}

const missingFields = {
  "destination.ip": ["Destination IP", "A URL or hostname does not identify one destination IP. Enter the actual IP, or check a cached candidate below."],
  "destination.port": ["Destination port", "Include a port in the target, such as example.com:443."],
  domain_mapping: ["Kernel domain mapping", "Kernel domain rules use existing DNS-to-IP mappings. Entering a hostname or SNI does not create a mapping."],
  hostname: ["TLS / HTTP hostname", "Supply TLS SNI or an HTTP(S) URL. Use advanced JSON with flow.sni set to an empty string to explicitly declare no hostname."],
  hostname_verification: ["Hostname verification", "Resolver evidence is needed to verify the hostname. This check does not query DNS."],
  trusted_hostname: ["Trusted hostname", "The current hostname evidence is insufficient for this routing stage."],
  rewritten_target_address: ["Rewritten destination IP", "A plugin changed the target. Its destination address is needed to continue."],
  mitm_client_identity: ["Device identity", "A known device is needed to evaluate its HTTPS module settings."],
};

function MissingContext({ decision, context, onEdit, onUseIP }) {
  const missing = decision.missing || [];
  const id = useId();
  const [candidate, setCandidate] = useState("");
  const daemon = context.some(field => field.name === "origin" && field.value === "daemon");
  const source = !daemon && context.find(field => field.name === "source_ip" && field.source !== "unknown")?.value;
  // An inherited IPv4 identity cannot simulate an IPv6 connection (or vice versa).
  const candidates = [...new Set((decision.targets || []).map(target => target.match(/^\[([^\]]+)\]:\d+$/)?.[1] || target.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/)?.[1]).filter(ip => ip && (!source || ip.includes(":") === source.includes(":"))))];
  if (!missing.length) return null;
  return <div className="trace-missing">
    <h4>Complete the missing information</h4>
    <ul>{missing.map(field => <li key={field}><strong>{missingFields[field]?.[0] || words(field)}</strong><span>{missingFields[field]?.[1] || "Supply this field in Advanced context if it is known. Omitted values remain unknown."}</span></li>)}</ul>
    <div className="button-row">
      {missing.includes("destination.ip") && <button type="button" onClick={() => onEdit("ip")}>Enter destination IP</button>}
      {missing.includes("hostname") && <button type="button" onClick={() => onEdit("sni")}>Enter hostname</button>}
      {missing.some(field => !["destination.ip", "domain_mapping", "hostname"].includes(field)) && <button type="button" onClick={() => onEdit(missing.includes("destination.port") ? "target" : "overrides")}>Edit test context</button>}
    </div>
    {missing.includes("destination.ip") && candidates.length > 0 && <div className="trace-candidates">
      <label htmlFor={id}>Check one cached IP <span className="field-hint">{candidates.length} candidates{source ? ` · ${source.includes(":") ? "IPv6" : "IPv4"}` : ""} · no DNS query</span></label>
      <div className="trace-candidate-controls"><select id={id} value={candidate} onChange={event => setCandidate(event.target.value)}>
        <option value="">Choose an IP…</option>{candidates.map(ip => <option key={ip}>{ip}</option>)}
      </select><button type="button" disabled={!candidate} onClick={() => onUseIP(candidate)}>Check this IP</button></div>
      <p className="field-hint">The result applies to the selected IP only. Your client may use another address.</p>
    </div>}
  </div>;
}

function TraceResult({ title, result, kind, context, onEdit, onUseIP }) {
  const decision = result.decision, steps = result.steps || [];
  const [headline, description] = outcome(result, kind);
  const selected = decision.complete && steps.find(step => step.id === decision.rule_id);
  const targets = decision.targets || [];
  const domains = result.domains || [], group = result.outbounds?.[0];
  const facts = kind === "domain" ? [
    ["Cached records", domains.length], ["Present in kernel", domains.filter(entry => entry.resident).length], ["DNS lookup", "Not sent"],
  ] : kind === "outbound" ? [
    ["Group", group?.name || "—"], ["Selection policy", group?.policy || "builtin"], ["Network", group?.network || "—"],
  ] : [
    ["Outbound", decision.outbound ? <>{decision.outbound}{!decision.complete && <span className="field-hint"> · provisional</span>}</> : decision.complete ? "Not applicable" : "Not determined"],
    ["Policy", decision.policy || "—"],
    [!decision.complete && targets.length > 1 ? "Candidate destinations" : "Destination", targets.length === 1 ? targets[0] : targets.length ? `${targets.length} candidates · see details` : decision.original_target || "—"],
  ];
  return <section className="trace-result">
    <div className="trace-outcome" data-state={!decision.complete ? "unknown" : decision.verdict === "drop" ? "blocked" : "complete"}>
      <p className="trace-label">{title}</p><h3>{headline}</h3><p>{description}</p>
      <dl className="trace-facts">
        {facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
      {decision.original_outbound && decision.original_outbound !== decision.outbound && <p className="trace-fallback">{decision.original_outbound} is unavailable; fallback outbound: {decision.outbound || "undetermined"}.</p>}
      {selected && <div className="trace-selected"><strong>Deciding rule</strong><code>{selected.expression}</code><span className="field-hint">{reasonText(selected.reason)}</span></div>}
    </div>
    {!decision.complete && <MissingContext decision={decision} context={context} onEdit={onEdit} onUseIP={onUseIP} />}
    {!decision.complete && !decision.missing?.length && result.notes?.length > 0 && <p className="trace-runtime-note">{result.notes.filter(note => !note.startsWith("Fresh unfragmented flow")).join(" ")}</p>}
    {steps.length > 0 && <RuleTrace steps={steps} />}
    {(result.outbounds || []).map((group, index) => <Disclosure className="trace-disclosure" key={index} title={`Outbound nodes · ${group.name}`} meta={group.available ? "available" : "unavailable"}>
      <p className="muted">{group.policy || "builtin"} · {group.network}{group.random ? " · random selection at connection time" : ""}</p>
      <div className="trace-scroll">{group.nodes.map((node, index) => <p key={index}><strong>{node.name}</strong>{node.selected ? " · selected" : ""}: {words(node.reason)}{node.selection ? ` · priority ${node.selection.priority} · score ${node.selection.score}` : ""}</p>)}</div>
    </Disclosure>)}
    {result.domains?.length > 0 && <Disclosure className="trace-disclosure" title="Cached domain records" meta={`${result.domains.length} records`}>
      <div className="trace-scroll">{result.domains.map((entry, index) => <p key={index}>{entry.domain} → {entry.ip} · {entry.resident ? "present in kernel" : "absent from kernel"} · {words(entry.source)}{entry.retain_until ? ` · retained until ${entry.retain_until}` : ""}</p>)}</div>
    </Disclosure>}
    <Disclosure className="trace-disclosure" title="Technical details">
      <dl className="trace-technical">
        {Object.entries({ Verdict: decision.verdict, Complete: String(decision.complete), "Rule ID": decision.rule_id || "—", "Original target": decision.original_target || "—", "Original outbound": decision.original_outbound || "—", Mark: decision.mark, Must: String(decision.must), Capture: (decision.capture || []).join(", ") || "none" }).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
      {targets.length > 0 && <Disclosure nested title="Destination list" meta={`${targets.length}`}><div className="trace-scroll">{targets.map((target, index) => <p key={index}>{target}</p>)}</div></Disclosure>}
      {(result.notes || []).map((note, index) => <p key={index} className="muted">{note}</p>)}
    </Disclosure>
  </section>;
}

export function Explanation({ response, kind = "flow", target, onEdit, onUseIP }) {
  return <div className="explanation">
    <div className="trace-heading"><h2>Result</h2>{target && <span className="muted">{target}</span>}</div>
    {response.compared && <p className="muted">Compare the same target and context. Proposed changes have not been applied.</p>}
    <div className={`trace-results${response.compared ? " trace-comparison" : ""}`}>
      <TraceResult title="Current settings" result={response.current} kind={kind} context={response.context} onEdit={onEdit} onUseIP={onUseIP} />
      {response.compared && <TraceResult title="With proposed changes" result={response.compared} kind={kind} context={response.context} onEdit={onEdit} onUseIP={onUseIP} />}
    </div>
    {kind === "flow" && <p className="trace-footnote">For a new connection using the current state. Existing connections may keep their earlier route.</p>}
    <Disclosure className="trace-disclosure" title="Input context and raw response">
      <p className="muted">Generation {response.generation} · {response.observed_at}</p>
      <dl className="trace-technical">{response.context.map((field, index) => <div key={index}><dt>{field.name}</dt><dd>{field.value || "—"} <span className="muted">[{field.source}]</span></dd></div>)}</dl>
      <Disclosure nested title="Response JSON"><pre className="code-block trace-scroll">{JSON.stringify(response, null, 2)}</pre></Disclosure>
    </Disclosure>
  </div>;
}
