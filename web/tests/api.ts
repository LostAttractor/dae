import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import type { Fixture } from "./fixtures.ts";

const source = ts.transpileModule(await readFile(new URL("../src/api.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

function boundary(page = "https://panel.example", target = "") {
  const calls: { url: string; options: RequestInit }[] = [];
  const proof = { id: "proof", ca_fingerprint: "test-ca" };
  const exports = {};
  runInNewContext(source, {
    exports, URL, AbortSignal, __DAE_API_URL__: target, location: new URL(page),
    // Accessing either browser storage is a regression.
    get localStorage() { throw new Error("Unexpected localStorage access"); },
    get sessionStorage() { throw new Error("Unexpected sessionStorage access"); },
    document: { createElement: () => ({ click() {} }) }, setTimeout(callback: () => void) { callback(); },
    fetch: async (url: URL, options: RequestInit) => {
      calls.push({ url: url.href, options });
      return new Response(JSON.stringify(proof), { headers: { "Content-Type": "application/json" } });
    },
  });
  return { api: exports as {
    loginAvailable: boolean;
    request(path: string, method?: string, body?: unknown, headers?: Record<string, string>): Promise<unknown>;
    downloadCertificate(format: string): Promise<void>;
    certificateRequest(): Promise<unknown>;
    challengeRequest(address: string, origins: string[]): Promise<unknown>;
  }, calls };
}

test("fixed target, cookies and explicit raw-key login never use browser storage or automatic Bearer", async () => {
  for (const target of ["", "https://api.example:9080"]) {
    const { api, calls } = boundary("https://panel.example", target);
    await api.request("/api/session", "PUT", undefined, { Authorization: "Bearer raw-key" });
    await api.request("/api/selectors");
    await api.request("/api/session", "DELETE");
    await api.downloadCertificate("pem");
    for (const call of calls) {
      assert.equal(new URL(call.url).origin, target || "https://panel.example");
      assert.equal(call.options.credentials, "include");
      assert.equal(call.options.redirect, "error");
    }
    assert.equal((calls[0]!.options.headers as Record<string, string>).Authorization, "Bearer raw-key");
    assert.equal((calls[0]!.options.headers as Record<string, string>)["X-Dae-API"], "1");
    assert.equal((calls[2]!.options.headers as Record<string, string>)["X-Dae-API"], "1");
    for (const call of calls.slice(1)) assert.equal(new Headers(call.options.headers).get("Authorization"), null);
    await assert.rejects(api.request("https://evil.example/api/session", "PUT"), /Invalid API/);
    await assert.rejects(api.request("//evil.example/api/session", "PUT"), /Invalid API/);
    await assert.rejects(api.request("/not-api"), /Invalid API/);
    assert.equal(calls.length, 4);
  }
});

test("HTTP pages cannot submit keys even to a fixed HTTPS API", async () => {
  for (const target of ["", "https://api.example"]) {
    const { api, calls } = boundary("http://panel.example", target);
    assert.equal(api.loginAvailable, false);
    await assert.rejects(api.request("/api/session", "PUT", undefined, { authorization: "Bearer raw-key" }), /HTTPS page/);
    assert.equal(calls.length, 0);
    await api.request("/api/certificate");
    await api.downloadCertificate("pem");
    assert.deepEqual(calls.map(call => call.options.credentials), ["omit", "omit"]);
  }
});

test("anonymous HTTP setup still permits direct HTTPS CA proofs", async () => {
  const { api, calls } = boundary("http://192.0.2.1:9080");
  await api.certificateRequest();
  assert.equal(calls[0]!.url, "http://192.0.2.1:9080/api/certificate/tests");
  assert.equal(new Headers(calls[0]!.options.headers).get("Authorization"), null);
  assert.equal(calls[1]!.url, "https://192.0.2.1:9080/api/certificate/tests/proof");
  assert.equal(calls[1]!.options.credentials, "omit");
  assert.equal(calls[1]!.options.redirect, "error");
});

test("proofs omit cookies and headers, refuse redirects, and enforce exact challenge destinations", async () => {
  const { api, calls } = boundary("https://panel.example", "https://api.example:9080");
  await api.certificateRequest();
  await api.challengeRequest("https://[2001:db8::254]:9443/test/proof", ["https://[2001:db8::254]:9443"]);
  assert.equal(calls[0]!.options.credentials, "include", "only challenge creation is authenticated");
  assert.equal(calls[1]!.url, "https://api.example:9080/api/certificate/tests/proof");
  for (const call of calls.slice(1)) {
    assert.equal(call.options.credentials, "omit");
    assert.equal(call.options.redirect, "error");
    assert.equal(call.options.mode, "cors");
    assert.equal(call.options.headers, undefined);
  }
  for (const url of ["http://test.example/test/x", "https://evil.example/test/x", "https://test.example:9443/test/x", "https://user@test.example/test/x", "https://test.example/api/x", "https://test.example/test/x?q=1", "https://test.example/test/x#fragment"]) {
    assert.throws(() => api.challengeRequest(url, ["https://test.example"]), /Invalid MITM/);
  }
  assert.equal(calls.length, 3);
});

const certificateSource = ts.transpileModule(await readFile(new URL("../src/certificate.ts", import.meta.url), "utf8"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

function certificateBoundary() {
  const metadata: NonNullable<Fixture["certificate"]> = { name: "Test CA", fingerprint: "test-ca", mitm_test_generation: "one" };
  const device: Fixture["device"] = { source_ip: "192.0.2.8", mac: "02:00:00:00:00:08", sets: [],
    mitm: { enabled: true, default: true, override: null, ca_fingerprint: metadata.fingerprint } };
  const pending: ReturnType<typeof Promise.withResolvers<{ ca_fingerprint: string }>>[] = [];
  const calls: string[] = [];
  const nodes = new Map<string, { textContent: string; dataset: Record<string, string>; disabled: boolean; hidden: boolean; href?: string }>();
  const node = (id: string) => {
    if (!nodes.has(id)) nodes.set(id, { textContent: "", dataset: {}, disabled: false, hidden: false });
    return nodes.get(id)!;
  };
  const proof = () => ({ id: "mitm-proof", ca_fingerprint: metadata.fingerprint });
  const api = {
    certificateRequest() {
      calls.push("ca");
      const result = Promise.withResolvers<{ ca_fingerprint: string }>();
      pending.push(result);
      return result.promise;
    },
    async request(_path: string, method = "GET") {
      calls.push(method === "POST" ? "mitm" : "observation");
      return { ...proof(), mitm_enabled: true, mitm_observed: true, mitm_url: "https://203.0.113.254/test/mitm-proof" };
    },
    async challengeRequest() { calls.push("proof"); return proof(); },
    errorStatus: (error: { status?: number }) => error.status,
    errorMessage: String,
    apiOrigin: () => "https://panel.example",
  };
  const exports = {};
  runInNewContext(certificateSource, {
    exports, URL, location: new URL("https://panel.example"),
    require: (path: string) => {
      if (path === "./api.ts") return api;
      assert.equal(path, "./dom.ts");
      return { byId: node };
    },
  });
  const certificate = exports as {
    certificateDevice(device: Fixture["device"]): void;
    certificateIdentity(metadata: Fixture["certificate"]): void;
    certificateAccessChanged(): void;
    onCertificateTrust(listener: (trust: string) => void): void;
    testCertificate(): Promise<{ text: string; tone: string } | undefined>;
  };
  let trust = "";
  certificate.onCertificateTrust(value => { trust = value; });
  certificate.certificateIdentity(metadata);
  certificate.certificateDevice(device);
  return { certificate, metadata, device, pending, calls, node, trust: () => trust };
}

test("failed certificate verification links to HTTP setup on the same default HTTPS port", async () => {
  const { certificate, pending, node } = certificateBoundary();
  const result = certificate.testCertificate();
  pending[0]!.reject(new Error("untrusted certificate"));
  assert.equal((await result)?.tone, "warning");
  assert.equal(node("certificate-http-setup").hidden, false);
  assert.equal(node("certificate-http-setup").href, "http://panel.example:443/");
});

test("automatic and manual certificate verification share only their pending task", async () => {
  const { certificate, metadata, pending, calls } = certificateBoundary();
  const manual = certificate.testCertificate();
  assert.equal(certificate.testCertificate(), manual);
  assert.equal(pending.length, 1, "manual testing joins the blocked automatic CA challenge");
  pending[0]!.resolve({ ca_fingerprint: metadata.fingerprint });
  assert.equal((await manual)?.tone, "success");
  assert.deepEqual(calls, ["ca", "mitm", "proof", "observation"]);
  const next = certificate.testCertificate();
  assert.notEqual(next, manual, "completed results are not cached as running tests");
  assert.equal(pending.length, 2);
  pending[1]!.resolve({ ca_fingerprint: metadata.fingerprint });
  await next;
});

for (const change of ["ca", "device", "generation", "enabled", "access"] as const) {
  for (const outcome of ["proof", 401, 403] as const) {
    test(`${change} changes retire a shared certificate task before its late ${outcome}`, async () => {
      const { certificate, metadata, device, pending, node, trust } = certificateBoundary();
      const previous = certificate.testCertificate();
      if (change === "ca") { metadata.fingerprint = "next-ca"; certificate.certificateIdentity(metadata); }
      if (change === "device") { device.mac = "02:00:00:00:00:09"; certificate.certificateDevice(device); }
      if (change === "generation") { metadata.mitm_test_generation = "two"; certificate.certificateIdentity(metadata); }
      if (change === "enabled") { device.mitm!.enabled = false; certificate.certificateDevice(device); }
      if (change === "access") certificate.certificateAccessChanged();
      const current = certificate.testCertificate();
      assert.notEqual(current, previous);
      assert.equal(pending.length, 2, "the changed context starts a new task");
      if (outcome === "proof") pending[0]!.resolve({ ca_fingerprint: "test-ca" });
      else pending[0]!.reject({ status: outcome });
      assert.equal(await previous, undefined);
      assert.equal(trust(), "testing", "a retired proof or denial cannot overwrite the current task");
      assert.equal(node("test-certificate").disabled, false);
      assert.equal(certificate.testCertificate(), current, "retired cleanup cannot remove the current task");
      assert.equal(pending.length, 2);
      pending[1]!.resolve({ ca_fingerprint: metadata.fingerprint });
      assert.equal((await current)?.tone, "success");
      assert.equal(trust(), "trusted");
    });
  }
}

for (const status of [401, 403]) {
  test(`access changes preserve the completed ${status} certificate denial semantics`, async () => {
    const { certificate, metadata, pending, node, trust } = certificateBoundary();
    const current = certificate.testCertificate();
    pending[0]!.reject({ status });
    await current;
    certificate.certificateAccessChanged();
    certificate.certificateIdentity(metadata);
    assert.equal(trust(), status === 401 ? "unknown" : "unavailable");
    assert.equal(node("test-certificate").disabled, status === 403);
    assert.equal(pending.length, 1, "unchanged metadata does not repeat a completed automatic test");
  });
}
