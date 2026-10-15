import type { Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import type { Protocol } from "devtools-protocol";
import { cdp } from "./cdp.ts";
import { serverPort } from "./server.ts";
import { deferred, type Fixture, type FixtureStats, type FixtureGroup, type FixtureBody, type FixtureResult, type RecordedRequest } from "./fixtures.ts";
// Browser regressions use Node's built-ins, the production bundle and installed Chromium.
import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTLSServer } from "node:https";
import { createServer as createTCPServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gunzipSync } from "node:zlib";

const profile = await mkdtemp(join(tmpdir(), "dae-web-"));
const source = join(profile, "public");
await promisify(execFile)(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../build.ts", import.meta.url)), source]);
for (const entry of await readdir(source, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile()) continue;
  const path = join(entry.parentPath, entry.name);
  const data = await readFile(path);
  if (entry.name.endsWith(".js")) assert.ok(data.length <= 500_000, `${entry.name} stays within the JS chunk budget`);
  if (!entry.name.endsWith(".gz")) continue;
  const original = await readFile(path.slice(0, -3));
  assert.deepEqual(gunzipSync(data), original, `${entry.name} precompressed contents`);
  assert.ok(data.length < original.length, `${entry.name} compression saves bytes`);
}
const html = await readFile(join(source, "index.html"), "utf8");
const entryScript = html.match(/<script\b[^>]*\bsrc="([^"]+)"/)?.[1];
assert.ok(entryScript, "production HTML references its entry script");
await readFile(join(source, "index.html.gz"));
await readFile(join(source, `${entryScript}.gz`));
console.log("PASS production asset sizes and gzip round trips");
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
let fixture: Fixture;
const chartRequests: string[] = [];
let chartResponse: { release: ReturnType<typeof deferred>; fail?: boolean } | null = null;
const tlsServers: Partial<Record<"trust" | "mitm" | "untrusted", ReturnType<typeof createTLSServer>>> = {};
const mitmOrigins = ["https://203.0.113.254", "https://[2001:db8:ffff::254]"];
let proxy: ReturnType<typeof createServer> | undefined;
let caGeneration = 0;
const handshakeGeneration = new WeakMap<TLSSocket, number>();
let renewAPILeaf: () => Promise<void>;

// Real browser trust-store checks. HOME and the NSS database belong to
// this temporary profile; no system/browser certificate store is modified.
{
  const exec = promisify(execFile);
  const root = join(profile, "root.pem"), rootKey = join(profile, "root.key");
  const leaf = join(profile, "leaf.pem"), leafKey = join(profile, "leaf.key"), csr = join(profile, "leaf.csr");
  const extensions = join(profile, "leaf.ext");
  await writeFile(extensions, "subjectAltName=IP:127.0.0.1,IP:::1,IP:203.0.113.254,IP:2001:db8:ffff::254\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n");
  await exec("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", rootKey, "-out", root, "-subj", "/CN=dae Browser Test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  await exec("openssl", ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", leafKey, "-out", csr, "-subj", "/CN=127.0.0.1"]);
  await exec("openssl", ["x509", "-req", "-in", csr, "-CA", root, "-CAkey", rootKey, "-CAcreateserial", "-out", leaf, "-days", "1", "-extfile", extensions]);
  const untrusted = join(profile, "untrusted.pem"), untrustedKey = join(profile, "untrusted.key");
  await exec("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", untrustedKey, "-out", untrusted, "-subj", "/CN=Untrusted Test", "-days", "1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const database = join(profile, ".pki", "nssdb");
  await mkdir(database, { recursive: true });
  await exec("certutil", ["-N", "--empty-password", "-d", `sql:${database}`]);
  await exec("certutil", ["-A", "-d", `sql:${database}`, "-n", "dae-browser-test", "-t", "C,,", "-i", root]);
  renewAPILeaf = async () => {
    const cert = join(profile, "renewed.pem");
    await exec("openssl", ["x509", "-req", "-in", csr, "-CA", fixture.untrusted ? untrusted : root, "-CAkey", fixture.untrusted ? untrustedKey : rootKey, "-set_serial", String(++caGeneration + 100), "-out", cert, "-days", "1", "-extfile", extensions]);
    tlsServers[fixture.untrusted ? "untrusted" : "trust"]!.setSecureContext({ cert: await readFile(cert), key: await readFile(leafKey) });
  };
  for (const kind of ["trust", "mitm", "untrusted"] as const) {
    const server = createTLSServer({ cert: await readFile(kind === "untrusted" ? untrusted : leaf), key: await readFile(kind === "untrusted" ? untrustedKey : leafKey) }, (req, res) => {
      const mitm = kind === "mitm";
      if (!mitm && req.url !== `/api/certificate/tests/${fixture.caTest?.id}`) return void httpServer.emit("request", req, res);
      if ((req.headers.origin && req.headers.origin !== origin) || req.url !== (mitm ? "/test/browser-proof" : `/api/certificate/tests/${fixture.caTest?.id}`)) return res.writeHead(403).end();
      if (!mitm && (handshakeGeneration.get(req.socket as TLSSocket) ?? 0) < caGeneration) return res.writeHead(409, { "Access-Control-Allow-Origin": origin, Connection: "close" }).end();
      if (mitm) {
        assert.ok(fixture.testData);
        fixture.testData.mitm_observed = true;
      }
      res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": origin, "Cache-Control": "no-store", Connection: "close" });
      res.end(JSON.stringify(mitm ? { id: "browser-proof", ca_fingerprint: "browser-ca" } : fixture.caTest));
    });
    server.on("secureConnection", socket => handshakeGeneration.set(socket, caGeneration));
    tlsServers[kind] = server;
  }
  // A minimal local tunnel carries the virtual origins in this browser fixture.
  // Production transparent admission and zero-upstream replies are tested in Go.
  proxy = createServer();
  proxy.on("connect", (req, socket, head) => {
    if (!fixture || fixture.bypass || !["203.0.113.254:443", "[2001:db8:ffff::254]:443"].includes(req.url || "")) return socket.destroy();
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) socket.unshift(head);
    tlsServers.mitm!.emit("connection", socket);
  });
  proxy.listen(0, "127.0.0.1");
  await once(proxy, "listening");
}

function statusGroups(stats: FixtureStats): FixtureGroup[] {
  return [
    { name: "direct", target_kind: "builtin", health: "healthy", stats, nodes: [{ name: "direct", checks_connectivity: false, health: "unknown", stats }] },
    { name: "proxy_jp", policy: "min_moving_avg", health: "healthy", connectivity: "available", stats, nodes: [
      { name: "Tokyo premium → IPv6", checks_connectivity: true, healthy: true, health: "healthy", stats },
      { name: "Osaka backup", checks_connectivity: true, healthy: false, health: "unhealthy", stats: { active_connections: 0 } },
    ] },
  ];
}

function lastRequest(): RecordedRequest {
  const request = fixture.requests.at(-1);
  assert.ok(request, "the browser sent a request");
  return request;
}

function resetFixture() {
  const nodes = Array.from({ length: 1000 }, (_, i) => ({
    id: `node-${i}`, name: i < 3 ? ["Hong Kong", "Tokyo", "Singapore"][i] : `Node ${i} · ${"Long subscription name ".repeat(4)}`,
    health: i === 0 ? "healthy" as const : "unknown" as const, healthy: i === 0, tested: i === 0, tracking: i === 0, checking: false,
    ...(i === 0 ? { latency_ms: 28.5, checked_at: "2026-09-22T00:00:00Z" } : {}),
  }));
  fixture = {
    mode: "lan", requests: [], nextRead: null,
    nextDeviceRead: null, nextGlobalRead: null, certificate: null, groups: [], tables: [], plugins: [],
    stats: { active_connections: 2, total_connections: 7, upload_bytes: 2048, download_bytes: 8192, history: { upload_bytes_per_second: [100, 200], download_bytes_per_second: [400, 800] } },
    selectors: [
      { name: "On demand", node_id: "node-0", track_all: false, overridden: false, nodes },
      { name: "With default", node_id: "node-1", default_node_id: "node-0", track_all: false, overridden: true, nodes: structuredClone(nodes.slice(0, 3)) },
      { name: "Tracked", node_id: "node-0", track_all: true, overridden: false, nodes: structuredClone(nodes.slice(0, 3)) },
      { name: "Tracked default", node_id: "node-1", default_node_id: "node-0", track_all: true, overridden: true, nodes: structuredClone(nodes.slice(0, 3)) },
    ],
    device: { source_ip: "192.168.1.8", mac: "02:00:00:00:00:08", sets: [
      { name: "internal/work", description: "Work network", joined: false },
      { name: "gaming", description: "", joined: true },
    ] },
  };
}

// A managed device lists every routing group; the fixture has one.
function managedDevice(mac: string) {
  return fixture.managed?.mac === mac ? fixture.managed : { mac, sets: [{ name: "internal/work", description: "Managed group", joined: false }], mitm_override: null };
}

const httpServer = createServer(async (req, res) => {
  const url = req.url || "/";
  const json = (data: unknown, status = 200) => {
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(JSON.stringify(data));
  };
  const delayedJSON = async (key: "nextImpact" | "nextExplanation" | "nextManagedDevice" | "nextContextRead", data: unknown) => {
    const override = fixture[key];
    fixture[key] = null;
    const snapshot = structuredClone(data);
    override?.started.resolve();
    if (override?.release) await override.release.promise;
    return json(override?.status ? { error: "Deferred fixture error" } : snapshot, override?.status || 200);
  };
  try {
    if (!url.startsWith("/api/")) {
      const path = url === "/" ? "index.html" : url.slice(1);
      if (!/^(?:assets\/)?[\w-]+\.(html|js|css)$/.test(path)) { res.writeHead(404).end(); return; }
      if (path.startsWith("assets/traffic-chart-")) {
        chartRequests.push(path);
        const response = chartResponse;
        if (response) await response.release.promise;
        if (response?.fail) { res.writeHead(503, { "Cache-Control": "no-store" }).end(); return; }
      }
      const types: Record<string, string> = { html: "text/html", js: "text/javascript", css: "text/css" };
      res.writeHead(200, {
        "Content-Type": types[path.split(".").at(-1)!], "Cache-Control": "no-store",
        "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' https://${new URL(origin).hostname.includes(":") ? "*" : new URL(origin).hostname}:${serverPort(server)}/api/certificate/tests/ https://203.0.113.254:443/test/ https://*:443/test/; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
      });
      res.end(await readFile(join(source, path)));
      return;
    }
    if (url.endsWith("/diagnostics/explain") || url.endsWith("/impact")) {
      if (fixture.mode === "denied") return json({ error: "Access denied" }, 403);
      if (fixture.mode === "api_key" && !req.headers.cookie?.includes("session=valid")) return json({ error: "Administrator access required" }, 401);
    }
    if (req.method !== "GET") {
      assert.equal(req.headers["x-dae-api"], "1");
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body: FixtureBody = JSON.parse(Buffer.concat(chunks).toString() || "{}");
      fixture.requests.push({ method: req.method || "GET", path: url, body });
      if (url === "/api/certificate/tests") {
        await renewAPILeaf();
        fixture.caTest = { id: `ca-test-${caGeneration}`, ca_fingerprint: fixture.certificate!.fingerprint, expires_at: new Date(Date.now() + 60000).toISOString() };
        res.setHeader("Connection", "close");
        return json(fixture.caTest, 201);
      }
      if (url === "/api/session") {
        if (req.method === "PUT" && req.headers.authorization !== "Bearer test-key") return json({ error: "Incorrect API key" }, 401);
        res.setHeader("Set-Cookie", req.method === "PUT" ? "session=valid; Path=/api; HttpOnly; SameSite=Strict" : "session=; Path=/api; Max-Age=0");
        res.writeHead(204).end();
        return;
      }
      if (url === "/api/probes") {
        const selector = fixture.selectors.find((entry) => entry.name === body.outbound);
        assert.ok(selector);
        for (const node of selector.nodes) {
          if (!body.node_id || node.id === body.node_id) node.checking = true;
        }
        return json({ outbound: body.outbound, node_ids: selector.nodes.map((node) => node.id) }, 202);
      }
      if (url.endsWith("/impact")) {
        const name = decodeURIComponent(url.slice("/api/device/sets/".length, -"/impact".length));
        const set = fixture.device.sets.find((entry) => entry.name === name);
        assert.ok(set);
        return delayedJSON("nextImpact", { generation: 7, name, joined_before: set.joined, joined_after: body.joined, connection_behavior: "retain", exports: [], rules: fixture.impactRules || [{ id: "work/1", parent: "main", policy: "main", section: "routing", stage: "client_impact", expression: 'client(work) && domain(suffix: example.com) -> proxy', status: "referenced", match: "unknown", reason: "client_reference", conditions: [{ expression: "client(work)", actual: String(set.joined), expected: String(body.joined), match: "match", status: "supplementary", reason: "membership_change" }] }] });
      }
      if (url.endsWith("/diagnostics/explain")) {
        const result = (verdict: string, outbound: string) => ({ decision: { complete: true, verdict, outbound, rule_id: "rule/1", policy: "main", targets: ["198.51.100.10:443"], mark: 0, must: false }, steps: [{ id: "rule/1", stage: "kernel", expression: '<img src=x onerror="throw 1">', status: "selected", match: "match", reason: "terminal_decision" }], domains: [], outbounds: [], notes: [`Analysis: ${body.kind}`] });
        return delayedJSON("nextExplanation", fixture.explanation || { schema: 1, generation: 7, observed_at: "2026-10-09T00:00:00Z", context: [{ name: "mac", value: fixture.device.mac, source: "request" }], current: result("kernel_direct", "direct"), ...(body.compare ? { compared: result("userspace", "proxy") } : {}) });
      }
      if (url.startsWith("/api/clients/") && url.includes("/members/")) {
        const [group, mac] = url.slice("/api/clients/".length).split("/members/").map(decodeURIComponent);
        fixture.managed = { mac, sets: [{ name: group, description: "Managed group", joined: req.method === "PUT" }], mitm_override: fixture.managed?.mac === mac ? fixture.managed.mitm_override : null };
        return json({ name: group, description: "Managed group", members: req.method === "PUT" ? [mac] : [] });
      }
      if (url.startsWith("/api/devices/") && url.endsWith("/mitm")) {
        const mac = decodeURIComponent(url.slice("/api/devices/".length, -"/mitm".length));
        if (req.method !== "DELETE") assert.equal(typeof body.enabled, "boolean");
        assert.equal(req.headers["x-dae-mitm"], fixture.certificate?.fingerprint);
        fixture.managed = { ...managedDevice(mac), mitm_override: req.method === "DELETE" ? null : body.enabled! };
        return json(fixture.managed);
      }
      if (url.startsWith("/api/device/sets/")) {
        const set = fixture.device.sets.find((entry) => entry.name === decodeURIComponent(url.slice("/api/device/sets/".length)));
        assert.ok(set);
        set.joined = req.method === "PUT";
        return json(fixture.device);
      }
      if (url === "/api/device/mitm") {
        assert.ok(fixture.device.mitm);
        if (req.method !== "DELETE") assert.equal(typeof body.enabled, "boolean");
        assert.equal(req.headers["x-dae-mitm"], fixture.device.mitm.ca_fingerprint);
        fixture.device.mitm.override = req.method === "DELETE" ? null : body.enabled!;
        fixture.device.mitm.enabled = fixture.device.mitm.override ?? fixture.device.mitm.default;
        return json(fixture.device);
      }
      if (url === "/api/device/mitm-tests") {
        assert.ok(fixture.device.mitm);
        fixture.testData = { id: "browser-proof", ca_fingerprint: "browser-ca", mitm_enabled: fixture.device.mitm.enabled,
          mitm_url: `${mitmOrigins[new URL(origin).hostname.includes(":") ? 1 : 0]}/test/browser-proof`, mitm_observed: false };
        return json(fixture.testData, 201);
      }
      const selector = fixture.selectors.find((entry) => entry.name === decodeURIComponent(url.slice("/api/selectors/".length)));
      assert.ok(selector);
      const nodeID = req.method === "DELETE" ? selector.default_node_id : body.node_id;
      assert.ok(nodeID);
      selector.node_id = nodeID;
      selector.overridden = req.method !== "DELETE";
      selector.saved_selection = selector.overridden ? { name: selector.nodes.find((node) => node.id === selector.node_id)!.name, status: "matched" } : undefined;
      return json(selector);
    }
    if (url === "/api/selectors") {
      const override = fixture.nextRead;
      fixture.nextRead = null;
      const status = override?.status || (fixture.mode === "denied" ? 403 : fixture.mode === "api_key" && !req.headers.cookie?.includes("session=valid") ? 401 : 200);
      const data = status === 200 ? { auth_mode: fixture.mode, admin_enabled: true, selectors: fixture.selectors } : { error: status === 401 ? "Login required" : status === 403 ? "Direct LAN access required" : "API is reloading" };
      const snapshot = structuredClone(data);
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(snapshot, status);
    }
    if (url === "/api/device/status") {
      fixture.deviceStatusReads = (fixture.deviceStatusReads || 0) + 1;
      if (fixture.l3) return json({ error: "Ethernet MAC required" }, 403);
      const override = fixture.nextDeviceRead;
      fixture.nextDeviceRead = null;
      const snapshot = structuredClone({ device: fixture.device, scope: "userspace_upstream", started_at: "2026-10-01T00:00:00Z", stats: fixture.stats, outbounds: [{ name: "device-outbound", stats: fixture.stats }] });
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(override?.status ? { error: "Device unavailable" } : snapshot, override?.status || 200);
    }
    if (url === "/api/device/mitm-tests/browser-proof") return json(fixture.testData);
    if (url === "/api/status") {
      const override = fixture.nextGlobalRead;
      fixture.nextGlobalRead = null;
      const status = override?.status || (fixture.mode === "denied" ? 403 : fixture.mode === "api_key" && !req.headers.cookie?.includes("session=valid") ? 401 : 200);
      const snapshot = { buffer_memory: { limit: 67108864, used: 1048576, peak: 2097152, denied: 3 }, version: "test-daemon", started_at: "2026-10-01T00:00:00Z", stats: { ...fixture.stats, active_connections: 20 }, direct_fallback_connections: 3, groups: structuredClone(fixture.groups), tables: fixture.tables, plugins: fixture.plugins };
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(status === 200 ? snapshot : { error: "Global status unavailable" }, status);
    }
    if (url === "/api/device") return json(fixture.device);
    if (url === "/api/device/context") return delayedJSON("nextContextRead", fixture.l3
      ? { generation: fixture.generation ?? 7, context: { source_ip: "100.64.0.23", link_type: "ip", ifindex: 8 }, fields: [{ name: "link_type", value: "ip", source: "request" }] }
      : { generation: fixture.generation ?? 7, context: { source_ip: fixture.device.source_ip, mac: fixture.device.mac, link_type: "ethernet" }, device: fixture.device, fields: [{ name: "mac", value: fixture.device.mac, source: "request" }] });
    if (url.startsWith("/api/devices/")) return delayedJSON("nextManagedDevice", managedDevice(decodeURIComponent(url.slice("/api/devices/".length))));
    if (url === "/api/certificate") return fixture.certificate ? json(fixture.certificate) : json({ error: "No certificate" }, 404);
    json({ error: "Not found" }, 404);
  } catch (error) {
    console.error(error);
    res.writeHead(500).end();
  }
});
const sockets = new Set<Socket>();
const server = createTCPServer(socket => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
  socket.once("readable", () => {
    const data = socket.read(1);
    if (!data) return socket.destroy();
    socket.unshift(data);
    const branch = data[0] === 0x16 ? tlsServers[fixture.untrusted ? "untrusted" : "trust"] : httpServer;
    if (!branch) return socket.destroy();
    branch.emit("connection", socket);
  });
});
server.listen(0);
await once(server, "listening");
let origin = `http://127.0.0.1:${serverPort(server)}`;
const chromium = spawn(process.env.CHROMIUM || "chromium", [
  "--headless", "--disable-gpu", "--no-first-run", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
  // Headless Chromium reports no pointing device; emulate a mouse so hover-only styles apply.
  // Touch emulation still switches pages to a coarse pointer.
  "--blink-settings=primaryHoverType=2,primaryPointerType=4,availableHoverTypes=2,availablePointerTypes=4", "about:blank",
  ...(proxy ? [`--proxy-server=http://127.0.0.1:${serverPort(proxy)}`] : []),
], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, HOME: profile, XDG_CONFIG_HOME: join(profile, "config"), XDG_CACHE_HOME: join(profile, "cache") } });
const stopped = new Promise((resolve) => chromium.once("close", resolve));

let socket: WebSocket | undefined;
let failures = 0;
try {
  const browserURL = await new Promise<string>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Chromium did not start")), 15000);
    chromium.once("error", (error) => { clearTimeout(timeout); reject(error); });
    chromium.stderr.on("data", (chunk) => {
      const match = chunk.toString().match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
  });
  const endpoint = new URL(browserURL);
  const target = await (await fetch(`http://${endpoint.host}/json/new?about:blank`, { method: "PUT" })).json() as { webSocketDebuggerUrl: string };
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await once(socket, "open");
  const { call, js, exceptions, browserLogs } = cdp(socket);
  const until = async (expression: string) => {
    const end = Date.now() + 10000;
    while (!await js(expression)) {
      if (Date.now() > end) throw Error(`Timed out: ${expression}`);
      await delay(30);
    }
  };
  const ready = () => until('document.querySelector("#controls")?.getAttribute("aria-busy") === "false"');
  const page = async (hash = "") => {
    // Force a new document even when only the fragment changes. visit() and
    // Back/Forward exercise same-document navigation separately.
    await call("Page.navigate", { url: "about:blank" });
    await until('location.href === "about:blank"');
    await call("Page.navigate", { url: origin + hash });
    await ready();
  };
  const visit = async (name: "overview" | "devices" | "selector" | "explain") => {
    if (name === "overview") await js(`document.querySelector('.page-nav a[href="#overview"]').click()`);
    else {
      if (!await js('document.querySelector("#setting-page").checkVisibility()')) await js(`document.querySelector('.page-nav a[href^="#setting/"]').click()`);
      await js(`document.querySelector('#setting-${name}-tab').focus(); document.querySelector('#setting-${name}-tab').click()`);
    }
    await until(`document.querySelector('#${name === "overview" ? "overview-page" : `setting-${name}`}').checkVisibility()`);
  };
  const setDisclosure = async (selector: string, open = true) => {
    const trigger = JSON.stringify(`${selector} > .disclosure-trigger`);
    await js(`(() => { const button = document.querySelector(${trigger}); if (button.getAttribute('aria-expanded') !== '${open}') button.click(); })()`);
    await until(`document.querySelector(${trigger}).getAttribute('aria-expanded') === '${open}'`);
  };
  const fillSearch = async (value: string) => {
    await js('document.querySelector(".node-search input").focus(); document.querySelector(".node-search input").select()');
    if (value) await call("Input.insertText", { text: value });
    else {
      await key("Backspace", 8);
      await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Backspace", code: "Backspace", windowsVirtualKeyCode: 8 });
    }
  };
  const row = 'document.querySelector(".selector-row")';
  const openPicker = async (view: "overview" | "selector" = "selector") => {
    await visit(view);
    await js(`${row}.querySelector('.node-picker').focus(); ${row}.querySelector('.node-picker').click()`);
    await until(`document.querySelector('.node-popover') !== null && document.activeElement.matches('.node-search input')`);
  };
  // Kumo selects open a listbox from their trigger; closed listboxes stay mounted but hidden.
  const listbox = '[...document.querySelectorAll("[role=listbox]")].find(list => list.checkVisibility())';
  const openSelect = async (trigger: string) => {
    await js(`document.querySelector(${JSON.stringify(trigger)}).focus()`);
    await key("ArrowDown", 40);
    await until(`${listbox}?.querySelector("[role=option]") != null`);
  };
  const optionLabels = async (trigger: string) => {
    await openSelect(trigger);
    const labels = await js<string[]>(`[...${listbox}.querySelectorAll("[role=option]")].map(option => option.textContent.trim())`);
    await key("Escape", 27);
    await until(`${listbox} === undefined`);
    return labels;
  };
  const choose = async (trigger: string, label: string) => {
    await openSelect(trigger);
    await js(`[...${listbox}.querySelectorAll("[role=option]")].find(option => option.textContent.trim() === ${JSON.stringify(label)}).click()`);
    await until(`${listbox} === undefined && document.querySelector(${JSON.stringify(trigger)}).textContent.includes(${JSON.stringify(label)})`);
  };
  const toastRoot = 'document.querySelector("#message")?.closest("[role=dialog], [role=alertdialog]")';
  // Notice icons are centered on their text block, one line or several (DESIGN.md).
  const iconsCentered = (selector: string) => js<string[]>(`[...document.querySelectorAll(${JSON.stringify(selector)})].filter(notice => notice.checkVisibility()).flatMap(notice => {
    const icon = notice.querySelector(".notice-icon, .trace-outcome-icon");
    if (!icon) return [];
    const text = notice.matches(".status-banner") ? notice.lastElementChild.firstElementChild : icon.nextElementSibling;
    const middle = rect => (rect.top + rect.bottom) / 2, offset = middle(icon.getBoundingClientRect()) - middle(text.getBoundingClientRect());
    return Math.abs(offset) < 1 ? [] : [notice.className + " " + offset.toFixed(2)];
  })`);
  // Review screenshot of one element, scrolled into view so it is painted.
  const elementShot = async (selector: string, name: string) => {
    if (!process.env.SCREENSHOT_DIR) return;
    const rect = await js<{ x: number; y: number; width: number; height: number }>(`(() => { const element = document.querySelector(${JSON.stringify(selector)}); element.scrollIntoView({ block: "start" }); const r = element.getBoundingClientRect(); return { x: r.x + scrollX, y: r.y + scrollY, width: r.width, height: r.height }; })()`);
    const image = await call("Page.captureScreenshot", { clip: { ...rect, scale: 1 }, captureBeyondViewport: true });
    await writeFile(join(process.env.SCREENSHOT_DIR, `${name}.png`), Buffer.from(image.data, "base64"));
  };
  const key = (name: string, code: number) => call("Input.dispatchKeyEvent", { type: "keyDown", key: name, code: name, windowsVirtualKeyCode: code });
  const test = async (name: string, action: () => Promise<void>) => {
    if (process.env.TEST_FILTER && !name.includes(process.env.TEST_FILTER)) return;
    resetFixture();
    await call("Network.clearBrowserCookies");
    await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
    exceptions.length = 0;
    browserLogs.length = 0;
    await page();
    try {
      await action();
      assert.deepEqual(exceptions, []);
      assert.deepEqual(browserLogs.filter(entry => /Content Security Policy|Refused to/i.test(entry)), [], "no CSP violations");
      console.log(`PASS ${name}`);
    }
    catch (error) {
      failures++;
      console.error(`FAIL ${name}: ${error instanceof Error ? error.stack : JSON.stringify(error)}\n${browserLogs.slice(-8).join("\n")}`);
      console.error("Page state:", await js('({ message: document.querySelector("#message")?.textContent, tone: document.querySelector("#message")?.dataset.tone, busy: document.querySelector("#controls")?.getAttribute("aria-busy"), focused: document.activeElement?.id })'));
      console.error("Viewport:", await js('({ width: innerWidth, scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth })'));
      console.error("Overflow:", await js('[...document.querySelectorAll("body *")].filter(el => el.checkVisibility() && (el.getBoundingClientRect().right > innerWidth + 1 || el.clientWidth && el.scrollWidth > el.clientWidth + 1)).slice(0, 12).map(el => ({ tag: el.tagName, id: el.id, class: el.className, width: el.getBoundingClientRect().width }))'));
      if (process.env.SCREENSHOT_DIR) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `failure-${name.replaceAll(/[^a-z0-9]+/gi, "-")}.png`), Buffer.from(image.data, "base64"));
      }
    }
  };
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
  await call("Log.enable");

  await test("traffic chart loads only on demand and leaves controls usable while pending", async () => {
    await page("#setting/explain");
    chartRequests.length = 0;
    await page("#setting/explain");
    assert.deepEqual(chartRequests, [], "Setting does not request chart code");
    const response = { release: deferred() };
    chartResponse = response;
    try {
      await visit("overview");
      await until('document.querySelector(".traffic-empty")?.textContent === "Loading traffic chart…"');
      assert.match(await js('document.querySelector("#device-traffic .traffic-metrics").textContent'), /200 B\/s/);
      await js('document.querySelector("#refresh").click()');
      await ready();
      await visit("explain");
      assert.equal(await js('document.querySelector("#diagnostic-form").checkVisibility()'), true);
      response.release.resolve();
      await visit("overview");
      await until('document.querySelector("#device-traffic .recharts-surface") !== null');
      await visit("explain");
      await visit("overview");
      await until('document.querySelector("#device-traffic .recharts-surface") !== null');
      assert.equal(chartRequests.length, 1, "both scopes and repeat navigation share the chart module");
    } finally { response.release.resolve(); chartResponse = null; }
  });

  await test("traffic chart waits for samples before downloading", async () => {
    fixture.stats.history = {};
    chartRequests.length = 0;
    await page();
    assert.deepEqual(chartRequests, []);
    assert.match(await js('document.querySelector(".traffic-empty").textContent'), /Waiting for the first traffic sample/);
    fixture.stats.history = { upload_bytes_per_second: [321] };
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelector("#device-traffic .recharts-surface") !== null');
    assert.equal(chartRequests.length, 1);
  });

  await test("traffic chart download failure preserves statistics and navigation", async () => {
    await page("#setting/explain");
    const response = { release: deferred(), fail: true };
    chartResponse = response;
    try {
      await visit("overview");
      response.release.resolve();
      await until('document.querySelector(".traffic-empty")?.textContent.includes("Traffic chart unavailable")');
      assert.match(await js('document.querySelector("#device-traffic .traffic-metrics").textContent'), /200 B\/s/);
      await visit("explain");
      assert.equal(await js('document.querySelector("#diagnostic-form").checkVisibility()'), true);
      await visit("overview");
      chartResponse = null;
      await js('document.querySelector(".traffic-empty a").click()');
      await ready();
      await until('document.querySelector("#device-traffic .recharts-surface") !== null');
    } finally { response.release.resolve(); chartResponse = null; }
  });

  await test("L3 LAN retains management and diagnostics without device controls", async () => {
    fixture.l3 = true;
    fixture.requests = [];
    fixture.deviceStatusReads = 0;
    await page();
    assert.equal(await js('document.querySelector("#access-title").textContent'), "LAN Access");
    assert.equal(await js('document.querySelector("#identity").textContent'), "100.64.0.23");
    assert.match(await js('document.querySelector("#device-mac").textContent'), /Unavailable \(IP-only connection\)/);
    assert.match(await js('document.querySelector("#sets").textContent'), /no Ethernet MAC/);
    assert.equal(await js('document.querySelectorAll("#sets .status-banner[data-tone=warning] svg").length'), 1);
    assert.equal(await js('document.querySelectorAll("#device-traffic .status-banner[data-tone=warning] svg").length'), 1);
    assert.deepEqual(await iconsCentered(".inline-notice, .status-banner"), []);
    assert.doesNotMatch(await js('document.querySelector("#device-status").textContent'), /failed|Retrying/);
    for (const theme of ["dark", "light"]) {
      await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      // Warning text keeps the readable default color; the shared warning icon color carries the tone.
      assert.equal(await js('(() => { const icon = element => getComputedStyle(element.querySelector("svg")).color; const warning = document.querySelector("#sets .status-banner"); const note = document.querySelector("#routing-change-note"); return icon(warning) === icon(note) && icon(note) !== getComputedStyle(document.body).color && getComputedStyle(note).color === getComputedStyle(document.body).color; })()'), true);
      if (process.env.SCREENSHOT_DIR) {
        await delay(250);
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-warning-${theme}.png`), Buffer.from(image.data, "base64"));
      }
    }
    assert.equal(await js('document.querySelector("#test-certificate").disabled'), true);
    await delay(2200);
    assert.equal(fixture.deviceStatusReads, 0);
    await visit("explain");
    assert.equal(await js('document.querySelector("#diagnostic-view").checkVisibility()'), true);
    fixture.l3 = false;
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.match(await js('document.querySelector("#device-mac").textContent'), /02:00:00:00:00:08/);
  });

  await test("L3 context recovery clears a transient error with unchanged identity", async () => {
    fixture.l3 = true;
    await page();
    fixture.nextContextRead = { started: deferred(), status: 500 };
    // Let the background poll retain the unchanged identity through the failure.
    await until('document.querySelector("#device-status").textContent.includes("Device update failed")');
    await until('!document.querySelector("#device-status").textContent.includes("Device update failed")');
    assert.equal(await js('document.querySelector("#identity").textContent'), "100.64.0.23");
    assert.doesNotMatch(await js('document.querySelector("#device-status").textContent'), /failed|Retrying/);
  });

  await test("real browser TLS accepts the installed CA and rejects an untrusted certificate", async () => {
    fixture.certificate = { name: "Browser CA", fingerprint: "browser-ca", mitm_test_generation: "browser-one", mitm_test_origins: mitmOrigins };
    fixture.device.mitm = { enabled: true, override: null, default: true, ca_fingerprint: "browser-ca" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    // HTTPS modules are on, so the page tests the CA by itself and reports it beside the choice.
    await until('document.querySelector("#certificate-mitm-result").textContent === "Transparent MITM verified"');
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser");
    assert.equal(await js('document.querySelector("#mitm .trust-notice").dataset.tone'), "success");
    assert.deepEqual(await iconsCentered("#mitm .trust-notice"), []);
    await elementShot(".device-settings", "dae-web-https-trusted");
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser");
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified");
    fixture.bypass = true;
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Verification incomplete");
    fixture.untrusted = true;
    const previousTest = fixture.testData;
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete");
    assert.ok(fixture.testData);
    assert.equal(fixture.testData.mitm_observed, false);
    assert.equal(fixture.testData, previousTest, "failed CA verification creates no MITM challenge");
    // An unverified CA breaks HTTPS while modules are on; before that it stays a warning.
    assert.equal(await js('document.querySelector("#mitm .status-banner")?.dataset.tone'), "error");
    assert.equal(await js('document.querySelector("#mitm .retest-certificate").textContent'), "Test again");
    assert.deepEqual(await iconsCentered("#mitm .status-banner"), [], "the alert icon is centered like its action");
    await elementShot(".device-settings", "dae-web-https-unverified");
    fixture.device.mitm.enabled = false;
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#mitm .status-banner").dataset.tone'), "warning");
    assert.equal(await js('document.querySelector("#mitm .retest-certificate")'), null);
    assert.deepEqual(await js('(() => { const heading = document.querySelector("#https-title").getBoundingClientRect(), banner = document.querySelector("#mitm .status-banner").getBoundingClientRect(), choice = document.querySelector("#mitm-choice").getBoundingClientRect(); return [Math.round(banner.top - heading.bottom), Math.round(choice.top - banner.bottom)]; })()'), [12, 12], "the warning keeps equal space to its heading and the choice");
    await elementShot(".device-settings", "dae-web-https-warning");
    // Turning modules on tests the CA again.
    fixture.untrusted = false;
    fixture.device.mitm.enabled = true;
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelector("#mitm .trust-notice")?.dataset.tone === "success"');
    const ipv4Origin = origin;
    try {
      origin = `http://[::1]:${serverPort(server)}`;
      fixture.untrusted = false;
      fixture.bypass = false;
      await page();
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser", "IPv6 browser CA test");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified", "IPv6 virtual target test");
      origin = `https://127.0.0.1:${serverPort(server)}`;
      await page();
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser", "HTTPS page CA test");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified", "HTTPS page MITM test");
      fixture.device.mitm.enabled = false;
      fixture.testData = undefined;
      await js('document.querySelector("#refresh").click()');
      await ready();
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "MITM is disabled");
      assert.equal(fixture.testData, undefined, "disabled devices need no MITM challenge");
      fixture.certificate = { name: "Browser CA", fingerprint: "browser-ca" };
      fixture.device.mitm = undefined;
      fixture.l3 = true;
      await page();
      assert.equal(await js('document.querySelector("#test-certificate").disabled'), false, "HTTPS verification needs neither MITM nor device identity");
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "MITM is unavailable");
      assert.equal(fixture.testData, undefined);
    } finally { origin = ipv4Origin; }
  });

  await test("real browser TLS warning does not establish CA trust", async () => {
    fixture.certificate = { name: "Browser CA", fingerprint: "browser-ca" };
    fixture.untrusted = true;
    // Switching this fixture's CA must retire pooled connections from earlier
    // cases, or navigation can still use their already trusted TLS handshake.
    for (const socket of sockets) socket.destroy();
    const httpOrigin = origin;
    try {
      origin = origin.replace("http:", "https:");
      await call("Page.navigate", { url: "about:blank" });
      await call("Page.navigate", { url: origin });
      await until('document.querySelector("#details-button") !== null');
      await js('document.querySelector("#details-button").click()');
      await until('document.querySelector("#proceed-link")?.checkVisibility()');
      await js('document.querySelector("#proceed-link").click()');
      await ready();
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete", "an HTTPS warning override is not CA trust");
      origin = httpOrigin;
      await page();
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete", "HTTP setup must not reuse the HTTPS exception");
    } finally { origin = httpOrigin; }
  });

  await test("Recharts shows rate history, keyboard tooltips and stable live updates", async () => {
    const chart = 'document.querySelector("#device-traffic .recharts-surface")';
    await until(`${chart} !== null`);
    await until('document.querySelectorAll("#device-traffic .recharts-line-curve").length === 2');
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /800 B\/s/);
    await js(`window.trafficChart = ${chart}; trafficChart.focus()`);
    for (let i = 0; i < 12; i++) await key("ArrowRight", 39);
    await until('document.querySelector("#device-traffic .traffic-tooltip")?.textContent.includes("Latest sample")');
    assert.match(await js('document.querySelector("#device-traffic .traffic-tooltip").textContent'), /Upload200 B\/sDownload800 B\/s/);
    fixture.stats.history.download_bytes_per_second = [400, 1600];
    await until('document.querySelector("#device-traffic .traffic-tooltip")?.textContent.includes("1.6 KiB/s")');
    assert.equal(await js(`${chart} === trafficChart && document.activeElement === trafficChart`), true);
    await key("ArrowLeft", 37);
    await until('document.querySelector("#device-traffic .traffic-tooltip")?.textContent.includes("5s before latest")');
    assert.match(await js('document.querySelector("#device-traffic .traffic-tooltip").textContent'), /Upload100 B\/sDownload400 B\/s/);
    assert.equal(browserLogs.some((entry) => /Content Security Policy|Refused to|violates/i.test(entry)), false);
  });

  await test("Overview and Setting sections have direct links and preserve browser navigation", async () => {
    assert.equal(await js('document.querySelector("#overview-page").checkVisibility()'), true);
    assert.equal(await js('document.querySelector("#diagnostics").checkVisibility()'), false);
    await openPicker();
    await visit("explain");
    assert.equal(await js('document.querySelector(".node-popover")'), null);
    assert.equal(await js('document.activeElement.id'), "setting-explain-tab");
    assert.equal(await js('document.querySelector(".page-nav [aria-selected=true]").textContent'), "Setting");
    assert.equal(await js('document.querySelector(".traffic-chart")'), null);
    await js('document.querySelector("#diagnostic-target").value = "example.com:443"');
    await visit("devices");
    await js('document.querySelector("#setting-devices-tab").click()');
    await until('document.querySelector("#managed-client-mac").checkVisibility()');
    await js('history.back()');
    await until('document.querySelector("#setting-explain").checkVisibility()');
    assert.equal(await js('document.querySelector("#diagnostic-target").value'), "example.com:443");
    await js('history.forward()');
    await until('document.querySelector("#setting-page").checkVisibility()');
    await page("#setting/explain");
    assert.equal(await js('document.querySelector("#diagnostic-form").checkVisibility()'), true);
    assert.equal(await js('document.title'), "Network Panel · Setting · Explain");
    assert.equal(await js('document.querySelector("#diagnostics .setting-heading span[title]").textContent'), "Read-only");
    assert.match(await js('document.querySelector("#updated time").getAttribute("aria-label")'), /^Updated /);
    fixture.mode = "api_key";
    await page("#setting/devices");
    assert.equal(await js('document.querySelector("#devices-locked").checkVisibility()'), true);
    assert.equal(await js('document.querySelector("#managed-client-form").checkVisibility()'), false);
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    assert.equal(await js('document.querySelector("#managed-client-form").checkVisibility()'), true);
    assert.equal(await js('location.hash'), "#setting/devices");
    await page("#unknown");
    assert.equal(await js('location.hash'), "#overview");
    assert.equal(await js('document.querySelector("#sets").checkVisibility()'), true);
  });

  await test("action notifications float, replace feedback and dismiss without moving content", async () => {
    await until('document.querySelector("#message") === null');
    const contentTop = await js('document.querySelector("#overview-page").getBoundingClientRect().top');
    await js('document.querySelector("#refresh").focus(); document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#overview-page").getBoundingClientRect().top'), contentTop);
    assert.equal(await js('document.activeElement.id'), "refresh");
    assert.equal(await js('getComputedStyle(document.querySelector("#message").closest("[aria-live]")).position'), "fixed");
    assert.equal(await js(`${toastRoot}.getAttribute("role")`), "dialog");
    assert.equal(await js('document.querySelector("#message").closest("[aria-live]").getAttribute("aria-live")'), "polite");
    for (const [width, height, theme] of [[1280, 1000, "dark"], [390, 844, "light"]] as const) {
      await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelectorAll("#message").length'), 1);
      await delay(600);
      const toast = await js<{ left: number; top: number; right: number; bottom: number }>(`${toastRoot}.getBoundingClientRect().toJSON()`);
      assert.deepEqual(await iconsCentered(".toast-message"), []);
      assert.equal(await js(`(() => { const middle = rect => (rect.top + rect.bottom) / 2, text = document.querySelector(".toast-message").getBoundingClientRect(), close = ${toastRoot}.querySelector("[aria-label=Close]").getBoundingClientRect(); return Math.abs(middle(text) - middle(close)) < 1; })()`), true, "the close button is centered on the message");
      assert.equal(await js(`(() => { const text = document.querySelector(".toast-message").lastElementChild.getBoundingClientRect(), close = ${toastRoot}.querySelector("[aria-label=Close]").getBoundingClientRect(); return text.right <= close.left || text.top >= close.bottom; })()`), true, `the message keeps clear of the close button at ${width}px`);
      assert.equal(toast.left >= 0 && toast.right <= width && toast.top >= 0 && toast.bottom <= height, true, `notification fits at ${width}px: ${JSON.stringify(toast)}`);
      if (process.env.SCREENSHOT_DIR) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-notification-${width}.png`), Buffer.from(image.data, "base64"));
      }
    }
    // F6 moves focus to the notification region; Tab reaches the notification and its close button.
    await key("F6", 117);
    assert.equal(await js('document.activeElement.contains(document.querySelector("#message"))'), true);
    await key("Tab", 9);
    await key("Tab", 9);
    assert.equal(await js('document.activeElement.getAttribute("aria-label")'), "Close");
    await js('document.activeElement.click()');
    await until('document.querySelector("#message") === null');
    assert.equal(await js('document.activeElement.id'), "refresh");
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelector("#message") === null');

    fixture.mode = "api_key";
    await page();
    await js('document.querySelector("#api-key").value = "wrong"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    assert.equal(await js(`${toastRoot}.getAttribute("role")`), "alertdialog");
    assert.equal(await js(`${toastRoot}.querySelectorAll("svg").length`), 2, "the error notification has a status icon and a close icon");
    assert.equal(await js('document.querySelector("#message").getAttribute("data-tone")'), "error");
    if (process.env.SCREENSHOT_DIR) {
      await delay(250);
      const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-error-notice.png"), Buffer.from(image.data, "base64"));
    }
    await delay(5500);
    assert.match(await js('document.querySelector("#message").textContent'), /Incorrect API key/);
    await key("F6", 117);
    await key("Tab", 9);
    await key("Tab", 9);
    await js('document.activeElement.click()');
    await until('document.querySelector("#message") === null');
    assert.equal(await js('document.activeElement.id'), "api-key");
    assert.equal(browserLogs.some((entry) => /Content Security Policy|Refused to|violates/i.test(entry)), false);
  });

  await test("small screens show live status below settings across navigation and resizing", async () => {
    await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await page();
    await until('document.querySelector("#device-traffic .recharts-surface") !== null');
    assert.equal(await js('document.querySelector("#status-toggle")'), null);
    assert.equal(await js('document.querySelector("#traffic-content").checkVisibility()'), true);
    assert.equal(await js('document.querySelector("#status-view").getBoundingClientRect().top >= document.querySelector(".dashboard-main").getBoundingClientRect().bottom'), true);
    assert.equal(await js('document.querySelector("#quick-setting-title").getBoundingClientRect().top < innerHeight'), true);
    assert.equal(await js('document.querySelector("#diagnostics").checkVisibility()'), false);
    if (process.env.SCREENSHOT_DIR) {
      const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-overview-mobile-default.png"), Buffer.from(image.data, "base64"));
    }
    fixture.stats.upload_bytes = 65536;
    await until('document.querySelector("#device-traffic").textContent.includes("64 KiB")');
    await visit("explain");
    assert.equal(await js('document.querySelector(".traffic-chart")'), null);
    await visit("overview");
    assert.equal(await js('document.activeElement.id'), "page-title");
    await until('document.querySelector("#device-traffic .recharts-surface") !== null');
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#traffic-content").checkVisibility()'), true);
    await page();
    await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    await until('document.querySelectorAll(".traffic-chart").length === 2');
    await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await until('document.querySelectorAll(".traffic-chart").length === 1 && document.querySelector("#device-traffic .recharts-surface") !== null');
  });

  await test("Recharts distinguishes empty, single and zero samples and recovers after access loss", async () => {
    fixture.stats.history = {};
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelector("#device-traffic .traffic-empty") !== null');
    assert.match(await js('document.querySelector("#device-traffic .traffic-metrics").textContent'), /Upload rate—Download rate—/);
    fixture.stats.history = { upload_bytes_per_second: [0], download_bytes_per_second: [0] };
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelectorAll("#device-traffic .recharts-line-dot").length === 2');
    assert.match(await js('document.querySelector("#device-traffic .traffic-metrics").textContent'), /Upload rate0 B\/sDownload rate0 B\/s/);
    fixture.nextDeviceRead = { status: 403, started: deferred() };
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#device-traffic .recharts-surface") === null'), true);
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /Device unavailable/);
    fixture.stats.history = { upload_bytes_per_second: [1024], download_bytes_per_second: [2048] };
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelectorAll("#device-traffic .recharts-line-dot").length === 2');
    assert.match(await js('document.querySelector("#device-traffic .traffic-metrics").textContent'), /2 KiB\/s/);
  });

  await test("device statistics remain live without global administration access", async () => {
    await call("Emulation.setDeviceMetricsOverride", { width: 960, height: 1000, deviceScaleFactor: 1, mobile: false });
    fixture.mode = "api_key";
    await page();
    assert.equal(await js('document.querySelector("#global-tab").getAttribute("aria-disabled") === "true"'), true);
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /2 KiB/);
    fixture.stats.upload_bytes = 4096;
    await until('document.querySelector("#device-traffic").textContent.includes("4 KiB")');
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    assert.equal(await js('document.querySelector("#global-tab").getAttribute("aria-disabled") === "true"'), false);
    assert.match(await js('document.querySelector("#daemon-version").textContent'), /test-daemon/);
    await js('document.querySelector("#global-tab").click()');
    await until('document.querySelector("#global-traffic .recharts-surface") !== null');
    await js('document.querySelector("#logout").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-traffic .recharts-surface")'), null);
    assert.equal(await js('document.querySelector("#daemon-version").textContent'), "");
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /4 KiB/);
    assert.equal(await js('document.querySelector("#device-tab").getAttribute("aria-selected")'), "true");
  });

  await test("traffic scopes switch by keyboard and device identity appears beside access", async () => {
    await call("Emulation.setDeviceMetricsOverride", { width: 960, height: 1000, deviceScaleFactor: 1, mobile: false });
    await until('document.querySelector("#device-tab") !== null');
    assert.equal(await js('document.querySelector(".device-identity #identity").textContent'), fixture.device.source_ip);
    assert.equal(await js('document.querySelector("#device-mac").checkVisibility()'), true);
    assert.equal(await js('document.querySelector(".page-title-row #access-title").textContent'), "LAN Access");
    assert.equal(await js('document.querySelector("#refresh").textContent'), "Refresh");
    assert.match(await js('document.querySelector("#device-mac").textContent'), /02:00:00:00:00:08/);
    assert.equal(await js('document.querySelectorAll("#status-view h2").length'), 1);
    assert.equal(await js('document.querySelector("#status-view").textContent.includes("test-daemon")'), false);
    await js('document.querySelector("#device-tab").focus()');
    await key("ArrowRight", 39);
    await until('document.querySelector("#global-traffic .recharts-surface") !== null');
    assert.equal(await js('document.activeElement.id'), "global-tab");
    assert.equal(await js('document.querySelector("#device-traffic .recharts-surface")'), null);
    assert.match(await js('document.querySelector("#global-traffic .traffic-metrics").textContent'), /Active connections20/);
    fixture.stats.upload_bytes = 65536;
    await until('document.querySelector("#global-traffic").textContent.includes("64 KiB")');
    assert.equal(await js('document.activeElement.id'), "global-tab");
    await key("Home", 36);
    await until('document.querySelector("#device-traffic .recharts-surface") !== null');
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /64 KiB/);
    assert.equal(await js('document.querySelectorAll(".traffic-chart").length'), 1);
  });

  await test("late device and global reads cannot undo a refresh or logout", async () => {
    const device = { started: deferred(), release: deferred() };
    const global = { started: deferred(), release: deferred() };
    fixture.nextDeviceRead = device;
    fixture.nextGlobalRead = global;
    await Promise.all([device.started.promise, global.started.promise]);
    fixture.device.sets[0].joined = true;
    fixture.stats.upload_bytes = 16384;
    await js('document.querySelector("#refresh").click()');
    await ready();
    device.release.resolve();
    global.release.resolve();
    await delay(200);
    assert.equal(await js('document.querySelector(".set-state").textContent'), "On");
    assert.equal(await js('document.querySelector(".client-toggle [role=switch]").getAttribute("aria-checked") === "true"'), true);
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /16 KiB/);
    fixture.mode = "api_key";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-traffic .recharts-surface")'), null);
    assert.equal(await js('document.querySelector("#daemon-version").textContent'), "");
  });

  await test("Overview aggregates quick and device settings while Setting has three focused sections", async () => {
    await until('document.querySelectorAll(".traffic-chart").length === 2');
    assert.deepEqual(await js('[...document.querySelectorAll(".page-nav a")].map(link => link.textContent)'), ["Overview", "Setting"]);
    assert.equal(await js('document.querySelector("#page-title").textContent'), "Network Panel");
    assert.equal(await js('document.querySelector("#quick-selectors").checkVisibility()'), true);
    assert.equal(await js('document.querySelector("#device-setting-title").textContent'), "Device Setting");
    assert.equal(await js('document.querySelector("#device-tab")'), null, "wide screens show both scopes without tabs");
    assert.match(await js('document.querySelector("#device-traffic .traffic-metrics").textContent'), /Active connections2/);
    assert.match(await js('document.querySelector("#global-traffic .traffic-metrics").textContent'), /Active connections20/);
    assert.equal(await js('document.querySelector("#device-traffic").getBoundingClientRect().bottom < document.querySelector("#global-traffic").getBoundingClientRect().top'), true);
    await visit("devices");
    await until('document.querySelector("#managed-client-mac").checkVisibility()');
    assert.deepEqual(await js('[...document.querySelectorAll("#setting-navigation a")].map(link => link.innerText)'), ["Devices", "Selector", "Explain"]);
    assert.equal(await js('document.querySelectorAll(".traffic-chart").length'), 0);
    assert.equal(await js('document.querySelector("#managed-client-form").checkVisibility()'), true);
    await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:44"; document.querySelector("#setting-devices-tab").focus()');
    // The wide-screen sidebar uses ordinary links: Tab moves focus, Enter follows the link.
    await key("Tab", 9);
    assert.equal(await js('document.activeElement.id'), "setting-selector-tab");
    assert.equal(await js('location.hash'), "#setting/devices", "focusing a sidebar link does not activate it");
    await key("Enter", 13);
    await until('document.querySelector("#selectors").checkVisibility()');
    assert.equal(await js('location.hash'), "#setting/selector");
    assert.equal(await js('document.activeElement.id'), "setting-selector-tab");
    assert.equal(await js('document.querySelector("#managed-client-form").checkVisibility()'), false);
    await key("Tab", 9);
    await key("Enter", 13);
    await until('document.querySelector("#diagnostic-form").checkVisibility()');
    assert.equal(await js('location.hash'), "#setting/explain");
    assert.equal(await js('document.activeElement.id'), "setting-explain-tab");
    await visit("overview");
    await js(`document.querySelector('.page-nav a[href^="#setting/"]').click()`);
    assert.equal(await js('document.querySelector("#setting-explain-tab").getAttribute("aria-current")'), "page");
    await js('document.querySelector("#setting-explain-tab").focus()');
    // Narrow screens switch to tabs, where arrow keys select the focused section.
    await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await until('document.querySelector("#setting-navigation [role=tablist]") !== null');
    assert.equal(await js('document.activeElement.id'), "setting-explain-tab", "responsive navigation preserves focus");
    await key("Home", 36);
    await until('document.querySelector("#setting-devices").checkVisibility()');
    await key("ArrowRight", 39);
    await until('document.querySelector("#setting-selector").checkVisibility()');
    await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
    await until('document.querySelector("#setting-navigation .setting-sidebar") !== null');
    assert.equal(await js('document.activeElement.id'), "setting-selector-tab");
    await visit("devices");
    assert.equal(await js('document.querySelector("#managed-client-mac").value'), "02:00:00:00:00:44");
    await visit("overview");
    await until('document.querySelectorAll(".traffic-chart").length === 2');
    fixture.mode = "api_key";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelectorAll(".traffic-chart").length'), 1);
    assert.equal(await js('document.querySelector("#global-status").checkVisibility()'), false);
    assert.equal(await js('document.querySelector("#quick-selectors-locked").checkVisibility()'), true);
    await visit("selector");
    assert.equal(await js('document.querySelector("#selectors-locked").checkVisibility()'), true);
    assert.equal(await js('document.querySelectorAll(".traffic-chart").length'), 0);
  });

  await test("quick and full selectors share saved choices and clear both views after access loss", async () => {
    await openPicker("overview");
    await delay(250);
    assert.equal(await js('(() => { const menu = document.querySelector(".node-popover").getBoundingClientRect(); return [0.25, 0.5, 0.9].every(y => document.elementFromPoint(menu.left + menu.width / 2, menu.top + menu.height * y)?.closest(".node-popover") !== null); })()'), true, "the node menu paints above the following cards");
    assert.equal(await js('document.querySelector(".node-popover .test-node").checkVisibility()'), true);
    assert.equal(await js('[...document.querySelectorAll(".test-selected, .test-all")].some(button => button.checkVisibility())'), false);
    await js('document.querySelector(".node-popover .test-node").focus(); document.querySelector(".node-popover .test-node").click()');
    await ready();
    assert.deepEqual(lastRequest(), { method: "POST", path: "/api/probes", body: { outbound: "On demand", node_id: "node-0" } });
    assert.equal(fixture.requests.some(entry => entry.path.startsWith("/api/selectors/")), false, "testing a node does not change the saved choice");
    assert.equal(await js('document.querySelector("#popup-layer .node-popover") !== null'), true);
    assert.equal(await js('document.activeElement.matches(".select-node")'), true);
    assert.equal(await js('document.querySelector(".node-popover .test-node").disabled'), true, "a running test cannot be queued again");
    await js('document.querySelectorAll(".select-node")[1].click()');
    await ready();
    assert.equal(await js('document.querySelector("#quick-selectors .selected-name").textContent'), "Tokyo");
    await visit("selector");
    assert.equal(await js('document.querySelector("#selectors .selected-name").textContent'), "Tokyo");
    assert.equal(await js('document.querySelector("#selectors .test-selected").checkVisibility()'), true);
    await openPicker();
    await js('document.querySelectorAll(".select-node")[2].click()');
    await ready();
    await visit("overview");
    assert.equal(await js('document.querySelector("#quick-selectors .selected-name").textContent'), "Singapore");
    assert.deepEqual(fixture.requests.filter(entry => entry.path.startsWith("/api/selectors/")).map(entry => entry.body.node_id), ["node-1", "node-2"]);
    fixture.mode = "denied";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 0);
    assert.equal(await js('document.querySelector("#quick-access-required").textContent'), "Access denied");
    await visit("selector");
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 0);
    assert.equal(await js('document.querySelector("#access-required").textContent'), "Access denied");
  });

  await test("certificate UI requires both browser proof and interception observation", async () => {
    fixture.certificate = { name: "Test CA", fingerprint: "test-ca", mitm_test_generation: "one", mitm_test_origins: mitmOrigins };
    fixture.device.mitm = { enabled: true, override: null, default: true, ca_fingerprint: "test-ca" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    // Enabled modules start a CA test on their own; let it finish before replacing fetch.
    await until('!["pending", undefined].includes(document.querySelector("#certificate-trust-result").dataset.tone) && document.querySelector("#certificate-mitm-result").dataset.tone !== "pending"');
    // One download action lists each format; the profile opens normally for Safari to install it.
    await js('document.querySelector("#certificate-download").click()');
    await until('document.querySelector(".certificate-downloads")?.checkVisibility()');
    assert.deepEqual(await js('[...document.querySelectorAll(".certificate-downloads a")].map(link => [link.getAttribute("href"), link.hasAttribute("download")])'), [["/ca.mobileconfig", false], ["/ca.cer", true], ["/ca.pem", true]]);
    await elementShot(".device-settings", "dae-web-certificate-downloads");
    await key("Escape", 27);
    await until('!document.querySelector(".certificate-downloads")?.checkVisibility()');
    await js(`
      window.testMode = "mitm";
      const originalFetch = window.fetch;
      window.fetch = async (url, options) => {
        const address = String(url);
        const reply = data => new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
        if (address === "/api/certificate/tests") return reply({ id: "ca-challenge", ca_fingerprint: "test-ca" });
        if (address === "/api/device/mitm-tests") {
          if (testMode === "unavailable") return new Response(JSON.stringify({ error: "Certificate testing unavailable" }), { status: 503 });
          return reply({ id: "challenge", ca_fingerprint: "test-ca", mitm_enabled: testMode !== "disabled", mitm_url: "https://203.0.113.254/test/challenge" });
        }
        if (address === "/api/device/mitm-tests/challenge") return reply({ mitm_observed: testMode === "mitm" });
        if (address.startsWith("https://")) {
          if (options.credentials !== "omit" || options.redirect !== "error" || options.mode !== "cors") throw Error("unsafe challenge request");
          if (testMode === "tls-error") throw new TypeError("Failed to fetch");
          if (testMode === "bypass" && address.includes("203.0.113.254")) throw new TypeError("Failed to fetch");
          return reply(address.includes("203.0.113.254") ? { id: "challenge", ca_fingerprint: "test-ca" } : { id: "ca-challenge", ca_fingerprint: testMode === "wrong-ca" ? "other-ca" : "test-ca" });
        }
        return originalFetch(url, options);
      };
    `);
    const feedback = async (tone: string, trust: string, mitm: string) => {
      assert.deepEqual(await js('["message", "certificate-trust-result", "certificate-mitm-result"].map(id => document.getElementById(id).dataset.tone)'), [tone, trust, mitm]);
      assert.equal(await js(`(() => {
        const colors = { success: '--text-color-kumo-success', warning: '--text-color-kumo-warning', error: '--text-color-kumo-danger', neutral: '--text-color-kumo-subtle' };
        return ['certificate-trust-result', 'certificate-mitm-result'].every(id => {
          const node = document.getElementById(id), probe = document.createElement('span');
          probe.style.color = 'var(' + colors[node.dataset.tone] + ')';
          document.body.append(probe);
          const matches = getComputedStyle(node).color === getComputedStyle(probe).color;
          probe.remove(); return matches;
        });
      })()`), true, "result text uses the semantic theme colors");
      assert.equal(await js(`${toastRoot}.querySelectorAll("svg").length`), 2, "feedback includes a status icon beside the close icon");
    };
    for (const theme of ["light", "dark"] as const) {
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      await js('testMode = "mitm"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified");
      assert.equal(await js('document.querySelector("#message").textContent'), "CA trust and interception verified.");
      await feedback("success", "success", "success");
      if (process.env.SCREENSHOT_DIR) {
        await js('document.querySelector("#certificate-test-panel").scrollIntoView({ block: "center" })');
        await delay(250);
        const image = await call("Page.captureScreenshot");
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-certificate-success-${theme}.png`), Buffer.from(image.data, "base64"));
      }
      await js('testMode = "bypass"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Verification incomplete");
      assert.match(await js('document.querySelector("#message").textContent'), /interception could not be verified/);
      await feedback("warning", "success", "warning");
      if (process.env.SCREENSHOT_DIR) {
        await delay(250);
        const image = await call("Page.captureScreenshot");
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-certificate-warning-${theme}.png`), Buffer.from(image.data, "base64"));
      }
      await js('testMode = "tls-error"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "CA trust test required");
      await feedback("warning", "warning", "warning");
      await js('testMode = "disabled"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "MITM is disabled");
      assert.match(await js('document.querySelector("#message").textContent'), /MITM is disabled/);
      await feedback("success", "success", "neutral");
      await js('testMode = "unavailable"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Test unavailable");
      await feedback("error", "success", "error");
    }
    await js('testMode = "wrong-ca"; document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete");
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "CA trust test required");
    await js('testMode = "stale-generation"; document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser", "MITM generation does not determine HTTPS acceptance");
    await call("Emulation.setDeviceMetricsOverride", { width: 320, height: 568, deviceScaleFactor: 1, mobile: true });
    await until('document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "false"');
    await setDisclosure(".certificate-disclosure");
    await js('testMode = "bypass"; document.querySelector("#test-certificate").click()');
    await ready();
    await feedback("warning", "success", "warning");
    assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, "certificate results fit a narrow screen");
    if (process.env.SCREENSHOT_DIR) {
      await js('document.querySelector("#certificate-test-panel").scrollIntoView({ block: "center" })');
      await delay(250);
      const image = await call("Page.captureScreenshot");
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-certificate-warning-mobile.png"), Buffer.from(image.data, "base64"));
    }
    fixture.certificate.mitm_test_generation = "two";
    await until('document.querySelector("#certificate-mitm-result").textContent === "Not tested"');
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "CA trusted by this browser", "MITM reload preserves HTTPS result");
  });

  await test("certificate disclosure adapts to available space and preserves manual choices", async () => {
    fixture.certificate = { name: "Test CA", fingerprint: "test-ca", mitm_test_generation: "disclosure" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-name").textContent'), "Test CA");
    assert.equal(await js('document.querySelector("#certificate-fingerprint").textContent'), "test-ca");
    const resize = async (width: number, height: number, expanded: boolean) => {
      await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
      await until(`(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true") === ${expanded}`);
    };
    await resize(390, 844, false);
    await resize(844, 390, false);
    await resize(1280, 900, true);
    await js('document.querySelector(".certificate-disclosure > .disclosure-trigger").click()');
    await resize(390, 844, false);
    await resize(1280, 900, false);
    await js('document.querySelector("#refresh").click()');
    await ready();
    await visit("explain");
    await visit("overview");
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true")'), false, "manual collapse survives refresh and navigation");
    await page();
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true")'), true, "reload restores the desktop default");
    await resize(390, 844, false);
    await page();
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true")'), false, "a phone starts collapsed");
    await js('document.querySelector(".certificate-disclosure > .disclosure-trigger").focus()');
    assert.equal(await js('document.activeElement.matches(".certificate-disclosure > .disclosure-trigger")'), true);
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await until('(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true")');
    await resize(1280, 900, true);
    await resize(390, 844, true);
    await js('document.querySelector("#refresh").click()');
    await ready();
    await visit("explain");
    await visit("overview");
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true")'), true, "manual expansion survives resize, refresh and navigation");
  });

  await test("late unauthorized poll cannot erase a successful refresh", async () => {
    const read = { status: 401, started: deferred(), release: deferred() };
    fixture.nextRead = read;
    await read.started.promise;
    await js('document.querySelector("#refresh").click()');
    await ready();
    read.release.resolve();
    await delay(200);
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 4);
    assert.equal(await js('document.querySelector("#login-form").hidden'), true);
  });

  await test("late successful poll cannot undo a saved selection", async () => {
    const read = { started: deferred(), release: deferred() };
    fixture.nextRead = read;
    await read.started.promise;
    await openPicker();
    await js('document.querySelectorAll(".select-node")[1].click()');
    await ready();
    read.release.resolve();
    await delay(200);
    assert.equal(await js(`${row}.querySelector('.selected-name').textContent`), "Tokyo");
    assert.match(await js('document.querySelector("#message").textContent'), /selection saved/);
  });

  await test("live node reordering follows the API and preserves focus", async () => {
    await openPicker();
    await key("ArrowDown", 40);
    await js("window.focusedNode = document.activeElement; void 0");
    const nodes = fixture.selectors[0].nodes;
    [nodes[0], nodes[1]] = [nodes[1], nodes[0]];
    await until(`document.querySelector('.node-list .node-name').textContent === 'Tokyo'`);
    assert.equal(await js("document.activeElement === focusedNode"), true);
  });

  await test("poll failure indicator clears after recovery", async () => {
    await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await page();
    fixture.nextRead = { status: 503, started: deferred() };
    await until('document.querySelector("#updated").textContent.includes("failed")');
    assert.equal(await js('document.querySelector("#updated").checkVisibility()'), true, "refresh errors remain visible on small screens");
    await until('!document.querySelector("#updated").textContent.includes("failed")');
  });

  await test("configuration modes, large dropdown, probes and selection", async () => {
    await visit("selector");
    assert.equal(await js('document.querySelectorAll(".selector-node").length'), 0);
    for (const [i, tracked, defaults] of [[0, false, false], [1, false, true], [2, true, false], [3, true, true]]) {
      const target = `document.querySelectorAll('.selector-row')[${i}]`;
      assert.equal(await js(`${target}.querySelector('.test-selected').hidden`), tracked);
      assert.equal(await js(`${target}.querySelector('.test-all').hidden`), tracked);
      assert.equal(await js(`${target}.querySelector('.reset').hidden`), !defaults);
      assert.equal(await js(`${target}.querySelector('.selection-source').hidden`), !defaults);
    }
    await openPicker();
    assert.equal(await js('document.querySelectorAll(".selector-node").length'), 1000);
    await js(`window.searchInput = document.querySelector('.node-search input'); true`);
    await fillSearch("Tokyo");
    assert.equal(await js('document.querySelectorAll(".selector-node:not([hidden])").length'), 1);
    await js('document.querySelector(".selector-node:not([hidden]) .test-node").click()');
    await ready();
    assert.equal(await js('document.querySelector(".selector-node:not([hidden]) .node-latency").textContent'), "Testing…");
    assert.equal(await js('document.querySelector(".selector-node:not([hidden]) .node-health").textContent'), "Not tested");
    assert.equal(await js('document.querySelector(".node-search input") === searchInput && searchInput.value === "Tokyo"'), true);
    fixture.selectors[0].nodes[1].checking = false;
    fixture.selectors[0].nodes[1].tested = true;
    fixture.selectors[0].nodes[1].healthy = true;
    fixture.selectors[0].nodes[1].health = "healthy";
    await until('document.querySelector(".selector-node:not([hidden]) .node-health").textContent === "Healthy"');
    await js('document.querySelector(".selector-node:not([hidden]) .select-node").click()');
    await ready();
    await until('document.querySelectorAll(".selector-node").length === 0');
    assert.equal(await js(`${row}.querySelector('.selected-name').textContent`), "Tokyo");
    assert.equal(await js('document.activeElement.matches(".node-picker")'), true);
    await js(`${row}.querySelector('.test-all').click()`);
    await ready();
    const probes = fixture.requests.filter((entry) => entry.path === "/api/probes");
    assert.deepEqual(probes.map((entry) => entry.body), [{ outbound: "On demand", node_id: "node-1" }, { outbound: "On demand" }]);
    assert.ok(probes.every((entry) => entry.method === "POST"));
    await js('document.querySelectorAll(".selector-row")[1].querySelector(".reset").click()');
    await ready();
    assert.equal(await js('document.querySelectorAll(".selector-row")[1].querySelector(".reset").disabled'), true);
  });

  await test("a missing saved choice is visible and the current fallback can be saved explicitly", async () => {
    fixture.selectors[0].overridden = true;
    fixture.selectors[0].saved_selection = { name: "Missing Hong Kong [IPv6]", status: "missing" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js(`${row}.querySelector('.selection-source').hidden`), false);
    assert.match(await js(`${row}.querySelector('.selection-source').textContent`), /Temporary fallback/);
    assert.match(await js(`${row}.querySelector('.selection-source').title`), /Missing Hong Kong/);
    await openPicker();
    await js('document.querySelector(".select-node").click()');
    await ready();
    assert.deepEqual(lastRequest(), { method: "PUT", path: "/api/selectors/On%20demand", body: { node_id: "node-0" } });
    assert.equal(fixture.selectors[0].saved_selection?.status, "matched");
    assert.equal(await js(`${row}.querySelector('.selection-source').textContent`), "Custom");
  });

  await test("the initial selected node can be pinned without first selecting another node", async () => {
    await openPicker();
    await js('document.querySelector(".select-node").click()');
    await ready();
    assert.equal(fixture.selectors[0].saved_selection?.status, "matched");
    assert.equal(lastRequest().method, "PUT");
    const count = fixture.requests.length;
    await openPicker();
    await js('document.querySelector(".select-node").click()');
    assert.equal(fixture.requests.length, count);
  });

  await test("keyboard navigation skips disabled probe controls and preserves search editing", async () => {
    fixture.selectors[0].nodes[1].checking = true;
    await js('document.querySelector("#refresh").click()');
    await ready();
    await openPicker();
    await fillSearch("test");
    await key("Home", 36);
    assert.equal(await js('document.activeElement.matches(".node-search input")'), true);
    await js('document.querySelector(".node-search button").click()');
    assert.equal(await js('document.activeElement.matches(".node-search input") && document.activeElement.value === ""'), true);
    assert.equal(await js('document.querySelectorAll(".selector-node:not([hidden])").length'), 1000);
    await js('document.querySelector(".test-node").focus()');
    await key("ArrowDown", 40);
    assert.equal(await js('document.activeElement.closest(".selector-node").querySelector(".node-name").textContent'), "Tokyo");
    assert.equal(await js('getComputedStyle(document.activeElement).outlineStyle'), "none", "node focus does not draw a separate frame around the text");
    assert.equal(await js('(() => { const row = document.activeElement.closest(".selector-node"); const style = getComputedStyle(row); const card = row.getBoundingClientRect(); const test = row.querySelector(".test-node").getBoundingClientRect(); return style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0 && test.left > card.left && test.right < card.right && test.top > card.top && test.bottom < card.bottom; })()'), true, "the focused node frame also encloses its Test button");
    if (process.env.SCREENSHOT_DIR) {
      const image = await call("Page.captureScreenshot");
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-node-focus-frame.png"), Buffer.from(image.data, "base64"));
    }
    await key("End", 35);
    assert.match(await js('document.activeElement.querySelector(".node-name").textContent'), /^Node 999/);
    await key("Escape", 27);
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await until('document.querySelectorAll(".selector-node").length === 0');
    // The node rows unmount at once; the popover returns focus after its exit transition.
    await until('document.activeElement.matches(".node-picker")');
  });

  await test("group order, removed nodes and empty results reflect live data", async () => {
    fixture.selectors.reverse();
    await until(`${row}.dataset.group === 'Tracked default'`);
    await openPicker();
    await key("ArrowDown", 40);
    fixture.selectors[0].nodes.shift();
    await until(`document.querySelector('.node-list .node-name').textContent === 'Tokyo'`);
    assert.equal(await js('document.activeElement.matches(".node-search input")'), true);
    await fillSearch("missing node");
    assert.equal(await js('document.querySelector(".no-nodes").hidden'), false);
    await key("ArrowDown", 40);
    assert.equal(await js('document.activeElement.matches(".node-search input")'), true);
    fixture.selectors = [];
    await until('document.querySelectorAll("#selectors .selector-row").length === 0 && document.querySelector("#selectors").textContent.includes("No outbound groups")');
    assert.equal(await js('document.querySelector("#selector-count").textContent'), "0 groups");
  });

  await test("device descriptions hide configuration names but mutations use the name", async () => {
    assert.deepEqual(await js('[...document.querySelectorAll(".set-name")].map((entry) => entry.textContent)'), ["Work network", "gaming"]);
    assert.deepEqual(await js('[...document.querySelectorAll(".set-state")].map(state => state.textContent)'), ["Off", "On"]);
    await js('document.querySelector(".client-toggle [role=switch]").focus()');
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await ready();
    assert.deepEqual(fixture.requests[0], { method: "PUT", path: "/api/device/sets/internal%2Fwork", body: {} });
    assert.match(await js('document.querySelector("#message").textContent'), /Work network turned on/);
    assert.equal(await js('document.querySelector(".client-toggle [role=switch]").getAttribute("aria-label")'), "Work network");
    assert.deepEqual(await js('[...document.querySelectorAll(".client-toggle [role=switch]")].map(toggle => toggle.getAttribute("aria-checked") === "true")'), [true, true]);
    assert.deepEqual(await js('[...document.querySelectorAll(".set-state")].map(state => state.textContent)'), ["On", "On"]);
    await js('document.querySelector(".client-toggle [role=switch]").click()');
    await ready();
    assert.deepEqual(lastRequest(), { method: "DELETE", path: "/api/device/sets/internal%2Fwork", body: {} });
    assert.deepEqual(await js('[...document.querySelectorAll(".set-state")].map(state => state.textContent)'), ["Off", "On"]);
    assert.deepEqual(await js('[...document.querySelectorAll(".client-toggle [role=switch]")].map(toggle => toggle.getAttribute("aria-checked") === "true")'), [false, true]);
    // The switch's surrounding touch target toggles it once.
    const edge = await js<{ x: number; y: number }>('(() => { const rect = document.querySelector(".client-toggle").getBoundingClientRect(); return { x: rect.left + 2, y: rect.top + 2 }; })()');
    const count = fixture.requests.length;
    await call("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount: 1, ...edge });
    await call("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount: 1, ...edge });
    await ready();
    assert.deepEqual(fixture.requests.slice(count), [{ method: "PUT", path: "/api/device/sets/internal%2Fwork", body: {} }]);
    assert.equal(await js('document.querySelector(".client-toggle [role=switch]").getAttribute("aria-checked")'), "true");
  });

  await test("client routing impact is lazy and feeds a read-only target comparison", async () => {
    assert.equal(fixture.requests.length, 0);
    assert.equal(await js('document.querySelectorAll(".set-details").length'), 2);
    assert.equal(await js('document.querySelectorAll(".impact-content").length'), 0);
    await js('document.querySelector(".set-details > button").focus()');
    assert.equal(await js('document.activeElement.matches(".set-details > button")'), true);
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await until('document.querySelector(".impact-content")?.textContent.includes("Compare a target")');
    assert.deepEqual(fixture.requests[0], { method: "POST", path: "/api/device/sets/internal%2Fwork/impact", body: { joined: true, context: {} } });
    assert.equal(fixture.device.sets[0].joined, false);
    await js('document.querySelector(".impact-content .compare-target").click(); document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
    assert.equal(await js('location.hash'), "#setting/explain");
    assert.equal(await js('document.activeElement.id'), "diagnostic-target");
    await until('document.querySelector("#diagnostic-result").textContent.includes("With proposed changes")');
    const sent = lastRequest();
    assert.equal(sent.path, "/api/device/diagnostics/explain");
    assert.deepEqual(sent.body.context, {});
    assert.deepEqual(sent.body.compare?.client_sets, { "internal/work": true });
    assert.match(await js('document.querySelector("#diagnostic-result").textContent'), /kernel_direct/);
    assert.equal(await js('document.querySelectorAll("#diagnostic-result img").length'), 0);
    assert.equal(fixture.device.sets[0].joined, false);
    for (const width of [320, 1280]) {
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      assert.equal(await js('document.documentElement.scrollWidth <= innerWidth'), true, "comparison fits the viewport");
      assert.equal(await js('(() => { const [before, after] = [...document.querySelectorAll(".trace-result")].map(element => element.getBoundingClientRect()); return innerWidth >= 960 ? before.right < after.left : before.bottom < after.top; })()'), true);
      if (process.env.SCREENSHOT_DIR) {
        await js('window.scrollTo(0, 0)');
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-explanation-comparison-${width}.png`), Buffer.from(image.data, "base64"));
      }
    }
    await js('document.querySelector("#diagnostic-clear-comparison").click()');
    assert.equal(await js('document.querySelector("#diagnostic-comparison").textContent'), "Current settings");
  });

  await test("routing reference labels show policy applicability and preserve text alignment", async () => {
    const reference = { stage: "client_impact", status: "referenced", match: "unknown", reason: "client_reference" };
    fixture.impactRules = [
      { ...reference, id: "main/rules/0", section: "rules", policy: "main", policy_match: "match", parent: "main", expression: 'client("work") && dport("53") -> dnat("127.0.0.54:53")' },
      { ...reference, id: "main/0", section: "routing", policy: "main", policy_match: "match", parent: "main", expression: 'client("work") -> direct', conditions: [{ expression: 'client("work")', actual: "false", expected: "true", match: "match", status: "supplementary", reason: "membership_change" }] },
      { ...reference, id: "tor/0", section: "routing", policy: "tor", policy_match: "miss", parent: "tor", expression: `client("work") && domain(${Array.from({ length: 24 }, (_, i) => `"service-${i}.example.com"`).join(", ")}) -> proxy` },
    ];
    await setDisclosure('.set-row[data-name="internal/work"] .set-details', true);
    await until('document.querySelectorAll(".impact-content .trace-step").length === 3');
    assert.deepEqual(await js('[...document.querySelectorAll(".trace-step-badges")].map(group => [...group.children].filter(badge => !badge.matches(".trace-policy-indicator")).map(badge => badge.textContent))'), [["Referenced"], ["Referenced"], ["Referenced"]]);
    assert.deepEqual(await js('[...document.querySelectorAll(".trace-policy-indicator")].map(dot => dot.getAttribute("aria-label"))'), ["Policy: main · Applies", "Policy: main · Applies", "Policy: tor · Does not apply"]);
    await setDisclosure('.impact-content .trace-step:first-child', true);
    assert.deepEqual(await js('[...document.querySelector(".impact-content .trace-step:first-child .trace-step-meta").children].map(badge => badge.textContent)'), ["Rules", "Policy: main · Applies"]);
    await setDisclosure('.impact-content .trace-step:first-child', false);
    assert.equal(await js('document.querySelector(".impact-content").textContent.includes("Uncertain")'), false);
    const shortRule = '.impact-content .trace-step:nth-child(2)';
    const longRule = '.impact-content .trace-step:nth-child(3)';
    const geometry = () => js<{ height: number; offset: number; textHeight: number; lineHeight: number; fits: boolean; glyphTop: number; glyphBottom: number }>(`(() => {
      const button = document.querySelector(${JSON.stringify(shortRule + ' > button')}), expression = button.querySelector('.trace-expression');
      const rect = button.getBoundingClientRect(), text = expression.getBoundingClientRect(), range = document.createRange();
      range.selectNodeContents(expression);
      const glyph = range.getBoundingClientRect();
      return { height: rect.height, offset: text.top - rect.top, textHeight: text.height, lineHeight: parseFloat(getComputedStyle(expression).lineHeight), fits: expression.scrollWidth <= expression.clientWidth, glyphTop: glyph.top - text.top, glyphBottom: text.bottom - glyph.bottom };
    })()`);
    for (const width of [1280, 320]) {
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      await js('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      if (width === 1280) assert.equal(await js('(() => { const el = document.querySelector(".impact-content .trace-step:first-child .trace-expression"); return el.scrollWidth <= el.clientWidth; })()'), true, "compact metadata leaves room for the full DNAT rule");
      const before = await geometry();
      await setDisclosure(shortRule, true);
      const after = await geometry();
      // A fallback monospace font can make even this short rule wrap at 320px.
      if (before.fits) {
        assert.ok(Math.abs(after.height - before.height) < 1, "a rule that fits keeps its title height");
        assert.ok(after.textHeight < after.lineHeight * 2, "an expression that fits still occupies one line");
      } else {
        assert.ok(after.textHeight > before.textHeight, "a clipped expression wraps when expanded");
        assert.ok(Math.abs((after.height - before.height) - (after.textHeight - before.textHeight)) < 1, "the title grows by the wrapped text height");
      }
      assert.ok(Math.abs(after.offset - before.offset) < 1, "the first line keeps its vertical position");
      assert.ok(after.fits, "the expanded expression fits without horizontal overflow");
      assert.ok(after.glyphTop >= 0 && after.glyphBottom >= 0, "the text box contains the entire font height");
      assert.match(await js(`document.querySelector(${JSON.stringify(shortRule + ' .trace-step-content')}).innerText`), /rule still depends on its conditions[\s\S]*Before: false\s+After: true/);
      await setDisclosure(longRule, true);
      assert.match(await js(`document.querySelector(${JSON.stringify(longRule + ' .trace-step-content')}).innerText`), /policy is not selected.*rule cannot apply/);
      assert.equal(await js(`(() => { const el = document.querySelector(${JSON.stringify(longRule + ' .trace-expression')}); return el.scrollWidth <= el.clientWidth && el.getBoundingClientRect().height > parseFloat(getComputedStyle(el).lineHeight) * 2; })()`), true, "the long expression wraps in full");
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, "rule labels and expanded expressions fit the viewport");
      if (process.env.SCREENSHOT_DIR) {
        const rect = await js<{ x: number; y: number; width: number; height: number }>('(() => { const r = document.querySelector(".impact-content").getBoundingClientRect(); return {x:r.x + scrollX, y:r.y + scrollY, width:r.width, height:r.height}; })()');
        const image = await call("Page.captureScreenshot", { clip: { ...rect, scale: 1 }, captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-routing-references-${width}.png`), Buffer.from(image.data, "base64"));
      }
      await setDisclosure(shortRule, false);
      await setDisclosure(longRule, false);
    }
    await setDisclosure('.set-row[data-name="internal/work"] .set-details', false);
    fixture.impactRules = fixture.impactRules.map(rule => ({ ...rule, policy_match: "unknown" }));
    await setDisclosure('.set-row[data-name="internal/work"] .set-details', true);
    await until('document.querySelectorAll(".impact-content .trace-policy-indicator").length === 3');
    assert.deepEqual(await js('[...document.querySelectorAll(".trace-policy-indicator")].map(dot => dot.getAttribute("aria-label"))'), ["Policy: main · Unknown", "Policy: main · Unknown", "Policy: tor · Unknown"]);
    await setDisclosure(shortRule, true);
    assert.match(await js(`document.querySelector(${JSON.stringify(shortRule + ' .trace-step-content')}).innerText`), /ingress interface is unknown/);
  });

  await test("routing rows expand independently and retain the matching details after reordering", async () => {
    await setDisclosure('.set-row[data-name="internal/work"] .set-details', true);
    await setDisclosure('.set-row[data-name="gaming"] .set-details', true);
    await until('document.querySelectorAll(".impact-content .compare-target").length === 2');
    assert.deepEqual(fixture.requests.map(request => request.path).sort(), ["/api/device/sets/gaming/impact", "/api/device/sets/internal%2Fwork/impact"]);
    for (const width of [320, 1280]) {
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      await js('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `expanded routing details fit at ${width}px`);
      assert.equal(await js('(() => { const rows = [...document.querySelectorAll(".set-row")]; return rows.every((row, index) => { const arrow = row.querySelector(".set-details > button").getBoundingClientRect(); const toggle = row.querySelector(".client-toggle").getBoundingClientRect(); const body = row.querySelector(".impact-content").getBoundingClientRect(); return arrow.width >= 36 && arrow.height >= 36 && toggle.width >= 48 && toggle.height >= 44 && arrow.left >= toggle.right && body.top >= arrow.bottom && (!index || row.getBoundingClientRect().top >= rows[index - 1].getBoundingClientRect().bottom); }); })()'), true, "arrows and switches stay separate, with details below their own row");
      if (process.env.SCREENSHOT_DIR) {
        await js('document.querySelector("#device-title").scrollIntoView()');
        const image = await call("Page.captureScreenshot");
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-routing-details-${width}.png`), Buffer.from(image.data, "base64"));
      }
    }
    await setDisclosure('.set-row[data-name="internal/work"] .set-details', false);
    fixture.device.sets.reverse();
    await js('document.querySelector("#refresh").click()');
    await ready();
    await until('document.querySelector(".set-row[data-name=gaming] .impact-content")?.textContent.includes("Change: On → Off")');
    assert.equal(await js('document.querySelectorAll(".impact-content").length'), 1);
    assert.equal(await js('document.querySelector(".set-row").dataset.name'), "gaming");
    assert.equal(await js('document.querySelector(".set-row[data-name=gaming] .client-toggle [role=switch]").getAttribute("aria-checked") === "true"'), true);
  });

  await test("closing a routing row discards its late reply without affecting another row", async () => {
    const held = { started: deferred(), release: deferred() };
    fixture.nextImpact = held;
    try {
      await setDisclosure('.set-row[data-name="internal/work"] .set-details', true);
      await held.started.promise;
      await setDisclosure('.set-row[data-name="internal/work"] .set-details', false);
      await setDisclosure('.set-row[data-name="gaming"] .set-details', true);
      await until('document.querySelector(".impact-content").textContent.includes("Change: On → Off")');
      assert.equal(lastRequest().path, "/api/device/sets/gaming/impact");
      held.release.resolve();
      await delay(100);
      assert.equal(await js('document.querySelectorAll(".impact-content").length'), 1);
      assert.equal(await js('document.querySelector(".set-row[data-name=gaming] .client-toggle [role=switch]").getAttribute("aria-checked") === "true"'), true);
      assert.match(await js('document.querySelector(".impact-content").textContent'), /Change: On → Off/);
      await js('document.querySelector(".impact-content .compare-target").click()');
      assert.equal(await js('document.querySelector("#diagnostic-comparison").textContent'), "Leave gaming");
      await setDisclosure('.set-row[data-name="gaming"] .set-details', false);
      await until('document.querySelector(".impact-content") === null');
    } finally { held.release.resolve(); }
  });

  await test("diagnostics summarize missing context and make cached IPs actionable without a rule wall", async () => {
    fixture.explanation = {
      schema: 1, generation: 7, observed_at: "2026-10-09T00:00:00Z",
      context: [{ name: "source_ip", value: fixture.device.source_ip, source: "device" }],
      current: {
        decision: { complete: false, verdict: "unknown", policy: "main", original_target: "example.com:443", targets: [...Array.from({ length: 90 }, (_, i) => `198.51.100.${i + 1}:443`), "[2001:db8::1]:443"], mark: 0, must: false, missing: ["destination.ip", "domain_mapping"] },
        steps: Array.from({ length: 120 }, (_, i) => ({ id: `rule/${i}`, stage: "kernel", expression: `dip(${"198.51.100.0/24, ".repeat(40)}) -> proxy`, status: i < 60 ? "conditional" : "inactive", match: "unknown", reason: i < 60 ? "missing_context" : "different_ingress_policy" })),
        domains: [], outbounds: [], notes: [],
      },
    };
    await visit("explain");
    await js('document.querySelector("#diagnostic-target").value = "https://example.com"; document.querySelector("#diagnostic-form").requestSubmit()');
    await until('document.querySelector(".trace-missing") !== null');
    assert.equal(await js('document.querySelector(".trace-outcome h3").textContent'), "Destination IP needed");
    assert.deepEqual(await iconsCentered(".trace-outcome h3"), []);
    assert.match(await js('document.querySelector(".trace-missing").textContent'), /Entering a hostname or SNI does not create a mapping/);
    assert.equal((await optionLabels(".trace-candidates [data-kumo-part=trigger]")).length, 90, "exclude IPv6 candidates for the inherited IPv4 identity");
    assert.equal(await js('document.querySelector(".check-candidate").disabled'), true);
    assert.equal(await js('document.querySelectorAll(".explanation .disclosure-trigger[aria-expanded=true]").length === 0'), true);
    assert.equal(await js('document.querySelector(".trace-outcome").textContent.includes("198.51.100.89")'), false, "large candidate lists are summarized");
    for (const [width, theme] of [[320, "light"], [390, "dark"], [768, "light"], [1280, "dark"], [1920, "dark"]] as const) {
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      assert.equal(await js('document.documentElement.scrollWidth <= innerWidth'), true, `explanation fits ${width}px`);
      if (width === 320) {
        const longHeight = await js<number>('document.querySelector(".explanation").getBoundingClientRect().height');
        const allSteps = fixture.explanation.current.steps;
        fixture.explanation.current.steps = allSteps.slice(0, 1);
        await js('document.querySelector("#diagnostic-form").requestSubmit()');
        await until('document.querySelector(".trace-rule-list .count")?.textContent === "1 rule"');
        const shortHeight = await js<number>('document.querySelector(".explanation").getBoundingClientRect().height');
        assert.ok(Math.abs(longHeight - shortHeight) < 2, "120 rules take no more default reading space than one rule");
        fixture.explanation.current.steps = allSteps;
        await js('document.querySelector("#diagnostic-form").requestSubmit()');
        await until('document.querySelector(".trace-rule-list .count")?.textContent === "120 rules"');
      }
      if (process.env.SCREENSHOT_DIR) {
        await js('window.scrollTo(0, 0)');
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-explanation-missing-${width}.png`), Buffer.from(image.data, "base64"));
      }
    }
    await setDisclosure(".trace-rule-list");
    await choose(".trace-filter [data-kumo-part=trigger]", "Uncertain (60)");
    assert.equal(await js('document.querySelectorAll(".trace-steps > .trace-step").length'), 60);
    await setDisclosure(".trace-steps .trace-step");
    assert.match(await js('document.querySelector(".trace-step p").textContent'), /More information/);
    assert.equal(await js('document.documentElement.scrollWidth <= innerWidth'), true);
    await js('document.querySelector(".trace-missing button").click()');
    assert.equal(await js('document.activeElement.id'), "diagnostic-ip");
    fixture.explanation = null;
    await choose(".trace-candidates [data-kumo-part=trigger]", "198.51.100.8");
    await js('document.querySelector(".check-candidate").click()');
    await until('document.querySelector(".trace-outcome h3")?.textContent === "Direct in the kernel"');
    assert.equal(lastRequest().body.flow?.destination.ip, "198.51.100.8");
    assert.equal(lastRequest().body.flow?.http?.url, "https://example.com");
    assert.equal(await js('document.querySelector("#diagnostic-ip").value'), "198.51.100.8");
    assert.equal(await js('document.querySelectorAll("#diagnostic-result img").length'), 0);
    await js('document.querySelector("#diagnostic-target").value = "other.example:443"; document.querySelector("#diagnostic-target").dispatchEvent(new Event("input", { bubbles: true }))');
    assert.equal(await js('document.querySelector("#diagnostic-result").textContent'), "", "editing inputs invalidates the previous conclusion");
    assert.equal(await js('document.querySelector("#diagnostic-ip").value'), "", "a cached IP for one hostname must not carry over to another target");
  });

  await test("diagnostics distinguish kernel direct, userspace direct, blocked and incomplete decisions", async () => {
    await visit("explain");
    await js('document.querySelector("#diagnostic-target").value = "https://198.51.100.10/"');
    for (const [verdict, outbound, complete, headline] of [
      ["kernel_direct", "direct", true, "Direct in the kernel"],
      ["userspace", "direct", true, "Direct through userspace"],
      ["userspace", "proxy", true, "Routed via proxy"],
      ["drop", "block", true, "Connection blocked"],
      ["local_response", "", true, "Answered locally"],
      ["userspace", "direct", false, "Cannot determine the result yet"],
    ] as const) {
      fixture.explanation = { schema: 1, generation: 7, observed_at: "2026-10-09T00:00:00Z", context: [], current: {
        decision: { verdict, outbound, complete, policy: "main", rule_id: "kernel/1", targets: ["198.51.100.10:443"], capture: verdict === "userspace" ? ["http"] : [], mark: 42, must: true },
        steps: [{ id: "kernel/1", stage: "kernel", expression: `dip(198.51.100.10) -> ${outbound || "direct"}`, status: "selected", match: "match", reason: "terminal_decision" }], domains: [], outbounds: [], notes: complete ? [] : ["A plugin requires runtime execution or additional context; subsequent routing is undetermined."],
      } };
      await js('document.querySelector("#diagnostic-form").requestSubmit()');
      await until('document.querySelector(".trace-outcome h3") !== null');
      assert.equal(await js('document.querySelector(".trace-outcome h3").textContent'), headline);
      assert.equal(lastRequest().body.flow?.destination.ip, "198.51.100.10", "IP URLs keep the destination address");
      assert.match(await js('document.querySelector(".trace-technical").textContent'), /Mark42Musttrue/);
      if (!complete) {
        assert.match(await js('document.querySelector(".trace-facts").textContent'), /provisional/);
        assert.equal(await js('document.querySelector(".trace-selected")'), null);
      }
      if (process.env.SCREENSHOT_DIR && verdict === "userspace" && outbound === "proxy") {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-explanation-route-1280.png"), Buffer.from(image.data, "base64"));
      }
    }
  });

  await test("diagnostics use analysis-specific summaries for domain, outbound and plugin checks", async () => {
    await visit("explain");
    const cases: [string, string, Partial<FixtureResult>, string][] = [
      ["domain", "example.com", { domains: [{ domain: "example.com", ip: "198.51.100.10", resident: true, source: "dns" }, { domain: "example.com", ip: "198.51.100.11", resident: false, source: "dns" }] }, "2 cached domain records"],
      ["outbound", "proxy", { outbounds: [{ name: "proxy", policy: "fixed", network: "tcp4", available: true, random: false, nodes: [{ name: "Tokyo", selected: true, usable: true, reason: "selected" }] }] }, "Selected node: Tokyo"],
      ["plugins", "https://example.com", { steps: [{ id: "http/disabled", stage: "mitm", expression: "HTTP interception", status: "inactive", match: "miss", reason: "http_disabled" }] }, "HTTP interception is disabled."],
      ["dns", "example.com", {}, "DNS policy evaluated"],
    ];
    for (const [kind, value, extra, headline] of cases) {
      fixture.explanation = { schema: 1, generation: 7, observed_at: "2026-10-09T00:00:00Z", context: [], current: {
        decision: { complete: true, verdict: "analysis", mark: 0, must: false }, steps: [], domains: [], outbounds: [], notes: [], ...extra,
      } };
      await choose("#diagnostic-kind", { domain: "Cached domain records", outbound: "Outbound nodes", plugins: "HTTP plugins", dns: "DNS policy" }[kind]!);
      await js(`document.querySelector("#diagnostic-target").value = ${JSON.stringify(value)}; document.querySelector("#diagnostic-form").requestSubmit()`);
      await until('document.querySelector(".trace-outcome h3") !== null');
      assert.equal(await js('document.querySelector(".trace-outcome h3").textContent'), headline);
      if (kind === "domain") assert.match(await js('document.querySelector(".trace-facts").textContent'), /Present in kernel1/);
      if (kind === "outbound") assert.match(await js('document.querySelector(".trace-facts").textContent'), /Groupproxy/);
    }
  });

  await test("React diagnostics keep context reads independent and reject outdated explanations", async () => {
    await visit("explain");
    const held = { started: deferred(), release: deferred() };
    fixture.nextExplanation = held;
    try {
      await js('document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
      await held.started.promise;
      await setDisclosure(".diagnostic-advanced");
      await js('document.querySelector("#diagnostic-context").click()');
      await until('document.querySelector("#diagnostic-context-view").textContent.includes("[request]")');
      assert.equal(await js('document.querySelector("#diagnostic-run").disabled'), true);
      await choose("#diagnostic-kind", "DNS policy");
      await until('!document.querySelector("#diagnostic-run").disabled');
      await js('document.querySelector("#diagnostic-target").value = "example.com"; document.querySelector("#diagnostic-form").requestSubmit()');
      await until('document.querySelector("#diagnostic-result").textContent.includes("Analysis: dns")');
      held.release.resolve();
      await delay(100);
      assert.equal(await js('document.querySelector("#diagnostic-result").textContent.includes("Analysis: flow")'), false);
      assert.equal(await js('document.querySelector("#diagnostic-run").disabled'), false);
      assert.equal(await js('document.querySelector("#diagnostic-target").value'), "example.com");
    } finally { held.release.resolve(); }
  });

  await test("React diagnostics invalidate completed and pending results after runtime changes", async () => {
    await visit("explain");
    for (const change of ["mitm", "generation", "managed"] as const) {
      await js('document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
      await until('document.querySelector("#diagnostic-result").textContent.includes("Analysis: flow")');
      const apply = async () => {
        if (change === "mitm") fixture.device.mitm = { enabled: !fixture.device.mitm?.enabled, override: null, default: !fixture.device.mitm?.enabled, ca_fingerprint: "test-ca" };
        else if (change === "generation") fixture.generation = (fixture.generation ?? 7) + 1;
        else {
          await visit("devices");
          await until('document.querySelector("#managed-client-mac").checkVisibility()');
          await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:99"; document.querySelector("#managed-client-form button[value=show]").click()');
          await until('document.querySelector("#managed-set-0") !== null');
          const joined = await js<string>('document.querySelector("#managed-set-0").getAttribute("aria-checked")');
          await js('document.querySelector("#managed-set-0").click()');
          await until(`document.querySelector("#managed-set-0")?.getAttribute("aria-checked") === "${joined === "true" ? "false" : "true"}" && !document.querySelector("#managed-client-result").ariaBusy?.includes("true")`);
          await visit("explain");
          return;
        }
        await js('document.querySelector("#refresh").click()');
        await ready();
      };
      await apply();
      await until('document.querySelector("#diagnostic-result").textContent === ""');
      const held = { started: deferred(), release: deferred() };
      fixture.nextExplanation = held;
      try {
        await js('document.querySelector("#diagnostic-form").requestSubmit()');
        await held.started.promise;
        await apply();
        held.release.resolve();
        await delay(100);
        assert.equal(await js('document.querySelector("#diagnostic-result").textContent'), "");
        assert.equal(await js('document.querySelector("#diagnostic-run").disabled'), false);
      } finally { held.release.resolve(); }
    }
  });

  await test("React diagnostics clear manual work and ignore late errors after access loss", async () => {
    await visit("explain");
    await setDisclosure(".diagnostic-advanced");
    await choose("#diagnostic-scope", "Custom identity");
    const held = { status: 500, started: deferred(), release: deferred() };
    fixture.nextExplanation = held;
    try {
      await js('document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
      await held.started.promise;
      assert.equal(lastRequest().path, "/api/diagnostics/explain");
      fixture.mode = "denied";
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelector("#diagnostic-form")'), null);
      assert.equal(await js('document.querySelector("#setting-explain-tab")'), null);
      assert.match(await js('document.querySelector("#diagnostic-view").textContent'), /Administrator access required/);
      held.release.resolve();
      await delay(100);
      assert.equal(await js('document.querySelector("#diagnostic-result")'), null);
    } finally { held.release.resolve(); }
  });

  await test("LAN guests retain device controls without diagnostic entry points", async () => {
    fixture.mode = "api_key";
    await page("#setting/explain");
    assert.equal(await js('document.querySelector("#diagnostic-form")'), null);
    assert.equal(await js('document.querySelector("#setting-explain-tab")'), null);
    assert.match(await js('document.querySelector("#diagnostic-view").textContent'), /Administrator access required/);
    await visit("overview");
    assert.equal(await js('document.querySelectorAll("#sets .client-toggle").length'), 2);
    assert.equal(await js('document.querySelectorAll("#sets .set-details").length'), 0);
    assert.equal(await js('document.querySelector("#device-traffic").checkVisibility()'), true);
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    await until('document.querySelector("#access-title").textContent === "Administrator"');
    assert.equal(await js('document.querySelectorAll("#sets .set-details").length'), 2);
    await visit("explain");
    assert.equal(await js('document.querySelector("#diagnostic-form").checkVisibility()'), true);
  });

  await test("logout discards pending current-device explanations and routing impact", async () => {
    fixture.mode = "api_key";
    await page();
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    await until('document.querySelector("#access-title").textContent === "Administrator"');
    const explanation = { started: deferred(), release: deferred() }, impact = { started: deferred(), release: deferred() };
    fixture.nextImpact = impact;
    fixture.nextExplanation = explanation;
    try {
      await setDisclosure('.set-row[data-name="internal/work"] .set-details', true);
      await impact.started.promise;
      await visit("explain");
      await js('document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
      await explanation.started.promise;
      assert.equal(lastRequest().path, "/api/device/diagnostics/explain");
      await js('document.querySelector("#logout").click()');
      await ready();
      assert.equal(await js('document.querySelector("#diagnostic-form")'), null);
      assert.equal(await js('document.querySelectorAll("#sets .set-details").length'), 0);
      explanation.release.resolve(); impact.release.resolve();
      await delay(100);
      assert.equal(await js('document.querySelector("#diagnostic-result")'), null);
      assert.equal(await js('document.querySelector(".impact-content")'), null);
      await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
      await ready();
      await until('document.querySelector("#diagnostic-form") !== null');
      assert.equal(await js('document.querySelector("#diagnostic-result").textContent'), "");
      assert.equal(await js('document.querySelector(".impact-content")'), null);
    } finally { explanation.release.resolve(); impact.release.resolve(); }
  });

  await test("React client impact reloads changed membership and discards the old response", async () => {
    const held = { started: deferred(), release: deferred() };
    fixture.nextImpact = held;
    try {
      await setDisclosure('.set-row[data-name="internal/work"] .set-details', true);
      await held.started.promise;
      fixture.device.sets[0].joined = true;
      await js('document.querySelector("#refresh").click()');
      await ready();
      await until('document.querySelector(".impact-content").textContent.includes("Change: On → Off")');
      held.release.resolve();
      await delay(100);
      assert.match(await js('document.querySelector(".impact-content").textContent'), /Change: On → Off/);
      await js('document.querySelector(".impact-content .compare-target").click()');
      assert.equal(await js('document.querySelector("#diagnostic-comparison").textContent'), "Leave Work network");
      fixture.device.mac = "02:00:00:00:00:09";
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelector(".set-details > .disclosure-trigger").getAttribute("aria-expanded")'), "false");
      assert.equal(await js('document.querySelector("#diagnostic-comparison").textContent'), "Current settings");
    } finally { held.release.resolve(); }
  });

  await test("React managed devices cannot restore data after access is revoked", async () => {
    await visit("devices");
    await js('document.querySelector("#setting-devices-tab").click()');
    await until('document.querySelector("#managed-client-mac").checkVisibility()');
    const held = { started: deferred(), release: deferred() };
    fixture.nextManagedDevice = held;
    try {
      await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:99"; document.querySelector("#managed-client-form button[value=show]").click()');
      await held.started.promise;
      fixture.mode = "denied";
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelector("#managed-clients").hidden'), true);
      held.release.resolve();
      await delay(100);
      assert.equal(await js('document.querySelector("#managed-client-result").textContent'), "");
      fixture.mode = "lan";
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelector("#managed-client-result").textContent'), "");
      assert.equal(await js('document.querySelector("#managed-clients").checkVisibility()'), true);
    } finally { held.release.resolve(); }
  });

  await test("actions restore keyboard focus after disabling or replacing controls", async () => {
    await openPicker();
    await js('document.querySelector(".test-node").focus(); document.querySelector(".test-node").click()');
    await ready();
    assert.equal(await js('document.querySelector(".node-popover").contains(document.activeElement)'), true, "Probe lost focus outside the popup");
    await key("Escape", 27);
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await visit("overview");
    await js('document.querySelector(".client-toggle [role=switch]").focus(); document.querySelector(".client-toggle [role=switch]").click()');
    await ready();
    assert.equal(await js('document.activeElement.getAttribute("aria-label")'), "Work network");
    fixture.device.mitm = { enabled: false, override: null, default: false, ca_fingerprint: "test-ca" };
    await js('document.querySelector("#refresh").focus(); document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.activeElement.id'), "refresh");
    // The router default is one of three choices and shows its current value.
    assert.equal(await js('document.querySelector("#mitm-choice").textContent'), "Router default (Off)");
    assert.deepEqual(await optionLabels("#mitm-choice"), ["Router default (Off)", "On", "Off"]);
    await choose("#mitm-choice", "On");
    await ready();
    assert.deepEqual(lastRequest(), { method: "PUT", path: "/api/device/mitm", body: { enabled: true } });
    assert.equal(await js('document.activeElement.id'), "mitm-choice");
    assert.match(await js('document.querySelector("#message").textContent'), /HTTPS modules turned on/);
    await choose("#mitm-choice", "Router default (Off)");
    await ready();
    assert.deepEqual(lastRequest(), { method: "DELETE", path: "/api/device/mitm", body: {} });
    assert.equal(await js('document.activeElement.id'), "mitm-choice");
    assert.equal(fixture.device.mitm.override, null);
  });

  await test("administrator device management uses the specified MAC", async () => {
    fixture.certificate = { name: "Test CA", fingerprint: "test-ca" };
    await visit("devices");
    await js('document.querySelector("#setting-devices-tab").click()');
    await until('document.querySelector("#managed-client-mac").checkVisibility()');
    await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:99"; document.querySelector("#managed-client-form button[value=show]").click()');
    await until('document.querySelector("#managed-set-0") !== null');
    await elementShot("#managed-clients", "dae-web-managed-device");
    assert.deepEqual(await js('[document.querySelector("#managed-set-0").getAttribute("aria-checked"), document.querySelector(".managed-set-state").textContent, document.querySelector("#managed-mitm-choice").textContent]'), ["false", "Off", "Router default"]);
    // A membership switch saves for the specified MAC and keeps focus on the switch.
    await js('document.querySelector("#managed-set-0").focus(); document.querySelector("#managed-set-0").click()');
    await until('document.querySelector("#managed-set-0").getAttribute("aria-checked") === "true" && document.querySelector("#managed-client-result").getAttribute("aria-busy") === "false"');
    assert.deepEqual(lastRequest(), { method: "PUT", path: "/api/clients/internal%2Fwork/members/02%3A00%3A00%3A00%3A00%3A99", body: {} });
    assert.equal(fixture.device.sets[0].joined, false, "this device's own membership is unchanged");
    assert.equal(await js('document.activeElement.id'), "managed-set-0");
    assert.equal(await js('document.querySelector(".managed-set-state").textContent'), "On");
    await js('document.querySelector("#managed-set-0").click()');
    await until('document.querySelector("#managed-set-0").getAttribute("aria-checked") === "false" && document.querySelector("#managed-client-result").getAttribute("aria-busy") === "false"');
    assert.deepEqual(lastRequest(), { method: "DELETE", path: "/api/clients/internal%2Fwork/members/02%3A00%3A00%3A00%3A00%3A99", body: {} });
    // The HTTPS module choice sets or clears the device override with the CA fingerprint.
    await choose("#managed-mitm-choice", "On");
    await until('document.querySelector("#managed-client-result").getAttribute("aria-busy") === "false"');
    assert.deepEqual(lastRequest(), { method: "PUT", path: "/api/devices/02%3A00%3A00%3A00%3A00%3A99/mitm", body: { enabled: true } });
    assert.equal(fixture.managed?.mitm_override, true);
    assert.equal(await js('document.activeElement.id'), "managed-mitm-choice");
    await choose("#managed-mitm-choice", "Router default");
    await until('document.querySelector("#managed-client-result").getAttribute("aria-busy") === "false"');
    assert.deepEqual(lastRequest(), { method: "DELETE", path: "/api/devices/02%3A00%3A00%3A00%3A00%3A99/mitm", body: {} });
    assert.equal(fixture.managed?.mitm_override, null);
    await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:98"; document.querySelector("#managed-client-mac").dispatchEvent(new Event("input", { bubbles: true }))');
    assert.equal(await js('document.querySelector("#managed-client-result").textContent'), "", "editing the MAC cannot leave another device's settings visible");
    fixture.mode = "denied";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#managed-clients").hidden'), true);
    assert.equal(await js('document.querySelector("#managed-client-result").textContent'), "");
  });

  await test("cookie login, expired session and delayed reads after logout", async () => {
    fixture.mode = "api_key";
    await page();
    assert.equal(await js('document.querySelector("#login-form").hidden'), false);
    for (const width of [320, 1280]) {
      await call("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
      await page();
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `guest controls fit at ${width}px`);
      assert.equal(await js('[...document.querySelectorAll("#login-form input, #login-form button")].every(element => { const rect = element.getBoundingClientRect(); return rect.width > 0 && rect.left >= 0 && rect.right <= document.documentElement.clientWidth; })'), true);
      if (process.env.SCREENSHOT_DIR) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-login-${width}.png`), Buffer.from(image.data, "base64"));
      }
    }
    await js('document.querySelector("#api-key").value = "wrong"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    assert.equal(await js('document.querySelector("#message").dataset.tone'), "error");
    assert.equal(await js('document.activeElement.id'), "api-key");
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    assert.equal(await js('document.querySelector("#access-title").textContent'), "Administrator");
    assert.equal(await js('document.querySelector("#api-key").value'), "");
    assert.equal(await js('document.activeElement.id'), "refresh");
    await page();
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 4);
    const read = { started: deferred(), release: deferred() };
    fixture.nextRead = read;
    await read.started.promise;
    await js('document.querySelector("#logout").click()');
    await ready();
    read.release.resolve();
    await delay(200);
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 0);
    assert.equal(await js('document.querySelector("#login-form").hidden'), false);
    assert.equal(await js('document.activeElement.id'), "api-key");
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    await call("Network.clearBrowserCookies");
    await until('document.querySelector("#updated").textContent === "Login required"');
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 0);
    assert.equal(await js('document.querySelector("#selectors-locked").hidden'), false);
  });

  await test("forbidden LAN access is not presented as a missing login", async () => {
    fixture.mode = "denied";
    await page();
    assert.equal(await js('document.querySelector("#access-description").textContent'), "Direct LAN access required");
    assert.equal(await js('document.querySelector("#access-required").textContent'), "Access denied");
    assert.equal(await js('document.querySelector("#selector-count").textContent'), "Access denied");
    assert.equal(await js('document.querySelectorAll(".selector-row").length'), 0);
  });

  await test("network timeout releases the controls", async () => {
    const read = { started: deferred(), release: deferred() };
    fixture.nextRead = read;
    await js('const timeout = AbortSignal.timeout; AbortSignal.timeout = () => timeout(50); document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#message").dataset.tone'), "error");
    read.release.resolve();
  });

  await test("expanded outbound details preserve focus and scrolling across polls", async () => {
    fixture.groups = [
      { name: "proxy_jp", policy: "min_moving_avg", health: "healthy", connectivity: "available", stats: fixture.stats, nodes: Array.from({ length: 80 }, (_, index) => ({
        name: `Japan premium dedicated connection ${index + 1} → lightsail [IPv6]`, checks_connectivity: true, healthy: true, health: "healthy", stats: { active_connections: 0 },
      })) },
      { name: "direct", target_kind: "builtin", health: "healthy", stats: fixture.stats, nodes: [] },
    ];
    await call("Emulation.setDeviceMetricsOverride", { width: 1366, height: 1000, deviceScaleFactor: 1, mobile: false });
    await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
    await js('document.querySelector("#refresh").click()');
    await ready();
    await setDisclosure("#global-traffic .outbounds-section");
    assert.deepEqual(await js('[...document.querySelectorAll("#global-traffic .status-sections > .status-section > .disclosure-trigger .disclosure-title")].map(label => label.textContent)'), ["Connection statistics", "Outbounds", "Domain Tables", "Plugins"]);
    assert.equal(await js('document.querySelector("#global-traffic .connection-details > .disclosure-trigger").getAttribute("aria-expanded")'), "false", "outbounds open independently of connection totals");
    assert.equal(await js('document.querySelectorAll("#global-groups .status-nodes li").length'), 0);
    await js('window.openGroup = document.querySelector("#global-groups .status-entry"); openGroup.querySelector(".disclosure-trigger").click(); openGroup.querySelector(".disclosure-trigger").focus()');
    await until('openGroup.querySelectorAll(".status-nodes li").length === 80');
    assert.equal(await js('(() => { const list = document.querySelector("#global-groups .status-nodes"); return list.scrollHeight > list.clientHeight && list.clientHeight <= 320; })()'), true);
    assert.equal(await js('(() => { const device = document.querySelector("#device-status").getBoundingClientRect(); const global = document.querySelector("#global-status").getBoundingClientRect(); return device.bottom < global.top && device.left === global.left; })()'), true);
    await js('document.querySelector("#global-groups .status-nodes").scrollTop = 120');
    fixture.groups[0].nodes[0].health = "unknown";
    fixture.groups[0].nodes[1].health = "confirming";
    await until('openGroup.querySelectorAll(".status-node-state")[0].textContent === "Not tested"');
    assert.equal(await js('openGroup.querySelectorAll(".status-node-state")[1].textContent'), "Confirming failure");
    fixture.groups[0].nodes[20].stats.active_connections = 41;
    await until('openGroup.querySelectorAll(".status-nodes li")[20].textContent.includes("41 active")');
    assert.equal(await js('(openGroup.querySelector(".disclosure-trigger").getAttribute("aria-expanded") === "true") && document.activeElement === openGroup.querySelector(".disclosure-trigger")'), true);
    assert.equal(await js('document.querySelector("#global-groups .status-nodes").scrollTop'), 120);
    if (process.env.SCREENSHOT_DIR) {
      await js('document.querySelector("#global-groups .status-nodes").scrollTop = 0; window.scrollTo(0, 0)');
      const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-expanded-status.png"), Buffer.from(image.data, "base64"));
    }
    fixture.groups.reverse();
    await until('document.querySelector("#global-groups").firstElementChild.dataset.name === "direct"');
    assert.equal(await js('openGroup.isConnected && (openGroup.querySelector(".disclosure-trigger").getAttribute("aria-expanded") === "true") && document.activeElement === openGroup.querySelector(".disclosure-trigger")'), true);
    fixture.mode = "api_key";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-groups")'), null);
  });

  await test("responsive layouts and dark mode keep the popup usable", async () => {
    const checkNodeActions = async (view: string, width: number, height: number) => {
      assert.equal(await js('document.querySelector(".test-node").checkVisibility()'), true, `${view} exposes node testing`);
      assert.equal(await js('(() => { const row = document.querySelector(".selector-node"); const card = row.getBoundingClientRect(); const choice = row.querySelector(".select-node").getBoundingClientRect(); const test = row.querySelector(".test-node").getBoundingClientRect(); return Math.abs((card.top + card.bottom) / 2 - (test.top + test.bottom) / 2) <= 1 && test.top > card.top && test.bottom < card.bottom && test.right < card.right && choice.right <= test.left; })()'), true, `${view} centers the inset Test button without overlapping node selection at ${width}px`);
      assert.equal(await js('(() => { const test = document.querySelector(".test-node").getBoundingClientRect(); return test.width >= 64 && test.height >= 36; })()'), true, `${view} provides a Test target at Kumo control height at ${width}px`);
      if (width === 1280 && height === 960) {
        await call("Input.dispatchMouseEvent", { type: "mouseMoved", x: 0, y: 0 });
        const resting = await js('getComputedStyle(document.querySelector(".selector-node[data-node=node-1]")).backgroundColor');
        const point = await js<{ x: number; y: number }>('(() => { const choice = document.querySelector(".selector-node[data-node=node-1] .select-node"); choice.scrollIntoView({ block: "nearest" }); const rect = choice.getBoundingClientRect(); return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 }; })()');
        await call("Input.dispatchMouseEvent", { type: "mouseMoved", ...point });
        await until('document.querySelector(".selector-node[data-node=node-1] .select-node").matches(":hover")');
        assert.notEqual(await js('getComputedStyle(document.querySelector(".selector-node[data-node=node-1]")).backgroundColor'), resting, `${view} highlights the whole hovered row`);
        assert.deepEqual(await js('(() => { const style = getComputedStyle(document.querySelector(".selector-node[data-node=node-1] .select-node")); return [style.backgroundColor, style.backgroundImage]; })()'), ["rgba(0, 0, 0, 0)", "none"], `${view} has no separate partial highlight over the row`);
      }
      if (process.env.SCREENSHOT_DIR && (width === 320 && height === 568 || width === 1280 && height === 960)) {
        const image = await call("Page.captureScreenshot");
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-node-actions-${view}-${width}.png`), Buffer.from(image.data, "base64"));
      }
    };
    fixture.groups = statusGroups(fixture.stats);
    fixture.tables = [{ name: "resolved_domains", used: 128, limit: 4096 }];
    fixture.plugins = [{ id: "request_rules", type: "http", state: "ready" }];
    fixture.certificate = { name: "Test CA", fingerprint: "12:34:56:78:".repeat(7) + "12:34:56:78", mitm_test_generation: "layout" };
    fixture.device.mitm = { enabled: false, override: null, default: false, ca_fingerprint: fixture.certificate.fingerprint };
    fixture.selectors[0].name = "Long outbound group name · " + "subscription ".repeat(6);
    fixture.stats.history = {
      upload_bytes_per_second: [300, 500, 420, 1200, 850, 640, 760, 400, 1400, 1100, 900, 700].map(value => value * 1024),
      download_bytes_per_second: [1600, 2400, 1800, 3800, 2900, 3200, 2500, 4100, 3500, 2400, 3000, 3600].map(value => value * 1024),
    };
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true")'), true);
    await delay(250);
    await js(`${toastRoot}?.querySelector("[aria-label=Close]").click()`);
    await until('document.querySelector("#message") === null');
    const viewports: [number, number, "light" | "dark"][] = [
      // Phones, including a short viewport while a keyboard is open.
      [320, 568, "light"], [360, 800, "dark"], [390, 844, "light"], [430, 932, "dark"], [390, 220, "dark"], [844, 390, "dark"],
      // Square windows, foldable screens and portrait tablets.
      [600, 600, "light"], [768, 768, "dark"], [960, 900, "light"], [1024, 1024, "dark"], [1200, 1200, "light"], [768, 1024, "light"],
      // Both sides of the settings/status column boundary.
      [1023, 900, "light"], [1024, 900, "dark"],
      // 4:3 desktop windows and displays.
      [1024, 768, "light"], [1280, 960, "dark"], [1600, 1200, "light"], [1920, 1440, "dark"],
      // 16:9 laptops and desktop displays.
      [1280, 720, "light"], [1366, 768, "dark"], [1600, 900, "light"], [1920, 1080, "dark"], [2560, 1440, "dark"],
    ];
    for (const [width, height, theme] of viewports) {
      await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
      await page();
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      const certificateExpanded = width >= 768 && height >= 600;
      await until(`(document.querySelector(".certificate-disclosure > .disclosure-trigger").getAttribute("aria-expanded") === "true") === ${certificateExpanded}`);
      const dualScope = width >= 1024;
      await until(`(document.querySelector("#global-tab") === null) === ${dualScope}`);
      if (!dualScope) {
        await until('document.querySelector("#global-tab") !== null');
        await js('document.querySelector("#global-tab").click()');
      }
      await until('document.querySelector("#global-traffic .recharts-surface") !== null');
      await until(`document.querySelectorAll(".traffic-chart").length === ${dualScope ? 2 : 1}`);
      if (dualScope) assert.equal(await js('(() => { const [device, global] = document.querySelectorAll(".status-grid > div"); return global.getBoundingClientRect().top - device.getBoundingClientRect().bottom; })()'), 20, `status scopes keep their 20px divider spacing at ${width}px`);
      await until('[...document.querySelectorAll(".traffic-chart")].every(chart => { const svg = chart.querySelector(".recharts-surface"); return svg && Math.abs(svg.getBoundingClientRect().width - chart.clientWidth) <= 1; })');
      assert.equal(await js('[...document.querySelectorAll(".traffic-chart .recharts-line-curve")].every(line => !/NaN|Infinity/.test(line.getAttribute("d")))'), true);
      assert.equal(await js('[...document.querySelectorAll(".traffic-chart .recharts-cartesian-axis-tick")].every(tick => { const rect = tick.getBoundingClientRect(); const chart = tick.closest(".traffic-chart").getBoundingClientRect(); return rect.left >= chart.left - 1 && rect.right <= chart.right + 1 && rect.top >= chart.top - 1 && rect.bottom <= chart.bottom + 1; })'), true, `chart labels fit at ${width}px`);
      assert.equal(await js('[...document.querySelectorAll(".panel-card, .traffic-metrics, .diagnostic-fields, .selector-control")].every(element => element.scrollWidth <= element.clientWidth + 1)'), true, `panels fit at ${width}px`);
      if (height >= 600 && (width < 500 || width === 1280)) {
        // Touch emulation switches to a coarse pointer, which enlarges controls; measure afterwards.
        if (width < 500) await call("Emulation.setTouchEmulationEnabled", { enabled: true });
        const point = await js<{ x: number; y: number }>('(() => { const chart = document.querySelector("#global-traffic .traffic-chart"); chart.scrollIntoView({ block: "center" }); const dot = [...chart.querySelectorAll(".recharts-line-dot")].at(-1).getBoundingClientRect(); return { x: dot.x + dot.width / 2, y: dot.y + dot.height / 2 }; })()');
        if (width < 500) {
          await call("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [point] });
          await call("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
        } else {
          await call("Input.dispatchMouseEvent", { type: "mouseMoved", ...point });
        }
        await until('document.querySelector("#global-traffic .traffic-tooltip")?.textContent.includes("3.5 MiB/s")');
        assert.equal(await js('(() => { const tip = document.querySelector("#global-traffic .traffic-tooltip").getBoundingClientRect(); return tip.left >= 0 && tip.right <= innerWidth; })()'), true, `tooltip fits at ${width}px`);
        if (process.env.SCREENSHOT_DIR) {
          const image = await call("Page.captureScreenshot");
          await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-tooltip-${width}x${height}.png`), Buffer.from(image.data, "base64"));
        }
        await key("Escape", 27);
        // Disabling touch emulation also drops the emulated mouse until the next page load.
        if (width < 500) await call("Emulation.setTouchEmulationEnabled", { enabled: false });
      }
      await openPicker();
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `outbounds fit the content viewport at ${width}x${height}`);
      assert.equal(await js('(() => { const menu = document.querySelector(".node-popover").getBoundingClientRect(); return menu.left >= 0 && menu.top >= 0 && menu.right <= innerWidth && menu.bottom <= innerHeight; })()'), true);
      assert.equal(await js('document.querySelector(".node-list").clientHeight > 20'), true);
      await checkNodeActions("setting", width, height);
      if (process.env.SCREENSHOT_DIR && width === 390 && height === 844) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-mobile-open.png"), Buffer.from(image.data, "base64"));
      }
      await js('document.querySelector(".node-search input").focus()');
      await key("Escape", 27);
      await until('document.querySelectorAll(".selector-node").length === 0');
      if (process.env.SCREENSHOT_DIR && height >= 600) {
        await js('window.scrollTo(0, 0)');
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-selector-${width}x${height}.png`), Buffer.from(image.data, "base64"));
      }
      await visit("overview");
      await openPicker("overview");
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `quick selector actions fit at ${width}px`);
      await checkNodeActions("overview", width, height);
      await js('document.querySelector(".node-search input").focus()');
      await key("Escape", 27);
      await until('document.querySelectorAll(".selector-node").length === 0');
      const overviewBounds = await js('(() => { const rect = document.querySelector(".workspace").getBoundingClientRect(); return { left: rect.left, width: rect.width, navWidth: document.querySelector(".page-nav").getBoundingClientRect().width }; })()');
      assert.equal(await js('(() => { const box = document.querySelector(".device-identity").getBoundingClientRect(); const refresh = document.querySelector("#refresh").getBoundingClientRect(); return refresh.width >= 44 && refresh.height >= 36 && (innerWidth <= 760 ? refresh.bottom < box.top : box.right < refresh.left || box.bottom < refresh.top); })()'), true, `identity and refresh remain separate and readable at ${width}px`);
      assert.equal(await js('document.querySelector("#identity").checkVisibility() && document.querySelector("#device-mac").checkVisibility()'), true, `IP and MAC stay visible at ${width}px`);
      assert.equal(await js('document.querySelector("#https-title").closest("section").getBoundingClientRect().top > document.querySelector("#device-title").closest("section").getBoundingClientRect().bottom'), true, "settings stack within their column");
      assert.equal(await js(`(() => { const settings = document.querySelector(".dashboard-main").getBoundingClientRect(); const status = document.querySelector("#status-view").getBoundingClientRect(); return ${dualScope} ? settings.right < status.left && settings.top === status.top : settings.bottom < status.top; })()`), true, `settings and status form separate columns or stacked sections at ${width}px`);
      if (dualScope) {
        assert.equal(await js('(() => { const device = document.querySelector("#device-status").getBoundingClientRect(); const global = document.querySelector("#global-status").getBoundingClientRect(); return device.bottom < global.top && device.left === global.left; })()'), true, "device and global status stack within the status column");
      }
      if (process.env.SCREENSHOT_DIR && height >= 600) {
        await js('window.scrollTo(0, 0)');
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-overview-${width}x${height}.png`), Buffer.from(image.data, "base64"));
        const viewportImage = await call("Page.captureScreenshot", { captureBeyondViewport: false });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-overview-viewport-${width}x${height}.png`), Buffer.from(viewportImage.data, "base64"));
      }
      await setDisclosure(".certificate-disclosure");
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `expanded settings fit at ${width}px`);
      if (process.env.SCREENSHOT_DIR && (width === 390 && height === 844 || width === 1280 && height === 960)) {
        const clip = await js<Protocol.Page.Viewport>('(() => { const rect = document.querySelector("#https-title").closest("section").getBoundingClientRect(); return { x: rect.x + scrollX, y: rect.y + scrollY, width: rect.width, height: rect.height, scale: 1 }; })()');
        const certificateImage = await call("Page.captureScreenshot", { captureBeyondViewport: true, clip });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-certificate-${width}.png`), Buffer.from(certificateImage.data, "base64"));
      }
      await setDisclosure(".certificate-disclosure", certificateExpanded);
      await visit("explain");
      assert.deepEqual(await js('(() => { const rect = document.querySelector(".workspace").getBoundingClientRect(); return { left: rect.left, width: rect.width, navWidth: document.querySelector(".page-nav").getBoundingClientRect().width }; })()'), overviewBounds, `Explain keeps Overview width and alignment at ${width}px`);
      assert.equal(await js(`(() => { const nav = document.querySelector("#setting-navigation").getBoundingClientRect(); const content = document.querySelector("#setting-content").getBoundingClientRect(); const links = [...document.querySelectorAll("#setting-navigation a, #setting-navigation [role=tab]")].map(link => link.getBoundingClientRect()); return ${width} >= 768 ? nav.right < content.left && nav.top === content.top && links.every((rect, i) => !i || rect.top >= links[i - 1].bottom) : nav.bottom <= content.top && links.every(rect => rect.top === links[0].top); })()`), true, `Setting uses a left sidebar or top tabs at ${width}px`);
      const fieldSizes = await js<{ inputHeight: number; selectHeight: number; inputWidth: number }>('(() => { const input = document.querySelector("#diagnostic-target").getBoundingClientRect(); const select = document.querySelector("#diagnostic-protocol").getBoundingClientRect(); return { inputHeight: input.height, selectHeight: select.height, inputWidth: input.width }; })()');
      assert.equal(fieldSizes.inputHeight === fieldSizes.selectHeight && fieldSizes.inputWidth >= 240, true, `aligned diagnostic inputs at ${width}px: ${JSON.stringify(fieldSizes)}`);
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `testing fits at ${width}px`);
      assert.equal(await js('(() => { const header = document.querySelector(".page-header").getBoundingClientRect(); return [...document.querySelectorAll("#setting-page, footer")].every(element => { const rect = element.getBoundingClientRect(); return Math.abs(rect.left - header.left) < 1 && Math.abs(rect.right - header.right) < 1; }); })()'), true, `testing content aligns with the page at ${width}px`);
      assert.equal(await js('(() => { const nav = document.querySelector(".page-nav").getBoundingClientRect(); const heading = document.querySelector(".page-heading").getBoundingClientRect(); const refresh = document.querySelector("#refresh").getBoundingClientRect(); const links = [...document.querySelectorAll(".page-nav a")].map(link => link.getBoundingClientRect()); const center = rect => (rect.top + rect.bottom) / 2; return (innerWidth <= 760 ? nav.top > heading.bottom && nav.right < refresh.left && Math.abs(center(nav) - center(refresh)) < 1 : nav.left > heading.right && (innerWidth < 1024 || Math.abs(center(nav) - center(refresh)) < 1)) && links.every(link => link.top === links[0].top && link.height >= 32); })()'), true, `header forms one bar on desktop and keeps navigation beside refresh on mobile at ${width}px`);
      if (process.env.SCREENSHOT_DIR && height >= 600) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-explain-${width}x${height}.png`), Buffer.from(image.data, "base64"));
      }
      await visit("devices");
      assert.deepEqual(await js('(() => { const rect = document.querySelector(".workspace").getBoundingClientRect(); return { left: rect.left, width: rect.width, navWidth: document.querySelector(".page-nav").getBoundingClientRect().width }; })()'), overviewBounds, `Devices keeps Overview width and alignment at ${width}px`);
      await js('document.querySelector("#setting-devices-tab").click()');
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `devices fit at ${width}px`);
      assert.equal(await js('(() => { const header = document.querySelector(".page-header").getBoundingClientRect(); return [...document.querySelectorAll("#setting-page, footer")].every(element => { const rect = element.getBoundingClientRect(); return Math.abs(rect.left - header.left) < 1 && Math.abs(rect.right - header.right) < 1; }); })()'), true, `device controls align with the page at ${width}px`);
      assert.equal(await js('[...document.querySelectorAll(".managed-client-fields input, .managed-client-fields select, #managed-client-form button")].every(element => { const rect = element.getBoundingClientRect(); return rect.width > 0 && rect.left >= 0 && rect.right <= innerWidth; })'), true);
      if (process.env.SCREENSHOT_DIR && height >= 600) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-devices-${width}x${height}.png`), Buffer.from(image.data, "base64"));
      }
      await visit("overview");
      for (const section of ["connection-details", "outbounds-section", "tables-section", "plugins-section"]) await setDisclosure(`#global-traffic .${section}`);
      assert.match(await js<string>('document.querySelector("#global-traffic .buffer-memory").textContent'), /Body buffers \(process\):.*denied: 3/);
      await setDisclosure('#global-groups .status-entry[data-name="proxy_jp"]');
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `expanded status fits at ${width}px`);
      if (process.env.SCREENSHOT_DIR && height >= 600) {
        await delay(250);
        await js('document.querySelector("#global-status").scrollIntoView({ block: "start" })');
        const clip = await js<Protocol.Page.Viewport>('(() => { const rect = document.querySelector("#global-status").getBoundingClientRect(); return { x: rect.left + scrollX, y: rect.top + scrollY, width: rect.width, height: rect.height, scale: 1 }; })()');
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true, clip });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-status-expanded-${width}x${height}.png`), Buffer.from(image.data, "base64"));
      }
    }
    await visit("explain");
    await choose("#diagnostic-kind", "DNS policy");
    assert.equal(await js('document.querySelector("#diagnostic-qtype").checkVisibility() && !document.querySelector("#diagnostic-sni").checkVisibility()'), true);
    await choose("#diagnostic-kind", "Connection routing");
    assert.equal(await js('!document.querySelector("#diagnostic-sni").checkVisibility() && !document.querySelector("#diagnostic-qtype").checkVisibility()'), true);
    await setDisclosure(".diagnostic-advanced", true);
    assert.equal(await js('document.querySelector("#diagnostic-sni").checkVisibility()'), true);
    assert.equal(browserLogs.some((entry) => /Content Security Policy|Refused to|violates/i.test(entry)), false);
  });

  if (process.env.SCREENSHOT_DIR) {
    const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
    await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-review.png"), Buffer.from(image.data, "base64"));
  }
} finally {
  socket?.close();
  chromium.kill();
  await stopped;
  for (const socket of sockets) socket.destroy();
  httpServer.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  for (const server of Object.values(tlsServers)) {
    server.closeAllConnections();
  }
  if (proxy) await new Promise(resolve => proxy.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
if (failures) process.exitCode = 1;
