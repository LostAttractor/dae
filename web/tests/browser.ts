import type { Socket } from "node:net";
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

// Optional real browser trust-store checks. HOME and the NSS database belong to
// this temporary profile; no system/browser certificate store is modified.
if (process.env.CERTUTIL) {
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
  await exec(process.env.CERTUTIL, ["-N", "--empty-password", "-d", `sql:${database}`]);
  await exec(process.env.CERTUTIL, ["-A", "-d", `sql:${database}`, "-n", "dae-browser-test", "-t", "C,,", "-i", root]);
  for (const kind of ["trust", "mitm", "untrusted"] as const) {
    const server = createTLSServer({ cert: await readFile(kind === "untrusted" ? untrusted : leaf), key: await readFile(kind === "untrusted" ? untrustedKey : leafKey) }, (req, res) => {
      if (req.headers.origin !== origin || req.url !== "/test/browser-proof") return res.writeHead(403).end();
      const stage = kind === "mitm" ? "mitm" : "trust";
      assert.ok(fixture.testData);
      fixture.testData[`${stage}_observed`] = true;
      res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": origin, "Cache-Control": "no-store", Connection: "close" });
      res.end(JSON.stringify({ id: "browser-proof", ca_fingerprint: "browser-ca", stage }));
    });
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
    { name: "direct", target_kind: "builtin", stats, nodes: [{ name: "direct", checks_connectivity: false, stats }] },
    { name: "proxy_jp", policy: "min_moving_avg", connectivity: "available", stats, nodes: [
      { name: "Tokyo premium → IPv6", checks_connectivity: true, healthy: true, stats },
      { name: "Osaka backup", checks_connectivity: true, healthy: false, stats: { active_connections: 0 } },
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
    healthy: i === 0, tested: i === 0, tracking: i === 0, checking: false,
    ...(i === 0 ? { latency_ms: 28.5, checked_at: "2026-09-22T00:00:00Z" } : {}),
  }));
  fixture = {
    mode: "lan", requests: [], nextRead: null, clientReads: 0,
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
        "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' https://${new URL(origin).hostname.includes(":") ? "*" : new URL(origin).hostname}:${serverPort(server)}/test/ https://203.0.113.254:443/test/ https://*:443/test/; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
      });
      res.end(await readFile(join(source, path)));
      return;
    }
    if (req.method !== "GET") {
      assert.equal(req.headers["x-dae-api"], "1");
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body: FixtureBody = JSON.parse(Buffer.concat(chunks).toString() || "{}");
      fixture.requests.push({ method: req.method || "GET", path: url, body });
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
        fixture.managed = { mac, sets: [{ name: group, description: "Managed group", joined: req.method === "PUT" }], mitm_override: null };
        return json({ name: group, description: "Managed group", members: req.method === "PUT" ? [mac] : [] });
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
        fixture.device.mitm.enabled = fixture.device.mitm.override ?? false;
        return json(fixture.device);
      }
      if (url === "/api/device/certificate-tests") {
        assert.ok(fixture.device.mitm);
        fixture.testData = { id: "browser-proof", ca_fingerprint: "browser-ca", mitm_enabled: fixture.device.mitm.enabled,
          trust_url: `${origin.replace("http:", "https:")}/test/browser-proof`,
          mitm_url: `${mitmOrigins[new URL(origin).hostname.includes(":") ? 1 : 0]}/test/browser-proof`, trust_observed: false, mitm_observed: false };
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
    if (url === "/api/device/certificate-tests/browser-proof") return json(fixture.testData);
    if (url === "/api/status") {
      const override = fixture.nextGlobalRead;
      fixture.nextGlobalRead = null;
      const status = override?.status || (fixture.mode === "denied" ? 403 : fixture.mode === "api_key" && !req.headers.cookie?.includes("session=valid") ? 401 : 200);
      const snapshot = { version: "test-daemon", started_at: "2026-10-01T00:00:00Z", stats: { ...fixture.stats, active_connections: 20 }, direct_fallback_connections: 3, groups: structuredClone(fixture.groups), tables: fixture.tables, plugins: fixture.plugins };
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(status === 200 ? snapshot : { error: "Global status unavailable" }, status);
    }
    if (url === "/api/device") return json(fixture.device);
    if (url === "/api/device/context") return delayedJSON("nextContextRead", fixture.l3
      ? { generation: fixture.generation ?? 7, context: { source_ip: "100.64.0.23", link_type: "ip", ifindex: 8 }, fields: [{ name: "link_type", value: "ip", source: "request" }] }
      : { generation: fixture.generation ?? 7, context: { source_ip: fixture.device.source_ip, mac: fixture.device.mac, link_type: "ethernet" }, device: fixture.device, fields: [{ name: "mac", value: fixture.device.mac, source: "request" }] });
    if (url === "/api/clients") {
      fixture.clientReads++;
      return json({ groups: [{ name: "internal/work", description: "Managed group", members: [] }] });
    }
    if (url.startsWith("/api/devices/")) return delayedJSON("nextManagedDevice", fixture.managed || { mac: decodeURIComponent(url.slice("/api/devices/".length)), sets: [], mitm_override: null });
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
  "--headless", "--disable-gpu", "--no-first-run", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank",
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
    const trigger = JSON.stringify(`${selector} > .astryx-collapsible-trigger`);
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
    await until(`${row}.querySelector('.node-popover').matches(':popover-open') && document.activeElement.matches('.node-search input')`);
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
    try { await action(); assert.deepEqual(exceptions, []); console.log(`PASS ${name}`); }
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
    assert.equal(await js('document.querySelectorAll("#sets .astryx-banner[data-status=warning] svg").length'), 1);
    assert.equal(await js('document.querySelectorAll("#device-traffic .astryx-banner[data-status=warning] svg").length'), 1);
    assert.doesNotMatch(await js('document.querySelector("#device-status").textContent'), /failed|Retrying/);
    for (const theme of ["dark", "light"]) {
      await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      assert.equal(await js('(() => { const warning = document.querySelector("#sets .astryx-banner"); const note = document.querySelector("#routing-change-note"); return getComputedStyle(warning).color === getComputedStyle(note).color && getComputedStyle(note).color !== getComputedStyle(document.body).color && note.querySelector("svg") !== null; })()'), true);
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

  if (process.env.CERTUTIL) await test("real browser TLS accepts the installed CA and rejects an untrusted certificate", async () => {
    fixture.certificate = { name: "Browser CA", fingerprint: "browser-ca", test_available: true, test_generation: "browser-one", test_mitm_origins: mitmOrigins };
    fixture.device.mitm = { enabled: true, override: null, ca_fingerprint: "browser-ca" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Accepted by this browser");
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified");
    fixture.bypass = true;
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Verification incomplete");
    fixture.untrusted = true;
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete");
    assert.ok(fixture.testData);
    assert.equal(fixture.testData.trust_observed, false);
    assert.equal(fixture.testData.mitm_observed, false);
    const ipv4Origin = origin;
    try {
      origin = `http://[::1]:${serverPort(server)}`;
      fixture.untrusted = false;
      fixture.bypass = false;
      await page();
      await js('document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Accepted by this browser", "IPv6 browser CA test");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified", "IPv6 virtual target test");
    } finally { origin = ipv4Origin; }
  });
  else console.log("SKIP real browser CA trust-store checks (set CERTUTIL to an NSS certutil executable)");

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
    assert.equal(fixture.clientReads, 0);
    await openPicker();
    await visit("explain");
    assert.equal(await js('document.querySelector(".node-popover:popover-open")'), null);
    assert.equal(await js('document.activeElement.id'), "setting-explain-tab");
    assert.equal(await js('document.querySelector(".page-nav [aria-current=page]").textContent'), "Setting");
    assert.equal(await js('document.querySelector(".traffic-chart")'), null);
    await js('document.querySelector("#diagnostic-target").value = "example.com:443"');
    await visit("devices");
    await js('document.querySelector("#setting-devices-tab").click()');
    await until('document.querySelector("#managed-client-group").options.length === 1');
    assert.ok(fixture.clientReads >= 1);
    await js('history.back()');
    await until('document.querySelector("#setting-explain").checkVisibility()');
    assert.equal(await js('document.querySelector("#diagnostic-target").value'), "example.com:443");
    await js('history.forward()');
    await until('document.querySelector("#setting-page").checkVisibility()');
    await page("#setting/explain");
    assert.equal(await js('document.querySelector("#diagnostic-form").checkVisibility()'), true);
    assert.equal(await js('document.title'), "Network Panel · Setting · Explain");
    assert.equal(await js('document.querySelector("#diagnostics .setting-heading .astryx-badge").textContent'), "Read-only");
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
    assert.equal(await js('getComputedStyle(document.querySelector("#message").closest("[popover]")).position'), "fixed");
    assert.equal(await js('document.querySelector("#message").closest(".astryx-toast").getAttribute("role")'), "status");
    for (const [width, height, theme] of [[1280, 1000, "dark"], [390, 844, "light"]] as const) {
      await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelectorAll(".astryx-toast").length'), 1);
      await delay(250);
      const toast = await js<{ left: number; top: number; right: number; bottom: number }>('document.querySelector(".astryx-toast").getBoundingClientRect().toJSON()');
      assert.equal(toast.left >= 0 && toast.right <= width && toast.top >= 0 && toast.bottom <= height, true, `notification fits at ${width}px: ${JSON.stringify(toast)}`);
      if (process.env.SCREENSHOT_DIR) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-notification-${width}.png`), Buffer.from(image.data, "base64"));
      }
    }
    await key("F6", 117);
    assert.equal(await js('document.activeElement.closest(".astryx-toast") !== null'), true);
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
    assert.equal(await js('document.querySelector("#message").closest(".astryx-toast").getAttribute("role")'), "alert");
    assert.equal(await js('document.querySelectorAll("#message svg").length'), 1);
    assert.equal(await js('document.querySelector("#message").getAttribute("data-tone")'), "error");
    if (process.env.SCREENSHOT_DIR) {
      await delay(250);
      const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-error-notice.png"), Buffer.from(image.data, "base64"));
    }
    await delay(5500);
    assert.match(await js('document.querySelector("#message").textContent'), /Incorrect API key/);
    await key("F6", 117);
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
    assert.equal(await js('document.querySelector(".client-toggle input").checked'), true);
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
    await until('document.querySelector("#managed-client-group").options.length === 1');
    assert.deepEqual(await js('[...document.querySelectorAll("#setting-navigation a")].map(link => link.innerText)'), ["Devices", "Selector", "Explain"]);
    assert.equal(await js('document.querySelectorAll(".traffic-chart").length'), 0);
    assert.equal(await js('document.querySelector("#managed-client-form").checkVisibility()'), true);
    await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:44"; document.querySelector("#setting-devices-tab").focus()');
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
    await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await until('document.querySelector("#setting-navigation [role=tablist]") !== null');
    assert.equal(await js('document.activeElement.id'), "setting-explain-tab", "responsive navigation preserves focus");
    await key("Home", 36);
    await until('document.querySelector("#setting-devices").checkVisibility()');
    await key("ArrowRight", 39);
    await until('document.querySelector("#setting-selector").checkVisibility()');
    await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
    await until('document.querySelector("#setting-navigation .astryx-side-nav") !== null');
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
    assert.equal(await js('[...document.querySelectorAll(".test-node, .test-selected, .test-all")].some(button => button.checkVisibility())'), false);
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
    fixture.certificate = { name: "Test CA", fingerprint: "test-ca", test_available: true, test_generation: "one", test_mitm_origins: mitmOrigins };
    fixture.device.mitm = { enabled: true, override: null, ca_fingerprint: "test-ca" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    await js(`
      window.testMode = "mitm";
      const originalFetch = window.fetch;
      window.fetch = async (url, options) => {
        const address = String(url);
        const reply = data => new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
        if (address === "/api/device/certificate-tests") {
          if (testMode === "unavailable") return new Response(JSON.stringify({ error: "Certificate testing unavailable" }), { status: 503 });
          return reply({ id: "challenge", ca_fingerprint: "test-ca", mitm_enabled: testMode !== "disabled", trust_url: location.origin.replace("http:", "https:") + "/test/challenge", mitm_url: "https://203.0.113.254/test/challenge" });
        }
        if (address === "/api/device/certificate-tests/challenge") return reply({ trust_observed: true, mitm_observed: testMode === "mitm" });
        if (address.startsWith("https://")) {
          if (options.credentials !== "omit" || options.redirect !== "error" || options.mode !== "cors") throw Error("unsafe challenge request");
          if (testMode === "tls-error") throw new TypeError("Failed to fetch");
          if (testMode === "bypass" && address.includes("203.0.113.254")) throw new TypeError("Failed to fetch");
          return reply({ id: "challenge", ca_fingerprint: "test-ca", stage: address.includes("203.0.113.254") ? "mitm" : "trust" });
        }
        return originalFetch(url, options);
      };
    `);
    const feedback = async (tone: string, trust: string, mitm: string) => {
      assert.deepEqual(await js('["message", "certificate-trust-result", "certificate-mitm-result"].map(id => document.getElementById(id).dataset.tone)'), [tone, trust, mitm]);
      assert.equal(await js(`(() => {
        const colors = { success: '--fgColor-success', warning: '--fgColor-attention', error: '--fgColor-danger', neutral: '--fgColor-muted' };
        return ['message', 'certificate-trust-result', 'certificate-mitm-result'].every(id => {
          const node = document.getElementById(id), probe = document.createElement('span');
          probe.style.color = 'var(' + colors[node.dataset.tone] + ')';
          document.body.append(probe);
          const matches = getComputedStyle(node).color === getComputedStyle(probe).color;
          probe.remove(); return matches;
        });
      })()`), true, "result text uses the semantic theme colors");
      assert.equal(await js('document.querySelectorAll("#message svg").length'), 1, "feedback includes a status icon");
      assert.equal(await js('getComputedStyle(document.querySelector(".astryx-toast")).backgroundColor !== getComputedStyle(document.body).backgroundColor'), true, "feedback has a tinted surface");
    };
    for (const theme of ["light", "dark"] as const) {
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      await js('testMode = "mitm"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Accepted by this browser");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified");
      assert.equal(await js('document.querySelector("#message").textContent'), "Certificate trusted and HTTPS interception verified.");
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
      assert.match(await js('document.querySelector("#message").textContent'), /HTTPS interception could not be verified/);
      await feedback("warning", "success", "warning");
      if (process.env.SCREENSHOT_DIR) {
        await delay(250);
        const image = await call("Page.captureScreenshot");
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-certificate-warning-${theme}.png`), Buffer.from(image.data, "base64"));
      }
      await js('testMode = "tls-error"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete");
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "CA test required");
      await feedback("warning", "warning", "warning");
      await js('testMode = "disabled"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "MITM is disabled");
      assert.match(await js('document.querySelector("#message").textContent'), /HTTPS interception is disabled/);
      await feedback("success", "success", "neutral");
      await js('testMode = "unavailable"; document.querySelector("#test-certificate").click()');
      await ready();
      assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Test unavailable");
      await feedback("error", "error", "neutral");
    }
    await call("Emulation.setDeviceMetricsOverride", { width: 320, height: 568, deviceScaleFactor: 1, mobile: true });
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
    fixture.certificate.test_generation = "two";
    await until('document.querySelector("#certificate-trust-result").textContent === "Not tested"');
  });

  await test("certificate disclosure adapts to available space and preserves manual choices", async () => {
    fixture.certificate = { name: "Test CA", fingerprint: "test-ca", test_available: true, test_generation: "disclosure" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-name").textContent'), "Test CA");
    assert.equal(await js('document.querySelector("#certificate-fingerprint").textContent'), "test-ca");
    const resize = async (width: number, height: number, expanded: boolean) => {
      await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
      await until(`(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true") === ${expanded}`);
    };
    await resize(390, 844, false);
    await resize(844, 390, false);
    await resize(1280, 900, true);
    await js('document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").click()');
    await resize(390, 844, false);
    await resize(1280, 900, false);
    await js('document.querySelector("#refresh").click()');
    await ready();
    await visit("explain");
    await visit("overview");
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true")'), false, "manual collapse survives refresh and navigation");
    await page();
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true")'), true, "reload restores the desktop default");
    await resize(390, 844, false);
    await page();
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true")'), false, "a phone starts collapsed");
    await js('document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").focus()');
    assert.equal(await js('document.activeElement.matches(".certificate-disclosure > .astryx-collapsible-trigger")'), true);
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await until('(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true")');
    await resize(1280, 900, true);
    await resize(390, 844, true);
    await js('document.querySelector("#refresh").click()');
    await ready();
    await visit("explain");
    await visit("overview");
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true")'), true, "manual expansion survives resize, refresh and navigation");
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
    await until(`${row}.querySelector('.node-list .node-name').textContent === 'Tokyo'`);
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
    await js(`window.searchInput = ${row}.querySelector('.node-search input'); true`);
    await fillSearch("Tokyo");
    assert.equal(await js('document.querySelectorAll(".selector-node:not([hidden])").length'), 1);
    await js('document.querySelector(".selector-node:not([hidden]) .test-node").click()');
    await ready();
    assert.equal(await js('document.querySelector(".selector-node:not([hidden]) .node-health").textContent'), "Testing…");
    assert.equal(await js('document.querySelector(".node-search input") === searchInput && searchInput.value === "Tokyo"'), true);
    fixture.selectors[0].nodes[1].checking = false;
    fixture.selectors[0].nodes[1].tested = true;
    fixture.selectors[0].nodes[1].healthy = true;
    await until('document.querySelector(".selector-node:not([hidden]) .node-health").textContent === "Available"');
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
    await key("End", 35);
    assert.match(await js('document.activeElement.querySelector(".node-name").textContent'), /^Node 999/);
    await key("Escape", 27);
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await until('document.querySelectorAll(".selector-node").length === 0');
    assert.equal(await js('document.activeElement.matches(".node-picker")'), true);
  });

  await test("group order, removed nodes and empty results reflect live data", async () => {
    fixture.selectors.reverse();
    await until(`${row}.dataset.group === 'Tracked default'`);
    await openPicker();
    await key("ArrowDown", 40);
    fixture.selectors[0].nodes.shift();
    await until(`${row}.querySelector('.node-list .node-name').textContent === 'Tokyo'`);
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
    await js('document.querySelector(".client-toggle input").focus()');
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: " ", code: "Space", windowsVirtualKeyCode: 32 });
    await ready();
    assert.deepEqual(fixture.requests[0], { method: "PUT", path: "/api/device/sets/internal%2Fwork", body: {} });
    assert.match(await js('document.querySelector("#message").textContent'), /Work network turned on/);
    assert.equal(await js('document.querySelector(".client-toggle input").labels[0].textContent'), "Work network");
    assert.deepEqual(await js('[...document.querySelectorAll(".client-toggle input")].map(toggle => toggle.checked)'), [true, true]);
    assert.deepEqual(await js('[...document.querySelectorAll(".set-state")].map(state => state.textContent)'), ["On", "On"]);
    await js('document.querySelector(".client-toggle input").click()');
    await ready();
    assert.deepEqual(lastRequest(), { method: "DELETE", path: "/api/device/sets/internal%2Fwork", body: {} });
    assert.deepEqual(await js('[...document.querySelectorAll(".set-state")].map(state => state.textContent)'), ["Off", "On"]);
    assert.deepEqual(await js('[...document.querySelectorAll(".client-toggle input")].map(toggle => toggle.checked)'), [false, true]);
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
    await js('document.querySelector(".impact-content .astryx-button").click(); document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
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
    assert.deepEqual(await js('[...document.querySelectorAll(".trace-step-badges")].map(group => [...group.querySelectorAll(".astryx-badge")].map(badge => badge.textContent))'), [["Referenced"], ["Referenced"], ["Referenced"]]);
    assert.deepEqual(await js('[...document.querySelectorAll(".trace-policy-indicator")].map(dot => dot.getAttribute("aria-label"))'), ["Policy: main · Applies", "Policy: main · Applies", "Policy: tor · Does not apply"]);
    await setDisclosure('.impact-content .trace-step:first-child', true);
    assert.deepEqual(await js('[...document.querySelectorAll(".impact-content .trace-step:first-child .trace-step-meta .astryx-badge")].map(badge => badge.textContent)'), ["Rules", "Policy: main · Applies"]);
    await setDisclosure('.impact-content .trace-step:first-child', false);
    assert.equal(await js('document.querySelector(".impact-content").textContent.includes("Uncertain")'), false);
    const shortRule = '.impact-content .trace-step:nth-child(2)';
    const longRule = '.impact-content .trace-step:nth-child(3)';
    const geometry = () => js<{ height: number; offset: number; textHeight: number; lineHeight: number; glyphTop: number; glyphBottom: number }>(`(() => {
      const button = document.querySelector(${JSON.stringify(shortRule + ' > button')}), expression = button.querySelector('.trace-expression');
      const rect = button.getBoundingClientRect(), text = expression.getBoundingClientRect(), range = document.createRange();
      range.selectNodeContents(expression);
      const glyph = range.getBoundingClientRect();
      return { height: rect.height, offset: text.top - rect.top, textHeight: text.height, lineHeight: parseFloat(getComputedStyle(expression).lineHeight), glyphTop: glyph.top - text.top, glyphBottom: text.bottom - glyph.bottom };
    })()`);
    for (const width of [1280, 320]) {
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      await js('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      if (width === 1280) assert.equal(await js('(() => { const el = document.querySelector(".impact-content .trace-step:first-child .trace-expression"); return el.scrollWidth <= el.clientWidth; })()'), true, "compact metadata leaves room for the full DNAT rule");
      const before = await geometry();
      await setDisclosure(shortRule, true);
      const after = await geometry();
      assert.ok(Math.abs(after.height - before.height) < 1, "a short rule keeps its title height");
      assert.ok(Math.abs(after.offset - before.offset) < 1, "a short expression does not move upward");
      assert.ok(after.textHeight < after.lineHeight * 2, "the short expression still occupies one line");
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
    await until('document.querySelectorAll(".impact-content .astryx-button").length === 2');
    assert.deepEqual(fixture.requests.map(request => request.path).sort(), ["/api/device/sets/gaming/impact", "/api/device/sets/internal%2Fwork/impact"]);
    for (const width of [320, 1280]) {
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      await js('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `expanded routing details fit at ${width}px`);
      assert.equal(await js('(() => { const rows = [...document.querySelectorAll(".set-row")]; return rows.every((row, index) => { const arrow = row.querySelector(".set-details > button").getBoundingClientRect(); const toggle = row.querySelector(".client-toggle").getBoundingClientRect(); const body = row.querySelector(".impact-content").getBoundingClientRect(); return arrow.width >= 44 && arrow.height >= 44 && arrow.left >= toggle.right && body.top >= arrow.bottom && (!index || row.getBoundingClientRect().top >= rows[index - 1].getBoundingClientRect().bottom); }); })()'), true, "arrows and switches stay separate, with details below their own row");
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
    assert.equal(await js('document.querySelector(".set-row[data-name=gaming] .client-toggle input").checked'), true);
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
      assert.equal(await js('document.querySelector(".set-row[data-name=gaming] .client-toggle input").checked'), true);
      assert.match(await js('document.querySelector(".impact-content").textContent'), /Change: On → Off/);
      await js('document.querySelector(".impact-content .astryx-button").click()');
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
    assert.match(await js('document.querySelector(".trace-missing").textContent'), /Entering a hostname or SNI does not create a mapping/);
    assert.equal(await js('document.querySelector(".trace-candidates select").options.length'), 91, "exclude IPv6 candidates for the inherited IPv4 identity");
    assert.equal(await js('document.querySelector(".trace-candidates button").disabled'), true);
    assert.equal(await js('document.querySelectorAll(".explanation .astryx-collapsible-trigger[aria-expanded=true]").length === 0'), true);
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
    await js('document.querySelector(".trace-filter select").value = "uncertain"; document.querySelector(".trace-filter select").dispatchEvent(new Event("change", { bubbles: true }))');
    assert.equal(await js('document.querySelectorAll(".trace-steps > .trace-step").length'), 60);
    await setDisclosure(".trace-steps .trace-step");
    assert.match(await js('document.querySelector(".trace-step p").textContent'), /More information/);
    assert.equal(await js('document.documentElement.scrollWidth <= innerWidth'), true);
    await js('document.querySelector(".trace-missing button").click()');
    assert.equal(await js('document.activeElement.id'), "diagnostic-ip");
    fixture.explanation = null;
    await js('document.querySelector(".trace-candidates select").value = "198.51.100.8"; document.querySelector(".trace-candidates select").dispatchEvent(new Event("change", { bubbles: true }))');
    await js('document.querySelector(".trace-candidates button").click()');
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
      await js(`document.querySelector("#diagnostic-kind").value = ${JSON.stringify(kind)}; document.querySelector("#diagnostic-kind").dispatchEvent(new Event("change", { bubbles: true })); document.querySelector("#diagnostic-target").value = ${JSON.stringify(value)}; document.querySelector("#diagnostic-form").requestSubmit()`);
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
      await js('document.querySelector("#diagnostic-kind").value = "dns"; document.querySelector("#diagnostic-kind").dispatchEvent(new Event("change", { bubbles: true }))');
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
        if (change === "mitm") fixture.device.mitm = { enabled: !fixture.device.mitm?.enabled, override: null, ca_fingerprint: "test-ca" };
        else if (change === "generation") fixture.generation = (fixture.generation ?? 7) + 1;
        else {
          await visit("devices");
          await until('document.querySelector("#managed-client-group").options.length === 1');
          await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:99"; document.querySelector("#managed-client-form button[value=join]").click()');
          await until('document.querySelector("#managed-client-result .astryx-badge")?.textContent === "Joined"');
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
    await js('document.querySelector("#diagnostic-scope").value = "manual"; document.querySelector("#diagnostic-scope").dispatchEvent(new Event("change", { bubbles: true }))');
    const held = { status: 500, started: deferred(), release: deferred() };
    fixture.nextExplanation = held;
    try {
      await js('document.querySelector("#diagnostic-target").value = "198.51.100.10:443"; document.querySelector("#diagnostic-form").requestSubmit()');
      await held.started.promise;
      assert.equal(lastRequest().path, "/api/diagnostics/explain");
      fixture.mode = "denied";
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelector("#diagnostic-scope").value'), "self");
      assert.equal(await js('document.querySelector("#diagnostic-result").textContent'), "");
      assert.equal(await js('document.querySelector("#diagnostic-run").disabled'), false);
      held.release.resolve();
      await delay(100);
      assert.equal(await js('document.querySelector("#diagnostic-result").textContent'), "");
    } finally { held.release.resolve(); }
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
      await js('document.querySelector(".impact-content .astryx-button").click()');
      assert.equal(await js('document.querySelector("#diagnostic-comparison").textContent'), "Leave Work network");
      fixture.device.mac = "02:00:00:00:00:09";
      await js('document.querySelector("#refresh").click()');
      await ready();
      assert.equal(await js('document.querySelector(".set-details > .astryx-collapsible-trigger").getAttribute("aria-expanded")'), "false");
      assert.equal(await js('document.querySelector("#diagnostic-comparison").textContent'), "Current settings");
    } finally { held.release.resolve(); }
  });

  await test("React managed devices cannot restore data after access is revoked", async () => {
    await visit("devices");
    await js('document.querySelector("#setting-devices-tab").click()');
    await until('document.querySelector("#managed-client-group").options.length === 1');
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
    await js('document.querySelector(".client-toggle input").focus(); document.querySelector(".client-toggle input").click()');
    await ready();
    assert.equal(await js('document.activeElement.labels[0].textContent'), "Work network");
    fixture.device.mitm = { enabled: false, override: null, ca_fingerprint: "test-ca" };
    await js('document.querySelector("#refresh").focus(); document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.activeElement.id'), "refresh");
    assert.equal(await js('document.querySelector("#mitm-summary").textContent'), "Disabled (Default)");
    await js('document.querySelector("#mitm .toggle").focus(); document.querySelector("#mitm .toggle").click()');
    await ready();
    assert.equal(await js('document.activeElement.matches(".toggle")'), true);
    assert.equal(await js('document.querySelector("#mitm-summary").textContent'), "Enabled (Custom)");
    await js('document.querySelector("#mitm .reset").focus(); document.querySelector("#mitm .reset").click()');
    await ready();
    assert.equal(await js('document.activeElement.matches(".toggle")'), true);
    assert.equal(await js('document.querySelector("#mitm-summary").textContent'), "Disabled (Default)");
  });

  await test("administrator device management uses the specified MAC", async () => {
    await visit("devices");
    await js('document.querySelector("#setting-devices-tab").click()');
    await until('document.querySelector("#managed-client-group").options.length === 1');
    await js('document.querySelector("#managed-client-mac").value = "02:00:00:00:00:99"; document.querySelector("#managed-client-form button[value=join]").click()');
    await until('document.querySelector("#managed-client-result .astryx-badge")?.textContent === "Joined"');
    assert.deepEqual(lastRequest(), { method: "PUT", path: "/api/clients/internal%2Fwork/members/02%3A00%3A00%3A00%3A00%3A99", body: {} });
    assert.equal(fixture.device.sets[0].joined, false);
    await js('document.querySelector("#managed-client-form button[value=leave]").click()');
    await until('document.querySelector("#managed-client-result .astryx-badge")?.textContent === "Not joined"');
    assert.match(await js('document.querySelector(".managed-device-settings").textContent'), /HTTPS modulesUse default/);
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
      { name: "proxy_jp", policy: "min_moving_avg", connectivity: "available", stats: fixture.stats, nodes: Array.from({ length: 80 }, (_, index) => ({
        name: `Japan premium dedicated connection ${index + 1} → lightsail [IPv6]`, checks_connectivity: true, healthy: true, stats: { active_connections: 0 },
      })) },
      { name: "direct", target_kind: "builtin", stats: fixture.stats, nodes: [] },
    ];
    await call("Emulation.setDeviceMetricsOverride", { width: 1366, height: 1000, deviceScaleFactor: 1, mobile: false });
    await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
    await js('document.querySelector("#refresh").click()');
    await ready();
    await setDisclosure("#global-traffic .outbounds-section");
    assert.deepEqual(await js('[...document.querySelectorAll("#global-traffic .status-sections > .status-section > .astryx-collapsible-trigger .status-section-label > span:first-child")].map(label => label.textContent)'), ["Connection statistics", "Outbounds", "Domain Tables", "Plugins"]);
    assert.equal(await js('document.querySelector("#global-traffic .connection-details > .astryx-collapsible-trigger").getAttribute("aria-expanded")'), "false", "outbounds open independently of connection totals");
    assert.equal(await js('document.querySelectorAll("#global-groups .status-nodes li").length'), 0);
    await js('window.openGroup = document.querySelector("#global-groups .status-entry"); openGroup.querySelector(".astryx-collapsible-trigger").click(); openGroup.querySelector(".astryx-collapsible-trigger").focus()');
    await until('openGroup.querySelectorAll(".status-nodes li").length === 80');
    assert.equal(await js('(() => { const list = document.querySelector("#global-groups .status-nodes"); return list.scrollHeight > list.clientHeight && list.clientHeight <= 320; })()'), true);
    assert.equal(await js('(() => { const device = document.querySelector("#device-status").getBoundingClientRect(); const global = document.querySelector("#global-status").getBoundingClientRect(); return device.bottom < global.top && device.left === global.left; })()'), true);
    await js('document.querySelector("#global-groups .status-nodes").scrollTop = 120');
    fixture.groups[0].nodes[20].stats.active_connections = 41;
    await until('openGroup.querySelectorAll(".status-nodes li")[20].textContent.includes("41 active")');
    assert.equal(await js('(openGroup.querySelector(".astryx-collapsible-trigger").getAttribute("aria-expanded") === "true") && document.activeElement === openGroup.querySelector(".astryx-collapsible-trigger")'), true);
    assert.equal(await js('document.querySelector("#global-groups .status-nodes").scrollTop'), 120);
    if (process.env.SCREENSHOT_DIR) {
      await js('document.querySelector("#global-groups .status-nodes").scrollTop = 0; window.scrollTo(0, 0)');
      const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-expanded-status.png"), Buffer.from(image.data, "base64"));
    }
    fixture.groups.reverse();
    await until('document.querySelector("#global-groups").firstElementChild.dataset.name === "direct"');
    assert.equal(await js('openGroup.isConnected && (openGroup.querySelector(".astryx-collapsible-trigger").getAttribute("aria-expanded") === "true") && document.activeElement === openGroup.querySelector(".astryx-collapsible-trigger")'), true);
    fixture.mode = "api_key";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-groups")'), null);
  });

  await test("larger text reflows every page and keeps controls readable", async () => {
    fixture.groups = statusGroups(fixture.stats);
    fixture.certificate = { name: "Test CA", fingerprint: "12:34:".repeat(16), test_available: true, test_generation: "large-text" };
    await js('document.querySelector("#refresh").click()');
    await ready();
    // Text-only zoom exercises user font preferences independently of viewport zoom.
    for (const width of [320, 768, 1280]) {
      await call("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: width < 500 });
      await page();
      await until(`(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true") === ${width >= 768}`);
      await setDisclosure(".certificate-disclosure");
      await js('document.documentElement.style.fontSize = "200%"');
      for (const name of ["overview", "devices", "selector", "explain"] as const) {
        await visit(name);
        if (name === "overview") {
          await js('document.querySelector("#global-tab")?.click()');
          for (const section of ["connection-details", "outbounds-section", "tables-section", "plugins-section"]) await setDisclosure(`#global-traffic .${section}`);
          await setDisclosure('#global-groups .status-entry[data-name="proxy_jp"]');
        }
        if (name === "explain") {
          await setDisclosure(".diagnostic-advanced");
          await js('document.querySelector("#diagnostic-target").value = "missing-port"; document.querySelector("#diagnostic-form").requestSubmit()');
          await until('document.querySelector("#diagnostic-result [role=alert]") !== null');
          assert.match(await js('document.querySelector("#diagnostic-result [role=alert]").textContent'), /Enter an IP:port/);
        }
        await js('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
        assert.equal(await js(`document.documentElement.scrollWidth <= ${width}`), true, `${name} reflows at ${width}px with double-size text`);
        // Screen-reader-only labels deliberately clip their text to a 1px box.
        const clipped = await js('[...document.querySelectorAll("button, .page-nav a, .download-links a, .selector-name, .managed-section p, .astryx-field-label, .astryx-banner-description")].filter(element => element.checkVisibility() && getComputedStyle(element).clip !== "rect(0px, 0px, 0px, 0px)" && element.scrollWidth > element.clientWidth + 1).map(element => element.textContent.trim())');
        assert.deepEqual(clipped, [], `${name} has no clipped labels at ${width}px`);
        assert.equal(await js(`([...document.querySelectorAll("button")].filter(element => element.checkVisibility()).every(element => { const rect = element.getBoundingClientRect(); const card = element.closest(".panel-card")?.getBoundingClientRect(); const strip = element.closest(".astryx-tab-strip")?.getBoundingClientRect(); if (strip) return strip.left >= 0 && strip.right <= ${width} && rect.width <= strip.width; return rect.left >= 0 && rect.right <= ${width} && (!card || rect.right <= card.right); }))`), true, `${name} keeps controls inside their panels at ${width}px`);
        if (process.env.SCREENSHOT_DIR && width === 320) {
          await js('window.scrollTo(0, 0)');
          const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
          await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-large-text-${name}.png`), Buffer.from(image.data, "base64"));
        }
      }
    }
    await js('document.documentElement.style.fontSize = ""');
  });

  await test("responsive layouts and dark mode keep the popup usable", async () => {
    fixture.groups = statusGroups(fixture.stats);
    fixture.tables = [{ name: "resolved_domains", used: 128, limit: 4096 }];
    fixture.plugins = [{ id: "request_rules", type: "http", state: "ready" }];
    fixture.certificate = { name: "Test CA", fingerprint: "12:34:56:78:".repeat(7) + "12:34:56:78", test_available: true, test_generation: "layout" };
    fixture.device.mitm = { enabled: false, override: null, ca_fingerprint: fixture.certificate.fingerprint };
    fixture.selectors[0].name = "Long outbound group name · " + "subscription ".repeat(6);
    fixture.stats.history = {
      upload_bytes_per_second: [300, 500, 420, 1200, 850, 640, 760, 400, 1400, 1100, 900, 700].map(value => value * 1024),
      download_bytes_per_second: [1600, 2400, 1800, 3800, 2900, 3200, 2500, 4100, 3500, 2400, 3000, 3600].map(value => value * 1024),
    };
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true")'), true);
    await delay(250);
    await js('document.querySelector(".astryx-toast button")?.click()');
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
      await until(`(document.querySelector(".certificate-disclosure > .astryx-collapsible-trigger").getAttribute("aria-expanded") === "true") === ${certificateExpanded}`);
      const dualScope = width >= 1024;
      await until(`(document.querySelector("#global-tab") === null) === ${dualScope}`);
      if (!dualScope) {
        await until('document.querySelector("#global-tab") !== null');
        await js('document.querySelector("#global-tab").click()');
      }
      await until('document.querySelector("#global-traffic .recharts-surface") !== null');
      await until(`document.querySelectorAll(".traffic-chart").length === ${dualScope ? 2 : 1}`);
      await until('[...document.querySelectorAll(".traffic-chart")].every(chart => { const svg = chart.querySelector(".recharts-surface"); return svg && Math.abs(svg.getBoundingClientRect().width - chart.clientWidth) <= 1; })');
      assert.equal(await js('[...document.querySelectorAll(".traffic-chart .recharts-line-curve")].every(line => !/NaN|Infinity/.test(line.getAttribute("d")))'), true);
      assert.equal(await js('[...document.querySelectorAll(".traffic-chart .recharts-cartesian-axis-tick")].every(tick => { const rect = tick.getBoundingClientRect(); const chart = tick.closest(".traffic-chart").getBoundingClientRect(); return rect.left >= chart.left - 1 && rect.right <= chart.right + 1 && rect.top >= chart.top - 1 && rect.bottom <= chart.bottom + 1; })'), true, `chart labels fit at ${width}px`);
      assert.equal(await js('[...document.querySelectorAll(".panel-card, .traffic-metrics, .diagnostic-fields, .selector-control")].every(element => element.scrollWidth <= element.clientWidth + 1)'), true, `panels fit at ${width}px`);
      if (height >= 600 && (width < 500 || width === 1280)) {
        const point = await js<{ x: number; y: number }>('(() => { const chart = document.querySelector("#global-traffic .traffic-chart"); chart.scrollIntoView({ block: "center" }); const dot = [...chart.querySelectorAll(".recharts-line-dot")].at(-1).getBoundingClientRect(); return { x: dot.x + dot.width / 2, y: dot.y + dot.height / 2 }; })()');
        if (width < 500) {
          await call("Emulation.setTouchEmulationEnabled", { enabled: true });
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
        await call("Emulation.setTouchEmulationEnabled", { enabled: false });
      }
      await openPicker();
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `outbounds fit the content viewport at ${width}x${height}`);
      assert.equal(await js('(() => { const menu = document.querySelector(".node-popover").getBoundingClientRect(); return menu.left >= 0 && menu.top >= 0 && menu.right <= innerWidth && menu.bottom <= innerHeight; })()'), true);
      assert.equal(await js('document.querySelector(".node-list").clientHeight > 20'), true);
      if (process.env.SCREENSHOT_DIR && width === 390 && height === 844) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-mobile-open.png"), Buffer.from(image.data, "base64"));
      }
      await js('document.querySelector(".node-popover").hidePopover()');
      await until('document.querySelectorAll(".selector-node").length === 0');
      if (process.env.SCREENSHOT_DIR && height >= 600) {
        await js('window.scrollTo(0, 0)');
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: false });
        await writeFile(join(process.env.SCREENSHOT_DIR, `dae-web-selector-${width}x${height}.png`), Buffer.from(image.data, "base64"));
      }
      await visit("overview");
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
      assert.equal(await js(`(() => { const nav = document.querySelector("#setting-navigation").getBoundingClientRect(); const content = document.querySelector("#setting-content").getBoundingClientRect(); const links = [...document.querySelectorAll("#setting-navigation a, #setting-navigation [role=tab]")].map(link => link.getBoundingClientRect()); return ${width} >= 960 ? nav.right < content.left && nav.top === content.top && links.every((rect, i) => !i || rect.top >= links[i - 1].bottom) : nav.bottom < content.top && links.every(rect => rect.top === links[0].top); })()`), true, `Setting uses a left sidebar or top tabs at ${width}px`);
      const fieldSizes = await js<{ inputHeight: number; selectHeight: number; inputWidth: number }>('(() => { const input = document.querySelector("#diagnostic-target").getBoundingClientRect(); const select = document.querySelector("#diagnostic-protocol").getBoundingClientRect(); return { inputHeight: input.height, selectHeight: select.height, inputWidth: input.width }; })()');
      assert.equal(fieldSizes.inputHeight === fieldSizes.selectHeight && fieldSizes.inputWidth >= 240, true, `aligned diagnostic inputs at ${width}px: ${JSON.stringify(fieldSizes)}`);
      assert.equal(await js('document.documentElement.scrollWidth <= document.documentElement.clientWidth'), true, `testing fits at ${width}px`);
      assert.equal(await js('(() => { const header = document.querySelector(".page-header").getBoundingClientRect(); return [...document.querySelectorAll("#setting-page, footer")].every(element => { const rect = element.getBoundingClientRect(); return Math.abs(rect.left - header.left) < 1 && Math.abs(rect.right - header.right) < 1; }); })()'), true, `testing content aligns with the page at ${width}px`);
      assert.equal(await js('(() => { const nav = document.querySelector(".page-nav").getBoundingClientRect(); const heading = document.querySelector(".page-heading").getBoundingClientRect(); const refresh = document.querySelector("#refresh").getBoundingClientRect(); const links = [...document.querySelectorAll(".page-nav a")].map(link => link.getBoundingClientRect()); const center = rect => (rect.top + rect.bottom) / 2; return (innerWidth <= 760 ? nav.top > heading.bottom && nav.right < refresh.left && Math.abs(center(nav) - center(refresh)) < 1 : nav.left > heading.right && (innerWidth < 1024 || Math.abs(center(nav) - center(refresh)) < 1)) && links.every(link => link.top === links[0].top && link.height >= (innerWidth <= 760 ? 44 : 36)); })()'), true, `header forms one bar on desktop and keeps navigation beside refresh on mobile at ${width}px`);
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
    await js('document.querySelector("#diagnostic-kind").value = "dns"; document.querySelector("#diagnostic-kind").dispatchEvent(new Event("change", { bubbles: true }))');
    assert.equal(await js('document.querySelector("#diagnostic-qtype").checkVisibility() && !document.querySelector("#diagnostic-sni").checkVisibility()'), true);
    await js('document.querySelector("#diagnostic-kind").value = "flow"; document.querySelector("#diagnostic-kind").dispatchEvent(new Event("change", { bubbles: true }))');
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
