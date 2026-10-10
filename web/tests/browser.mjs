// Browser regressions use Node's built-ins and an installed Chromium; no npm dependencies.
import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTLSServer } from "node:https";
import { createServer as createTCPServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const source = fileURLToPath(new URL("../src/", import.meta.url));
const profile = await mkdtemp(join(tmpdir(), "dae-web-"));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deferred = () => Promise.withResolvers();
let fixture;
const tlsServers = {};
const mitmOrigins = ["https://203.0.113.254", "https://[2001:db8:ffff::254]"];
let proxy;

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
  for (const kind of ["trust", "mitm", "untrusted"]) {
    const server = createTLSServer({ cert: await readFile(kind === "untrusted" ? untrusted : leaf), key: await readFile(kind === "untrusted" ? untrustedKey : leafKey) }, (req, res) => {
      if (req.headers.origin !== origin || req.url !== "/test/browser-proof") return res.writeHead(403).end();
      const stage = kind === "mitm" ? "mitm" : "trust";
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
    if (!fixture || fixture.bypass || !["203.0.113.254:443", "[2001:db8:ffff::254]:443"].includes(req.url)) return socket.destroy();
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) socket.unshift(head);
    tlsServers.mitm.emit("connection", socket);
  });
  proxy.listen(0, "127.0.0.1");
  await once(proxy, "listening");
}

function resetFixture() {
  const nodes = Array.from({ length: 1000 }, (_, i) => ({
    id: `node-${i}`, name: i < 3 ? ["Hong Kong", "Tokyo", "Singapore"][i] : `Node ${i} · ${"Long subscription name ".repeat(4)}`,
    healthy: i === 0, tested: i === 0, tracking: i === 0, checking: false,
    ...(i === 0 ? { latency_ms: 28.5, checked_at: "2026-09-22T00:00:00Z" } : {}),
  }));
  fixture = {
    mode: "lan", requests: [], nextRead: null,
    nextDeviceRead: null, nextGlobalRead: null, certificate: null, groups: [],
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
  const json = (data, status = 200) => {
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(JSON.stringify(data));
  };
  try {
    if (!req.url.startsWith("/api/")) {
      const path = req.url === "/" ? "index.html" : req.url.slice(1);
      if (!/^[a-z-]+\.(html|js|css)$/.test(path)) { res.writeHead(404).end(); return; }
      const types = { html: "text/html", js: "text/javascript", css: "text/css" };
      res.writeHead(200, {
        "Content-Type": types[path.split(".").at(-1)], "Cache-Control": "no-store",
        "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' https://${new URL(origin).hostname.includes(":") ? "*" : new URL(origin).hostname}:${server.address().port}/test/ https://203.0.113.254:443/test/ https://*:443/test/; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
      });
      res.end(await readFile(join(source, path)));
      return;
    }
    if (req.method !== "GET") {
      assert.equal(req.headers["x-dae-api"], "1");
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString() || "{}");
      fixture.requests.push({ method: req.method, path: req.url, body });
      if (req.url === "/api/session") {
        if (req.method === "PUT" && req.headers.authorization !== "Bearer test-key") return json({ error: "Incorrect API key" }, 401);
        res.setHeader("Set-Cookie", req.method === "PUT" ? "session=valid; Path=/api; HttpOnly; SameSite=Strict" : "session=; Path=/api; Max-Age=0");
        res.writeHead(204).end();
        return;
      }
      if (req.url === "/api/probes") {
        const selector = fixture.selectors.find((entry) => entry.name === body.outbound);
        for (const node of selector.nodes) {
          if (!body.node_id || node.id === body.node_id) node.checking = true;
        }
        return json({ outbound: body.outbound, node_ids: selector.nodes.map((node) => node.id) }, 202);
      }
      if (req.url.startsWith("/api/device/sets/")) {
        const set = fixture.device.sets.find((entry) => entry.name === decodeURIComponent(req.url.slice("/api/device/sets/".length)));
        set.joined = req.method === "PUT";
        return json(fixture.device);
      }
      if (req.url === "/api/device/mitm") {
        assert.equal(req.headers["x-dae-mitm"], fixture.device.mitm.ca_fingerprint);
        fixture.device.mitm.override = req.method === "DELETE" ? null : body.enabled;
        fixture.device.mitm.enabled = fixture.device.mitm.override ?? false;
        return json(fixture.device);
      }
      if (req.url === "/api/device/certificate-tests") {
        fixture.testData = { id: "browser-proof", ca_fingerprint: "browser-ca", mitm_enabled: fixture.device.mitm.enabled,
          trust_url: `${origin.replace("http:", "https:")}/test/browser-proof`,
          mitm_url: `${mitmOrigins[new URL(origin).hostname.includes(":") ? 1 : 0]}/test/browser-proof`, trust_observed: false, mitm_observed: false };
        return json(fixture.testData, 201);
      }
      const selector = fixture.selectors.find((entry) => entry.name === decodeURIComponent(req.url.slice("/api/selectors/".length)));
      selector.node_id = req.method === "DELETE" ? selector.default_node_id : body.node_id;
      selector.overridden = req.method !== "DELETE";
      selector.saved_selection = selector.overridden ? { name: selector.nodes.find((node) => node.id === selector.node_id).name, status: "matched" } : undefined;
      return json(selector);
    }
    if (req.url === "/api/selectors") {
      const override = fixture.nextRead;
      fixture.nextRead = null;
      const status = override?.status || (fixture.mode === "denied" ? 403 : fixture.mode === "api_key" && !req.headers.cookie?.includes("session=valid") ? 401 : 200);
      const data = status === 200 ? { auth_mode: fixture.mode, admin_enabled: true, selectors: fixture.selectors } : { error: status === 401 ? "Login required" : status === 403 ? "Direct LAN access required" : "API is reloading" };
      const snapshot = structuredClone(data);
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(snapshot, status);
    }
    if (req.url === "/api/device/status") {
      const override = fixture.nextDeviceRead;
      fixture.nextDeviceRead = null;
      const snapshot = structuredClone({ device: fixture.device, scope: "userspace_upstream", started_at: "2026-10-01T00:00:00Z", stats: fixture.stats, outbounds: [{ name: "device-outbound", stats: fixture.stats }] });
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(override?.status ? { error: "Device unavailable" } : snapshot, override?.status || 200);
    }
    if (req.url === "/api/device/certificate-tests/browser-proof") return json(fixture.testData);
    if (req.url === "/api/status") {
      const override = fixture.nextGlobalRead;
      fixture.nextGlobalRead = null;
      const status = override?.status || (fixture.mode === "denied" ? 403 : fixture.mode === "api_key" && !req.headers.cookie?.includes("session=valid") ? 401 : 200);
      const snapshot = { version: "test-daemon", started_at: "2026-10-01T00:00:00Z", stats: { ...fixture.stats, active_connections: 20 }, direct_fallback_connections: 3, groups: structuredClone(fixture.groups), tables: [], plugins: [] };
      override?.started.resolve();
      if (override?.release) await override.release.promise;
      return json(status === 200 ? snapshot : { error: "Global status unavailable" }, status);
    }
    if (req.url === "/api/device") return json(fixture.device);
    if (req.url === "/api/certificate") return fixture.certificate ? json(fixture.certificate) : json({ error: "No certificate" }, 404);
    json({ error: "Not found" }, 404);
  } catch (error) {
    console.error(error);
    res.writeHead(500).end();
  }
});
const sockets = new Set();
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
let origin = `http://127.0.0.1:${server.address().port}`;
const chromium = spawn(process.env.CHROMIUM || "chromium", [
  "--headless", "--disable-gpu", "--no-first-run", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank",
  ...(proxy ? [`--proxy-server=http://127.0.0.1:${proxy.address().port}`] : []),
], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, HOME: profile, XDG_CONFIG_HOME: join(profile, "config"), XDG_CACHE_HOME: join(profile, "cache") } });
const stopped = new Promise((resolve) => chromium.once("close", resolve));

let socket;
let failures = 0;
try {
  const browserURL = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Chromium did not start")), 15000);
    chromium.once("error", (error) => { clearTimeout(timeout); reject(error); });
    chromium.stderr.on("data", (chunk) => {
      const match = chunk.toString().match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
  });
  const endpoint = new URL(browserURL);
  const target = await (await fetch(`http://${endpoint.host}/json/new?about:blank`, { method: "PUT" })).json();
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await once(socket, "open");
  let sequence = 0;
  const pending = new Map();
  const exceptions = [];
  const browserLogs = [];
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === "Runtime.exceptionThrown") exceptions.push(message.params.exceptionDetails);
    if (message.method === "Log.entryAdded") browserLogs.push(message.params.entry.text);
    if (message.method === "Network.loadingFailed") browserLogs.push(JSON.stringify(message.params));
    if (!message.id) return;
    const call = pending.get(message.id);
    pending.delete(message.id);
    message.error ? call.reject(message.error) : call.resolve(message.result);
  };
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const js = async (expression) => {
    const result = await call("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  const until = async (expression) => {
    const end = Date.now() + 10000;
    while (!await js(expression)) {
      if (Date.now() > end) throw Error(`Timed out: ${expression}`);
      await delay(30);
    }
  };
  const ready = () => until('document.querySelector("#controls")?.getAttribute("aria-busy") === "false"');
  const page = async () => {
    await call("Page.navigate", { url: origin });
    await ready();
  };
  const row = 'document.querySelector(".selector-row")';
  const openPicker = async () => {
    await js(`${row}.querySelector('.node-picker').focus(); ${row}.querySelector('.node-picker').click()`);
    await until(`${row}.querySelector('.node-popover').matches(':popover-open') && document.activeElement.matches('.node-search')`);
  };
  const key = (name, code) => call("Input.dispatchKeyEvent", { type: "keyDown", key: name, code: name, windowsVirtualKeyCode: code });
  const test = async (name, action) => {
    if (process.env.TEST_FILTER && !name.includes(process.env.TEST_FILTER)) return;
    resetFixture();
    await call("Network.clearBrowserCookies");
    await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
    await page();
    exceptions.length = 0;
    browserLogs.length = 0;
    try { await action(); assert.deepEqual(exceptions, []); console.log(`PASS ${name}`); }
    catch (error) { failures++; console.error(`FAIL ${name}: ${error.stack}\n${browserLogs.slice(-8).join("\n")}`); }
  };
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
  await call("Log.enable");

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
    assert.equal(fixture.testData.trust_observed, false);
    assert.equal(fixture.testData.mitm_observed, false);
    const ipv4Origin = origin;
    try {
      origin = `http://[::1]:${server.address().port}`;
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

  await test("device statistics remain live without global administration access", async () => {
    fixture.mode = "api_key";
    await page();
    assert.equal(await js('document.querySelector("#global-status-content").hidden'), true);
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /2 KiB/);
    fixture.stats.upload_bytes = 4096;
    await until('document.querySelector("#device-traffic").textContent.includes("4 KiB")');
    await js('document.querySelector("#api-key").value = "test-key"; document.querySelector("#login-form").requestSubmit()');
    await ready();
    assert.equal(await js('document.querySelector("#global-status-content").hidden'), false);
    assert.match(await js('document.querySelector("#global-runtime").textContent'), /test-daemon/);
    await js('document.querySelector("#logout").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-traffic").textContent'), "");
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /4 KiB/);
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
    assert.equal(await js('document.querySelector(".set-row button").textContent'), "Leave");
    assert.match(await js('document.querySelector("#device-traffic").textContent'), /16 KiB/);
    fixture.mode = "api_key";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-traffic").textContent'), "");
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
        if (address === "/api/device/certificate-tests") return reply({ id: "challenge", ca_fingerprint: "test-ca", mitm_enabled: true, trust_url: location.origin.replace("http:", "https:") + "/test/challenge", mitm_url: "https://203.0.113.254/test/challenge" });
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
    await js('document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Accepted by this browser");
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified");
    await js('testMode = "bypass"; document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-mitm-result").textContent'), "Verification incomplete");
    await js('testMode = "tls-error"; document.querySelector("#test-certificate").click()');
    await ready();
    assert.equal(await js('document.querySelector("#certificate-trust-result").textContent'), "Verification incomplete");
    assert.notEqual(await js('document.querySelector("#certificate-mitm-result").textContent'), "Transparent MITM verified");
    fixture.certificate.test_generation = "two";
    await until('document.querySelector("#certificate-trust-result").textContent === "Not tested"');
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
    await js("window.focusedNode = document.activeElement");
    const nodes = fixture.selectors[0].nodes;
    [nodes[0], nodes[1]] = [nodes[1], nodes[0]];
    await until(`${row}.querySelector('.node-list .node-name').textContent === 'Tokyo'`);
    assert.equal(await js("document.activeElement === focusedNode"), true);
  });

  await test("poll failure indicator clears after recovery", async () => {
    fixture.nextRead = { status: 503, started: deferred() };
    await until('document.querySelector("#updated").textContent.includes("failed")');
    await until('!document.querySelector("#updated").textContent.includes("failed")');
  });

  await test("configuration modes, large dropdown, probes and selection", async () => {
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
    await js(`window.searchInput = ${row}.querySelector('.node-search'); searchInput.value = 'Tokyo'; searchInput.dispatchEvent(new Event('input'));`);
    assert.equal(await js('document.querySelectorAll(".selector-node:not([hidden])").length'), 1);
    await js('document.querySelector(".selector-node:not([hidden]) .test-node").click()');
    await ready();
    assert.equal(await js('document.querySelector(".selector-node:not([hidden]) .node-health").textContent'), "Testing…");
    assert.equal(await js('document.querySelector(".node-search") === searchInput && searchInput.value === "Tokyo"'), true);
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
    assert.deepEqual(fixture.requests.at(-1), { method: "PUT", path: "/api/selectors/On%20demand", body: { node_id: "node-0" } });
    assert.equal(fixture.selectors[0].saved_selection.status, "matched");
    assert.equal(await js(`${row}.querySelector('.selection-source').textContent`), "Custom");
  });

  await test("the initial selected node can be pinned without first selecting another node", async () => {
    await openPicker();
    await js('document.querySelector(".select-node").click()');
    await ready();
    assert.equal(fixture.selectors[0].saved_selection.status, "matched");
    assert.equal(fixture.requests.at(-1).method, "PUT");
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
    await js('document.querySelector(".node-search").value = "test"; document.querySelector(".node-search").setSelectionRange(4, 4)');
    await key("Home", 36);
    assert.equal(await js('document.activeElement.matches(".node-search")'), true);
    await js('document.querySelector(".node-search").value = ""; document.querySelector(".node-search").dispatchEvent(new Event("input")); document.querySelector(".test-node").focus()');
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
    assert.equal(await js('document.activeElement.matches(".node-search")'), true);
    await js('document.querySelector(".node-search").value = "missing node"; document.querySelector(".node-search").dispatchEvent(new Event("input"))');
    assert.equal(await js('document.querySelector(".no-nodes").hidden'), false);
    await key("ArrowDown", 40);
    assert.equal(await js('document.activeElement.matches(".node-search")'), true);
    fixture.selectors = [];
    await until('document.querySelector("#selectors").textContent.includes("No selector")');
    assert.equal(await js('document.querySelector("#selector-count").textContent'), "0 groups");
  });

  await test("device descriptions hide configuration names but mutations use the name", async () => {
    assert.deepEqual(await js('[...document.querySelectorAll(".set-row strong")].map((entry) => entry.textContent)'), ["Work network", "gaming"]);
    await js('document.querySelector(".set-row button").click()');
    await ready();
    assert.deepEqual(fixture.requests[0], { method: "PUT", path: "/api/device/sets/internal%2Fwork", body: {} });
    assert.match(await js('document.querySelector("#message").textContent'), /Joined Work network/);
    assert.equal(await js('document.querySelector(".set-row button").getAttribute("aria-label")'), "Leave Work network");
  });

  await test("actions restore keyboard focus after disabling or replacing controls", async () => {
    await openPicker();
    await js('document.querySelector(".test-node").focus(); document.querySelector(".test-node").click()');
    await ready();
    assert.equal(await js('document.querySelector(".node-popover").contains(document.activeElement)'), true, "Probe lost focus outside the popup");
    await key("Escape", 27);
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
    await js('document.querySelector(".set-row button").focus(); document.querySelector(".set-row button").click()');
    await ready();
    assert.equal(await js('document.activeElement.getAttribute("aria-label")'), "Leave Work network");
    fixture.device.mitm = { enabled: false, override: null, ca_fingerprint: "test-ca" };
    await js('document.querySelector("#refresh").focus(); document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.activeElement.id'), "refresh");
    await js('document.querySelector("#mitm .toggle").focus(); document.querySelector("#mitm .toggle").click()');
    await ready();
    assert.equal(await js('document.activeElement.matches(".toggle")'), true);
    await js('document.querySelector("#mitm .reset").focus(); document.querySelector("#mitm .reset").click()');
    await ready();
    assert.equal(await js('document.activeElement.matches(".toggle")'), true);
  });

  await test("cookie login, expired session and delayed reads after logout", async () => {
    fixture.mode = "api_key";
    await page();
    assert.equal(await js('document.querySelector("#login-form").hidden'), false);
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
    await call("Emulation.setDeviceMetricsOverride", { width: 1160, height: 1000, deviceScaleFactor: 1, mobile: false });
    await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
    await js('document.querySelector("#refresh").click()');
    await ready();
    await js('document.querySelector("#global-groups").parentElement.open = true');
    assert.equal(await js('document.querySelectorAll("#global-groups .status-nodes p").length'), 0);
    await js('window.openGroup = document.querySelector("#global-groups .status-entry"); openGroup.querySelector("summary").click(); openGroup.querySelector("summary").focus()');
    await until('openGroup.querySelectorAll(".status-nodes p").length === 80');
    assert.equal(await js('(() => { const list = document.querySelector("#global-groups"); return list.scrollHeight > list.clientHeight && list.clientHeight <= 360; })()'), true);
    assert.equal(await js('(() => { const global = document.querySelector("#global-status-title").closest("section").getBoundingClientRect(); const device = document.querySelector("#device-status-title").closest("section").getBoundingClientRect(); const selectors = document.querySelector(".selectors-card").getBoundingClientRect(); return global.left === device.left && global.right < selectors.left && device.top >= global.bottom; })()'), true);
    await js('document.querySelector("#global-groups").scrollTop = 120');
    fixture.groups[0].nodes[20].stats.active_connections = 41;
    await until('openGroup.querySelectorAll(".status-nodes p")[20].textContent.includes("41 active")');
    assert.equal(await js('openGroup.open && document.activeElement === openGroup.querySelector("summary")'), true);
    assert.equal(await js('document.querySelector("#global-groups").scrollTop'), 120);
    if (process.env.SCREENSHOT_DIR) {
      await js('document.querySelector("#global-groups").scrollTop = 0; window.scrollTo(0, 0)');
      const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
      await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-expanded-status.png"), Buffer.from(image.data, "base64"));
    }
    fixture.groups.reverse();
    await until('document.querySelector("#global-groups").firstElementChild.dataset.name === "direct"');
    assert.equal(await js('openGroup.isConnected && openGroup.open && document.activeElement === openGroup.querySelector("summary")'), true);
    fixture.mode = "api_key";
    await js('document.querySelector("#refresh").click()');
    await ready();
    assert.equal(await js('document.querySelector("#global-groups").childElementCount'), 0);
  });

  await test("responsive layouts and dark mode keep the popup usable", async () => {
    fixture.certificate = { name: "Test CA", fingerprint: "12:34:56:78:".repeat(7) + "12:34:56:78", test_available: true, test_generation: "layout" };
    fixture.device.mitm = { enabled: false, override: null, ca_fingerprint: fixture.certificate.fingerprint };
    await js('document.querySelector("#refresh").click()');
    await ready();
    for (const [width, height, theme] of [[390, 844, "light"], [320, 600, "light"], [390, 220, "dark"], [960, 900, "light"], [1024, 900, "dark"], [1160, 1000, "dark"], [1280, 900, "dark"], [1600, 1000, "light"], [1920, 1080, "dark"], [2560, 1440, "dark"]]) {
      await call("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 500 });
      await call("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
      await openPicker();
      assert.equal(await js('document.documentElement.scrollWidth <= innerWidth'), true);
      assert.equal(await js('(() => { const menu = document.querySelector(".node-popover").getBoundingClientRect(); return menu.left >= 0 && menu.top >= 0 && menu.right <= innerWidth && menu.bottom <= innerHeight; })()'), true);
      assert.equal(await js('document.querySelector(".node-list").clientHeight > 20'), true);
      if (process.env.SCREENSHOT_DIR && width === 390 && height === 844) {
        const image = await call("Page.captureScreenshot", { captureBeyondViewport: true });
        await writeFile(join(process.env.SCREENSHOT_DIR, "dae-web-mobile-open.png"), Buffer.from(image.data, "base64"));
      }
      await js('document.querySelector(".node-popover").hidePopover()');
      await until('document.querySelectorAll(".selector-node").length === 0');
    }
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
