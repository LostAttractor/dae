// Exercise production Go TLS, CORS and CSP with the production browser request
// helper. Trust stores and warning exceptions belong only to temporary profiles.
import assert from "node:assert/strict";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { connect as connectTLS } from "node:tls";
import ts from "typescript";
import { cdp } from "./cdp.ts";

const exec = promisify(execFile);
const temporary = await mkdtemp(join(tmpdir(), "dae-ca-browser-"));
const children: ChildProcess[] = [];
const root = join(temporary, "ca.pem"), key = join(temporary, "ca.key");
const assets = join(temporary, "public");
const repo = fileURLToPath(new URL("../../", import.meta.url));
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

function output(child: ChildProcess, pattern: RegExp, stderr = false): Promise<string> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Process did not emit ${pattern}`)), 15000);
    child.once("error", error => { clearTimeout(timeout); reject(error); });
    child.once("exit", code => { clearTimeout(timeout); reject(new Error(`Process exited: ${code}`)); });
    (stderr ? child.stderr : child.stdout)!.on("data", data => {
      const match = String(data).match(pattern);
      if (match) { clearTimeout(timeout); resolve(match[1]!); }
    });
  });
}

try {
  await mkdir(assets);
  const source = await readFile(new URL("../src/api.ts", import.meta.url), "utf8");
  await writeFile(join(assets, "api.js"), ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);
  await writeFile(join(assets, "probe.js"), 'import {certificateRequest} from "./api.js"; window.checkCA = () => certificateRequest().then(proof => ({ok: true, proof}), error => ({ok: false, error: String(error)}));');
  await writeFile(join(assets, "index.html"), '<!doctype html><title>dae certificate test</title><script type="module" src="/probe.js"></script>');
  await exec("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", root, "-subj", "/CN=dae trust regression CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  const binary = join(temporary, "server");
  await exec("go", ["build", "-o", binary, "./internal/testutil/certbrowser"], { cwd: repo });
  const server = spawn(binary, [root, key, assets], { stdio: ["ignore", "pipe", "pipe"] });
  children.push(server);
  const port = await output(server, /\[::\]:(\d+)/);
  const caFingerprint = new X509Certificate(await readFile(root)).fingerprint256.replaceAll(":", "");
  const certificateFile = (host: string) => join(temporary, "api-tls", caFingerprint, `${host.replace(/[\[\]]/g, "")}.pem`);
  const managementLeaves = new Map<string, Buffer>();
  const checkManagementLeaf = async (host: string) => {
    // This Node connection only inspects certificate bytes. All trust assertions
    // below run in Chromium without disabling its certificate validation.
    const connection = connectTLS({ host: host.replace(/[\[\]]/g, ""), port: Number(port), rejectUnauthorized: false });
    try {
      await once(connection, "secureConnect");
      const stored = managementLeaves.get(host)!;
      assert.deepEqual(connection.getPeerCertificate().raw, new X509Certificate(stored).raw, `${host}: management leaf not restored`);
      assert.deepEqual(await readFile(certificateFile(host)), stored, `${host}: test changed persistent identity`);
    } finally {
      connection.destroy();
    }
  };
  const lan = Object.values(networkInterfaces()).flat().find(address => address?.family === "IPv4" && !address.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address.address))?.address;
  const hosts = ["127.0.0.1", "[::1]", ...(lan ? [lan] : [])];
  if (!lan) console.log("SKIP LAN-origin certificate test: no private IPv4 interface");

  for (const trusted of [false, true]) {
    const profile = join(temporary, trusted ? "trusted" : "untrusted");
    const database = join(profile, ".pki", "nssdb");
    await mkdir(database, { recursive: true });
    await exec("certutil", ["-N", "--empty-password", "-d", `sql:${database}`]);
    if (trusted) await exec("certutil", ["-A", "-d", `sql:${database}`, "-n", "dae-test", "-t", "C,,", "-i", root]);
    const browser = spawn(process.env.CHROMIUM || "chromium", ["--headless", "--disable-gpu", "--no-first-run", "--no-proxy-server", "--remote-debugging-port=0", `--user-data-dir=${join(profile, "browser")}`, "about:blank"], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, HOME: profile, XDG_CONFIG_HOME: join(profile, "config"), XDG_CACHE_HOME: join(profile, "cache") } });
    children.push(browser);
    const endpoint = new URL(await output(browser, /DevTools listening on (ws:\/\/\S+)/, true));
    const target = await (await fetch(`http://${endpoint.host}/json/new?about:blank`, { method: "PUT" })).json() as { webSocketDebuggerUrl: string };
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await once(socket, "open");
    const { call, js, browserLogs } = cdp(socket);
    await call("Page.enable");
    await call("Network.enable");
    await call("Log.enable");
    const until = async (expression: string) => {
      const deadline = Date.now() + 10000;
      while (!await js(expression)) {
        if (Date.now() > deadline) throw new Error(`Timed out: ${expression}\n${browserLogs.join("\n")}`);
        await delay(30);
      }
    };
    const page = async (url: string, override = false) => {
      await call("Page.navigate", { url: "about:blank" });
      await call("Page.navigate", { url });
      if (override) {
        await until('document.querySelector("#details-button") !== null');
        await js('document.querySelector("#details-button").click()');
        await until('document.querySelector("#proceed-link")?.checkVisibility()');
        await js('document.querySelector("#proceed-link").click()');
      }
      await until('typeof window.checkCA === "function"');
    };
    try {
      for (const host of hosts) {
        const address = `${host}:${port}`;
        // Accept the persistent management leaf before any challenge exists.
        // No ignore-certificate-errors flag or CDP security bypass is used.
        await page(`https://${address}`, !trusted);
        const stored = await readFile(certificateFile(host));
        if (!managementLeaves.has(host)) managementLeaves.set(host, stored);
        assert.deepEqual(stored, managementLeaves.get(host), `${host}: management identity changed between profiles`);
        const https = await js<{ ok: boolean; error?: string }>("checkCA()");
        assert.equal(https.ok, trusted, `${host} HTTPS warning must not establish CA trust: ${JSON.stringify(https)}`);
        await page(`http://${address}`);
        const initial = await js<{ ok: boolean; error?: string }>("checkCA()");
        assert.equal(initial.ok, trusted, `${host} HTTP trust=${trusted}: ${JSON.stringify(initial)}`);
        const repeated = await js<{ ok: boolean; error?: string }>("checkCA()");
        assert.equal(repeated.ok, trusted, `${host} HTTP after warning override: ${JSON.stringify(repeated)}`);
        assert.deepEqual(await readFile(certificateFile(host)), stored, `${host}: challenge overwrote the management certificate or key`);
        if (trusted) {
          const parallel = await js<Array<{ ok: boolean }>>("Promise.all([checkCA(), checkCA()])");
          assert.ok(parallel.every(result => result.ok), `${host}: parallel trust tests interfered`);
          await checkManagementLeaf(host);
        }
        console.log(`PASS production CA challenge ${host}: ${trusted ? "installed CA succeeds" : "uninstalled CA and accepted HTTPS warning both fail"} from HTTP and HTTPS`);
      }
      if (!trusted) {
        // Failed TLS has no HTTP proof request. Expiry alone must restore the
        // management leaf, including the user's exception for that exact leaf.
        await delay(61000);
        for (const host of hosts) {
          await checkManagementLeaf(host);
          await page(`https://${host}:${port}`);
        }
        console.log("PASS failed challenges expire and restore the unchanged management certificate and its browser exception");
      }
    } finally {
      socket.close();
      const stopped = once(browser, "exit");
      browser.kill();
      await stopped;
    }
  }
} finally {
  await Promise.all(children.filter(child => child.exitCode === null && child.signalCode === null).map(async child => {
    const stopped = once(child, "exit");
    child.kill();
    await stopped;
  }));
  await rm(temporary, { recursive: true, force: true });
}
