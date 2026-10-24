// Real Go Cookie/CORS/proxy behavior, using the production browser HTTP boundary.
import assert from "node:assert/strict";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import ts from "typescript";
import { apiTarget } from "../tooling/api-target.ts";
import { cdp } from "./cdp.ts";

const exec = promisify(execFile);
const temporary = await mkdtemp(join(tmpdir(), "dae-session-browser-"));
const children: ChildProcess[] = [];
const root = join(temporary, "ca.pem"), key = join(temporary, "ca.key");
const assets = join(temporary, "public");
const repo = fileURLToPath(new URL("../../", import.meta.url));
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

type Entry = "direct" | "same-site" | "proxy" | "cross-site";
interface Result { ok: boolean; value?: Record<string, unknown>; status?: number; error?: string; invalidSession?: boolean }

function output(child: ChildProcess, pattern: RegExp, stderr = false): Promise<string> {
  return new Promise((resolve, reject) => {
    let received = "";
    const timeout = setTimeout(() => reject(new Error(`Process did not emit ${pattern}: ${received}`)), 15000);
    child.once("error", error => { clearTimeout(timeout); reject(error); });
    child.once("exit", (code, signal) => { clearTimeout(timeout); reject(new Error(`Process exited: ${code ?? signal}\n${received}`)); });
    (stderr ? child.stderr : child.stdout)!.on("data", data => {
      received += String(data);
      const match = received.match(pattern);
      if (match) { clearTimeout(timeout); resolve(match[1]!); }
    });
  });
}

let socket: WebSocket | undefined;
try {
  await mkdir(assets);
  await exec("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", root, "-subj", "/CN=dae session browser CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  const binary = join(temporary, "server");
  await exec("go", ["build", "-o", binary, "./internal/testutil/certbrowser"], { cwd: repo });
  const server = spawn(binary, [root, key, assets, "session"], { stdio: ["ignore", "pipe", "pipe"] });
  children.push(server);
  const origins = JSON.parse(await output(server, /^(\{[^\n]+\})\n/m)) as Record<Entry, string>;
  assert.deepEqual(Object.keys(origins).sort(), ["cross-site", "direct", "proxy", "same-site"]);
  const source = await readFile(new URL("../src/api.ts", import.meta.url), "utf8");
  for (const name of Object.keys(origins) as Entry[]) {
    const directory = join(assets, name);
    await mkdir(directory);
    const target = apiTarget(name === "same-site" || name === "cross-site" ? origins.direct : "");
    await writeFile(join(directory, "dae-web.json"), JSON.stringify({ api_origin: target }));
    await writeFile(join(directory, "api.js"), ts.transpileModule(`const __DAE_API_URL__ = ${JSON.stringify(target)};\n${source}`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);
    await writeFile(join(directory, "probe.js"), `
      import {request, certificateRequest, apiOrigin, errorStatus, errorMessage, HTTPError} from "./api.js";
      const result = async action => {
        try { return {ok: true, value: await action()}; }
        catch (error) { return {ok: false, status: errorStatus(error), error: errorMessage(error), invalidSession: error instanceof HTTPError && error.invalidSession}; }
      };
      window.management = (path, method = "GET", key) => result(() => request(path, method, undefined, key ? {Authorization: "Bearer " + key} : {}));
      window.checkCA = () => result(certificateRequest);
      window.publicProof = () => fetch(new URL("/api/certificate/tests/not-a-challenge", apiOrigin()), {mode: "cors", credentials: "omit", redirect: "error"}).then(response => response.status);
    `);
    await writeFile(join(directory, "index.html"), '<!doctype html><title>dae session test</title><script type="module" src="/probe.js"></script>');
  }

  const profile = join(temporary, "profile"), database = join(profile, ".pki", "nssdb");
  await mkdir(database, { recursive: true });
  await exec("certutil", ["-N", "--empty-password", "-d", `sql:${database}`]);
  await exec("certutil", ["-A", "-d", `sql:${database}`, "-n", "dae-session-test", "-t", "C,,", "-i", root]);
  const browser = spawn(process.env.CHROMIUM || "chromium", ["--headless", "--disable-gpu", "--no-first-run", "--no-proxy-server", "--remote-debugging-port=0", `--user-data-dir=${join(profile, "browser")}`, "about:blank"], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, HOME: profile, XDG_CONFIG_HOME: join(profile, "config"), XDG_CACHE_HOME: join(profile, "cache") } });
  children.push(browser);
  const endpoint = new URL(await output(browser, /DevTools listening on (ws:\/\/\S+)/, true));
  const tab = await (await fetch(`http://${endpoint.host}/json/new?about:blank`, { method: "PUT" })).json() as { webSocketDebuggerUrl: string };
  socket = new WebSocket(tab.webSocketDebuggerUrl);
  await once(socket, "open");
  const { call, js, exceptions, browserLogs } = cdp(socket);
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
  const page = async (name: Entry) => {
    await call("Page.navigate", { url: "about:blank" });
    await until('location.href === "about:blank"');
    await call("Page.navigate", { url: origins[name] });
    await until('typeof window.management === "function"');
  };
  const request = (path: string, method = "GET", rawKey?: string) => js<Result>(`management(${JSON.stringify(path)}, ${JSON.stringify(method)}, ${JSON.stringify(rawKey)})`);
  const denied = (result: Result, status: number) => {
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.status, status, `error is readable, not a CORS/network failure: ${JSON.stringify(result)}`);
  };
  const cookies = async () => (await call("Network.getCookies", { urls: Object.values(origins) })).cookies.filter(cookie => cookie.name === "__Host-dae-session");

  for (const name of ["direct", "same-site", "proxy"] as const) {
    for (const role of ["user", "admin"] as const) {
      await call("Network.clearBrowserCookies");
      await page(name);
      denied(await request("/api/status"), 401);
      const login = await request("/api/session", "PUT", `test-${role}`);
      assert.equal(login.ok, true, JSON.stringify(login));
      assert.ok(login.value);
      assert.deepEqual(Object.keys(login.value).sort(), ["expires_at", "role"]);
      assert.equal(login.value.role, role);
      assert.ok(Date.parse(String(login.value.expires_at)) > Date.now());
      const stored = await cookies();
      assert.equal(stored.length, 1);
      assert.ok(stored[0]!.httpOnly && stored[0]!.secure);
      assert.equal(stored[0]!.sameSite, "Strict");
      assert.equal(stored[0]!.path, "/");
      assert.equal(stored[0]!.domain, "127.0.0.1", "host-only cookie without a Domain attribute");
      assert.equal(await js("document.cookie"), "");
      assert.equal(await js("localStorage.length + sessionStorage.length"), 0);
      assert.equal((await request("/api/status")).ok, true);
      denied(await request("/api/session", "PUT"), 401);
      denied(await request("/api/session", "PUT", "wrong-key"), 401);
      await page(name);
      assert.equal((await request("/api/status")).ok, true, "Cookie survives document reload");
      if (name === "proxy") {
        denied(await request("/api/device/context"), 403);
        denied(await request("/api/certificate/tests", "POST"), 403);
        denied(await js<Result>("checkCA()"), 403);
        assert.equal(await js("publicProof()"), 403, "proxy cannot fetch even an unauthenticated certificate proof");
      }
      assert.equal((await request("/api/session", "DELETE")).ok, true);
      assert.equal((await cookies()).length, 0);
      denied(await request("/api/status"), 401);
      console.log(`PASS real Go session ${name}: ${role} Cookie login, reload and logout`);
    }
  }

  await page("same-site");
  await call("Network.setCookie", { url: origins.direct, name: "__Host-dae-session", value: "stale", secure: true, httpOnly: true, sameSite: "Strict", path: "/" });
  const stale = await request("/api/status");
  denied(stale, 401);
  assert.equal(stale.invalidSession, true, "same-site Web can identify an invalid session");
  assert.equal((await request("/api/session", "DELETE")).ok, true);
  assert.equal((await cookies()).length, 0);

  assert.equal((await request("/api/session", "PUT", "test-user")).ok, true);
  await call("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: temporary });
  await js(`{
    const link = document.createElement("a");
    link.href = new URL("/api/certificate/ca.mobileconfig", ${JSON.stringify(origins.direct)}).href;
    link.referrerPolicy = "origin";
    document.body.append(link);
    link.click();
  }`);
  let profileData: string | undefined;
  const downloadDeadline = Date.now() + 10000;
  while (profileData === undefined && Date.now() < downloadDeadline) {
    profileData = await readFile(join(temporary, "ca.mobileconfig"), "utf8").catch(error => {
      if (error.code !== "ENOENT") throw error;
      return undefined;
    });
    if (profileData === undefined) await delay(30);
  }
  assert.match(profileData ?? "", /com\.apple\.security\.root/, "native navigation downloaded the CA profile across HTTPS ports");
  console.log("PASS real Go native CA profile navigation from an approved same-site page");

  // The foreign page is explicitly allowlisted, so a readable 403 proves that
  // browser Fetch Metadata rejects it independently of CORS and credentials.
  await page("direct");
  assert.equal((await request("/api/session", "PUT", "test-admin")).ok, true);
  await page("cross-site");
  denied(await request("/api/status"), 403);
  for (const key of ["test-user", "test-admin"]) denied(await request("/api/session", "PUT", key), 403);
  assert.equal(await js("document.cookie"), "");
  assert.equal(await js("localStorage.length + sessionStorage.length"), 0);
  await page("direct");
  assert.equal((await request("/api/status")).ok, true, "cross-site failure did not replace the existing session");
  assert.equal((await request("/api/session", "DELETE")).ok, true);
  assert.deepEqual(exceptions, []);
  assert.deepEqual(browserLogs.filter(entry => /Content Security Policy|Refused to/i.test(entry)), []);
  console.log("PASS allowlisted cross-site page cannot use or mint management sessions");
} finally {
  socket?.close();
  await Promise.all(children.filter(child => child.exitCode === null && child.signalCode === null).map(async child => {
    const stopped = once(child, "exit");
    child.kill();
    await stopped;
  }));
  await rm(temporary, { recursive: true, force: true });
}
