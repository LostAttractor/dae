import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer as createHTTPServer, request } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createServer } from "vite";
import { apiTarget } from "../tooling/dev-proxy.ts";
import type { IncomingHttpHeaders } from "node:http";
import type { HMRPayload } from "vite";
import { serverPort } from "./server.ts";

test("development target requires the daemon's literal HTTP address", () => {
  assert.equal(apiTarget("http://192.0.2.1:9080/"), "http://192.0.2.1:9080");
  assert.equal(apiTarget("http://[2001:db8::1]:9080"), "http://[2001:db8::1]:9080");
  for (const value of [undefined, "", "192.0.2.1:9080", "https://192.0.2.1:9080", "http://router.local", "http://key@192.0.2.1", "http://192.0.2.1/api", "http://192.0.2.1/?key=secret"]) {
    assert.throws(() => apiTarget(value), /DAE_API_URL/);
  }
});

test("Vite serves local assets, proxies dae sessions and reloads changed source", async t => {
  const directory = await mkdtemp(join(tmpdir(), "dae-vite-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, "index.html"), '<div id="app"></div><script type="module" src="/probe.ts"></script>');
  const stylesheet = fileURLToPath(new URL("../src/style.css", import.meta.url));
  await writeFile(join(directory, "probe.ts"), `import "./probe.css"; import ${JSON.stringify(stylesheet)}; export const value: number = 1;`);
  await writeFile(join(directory, "probe.css"), ':root { --probe: 1; }');
  const received: { url?: string; method?: string; headers: IncomingHttpHeaders; body: string }[] = [];
  const api = createHTTPServer(async (req, res) => {
    const body = [];
    for await (const chunk of req) body.push(chunk);
    received.push({ url: req.url, method: req.method, headers: req.headers, body: Buffer.concat(body).toString() });
    if (req.url === "/api/session") {
      if (req.headers["x-dae-api"] !== "1" || (req.method === "PUT" && req.headers.authorization !== "Bearer fixture-key")) {
        res.writeHead(401).end();
        return;
      }
      res.setHeader("Set-Cookie", req.method === "PUT"
        ? "dae_session=fixture; Path=/api; HttpOnly; SameSite=Strict"
        : "dae_session=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0");
      res.writeHead(204).end();
    } else if (req.url === "/ca.pem") {
      res.writeHead(200, { "Content-Type": "application/x-pem-file", "Content-Disposition": 'attachment; filename="dae-ca.pem"' }).end("fixture certificate");
    } else if (req.url === "/api/selectors") {
      res.writeHead(req.headers.cookie === "dae_session=fixture" ? 200 : 401, { "Content-Type": "application/json" }).end('{"selectors":[]}');
    } else {
      res.writeHead(404).end();
    }
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  t.after(() => new Promise<void>((resolve, reject) => { api.closeAllConnections(); api.close(error => error ? reject(error) : resolve()); }));
  const target = `http://127.0.0.1:${serverPort(api)}`;
  const previous = process.env.DAE_API_URL;
  process.env.DAE_API_URL = target;
  let vite;
  try {
    vite = await createServer({
      configFile: fileURLToPath(new URL("../vite.config.ts", import.meta.url)),
      root: directory,
      logLevel: "silent",
      server: { port: 0, fs: { allow: [directory, fileURLToPath(new URL("..", import.meta.url))] } },
      optimizeDeps: { noDiscovery: true },
    });
  } finally {
    if (previous === undefined) delete process.env.DAE_API_URL;
    else process.env.DAE_API_URL = previous;
  }
  t.after(() => vite.close());
  await vite.listen();
  assert.ok(vite.httpServer);
  const origin = `http://127.0.0.1:${serverPort(vite.httpServer)}`;
  const browserHeaders = { Origin: origin, "Sec-Fetch-Site": "same-origin" };

  await t.test("HTML, Tailwind styles and component updates use Vite", async () => {
    const html = await (await fetch(origin)).text();
    assert.match(html, /\/@vite\/client/);
    assert.match(html, /\/@react-refresh/);
    const source = await (await fetch(`${origin}/probe.ts`)).text();
    assert.match(source, /style\.css/);
    const styles = await fetch(`${origin}/@fs${stylesheet}?direct`);
    assert.equal(styles.status, 200);
    assert.match(await styles.text(), /--color-kumo-canvas/, "Tailwind compiles Kumo's tokens");
  });

  await t.test("login, authenticated reads and logout preserve headers and cookies", async () => {
    assert.equal((await fetch(`${origin}/api/selectors`)).status, 401);
    const login = await fetch(`${origin}/api/session`, {
      method: "PUT", headers: { ...browserHeaders, "X-Dae-API": "1", Authorization: "Bearer fixture-key" },
    });
    assert.equal(login.status, 204);
    const setCookie = login.headers.get("set-cookie");
    assert.ok(setCookie);
    assert.match(setCookie, /HttpOnly; SameSite=Strict/);
    const cookie = setCookie.split(";")[0];
    assert.equal((await fetch(`${origin}/api/selectors`, { headers: { ...browserHeaders, Cookie: cookie } })).status, 200);
    const last = received.at(-1);
    assert.ok(last);
    assert.equal(last.headers.host, new URL(target).host);
    assert.equal(last.headers.origin, target);
    assert.equal(last.headers["x-forwarded-for"], undefined);
    const logout = await fetch(`${origin}/api/session`, { method: "DELETE", headers: { ...browserHeaders, Cookie: cookie, "X-Dae-API": "1" } });
    assert.equal(logout.status, 204);
    assert.match(logout.headers.get("set-cookie") || "", /Max-Age=0/);
  });

  await t.test("downloads retain their response metadata; unrelated paths stay local", async () => {
    const download = await fetch(`${origin}/ca.pem`);
    assert.equal(await download.text(), "fixture certificate");
    assert.equal(download.headers.get("content-disposition"), 'attachment; filename="dae-ca.pem"');
    const count = received.length;
    for (const path of ["/apiary", "/ca.pem.extra", "/test/proof"]) assert.equal((await fetch(origin + path)).status, 404);
    assert.equal(received.length, count);
  });

  await t.test("foreign origins and forged hosts never reach the daemon", async () => {
    const count = received.length;
    for (const headers of [{ Origin: "http://foreign.example" }, { Origin: "null" }, { "Sec-Fetch-Site": "cross-site" }]) {
      assert.equal((await fetch(`${origin}/api/session`, { method: "PUT", headers: { ...headers, "X-Dae-API": "1" } })).status, 403);
    }
    const status = await new Promise((resolve, reject) => {
      const req = request(`${origin}/api/selectors`, { headers: { Host: "foreign.example", Origin: "http://foreign.example" } }, res => { res.resume(); resolve(res.statusCode); });
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 403);
    assert.equal(received.length, count);
  });

  await t.test("a stylesheet edit reaches the HMR websocket", async () => {
    await fetch(`${origin}/probe.css`);
    const socket = new WebSocket(`${origin.replace("http:", "ws:")}/?token=${vite.config.webSocketToken}`, "vite-hmr");
    t.after(() => socket.close());
    const update = new Promise<HMRPayload>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("No CSS hot update received")), 10000);
      socket.addEventListener("message", event => {
        const message: HMRPayload = JSON.parse(String(event.data));
        if (message.type === "update" && message.updates.some(item => item.path === "/probe.css")) {
          clearTimeout(timeout);
          resolve(message);
        }
      });
    });
    await once(socket, "open");
    await writeFile(join(directory, "probe.css"), ':root { --probe: 2; }');
    await update;
    assert.match(await (await fetch(`${origin}/probe.css`)).text(), /--probe: 2/);
    socket.close();
  });
});
