import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { connect } from "node:tls";
import { createServer, resolveConfig } from "vite";
import { apiTarget } from "../tooling/api-target.ts";
import type { HMRPayload } from "vite";
import { serverPort } from "./server.ts";

const configFile = fileURLToPath(new URL("../vite.config.ts", import.meta.url));

test("deployment target accepts only HTTPS origins, including proxy domains", () => {
  assert.equal(apiTarget(undefined), "");
  assert.equal(apiTarget(""), "");
  assert.equal(apiTarget("https://192.0.2.1:9080"), "https://192.0.2.1:9080");
  assert.equal(apiTarget("https://API.Example.com:443/"), "https://api.example.com");
  assert.equal(apiTarget("https://[2001:db8::1]:9080"), "https://[2001:db8::1]:9080");
  for (const value of ["192.0.2.1:9080", "http://192.0.2.1", "http://router.local", "https://key@192.0.2.1", "https://192.0.2.1/api", "https://192.0.2.1/?key=secret", "https://192.0.2.1/?", "https://api.example/#fragment", "https://api.example/#", "https://api.example:", "https://api.example:0", "https://api.example:65536", "https://[fe80::1%25eth0]", " https://api.example", "https://api.example;script-src"]) {
    assert.throws(() => apiTarget(value), /DAE_API_URL/);
  }
});

test("Vite serves independent assets and reloads changed source", async t => {
  const directory = await mkdtemp(join(tmpdir(), "dae-vite-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, "index.html"), '<div id="app"></div><script type="module" src="/probe.ts"></script>');
  const stylesheet = fileURLToPath(new URL("../src/style.css", import.meta.url));
  await writeFile(join(directory, "probe.ts"), `import "./probe.css"; import ${JSON.stringify(stylesheet)}; export const value: number = 1;`);
  await writeFile(join(directory, "probe.css"), ':root { --probe: 1; }');
  const target = "https://api.example.com:9080";
  const previous = process.env;
  process.env = { ...previous, DAE_API_URL: target, DAE_DEV_TLS_CERT: "", DAE_DEV_TLS_KEY: "" };
  let vite;
  try {
    vite = await createServer({
      configFile,
      root: directory,
      logLevel: "silent",
      server: { port: 0, fs: { allow: [directory, fileURLToPath(new URL("..", import.meta.url))] } },
      optimizeDeps: { noDiscovery: true },
    });
    const production = await resolveConfig({ configFile, logLevel: "silent" }, "build");
    assert.equal(production.define?.__DAE_API_URL__, JSON.stringify(target), "build and development share the fixed API target");
    assert.equal(vite.config.define?.__DAE_API_URL__, production.define?.__DAE_API_URL__);
    const plugin = production.plugins.find(plugin => plugin.name === "dae-api-target");
    assert.ok(plugin && typeof plugin.generateBundle === "function");
    const emitted: unknown[] = [];
    await Reflect.apply(plugin.generateBundle, { emitFile: (asset: unknown) => emitted.push(asset) }, []);
    assert.deepEqual(emitted, [{ type: "asset", fileName: "dae-web.json", source: JSON.stringify({ api_origin: target }) }]);
  } finally {
    process.env = previous;
  }
  t.after(() => vite.close());
  await vite.listen();
  assert.ok(vite.httpServer);
  const origin = `http://127.0.0.1:${serverPort(vite.httpServer)}`;
  assert.deepEqual(await (await fetch(`${origin}/dae-web.json`)).json(), { api_origin: target });

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

  await t.test("API requests are never proxied by the static development server", async () => {
    assert.equal((await fetch(`${origin}/api/status`)).status, 404);
    assert.equal((await fetch(`${origin}/api/session`, { method: "PUT" })).status, 404);
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

test("only the dev server reads the TLS pair and serves its certificate", async t => {
  const directory = await mkdtemp(join(tmpdir(), "dae-vite-tls-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const cert = join(directory, "cert.pem"), key = join(directory, "key.pem");
  const config = { configFile, root: directory, logLevel: "silent" as const, server: { port: 0 }, optimizeDeps: { noDiscovery: true } };
  const previous = process.env;
  process.env = { ...previous, DAE_DEV_TLS_CERT: cert, DAE_DEV_TLS_KEY: "", DAE_API_CA: "" };
  t.after(() => { process.env = previous; });
  await assert.rejects(resolveConfig(config, "serve"), /Set both DAE_DEV_TLS_CERT and DAE_DEV_TLS_KEY/);
  assert.equal((await resolveConfig(config, "build")).server.https, undefined);
  assert.equal((await resolveConfig(config, "serve", "production", "production", true)).preview.https, undefined);
  const linked = join(directory, "workspace-key");
  await symlink(configFile, linked);
  process.env.DAE_DEV_TLS_KEY = linked;
  await assert.rejects(resolveConfig(config, "serve"), /outside the workspace/);
  process.env.DAE_DEV_TLS_KEY = key;
  await assert.rejects(resolveConfig(config, "serve"), /ENOENT/);

  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=dev", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert], { stdio: "ignore" });
  const router = { ...config, mode: "router" };
  process.env.DAE_API_URL = "";
  await assert.rejects(resolveConfig(router, "serve"), /Set DAE_API_URL/);
  for (const host of ["127.0.0.1", "localhost"]) {
    process.env.DAE_API_URL = `https://${host}:5173`;
    await assert.rejects(resolveConfig({ ...router, server: { port: 5173 } }, "serve"), /not the Vite dev server/);
  }
  process.env.DAE_API_URL = "https://192.0.2.1:9080";
  await assert.rejects(resolveConfig({ ...router, server: { host: true } }, "serve"), /must bind to 127.0.0.1/);
  const build = await resolveConfig(router, "build");
  assert.equal(build.server.proxy, undefined);
  assert.equal(build.define?.__DAE_API_URL__, JSON.stringify(process.env.DAE_API_URL));
  process.env.DAE_DEV_TLS_KEY = process.env.DAE_DEV_TLS_CERT = "";
  await assert.rejects(resolveConfig(router, "serve"), /Set both DAE_DEV_TLS_CERT and DAE_DEV_TLS_KEY/);
  process.env.DAE_DEV_TLS_CERT = cert;
  process.env.DAE_DEV_TLS_KEY = key;
  const vite = await createServer(config);
  t.after(() => vite.close());
  await vite.listen();
  assert.ok(vite.httpServer);
  const socket = connect({ host: "127.0.0.1", port: serverPort(vite.httpServer), ca: await readFile(cert) });
  try { await once(socket, "secureConnect"); assert.ok(socket.authorized); }
  finally { socket.destroy(); }
});
