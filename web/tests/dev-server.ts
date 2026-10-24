import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createServer, resolveConfig } from "vite";
import { apiTarget } from "../tooling/api-target.ts";
import type { HMRPayload } from "vite";
import { serverPort } from "./server.ts";

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
    const production = await resolveConfig({ configFile: fileURLToPath(new URL("../vite.config.ts", import.meta.url)), logLevel: "silent" }, "build");
    assert.equal(production.define?.__DAE_API_URL__, JSON.stringify(target), "build and development share the fixed API target");
    assert.equal(vite.config.define?.__DAE_API_URL__, production.define?.__DAE_API_URL__);
    const plugin = production.plugins.find(plugin => plugin.name === "dae-api-target");
    assert.ok(plugin && typeof plugin.generateBundle === "function");
    const emitted: unknown[] = [];
    await Reflect.apply(plugin.generateBundle, { emitFile: (asset: unknown) => emitted.push(asset) }, []);
    assert.deepEqual(emitted, [{ type: "asset", fileName: "dae-web.json", source: JSON.stringify({ api_origin: target }) }]);
  } finally {
    if (previous === undefined) delete process.env.DAE_API_URL;
    else process.env.DAE_API_URL = previous;
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
