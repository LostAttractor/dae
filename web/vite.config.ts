import { defineConfig, loadEnv, searchForWorkspaceRoot } from "vite";
import type { UserConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve, sep } from "node:path";
import { apiTarget } from "./tooling/api-target.ts";

const root = fileURLToPath(new URL("./", import.meta.url));

export default defineConfig(({ command, mode, isPreview }): UserConfig => {
  const env = loadEnv(mode, root, "DAE_");
  const dev = command === "serve" && !isPreview;
  const router = dev && mode === "router";
  const upstream = apiTarget(env.DAE_API_URL);
  const target = router ? "" : upstream;
  const metadata = JSON.stringify({ api_origin: target });
  const { DAE_DEV_TLS_CERT: cert, DAE_DEV_TLS_KEY: key } = env;
  let https;
  if (dev && (cert || key || router)) {
    if (!cert || !key) throw new Error("Set both DAE_DEV_TLS_CERT and DAE_DEV_TLS_KEY to enable development HTTPS");
    const configuredKey = resolve(root, key);
    const keyPath = realpathSync(configuredKey);
    const workspace = realpathSync(searchForWorkspaceRoot(root)) + sep;
    if (configuredKey.startsWith(workspace) || keyPath.startsWith(workspace)) {
      throw new Error("Keep DAE_DEV_TLS_KEY outside the workspace served by Vite");
    }
    https = { cert: realpathSync(resolve(root, cert)), key: keyPath };
  }
  if (router && !upstream) throw new Error("Set DAE_API_URL to the router's HTTPS API origin for dev:router");
  return {
    root: join(root, "src"),
    envDir: root,
    appType: "mpa",
    plugins: [react(), tailwindcss(), {
      name: "dae-api-target",
      configResolved(config) {
        if (!router) return;
        if (config.server.host !== "127.0.0.1") throw new Error("dev:router must bind to 127.0.0.1");
        const api = new URL(upstream);
        if (["127.0.0.1", "localhost", "localhost."].includes(api.hostname) && Number(api.port || 443) === config.server.port) {
          throw new Error("DAE_API_URL must point to dae, not the Vite dev server itself");
        }
      },
      generateBundle() { this.emitFile({ type: "asset", fileName: "dae-web.json", source: metadata }); },
      configureServer(server) {
        server.middlewares.use("/dae-web.json", (_request, response) => {
          response.setHeader("Content-Type", "application/json");
          response.setHeader("Cache-Control", "no-store");
          response.end(metadata);
        });
      },
    }],
    define: { __DAE_API_URL__: JSON.stringify(target) },
    server: {
      https,
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      cors: false,
      proxy: router ? {
        "/api/": {
          target: upstream, changeOrigin: true, secure: true,
          headers: { "x-dae-proxy": "1" },
          ca: env.DAE_API_CA ? readFileSync(resolve(root, env.DAE_API_CA), "utf8") : undefined,
        },
      } : undefined,
    },
    build: {
      outDir: join(root, "dist"),
      emptyOutDir: true,
      target: "es2022",
      license: { fileName: "licenses.txt" },
      rolldownOptions: { output: {
        postBanner: "/* Bundled dependency licenses: /licenses.txt */",
        // Keep the shared runtime cached across application and chart updates.
        codeSplitting: { groups: [{ name: "react", test: /node_modules[\\/](?:react|react-dom|scheduler)[\\/]/ }] },
      } },
    },
  };
});
