import { defineConfig, loadEnv } from "vite";
import type { UserConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { apiTarget } from "./tooling/api-target.ts";

const root = fileURLToPath(new URL("./", import.meta.url));

export default defineConfig(({ mode }): UserConfig => {
  const target = apiTarget(loadEnv(mode, root, "DAE_").DAE_API_URL);
  const metadata = JSON.stringify({ api_origin: target });
  return {
    root: join(root, "src"),
    envDir: root,
    appType: "mpa",
    plugins: [react(), tailwindcss(), {
      name: "dae-api-target",
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
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      cors: false,
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
