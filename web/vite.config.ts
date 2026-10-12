import { defineConfig, loadEnv } from "vite";
import type { UserConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { apiTarget, devProxy } from "./tooling/dev-proxy.ts";
import { themePlugin } from "./tooling/theme-plugin.ts";

const root = fileURLToPath(new URL("./", import.meta.url));

export default defineConfig(async ({ command, mode }): Promise<UserConfig> => {
  const target = command === "serve" ? apiTarget(loadEnv(mode, root, "DAE_").DAE_API_URL) : "";
  const development = target ? devProxy(target) : null;
  return {
    root: join(root, "src"),
    envDir: root,
    appType: "mpa",
    plugins: [react(), await themePlugin(), development?.plugin],
    define: { __DAE_DEV_API_URL__: JSON.stringify(target) },
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      cors: false,
      proxy: development?.proxy,
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
