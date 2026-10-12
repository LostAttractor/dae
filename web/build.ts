import { build } from "vite";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

await build({
  configFile: fileURLToPath(new URL("./vite.config.ts", import.meta.url)),
  ...(process.argv[2] ? { build: { outDir: resolve(process.argv[2]) } } : {}),
});
