import { build } from "vite";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { gzip } from "node:zlib";

const outDir = process.argv[2] ? resolve(process.argv[2]) : fileURLToPath(new URL("./dist", import.meta.url));
await build({
  configFile: fileURLToPath(new URL("./vite.config.ts", import.meta.url)),
  build: { outDir },
});

// Compress once at build time, including generated HTML and licenses.
const compress = promisify(gzip);
const entries = await readdir(outDir, { recursive: true, withFileTypes: true });
await Promise.all(entries.filter(entry => entry.isFile() && /\.(?:html|js|css|svg|json|txt)$/.test(entry.name)).map(async entry => {
  const path = join(entry.parentPath, entry.name);
  const source = await readFile(path);
  const compressed = await compress(source, { level: 9 });
  if (compressed.length < source.length) await writeFile(`${path}.gz`, compressed);
}));
