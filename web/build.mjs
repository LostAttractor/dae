import { build } from "esbuild";
import { copyFile, mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("./", import.meta.url));
const output = resolve(process.argv[2] || join(root, "dist"));
await mkdir(output, { recursive: true });
await build({
  entryPoints: [join(root, "src/app.js")],
  outfile: join(output, "app.js"),
  bundle: true,
  format: "esm",
  jsx: "automatic",
  minify: true,
  target: "es2022",
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "linked",
  logLevel: "info",
});
for (const name of ["index.html", "style.css"]) {
  await copyFile(join(root, "src", name), join(output, name));
}
