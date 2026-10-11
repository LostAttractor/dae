import { build } from "esbuild";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { dataTokenDefaults, generateThemeCSS } from "@astryxdesign/core/theme";
import { theme } from "./src/theme.js";

const root = fileURLToPath(new URL("./", import.meta.url));
const output = resolve(process.argv[2] || join(root, "dist"));
await mkdir(output, { recursive: true });
const themeCSS = generateThemeCSS(theme);
// Astryx 0.6.8's Layer installs these static rules at runtime. Serve its own
// generated rules as a stylesheet with the expected ID so style-src 'self'
// remains sufficient. Resolve beside the public Layer entry of the pinned package.
const { slideRulesCss } = await import(new URL("layerSlideRules.js", import.meta.resolve("@astryxdesign/core/Layer")));
await writeFile(join(output, "astryx-layers.css"), slideRulesCss());
const dataCSS = Object.entries(dataTokenDefaults).map(([name, value]) => `${name}:${value};`).join("");
await build({
  entryPoints: [join(root, "src/app.js"), join(root, "src/style.css")],
  outdir: output,
  bundle: true,
  format: "esm",
  jsx: "automatic",
  minify: true,
  target: "es2022",
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "linked",
  logLevel: "info",
  plugins: [{
    name: "dae-theme",
    setup(build) {
      build.onResolve({ filter: /^dae-theme(?:\.css)?$/ }, args => ({ path: args.path, namespace: "dae-theme" }));
      build.onLoad({ filter: /.*/, namespace: "dae-theme" }, args => args.path.endsWith(".css")
        ? { contents: `@layer reset {${themeCSS.prose}}\n@layer astryx-base {:root {${dataCSS}}}\n@layer astryx-theme {${themeCSS.component}}`, loader: "css" }
        : { contents: `export const theme = ${JSON.stringify({ ...theme, __built: true })}`, loader: "js" });
    },
  }],
});
await copyFile(join(root, "src/index.html"), join(output, "index.html"));
