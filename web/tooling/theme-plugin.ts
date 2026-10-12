import { dataTokenDefaults, generateThemeCSS } from "@astryxdesign/core/theme";
import { theme } from "../src/theme.ts";
import type { Plugin } from "vite";

// Astryx's built theme and static Layer rules are shared by dev and production.
// The stylesheet ID keeps Layer from injecting inline rules under dae's CSP.
export async function themePlugin(): Promise<Plugin> {
  const { slideRulesCss }: { slideRulesCss: () => string } = await import(new URL("layerSlideRules.js", import.meta.resolve("@astryxdesign/core/Layer")).href);
  const layers = slideRulesCss();
  const css = generateThemeCSS(theme);
  const data = Object.entries(dataTokenDefaults).map(([name, value]) => `${name}:${value};`).join("");
  return {
    name: "dae-theme",
    resolveId(id) {
      if (id === "dae-theme" || id === "dae-theme.css") return `\0${id}`;
    },
    load(id) {
      if (id === "\0dae-theme") return `export const theme = ${JSON.stringify({ ...theme, __built: true })}`;
      if (id === "\0dae-theme.css") return `@layer reset {${css.prose}}\n@layer astryx-base {:root {${data}}}\n@layer astryx-theme {${css.component}}`;
    },
    transformIndexHtml() {
      return [{ tag: "link", attrs: { id: "astryx-layer-slide-rules", rel: "stylesheet", href: "/astryx-layers.css" }, injectTo: "head" }];
    },
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.split("?")[0] !== "/astryx-layers.css") return next();
        res.setHeader("Content-Type", "text/css");
        res.end(layers);
      });
    },
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "astryx-layers.css", source: layers });
    },
  };
}
