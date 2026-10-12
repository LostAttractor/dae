import { isIP } from "node:net";
import type { Plugin, ProxyOptions } from "vite";

const apiPaths = /^\/(?:api(?:\/|$)|ca\.(?:pem|cer|mobileconfig)(?:\?|$))/;

export function apiTarget(value: string | undefined) {
  let url;
  try { url = new URL(value || ""); } catch { /* Report the expected format below. */ }
  if (!url || url.protocol !== "http:" || !isIP(url.hostname.replace(/^\[|\]$/g, "")) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Set DAE_API_URL to dae's HTTP IP address and port, e.g. http://192.168.1.1:2023 (in .env.local or the environment).");
  }
  return url.origin;
}

export function devProxy(target: string): { plugin: Plugin; proxy: Record<string, ProxyOptions> } {
  return {
    plugin: {
      name: "dae-dev-proxy",
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          if (!apiPaths.test(req.url || "")) return next();
          const host = req.headers.host || "";
          const origin = req.headers.origin;
          const site = req.headers["sec-fetch-site"];
          // Check the browser's origin before translating it to the API origin.
          // Do not turn cross-origin requests into trusted LAN requests.
          if (!/^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host) || (origin && origin !== `http://${host}`) || (site && site !== "same-origin" && site !== "none")) {
            res.writeHead(403, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Open the local development page to use the dae API." }));
            return;
          }
          next();
        });
      },
    },
    proxy: {
      [apiPaths.source]: {
        target,
        changeOrigin: true,
        xfwd: false,
        configure(proxy) {
          proxy.on("proxyReq", (upstream, request) => {
            if (request.headers.origin) upstream.setHeader("Origin", target);
          });
        },
      },
    },
  };
}
