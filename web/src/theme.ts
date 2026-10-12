import { defineTheme } from "@astryxdesign/core/theme";

// Primer owns the light/dark palette; Astryx owns the component semantics.
// Keep these references intact so every surface follows the same color mode.
export const theme = defineTheme({
  name: "dae-primer",
  typography: {
    body: { family: "system-ui", fallbacks: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" },
    code: { family: "ui-monospace", fallbacks: "'SF Mono', Consolas, monospace" },
  },
  tokens: {
    "--color-accent": "var(--bgColor-accent-emphasis)",
    "--color-accent-muted": "var(--bgColor-accent-muted)",
    "--color-background-body": "var(--bgColor-default)",
    "--color-background-surface": "var(--bgColor-default)",
    "--color-background-card": "var(--bgColor-default)",
    "--color-background-popover": "var(--bgColor-default)",
    "--color-background-muted": "var(--bgColor-muted)",
    "--color-text-primary": "var(--fgColor-default)",
    "--color-text-secondary": "var(--fgColor-muted)",
    "--color-text-disabled": "var(--fgColor-disabled)",
    "--color-text-accent": "var(--fgColor-accent)",
    "--color-icon-primary": "var(--fgColor-default)",
    "--color-icon-secondary": "var(--fgColor-muted)",
    "--color-icon-disabled": "var(--fgColor-disabled)",
    "--color-icon-accent": "var(--fgColor-accent)",
    "--color-border": "var(--borderColor-default)",
    "--color-border-emphasized": "var(--borderColor-emphasis)",
    "--color-success": "var(--fgColor-success)",
    "--color-success-muted": "var(--bgColor-success-muted)",
    "--color-error": "var(--fgColor-danger)",
    "--color-error-muted": "var(--bgColor-danger-muted)",
    "--color-warning": "var(--fgColor-attention)",
    "--color-warning-muted": "var(--bgColor-attention-muted)",
    "--radius-inner": "var(--radius)",
    "--radius-element": "var(--radius)",
    "--radius-container": "var(--radius)",
    "--size-element-md": "2.5rem",
  },
  components: {
    "side-nav": { base: { width: "100%", height: "auto", backgroundColor: "transparent" } },
    "side-nav-item": { base: { minHeight: "44px", fontSize: "1rem", lineHeight: "1.5" } },
    banner: {
      "status:warning": { color: "var(--fgColor-attention)", "--color-text-primary": "var(--fgColor-attention)" },
      "status:error": { color: "var(--fgColor-danger)", "--color-text-primary": "var(--fgColor-danger)" },
    },
    "banner-description": { base: { color: "inherit" } },
    badge: {
      base: { border: "1px solid var(--borderColor-default)", borderRadius: "var(--radius)", height: "auto", minHeight: "1.5rem", padding: "2px 8px", fontSize: ".875rem", lineHeight: "1.4" },
      "variant:neutral": { backgroundColor: "transparent", color: "var(--fgColor-muted)" },
      "variant:error": { borderColor: "var(--borderColor-danger-emphasis)", backgroundColor: "var(--bgColor-danger-muted)", color: "var(--fgColor-danger)" },
      "variant:warning": { borderColor: "var(--borderColor-attention-emphasis)", backgroundColor: "var(--bgColor-attention-muted)", color: "var(--fgColor-attention)" },
      "variant:success": { borderColor: "var(--borderColor-success-emphasis)", backgroundColor: "var(--bgColor-success-muted)", color: "var(--fgColor-success)" },
    },
    "field-label": { base: { fontSize: "1rem", lineHeight: "1.5", fontWeight: "500" } },
    "collapsible-trigger": { base: { minHeight: "44px", fontSize: "1rem", lineHeight: "1.5" } },
    "collapsible-content": { base: { fontSize: "1rem", lineHeight: "1.55" } },
    switch: {
      base: { position: "relative", width: "48px", height: "24px", padding: "2px", borderRadius: "var(--radius)", backgroundColor: "var(--bgColor-default)", boxShadow: "inset 0 0 0 1px var(--borderColor-emphasis)" },
      checked: { backgroundColor: "var(--bgColor-accent-emphasis)", boxShadow: "none" },
    },
    "switch-thumb": {
      base: { width: "20px", height: "20px", borderRadius: "var(--radius)", backgroundColor: "var(--button-default-bgColor-rest)", boxShadow: "inset 0 0 0 1px var(--borderColor-default)", transform: "translateX(0)" },
      checked: { backgroundColor: "var(--fgColor-white)", boxShadow: "none", transform: "translateX(24px)", ":dir(rtl)": { transform: "translateX(-24px)" } },
    },
    toast: {
      base: { backgroundColor: "var(--bgColor-default)", color: "var(--fgColor-default)", border: "1px solid var(--borderColor-default)", fontSize: "1rem" },
      "type:error": { backgroundColor: "var(--bgColor-danger-muted)", color: "var(--fgColor-danger)", borderColor: "var(--borderColor-danger-emphasis)" },
    },
    button: {
      base: { minHeight: "2.5rem", height: "auto", padding: "6px 12px", fontSize: "1rem", lineHeight: "1.5", fontWeight: "500", whiteSpace: "normal" },
      "variant:secondary": { backgroundColor: "var(--button-default-bgColor-rest)", border: "1px solid var(--button-default-borderColor-rest)", color: "var(--button-default-fgColor-rest)", ":hover": { backgroundColor: "var(--button-default-bgColor-hover)" } },
      "variant:primary": { backgroundColor: "var(--button-primary-bgColor-rest)", border: "1px solid var(--button-primary-borderColor-rest)", color: "var(--button-primary-fgColor-rest)", ":hover": { backgroundColor: "var(--button-primary-bgColor-hover)" } },
    },
  },
});
