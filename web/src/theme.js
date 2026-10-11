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
    "--color-border": "var(--borderColor-default)",
    "--color-border-emphasized": "var(--borderColor-emphasis)",
    "--color-success": "var(--fgColor-success)",
    "--color-success-muted": "var(--bgColor-success-muted)",
    "--color-error": "var(--fgColor-danger)",
    "--color-error-muted": "var(--bgColor-danger-muted)",
    "--color-warning": "var(--fgColor-attention)",
    "--color-warning-muted": "var(--bgColor-attention-muted)",
    "--radius-inner": "2px",
    "--radius-element": "2px",
    "--radius-container": "2px",
    "--size-element-md": "2.5rem",
  },
  components: {
    "switch-label": { base: { fontSize: "1rem", color: "var(--fgColor-default)" } },
    switch: { base: { backgroundColor: "var(--borderColor-emphasis)" }, checked: { backgroundColor: "var(--bgColor-accent-emphasis)" } },
    "switch-thumb": { base: { backgroundColor: "var(--fgColor-onEmphasis)" } },
    button: {
      base: { minHeight: "2.5rem", height: "auto", padding: "6px 12px", fontSize: "1rem", lineHeight: "1.5", fontWeight: "500", whiteSpace: "normal" },
      "variant:secondary": { backgroundColor: "var(--button-default-bgColor-rest)", border: "1px solid var(--button-default-borderColor-rest)", color: "var(--button-default-fgColor-rest)", ":hover": { backgroundColor: "var(--button-default-bgColor-hover)" } },
      "variant:primary": { backgroundColor: "var(--button-primary-bgColor-rest)", border: "1px solid var(--button-primary-borderColor-rest)", color: "var(--button-primary-fgColor-rest)", ":hover": { backgroundColor: "var(--button-primary-bgColor-hover)" } },
    },
  },
});
