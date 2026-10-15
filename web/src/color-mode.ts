// Kumo selects its dark palette with data-mode; follow the system preference.
export function followColorScheme(root = document.documentElement) {
  const dark = matchMedia("(prefers-color-scheme: dark)");
  const apply = () => { root.dataset.mode = dark.matches ? "dark" : "light"; };
  dark.addEventListener("change", apply);
  apply();
}
