export function apiTarget(value: string | undefined) {
  if (!value) return ""; // The embedded page uses its own /api endpoint.
  let url;
  if (value.trim() === value && !/[?#]/.test(value)) {
    try { url = new URL(value); } catch { /* Report a single configuration error. */ }
  }
  const authority = value.replace(/^https:\/\//i, "").replace(/\/$/, "");
  const portValid = !url?.port || (/^\d+$/.test(url.port) && Number(url.port) >= 1 && Number(url.port) <= 65535);
  if (!url || url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || !authority || authority.endsWith(":") || !portValid || url.hostname.includes("%") || (!url.hostname.startsWith("[") && !/^[a-z0-9.-]+$/.test(url.hostname))) {
    throw new Error("DAE_API_URL must be an HTTPS origin without a path, e.g. https://api.example.com:9080");
  }
  return url.origin;
}
