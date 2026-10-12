// HTTP boundary shared by browser clients. All paths are relative to the API origin.
import type { CertificateTestProof } from "./types.ts";

export type HTTPMethod = "GET" | "POST" | "PUT" | "DELETE";

export class HTTPError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

export const errorMessage = (error: unknown): string => error instanceof Error ? error.message : String(error);
export const errorStatus = (error: unknown): number | undefined => error instanceof HTTPError ? error.status : undefined;

export async function request<T = unknown>(path: string, method: HTTPMethod = "GET", body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  if (method === "PUT" || method === "DELETE" || method === "POST") headers["X-Dae-API"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method, headers, cache: "no-store", credentials: "same-origin",
    signal: AbortSignal.timeout(15000),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = response.headers.get("Content-Type")?.startsWith("application/json")
      ? (await response.json()).error : await response.text();
    throw new HTTPError(detail || `Request failed (${response.status}).`, response.status);
  }
  return response.status === 204 ? undefined as T : response.json();
}

// CA tests use HTTPS on the exact API socket. MITM tests use the virtual origins
// advertised by the daemon's certificate metadata.
// Never send management cookies/headers, follow redirects, or accept opaque data.
export async function challengeRequest(address: string, allowedOrigins?: string[]): Promise<CertificateTestProof> {
  const url = new URL(address);
  const allowed = allowedOrigins === undefined
    ? url.hostname === location.hostname && Number(url.port || 443) === Number(location.port || 80)
    : allowedOrigins.includes(url.origin);
  if (url.protocol !== "https:" || !allowed || url.username || url.password || url.search || url.hash || !url.pathname.startsWith("/test/")) {
    throw new Error("Invalid certificate test address");
  }
  const response = await fetch(url, {
    mode: "cors", credentials: "omit", cache: "no-store", redirect: "error",
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Certificate test failed (${response.status})`);
  return response.json();
}
