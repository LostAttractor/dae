// HTTP boundary shared by browser clients. All paths are relative to the API origin.
import type { MITMTestProof, CertificateTest } from "./types.ts";

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

// A temporary leaf excludes previously accepted certificate warnings without
// replacing the persistent management leaf. The proof consumes the challenge.
export async function certificateRequest(): Promise<CertificateTest> {
  const test = await request<CertificateTest>("/api/certificate/tests", "POST");
  const url = new URL(`/api/certificate/tests/${encodeURIComponent(test.id)}`, location.href);
  const port = location.port || (location.protocol === "https:" ? "443" : "80");
  url.protocol = "https:";
  url.port = port;
  const signal = AbortSignal.timeout(10000);
  // Retire pooled connections individually; management requests on other
  // connections remain usable. The server never returns proof over an old leaf.
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const proof = await verifiedHTTPS<CertificateTest>(url, signal);
      if (proof.id !== test.id || proof.ca_fingerprint !== test.ca_fingerprint) throw new Error("Certificate proof does not match the test");
      return proof;
    } catch (error) {
      if (!(error instanceof HTTPError) || error.status !== 409) throw error;
    }
  }
  throw new Error("Could not establish a fresh TLS connection");
}

// MITM proofs may come only from the daemon's advertised virtual destinations.
export function challengeRequest(address: string, allowedOrigins: string[]): Promise<MITMTestProof> {
  const url = new URL(address);
  if (url.protocol !== "https:" || !allowedOrigins.includes(url.origin) || url.username || url.password || url.search || url.hash || !url.pathname.startsWith("/test/")) {
    throw new Error("Invalid MITM test address");
  }
  return verifiedHTTPS<MITMTestProof>(url);
}

// Never send management cookies/headers, follow redirects, or accept opaque data.
async function verifiedHTTPS<T>(url: URL, signal = AbortSignal.timeout(10000)): Promise<T> {
  const response = await fetch(url, {
    mode: "cors", credentials: "omit", cache: "no-store", redirect: "error",
    signal,
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new HTTPError(`Certificate test failed (${response.status})`, response.status);
  }
  return response.json();
}
