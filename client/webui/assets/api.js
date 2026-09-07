// HTTP boundary shared by browser clients. All paths are relative to the API origin.
export async function request(path, method = "GET", body, headers = {}) {
  if (method === "PUT" || method === "DELETE") headers["X-Dae-API"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method, headers, cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = response.headers.get("Content-Type")?.startsWith("application/json")
      ? (await response.json()).error : await response.text();
    const error = new Error(detail || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}
