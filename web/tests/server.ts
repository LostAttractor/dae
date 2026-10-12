import assert from "node:assert/strict";
import type { Server } from "node:net";

export function serverPort(server: Pick<Server, "address">): number {
  const address = server.address();
  assert.ok(address && typeof address !== "string", "fixture server has an IP listener");
  return address.port;
}
