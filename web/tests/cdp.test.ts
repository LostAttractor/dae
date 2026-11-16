import assert from "node:assert/strict";
import test from "node:test";
import { cdp } from "./cdp.ts";

class Socket extends EventTarget {
  readyState: number = WebSocket.OPEN;
  sent: string[] = [];
  send(message: string) { this.sent.push(message); }
}

test("CDP disconnect rejects every pending command", { timeout: 1000 }, async () => {
  const socket = new Socket();
  const { call, js } = cdp(socket as unknown as WebSocket);
  const rejected = Promise.all([
    assert.rejects(call("Page.enable"), /CDP connection closed/),
    assert.rejects(js("document.title"), /CDP connection closed/),
  ]);
  assert.equal(socket.sent.length, 2);
  socket.readyState = WebSocket.CLOSED;
  socket.dispatchEvent(new Event("close"));
  await rejected;
  await assert.rejects(call("Page.enable"), /CDP connection is not open/);
  assert.equal(socket.sent.length, 2);
});

test("CDP does not send commands without an open connection", async () => {
  for (const state of [WebSocket.CONNECTING, WebSocket.CLOSING, WebSocket.CLOSED]) {
    const socket = new Socket();
    socket.readyState = state;
    const { call } = cdp(socket as unknown as WebSocket);
    await assert.rejects(call("Page.enable"), /CDP connection is not open/);
    assert.equal(socket.sent.length, 0);
  }
});
