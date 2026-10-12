import type { ProtocolMapping } from "devtools-protocol/types/protocol-mapping.js";
import type { Protocol } from "devtools-protocol";

type Commands = ProtocolMapping.Commands;
type Events = ProtocolMapping.Events;
type EventMessage = { [Event in keyof Events]: { method: Event; params: Events[Event][0] } }[keyof Events];
type Reply = { id: number; result?: unknown; error?: { code: number; message: string } };

export function cdp(socket: WebSocket) {
  let sequence = 0;
  const pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: unknown) => void }>();
  const exceptions: Protocol.Runtime.ExceptionDetails[] = [];
  const browserLogs: string[] = [];
  socket.onmessage = ({ data }) => {
    const message: EventMessage | Reply = JSON.parse(String(data));
    if ("method" in message) {
      if (message.method === "Runtime.exceptionThrown") exceptions.push(message.params.exceptionDetails);
      if (message.method === "Log.entryAdded") browserLogs.push(message.params.entry.text);
      if (message.method === "Network.loadingFailed") browserLogs.push(JSON.stringify(message.params));
      return;
    }
    const command = pending.get(message.id);
    if (!command) return;
    pending.delete(message.id);
    if (message.error) command.reject(new Error(message.error.message));
    else command.resolve(message.result);
  };

  function call<Method extends keyof Commands>(method: Method, ...[params]: Commands[Method]["paramsType"]): Promise<Commands[Method]["returnType"]> {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, { resolve: value => resolve(value as Commands[Method]["returnType"]), reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async function js<T = unknown>(expression: string): Promise<T> {
    const result = await call("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value as T;
  }

  return { call, js, exceptions, browserLogs };
}
