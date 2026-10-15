// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const fs = require("node:fs");
const vm = require("node:vm");
const maxFrame = Number(process.argv[1]);

function readExact(size) {
  const data = Buffer.allocUnsafe(size);
  let offset = 0;
  while (offset < size) {
    const n = fs.readSync(0, data, offset, size - offset, null);
    if (!n) process.exit(0);
    offset += n;
  }
  return data;
}
function read() {
  const size = readExact(4).readUInt32BE();
  if (!size || size > maxFrame) process.exit(1);
  return JSON.parse(readExact(size).toString("utf8"));
}
function write(message) {
  const data = Buffer.from(JSON.stringify(message));
  if (data.length > maxFrame) process.exit(1);
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(data.length);
  for (const chunk of [header, data]) {
    let offset = 0;
    while (offset < chunk.length) offset += fs.writeSync(1, chunk, offset, chunk.length - offset);
  }
}

// Only primitives cross back into the script realm, including host errors.
// The injected functions are captured by realm-local wrappers and then deleted.
function host(argsJSON) {
  try {
    const args = JSON.parse(argsJSON);
    if (!Array.isArray(args) || args.length > 5 || args.some(arg => typeof arg !== "string"))
      return JSON.stringify({error: "host callback accepts at most 5 string arguments"});
    write({kind: "host", args: args.map(arg => arg.toWellFormed())});
    const result = read();
    if (result.op !== "reply") process.exit(1);
    return JSON.stringify(result);
  } catch (_) {
    return JSON.stringify({error: "Node host bridge failed"});
  }
}
Object.setPrototypeOf(host, null);

const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const bufferOf = Function.prototype.call.bind(Object.getOwnPropertyDescriptor(typedArray, "buffer").get);
const offsetOf = Function.prototype.call.bind(Object.getOwnPropertyDescriptor(typedArray, "byteOffset").get);
const lengthOf = Function.prototype.call.bind(Object.getOwnPropertyDescriptor(typedArray, "byteLength").get);
function codec(kind, data) {
  try {
    if (kind === "encode") return Buffer.from(bufferOf(data), offsetOf(data), lengthOf(data)).toString("base64");
    if (kind === "decode" && typeof data === "string") return Buffer.from(data, "base64").toString("latin1");
  } catch (_) {}
  return null;
}
Object.setPrototypeOf(codec, null);

const prelude = new vm.Script(`
(function (call, codec, input) {
  "use strict";
  delete globalThis.__daeCall;
  delete globalThis.__daeCodec;
  delete globalThis.__daeInputText;
  const parse = JSON.parse, stringify = JSON.stringify;
  globalThis.__daeHost = (...args) => {
    const result = parse(call(stringify(args)));
    if (result.error) throw new TypeError(result.error);
    return result.value;
  };
  globalThis.__daeInput = parse(input);
  if (!Uint8Array.prototype.toBase64) Object.defineProperty(Uint8Array.prototype, "toBase64", {
    configurable: true, writable: true,
    value: function () {
      if (!(this instanceof Uint8Array)) throw new TypeError("Expected Uint8Array");
      const value = codec("encode", this);
      if (value === null) throw new TypeError("Invalid bytes");
      return value;
    }
  });
  if (!Uint8Array.fromBase64) Uint8Array.fromBase64 = text => {
    const raw = codec("decode", String(text));
    if (raw === null) throw new TypeError("Invalid base64");
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  };
  Atomics.wait = () => { throw new TypeError("Blocking Atomics.wait is unavailable"); };
})(__daeCall, __daeCodec, __daeInputText);
`, {filename: "dae-node-prelude.js"});

let context, bootstrap;

// Like QuickJS, rejected promises do not complete an invocation; it still needs
// $done. Drain Node's rejection bookkeeping between commands so its pending
// rejection map cannot retain retired script contexts indefinitely.
process.on("unhandledRejection", () => {});
async function serve() {
  for (;;) {
    const command = read();
    try {
      switch (command.op) {
        case "init":
          bootstrap = new vm.Script(command.text, {filename: "dae-surge-bootstrap.js"});
          break;
        case "context":
          context = vm.createContext(vm.constants.DONT_CONTEXTIFY, {microtaskMode: "afterEvaluate"});
          context.__daeCall = host;
          context.__daeCodec = codec;
          context.__daeInputText = command.text;
          prelude.runInContext(context);
          break;
        case "bootstrap": bootstrap.runInContext(context); break;
        case "eval": new vm.Script(command.text, {filename: "surge.js"}).runInContext(context); break;
        case "dispatch":
          // Embed only serialized primitives, never evaluate callback objects in
          // the outer realm or share its Promise queue with a script.
          vm.runInContext("__daeDispatch(" + command.id + "," + JSON.stringify(command.text) + ")", context);
          break;
        case "reset": context = undefined; break;
        default: throw new Error("Invalid Node worker command");
      }
      write({kind: "ok"});
    } catch (error) {
      write({kind: "error", error: String(error)});
    }
    await new Promise(resolve => setImmediate(resolve));
  }
}
serve().catch(() => process.exit(1));
