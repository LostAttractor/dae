// Host capabilities are captured and removed from the global namespace.
(function (host, input) {
  "use strict";
  delete globalThis.__daeHost;
  delete globalThis.__daeInput;
  // Capture the backend's base64 intrinsics before running user scripts. Native
  // encoding avoids building one temporary JS string for every three bytes.
  const toBase64 = Function.prototype.call.bind(Uint8Array.prototype.toBase64);
  const decodeBase64 = Uint8Array.fromBase64;
  function fromBase64(text) {
    text = String(text).replace(/[\t\n\f\r ]/g, "");
    if (text.length % 4 === 0) text = text.replace(/={1,2}$/, "");
    if (text.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(text)) throw new TypeError("Invalid base64");
    return decodeBase64(text);
  }
  function bytes(value) {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new TypeError("Expected an ArrayBuffer or typed array");
  }
  globalThis.atob = text => {
    const data = fromBase64(text), chunks = [];
    for (let i = 0; i < data.length; i += 4096) chunks.push(String.fromCharCode(...data.subarray(i, i + 4096)));
    return chunks.join("");
  };
  globalThis.btoa = text => {
    text = String(text);
    const data = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) {
      const n = text.charCodeAt(i);
      if (n > 255) throw new TypeError("btoa only accepts Latin-1 data");
      data[i] = n;
    }
    return toBase64(data);
  };
  globalThis.TextEncoder = class TextEncoder {
    get encoding() { return "utf-8"; }
    encode(text = "") { return fromBase64(host("encode", String(text))); }
    encodeInto(text, dest) {
      if (!(dest instanceof Uint8Array)) throw new TypeError("Expected Uint8Array");
      let read = 0, written = 0;
      // Write complete code points directly. Encoding each character through
      // the host bridge would require an IPC round trip per character on Node.
      for (const char of String(text)) {
        let code = char.codePointAt(0);
        if (code >= 0xd800 && code <= 0xdfff) code = 0xfffd;
        const size = code <= 0x7f ? 1 : code <= 0x7ff ? 2 : code <= 0xffff ? 3 : 4;
        if (written + size > dest.length) break;
        if (size === 1) dest[written++] = code;
        else {
          dest[written++] = (size === 2 ? 0xc0 : size === 3 ? 0xe0 : 0xf0) | (code >> (6 * (size - 1)));
          for (let shift = 6 * (size - 2); shift >= 0; shift -= 6)
            dest[written++] = 0x80 | ((code >> shift) & 0x3f);
        }
        read += char.length;
      }
      return { read, written };
    }
  };
  globalThis.TextDecoder = class TextDecoder {
    constructor(label = "utf-8", options = {}) {
      if (!["utf-8", "utf8", "unicode-1-1-utf-8"].includes(String(label).trim().toLowerCase()))
        throw new RangeError("Only UTF-8 decoding is supported");
      this.encoding = "utf-8"; this.fatal = !!options.fatal; this.ignoreBOM = !!options.ignoreBOM;
    }
    decode(data = new Uint8Array(), options = {}) {
      if (options.stream) throw new TypeError("Streaming TextDecoder is not supported");
      return host("decode", toBase64(bytes(data)), this.fatal ? "fatal" : "", this.ignoreBOM ? "keep-bom" : "");
    }
  };
  function message(value) {
    if (!value) return undefined;
    value.headers = input.fullHeaders ? value.headers : headerObject(value.headers);
    if (value.h2_trailers != null && !input.fullHeaders) value.h2_trailers = headerObject(value.h2_trailers);
    if (Object.prototype.hasOwnProperty.call(value, "bodyBase64")) {
      value.body = input.binary ? fromBase64(value.bodyBase64) : host("decode", value.bodyBase64, "", "");
      delete value.bodyBase64;
    }
    return value;
  }
  if (input.request) globalThis.$request = message(input.request);
  if (input.response) globalThis.$response = message(input.response);
  if (input.argumentSet) globalThis.$argument = input.argument;
  if (input.type === "dns") globalThis.$domain = input.domain;
  if (input.type === "cron") globalThis.$cronexp = input.cronexp;
  if (input.trigger) globalThis.$trigger = input.trigger;
  globalThis.$script = { name: input.name, type: input.type, startTime: input.startTime, sessionID: input.sessionID, binaryBodyMode: input.binary };
  globalThis.$environment = input.environment;
  function storeKey(key) {
    if (key === undefined) return input.storeKey;
    if (typeof key !== "string" || !key || /[\\/\0]/.test(key)) throw new TypeError("Store key must be a plain name");
    return key;
  }
  globalThis.$persistentStore = {
    read: key => host("read", storeKey(key)),
    write: (value, key) => {
      if (value !== null && typeof value !== "string") throw new TypeError("Store value must be a string or null");
      return host("write", storeKey(key), value === null ? "" : value, value === null ? "delete" : "");
    }
  };
  function log(level, ...args) {
    host("log", level, args.map(v => typeof v === "string" ? v : JSON.stringify(v)).join(" "));
  }
  globalThis.console = {
    log: (...args) => log("info", ...args),
    info: (...args) => log("info", ...args),
    warn: (...args) => log("warn", ...args),
    error: (...args) => log("error", ...args),
    debug: (...args) => log("debug", ...args)
  };
  globalThis.$notification = { post: (title, subtitle, body) => {
    const values = [title, subtitle, body].map(v => typeof v === "string" ? v : JSON.stringify(v) ?? "");
    host("notify", ...values);
  } };
  globalThis.$utils = { ungzip: data => {
    const result = host("ungzip", toBase64(bytes(data)));
    return result === null ? null : fromBase64(result);
  } };
  function headerObject(value) {
    const keyFor = (object, key) => typeof key === "string"
      ? Object.keys(object).find(name => name.toLowerCase() === key.toLowerCase()) ?? key : key;
    return new Proxy(value ?? {}, {
      get: (object, key) => Reflect.get(object, keyFor(object, key)),
      has: (object, key) => Reflect.has(object, keyFor(object, key)),
      set: (object, key, data) => Reflect.set(object, keyFor(object, key), data),
      deleteProperty: (object, key) => Reflect.deleteProperty(object, keyFor(object, key)),
      getOwnPropertyDescriptor: (object, key) => Reflect.getOwnPropertyDescriptor(object, keyFor(object, key))
    });
  }
  function headers(value) {
    if (value == null) return undefined;
    const out = Object.create(null);
    const entries = Array.isArray(value) ? value.map(item => {
      if (!item || typeof item.field !== "string" || typeof item.value !== "string")
        throw new TypeError("Header array requires {field, value} strings");
      return [item.field, item.value];
    }) : Object.entries(value).map(([key, val]) => [key,
      Array.isArray(val) ? val.join(key.toLowerCase() === "cookie" ? "; " : ", ") : String(val)]);
    for (const [key, val] of entries) {
      (out[key.toLowerCase()] ??= []).push(val);
    }
    return out;
  }
  function normalize(value) {
    if (value == null) return {};
    if (typeof value !== "object") throw new TypeError("$done expects an object");
    const out = {};
    if (value.url != null) out.url = String(value.url);
    if (value.headers != null) out.headers = headers(value.headers);
    if (value.h2_trailers != null) out.h2_trailers = headers(value.h2_trailers);
    if (value.status != null) out.status = value.status;
    if (value.abort != null) out.abort = !!value.abort;
    if (value.response != null) out.response = normalize(value.response);
    if (Object.prototype.hasOwnProperty.call(value, "body") && value.body != null) {
      if (typeof value.body === "string") out.body = value.body;
      else out.bodyBase64 = toBase64(bytes(value.body));
    }
    return out;
  }
  let completed = false;
  globalThis.$done = value => {
    if (completed) return;
    host("done", JSON.stringify(input.type === "cron" || input.type === "generic" ? {} : input.type === "dns" ? value ?? {} : normalize(value)));
    completed = true;
  };
  let sequence = 0;
  const callbacks = new Map();
  function registerCallback(callback, operation, payload) {
    const id = ++sequence;
    callbacks.set(id, callback);
    try { host(operation, String(id), payload); }
    catch (error) { callbacks.delete(id); throw error; }
    return id;
  }
  globalThis.__daeDispatch = (id, json) => {
    const callback = callbacks.get(id);
    if (!callback || completed) return;
    callbacks.delete(id);
    callback(JSON.parse(json));
  };
  globalThis.setTimeout = (fn, ms = 0, ...args) => {
    if (typeof fn !== "function") throw new TypeError("setTimeout expects a function");
    return registerCallback(() => fn(...args), "timer", String(Math.max(0, Math.floor(Number(ms) || 0))));
  };
  globalThis.clearTimeout = id => { callbacks.delete(id); host("clear-timer", String(id)); };
  function httpRequest(method, options, callback, fetch = false) {
    if (typeof callback !== "function") throw new TypeError("$httpClient expects a callback");
    options = typeof options === "string" ? { url: options } : options;
    let request = options;
    if (options.body !== null && typeof options.body === "object" &&
        !(options.body instanceof ArrayBuffer) && !ArrayBuffer.isView(options.body)) {
      const fields = headers(options.headers) ?? {};
      for (const key of Object.keys(fields)) if (key.toLowerCase() === "content-type") delete fields[key];
      fields["Content-Type"] = ["application/json"];
      request = {...options, headers: fields, body: JSON.stringify(options.body)};
    }
    const payload = normalize(request);
    payload.method = method; payload.timeout = options.timeout; payload.fetch = fetch;
    if (options.policy !== undefined && typeof options.policy !== "string") throw new TypeError("policy must be a string");
    if (options["policy-descriptor"] !== undefined) throw new TypeError("policy-descriptor is not supported");
    if (options.insecure !== undefined && typeof options.insecure !== "boolean") throw new TypeError("insecure must be a boolean");
    if (options.insecure) throw new TypeError("insecure is not supported");
    payload.policy = options.policy;
    for (const key of ["auto-redirect", "auto-cookie", "full-header-mode"]) {
      if (options[key] !== undefined && typeof options[key] !== "boolean") throw new TypeError(key + " must be a boolean");
      payload[key] = options[key];
    }
    const id = registerCallback(event => {
      const body = event.bodyBase64 == null ? null : options["binary-mode"]
        ? fromBase64(event.bodyBase64) : host("decode", event.bodyBase64, "", "");
      if (event.response && !options["full-header-mode"]) {
        event.response.headers = headerObject(event.response.headers);
        if (event.response.h2_trailers != null) event.response.h2_trailers = headerObject(event.response.h2_trailers);
      }
      callback(event.error || null, event.response || null, body);
    }, "http", JSON.stringify(payload));
    return () => host("cancel-http", String(id));
  }
  globalThis.$httpClient = {};
  for (const method of ["get", "post", "put", "delete", "head", "options", "patch"]) {
    $httpClient[method] = (options, callback) => { httpRequest(method.toUpperCase(), options, callback); };
  }
  const installFetch = globalThis.__daeInstallFetch;
  delete globalThis.__daeInstallFetch;
  installFetch((method, options, callback) => httpRequest(method, options, callback, true));
})(globalThis.__daeHost, globalThis.__daeInput);
