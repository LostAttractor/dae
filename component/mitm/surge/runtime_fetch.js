// Buffered Fetch APIs share $httpClient's routing, deadlines and resource limits.
globalThis.__daeInstallFetch = function (sendHTTP) {
  "use strict";
  function readonly(target, names) {
    for (const name of names) Object.defineProperty(target, name, {writable: false, configurable: false});
  }
  const signals = new WeakMap();
  function abortError(name = "AbortError") { const error = new Error(name === "AbortError" ? "The operation was aborted" : "The operation timed out"); error.name = name; return error; }
  function abort(signal, reason) {
    const state = signals.get(signal);
    if (state.aborted) return;
    state.aborted = true; state.reason = reason === undefined ? abortError() : reason;
    const event = {type: "abort", target: signal};
    for (const [listener, once] of [...state.listeners]) {
      if (!state.listeners.has(listener)) continue;
      if (once) state.listeners.delete(listener);
      try {
        if (typeof listener === "function") listener.call(signal, event);
        else listener.handleEvent(event);
      } catch (error) { console.error(error); }
    }
    try { if (typeof signal.onabort === "function") signal.onabort.call(signal, event); }
    catch (error) { console.error(error); }
  }
  const signalToken = {};
  class AbortSignal {
    constructor(token) {
      if (token !== signalToken) throw new TypeError("Illegal constructor");
      signals.set(this, {aborted: false, reason: undefined, listeners: new Map()});
      this.onabort = null;
    }
    get aborted() { return signals.get(this).aborted; }
    get reason() { return signals.get(this).reason; }
    throwIfAborted() { if (this.aborted) throw this.reason; }
    addEventListener(type, listener, options = {}) {
      if (type === "abort" && listener != null && !signals.get(this).listeners.has(listener))
        signals.get(this).listeners.set(listener, !!options?.once);
    }
    removeEventListener(type, listener) { if (type === "abort") signals.get(this).listeners.delete(listener); }
    static abort(reason) { const signal = new AbortSignal(signalToken); abort(signal, reason); return signal; }
    static timeout(ms) {
      if (!Number.isSafeInteger(ms) || ms < 0) throw new RangeError("Invalid timeout");
      const signal = new AbortSignal(signalToken);
      setTimeout(() => abort(signal, abortError("TimeoutError")), ms);
      return signal;
    }
  }
  class AbortController {
    constructor() { this.signal = new AbortSignal(signalToken); readonly(this, ["signal"]); }
    abort(reason) { abort(this.signal, reason); }
  }
  const immutableHeaders = new WeakSet();
  function checkMutable(headers) { if (immutableHeaders.has(headers)) throw new TypeError("Headers are immutable"); }
  function headerName(value) {
    value = String(value).toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(value)) throw new TypeError("Invalid header name");
    return value;
  }
  function headerValue(value) {
    value = String(value).replace(/^[\t ]+|[\t ]+$/g, "");
    if (/[\0\r\n\u0100-\uffff]/.test(value)) throw new TypeError("Invalid header value");
    return value;
  }
  class Headers {
    #values = new Map();
    constructor(init = []) {
      const entries = typeof init[Symbol.iterator] === "function" ? init : Object.entries(init);
      for (const entry of entries) {
        const pair = Array.from(entry);
        if (pair.length !== 2) throw new TypeError("Headers entries require two values");
        this.append(pair[0], pair[1]);
      }
    }
    append(name, value) {
      name = headerName(name); value = headerValue(value);
      checkMutable(this);
      if (!this.#values.has(name)) this.#values.set(name, []);
      this.#values.get(name).push(value);
    }
    set(name, value) { name = headerName(name); value = headerValue(value); checkMutable(this); this.#values.set(name, [value]); }
    delete(name) { name = headerName(name); checkMutable(this); this.#values.delete(name); }
    has(name) { return this.#values.has(headerName(name)); }
    get(name) {
      name = headerName(name);
      return this.#values.get(name)?.join(name === "cookie" ? "; " : ", ") ?? null;
    }
    getSetCookie() { return [...(this.#values.get("set-cookie") ?? [])]; }
    *entries() {
      for (const name of [...this.#values.keys()].sort()) {
        if (name === "set-cookie") { for (const value of this.#values.get(name)) yield [name, value]; }
        else yield [name, this.get(name)];
      }
    }
    *keys() { for (const [name] of this) yield name; }
    *values() { for (const [, value] of this) yield value; }
    [Symbol.iterator]() { return this.entries(); }
    forEach(callback, thisArg) { for (const [name, value] of this) callback.call(thisArg, value, name, this); }
  }
  const bodies = new WeakMap();
  function initBody(target, value, headers) {
    let data = null, type;
    if (value instanceof ArrayBuffer) data = new Uint8Array(value.slice(0));
    else if (ArrayBuffer.isView(value)) data = new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
    else if (value != null) {
      if (value instanceof URLSearchParams) type = "application/x-www-form-urlencoded;charset=UTF-8";
      else type = "text/plain;charset=UTF-8";
      data = new TextEncoder().encode(`${value}`.toWellFormed());
    }
    if (type && !headers.has("content-type")) headers.set("content-type", type);
    bodies.set(target, {data, used: false});
  }
  function bodyData(target) {
    const body = bodies.get(target);
    if (body.used) throw new TypeError("Body has already been consumed");
    return body.data;
  }
  function consume(target) {
    const data = bodyData(target);
    if (data !== null) bodies.get(target).used = true;
    return data;
  }
  class Body {
    get bodyUsed() { return bodies.get(this).used; }
    async arrayBuffer() { return (consume(this) ?? new Uint8Array()).slice().buffer; }
    async bytes() { return new Uint8Array(await this.arrayBuffer()); }
    async text() { return new TextDecoder().decode(consume(this) ?? new Uint8Array()); }
    async json() { return JSON.parse(await this.text()); }
  }
  class Request extends Body {
    constructor(input, init = {}) {
      super();
      for (const key of ["mode", "cache", "integrity", "referrer", "referrerPolicy", "keepalive", "duplex"]) {
        if (init[key] !== undefined) throw new TypeError("fetch does not support " + key);
      }
      const source = input instanceof Request ? input : null;
      const url = new URL(source ? source.url : `${input}`);
      if (url.username || url.password) throw new TypeError("Request URL cannot include credentials");
      this.url = url.href;
      this.method = `${init.method ?? source?.method ?? "GET"}`;
      const upperMethod = this.method.toUpperCase();
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(this.method) || ["CONNECT", "TRACE", "TRACK"].includes(upperMethod))
        throw new TypeError("Invalid fetch method");
      if (["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"].includes(upperMethod)) this.method = upperMethod;
      this.headers = new Headers(init.headers ?? source?.headers);
      this.redirect = init.redirect ?? source?.redirect ?? "follow";
      if (!["follow", "error", "manual"].includes(this.redirect)) throw new TypeError("Invalid redirect mode");
      this.credentials = init.credentials ?? source?.credentials ?? "same-origin";
      if (!["omit", "same-origin", "include"].includes(this.credentials)) throw new TypeError("Invalid credentials mode");
      this.policy = init.policy ?? source?.policy;
      this.timeout = init.timeout ?? source?.timeout;
      this.signal = (init.signal === undefined ? source?.signal : init.signal) ?? new AbortController().signal;
      if (!signals.has(this.signal)) throw new TypeError("Invalid AbortSignal");
      const body = init.body ?? (source ? bodyData(source) : null);
      if (body !== null && (this.method === "GET" || this.method === "HEAD")) throw new TypeError("GET/HEAD cannot have a body");
      initBody(this, body, this.headers);
      if (source && init.body == null) consume(source);
      readonly(this, ["url", "method", "headers", "redirect", "credentials", "policy", "timeout", "signal"]);
    }
    clone() {
      const copy = new Request(this.url, this);
      initBody(copy, bodyData(this), copy.headers);
      return copy;
    }
  }
  const responseMetadata = new WeakMap();
  class Response extends Body {
    constructor(body = null, init = {}) {
      super();
      this.status = init.status === undefined ? 200 : Number(init.status);
      if (!Number.isInteger(this.status) || this.status < 200 || this.status > 599) throw new RangeError("Invalid response status");
      if (body !== null && [204, 205, 304].includes(this.status)) throw new TypeError("Response status cannot have a body");
      this.statusText = String(init.statusText ?? "");
      if (/[^\t\x20-\x7e\x80-\xff]/.test(this.statusText)) throw new TypeError("Invalid status text");
      this.headers = new Headers(init.headers);
      responseMetadata.set(this, {url: "", redirected: false, type: "default"});
      initBody(this, body, this.headers);
      readonly(this, ["status", "statusText", "headers"]);
    }
    get url() { return responseMetadata.get(this).url; }
    get redirected() { return responseMetadata.get(this).redirected; }
    get type() { return responseMetadata.get(this).type; }
    get ok() { return this.status >= 200 && this.status <= 299; }
    clone() {
      const copy = new Response(bodyData(this), this);
      responseMetadata.set(copy, {...responseMetadata.get(this)});
      if (immutableHeaders.has(this.headers)) immutableHeaders.add(copy.headers);
      return copy;
    }
    static json(data, init = {}) {
      const body = JSON.stringify(data);
      if (body === undefined) throw new TypeError("Value cannot be serialized as JSON");
      const headers = new Headers(init.headers);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
      return new Response(body, {...init, headers});
    }
  }
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    request.signal.throwIfAborted();
    return new Promise((resolve, reject) => {
      let cancel, settled = false;
      function finish(callback, value) {
        if (settled) return;
        settled = true;
        request.signal.removeEventListener("abort", onAbort);
        callback(value);
      }
      function onAbort() { cancel?.(); finish(reject, request.signal.reason); }
      request.signal.addEventListener("abort", onAbort);
      try { cancel = sendHTTP(request.method, {
        url: request.url, headers: [...request.headers].map(([field, value]) => ({field, value})),
        body: consume(request), policy: request.policy, timeout: request.timeout,
        "auto-redirect": request.redirect === "follow", "auto-cookie": request.credentials === "include",
        "binary-mode": true, "full-header-mode": true
      }, (error, response, data) => {
        if (settled) return;
        if (error) { finish(reject, new TypeError(error)); return; }
        try {
          if (request.redirect === "error" && [301, 302, 303, 307, 308].includes(response.status) &&
              response.headers.some(header => header.field.toLowerCase() === "location"))
            throw new TypeError("Redirect is not allowed");
          const body = request.method === "HEAD" || [204, 205, 304].includes(response.status) ? null : data;
          const result = new Response(body, {
            status: response.status, statusText: response.statusText,
            headers: response.headers.map(({field, value}) => [field, value])
          });
          responseMetadata.set(result, {url: response.url, redirected: response.redirected, type: "basic"});
          immutableHeaders.add(result.headers);
          finish(resolve, result);
        } catch (error) { finish(reject, error); }
      }); } catch (error) { finish(reject, error); }
    });
  };
  Object.assign(globalThis, {Headers, Request, Response, AbortController, AbortSignal});
};
