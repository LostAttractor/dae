// Network URL and inert HTML APIs needed by Sparkle/Bilijump. These do not
// create a browser, run page scripts, or load external HTML resources.
(function (host) {
  "use strict";
  const decode = text => {
    try { return decodeURIComponent(text.replace(/\+/g, " ")); }
    catch { throw new TypeError("Invalid URL query encoding"); }
  };
  const encode = value => encodeURIComponent(String(value)).replace(/%20/g, "+")
    .replace(/[!'()~]/g, char => "%" + char.charCodeAt(0).toString(16).toUpperCase());
  class URLSearchParams {
    constructor(init = "") {
      this._pairs = [];
      if (typeof init === "string") {
        for (const part of init.replace(/^\?/, "").split("&")) {
          if (!part) continue;
          const index = part.indexOf("=");
          this._pairs.push([decode(index < 0 ? part : part.slice(0, index)), decode(index < 0 ? "" : part.slice(index + 1))]);
        }
      } else if (init != null && typeof init[Symbol.iterator] === "function") {
        for (const pair of init) {
          const values = Array.from(pair);
          if (values.length !== 2) throw new TypeError("URLSearchParams entries must contain two values");
          this._pairs.push(values.map(String));
        }
      } else {
        this._pairs = Object.entries(init).map(([key, value]) => [key, String(value)]);
      }
    }
    get size() { return this._pairs.length; }
    get(name) { return this._pairs.find(pair => pair[0] === String(name))?.[1] ?? null; }
    getAll(name) { return this._pairs.filter(pair => pair[0] === String(name)).map(pair => pair[1]); }
    has(name) { return this._pairs.some(pair => pair[0] === String(name)); }
    append(name, value) { this._pairs.push([String(name), String(value)]); this._changed?.(); }
    delete(name) { this._pairs = this._pairs.filter(pair => pair[0] !== String(name)); this._changed?.(); }
    set(name, value) {
      name = String(name); value = String(value);
      const index = this._pairs.findIndex(pair => pair[0] === name);
      this._pairs = this._pairs.filter((pair, i) => pair[0] !== name || i === index);
      if (index < 0) this._pairs.push([name, value]); else this._pairs[index][1] = value;
      this._changed?.();
    }
    sort() { this._pairs.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0); this._changed?.(); }
    toString() { return this._pairs.map(([key, value]) => encode(key) + "=" + encode(value)).join("&"); }
    *entries() { yield* this._pairs.map(pair => [...pair]); }
    *keys() { for (const [key] of this._pairs) yield key; }
    *values() { for (const [, value] of this._pairs) yield value; }
    [Symbol.iterator]() { return this.entries(); }
    forEach(callback, thisArg) { for (const [key, value] of this._pairs) callback.call(thisArg, value, key, this); }
  }
  class URL {
    constructor(value, base) {
      this._parts = JSON.parse(host("url", "parse", String(value), base === undefined ? "" : String(base), ""));
      this.searchParams = new URLSearchParams(this._parts.search);
      this.searchParams._changed = () => this._update("search", this.searchParams.toString());
    }
    _update(key, value) {
      this._parts = JSON.parse(host("url", "set", this.href, key, String(value)));
    }
    get href() { return this._parts.href; }
    set href(value) {
      this._parts = JSON.parse(host("url", "parse", String(value), "", ""));
      this.searchParams._pairs = new URLSearchParams(this._parts.search)._pairs;
    }
    get origin() { return this._parts.origin; }
    get protocol() { return this._parts.protocol; }
    get host() { return this._parts.host; }
    get hostname() { return this._parts.hostname; }
    set hostname(value) { this._update("hostname", value); }
    get port() { return this._parts.port; }
    get pathname() { return this._parts.pathname; }
    set pathname(value) { this._update("pathname", value); }
    get search() { return this._parts.search; }
    set search(value) { this._update("search", value); this.searchParams._pairs = new URLSearchParams(this._parts.search)._pairs; }
    get hash() { return this._parts.hash; }
    set hash(value) { this._update("hash", value); }
    toString() { return this.href; }
    toJSON() { return this.href; }
  }
  globalThis.URL = URL;
  globalThis.URLSearchParams = URLSearchParams;
  const nodeIDs = new WeakMap();
  const nodes = new Map();
  function wrap(id) {
    if (id === "0") return null;
    if (!nodes.has(id)) {
      const node = new HTMLNode();
      nodeIDs.set(node, id); nodes.set(id, node);
    }
    return nodes.get(id);
  }
  class HTMLNode {
    get documentElement() { return wrap(host("dom", "documentElement", nodeIDs.get(this), "")); }
    get head() { return wrap(host("dom", "head", nodeIDs.get(this), "")); }
    get body() { return wrap(host("dom", "body", nodeIDs.get(this), "")); }
    get outerHTML() { return host("dom", "outerHTML", nodeIDs.get(this), ""); }
    set textContent(value) { host("dom", "textContent", nodeIDs.get(this), String(value)); }
    createElement(name) { return wrap(host("dom", "create", String(name), "")); }
    appendChild(node) {
      if (!nodeIDs.has(node)) throw new TypeError("appendChild expects an HTML node");
      host("dom", "appendChild", nodeIDs.get(this), nodeIDs.get(node)); return node;
    }
    querySelectorAll() { throw new TypeError("DOMParser querySelectorAll is not supported by this inert HTML subset"); }
  }
  globalThis.DOMParser = class DOMParser {
    parseFromString(source, type) {
      if (type !== "text/html") throw new TypeError("DOMParser only supports text/html");
      return wrap(host("dom", "parse", String(source), ""));
    }
  };
})(globalThis.__daeHost);
