// Test fence. Any outbound connect, DNS lookup, or HTTP request fails the process.
import net from "node:net";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";

function record(kind, detail) {
  const line = `BLOCKED_${kind} ${detail}`;
  console.error(line);
  const error = new Error(line);
  error.code = "ENETUNREACH";
  throw error;
}

function describeRequest(input) {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  if (input && typeof input === "object") {
    const host = input.hostname || input.host || "";
    const path = input.path || input.pathname || "";
    return `${input.protocol || ""}//${host}${path}`;
  }
  return String(input);
}

net.Socket.prototype.connect = function blockedConnect(...args) {
  const detail = args
    .map((arg) => {
      if (typeof arg === "function") return "callback";
      if (arg && typeof arg === "object") {
        return JSON.stringify({ port: arg.port, host: arg.host, hostname: arg.hostname, path: arg.path });
      }
      return String(arg);
    })
    .join(" ");
  record("CONNECT", detail);
};

function wrapLookup(name, fn) {
  return function blockedLookup(hostname, ...rest) {
    record(name, String(hostname));
    return fn.call(this, hostname, ...rest);
  };
}
dns.lookup = wrapLookup("DNS", dns.lookup);
dns.promises.lookup = wrapLookup("DNS_PROMISE", dns.promises.lookup);

function wrapRequest(mod, label) {
  const original = mod.request;
  mod.request = function blockedRequest(input, ...rest) {
    record(label, describeRequest(input));
    return original.call(this, input, ...rest);
  };
  mod.get = function blockedGet(input, ...rest) {
    record(`${label}_GET`, describeRequest(input));
    return original.get.call(this, input, ...rest);
  };
}
wrapRequest(http, "HTTP");
wrapRequest(https, "HTTPS");
