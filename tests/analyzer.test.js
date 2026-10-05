"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const TP = require("../js/analyzer.js");

// Build an unsigned token from header/payload objects (signature is cosmetic
// for the decoder — crypto verification is tested in the browser).
function mk(header, payload, sig) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return b(header) + "." + b(payload) + "." + (sig === undefined ? "AAAA" : sig);
}
const ids = (r) => r.findings.map((f) => f.id);

test("parses a well-formed token", () => {
  const t = mk({ alg: "HS256", typ: "JWT" }, { sub: "123", name: "Bo" });
  const r = TP.analyze(t);
  assert.strictEqual(r.parsed.errors.length, 0);
  assert.strictEqual(r.parsed.header.alg, "HS256");
  assert.strictEqual(r.parsed.payload.sub, "123");
});

test("rejects non-JWT input", () => {
  const r = TP.parseJwt("hello world");
  assert.ok(r.errors.length > 0);
});

test("b64urlDecode handles UTF-8", () => {
  const enc = Buffer.from("Café ☕").toString("base64url");
  assert.strictEqual(TP.b64urlDecode(enc), "Café ☕");
});

test("alg=none is CRITICAL", () => {
  const r = TP.analyze(mk({ alg: "none", typ: "JWT" }, { sub: "1" }, ""));
  assert.strictEqual(r.verdict, "CRITICAL");
  assert.ok(ids(r).includes("alg-none"));
});

test("flags sensitive data in payload", () => {
  const r = TP.analyze(mk({ alg: "HS256" }, { sub: "1", password: "x", api_key: "y" }));
  const found = ids(r);
  assert.ok(found.some((i) => i.startsWith("sensitive-password")));
  assert.ok(found.some((i) => i.startsWith("sensitive-api_key")));
  assert.strictEqual(r.verdict, "HIGH");
});

test("flags missing expiry", () => {
  const r = TP.analyze(mk({ alg: "HS256" }, { sub: "1" }));
  assert.ok(ids(r).includes("no-exp"));
});

test("detects expired token", () => {
  const past = Math.floor(Date.now() / 1000) - 3600;
  const r = TP.analyze(mk({ alg: "HS256" }, { sub: "1", exp: past, iat: past - 60 }));
  assert.ok(ids(r).includes("expired"));
  const expRow = r.claims.find((c) => c.key === "exp");
  assert.strictEqual(expRow.status, "expired");
});

test("flags jku / jwk key-injection headers", () => {
  const r = TP.analyze(mk({ alg: "RS256", jku: "https://evil.example/keys" }, { sub: "1", exp: 9999999999 }));
  assert.ok(ids(r).includes("hdr-jku"));
  assert.strictEqual(r.verdict, "HIGH");
});

test("flags suspicious kid", () => {
  const r = TP.analyze(mk({ alg: "HS256", kid: "../../dev/null" }, { sub: "1", exp: 9999999999 }));
  assert.ok(ids(r).includes("hdr-kid"));
});

test("long lifetime is flagged", () => {
  const iat = 1700000000;
  const r = TP.analyze(mk({ alg: "HS256" }, { sub: "1", iat, exp: iat + 40000000 }));
  assert.ok(ids(r).includes("long-exp"));
});

test("clean asymmetric token with short expiry is low/ok", () => {
  const now = Math.floor(Date.now() / 1000);
  const r = TP.analyze(mk({ alg: "RS256", typ: "JWT" }, { sub: "1", iss: "me", aud: "you", iat: now, exp: now + 300 }));
  assert.ok(["OK", "LOW"].includes(r.verdict));
});

test("findings are sorted by severity", () => {
  const r = TP.analyze(mk({ alg: "none", jku: "x" }, { sub: "1", password: "p" }, ""));
  const sev = r.findings.map((f) => TP.ORDER[f.severity]);
  for (let i = 1; i < sev.length; i++) assert.ok(sev[i - 1] >= sev[i]);
});
