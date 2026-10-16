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

// RFC 7519 section 4.1: comparisons are exact and case-sensitive.
test("expected claims are opt-in and preserve existing findings/verdict", () => {
  const token = mk({alg: "HS256"}, {iss: "issuer", aud: "api", exp: 9999999999});
  const before = TP.analyze(token, 1700000000000);
  const after = TP.analyze(token, 1700000000000, {issuer: "other", audience: "other"});
  assert.deepStrictEqual(before.expectedClaims, []);
  assert.deepStrictEqual(after.findings, before.findings);
  assert.strictEqual(after.verdict, before.verdict);
  assert.deepStrictEqual(after.expectedClaims.map(c => c.status), ["mismatch", "mismatch"]);
});

test("matching issuer and string audience", () => {
  const checks = TP.checkExpectedClaims({iss: "https://id.example", aud: "api"},
    {issuer: "https://id.example", audience: "api"});
  assert.deepStrictEqual(checks.map(c => c.status), ["match", "match"]);
});

test("audience list accepts an exact member", () => {
  const check = TP.checkExpectedClaims({aud: ["web", "api"]}, {audience: "api"})[0];
  assert.strictEqual(check.status, "match");
  assert.match(check.detail, /signature verification is separate/);
});

test("audience membership is not substring matching", () => {
  for (const aud of ["api-admin", ["api-admin"], []]) {
    assert.strictEqual(TP.checkExpectedClaims({aud}, {audience: "api"})[0].status, "mismatch");
  }
});

test("issuer comparison does not normalize case, slash or whitespace", () => {
  for (const iss of ["https://ID.example", "https://id.example/", " https://id.example"]) {
    assert.strictEqual(TP.checkExpectedClaims({iss}, {issuer: "https://id.example"})[0].status, "mismatch");
  }
});

test("audience comparison preserves case and whitespace", () => {
  for (const aud of ["API", "api ", ["API"]]) {
    assert.strictEqual(TP.checkExpectedClaims({aud}, {audience: "api"})[0].status, "mismatch");
  }
});

test("missing expected claims are explicit", () => {
  const checks = TP.checkExpectedClaims({}, {issuer: "issuer", audience: "api"});
  assert.deepStrictEqual(checks.map(c => c.status), ["missing", "missing"]);
});

test("wrong issuer types do not coerce into a match", () => {
  for (const iss of [null, 123, true, ["issuer"], {value: "issuer"}]) {
    assert.strictEqual(TP.checkExpectedClaims({iss}, {issuer: "issuer"})[0].status, "invalid");
  }
});

test("wrong audience types and mixed arrays are invalid", () => {
  for (const aud of [null, 123, true, {value: "api"}, ["api", 123], [null, "api"]]) {
    assert.strictEqual(TP.checkExpectedClaims({aud}, {audience: "api"})[0].status, "invalid");
  }
});

test("malformed payloads cannot produce a matching check", () => {
  for (const payload of [null, "api", 123, ["api"]]) {
    assert.strictEqual(TP.checkExpectedClaims(payload, {audience: "api"})[0].status, "invalid");
  }
  const invalid = TP.analyze("not.a.token", undefined, {issuer: "issuer"});
  assert.strictEqual(invalid.expectedClaims[0].status, "invalid");
});

test("blank expectations skip comparisons", () => {
  assert.deepStrictEqual(TP.checkExpectedClaims({}, {issuer: "", audience: ""}), []);
  assert.deepStrictEqual(TP.checkExpectedClaims({}), []);
});

test("non-string expectations fail clearly", () => {
  assert.throws(() => TP.checkExpectedClaims({}, {issuer: 123}), TypeError);
  assert.throws(() => TP.checkExpectedClaims({}, {audience: ["api"]}), TypeError);
});

test("claims must belong to the payload itself", () => {
  const checks = TP.checkExpectedClaims(Object.create({iss: "issuer", aud: "api"}),
    {issuer: "issuer", audience: "api"});
  assert.deepStrictEqual(checks.map(c => c.status), ["missing", "missing"]);
});

test("matching claims do not override an unsigned token verdict", () => {
  const r = TP.analyze(mk({alg: "none"}, {iss: "issuer", aud: "api"}, ""), undefined,
    {issuer: "issuer", audience: "api"});
  assert.strictEqual(r.verdict, "CRITICAL");
  assert.deepStrictEqual(r.expectedClaims.map(c => c.status), ["match", "match"]);
});
