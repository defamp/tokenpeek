/*
 * tokenpeek — JWT decoding + security analysis (pure logic).
 *
 * Written as plain functions with no DOM / crypto dependencies so the same
 * code runs in the browser (window.TokenPeek) and under Node for tests.
 * The signature-cracking / verification lives in app.js (it needs Web Crypto).
 */
(function (root) {
  "use strict";

  // --- base64url helpers --------------------------------------------------- //
  function b64urlToB64(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return s;
  }

  function b64urlDecode(s) {
    // atob exists in browsers and in Node >= 16.
    var bin = atob(b64urlToB64(s));
    try {
      // Recover UTF-8 (handles non-ASCII claim values).
      var bytes = Uint8Array.from(bin, function (c) {
        return c.charCodeAt(0);
      });
      return new TextDecoder("utf-8").decode(bytes);
    } catch (e) {
      return bin;
    }
  }

  // --- parsing ------------------------------------------------------------- //
  function parseJwt(token) {
    var out = { raw: (token || "").trim(), header: null, payload: null, signature: "", parts: [], errors: [] };
    if (!out.raw) {
      out.errors.push("empty input");
      return out;
    }
    out.parts = out.raw.split(".");
    if (out.parts.length < 2) {
      out.errors.push("not a JWT: expected at least two dot-separated segments");
      return out;
    }
    if (out.parts.length > 3) {
      out.errors.push("too many segments (JWE or malformed token?)");
    }
    try {
      out.header = JSON.parse(b64urlDecode(out.parts[0]));
    } catch (e) {
      out.errors.push("header is not valid base64url JSON");
    }
    try {
      out.payload = JSON.parse(b64urlDecode(out.parts[1]));
    } catch (e) {
      out.errors.push("payload is not valid base64url JSON");
    }
    out.signature = out.parts[2] || "";
    return out;
  }

  // --- claim timeline ------------------------------------------------------ //
  var CLAIM_NAMES = {
    iss: "Issuer",
    sub: "Subject",
    aud: "Audience",
    exp: "Expires",
    nbf: "Not before",
    iat: "Issued at",
    jti: "JWT ID",
  };

  function humanTime(ts, now) {
    var d = new Date(ts * 1000);
    var diff = ts - Math.floor(now / 1000);
    var ago = Math.abs(diff);
    var unit = "second";
    var n = ago;
    if (ago >= 86400) { n = Math.round(ago / 86400); unit = "day"; }
    else if (ago >= 3600) { n = Math.round(ago / 3600); unit = "hour"; }
    else if (ago >= 60) { n = Math.round(ago / 60); unit = "minute"; }
    var rel = diff >= 0 ? "in " + n + " " + unit + (n !== 1 ? "s" : "")
                        : n + " " + unit + (n !== 1 ? "s" : "") + " ago";
    return { iso: d.toISOString(), rel: rel };
  }

  function analyzeClaims(payload, now) {
    now = now || Date.now();
    var rows = [];
    if (!payload || typeof payload !== "object") return rows;
    Object.keys(payload).forEach(function (k) {
      var v = payload[k];
      var row = { key: k, label: CLAIM_NAMES[k] || k, value: v, time: null, status: "" };
      if (["exp", "nbf", "iat"].indexOf(k) >= 0 && typeof v === "number") {
        row.time = humanTime(v, now);
        if (k === "exp") row.status = v * 1000 < now ? "expired" : "valid";
        if (k === "nbf") row.status = v * 1000 > now ? "not-yet-valid" : "active";
      }
      rows.push(row);
    });
    return rows;
  }

  // --- security findings --------------------------------------------------- //
  var SENSITIVE_KEYS = /pass(word|wd)?|secret|api[_-]?key|private[_-]?key|credit|card|ssn|cvv|token|authorization/i;

  function findings(parsed, now) {
    now = now || Date.now();
    var f = [];
    var header = parsed.header || {};
    var payload = parsed.payload || {};
    var alg = (header.alg || "").toString();

    function add(severity, id, title, detail) {
      f.push({ severity: severity, id: id, title: title, detail: detail });
    }

    // Algorithm issues.
    if (/^none$/i.test(alg)) {
      add("critical", "alg-none", "Algorithm is \"none\"",
        "The token is unsigned. If the server trusts alg, anyone can forge a valid token by setting alg=none.");
    } else if (/^HS/i.test(alg)) {
      add("info", "alg-hs", "Symmetric algorithm (" + alg + ")",
        "Signed with a shared secret. Security depends entirely on that secret's strength — try the weak-secret check.");
    } else if (/^(RS|ES|PS)/i.test(alg)) {
      add("low", "alg-asym", "Asymmetric algorithm (" + alg + ")",
        "Signed with a private key. Verify against the server's public key; watch for alg-confusion (RS256 → HS256) if the server is lax.");
    } else if (alg) {
      add("medium", "alg-unknown", "Unrecognised algorithm (" + alg + ")", "Non-standard alg header value.");
    } else {
      add("medium", "alg-missing", "No alg header", "The header does not declare a signing algorithm.");
    }

    // Header-based key-injection vectors.
    ["jku", "x5u"].forEach(function (h) {
      if (header[h]) {
        add("high", "hdr-" + h, "Header contains " + h.toUpperCase(),
          "Points the verifier at a remote key (" + header[h] + "). If not strictly allow-listed, an attacker can host their own key and forge tokens.");
      }
    });
    if (header.jwk) {
      add("high", "hdr-jwk", "Embedded JWK in header",
        "The token ships its own public key. A server that trusts it will accept attacker-signed tokens.");
    }
    if (typeof header.kid === "string" && /[;'"`\\]|\.\.\//.test(header.kid)) {
      add("high", "hdr-kid", "Suspicious kid value",
        "kid = \"" + header.kid + "\" contains characters used in path-traversal / SQL-injection. kid is attacker-controlled and often used unsafely.");
    }

    // Signature presence.
    if (!/^none$/i.test(alg) && !parsed.signature) {
      add("critical", "no-sig", "Missing signature", "alg is set but the signature segment is empty.");
    }

    // Expiry / timing.
    if (payload && typeof payload === "object") {
      if (!("exp" in payload)) {
        add("medium", "no-exp", "No expiry (exp)", "The token never expires on its own — a stolen token is valid forever.");
      } else if (typeof payload.exp === "number") {
        if (payload.exp * 1000 < now) {
          add("info", "expired", "Token is expired", "exp is in the past (operational, not a vulnerability).");
        }
        var iat = typeof payload.iat === "number" ? payload.iat : payload.exp - 1;
        if (payload.exp - iat > 31536000) {
          add("low", "long-exp", "Very long lifetime", "The token is valid for more than a year.");
        }
      }
      if (typeof payload.nbf === "number" && payload.nbf * 1000 > now) {
        add("info", "nbf-future", "Not valid yet (nbf)", "nbf is in the future.");
      }

      // Sensitive data — JWTs are signed, NOT encrypted; anyone can read the payload.
      Object.keys(payload).forEach(function (k) {
        if (SENSITIVE_KEYS.test(k)) {
          add("high", "sensitive-" + k, "Sensitive data in payload: " + k,
            "JWT payloads are only base64 — not encrypted. \"" + k + "\" is readable by anyone holding the token.");
        }
      });
    }

    return f;
  }

  var ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  function verdict(f) {
    if (!f.length) return "OK";
    var top = f.reduce(function (m, x) { return Math.max(m, ORDER[x.severity] || 0); }, 0);
    if (top >= 4) return "CRITICAL";
    if (top >= 3) return "HIGH";
    if (top >= 2) return "MEDIUM";
    if (top >= 1) return "LOW";
    return "OK";
  }

  function analyze(token, now) {
    var parsed = parseJwt(token);
    var f = parsed.errors.length && !parsed.header ? [] : findings(parsed, now);
    // Sort most-severe first.
    f.sort(function (a, b) { return (ORDER[b.severity] || 0) - (ORDER[a.severity] || 0); });
    return {
      parsed: parsed,
      claims: analyzeClaims(parsed.payload, now),
      findings: f,
      verdict: verdict(f),
    };
  }

  var api = {
    b64urlDecode: b64urlDecode,
    parseJwt: parseJwt,
    analyzeClaims: analyzeClaims,
    findings: findings,
    verdict: verdict,
    analyze: analyze,
    ORDER: ORDER,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.TokenPeek = api;
})(typeof window !== "undefined" ? window : globalThis);
