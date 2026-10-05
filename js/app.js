/* tokenpeek — browser wiring: rendering + Web Crypto signature checks. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder();

  // A deliberately weak sample: HS256 signed with "secret", leaks a password,
  // has an admin role and no expiry — so every feature has something to show.
  var SAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIiwicGFzc3dvcmQiOiJodW50ZXIyIiwiaWF0IjoxNzAwMDAwMDAwfQ.Hj5y8zWDwmKWSfMtMx6k-cMvZ4xHgK4Db2imtNrTYrE";

  // --- base64url byte helpers --------------------------------------------- //
  function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64url(bytes) {
    var bin = "";
    bytes.forEach(function (b) { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function esc(s) {
    return String(s).replace(/[&<>]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c];
    });
  }

  // --- render -------------------------------------------------------------- //
  function render(token) {
    var errBox = $("errors"), results = $("results");
    if (!token.trim()) { results.hidden = true; errBox.hidden = true; return; }

    var r = window.TokenPeek.analyze(token);
    if (r.parsed.errors.length) {
      errBox.hidden = false;
      errBox.textContent = "⚠ " + r.parsed.errors.join(" · ");
      if (!r.parsed.header) { results.hidden = true; return; }
    } else {
      errBox.hidden = true;
    }
    results.hidden = false;

    // verdict
    var v = $("verdict");
    v.className = "verdict v-" + r.verdict;
    var notes = { OK: "No obvious weaknesses found.", LOW: "Minor notes.", MEDIUM: "Worth reviewing.",
      HIGH: "Significant weaknesses.", CRITICAL: "Serious issue — likely forgeable." };
    v.innerHTML = r.verdict + " <small>" + esc(notes[r.verdict] || "") + "</small>";

    // decoded
    $("header").textContent = r.parsed.header ? JSON.stringify(r.parsed.header, null, 2) : "(unreadable)";
    $("payload").textContent = r.parsed.payload ? JSON.stringify(r.parsed.payload, null, 2) : "(unreadable)";
    $("signature").textContent = r.parsed.signature || "(none)";

    // findings
    var fc = $("findings");
    $("findings-count").textContent = r.findings.length;
    if (!r.findings.length) {
      fc.innerHTML = '<p class="ok-note">✓ No security issues detected.</p>';
    } else {
      fc.innerHTML = r.findings.map(function (f) {
        return '<div class="finding"><span class="sev sev-' + f.severity + '">' + f.severity +
          '</span><div><div class="f-title">' + esc(f.title) + '</div><div class="f-detail">' +
          esc(f.detail) + "</div></div></div>";
      }).join("");
    }

    // claims
    $("claims-card").hidden = !r.claims.length;
    $("claims").innerHTML = r.claims.map(function (c) {
      var when = "", tag = "";
      if (c.time) when = c.time.iso + " (" + c.time.rel + ")";
      if (c.status) tag = ' <span class="tag tag-' + c.status + '">' + c.status + "</span>";
      var val = typeof c.value === "object" ? JSON.stringify(c.value) : String(c.value);
      return "<tr><td>" + esc(c.label) + "</td><td>" + esc(val) + tag + "</td><td>" + esc(when) + "</td></tr>";
    }).join("");

    setupSigCheck(r);
  }

  // --- signature check ----------------------------------------------------- //
  function hashFor(alg) {
    return { "256": "SHA-256", "384": "SHA-384", "512": "SHA-512" }[String(alg).slice(2)] || "SHA-256";
  }

  function setupSigCheck(r) {
    var alg = (r.parsed.header && r.parsed.header.alg || "").toString();
    $("hs-check").hidden = !/^HS/i.test(alg);
    $("asym-check").hidden = !/^(RS|ES|PS)/i.test(alg);
    $("nosig-check").hidden = /^(HS|RS|ES|PS)/i.test(alg);
    $("hs-result").textContent = "";
    $("asym-result").textContent = "";
    if (/^HS/i.test(alg)) $("hs-alg").textContent = alg;
    if (/^(RS|ES|PS)/i.test(alg)) $("asym-alg").textContent = alg;
    window.__tp = { parsed: r.parsed, alg: alg };
  }

  async function hmacB64url(secret, data, hash) {
    var key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: hash }, false, ["sign"]);
    var sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return bytesToB64url(new Uint8Array(sig));
  }

  async function tryHS(secrets) {
    var tp = window.__tp, p = tp.parsed;
    var signingInput = p.parts[0] + "." + p.parts[1];
    var hash = hashFor(tp.alg);
    for (var i = 0; i < secrets.length; i++) {
      var computed = await hmacB64url(secrets[i], signingInput, hash);
      if (computed === p.signature) return secrets[i];
    }
    return null;
  }

  function pemToDer(pem) {
    var b64 = pem.replace(/-----(BEGIN|END)[^-]+-----/g, "").replace(/\s+/g, "");
    return b64urlToBytes(b64.replace(/\+/g, "-").replace(/\//g, "_"));
  }

  async function verifyAsym(pem) {
    var tp = window.__tp, p = tp.parsed, alg = tp.alg, hash = hashFor(alg);
    var algo;
    if (/^RS/i.test(alg)) algo = { name: "RSASSA-PKCS1-v1_5", hash: hash };
    else if (/^PS/i.test(alg)) algo = { name: "RSA-PSS", hash: hash, saltLength: parseInt(hash.slice(4)) / 8 };
    else algo = { name: "ECDSA", namedCurve: { "256": "P-256", "384": "P-384", "512": "P-521" }[alg.slice(2)] };
    var key = await crypto.subtle.importKey("spki", pemToDer(pem), algo, false, ["verify"]);
    var verifyAlgo = /^ES/i.test(alg) ? { name: "ECDSA", hash: hash } : algo;
    var sig = b64urlToBytes(p.signature);
    var data = enc.encode(p.parts[0] + "." + p.parts[1]);
    return crypto.subtle.verify(verifyAlgo, key, sig, data);
  }

  // --- events -------------------------------------------------------------- //
  document.addEventListener("DOMContentLoaded", function () {
    var ta = $("token");
    ta.addEventListener("input", function () { render(ta.value); });
    $("sample").addEventListener("click", function () { ta.value = SAMPLE; render(SAMPLE); });
    $("clear").addEventListener("click", function () { ta.value = ""; render(""); ta.focus(); });

    $("crack").addEventListener("click", async function () {
      var out = $("hs-result");
      out.textContent = "Testing " + window.WEAK_SECRETS.length + " common secrets…";
      try {
        var hit = await tryHS(window.WEAK_SECRETS);
        out.className = "sig-result " + (hit ? "sig-cracked" : "sig-ok");
        out.textContent = hit
          ? '🔓 CRACKED — token is signed with a weak secret: "' + hit + '"'
          : "✓ None of the common secrets matched (secret is not in the weak list — not proof it's strong).";
      } catch (e) { out.className = "sig-result sig-bad"; out.textContent = "Error: " + e.message; }
    });

    $("verify-hs").addEventListener("click", async function () {
      var out = $("hs-result"), s = $("secret").value;
      if (!s) { out.textContent = "Enter a secret to test."; return; }
      try {
        var hit = await tryHS([s]);
        out.className = "sig-result " + (hit ? "sig-cracked" : "sig-bad");
        out.textContent = hit ? '✓ Valid — signature matches secret "' + s + '"' : "✗ Invalid — signature does not match that secret.";
      } catch (e) { out.className = "sig-result sig-bad"; out.textContent = "Error: " + e.message; }
    });

    $("verify-asym").addEventListener("click", async function () {
      var out = $("asym-result"), pem = $("pubkey").value.trim();
      if (!pem) { out.textContent = "Paste a public key (PEM)."; return; }
      out.textContent = "Verifying…";
      try {
        var ok = await verifyAsym(pem);
        out.className = "sig-result " + (ok ? "sig-ok" : "sig-bad");
        out.textContent = ok ? "✓ Signature is VALID for this public key." : "✗ Signature does NOT verify against this key.";
      } catch (e) { out.className = "sig-result sig-bad"; out.textContent = "Error: " + e.message + " (check the key format)"; }
    });
  });
})();
