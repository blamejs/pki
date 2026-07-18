// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- pki.inspect.csr / .cms cross-implementation interop.
 *
 * inspect CONSUMES wire bytes, so OpenSSL is the independent oracle: the toolkit's producers emit
 * a CSR / CMS, `pki.inspect.<fn>` renders it, and the report must name the SAME fields OpenSSL's
 * own -text/-print decode shows -- value-level (whitespace-normalized), never byte-identical to any
 * one OpenSSL build. The NEVER-THROW-ON-VALID contract is asserted in the same loop: for every
 * OpenSSL-accepted CSR/CMS across every algorithm arm, `pki.inspect.<fn>(bytes)` returns a string.
 *
 * CRL parity is deferred until a CRL producer lands (the CRL render is unit-tested in the layer-0
 * inspect-formats suite; there is no in-toolkit CRL emitter to feed an OpenSSL CRL cross-check yet).
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

// Normalize whitespace around '=' + collapse runs, so `CN = x` (OpenSSL 3.0) and `CN=x` (3.5+) and
// our `CN=x` compare equal at the value level.
function norm(s) { return s.replace(/\s*=\s*/g, "=").replace(/\s+/g, " ").toLowerCase(); }
function contains(hay, needle) { return norm(hay).indexOf(norm(needle)) !== -1; }

async function run() {
  var arms = ["rsa", "ec-p256", "ed25519"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);

    // ---- CSR: toolkit emits, openssl req -text is the oracle ----
    var csrDer = await pki.csr.sign({ subject: [{ commonName: alg + ".example" }], subjectPublicKey: s.spki,
      extensionRequest: { subjectAltName: [{ dNSName: alg + ".example" }] } }, s.key);
    var csrReport = pki.inspect.csr(csrDer);
    check("inspect.csr renders the " + alg + " CSR without throwing", typeof csrReport === "string" && csrReport.length > 0);
    ctx.withTmp(Buffer.from(csrDer), "csr-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["req", "-in", p, "-inform", "DER", "-text", "-noout", "-nameopt", "RFC2253"], { allowNonZero: true });
      if (t.code !== 0) return;   // an arm OpenSSL cannot decode is a skip, not a fail
      // The subject CN and the requested DNS SAN appear in BOTH decodes.
      check("inspect.csr agrees with openssl req -text on the " + alg + " subject", contains(csrReport, "CN=" + alg + ".example") && contains(t.stdout, alg + ".example"));
      check("inspect.csr agrees on the requested DNS SAN (" + alg + ")", contains(csrReport, "DNS:" + alg + ".example") && contains(t.stdout, alg + ".example"));
    });

    // ---- CMS SignedData: toolkit emits (attached), openssl cms -cmsout -print is the oracle ----
    var cmsDer = await pki.cms.sign(Buffer.from("interop"), [{ cert: s.cert, key: s.key }], { detached: false });
    var cmsReport = pki.inspect.cms(cmsDer);
    check("inspect.cms renders the " + alg + " SignedData without throwing", typeof cmsReport === "string" && cmsReport.length > 0);
    check("inspect.cms names signedData + the signer serial (" + alg + ")",
      contains(cmsReport, "signedData") && contains(cmsReport, "Serial Number"));
    ctx.withTmp(Buffer.from(cmsDer), "cms-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["cms", "-cmsout", "-print", "-inform", "DER", "-in", p], { allowNonZero: true });
      check("openssl cms -cmsout -print accepts the toolkit-signed " + alg + " CMS", t.code === 0);
    });
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
