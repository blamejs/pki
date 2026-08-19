// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 4211 proof-of-possession verification (pki.crmf.verifyPop) cross-implementation
 * interop.
 *
 * OpenSSL has no standalone CRMF generator, but its `cmp` client builds one: `-cmd ir -reqout`
 * writes the PKIMessage it would have sent, and the `ir` body IS a CertReqMessages carrying a real
 * POPOSigningKey proof. That makes an independent producer available for the direction verifyPop is
 * for, which matters because a verifier exercised only against its own signer agrees with itself
 * about conventions no spec fixes.
 *
 *  (a) the CRMF an independent client produced verifies TRUE;
 *  (b) the same message with a flipped signature byte verifies FALSE, so (a) is not a verifier that
 *      says true about everything;
 *  (c) the verdict reports the subject that client asked for, so the fields travel with it.
 *
 * The client is run with no reachable server, so it exits non-zero after writing `-reqout`. The
 * request file is therefore the availability signal, never the exit code.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var os = require("os");
var path = require("path");
var fs = require("fs");
var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;

// Write a CMP `ir` request with `openssl cmp`, and hand back the CertReqMessages DER inside it.
function opensslCrmf(stem, subject) {
  var keyPath = stem + ".key.pem";
  var reqPath = stem + ".req.der";
  var g = ctx.runOpenssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-out", keyPath], { allowNonZero: true });
  if (g.code !== 0 || !fs.existsSync(keyPath)) return null;
  ctx.runOpenssl(["cmp", "-cmd", "ir", "-server", "127.0.0.1:1", "-ref", "interop",
    "-secret", "pass:interop-secret", "-newkey", keyPath, "-subject", subject,
    "-reqout", reqPath, "-certout", stem + ".cert.pem"], { allowNonZero: true });
  if (!fs.existsSync(reqPath)) return null;
  var der = fs.readFileSync(reqPath);
  if (!der.length) return null;
  var body = pki.schema.cmp.parse(der).body;
  return { keyPath: keyPath, reqPath: reqPath, arm: body.arm, crmf: Buffer.from(body.bytes) };
}

async function run() {
  var stem = path.join(os.tmpdir(), "pkijs-crmfv-" + process.pid);
  try {
    var made = opensslCrmf(stem, "/CN=cmp interop");
    if (!made) {
      ctx.skip("openssl cmp could not write a CertReqMessages (-reqout)");
      return;
    }
    check("the openssl cmp request carries an ir body", made.arm === "ir");

    var r = await pki.crmf.verifyPop(made.crmf);
    check("pki.crmf.verifyPop accepts an OpenSSL-generated CertReqMessages", r.verified === true);
    check("the proof is reported as a signature POP", r.messages[0].method === "signature");
    check("the verdict reports the subject that client asked for", /cmp interop/.test(r.messages[0].subject.dn));
    check("the verdict carries the requested key", Buffer.isBuffer(r.messages[0].publicKey) && r.messages[0].publicKey.length > 0);

    // Flip a byte in the trailing signature and confirm the verdict turns over.
    var bad = Buffer.from(made.crmf);
    bad[bad.length - 1] ^= 0xff;
    var v = await pki.crmf.verifyPop(bad).then(function (x) { return x.verified; }, function (e) { return e.code; });
    check("a flipped signature byte on that message no longer verifies", v !== true);
  } finally {
    [".key.pem", ".req.der", ".cert.pem"].forEach(function (ext) {
      try { fs.unlinkSync(stem + ext); } catch (_e) { /* best-effort */ }
    });
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
