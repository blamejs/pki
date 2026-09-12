// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- OCSP response issuance (pki.ocsp.sign) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's OCSP producing side:
 *  (a) a response the toolkit signs under a delegated responder parses (`openssl ocsp -respin -text`)
 *      and its signature chain verifies against the issuing CA (`openssl ocsp -CAfile`), which also
 *      checks the responder certificate's id-kp-OCSPSigning and id-pkix-ocsp-nocheck;
 *  (b) the RFC 6960 sec. 4.4.4 archive cutoff and sec. 4.4.2 CRL reference singleExtensions the
 *      toolkit writes are decoded by OpenSSL down to their fields, so the encoding is read by an
 *      implementation that did not write it;
 *  (c) a response whose signature byte is flipped is REJECTED.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var ocspWorld = require("../helpers/ocsp-world");
var os = require("node:os");
var fs = require("node:fs");
var path = require("node:path");

var TU = new Date("2027-01-01T00:00:00Z"), NU = new Date("2028-01-01T00:00:00Z");
var CUTOFF = new Date("2020-06-01T00:00:00Z"), CRL_TIME = new Date("2027-05-01T12:00:00Z");

async function run() {
  var w = await ocspWorld.makeOcspWorld("ec-p256");
  var der = await pki.ocsp.sign({
    responderID: "byName",
    responses: [{
      cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU,
      singleExtensions: {
        archiveCutoff: CUTOFF,
        crlReferences: { crlUrl: "https://crl.interop.example/ca.crl", crlNum: 42, crlTime: CRL_TIME },
      },
    }],
  }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-ocsp-"));
  try {
    var respFile = path.join(dir, "resp.der"); fs.writeFileSync(respFile, der);
    var caFile = path.join(dir, "ca.pem"); fs.writeFileSync(caFile, pki.schema.x509.pemEncode(w.issuerCertDer, "CERTIFICATE"));

    // ---- (a) parses, and the delegated responder's signature chain verifies against the CA ----
    var t = ctx.runOpenssl(["ocsp", "-respin", respFile, "-text", "-noverify"], { allowNonZero: true });
    check("openssl ocsp -respin -text parses the toolkit-signed response", t.code === 0);
    check("openssl reports the certificate status the toolkit wrote", /Cert Status:\s*good/i.test(t.stdout));
    var v = ctx.runOpenssl(["ocsp", "-respin", respFile, "-CAfile", caFile], { allowNonZero: true });
    check("openssl ocsp -CAfile verifies the delegated responder's signature and certificate", /Response verify OK/i.test(v.stdout + v.stderr));

    // ---- (b) the singleExtensions are decoded by OpenSSL down to their fields ----
    // Names come from the release's object table, so presence is by name or OID; the decoded VALUES
    // are what an independent reading proves.
    check("openssl shows the archive cutoff extension, named or by OID",
      /Archive Cutoff/i.test(t.stdout) || t.stdout.indexOf("1.3.6.1.5.5.7.48.1.6") >= 0);
    check("openssl decodes the archive cutoff to the date the toolkit wrote", /Jun\s+1 00:00:00 2020 GMT/.test(t.stdout));
    check("openssl shows the CRL reference extension, named or by OID",
      /CRL ID/i.test(t.stdout) || t.stdout.indexOf("1.3.6.1.5.5.7.48.1.3") >= 0);
    check("openssl decodes the CRL reference URL, number and time the toolkit wrote",
      /crlUrl:\s*https:\/\/crl\.interop\.example\/ca\.crl/i.test(t.stdout) && /crlNum:\s*2A/i.test(t.stdout) && /May\s+1 12:00:00 2027 GMT/.test(t.stdout));

    // ---- (c) a flipped signature byte is REJECTED ----
    var bad = Buffer.from(der); bad[bad.length - 1] ^= 0xff;
    var badFile = path.join(dir, "bad.der"); fs.writeFileSync(badFile, bad);
    var vb = ctx.runOpenssl(["ocsp", "-respin", badFile, "-CAfile", caFile], { allowNonZero: true });
    check("openssl ocsp -CAfile REJECTS a response with a flipped signature byte", !/Response verify OK/i.test(vb.stdout + vb.stderr));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
