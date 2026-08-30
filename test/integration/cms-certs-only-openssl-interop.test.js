// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- pki.cms.certsOnly / pki.smime.buildCertsOnly cross-implementation interop.
 *
 * A certs-only message (RFC 8551 sec. 3.8) is a degenerate CMS SignedData that conveys certificates
 * and nothing else. OpenSSL is the independent oracle for the structure the toolkit emits:
 *
 *   Gate A -- `openssl pkcs7 -print_certs` (the classic .p7c reader) parses the certs-only DER and
 *     prints every certificate it carries, so the certificates [0] set and the empty signerInfos are
 *     a shape OpenSSL accepts.
 *   Gate B -- `openssl cms -cmsout` parses the whole message as a well-formed CMS SignedData.
 *   Gate C -- the certificates OpenSSL extracts round-trip: each PEM certificate OpenSSL prints,
 *     re-encoded to DER, is one the toolkit's own reader returned.
 *   Gate D -- the S/MIME `pki.smime.buildCertsOnly` frame's base64 body is the same certs-only DER,
 *     and OpenSSL reads its certificates too.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

async function run() {
  var certA = signing.makeSigner("rsa").cert;
  var certB = signing.makeSigner("ec-p256").cert;
  var bag = pki.cms.certsOnly([certA, certB]);
  var bagPath = ctx.tmpFile(bag, "certs-only.der");

  // Gate A: openssl's PKCS#7 reader extracts both certificates from the certs-only bag.
  var printed = ctx.runOpenssl(["pkcs7", "-inform", "DER", "-in", bagPath, "-print_certs"], { allowNonZero: true });
  check("Gate A: openssl pkcs7 -print_certs parses our certs-only message", printed.code === 0);
  var pemCount = printed.stdout.split("-----BEGIN CERTIFICATE-----").length - 1;
  check("Gate A: openssl finds both embedded certificates", pemCount === 2);

  // Gate B: openssl parses the whole message as a CMS SignedData structure.
  var cmsout = ctx.runOpenssl(["cms", "-cmsout", "-noout", "-print", "-inform", "DER", "-in", bagPath], { allowNonZero: true });
  check("Gate B: openssl cms -cmsout parses the certs-only SignedData", cmsout.code === 0);

  // Gate C: the certificates openssl extracts are exactly the two the toolkit's reader returns.
  var extractedPem = ctx.runOpenssl(["pkcs7", "-inform", "DER", "-in", bagPath, "-print_certs", "-outform", "PEM"], { allowNonZero: true });
  var ours = pki.cms.parseCertsOnly(bag).certificates.slice().sort(Buffer.compare);
  var opensslDers = extractedPem.stdout.split("-----BEGIN CERTIFICATE-----").slice(1).map(function (chunk) {
    return pki.schema.x509.pemDecode("-----BEGIN CERTIFICATE-----" + chunk.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n");
  }).sort(Buffer.compare);
  check("Gate C: openssl-extracted certificates match the toolkit's reader byte-for-byte",
    opensslDers.length === 2 && Buffer.compare(opensslDers[0], ours[0]) === 0 && Buffer.compare(opensslDers[1], ours[1]) === 0);

  // Gate D: the S/MIME frame carries the same certs-only DER openssl can read.
  var mime = pki.smime.buildCertsOnly([certA, certB]).toString("latin1");
  var body = Buffer.from(mime.split("\r\n\r\n")[1].replace(/[\r\n]/g, ""), "base64");
  var bodyPath = ctx.tmpFile(body, "smime-p7c.der");
  var mimePrint = ctx.runOpenssl(["pkcs7", "-inform", "DER", "-in", bodyPath, "-print_certs"], { allowNonZero: true });
  check("Gate D: openssl reads the certificates from the S/MIME certs-only frame body",
    mimePrint.code === 0 && (mimePrint.stdout.split("-----BEGIN CERTIFICATE-----").length - 1) === 2);

  [bagPath, bodyPath].forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
