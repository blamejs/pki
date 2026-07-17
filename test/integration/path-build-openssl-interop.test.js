// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- certification path BUILDING (pki.path.build) cross-implementation interop.
 *
 * `openssl verify` is the independent oracle for path BUILDING: `openssl verify -CAfile <anchors>
 * -untrusted <pool> <leaf>` builds the chain from the untrusted pool and validates it against the
 * anchors -- the exact operation pki.path.build performs. The check asserts build and openssl reach
 * the SAME accept/reject verdict across three cases:
 *  (a) a buildable pool -> openssl ": OK" AND build valid:true, and build's ordered path validates
 *      through the shipped pki.path.validate (the in-tree GREEN oracle);
 *  (b) a pool that reaches no configured anchor -> openssl non-zero AND build throws path/no-path;
 *  (c) a decoy pool with two intermediates sharing a subject DN (only one signed the leaf) -> BOTH
 *      openssl and build pick the real issuer and accept.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var os = require("node:os");
var fs = require("node:fs");
var path = require("node:path");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");
var T = new Date("2027-06-01T00:00:00Z");

function caSpec(cn, spki) {
  return { subject: [{ commonName: cn }], subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } };
}
function parse(pem) { return pki.schema.x509.parse(pki.schema.x509.pemDecode(pem, "CERTIFICATE")); }
function der(pem) { return Buffer.from(pki.schema.x509.pemDecode(pem, "CERTIFICATE")); }

async function run() {
  // A self-signed root (anchor) + an intermediate issued under it + a leaf issued under the intermediate.
  var rootKp = signing.makeSigner("ec-p256");
  var rootPem = await pki.x509.sign(caSpec("Interop Build Root", rootKp.spki), { key: rootKp.key }, { pem: true });
  var rootCert = parse(rootPem);

  var interKp = signing.makeSigner("ec-p256");
  var interPem = await pki.x509.sign(caSpec("Interop Build Intermediate", interKp.spki), { cert: rootCert, key: rootKp.key }, { pem: true });
  var interCert = parse(interPem);

  var leafKp = signing.makeSigner("ed25519");
  var leafPem = await pki.x509.sign({
    subject: [{ commonName: "leaf.build.example" }], subjectPublicKey: leafKp.spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "leaf.build.example" }], authorityKeyIdentifier: true },
  }, { cert: interCert, key: interKp.key }, { pem: true });

  // A decoy intermediate: the SAME subject DN as the real one, issued under the root, but a DIFFERENT
  // key -- it did NOT sign the leaf. openssl and build must both pick the real signer from the pool.
  var decoyKp = signing.makeSigner("ec-p256");
  var decoyInterPem = await pki.x509.sign(caSpec("Interop Build Intermediate", decoyKp.spki), { cert: rootCert, key: rootKp.key }, { pem: true });

  // A second, unrelated root that never issued anything in the chain (the no-path anchor).
  var otherRootKp = signing.makeSigner("ec-p256");
  var otherRootPem = await pki.x509.sign(caSpec("Interop Build Other Root", otherRootKp.spki), { key: otherRootKp.key }, { pem: true });

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-pathbuild-"));
  try {
    var rootFile = path.join(dir, "root.pem"); fs.writeFileSync(rootFile, rootPem);
    var otherRootFile = path.join(dir, "other-root.pem"); fs.writeFileSync(otherRootFile, otherRootPem);
    var interFile = path.join(dir, "inter.pem"); fs.writeFileSync(interFile, interPem);
    var poolFile = path.join(dir, "pool.pem"); fs.writeFileSync(poolFile, decoyInterPem + interPem);   // decoy first
    var leafFile = path.join(dir, "leaf.pem"); fs.writeFileSync(leafFile, leafPem);

    // ---- (a) buildable pool: openssl builds+validates, build validates, the order round-trips ----
    var vOk = ctx.runOpenssl(["verify", "-CAfile", rootFile, "-untrusted", interFile, leafFile], { allowNonZero: true });
    check("openssl verify builds + validates the chain from the untrusted pool", vOk.code === 0 && /:\s*OK\s*$/.test(vOk.stdout.trim()));
    var rBuild = await pki.path.build(der(leafPem), { candidates: [der(interPem)], trustAnchors: [der(rootPem)], time: T });
    check("pki.path.build reaches valid:true on the same pool (agrees with openssl)", rBuild.valid === true);
    var green = await pki.path.validate(rBuild.path, { time: T, trustAnchor: rBuild.trustAnchor });
    check("the built path round-trips through the shipped pki.path.validate", green.valid === true);

    // ---- (b) no path to the configured anchor: openssl non-zero AND build throws path/no-path ----
    var vNo = ctx.runOpenssl(["verify", "-CAfile", otherRootFile, "-untrusted", interFile, leafFile], { allowNonZero: true });
    check("openssl verify rejects the chain against an unrelated anchor", vNo.code !== 0);
    var noPathCode = "NO-THROW";
    try { await pki.path.build(der(leafPem), { candidates: [der(interPem)], trustAnchors: [der(otherRootPem)], time: T }); }
    catch (e) { noPathCode = (e && e.code) || "RAW"; }
    check("pki.path.build throws path/no-path against an unrelated anchor (agrees with openssl)", noPathCode === "path/no-path");

    // ---- (c) decoy same-DN pool: openssl and build both pick the real issuer ----
    var vDecoy = ctx.runOpenssl(["verify", "-CAfile", rootFile, "-untrusted", poolFile, leafFile], { allowNonZero: true });
    check("openssl verify picks the real issuer from a decoy-bearing pool", vDecoy.code === 0 && /:\s*OK\s*$/.test(vDecoy.stdout.trim()));
    var rDecoy = await pki.path.build(der(leafPem), { candidates: [der(decoyInterPem), der(interPem)], trustAnchors: [der(rootPem)], time: T });
    check("pki.path.build picks the real issuer from a decoy-bearing pool (agrees with openssl)",
      rDecoy.valid === true && Buffer.from(rDecoy.path[0].subjectPublicKeyInfo.bytes).equals(interKp.spki));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
