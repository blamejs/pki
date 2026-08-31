// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- CRL REVOCATION semantics (pki.path.crlChecker) cross-implementation interop.
 *
 * `openssl verify -crl_check -CAfile ca.pem -CRLfile crls.pem [-extended_crl] [-use_deltas] leaf.pem`
 * is an independent oracle for the two shapes this checker gained: reason-shard accumulation
 * (RFC 5280 sec. 6.3.3(d),(l)) and delta-CRL merging (sec. 5.2.4 / 6.3.3(c)). Both sides consume
 * CRLs and certificates the toolkit itself produced, so a disagreement is a real semantic
 * difference rather than a fixture artifact.
 *
 *  (a) Two reason shards whose masks union to all-reasons -> BOTH reach "good".
 *  (b) One shard alone -> BOTH refuse (partial coverage is not good).
 *  (c) The shards WITHOUT -extended_crl -> openssl refuses, which is the control proving (a)'s OK
 *      comes from reason-mask accumulation and not from openssl ignoring the IDP.
 *  (d) Base carrying freshestCRL + a delta revoking the serial -> BOTH report revoked.
 *  (e) Base listing certificateHold + a delta listing removeFromCRL -> BOTH release it.
 *
 *  (f) A DELIBERATE DIVERGENCE, asserted rather than papered over: a base WITHOUT freshestCRL plus
 *      a delta revoking the serial. openssl applies no delta and answers OK; this checker still
 *      reports revoked, because an unmerged delta is consulted for revocation. Matching openssl
 *      here would mean letting an unmergeable delta ERASE a revocation -- turning a revoked into a
 *      good, which is the one thing the merge may never do. The check pins both verdicts so the
 *      difference stays visible and intentional.
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

var b = pki.asn1.build;
var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");
// openssl verifies against the REAL system clock (there is no -attime here), so the CRL window
// must contain "now" as well as the toolkit-side check time T -- a future thisUpdate reads as
// "CRL is not yet valid" and the comparison would measure the fixture, not the semantics.
var TU = new Date("2026-01-02T00:00:00Z");
var NU = new Date("2035-06-01T00:00:00Z");
var T = new Date("2027-06-01T00:00:00Z");
var SERIAL = 0x4321n;
var DP_URL = "http://interop.example/crl/shard";

function parseCert(pem) { return pki.schema.x509.parse(pki.schema.x509.pemDecode(pem, "CERTIFICATE")); }
function derOf(pem) { return Buffer.from(pki.schema.x509.pemDecode(pem, "CERTIFICATE")); }

// A pre-encoded Extension SEQUENCE { extnID, critical?, extnValue } -- the documented hatch for a
// field the object form does not model (onlySomeReasons, and the DP-bearing IDP forms here).
function extDer(oidName, critical, valueDer) {
  var kids = [b.oid(pki.oid.byName(oidName))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(valueDer));
  return b.sequence(kids);
}
// ReasonFlags as minimal-DER NamedBitList content (X.690 sec. 11.2.2).
function reasonBits(bits) {
  var hi = Math.max.apply(null, bits);
  var out = Buffer.alloc(Math.floor(hi / 8) + 1);
  bits.forEach(function (bit) { out[Math.floor(bit / 8)] |= 0x80 >> (bit % 8); });
  return Buffer.concat([Buffer.from([7 - (hi % 8)]), out]);
}
var dpName = b.contextConstructed(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from(DP_URL, "ascii"))));
function idpExtDer(onlySomeReasons) {
  var kids = [dpName];
  if (onlySomeReasons) kids.push(b.contextPrimitive(3, onlySomeReasons));
  return extDer("issuingDistributionPoint", true, b.sequence(kids));
}
function freshestExtDer() {
  return extDer("freshestCRL", false, b.sequence([b.sequence([b.contextConstructed(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from(DP_URL, "ascii"))))])]));
}
function deltaExtDer(baseNumber) { return extDer("deltaCRLIndicator", true, b.integer(BigInt(baseNumber))); }

function pemWrap(der, label) {
  var b64 = Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n");
  return "-----BEGIN " + label + "-----\n" + b64 + (b64.endsWith("\n") ? "" : "\n") + "-----END " + label + "-----\n";
}

async function run() {
  var caKp = signing.makeSigner("ec-p256");
  var caPem = await pki.x509.sign({
    subject: [{ commonName: "Interop Revocation Root" }], subjectPublicKey: caKp.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: caKp.key }, { pem: true });
  var caCert = parseCert(caPem);

  var leafKp = signing.makeSigner("ed25519");
  var leafPem = await pki.x509.sign({
    subject: [{ commonName: "revoked.interop.example" }], subjectPublicKey: leafKp.spki, notBefore: NB, notAfter: NA,
    serialNumber: SERIAL,
    // The array form (pre-encoded Extension DER) -- cRLDistributionPoints has no object form, and
    // the array form is all-or-nothing, so keyUsage rides along in the same shape.
    extensions: [
      extDer("keyUsage", true, b.bitString(Buffer.from([0x80]), 7)),   // digitalSignature
      extDer("cRLDistributionPoints", false, b.sequence([b.sequence([dpName])])),
    ],
  }, { cert: caCert, key: caKp.key }, { pem: true });

  async function signCrl(spec) {
    return pki.crl.sign(Object.assign({ thisUpdate: TU, nextUpdate: NU }, spec), { cert: caCert, key: caKp.key });
  }
  async function ourVerdict(crlDers) {
    return pki.path.validate([derOf(leafPem)], {
      time: T, trustAnchors: caCert,
      revocationChecker: pki.path.crlChecker(crlDers),
    });
  }

  var shardA = await signCrl({ crlNumber: 10n, extensions: [idpExtDer(reasonBits([1, 2, 8]))] });
  var shardB = await signCrl({ crlNumber: 11n, extensions: [idpExtDer(reasonBits([3, 4, 5, 6, 7]))] });
  var baseFresh = await signCrl({ crlNumber: 20n, extensions: [freshestExtDer()] });
  var deltaRevoke = await signCrl({ crlNumber: 21n, revoked: [{ serialNumber: SERIAL, revocationDate: TU, reason: "keyCompromise" }], extensions: [deltaExtDer(20)] });
  var baseNoFresh = await signCrl({ crlNumber: 30n });
  var deltaRevoke2 = await signCrl({ crlNumber: 31n, revoked: [{ serialNumber: SERIAL, revocationDate: TU, reason: "keyCompromise" }], extensions: [deltaExtDer(30)] });
  var holdBase = await signCrl({ crlNumber: 40n, revoked: [{ serialNumber: SERIAL, revocationDate: TU, reason: "certificateHold" }], extensions: [freshestExtDer()] });
  var releaseDelta = await signCrl({ crlNumber: 41n, revoked: [{ serialNumber: SERIAL, revocationDate: TU, reason: "removeFromCRL" }], extensions: [deltaExtDer(40)] });

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-crlrevoke-"));
  try {
    var caFile = path.join(dir, "ca.pem"); fs.writeFileSync(caFile, caPem);
    var leafFile = path.join(dir, "leaf.pem"); fs.writeFileSync(leafFile, leafPem);
    function crlFile(name, ders) {
      var f = path.join(dir, name);
      fs.writeFileSync(f, ders.map(function (d) { return pemWrap(d, "X509 CRL"); }).join(""));
      return f;
    }

    // ---- (a) two shards covering all eight reasons ----
    var bothShards = crlFile("shards.pem", [shardA, shardB]);
    var vBoth = ctx.runOpenssl(["verify", "-crl_check", "-extended_crl", "-CAfile", caFile, "-CRLfile", bothShards, leafFile], { allowNonZero: true });
    check("openssl accepts when two reason shards union to all-reasons", vBoth.code === 0 && /:\s*OK\s*$/.test(vBoth.stdout.trim()));
    var rBoth = await ourVerdict([shardA, shardB]);
    check("pki.path.validate accepts the same two shards (agrees with openssl)", rBoth.valid === true);

    // ---- (b) one shard is partial coverage ----
    var oneShard = crlFile("shard-a.pem", [shardA]);
    var vOne = ctx.runOpenssl(["verify", "-crl_check", "-extended_crl", "-CAfile", caFile, "-CRLfile", oneShard, leafFile], { allowNonZero: true });
    check("openssl refuses a single reason shard (partial coverage)", vOne.code !== 0);
    var rOne = await ourVerdict([shardA]);
    check("pki.path.validate refuses the same single shard (agrees with openssl)", rOne.valid === false);

    // ---- (c) the control: without -extended_crl openssl ignores the shards entirely ----
    var vNoExt = ctx.runOpenssl(["verify", "-crl_check", "-CAfile", caFile, "-CRLfile", bothShards, leafFile], { allowNonZero: true });
    check("openssl without -extended_crl refuses the shards (so (a) really is accumulation)", vNoExt.code !== 0);

    // ---- (d) base + delta, locator present -> revoked on both sides ----
    var baseDelta = crlFile("base-delta.pem", [baseFresh, deltaRevoke]);
    var vDelta = ctx.runOpenssl(["verify", "-crl_check", "-use_deltas", "-CAfile", caFile, "-CRLfile", baseDelta, leafFile], { allowNonZero: true });
    check("openssl applies a delta when the base carries freshestCRL (revoked)", vDelta.code !== 0 && /revoked/i.test(vDelta.stdout + vDelta.stderr));
    var rDelta = await ourVerdict([baseFresh, deltaRevoke]);
    check("pki.path.validate reports revoked for the same base+delta (agrees with openssl)", rDelta.valid === false);

    // ---- (e) hold on the base, released by the delta -> good on both sides ----
    var holdRelease = crlFile("hold-release.pem", [holdBase, releaseDelta]);
    var vRelease = ctx.runOpenssl(["verify", "-crl_check", "-use_deltas", "-CAfile", caFile, "-CRLfile", holdRelease, leafFile], { allowNonZero: true });
    check("openssl releases a held certificate through its delta (OK)", vRelease.code === 0 && /:\s*OK\s*$/.test(vRelease.stdout.trim()));
    var rRelease = await ourVerdict([holdBase, releaseDelta]);
    check("pki.path.validate releases the same held certificate (agrees with openssl)", rRelease.valid === true);
    // and the control: the same hold WITHOUT the delta stays revoked on both sides.
    var holdOnly = crlFile("hold-only.pem", [holdBase]);
    var vHold = ctx.runOpenssl(["verify", "-crl_check", "-CAfile", caFile, "-CRLfile", holdOnly, leafFile], { allowNonZero: true });
    check("openssl reports a certificateHold with no delta as revoked", vHold.code !== 0);
    var rHold = await ourVerdict([holdBase]);
    check("pki.path.validate reports the same hold as revoked (agrees with openssl)", rHold.valid === false);

    // ---- (f) the DELIBERATE divergence: an unmergeable delta ----
    // openssl applies no delta (no locator) and answers OK. This checker keeps the delta's
    // revocation, because an unmerged delta is still consulted -- letting it be dropped would let
    // an attacker-influenced delta ERASE a revocation. Both verdicts are asserted so the
    // difference is a recorded decision rather than an unnoticed drift.
    var noLocator = crlFile("no-locator.pem", [baseNoFresh, deltaRevoke2]);
    var vNoLoc = ctx.runOpenssl(["verify", "-crl_check", "-use_deltas", "-CAfile", caFile, "-CRLfile", noLocator, leafFile], { allowNonZero: true });
    check("openssl ignores a delta with no freshestCRL locator and accepts", vNoLoc.code === 0);
    var rNoLoc = await ourVerdict([baseNoFresh, deltaRevoke2]);
    check("pki.path.validate still reports revoked (deliberately stricter: an unmerged delta cannot erase a revocation)",
      rNoLoc.valid === false);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
