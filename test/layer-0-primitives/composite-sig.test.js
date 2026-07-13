// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- composite ML-DSA signature verification
 * (draft-ietf-lamps-pq-composite-sigs), driven through the shipped consumer path
 * pki.path.validate over each fixture's self-signed composite certificate.
 *
 * Oracle: the draft-19 official test vectors
 * (github.com/lamps-wg/draft-composite-sigs). Each x5c is a self-signed composite
 * root; validating it as its own trust anchor exercises builtinVerify's composite
 * branch -- the fixed-offset split, the M' reconstruction, the ML-DSA-with-context
 * component verify, the traditional component verify, and the AND-combination.
 */

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "composite", "kat.json"), "utf8"));
// The arms Node's WebCrypto surface cannot verify (brainpool curves; the
// SHAKE256/64 pre-hash): registered + params-guarded, deferred at verify.
var DEFERRED = {
  "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512": 1,
  "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512": 1,
  "id-MLDSA87-Ed448-SHAKE256": 1,
};
var T = new Date("2030-01-01T00:00:00Z");

function anchorFor(c) {
  return { name: c.subject, publicKey: c.subjectPublicKeyInfo.bytes, algorithm: c.subjectPublicKeyInfo.algorithm };
}
function sigCheck(res) {
  var ch = res.results[0].checks.find(function (x) { return x.name === "signature"; });
  return ch ? ch.ok : null;
}
async function verifyDer(der) {
  var c = pki.schema.x509.parse(der);
  return sigCheck(await pki.path.validate([c], { time: T, trustAnchor: anchorFor(c) }));
}

async function run() {
  // 1. Every supported variant verifies byte-exactly against the draft KAT; every
  //    deferred variant fails closed (never silently accepted).
  for (var i = 0; i < KAT.tests.length; i++) {
    var t = KAT.tests[i];
    var ok = await verifyDer(Buffer.from(t.x5c, "base64"));
    if (DEFERRED[t.tcId]) check("composite " + t.tcId + " (unsupported arm) fails closed at verify", ok === false);
    else check("composite " + t.tcId + " verifies against the draft-19 KAT", ok === true);
  }

  // 2. AND-combination (THREAT-MODEL: all components MUST pass -- never AND->OR).
  //    Corrupting EITHER the ML-DSA half or the traditional half fails the whole
  //    composite. The signatureValue content is mldsaSig || tradSig; ML-DSA-65's
  //    signature is the fixed first 3309 bytes, the ECDSA DER is the remainder.
  var v = KAT.tests.find(function (x) { return x.tcId === "id-MLDSA65-ECDSA-P256-SHA512"; });
  var der = Buffer.from(v.x5c, "base64");
  var cert = pki.schema.x509.parse(der);
  var off = der.indexOf(cert.signatureValue.bytes);
  var MLDSA65_SIG = 3309;
  function flip(k) { var b = Buffer.from(der); b[off + k] ^= 0xff; return b; }
  check("composite: intact self-signed cert verifies (baseline)", (await verifyDer(der)) === true);
  check("composite: a corrupted ML-DSA component fails the whole signature (AND, not OR)", (await verifyDer(flip(20))) === false);
  check("composite: a corrupted traditional component fails the whole signature (AND, not OR)", (await verifyDer(flip(MLDSA65_SIG + 20))) === false);

  // 3. Registry + params-absent policy: the 18 composite OIDs round-trip by name
  //    and every one demands absent AlgorithmIdentifier parameters (draft sec. 5.3).
  var names = [
    "id-MLDSA44-RSA2048-PSS-SHA256", "id-MLDSA44-RSA2048-PKCS15-SHA256", "id-MLDSA44-Ed25519-SHA512",
    "id-MLDSA44-ECDSA-P256-SHA256", "id-MLDSA65-RSA3072-PSS-SHA512", "id-MLDSA65-RSA3072-PKCS15-SHA512",
    "id-MLDSA65-RSA4096-PSS-SHA512", "id-MLDSA65-RSA4096-PKCS15-SHA512", "id-MLDSA65-ECDSA-P256-SHA512",
    "id-MLDSA65-ECDSA-P384-SHA512", "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "id-MLDSA65-Ed25519-SHA512",
    "id-MLDSA87-ECDSA-P384-SHA512", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "id-MLDSA87-Ed448-SHAKE256",
    "id-MLDSA87-RSA3072-PSS-SHA512", "id-MLDSA87-RSA4096-PSS-SHA512", "id-MLDSA87-ECDSA-P521-SHA512",
  ];
  var leaf = 37, allRoundTrip = true, allParamsAbsent = true;
  names.forEach(function (nm) {
    var dotted = "1.3.6.1.5.5.7.6." + (leaf++);
    if (pki.oid.byName(nm) !== dotted || pki.oid.name(dotted) !== nm) allRoundTrip = false;
    if (pki.oid.paramsMustBeAbsent(dotted) !== true) allParamsAbsent = false;
  });
  check("all 18 composite OIDs round-trip name<->1.3.6.1.5.5.7.6.37-54", allRoundTrip);
  check("all 18 composite AlgorithmIdentifiers require absent parameters (draft sec. 5.3)", allParamsAbsent);

  // 4. Malformed composite public keys fail closed (the split + decode edges). Drive
  //    a real composite-signed leaf against a crafted trust-anchor SPKI whose OID
  //    matches (passing the key<->sig binding) but whose key body is malformed.
  var b = pki.asn1.build;
  var leaf = pki.schema.x509.parse(Buffer.from(v.x5c, "base64"));
  var algSeq = b.sequence([b.oid(pki.oid.byName("id-MLDSA65-ECDSA-P256-SHA512"))]);
  function anchorSpki(spki) { return { name: leaf.subject, publicKey: spki, algorithm: leaf.subjectPublicKeyInfo.algorithm }; }
  async function sigWithAnchor(spki) {
    return sigCheck(await pki.path.validate([leaf], { time: T, trustAnchor: anchorSpki(spki) }));
  }
  // A composite subjectPublicKey BIT STRING with a non-zero unused-bit count.
  check("composite: anchor SPKI with unused bits fails closed",
    (await sigWithAnchor(b.sequence([algSeq, b.bitString(Buffer.alloc(2100), 3)]))) === false);
  // A key body shorter than the fixed ML-DSA component (1952 for ML-DSA-65).
  check("composite: anchor SPKI shorter than the ML-DSA component fails closed",
    (await sigWithAnchor(b.sequence([algSeq, b.bitString(Buffer.alloc(100), 0)]))) === false);
  // A subjectPublicKey that is not a BIT STRING (an OCTET STRING) -- the decode throws.
  check("composite: anchor SPKI whose key is not a BIT STRING fails closed",
    (await sigWithAnchor(b.sequence([algSeq, b.octetString(Buffer.alloc(2100))]))) === false);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
