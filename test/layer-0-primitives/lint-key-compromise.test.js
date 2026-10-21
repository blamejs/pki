// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lint/key-compromise/small-ec-private-key: an elliptic curve public key whose private
 * scalar is a small integer, so the private key can be found by trying every candidate.
 *
 * The rule compares the public point's x-coordinate with d*G for every d below the bound. The
 * points d*G and (n-d)*G share an x-coordinate, so a key whose scalar is n-d is reported too. The
 * known answer is a CA certificate that was issued and trusted with such a key: "EM DV TLS CA -
 * G3B", whose P-384 private key is 156, revoked for key compromise on 2026-10-18.
 *
 *   K1-K3  the real certificate, the default rule set, and the profile by name
 *   K4-K7  each supported curve, the n-d mirror, the bound, and a random key (control)
 *   K8     a certification request with such a key
 */

var crypto = require("crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");

var EM_DV_TLS_CA_G3B = [
  "-----BEGIN CERTIFICATE-----",
  "MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQsw",
  "CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl",
  "ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1",
  "NDA4WhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11",
  "ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C",
  "AQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/J",
  "hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p",
  "1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L",
  "WUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQG",
  "CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow",
  "KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB",
  "BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY",
  "aHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw",
  "b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0f",
  "BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j",
  "cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E",
  "AwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPO",
  "Ibh1grvdULDCAjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8",
  "gt2TlfJbHii+KNvK",
  "-----END CERTIFICATE-----",
  "",
].join("\n");

var ID = "lint/key-compromise/small-ec-private-key";
var ORDER = {
  secp384r1: BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
};

function has(report, id) { return report.findings.some(function (f) { return f.id === id; }); }

// pki.x509.sign and pki.csr.sign refuse a small-scalar key, so the fixtures are built and signed
// outside them.
function keyFromScalar(curve, d) { return signing.smallScalarKey(curve, d); }

var ISSUER = null;
function issuer() {
  if (ISSUER) return ISSUER;
  var kp = crypto.generateKeyPairSync("ed25519");
  ISSUER = { keyObject: kp.privateKey, cert: signing.rawSignedCert({ subject: "Small Scalar Test CA",
    spki: kp.publicKey.export({ type: "spki", format: "der" }), issuerKey: kp.privateKey, ca: true }) };
  return ISSUER;
}

function certWithSpki(spki) {
  return signing.rawSignedCert({ subject: "small-scalar", issuerName: "Small Scalar Test CA", spki: spki, issuerKey: issuer().keyObject, serial: 2 });
}

function certFor(curve, d) { return certWithSpki(keyFromScalar(curve, d).spki); }

// A PKCS#10 request for `key`, signed with it (ECDSA with SHA-384) and built outside pki.csr.sign.
function csrFor(key) {
  var b = pki.asn1.build;
  var name = b.sequence([b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.utf8("small-csr.example")])])]);
  var info = b.sequence([b.integer(0n), name, b.raw(key.spki), b.contextConstructed(0, Buffer.alloc(0))]);
  var alg = b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA384"))]);
  return b.sequence([info, alg, b.bitString(crypto.sign("sha384", info, key.keyObject), 0)]);
}

async function run() {
  var real = pki.lint.certificate(EM_DV_TLS_CA_G3B);
  check("K1. the default rule set reports the real CA certificate whose P-384 private key is 156", has(real, ID));
  var finding = real.findings.filter(function (f) { return f.id === ID; })[0];
  check("K1b. ...as an error naming the curve", finding.severity === "error" && finding.context && finding.context.curve === "secp384r1");
  check("K1c. ...without disclosing the scalar", JSON.stringify(finding).indexOf("156") === -1);
  check("K2. the key-compromise profile is listed", pki.lint.profiles().indexOf("key-compromise") !== -1);
  check("K3. ...and runs the row by name", has(pki.lint.certificate(EM_DV_TLS_CA_G3B, { profile: "key-compromise" }), ID));

  var curves = ["prime256v1", "secp384r1", "secp521r1", "secp256k1"];
  for (var i = 0; i < curves.length; i++) {
    check("K4. a private key of 1 is reported on " + curves[i], has(pki.lint.certificate(await certFor(curves[i], 1n)), ID));
    check("K4b. a private key of 255 is reported on " + curves[i], has(pki.lint.certificate(await certFor(curves[i], 255n)), ID));
  }
  check("K5. a private key of n-7 shares an x-coordinate with 7 and is reported",
    has(pki.lint.certificate(await certFor("secp384r1", ORDER.secp384r1 - 7n)), ID));
  check("K6. a private key of 256 is outside the bound and not reported",
    !has(pki.lint.certificate(await certFor("prime256v1", 256n)), ID));
  var random = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  var randomCert = await pki.x509.sign({ subject: "random-p384", subjectPublicKey: random.publicKey.export({ type: "spki", format: "der" }),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") },
    { key: random.privateKey.export({ type: "pkcs8", format: "der" }) });
  check("K7. CONTROL a randomly generated key is not reported", !has(pki.lint.certificate(randomCert), ID));
  check("K7b. a key that is not an elliptic curve point is not applicable", !has(pki.lint.certificate((await issuer()).cert), ID));

  // The same small key in the other encodings a certificate can carry: explicit curve parameters,
  // a compressed point and a hybrid point. A point that is not on the curve is not a key, and the
  // linter reports nothing about it rather than throwing.
  var b = pki.asn1.build;
  var named = keyFromScalar("secp384r1", 11n).spki;
  var namedPoint = pki.asn1.read.bitString(pki.asn1.decode(named).children[1]).bytes;
  var explicitParams = pki.asn1.decode(crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1", paramEncoding: "explicit",
    publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "der" } }).publicKey).children[0].children[1].bytes;
  var explicitSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("ecPublicKey")), b.raw(explicitParams)]), b.bitString(namedPoint, 0)]);
  var compressedPoint = crypto.ECDH.convertKey(namedPoint, "secp384r1", undefined, undefined, "compressed");
  var algId = pki.asn1.decode(named).children[0].bytes;
  var compressedSpki = b.sequence([b.raw(algId), b.bitString(compressedPoint, 0)]);
  var hybridPoint = crypto.ECDH.convertKey(namedPoint, "secp384r1", undefined, undefined, "hybrid");
  var hybridSpki = b.sequence([b.raw(algId), b.bitString(hybridPoint, 0)]);
  check("K9. a small key with explicit curve parameters is reported",
    has(pki.lint.certificate(await certWithSpki(explicitSpki)), ID));
  check("K9b. a small key carried as a compressed point is reported",
    has(pki.lint.certificate(await certWithSpki(compressedSpki)), ID));
  check("K9c. a small key carried as a hybrid point is reported",
    has(pki.lint.certificate(await certWithSpki(hybridSpki)), ID));
  var offCurve = Buffer.from(namedPoint);
  offCurve[offCurve.length - 1] ^= 1;
  var offCurveSpki = b.sequence([b.raw(algId), b.bitString(offCurve, 0)]);
  var offReport = null, offThrew = false;
  try { offReport = pki.lint.certificate(await certWithSpki(offCurveSpki)); } catch (_e) { offThrew = true; }
  check("K9d. a point that is not on the curve is not reported as a small key, and the lint does not throw",
    offThrew === false && offReport !== null && !has(offReport, ID));

  var small = keyFromScalar("secp384r1", 9n);
  var csr = csrFor(small);
  check("K8. a certification request for such a key is reported by the default request rule set", has(pki.lint.csr(csr), ID));
  check("K8b. ...and by the key-compromise request profile", has(pki.lint.csr(csr, { profile: "key-compromise" }), ID));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
