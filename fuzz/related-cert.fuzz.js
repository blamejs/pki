// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 9763 related certificates -- the relatedCertificate extension value read through
 * pki.schema.x509, the relatedCertRequest attribute value read through pki.schema.csr, and the
 * pki.relatedCert verbs over both.
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: every one of these on hostile input either
 * returns or throws a pki.errors.PkiError -- any other throw (a RangeError from a hash length, a
 * BigInt fault out of the BinaryTime reader, a TypeError from a field the decoder left absent) is a
 * finding and is rethrown so the fuzzer records a reproducer.
 *
 * Two surfaces need the fuzzer bytes wrapped rather than handed over raw, because neither structure
 * is a top-level format: the extension value is reached by placing it inside a certificate, and the
 * attribute value by placing it inside a certification request. Both wrappers are built here from
 * fixed bytes so the only variable is the value under test, and the enclosing signature is never
 * verified by a parse, which is what lets the wrapper be assembled without a key.
 */
var pki = require("..");
var b = pki.asn1.build;

function guard(fn) {
  try { return fn(); } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}
async function guardAsync(p) {
  try { return await p; } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}
function O(n) { return pki.oid.byName(n); }

var NAME = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("Fuzz")])])]);
var ALG = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
var SIG = b.bitString(Buffer.alloc(64, 1), 0);
var VALIDITY = b.sequence([
  b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z")),
]);
/** @internal A real SPKI, so the certificate wrapper parses far enough to reach the extension. */
var SPKI = pki.asn1.decode(pki.schema.x509.parse(
  b.sequence([b.sequence([b.explicit(0, b.integer(2n)), b.integer(1n), ALG, NAME, VALIDITY, NAME,
    b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]),
      b.bitString(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 7)]), 0)])]), ALG, SIG])
).subjectPublicKeyInfo.bytes);

function certCarrying(extValueDer, critical) {
  var fields = [b.oid(O("relatedCertificate"))];
  if (critical) fields.push(b.boolean(true));
  fields.push(b.octetString(extValueDer));
  var tbs = b.sequence([b.explicit(0, b.integer(2n)), b.integer(1n), ALG, NAME, VALIDITY, NAME,
    b.raw(SPKI.bytes), b.explicit(3, b.sequence([b.sequence(fields)]))]);
  return b.sequence([tbs, ALG, SIG]);
}

function csrCarrying(attrValueDer) {
  var attr = b.sequence([b.oid(O("relatedCertRequest")), b.set([attrValueDer])]);
  var cri = b.sequence([b.integer(0n), NAME, b.raw(SPKI.bytes), b.contextConstructed(0, attr)]);
  return b.sequence([cri, ALG, SIG]);
}

module.exports.fuzz = async function (data) {
  /** @internal The fuzzer's bytes as the extension value, both criticalities: sec. 4.1 states the
   *  rule at SHOULD NOT, so a critical one parses and must be read by the same decoder. */
  guard(function () { return pki.schema.x509.parse(certCarrying(data, false)); });
  guard(function () { return pki.schema.x509.parse(certCarrying(data, true)); });

  /** @internal And through the extension decoder, which is where a length or algorithm fault lands. */
  guard(function () {
    var p = pki.schema.x509.parse(certCarrying(data, false));
    var e = p.extensions.filter(function (x) { return x.oid === O("relatedCertificate"); })[0];
    return e === undefined ? null : pki.schema.x509.decodeExtension(e);
  });

  /** @internal The fuzzer's bytes as the attribute value. */
  guard(function () { return pki.schema.csr.parse(csrCarrying(data)); });

  /** @internal The verbs over the fuzzer's bytes directly: a certificate that is not one, a digest
   *  value of an arbitrary length, and a digest algorithm named from the input. */
  guard(function () { return pki.relatedCert.certificateHash(data); });
  guard(function () { return pki.relatedCert.certificateHash(data, "sha256"); });
  var name = data.length > 0 ? ["sha256", "sha384", "sha512", "sha1", "md5", "sha3-256"][data[0] % 6] : "sha256";
  guard(function () { return pki.relatedCert.certificateHash(certCarrying(b.nullValue(), false), name); });
  guard(function () { return pki.relatedCert.matchesCertificate({ hashAlgorithm: name, hashValue: data }, data); });

  /** @internal The preimage builder over a Name and a serial taken from the input, where the Name is
   *  the fuzzer's bytes and the time is read as a BinaryTime. */
  var serial = data.length > 1 ? BigInt(data[0]) * 256n + BigInt(data[1]) : 1n;
  var when = data.length > 2 ? BigInt(data[2]) * 65536n : 0n;
  guard(function () {
    return pki.relatedCert.requestSignedData({ certID: { issuer: data, serialNumber: serial }, requestTime: when });
  });
  guard(function () {
    return pki.relatedCert.requestSignedData({ certID: { issuer: NAME, serialNumber: serial }, requestTime: when });
  });

  /** @internal And the verifier, over a request whose fields come from the input and a certificate
   *  that is a real one, so the mismatch check and the algorithm derivation are both walked. */
  var realCert = certCarrying(b.nullValue(), false);
  var realParsed = guard(function () { return pki.schema.x509.parse(realCert); });
  if (realParsed) {
    await guardAsync(pki.relatedCert.verifyRequest({
      certID: { issuer: realParsed.issuer.bytes, serialNumber: realParsed.serialNumber },
      requestTime: when, locationInfo: ["https://a.example/"],
      signature: { unusedBits: 0, bytes: data },
    }, realCert));
    await guardAsync(pki.relatedCert.verifyRequest({
      certID: { issuer: data, serialNumber: serial }, requestTime: when,
      locationInfo: ["https://a.example/"], signature: { unusedBits: 0, bytes: data },
    }, realCert));
    await guardAsync(pki.relatedCert.verifyRequest({
      certID: { issuer: realParsed.issuer.bytes, serialNumber: realParsed.serialNumber },
      requestTime: when, locationInfo: ["https://a.example/"],
      signature: { unusedBits: 0, bytes: Buffer.alloc(64, 2) },
    }, realCert, { signatureAlgorithm: data }));
  }
};
