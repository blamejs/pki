// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the ITU-T X.509 (2019) clause 9.8 alternative-signature surface -- the three extension
 * value decoders reached through pki.schema.x509 and pki.schema.crl, and pki.altSig.signedData /
 * verify / subjectAltPublicKey over both structures.
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: every one of these on hostile input either
 * returns or throws a pki.errors.PkiError -- any other throw is a finding and is rethrown so the
 * fuzzer records a reproducer.
 *
 * `signedData` is the interesting target and the reason this harness exists. It is the one place the
 * toolkit rebuilds a structure it parsed, and it does that by slicing original byte ranges out of a
 * decoded tree and recomputing three SEQUENCE headers. Every index it reads is therefore a place a
 * malformed tree could send it off the end, so the fuzzer is pointed at the tree shape rather than at
 * the extension values alone: the bytes are used BOTH as an extension value inside a well-formed
 * wrapper and as a whole structure handed over raw.
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

var SAPKI = O("subjectAltPublicKeyInfo");
var ALT_ALG = O("altSignatureAlgorithm");
var ALT_VAL = O("altSignatureValue");

var NAME = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("Fuzz")])])]);
var ALG = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
var SIG = b.bitString(Buffer.alloc(64, 1), 0);
var VALIDITY = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
var SPKI = b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]),
  b.bitString(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 7)]), 0)]);
/** @internal A real ML-DSA-65 SPKI shape, so a well-formed alternative key is in the corpus reach. */
var ALT_SPKI = b.sequence([b.sequence([b.oid(O("id-ml-dsa-65"))]), b.bitString(Buffer.alloc(1952, 3), 0)]);

function ext(o, critical, valueDer) {
  var f = [b.oid(o)];
  if (critical) f.push(b.boolean(true));
  f.push(b.octetString(valueDer));
  return b.sequence(f);
}

/** @internal A certificate whose three alternative extensions are built from the fuzzer's bytes in
 *  whichever combination the first input byte selects, so both a complete set and each broken subset
 *  are reached. */
function certWith(data, pick) {
  var exts = [];
  if (pick & 1) exts.push(ext(SAPKI, (pick & 8) !== 0, data.length ? data : ALT_SPKI));
  if (pick & 2) exts.push(ext(ALT_ALG, false, data.length ? data : ALG));
  if (pick & 4) exts.push(ext(ALT_VAL, false, data.length ? data : SIG));
  var fields = [b.explicit(0, b.integer(2n)), b.integer(1n), ALG, NAME, VALIDITY, NAME, b.raw(SPKI)];
  if (exts.length) fields.push(b.explicit(3, b.sequence(exts)));
  return b.sequence([b.sequence(fields), ALG, SIG]);
}

function crlWith(data, pick) {
  var exts = [];
  if (pick & 2) exts.push(ext(ALT_ALG, false, data.length ? data : ALG));
  if (pick & 4) exts.push(ext(ALT_VAL, false, data.length ? data : SIG));
  var fields = [b.integer(1n), ALG, NAME, b.utcTime(new Date("2020-01-01T00:00:00Z"))];
  if (exts.length) fields.push(b.explicit(0, b.sequence(exts)));
  return b.sequence([b.sequence(fields), ALG, SIG]);
}

module.exports.fuzz = async function (data) {
  var pick = data.length ? (data[0] % 16) : 7;

  /** @internal The fuzzer's bytes as each extension value, in every present/absent combination, read
   *  through the shipped parse and the shared extension decoder. */
  var certDer = guard(function () { return certWith(data, pick); });
  if (certDer) {
    guard(function () {
      var p = pki.schema.x509.parse(certDer);
      p.extensions.forEach(function (e) { guard(function () { return pki.schema.x509.decodeExtension(e); }); });
      return p;
    });
    guard(function () { return pki.altSig.signedData(certDer); });
    guard(function () { return pki.altSig.subjectAltPublicKey(certDer); });
    await guardAsync(pki.altSig.verify(certDer, ALT_SPKI));
    await guardAsync(pki.altSig.verify(certDer, data));
    guard(function () { return pki.inspect.certificate(certDer); });
  }

  var crlDer = guard(function () { return crlWith(data, pick); });
  if (crlDer) {
    guard(function () { return pki.schema.crl.parse(crlDer); });
    guard(function () { return pki.altSig.signedData(crlDer); });
    guard(function () { return pki.altSig.subjectAltPublicKey(crlDer); });
    await guardAsync(pki.altSig.verify(crlDer, ALT_SPKI));
  }

  /** @internal And the bytes handed over as a whole structure, which is where a malformed tree reaches
   *  the byte-range slicing directly rather than inside a wrapper this harness built. */
  guard(function () { return pki.altSig.signedData(data); });
  guard(function () { return pki.altSig.subjectAltPublicKey(data); });
  await guardAsync(pki.altSig.verify(data, ALT_SPKI));
  await guardAsync(pki.altSig.verify(data, data));

  /** @internal The lint profile over the same certificate, so the rules that read these extensions see
   *  a value the decoder may have refused. */
  if (certDer) guard(function () { return pki.lint.certificate(certDer, { profile: "x509-altsig" }); });
};
