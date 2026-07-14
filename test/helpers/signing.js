// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Signing test helper. Private keys cannot be committed (CI's gitleaks blocks them and the
// *.key credential-hygiene ignore is not re-allowed under test/fixtures), so a signer is
// generated at runtime: an ephemeral keypair plus a MINIMAL certificate hand-built around its
// public key. pki.cms.verify does not verify the signer certificate's own self-signature (it
// only reads the SPKI + matches the issuer/serial or SKI), so the cert carries a dummy
// signature and no real cert-signing is needed.

var crypto = require("node:crypto");
var pki = require("../../index.js");
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }

// A minimal X.509 certificate (v3) around `spki`, self-issued, with a dummy signature.
// opts.ski adds a subjectKeyIdentifier extension; opts.serial / opts.cn override the defaults.
function minimalCert(spki, opts) {
  opts = opts || {};
  var alg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
  var name = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable(opts.cn || "Test Signer")])])]);
  var validity = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
  var tbsFields = [b.explicit(0, b.integer(2n)), b.integer(BigInt(opts.serial || 0x77)), alg, name, validity, name, b.raw(spki)];
  if (opts.ski) {
    var keyid = crypto.createHash("sha1").update(spki).digest();
    var inner = opts.badSki ? b.integer(5) : b.octetString(keyid);   // badSki: the value is not an OCTET STRING
    var ext = b.sequence([b.oid(O("subjectKeyIdentifier")), b.octetString(inner)]);
    tbsFields.push(b.explicit(3, b.sequence([ext])));   // extensions [3] EXPLICIT
  }
  return b.sequence([b.sequence(tbsFields), alg, b.bitString(Buffer.from([0, 0, 0, 0]), 0)]);
}

// makeSigner(alg, opts) -> { cert (DER Buffer), key (PKCS#8 DER Buffer), keyObject, spki }.
// alg: "rsa" | "rsa-pss" | "ec-p256" | "ec-p384" | "ec-p521" | "ed25519" | "ed448".
// opts.pssHash pins the id-RSASSA-PSS key's permitted hash in its SPKI params (e.g. "sha384").
function makeSigner(alg, opts) {
  opts = opts || {};
  var kp;
  switch (alg) {
    case "rsa": kp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }); break;
    case "rsa-pss": kp = crypto.generateKeyPairSync("rsa-pss", opts.pssHash ? { modulusLength: 2048, hashAlgorithm: opts.pssHash, mgf1HashAlgorithm: opts.pssHash } : { modulusLength: 2048 }); break;   // SPKI OID is id-RSASSA-PSS
    case "ec-p256": kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }); break;
    case "ec-p384": kp = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }); break;
    case "ec-p521": kp = crypto.generateKeyPairSync("ec", { namedCurve: "secp521r1" }); break;
    case "ed25519": kp = crypto.generateKeyPairSync("ed25519"); break;
    case "ed448": kp = crypto.generateKeyPairSync("ed448"); break;
    default: throw new Error("makeSigner: unknown algorithm " + alg);
  }
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  return { cert: minimalCert(spki, opts), key: kp.privateKey.export({ format: "der", type: "pkcs8" }), keyObject: kp.privateKey, spki: spki };
}

module.exports = { makeSigner: makeSigner, minimalCert: minimalCert };
