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
var compositeSig = require("../../lib/composite-sig");
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
// The raw subjectPublicKey bytes (past the unused-bits octet) of an exported SPKI DER.
function _rawSpkiKey(spkiDer) { return pki.asn1.read.bitString(pki.asn1.decode(spkiDer).children[1]).bytes; }
// The node keygen type for an EC WebCrypto curve.
var _EC_NODE_CURVE = { "P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1" };

// A minimal X.509 certificate (v3) around `spki`, self-issued, with a dummy signature.
// opts.ski adds a subjectKeyIdentifier extension; opts.exts is an array of pre-built Extension
// SEQUENCEs appended to the extensions [3] block; opts.serial / opts.cn override the defaults.
function minimalCert(spki, opts) {
  opts = opts || {};
  var alg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
  var name = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable(opts.cn || "Test Signer")])])]);
  var validity = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
  var tbsFields = [b.explicit(0, b.integer(2n)), b.integer(BigInt(opts.serial || 0x77)), alg, name, validity, name, b.raw(spki)];
  var exts = (opts.exts || []).slice();
  if (opts.ski) {
    var keyid = crypto.createHash("sha1").update(spki).digest();
    var inner = opts.badSki ? b.integer(5) : b.octetString(keyid);   // badSki: the value is not an OCTET STRING
    exts.push(b.sequence([b.oid(O("subjectKeyIdentifier")), b.octetString(inner)]));
  }
  if (exts.length) tbsFields.push(b.explicit(3, b.sequence(exts)));   // extensions [3] EXPLICIT
  return b.sequence([b.sequence(tbsFields), alg, b.bitString(Buffer.from([0, 0, 0, 0]), 0)]);
}

var _EC_WIDTH = { prime256v1: 32, secp384r1: 48, secp521r1: 66, secp256k1: 32 };
var _EC_JWK_CURVE = { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521", secp256k1: "secp256k1" };

// smallScalarKey(curve, d) -> { spki, key (PKCS#8 DER), keyObject } for the EC key whose private key is
// the integer `d` (a BigInt). A key with d below 256, or within 256 of the group order, is one every
// verb in the toolkit refuses as compromised.
function smallScalarKey(curve, d) {
  var hex = d.toString(16);
  while (hex.length < _EC_WIDTH[curve] * 2) hex = "0" + hex;
  var ecdh = crypto.createECDH(curve);
  ecdh.setPrivateKey(Buffer.from(hex, "hex"));
  var pub = ecdh.getPublicKey();
  var w = _EC_WIDTH[curve];
  var keyObject = crypto.createPrivateKey({ format: "jwk", key: { kty: "EC", crv: _EC_JWK_CURVE[curve],
    x: pub.subarray(1, 1 + w).toString("base64url"), y: pub.subarray(1 + w).toString("base64url"),
    d: Buffer.from(hex, "hex").toString("base64url") } });
  return { spki: crypto.createPublicKey(keyObject).export({ type: "spki", format: "der" }),
    key: keyObject.export({ type: "pkcs8", format: "der" }), keyObject: keyObject };
}

// rawSignedCert(o) -> a v3 certificate DER, signed with o.issuerKey (an Ed25519 or EC KeyObject) but
// built here rather than by pki.x509.sign, which refuses to certify a compromised key or sign with one.
// o: { subject (a CN string or Name DER), issuerName (the same; default the subject), spki, issuerKey,
// serial (default 1), ca (adds a critical basicConstraints cA and keyUsage keyCertSign + cRLSign),
// keyUsageByte (the keyUsage bits ca sets, as one byte, default 0x06), san (a list of { dNSName } /
// { iPAddress: "a.b.c.d" } entries for a subjectAltName), exts (further Extension DER), notBefore,
// notAfter }.
function rawSignedCert(o) {
  function nameOf(v) { return Buffer.isBuffer(v) ? v : b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8(v)])])]); }
  var subject = nameOf(o.subject);
  var issuer = o.issuerName === undefined ? subject : nameOf(o.issuerName);
  var hash = null, alg;
  if (o.issuerKey.asymmetricKeyType === "ed25519") alg = b.sequence([b.oid(O("Ed25519"))]);
  else if (o.issuerKey.asymmetricKeyType === "ec") {
    hash = { prime256v1: "sha256", secp256k1: "sha256", secp384r1: "sha384", secp521r1: "sha512" }[o.issuerKey.asymmetricKeyDetails.namedCurve];
    alg = b.sequence([b.oid(O({ sha256: "ecdsaWithSHA256", sha384: "ecdsaWithSHA384", sha512: "ecdsaWithSHA512" }[hash]))]);
  } else throw new Error("rawSignedCert: unsupported issuer key type " + o.issuerKey.asymmetricKeyType);
  var validity = b.sequence([b.utcTime(o.notBefore || new Date("2026-01-01T00:00:00Z")), b.utcTime(o.notAfter || new Date("2030-01-01T00:00:00Z"))]);
  var fields = [b.explicit(0, b.integer(2n)), b.integer(BigInt(o.serial || 1)), alg, issuer, validity, subject, b.raw(o.spki)];
  var exts = [];
  if (o.ca) {
    exts.push(b.sequence([b.oid(O("basicConstraints")), b.boolean(true), b.octetString(b.sequence([b.boolean(true)]))]));
    var ku = o.keyUsageByte || 0x06, unused = 0;
    while (unused < 7 && !(ku & (1 << unused))) unused++;   // DER: the unused bits are the trailing zero bits
    exts.push(b.sequence([b.oid(O("keyUsage")), b.boolean(true), b.octetString(b.bitString(Buffer.from([ku]), unused))]));
  }
  if (o.san) {
    var names = o.san.map(function (n) {
      return n.dNSName !== undefined ? b.contextPrimitive(2, Buffer.from(n.dNSName, "ascii"))
        : b.contextPrimitive(7, Buffer.from(n.iPAddress.split(".").map(Number)));
    });
    exts.push(b.sequence([b.oid(O("subjectAltName")), b.octetString(b.sequence(names))]));
  }
  if (o.exts) exts = exts.concat(o.exts);
  if (exts.length) fields.push(b.explicit(3, b.sequence(exts)));
  var tbs = b.sequence(fields);
  return b.sequence([tbs, alg, b.bitString(crypto.sign(hash, tbs, o.issuerKey), 0)]);
}

// makeSigner(alg, opts) -> { cert (DER Buffer), key (PKCS#8 DER Buffer), keyObject, spki }.
// alg: "rsa" | "rsa-pss" | "ec-p256" | "ec-p384" | "ec-p521" | "ed25519" | "ed448".
// opts.pssHash pins the id-RSASSA-PSS key's permitted hash in its SPKI params (e.g. "sha384").
function makeSigner(alg, opts) {
  opts = opts || {};
  var kp;
  if (alg.indexOf("slh-dsa-") === 0) { kp = crypto.generateKeyPairSync(alg); }   // FIPS 205 SLH-DSA -- any of the twelve pure sets (node type == the OID name minus id-)
  else switch (alg) {
    case "rsa": kp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }); break;
    case "rsa-pss": kp = crypto.generateKeyPairSync("rsa-pss", opts.pssHash ? { modulusLength: 2048, hashAlgorithm: opts.pssHash, mgf1HashAlgorithm: opts.pssHash } : { modulusLength: 2048 }); break;   // SPKI OID is id-RSASSA-PSS
    case "ec-p256": kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }); break;
    case "ec-p384": kp = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }); break;
    case "ec-p521": kp = crypto.generateKeyPairSync("ec", { namedCurve: "secp521r1" }); break;
    case "ed25519": kp = crypto.generateKeyPairSync("ed25519"); break;
    case "ed448": kp = crypto.generateKeyPairSync("ed448"); break;
    case "ml-dsa-44": kp = crypto.generateKeyPairSync("ml-dsa-44"); break;   // SPKI OID is id-ml-dsa-44
    case "ml-dsa-65": kp = crypto.generateKeyPairSync("ml-dsa-65"); break;
    case "ml-dsa-87": kp = crypto.generateKeyPairSync("ml-dsa-87"); break;
    default: throw new Error("makeSigner: unknown algorithm " + alg);
  }
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  return { cert: minimalCert(spki, opts), key: kp.privateKey.export({ format: "der", type: "pkcs8" }), keyObject: kp.privateKey, spki: spki };
}

// A keyUsage extension (SEQUENCE { extnID, critical BOOLEAN, extnValue OCTET STRING }) asserting a
// single named bit -- keyEncipherment (2) or keyAgreement (4), which M9/M15 of the CMS enveloped
// profile require on a recipient certificate.
// The RFC 5280 sec. 4.2.1.3 KeyUsage bit positions, all nine, so a vector can mint a certificate
// confined to any one of them.
var _KU_BIT = { digitalSignature: 0, nonRepudiation: 1, keyEncipherment: 2, dataEncipherment: 3,
  keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8 };
function keyUsageExt(bitName) {
  var ku = b.namedBitString([_KU_BIT[bitName]]);   // minimal single-bit NamedBitList (X.690 sec. 11.2.2)
  return b.sequence([b.oid(O("keyUsage")), b.boolean(true), b.octetString(ku)]);
}

// makeRecipient(kind, opts) -- an encryption recipient for pki.cms.encrypt/decrypt tests: a runtime
// keypair (gitleaks blocks committed private keys) + a minimal certificate around its SPKI carrying
// the profile-mandated keyUsage. Returns { cert, key (PKCS#8 DER), keyObject, spki }.
var _RECIP = {
  "rsa": { gen: ["rsa", { modulusLength: 2048 }], ku: "keyEncipherment" },
  "ec-p256": { gen: ["ec", { namedCurve: "prime256v1" }], ku: "keyAgreement" },
  "ec-p384": { gen: ["ec", { namedCurve: "secp384r1" }], ku: "keyAgreement" },
  "ec-p521": { gen: ["ec", { namedCurve: "secp521r1" }], ku: "keyAgreement" },
  "x25519": { gen: ["x25519"], ku: "keyAgreement" },
  "x448": { gen: ["x448"], ku: "keyAgreement" },
  "ml-kem-512": { gen: ["ml-kem-512"], ku: "keyEncipherment" },
  "ml-kem-768": { gen: ["ml-kem-768"], ku: "keyEncipherment" },
  "ml-kem-1024": { gen: ["ml-kem-1024"], ku: "keyEncipherment" },
};
var _recipSerial = 0x1000;
function makeRecipient(kind, opts) {
  opts = opts || {};
  var spec = _RECIP[kind];
  if (!spec) throw new Error("makeRecipient: unknown kind " + kind);
  var kp = crypto.generateKeyPairSync.apply(crypto, spec.gen);
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var exts = (opts.exts || []).slice();
  if (opts.keyUsage !== false) exts.push(keyUsageExt(opts.keyUsage || spec.ku));
  // A unique serial + CN per recipient so two recipients never collide on the issuerAndSerialNumber
  // rid (recipient certs are self-issued, so the issuer DN is the per-recipient CN).
  var serial = opts.serial != null ? opts.serial : (_recipSerial += 1);
  var cert = minimalCert(spki, { cn: opts.cn || ("Recipient " + kind + " " + serial), serial: serial, ski: opts.ski, exts: exts });
  return { cert: cert, key: kp.privateKey.export({ format: "der", type: "pkcs8" }), keyObject: kp.privateKey, spki: spki };
}

// makeCompositeSigner(arm, opts) -> { cert (DER), key: { mldsa, trad } (PKCS#8 DER pair), spki,
// comp } for a composite ML-DSA arm (draft-ietf-lamps-pq-composite-sigs). Generates the two
// component keypairs and builds a minimal signer cert whose SPKI carries the composite OID over the
// raw mldsaPK || tradPK concatenation (sec. 4.1) -- the exact shape pki.cms.verify / pki.path.validate
// split. The traditional public key is the uncompressed EC point, the raw EdDSA key, or the
// RSAPublicKey DER, matching composite-sig's _verifyTradComponent SPKI wrappers.
function makeCompositeSigner(arm, opts) {
  var comp = compositeSig.COMPOSITE_ALGS[O(arm)];
  if (!comp) throw new Error("makeCompositeSigner: unknown composite arm " + arm);
  if (comp.trad.unsupported) throw new Error("makeCompositeSigner: " + arm + " is unsupported (" + comp.trad.unsupported + ")");
  var mk = crypto.generateKeyPairSync(comp.mldsa.toLowerCase());   // "ML-DSA-65" -> node "ml-dsa-65"
  var mldsaPK = _rawSpkiKey(mk.publicKey.export({ format: "der", type: "spki" }));
  var tk, tradPK;
  if (comp.trad.ec) {
    tk = crypto.generateKeyPairSync("ec", { namedCurve: _EC_NODE_CURVE[comp.trad.ec] });
    tradPK = _rawSpkiKey(tk.publicKey.export({ format: "der", type: "spki" }));   // uncompressed point (leading 0x04)
  } else if (comp.trad.eddsa) {
    tk = crypto.generateKeyPairSync(comp.trad.eddsa.toLowerCase());               // "Ed25519" -> "ed25519"
    tradPK = _rawSpkiKey(tk.publicKey.export({ format: "der", type: "spki" }));
  } else {
    tk = crypto.generateKeyPairSync("rsa", { modulusLength: comp.trad.rsaBits });
    tradPK = tk.publicKey.export({ format: "der", type: "pkcs1" });               // RSAPublicKey DER
  }
  var spki = b.sequence([b.sequence([b.oid(O(arm))]), b.bitString(Buffer.concat([mldsaPK, tradPK]), 0)]);
  return {
    cert: minimalCert(spki, opts),
    key: { mldsa: mk.privateKey.export({ format: "der", type: "pkcs8" }), trad: tk.privateKey.export({ format: "der", type: "pkcs8" }) },
    spki: spki, comp: comp,
  };
}

// signerOf(bag) -> the signer descriptor a signing verb reads, and nothing else. makeSigner returns
// keyObject and spki alongside cert and key for callers that need them, and a verb that reads two of
// those fields refuses the rest: a name the verb does not read is a request it never carried out,
// which is what `pki.cms.sign`'s unknown-field door exists to report. Takes one bag or an array of
// them, and leaves a descriptor literal alone, so a vector that supplies a deliberately bad field
// still reaches the door. The form follows `cert`, as the verb's own does.
var _CERT_FORM = ["cert", "key", "pss", "digestAlgorithm", "combinedRsaSig"];
var _KEY_ONLY_FORM = ["spki", "keyIdentifier", "key", "pss", "digestAlgorithm", "combinedRsaSig"];
function signerOf(v) {
  if (Array.isArray(v)) return v.map(signerOf);
  if (v === null || typeof v !== "object") return v;
  var fields = v.cert == null && v.spki != null ? _KEY_ONLY_FORM : _CERT_FORM;
  var out = {};
  fields.forEach(function (k) { if (Object.prototype.hasOwnProperty.call(v, k)) out[k] = v[k]; });
  return out;
}

// makeTsa(alg, opts) -> { cert, key }: the TSA argument pki.tsp.sign actually reads. makeSigner
// also returns keyObject and spki for callers that need them, and handing the whole bag to a verb
// that reads two of its fields is the shape the unknown-field doors exist to refuse -- a name
// belonging on the OPTIONS, placed here instead, would otherwise be dropped in silence.
// makeTsa(alg, opts) -- a TSA whose certificate satisfies RFC 3161 sec. 2.3: one critical
// extendedKeyUsage naming id-kp-timeStamping alone, plus keyUsage digitalSignature.
function makeTsa(alg, opts) {
  var o = Object.assign({}, opts || {});
  var eku = b.sequence([b.oid(O("extKeyUsage")), b.boolean(true), b.octetString(b.sequence([b.oid(O("timeStamping"))]))]);
  o.exts = (o.exts || []).concat([keyUsageExt("digitalSignature"), eku]);
  var s = makeSigner(alg, o);
  return { cert: s.cert, key: s.key };
}

module.exports = { makeSigner: makeSigner, makeTsa: makeTsa, minimalCert: minimalCert, smallScalarKey: smallScalarKey, rawSignedCert: rawSignedCert, makeCompositeSigner: makeCompositeSigner, makeRecipient: makeRecipient, keyUsageExt: keyUsageExt, signerOf: signerOf };
