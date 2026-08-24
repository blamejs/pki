// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.path.validate (RFC 5280 §6 certification-path validation).
 * RED conformance vectors written BEFORE the implementation: every vector
 * drives the public pki.path surface with REAL signed certificates (issuer
 * keys generated per algorithm, signatures produced by pki.webcrypto), so
 * the signature-chaining checks genuinely verify or genuinely fail.
 *
 * Vector numbering follows the build plan's RED list (V1..V46): accept
 * paths, each canonical §6.1 rejection, the notorious off-by-one and
 * self-issued rules, the CVE-anchored guards (2021-3450 CA gate, 2022-21449
 * zero ECDSA, 2023-0464 policy-tree cap, 2023-0465 bad policy OID,
 * 2009-2408 NUL-in-DN, 2015-9235 algorithm confusion), and the §6.3 CRL
 * checker contract.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var b = pki.asn1.build;
var subtle = pki.webcrypto.subtle;

async function codeOf(promise) {
  try { await promise; return "NO-THROW"; }
  catch (e) { return e.code || e.name; }
}

// ---------------------------------------------------------------------------
// Signature plumbing — per-algorithm key material, generated once.
// Ed25519 is the workhorse chain algorithm (deterministic, no hash params,
// no encoding conversion); RSA / ECDSA-P256 / ML-DSA-65 get dedicated
// vectors (V1/V3/V4) so every verify path in the bridge is exercised.
// ---------------------------------------------------------------------------

var ALG = {
  ed25519: {
    gen: { name: "Ed25519" }, sign: { name: "Ed25519" },
    sigOid: "1.3.101.112", sigParams: "omit",
  },
  rsa: {
    gen: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSASSA-PKCS1-v1_5" },
    sigOid: "1.2.840.113549.1.1.11", sigParams: "null",
  },
  p256: {
    gen: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" },
    sigOid: "1.2.840.10045.4.3.2", sigParams: "omit", p1363: 32,
  },
  mldsa65: {
    gen: { name: "ML-DSA-65" }, sign: { name: "ML-DSA-65" },
    sigOid: "2.16.840.1.101.3.4.3.18", sigParams: "omit",
  },
  // SLH-DSA-SHA2-128F — the fast-signing set keeps the verify-path test quick.
  slhdsa: {
    gen: { name: "SLH-DSA-SHA2-128F" }, sign: { name: "SLH-DSA-SHA2-128F" },
    sigOid: "2.16.840.1.101.3.4.3.21", sigParams: "omit",
  },
  rsapss: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss",
  },
  // A real RSA-PSS key that DECLARES an unsupported hash OID in its PSS params
  // (the signature is genuine SHA-256; resolution must reject on the bad hash).
  pssbad: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-badhash",
  },
  // PSS params declaring a MGF1 hash (SHA-384) that mismatches the signature
  // hash (SHA-256) — WebCrypto cannot honor it, so resolution must reject.
  pssbadmgf: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-badmgf",
  },
  // PSS AlgorithmIdentifier whose parameters field is a DER NULL (not a
  // RSASSA-PSS-params SEQUENCE) — must fail closed, not default to SHA-1.
  pssnull: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "null",
  },
  // PSS params SEQUENCE carrying a malformed primitive [0] hashAlgorithm field.
  pssprim: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-primfield",
  },
  // PSS params declaring a NEGATIVE saltLength (-1) — the OpenSSL shim would
  // read it as a salt-length constant; must be rejected.
  pssnegsalt: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-negsalt",
  },
  // PSS params declaring an OVERSIZED saltLength (past the safe-integer
  // range) — the value must stay exact through conversion; a length that
  // would round is not verifiable material.
  pssbigsalt: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-bigsalt",
  },
  // PSS declaring SHA-1 (explicitly rejected — SHAttered) hash + mgf1SHA1.
  psssha1: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-sha1",
  },
  // PSS with an explicit SHA-256 hash but NO maskGenAlgorithm (defaults to
  // mgf1SHA1, which mismatches -> must be rejected).
  pssnomgf: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-nomgf",
  },
  // PSS params carrying an unexpected [4] field -> structural fault, rejected.
  pssextra: {
    gen: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
    sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-extrafield",
  },
};
var OID_SHA1 = "1.3.14.3.2.26";

// Aliases: distinct keypairs of the same algorithm (KEYS is keyed by the
// alias), so an intermediate / rollover / leaf each get their own key.
ALG.ed25519i = ALG.ed25519;
ALG.ed25519j = ALG.ed25519;
ALG.ed25519leaf = ALG.ed25519;
ALG.p256i = ALG.p256;

// Rebuild an EC SubjectPublicKeyInfo with its namedCurve parameters removed
// (a key that inherits its curve from the issuer), and extract those params.
function stripEcParams(spkiBuf) {
  var n = pki.asn1.decode(spkiBuf);
  return b.sequence([b.sequence([b.raw(n.children[0].children[0].bytes)]), b.raw(n.children[1].bytes)]);
}
function ecCurveParams(spkiBuf) {
  return pki.asn1.decode(spkiBuf).children[0].children[1].bytes;
}

var KEYS = {}; // algKey -> { privateKey, publicKey, spki: Buffer }

async function ensureKeys(algKey) {
  if (KEYS[algKey]) return KEYS[algKey];
  var a = ALG[algKey];
  var kp = await subtle.generateKey(a.gen, true, ["sign", "verify"]);
  var spki = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
  KEYS[algKey] = { privateKey: kp.privateKey, publicKey: kp.publicKey, spki: spki, alg: a };
  return KEYS[algKey];
}

// P1363 (fixed-width r||s) -> DER SEQUENCE { r INTEGER, s INTEGER } — the
// on-wire form an X.509 ECDSA signatureValue carries. The INVERSE of the
// validator's verify-bridge shim, needed fixture-side to author real certs.
function p1363ToDer(sig, width) {
  var r = BigInt("0x" + Buffer.from(sig.slice(0, width)).toString("hex"));
  var s = BigInt("0x" + Buffer.from(sig.slice(width)).toString("hex"));
  return b.sequence([b.integer(r), b.integer(s)]);
}

// ---------------------------------------------------------------------------
// DER fixture builders (canonical shapes, mirroring the schema-x509 suite)
// ---------------------------------------------------------------------------

var OID_SHA256 = "2.16.840.1.101.3.4.2.1", OID_SHA384 = "2.16.840.1.101.3.4.2.2", OID_MGF1 = "1.2.840.113549.1.1.8";
function algIdDer(a) {
  var children = [b.oid(a.sigOid)];
  if (a.sigParams === "null") children.push(b.nullValue());
  else if (a.sigParams === "pss-primfield") {
    // a malformed primitive [0] where an EXPLICIT constructed field is required
    children.push(b.sequence([b.contextPrimitive(0, Buffer.from([0x01]))]));
  }
  else if (a.sigParams === "pss-bigsalt") {
    var shaBig = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, shaBig),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), shaBig])),
      b.explicit(2, b.integer(1n << 60n)),   // saltLength past the safe-integer range
    ]));
  }
  else if (a.sigParams === "pss-negsalt") {
    var sha = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, sha),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), sha])),
      b.explicit(2, b.integer(-1n)),   // negative saltLength
    ]));
  }
  else if (a.sigParams === "pss-sha1") {
    var sha1 = b.sequence([b.oid(OID_SHA1), b.nullValue()]);
    children.push(b.sequence([b.explicit(0, sha1), b.explicit(1, b.sequence([b.oid(OID_MGF1), sha1]))]));
  }
  else if (a.sigParams === "pss-nomgf") {
    children.push(b.sequence([b.explicit(0, b.sequence([b.oid(OID_SHA256), b.nullValue()]))]));   // hash only, no MGF
  }
  else if (a.sigParams === "pss-bare-hash") {
    // MALFORMED: hashAlgorithm [0] EXPLICIT wraps a bare OID, not an
    // AlgorithmIdentifier SEQUENCE { algorithm, parameters }. A lenient reader
    // that falls back to the OID accepts it as SHA-256 (forgery surface).
    var mgfHb = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, b.oid(OID_SHA256)),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), mgfHb])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-bare-mgfhash") {
    // MALFORMED: the MGF1 hash parameter is a bare OID, not an AlgorithmIdentifier.
    var hAlg = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, hAlg),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), b.oid(OID_SHA256)])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-hash-extra") {
    // MALFORMED: hashAlgorithm SEQUENCE carries a spurious third element beyond
    // { OID, parameters } — an AlgorithmIdentifier has at most two.
    var mgfHx = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, b.sequence([b.oid(OID_SHA256), b.nullValue(), b.integer(1n)])),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), mgfHx])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-hash-badparams") {
    // MALFORMED: hashAlgorithm parameters is a SEQUENCE, not the required NULL.
    var mgfHb2 = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, b.sequence([b.oid(OID_SHA256), b.sequence([])])),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), mgfHb2])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-hash-nullparams-nonempty") {
    // MALFORMED: hashAlgorithm parameters is a NULL with NON-EMPTY content (05 01 00)
    // — the right tag but not a well-formed empty NULL (X.690 8.8.2). A tag-only
    // check accepts it; the NULL's emptiness must be validated.
    var mgfHne = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, b.sequence([b.oid(OID_SHA256), Buffer.from([0x05, 0x01, 0x00])])),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), mgfHne])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-multichild-salt") {
    // MALFORMED: the EXPLICIT [2] saltLength wrapper carries TWO values; an
    // EXPLICIT wrapper holds exactly one, and reading children[0] would ignore
    // the rest, accepting non-DER PSS parameters.
    var hMs = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, hMs),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), hMs])),
      b.explicit(2, Buffer.concat([b.integer(32n), b.integer(1n)])),
    ]));
  }
  else if (a.sigParams === "pss-multichild-mgf") {
    // MALFORMED: the EXPLICIT [1] maskGenAlgorithm wrapper carries TWO values.
    var hMm = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    var mgfSeq = b.sequence([b.oid(OID_MGF1), hMm]);
    children.push(b.sequence([
      b.explicit(0, hMm),
      b.explicit(1, Buffer.concat([mgfSeq, mgfSeq])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-mgfhash-extra") {
    // MALFORMED: the MGF1 inner hash AlgorithmIdentifier has a spurious third element.
    var hAlg2 = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, hAlg2),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), b.sequence([b.oid(OID_SHA256), b.nullValue(), b.integer(1n)])])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  else if (a.sigParams === "pss-extrafield") {
    var shaX = b.sequence([b.oid(OID_SHA256), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, shaX),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), shaX])),
      b.explicit(4, b.integer(1n)),   // unexpected [4] field
    ]));
  }
  else if (a.sigParams === "pss" || a.sigParams === "pss-badhash" || a.sigParams === "pss-badmgf") {
    // RSASSA-PSS-params { hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2] } (RFC 4055 §3.1, EXPLICIT tags).
    var hashOid = a.sigParams === "pss-badhash" ? "1.3.6.1.4.1.99999.7" : OID_SHA256;
    var mgfHashOid = a.sigParams === "pss-badmgf" ? OID_SHA384 : OID_SHA256;
    var hashAlg = b.sequence([b.oid(hashOid), b.nullValue()]);
    var mgfHash = b.sequence([b.oid(mgfHashOid), b.nullValue()]);
    children.push(b.sequence([
      b.explicit(0, hashAlg),
      b.explicit(1, b.sequence([b.oid(OID_MGF1), mgfHash])),
      b.explicit(2, b.integer(32n)),
    ]));
  }
  return b.sequence(children);
}

function atv(typeOid, value) { return b.sequence([b.oid(typeOid), b.utf8(value)]); }

// A Name from either a CN string or an array of pre-built RDN SETs.
function nameDer(spec) {
  if (typeof spec === "string") return b.sequence([b.set([atv("2.5.4.3", spec)])]);
  return b.sequence(spec);
}

function validityDer(notBefore, notAfter) {
  return b.sequence([b.utcTime(notBefore), b.utcTime(notAfter)]);
}

// Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue
// OCTET STRING } — critical FALSE is OMITTED (DER DEFAULT rule).
function ext(oidStr, critical, valueDer) {
  var children = [b.oid(oidStr)];
  if (critical) children.push(b.boolean(true));
  children.push(b.octetString(valueDer));
  return b.sequence(children);
}

// BasicConstraints value: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen? }.
function bcVal(cA, pathLen) {
  var children = [];
  if (cA) children.push(b.boolean(true));
  if (pathLen !== undefined) children.push(b.integer(BigInt(pathLen)));
  return b.sequence(children);
}
function bcExt(cA, pathLen) { return ext("2.5.29.19", true, bcVal(cA, pathLen)); }

// KeyUsage value: BIT STRING of named bits (bit 0 = MSB). DER named-bit
// encoding trims trailing zero bits (minimal unused-bits form).
function kuVal(bitPositions) {
  var maxBit = Math.max.apply(null, bitPositions);
  var nBytes = (maxBit >> 3) + 1;
  var buf = Buffer.alloc(nBytes);
  bitPositions.forEach(function (p) { buf[p >> 3] |= (0x80 >> (p & 7)); });
  var unused = 7 - (maxBit & 7);
  return b.bitString(buf, unused);
}
function kuExt(bitPositions) { return ext("2.5.29.15", true, kuVal(bitPositions)); }
var KU_KEY_CERT_SIGN = 5, KU_CRL_SIGN = 6, KU_DIGITAL_SIGNATURE = 0;

// Composite ML-DSA SubjectPublicKeyInfo (draft-ietf-lamps-pq-composite-sigs sec.
// 4.1): AlgorithmIdentifier { compositeOID } with ABSENT parameters + the raw
// mldsaPK || tradPK as the subjectPublicKey BIT STRING. The key body is a
// fixed-length placeholder (ML-DSA-65 pk 1952 + ECDSA-P256 point 65); these
// vectors drive the composite keyUsage gate and the fail-closed composite verify
// seam, which run before any real key material is consumed.
var COMPOSITE_OID = pki.oid.byName("id-MLDSA65-ECDSA-P256-SHA512");
function compositeSpki() { return b.sequence([b.sequence([b.oid(COMPOSITE_OID)]), b.bitString(Buffer.alloc(1952 + 65), 0)]); }

// GeneralName arms used by the fixtures.
function gnDns(text) { return b.contextPrimitive(2, Buffer.from(text, "ascii")); }
function gnEmail(text) { return b.contextPrimitive(1, Buffer.from(text, "ascii")); }
function gnUri(text) { return b.contextPrimitive(6, Buffer.from(text, "ascii")); }
function gnIp(octets) { return b.contextPrimitive(7, Buffer.from(octets)); }
function gnDirectoryName(nDer) { return b.contextConstructed(4, nDer); }
// registeredID [8] IMPLICIT OBJECT IDENTIFIER — the context tag carries the raw OID content.
function gnRegisteredID(oidStr) { return b.contextPrimitive(8, pki.asn1.decode(b.oid(oidStr)).content); }
// x400Address [3] — a non-empty constructed form the validator does not decode.
function gnX400() { return b.contextConstructed(3, b.sequence([b.integer(1n)])); }

function sanExt(generalNames, critical) {
  return ext("2.5.29.17", critical === true, b.sequence(generalNames));
}

// NameConstraints value: SEQUENCE { permittedSubtrees [0]?, excludedSubtrees [1]? }
// of GeneralSubtree ::= SEQUENCE { base GeneralName } (minimum DEFAULT 0 omitted).
function subtree(baseGn) { return b.sequence([baseGn]); }
function ncVal(permitted, excluded) {
  var children = [];
  if (permitted) children.push(b.contextConstructed(0, Buffer.concat(permitted.map(subtree))));
  if (excluded) children.push(b.contextConstructed(1, Buffer.concat(excluded.map(subtree))));
  return b.sequence(children);
}
function ncExt(permitted, excluded) { return ext("2.5.29.30", true, ncVal(permitted, excluded)); }

// CertificatePolicies value: SEQUENCE OF PolicyInformation { policyIdentifier }.
function cpExt(policyOids) {
  return ext("2.5.29.32", false, b.sequence(policyOids.map(function (p) { return b.sequence([b.oid(p)]); })));
}
var ANY_POLICY = "2.5.29.32.0";

// PolicyMappings value: SEQUENCE OF SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }.
function pmExt(pairs) {
  return ext("2.5.29.33", true, b.sequence(pairs.map(function (pr) {
    return b.sequence([b.oid(pr[0]), b.oid(pr[1])]);
  })));
}

// PolicyConstraints value: SEQUENCE { requireExplicitPolicy [0]?, inhibitPolicyMapping [1]? }
// — [n] IMPLICIT INTEGER (context-primitive, minimal content octets).
function intContent(n) {
  var hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  var buf = Buffer.from(hex, "hex");
  if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
  return buf;
}
function pcExt(opts) {
  var children = [];
  if (opts.requireExplicitPolicy !== undefined) children.push(b.contextPrimitive(0, intContent(opts.requireExplicitPolicy)));
  if (opts.inhibitPolicyMapping !== undefined) children.push(b.contextPrimitive(1, intContent(opts.inhibitPolicyMapping)));
  return ext("2.5.29.36", true, b.sequence(children));
}

function iapExt(n) { return ext("2.5.29.54", true, b.integer(BigInt(n))); }

// ---------------------------------------------------------------------------
// mkCert — a REAL signed certificate. The issuer's private key signs the
// exact tbs DER, so chain verification genuinely runs.
// ---------------------------------------------------------------------------

var SERIAL = 1n;

async function mkCert(o) {
  var signer = await ensureKeys(o.signWith || "ed25519");
  var subjectKeys = o.subjectKeys ? await ensureKeys(o.subjectKeys) : signer;
  var spkiDer = o.spki || subjectKeys.spki;
  var a = signer.alg;

  var tbsChildren = [
    b.explicit(0, b.integer(BigInt(o.version !== undefined ? o.version : 2))),
    b.integer(o.serial !== undefined ? o.serial : (SERIAL += 1n)),
    o.sigAlgOverride || algIdDer(a),   // tbs signatureAlgorithm (must equal the outer, §4.1.1.2)
    nameDer(o.issuer),
    validityDer(o.notBefore || new Date("2026-01-01T00:00:00Z"), o.notAfter || new Date("2030-01-01T00:00:00Z")),
    nameDer(o.subject),
    b.raw(spkiDer),
  ];
  if (o.extensions && o.extensions.length) {
    tbsChildren.push(b.explicit(3, b.sequence(o.extensions)));
  }
  var tbs = o.mutateTbs ? o.mutateTbs(b.sequence(tbsChildren)) : b.sequence(tbsChildren);

  var sig = Buffer.from(await subtle.sign(a.sign, signer.privateKey, tbs));
  if (a.p1363) sig = p1363ToDer(sig, a.p1363);
  if (o.mutateSig) sig = o.mutateSig(sig);

  // o.sigAlgOverride replaces the signatureAlgorithm (both tbs + outer, to test
  // parameter-shape mismatches).
  var outerAlg = o.sigAlgOverride || algIdDer(a);
  return b.sequence([tbs, outerAlg, b.bitString(sig, 0)]);
}

// Anchor tuple from generated key material (§6.1.1(d-g)).
async function mkAnchor(algKey, name) {
  var k = await ensureKeys(algKey || "ed25519");
  return {
    name: pki.schema.x509.parse(await mkCert({ subject: name || "Anchor", issuer: name || "Anchor", signWith: algKey || "ed25519" })).subject,
    publicKey: k.spki,
    // The anchor `algorithm` is the KEY algorithm the SPKI self-describes (RFC 5280 sec. 6.1.4
    // workingPublicKeyAlgorithm), NOT the signature OID -- for EC the two differ (ecPublicKey vs
    // ecdsaWithSHA256). Derive it from the SPKI so it matches, as pki.path.validate now requires.
    algorithm: pki.asn1.read.oid(pki.asn1.decode(k.spki).children[0].children[0]),
  };
}

async function run(path, opts) {
  var parsed = path.map(function (der) { return Buffer.isBuffer(der) ? pki.schema.x509.parse(der) : der; });
  return pki.path.validate(parsed, opts);
}

// Extract the failing codes across all per-cert checks.
function failCodes(res) {
  var out = [];
  (res.results || []).forEach(function (r) {
    (r.checks || []).forEach(function (c) { if (!c.ok && c.code) out.push(c.code); });
  });
  return out;
}

var T2027 = new Date("2027-06-01T00:00:00Z"); // inside every default window

// ---------------------------------------------------------------------------
// ACCEPT vectors (V1-V7)
// ---------------------------------------------------------------------------

async function testAcceptChains() {
  var anchor = await mkAnchor("ed25519", "Root");

  // good 2-cert chain (RSA and PQC segments get dedicated runs below).
  var inter = await mkCert({ subject: "Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leaf = await mkCert({ subject: "Leaf", issuer: "Inter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });

  var res = await run([inter, leaf], { time: T2027, trustAnchor: anchor });
  check("good 2-cert chain validates", res.valid === true);
  check("per-cert results present", res.results.length === 2);
  check("workingPublicKey is the leaf SPKI", Buffer.isBuffer(res.workingPublicKey) && res.workingPublicKey.equals(KEYS.ed25519leaf.spki));

  // good 1-cert chain (anchor directly issues the leaf).
  var direct = await mkCert({ subject: "Direct", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var res1 = await run([direct], { time: T2027, trustAnchor: anchor });
  check("good 1-cert chain validates", res1.valid === true);

  // #74: a parsed root CERTIFICATE works as opts.trustAnchor (normalized to a tuple), and a mis-shaped
  // anchor is refused with path/bad-input instead of a soft verdict -- a tuple missing `algorithm`
  // previously validated the path (fail-OPEN) because a self-describing SPKI masked the undefined value.
  var rootCert74 = pki.schema.x509.parse(await mkCert({ subject: "Root", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] }));
  check("#74 a parsed root certificate is accepted as opts.trustAnchor",
    (await run([direct], { time: T2027, trustAnchor: rootCert74 })).valid === true);
  check("#74 a malformed trustAnchor tuple is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: "nope", algorithm: 1234 } }))) === "path/bad-input");
  check("#74 a trustAnchor tuple missing algorithm is refused (was a fail-open valid:true)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes } }))) === "path/bad-input");
  check("#74 a trustAnchor whose algorithm is an object with no OID is refused (self-describing SPKI would else mask it)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: {} } }))) === "path/bad-input");
  check("#74 a trustAnchor whose algorithm is a non-canonical OID string is refused (built-in verify reads the SPKI, not this)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "not-an-oid" } }))) === "path/bad-input");
  check("#74 a trustAnchor whose algorithm object carries a non-canonical OID is refused",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: { oid: "not-an-oid" } } }))) === "path/bad-input");
  check("#74 a trustAnchor whose declared algorithm is canonical but DISAGREES with its publicKey SPKI is refused (declared must equal the SPKI key algorithm)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.2.840.113549.1.1.1" } }))) === "path/bad-input");
  // TOCTOU: a caller publicKey getter must not answer the declared-vs-SPKI check with one key and hand
  // verification another. toAnchor pins publicKey once and the anchor it returns carries that pinned copy,
  // so a getter returning a matching EC SPKI to the check and the real Ed25519 signer to the key-binding
  // cannot force valid:true -- the check bytes ARE the bound bytes.
  var ecSpki74 = (await ensureKeys("p256")).spki;
  var ecOid74 = pki.asn1.read.oid(pki.asn1.decode(ecSpki74).children[0].children[0]);
  var pkReads74 = 0;
  var lyingAnchor74 = {
    name: rootCert74.subject,
    algorithm: ecOid74,   // declares ecPublicKey, matching the EC SPKI the check reads
    get publicKey() { pkReads74++; return pkReads74 <= 3 ? ecSpki74 : rootCert74.subjectPublicKeyInfo.bytes; },
  };
  var lyingRes74;
  try { lyingRes74 = await run([direct], { time: T2027, trustAnchor: lyingAnchor74 }); }
  catch (e) { lyingRes74 = { threw: (e && e.code) || "throw" }; }
  check("#74 a lying publicKey getter (matching SPKI to the check, real signer to the bind) cannot force valid:true (TOCTOU pinned)",
    lyingRes74.valid !== true);
  // Normalization must not re-read the publicKey accessor after snapshotting it: the flatten copy skips the
  // overridden fields (publicKey/algorithm/parameters), so an accessor-backed anchor is not read again for a
  // value that is immediately replaced. toAnchor reads publicKey 3x before the copy (truthiness,
  // Buffer.isBuffer, snapshot); a getter that throws on a 4th read still validates.
  var pkReadCount = 0;
  var accessorAnchor = {
    name: rootCert74.subject, algorithm: "1.3.101.112",
    get publicKey() { pkReadCount++; if (pkReadCount > 3) throw new Error("publicKey re-read after snapshot"); return rootCert74.subjectPublicKeyInfo.bytes; },
  };
  var rAccessor;
  try { rAccessor = await run([direct], { time: T2027, trustAnchor: accessorAnchor }); } catch (e) { rAccessor = { threw: (e && e.message) || "throw" }; }
  check("#74 the flatten copy does not re-read an overridden accessor field (publicKey) after snapshotting it",
    rAccessor.valid === true);
  // A publicKey that decodes to an AlgorithmIdentifier but omits the required key BIT STRING is a
  // structurally-incomplete SPKI: it must fail closed at the anchor door with path/bad-input, not slip
  // through the OID read to a soft valid:false when key import later rejects it (3007300506032b6570 =
  // SEQUENCE { SEQUENCE { OID ed25519 } } with no subjectPublicKey).
  check("#74 a structurally-incomplete trustAnchor SPKI (AlgorithmIdentifier, no key BIT STRING) is refused at entry",
    (await codeOf(run([direct], { time: T2027, trustAnchor: { name: rootCert74.subject, publicKey: Buffer.from("3007300506032b6570", "hex"), algorithm: "1.3.101.112" } }))) === "path/bad-input");
  check("#74 pki.path.anchorFromCert(cert) returns a tuple that validates",
    typeof pki.path.anchorFromCert === "function" &&
    (await run([direct], { time: T2027, trustAnchor: pki.path.anchorFromCert(rootCert74) })).valid === true);
  // The normalized anchor is a SELF-CONTAINED tuple: cloning it (Object.assign / spread / JSON) keeps every
  // field as its own property, so a caller can round-trip and reuse it. An anchor that only inherited its
  // name/metadata would lose them on Object.assign and be rejected as malformed on re-use.
  var normAnchor = pki.path.anchorFromCert({ name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" });
  var clonedAnchor = Object.assign({}, normAnchor);
  check("#74 a normalized anchor tuple is self-contained: an Object.assign clone keeps its name and re-validates",
    clonedAnchor.name !== undefined && Buffer.isBuffer(clonedAnchor.publicKey) &&
    (await run([direct], { time: T2027, trustAnchor: clonedAnchor })).valid === true);
  // anchorFromCert's documented output carries subjectDer; re-normalizing its result (a ready tuple) through
  // anchorFromCert again keeps it -- the conversion is idempotent, not lossy. A dropped subjectDer would make
  // the twice-normalized anchor a different shape than the once-normalized one, and the trust store keys its
  // dedup on subjectDer, so losing it on re-normalization would break a legitimate round-trip.
  var afcOnce = pki.path.anchorFromCert(rootCert74);
  var afcTwice = pki.path.anchorFromCert(afcOnce);
  check("#74 anchorFromCert is idempotent: re-normalizing its result preserves the documented subjectDer",
    Buffer.isBuffer(afcOnce.subjectDer) && Buffer.isBuffer(afcTwice.subjectDer) &&
    afcTwice.subjectDer.equals(afcOnce.subjectDer) &&
    (await run([direct], { time: T2027, trustAnchor: afcTwice })).valid === true);
  // A tuple anchor's documented trust-store identity fields -- label and mozillaCaPolicy, part of the closed
  // anchor field set pki.trust.parseCertdata emits -- survive normalization, so build's returned
  // result.trustAnchor still identifies which named store entry was selected. A field OUTSIDE the closed set
  // is not carried (proven separately).
  var labeledAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", label: "Test Root CA", mozillaCaPolicy: { serverAuth: true } };
  var buildLabeled74 = await pki.path.build(direct, { time: T2027, trustAnchors: [labeledAnchor74] });
  check("#74 a tuple anchor's documented data fields (label, mozillaCaPolicy) survive normalization on build's result.trustAnchor",
    buildLabeled74.valid === true && buildLabeled74.trustAnchor.label === "Test Root CA" &&
    !!buildLabeled74.trustAnchor.mozillaCaPolicy && buildLabeled74.trustAnchor.mozillaCaPolicy.serverAuth === true);
  // A tuple whose name / publicKey / algorithm is a THROWING accessor is a malformed anchor: the tuple
  // discriminator reads them under try/catch, so validate refuses with the documented path/bad-input rather
  // than leaking the getter's raw exception past the typed guards. Same for a throwing algorithm.oid getter.
  var throwName74 = { get name() { throw new Error("boom-name"); },
    publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  check("#74 a trustAnchor with a throwing name accessor is refused with path/bad-input, not a raw throw",
    (await codeOf(run([direct], { time: T2027, trustAnchor: throwName74 }))) === "path/bad-input");
  var throwAlgOid74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: { get oid() { throw new Error("boom-oid"); } } };
  check("#74 a trustAnchor with a throwing algorithm.oid accessor is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: throwAlgOid74 }))) === "path/bad-input");
  // A Proxy anchor is refused at the door with path/bad-input, before any field is read. A Proxy's traps can
  // answer the same read with different values on successive lookups, or report a field absent while forwarding
  // its siblings, so no field-by-field normalization can trust a Proxy to describe itself honestly. A
  // legitimate anchor is a plain tuple, a parsed certificate, or an Object.create(base) inheriting from one --
  // none is a Proxy -- so refusing it costs no real use and removes the whole class of trap-driven anchor forgery.
  var trapReads74 = 0;
  var proxyAnchor74 = new Proxy(
    { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" },
    { get: function (t, k, r) { trapReads74++; return Reflect.get(t, k, r); },
      getOwnPropertyDescriptor: function (t, k) { trapReads74++; return Object.getOwnPropertyDescriptor(t, k); } });
  check("#74 a Proxy trustAnchor is refused at the door with path/bad-input, before any field is read",
    (await codeOf(run([direct], { time: T2027, trustAnchor: proxyAnchor74 }))) === "path/bad-input" && trapReads74 === 0);
  // A Proxy whose target is a FUNCTION (typeof "function", not "object") is refused too: the door check tests
  // the Proxy internal slot, not the target's typeof, so a callable-target Proxy cannot slip past into a field read.
  var fnProxyAnchor74 = new Proxy(function () {}, { get: function () { return "1.3.101.112"; } });
  check("#74 a Proxy over a function target is also refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: fnProxyAnchor74 }))) === "path/bad-input");
  // A caller field OUTSIDE the closed anchor set is not carried onto the normalized anchor -- neither as
  // enumerable data nor as hidden non-enumerable state. A non-enumerable "internalSecret" is dropped entirely,
  // so it can never leak via Object.keys / spread / JSON nor ride along as hidden state.
  var hiddenAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  Object.defineProperty(hiddenAnchor74, "internalSecret", { value: "hidden", enumerable: false, configurable: true, writable: true });
  var buildHidden74 = await pki.path.build(direct, { time: T2027, trustAnchors: [hiddenAnchor74] });
  check("#74 a caller field outside the closed anchor set (non-enumerable) is dropped, not carried onto the normalized anchor",
    buildHidden74.valid === true && Object.keys(buildHidden74.trustAnchor).indexOf("internalSecret") === -1 &&
    buildHidden74.trustAnchor.internalSecret === undefined);
  // A Proxy anchor that reports `purposes` absent -- its getOwnPropertyDescriptor / has traps return
  // undefined / false for that one key while forwarding name / publicKey / algorithm -- would, if the
  // constraint maps were captured by reflection, drop the operator's { serverAuth: false } restriction and
  // validate a serverAuth path the anchor forbids. Refusing the Proxy at the door closes it: the descriptor
  // traps are never consulted, so the restriction cannot be hidden.
  var hidePurposes74 = new Proxy(
    { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
      purposes: { serverAuth: false } },
    { getOwnPropertyDescriptor: function (t, k) { return k === "purposes" ? undefined : Object.getOwnPropertyDescriptor(t, k); },
      has: function (t, k) { return k === "purposes" ? false : (k in t); } });
  check("#74 a Proxy anchor that hides a purposes restriction via its descriptor/has traps is refused, not read",
    (await codeOf(run([direct], { time: T2027, trustAnchor: hidePurposes74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A constraint MAP (purposes / distrustAfter) nested inside an otherwise-plain anchor and supplied as a Proxy
  // is refused too: its ownKeys trap could return an empty key list, dropping the restriction the caller
  // attached. A Proxy distrustAfter over { serverAuth: <past date> } that reports no keys would snapshot to an
  // empty map and omit the expired cutoff; it is refused at capture before it is reflected over.
  var proxyDistrust74 = new Proxy(
    { serverAuth: new Date("2000-01-01T00:00:00Z") },
    { ownKeys: function () { return []; }, getOwnPropertyDescriptor: function () { return undefined; } });
  var distrustProxyAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", distrustAfter: proxyDistrust74 };
  check("#74 a Proxy distrustAfter constraint map is refused with path/bad-input (its ownKeys trap cannot hide the cutoff)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: distrustProxyAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  var proxyPurposes74 = new Proxy({ serverAuth: false }, { ownKeys: function () { return []; } });
  var purposesProxyMapAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: proxyPurposes74 };
  check("#74 a Proxy purposes constraint map is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: purposesProxyMapAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A constraint map whose restriction is reached through the prototype -- Object.create({ serverAuth: <past
  // date> }) -- is refused, not silently dropped: getOwnPropertyNames reads only own keys, so an inherited entry
  // would normalize to an empty map and omit the cutoff. The map must be a plain object (or null-prototype).
  var inheritedDistrust74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", distrustAfter: Object.create({ serverAuth: new Date("2000-01-01T00:00:00Z") }) };
  check("#74 a distrustAfter map with a prototype-reached entry is refused with path/bad-input (not dropped to empty)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: inheritedDistrust74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  var inheritedPurposes74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: Object.create({ serverAuth: false }) };
  check("#74 a purposes map with a prototype-reached entry is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: inheritedPurposes74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A null-prototype constraint map is plain data and is accepted (a distrust cutoff BEFORE the check time
  // distrusts a leaf issued after it; here the anchor itself validates, proving the map was read, not refused).
  var nullProtoPurposes74 = Object.create(null); nullProtoPurposes74.serverAuth = true;
  var nullProtoAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: nullProtoPurposes74 };
  check("#74 a null-prototype constraint map is plain data and is accepted",
    (await run([direct], { time: T2027, trustAnchor: nullProtoAnchor74, checkPurpose: "serverAuth" })).valid === true);
  // A constraint map built in ANOTHER realm (vm context) has that realm's Object.prototype, not this one's, so
  // the identity test refuses it fail-closed. This is deliberate: a hostile object can mimic every STRUCTURAL
  // signal of a genuine Object.prototype (a non-enumerable data entry looks like a built-in), so only identity
  // is a sound plain-object test for a security-critical input. The operator passes a same-realm plain object.
  var crossRealmPurposes74 = require("vm").runInNewContext("({ serverAuth: true })");
  var crossRealmAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: crossRealmPurposes74 };
  check("#74 a constraint map from another realm (vm context) is refused fail-closed with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: crossRealmAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A restriction defined NON-ENUMERABLY on a custom prototype is refused too: the identity test refuses any
  // non-plain prototype regardless of how its entries are defined, so a non-enumerable serverAuth cannot slip
  // through looking like a built-in.
  var nonEnumProto74 = Object.create(Object.defineProperty(Object.create(null), "serverAuth", { value: new Date("2000-01-01T00:00:00Z"), enumerable: false }));
  var nonEnumAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", distrustAfter: nonEnumProto74 };
  check("#74 a non-enumerable restriction on a custom prototype is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: nonEnumAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A restriction defined as a NON-ENUMERABLE OWN entry on an otherwise-plain map must still be seen: the map is
  // materialized enumerable and the purpose-scoped-metadata gate counts own names (not Object.keys). With no
  // checkPurpose the anchor is refused (metadata present), not validated as though it carried none.
  var nonEnumEntryPurposes74 = {};
  Object.defineProperty(nonEnumEntryPurposes74, "serverAuth", { value: false, enumerable: false, configurable: true, writable: true });
  var nonEnumEntryAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: nonEnumEntryPurposes74 };
  check("#74 a non-enumerable own purposes entry still triggers the checkPurpose-required gate (not silently dropped)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: nonEnumEntryAnchor74 }))) === "path/bad-input");
  var rNonEnumApplied74 = await run([direct], { time: T2027, trustAnchor: nonEnumEntryAnchor74, checkPurpose: "serverAuth" });
  check("#74 a non-enumerable own purposes restriction is applied under checkPurpose (purpose not trusted)",
    rNonEnumApplied74.valid === false && failCodes(rNonEnumApplied74).indexOf("path/purpose-not-trusted") !== -1);
  // A symbol-keyed constraint entry is refused: getOwnPropertyNames omits symbols, so it would be dropped from
  // the snapshot and, keyed by no OID-name purpose, never applied. Refuse rather than silently drop.
  var symKeyPurposes74 = {};
  symKeyPurposes74[Symbol("serverAuth")] = false;
  var symKeyAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: symKeyPurposes74 };
  check("#74 a symbol-keyed constraint map entry is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: symKeyAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // An own __proto__ DATA entry on the map is refused: the snapshot skips __proto__ to avoid polluting the fresh
  // map, so it would be silently dropped. (defineProperty makes a data property NAMED __proto__ without changing
  // the object's prototype, so the map stays plain -- the presence of the entry is the concern, its value is
  // irrelevant, so a plain object is used to keep the intent unambiguous.)
  var protoKeyPurposes74 = {};
  Object.defineProperty(protoKeyPurposes74, "__proto__", { value: { note: "own data entry, not a prototype" }, enumerable: true, configurable: true, writable: true });
  var protoKeyAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: protoKeyPurposes74 };
  check("#74 an own __proto__ data entry on a constraint map is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: protoKeyAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A constraint map that is not a plain object -- a primitive, a Buffer, or an array -- carries no
  // purpose -> value restriction and is refused, not passed through as an unusable value that applies nothing.
  var primPurposesAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: "serverAuth" };
  check("#74 a primitive (string) constraint map is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: primPurposesAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  var bufDistrustAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", distrustAfter: Buffer.from([1, 2, 3]) };
  check("#74 a Buffer constraint map is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: bufDistrustAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  var arrPurposesAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: [false] };
  check("#74 an array constraint map is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: arrPurposesAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A parsed-certificate anchor with per-purpose constraints ATTACHED to it is refused: the certificate branch
  // carries no purposes / distrustAfter, so attaching them would silently drop the restriction and validate a
  // path the caller meant to forbid. Constraints belong on a { name, publicKey, algorithm, ... } tuple.
  var certForAttach74 = pki.schema.x509.parse(await mkCert({ subject: "AttachRoot", issuer: "AttachRoot", signWith: "ed25519", subjectKeys: "ed25519", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] }));
  certForAttach74.purposes = { serverAuth: false };
  check("#74 a parsed-certificate anchor with attached purposes is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: certForAttach74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  var certForAttachD74 = pki.schema.x509.parse(await mkCert({ subject: "AttachRootD", issuer: "AttachRootD", signWith: "ed25519", subjectKeys: "ed25519", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] }));
  certForAttachD74.distrustAfter = { serverAuth: new Date("2000-01-01T00:00:00Z") };
  check("#74 a parsed-certificate anchor with attached distrustAfter is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: certForAttachD74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // An INHERITED distrustAfter on a CERTIFICATE anchor (reached through the prototype, e.g. a polluted
  // Object.prototype) is refused: the cert branch's `in` check follows the chain, matching the tuple branch's
  // inherited-field refusal, rather than reading it by hasOwn (own-only) and letting the branch drop it.
  var certInheritCode74;
  Object.prototype.distrustAfter = { serverAuth: new Date("2000-01-01T00:00:00Z") };
  try { certInheritCode74 = await codeOf(run([direct], { time: T2027, trustAnchor: rootCert74, checkPurpose: "serverAuth" })); }
  finally { delete Object.prototype.distrustAfter; }
  check("#74 a certificate anchor with an inherited distrustAfter (polluted Object.prototype) is refused",
    certInheritCode74 === "path/bad-input");
  // An anchor that INHERITS from a Proxy is refused: the anchor object itself is not a Proxy (it passes the door
  // isProxy check), but its prototype is, and the inherited-field reads (the `in` tests and property accesses)
  // would run the Proxy's traps -- a `has` trap hiding purposes while a `get` trap still supplies name /
  // publicKey / algorithm drops the restriction. The prototype-chain walk refuses any Proxy in the chain.
  var hidingProtoAnchor74 = Object.create(new Proxy(
    { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112", purposes: { serverAuth: false } },
    { has: function (t, k) { return (k === "purposes" || k === "distrustAfter") ? false : (k in t); } }));
  check("#74 an anchor inheriting from a Proxy is refused with path/bad-input (Proxy in the prototype chain)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: hidingProtoAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // Direct cross-mutation regression: a name.rdns getter that would rewrite a WRONG object-form algorithm.oid to
  // the SPKI's real one is refused BEFORE it runs (name.rdns is an accessor, captured getter-free), so the
  // declared-algorithm mismatch refusal cannot be bypassed. Both nested fields are captured from own data
  // descriptors, so neither accessor can mutate the other -- no read order is relied on.
  var xmutAlg74 = { oid: "1.2.840.113549.1.1.1" };  // rsaEncryption -- wrong for the Ed25519 anchor key
  var xmutReads74 = 0;
  var xmutAnchor74 = {
    publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: xmutAlg74,
    name: { get rdns() { xmutReads74++; xmutAlg74.oid = "1.3.101.112"; return rootCert74.subject.rdns; } } };
  check("#74 a name.rdns getter cannot rewrite algorithm.oid: the accessor is refused before it runs (getter never invoked)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: xmutAnchor74 }))) === "path/bad-input" && xmutReads74 === 0 && xmutAlg74.oid === "1.2.840.113549.1.1.1");
  // A null-prototype object carrying an entry, used as the map's PARENT, is refused: the entry is inherited and
  // would be dropped, yet the parent is top-of-chain so a naive chain-depth test would pass it. The plain-object
  // test requires the top prototype to carry no enumerable own entries.
  var nullParentWithEntry74 = Object.create(Object.assign(Object.create(null), { serverAuth: new Date("2000-01-01T00:00:00Z") }));
  var nullParentDistrust74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", distrustAfter: nullParentWithEntry74 };
  check("#74 a constraint map whose null-prototype parent carries an entry is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: nullParentDistrust74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A map whose PROTOTYPE is a Proxy is refused before that Proxy's traps can run. The prototype here carries a
  // serverAuth restriction but its traps report a null prototype and no keys -- so a check that reflected on it
  // instead of refusing it up front would see a top-of-chain, entry-free prototype, accept the map, and drop the
  // inherited restriction. Only the map itself was checked for Proxy at capture; the prototype must be too.
  var hidingProto74 = new Proxy({ serverAuth: false },
    { getPrototypeOf: function () { return null; }, ownKeys: function () { return []; },
      getOwnPropertyDescriptor: function () { return undefined; } });
  var proxyProtoMap74 = Object.create(hidingProto74);
  var proxyProtoAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", purposes: proxyProtoMap74 };
  check("#74 a constraint map with a Proxy prototype is refused with path/bad-input (its traps never run)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: proxyProtoAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // publicKey is pinned to ONE read during tuple detection and used for the shape check and the snapshot: a
  // stateful getter that returns the key on its first read but would throw on a later read still validates,
  // because there is no later read. Re-reading it at the shape check or snapshot would leak the raw exception.
  var pkPinReads74 = 0;
  var pinnedPk74 = { name: rootCert74.subject, algorithm: "1.3.101.112",
    get publicKey() { pkPinReads74++; if (pkPinReads74 >= 2) throw new Error("pk-reread"); return rootCert74.subjectPublicKeyInfo.bytes; } };
  var pinnedPkResult74;
  try { pinnedPkResult74 = (await run([direct], { time: T2027, trustAnchor: pinnedPk74 })).valid === true ? "valid" : "invalid"; }
  catch (e) { pinnedPkResult74 = "threw:" + (e.code || e.name); }
  check("#74 the anchor publicKey is read once (pinned): a getter that would throw on a later read still validates, no raw leak",
    pinnedPkResult74 === "valid" && pkPinReads74 === 1);
  // Nested anchor accessors are read once under the typed-error guard: a throwing name.rdns getter is refused
  // with path/bad-input (not a raw throw), and a stateful algorithm.oid getter that answers the type probe
  // with a string but the value with a Symbol cannot leave algStr a Symbol and throw a raw TypeError.
  var throwRdns74 = { publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
    name: { get rdns() { throw new Error("rdns-boom"); } } };
  check("#74 a throwing name.rdns accessor is refused with path/bad-input, not a raw throw",
    (await codeOf(run([direct], { time: T2027, trustAnchor: throwRdns74 }))) === "path/bad-input");
  var algOidReads74 = 0;
  var statefulOid74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: { get oid() { algOidReads74++; return algOidReads74 === 1 ? "not-a-canonical-oid" : Symbol("oid"); } } };
  check("#74 an accessor algorithm.oid is refused with path/bad-input and its getter is never invoked (captured by descriptor)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: statefulOid74 }))) === "path/bad-input" && algOidReads74 === 0);
  // A symbol-keyed field is OUTSIDE the closed anchor set (whose members are all string-named) and is dropped:
  // the normalized anchor carries only the defined shape, never a caller's arbitrary symbol bookkeeping.
  var SYM74 = Symbol("storeTag");
  var symAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  symAnchor74[SYM74] = "symbol-metadata";
  var buildSym74 = await pki.path.build(direct, { time: T2027, trustAnchors: [symAnchor74] });
  check("#74 a symbol-keyed caller field is dropped: the normalized anchor carries only the closed string-named set",
    buildSym74.valid === true && buildSym74.trustAnchor[SYM74] === undefined);
  // An unknown string-keyed DATA field the caller stapled on is OUTSIDE the closed set and is dropped: the
  // normalized anchor has a defined shape, not an arbitrary passthrough. (The prior normalizer copied every
  // own data field, so it kept these -- this is the deliberate contract change.)
  var extraAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    algorithm: "1.3.101.112", customField: "operator-note", anotherOne: 42 };
  var buildExtra74 = await pki.path.build(direct, { time: T2027, trustAnchors: [extraAnchor74] });
  check("#74 an unknown string-keyed caller field is dropped from the normalized anchor (closed shape, not passthrough)",
    buildExtra74.valid === true && buildExtra74.trustAnchor.customField === undefined && buildExtra74.trustAnchor.anotherOne === undefined);
  // The closed set is read field-by-field, never enumerated, so an unrelated caller GETTER outside the set is
  // never evaluated: its side effect does not fire during normalization and the field does not appear on the
  // anchor.
  var unrelatedGetterRan74 = false;
  var getterAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  Object.defineProperty(getterAnchor74, "sideEffect", { enumerable: true, configurable: true, get: function () { unrelatedGetterRan74 = true; return "evaluated"; } });
  var buildGetter74 = await pki.path.build(direct, { time: T2027, trustAnchors: [getterAnchor74] });
  check("#74 an unrelated caller getter outside the closed set is never evaluated during normalization",
    buildGetter74.valid === true && unrelatedGetterRan74 === false && buildGetter74.trustAnchor.sideEffect === undefined);
  // An accessor name.rdns is refused: it is captured from its own data descriptor, so a stateful rdns getter
  // is never invoked (it cannot answer the shape check with one DN and hand name chaining another, and it cannot
  // mutate a sibling field such as algorithm.oid before that is captured). A plain { rdns, bytes } name is the
  // normal, unaffected form.
  var rdnsReads74 = 0;
  var flipNameAnchor74 = { publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
    name: { get rdns() { rdnsReads74++; return rdnsReads74 === 1 ? rootCert74.subject.rdns : []; } } };
  check("#74 an accessor name.rdns is refused with path/bad-input and its getter is never invoked (captured by descriptor)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: flipNameAnchor74 }))) === "path/bad-input" && rdnsReads74 === 0);
  // A tuple whose name.rdns is reached through the PROTOTYPE (Object.create) is refused too: name.rdns must be an
  // OWN data property, captured getter-free, so an inherited definition -- which could be a prototype accessor
  // running caller code -- cannot slip through. A plain own { rdns, bytes } name is the normal form.
  var inheritedRdnsAnchor74 = { publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
    name: Object.create({ rdns: rootCert74.subject.rdns }) };
  check("#74 a tuple whose name.rdns is inherited (Object.create) is refused with path/bad-input (own data property required)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: inheritedRdnsAnchor74 }))) === "path/bad-input");
  // An accessor algorithm.oid is refused before its getter runs, so a getter that would flip a denied purpose
  // in the snapshot maps never executes: the deny the anchor declared cannot be bypassed. (denyMap74 is left
  // unmutated because the getter is never invoked.)
  var denyMap74 = { serverAuth: false };
  var mutatingOidAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    purposes: denyMap74, algorithm: { get oid() { denyMap74.serverAuth = true; return "1.3.101.112"; } } };
  check("#74 an accessor algorithm.oid is refused before it can flip a denied purpose (getter never invoked)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: mutatingOidAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input" && denyMap74.serverAuth === false);
  // An accessor algorithm.oid is refused before its getter runs, so a getter that would overwrite the caller's
  // key Buffer never executes: the key is not zeroed and the anchor is refused for the accessor, not validated.
  var origSpki74 = Buffer.from(rootCert74.subjectPublicKeyInfo.bytes);
  var pkSwapAnchor74 = { name: rootCert74.subject, publicKey: origSpki74,
    algorithm: { get oid() { origSpki74.fill(0); return "1.3.101.112"; } } };
  check("#74 an accessor algorithm.oid is refused before its getter can overwrite the key Buffer (getter never invoked)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: pkSwapAnchor74 }))) === "path/bad-input" && origSpki74.some(function (b) { return b !== 0; }));
  // Same, for a name getter that runs during tuple discrimination: publicKey is read FIRST and pinned before
  // the name accessor is invoked, so a name getter overwriting the key Buffer cannot swap the bound key.
  var origSpki2_74 = Buffer.from(rootCert74.subjectPublicKeyInfo.bytes);
  var nameSwapAnchor74 = { publicKey: origSpki2_74, algorithm: "1.3.101.112",
    get name() { origSpki2_74.fill(0); return rootCert74.subject; } };
  check("#74 the anchor publicKey is pinned before the name accessor runs: a name getter overwriting the key Buffer cannot change the bound key",
    (await run([direct], { time: T2027, trustAnchor: nameSwapAnchor74 })).valid === true);
  // The optional identity metadata (subjectDer / label / mozillaCaPolicy) is captured from its own DATA
  // descriptor, so an accessor identity field is NEVER invoked: a subjectDer getter that overwrites the
  // caller's key Buffer cannot run before the key is pinned and swap the bound key. The anchor binds the
  // original key (the accessor subjectDer is dropped, being non-validation metadata).
  var origKeyId74 = Buffer.from(rootCert74.subjectPublicKeyInfo.bytes);
  var idGetterRan74 = false;
  var idAccessorAnchor74 = { name: rootCert74.subject, publicKey: origKeyId74, algorithm: "1.3.101.112",
    get subjectDer() { idGetterRan74 = true; origKeyId74.fill(0); return Buffer.alloc(4); } };
  var idAccessorOk74;
  try { idAccessorOk74 = (await run([direct], { time: T2027, trustAnchor: idAccessorAnchor74 })).valid === true; }
  catch (_e3) { idAccessorOk74 = false; }
  check("#74 an accessor identity field is captured by descriptor, not invoked: its getter cannot overwrite the pinned key",
    idAccessorOk74 === true && idGetterRan74 === false);
  // A TOP-LEVEL algorithm accessor (not the nested .oid) runs after publicKey; its getter must not mutate a
  // constraint map before it is snapshot. purposes/distrustAfter are snapshot in the discriminator BEFORE the
  // algorithm accessor is read, so a get algorithm() that flips a denied purpose does not reach validation.
  var denyMap2_74 = { serverAuth: false };
  var topAlgMutateAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes,
    purposes: denyMap2_74, get algorithm() { denyMap2_74.serverAuth = true; return "1.3.101.112"; } };
  var rTopAlg74 = await run([direct], { time: T2027, trustAnchor: topAlgMutateAnchor74, checkPurpose: "serverAuth" });
  check("#74 a top-level algorithm getter cannot mutate the snapshot purposes map to bypass a denied purpose",
    rTopAlg74.valid === false && failCodes(rTopAlg74).indexOf("path/purpose-not-trusted") !== -1);
  // The discriminator getters (publicKey / name) also run before the constraint maps would be captured unless
  // the snapshot precedes them. purposes/distrustAfter are snapshot BEFORE any discriminator field is read, so
  // a name getter that flips a denied purpose to allowed and returns the valid name cannot reach the captured
  // map: the deny the anchor declared stays enforced.
  var denyMap3_74 = { serverAuth: false };
  var nameMutatesPurposes74 = { publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
    purposes: denyMap3_74, get name() { denyMap3_74.serverAuth = true; return rootCert74.subject; } };
  var rNameMut74 = await run([direct], { time: T2027, trustAnchor: nameMutatesPurposes74, checkPurpose: "serverAuth" });
  check("#74 a name getter cannot mutate the snapshot purposes map to bypass a denied purpose (snapshot precedes the discriminator reads)",
    rNameMut74.valid === false && failCodes(rNameMut74).indexOf("path/purpose-not-trusted") !== -1);
  // A constraint map is captured from its own DATA descriptor, never by property access, so an accessor-backed
  // map -- a `get purposes()` whose getter could mutate the sibling distrustAfter map when read -- is REFUSED
  // with path/bad-input and its getter is never invoked.
  var accessorPurposes74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
    get purposes() { return { serverAuth: true }; } };
  check("#74 an accessor-backed purposes map is refused with path/bad-input (captured by descriptor, getter not invoked)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: accessorPurposes74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // An accessor-backed constraint-map ENTRY (a `get serverAuth()`) is refused too: entries are read from their
  // data descriptors, so an entry getter is never invoked.
  var accessorEntry74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112",
    purposes: Object.defineProperty({}, "serverAuth", { get: function () { return true; }, enumerable: true, configurable: true }) };
  check("#74 an accessor-backed constraint-map entry is refused with path/bad-input",
    (await codeOf(run([direct], { time: T2027, trustAnchor: accessorEntry74, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A CERTIFICATE anchor must not carry per-purpose constraints: the certificate branch produces no purposes /
  // distrustAfter, so attaching them to a parsed certificate would silently drop the restriction. Such a cert is
  // REFUSED -- by own-property EXISTENCE (hasOwn), which never invokes the property, so even a throwing purposes
  // getter is refused without being read. Constraints belong on a { name, publicKey, algorithm, ... } tuple.
  var certPurposesGetterInvoked74 = false;
  Object.defineProperty(rootCert74, "purposes", { get: function () { certPurposesGetterInvoked74 = true; throw new Error("cert-purposes-boom"); }, configurable: true });
  var certAttachCode74;
  try { certAttachCode74 = await codeOf(run([direct], { time: T2027, trustAnchor: rootCert74 })); }
  finally { delete rootCert74.purposes; }
  check("#74 a certificate anchor carrying purposes is refused by existence, without invoking its getter",
    certAttachCode74 === "path/bad-input" && certPurposesGetterInvoked74 === false);
  // A tuple carrying an own `__proto__` field (a JSON.parse product) must not repoint the normalized
  // anchor's prototype: copying with a plain `flat[name] =` would invoke Object.prototype's __proto__
  // setter and let an attacker inject inherited purposes (here a serverAuth:false restriction) that
  // validation consumes. With the own-data-property copy the injection is inert and the path validates.
  var protoAnchor = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  Object.defineProperty(protoAnchor, "__proto__", { value: { purposes: { serverAuth: false } }, enumerable: true, configurable: true, writable: true });
  var rProto = await run([direct], { time: T2027, trustAnchor: protoAnchor, checkPurpose: "serverAuth" });
  check("#74 an own __proto__ field cannot repoint the normalized anchor's prototype (no injected purpose restriction)",
    rProto.valid === true);
  // Cloning the NORMALIZED anchor must not repoint the clone's prototype either: the __proto__ field is
  // copied non-enumerable, so an Object.assign / spread / JSON clone skips it and cannot invoke the clone's
  // __proto__ setter to inherit the attacker's purposes restriction.
  var normProto = pki.path.anchorFromCert(protoAnchor);
  var clonedProto = Object.assign({}, normProto);
  var rClonedProto = await run([direct], { time: T2027, trustAnchor: clonedProto, checkPurpose: "serverAuth" });
  check("#74 cloning a normalized anchor that carried a __proto__ field does not repoint the clone's prototype",
    rClonedProto.valid === true);
  // An anchor whose fields are reached through its prototype (Object.create(baseAnchor)) must keep them: the
  // normalization reads each field by property access, which follows the prototype chain, so name and
  // purpose/distrustAfter restrictions are preserved rather than dropped (which would reject a valid anchor,
  // or silently weaken its trust restrictions).
  var baseAnchor74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  var inheritedAnchor74 = Object.create(baseAnchor74);
  check("#74 an anchor whose name/fields are inherited (Object.create) keeps them and validates",
    (await run([direct], { time: T2027, trustAnchor: inheritedAnchor74 })).valid === true);
  // An inherited constraint map (purposes / distrustAfter reached through the prototype, not an own property)
  // is REFUSED with path/bad-input, not enforced: a constraint map must be an own data property so it is
  // captured from its descriptor without invoking a getter (a `get purposes()` could mutate the sibling map).
  // Refusing -- rather than silently dropping an inherited map -- means a restriction is never lost to a
  // fail-open.
  var baseRestricted74 = { name: rootCert74.subject, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112", purposes: { serverAuth: false } };
  check("#74 an inherited anchor constraint map is refused with path/bad-input (must be an own data property)",
    (await codeOf(run([direct], { time: T2027, trustAnchor: Object.create(baseRestricted74), checkPurpose: "serverAuth" }))) === "path/bad-input");
  // A parsed CERTIFICATE is recognized by its PROVENANCE (guard.parsed.isRecorded, a getter-free WeakMap
  // lookup) BEFORE the tuple discriminator, which reads name/publicKey/algorithm by property access. So a
  // polluted Object.prototype supplying those three cannot reclassify a real certificate as a tuple and bind
  // the INHERITED (attacker) key: the cert routes to coerceCert and binds its OWN key. Object.prototype is
  // polluted, then restored in a finally so the pollution cannot leak to another test.
  var attackerRoot74 = pki.schema.x509.parse(await mkCert({ subject: "Attacker", issuer: "Attacker", signWith: "ed25519leaf", subjectKeys: "ed25519leaf" }));
  var pollutedOk74;
  try {
    Object.prototype.name = attackerRoot74.subject;
    Object.prototype.publicKey = attackerRoot74.subjectPublicKeyInfo.bytes;
    Object.prototype.algorithm = attackerRoot74.subjectPublicKeyInfo.algorithm.oid;
    var polAnchor74 = pki.path.anchorFromCert(rootCert74);
    pollutedOk74 = Buffer.isBuffer(polAnchor74.publicKey) &&
      polAnchor74.publicKey.equals(rootCert74.subjectPublicKeyInfo.bytes) &&
      !polAnchor74.publicKey.equals(attackerRoot74.subjectPublicKeyInfo.bytes);
  } finally {
    delete Object.prototype.name; delete Object.prototype.publicKey; delete Object.prototype.algorithm;
  }
  check("#74 a certificate is recognized before inherited tuple fields: a polluted Object.prototype cannot bind the attacker key",
    pollutedOk74 === true);
  // Certificate recognition is a getter-free provenance lookup, so publicKey is the FIRST property read on a
  // tuple: no certificate-structural probe (which would read tbsBytes / subject / ...) runs a tuple-controlled
  // getter before the key is pinned. A polluted Object.prototype.tbsBytes getter that zeros the caller's key
  // Buffer therefore cannot reach the key before it is captured -- the anchor binds the ORIGINAL key bytes.
  var origKey74 = Buffer.from(rootCert74.subjectPublicKeyInfo.bytes);
  var tbsPinOk74;
  try {
    Object.defineProperty(Object.prototype, "tbsBytes", { get: function () { origKey74.fill(0); return Buffer.alloc(4); }, configurable: true });
    var r3anchor74 = null;
    try { r3anchor74 = pki.path.anchorFromCert({ name: rootCert74.subject, publicKey: origKey74, algorithm: "1.3.101.112" }); } catch (_e) { r3anchor74 = null; }
    tbsPinOk74 = !!r3anchor74 && Buffer.isBuffer(r3anchor74.publicKey) && r3anchor74.publicKey.equals(rootCert74.subjectPublicKeyInfo.bytes);
  } finally {
    delete Object.prototype.tbsBytes;
  }
  check("#74 the anchor publicKey is pinned before any certificate-recognition read: a polluted tbsBytes getter cannot zero the bound key",
    tbsPinOk74 === true);
  // The anchor name.rdns is DEEP-copied: mutating a caller's nested RDN attribute after normalization (a
  // read-after-await hazard while an async validate awaits signature verification) must not change the
  // normalized anchor's issuer DN. A shallow arraySlice would share the nested attribute record.
  var deepName74 = { rdns: [ [ { type: "2.5.4.3", value: "DeepCN" } ] ], bytes: rootCert74.subject.bytes };
  var deepTuple74 = { name: deepName74, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  var deepAnchor74 = pki.path.anchorFromCert(deepTuple74);
  deepName74.rdns[0][0].value = "TamperedCN";
  check("#74 the anchor name.rdns is deep-copied: mutating a caller's nested RDN does not change the normalized anchor DN",
    deepAnchor74.name.rdns[0][0].value === "DeepCN");
  // A tuple whose name.rdns attribute value is reached through the PROTOTYPE (or an accessor) is preserved: the
  // anchor API accepts an inherited name.rdns, so the deep copy must snapshot the consumed type/value via
  // property access rather than drop an attribute reached through the chain (which would leave an incomplete DN
  // and fail name chaining).
  var inhName74 = { rdns: [ [ Object.create({ type: "2.5.4.3", value: "InheritedCN" }) ] ], bytes: rootCert74.subject.bytes };
  var inhTuple74 = { name: inhName74, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" };
  var inhAnchor74 = pki.path.anchorFromCert(inhTuple74);
  check("#74 an inherited (or accessor) DN attribute value is preserved in the deep copy, not dropped",
    inhAnchor74.name.rdns[0][0].value === "InheritedCN" && inhAnchor74.name.rdns[0][0].type === "2.5.4.3");
  // A SPARSE anchor rdns must stay sparse: the deep copy copies only OWN indexed elements, so a hole is not
  // filled from a polluted Array.prototype[i] slot (a slice reads inherited indices). Otherwise a name reached
  // through prototype pollution would fill the hole guard.name.dnEqual rejects and pass chaining. Array.prototype
  // is polluted, then restored in a finally so it cannot leak to another test.
  var sparseRdns74 = []; sparseRdns74.length = 1;   // one hole at index 0
  var sparseHolePreserved74;
  try {
    Array.prototype[0] = [ { type: "2.5.4.3", value: "PollutedCN" } ];
    var sparseAnchor74 = pki.path.anchorFromCert({ name: { rdns: sparseRdns74 }, publicKey: rootCert74.subjectPublicKeyInfo.bytes, algorithm: "1.3.101.112" });
    sparseHolePreserved74 = !Object.prototype.hasOwnProperty.call(sparseAnchor74.name.rdns, 0);
  } finally {
    delete Array.prototype[0];
  }
  check("#74 a sparse anchor rdns is copied hole-preserving: a polluted Array.prototype slot does not fill the hole",
    sparseHolePreserved74 === true);

  // ECDSA-P256 chain (exercises the DER->P1363 verify-bridge shim).
  var anchorEc = await mkAnchor("p256", "EcRoot");
  var leafEc = await mkCert({ subject: "EcLeaf", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf" });
  var resEc = await run([leafEc], { time: T2027, trustAnchor: anchorEc });
  check("ECDSA-P256-signed chain validates (DER->P1363 shim)", resEc.valid === true);

  // ML-DSA-65 chain (one-shot PQC verify path).
  var anchorPq = await mkAnchor("mldsa65", "PqRoot");
  var leafPq = await mkCert({ subject: "PqLeaf", issuer: "PqRoot", signWith: "mldsa65", subjectKeys: "ed25519leaf" });
  var resPq = await run([leafPq], { time: T2027, trustAnchor: anchorPq });
  check("ML-DSA-65-signed chain validates", resPq.valid === true);

  // SLH-DSA-SHA2-128F chain (FIPS 205 one-shot PQC verify path — the twelve
  // SIG_ALGS rows plug into the same builtinVerify the ML-DSA rows use).
  var anchorSlh = await mkAnchor("slhdsa", "SlhRoot");
  var leafSlh = await mkCert({ subject: "SlhLeaf", issuer: "SlhRoot", signWith: "slhdsa", subjectKeys: "ed25519leaf" });
  var resSlh = await run([leafSlh], { time: T2027, trustAnchor: anchorSlh });
  check("SLH-DSA-SHA2-128F-signed chain validates", resSlh.valid === true);

  // RSA chain.
  var anchorRsa = await mkAnchor("rsa", "RsaRoot");
  var leafRsa = await mkCert({ subject: "RsaLeaf", issuer: "RsaRoot", signWith: "rsa", subjectKeys: "ed25519leaf" });
  var resRsa = await run([leafRsa], { time: T2027, trustAnchor: anchorRsa });
  check("RSA-signed chain validates", resRsa.valid === true);
}

async function testSelfIssuedAndConstraints() {
  var anchor = await mkAnchor("ed25519", "Root");

  // a self-issued intermediate (same subject as issuer, key rollover)
  // does NOT consume max_path_length. Chain: Inter(pathLen:0) ->
  // Inter-rollover (self-issued) -> Leaf. A naive counting impl fails.
  var inter = await mkCert({ subject: "Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true, 0), kuExt([KU_KEY_CERT_SIGN])] });
  var rollover = await mkCert({ subject: "Inter", issuer: "Inter", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: [bcExt(true, 0), kuExt([KU_KEY_CERT_SIGN])] });
  var leaf = await mkCert({ subject: "Leaf5", issuer: "Inter", signWith: "ed25519j", subjectKeys: "ed25519leaf" });
  var res = await run([inter, rollover, leaf], { time: T2027, trustAnchor: anchor });
  check("self-issued intermediate not counted against pathLen", res.valid === true);

  // nameConstraints permitted: leaf SAN within the permitted dNSName tree.
  var interNc = await mkCert({ subject: "NcInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt([gnDns("example.com")], null)] });
  var leafNc = await mkCert({ subject: "NcLeaf", issuer: "NcInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("www.example.com")])] });
  var resNc = await run([interNc, leafNc], { time: T2027, trustAnchor: anchor });
  check("SAN within permitted subtree validates", resNc.valid === true);

  // explicit policy satisfied end-to-end.
  var P1 = "1.3.6.1.4.1.99999.1";
  var interP = await mkCert({ subject: "PInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), cpExt([P1])] });
  var leafP = await mkCert({ subject: "PLeaf", issuer: "PInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1])] });
  var resP = await run([interP, leafP], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("explicit policy satisfied validates", resP.valid === true);
  check("policy tree survives", resP.validPolicyTree !== null && resP.validPolicyTree !== undefined);
}

// ---------------------------------------------------------------------------
// REJECT vectors (V8-V18)
// ---------------------------------------------------------------------------

async function testCoreRejections() {
  var anchor = await mkAnchor("ed25519", "Root");

  // tampered tbs -> bad signature.
  var tampered = await mkCert({
    subject: "Tamper", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    mutateSig: function (sig) { var s = Buffer.from(sig); s[8] ^= 0xff; return s; },
  });
  var res8 = await run([tampered], { time: T2027, trustAnchor: anchor });
  check("bad signature rejected", res8.valid === false && failCodes(res8).indexOf("path/bad-signature") !== -1);

  // expired / not-yet-valid.
  var expired = await mkCert({ subject: "Old", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z") });
  var res9a = await run([expired], { time: T2027, trustAnchor: anchor });
  check("expired leaf rejected", res9a.valid === false && failCodes(res9a).indexOf("path/expired") !== -1);
  var future = await mkCert({ subject: "Future", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", notBefore: new Date("2029-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z") });
  var res9b = await run([future], { time: T2027, trustAnchor: anchor });
  check("not-yet-valid leaf rejected", res9b.valid === false && failCodes(res9b).indexOf("path/not-yet-valid") !== -1);

  // The same expired leaf, checked at a `time` that holds 2027 and reports 2020. `opts.time`
  // is validated at entry through the intrinsic, so the held instant is what was accepted;
  // comparing the Date object against the certificate's would have coerced it through
  // `Symbol.toPrimitive`, asking the caller a second time and getting a different answer. A
  // caller who wanted an expired certificate to pass needed only that one method.
  var ReportsAnEarlierMoment = class extends Date {
    [Symbol.toPrimitive](hint) {
      if (hint === "number" || hint === "default") return Date.parse("2020-06-01T00:00:00Z");
      return Date.prototype.toString.call(this);
    }
  };
  var twoFaced = new ReportsAnEarlierMoment(T2027.toISOString());
  check("the fixture holds 2027 and reports 2020",
    Date.prototype.getTime.call(twoFaced) === T2027.getTime() && Number(twoFaced) === Date.parse("2020-06-01T00:00:00Z"));
  var res9c = await run([expired], { time: twoFaced, trustAnchor: anchor });
  check("a Date that reports an earlier moment than it holds cannot revive an expired leaf",
    res9c.valid === false && failCodes(res9c).indexOf("path/expired") !== -1);

  // name-chaining break.
  var inter = await mkCert({ subject: "Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var orphan = await mkCert({ subject: "Orphan", issuer: "SomebodyElse", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res10 = await run([inter, orphan], { time: T2027, trustAnchor: anchor });
  check("issuer/subject chaining break rejected", res10.valid === false && failCodes(res10).indexOf("path/name-chaining") !== -1);

  // basicConstraints bypass: non-CA used as issuer (CVE-2021-3450 class).
  var notCa = await mkCert({ subject: "NotCa", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(false)] });
  var below = await mkCert({ subject: "Below", issuer: "NotCa", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res11a = await run([notCa, below], { time: T2027, trustAnchor: anchor });
  check("cA:FALSE intermediate rejected", res11a.valid === false && failCodes(res11a).indexOf("path/not-a-ca") !== -1);
  var noBc = await mkCert({ subject: "NoBc", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i" });
  var below2 = await mkCert({ subject: "Below2", issuer: "NoBc", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res11b = await run([noBc, below2], { time: T2027, trustAnchor: anchor });
  check("basicConstraints-absent intermediate rejected", res11b.valid === false && failCodes(res11b).indexOf("path/not-a-ca") !== -1);

  // pathLenConstraint:0 with a further non-self-issued CA below.
  var top = await mkCert({ subject: "Top", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true, 0), kuExt([KU_KEY_CERT_SIGN])] });
  var mid = await mkCert({ subject: "Mid", issuer: "Top", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leaf12 = await mkCert({ subject: "Leaf12", issuer: "Mid", signWith: "ed25519j", subjectKeys: "ed25519leaf" });
  var res12 = await run([top, mid, leaf12], { time: T2027, trustAnchor: anchor });
  check("pathLenConstraint exceeded rejected", res12.valid === false && failCodes(res12).indexOf("path/path-length-exceeded") !== -1);

  // keyUsage present WITHOUT keyCertSign on an intermediate.
  var noKcs = await mkCert({ subject: "NoKcs", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_DIGITAL_SIGNATURE])] });
  var below13 = await mkCert({ subject: "Below13", issuer: "NoKcs", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res13 = await run([noKcs, below13], { time: T2027, trustAnchor: anchor });
  check("keyUsage without keyCertSign rejected", res13.valid === false && failCodes(res13).indexOf("path/missing-key-cert-sign") !== -1);

  // name-constraint excluded + not-permitted.
  var interEx = await mkCert({ subject: "ExInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnDns("evil.example.com")])] });
  var leafEx = await mkCert({ subject: "ExLeaf", issuer: "ExInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.evil.example.com")])] });
  var res16a = await run([interEx, leafEx], { time: T2027, trustAnchor: anchor });
  check("excluded SAN rejected", res16a.valid === false && failCodes(res16a).indexOf("path/name-constraint-excluded") !== -1);
  var interPm = await mkCert({ subject: "PmInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt([gnDns("example.com")], null)] });
  var leafPm = await mkCert({ subject: "PmLeaf", issuer: "PmInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("other.org")])] });
  var res16b = await run([interPm, leafPm], { time: T2027, trustAnchor: anchor });
  check("not-permitted SAN rejected", res16b.valid === false && failCodes(res16b).indexOf("path/name-constraint-not-permitted") !== -1);

  // directoryName is the MUST-support constraint form (§4.2.1.10):
  // an excluded directoryName subtree matching the leaf's subject DN rejects.
  var interDir = await mkCert({ subject: "DirInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnDirectoryName(nameDer("Victim"))])] });
  var leafDir = await mkCert({ subject: "Victim", issuer: "DirInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res16c = await run([interDir, leafDir], { time: T2027, trustAnchor: anchor });
  check("excluded directoryName matching the subject DN rejected", res16c.valid === false && failCodes(res16c).indexOf("path/name-constraint-excluded") !== -1);

  // a uniformResourceIdentifier constraint applies to the URI's host;
  // a leading-dot domain constraint matches a subdomain host (RFC 5280 §4.2.1.10).
  var interUri = await mkCert({ subject: "UriInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnUri(".evil.example")])] });
  var leafUri = await mkCert({ subject: "UriLeaf", issuer: "UriInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://host.evil.example/callback")])] });
  var res16d = await run([interUri, leafUri], { time: T2027, trustAnchor: anchor });
  check("excluded URI subdomain host rejected", res16d.valid === false && failCodes(res16d).indexOf("path/name-constraint-excluded") !== -1);
  // ...and a bare-host URI constraint matches that host EXACTLY, not a subdomain.
  var interUriHost = await mkCert({ subject: "UriHostInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnUri("evil.example")])] });
  var leafUriSub = await mkCert({ subject: "UriSubLeaf", issuer: "UriHostInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://host.evil.example/x")])] });
  var res16dSub = await run([interUriHost, leafUriSub], { time: T2027, trustAnchor: anchor });
  check("bare-host URI constraint does NOT match a subdomain", res16dSub.valid === true);

  // emailAddress in the SUBJECT DN checked as an rfc822Name constraint (§I9).
  var interEm = await mkCert({ subject: "EmInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnEmail("banned.example")])] });
  var emailRdn = [b.set([atv("2.5.4.3", "EmLeaf")]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5("user@banned.example")])])];
  var leafEm = await mkCert({ subject: emailRdn, issuer: "EmInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res17 = await run([interEm, leafEm], { time: T2027, trustAnchor: anchor });
  check("email-in-DN checked as rfc822Name constraint", res17.valid === false && failCodes(res17).indexOf("path/name-constraint-excluded") !== -1);

  // unrecognized critical extension fails; same OID non-critical passes.
  var unkCrit = await mkCert({ subject: "UnkC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("1.3.6.1.4.1.99999.99", true, b.octetString(Buffer.from([1])))] });
  var res18a = await run([unkCrit], { time: T2027, trustAnchor: anchor });
  check("unrecognized critical extension rejected", res18a.valid === false && failCodes(res18a).indexOf("path/unrecognized-critical-extension") !== -1);
  // The criticality flag is what that check reads, and a parsed certificate may be
  // passed in place of its bytes. An extension entry with no `critical` property at
  // all is not "non-critical" -- `if (!ext.critical) continue` skips it, so the same
  // certificate that was just rejected would validate. The door refuses the object
  // instead, because an entry the parser produced always carries the flag.
  var unkCritParsed = pki.schema.x509.parse(unkCrit);
  var unkCritNoFlag = Object.assign({}, unkCritParsed, {
    extensions: unkCritParsed.extensions.map(function (e) {
      var copy = Object.assign({}, e);
      if (copy.oid === "1.3.6.1.4.1.99999.99") delete copy.critical;
      return copy;
    }),
  });
  check("an extension entry stripped of its criticality flag is refused at the door",
    (await codeOf(run([unkCritNoFlag], { time: T2027, trustAnchor: anchor }))) === "path/bad-input");

  var unkNon = await mkCert({ subject: "UnkN", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("1.3.6.1.4.1.99999.99", false, b.octetString(Buffer.from([1])))] });
  var res18b = await run([unkNon], { time: T2027, trustAnchor: anchor });
  check("same OID non-critical accepted", res18b.valid === true);
  // A CRITICAL qcStatements is REJECTED: it asserts qualified-certificate semantics (reliance limit,
  // certificate purpose) this validator does not enforce, so it is an unprocessed critical extension.
  var qcCrit = await mkCert({ subject: "QcC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("1.3.6.1.5.5.7.1.3", true, b.sequence([b.sequence([b.oid("0.4.0.1862.1.1")])]))] });
  var res18c = await run([qcCrit], { time: T2027, trustAnchor: anchor });
  check("critical qcStatements rejected (semantics not enforced)", res18c.valid === false && failCodes(res18c).indexOf("path/unrecognized-critical-extension") !== -1);
  // A NON-critical qcStatements is informational and does not affect the verdict.
  var qcNon = await mkCert({ subject: "QcN", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("1.3.6.1.5.5.7.1.3", false, b.sequence([b.sequence([b.oid("0.4.0.1862.1.1")])]))] });
  var res18d = await run([qcNon], { time: T2027, trustAnchor: anchor });
  check("non-critical qcStatements accepted (informational)", res18d.valid === true);

  // The exported processed-extension set is FROZEN: a caller must not be able to add an OID and make
  // an attacker's critical, decoder-less extension pass the unrecognized-critical check.
  check("PROCESSED_EXTENSIONS is frozen", Object.isFrozen(pki.path.PROCESSED_EXTENSIONS));
  check("TARGET_UNPROCESSED_IF_CRITICAL is frozen", Object.isFrozen(pki.path.TARGET_UNPROCESSED_IF_CRITICAL));
  var injOid = "1.2.3.4.5.6.7.8.9";
  try { pki.path.PROCESSED_EXTENSIONS[injOid] = true; } catch (_e) { /* strict-mode throw on a frozen write is acceptable */ }
  check("a write to PROCESSED_EXTENSIONS does not take effect", pki.path.PROCESSED_EXTENSIONS[injOid] !== true);
  var injCrit = await mkCert({ subject: "Inj", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext(injOid, true, b.nullValue())] });
  var res18e = await run([injCrit], { time: T2027, trustAnchor: anchor });
  check("a critical extension whose OID a caller tried to inject is still rejected", res18e.valid === false && failCodes(res18e).indexOf("path/unrecognized-critical-extension") !== -1);

  // Freezing the table stops a WRITE to it; it does not stop an inherited lookup. The membership
  // test must ask the table for its OWN property, or a name planted on Object.prototype answers for
  // every OID the table does not carry and the unrecognized-critical gate reports the extension
  // processed.
  var protoOid = "1.2.3.4.5.6.7.8.10";
  var protoCrit = await mkCert({ subject: "Proto", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext(protoOid, true, b.nullValue())] });
  // The options bag has a null prototype so the unknown-option door does not see the planted name
  // and refuse the call first; this vector is aimed at the extension table, not at that door.
  var protoOpts = Object.create(null);
  protoOpts.time = T2027;
  protoOpts.trustAnchor = anchor;
  var res18f;
  Object.prototype[protoOid] = true;  try { res18f = await run([protoCrit], protoOpts); }
  finally { delete Object.prototype[protoOid]; }
  check("a critical extension whose OID was planted on Object.prototype is still rejected",
    res18f.valid === false && failCodes(res18f).indexOf("path/unrecognized-critical-extension") !== -1);

  // The same planted name, on a CA certificate rather than the target. Only one of the two tables is
  // consulted for a non-target, so a vector aimed at the target alone does not answer for this
  // position: there, the second lookup happens to trip on the same planted name and mask the first.
  var protoInter = await mkCert({ subject: "ProtoInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ext(protoOid, true, b.nullValue())] });
  var protoLeaf = await mkCert({ subject: "ProtoLeaf", issuer: "ProtoInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var protoOpts2 = Object.create(null);
  protoOpts2.time = T2027;
  protoOpts2.trustAnchor = anchor;
  var res18g;
  Object.prototype[protoOid] = true;  try { res18g = await run([protoInter, protoLeaf], protoOpts2); }
  finally { delete Object.prototype[protoOid]; }
  check("a planted OID does not make a CA certificate's critical extension processed",
    res18g.valid === false && failCodes(res18g).indexOf("path/unrecognized-critical-extension") !== -1);
}

// ---------------------------------------------------------------------------
// Policy machinery (V19-V23, V35-V39) — the §6.1 counters and tree rules
// ---------------------------------------------------------------------------

var P1 = "1.3.6.1.4.1.99999.1", P2 = "1.3.6.1.4.1.99999.2", P3 = "1.3.6.1.4.1.99999.3";

// A standard CA extension pair for policy-chain intermediates.
function caExts(extra) { return [bcExt(true), kuExt([KU_KEY_CERT_SIGN])].concat(extra || []); }

async function testPolicyMachinery() {
  var anchor = await mkAnchor("ed25519", "Root");

  // explicit policy demanded, tree pruned to NULL by disjoint sets.
  var interA = await mkCert({ subject: "PA", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1])]) });
  var leafB = await mkCert({ subject: "PB", issuer: "PA", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2])] });
  var res19 = await run([interA, leafB], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("disjoint policies under explicit-policy rejected", res19.valid === false && failCodes(res19).indexOf("path/policy-required") !== -1);

  // mapping to/from anyPolicy is prohibited (§6.1.4(a)).
  var interMapAny = await mkCert({ subject: "MapAny", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1]), pmExt([[P1, ANY_POLICY]])]) });
  var leafAny = await mkCert({ subject: "LeafAny", issuer: "MapAny", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1])] });
  var res20 = await run([interMapAny, leafAny], { time: T2027, trustAnchor: anchor });
  check("policyMappings naming anyPolicy rejected", res20.valid === false && failCodes(res20).indexOf("path/bad-policy") !== -1);

  // policy-tree node cap fail-closed (CVE-2023-0464 class): a tiny
  // maxPolicyNodes with a policy-rich chain terminates typed, never hangs.
  var interRich = await mkCert({ subject: "Rich", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY])]) });
  var leafRich = await mkCert({ subject: "RichLeaf", issuer: "Rich", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1, P2, P3])] });
  var res21 = await run([interRich, leafRich], { time: T2027, trustAnchor: anchor, maxPolicyNodes: 2 });
  check("policy-tree cap fail-closed", res21.valid === false && failCodes(res21).indexOf("path/policy-tree-cap") !== -1);

  // a malformed policy OID is rejected, never silently dropped
  // (CVE-2023-0465 class). 0x80 is an invalid first OID content byte.
  var badPolicyVal = b.sequence([b.sequence([b.raw(Buffer.from([0x06, 0x01, 0x80]))])]);
  var leafBadP = await mkCert({ subject: "BadP", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.32", false, badPolicyVal)] });
  var res22 = await run([leafBadP], { time: T2027, trustAnchor: anchor });
  check("malformed policy OID rejected not dropped", res22.valid === false && failCodes(res22).indexOf("path/bad-policy") !== -1);

  // the §6.1.2(d) n+1 (not n) counter init, both directions: a
  // no-policy 2-cert chain PASSES with initial-explicit-policy FALSE
  // (an n-init implementation hits 0 at wrap-up and fails), and the same
  // chain FAILS with initial-explicit-policy TRUE (init 0, tree NULL).
  var inter23 = await mkCert({ subject: "C23", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts() });
  var leaf23 = await mkCert({ subject: "L23", issuer: "C23", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res23a = await run([inter23, leaf23], { time: T2027, trustAnchor: anchor });
  check("no-policy chain passes with explicit-policy unset (n+1 init)", res23a.valid === true);
  var res23b = await run([inter23, leaf23], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("no-policy chain fails with explicit-policy set", res23b.valid === false && failCodes(res23b).indexOf("path/policy-required") !== -1);

  // anyPolicy suppression at inhibit_anyPolicy == 0 (§6.1.3(d)(2), §I5).
  var interIap = await mkCert({ subject: "Iap", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY]), iapExt(0)]) });
  var interAny = await mkCert({ subject: "Any", issuer: "Iap", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([ANY_POLICY])]) });
  var leaf35 = await mkCert({ subject: "L35", issuer: "Any", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P1])] });
  var res35 = await run([interIap, interAny, leaf35], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("anyPolicy suppressed once inhibit_anyPolicy hits 0", res35.valid === false && failCodes(res35).indexOf("path/policy-required") !== -1);
  var interNoIap = await mkCert({ subject: "Iap", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY])]) });
  var res35b = await run([interNoIap, interAny, leaf35], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("control: same chain without inhibitAnyPolicy validates", res35b.valid === true);

  // a LEAF requireExplicitPolicy == 0 forces explicit_policy = 0 at
  // wrap-up (§6.1.5(b), §I6): with a NULL tree the chain fails where an
  // implementation skipping §6.1.5(b) would pass.
  var inter36 = await mkCert({ subject: "C36", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts() });
  var leaf36 = await mkCert({ subject: "L36", issuer: "C36", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [pcExt({ requireExplicitPolicy: 0 })] });
  var res36 = await run([inter36, leaf36], { time: T2027, trustAnchor: anchor });
  check("leaf requireExplicitPolicy=0 flips the wrap-up verdict", res36.valid === false && failCodes(res36).indexOf("path/policy-required") !== -1);

  // a mapping carried on the SAME cert as an inhibitPolicyMapping:0
  // still applies (§6.1.4 order: (b) mapping before (i)(2) clamp)...
  var interMapSelf = await mkCert({ subject: "MapSelf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1]), pmExt([[P1, P2]]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var leaf38 = await mkCert({ subject: "L38", issuer: "MapSelf", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2])] });
  var res38 = await run([interMapSelf, leaf38], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("same-cert mapping applies before the inhibit clamp", res38.valid === true);

  // ...but a mapping arriving AFTER the counter reached 0 DELETES the
  // mapped nodes instead of remapping (§6.1.4(b) zero arm).
  var interClamp = await mkCert({ subject: "Clamp", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var interMapLate = await mkCert({ subject: "MapLate", issuer: "Clamp", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([P1]), pmExt([[P1, P2]])]) });
  var leaf39 = await mkCert({ subject: "L39", issuer: "MapLate", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P2])] });
  var res39 = await run([interClamp, interMapLate, leaf39], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("mapping at policy_mapping==0 deletes, not remaps", res39.valid === false && failCodes(res39).indexOf("path/policy-required") !== -1);
}

// ---------------------------------------------------------------------------
// Name-constraint ordering, empty subject, anchor rules (V37, V40, V41)
// ---------------------------------------------------------------------------

async function testConstraintOrderingAndAnchor() {
  var anchor = await mkAnchor("ed25519", "Root");

  // a cert's OWN names are checked BEFORE its nameConstraints absorb
  // (§I8): B's SAN violates the constraint B itself introduces, yet B
  // passes; the NEXT cert violating it fails.
  var interB = await mkCert({ subject: "B37", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnDns("b.example")]), sanExt([gnDns("host.b.example")])]) });
  var cleanLeaf = await mkCert({ subject: "L37", issuer: "B37", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("ok.example.org")])] });
  var res37a = await run([interB, cleanLeaf], { time: T2027, trustAnchor: anchor });
  check("own-name checked before absorb (clean leaf passes)", res37a.valid === true);
  var dirtyLeaf = await mkCert({ subject: "L37d", issuer: "B37", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.b.example")])] });
  var res37b = await run([interB, dirtyLeaf], { time: T2027, trustAnchor: anchor });
  check("next cert violating the absorbed constraint fails", res37b.valid === false && failCodes(res37b).indexOf("path/name-constraint-excluded") !== -1);

  // an empty subject is legal ONLY with a critical SAN (§4.1.2.6).
  var emptySubjCritSan = await mkCert({ subject: [], issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("empty.example")], true)] });
  var res40a = await run([emptySubjCritSan], { time: T2027, trustAnchor: anchor });
  check("empty subject with critical SAN accepted", res40a.valid === true);
  var emptySubjPlainSan = await mkCert({ subject: [], issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("empty.example")], false)] });
  var res40b = await run([emptySubjPlainSan], { time: T2027, trustAnchor: anchor });
  check("empty subject with non-critical SAN rejected", res40b.valid === false && failCodes(res40b).length > 0);

  // the trust anchor is INPUT, never a path certificate: an expired
  // anchor still anchors a currently-valid chain (§I3).
  var k = await ensureKeys("ed25519");
  var expiredAnchorCert = pki.schema.x509.parse(await mkCert({ subject: "OldRoot", issuer: "OldRoot", signWith: "ed25519", notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z") }));
  var anchorFromExpired = { name: expiredAnchorCert.subject, publicKey: k.spki, algorithm: ALG.ed25519.sigOid };
  var leaf41 = await mkCert({ subject: "L41", issuer: "OldRoot", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var res41 = await run([leaf41], { time: T2027, trustAnchor: anchorFromExpired });
  check("expired anchor still anchors (anchor never validated)", res41.valid === true);
}

// ---------------------------------------------------------------------------
// Signature edge cases (V28, V29, V30, V31, V32, V33, V34-subset)
// ---------------------------------------------------------------------------

async function testSignatureAndInputEdges() {
  var anchor = await mkAnchor("ed25519", "Root");

  // all-zero ECDSA signature must be rejected (CVE-2022-21449).
  var anchorEc = await mkAnchor("p256", "EcRoot");
  var zeroSig = await mkCert({
    subject: "Zero", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf",
    mutateSig: function () { return b.sequence([b.integer(0n), b.integer(0n)]); },
  });
  var res28 = await run([zeroSig], { time: T2027, trustAnchor: anchorEc });
  check("r=0,s=0 ECDSA signature rejected", res28.valid === false && failCodes(res28).indexOf("path/bad-signature") !== -1);

  // the EdDSA analogue: a low-order issuer key verifies a matching low-order signature as TRUE for
  // EVERY message -- a trivial forgery node/OpenSSL import without complaint. With the issuer key
  // the identity point (0,1) and the signature R=identity, S=0, the verification equation
  // [S]B == R + H(..)*A collapses to identity == identity regardless of the signed bytes. The
  // issuer point MUST be rejected before verify, so the forged path is refused, not accepted.
  var ID_POINT = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);   // (0,1) encoded little-endian
  var loAnchor = await mkAnchor("ed25519", "LoRoot");
  loAnchor.publicKey = b.sequence([b.sequence([b.oid(pki.oid.byName("Ed25519"))]), b.bitString(ID_POINT, 0)]);
  var loLeaf = await mkCert({
    subject: "LoLeaf", issuer: "LoRoot", signWith: "ed25519", subjectKeys: "ed25519leaf",
    mutateSig: function () { return Buffer.concat([ID_POINT, Buffer.alloc(32)]); },   // R=identity, S=0
  });
  var resLo = await run([loLeaf], { time: T2027, trustAnchor: loAnchor });
  check("low-order EdDSA issuer key rejected before verify", resLo.valid === false && failCodes(resLo).indexOf("path/bad-signature") !== -1);

  // an embedded NUL in a constrained name never truncates the
  // comparison (CVE-2009-2408): either the parse layer refuses the name or
  // the validator refuses the match — never valid:true.
  var interNc = await mkCert({ subject: "NulNc", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnDns("example.com")], null)]) });
  var out29;
  try {
    var nulLeaf = await mkCert({ subject: "NulLeaf", issuer: "NulNc", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("www.example.com\u0000.evil.org")])] });
    var res29 = await run([interNc, nulLeaf], { time: T2027, trustAnchor: anchor });
    out29 = res29.valid === false;
  } catch (e) {
    out29 = typeof e.code === "string"; // typed reject at parse is equally fail-closed
  }
  check("NUL-embedded SAN never validates inside the permitted tree", out29 === true);

  // empty path is a caller error.
  check("empty path throws path/empty-path", (await codeOf(run([], { time: T2027, trustAnchor: anchor }))) === "path/empty-path");

  // algorithm confusion: the verify algorithm derives from the cert +
  // working key, never trusted blindly (CVE-2015-9235). A cert declaring an
  // RSA signatureAlgorithm while chained to an Ed25519 anchor key must fail
  // typed, not verify.
  var confusedAlg = Object.create(ALG.ed25519);
  confusedAlg.sigOid = ALG.rsa.sigOid; confusedAlg.sigParams = "null";
  ALG.confused = confusedAlg;
  var edKeys = await ensureKeys("ed25519");
  // The same Ed25519 key pair under a lying (RSA) algorithm identifier.
  KEYS.confused = { privateKey: edKeys.privateKey, publicKey: edKeys.publicKey, spki: edKeys.spki, alg: confusedAlg };
  var confused = await mkCert({ subject: "Confused", issuer: "Root", signWith: "confused", subjectKeys: "ed25519leaf" });
  var res31 = await run([confused], { time: T2027, trustAnchor: anchor });
  var codes31 = failCodes(res31);
  check("algorithm-confused cert rejected typed", res31.valid === false &&
    (codes31.indexOf("path/bad-signature") !== -1 || codes31.indexOf("path/unsupported-algorithm") !== -1));

  // multi-defect chain fails typed, never a raw TypeError.
  var notCa = await mkCert({ subject: "MD", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(false)] });
  var brokenLeaf = await mkCert({
    subject: "MDL", issuer: "MD", signWith: "ed25519i", subjectKeys: "ed25519leaf",
    notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"),
    mutateSig: function (sig) { var s = Buffer.from(sig); s[3] ^= 0x55; return s; },
  });
  var res32 = await run([notCa, brokenLeaf], { time: T2027, trustAnchor: anchor });
  var codes32 = failCodes(res32);
  check("multi-defect chain fails with typed path/* codes", res32.valid === false && codes32.length > 0 &&
    codes32.every(function (c) { return c.indexOf("path/") === 0; }));

  // purity / re-entrancy: identical results on a second run; the
  // input cert objects are not mutated.
  var leaf33 = await mkCert({ subject: "L33", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var parsed33 = [pki.schema.x509.parse(leaf33)];
  var snapshot = JSON.stringify({ dn: parsed33[0].subject.dn, serial: parsed33[0].serialNumberHex, nb: parsed33[0].validity.notBefore.toISOString() });
  var runA = await pki.path.validate(parsed33, { time: T2027, trustAnchor: anchor });
  var runB = await pki.path.validate(parsed33, { time: T2027, trustAnchor: anchor });
  check("re-entrant: two runs agree", runA.valid === runB.valid && JSON.stringify(failCodes(runA)) === JSON.stringify(failCodes(runB)));
  check("inputs not mutated", JSON.stringify({ dn: parsed33[0].subject.dn, serial: parsed33[0].serialNumberHex, nb: parsed33[0].validity.notBefore.toISOString() }) === snapshot);

  // V34 (validator-level subset) — an 8-octet iPAddress subtree base (addr +
  // mask) is the LEGAL constraint form and must work; a 4-octet subtree base
  // is malformed. (The SAN-side 4/16 rule is enforced at parse and has its
  // own vectors in the pkix suites.)
  var interIp = await mkCert({ subject: "Ip", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnIp([192, 168, 0, 0, 255, 255, 0, 0])], null)]) });
  var leafIpIn = await mkCert({ subject: "IpIn", issuer: "Ip", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnIp([192, 168, 5, 9])])] });
  var res34a = await run([interIp, leafIpIn], { time: T2027, trustAnchor: anchor });
  check("8-octet subtree base constrains a 4-octet SAN address", res34a.valid === true);
  var leafIpOut = await mkCert({ subject: "IpOut", issuer: "Ip", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnIp([10, 0, 0, 1])])] });
  var res34b = await run([interIp, leafIpOut], { time: T2027, trustAnchor: anchor });
  check("address outside the masked subtree rejected", res34b.valid === false && failCodes(res34b).indexOf("path/name-constraint-not-permitted") !== -1);
  var interIpBad = await mkCert({ subject: "IpBad", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnIp([192, 168, 0, 0])], null)]) });
  var leaf34c = await mkCert({ subject: "L34c", issuer: "IpBad", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnIp([192, 168, 5, 9])])] });
  var res34c = await run([interIpBad, leaf34c], { time: T2027, trustAnchor: anchor });
  check("4-octet subtree base (no mask) rejected as malformed", res34c.valid === false && failCodes(res34c).indexOf("path/bad-name-constraints") !== -1);
}

// ---------------------------------------------------------------------------
// Revocation — the pluggable checker contract + the CRL checker (V14, V15,
// V25, V26, V27, V42-V46)
// ---------------------------------------------------------------------------

// A REAL signed CRL, mirroring mkCert.
async function mkCrl(o) {
  var signer = await ensureKeys(o.signWith);
  var a = signer.alg;
  var hasExts = (o.extensions && o.extensions.length) || (o.revoked || []).some(function (r) { return r.exts; });
  var tbsChildren = [];
  if (hasExts) tbsChildren.push(b.integer(1n)); // v2 iff extensions ride along
  tbsChildren.push(algIdDer(a));
  tbsChildren.push(nameDer(o.issuer));
  tbsChildren.push(b.utcTime(o.thisUpdate || new Date("2027-01-01T00:00:00Z")));
  if (o.nextUpdate !== null) tbsChildren.push(b.utcTime(o.nextUpdate || new Date("2028-06-01T00:00:00Z")));
  if (o.revoked && o.revoked.length) {
    tbsChildren.push(b.sequence(o.revoked.map(function (r) {
      var entry = [b.integer(r.serial), b.utcTime(r.date || new Date("2026-06-01T00:00:00Z"))];
      if (r.exts) entry.push(b.sequence(r.exts));
      return b.sequence(entry);
    })));
  }
  if (o.extensions && o.extensions.length) tbsChildren.push(b.explicit(0, b.sequence(o.extensions)));
  var tbs = b.sequence(tbsChildren);
  var sig = Buffer.from(await subtle.sign(a.sign, signer.privateKey, tbs));
  if (a.p1363) sig = p1363ToDer(sig, a.p1363);
  if (o.mutateSig) sig = o.mutateSig(sig);
  return b.sequence([tbs, algIdDer(a), b.bitString(sig, 0)]);
}

// IssuingDistributionPoint value (§5.2.5) — the scope fields the checker honors.
function idpVal(o) {
  var children = [];
  if (o.distributionPoint) children.push(b.contextConstructed(0, o.distributionPoint));
  if (o.onlyUser) children.push(b.contextPrimitive(1, Buffer.from([0xff])));
  if (o.onlyCa) children.push(b.contextPrimitive(2, Buffer.from([0xff])));
  if (o.onlySomeReasons) children.push(b.contextPrimitive(3, o.onlySomeReasons));
  if (o.indirect) children.push(b.contextPrimitive(4, Buffer.from([0xff])));
  if (o.onlyAttr) children.push(b.contextPrimitive(5, Buffer.from([0xff])));
  return b.sequence(children);
}
function idpExt(o) { return ext("2.5.29.28", true, idpVal(o)); }
// DistributionPointName fullName [0] { GeneralName... } (IMPLICIT GeneralNames).
function dpnFull(gns) { return b.contextConstructed(0, Buffer.concat([].concat(gns))); }
// DistributionPointName nameRelativeToCRLIssuer [1] { AttributeTypeAndValue... }
// (IMPLICIT RelativeDistinguishedName — the [1] tag replaces the SET tag).
function dpnRel(atvs) { return b.contextConstructed(1, Buffer.concat(atvs)); }
// One DistributionPoint SEQUENCE { distributionPoint [0] EXPLICIT <DPN>, reasons [1]? }.
function distPoint(dpn, reasonsBits) {
  var kids = [b.contextConstructed(0, dpn)];
  if (reasonsBits) kids.push(b.contextPrimitive(1, reasonsBits));
  return b.sequence(kids);
}
// cRLDistributionPoints / freshestCRL certificate extensions (§4.2.1.13 / §4.2.1.15).
function cdpExt(dps) { return ext("2.5.29.31", false, b.sequence(dps)); }
function freshestExt(dps) { return ext("2.5.29.46", false, b.sequence(dps)); }
function crlNumberExt(n) { return ext("2.5.29.20", false, b.integer(BigInt(n))); }
// reasonCode CRL-entry extension (§5.3.1) — value is an ENUMERATED.
function reasonCodeExt(n) { return ext("2.5.29.21", false, b.enumerated(BigInt(n))); }
// A CRL extension with an OID the checker does not understand, marked critical.
function unknownCriticalCrlExt() { return ext("1.3.6.1.4.1.99999.42", true, b.octetString(Buffer.from([1]))); }

// ---------------------------------------------------------------------------
// mkOcsp — a REAL signed OCSPResponse, the INVERSE of pki.path.ocspChecker. It
// computes each CertID's issuerNameHash/issuerKeyHash under the per-response
// hash algorithm over the issuer Name DER + issuer key BIT STRING value (so the
// checker's recomputation matches), assembles the ResponseData, signs it with
// the responder key, and wraps it as an OCSPResponse (RFC 6960 sec. 4.2.1).
// o = {
//   responseStatus? : OCSPResponseStatus (default 0 successful; a non-zero code
//                     emits a status-only response with no responseBytes),
//   responderID     : { byName: <name spec> } | { byKeyOf: <spki Buffer> },
//   signWith        : the responder's key alg (the issuer key for the direct model),
//   producedAt?     : Date,
//   certs?          : [ <cert DER Buffer> ]  embedded delegate certs,
//   single          : [ { issuerName, issuerKeyAlg, serial,
//                         status:"good"|"revoked"|"unknown", hashAlg?:"SHA-1"|"SHA-256"|"SHA-384",
//                         thisUpdate?, nextUpdate?(null=omit), revocationTime?,
//                         revocationReason?(CRLReason int) } ],
//   mutateSig?      : fn(sigBuf)->sigBuf,
// }
// ---------------------------------------------------------------------------
var OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
var EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
var OID_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";
// id-pkix-ocsp-nocheck (RFC 6960 sec. 4.2.2.2.1): the CA vouches for the responder
// for its certificate lifetime without a revocation check. A delegated responder
// needs it (or a caller-supplied status) to be authorized.
function nocheckExt() { return ext(OID_OCSP_NOCHECK, false, b.nullValue()); }

// The subjectPublicKey BIT STRING VALUE (excluding the unused-bits octet) of an
// SPKI DER -- the exact bytes the CertID issuerKeyHash / byKey KeyHash hash over.
function _spkiKeyValue(spkiDer) {
  return pki.asn1.read.bitString(pki.asn1.decode(spkiDer).children[1]).bytes;
}
async function _digest(alg, buf) { return Buffer.from(await subtle.digest(alg, buf)); }
function _certIdHashOid(alg) { return alg === "SHA-256" ? OID_SHA256 : (alg === "SHA-384" ? OID_SHA384 : OID_SHA1); }

async function mkOcsp(o) {
  if (o.responseStatus !== undefined && o.responseStatus !== 0) {
    // Non-successful: an OCSPResponse carrying only the ENUMERATED status.
    return b.sequence([b.enumerated(BigInt(o.responseStatus))]);
  }
  var signer = await ensureKeys(o.signWith);
  var sa = signer.alg;

  var ridNode;
  if (o.responderID.byName) {
    ridNode = b.explicit(1, nameDer(o.responderID.byName));               // byName [1] EXPLICIT Name
  } else {
    var kh = await _digest("SHA-1", _spkiKeyValue(o.responderID.byKeyOf)); // byKey [2] EXPLICIT KeyHash
    ridNode = b.explicit(2, b.octetString(kh));
  }

  var srNodes = [];
  for (var i = 0; i < o.single.length; i++) {
    var sr = o.single[i];
    var hAlg = sr.hashAlg || "SHA-1";
    var issuerKeys = await ensureKeys(sr.issuerKeyAlg);
    var nameHash = await _digest(hAlg, nameDer(sr.issuerName));
    var keyHash = await _digest(hAlg, _spkiKeyValue(issuerKeys.spki));
    var certId = b.sequence([
      b.sequence([b.oid(sr.hashOidOverride || _certIdHashOid(hAlg)), b.nullValue()]),
      b.octetString(nameHash),
      b.octetString(keyHash),
      b.integer(BigInt(sr.serial)),
    ]);
    var statusNode;
    if (sr.status === "revoked") {
      var ri = [b.generalizedTime(sr.revocationTime || new Date("2026-06-01T00:00:00Z"))];
      if (sr.revocationReason !== undefined && sr.revocationReason !== null) {
        ri.push(b.explicit(0, b.enumerated(BigInt(sr.revocationReason))));  // revocationReason [0] EXPLICIT CRLReason
      }
      statusNode = b.contextConstructed(1, Buffer.concat(ri));              // revoked [1] IMPLICIT RevokedInfo
    } else if (sr.status === "unknown") {
      statusNode = b.contextPrimitive(2, Buffer.alloc(0));                  // unknown [2] IMPLICIT NULL
    } else {
      statusNode = b.contextPrimitive(0, Buffer.alloc(0));                  // good [0] IMPLICIT NULL
    }
    var srChildren = [certId, statusNode, b.generalizedTime(sr.thisUpdate || new Date("2027-01-01T00:00:00Z"))];
    if (sr.nextUpdate !== null) {
      srChildren.push(b.explicit(0, b.generalizedTime(sr.nextUpdate || new Date("2028-06-01T00:00:00Z"))));  // nextUpdate [0] EXPLICIT
    }
    if (sr.singleExtensions && sr.singleExtensions.length) {
      srChildren.push(b.explicit(1, b.sequence(sr.singleExtensions)));  // singleExtensions [1] EXPLICIT
    }
    srNodes.push(b.sequence(srChildren));
  }

  var rdChildren = [
    ridNode,
    b.generalizedTime(o.producedAt || new Date("2027-01-01T00:00:00Z")),
    b.sequence(srNodes),
  ];
  if (o.responseExtensions && o.responseExtensions.length) {
    rdChildren.push(b.explicit(1, b.sequence(o.responseExtensions)));  // responseExtensions [1] EXPLICIT
  }
  var responseData = b.sequence(rdChildren);

  var sig = Buffer.from(await subtle.sign(sa.sign, signer.privateKey, responseData));
  if (sa.p1363) sig = p1363ToDer(sig, sa.p1363);
  if (o.mutateSig) sig = o.mutateSig(sig);

  var basicChildren = [responseData, o.sigAlgOverride || algIdDer(sa), b.bitString(sig, 0)];
  if (o.certs && o.certs.length) {
    basicChildren.push(b.explicit(0, b.sequence(o.certs.map(function (c) { return b.raw(c); }))));  // certs [0] EXPLICIT
  }
  var responseBytes = b.sequence([b.oid(OID_OCSP_BASIC), b.octetString(b.sequence(basicChildren))]);
  return b.sequence([b.enumerated(0n), b.explicit(0, responseBytes)]);      // successful + responseBytes [0] EXPLICIT
}

async function testRevocation() {
  var anchor = await mkAnchor("ed25519", "Root");
  var LEAF_SERIAL = 7777n;

  // checker contract: UNDETERMINED fails closed; softFail opts out.
  var leaf = await mkCert({ subject: "R1", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: LEAF_SERIAL });
  var unknownChecker = { check: function () { return Promise.resolve({ status: "unknown" }); } };
  var res15a = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: unknownChecker });
  check("UNDETERMINED revocation fails closed", res15a.valid === false && failCodes(res15a).indexOf("path/revocation-undetermined") !== -1);
  var res15b = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: unknownChecker, softFail: true });
  check("softFail opts into UNDETERMINED-as-pass", res15b.valid === true);

  // "checked, and it said good" and "could not check, and you waived it" are the SAME claim to a
  // caller reading a bare `valid: true` -- and they were the same object in `checks` too. The
  // verdict now says which happened, at the top level and per certificate, because a stored path
  // verdict is re-read later to answer exactly this and cannot answer it from a boolean.
  var goodChecker = { check: function () { return Promise.resolve({ status: "good" }); } };
  var resDet = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: goodChecker });
  check("a determined non-revocation reports itself determined",
    resDet.valid === true && resDet.revocationChecked === "determined");
  check("softFail waiving an undetermined status says so, rather than reading as checked",
    res15b.revocationChecked === "waived");
  check("no checker at all reports the rule as not requested",
    (await run([leaf], { time: T2027, trustAnchor: anchor })).revocationChecked === false);
  // The field says whether revocation was ESTABLISHED, so a run that failed BECAUSE it could not be
  // established must not report the same word as one that established it. Deriving the answer from
  // "a checker ran" put the two on the same value, which is the reading the field exists to prevent.
  check("an undetermined status that fails the path reports itself undetermined, not determined",
    res15a.revocationChecked === "undetermined");
  var revokedChecker = { check: function () { return Promise.resolve({ status: "revoked" }); } };
  var resRevoked = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: revokedChecker });
  check("a revoked status is a determination, and reports as one",
    resRevoked.valid === false && resRevoked.revocationChecked === "determined");
  // A path long enough to mix outcomes takes the WEAKEST: one certificate nobody could answer for
  // leaves the path's revocation unestablished however many others answered good.
  var mixInter = await mkCert({ subject: "MixInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var mixLeaf = await mkCert({ subject: "MixLeaf", issuer: "MixInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var seen = 0;
  var mixed = { check: function () { seen++; return Promise.resolve({ status: seen === 1 ? "good" : "unknown" }); } };
  var resMixed = await run([mixInter, mixLeaf], { time: T2027, trustAnchor: anchor, revocationChecker: mixed, softFail: true });
  check("one waived certificate outranks the determined ones on the same path",
    seen === 2 && resMixed.valid === true && resMixed.revocationChecked === "waived");
  // Per certificate, too: the waived entry is distinguishable from the determined one, and names
  // the status that could not be turned into a determination.
  var waivedCheck = res15b.results[res15b.results.length - 1].checks.filter(function (c) { return c.name === "revocation"; })[0];
  var goodCheck = resDet.results[resDet.results.length - 1].checks.filter(function (c) { return c.name === "revocation"; })[0];
  check("the waived per-certificate entry is not byte-identical to the determined one",
    waivedCheck.ok === true && waivedCheck.waived === true && waivedCheck.status === "unknown" &&
    goodCheck.ok === true && goodCheck.waived === undefined && goodCheck.status === "good");
  // A checker that THROWS is a fault in the checker, not a revocation status it could not reach.
  // softFail is the caller opting into an UNDETERMINED answer -- the built-in CRL and OCSP checkers
  // return `{status:"unknown"}` for every unreachable or unverifiable condition and never throw --
  // so waiving a throw would waive the caller's own bug, and the certificate would pass without any
  // revocation result at all. The fault fails the path whatever softFail says, and is carried on the
  // check so an operator can tell their bug from a network condition.
  var throwingChecker = { check: function () { throw new Error("checker exploded"); } };
  var resThrew = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: throwingChecker, softFail: true });
  var threwCheck = resThrew.results[resThrew.results.length - 1].checks.filter(function (c) { return c.name === "revocation"; })[0];
  check("a checker that throws fails the path even under softFail, and is not called a waiver",
    resThrew.valid === false && resThrew.revocationChecked === "undetermined" &&
    threwCheck.ok === false && threwCheck.waived === undefined &&
    threwCheck.code === "path/revocation-checker-error");
  check("...and carries the fault, so a broken checker is not a network condition",
    threwCheck.status === "error" && !!threwCheck.error && /checker exploded/.test(threwCheck.error.message));
  // A checker that REJECTS is the same fault by another route: an async checker's bug arrives as a
  // rejected promise, and reaching the waiver through it would restore exactly what the throw lost.
  var rejectingChecker = { check: function () { return Promise.reject(new Error("responder client bug")); } };
  var resRej = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: rejectingChecker, softFail: true });
  check("a checker that rejects is the same fault as one that throws",
    resRej.valid === false && resRej.revocationChecked === "undetermined" &&
    failCodes(resRej).indexOf("path/revocation-checker-error") !== -1);

  // a real CRL revoking the leaf serial, via pki.path.crlChecker.
  var crlRevoking = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: LEAF_SERIAL }] });
  var res14 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlRevoking]) });
  check("revoked serial rejected via CRL checker", res14.valid === false && failCodes(res14).indexOf("path/revoked") !== -1);

  // ...and the same CRL without the serial passes.
  var crlClean = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1234n }] });
  var res14b = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlClean]) });
  check("unlisted serial passes the CRL checker", res14b.valid === true);

  // stale CRL (nextUpdate < time) -> unknown -> undetermined.
  var crlStale = await mkCrl({ issuer: "Root", signWith: "ed25519", nextUpdate: new Date("2026-06-01T00:00:00Z") });
  var res27 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlStale]) });
  check("stale CRL yields undetermined", res27.valid === false && failCodes(res27).indexOf("path/revocation-undetermined") !== -1);

  // thisUpdate in the future -> unknown.
  var crlFuture = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2028-01-01T00:00:00Z"), nextUpdate: new Date("2029-01-01T00:00:00Z") });
  var res44 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFuture]) });
  check("future thisUpdate yields undetermined", res44.valid === false && failCodes(res44).indexOf("path/revocation-undetermined") !== -1);

  // a CRL whose signature does not verify -> unknown.
  var crlBadSig = await mkCrl({ issuer: "Root", signWith: "ed25519", mutateSig: function (sig) { var s = Buffer.from(sig); s[5] ^= 0xaa; return s; } });
  var res42 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlBadSig]) });
  check("bad CRL signature yields undetermined", res42.valid === false && failCodes(res42).indexOf("path/revocation-undetermined") !== -1);

  // a CRL from an unauthorized third-party issuer -> unknown.
  var crlThirdParty = await mkCrl({ issuer: "SomeoneElse", signWith: "ed25519i" });
  var res43 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlThirdParty]) });
  check("unauthorized CRL issuer yields undetermined", res43.valid === false && failCodes(res43).indexOf("path/revocation-undetermined") !== -1);

  // the CRL signer's certificate lacks keyUsage.cRLSign -> unknown;
  // the positive control (signer WITH cRLSign) passes. A Root-issued CRL
  // covers the intermediate in both runs, so the only variable is the leaf
  // CRL's signer.
  var rootCrl = await mkCrl({ issuer: "Root", signWith: "ed25519" });
  var interNoCrlSign = await mkCert({ subject: "NoCrlSign", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leafUnder = await mkCert({ subject: "Under", issuer: "NoCrlSign", signWith: "ed25519i", subjectKeys: "ed25519leaf", serial: 4242n });
  var crlByInter = await mkCrl({ issuer: "NoCrlSign", signWith: "ed25519i" });
  var res26 = await run([interNoCrlSign, leafUnder], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrl, crlByInter]) });
  check("CRL signer without cRLSign yields undetermined", res26.valid === false && failCodes(res26).indexOf("path/revocation-undetermined") !== -1);
  var interCrlSign = await mkCert({ subject: "WithCrlSign", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519j", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN, KU_CRL_SIGN])] });
  var leafUnder2 = await mkCert({ subject: "Under2", issuer: "WithCrlSign", signWith: "ed25519j", subjectKeys: "ed25519leaf", serial: 4243n });
  var crlByInter2 = await mkCrl({ issuer: "WithCrlSign", signWith: "ed25519j" });
  var res26b = await run([interCrlSign, leafUnder2], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrl, crlByInter2]) });
  check("control: CRL signer with cRLSign passes", res26b.valid === true);

  // scoped CRLs (onlySomeReasons) covering only part of the reason
  // space are never a definitive UNREVOKED.
  var someReasons = Buffer.from([0x06, 0x40]); // BIT STRING content: 6 unused bits, keyCompromise only
  var crlPartial = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(1), idpExt({ onlySomeReasons: someReasons })] });
  var res45 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlPartial]) });
  check("partial reasons_mask coverage yields undetermined", res45.valid === false && failCodes(res45).indexOf("path/revocation-undetermined") !== -1);

  // IDP scope mismatch: an onlyContainsCACerts CRL consulted for an
  // end-entity certificate -> unknown.
  var crlCaOnly = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(2), idpExt({ onlyCa: true })] });
  var res46 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCaOnly]) });
  check("onlyContainsCACerts CRL out of scope for an EE cert", res46.valid === false && failCodes(res46).indexOf("path/revocation-undetermined") !== -1);
}

// The standalone pki.path.crlChecker (the RevocationChecker interface an
// external validator composes) must fail CLOSED when an extension its
// authorization / scope gates read is unreadable. Driven through
// checker.check directly: inside pki.path.validate the same malformed
// extension already fails the path in the 6.1.4 processing, which would
// mask the checker's own verdict.
async function testCrlCheckerUnreadableExtensions() {
  var signer = await ensureKeys("ed25519i");
  var rootKeys = await ensureKeys("ed25519");
  var ctx = { time: T2027, historicalMode: false };

  // RFC 5280 §6.3.3(f): a PRESENT keyUsage must have its cRLSign bit
  // VERIFIED. Garbage keyUsage bytes on the CRL issuer's certificate cannot
  // be verified, so they must not authorize CRL signing (an unreadable
  // extension is not an absent one).
  var badKu = ext("2.5.29.15", false, b.octetString(Buffer.from([0xde, 0xad])));   // OCTET STRING where a BIT STRING must be
  var interBadKu = pki.schema.x509.parse(await mkCert({ subject: "BadKuSigner", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), badKu] }));
  var leafUnderBad = pki.schema.x509.parse(await mkCert({ subject: "UnderBadKu", issuer: "BadKuSigner", signWith: "ed25519i", subjectKeys: "ed25519leaf", serial: 6161n }));
  var cleanCrl = await mkCrl({ issuer: "BadKuSigner", signWith: "ed25519i" });
  var r1 = await pki.path.crlChecker([cleanCrl]).check(leafUnderBad, { workingPublicKey: signer.spki, issuerCert: interBadKu }, ctx);
  check("unreadable CRL-issuer keyUsage yields unknown, never good", r1.status === "unknown");
  // control: the same shape with a well-formed cRLSign keyUsage is authoritative.
  var interGoodKu = pki.schema.x509.parse(await mkCert({ subject: "GoodKuSigner", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN, KU_CRL_SIGN])] }));
  var leafUnderGood = pki.schema.x509.parse(await mkCert({ subject: "UnderGoodKu", issuer: "GoodKuSigner", signWith: "ed25519i", subjectKeys: "ed25519leaf", serial: 6162n }));
  var crlGood = await mkCrl({ issuer: "GoodKuSigner", signWith: "ed25519i" });
  var r2 = await pki.path.crlChecker([crlGood]).check(leafUnderGood, { workingPublicKey: signer.spki, issuerCert: interGoodKu }, ctx);
  check("control: readable cRLSign keyUsage stays authoritative", r2.status === "good");

  // §6.3.3(b)(2) scope: a cert whose basicConstraints is unreadable has
  // UNDETERMINABLE CA-ness, so neither an onlyContainsUserCerts nor an
  // onlyContainsCACerts CRL can be shown to cover it -- a clean scoped CRL
  // must not establish "good" for it.
  var badBc = ext("2.5.29.19", false, b.boolean(true));   // BOOLEAN where a SEQUENCE must be
  var leafBadBc = pki.schema.x509.parse(await mkCert({ subject: "BadBcLeaf", issuer: "ScopeRoot", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 6163n, extensions: [badBc] }));
  var crlUserOnly = await mkCrl({ issuer: "ScopeRoot", signWith: "ed25519", extensions: [crlNumberExt(9), idpExt({ onlyUser: true })] });
  var r3 = await pki.path.crlChecker([crlUserOnly]).check(leafBadBc, { workingPublicKey: rootKeys.spki, issuerCert: null }, ctx);
  check("unreadable basicConstraints skips a user-scoped CRL (unknown)", r3.status === "unknown");
  var crlCaScoped = await mkCrl({ issuer: "ScopeRoot", signWith: "ed25519", extensions: [crlNumberExt(10), idpExt({ onlyCa: true })] });
  var r4 = await pki.path.crlChecker([crlCaScoped]).check(leafBadBc, { workingPublicKey: rootKeys.spki, issuerCert: null }, ctx);
  check("unreadable basicConstraints skips a CA-scoped CRL (unknown)", r4.status === "unknown");
  // control: a readable end-entity cert IS covered by the user-scoped CRL.
  var leafOkBc = pki.schema.x509.parse(await mkCert({ subject: "OkBcLeaf", issuer: "ScopeRoot", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 6164n, extensions: [bcExt(false)] }));
  var r5 = await pki.path.crlChecker([crlUserOnly]).check(leafOkBc, { workingPublicKey: rootKeys.spki, issuerCert: null }, ctx);
  check("control: a readable end-entity cert is covered by the user-scoped CRL", r5.status === "good");
  // a FULL-scope CRL covers every cert of the issuer regardless of CA-ness,
  // so it still speaks for the unreadable-basicConstraints cert.
  var crlFull = await mkCrl({ issuer: "ScopeRoot", signWith: "ed25519" });
  var r6 = await pki.path.crlChecker([crlFull]).check(leafBadBc, { workingPublicKey: rootKeys.spki, issuerCert: null }, ctx);
  check("a full-scope CRL still covers a cert with unreadable basicConstraints", r6.status === "good");
}

// ---------------------------------------------------------------------------
// Leaf exemption + parameter inheritance (V24, V25)
// ---------------------------------------------------------------------------

async function testLeafRulesAndParams() {
  var anchor = await mkAnchor("ed25519", "Root");

  // the leaf is NOT subject to §6.1.4: cA:FALSE + no keyUsage at
  // position n is fine (§I10).
  var leaf25 = await mkCert({ subject: "L25", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [bcExt(false)] });
  var res25 = await run([leaf25], { time: T2027, trustAnchor: anchor });
  check("non-CA leaf accepted at position n", res25.valid === true);

  // §6.1.4(e) parameter inheritance, observed through the verifier
  // seam: same-algorithm absent params inherit; a different algorithm with
  // absent params clears them.
  var PARAMS = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]); // opaque anchor parameters
  var SYN_ALG = "1.3.6.1.4.1.99999.77";
  var synSpkiSame = b.sequence([b.sequence([b.oid(SYN_ALG)]), b.bitString(Buffer.from([0x04, 0x01]), 0)]);
  var synSpkiOther = b.sequence([b.sequence([b.oid("1.3.6.1.4.1.99999.78")]), b.bitString(Buffer.from([0x04, 0x02]), 0)]);

  var seen = [];
  var recordingVerifier = {
    verify: function (ctx) {
      seen.push({ alg: ctx.workingPublicKeyAlgorithm, params: ctx.workingPublicKeyParameters ? Buffer.from(ctx.workingPublicKeyParameters).toString("hex") : null });
      return Promise.resolve(true);
    },
  };
  var synAnchorName = pki.schema.x509.parse(await mkCert({ subject: "SynRoot", issuer: "SynRoot", signWith: "ed25519" })).subject;
  // The anchor's publicKey SPKI must self-describe SYN_ALG so its declared algorithm matches it (the
  // recordingVerifier never checks the key, so a synthetic SPKI is enough to drive the sec. 6.1.4 seam).
  // The anchor's parameters are DERIVED from its SPKI's AlgorithmIdentifier (never a declared field), so
  // the synthetic SPKI must carry PARAMS there for the sec. 6.1.4 inherit-vs-clear seam below to see them.
  var synAnchorSpki = b.sequence([b.sequence([b.oid(SYN_ALG), b.raw(PARAMS)]), b.bitString(Buffer.from([0x04, 0x00]), 0)]);
  var synAnchor = { name: synAnchorName, publicKey: synAnchorSpki, algorithm: SYN_ALG };

  var certSame = await mkCert({ subject: "Same", issuer: "SynRoot", signWith: "ed25519", spki: synSpkiSame, extensions: caExts() });
  var certUnder = await mkCert({ subject: "UnderSame", issuer: "Same", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  seen.length = 0;
  var resSame = await run([certSame, certUnder], { time: T2027, trustAnchor: synAnchor, verifier: recordingVerifier });
  check("same-algorithm absent params inherited", resSame.valid === true && seen.length === 2 && seen[1].params === PARAMS.toString("hex"));

  var certOther = await mkCert({ subject: "Other", issuer: "SynRoot", signWith: "ed25519", spki: synSpkiOther, extensions: caExts() });
  var certUnder2 = await mkCert({ subject: "UnderOther", issuer: "Other", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  seen.length = 0;
  var resOther = await run([certOther, certUnder2], { time: T2027, trustAnchor: synAnchor, verifier: recordingVerifier });
  check("different-algorithm absent params cleared", resOther.valid === true && seen.length === 2 && seen[1].params === null);

  // an EXPLICIT DER NULL parameters field is treated identically to
  // omitted (§6.1.4(e)): the same-algorithm intermediate inherits, not copies
  // the NULL. synSpkiNull carries SYN_ALG with an explicit NULL parameter.
  var synSpkiNull = b.sequence([b.sequence([b.oid(SYN_ALG), b.nullValue()]), b.bitString(Buffer.from([0x04, 0x03]), 0)]);
  var certNull = await mkCert({ subject: "NullP", issuer: "SynRoot", signWith: "ed25519", spki: synSpkiNull, extensions: caExts() });
  var certUnder3 = await mkCert({ subject: "UnderNull", issuer: "NullP", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  seen.length = 0;
  var resNull = await run([certNull, certUnder3], { time: T2027, trustAnchor: synAnchor, verifier: recordingVerifier });
  check("explicit NULL params inherit like omitted (not copied)", resNull.valid === true && seen.length === 2 && seen[1].params === PARAMS.toString("hex"));
}

// ---------------------------------------------------------------------------
// RFC 5280 conformance MUSTs pinned individually -- each vector drives a
// distinct under-enforceable rule (criticality, scope, encoding-form) through
// the shipped validate()/crlChecker() surface on the malformed input.
// ---------------------------------------------------------------------------

async function testRfc5280ConformanceMusts() {
  var anchor = await mkAnchor("ed25519", "Root");
  var P1m = "1.3.6.1.4.1.99999.1", P2m = "1.3.6.1.4.1.99999.2", P3m = "1.3.6.1.4.1.99999.3";
  var SER = 9911n;
  var leafCrl = await mkCert({ subject: "CrlL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER });

  // permitted subtrees INTERSECT, not union (§6.1.4(g)): a subordinate CA
  // that permits a broader name cannot re-admit what its parent excluded from
  // the permitted set. Parent permits dNSName "a.example"; child permits
  // "evil.com"; a leaf SAN "host.evil.com" is NOT within the parent's set.
  var parentNc = await mkCert({ subject: "P1a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnDns("a.example")], null)]) });
  var childNc = await mkCert({ subject: "C1a", issuer: "P1a", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([ncExt([gnDns("evil.com")], null)]) });
  var leafA1 = await mkCert({ subject: "L1a", issuer: "C1a", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.evil.com")])] });
  var resA1 = await run([parentNc, childNc, leafA1], { time: T2027, trustAnchor: anchor });
  check("permitted-subtree intersection blocks a subordinate broadening", resA1.valid === false && failCodes(resA1).indexOf("path/name-constraint-not-permitted") !== -1);
  // control: a leaf within BOTH generations passes... but the two generations
  // are disjoint (a.example vs evil.com), so no name satisfies both dNSName
  // sets — instead verify a single-generation permit still admits its match.
  var leafA1ok = await mkCert({ subject: "L1ok", issuer: "P1a", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.a.example")])] });
  var resA1ok = await run([parentNc, leafA1ok], { time: T2027, trustAnchor: anchor });
  check("control: name within the single permitted generation passes", resA1ok.valid === true);

  // rfc822Name leading-dot domain matches a SUBDOMAIN mailbox but not the
  // bare domain, and never a non-boundary label (§4.2.1.10).
  var interA2 = await mkCert({ subject: "P2", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail(".example.com")])]) });
  function emailLeaf(subj, addr) {
    var rdn = [b.set([atv("2.5.4.3", subj)]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5(addr)])])];
    return mkCert({ subject: rdn, issuer: "P2", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  }
  var resA2sub = await run([interA2, await emailLeaf("A2sub", "u@sub.example.com")], { time: T2027, trustAnchor: anchor });
  check("leading-dot rfc822 excludes a subdomain mailbox", resA2sub.valid === false && failCodes(resA2sub).indexOf("path/name-constraint-excluded") !== -1);
  var resA2bare = await run([interA2, await emailLeaf("A2bare", "u@example.com")], { time: T2027, trustAnchor: anchor });
  check("leading-dot rfc822 does NOT match the bare domain", resA2bare.valid === true);
  var resA2nb = await run([interA2, await emailLeaf("A2nb", "u@aexample.com")], { time: T2027, trustAnchor: anchor });
  check("leading-dot rfc822 does NOT match a non-boundary label", resA2nb.valid === true);

  // bare-host rfc822Name matches the host exactly, not a subdomain.
  var interA3 = await mkCert({ subject: "P3", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail("example.com")])]) });
  function emailLeaf3(subj, addr) {
    var rdn = [b.set([atv("2.5.4.3", subj)]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5(addr)])])];
    return mkCert({ subject: rdn, issuer: "P3", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  }
  var resA3exact = await run([interA3, await emailLeaf3("A3x", "u@example.com")], { time: T2027, trustAnchor: anchor });
  check("bare-host rfc822 matches the exact host (excluded)", resA3exact.valid === false && failCodes(resA3exact).indexOf("path/name-constraint-excluded") !== -1);
  var resA3sub = await run([interA3, await emailLeaf3("A3s", "u@sub.example.com")], { time: T2027, trustAnchor: anchor });
  check("bare-host rfc822 does NOT match a subdomain mailbox", resA3sub.valid === true);

  // an RSA-PSS-signed chain validates (the hashAlgorithm OID is decoded at
  // the correct EXPLICIT-tag depth).
  var anchorPss = await mkAnchor("rsapss", "PssRoot");
  var leafPss = await mkCert({ subject: "PssLeaf", issuer: "PssRoot", signWith: "rsapss", subjectKeys: "ed25519leaf" });
  var resA4 = await run([leafPss], { time: T2027, trustAnchor: anchorPss });
  check("RSA-PSS-signed chain validates", resA4.valid === true);

  // a PSS cert declaring an UNSUPPORTED hash OID must be
  // rejected, never silently verified under the SHA-1 default.
  var anchorPssBad = await mkAnchor("pssbad", "PssBadRoot");
  var leafBadPss = await mkCert({ subject: "BadPss", issuer: "PssBadRoot", signWith: "pssbad", subjectKeys: "ed25519leaf" });
  var resC6 = await run([leafBadPss], { time: T2027, trustAnchor: anchorPssBad });
  check("PSS cert with unsupported hash rejected (no SHA-1 fallback)", resC6.valid === false && failCodes(resC6).indexOf("path/unsupported-algorithm") !== -1);

  // PSS params whose MGF1 hash mismatches the signature hash
  // cannot be honored by WebCrypto and must be rejected, not verified anyway.
  var anchorBadMgf = await mkAnchor("pssbadmgf", "PssMgfRoot");
  var leafBadMgf = await mkCert({ subject: "BadMgf", issuer: "PssMgfRoot", signWith: "pssbadmgf", subjectKeys: "ed25519leaf" });
  var resC7 = await run([leafBadMgf], { time: T2027, trustAnchor: anchorBadMgf });
  check("PSS MGF1-hash mismatch rejected", resC7.valid === false && failCodes(resC7).indexOf("path/unsupported-algorithm") !== -1);

  // a PSS AlgorithmIdentifier with a present-but-non-SEQUENCE
  // parameters field (a DER NULL) must be rejected, not defaulted to SHA-1.
  var anchorPssNull = await mkAnchor("pssnull", "PssNullRoot");
  var leafPssNull = await mkCert({ subject: "PssNull", issuer: "PssNullRoot", signWith: "pssnull", subjectKeys: "ed25519leaf" });
  var resC10 = await run([leafPssNull], { time: T2027, trustAnchor: anchorPssNull });
  check("PSS non-SEQUENCE params rejected", resC10.valid === false && failCodes(resC10).indexOf("path/unsupported-algorithm") !== -1);

  // a critical excluded nameConstraints of a form the
  // validator cannot compare (registeredID) plus a cert presenting that form
  // must fail closed, not be treated as "not excluded".
  var interRegId = await mkCert({ subject: "RegIdInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnRegisteredID("1.3.6.1.4.1.99999.5")])]) });
  var leafRegId = await mkCert({ subject: "RegIdLeaf", issuer: "RegIdInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnRegisteredID("1.3.6.1.4.1.99999.5")])] });
  var resC9 = await run([interRegId, leafRegId], { time: T2027, trustAnchor: anchor });
  check("unsupported excluded name form fails closed", resC9.valid === false && failCodes(resC9).indexOf("path/name-constraint-unsupported") !== -1);

  // an UNDECODED SAN form (x400Address [3]) must still be
  // preserved so a critical excluded constraint of that form fails closed.
  var interX400 = await mkCert({ subject: "X400Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnX400()])]) });
  var leafX400 = await mkCert({ subject: "X400Leaf", issuer: "X400Inter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnX400()])] });
  var resC11 = await run([interX400, leafX400], { time: T2027, trustAnchor: anchor });
  check("undecoded SAN form preserved for constraints (fails closed)", resC11.valid === false && failCodes(resC11).indexOf("path/name-constraint-unsupported") !== -1);

  // a CA asserting only anyPolicy plus a policyMappings
  // P1->P2 generates the P1 node from the anyPolicy node; a leaf asserting the
  // mapped-TO policy P2 validates under explicit policy.
  var interAnyMap = await mkCert({ subject: "AnyMap", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY]), pmExt([[P1m, P2m]])]) });
  var leafAnyMap = await mkCert({ subject: "AnyMapLeaf", issuer: "AnyMap", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resC12 = await run([interAnyMap, leafAnyMap], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("policy mapping generates the ID-P node from anyPolicy", resC12.valid === true);

  // a PSS params SEQUENCE with a malformed primitive [0]
  // field must be rejected, not skipped-and-defaulted.
  var anchorPssPrim = await mkAnchor("pssprim", "PssPrimRoot");
  var leafPssPrim = await mkCert({ subject: "PssPrim", issuer: "PssPrimRoot", signWith: "pssprim", subjectKeys: "ed25519leaf" });
  var resC13 = await run([leafPssPrim], { time: T2027, trustAnchor: anchorPssPrim });
  check("malformed PSS parameter field rejected", resC13.valid === false && failCodes(resC13).indexOf("path/unsupported-algorithm") !== -1);

  // an indirect CRL (IDP indirectCRL) attributes entries by
  // the per-entry certificateIssuer (not tracked here), so it is unusable.
  var crlIndirect = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(6), idpExt({ indirect: true })] });
  var resC14 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlIndirect]) });
  check("indirect CRL is unusable (undetermined)", resC14.valid === false && failCodes(resC14).indexOf("path/revocation-undetermined") !== -1);

  // a CRL with NO nextUpdate has no bounded validity: its
  // currency cannot be confirmed, so it is unusable (a replayed old CRL must
  // not read good).
  var crlNoNext = await mkCrl({ issuer: "Root", signWith: "ed25519", nextUpdate: null });
  var resC15 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlNoNext]) });
  check("CRL without nextUpdate is unusable (undetermined)", resC15.valid === false && failCodes(resC15).indexOf("path/revocation-undetermined") !== -1);

  // a revoked entry marked removeFromCRL (reasonCode 8) is
  // NOT a revocation; the cert is good (covered, un-revoked).
  var crlRemove = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n, exts: [reasonCodeExt(8)] }] });
  var resC16 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlRemove]) });
  check("removeFromCRL entry is not a revocation (good)", resC16.valid === true);

  // a negative RSASSA-PSS saltLength must be rejected (the
  // OpenSSL shim would treat it as RSA_PSS_SALTLEN_AUTO, accepting any salt).
  var anchorNegSalt = await mkAnchor("pssnegsalt", "NegSaltRoot");
  var leafNegSalt = await mkCert({ subject: "NegSalt", issuer: "NegSaltRoot", signWith: "pssnegsalt", subjectKeys: "ed25519leaf" });
  var resC17 = await run([leafNegSalt], { time: T2027, trustAnchor: anchorNegSalt });
  check("negative PSS saltLength rejected", resC17.valid === false && failCodes(resC17).indexOf("path/unsupported-algorithm") !== -1);

  // an oversized RSASSA-PSS saltLength must be rejected before it
  // rounds through Number conversion (exact-or-rejected verifier inputs).
  var anchorBigSalt = await mkAnchor("pssbigsalt", "BigSaltRoot");
  var leafBigSalt = await mkCert({ subject: "BigSalt", issuer: "BigSaltRoot", signWith: "pssbigsalt", subjectKeys: "ed25519leaf" });
  var resC17b = await run([leafBigSalt], { time: T2027, trustAnchor: anchorBigSalt });
  check("oversized PSS saltLength rejected", resC17b.valid === false && failCodes(resC17b).indexOf("path/unsupported-algorithm") !== -1);

  // a trailing-dot dNSName SAN must not escape an excluded
  // dNSName constraint (FQDN root-label normalization).
  var interTd = await mkCert({ subject: "TdInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnDns("evil.com")])]) });
  var leafTd = await mkCert({ subject: "TdLeaf", issuer: "TdInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.evil.com.")])] });
  var resC18 = await run([interTd, leafTd], { time: T2027, trustAnchor: anchor });
  check("trailing-dot dNSName does not escape the exclusion", resC18.valid === false && failCodes(resC18).indexOf("path/name-constraint-excluded") !== -1);

  // a URI SAN with no authority component under a URI
  // constraint cannot be evaluated -> fail closed, not escape.
  var interUriC = await mkCert({ subject: "UriCInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("evil.example")])]) });
  var leafUriC = await mkCert({ subject: "UriCLeaf", issuer: "UriCInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("urn:example:resource")])] });
  var resC19 = await run([interUriC, leafUriC], { time: T2027, trustAnchor: anchor });
  check("hostless URI under a URI constraint fails closed", resC19.valid === false && failCodes(resC19).indexOf("path/name-constraint-unsupported") !== -1);

  // a CRL whose IDP carries a malformed IMPLICIT BOOLEAN
  // (onlyContainsCACerts [2] encoded CONSTRUCTED) has an unknown scope -> the
  // CRL is unusable, not treated as unrestricted-authoritative.
  var idpBadBool = ext("2.5.29.28", true, b.sequence([b.contextConstructed(2, b.octetString(Buffer.from([0xff])))]));
  var crlBadBool = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(7), idpBadBool] });
  var resC20 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlBadBool]) });
  check("malformed IDP BOOLEAN makes the CRL unusable", resC20.valid === false && failCodes(resC20).indexOf("path/revocation-undetermined") !== -1);

  // DER encodes SEQUENCE fields in definition order, at most once -- an IDP
  // carrying [1] twice, or [4] before [1], is not a DER IssuingDistributionPoint,
  // so the scope is unknown and the CRL unusable.
  var idpDupField = ext("2.5.29.28", true, b.sequence([b.contextPrimitive(1, Buffer.from([0xff])), b.contextPrimitive(1, Buffer.from([0xff]))]));
  var crlDupField = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(7), idpDupField] });
  var resC20b = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlDupField]) });
  check("duplicate IDP field makes the CRL unusable", resC20b.valid === false && failCodes(resC20b).indexOf("path/revocation-undetermined") !== -1);
  var idpDisorder = ext("2.5.29.28", true, b.sequence([b.contextPrimitive(4, Buffer.from([0xff])), b.contextPrimitive(1, Buffer.from([0xff]))]));
  var crlDisorder = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(7), idpDisorder] });
  var resC20c = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlDisorder]) });
  check("out-of-order IDP fields make the CRL unusable", resC20c.valid === false && failCodes(resC20c).indexOf("path/revocation-undetermined") !== -1);
  // an explicitly-encoded FALSE is the omitted DEFAULT (X.690 sec. 11.5) -- non-DER.
  var idpFalse = ext("2.5.29.28", true, b.sequence([b.contextPrimitive(1, Buffer.from([0x00]))]));
  var crlFalse = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(7), idpFalse] });
  var resC20d = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFalse]) });
  check("encoded-FALSE IDP flag makes the CRL unusable", resC20d.valid === false && failCodes(resC20d).indexOf("path/revocation-undetermined") !== -1);

  // The validator's own octet-alignment guard (a signature BIT STRING with a non-zero unused-bit
  // count) is defense in depth behind the strict DER codec, which rejects such bytes at parse. It
  // used to be reachable by editing a PARSED certificate -- which is exactly the route that is now
  // closed: a certificate reaching a verdict is re-derived from the bytes its parser read, so an
  // edit made afterwards is discarded rather than believed.
  //
  // That leaves the guard with no route from the public verb, so what is pinned here is the door
  // that closed it. This is the stronger property: the old vector showed one hand-made malformation
  // being caught, while this shows that no hand-made certificate is answered from at all -- and the
  // substitution that matters is not a broken signature but a VALID one beside a swapped key.
  var alignedDer = await mkCert({ subject: "Aligned", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var leafC21 = pki.schema.x509.parse(alignedDer);
  var editedC21 = Object.assign({}, leafC21, { signatureValue: { unusedBits: 3, bytes: leafC21.signatureValue.bytes } });
  check("an edited certificate is refused rather than walked",
    (await codeOf(run([editedC21], { time: T2027, trustAnchor: anchor }))) === "path/bad-input");
  // The attack the re-derivation exists for: a genuine certificate's signed bytes and signature
  // beside somebody else's public key. Every field is well-formed and the signature verifies over
  // the original range, so no completeness or signature check can see it -- only provenance can.
  var otherKeyCert = pki.schema.x509.parse(await mkCert({ subject: "Other", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i" }));
  var swappedKey = Object.assign({}, leafC21, { subjectPublicKeyInfo: otherKeyCert.subjectPublicKeyInfo });
  check("a genuine certificate with a substituted public key is refused",
    (await codeOf(run([swappedKey], { time: T2027, trustAnchor: anchor }))) === "path/bad-input");
  // ...while the parser's own unmodified result still validates, so the rule costs a caller nothing.
  var resC21 = await run([leafC21], { time: T2027, trustAnchor: anchor });
  check("the parser's own certificate object still validates", resC21.valid === true);

  // A fixed-parameter algorithm carrying the WRONG parameter shape — Ed25519
  // with a stray DER NULL where RFC 8410 §3 requires the parameters ABSENT — is
  // now rejected fail-closed at PARSE by the shared AlgorithmIdentifier guard,
  // before the path validator runs. (The validator's own params-shape check
  // remains as defense-in-depth for a hand-built parsed path.)
  var ecNullParams = b.sequence([b.oid("1.3.101.112"), b.nullValue()]);   // Ed25519 OID + a stray NULL
  var leafWrongParams = await mkCert({ subject: "WrongP", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: ecNullParams });
  var wrongParamsCode;
  try { pki.schema.x509.parse(leafWrongParams); } catch (e) { wrongParamsCode = e.code; }
  check("EdDSA with a stray NULL parameter rejected at parse (RFC 8410 §3 params-absent)", wrongParamsCode === "x509/bad-algorithm-parameters");

  // Algorithm confusion (RFC 9814 §4 consistency): a certificate SIGNED by the
  // issuer's Ed25519 key but LABELING its signatureAlgorithm as a one-shot PQC
  // OID must NOT validate. Node's WebCrypto imports a mismatched SPKI under the
  // requested PQC name and verifies with the real key, so the issuer-key ↔
  // signature-algorithm consistency is enforced structurally (the key algorithm
  // OID must equal the signature OID for the same-OID one-shot families).
  var edConfAnchor = await mkAnchor("ed25519", "EdConfRoot");
  var slhLabel = b.sequence([b.oid("2.16.840.1.101.3.4.3.21")]);   // id-slh-dsa-sha2-128f, params absent
  var confusedSlh = await mkCert({ subject: "ConfSlh", issuer: "EdConfRoot", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: slhLabel });
  var resConfSlh = await run([confusedSlh], { time: T2027, trustAnchor: edConfAnchor });
  check("Ed25519-signed cert labeled SLH-DSA rejected (no algorithm confusion)",
    resConfSlh.valid === false && failCodes(resConfSlh).indexOf("path/algorithm-mismatch") !== -1);
  var mlLabel = b.sequence([b.oid("2.16.840.1.101.3.4.3.18")]);   // id-ml-dsa-65, params absent
  var confusedMl = await mkCert({ subject: "ConfMl", issuer: "EdConfRoot", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: mlLabel });
  var resConfMl = await run([confusedMl], { time: T2027, trustAnchor: edConfAnchor });
  check("Ed25519-signed cert labeled ML-DSA rejected (no algorithm confusion)",
    resConfMl.valid === false && failCodes(resConfMl).indexOf("path/algorithm-mismatch") !== -1);

  // a SHA-1 PSS signature is rejected (SHA-1 is dropped from
  // the supported set, matching the no-sha1WithRSAEncryption posture).
  var anchorSha1 = await mkAnchor("psssha1", "Sha1Root");
  var leafSha1 = await mkCert({ subject: "Sha1Pss", issuer: "Sha1Root", signWith: "psssha1", subjectKeys: "ed25519leaf" });
  var resC23 = await run([leafSha1], { time: T2027, trustAnchor: anchorSha1 });
  check("SHA-1 PSS signature rejected", resC23.valid === false && failCodes(resC23).indexOf("path/unsupported-algorithm") !== -1);

  // a PSS AlgorithmIdentifier declaring an explicit SHA-256
  // hash but OMITTING maskGenAlgorithm (RFC 4055 default mgf1SHA1) must be
  // rejected, not verified as SHA-256/MGF1-SHA256.
  var anchorNoMgf = await mkAnchor("pssnomgf", "NoMgfRoot");
  var leafNoMgf = await mkCert({ subject: "NoMgf", issuer: "NoMgfRoot", signWith: "pssnomgf", subjectKeys: "ed25519leaf" });
  var resC24 = await run([leafNoMgf], { time: T2027, trustAnchor: anchorNoMgf });
  check("PSS with absent maskGenAlgorithm rejected (SHA-1 default)", resC24.valid === false && failCodes(resC24).indexOf("path/unsupported-algorithm") !== -1);

  // a NUL byte in the leaf SUBJECT DN must not crash the
  // validate() promise (selfIssued's dnEqual throws on a NUL; the throw must
  // be swallowed to a structured verdict). A directoryName name constraint
  // over such a subject additionally fails the path closed.
  var nulRdn = [b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("a" + String.fromCharCode(0) + "b")])])];
  var nulLeaf = await mkCert({ subject: nulRdn, issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var res25threw = false;
  try { await run([nulLeaf], { time: T2027, trustAnchor: anchor }); }
  catch (_e) { res25threw = true; }
  check("NUL in subject DN yields a verdict, not an uncaught throw", res25threw === false);
  var interDirNul = await mkCert({ subject: "DirNulInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnDirectoryName(nameDer("X"))], null)]) });
  var nulLeaf2 = await mkCert({ subject: nulRdn, issuer: "DirNulInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res25b = await run([interDirNul, nulLeaf2], { time: T2027, trustAnchor: anchor });
  check("NUL subject under a directoryName constraint fails closed", res25b.valid === false);

  // a CRL with a revoked entry carrying an UNKNOWN CRITICAL
  // CRL-entry extension is unusable for any cert (§5.3) -> undetermined.
  var critEntryExt = ext("1.3.6.1.4.1.99999.43", true, b.octetString(Buffer.from([1])));
  var crlCritEntry = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1234n, exts: [critEntryExt] }] });
  var resC26 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCritEntry]) });
  check("unknown critical CRL-entry extension makes the CRL unusable", resC26.valid === false && failCodes(resC26).indexOf("path/revocation-undetermined") !== -1);

  // The same rule on the CRL side of the door: crlChecker takes bytes or the CRL
  // parser's output, and the unusable-CRL check above reads each entry extension's
  // `critical`. An entry extension with the property removed would read as
  // non-critical and the CRL would be used, so the shape requires it there too.
  var crlCritParsed = pki.schema.crl.parse(crlCritEntry);
  var crlCritNoFlag = Object.assign({}, crlCritParsed, {
    revokedCertificates: crlCritParsed.revokedCertificates.map(function (r) {
      return Object.assign({}, r, {
        crlEntryExtensions: r.crlEntryExtensions.map(function (e) {
          var copy = Object.assign({}, e);
          if (copy.oid === "1.3.6.1.4.1.99999.43") delete copy.critical;
          return copy;
        }),
      });
    }),
  });
  // crlChecker screens its CRLs when it is BUILT, so the door fires before validate
  // is entered -- the call is deferred into the promise chain to catch it either way.
  check("a CRL-entry extension stripped of its criticality flag is refused at the door",
    (await codeOf(Promise.resolve().then(function () {
      return run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCritNoFlag]) });
    }))) === "path/bad-input");

  // RFC 5280 6.1.3(d)(1)(ii): the child-from-anyPolicy fallback is
  // UNCONDITIONAL — inhibit_anyPolicy (4.2.1.14) gates only the (d)(2)
  // expansion of a cert-asserted anyPolicy. An intermediate asserting anyPolicy
  // with inhibitAnyPolicy:0 then a leaf asserting P1: P1 chains through the
  // depth-1 anyPolicy node (created while processing was active), so explicit
  // policy is satisfied and the user-constrained set is [P1].
  var interIapC = await mkCert({ subject: "IapC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY]), iapExt(0)]) });
  var leafIapC = await mkCert({ subject: "IapCLeaf", issuer: "IapC", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1m])] });
  var resC27 = await run([interIapC, leafIapC], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("anyPolicy fallback unconditional under an exhausted inhibit counter", resC27.valid === true && resC27.userConstrainedPolicySet.indexOf(P1m) !== -1);

  // a URI SAN with an empty authority cannot be evaluated
  // against a URI constraint -> fail closed, not escape.
  var interUriE = await mkCert({ subject: "UriEInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("evil.example")])]) });
  var leafUriE = await mkCert({ subject: "UriELeaf", issuer: "UriEInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https:///path")])] });
  var resC28 = await run([interUriE, leafUriE], { time: T2027, trustAnchor: anchor });
  check("empty-authority URI fails closed under a URI constraint", resC28.valid === false && failCodes(resC28).indexOf("path/name-constraint-unsupported") !== -1);

  // a PSS params SEQUENCE with an unexpected [4] field is a
  // structural fault and must be rejected.
  var anchorPssX = await mkAnchor("pssextra", "PssXRoot");
  var leafPssX = await mkCert({ subject: "PssX", issuer: "PssXRoot", signWith: "pssextra", subjectKeys: "ed25519leaf" });
  var resC29 = await run([leafPssX], { time: T2027, trustAnchor: anchorPssX });
  check("unexpected PSS parameter field rejected", resC29.valid === false && failCodes(resC29).indexOf("path/unsupported-algorithm") !== -1);

  // the unhandled-critical-entry check keys on the STABLE
  // OID, not the display name: a custom OID aliased to the name "reasonCode"
  // must still be treated as unhandled (the CRL is unusable). Registered last so
  // it cannot perturb earlier OID resolutions in this file.
  var FAKE_REASON = "1.3.6.1.4.1.99999.77";
  pki.oid.register(FAKE_REASON, "reasonCode");
  var fakeReasonEntryExt = ext(FAKE_REASON, true, b.octetString(Buffer.from([1])));
  var crlFakeReason = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1234n, exts: [fakeReasonEntryExt] }] });
  var resC30 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFakeReason]) });
  check("critical entry ext keyed by OID not display name (unusable)", resC30.valid === false && failCodes(resC30).indexOf("path/revocation-undetermined") !== -1);

  // a revocationChecker returning a status OUTSIDE
  // good/revoked/unknown (an OCSP tryLater/unauthorized, a typo) must be treated
  // as undetermined and fail closed, never as a pass.
  var oddChecker = { check: function () { return Promise.resolve({ status: "tryLater" }); } };
  var leafC31 = await mkCert({ subject: "C31", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var resC31 = await run([leafC31], { time: T2027, trustAnchor: anchor, revocationChecker: oddChecker });
  check("unexpected revocation status fails closed", resC31.valid === false && failCodes(resC31).indexOf("path/revocation-undetermined") !== -1);
  // ...and softFail opts the SAME unexpected status into a pass.
  var resC31s = await run([leafC31], { time: T2027, trustAnchor: anchor, revocationChecker: oddChecker, softFail: true });
  check("softFail opts unexpected status into a pass", resC31s.valid === true);

  // an RSASSA-PSS hashAlgorithm [0] EXPLICIT wrapping a BARE
  // OID (not an AlgorithmIdentifier SEQUENCE) is malformed and must fail closed,
  // never be read leniently as SHA-256. Same for the MGF1 hash parameter.
  var pssBareHash = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-bare-hash" });
  var leafC32a = await mkCert({ subject: "C32a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssBareHash });
  var resC32a = await run([leafC32a], { time: T2027, trustAnchor: anchor });
  check("PSS hashAlgorithm as a bare OID (no AlgorithmIdentifier SEQUENCE) rejected", resC32a.valid === false && failCodes(resC32a).indexOf("path/unsupported-algorithm") !== -1);
  var pssBareMgf = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-bare-mgfhash" });
  var leafC32b = await mkCert({ subject: "C32b", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssBareMgf });
  var resC32b = await run([leafC32b], { time: T2027, trustAnchor: anchor });
  check("PSS MGF1 hash as a bare OID rejected", resC32b.valid === false && failCodes(resC32b).indexOf("path/unsupported-algorithm") !== -1);
  // an RSASSA-PSS hashAlgorithm parameters field that is a NULL with NON-EMPTY
  // content is malformed DER — the right tag but not a well-formed empty NULL
  // (X.690 8.8.2); a tag-only check would accept it. Must fail closed.
  var pssHashNullNe = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-hash-nullparams-nonempty" });
  var leafC32c = await mkCert({ subject: "C32c", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssHashNullNe });
  var resC32c = await run([leafC32c], { time: T2027, trustAnchor: anchor });
  check("PSS hashAlgorithm NULL parameters with non-empty content rejected", resC32c.valid === false && failCodes(resC32c).indexOf("path/unsupported-algorithm") !== -1);

  // the returned validPolicyTree must be acyclic: no internal
  // `parent` back-pointer, so a caller can JSON.stringify(result) on a
  // policy-bearing chain without throwing on a circular reference.
  var P33 = "1.3.6.1.4.1.99999.33";
  var interC33 = await mkCert({ subject: "C33i", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P33])]) });
  var leafC33 = await mkCert({ subject: "C33l", issuer: "C33i", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P33])] });
  var resC33 = await run([interC33, leafC33], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P33] });
  var c33Serialized = true;
  try { JSON.stringify(resC33.validPolicyTree); } catch (_e) { c33Serialized = false; }
  check("policy tree is JSON-serializable (acyclic, no circular parent)", resC33.valid === true && resC33.validPolicyTree !== null && c33Serialized);
  var c33NoParent = (function noParent(node) { if (!node) return true; if ("parent" in node) return false; return node.children.every(noParent); });
  check("returned policy tree carries no parent back-pointer", c33NoParent(resC33.validPolicyTree));

  // RFC 5280 requires basicConstraints (4.2.1.9),
  // nameConstraints (4.2.1.10), policyConstraints (4.2.1.11) and
  // inhibitAnyPolicy (4.2.1.14) on a CA certificate to be marked CRITICAL. A
  // non-critical form is non-conforming: a relying party that skips
  // non-critical extensions would not see the constraint. Fail closed on each.
  var interNCBC = await mkCert({ subject: "NCBCi", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [ext("2.5.29.19", false, bcVal(true)), kuExt([KU_KEY_CERT_SIGN])] });
  var leafNCBC = await mkCert({ subject: "NCBCl", issuer: "NCBCi", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var resC34a = await run([interNCBC, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("non-critical CA basicConstraints rejected", resC34a.valid === false && failCodes(resC34a).indexOf("path/extension-not-critical") !== -1);
  // control: the critical form of the SAME chain validates.
  var interCBC = await mkCert({ subject: "NCBCi", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([]) });
  var resC34ctl = await run([interCBC, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("control: critical basicConstraints validates", resC34ctl.valid === true);

  var interNCnc = await mkCert({ subject: "NCnci", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ext("2.5.29.30", false, ncVal([gnDns("example.com")], null))]) });
  var resC34b = await run([interNCnc, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("non-critical nameConstraints rejected", resC34b.valid === false && failCodes(resC34b).indexOf("path/extension-not-critical") !== -1);

  var interNCpc = await mkCert({ subject: "NCpci", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ext("2.5.29.36", false, b.sequence([b.contextPrimitive(0, intContent(0))]))]) });
  var resC34c = await run([interNCpc, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("non-critical policyConstraints rejected", resC34c.valid === false && failCodes(resC34c).indexOf("path/extension-not-critical") !== -1);

  var interNCiap = await mkCert({ subject: "NCiapi", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ext("2.5.29.54", false, b.integer(0n))]) });
  var resC34d = await run([interNCiap, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("non-critical inhibitAnyPolicy rejected", resC34d.valid === false && failCodes(resC34d).indexOf("path/extension-not-critical") !== -1);

  // A revocation is effective as of its revocationDate (RFC 5280 §5.3).
  // thisUpdate(2027-01-01) <= T2027 <= nextUpdate(2028-06-01).
  var crlFutureRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, date: new Date("2027-12-01T00:00:00Z") }] });
  // DEFAULT (present-time) validation is STRICT per §6.3.3: a listed serial is
  // revoked regardless of a future revocationDate (post-dating / clock skew must
  // not read good).
  var resFutStrict = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFutureRev]) });
  check("future revocationDate is revoked by default (strict §6.3.3)", resFutStrict.valid === false && failCodes(resFutStrict).indexOf("path/revoked") !== -1);
  // Under an EXPLICIT historical validation, a revocation dated AFTER the
  // validation instant is not yet effective (validating a timestamped signature).
  var resFutHist = await run([leafCrl], { time: T2027, trustAnchor: anchor, historicalMode: true, revocationChecker: pki.path.crlChecker([crlFutureRev]) });
  check("historicalMode: future revocationDate is not yet effective", resFutHist.valid === true);
  // control: a revocationDate at/before the instant IS a revocation in either mode.
  var crlPastRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, date: new Date("2027-03-01T00:00:00Z") }] });
  var resC35b = await run([leafCrl], { time: T2027, trustAnchor: anchor, historicalMode: true, revocationChecker: pki.path.crlChecker([crlPastRev]) });
  check("control: revocationDate at/before the instant is revoked", resC35b.valid === false && failCodes(resC35b).indexOf("path/revoked") !== -1);

  // an AlgorithmIdentifier is { OID, parameters? }: at most
  // one optional parameters element, and a PSS hash's parameters must be NULL.
  // A spurious third element or non-NULL hash parameters is malformed and must
  // fail closed rather than be read leniently as its named hash.
  var pssHashExtra = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-hash-extra" });
  var resC36a = await run([await mkCert({ subject: "C36a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssHashExtra })], { time: T2027, trustAnchor: anchor });
  check("PSS hashAlgorithm with a spurious third element rejected", resC36a.valid === false && failCodes(resC36a).indexOf("path/unsupported-algorithm") !== -1);
  var pssHashBad = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-hash-badparams" });
  var resC36b = await run([await mkCert({ subject: "C36b", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssHashBad })], { time: T2027, trustAnchor: anchor });
  check("PSS hashAlgorithm with non-NULL parameters rejected", resC36b.valid === false && failCodes(resC36b).indexOf("path/unsupported-algorithm") !== -1);
  var pssMgfExtra = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-mgfhash-extra" });
  var resC36c = await run([await mkCert({ subject: "C36c", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssMgfExtra })], { time: T2027, trustAnchor: anchor });
  check("PSS MGF1 hash with a spurious third element rejected", resC36c.valid === false && failCodes(resC36c).indexOf("path/unsupported-algorithm") !== -1);

  // policyMappings is semantically processed ONLY in prepare-
  // for-next (§6.1.4(a),(b)), which is skipped for the target cert. A critical
  // policyMappings on the leaf is therefore unprocessed and must fail closed —
  // otherwise a critical mapping to/from anyPolicy bypasses the §6.1.4(a)
  // rejection. policyMappings is SHOULD-be-non-critical (§4.2.1.5), so this does
  // not over-reject a conforming certificate.
  var leafPmCrit = await mkCert({ subject: "PmCrit", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [pmExt([[P1m, P2m]])] });
  var resC37a = await run([leafPmCrit], { time: T2027, trustAnchor: anchor });
  check("critical policyMappings on the target rejected as unprocessed", resC37a.valid === false && failCodes(resC37a).indexOf("path/unrecognized-critical-extension") !== -1);
  // the anyPolicy-mapping bypass specifically (critical):
  var leafPmAny = await mkCert({ subject: "PmAny", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [pmExt([[ANY_POLICY, P2m]])] });
  var resC37b = await run([leafPmAny], { time: T2027, trustAnchor: anchor });
  check("critical anyPolicy mapping on the target rejected", resC37b.valid === false && failCodes(resC37b).indexOf("path/unrecognized-critical-extension") !== -1);
  // a NON-critical anyPolicy mapping on the target is caught by the structural rule.
  var leafPmAnyNC = await mkCert({ subject: "PmAnyNC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.33", false, b.sequence([b.sequence([b.oid(ANY_POLICY), b.oid(P2m)])]))] });
  var resC37c = await run([leafPmAnyNC], { time: T2027, trustAnchor: anchor });
  check("non-critical anyPolicy mapping on the target rejected (structural)", resC37c.valid === false && failCodes(resC37c).indexOf("path/bad-policy") !== -1);
  // control: a critical policyMappings on an INTERMEDIATE still processes normally.
  var interPm = await mkCert({ subject: "PmInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m]), pmExt([[P1m, P2m]])]) });
  var leafPmOk = await mkCert({ subject: "PmLeaf", issuer: "PmInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resC37d = await run([interPm, leafPmOk], { time: T2027, trustAnchor: anchor });
  check("control: critical policyMappings on an intermediate still validates", resC37d.valid === true);

  // each RSASSA-PSS-params field is an EXPLICIT [n] wrapper around EXACTLY
  // ONE value. A wrapper carrying more than one child is malformed: reading
  // children[0] and ignoring the rest would accept non-DER parameters.
  var pssMultiSalt = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-multichild-salt" });
  var resC38a = await run([await mkCert({ subject: "C38a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssMultiSalt })], { time: T2027, trustAnchor: anchor });
  check("multi-child EXPLICIT [2] saltLength wrapper rejected", resC38a.valid === false && failCodes(resC38a).indexOf("path/unsupported-algorithm") !== -1);
  var pssMultiMgf = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-multichild-mgf" });
  var resC38b = await run([await mkCert({ subject: "C38b", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssMultiMgf })], { time: T2027, trustAnchor: anchor });
  check("multi-child EXPLICIT [1] maskGenAlgorithm wrapper rejected", resC38b.valid === false && failCodes(resC38b).indexOf("path/unsupported-algorithm") !== -1);

  // A certificate rfc822Name with more than one "@" (a quoted local part such as
  // "a@b"@example.com) is ambiguous: its domain cannot be determined, so an
  // rfc822Name name constraint fails CLOSED rather than parse a bogus host that
  // could slip the constraint (RFC 5280 4.2.1.6 / RFC 5321 addr-spec).
  var interEmAmb = await mkCert({ subject: "EmAmbInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail("example.com")])]) });
  var leafEmAmb = await mkCert({ subject: "EmAmbLeaf", issuer: "EmAmbInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("\"a@b\"@example.com")])] });
  var resEmAmb = await run([interEmAmb, leafEmAmb], { time: T2027, trustAnchor: anchor });
  check("multi-@ rfc822Name fails closed under a name constraint", resEmAmb.valid === false && failCodes(resEmAmb).indexOf("path/name-constraint-unsupported") !== -1);
  // control: a single-@ mailbox at the excluded host is still matched and rejected.
  var leafEmOk = await mkCert({ subject: "EmOkLeaf", issuer: "EmAmbInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("u@example.com")])] });
  var resEmOk = await run([interEmAmb, leafEmOk], { time: T2027, trustAnchor: anchor });
  check("control: single-@ mailbox at the excluded host is rejected", resEmOk.valid === false && failCodes(resEmOk).indexOf("path/name-constraint-excluded") !== -1);

  // A URI authority with more than one "@" is likewise ambiguous (RFC 3986
  // userinfo carries no raw "@"), so a uniformResourceIdentifier constraint
  // fails closed instead of extracting a guessed host.
  var interUriAmb = await mkCert({ subject: "UriAmbInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("evil.com")])]) });
  var leafUriAmb = await mkCert({ subject: "UriAmbLeaf", issuer: "UriAmbInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://a@b@evil.com/")])] });
  var resUriAmb = await run([interUriAmb, leafUriAmb], { time: T2027, trustAnchor: anchor });
  check("multi-@ URI authority fails closed under a name constraint", resUriAmb.valid === false && failCodes(resUriAmb).indexOf("path/name-constraint-unsupported") !== -1);

  // RFC 5280 §6.3.3(f): cRLSign is required only when keyUsage is PRESENT. An
  // issuer that omits keyUsage is unconstrained — the same rule §6.1.4(n) applies
  // to certificate signing — so its current, verified CRL is authoritative.
  var rootCrlCov = await mkCrl({ issuer: "Root", signWith: "ed25519" });   // covers the intermediate
  var interNoKu = await mkCert({ subject: "NoKuInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true)] });
  var leafNoKu = await mkCert({ subject: "NoKuLeaf", issuer: "NoKuInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", serial: 5151n });
  var crlNoKu = await mkCrl({ issuer: "NoKuInter", signWith: "ed25519i" });
  var resNoKu = await run([interNoKu, leafNoKu], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrlCov, crlNoKu]) });
  check("CRL signer that omits keyUsage is authoritative (cRLSign required only when keyUsage present)", resNoKu.valid === true);
  // a signer WITH keyUsage but WITHOUT cRLSign is not authorized -> undetermined.
  var interKuNoCrl = await mkCert({ subject: "KuNoCrlInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leafKuNoCrl = await mkCert({ subject: "KuNoCrlLeaf", issuer: "KuNoCrlInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", serial: 5153n });
  var crlKuNoCrl = await mkCrl({ issuer: "KuNoCrlInter", signWith: "ed25519i" });
  var resKuNoCrl = await run([interKuNoCrl, leafKuNoCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrlCov, crlKuNoCrl]) });
  check("CRL signer with keyUsage but no cRLSign yields undetermined", resKuNoCrl.valid === false && failCodes(resKuNoCrl).indexOf("path/revocation-undetermined") !== -1);
  // control: the same intermediate WITH keyUsage cRLSign produces an authoritative CRL.
  var interKu = await mkCert({ subject: "KuInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519j", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN, KU_CRL_SIGN])] });
  var leafKu = await mkCert({ subject: "KuLeaf", issuer: "KuInter", signWith: "ed25519j", subjectKeys: "ed25519leaf", serial: 5152n });
  var crlKu = await mkCrl({ issuer: "KuInter", signWith: "ed25519j" });
  var resKu = await run([interKu, leafKu], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrlCov, crlKu]) });
  check("control: CRL signer with keyUsage cRLSign is authoritative", resKu.valid === true);

  // A delta CRL (deltaCRLIndicator) lists only the changes since a base CRL;
  // without base/delta processing it is unusable on its own — a serial absent
  // from it is NOT "good" — even when the indicator is non-critical (RFC 5280
  // 5.2.4). The critical form is likewise unusable.
  var crlDeltaNC = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [ext("2.5.29.27", false, b.integer(3n))] });
  var resDeltaNC = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlDeltaNC]) });
  check("non-critical delta CRL is unusable (undetermined)", resDeltaNC.valid === false && failCodes(resDeltaNC).indexOf("path/revocation-undetermined") !== -1);
  var crlDeltaC = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [ext("2.5.29.27", true, b.integer(3n))] });
  var resDeltaC = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlDeltaC]) });
  check("critical delta CRL is unusable (undetermined)", resDeltaC.valid === false && failCodes(resDeltaC).indexOf("path/revocation-undetermined") !== -1);
  // a clean base CRL must NOT override an AUTHORITATIVE delta that lists the
  // serial: the delta (current + verified) reveals the revocation, so the cert
  // is revoked — never "good" (else a certificate the delta revokes is accepted).
  var baseCleanCrl = await mkCrl({ issuer: "Root", signWith: "ed25519" });
  var deltaRevoking = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }], extensions: [ext("2.5.29.27", true, b.integer(1n))] });
  var resBaseDelta = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([baseCleanCrl, deltaRevoking]) });
  check("an authoritative delta listing the serial revokes despite a clean base", resBaseDelta.valid === false && failCodes(resBaseDelta).indexOf("path/revoked") !== -1);
  // a STALE or unverifiable delta must NOT block a good result from a valid base
  // (the delta is acted on only after its own currency/signature checks pass).
  var staleDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", nextUpdate: new Date("2026-06-01T00:00:00Z"), extensions: [ext("2.5.29.27", true, b.integer(1n))] });
  var resStaleDelta = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([baseCleanCrl, staleDelta]) });
  check("a stale delta does not block a good result from a valid base", resStaleDelta.valid === true);
  // A delta that RELEASES the serial from hold (removeFromCRL) must prevent a
  // definitive revoked from a base CRL that still lists it — without base/delta
  // merging the status is undetermined, so a released cert is not stuck rejected.
  var baseRevoking = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }] });
  var deltaRelease = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }], extensions: [ext("2.5.29.27", true, b.integer(1n))] });
  var resDeltaRel = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([baseRevoking, deltaRelease]) });
  check("delta removeFromCRL prevents a definitive revoked from the base (undetermined)", resDeltaRel.valid === false && failCodes(resDeltaRel).indexOf("path/revocation-undetermined") !== -1);
  // control: the same base revocation WITHOUT a delta removal is still revoked.
  var resBaseOnlyRev = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([baseRevoking]) });
  check("control: base revocation with no delta removal is revoked", resBaseOnlyRev.valid === false && failCodes(resBaseOnlyRev).indexOf("path/revoked") !== -1);

  // A CRL whose issuer DN carries an embedded NUL (CVE-2009-2408) makes dnEqual
  // throw; it must be treated as unusable and SKIPPED, not abort the whole
  // revocation check — a valid revoking CRL later in the bundle must still be
  // consulted (else the malformed CRL masks it and passes under softFail).
  var nulIssuerRdn = [b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("R" + String.fromCharCode(0) + "oot")])])];
  var crlNulIssuer = await mkCrl({ issuer: nulIssuerRdn, signWith: "ed25519" });
  var crlRealRevoke = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }] });
  var resNulMask = await run([leafCrl], { time: T2027, trustAnchor: anchor, softFail: true, revocationChecker: pki.path.crlChecker([crlNulIssuer, crlRealRevoke]) });
  check("a malformed-issuer CRL is skipped, not masking a valid revoking CRL", resNulMask.valid === false && failCodes(resNulMask).indexOf("path/revoked") !== -1);

  // The internal resolveDescriptor fallback that turns an asn1/* fault from malformed
  // signatureAlgorithm.parameters into path/unsupported-algorithm has no route left from the public
  // verb: such parameters are refused by the AlgorithmIdentifier guard at PARSE, and the other route
  // -- editing them onto a parsed certificate -- is what the re-derivation now discards. Verified
  // unreachable rather than forced: the fallback stays as defense in depth for a future decoder that
  // admits a shape this one does not, and what is pinned here is the door that closed the edit.
  var anchorPssParam = await mkAnchor("rsapss", "PssRoot");
  var pssParsed = pki.schema.x509.parse(await mkCert({ subject: "PssBadParam", issuer: "PssRoot", signWith: "rsapss", subjectKeys: "ed25519leaf" }));
  var pssEdited = Object.assign({}, pssParsed, {
    signatureAlgorithm: { oid: pssParsed.signatureAlgorithm.oid, name: pssParsed.signatureAlgorithm.name, parameters: Buffer.from([0x30, 0x03, 0x02, 0x81, 0x01]) },
  });
  check("a certificate with edited algorithm parameters is refused, not walked",
    (await codeOf(run([pssEdited], { time: T2027, trustAnchor: anchorPssParam }))) === "path/bad-input");
  var resPssOk = await run([pssParsed], { time: T2027, trustAnchor: anchorPssParam });
  check("...while the unmodified RSASSA-PSS certificate still validates", resPssOk.valid === true);

  // RFC 5280 4.2.1.10: the legacy emailAddress in the subject DN is checked as an
  // rfc822Name UNLESS the SAN carries the email identity as an rfc822Name entry.
  // A SAN of a DIFFERENT form (dNSName only) does NOT cover the email, so an
  // excluded DN email must still be rejected — not bypassed.
  var interEmSan = await mkCert({ subject: "EmSanInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail("banned.example")])]) });
  var emSanRdn = [b.set([atv("2.5.4.3", "EmSanLeaf")]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5("user@banned.example")])])];
  var leafEmSan = await mkCert({ subject: emSanRdn, issuer: "EmSanInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("good.example")])] });
  var resEmSan = await run([interEmSan, leafEmSan], { time: T2027, trustAnchor: anchor });
  check("excluded subject-DN email is constrained when the SAN has no rfc822Name entry", resEmSan.valid === false && failCodes(resEmSan).indexOf("path/name-constraint-excluded") !== -1);
  // control: with NO SAN, the legacy emailAddress IS constrained (excluded).
  var leafEmNoSan = await mkCert({ subject: emSanRdn, issuer: "EmSanInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var resEmNoSan = await run([interEmSan, leafEmNoSan], { time: T2027, trustAnchor: anchor });
  check("control: legacy subject emailAddress IS constrained without a SAN", resEmNoSan.valid === false && failCodes(resEmNoSan).indexOf("path/name-constraint-excluded") !== -1);
  // control: when the SAN DOES carry an rfc822Name (the authoritative email), the
  // legacy DN email is NOT additionally constrained — the SAN email is checked.
  var leafEmRfcSan = await mkCert({ subject: emSanRdn, issuer: "EmSanInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("user@ok.example")])] });
  var resEmRfcSan = await run([interEmSan, leafEmRfcSan], { time: T2027, trustAnchor: anchor });
  check("control: an rfc822Name SAN suppresses the legacy DN-email check", resEmRfcSan.valid === true);

  // RFC 5280 4.2.1.10: a URI SAN whose authority host is not a FQDN (an IP
  // literal or a dotless label such as localhost) cannot be matched against a
  // URI constraint — fail closed rather than pass it as an ordinary non-match.
  var interUriFqdn = await mkCert({ subject: "UriFqdnInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("evil.com")])]) });
  var leafUriIp = await mkCert({ subject: "UriIpLeaf", issuer: "UriFqdnInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://127.0.0.1/")])] });
  var resUriIp = await run([interUriFqdn, leafUriIp], { time: T2027, trustAnchor: anchor });
  check("URI SAN with an IP-literal host fails closed under a URI constraint", resUriIp.valid === false && failCodes(resUriIp).indexOf("path/name-constraint-unsupported") !== -1);
  var leafUriLocal = await mkCert({ subject: "UriLocalLeaf", issuer: "UriFqdnInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://localhost/")])] });
  var resUriLocal = await run([interUriFqdn, leafUriLocal], { time: T2027, trustAnchor: anchor });
  check("URI SAN with a dotless host fails closed under a URI constraint", resUriLocal.valid === false && failCodes(resUriLocal).indexOf("path/name-constraint-unsupported") !== -1);
  // control: a FQDN URI host outside the excluded set validates.
  var leafUriOk = await mkCert({ subject: "UriOkLeaf", issuer: "UriFqdnInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://good.example/")])] });
  var resUriOk = await run([interUriFqdn, leafUriOk], { time: T2027, trustAnchor: anchor });
  check("control: FQDN URI host outside the excluded set validates", resUriOk.valid === true);
  // RFC 5280 4.2.1.10: a URI CONSTRAINT must itself be an FQDN (a host or a
  // .domain), not a full URI. A malformed constraint cannot be matched and must
  // fail closed rather than silently never-match (ignoring a critical exclusion).
  var interUriBadC = await mkCert({ subject: "UriBadCInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("http://blocked.example")])]) });
  var leafUriBadC = await mkCert({ subject: "UriBadCLeaf", issuer: "UriBadCInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://blocked.example/")])] });
  var resUriBadC = await run([interUriBadC, leafUriBadC], { time: T2027, trustAnchor: anchor });
  check("malformed (non-FQDN) URI constraint fails closed", resUriBadC.valid === false && failCodes(resUriBadC).indexOf("path/name-constraint-unsupported") !== -1);

  // RFC 5280 4.2.1.11: policyConstraints MUST be critical — on the TARGET cert
  // too. The wrap-up applies it, so a non-critical policyConstraints on the leaf
  // must fail closed consistently with the intermediate path.
  var leafPcNC = await mkCert({ subject: "PcTargetNC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.36", false, b.sequence([b.contextPrimitive(1, intContent(0))]))] });
  var resPcNC = await run([leafPcNC], { time: T2027, trustAnchor: anchor });
  check("non-critical policyConstraints on the target cert rejected", resPcNC.valid === false && failCodes(resPcNC).indexOf("path/extension-not-critical") !== -1);
  // control: a critical policyConstraints on the target is accepted.
  var leafPcC = await mkCert({ subject: "PcTargetC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.36", true, b.sequence([b.contextPrimitive(1, intContent(0))]))] });
  var resPcC = await run([leafPcC], { time: T2027, trustAnchor: anchor });
  check("control: critical policyConstraints on the target is accepted", resPcC.valid === true);

  // RFC 5321: an rfc822Name local part is case-SENSITIVE; only the host folds
  // case-insensitively. A permitted full-mailbox constraint must not admit a
  // different-case local part.
  var interEmCase = await mkCert({ subject: "EmCaseInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnEmail("Admin@example.com")], null)]) });
  var leafEmCaseBad = await mkCert({ subject: "EmCaseBad", issuer: "EmCaseInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("admin@example.com")])] });
  var resEmCaseBad = await run([interEmCase, leafEmCaseBad], { time: T2027, trustAnchor: anchor });
  check("different-case local part is not admitted by a full-mailbox permit", resEmCaseBad.valid === false && failCodes(resEmCaseBad).indexOf("path/name-constraint-not-permitted") !== -1);
  // control: the exact-case local part with a case-folded host is permitted.
  var leafEmCaseOk = await mkCert({ subject: "EmCaseOk", issuer: "EmCaseInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("Admin@EXAMPLE.com")])] });
  var resEmCaseOk = await run([interEmCase, leafEmCaseOk], { time: T2027, trustAnchor: anchor });
  check("control: exact local part with a case-folded host is permitted", resEmCaseOk.valid === true);

  // RFC 5280 4.2.1.10: an rfc822Name host is canonicalized like dNSName/URI, so a
  // trailing-dot mailbox host must not escape an excluded rfc822 constraint.
  var interEmDot = await mkCert({ subject: "EmDotInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail("evil.example.com")])]) });
  var leafEmDot = await mkCert({ subject: "EmDotLeaf", issuer: "EmDotInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("user@evil.example.com.")])] });
  var resEmDot = await run([interEmDot, leafEmDot], { time: T2027, trustAnchor: anchor });
  check("trailing-dot rfc822 host does not escape an excluded host constraint", resEmDot.valid === false && failCodes(resEmDot).indexOf("path/name-constraint-excluded") !== -1);
  // a trailing-dot full mailbox likewise cannot escape a full-mailbox exclusion.
  var interEmDot2 = await mkCert({ subject: "EmDot2Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail("user@evil.example.com")])]) });
  var leafEmDot2 = await mkCert({ subject: "EmDot2Leaf", issuer: "EmDot2Inter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnEmail("user@evil.example.com.")])] });
  var resEmDot2 = await run([interEmDot2, leafEmDot2], { time: T2027, trustAnchor: anchor });
  check("trailing-dot full mailbox does not escape a full-mailbox exclusion", resEmDot2.valid === false && failCodes(resEmDot2).indexOf("path/name-constraint-excluded") !== -1);

  // A certification path longer than the maxPathCerts ceiling is rejected BEFORE
  // any per-cert asymmetric verify runs (bounds crypto amplification on an
  // untrusted bundle). A small opt-in cap makes the guard observable.
  var overLong = [];
  for (var oi = 0; oi < 4; oi++) overLong.push(await mkCert({ subject: "OL" + oi, issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" }));
  check("path exceeding maxPathCerts throws path/bad-input", (await codeOf(run(overLong, { time: T2027, trustAnchor: anchor, maxPathCerts: 3 }))) === "path/bad-input");
  // control: a path at the limit is not rejected by the cap (fails later on chain, not on the cap).
  var atLimit = await run([leafCrl], { time: T2027, trustAnchor: anchor, maxPathCerts: 1 });
  check("control: a path within maxPathCerts is not rejected by the cap", failCodes(atLimit).indexOf("path/bad-input") === -1);

  // opts.requireRevocation makes the 6.1.3(a)(3) determination mandatory: with no
  // revocationChecker the step cannot run, so the path fails closed rather than
  // silently skipping revocation.
  var leafReq = await mkCert({ subject: "ReqRev", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var resReqNoChecker = await run([leafReq], { time: T2027, trustAnchor: anchor, requireRevocation: true });
  check("requireRevocation with no checker fails closed", resReqNoChecker.valid === false && failCodes(resReqNoChecker).indexOf("path/revocation-undetermined") !== -1);
  // control: without requireRevocation the same no-checker path validates (revocation opt-in).
  var resNoReq = await run([leafReq], { time: T2027, trustAnchor: anchor });
  check("control: no checker + no requireRevocation validates", resNoReq.valid === true);
  // control: requireRevocation with a checker returning good validates.
  var goodChecker = { check: function () { return Promise.resolve({ status: "good" }); } };
  var resReqGood = await run([leafReq], { time: T2027, trustAnchor: anchor, requireRevocation: true, revocationChecker: goodChecker });
  check("control: requireRevocation + good status validates", resReqGood.valid === true);

  // A partition-scoped CRL (onlySomeReasons or a specific distributionPoint)
  // covers only a shard, so it cannot establish "good" — but a serial it LISTS
  // is a genuine revocation and must be honored even under softFail (which opts
  // into accepting an undetermined status, not a revoked one).
  var someReasonsB = Buffer.from([0x06, 0x40]); // BIT STRING: keyCompromise only
  var crlPartRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }], extensions: [crlNumberExt(9), idpExt({ onlySomeReasons: someReasonsB })] });
  var resPartRev = await run([leafCrl], { time: T2027, trustAnchor: anchor, softFail: true, revocationChecker: pki.path.crlChecker([crlPartRev]) });
  check("reason-partitioned CRL listing the serial revokes even under softFail", resPartRev.valid === false && failCodes(resPartRev).indexOf("path/revoked") !== -1);
  var dpNameScope = dpnFull([gnUri("http://crl.example/partition/1")]);
  var crlDpRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }], extensions: [crlNumberExt(10), idpExt({ distributionPoint: dpNameScope })] });
  var resDpRev = await run([leafCrl], { time: T2027, trustAnchor: anchor, softFail: true, revocationChecker: pki.path.crlChecker([crlDpRev]) });
  check("distributionPoint-scoped CRL listing the serial revokes even under softFail", resDpRev.valid === false && failCodes(resDpRev).indexOf("path/revoked") !== -1);
  // control: a clean partition-scoped CRL still cannot establish good.
  var crlPartClean = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(11), idpExt({ onlySomeReasons: someReasonsB })] });
  var resPartClean = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlPartClean]) });
  check("control: a clean partition-scoped CRL cannot establish good (undetermined)", resPartClean.valid === false && failCodes(resPartClean).indexOf("path/revocation-undetermined") !== -1);

  // -------------------------------------------------------------------------
  // RFC 5280 sec. 6.3.3 reason-mask accumulation + delta-CRL merge.
  //
  // A CA that partitions revocations by reason code publishes no single CRL
  // covering all reasons, and a CA that publishes a delta alongside its base
  // makes holding BOTH strictly worse than holding the base alone. Both shapes
  // now reach a real verdict: interim_reasons_mask is accumulated across
  // corresponding distribution points until the eight legal reasons are covered
  // (sec. 6.3.3(d)(1)-(4),(l)), and a delta is merged onto its base under the
  // sec. 5.2.4 / 6.3.3(c) preconditions with the (i) -> (j) -> (k) scan order.
  //
  // The invariant that bounds the whole feature: the merge may only turn
  // UNDETERMINED into good/revoked. It may NEVER turn a revoked into a good.
  // -------------------------------------------------------------------------

  // ReasonFlags (sec. 4.2.1.13) as minimal-DER NamedBitList CONTENT: the leading
  // octet is the unused-bit count and trailing zero octets are dropped (X.690
  // 11.2.2). Built from the bit list so a vector never hand-encodes a mask.
  function reasonBits(bits) {
    var hi = Math.max.apply(null, bits);
    var nBytes = Math.floor(hi / 8) + 1;
    var out = Buffer.alloc(nBytes);
    bits.forEach(function (bit) { out[Math.floor(bit / 8)] |= 0x80 >> (bit % 8); });
    return Buffer.concat([Buffer.from([7 - (hi % 8)]), out]);
  }
  function deltaExt(baseNumber, critical) { return ext("2.5.29.27", critical !== false, b.integer(BigInt(baseNumber))); }

  var SHARD_URL = "http://crl.example/shard";
  var shardDpn = dpnFull([gnUri(SHARD_URL)]);
  var leafShard = await mkCert({ subject: "ShardL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER,
    extensions: [cdpExt([distPoint(shardDpn)])] });

  // R14 -- THE MONOTONICITY TRAP. A delta naming a base this verifier does not
  // hold (baseCRLNumber 30 vs the base's cRLNumber 10) merges with nothing. A
  // literal reading of sec. 6.3.3(c) drops it entirely, leaving the clean base to
  // report GOOD -- turning a shipped `revoked` into a `valid`. It must stay
  // revoked: an unmerged delta is still consulted for revocation.
  var monoBase = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(10), freshestExt([distPoint(shardDpn)])] });
  var monoDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(1)] }],
    extensions: [crlNumberExt(31), deltaExt(30)] });
  var resMono = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([monoBase, monoDelta]) });
  check("R14 an unmergeable delta still revokes -- the merge never turns revoked into good",
    resMono.valid === false && failCodes(resMono).indexOf("path/revoked") !== -1);

  // R1 (headline) -- two reason shards whose masks union to all-reasons, neither
  // listing the serial, both corresponding to the leaf's DP -> good.
  var shardA = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(20), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([1, 2, 8]) })] });
  var shardB = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(21), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([3, 4, 5, 6, 7]) })] });
  var resR1 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([shardA, shardB]) });
  check("R1 two reason shards covering all eight reasons establish good", resR1.valid === true);

  // R3 -- one shard alone is partial coverage and still fails closed.
  var resR3 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([shardA]) });
  check("R3 a single reason shard cannot establish good (partial coverage)",
    resR3.valid === false && failCodes(resR3).indexOf("path/revocation-undetermined") !== -1);

  // R2 -- shards whose union falls short of all-reasons stay undetermined.
  var shardShort = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(22), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([3, 4]) })] });
  var resR2 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([shardA, shardShort]) });
  check("R2 shards whose union is short of all-reasons stay undetermined",
    resR2.valid === false && failCodes(resR2).indexOf("path/revocation-undetermined") !== -1);

  // R4 -- OVERLAPPING shards that together cover 1..8: the accumulator is a
  // union, not a sum, so double-counted reasons must not over- or under-count.
  var ovlA = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(23), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([1, 2, 3, 4, 5]) })] });
  var ovlB = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(24), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([4, 5, 6, 7, 8]) })] });
  var resR4 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([ovlA, ovlB]) });
  check("R4 overlapping shards union to full coverage", resR4.valid === true);

  // R10 -- a shard that does NOT correspond to the leaf's DP contributes nothing
  // to coverage, but a serial it lists is still a genuine revocation.
  var otherDpn = dpnFull([gnUri("http://crl.example/other")]);
  var nonCorrRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }],
    extensions: [crlNumberExt(25), idpExt({ distributionPoint: otherDpn, onlySomeReasons: reasonBits([1, 2, 3, 4, 5, 6, 7, 8]) })] });
  var resR10 = await run([leafShard], { time: T2027, trustAnchor: anchor, softFail: true, revocationChecker: pki.path.crlChecker([nonCorrRev]) });
  check("R10 a non-corresponding shard still revokes a serial it lists",
    resR10.valid === false && failCodes(resR10).indexOf("path/revoked") !== -1);
  var nonCorrClean = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(26), idpExt({ distributionPoint: otherDpn, onlySomeReasons: reasonBits([1, 2, 3, 4, 5, 6, 7, 8]) })] });
  var resR10b = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([nonCorrClean]) });
  check("R10 a non-corresponding shard contributes nothing to coverage",
    resR10b.valid === false && failCodes(resR10b).indexOf("path/revocation-undetermined") !== -1);

  // A shard that covers NO reasons for this certificate contributes nothing to coverage -- but it
  // is still SCANNED for revocations, so it must clear every authenticity gate first. Recording
  // "no coverage" must never short-circuit the currency and signature checks: an unsigned or
  // expired shard that lists the serial would otherwise falsely revoke a certificate, which is a
  // denial of service any attacker who can hand over a CRL bundle could mount.
  var forgedNonCorr = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }],
    extensions: [crlNumberExt(31), idpExt({ distributionPoint: otherDpn })],
    mutateSig: function (sig) { var c = Buffer.from(sig); c[c.length - 1] ^= 0xff; return c; } });
  var resForged = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([forgedNonCorr]) });
  check("a non-corresponding shard with a BAD SIGNATURE cannot revoke",
    resForged.valid === false && failCodes(resForged).indexOf("path/revoked") === -1);
  var staleNonCorr = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }],
    nextUpdate: new Date("2026-06-01T00:00:00Z"),
    extensions: [crlNumberExt(32), idpExt({ distributionPoint: otherDpn })] });
  var resStale = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([staleNonCorr]) });
  check("a non-corresponding shard that is STALE cannot revoke",
    resStale.valid === false && failCodes(resStale).indexOf("path/revoked") === -1);
  // ... while a properly signed, current one still does (the gates reject the bad, not the shape).
  var goodNonCorr = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }],
    extensions: [crlNumberExt(33), idpExt({ distributionPoint: otherDpn })] });
  var resGoodNC = await run([leafShard], { time: T2027, trustAnchor: anchor, softFail: true, revocationChecker: pki.path.crlChecker([goodNonCorr]) });
  check("control: a signed, current non-corresponding shard still revokes what it lists",
    resGoodNC.valid === false && failCodes(resGoodNC).indexOf("path/revoked") !== -1);

  // The severe form of the same class: a FORGED delta must not be able to SUPPRESS a real
  // revocation. Because the merged pair searches the delta first and a removeFromCRL there releases
  // the certificate without the base ever being searched, an unsigned delta that slipped past the
  // gates would erase the base's genuine revocation and -- with any clean full-scope CRL supplying
  // coverage -- produce `good`. That is the exact inversion of the monotonicity rule, so it gets its
  // own vector rather than relying on the false-revocation one above.
  var legitRevokingBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(1)] }],
    extensions: [crlNumberExt(50), freshestExt([distPoint(shardDpn)]), idpExt({ distributionPoint: otherDpn })] });
  var forgedReleasingDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [crlNumberExt(51), deltaExt(50), idpExt({ distributionPoint: otherDpn })],
    mutateSig: function (sig) { var c = Buffer.from(sig); c[c.length - 1] ^= 0xff; return c; } });
  var cleanCoverage = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(52)] });
  var resSuppress = await run([leafShard], { time: T2027, trustAnchor: anchor,
    revocationChecker: pki.path.crlChecker([legitRevokingBase, forgedReleasingDelta, cleanCoverage]) });
  check("a forged delta cannot suppress a genuine revocation on its base",
    resSuppress.valid === false && failCodes(resSuppress).indexOf("path/revoked") !== -1);

  // R12 -- an UNDEFINED ReasonFlags bit (9) is ignored: it can neither complete
  // coverage on its own nor break the union that the defined bits achieve.
  var oddBitShard = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(27), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([1, 2, 8, 9]) })] });
  var restShard = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(28), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([3, 4, 5, 6, 7]) })] });
  var resR12 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([oddBitShard, restShard]) });
  check("R12 an undefined ReasonFlags bit neither completes nor breaks coverage", resR12.valid === true);

  // R13 -- ReasonFlags bit 0 is `unused`, not a reason: sec. 6.3.2(a)'s legal set is the eight
  // NAMED reasons. A shard asserting only bit 0 covers nothing, so it must read as no coverage at
  // all rather than as partial coverage; and bit 0 alongside the eight must not disturb them.
  var bitZeroOnly = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(34), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([0]) })] });
  var resBit0 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([bitZeroOnly]) });
  check("R13 a shard asserting only ReasonFlags bit 0 establishes no coverage",
    resBit0.valid === false && failCodes(resBit0).indexOf("path/revocation-undetermined") !== -1);
  var bitZeroPlusAll = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(35), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([0, 1, 2, 3, 4, 5, 6, 7, 8]) })] });
  var resBit0All = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([bitZeroPlusAll]) });
  check("R13 bit 0 alongside all eight named reasons still establishes good", resBit0All.valid === true);

  // R11 -- the criticality decision governs the WHOLE IDP scope. A NON-CRITICAL IDP is one a
  // relying party may ignore entirely (sec. 5.2.5 @3601), so its onlySomeReasons cannot establish
  // coverage either -- two non-critical shards whose masks would union to all-reasons must still
  // fail closed. This preserves the shipped property that an onlySomeReasons shard could only ever
  // withhold good, never grant it.
  function ncIdpExt(o) { return ext("2.5.29.28", false, idpVal(o)); }
  // NO distributionPoint on these: with one, the correspondence gate already refuses a
  // non-critical IDP, so the shards would fall to interim 0 for that reason and prove nothing
  // about the reason mask itself.
  var ncShardA = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(36), ncIdpExt({ onlySomeReasons: reasonBits([1, 2, 8]) })] });
  var ncShardB = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(37), ncIdpExt({ onlySomeReasons: reasonBits([3, 4, 5, 6, 7]) })] });
  var resNcShards = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([ncShardA, ncShardB]) });
  check("R11 two NON-CRITICAL reason shards cannot establish good even when their masks union",
    resNcShards.valid === false && failCodes(resNcShards).indexOf("path/revocation-undetermined") !== -1);
  // ... and the same shards marked CRITICAL do, so the gate is criticality and nothing else.
  var resCritShards = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([shardA, shardB]) });
  check("control: the same reason coverage marked critical does establish good", resCritShards.valid === true);

  // R8 / R9 regressions -- the shipped shapes must survive the rewrite.
  var fullScopeForShard = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(29), idpExt({ distributionPoint: shardDpn })] });
  var resR8 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([fullScopeForShard]) });
  check("R8 a DP-matched CRL with no onlySomeReasons still establishes good", resR8.valid === true);
  var noIdpCrl = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(30)] });
  var resR9 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([noIdpCrl]) });
  check("R9 a full-scope CRL with no IDP still covers a CDP-bearing certificate", resR9.valid === true);

  // R15 -- clean base + clean delta -> good. Holding both must not be worse than
  // holding the base alone (which is what the shipped `sawDelta` block did).
  var mergeBase = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(40), freshestExt([distPoint(shardDpn)])] });
  var mergeDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(41), deltaExt(40)] });
  var resR15 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([mergeBase, mergeDelta]) });
  check("R15 a clean base merged with its clean delta establishes good", resR15.valid === true);

  // R16 -- hold then release: (i) finds removeFromCRL on the delta, (j) is
  // skipped because cert_status is no longer UNREVOKED, (k) normalizes to
  // UNREVOKED. The base's certificateHold entry never gets to stand.
  var holdBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [crlNumberExt(50), freshestExt([distPoint(shardDpn)])] });
  var releaseDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [crlNumberExt(51), deltaExt(50)] });
  var resR16 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([holdBase, releaseDelta]) });
  check("R16 a delta releasing the serial from hold establishes good", resR16.valid === true);

  // R17 -- the same hold WITHOUT the delta stays revoked: (k) must not fire on
  // its own.
  var resR17 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([holdBase]) });
  check("R17 a certificateHold with no delta stays revoked",
    resR17.valid === false && failCodes(resR17).indexOf("path/revoked") !== -1);

  // R20 / R21 -- the delta locator gate (sec. 6.3.3(a)(2)): a delta is merged
  // only when the certificate OR the complete CRL carries freshestCRL.
  var baseNoLocator = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(60)] });
  var deltaNoLocator = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(61), deltaExt(60)] });
  var resR20 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([baseNoLocator, deltaNoLocator]) });
  check("R20 no freshestCRL on either side means no merge (undetermined)",
    resR20.valid === false && failCodes(resR20).indexOf("path/revocation-undetermined") !== -1);
  var leafFreshest = await mkCert({ subject: "FreshL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER,
    extensions: [cdpExt([distPoint(shardDpn)]), freshestExt([distPoint(dpnFull([gnUri("http://crl.example/delta")]))])] });
  var resR21 = await run([leafFreshest], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([baseNoLocator, deltaNoLocator]) });
  check("R21 a certificate-side freshestCRL is a sufficient delta locator", resR21.valid === true);

  // R22 -- useDeltas: false (sec. 6.3.1(b)) turns the merge off entirely.
  var resR22 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([mergeBase, mergeDelta], { useDeltas: false }) });
  check("R22 useDeltas:false leaves the delta unmerged (undetermined)",
    resR22.valid === false && failCodes(resR22).indexOf("path/revocation-undetermined") !== -1);

  // R18 / R19 -- the revocation REASON is surfaced by step (i): from the entry's
  // reasonCode, or `unspecified` (0) when the entry carries none (T4 -- a shard
  // entry is not required to carry one).
  var reasonChecker = pki.path.crlChecker([mergeBase,
    await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(1)] }], extensions: [crlNumberExt(42), deltaExt(40)] })]);
  var reasonVerdict = await reasonChecker.check(pki.schema.x509.parse(leafShard), { workingPublicKey: anchor.publicKey, issuerCert: null }, { time: T2027 });
  check("R18 a delta revocation surfaces its reasonCode and name",
    reasonVerdict.status === "revoked" && reasonVerdict.reasonCode === 1 && /keyCompromise/.test(reasonVerdict.reason || ""));
  var noReasonChecker = pki.path.crlChecker([mergeBase,
    await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }], extensions: [crlNumberExt(43), deltaExt(40)] })]);
  var noReasonVerdict = await noReasonChecker.check(pki.schema.x509.parse(leafShard), { workingPublicKey: anchor.publicKey, issuerCert: null }, { time: T2027 });
  check("R19 an entry with no reasonCode reports unspecified (0)",
    noReasonVerdict.status === "revoked" && noReasonVerdict.reasonCode === 0);

  // R39 / R40 -- ReasonFlags is a NamedBitList, so a non-minimal encoding is not
  // DER (X.690 sec. 11.2.2). The certificate-side  decoder must reject
  // both shapes: a trailing zero octet, and an unused-bit count that does not
  // match the last set bit. The consumer effect is what makes this load-bearing --
  // a certificate whose DP  will not decode can no longer establish
  // sec. 6.3.3(b)(2)(i) correspondence, so a shard contributes NO coverage rather
  // than having its onlySomeReasons intersected against a value DER forbids.
  var allBitsTrailingZero = Buffer.from([0x00, 0x7F, 0x80, 0x00]);  // bits 1..8 set, trailing zero octet
  var allBitsWrongUnused = Buffer.from([0x00, 0x7F, 0x80]);         // last set bit is 8, so unusedBits must be 7
  var allShard = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(72), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([1, 2, 3, 4, 5, 6, 7, 8]) })] });
  var leafTrailingZero = await mkCert({ subject: "BadReasonsL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER,
    extensions: [cdpExt([distPoint(shardDpn, allBitsTrailingZero)])] });
  var resR39 = await run([leafTrailingZero], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([allShard]) });
  check("R39 a DP whose ReasonFlags has a trailing zero octet cannot establish correspondence",
    resR39.valid === false && failCodes(resR39).indexOf("path/revocation-undetermined") !== -1);
  var leafWrongUnused = await mkCert({ subject: "BadUnusedL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER,
    extensions: [cdpExt([distPoint(shardDpn, allBitsWrongUnused)])] });
  var resR40 = await run([leafWrongUnused], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([allShard]) });
  check("R40 a DP whose ReasonFlags unused-bit count is not minimal cannot establish correspondence",
    resR40.valid === false && failCodes(resR40).indexOf("path/revocation-undetermined") !== -1);
  // The control that makes the two above meaningful: the SAME reason set, encoded
  // minimally, does correspond and does establish good.
  var leafGoodReasons = await mkCert({ subject: "GoodReasonsL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER,
    extensions: [cdpExt([distPoint(shardDpn, reasonBits([1, 2, 3, 4, 5, 6, 7, 8]))])] });
  var resR39c = await run([leafGoodReasons], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([allShard]) });
  check("control: the same reason set encoded minimally establishes good", resR39c.valid === true);

  // R41 -- the same rule on the CRL side: a non-minimal onlySomeReasons leaves the
  // IDP malformed, so the CRL is unusable for coverage AND for revocation.
  var badIdpShard = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }],
    extensions: [crlNumberExt(70), idpExt({ distributionPoint: shardDpn, onlySomeReasons: allBitsTrailingZero })] });
  var resR41 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([badIdpShard]) });
  check("R41 a CRL whose onlySomeReasons is non-minimal is unusable entirely",
    resR41.valid === false && failCodes(resR41).indexOf("path/revocation-undetermined") !== -1);

  // R5 (d)(1) -- the certificate DP's `reasons` BOUNDS the CRL's onlySomeReasons:
  // the interim mask is their INTERSECTION, so a DP limited to {1,2} cannot be
  // covered by an all-reasons shard alone.
  var leafDpReasons = await mkCert({ subject: "DpReasonsL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER,
    extensions: [cdpExt([distPoint(shardDpn, reasonBits([1, 2]))])] });
  var allReasonShard = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(71), idpExt({ distributionPoint: shardDpn, onlySomeReasons: reasonBits([1, 2, 3, 4, 5, 6, 7, 8]) })] });
  var resR5 = await run([leafDpReasons], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([allReasonShard]) });
  check("R5 the certificate DP's reasons bound the CRL's onlySomeReasons (intersection)",
    resR5.valid === false && failCodes(resR5).indexOf("path/revocation-undetermined") !== -1);

  // R29 (T2) -- two CURRENT deltas for one base are LEGAL; the one with the later
  // thisUpdate is selected, never treated as a fault.
  var t2Base = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [crlNumberExt(80), freshestExt([distPoint(shardDpn)])] });
  var deltaEarlyClean = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2027-01-01T00:00:00Z"),
    extensions: [crlNumberExt(81), deltaExt(80)] });
  var deltaLateRelease = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2027-03-01T00:00:00Z"),
    revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }], extensions: [crlNumberExt(82), deltaExt(80)] });
  var resR29 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([t2Base, deltaEarlyClean, deltaLateRelease]) });
  check("R29 with two current deltas the later thisUpdate is selected (release wins)", resR29.valid === true);
  // Swap which delta is later: the clean one is selected, so (j) finds the hold.
  var deltaLateClean = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2027-03-01T00:00:00Z"),
    extensions: [crlNumberExt(83), deltaExt(80)] });
  var deltaEarlyRelease = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2027-01-01T00:00:00Z"),
    revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }], extensions: [crlNumberExt(84), deltaExt(80)] });
  var resR29b = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([t2Base, deltaLateClean, deltaEarlyRelease]) });
  check("R29 selecting the later clean delta lets the base's hold stand (revoked)",
    resR29b.valid === false && failCodes(resR29b).indexOf("path/revoked") !== -1);

  // A SUPERSEDED delta does not speak for its scope in EITHER direction. The selected (later)
  // delta decides: an older delta revoking a certificate that the newer one released must not
  // resurrect the revocation the CA withdrew, just as an older release cannot override a newer
  // clean delta. Ignoring only one of the two would be incoherent.
  var supBase = await mkCrl({ issuer: "Root", signWith: "ed25519",
    extensions: [crlNumberExt(85), freshestExt([distPoint(shardDpn)])] });
  var supOldRevoking = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2027-01-01T00:00:00Z"),
    revoked: [{ serial: SER, exts: [reasonCodeExt(1)] }], extensions: [crlNumberExt(86), deltaExt(85)] });
  var supNewReleasing = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2027-03-01T00:00:00Z"),
    revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }], extensions: [crlNumberExt(87), deltaExt(85)] });
  var resSuperseded = await run([leafShard], { time: T2027, trustAnchor: anchor,
    revocationChecker: pki.path.crlChecker([supBase, supOldRevoking, supNewReleasing]) });
  check("a superseded delta's revocation does not resurrect what the selected delta released",
    resSuperseded.valid === true);

  // sec. 5.2.4 makes deltaCRLIndicator a MUST-be-critical extension. A non-critical one is still
  // treated as a delta and still consulted for revocation (the shipped behavior), but it does not
  // earn the new capability of being MERGED -- merging can release a certificate, and that must
  // rest on a conforming indicator.
  var ncBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [crlNumberExt(88), freshestExt([distPoint(shardDpn)])] });
  var ncDeltaRelease = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [crlNumberExt(89), deltaExt(88, false)] });
  var resNonCritical = await run([leafShard], { time: T2027, trustAnchor: anchor,
    revocationChecker: pki.path.crlChecker([ncBase, ncDeltaRelease]) });
  check("a NON-CRITICAL delta indicator cannot merge, so it cannot release a held certificate",
    resNonCritical.valid === false);

  // R24 / R25 / R26 / R27 -- each merge precondition, one at a time, on the
  // hold/release pair: a failed merge must never let the release stand.
  var mmBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [crlNumberExt(90), freshestExt([distPoint(shardDpn)]), idpExt({ distributionPoint: shardDpn })] });
  var mmDeltaNoIdp = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [crlNumberExt(91), deltaExt(90)] });
  var resR24 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([mmBase, mmDeltaNoIdp]) });
  check("R24 a delta omitting the base's IDP is not merged (never good)", resR24.valid === false);
  var mmDeltaOtherIdp = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [crlNumberExt(92), deltaExt(90), idpExt({ distributionPoint: otherDpn })] });
  var resR25 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([mmBase, mmDeltaOtherIdp]) });
  check("R25 a delta whose IDP differs from the base's is not merged", resR25.valid === false);
  var eqBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [crlNumberExt(95), freshestExt([distPoint(shardDpn)])] });
  var eqDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [crlNumberExt(95), deltaExt(95)] });
  var resR27 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([eqBase, eqDelta]) });
  check("R27 a delta whose cRLNumber does not exceed the base's is not merged", resR27.valid === false);

  // ... and a number PAST the RFC 5280 sec. 5.2.3 20-octet ceiling is non-conforming, so it does
  // not earn the merge -- which can release a certificate. The CRL is still consulted for
  // revocation; only the new capability is withheld. pki.crl.sign enforces the same ceiling when
  // emitting, so this is the consumer half of a rule the producer already keeps.
  var over = 1n << 168n;   // 22 octets encoded
  var overBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [ext("2.5.29.20", false, b.integer(over)), freshestExt([distPoint(shardDpn)])] });
  var overDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [ext("2.5.29.20", false, b.integer(over + 1n)), ext("2.5.29.27", true, b.integer(over))] });
  var resOver = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([overBase, overDelta]) });
  check("a CRL number past the 20-octet ceiling cannot merge, so it cannot release a held certificate",
    resOver.valid === false);

  // R36 (MUST 36) -- 20-octet CRL numbers compare as BigInts, never narrowed.
  var big = (1n << 158n) + 7n;
  var bigBase = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(6)] }],
    extensions: [ext("2.5.29.20", false, b.integer(big)), freshestExt([distPoint(shardDpn)])] });
  var bigDelta = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, exts: [reasonCodeExt(8)] }],
    extensions: [ext("2.5.29.20", false, b.integer(big + 1n)), ext("2.5.29.27", true, b.integer(big))] });
  var resR36 = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([bigBase, bigDelta]) });
  check("R36 20-octet CRL numbers merge correctly (BigInt, never narrowed)", resR36.valid === true);

  // R49 -- the accumulator is per-CALL state, not per-checker: two checks with one
  // checker instance must agree, or a mask left over from the first would leak in.
  var reentrantChecker = pki.path.crlChecker([shardA, shardB]);
  var reentA = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: reentrantChecker });
  var reentB = await run([leafShard], { time: T2027, trustAnchor: anchor, revocationChecker: reentrantChecker });
  check("R49 the reason mask is per-call state (a reused checker agrees with itself)",
    reentA.valid === true && reentB.valid === true);

  // An EC certificate whose SPKI OMITS the curve parameters inherits them from
  // its issuer (RFC 5280 6.1.4(f)); the inherited parameters are spliced back so
  // importKey can consume the key, rather than rejecting a valid cert.
  var p256iKeys = await ensureKeys("p256i");
  var p256spki = (await ensureKeys("p256")).spki;
  var ecKeyAlgOid = pki.asn1.read.oid(pki.asn1.decode(p256spki).children[0].children[0]);  // id-ecPublicKey (the KEY alg, §6.1.1(e))
  var ecAnchorParams = { name: (await mkAnchor("p256", "EcParamRoot")).name, publicKey: p256spki, algorithm: ecKeyAlgOid, parameters: ecCurveParams(p256spki) };
  var interNoParams = await mkCert({ subject: "NoParamsInter", issuer: "EcParamRoot", signWith: "p256", subjectKeys: "p256i", spki: stripEcParams(p256iKeys.spki), extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leafNoParams = await mkCert({ subject: "NoParamsLeaf", issuer: "NoParamsInter", signWith: "p256i", subjectKeys: "ed25519leaf" });
  var resNoParams = await run([interNoParams, leafNoParams], { time: T2027, trustAnchor: ecAnchorParams });
  check("EC cert inheriting its curve parameters verifies (params spliced)", resNoParams.valid === true);
  // The object algorithm form { oid, parameters } normalizes to the same flat shape: workingPublicKeyAlgorithm
  // seeds from the string OID (not an object, which would never match the child's keyAlg.oid and would clear
  // the inherited params) and the nested parameters surface at anchor.parameters, so inheritance still holds.
  var ecAnchorObjForm = { name: ecAnchorParams.name, publicKey: p256spki, algorithm: { oid: ecKeyAlgOid, parameters: ecCurveParams(p256spki) } };
  var resObjForm = await run([interNoParams, leafNoParams], { time: T2027, trustAnchor: ecAnchorObjForm });
  check("#74 an object-form EC anchor { oid, parameters } inherits curve params like the flat form", resObjForm.valid === true);
  // A FROZEN object-form anchor still normalizes: the OID override is defined as an OWN property, so an
  // inherited non-writable/accessor `algorithm` descriptor cannot block it (a plain assignment would throw
  // in strict mode or silently leave the object algorithm in place, breaking EC parameter inheritance).
  var frozenObjForm = Object.freeze({ name: ecAnchorParams.name, publicKey: p256spki, algorithm: Object.freeze({ oid: ecKeyAlgOid, parameters: ecCurveParams(p256spki) }) });
  var resFrozen = await run([interNoParams, leafNoParams], { time: T2027, trustAnchor: frozenObjForm });
  check("#74 a frozen object-form EC anchor still normalizes and inherits curve params", resFrozen.valid === true);
  // The anchor's parameters are DERIVED from its publicKey SPKI, never a declared field: an object-form
  // anchor declaring a WRONG curve (P-384 params on a P-256 key) must not promote that curve into the
  // working state. The same-curve child that omits its params still inherits the anchor's REAL P-256 curve
  // and validates; the wrong declared P-384 would otherwise be spliced onto the P-256 key and break it --
  // and, worse, would let an actual P-384 child inherit P-384 and validate a chain RFC 5280 inheritance
  // from the real params rejects.
  var ecAnchorWrongParams = { name: ecAnchorParams.name, publicKey: p256spki, algorithm: { oid: ecKeyAlgOid, parameters: pki.asn1.build.oid("1.3.132.0.34") } };
  var resWrongParams = await run([interNoParams, leafNoParams], { time: T2027, trustAnchor: ecAnchorWrongParams });
  check("#74 a wrong declared anchor curve is ignored; the SPKI's real curve seeds child parameter inheritance", resWrongParams.valid === true);

  // a missing check date fails closed (never silently disables the
  // always-on validity window).
  var leafA7 = await mkCert({ subject: "A7", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  check("missing opts.time throws path/bad-input", (await codeOf(run([leafA7], { trustAnchor: anchor }))) === "path/bad-input");

  // the wrap-up sets workingPublicKeyAlgorithm to the leaf's key algorithm.
  var anchorEc = await mkAnchor("p256", "EcRoot2");
  var leafA10 = await mkCert({ subject: "A10", issuer: "EcRoot2", signWith: "p256", subjectKeys: "ed25519leaf" });
  var resA10 = await run([leafA10], { time: T2027, trustAnchor: anchorEc });
  check("wrap-up carries the leaf key algorithm out", resA10.valid === true && resA10.workingPublicKeyAlgorithm === ALG.ed25519.sigOid);

  // §6.1.5(f): the user-constrained policy set is computed.
  var P1x = "1.3.6.1.4.1.99999.1";
  var interA11 = await mkCert({ subject: "A11i", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1x])]) });
  var leafA11 = await mkCert({ subject: "A11l", issuer: "A11i", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1x])] });
  var resA11 = await run([interA11, leafA11], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P1x] });
  check("userConstrainedPolicySet computed", resA11.valid === true && Array.isArray(resA11.userConstrainedPolicySet) && resA11.userConstrainedPolicySet.indexOf(P1x) !== -1);

  // policy-mapping REPLACES the expected-policy set (§6.1.4(b)(1)): after
  // mapping P1->P2, a leaf asserting the mapped-FROM policy P1 must NOT satisfy
  // the chain (the pre-mapping policy is gone). Second-pass P1.
  var interMap = await mkCert({ subject: "MapFrom", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m]), pmExt([[P1m, P2m]])]) });
  var leafFrom = await mkCert({ subject: "LeafFrom", issuer: "MapFrom", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1m])] });
  var resA12 = await run([interMap, leafFrom], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("leaf asserting the mapped-FROM policy is rejected", resA12.valid === false && failCodes(resA12).indexOf("path/policy-required") !== -1);
  // control: a leaf asserting the mapped-TO policy P2 IS accepted.
  var leafTo = await mkCert({ subject: "LeafTo", issuer: "MapFrom", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resA12ok = await run([interMap, leafTo], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("control: leaf asserting the mapped-TO policy validates", resA12ok.valid === true);

  // two mappings in one extension arriving at policy_mapping==0: the
  // first empties the tree; the second must not crash on a null tree (typed
  // path/policy-required, never a raw TypeError). Second-pass P2.
  var interClamp2 = await mkCert({ subject: "Clamp2", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var interDbl = await mkCert({ subject: "DblMap", issuer: "Clamp2", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([P1m]), pmExt([[P1m, P2m], [P1m, P3m]])]) });
  var leafA13 = await mkCert({ subject: "LA13", issuer: "DblMap", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resA13 = await run([interClamp2, interDbl, leafA13], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("double-mapping at policy_mapping==0 fails typed, not a crash", resA13.valid === false && failCodes(resA13).every(function (c) { return c.indexOf("path/") === 0; }) && failCodes(resA13).indexOf("path/policy-required") !== -1);

  // the policy_mapping==0 delete arm must delete ONLY the mapped-from
  // nodes, not over-prune surviving unmapped policies (§6.1.4(b)(2)). ClampX
  // sets policy_mapping=0 and seeds {P1,P2}; MapX maps P1->P3 (deleting the
  // depth-2 P1 node) but P2 must survive; the leaf asserts P2 -> valid.
  var clampA15 = await mkCert({ subject: "ClampA15", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m, P2m]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var mapA15 = await mkCert({ subject: "MapA15", issuer: "ClampA15", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([P1m, P2m]), pmExt([[P1m, P3m]])]) });
  var leafA15 = await mkCert({ subject: "LA15", issuer: "MapA15", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resA15 = await run([clampA15, mapA15, leafA15], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("delete arm keeps surviving unmapped policies (no over-prune)", resA15.valid === true && resA15.userConstrainedPolicySet.indexOf(P2m) !== -1);

  // §6.1.5(g) step 3: an all-anyPolicy chain under a restrictive user set
  // reports the user policies in userConstrainedPolicySet, not the empty set.
  var interAny14 = await mkCert({ subject: "Any14", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY])]) });
  var leafAny14 = await mkCert({ subject: "LAny14", issuer: "Any14", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([ANY_POLICY])] });
  var resA14 = await run([interAny14, leafAny14], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P1m] });
  check("anyPolicy leaf under restrictive user set expands the policy set", resA14.valid === true && resA14.userConstrainedPolicySet.indexOf(P1m) !== -1);

  // a clean CRL must not shadow a revoking one: with
  // both a clean and a revoking CRL for the issuer, the cert is REVOKED.
  var cleanCrl = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1n }] });
  var revokingCrl = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }] });
  var resCleanFirst = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([cleanCrl, revokingCrl]) });
  check("clean CRL does not shadow the revoking one (order A)", resCleanFirst.valid === false && failCodes(resCleanFirst).indexOf("path/revoked") !== -1);
  var resRevFirst = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([revokingCrl, cleanCrl]) });
  check("revoked regardless of CRL order (order B)", resRevFirst.valid === false && failCodes(resRevFirst).indexOf("path/revoked") !== -1);

  // §6.1.5(g): with explicit policy required and a restrictive
  // userInitialPolicySet, a path whose surviving policies are OUTSIDE the user
  // set must FAIL (the tree is pruned against the user set before success). The
  // chain asserts P1m throughout; the user set is [P3m], disjoint.
  var interC4 = await mkCert({ subject: "C4i", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m])]) });
  var leafC4 = await mkCert({ subject: "C4l", issuer: "C4i", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1m])] });
  var resC4 = await run([interC4, leafC4], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P3m] });
  check("required policy with empty user-set intersection rejected", resC4.valid === false && failCodes(resC4).indexOf("path/policy-required") !== -1);
  // control: the SAME chain with the matching user set validates.
  var resC4ok = await run([interC4, leafC4], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P1m] });
  check("control: matching user set validates", resC4ok.valid === true && resC4ok.userConstrainedPolicySet.indexOf(P1m) !== -1);

  // a LEAF with a critical MALFORMED keyUsage must fail
  // closed: the semantic gate is skipped on the leaf, but the structure is
  // still validated. keyUsage value here is an INTEGER, not a BIT STRING.
  var badKuLeaf = await mkCert({ subject: "BadKu", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.15", true, b.integer(1n))] });
  var resC1 = await run([badKuLeaf], { time: T2027, trustAnchor: anchor });
  check("leaf critical malformed keyUsage rejected", resC1.valid === false && failCodes(resC1).indexOf("path/bad-key-usage") !== -1);
  // control: a well-formed critical keyUsage on the leaf is accepted.
  var okKuLeaf = await mkCert({ subject: "OkKu", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [kuExt([KU_DIGITAL_SIGNATURE])] });
  var resC1ok = await run([okKuLeaf], { time: T2027, trustAnchor: anchor });
  check("control: well-formed critical keyUsage on the leaf accepted", resC1ok.valid === true);

  // a CRL scoped to a specific distributionPoint cannot be
  // confirmed in-scope for this cert -> not authoritative -> undetermined.
  var dpName = dpnFull([gnUri("http://crl.example/partition/1")]);
  var crlDp = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(1), idpExt({ distributionPoint: dpName })] });
  var resC2 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlDp]) });
  check("partitioned CRL (distributionPoint IDP) yields undetermined", resC2.valid === false && failCodes(resC2).indexOf("path/revocation-undetermined") !== -1);

  // a validly-signed CRL carrying an UNHANDLED critical
  // extension is unusable -> undetermined, never authoritative "good".
  var crlUnkCrit = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(2), unknownCriticalCrlExt()] });
  var resC3 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlUnkCrit]) });
  check("CRL with unhandled critical extension yields undetermined", resC3.valid === false && failCodes(resC3).indexOf("path/revocation-undetermined") !== -1);

  // a CRL scoped onlyContainsAttributeCerts is out of scope
  // for a public-key certificate -> undetermined, never authoritative "good".
  var crlAttrOnly = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(4), idpExt({ onlyAttr: true })] });
  var resC5 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlAttrOnly]) });
  check("attribute-cert-only CRL out of scope for a public-key cert", resC5.valid === false && failCodes(resC5).indexOf("path/revocation-undetermined") !== -1);

  // a critical IDP whose value is not a SEQUENCE leaves the
  // scope unknown: the CRL is unusable, not treated as unrestricted.
  var crlBadIdp = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(5), ext("2.5.29.28", true, b.integer(1n))] });
  var resC8 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlBadIdp]) });
  check("malformed IDP CRL is unusable (undetermined)", resC8.valid === false && failCodes(resC8).indexOf("path/revocation-undetermined") !== -1);
  // ...and it must not let a revoked serial read good either — a revoking CRL
  // with an unhandled critical extension is unusable, so the cert is undetermined.
  var crlRevUnk = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(3), unknownCriticalCrlExt()] });
  var resC3b = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlRevUnk]) });
  check("unusable revoking CRL does not read as revoked either (undetermined)", resC3b.valid === false && failCodes(resC3b).indexOf("path/revocation-undetermined") !== -1);
}

// ---------------------------------------------------------------------------
// 6.1.1 user-initial inputs, target-cert criticality, extendedKeyUsage
// ---------------------------------------------------------------------------

// CertificatePolicies with a policyQualifiers SEQUENCE OF PolicyQualifierInfo
// { id-qt-cps, CPSuri } on each PolicyInformation — exercises AP-Q propagation.
function cpQualExt(policyOids, cpsUri) {
  return ext("2.5.29.32", false, b.sequence(policyOids.map(function (p) {
    return b.sequence([b.oid(p), b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.ia5(cpsUri)])])]);
  })));
}

// ExtKeyUsage ::= SEQUENCE SIZE(1..MAX) OF KeyPurposeId.
function ekuExt(purposeOids, critical) {
  return ext("2.5.29.37", critical === true, b.sequence(purposeOids.map(function (p) { return b.oid(p); })));
}
var EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1", EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3", EKU_ANY = "2.5.29.37.0";

async function testInitialInputsAndTargetGates() {
  var anchor = await mkAnchor("ed25519", "Root");
  var Pq1 = "1.3.6.1.4.1.99999.61", Pq2 = "1.3.6.1.4.1.99999.62";

  // ---- 6.1.1(b,c) initial permitted / excluded subtrees --------------------
  // A correct-shape excluded seed rejects a matching SAN.
  var leafEvil = await mkCert({ subject: "SeedEvil", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("www.evil.example")])] });
  var resSeedEx = await run([leafEvil], { time: T2027, trustAnchor: anchor, initialExcludedSubtrees: [{ tag: 2, base: "evil.example" }] });
  check("initialExcludedSubtrees rejects a matching dNSName SAN", resSeedEx.valid === false && failCodes(resSeedEx).indexOf("path/name-constraint-excluded") !== -1);
  // A MIS-SHAPED seed entry (the decoder-natural { base: { tagNumber, value } }
  // shape) must throw at the entry point — absorbed raw it would never match
  // and the configured exclusion would silently not apply.
  check("mis-shaped excluded seed throws path/bad-input",
    (await codeOf(run([leafEvil], { time: T2027, trustAnchor: anchor, initialExcludedSubtrees: [{ base: { tagNumber: 2, value: "evil.example" } }] }))) === "path/bad-input");
  check("excluded seed with a wrong-typed base throws path/bad-input",
    (await codeOf(run([leafEvil], { time: T2027, trustAnchor: anchor, initialExcludedSubtrees: [{ tag: 2, base: 42 }] }))) === "path/bad-input");
  check("non-array initialExcludedSubtrees throws path/bad-input",
    (await codeOf(run([leafEvil], { time: T2027, trustAnchor: anchor, initialExcludedSubtrees: { tag: 2, base: "evil.example" } }))) === "path/bad-input");
  // An initial permitted generation constrains the form for the whole path.
  var leafOutside = await mkCert({ subject: "SeedOut", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.other.example")])] });
  var resSeedPerm = await run([leafOutside], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 2, base: "good.example" }] });
  check("initialPermittedSubtrees rejects a name outside the seed", resSeedPerm.valid === false && failCodes(resSeedPerm).indexOf("path/name-constraint-not-permitted") !== -1);
  var leafInside = await mkCert({ subject: "SeedIn", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.good.example")])] });
  var resSeedPermOk = await run([leafInside], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 2, base: "good.example" }] });
  check("control: a name within the permitted seed validates", resSeedPermOk.valid === true);
  check("mis-shaped permitted seed throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: "2", base: "good.example" }] }))) === "path/bad-input");

  // ---- maxPolicyNodes is entry-point-validated ------------------------------
  check("maxPolicyNodes 0 throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, maxPolicyNodes: 0 }))) === "path/bad-input");
  check("negative maxPolicyNodes throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, maxPolicyNodes: -5 }))) === "path/bad-input");
  check("non-numeric maxPolicyNodes throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, maxPolicyNodes: "4096" }))) === "path/bad-input");
  // A fractional count is not an integer node/cert budget -- it must fail closed
  // like 0 / negative / non-numeric, not be silently tolerated (the shared
  // guard.limits.cap integer floor the hand-rolled isFinite check had dropped).
  check("fractional maxPolicyNodes throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, maxPolicyNodes: 1.5 }))) === "path/bad-input");
  check("fractional maxPathCerts throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, maxPathCerts: 1.5 }))) === "path/bad-input");

  // ---- userInitialPolicySet is entry-point-validated -------------------------
  // A raw string would be consulted via indexOf — a SUBSTRING match, not set
  // membership — so a non-array (or empty / non-string-element) set throws.
  check("string userInitialPolicySet throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, userInitialPolicySet: "1.3.6.1.4.1.99999.61" }))) === "path/bad-input");
  check("empty userInitialPolicySet throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, userInitialPolicySet: [] }))) === "path/bad-input");
  check("non-string userInitialPolicySet element throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, userInitialPolicySet: [42] }))) === "path/bad-input");
  // A non-canonical OID key can never match the canonical decoder output it is
  // compared against (a silent false-reject) -- so a leading-zero / non-dotted
  // policy or EKU string fails closed at the entry point ("catch the typo at boot").
  check("non-canonical userInitialPolicySet entry throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, userInitialPolicySet: ["1.3.6.1.4.1.99999.061"] }))) === "path/bad-input");
  check("leading-zero requiredEku entry throws path/bad-input",
    (await codeOf(run([leafInside], { time: T2027, trustAnchor: anchor, requiredEku: ["1.3.6.1.5.5.7.3.01"] }))) === "path/bad-input");

  // ---- 6.1.1(e) initial-any-policy-inhibit ----------------------------------
  // With the inhibit set, a cert-asserted anyPolicy is not expanded ((d)(2)
  // gated from the start), so an anyPolicy-only leaf leaves the tree empty.
  var leafAnyOnly = await mkCert({ subject: "IapiLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [cpExt([ANY_POLICY])] });
  var resIapi = await run([leafAnyOnly], { time: T2027, trustAnchor: anchor, initialAnyPolicyInhibit: true, initialExplicitPolicy: true });
  check("initialAnyPolicyInhibit suppresses a cert-asserted anyPolicy", resIapi.valid === false && failCodes(resIapi).indexOf("path/policy-required") !== -1);
  var resIapiCtl = await run([leafAnyOnly], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("control: without the inhibit the anyPolicy leaf validates", resIapiCtl.valid === true);

  // ---- 6.1.1(e) initial-policy-mapping-inhibit -------------------------------
  // With the inhibit set, a mapping cert's mapped-from nodes are DELETED
  // (6.1.4(b)(2)) instead of remapped, emptying the tree.
  var interMapI = await mkCert({ subject: "IpmiInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([Pq1]), pmExt([[Pq1, Pq2]])]) });
  var leafMapped = await mkCert({ subject: "IpmiLeaf", issuer: "IpmiInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([Pq2])] });
  var resIpmi = await run([interMapI, leafMapped], { time: T2027, trustAnchor: anchor, initialPolicyMappingInhibit: true, initialExplicitPolicy: true });
  check("initialPolicyMappingInhibit forces the (b)(2) deletion arm", resIpmi.valid === false && failCodes(resIpmi).indexOf("path/policy-required") !== -1);
  var resIpmiCtl = await run([interMapI, leafMapped], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("control: without the inhibit the mapped chain validates", resIpmiCtl.valid === true && resIpmiCtl.userConstrainedPolicySet.indexOf(Pq2) !== -1);

  // ---- 6.1.3(d)(2): expansion children carry AP-Q ---------------------------
  // The anyPolicy entry's qualifier set (AP-Q) must ride on every (d)(2)
  // expansion child ("set the qualifier_set to AP-Q"), not be dropped.
  var cpsQual = b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.ia5("https://cps.example/cps")])]);
  var interQ = await mkCert({ subject: "ApqInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpQualExt([ANY_POLICY], "https://cps.example/cps")]) });
  var leafQ = await mkCert({ subject: "ApqLeaf", issuer: "ApqInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([Pq1])] });
  var resApq = await run([interQ, leafQ], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  var apqNode = resApq.validPolicyTree && resApq.validPolicyTree.children[0];
  check("(d)(2) expansion node carries the anyPolicy qualifiers (AP-Q)",
    resApq.valid === true && !!apqNode && apqNode.validPolicy === ANY_POLICY &&
    apqNode.qualifierSet.length === 1 && Buffer.isBuffer(apqNode.qualifierSet[0]) && apqNode.qualifierSet[0].equals(cpsQual));

  // ---- 4.2.1.10 / 4.2.1.14 criticality on the TARGET cert -------------------
  // nameConstraints and inhibitAnyPolicy MUST be critical wherever they appear;
  // the target leg applies the same check the intermediate path does.
  var leafNcNC = await mkCert({ subject: "NcTargetNC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.30", false, ncVal([gnDns("example.com")], null))] });
  var resNcNC = await run([leafNcNC], { time: T2027, trustAnchor: anchor });
  check("non-critical nameConstraints on the target rejected", resNcNC.valid === false && failCodes(resNcNC).indexOf("path/extension-not-critical") !== -1);
  var leafIapNC = await mkCert({ subject: "IapTargetNC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.54", false, b.integer(0n))] });
  var resIapNC = await run([leafIapNC], { time: T2027, trustAnchor: anchor });
  check("non-critical inhibitAnyPolicy on the target rejected", resIapNC.valid === false && failCodes(resIapNC).indexOf("path/extension-not-critical") !== -1);
  // controls: the critical forms are accepted (semantically inert on a leaf,
  // structure still validated).
  var leafNcC = await mkCert({ subject: "NcTargetC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ncExt([gnDns("example.com")], null)] });
  check("control: critical nameConstraints on the target accepted", (await run([leafNcC], { time: T2027, trustAnchor: anchor })).valid === true);
  var leafIapCr = await mkCert({ subject: "IapTargetC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [iapExt(0)] });
  check("control: critical inhibitAnyPolicy on the target accepted", (await run([leafIapCr], { time: T2027, trustAnchor: anchor })).valid === true);

  // ---- 4.2.1.12 extendedKeyUsage --------------------------------------------
  // EKU is RECOGNIZED: the critical form is legal ('MAY ... be either critical
  // or non-critical') and appears in the wild (RFC 6960 §4.2.2.2 delegated OCSP
  // responders), so it must not fail as unrecognized. RFC 5280 6.1 defines no
  // EKU processing step — purpose enforcement is the caller's opts.requiredEku.
  var leafEkuCrit = await mkCert({ subject: "EkuCrit", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ekuExt([EKU_SERVER_AUTH], true)] });
  var resEkuCrit = await run([leafEkuCrit], { time: T2027, trustAnchor: anchor });
  check("critical extendedKeyUsage is recognized", resEkuCrit.valid === true);
  // a critical MALFORMED EKU still fails closed structurally.
  var leafEkuBad = await mkCert({ subject: "EkuBad", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.37", true, b.integer(1n))] });
  var resEkuBad = await run([leafEkuBad], { time: T2027, trustAnchor: anchor });
  check("critical malformed extendedKeyUsage rejected", resEkuBad.valid === false && failCodes(resEkuBad).indexOf("path/bad-extension-value") !== -1);
  // requiredEku: every named purpose must be asserted by the target's EKU.
  check("requiredEku satisfied by the asserted purpose", (await run([leafEkuCrit], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] })).valid === true);
  check("requiredEku accepts a dotted purpose OID", (await run([leafEkuCrit], { time: T2027, trustAnchor: anchor, requiredEku: [EKU_SERVER_AUTH] })).valid === true);
  var leafEkuCode = await mkCert({ subject: "EkuCode", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ekuExt([EKU_CODE_SIGNING], false)] });
  var resEkuMiss = await run([leafEkuCode], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] });
  check("required purpose missing from the EKU fails path/eku-not-permitted", resEkuMiss.valid === false && failCodes(resEkuMiss).indexOf("path/eku-not-permitted") !== -1);
  // The purpose test is a RULE, so it is decided by comparison rather than by a prototype method.
  // Written as `purposes.indexOf(p) !== -1`, the answer came from `Array.prototype.indexOf` as it
  // was at the moment of the call: replaced after load to report every value present, this same
  // codeSigning-only certificate satisfied a serverAuth requirement and the chain went from
  // valid:false to valid:true, with every check around it still running and passing.
  var realIndexOf = Array.prototype.indexOf;
  Array.prototype.indexOf = function () { return 0; };
  var resEkuSwapped;
  try { resEkuSwapped = await run([leafEkuCode], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] }); }
  finally { Array.prototype.indexOf = realIndexOf; }
  check("...and still fails with Array.prototype.indexOf replaced after load", resEkuSwapped.valid === false);
  // anyExtendedKeyUsage satisfies a required purpose (4.2.1.12: rejecting it is
  // an application MAY, not the default).
  var leafEkuAny = await mkCert({ subject: "EkuAny", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ekuExt([EKU_ANY], false)] });
  check("anyExtendedKeyUsage satisfies a required purpose", (await run([leafEkuAny], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] })).valid === true);
  // an ABSENT EKU leaves the key unrestricted (4.2.1.12 restricts only when present).
  var leafNoEku = await mkCert({ subject: "EkuNone", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  check("absent EKU is unrestricted under requiredEku", (await run([leafNoEku], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] })).valid === true);
  // RFC 5280 4.2.1.12 EKU chaining: an intermediate CA carrying an EKU
  // constrains the purposes of the certs beneath it. An intermediate whose EKU
  // is {codeSigning} cannot issue a serverAuth path -- the required purpose must
  // be in every CA cert's EKU too, not only the target's.
  var interEkuCode = await mkCert({ subject: "EkuCodeInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ekuExt([EKU_CODE_SIGNING], true)] });
  var leafUnderCode = await mkCert({ subject: "LeafUnderCode", issuer: "EkuCodeInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [ekuExt([EKU_SERVER_AUTH], false)] });
  var resEkuChain = await run([interEkuCode, leafUnderCode], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] });
  check("intermediate EKU excluding the required purpose fails the path", resEkuChain.valid === false && failCodes(resEkuChain).indexOf("path/eku-not-permitted") !== -1);
  // an intermediate whose EKU INCLUDES the purpose (or anyExtendedKeyUsage) chains fine.
  var interEkuBoth = await mkCert({ subject: "EkuBothInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ekuExt([EKU_SERVER_AUTH, EKU_CODE_SIGNING], true)] });
  var leafUnderBoth = await mkCert({ subject: "LeafUnderBoth", issuer: "EkuBothInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [ekuExt([EKU_SERVER_AUTH], false)] });
  check("intermediate EKU including the required purpose chains", (await run([interEkuBoth, leafUnderBoth], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] })).valid === true);
  // an intermediate with NO EKU is unconstrained (chaining restricts only when present).
  var interNoEku = await mkCert({ subject: "NoEkuInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leafUnderNone = await mkCert({ subject: "LeafUnderNone", issuer: "NoEkuInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [ekuExt([EKU_SERVER_AUTH], false)] });
  check("intermediate without an EKU does not constrain the path", (await run([interNoEku, leafUnderNone], { time: T2027, trustAnchor: anchor, requiredEku: ["serverAuth"] })).valid === true);

  // requiredEku is entry-point-validated.
  check("empty requiredEku throws path/bad-input", (await codeOf(run([leafNoEku], { time: T2027, trustAnchor: anchor, requiredEku: [] }))) === "path/bad-input");
  check("unregistered requiredEku name throws path/bad-input", (await codeOf(run([leafNoEku], { time: T2027, trustAnchor: anchor, requiredEku: ["no-such-purpose-name"] }))) === "path/bad-input");
}

// ---------------------------------------------------------------------------
// OCSP revocation checking (pki.path.ocspChecker) — RFC 6960
// ---------------------------------------------------------------------------

// Integration axis: drive pki.path.validate with an ocspChecker over the leaf's
// issuer (the trust anchor), so the verdict is observed on the shipped consumer.
async function testOcspRevocation() {
  var anchor = await mkAnchor("ed25519", "Root");
  var leaf = await mkCert({ subject: "OcspLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 100n });
  function goodSingle(extra) { return Object.assign({ issuerName: "Root", issuerKeyAlg: "ed25519", serial: 100, status: "good" }, extra || {}); }
  function ocspRun(resp, extra) {
    return run([leaf], Object.assign({ time: T2027, trustAnchor: anchor, revocationChecker: pki.path.ocspChecker([resp]) }, extra || {}));
  }
  function undetermined(res) { return res.valid === false && failCodes(res).indexOf("path/revocation-undetermined") !== -1; }
  function revoked(res) { return res.valid === false && failCodes(res).indexOf("path/revoked") !== -1; }

  // O1 — issuer-direct, SHA-1 CertID, good (also proves the mkOcsp fixture builder).
  var o1 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle()] });
  check("mkOcsp builds a parseable successful basic response", pki.schema.ocsp.parseResponse(o1).basicResponse.responses.length === 1);
  check("O1 OCSP good (issuer-direct, SHA-1 CertID) -> valid", (await ocspRun(o1)).valid === true);

  // O2 — the same under a SHA-256 CertID (hash-algorithm agnostic).
  var o2 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ hashAlg: "SHA-256" })] });
  check("O2 OCSP good (SHA-256 CertID) -> valid", (await ocspRun(o2)).valid === true);

  // O5 — revoked.
  var o5 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked", revocationReason: 1 })] });
  check("O5 OCSP revoked -> path/revoked", revoked(await ocspRun(o5)));

  // O7 — authoritative, current, verified, but certStatus unknown.
  var o7 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "unknown" })] });
  check("O7 OCSP unknown status -> undetermined (unknown is not good)", undetermined(await ocspRun(o7)));

  // O11 — CertID serial matches but the issuer hashes are for a DIFFERENT issuer.
  var o11 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ issuerName: "OtherCA", issuerKeyAlg: "ed25519i" })] });
  check("O11 OCSP wrong-issuer CertID -> undetermined (cross-CA same-serial defense)", undetermined(await ocspRun(o11)));

  // O12 — stale: nextUpdate already passed.
  var o12 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ nextUpdate: new Date("2027-03-01T00:00:00Z") })] });
  check("O12 OCSP stale (nextUpdate past) -> undetermined", undetermined(await ocspRun(o12)));

  // O13 — not yet valid: thisUpdate in the future.
  var o13 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ thisUpdate: new Date("2028-01-01T00:00:00Z") })] });
  check("O13 OCSP thisUpdate future -> undetermined", undetermined(await ocspRun(o13)));

  // O14 — no nextUpdate: no bounded validity, fail closed.
  var o14 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ nextUpdate: null })] });
  check("O14 OCSP no nextUpdate -> undetermined (fail-closed, replay defense)", undetermined(await ocspRun(o14)));

  // O15a/b/c — non-successful responseStatus conveys no status.
  var o15codes = [{ n: 1, name: "malformedRequest" }, { n: 3, name: "tryLater" }, { n: 6, name: "unauthorized" }];
  for (var g = 0; g < o15codes.length; g++) {
    var o15 = await mkOcsp({ responseStatus: o15codes[g].n });
    check("O15 OCSP responseStatus " + o15codes[g].name + " -> undetermined", undetermined(await ocspRun(o15)));
  }

  // O16 — the response signature is mutated (tbs intact).
  var o16 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle()], mutateSig: function (s) { var c = Buffer.from(s); c[c.length - 1] ^= 0xff; return c; } });
  check("O16 OCSP tampered signature -> undetermined", undetermined(await ocspRun(o16)));

  // O17 — a future revocationTime under historical validation is not yet effective.
  var o17 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked", revocationTime: new Date("2028-01-01T00:00:00Z"), revocationReason: 1 })] });
  check("O17 historical mode, future revocationTime -> valid", (await ocspRun(o17, { historicalMode: true })).valid === true);
  check("O17b present mode, future revocationTime -> path/revoked", revoked(await ocspRun(o17)));
  var o17c = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked", revocationTime: new Date("2027-01-01T00:00:00Z"), revocationReason: 1 })] });
  check("O17c historical mode, past revocationTime -> path/revoked", revoked(await ocspRun(o17c, { historicalMode: true })));

  // O18 — empty bundle.
  check("O18 ocspChecker([]) -> undetermined", undetermined(await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.ocspChecker([]) })));

  // O19 — a successful, authoritative response that covers only other serials.
  var o19 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ serial: 999 })] });
  check("O19 OCSP response for other serials only -> undetermined", undetermined(await ocspRun(o19)));

  // O20b — an unusable (bad-sig) response must not mask a revoking one under softFail.
  var o20bad = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle()], mutateSig: function (s) { var c = Buffer.from(s); c[c.length - 1] ^= 0xff; return c; } });
  var o20rev = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked", revocationReason: 1 })] });
  check("O20b unusable response does not mask a revoking one under softFail -> path/revoked",
    revoked(await run([leaf], { time: T2027, trustAnchor: anchor, softFail: true, revocationChecker: pki.path.ocspChecker([o20bad, o20rev]) })));

  // O22 — a non-basic responseType throws at construction (config-tier parity with crl.parse).
  var nonBasic = b.sequence([b.enumerated(0n), b.explicit(0, b.sequence([b.oid("1.3.6.1.5.5.7.48.1.2"), b.octetString(Buffer.from([1]))]))]);
  check("O22 non-basic responseType throws at construction", (await codeOf((async function () { return pki.path.ocspChecker([nonBasic]); })())) === "ocsp/unsupported-response-type");
}

// Standalone axis: drive ocspChecker(...).check(...) directly, where pki.path.validate
// would mask the verdict (authorization edges) or cannot surface revocationReason.
async function testOcspCheckerStandalone() {
  var ctx = { time: T2027, historicalMode: false };
  var caKeys = await ensureKeys("ed25519");
  var caCert = pki.schema.x509.parse(await mkCert({ subject: "Root", issuer: "Root", signWith: "ed25519", serial: 1n }));
  var leaf = pki.schema.x509.parse(await mkCert({ subject: "OcspLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 100n }));
  var issuerArg = { workingPublicKey: caKeys.spki, workingIssuerName: caCert.subject, issuerCert: caCert };
  function chk(resp, c) { return pki.path.ocspChecker([resp]).check(leaf, issuerArg, c || ctx); }
  function goodSingle(extra) { return Object.assign({ issuerName: "Root", issuerKeyAlg: "ed25519", serial: 100, status: "good" }, extra || {}); }

  // O3 — responderID byKey = SHA-1 of the issuer key value.
  var o3 = await mkOcsp({ responderID: { byKeyOf: caKeys.spki }, signWith: "ed25519", single: [goodSingle()] });
  check("O3 OCSP byKey=issuer key -> good", (await chk(o3)).status === "good");

  // O4 — delegated ECDSA-P256 responder issued by the CA with id-kp-OCSPSigning.
  var delegate = await mkCert({ subject: "OcspResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 50n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt()] });
  var o4 = await mkOcsp({ responderID: { byName: "OcspResponder" }, signWith: "p256", certs: [delegate], single: [goodSingle()] });
  check("O4 delegated responder (ECDSA, id-kp-OCSPSigning) -> good", (await chk(o4)).status === "good");

  // O4b — the same delegate identified byKey.
  var p256Keys = await ensureKeys("p256");
  var o4b = await mkOcsp({ responderID: { byKeyOf: p256Keys.spki }, signWith: "p256", certs: [delegate], single: [goodSingle()] });
  check("O4b delegated responder byKey -> good", (await chk(o4b)).status === "good");

  // O4c — a delegated responder whose SUBJECT key is a low-order Ed25519 point (the identity),
  // legitimately issued by the CA. That low-order key verifies a forged response signature (the
  // identity-point forgery, R=identity S=0, which verifies for every message) so an authorized
  // responder could assert any status by forgery. The response-signature verify path validates the
  // point first -- the revocation analogue of the certificate-path gate -- and refuses it, so the
  // forged response yields unknown, never a forged good/revoked.
  var ID_POINT = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);   // (0,1), a low-order Ed25519 point
  var loSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("Ed25519"))]), b.bitString(ID_POINT, 0)]);
  var loDelegate = await mkCert({ subject: "LoResponder", issuer: "Root", signWith: "ed25519", spki: loSpki, serial: 55n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt()] });
  var oLo = await mkOcsp({ responderID: { byName: "LoResponder" }, signWith: "ed25519", certs: [loDelegate], single: [goodSingle()], mutateSig: function () { return Buffer.concat([ID_POINT, Buffer.alloc(32)]); } });
  check("O4c low-order delegate responder key -> unknown (forged response refused)", (await chk(oLo)).status === "unknown");

  // O5 / O5b — revoked surfaces (or omits) the revocationReason.
  var o5 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked", revocationReason: 1 })] });
  var r5 = await chk(o5);
  check("O5 OCSP revoked surfaces revocationReason", r5.status === "revoked" && r5.revocationReason === "keyCompromise");
  var o5b = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked" })] });
  var r5b = await chk(o5b);
  check("O5b OCSP revoked without reason -> revoked, reason null", r5b.status === "revoked" && (r5b.revocationReason === null || r5b.revocationReason === undefined));

  // O6 — revocation surfaces through the delegated model too.
  var o6 = await mkOcsp({ responderID: { byName: "OcspResponder" }, signWith: "p256", certs: [delegate], single: [goodSingle({ status: "revoked", revocationReason: 1 })] });
  check("O6 delegated revoked -> revoked", (await chk(o6)).status === "revoked");

  // O8 — delegate lacks id-kp-OCSPSigning (serverAuth only).
  var badEku = await mkCert({ subject: "BadResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 51n, extensions: [ekuExt([EKU_SERVER_AUTH], false)] });
  var o8 = await mkOcsp({ responderID: { byName: "BadResponder" }, signWith: "p256", certs: [badEku], single: [goodSingle()] });
  check("O8 delegate without id-kp-OCSPSigning -> unknown (never good)", (await chk(o8)).status === "unknown");

  // O8b — delegate carries anyExtendedKeyUsage only.
  var anyEku = await mkCert({ subject: "AnyResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 52n, extensions: [ekuExt([EKU_ANY], false)] });
  var o8b = await mkOcsp({ responderID: { byName: "AnyResponder" }, signWith: "p256", certs: [anyEku], single: [goodSingle()] });
  check("O8b delegate anyExtendedKeyUsage only -> unknown", (await chk(o8b)).status === "unknown");

  // O9 — delegate not issued by the CA that issued the target.
  var rogue = await mkCert({ subject: "RogueResponder", issuer: "OtherCA", signWith: "ed25519i", subjectKeys: "p256", serial: 53n, extensions: [ekuExt([EKU_OCSP_SIGNING], false)] });
  var o9 = await mkOcsp({ responderID: { byName: "RogueResponder" }, signWith: "p256", certs: [rogue], single: [goodSingle()] });
  check("O9 delegate not issued by the CA -> unknown", (await chk(o9)).status === "unknown");

  // O10 — responderID matches neither the issuer nor any embedded cert.
  var o10 = await mkOcsp({ responderID: { byName: "Nobody" }, signWith: "ed25519", single: [goodSingle()] });
  check("O10 responderID matches no authorized responder -> unknown", (await chk(o10)).status === "unknown");

  // O10b — responderID names the issuer but the response is signed by an impostor key.
  var o10b = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519i", single: [goodSingle()] });
  check("O10b responderID=issuer but impostor signature -> unknown", (await chk(o10b)).status === "unknown");

  // O11b / O11c — both issuer hashes must match.
  var o11b = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ issuerKeyAlg: "ed25519i" })] });
  check("O11b issuerKeyHash mismatch -> unknown", (await chk(o11b)).status === "unknown");
  var o11c = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ issuerName: "NotRoot" })] });
  check("O11c issuerNameHash mismatch -> unknown", (await chk(o11c)).status === "unknown");

  // O16b — a SHA-1 signature algorithm is rejected (distinct from the SHA-1 CertID policy).
  var o16b = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle()], sigAlgOverride: b.sequence([b.oid("1.2.840.113549.1.1.5"), b.nullValue()]) });
  check("O16b SHA-1 signature algorithm -> unknown (CertID-hash policy != signature-hash policy)", (await chk(o16b)).status === "unknown");

  // O20 — a revoked response outranks a good one, both orderings.
  var oGood = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle()] });
  var oRev = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ status: "revoked", revocationReason: 1 })] });
  check("O20 {good,revoked} -> revoked", (await pki.path.ocspChecker([oGood, oRev]).check(leaf, issuerArg, ctx)).status === "revoked");
  check("O20 {revoked,good} -> revoked", (await pki.path.ocspChecker([oRev, oGood]).check(leaf, issuerArg, ctx)).status === "revoked");

  // O21 — an authorized OCSPSigning delegate that is expired at the validation instant.
  var expired = await mkCert({ subject: "ExpiredResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 54n, notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"), extensions: [ekuExt([EKU_OCSP_SIGNING], false)] });
  var o21 = await mkOcsp({ responderID: { byName: "ExpiredResponder" }, signWith: "p256", certs: [expired], single: [goodSingle()] });
  check("O21 expired delegate responder -> unknown", (await chk(o21)).status === "unknown");

  // O23 — the CertID issuerNameHash may be computed over the ISSUER CERTIFICATE's
  // subject encoding rather than the checked cert's issuer field. Here the checked
  // cert's issuer is "root" (lower-case) while the CA subject is "Root": RFC 5280
  // sec. 7.1-equal (name chaining passes) but a different DER encoding. A response
  // whose CertID hashes the CA subject "Root" must still match this cert.
  var caUpper = pki.schema.x509.parse(await mkCert({ subject: "Root", issuer: "Root", signWith: "ed25519", serial: 2n }));
  var leafLowerIssuer = pki.schema.x509.parse(await mkCert({ subject: "OcspLeaf", issuer: "root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 100n }));
  var issuerUpper = { workingPublicKey: caKeys.spki, workingIssuerName: caUpper.subject, issuerCert: caUpper };
  var o23 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [{ issuerName: "Root", issuerKeyAlg: "ed25519", serial: 100, status: "good" }] });
  check("O23 CertID over the issuer cert subject (RFC5280-equal, byte-different) -> good",
    (await pki.path.ocspChecker([o23]).check(leafLowerIssuer, issuerUpper, ctx)).status === "good");

  // O24 — a matching SingleResponse carrying a CRITICAL singleExtension the checker
  // does not implement is unusable (RFC 6960 sec. 4.4 / the critical-extension contract).
  var critExt = ext("1.3.6.1.4.1.99999.7", true, b.octetString(Buffer.from([1])));
  var nonCritExt = ext("1.3.6.1.4.1.99999.7", false, b.octetString(Buffer.from([1])));
  var o24 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ singleExtensions: [critExt] })] });
  check("O24 critical singleExtension -> unknown", (await chk(o24)).status === "unknown");
  var o24ok = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle({ singleExtensions: [nonCritExt] })] });
  check("O24 control: non-critical singleExtension -> good", (await chk(o24ok)).status === "good");

  // O25 — a CRITICAL responseExtension makes the whole signed response unusable.
  var o25 = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", responseExtensions: [critExt], single: [goodSingle()] });
  check("O25 critical responseExtension -> unknown", (await chk(o25)).status === "unknown");
  var o25ok = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", responseExtensions: [nonCritExt], single: [goodSingle()] });
  check("O25 control: non-critical responseExtension -> good", (await chk(o25ok)).status === "good");

  // O26 — a delegate responder cert with an unprocessed CRITICAL extension is not an
  // authorized signer (RFC 5280 sec. 6.1.4(o) critical-extension contract).
  var critDelegate = await mkCert({ subject: "CritResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 55n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), ext("1.3.6.1.4.1.99999.7", true, b.octetString(Buffer.from([1])))] });
  var o26 = await mkOcsp({ responderID: { byName: "CritResponder" }, signWith: "p256", certs: [critDelegate], single: [goodSingle()] });
  check("O26 delegate with unprocessed critical extension -> unknown", (await chk(o26)).status === "unknown");
  var okDelegate = await mkCert({ subject: "NonCritResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 56n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt(), ext("1.3.6.1.4.1.99999.7", false, b.octetString(Buffer.from([1])))] });
  var o26ok = await mkOcsp({ responderID: { byName: "NonCritResponder" }, signWith: "p256", certs: [okDelegate], single: [goodSingle()] });
  check("O26 control: delegate with non-critical extension -> good", (await chk(o26ok)).status === "good");

  // O27 — a delegate whose keyUsage does NOT permit digitalSignature cannot sign OCSP
  // responses (RFC 5280 sec. 4.2.1.3), even bearing id-kp-OCSPSigning.
  var noSigDelegate = await mkCert({ subject: "NoSigResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 57n, extensions: [kuExt([KU_CRL_SIGN]), ekuExt([EKU_OCSP_SIGNING], false)] });
  var o27 = await mkOcsp({ responderID: { byName: "NoSigResponder" }, signWith: "p256", certs: [noSigDelegate], single: [goodSingle()] });
  check("O27 delegate keyUsage without digitalSignature -> unknown", (await chk(o27)).status === "unknown");
  var sigDelegate = await mkCert({ subject: "SigResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 58n, extensions: [kuExt([KU_DIGITAL_SIGNATURE]), ekuExt([EKU_OCSP_SIGNING], false), nocheckExt()] });
  var o27ok = await mkOcsp({ responderID: { byName: "SigResponder" }, signWith: "p256", certs: [sigDelegate], single: [goodSingle()] });
  check("O27 control: delegate keyUsage with digitalSignature -> good", (await chk(o27ok)).status === "good");

  // O28 -- a delegated responder WITHOUT id-pkix-ocsp-nocheck cannot be established
  // as unrevoked by a transport-free checker, so it is not an authorized signer
  // (RFC 6960 sec. 4.2.2.2.1) -- otherwise a revoked responder keeps signing "good".
  var noNoCheck = await mkCert({ subject: "NoNoCheckResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 59n, extensions: [kuExt([KU_DIGITAL_SIGNATURE]), ekuExt([EKU_OCSP_SIGNING], false)] });
  var o28 = await mkOcsp({ responderID: { byName: "NoNoCheckResponder" }, signWith: "p256", certs: [noNoCheck], single: [goodSingle()] });
  check("O28 delegate without id-pkix-ocsp-nocheck -> unknown", (await chk(o28)).status === "unknown");

  // O29 -- a delegate with a RECOGNIZED critical extension whose value is malformed
  // must be rejected via critical-extension structure validation, exactly as the
  // path validator rejects it (not merely the unknown-critical-OID filter).
  var malformedCrit = await mkCert({ subject: "MalformedResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 60n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt(), ext("2.5.29.32", true, b.integer(1n))] });
  var o29 = await mkOcsp({ responderID: { byName: "MalformedResponder" }, signWith: "p256", certs: [malformedCrit], single: [goodSingle()] });
  check("O29 delegate with malformed critical extension -> unknown", (await chk(o29)).status === "unknown");

  // O30 -- a delegated responder that INHERITS its EC parameters from the issuing CA
  // (its SPKI omits the namedCurve, same key algorithm, RFC 5280 sec. 4.1.2.7) must
  // have them spliced before the response signature verify, else importKey has no
  // namedCurve and a valid response reads unknown.
  var ecCaKeys = await ensureKeys("p256");
  var ecCa = pki.schema.x509.parse(await mkCert({ subject: "EcRoot", issuer: "EcRoot", signWith: "p256", serial: 3n }));
  var ecLeaf = pki.schema.x509.parse(await mkCert({ subject: "EcOcspLeaf", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf", serial: 101n }));
  var ecIssuer = { workingPublicKey: ecCaKeys.spki, workingIssuerName: ecCa.subject, issuerCert: ecCa };
  var respKeys = await ensureKeys("p256i");
  var inheritDelegate = await mkCert({ subject: "InheritResponder", issuer: "EcRoot", signWith: "p256", spki: stripEcParams(respKeys.spki), serial: 61n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), kuExt([KU_DIGITAL_SIGNATURE]), nocheckExt()] });
  var o30 = await mkOcsp({ responderID: { byName: "InheritResponder" }, signWith: "p256i", certs: [inheritDelegate], single: [{ issuerName: "EcRoot", issuerKeyAlg: "p256", serial: 101, status: "good" }] });
  check("O30 delegate inheriting EC params from the CA -> good", (await pki.path.ocspChecker([o30]).check(ecLeaf, ecIssuer, ctx)).status === "good");

  // O31 -- a response embedding more than the cert cap fails closed at PARSE, so an
  // attacker-crafted certs list cannot drive unbounded pre-auth delegate verifies.
  var manyCerts = await mkOcsp({ responderID: { byName: "OcspResponder" }, signWith: "p256", certs: new Array(33).fill(delegate), single: [goodSingle()] });
  check("O31 over-cap embedded certs rejected at parse", (await codeOf((async function () { return pki.path.ocspChecker([manyCerts]); })())) === "ocsp/too-many-certs");

  // O32 -- a composite-keyed OCSP delegate (draft-ietf-lamps-pq-composite-sigs) is an
  // out-of-path signer subject to the sec. 5.2 keyUsage gate. A digitalSignature-only
  // composite delegate PASSES the gate and authorizes, so the response signature is
  // then checked through the shared verify seam under the composite key. This
  // transport-free checker has no composite signing material, so that signature
  // cannot verify -> fail closed to unknown (never "good"). The composite
  // signatureAlgorithm also drives the composite branch on the OCSP verify seam.
  var compDelegate = await mkCert({ subject: "CompositeResponder", issuer: "Root", signWith: "ed25519", spki: compositeSpki(), serial: 62n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), kuExt([KU_DIGITAL_SIGNATURE]), nocheckExt()] });
  var o32 = await mkOcsp({ responderID: { byName: "CompositeResponder" }, signWith: "ed25519", certs: [compDelegate], single: [goodSingle()], sigAlgOverride: b.sequence([b.oid(COMPOSITE_OID)]) });
  check("O32 composite digitalSignature delegate authorizes; composite response sig fails closed -> unknown", (await chk(o32)).status === "unknown");

  // O33 -- a DUAL-USAGE composite delegate (digitalSignature + keyEncipherment) passes
  // the delegate-authorization keyUsage check (digitalSignature present) but FAILS the
  // sec. 5.2 composite gate (a forbidden encryption bit), so it is NOT an authorized
  // responder -> unknown.
  var compDualKu = await mkCert({ subject: "CompositeDualResponder", issuer: "Root", signWith: "ed25519", spki: compositeSpki(), serial: 63n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), kuExt([KU_DIGITAL_SIGNATURE, 2]), nocheckExt()] });
  var o33 = await mkOcsp({ responderID: { byName: "CompositeDualResponder" }, signWith: "ed25519", certs: [compDualKu], single: [goodSingle()] });
  check("O33 dual-usage composite delegate fails the sec. 5.2 gate -> unauthorized -> unknown", (await chk(o33)).status === "unknown");
}

// Known-answer interop: the CertID issuerNameHash/issuerKeyHash conventions
// (SHA-1 over the raw issuer Name DER, and over the subjectPublicKey BIT STRING
// VALUE excluding the unused-bits octet -- RFC 6960 sec. 4.1.1) must agree with an
// independent implementation. Reference values are from `openssl x509 -ocspid`
// (OpenSSL 3.5.7) over the committed self-signed EC fixture; the issuerKeyHash
// off-by-one that self-tests green but fails real OCSP interop is pinned here.
async function testOcspCertIdInterop() {
  var pem = require("fs").readFileSync(require("path").join(__dirname, "..", "fixtures", "pkijs-selfsigned-ec.pem"), "utf8");
  var cert = pki.schema.x509.parse(pem);
  var nameHash = Buffer.from(await subtle.digest("SHA-1", cert.subject.bytes)).toString("hex").toUpperCase();
  var keyBits = pki.asn1.read.bitString(pki.asn1.decode(cert.subjectPublicKeyInfo.bytes).children[1]).bytes;
  var keyHash = Buffer.from(await subtle.digest("SHA-1", keyBits)).toString("hex").toUpperCase();
  check("OCSP issuerNameHash matches openssl -ocspid Subject OCSP hash", nameHash === "2BB4BD34D7178BC49FF1541DEAEDE9A63B5B7CF5");
  check("OCSP issuerKeyHash matches openssl -ocspid Public key OCSP hash", keyHash === "839131BE3342B9D83E4A87E3CA7409EB5626D451");
}

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Trust-anchor constraint contract (Do-FIRST): distrust-after + purpose (T19-T26)
// ---------------------------------------------------------------------------
async function testTrustAnchorConstraints() {
  // Gated so a bare anchor / absent checkPurpose is byte-identical to today.
  var anchor = await mkAnchor("ed25519", "Root");
  var D = new Date("2026-06-01T00:00:00Z");
  function leafAt(nb) { return mkCert({ subject: "Leaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", notBefore: nb }); }
  function withMeta(extra) { var a = {}; Object.keys(anchor).forEach(function (k) { a[k] = anchor[k]; }); Object.keys(extra).forEach(function (k) { a[k] = extra[k]; }); return a; }
  var BEFORE = new Date("2026-01-01T00:00:00Z"), AFTER = new Date("2026-06-01T00:00:01Z");

  // Entry-point: a bad checkPurpose is rejected like requiredEku.
  check("bad checkPurpose throws path/bad-input",
    (await codeOf(run([await leafAt(BEFORE)], { time: T2027, trustAnchor: anchor, checkPurpose: "bogusPurpose" }))) === "path/bad-input");

  var taSA = withMeta({ distrustAfter: { serverAuth: D } });
  // T19/T21 -- leaf notBefore one second AFTER distrustAfter -> distrusted (strict >).
  var r19 = await run([await leafAt(AFTER)], { time: T2027, trustAnchor: taSA, checkPurpose: "serverAuth" });
  check("T19 leaf after distrustAfter -> distrusted", r19.valid === false && failCodes(r19).indexOf("path/distrusted-after") !== -1);
  // T20 -- boundary: notBefore EXACTLY == distrustAfter -> TRUSTED; one second before -> trusted.
  var r20eq = await run([await leafAt(D)], { time: T2027, trustAnchor: taSA, checkPurpose: "serverAuth" });
  check("T20 notBefore == distrustAfter -> trusted", r20eq.valid === true && failCodes(r20eq).indexOf("path/distrusted-after") === -1);
  var r20lt = await run([await leafAt(new Date("2026-05-31T23:59:59Z"))], { time: T2027, trustAnchor: taSA, checkPurpose: "serverAuth" });
  check("T20 notBefore before distrustAfter -> trusted", r20lt.valid === true);
  // T22 -- purpose not a delegator purpose -> path/purpose-not-trusted.
  var taNot = withMeta({ purposes: { serverAuth: false, emailProtection: false, codeSigning: false } });
  var r22 = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: taNot, checkPurpose: "serverAuth" });
  check("T22 purpose not trusted -> path/purpose-not-trusted", r22.valid === false && failCodes(r22).indexOf("path/purpose-not-trusted") !== -1);
  // Constraint metadata that is NON-ENUMERABLE on an object-form-algorithm anchor must survive
  // normalization: the flat copy inherits from the entry, so a purpose restriction the validator reads
  // through normal property access is still enforced rather than silently dropped (a fail-open).
  var taObjAlgHidden = withMeta({ algorithm: { oid: anchor.algorithm } });
  Object.defineProperty(taObjAlgHidden, "purposes", { value: { serverAuth: false }, enumerable: false, configurable: true });
  var rHidden = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: taObjAlgHidden, checkPurpose: "serverAuth" });
  check("#74 a non-enumerable anchor purposes map survives object-form-algorithm normalization",
    rHidden.valid === false && failCodes(rHidden).indexOf("path/purpose-not-trusted") !== -1);
  // The purposes map is the operator's restriction, so it must answer from its OWN entries: a name
  // planted on Object.prototype would otherwise grant the purpose on every anchor that omits it.
  var taOmits = withMeta({ purposes: { emailProtection: false } });
  var t22Opts = Object.create(null);
  t22Opts.time = T2027;
  t22Opts.trustAnchor = taOmits;
  t22Opts.checkPurpose = "serverAuth";
  var leafT22 = await leafAt(BEFORE);
  var r22p;
  Object.prototype.serverAuth = true;  try { r22p = await run([leafT22], t22Opts); }
  finally { delete Object.prototype.serverAuth; }
  check("T22 a purpose planted on Object.prototype does not grant anchor trust",
    r22p.valid === false && failCodes(r22p).indexOf("path/purpose-not-trusted") !== -1);
  // T23 -- delegator for the purpose + leaf before D -> valid.
  var taOk = withMeta({ purposes: { serverAuth: true, emailProtection: false, codeSigning: false }, distrustAfter: { serverAuth: D } });
  var r23 = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: taOk, checkPurpose: "serverAuth" });
  check("T23 delegator + before D -> valid", r23.valid === true);
  // A distrustAfter that is an ACCESSOR (a getter) is REFUSED with path/bad-input, not materialized: a
  // constraint map must be an own DATA property so it is captured from its descriptor without invoking the
  // getter -- a getter could answer the gates with a restriction and the value read with {}, dropping the
  // distrust control, or mutate the sibling map when read. The distrusted leaf is still not accepted, now via
  // a fail-closed refusal at the anchor door rather than a soft distrusted-after verdict.
  var taTocDistrust = withMeta({});
  Object.defineProperty(taTocDistrust, "distrustAfter", {
    enumerable: true, configurable: true, get: function () { return { serverAuth: D }; }
  });
  check("#74 an accessor-backed distrustAfter is refused with path/bad-input (constraint maps must be own data)",
    (await codeOf(run([await leafAt(AFTER)], { time: T2027, trustAnchor: taTocDistrust, checkPurpose: "serverAuth" }))) === "path/bad-input");
  // An accessor algorithm.oid is refused before its getter runs, so a getter that would setTime() the caller's
  // own distrust Date to the future never executes: the anchor is refused for the accessor and the cutoff Date
  // is never moved.
  var mutCutoff74 = new Date(D.getTime());
  var setTimeAnchor74 = withMeta({ distrustAfter: { serverAuth: mutCutoff74 } });
  setTimeAnchor74.algorithm = { get oid() { mutCutoff74.setTime(new Date("2030-01-01T00:00:00Z").getTime()); return anchor.algorithm; } };
  check("#74 an accessor algorithm.oid is refused before its getter can setTime the caller's distrust Date (getter never invoked)",
    (await codeOf(run([await leafAt(AFTER)], { time: T2027, trustAnchor: setTimeAnchor74, checkPurpose: "serverAuth" }))) === "path/bad-input" && mutCutoff74.getTime() === D.getTime());
  // The purpose-scoped-metadata guard -- which refuses an anchor carrying purpose metadata when no
  // checkPurpose selects one -- reads the SAME value it enforces: an always-restriction accessor is refused
  // exactly like the data form, so a restriction cannot be hidden from the guard behind a getter.
  var taGetterRestrict = withMeta({});
  Object.defineProperty(taGetterRestrict, "purposes", {
    enumerable: true, configurable: true, get: function () { return { serverAuth: false }; }
  });
  check("#74 an always-restriction purposes accessor is refused without checkPurpose (guard reads what it enforces)",
    (await codeOf(run([await leafAt(BEFORE)], { time: T2027, trustAnchor: taGetterRestrict }))) === "path/bad-input");
  // A field OUTSIDE the anchor contract is never read during normalization or validation: an unrelated
  // caller accessor (here one that throws) is dropped, so a valid anchor still validates and the getter is
  // never spent -- normalization consumes only the contract fields it will bind.
  var taUnrelated = withMeta({});
  var unrelReads = 0;
  Object.defineProperty(taUnrelated, "customTag", {
    enumerable: true, configurable: true, get: function () { unrelReads++; throw new Error("unrelated anchor accessor evaluated"); }
  });
  var rUnrel = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: taUnrelated });
  check("#74 an unrelated anchor accessor is never evaluated during validate (dropped, not read)",
    rUnrel.valid === true && unrelReads === 0);
  // T24 -- bare anchor (no metadata), no checkPurpose -> identical to today (valid, no new checks).
  var r24 = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: anchor });
  check("T24 bare anchor preserved -> valid", r24.valid === true && failCodes(r24).indexOf("path/distrusted-after") === -1 && failCodes(r24).indexOf("path/purpose-not-trusted") === -1);
  // T25 -- an anchor CARRYING purpose-scoped trust metadata, validated with no checkPurpose to
  // select which purpose, is a configuration fault rather than a silent non-enforcement. The
  // constraint is keyed BY purpose, so without one there is no way to apply it -- and the caller
  // who attached a distrustAfter to their root has stated an intent that would otherwise be
  // discarded without a word. A root Mozilla distrusted in 2020 validated a 2026 leaf.
  check("T25 purpose-scoped anchor metadata without checkPurpose -> path/bad-input",
    (await codeOf(run([await leafAt(AFTER)], { time: T2027, trustAnchor: taSA }))) === "path/bad-input");
  check("T25 ...and a purposes map without checkPurpose likewise",
    (await codeOf(run([await leafAt(BEFORE)], { time: T2027, trustAnchor: withMeta({ purposes: { serverAuth: true } }) }))) === "path/bad-input");
  // ...and the verdict SAYS which purpose the anchor's metadata was judged under, so an archived
  // result can be re-read to tell an anchor that was checked from one that carried nothing.
  var r25p = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: taSA, checkPurpose: "serverAuth" });
  check("T25 the verdict names the purpose the anchor was judged under",
    r25p.anchorConstraints && r25p.anchorConstraints.checkedPurpose === "serverAuth" &&
    r25p.anchorConstraints.distrustAfterApplied === true);
  var r25bare = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: anchor });
  check("T25 a bare anchor says it carried no constraints, rather than saying nothing",
    r25bare.anchorConstraints && r25bare.anchorConstraints.checkedPurpose === null &&
    r25bare.anchorConstraints.distrustAfterApplied === false &&
    r25bare.anchorConstraints.purposeTrustApplied === false);
  // T26 -- checkPurpose emailProtection but only serverAuth distrust present -> unaffected.
  var r26 = await run([await leafAt(AFTER)], { time: T2027, trustAnchor: taSA, checkPurpose: "emailProtection" });
  check("T26 wrong-purpose distrust key -> unaffected", r26.valid === true);
  // T27 -- a PRESENT-but-malformed distrustAfter (an Invalid Date) must fail CLOSED.
  // An Invalid Date is instanceof Date, but `notBefore > InvalidDate` is NaN-false,
  // so the distrust restriction would silently NOT apply and a leaf that should be
  // distrusted passes -- the NaN-Date fail-open. The malformed caller config is a
  // config-time reject (guard.time.assertValid), not a silent bypass.
  var taBad = withMeta({ distrustAfter: { serverAuth: new Date("not-a-date") } });
  check("T27 malformed distrustAfter (Invalid Date) -> path/bad-input",
    (await codeOf(run([await leafAt(AFTER)], { time: T2027, trustAnchor: taBad, checkPurpose: "serverAuth" }))) === "path/bad-input");

  // T27 -- checkPurpose is an UNREGISTERED canonical dotted OID: oid.name returns
  // undefined, so it resolves through the fallback to the dotted string ITSELF,
  // which is then consumed as the index into the anchor's per-purpose trust map. A
  // delegator for that dotted purpose -> valid; a non-delegator -> not trusted.
  // CP_PURPOSE is a canonical dotted OID with NO registered name (a private-arc
  // sentinel that no test aliases): oid.name returns undefined, so checkPurpose
  // resolves through the fallback to the dotted string itself, which is then
  // consumed as the index into the anchor's per-purpose trust map. The computed
  // key guarantees the map key equals the resolved checkPurpose regardless of the
  // literal, so a delegator entry -> valid and a non-delegator -> not trusted.
  var CP_PURPOSE = "1.3.6.1.4.1.99999.424242";
  function purposesFor(v) { var p = {}; p[CP_PURPOSE] = v; return p; }
  var r27ok = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: withMeta({ purposes: purposesFor(true) }), checkPurpose: CP_PURPOSE });
  check("T27 unregistered dotted checkPurpose trusted via fallback -> valid", r27ok.valid === true);
  var r27no = await run([await leafAt(BEFORE)], { time: T2027, trustAnchor: withMeta({ purposes: purposesFor(false) }), checkPurpose: CP_PURPOSE });
  check("T27 unregistered dotted checkPurpose not a delegator -> purpose-not-trusted", r27no.valid === false && failCodes(r27no).indexOf("path/purpose-not-trusted") !== -1);
}

// ---------------------------------------------------------------------------
// CRL DistributionPoint<->IDP correspondence (RFC 5280 §6.3.3(b)(2)(i)) —
// a full-scope-for-its-partition shard CRL can establish "good" (D1-D13, D18).
// Monotone: the change only ADDS "good" for a corresponding + full-reason +
// current + verified shard; it never removes a "revoked" and never says "good"
// where the coarse interim reason mask is not all-reasons.
// ---------------------------------------------------------------------------
async function testCrlDpIdpCorrespondence() {
  var anchor = await mkAnchor("ed25519", "Root");
  var DSER = 4242n;
  var URL1 = "http://crl.example/a.crl", URL2 = "http://crl.example/b.crl";
  var someReasons = Buffer.from([0x06, 0x40]); // keyCompromise only
  function chk(crls, extra) {
    return Object.assign({ time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker(crls) }, extra || {});
  }
  var leafDp = await mkCert({ subject: "DpLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: DSER,
    extensions: [cdpExt([distPoint(dpnFull([gnUri(URL1)]))])] });

  // D1 — a corresponding, full-reason, current, verified shard establishes GOOD
  // (the gap this closes: previously any IDP distributionPoint meant
  // revocation-only, so a sharded CRL could never say "good").
  var crlD1 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(1), idpExt({ distributionPoint: dpnFull([gnUri(URL1)]) })] });
  var rD1 = await run([leafDp], chk([crlD1]));
  check("D1 corresponding full-reason shard establishes good", rD1.valid === true);

  // D2 — a non-corresponding shard stays UNDETERMINED (never falsely good).
  var crlD2 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(2), idpExt({ distributionPoint: dpnFull([gnUri(URL2)]) })] });
  var rD2 = await run([leafDp], chk([crlD2]));
  check("D2 non-corresponding shard undetermined", rD2.valid === false && failCodes(rD2).indexOf("path/revocation-undetermined") !== -1);

  // D3 — a corresponding shard LISTING the serial -> revoked (the good-path
  // flip must not break the revoked path).
  var crlD3 = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: DSER }], extensions: [crlNumberExt(3), idpExt({ distributionPoint: dpnFull([gnUri(URL1)]) })] });
  var rD3 = await run([leafDp], chk([crlD3]));
  check("D3 corresponding shard listing the serial revokes", rD3.valid === false && failCodes(rD3).indexOf("path/revoked") !== -1);

  // D4 — a NON-corresponding shard listing the serial still revokes, even
  // under softFail: serials are unique per issuer, so a listed serial is a
  // genuine revocation (deliberate hardening beyond the RFC minimum).
  var crlD4 = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: DSER }], extensions: [crlNumberExt(4), idpExt({ distributionPoint: dpnFull([gnUri(URL2)]) })] });
  var rD4 = await run([leafDp], chk([crlD4], { softFail: true }));
  check("D4 non-corresponding shard listing the serial revokes", rD4.valid === false && failCodes(rD4).indexOf("path/revoked") !== -1);

  // D5 — corresponding + onlySomeReasons: revocation-only under the coarse
  // rule (§6.3.3(d)(1)/(d)(2): the interim mask is below all-reasons).
  var crlD5 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(5), idpExt({ distributionPoint: dpnFull([gnUri(URL1)]), onlySomeReasons: someReasons })] });
  var rD5 = await run([leafDp], chk([crlD5]));
  check("D5 corresponding + onlySomeReasons cannot establish good", rD5.valid === false && failCodes(rD5).indexOf("path/revocation-undetermined") !== -1);

  // D6 — ...but a reason-scoped corresponding shard still reveals a revocation.
  var crlD6 = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: DSER, exts: [reasonCodeExt(1)] }], extensions: [crlNumberExt(6), idpExt({ distributionPoint: dpnFull([gnUri(URL1)]), onlySomeReasons: someReasons })] });
  var rD6 = await run([leafDp], chk([crlD6]));
  check("D6 reason-scoped corresponding shard reveals a revocation", rD6.valid === false && failCodes(rD6).indexOf("path/revoked") !== -1);

  // D7 — the CERT's matched DP carries `reasons`: §6.3.3(d)(3) sets the
  // interim mask to the DP reasons — below all-reasons, so revocation-only.
  var leafDpReasons = await mkCert({ subject: "DpLeafR", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [cdpExt([distPoint(dpnFull([gnUri(URL1)]), someReasons)])] });
  var crlD7 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(7), idpExt({ distributionPoint: dpnFull([gnUri(URL1)]) })] });
  var rD7 = await run([leafDpReasons], chk([crlD7]));
  check("D7 cert DP reasons -> revocation-only", rD7.valid === false && failCodes(rD7).indexOf("path/revocation-undetermined") !== -1);

  // D8 — nameRelativeToCRLIssuer on BOTH sides, byte-identical RDN -> GOOD
  // (both fragments append to the same base DN: the checker already gates
  // crl.issuer == cert.issuer and rejects indirect CRLs).
  var relAtv = atv("2.5.4.3", "Shard1");
  var leafRel = await mkCert({ subject: "RelLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [cdpExt([distPoint(dpnRel([relAtv]))])] });
  var crlD8 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(8), idpExt({ distributionPoint: dpnRel([relAtv]) })] });
  var rD8 = await run([leafRel], chk([crlD8]));
  check("D8 identical-RDN correspondence establishes good", rD8.valid === true);

  // D9 — MIXED DPN forms (fullName vs nameRelativeToCRLIssuer) never
  // correspond: cross-form resolution against the issuer DN is not attempted
  // (fail closed; deferred until an operator needs it).
  var crlD9 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(9), idpExt({ distributionPoint: dpnRel([relAtv]) })] });
  var rD9 = await run([leafDp], chk([crlD9]));
  check("D9 mixed DPN forms undetermined", rD9.valid === false && failCodes(rD9).indexOf("path/revocation-undetermined") !== -1);

  // D10a — a freshestCRL on the cert is decoded but INERT: it locates delta
  // CRLs only (§5.2.6) and must not feed the correspondence.
  var leafFreshest = await mkCert({ subject: "FrLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [cdpExt([distPoint(dpnFull([gnUri(URL1)]))]), freshestExt([distPoint(dpnFull([gnUri(URL2)]))])] });
  var rD10a = await run([leafFreshest], chk([crlD1]));
  check("D10a freshestCRL decode inert; corresponding shard still good", rD10a.valid === true);

  // D10b — a CORRESPONDING delta still fails closed to undetermined (no
  // base+delta merge; decoding freshestCRL/CDP must not enable a partial merge).
  var crlD10b = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(10), idpExt({ distributionPoint: dpnFull([gnUri(URL1)]) }), ext("2.5.29.27", true, b.integer(1n))] });
  var rD10b = await run([leafDp], chk([crlD10b]));
  check("D10b corresponding delta stays undetermined", rD10b.valid === false && failCodes(rD10b).indexOf("path/revocation-undetermined") !== -1);

  // D11 — behavior-preserving: a no-IDP full-scope CRL still establishes GOOD
  // for a cert that HAS a CDP (§6.3.3's fallback: a CRL not specified in any
  // DP is processed with an assumed DP naming the certificate issuer).
  var crlD11 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(11)] });
  var rD11 = await run([leafDp], chk([crlD11]));
  check("D11 full no-IDP CRL still establishes good for a cert with a CDP", rD11.valid === true);

  // D12 — (decision) a NON-critical IDP cannot vouch for its partition:
  // §5.2.5 describes the IDP as "a critical CRL extension" (descriptive, not
  // an imperative MUST), and a partition scope a non-supporting relying party
  // would ignore is not a scope to build "good" on — deliberate fail-closed
  // decision. The shard remains consultable for revocation.
  var crlD12 = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(12), ext("2.5.29.28", false, idpVal({ distributionPoint: dpnFull([gnUri(URL1)]) }))] });
  var rD12 = await run([leafDp], chk([crlD12]));
  check("D12 non-critical IDP cannot establish good", rD12.valid === false && failCodes(rD12).indexOf("path/revocation-undetermined") !== -1);

  // D13 — a malformed cert CDP (a DP with ONLY reasons violates "a
  // DistributionPoint MUST NOT consist of only the reasons field") fails
  // closed without crashing: DP-scoped shards stay revocation-only, the
  // full-CRL path is unaffected.
  var leafBadCdp = await mkCert({ subject: "BadCdpLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [ext("2.5.29.31", false, b.sequence([b.sequence([b.contextPrimitive(1, someReasons)])]))] });
  var rD13a = await run([leafBadCdp], chk([crlD1]));
  check("D13 malformed cert CDP: DP-scoped shard undetermined (no crash)", rD13a.valid === false && failCodes(rD13a).indexOf("path/revocation-undetermined") !== -1);
  var rD13b = await run([leafBadCdp], chk([crlD11]));
  check("D13 malformed cert CDP: full no-IDP CRL still good", rD13b.valid === true);

  // D18 — a malformed DPN inside the IDP leaves the CRL's scope UNKNOWN: the
  // shard is skipped as unusable, so it neither establishes good NOR reveals
  // a revocation (contrast D4, where a WELL-FORMED non-corresponding shard is
  // still consulted for revocation).
  var crlD18a = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: DSER }], extensions: [crlNumberExt(13), idpExt({ distributionPoint: b.contextConstructed(0, Buffer.alloc(0)) })] });
  var rD18a = await run([leafDp], chk([crlD18a]));
  check("D18 empty-fullName IDP DPN -> shard skipped (undetermined, not revoked)",
    rD18a.valid === false && failCodes(rD18a).indexOf("path/revocation-undetermined") !== -1 && failCodes(rD18a).indexOf("path/revoked") === -1);
  var crlD18b = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(14), idpExt({ distributionPoint: b.contextConstructed(2, gnUri(URL1)) })] });
  var rD18b = await run([leafDp], chk([crlD18b]));
  check("D18 non-[0]/[1] IDP DPN alternative -> shard skipped (undetermined)",
    rD18b.valid === false && failCodes(rD18b).indexOf("path/revocation-undetermined") !== -1);

  // D19 -- cRLDistributionPoints is a PROCESSED extension (the checker consults
  // it for the sec. 6.3.3 correspondence), so a CRITICAL instance (legal:
  // sec. 4.2.1.13 is only a SHOULD-non-critical) is recognized, not rejected as
  // an unrecognized critical extension.
  var leafCritDp = await mkCert({ subject: "CritDpLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [ext("2.5.29.31", true, b.sequence([distPoint(dpnFull([gnUri(URL1)]))]))] });
  var rD19 = await run([leafCritDp], { time: T2027, trustAnchor: anchor });
  check("D19 critical cRLDistributionPoints is recognized (processed)",
    rD19.valid === true && failCodes(rD19).indexOf("path/unrecognized-critical-extension") === -1);
  // D19b -- recognized means VALIDATED: a critical CDP whose value is malformed
  // (an empty SEQUENCE violates SIZE 1..MAX) fails typed on the structural
  // check, never passes the criticality gate unprocessed.
  var leafBadCritDp = await mkCert({ subject: "BadCritDpLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [ext("2.5.29.31", true, b.sequence([]))] });
  var rD19b = await run([leafBadCritDp], { time: T2027, trustAnchor: anchor });
  check("D19b malformed critical cRLDistributionPoints fails typed",
    rD19b.valid === false && failCodes(rD19b).indexOf("path/bad-crl-distribution-points") !== -1);
  // D19c -- freshestCRL stays OUT of the processed set: sec. 4.2.1.15 says the
  // extension MUST be non-critical, and the validator does not consult it (no
  // delta merge), so a critical instance keeps failing unrecognized-critical.
  var leafCritFresh = await mkCert({ subject: "CritFreshLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    extensions: [ext("2.5.29.46", true, b.sequence([distPoint(dpnFull([gnUri(URL2)]))]))] });
  var rD19c = await run([leafCritFresh], { time: T2027, trustAnchor: anchor });
  check("D19c critical freshestCRL still unrecognized-critical (MUST be non-critical)",
    rD19c.valid === false && failCodes(rD19c).indexOf("path/unrecognized-critical-extension") !== -1);
}

// ---------------------------------------------------------------------------
// Adversarial coverage edges -- each vector drives a fail-closed / malformed /
// out-of-range branch of the shipped pki.path surface that the accept/reject
// suites above do not reach: signature-algorithm-parameter resolution faults
// (RSASSA-PSS + the fixed-shape check), the algorithm-confusion key read, the
// ECDSA DER->P1363 bridge rejections, the RFC 5280 sec. 4.2.1.10 name-form
// comparison edges (malformed mailbox / multi-"@" URI authority / IP length
// mismatch / directoryName prefix), the entry-point 6.1.1 seed + option
// validation, every prepareNext / 6.1.5-wrapup extension-decode fault, and the
// CRL / OCSP checker fail-closed skips (unusable IDP, critical CRL-entry
// extension, delegated-responder disqualifications).
var PSS_OID = "1.2.840.113549.1.1.10";
function _hashSeq(o) { return b.sequence([b.oid(o), b.nullValue()]); }
function _mgfSeq(inner) { return b.sequence([b.oid(OID_MGF1), _hashSeq(inner)]); }

// Re-wrap a signed certificate/CRL DER so its signature BIT STRING declares a
// NON-zero unused-bits count (not octet-aligned). The signature bytes are already
// going to fail verification; clearing the last content bit keeps the BIT STRING
// valid DER (unused bits must be zero) so the parser accepts it and the
// guard.crypto.isOctetAligned fail-closed check is what rejects it.
function reSignUnaligned(der) {
  var n = pki.asn1.decode(der);
  var body = Buffer.from(pki.asn1.read.bitString(n.children[2]).bytes);
  body[body.length - 1] &= 0xfe;
  return b.sequence([b.raw(n.children[0].bytes), b.raw(n.children[1].bytes), b.bitString(body, 1)]);
}

// The two verbs in this module spell the anchor option differently. validate takes
// `trustAnchor` and build takes `trustAnchors`, so a caller moving between them carries the
// wrong one without leaving the namespace. Each refuses the other's spelling and says which
// is which, instead of ignoring it and reporting a missing anchor the caller believes it gave.
async function testUnknownOptionsRefused() {
  var codeOf = async function (p) {
    try { await p; return null; } catch (e) { return e && e.code; }
  };
  var msgOf = async function (p) {
    try { await p; return ""; } catch (e) { return (e && e.message) || ""; }
  };
  var anchor = { name: "x", publicKey: Buffer.alloc(1), algorithm: "Ed25519" };

  check("validate refuses the plural trustAnchors",
        await codeOf(pki.path.validate([], { time: new Date(), trustAnchors: [anchor] })) === "path/bad-input");
  check("validate's refusal names the singular it wants and the verb taking the plural",
        /trustAnchor.*singular/.test(await msgOf(
          pki.path.validate([], { time: new Date(), trustAnchors: [anchor] }))));
  check("build refuses the singular trustAnchor",
        await codeOf(pki.path.build(Buffer.alloc(1), { time: new Date(), trustAnchor: anchor })) === "path/bad-input");
  check("build's refusal names the plural it wants",
        /trustAnchors.*plural/.test(await msgOf(
          pki.path.build(Buffer.alloc(1), { time: new Date(), trustAnchor: anchor }))));
  check("validate refuses a misspelled option generally",
        await codeOf(pki.path.validate([], { time: new Date(), trustAnchor: anchor, softFale: true })) === "path/bad-input");
  // build forwards every validate option, so a validate-only option must still be accepted by
  // build. The union is what stops this gate rejecting the toolkit's own internal calls.
  // The assertion is on the message rather than the code: this fixture's leaf is not a
  // certificate, so the call fails with path/bad-input either way and the code alone cannot
  // tell which reason.
  check("build accepts a validate-only option it forwards",
        !/unknown option/.test(await msgOf(pki.path.build(Buffer.alloc(1), {
          time: new Date(), trustAnchors: [anchor], candidates: [], requiredEku: ["serverAuth"]
        }))));
}

async function testCoverageEdges() {
  var anchor = await mkAnchor("ed25519", "Root");
  var anchorEc = await mkAnchor("p256", "EcRoot");
  var R = [];
  async function cap(label, fn) {
    try {
      var res = await fn();
      if (res && typeof res.valid === "boolean") R.push({ label: label, valid: res.valid, codes: failCodes(res) });
      else if (res && typeof res.status === "string") R.push({ label: label, status: res.status });
      else R.push({ label: label, ret: String(res) });
    } catch (e) { R.push({ label: label, threw: (e && e.code) || (e && e.name) || String(e) }); }
  }

  // ---- RSASSA-PSS parameter resolution (a signatureAlgorithm bypass surface) --
  async function pssLeaf(paramsChild, subj) {
    var alg = paramsChild ? b.sequence([b.oid(PSS_OID), paramsChild]) : b.sequence([b.oid(PSS_OID)]);
    return run([await mkCert({ subject: subj, issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: alg })], { time: T2027, trustAnchor: anchor });
  }
  await cap("206 PSS absent parameters", async function () { return pssLeaf(null, "Pss206"); });
  await cap("213 PSS param field not context-tagged", async function () { return pssLeaf(b.sequence([b.integer(1n)]), "Pss213"); });
  await cap("245 PSS mgf present but no hashAlgorithm", async function () { return pssLeaf(b.sequence([b.explicit(1, _mgfSeq(OID_SHA256))]), "Pss245"); });
  await cap("248 PSS mask-gen OID not mgf1", async function () { return pssLeaf(b.sequence([b.explicit(0, _hashSeq(OID_SHA256)), b.explicit(1, b.sequence([b.oid("1.2.840.113549.1.1.9"), _hashSeq(OID_SHA256)]))]), "Pss248"); });
  await cap("249 PSS mgf1 without inner hash", async function () { return pssLeaf(b.sequence([b.explicit(0, _hashSeq(OID_SHA256)), b.explicit(1, b.sequence([b.oid(OID_MGF1)]))]), "Pss249"); });
  await cap("239+252 PSS trailerField != 1", async function () { return pssLeaf(b.sequence([b.explicit(0, _hashSeq(OID_SHA256)), b.explicit(1, _mgfSeq(OID_SHA256)), b.explicit(3, b.integer(2n))]), "Pss252"); });

  // ---- fixed-shape signatureAlgorithm parameters (RFC 4055 / 5758 / 8410) -----
  await cap("267 RSA PKCS1 with absent params", async function () {
    return run([await mkCert({ subject: "P267", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: b.sequence([b.oid("1.2.840.113549.1.1.11")]) })], { time: T2027, trustAnchor: anchor });
  });
  await cap("268 Ed25519 with present params", async function () {
    return run([await mkCert({ subject: "P268", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: b.sequence([b.oid("1.3.101.112"), b.nullValue()]) })], { time: T2027, trustAnchor: anchor });
  });

  // ---- 284 algorithm-confusion issuer-key read fault (one-shot sameKeyOid) ----
  await cap("284 malformed issuer SPKI for a sameKeyOid alg", async function () {
    var badAnchor = { name: anchor.name, publicKey: Buffer.from([0x30, 0x00]), algorithm: "1.3.101.112" };
    return (async function () {
      var leaf = await mkCert({ subject: "Akm284", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
      return run([leaf], { time: T2027, trustAnchor: badAnchor });
    })();
  });

  // ---- ECDSA DER->P1363 bridge rejections ------------------------------------
  await cap("298 ECDSA signature not a DER SEQUENCE", async function () {
    return run([await mkCert({ subject: "Ec298", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf", mutateSig: function () { return Buffer.from([0xff, 0x01, 0x02]); } })], { time: T2027, trustAnchor: anchorEc });
  });
  await cap("299 ECDSA signature not two INTEGERs", async function () {
    return run([await mkCert({ subject: "Ec299", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf", mutateSig: function () { return b.sequence([b.integer(1n)]); } })], { time: T2027, trustAnchor: anchorEc });
  });

  // ---- RFC 5280 sec. 4.2.1.10 name-form comparison edges ----------------------
  async function ncCase(permitted, excluded, leafSanGns, leafSubject) {
    var inter = await mkCert({ subject: "NcI", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(permitted, excluded)]) });
    var leaf = await mkCert({ subject: leafSubject || "NcL", issuer: "NcI", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: leafSanGns ? [sanExt(leafSanGns)] : [] });
    return run([inter, leaf], { time: T2027, trustAnchor: anchor });
  }
  await cap("401+544 rfc822 SAN without '@' vs host constraint", async function () { return ncCase([gnEmail("example.com")], null, [gnEmail("noatsign")]); });
  await cap("418 rfc822 SAN without '@' vs full-mailbox constraint", async function () { return ncCase([gnEmail("user@example.com")], null, [gnEmail("noat")]); });
  await cap("426 rfc822 SAN with empty host", async function () { return ncCase([gnEmail("example.com")], null, [gnEmail("user@")]); });
  await cap("441 empty dNSName permitted seed matches all", async function () {
    var leaf = await mkCert({ subject: "Empty441", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("anything.example")])] });
    return run([leaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 2, base: "" }] });
  });
  await cap("442 leading-dot dNSName permitted matches subdomain", async function () { return ncCase([gnDns(".example.com")], null, [gnDns("www.example.com")]); });
  await cap("488 URI SAN multi-'@' authority", async function () { return ncCase([gnUri("example.com")], null, [gnUri("http://a@b@evil.example/")]); });
  await cap("496 IPv4 constraint vs IPv6 SAN length mismatch", async function () { return ncCase([gnIp([192, 168, 0, 0, 255, 255, 0, 0])], null, [gnIp([32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])]); });
  await cap("523 directoryName constraint longer than subject", async function () { return ncCase([gnDirectoryName(nameDer([b.set([atv("2.5.4.3", "A")]), b.set([atv("2.5.4.11", "OU1")])]))], null, null, "SingleCN523"); });
  await cap("525 directoryName constraint RDN mismatch", async function () { return ncCase([gnDirectoryName(nameDer("ConstraintCN"))], null, null, "DifferentCN525"); });

  // ---- 6.1.1(b,c) subtree-seed base validation (isSubtreeBaseValid) -----------
  var plainLeaf = await mkCert({ subject: "SeedLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var seedName2 = pki.schema.x509.parse(await mkCert({ subject: "Seed668", issuer: "Seed668", signWith: "ed25519" })).subject;
  var leaf668 = await mkCert({ subject: [b.set([atv("2.5.4.3", "Seed668")]), b.set([atv("2.5.4.11", "Unit")])], issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  await cap("666 iPAddress seed 8-octet base accepted", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 7, base: Buffer.from([10, 0, 0, 0, 255, 0, 0, 0]) }] }); });
  await cap("666 iPAddress seed 4-octet base rejected", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 7, base: Buffer.from([10, 0, 0, 0]) }] }); });
  await cap("668 directoryName seed Name base accepted", async function () { return run([leaf668], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 4, base: seedName2 }] }); });
  await cap("668 directoryName seed non-Name base rejected", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 4, base: {} }] }); });
  await cap("669 registeredID seed base accepted", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 8, base: "1.2.3.4" }] }); });
  await cap("669 default-form seed undefined base rejected", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 5 }] }); });

  // ---- 838 malformed extendedKeyUsage under requiredEku ----------------------
  await cap("838 malformed EKU with requiredEku", async function () {
    return run([await mkCert({ subject: "Eku838", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.37", false, b.integer(1n))] })], { time: T2027, trustAnchor: anchor, requiredEku: ["1.3.6.1.5.5.7.3.1"] });
  });

  // ---- prepareNext extension-decode faults on an intermediate (i != n) -------
  async function interCase(interExts) {
    var inter = await mkCert({ subject: "MInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: interExts });
    var leaf = await mkCert({ subject: "MLeaf", issuer: "MInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
    return run([inter, leaf], { time: T2027, trustAnchor: anchor });
  }
  await cap("860 intermediate malformed policyMappings", async function () { return interCase(caExts([ext("2.5.29.33", false, b.integer(5n))])); });
  await cap("889 intermediate malformed policyConstraints", async function () { return interCase(caExts([ext("2.5.29.36", true, b.integer(5n))])); });
  await cap("893 intermediate policyConstraints requireExplicitPolicy clamps", async function () {
    return (async function () {
      var inter = await mkCert({ subject: "PcInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([pcExt({ requireExplicitPolicy: 0 }), cpExt(["1.3.6.1.4.1.99999.1"])]) });
      var leaf = await mkCert({ subject: "PcLeaf", issuer: "PcInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt(["1.3.6.1.4.1.99999.1"])] });
      return run([inter, leaf], { time: T2027, trustAnchor: anchor });
    })();
  });
  await cap("898 intermediate malformed inhibitAnyPolicy", async function () { return interCase(caExts([ext("2.5.29.54", true, b.sequence([]))])); });
  await cap("906 intermediate malformed basicConstraints", async function () { return interCase([kuExt([KU_KEY_CERT_SIGN]), ext("2.5.29.19", true, b.integer(5n))]); });
  await cap("926 intermediate malformed keyUsage", async function () { return interCase([bcExt(true), ext("2.5.29.15", true, b.sequence([]))]); });

  // ---- 6.1.5 wrap-up extension-decode faults on the target cert (i == n) -----
  await cap("1234 target malformed policyConstraints", async function () { return run([await mkCert({ subject: "T1234", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.36", true, b.integer(5n))] })], { time: T2027, trustAnchor: anchor }); });
  await cap("1246 target malformed policyMappings", async function () { return run([await mkCert({ subject: "T1246", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.33", false, b.integer(5n))] })], { time: T2027, trustAnchor: anchor }); });
  await cap("1256 target malformed nameConstraints", async function () { return run([await mkCert({ subject: "T1256", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.30", true, b.integer(5n))] })], { time: T2027, trustAnchor: anchor }); });
  await cap("1260 target malformed inhibitAnyPolicy", async function () { return run([await mkCert({ subject: "T1260", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.54", true, b.sequence([]))] })], { time: T2027, trustAnchor: anchor }); });

  // ---- validate() entry-point validation -------------------------------------
  var e1Leaf = await mkCert({ subject: "E1", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  await cap("1055+1062+1065 no opts + DER path element", async function () { return pki.path.validate([e1Leaf]); });
  await cap("1056 non-array path", async function () { return pki.path.validate("nope", { time: T2027, trustAnchor: anchor }); });
  await cap("1102 requiredEku non-string entry", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, requiredEku: [123] }); });
  await cap("1119 checkPurpose non-string", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, checkPurpose: 123 }); });
  var directLeaf = await mkCert({ subject: "DirectCP", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  await cap("1122 checkPurpose dotted OID normalized", async function () { return run([directLeaf], { time: T2027, trustAnchor: anchor, checkPurpose: "1.3.6.1.5.5.7.3.1" }); });

  // ---- verifier / revocationChecker that throw -------------------------------
  await cap("1160 custom verifier throws", async function () { return run([directLeaf], { time: T2027, trustAnchor: anchor, verifier: { verify: function () { throw new Error("boom"); } } }); });
  await cap("1198 revocationChecker throws", async function () { return run([directLeaf], { time: T2027, trustAnchor: anchor, revocationChecker: { check: function () { throw new Error("boom"); } } }); });

  // ---- 1179 name chaining over a control-byte issuer DN ----------------------
  await cap("1179 control-byte issuer DN fails name chaining", async function () {
    var badIssuer = [b.set([atv("2.5.4.3", "Bad" + String.fromCharCode(1) + "CA")])];
    return (async function () {
      var leaf = await mkCert({ subject: "CtrlLeaf", issuer: badIssuer, signWith: "ed25519", subjectKeys: "ed25519leaf" });
      return run([leaf], { time: T2027, trustAnchor: anchor });
    })();
  });

  // ---- CRL checker fail-closed edges -----------------------------------------
  var crlLeaf = await mkCert({ subject: "CrlEdgeLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 5001n, extensions: [cdpExt([distPoint(dpnFull([gnUri("http://crl.example/a")]))])] });
  await cap("1393 IDP distributionPoint wrapping two DPNs", async function () {
    var crl2 = mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(30), idpExt({ distributionPoint: Buffer.concat([dpnFull([gnUri("http://crl.example/a")]), dpnFull([gnUri("http://crl.example/b")])]) })] });
    return (async function () { return run([crlLeaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([await crl2]) }); })();
  });
  await cap("1498 crlChecker() no-arg -> undetermined", async function () { return run([crlLeaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker() }); });
  await cap("1498 crlChecker with pre-parsed CRL -> revoked", async function () {
    return (async function () {
      var parsedCrl = pki.schema.crl.parse(await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 5001n }] }));
      return run([crlLeaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([parsedCrl]) });
    })();
  });
  await cap("1594 critical unknown CRL-entry extension -> unusable", async function () {
    return (async function () {
      var crlE = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 5001n, exts: [ext("1.3.6.1.4.1.99999.55", true, b.octetString(Buffer.from([1])))] }], extensions: [crlNumberExt(31)] });
      return run([crlLeaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlE]) });
    })();
  });
  // 1438/1439 cert DistributionPoint cRLIssuer gating (correspondingCertDp)
  await cap("1439 cert DP cRLIssuer names another party -> revocation-only", async function () {
    return (async function () {
      var dp = b.sequence([b.contextConstructed(0, dpnFull([gnUri("http://crl.example/a")])), b.contextConstructed(2, gnDirectoryName(nameDer("OtherCA")))]);
      var leafCi = await mkCert({ subject: "CrlIssuerLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 5101n, extensions: [ext("2.5.29.31", false, b.sequence([dp]))] });
      var crlCi = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(32), idpExt({ distributionPoint: dpnFull([gnUri("http://crl.example/a")]) })] });
      return run([leafCi], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCi]) });
    })();
  });
  await cap("1438 cert DP without distributionPoint (cRLIssuer only) -> revocation-only", async function () {
    return (async function () {
      var dp = b.sequence([b.contextConstructed(2, gnDirectoryName(nameDer("Root")))]);
      var leafCi = await mkCert({ subject: "CrlIssuerOnlyLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 5102n, extensions: [ext("2.5.29.31", false, b.sequence([dp]))] });
      var crlCi = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(33), idpExt({ distributionPoint: dpnFull([gnUri("http://crl.example/a")]) })] });
      return run([leafCi], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCi]) });
    })();
  });
  // 1466 the cRLIssuer directoryName carries an embedded control byte, so the RFC 5280 sec. 7.1
  // DN comparison (dnEqual, via guard.name) REJECTS it and crlIssuerNamesIssuer swallows the
  // fault to false: a malformed indirect-CRL issuer name never corresponds, its DP is excluded,
  // and the shard cannot establish non-revocation (fail closed to undetermined). Drives the
  // crlIssuerNamesIssuer catch explicitly, distinct from the valid-mismatch path above.
  await cap("1466 cert DP cRLIssuer is a control-byte directoryName -> excluded, revocation-only", async function () {
    return (async function () {
      var badCrlIssuer = nameDer([b.set([atv("2.5.4.3", "R" + String.fromCharCode(1) + "oot")])]);
      var dp = b.sequence([b.contextConstructed(0, dpnFull([gnUri("http://crl.example/a")])), b.contextConstructed(2, gnDirectoryName(badCrlIssuer))]);
      var leafCi = await mkCert({ subject: "CrlIssuerCtrlByteLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 5103n, extensions: [ext("2.5.29.31", false, b.sequence([dp]))] });
      var crlCi = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(34), idpExt({ distributionPoint: dpnFull([gnUri("http://crl.example/a")]) })] });
      return run([leafCi], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCi]) });
    })();
  });

  // ---- OCSP checker fail-closed edges (standalone check surface) --------------
  var caKeys = await ensureKeys("ed25519");
  var caCert = pki.schema.x509.parse(await mkCert({ subject: "Root", issuer: "Root", signWith: "ed25519", serial: 1n }));
  var ocspLeaf = pki.schema.x509.parse(await mkCert({ subject: "OcspEdgeLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 700n }));
  var issuerArg = { workingPublicKey: caKeys.spki, workingIssuerName: caCert.subject, issuerCert: caCert };
  var octx = { time: T2027, historicalMode: false };
  function goodSingle700(extra) { return Object.assign({ issuerName: "Root", issuerKeyAlg: "ed25519", serial: 700, status: "good" }, extra || {}); }
  var delegateOk = await mkCert({ subject: "OcspResponder", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 50n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt()] });

  await cap("1932 ocspChecker() no-arg -> undetermined", async function () { return run([e1Leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.ocspChecker() }); });
  await cap("1962 non-successful OCSP response -> undetermined", async function () {
    return (async function () {
      var o = await mkOcsp({ responseStatus: 3 });
      return run([e1Leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.ocspChecker([o]) });
    })();
  });
  await cap("1948 unreadable issuer key -> unknown", async function () {
    return (async function () {
      var o = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle700()] });
      return pki.path.ocspChecker([o]).check(ocspLeaf, { workingPublicKey: Buffer.from([0x30, 0x00]), workingIssuerName: caCert.subject, issuerCert: null }, octx);
    })();
  });
  await cap("1853 garbage embedded responder cert -> unknown", async function () {
    return (async function () {
      var o = await mkOcsp({ responderID: { byName: "OcspResponder" }, signWith: "p256", certs: [b.sequence([b.integer(1n)])], single: [goodSingle700()] });
      return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
    })();
  });
  await cap("1859 responder cert does not identify responderID -> unknown", async function () {
    return (async function () {
      var o = await mkOcsp({ responderID: { byName: "SomeoneElse" }, signWith: "p256", certs: [delegateOk], single: [goodSingle700()] });
      return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
    })();
  });
  await cap("1866 delegate signature does not verify -> unknown", async function () {
    return (async function () {
      var d = await mkCert({ subject: "SigFailResp", issuer: "Root", signWith: "ed25519i", subjectKeys: "p256", serial: 701n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt()] });
      var o = await mkOcsp({ responderID: { byName: "SigFailResp" }, signWith: "p256", certs: [d], single: [goodSingle700()] });
      return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
    })();
  });
  await cap("1872 delegate malformed EKU -> unknown", async function () {
    return (async function () {
      var d = await mkCert({ subject: "BadEkuResp", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 702n, extensions: [ext("2.5.29.37", false, b.integer(1n)), nocheckExt()] });
      var o = await mkOcsp({ responderID: { byName: "BadEkuResp" }, signWith: "p256", certs: [d], single: [goodSingle700()] });
      return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
    })();
  });
  await cap("1879 delegate malformed keyUsage -> unknown", async function () {
    return (async function () {
      var d = await mkCert({ subject: "BadKuResp", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 703n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), ext("2.5.29.15", false, b.sequence([])), nocheckExt()] });
      var o = await mkOcsp({ responderID: { byName: "BadKuResp" }, signWith: "p256", certs: [d], single: [goodSingle700()] });
      return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
    })();
  });

  // ---- 268b ECDSA signatureAlgorithm carrying a (forbidden) NULL parameters ---
  // Unlike the EdDSA 268 case (the x509 parser rejects EdDSA-with-parameters
  // first), an ECDSA signatureAlgorithm with a spurious NULL survives parsing and
  // reaches resolveDescriptor, which rejects the "absent"-shaped algorithm.
  await cap("268b ECDSA sigAlg with NULL params", async function () {
    return run([await mkCert({ subject: "Ecdsa268b", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf", sigAlgOverride: b.sequence([b.oid("1.2.840.10045.4.3.2"), b.nullValue()]) })], { time: T2027, trustAnchor: anchorEc });
  });

  // ---- 488 URI SAN with a SINGLE-'@' authority (userinfo stripped to host) -----
  // The existing 488 case is a MULTI-'@' authority (uriHost fails closed before
  // the slice); this drives the single-'@' branch that strips the userinfo.
  await cap("488b URI SAN single-'@' authority within a URI subtree", async function () { return ncCase([gnUri("host.example.com")], null, [gnUri("http://user@host.example.com/")]); });

  // ---- 665/666 subtree-seed base validation for the string + Uint8Array forms --
  await cap("665 rfc822Name (tag 1) string seed accepted", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 1, base: "user@host.example" }] }); });
  await cap("665 URI (tag 6) string seed accepted", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 6, base: "host.example" }] }); });
  await cap("666 iPAddress seed base as a plain Uint8Array accepted", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, initialPermittedSubtrees: [{ tag: 7, base: new Uint8Array([10, 0, 0, 0, 255, 0, 0, 0]) }] }); });

  // ---- 812 a certificate whose own SPKI carries explicit key parameters --------
  // An EC subject key SPKI states its namedCurve as AlgorithmIdentifier
  // parameters, so updateWorkingKey copies them rather than inheriting/clearing.
  await cap("812 EC subject-key parameters copied into the working key", async function () { return run([await mkCert({ subject: "EcKeyLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "p256", serial: 812n })], { time: T2027, trustAnchor: anchor }); });

  // ---- 1124 checkPurpose is a canonical dotted OID with no registered name -----
  await cap("1124 unregistered dotted checkPurpose kept as the dotted OID", async function () { return run([plainLeaf], { time: T2027, trustAnchor: anchor, checkPurpose: "1.3.6.1.4.1.99999.77" }); });

  // ---- composite ML-DSA keyUsage gate at the leaf (draft sec. 5.2) ------------
  // 475 a composite-keyed leaf with NO keyUsage places no restriction (RFC 5280
  // sec. 4.2.1.3): compositeKeyUsageCheck returns ok, the ed25519 anchor signs the
  // leaf so the signature verifies, and the 1-cert path is valid.
  await cap("475 composite-keyed leaf without keyUsage -> path valid", async function () {
    return run([await mkCert({ subject: "CompNoKu", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", spki: compositeSpki() })], { time: T2027, trustAnchor: anchor });
  });
  // 481 a composite keyUsage asserting ONLY a reserved bit (>= 9) decodes with every
  // NAMED flag false: it clears the encryption gate but asserts no signature bit, so
  // the sec. 5.2 signature-only rule rejects the composite key. (bit 9: 03 03 06 00 40.)
  await cap("481 composite keyUsage asserts no signature bit -> rejected", async function () {
    return run([await mkCert({ subject: "CompBit9", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", spki: compositeSpki(), extensions: [ext("2.5.29.15", true, b.bitString(Buffer.from([0x00, 0x40]), 6))] })], { time: T2027, trustAnchor: anchor });
  });

  // ---- ML-KEM keyUsage gate (RFC 9935 sec. 5) ---------------------------------
  // A certificate whose SPKI carries an id-ml-kem-* OID, IF it has a keyUsage
  // extension, MUST assert keyEncipherment as the ONLY key usage set. Absent
  // keyUsage places no restriction (RFC 5280 sec. 4.2.1.3). An ML-KEM key cannot
  // sign, so the cert is always signed by a non-KEM issuer key.
  var KU_KEY_ENCIPHERMENT = 2, KU_NON_REPUDIATION = 1, KU_DATA_ENCIPHERMENT = 3, KU_KEY_AGREEMENT = 4;
  var mlkemSpki = nodeCrypto.generateKeyPairSync("ml-kem-768").publicKey.export({ format: "der", type: "spki" });
  function kemLeaf(subj, kuBits) {
    var o = { subject: subj, issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", spki: mlkemSpki };
    if (kuBits) o.extensions = [kuExt(kuBits)];
    return mkCert(o);
  }
  await cap("9935 ML-KEM leaf keyUsage=keyEncipherment only -> valid", async function () {
    return run([await kemLeaf("KemOk", [KU_KEY_ENCIPHERMENT])], { time: T2027, trustAnchor: anchor });
  });
  await cap("9935 ML-KEM leaf without keyUsage -> valid (unconstrained)", async function () {
    return run([await kemLeaf("KemNoKu", null)], { time: T2027, trustAnchor: anchor });
  });
  await cap("9935 ML-KEM leaf keyUsage=digitalSignature -> rejected", async function () {
    return run([await kemLeaf("KemDs", [KU_DIGITAL_SIGNATURE])], { time: T2027, trustAnchor: anchor });
  });
  await cap("9935 ML-KEM leaf keyUsage=digitalSignature+keyEncipherment -> rejected", async function () {
    return run([await kemLeaf("KemDsKe", [KU_DIGITAL_SIGNATURE, KU_KEY_ENCIPHERMENT])], { time: T2027, trustAnchor: anchor });
  });
  await cap("9935 ML-KEM leaf keyUsage=keyAgreement -> rejected", async function () {
    return run([await kemLeaf("KemKa", [KU_KEY_AGREEMENT])], { time: T2027, trustAnchor: anchor });
  });
  await cap("9935 ML-KEM leaf keyUsage=dataEncipherment -> rejected", async function () {
    return run([await kemLeaf("KemDe", [KU_DATA_ENCIPHERMENT])], { time: T2027, trustAnchor: anchor });
  });
  await cap("9935 ML-KEM leaf keyUsage=nonRepudiation -> rejected (keyEncipherment not set)", async function () {
    return run([await kemLeaf("KemNr", [KU_NON_REPUDIATION])], { time: T2027, trustAnchor: anchor });
  });
  // "the ONLY key usage set" binds unnamed bits too: keyEncipherment + a reserved
  // bit (>= 9) is not keyEncipherment-only.
  await cap("9935 ML-KEM leaf keyUsage=keyEncipherment+reserved bit 9 -> rejected", async function () {
    return run([await kemLeaf("KemBit9", [KU_KEY_ENCIPHERMENT, 9])], { time: T2027, trustAnchor: anchor });
  });
  // The gate runs at the INTERMEDIATE position too: an ML-KEM "CA" asserting
  // keyCertSign is rejected explicitly (its inability to sign also fails the
  // leaf's signature check; the includes-assertion pins the explicit code).
  await cap("9935 ML-KEM intermediate keyUsage=keyCertSign -> rejected", async function () {
    var kemCa = await mkCert({ subject: "KemCa", issuer: "Root", signWith: "ed25519", spki: mlkemSpki, extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
    var leaf = await mkCert({ subject: "KemCaLeaf", issuer: "KemCa", signWith: "ed25519", subjectKeys: "ed25519leaf" });
    return run([kemCa, leaf], { time: T2027, trustAnchor: anchor });
  });
  // A MALFORMED keyUsage extension on an ML-KEM leaf: the decode throws, and the gate maps it to
  // path/kem-key-usage rather than letting a raw error escape (kemKeyUsageCheck's catch arm).
  await cap("9935 ML-KEM leaf with a malformed (non-BIT-STRING) keyUsage -> rejected", async function () {
    return run([await mkCert({ subject: "KemBadKu", issuer: "Root", signWith: "ed25519", spki: mlkemSpki, extensions: [ext("2.5.29.15", true, b.integer(5))] })], { time: T2027, trustAnchor: anchor });
  });

  // ---- 1462 cert DistributionPoint cRLIssuer names a NON-directoryName ---------
  // crlIssuerNamesIssuer skips any cRLIssuer GeneralName that is not a
  // directoryName [4]; with no directoryName the DP never corresponds -> the
  // shard is consulted for revocation only (fail closed to undetermined).
  await cap("1462 cert DP cRLIssuer is a URI (not directoryName) -> revocation-only", async function () {
    var dp = b.sequence([b.contextConstructed(0, dpnFull([gnUri("http://crl.example/a")])), b.contextConstructed(2, gnUri("http://other.example/"))]);
    var leafCi = await mkCert({ subject: "CrlIssuerUriLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 5110n, extensions: [ext("2.5.29.31", false, b.sequence([dp]))] });
    var crlCi = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(40), idpExt({ distributionPoint: dpnFull([gnUri("http://crl.example/a")]) })] });
    return run([leafCi], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCi]) });
  });

  // ---- 1465 cert DP cRLIssuer directoryName EQUALS the issuer, DP corresponds --
  // The cRLIssuer names the certificate issuer AND the DP names match the shard's
  // IDP: the shard is authoritative and, listing no revocation, establishes good.
  await cap("1465 cert DP cRLIssuer names the issuer + DP corresponds -> good", async function () {
    var dp = b.sequence([b.contextConstructed(0, dpnFull([gnUri("http://crl.example/a")])), b.contextConstructed(2, gnDirectoryName(nameDer("Root")))]);
    var leafCi = await mkCert({ subject: "CrlIssuerRootLeaf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: 5111n, extensions: [ext("2.5.29.31", false, b.sequence([dp]))] });
    var crlCi = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(41), idpExt({ distributionPoint: dpnFull([gnUri("http://crl.example/a")]) })] });
    return run([leafCi], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCi]) });
  });

  // ---- 1744 a CRL whose signature BIT STRING is not octet-aligned -------------
  await cap("1744 CRL non-octet-aligned signature -> undetermined", async function () {
    var crlUn = reSignUnaligned(await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9999n }] }));
    return run([e1Leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlUn]) });
  });

  // ---- 1783+1788 delegate key inherits nothing (EC-no-params key, Ed25519 CA) --
  // The delegate omits its EC parameters but the issuing CA is Ed25519, so the
  // issuer cannot supply EC parameters (issuer OID != key OID): ocspResponderSpki
  // returns the (incomplete) SPKI unchanged and the response verify fails closed.
  await cap("1783+1788 delegate EC-no-params key under an Ed25519 CA -> unknown", async function () {
    var respKeys = await ensureKeys("p256i");
    var d = await mkCert({ subject: "InheritEdResp", issuer: "Root", signWith: "ed25519", spki: stripEcParams(respKeys.spki), serial: 721n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), kuExt([KU_DIGITAL_SIGNATURE]), nocheckExt()] });
    var o = await mkOcsp({ responderID: { byName: "InheritEdResp" }, signWith: "p256i", certs: [d], single: [goodSingle700()] });
    return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
  });

  // ---- 1823 a SingleResponse CertID naming an unsupported hash algorithm -------
  await cap("1823 CertID with an unsupported hash OID -> unknown", async function () {
    var o = await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle700({ hashOidOverride: "1.3.6.1.4.1.99999.99" })] });
    return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
  });

  // ---- 1847+1858 responderID byName is a control-byte DN (dnEqual throws) ------
  // The RFC 5280 sec. 7.1 comparison rejects an embedded control byte; the throw is
  // swallowed to "no match" both against the issuer (1847) and each embedded cert
  // (1858), so no authorized responder is resolved.
  await cap("1847+1858 control-byte responderID byName -> unknown", async function () {
    var badRid = [b.set([atv("2.5.4.3", "R" + String.fromCharCode(1) + "oot")])];
    var o = await mkOcsp({ responderID: { byName: badRid }, signWith: "ed25519", certs: [delegateOk], single: [goodSingle700()] });
    return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
  });

  // ---- 1863 embedded delegate whose ISSUER DN carries a control byte ----------
  // The delegate identifies the responderID, but dnEqual(delegate.issuer, issuer)
  // throws on the control byte, so the candidate is skipped (fail closed).
  await cap("1863 delegate control-byte issuer DN -> unknown", async function () {
    var badIssuer = [b.set([atv("2.5.4.3", "R" + String.fromCharCode(1) + "oot")])];
    var d = await mkCert({ subject: "CtrlIssuerResp", issuer: badIssuer, signWith: "ed25519", subjectKeys: "p256", serial: 722n, extensions: [ekuExt([EKU_OCSP_SIGNING], false), nocheckExt()] });
    var o = await mkOcsp({ responderID: { byName: "CtrlIssuerResp" }, signWith: "p256", certs: [d], single: [goodSingle700()] });
    return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
  });

  // ---- 1865 embedded delegate cert with a non-octet-aligned signature ---------
  await cap("1865 embedded delegate non-octet-aligned signature -> unknown", async function () {
    var o = await mkOcsp({ responderID: { byName: "OcspResponder" }, signWith: "p256", certs: [reSignUnaligned(delegateOk)], single: [goodSingle700()] });
    return pki.path.ocspChecker([o]).check(ocspLeaf, issuerArg, octx);
  });

  // ---- 1932 ocspChecker consumes an ALREADY-PARSED response object ------------
  await cap("1932 already-parsed OCSP response consumed as-is -> good", async function () {
    var parsedResp = pki.schema.ocsp.parseResponse(await mkOcsp({ responderID: { byName: "Root" }, signWith: "ed25519", single: [goodSingle700()] }));
    return pki.path.ocspChecker([parsedResp]).check(ocspLeaf, issuerArg, octx);
  });

  // Each scenario's fail-closed verdict, asserted against the shipped surface.
  // `code` = valid===false AND the per-check code is present; `valid` = a clean
  // accept; `throw` = an entry-point typed rejection; `status` = the standalone
  // revocation-checker verdict. 268 is guarded upstream by the x509 parser (an
  // EdDSA signatureAlgorithm carrying parameters never reaches resolveDescriptor).
  var UA = "path/unsupported-algorithm", NCU = "path/name-constraint-unsupported",
      NCNP = "path/name-constraint-not-permitted", BADPOL = "path/bad-policy",
      RUND = "path/revocation-undetermined", BADSIG = "path/bad-signature",
      BADIN = "path/bad-input", UNK = "unknown";
  var EXPECT = {
    "206 PSS absent parameters": { code: UA },
    "213 PSS param field not context-tagged": { code: UA },
    "245 PSS mgf present but no hashAlgorithm": { code: UA },
    "248 PSS mask-gen OID not mgf1": { code: UA },
    "249 PSS mgf1 without inner hash": { code: UA },
    "239+252 PSS trailerField != 1": { code: UA },
    "267 RSA PKCS1 with absent params": { code: UA },
    "268 Ed25519 with present params": { throw: "x509/bad-algorithm-parameters" },
    "284 malformed issuer SPKI for a sameKeyOid alg": { throw: "path/bad-input" },
    "298 ECDSA signature not a DER SEQUENCE": { code: BADSIG },
    "299 ECDSA signature not two INTEGERs": { code: BADSIG },
    "401+544 rfc822 SAN without '@' vs host constraint": { code: NCU },
    "418 rfc822 SAN without '@' vs full-mailbox constraint": { code: NCU },
    "426 rfc822 SAN with empty host": { code: NCU },
    "441 empty dNSName permitted seed matches all": { valid: true },
    "442 leading-dot dNSName permitted matches subdomain": { valid: true },
    "488 URI SAN multi-'@' authority": { code: NCU },
    "496 IPv4 constraint vs IPv6 SAN length mismatch": { code: NCNP },
    "523 directoryName constraint longer than subject": { code: NCNP },
    "525 directoryName constraint RDN mismatch": { code: NCNP },
    "666 iPAddress seed 8-octet base accepted": { valid: true },
    "666 iPAddress seed 4-octet base rejected": { throw: BADIN },
    "668 directoryName seed Name base accepted": { valid: true },
    "668 directoryName seed non-Name base rejected": { throw: BADIN },
    "669 registeredID seed base accepted": { valid: true },
    "669 default-form seed undefined base rejected": { throw: BADIN },
    "838 malformed EKU with requiredEku": { code: "path/bad-extension-value" },
    "860 intermediate malformed policyMappings": { code: BADPOL },
    "889 intermediate malformed policyConstraints": { code: BADPOL },
    "893 intermediate policyConstraints requireExplicitPolicy clamps": { valid: true },
    "898 intermediate malformed inhibitAnyPolicy": { code: BADPOL },
    "906 intermediate malformed basicConstraints": { code: "path/bad-basic-constraints" },
    "926 intermediate malformed keyUsage": { code: "path/bad-key-usage" },
    "1234 target malformed policyConstraints": { code: BADPOL },
    "1246 target malformed policyMappings": { code: BADPOL },
    "1256 target malformed nameConstraints": { code: "path/bad-name-constraints" },
    "1260 target malformed inhibitAnyPolicy": { code: BADPOL },
    "1055+1062+1065 no opts + DER path element": { throw: BADIN },
    "1056 non-array path": { throw: BADIN },
    "1102 requiredEku non-string entry": { throw: BADIN },
    "1119 checkPurpose non-string": { throw: BADIN },
    "1122 checkPurpose dotted OID normalized": { valid: true },
    "1160 custom verifier throws": { code: BADSIG },
    // A checker that throws is a fault in the checker, not an undetermined status it reported: a
    // distinct code so an operator can tell their own broken checker from an unreachable responder.
    "1198 revocationChecker throws": { code: "path/revocation-checker-error" },
    "1179 control-byte issuer DN fails name chaining": { code: "path/name-chaining" },
    "1393 IDP distributionPoint wrapping two DPNs": { code: RUND },
    "1498 crlChecker() no-arg -> undetermined": { code: RUND },
    "1498 crlChecker with pre-parsed CRL -> revoked": { code: "path/revoked" },
    "1594 critical unknown CRL-entry extension -> unusable": { code: RUND },
    "1439 cert DP cRLIssuer names another party -> revocation-only": { code: RUND },
    "1438 cert DP without distributionPoint (cRLIssuer only) -> revocation-only": { code: RUND },
    "1466 cert DP cRLIssuer is a control-byte directoryName -> excluded, revocation-only": { code: RUND },
    "1932 ocspChecker() no-arg -> undetermined": { code: RUND },
    "1962 non-successful OCSP response -> undetermined": { code: RUND },
    "1948 unreadable issuer key -> unknown": { status: UNK },
    "1853 garbage embedded responder cert -> unknown": { status: UNK },
    "1859 responder cert does not identify responderID -> unknown": { status: UNK },
    "1866 delegate signature does not verify -> unknown": { status: UNK },
    "1872 delegate malformed EKU -> unknown": { status: UNK },
    "1879 delegate malformed keyUsage -> unknown": { status: UNK },
    "268b ECDSA sigAlg with NULL params": { code: UA },
    "488b URI SAN single-'@' authority within a URI subtree": { valid: true },
    "665 rfc822Name (tag 1) string seed accepted": { valid: true },
    "665 URI (tag 6) string seed accepted": { valid: true },
    "666 iPAddress seed base as a plain Uint8Array accepted": { valid: true },
    "812 EC subject-key parameters copied into the working key": { valid: true },
    "1124 unregistered dotted checkPurpose kept as the dotted OID": { valid: true },
    "475 composite-keyed leaf without keyUsage -> path valid": { valid: true },
    "481 composite keyUsage asserts no signature bit -> rejected": { code: "path/composite-key-usage" },
    "9935 ML-KEM leaf keyUsage=keyEncipherment only -> valid": { valid: true },
    "9935 ML-KEM leaf without keyUsage -> valid (unconstrained)": { valid: true },
    "9935 ML-KEM leaf keyUsage=digitalSignature -> rejected": { code: "path/kem-key-usage" },
    "9935 ML-KEM leaf keyUsage=digitalSignature+keyEncipherment -> rejected": { code: "path/kem-key-usage" },
    "9935 ML-KEM leaf keyUsage=keyAgreement -> rejected": { code: "path/kem-key-usage" },
    "9935 ML-KEM leaf keyUsage=dataEncipherment -> rejected": { code: "path/kem-key-usage" },
    "9935 ML-KEM leaf keyUsage=nonRepudiation -> rejected (keyEncipherment not set)": { code: "path/kem-key-usage" },
    "9935 ML-KEM leaf keyUsage=keyEncipherment+reserved bit 9 -> rejected": { code: "path/kem-key-usage" },
    "9935 ML-KEM intermediate keyUsage=keyCertSign -> rejected": { code: "path/kem-key-usage" },
    "9935 ML-KEM leaf with a malformed (non-BIT-STRING) keyUsage -> rejected": { code: "path/kem-key-usage" },
    "1462 cert DP cRLIssuer is a URI (not directoryName) -> revocation-only": { code: RUND },
    "1465 cert DP cRLIssuer names the issuer + DP corresponds -> good": { valid: true },
    "1744 CRL non-octet-aligned signature -> undetermined": { code: RUND },
    "1783+1788 delegate EC-no-params key under an Ed25519 CA -> unknown": { status: UNK },
    "1823 CertID with an unsupported hash OID -> unknown": { status: UNK },
    "1847+1858 control-byte responderID byName -> unknown": { status: UNK },
    "1863 delegate control-byte issuer DN -> unknown": { status: UNK },
    "1865 embedded delegate non-octet-aligned signature -> unknown": { status: UNK },
    "1932 already-parsed OCSP response consumed as-is -> good": { status: "good" },
  };
  check("coverage-edges: every scenario has an expectation", R.length === Object.keys(EXPECT).length);
  R.forEach(function (r) {
    var exp = EXPECT[r.label] || {};
    var ok;
    if (exp.valid === true) ok = r.valid === true;
    else if (exp.code) ok = r.valid === false && (r.codes || []).indexOf(exp.code) !== -1;
    else if (exp.throw) ok = r.threw === exp.throw;
    else if (exp.status) ok = r.status === exp.status;
    else ok = false;
    check("path-edge: " + r.label, ok === true);
  });
}

async function runSuite() {
  await testAcceptChains();
  await testSelfIssuedAndConstraints();
  await testCoreRejections();
  await testPolicyMachinery();
  await testConstraintOrderingAndAnchor();
  await testSignatureAndInputEdges();
  await testRevocation();
  await testCrlCheckerUnreadableExtensions();
  await testOcspRevocation();
  await testOcspCheckerStandalone();
  await testOcspCertIdInterop();
  await testLeafRulesAndParams();
  await testRfc5280ConformanceMusts();
  await testInitialInputsAndTargetGates();
  await testTrustAnchorConstraints();
  await testCrlDpIdpCorrespondence();
  await testCoverageEdges();
  await testUnknownOptionsRefused();
}

module.exports = { run: runSuite };

if (require.main === module) {
  runSuite().then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
