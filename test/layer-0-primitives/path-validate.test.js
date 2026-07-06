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
    algorithm: ALG[algKey || "ed25519"].sigOid,
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

  // V1 — good 2-cert chain (RSA and PQC segments get dedicated runs below).
  var inter = await mkCert({ subject: "Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leaf = await mkCert({ subject: "Leaf", issuer: "Inter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });

  var res = await run([inter, leaf], { time: T2027, trustAnchor: anchor });
  check("V1 good 2-cert chain validates", res.valid === true);
  check("V1 per-cert results present", res.results.length === 2);
  check("V1 workingPublicKey is the leaf SPKI", Buffer.isBuffer(res.workingPublicKey) && res.workingPublicKey.equals(KEYS.ed25519leaf.spki));

  // V2 — good 1-cert chain (anchor directly issues the leaf).
  var direct = await mkCert({ subject: "Direct", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var res1 = await run([direct], { time: T2027, trustAnchor: anchor });
  check("V2 good 1-cert chain validates", res1.valid === true);

  // V3 — ECDSA-P256 chain (exercises the DER->P1363 verify-bridge shim).
  var anchorEc = await mkAnchor("p256", "EcRoot");
  var leafEc = await mkCert({ subject: "EcLeaf", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf" });
  var resEc = await run([leafEc], { time: T2027, trustAnchor: anchorEc });
  check("V3 ECDSA-P256-signed chain validates (DER->P1363 shim)", resEc.valid === true);

  // V4 — ML-DSA-65 chain (one-shot PQC verify path).
  var anchorPq = await mkAnchor("mldsa65", "PqRoot");
  var leafPq = await mkCert({ subject: "PqLeaf", issuer: "PqRoot", signWith: "mldsa65", subjectKeys: "ed25519leaf" });
  var resPq = await run([leafPq], { time: T2027, trustAnchor: anchorPq });
  check("V4 ML-DSA-65-signed chain validates", resPq.valid === true);

  // V1b — RSA chain.
  var anchorRsa = await mkAnchor("rsa", "RsaRoot");
  var leafRsa = await mkCert({ subject: "RsaLeaf", issuer: "RsaRoot", signWith: "rsa", subjectKeys: "ed25519leaf" });
  var resRsa = await run([leafRsa], { time: T2027, trustAnchor: anchorRsa });
  check("V1b RSA-signed chain validates", resRsa.valid === true);
}

async function testSelfIssuedAndConstraints() {
  var anchor = await mkAnchor("ed25519", "Root");

  // V5 — a self-issued intermediate (same subject as issuer, key rollover)
  // does NOT consume max_path_length. Chain: Inter(pathLen:0) ->
  // Inter-rollover (self-issued) -> Leaf. A naive counting impl fails.
  var inter = await mkCert({ subject: "Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true, 0), kuExt([KU_KEY_CERT_SIGN])] });
  var rollover = await mkCert({ subject: "Inter", issuer: "Inter", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: [bcExt(true, 0), kuExt([KU_KEY_CERT_SIGN])] });
  var leaf = await mkCert({ subject: "Leaf5", issuer: "Inter", signWith: "ed25519j", subjectKeys: "ed25519leaf" });
  var res = await run([inter, rollover, leaf], { time: T2027, trustAnchor: anchor });
  check("V5 self-issued intermediate not counted against pathLen", res.valid === true);

  // V6 — nameConstraints permitted: leaf SAN within the permitted dNSName tree.
  var interNc = await mkCert({ subject: "NcInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt([gnDns("example.com")], null)] });
  var leafNc = await mkCert({ subject: "NcLeaf", issuer: "NcInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("www.example.com")])] });
  var resNc = await run([interNc, leafNc], { time: T2027, trustAnchor: anchor });
  check("V6 SAN within permitted subtree validates", resNc.valid === true);

  // V7 — explicit policy satisfied end-to-end.
  var P1 = "1.3.6.1.4.1.99999.1";
  var interP = await mkCert({ subject: "PInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), cpExt([P1])] });
  var leafP = await mkCert({ subject: "PLeaf", issuer: "PInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1])] });
  var resP = await run([interP, leafP], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V7 explicit policy satisfied validates", resP.valid === true);
  check("V7 policy tree survives", resP.validPolicyTree !== null && resP.validPolicyTree !== undefined);
}

// ---------------------------------------------------------------------------
// REJECT vectors (V8-V18)
// ---------------------------------------------------------------------------

async function testCoreRejections() {
  var anchor = await mkAnchor("ed25519", "Root");

  // V8 — tampered tbs -> bad signature.
  var tampered = await mkCert({
    subject: "Tamper", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf",
    mutateSig: function (sig) { var s = Buffer.from(sig); s[8] ^= 0xff; return s; },
  });
  var res8 = await run([tampered], { time: T2027, trustAnchor: anchor });
  check("V8 bad signature rejected", res8.valid === false && failCodes(res8).indexOf("path/bad-signature") !== -1);

  // V9 — expired / not-yet-valid.
  var expired = await mkCert({ subject: "Old", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z") });
  var res9a = await run([expired], { time: T2027, trustAnchor: anchor });
  check("V9 expired leaf rejected", res9a.valid === false && failCodes(res9a).indexOf("path/expired") !== -1);
  var future = await mkCert({ subject: "Future", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", notBefore: new Date("2029-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z") });
  var res9b = await run([future], { time: T2027, trustAnchor: anchor });
  check("V9 not-yet-valid leaf rejected", res9b.valid === false && failCodes(res9b).indexOf("path/not-yet-valid") !== -1);

  // V10 — name-chaining break.
  var inter = await mkCert({ subject: "Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var orphan = await mkCert({ subject: "Orphan", issuer: "SomebodyElse", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res10 = await run([inter, orphan], { time: T2027, trustAnchor: anchor });
  check("V10 issuer/subject chaining break rejected", res10.valid === false && failCodes(res10).indexOf("path/name-chaining") !== -1);

  // V11 — basicConstraints bypass: non-CA used as issuer (CVE-2021-3450 class).
  var notCa = await mkCert({ subject: "NotCa", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(false)] });
  var below = await mkCert({ subject: "Below", issuer: "NotCa", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res11a = await run([notCa, below], { time: T2027, trustAnchor: anchor });
  check("V11 cA:FALSE intermediate rejected", res11a.valid === false && failCodes(res11a).indexOf("path/not-a-ca") !== -1);
  var noBc = await mkCert({ subject: "NoBc", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i" });
  var below2 = await mkCert({ subject: "Below2", issuer: "NoBc", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res11b = await run([noBc, below2], { time: T2027, trustAnchor: anchor });
  check("V11 basicConstraints-absent intermediate rejected", res11b.valid === false && failCodes(res11b).indexOf("path/not-a-ca") !== -1);

  // V12 — pathLenConstraint:0 with a further non-self-issued CA below.
  var top = await mkCert({ subject: "Top", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true, 0), kuExt([KU_KEY_CERT_SIGN])] });
  var mid = await mkCert({ subject: "Mid", issuer: "Top", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leaf12 = await mkCert({ subject: "Leaf12", issuer: "Mid", signWith: "ed25519j", subjectKeys: "ed25519leaf" });
  var res12 = await run([top, mid, leaf12], { time: T2027, trustAnchor: anchor });
  check("V12 pathLenConstraint exceeded rejected", res12.valid === false && failCodes(res12).indexOf("path/path-length-exceeded") !== -1);

  // V13 — keyUsage present WITHOUT keyCertSign on an intermediate.
  var noKcs = await mkCert({ subject: "NoKcs", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_DIGITAL_SIGNATURE])] });
  var below13 = await mkCert({ subject: "Below13", issuer: "NoKcs", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res13 = await run([noKcs, below13], { time: T2027, trustAnchor: anchor });
  check("V13 keyUsage without keyCertSign rejected", res13.valid === false && failCodes(res13).indexOf("path/missing-key-cert-sign") !== -1);

  // V16 — name-constraint excluded + not-permitted.
  var interEx = await mkCert({ subject: "ExInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnDns("evil.example.com")])] });
  var leafEx = await mkCert({ subject: "ExLeaf", issuer: "ExInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.evil.example.com")])] });
  var res16a = await run([interEx, leafEx], { time: T2027, trustAnchor: anchor });
  check("V16 excluded SAN rejected", res16a.valid === false && failCodes(res16a).indexOf("path/name-constraint-excluded") !== -1);
  var interPm = await mkCert({ subject: "PmInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt([gnDns("example.com")], null)] });
  var leafPm = await mkCert({ subject: "PmLeaf", issuer: "PmInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("other.org")])] });
  var res16b = await run([interPm, leafPm], { time: T2027, trustAnchor: anchor });
  check("V16 not-permitted SAN rejected", res16b.valid === false && failCodes(res16b).indexOf("path/name-constraint-not-permitted") !== -1);

  // V16c — directoryName is the MUST-support constraint form (§4.2.1.10):
  // an excluded directoryName subtree matching the leaf's subject DN rejects.
  var interDir = await mkCert({ subject: "DirInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnDirectoryName(nameDer("Victim"))])] });
  var leafDir = await mkCert({ subject: "Victim", issuer: "DirInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res16c = await run([interDir, leafDir], { time: T2027, trustAnchor: anchor });
  check("V16c excluded directoryName matching the subject DN rejected", res16c.valid === false && failCodes(res16c).indexOf("path/name-constraint-excluded") !== -1);

  // V16d — a uniformResourceIdentifier constraint applies to the URI's host;
  // a leading-dot domain constraint matches a subdomain host (RFC 5280 §4.2.1.10).
  var interUri = await mkCert({ subject: "UriInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnUri(".evil.example")])] });
  var leafUri = await mkCert({ subject: "UriLeaf", issuer: "UriInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://host.evil.example/callback")])] });
  var res16d = await run([interUri, leafUri], { time: T2027, trustAnchor: anchor });
  check("V16d excluded URI subdomain host rejected", res16d.valid === false && failCodes(res16d).indexOf("path/name-constraint-excluded") !== -1);
  // ...and a bare-host URI constraint matches that host EXACTLY, not a subdomain.
  var interUriHost = await mkCert({ subject: "UriHostInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnUri("evil.example")])] });
  var leafUriSub = await mkCert({ subject: "UriSubLeaf", issuer: "UriHostInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https://host.evil.example/x")])] });
  var res16dSub = await run([interUriHost, leafUriSub], { time: T2027, trustAnchor: anchor });
  check("V16d bare-host URI constraint does NOT match a subdomain", res16dSub.valid === true);

  // V17 — emailAddress in the SUBJECT DN checked as an rfc822Name constraint (§I9).
  var interEm = await mkCert({ subject: "EmInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN]), ncExt(null, [gnEmail("banned.example")])] });
  var emailRdn = [b.set([atv("2.5.4.3", "EmLeaf")]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5("user@banned.example")])])];
  var leafEm = await mkCert({ subject: emailRdn, issuer: "EmInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res17 = await run([interEm, leafEm], { time: T2027, trustAnchor: anchor });
  check("V17 email-in-DN checked as rfc822Name constraint", res17.valid === false && failCodes(res17).indexOf("path/name-constraint-excluded") !== -1);

  // V18 — unrecognized critical extension fails; same OID non-critical passes.
  var unkCrit = await mkCert({ subject: "UnkC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("1.3.6.1.4.1.99999.99", true, b.octetString(Buffer.from([1])))] });
  var res18a = await run([unkCrit], { time: T2027, trustAnchor: anchor });
  check("V18 unrecognized critical extension rejected", res18a.valid === false && failCodes(res18a).indexOf("path/unrecognized-critical-extension") !== -1);
  var unkNon = await mkCert({ subject: "UnkN", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("1.3.6.1.4.1.99999.99", false, b.octetString(Buffer.from([1])))] });
  var res18b = await run([unkNon], { time: T2027, trustAnchor: anchor });
  check("V18 same OID non-critical accepted", res18b.valid === true);
}

// ---------------------------------------------------------------------------
// Policy machinery (V19-V23, V35-V39) — the §6.1 counters and tree rules
// ---------------------------------------------------------------------------

var P1 = "1.3.6.1.4.1.99999.1", P2 = "1.3.6.1.4.1.99999.2", P3 = "1.3.6.1.4.1.99999.3";

// A standard CA extension pair for policy-chain intermediates.
function caExts(extra) { return [bcExt(true), kuExt([KU_KEY_CERT_SIGN])].concat(extra || []); }

async function testPolicyMachinery() {
  var anchor = await mkAnchor("ed25519", "Root");

  // V19 — explicit policy demanded, tree pruned to NULL by disjoint sets.
  var interA = await mkCert({ subject: "PA", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1])]) });
  var leafB = await mkCert({ subject: "PB", issuer: "PA", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2])] });
  var res19 = await run([interA, leafB], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V19 disjoint policies under explicit-policy rejected", res19.valid === false && failCodes(res19).indexOf("path/policy-required") !== -1);

  // V20 — mapping to/from anyPolicy is prohibited (§6.1.4(a)).
  var interMapAny = await mkCert({ subject: "MapAny", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1]), pmExt([[P1, ANY_POLICY]])]) });
  var leafAny = await mkCert({ subject: "LeafAny", issuer: "MapAny", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1])] });
  var res20 = await run([interMapAny, leafAny], { time: T2027, trustAnchor: anchor });
  check("V20 policyMappings naming anyPolicy rejected", res20.valid === false && failCodes(res20).indexOf("path/bad-policy") !== -1);

  // V21 — policy-tree node cap fail-closed (CVE-2023-0464 class): a tiny
  // maxPolicyNodes with a policy-rich chain terminates typed, never hangs.
  var interRich = await mkCert({ subject: "Rich", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY])]) });
  var leafRich = await mkCert({ subject: "RichLeaf", issuer: "Rich", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1, P2, P3])] });
  var res21 = await run([interRich, leafRich], { time: T2027, trustAnchor: anchor, maxPolicyNodes: 2 });
  check("V21 policy-tree cap fail-closed", res21.valid === false && failCodes(res21).indexOf("path/policy-tree-cap") !== -1);

  // V22 — a malformed policy OID is rejected, never silently dropped
  // (CVE-2023-0465 class). 0x80 is an invalid first OID content byte.
  var badPolicyVal = b.sequence([b.sequence([b.raw(Buffer.from([0x06, 0x01, 0x80]))])]);
  var leafBadP = await mkCert({ subject: "BadP", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.32", false, badPolicyVal)] });
  var res22 = await run([leafBadP], { time: T2027, trustAnchor: anchor });
  check("V22 malformed policy OID rejected not dropped", res22.valid === false && failCodes(res22).indexOf("path/bad-policy") !== -1);

  // V23 — the §6.1.2(d) n+1 (not n) counter init, both directions: a
  // no-policy 2-cert chain PASSES with initial-explicit-policy FALSE
  // (an n-init implementation hits 0 at wrap-up and fails), and the same
  // chain FAILS with initial-explicit-policy TRUE (init 0, tree NULL).
  var inter23 = await mkCert({ subject: "C23", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts() });
  var leaf23 = await mkCert({ subject: "L23", issuer: "C23", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res23a = await run([inter23, leaf23], { time: T2027, trustAnchor: anchor });
  check("V23 no-policy chain passes with explicit-policy unset (n+1 init)", res23a.valid === true);
  var res23b = await run([inter23, leaf23], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V23 no-policy chain fails with explicit-policy set", res23b.valid === false && failCodes(res23b).indexOf("path/policy-required") !== -1);

  // V35 — anyPolicy suppression at inhibit_anyPolicy == 0 (§6.1.3(d)(2), §I5).
  var interIap = await mkCert({ subject: "Iap", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY]), iapExt(0)]) });
  var interAny = await mkCert({ subject: "Any", issuer: "Iap", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([ANY_POLICY])]) });
  var leaf35 = await mkCert({ subject: "L35", issuer: "Any", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P1])] });
  var res35 = await run([interIap, interAny, leaf35], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V35 anyPolicy suppressed once inhibit_anyPolicy hits 0", res35.valid === false && failCodes(res35).indexOf("path/policy-required") !== -1);
  var interNoIap = await mkCert({ subject: "Iap", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY])]) });
  var res35b = await run([interNoIap, interAny, leaf35], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V35 control: same chain without inhibitAnyPolicy validates", res35b.valid === true);

  // V36 — a LEAF requireExplicitPolicy == 0 forces explicit_policy = 0 at
  // wrap-up (§6.1.5(b), §I6): with a NULL tree the chain fails where an
  // implementation skipping §6.1.5(b) would pass.
  var inter36 = await mkCert({ subject: "C36", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts() });
  var leaf36 = await mkCert({ subject: "L36", issuer: "C36", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [pcExt({ requireExplicitPolicy: 0 })] });
  var res36 = await run([inter36, leaf36], { time: T2027, trustAnchor: anchor });
  check("V36 leaf requireExplicitPolicy=0 flips the wrap-up verdict", res36.valid === false && failCodes(res36).indexOf("path/policy-required") !== -1);

  // V38 — a mapping carried on the SAME cert as an inhibitPolicyMapping:0
  // still applies (§6.1.4 order: (b) mapping before (i)(2) clamp)...
  var interMapSelf = await mkCert({ subject: "MapSelf", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1]), pmExt([[P1, P2]]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var leaf38 = await mkCert({ subject: "L38", issuer: "MapSelf", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2])] });
  var res38 = await run([interMapSelf, leaf38], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V38 same-cert mapping applies before the inhibit clamp", res38.valid === true);

  // V39 — ...but a mapping arriving AFTER the counter reached 0 DELETES the
  // mapped nodes instead of remapping (§6.1.4(b) zero arm).
  var interClamp = await mkCert({ subject: "Clamp", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var interMapLate = await mkCert({ subject: "MapLate", issuer: "Clamp", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([P1]), pmExt([[P1, P2]])]) });
  var leaf39 = await mkCert({ subject: "L39", issuer: "MapLate", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P2])] });
  var res39 = await run([interClamp, interMapLate, leaf39], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("V39 mapping at policy_mapping==0 deletes, not remaps", res39.valid === false && failCodes(res39).indexOf("path/policy-required") !== -1);
}

// ---------------------------------------------------------------------------
// Name-constraint ordering, empty subject, anchor rules (V37, V40, V41)
// ---------------------------------------------------------------------------

async function testConstraintOrderingAndAnchor() {
  var anchor = await mkAnchor("ed25519", "Root");

  // V37 — a cert's OWN names are checked BEFORE its nameConstraints absorb
  // (§I8): B's SAN violates the constraint B itself introduces, yet B
  // passes; the NEXT cert violating it fails.
  var interB = await mkCert({ subject: "B37", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnDns("b.example")]), sanExt([gnDns("host.b.example")])]) });
  var cleanLeaf = await mkCert({ subject: "L37", issuer: "B37", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("ok.example.org")])] });
  var res37a = await run([interB, cleanLeaf], { time: T2027, trustAnchor: anchor });
  check("V37 own-name checked before absorb (clean leaf passes)", res37a.valid === true);
  var dirtyLeaf = await mkCert({ subject: "L37d", issuer: "B37", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.b.example")])] });
  var res37b = await run([interB, dirtyLeaf], { time: T2027, trustAnchor: anchor });
  check("V37 next cert violating the absorbed constraint fails", res37b.valid === false && failCodes(res37b).indexOf("path/name-constraint-excluded") !== -1);

  // V40 — an empty subject is legal ONLY with a critical SAN (§4.1.2.6).
  var emptySubjCritSan = await mkCert({ subject: [], issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("empty.example")], true)] });
  var res40a = await run([emptySubjCritSan], { time: T2027, trustAnchor: anchor });
  check("V40 empty subject with critical SAN accepted", res40a.valid === true);
  var emptySubjPlainSan = await mkCert({ subject: [], issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("empty.example")], false)] });
  var res40b = await run([emptySubjPlainSan], { time: T2027, trustAnchor: anchor });
  check("V40 empty subject with non-critical SAN rejected", res40b.valid === false && failCodes(res40b).length > 0);

  // V41 — the trust anchor is INPUT, never a path certificate: an expired
  // anchor still anchors a currently-valid chain (§I3).
  var k = await ensureKeys("ed25519");
  var expiredAnchorCert = pki.schema.x509.parse(await mkCert({ subject: "OldRoot", issuer: "OldRoot", signWith: "ed25519", notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z") }));
  var anchorFromExpired = { name: expiredAnchorCert.subject, publicKey: k.spki, algorithm: ALG.ed25519.sigOid };
  var leaf41 = await mkCert({ subject: "L41", issuer: "OldRoot", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var res41 = await run([leaf41], { time: T2027, trustAnchor: anchorFromExpired });
  check("V41 expired anchor still anchors (anchor never validated)", res41.valid === true);
}

// ---------------------------------------------------------------------------
// Signature edge cases (V28, V29, V30, V31, V32, V33, V34-subset)
// ---------------------------------------------------------------------------

async function testSignatureAndInputEdges() {
  var anchor = await mkAnchor("ed25519", "Root");

  // V28 — all-zero ECDSA signature must be rejected (CVE-2022-21449).
  var anchorEc = await mkAnchor("p256", "EcRoot");
  var zeroSig = await mkCert({
    subject: "Zero", issuer: "EcRoot", signWith: "p256", subjectKeys: "ed25519leaf",
    mutateSig: function () { return b.sequence([b.integer(0n), b.integer(0n)]); },
  });
  var res28 = await run([zeroSig], { time: T2027, trustAnchor: anchorEc });
  check("V28 r=0,s=0 ECDSA signature rejected", res28.valid === false && failCodes(res28).indexOf("path/bad-signature") !== -1);

  // V29 — an embedded NUL in a constrained name never truncates the
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
  check("V29 NUL-embedded SAN never validates inside the permitted tree", out29 === true);

  // V30 — empty path is a caller error.
  check("V30 empty path throws path/empty-path", (await codeOf(run([], { time: T2027, trustAnchor: anchor }))) === "path/empty-path");

  // V31 — algorithm confusion: the verify algorithm derives from the cert +
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
  check("V31 algorithm-confused cert rejected typed", res31.valid === false &&
    (codes31.indexOf("path/bad-signature") !== -1 || codes31.indexOf("path/unsupported-algorithm") !== -1));

  // V32 — multi-defect chain fails typed, never a raw TypeError.
  var notCa = await mkCert({ subject: "MD", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(false)] });
  var brokenLeaf = await mkCert({
    subject: "MDL", issuer: "MD", signWith: "ed25519i", subjectKeys: "ed25519leaf",
    notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"),
    mutateSig: function (sig) { var s = Buffer.from(sig); s[3] ^= 0x55; return s; },
  });
  var res32 = await run([notCa, brokenLeaf], { time: T2027, trustAnchor: anchor });
  var codes32 = failCodes(res32);
  check("V32 multi-defect chain fails with typed path/* codes", res32.valid === false && codes32.length > 0 &&
    codes32.every(function (c) { return c.indexOf("path/") === 0; }));

  // V33 — purity / re-entrancy: identical results on a second run; the
  // input cert objects are not mutated.
  var leaf33 = await mkCert({ subject: "L33", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var parsed33 = [pki.schema.x509.parse(leaf33)];
  var snapshot = JSON.stringify({ dn: parsed33[0].subject.dn, serial: parsed33[0].serialNumberHex, nb: parsed33[0].validity.notBefore.toISOString() });
  var runA = await pki.path.validate(parsed33, { time: T2027, trustAnchor: anchor });
  var runB = await pki.path.validate(parsed33, { time: T2027, trustAnchor: anchor });
  check("V33 re-entrant: two runs agree", runA.valid === runB.valid && JSON.stringify(failCodes(runA)) === JSON.stringify(failCodes(runB)));
  check("V33 inputs not mutated", JSON.stringify({ dn: parsed33[0].subject.dn, serial: parsed33[0].serialNumberHex, nb: parsed33[0].validity.notBefore.toISOString() }) === snapshot);

  // V34 (validator-level subset) — an 8-octet iPAddress subtree base (addr +
  // mask) is the LEGAL constraint form and must work; a 4-octet subtree base
  // is malformed. (The SAN-side 4/16 rule is enforced at parse and has its
  // own vectors in the pkix suites.)
  var interIp = await mkCert({ subject: "Ip", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnIp([192, 168, 0, 0, 255, 255, 0, 0])], null)]) });
  var leafIpIn = await mkCert({ subject: "IpIn", issuer: "Ip", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnIp([192, 168, 5, 9])])] });
  var res34a = await run([interIp, leafIpIn], { time: T2027, trustAnchor: anchor });
  check("V34 8-octet subtree base constrains a 4-octet SAN address", res34a.valid === true);
  var leafIpOut = await mkCert({ subject: "IpOut", issuer: "Ip", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnIp([10, 0, 0, 1])])] });
  var res34b = await run([interIp, leafIpOut], { time: T2027, trustAnchor: anchor });
  check("V34 address outside the masked subtree rejected", res34b.valid === false && failCodes(res34b).indexOf("path/name-constraint-not-permitted") !== -1);
  var interIpBad = await mkCert({ subject: "IpBad", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnIp([192, 168, 0, 0])], null)]) });
  var leaf34c = await mkCert({ subject: "L34c", issuer: "IpBad", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnIp([192, 168, 5, 9])])] });
  var res34c = await run([interIpBad, leaf34c], { time: T2027, trustAnchor: anchor });
  check("V34 4-octet subtree base (no mask) rejected as malformed", res34c.valid === false && failCodes(res34c).indexOf("path/bad-name-constraints") !== -1);
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
function crlNumberExt(n) { return ext("2.5.29.20", false, b.integer(BigInt(n))); }
// reasonCode CRL-entry extension (§5.3.1) — value is an ENUMERATED.
function reasonCodeExt(n) { return ext("2.5.29.21", false, b.enumerated(BigInt(n))); }
// A CRL extension with an OID the checker does not understand, marked critical.
function unknownCriticalCrlExt() { return ext("1.3.6.1.4.1.99999.42", true, b.octetString(Buffer.from([1]))); }

async function testRevocation() {
  var anchor = await mkAnchor("ed25519", "Root");
  var LEAF_SERIAL = 7777n;

  // V15 — checker contract: UNDETERMINED fails closed; softFail opts out.
  var leaf = await mkCert({ subject: "R1", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: LEAF_SERIAL });
  var unknownChecker = { check: function () { return Promise.resolve({ status: "unknown" }); } };
  var res15a = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: unknownChecker });
  check("V15 UNDETERMINED revocation fails closed", res15a.valid === false && failCodes(res15a).indexOf("path/revocation-undetermined") !== -1);
  var res15b = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: unknownChecker, softFail: true });
  check("V15 softFail opts into UNDETERMINED-as-pass", res15b.valid === true);

  // V14 — a real CRL revoking the leaf serial, via pki.path.crlChecker.
  var crlRevoking = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: LEAF_SERIAL }] });
  var res14 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlRevoking]) });
  check("V14 revoked serial rejected via CRL checker", res14.valid === false && failCodes(res14).indexOf("path/revoked") !== -1);

  // ...and the same CRL without the serial passes.
  var crlClean = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1234n }] });
  var res14b = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlClean]) });
  check("V14 unlisted serial passes the CRL checker", res14b.valid === true);

  // V27 — stale CRL (nextUpdate < time) -> unknown -> undetermined.
  var crlStale = await mkCrl({ issuer: "Root", signWith: "ed25519", nextUpdate: new Date("2026-06-01T00:00:00Z") });
  var res27 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlStale]) });
  check("V27 stale CRL yields undetermined", res27.valid === false && failCodes(res27).indexOf("path/revocation-undetermined") !== -1);

  // V44 — thisUpdate in the future -> unknown.
  var crlFuture = await mkCrl({ issuer: "Root", signWith: "ed25519", thisUpdate: new Date("2028-01-01T00:00:00Z"), nextUpdate: new Date("2029-01-01T00:00:00Z") });
  var res44 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFuture]) });
  check("V44 future thisUpdate yields undetermined", res44.valid === false && failCodes(res44).indexOf("path/revocation-undetermined") !== -1);

  // V42 — a CRL whose signature does not verify -> unknown.
  var crlBadSig = await mkCrl({ issuer: "Root", signWith: "ed25519", mutateSig: function (sig) { var s = Buffer.from(sig); s[5] ^= 0xaa; return s; } });
  var res42 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlBadSig]) });
  check("V42 bad CRL signature yields undetermined", res42.valid === false && failCodes(res42).indexOf("path/revocation-undetermined") !== -1);

  // V43 — a CRL from an unauthorized third-party issuer -> unknown.
  var crlThirdParty = await mkCrl({ issuer: "SomeoneElse", signWith: "ed25519i" });
  var res43 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlThirdParty]) });
  check("V43 unauthorized CRL issuer yields undetermined", res43.valid === false && failCodes(res43).indexOf("path/revocation-undetermined") !== -1);

  // V26 — the CRL signer's certificate lacks keyUsage.cRLSign -> unknown;
  // the positive control (signer WITH cRLSign) passes. A Root-issued CRL
  // covers the intermediate in both runs, so the only variable is the leaf
  // CRL's signer.
  var rootCrl = await mkCrl({ issuer: "Root", signWith: "ed25519" });
  var interNoCrlSign = await mkCert({ subject: "NoCrlSign", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN])] });
  var leafUnder = await mkCert({ subject: "Under", issuer: "NoCrlSign", signWith: "ed25519i", subjectKeys: "ed25519leaf", serial: 4242n });
  var crlByInter = await mkCrl({ issuer: "NoCrlSign", signWith: "ed25519i" });
  var res26 = await run([interNoCrlSign, leafUnder], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrl, crlByInter]) });
  check("V26 CRL signer without cRLSign yields undetermined", res26.valid === false && failCodes(res26).indexOf("path/revocation-undetermined") !== -1);
  var interCrlSign = await mkCert({ subject: "WithCrlSign", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519j", extensions: [bcExt(true), kuExt([KU_KEY_CERT_SIGN, KU_CRL_SIGN])] });
  var leafUnder2 = await mkCert({ subject: "Under2", issuer: "WithCrlSign", signWith: "ed25519j", subjectKeys: "ed25519leaf", serial: 4243n });
  var crlByInter2 = await mkCrl({ issuer: "WithCrlSign", signWith: "ed25519j" });
  var res26b = await run([interCrlSign, leafUnder2], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([rootCrl, crlByInter2]) });
  check("V26 control: CRL signer with cRLSign passes", res26b.valid === true);

  // V45 — scoped CRLs (onlySomeReasons) covering only part of the reason
  // space are never a definitive UNREVOKED.
  var someReasons = Buffer.from([0x06, 0x40]); // BIT STRING content: 6 unused bits, keyCompromise only
  var crlPartial = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(1), idpExt({ onlySomeReasons: someReasons })] });
  var res45 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlPartial]) });
  check("V45 partial reasons_mask coverage yields undetermined", res45.valid === false && failCodes(res45).indexOf("path/revocation-undetermined") !== -1);

  // V46 — IDP scope mismatch: an onlyContainsCACerts CRL consulted for an
  // end-entity certificate -> unknown.
  var crlCaOnly = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(2), idpExt({ onlyCa: true })] });
  var res46 = await run([leaf], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCaOnly]) });
  check("V46 onlyContainsCACerts CRL out of scope for an EE cert", res46.valid === false && failCodes(res46).indexOf("path/revocation-undetermined") !== -1);
}

// ---------------------------------------------------------------------------
// Leaf exemption + parameter inheritance (V24, V25)
// ---------------------------------------------------------------------------

async function testLeafRulesAndParams() {
  var anchor = await mkAnchor("ed25519", "Root");

  // V25 — the leaf is NOT subject to §6.1.4: cA:FALSE + no keyUsage at
  // position n is fine (§I10).
  var leaf25 = await mkCert({ subject: "L25", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [bcExt(false)] });
  var res25 = await run([leaf25], { time: T2027, trustAnchor: anchor });
  check("V25 non-CA leaf accepted at position n", res25.valid === true);

  // V24 — §6.1.4(e) parameter inheritance, observed through the verifier
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
  var synAnchor = { name: synAnchorName, publicKey: (await ensureKeys("ed25519")).spki, algorithm: SYN_ALG, parameters: PARAMS };

  var certSame = await mkCert({ subject: "Same", issuer: "SynRoot", signWith: "ed25519", spki: synSpkiSame, extensions: caExts() });
  var certUnder = await mkCert({ subject: "UnderSame", issuer: "Same", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  seen.length = 0;
  var resSame = await run([certSame, certUnder], { time: T2027, trustAnchor: synAnchor, verifier: recordingVerifier });
  check("V24 same-algorithm absent params inherited", resSame.valid === true && seen.length === 2 && seen[1].params === PARAMS.toString("hex"));

  var certOther = await mkCert({ subject: "Other", issuer: "SynRoot", signWith: "ed25519", spki: synSpkiOther, extensions: caExts() });
  var certUnder2 = await mkCert({ subject: "UnderOther", issuer: "Other", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  seen.length = 0;
  var resOther = await run([certOther, certUnder2], { time: T2027, trustAnchor: synAnchor, verifier: recordingVerifier });
  check("V24 different-algorithm absent params cleared", resOther.valid === true && seen.length === 2 && seen[1].params === null);

  // A8 — an EXPLICIT DER NULL parameters field is treated identically to
  // omitted (§6.1.4(e)): the same-algorithm intermediate inherits, not copies
  // the NULL. synSpkiNull carries SYN_ALG with an explicit NULL parameter.
  var synSpkiNull = b.sequence([b.sequence([b.oid(SYN_ALG), b.nullValue()]), b.bitString(Buffer.from([0x04, 0x03]), 0)]);
  var certNull = await mkCert({ subject: "NullP", issuer: "SynRoot", signWith: "ed25519", spki: synSpkiNull, extensions: caExts() });
  var certUnder3 = await mkCert({ subject: "UnderNull", issuer: "NullP", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  seen.length = 0;
  var resNull = await run([certNull, certUnder3], { time: T2027, trustAnchor: synAnchor, verifier: recordingVerifier });
  check("A8 explicit NULL params inherit like omitted (not copied)", resNull.valid === true && seen.length === 2 && seen[1].params === PARAMS.toString("hex"));
}

// ---------------------------------------------------------------------------
// Adversarial-audit regressions (A1-A11) — each pins a real RFC MUST the
// pre-push audit found under-enforced.
// ---------------------------------------------------------------------------

async function testAuditRegressions() {
  var anchor = await mkAnchor("ed25519", "Root");
  var P1m = "1.3.6.1.4.1.99999.1", P2m = "1.3.6.1.4.1.99999.2", P3m = "1.3.6.1.4.1.99999.3";
  var SER = 9911n;
  var leafCrl = await mkCert({ subject: "CrlL", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", serial: SER });

  // A1 — permitted subtrees INTERSECT, not union (§6.1.4(g)): a subordinate CA
  // that permits a broader name cannot re-admit what its parent excluded from
  // the permitted set. Parent permits dNSName "a.example"; child permits
  // "evil.com"; a leaf SAN "host.evil.com" is NOT within the parent's set.
  var parentNc = await mkCert({ subject: "P1a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnDns("a.example")], null)]) });
  var childNc = await mkCert({ subject: "C1a", issuer: "P1a", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([ncExt([gnDns("evil.com")], null)]) });
  var leafA1 = await mkCert({ subject: "L1a", issuer: "C1a", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.evil.com")])] });
  var resA1 = await run([parentNc, childNc, leafA1], { time: T2027, trustAnchor: anchor });
  check("A1 permitted-subtree intersection blocks a subordinate broadening", resA1.valid === false && failCodes(resA1).indexOf("path/name-constraint-not-permitted") !== -1);
  // control: a leaf within BOTH generations passes... but the two generations
  // are disjoint (a.example vs evil.com), so no name satisfies both dNSName
  // sets — instead verify a single-generation permit still admits its match.
  var leafA1ok = await mkCert({ subject: "L1ok", issuer: "P1a", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.a.example")])] });
  var resA1ok = await run([parentNc, leafA1ok], { time: T2027, trustAnchor: anchor });
  check("A1 control: name within the single permitted generation passes", resA1ok.valid === true);

  // A2 — rfc822Name leading-dot domain matches a SUBDOMAIN mailbox but not the
  // bare domain, and never a non-boundary label (§4.2.1.10).
  var interA2 = await mkCert({ subject: "P2", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail(".example.com")])]) });
  function emailLeaf(subj, addr) {
    var rdn = [b.set([atv("2.5.4.3", subj)]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5(addr)])])];
    return mkCert({ subject: rdn, issuer: "P2", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  }
  var resA2sub = await run([interA2, await emailLeaf("A2sub", "u@sub.example.com")], { time: T2027, trustAnchor: anchor });
  check("A2 leading-dot rfc822 excludes a subdomain mailbox", resA2sub.valid === false && failCodes(resA2sub).indexOf("path/name-constraint-excluded") !== -1);
  var resA2bare = await run([interA2, await emailLeaf("A2bare", "u@example.com")], { time: T2027, trustAnchor: anchor });
  check("A2 leading-dot rfc822 does NOT match the bare domain", resA2bare.valid === true);
  var resA2nb = await run([interA2, await emailLeaf("A2nb", "u@aexample.com")], { time: T2027, trustAnchor: anchor });
  check("A2 leading-dot rfc822 does NOT match a non-boundary label", resA2nb.valid === true);

  // A3 — bare-host rfc822Name matches the host exactly, not a subdomain.
  var interA3 = await mkCert({ subject: "P3", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnEmail("example.com")])]) });
  function emailLeaf3(subj, addr) {
    var rdn = [b.set([atv("2.5.4.3", subj)]), b.set([b.sequence([b.oid("1.2.840.113549.1.9.1"), b.ia5(addr)])])];
    return mkCert({ subject: rdn, issuer: "P3", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  }
  var resA3exact = await run([interA3, await emailLeaf3("A3x", "u@example.com")], { time: T2027, trustAnchor: anchor });
  check("A3 bare-host rfc822 matches the exact host (excluded)", resA3exact.valid === false && failCodes(resA3exact).indexOf("path/name-constraint-excluded") !== -1);
  var resA3sub = await run([interA3, await emailLeaf3("A3s", "u@sub.example.com")], { time: T2027, trustAnchor: anchor });
  check("A3 bare-host rfc822 does NOT match a subdomain mailbox", resA3sub.valid === true);

  // A4 — an RSA-PSS-signed chain validates (the hashAlgorithm OID is decoded at
  // the correct EXPLICIT-tag depth).
  var anchorPss = await mkAnchor("rsapss", "PssRoot");
  var leafPss = await mkCert({ subject: "PssLeaf", issuer: "PssRoot", signWith: "rsapss", subjectKeys: "ed25519leaf" });
  var resA4 = await run([leafPss], { time: T2027, trustAnchor: anchorPss });
  check("A4 RSA-PSS-signed chain validates", resA4.valid === true);

  // C6 (Codex :129) — a PSS cert declaring an UNSUPPORTED hash OID must be
  // rejected, never silently verified under the SHA-1 default.
  var anchorPssBad = await mkAnchor("pssbad", "PssBadRoot");
  var leafBadPss = await mkCert({ subject: "BadPss", issuer: "PssBadRoot", signWith: "pssbad", subjectKeys: "ed25519leaf" });
  var resC6 = await run([leafBadPss], { time: T2027, trustAnchor: anchorPssBad });
  check("C6 PSS cert with unsupported hash rejected (no SHA-1 fallback)", resC6.valid === false && failCodes(resC6).indexOf("path/unsupported-algorithm") !== -1);

  // C7 (Codex :140) — PSS params whose MGF1 hash mismatches the signature hash
  // cannot be honored by WebCrypto and must be rejected, not verified anyway.
  var anchorBadMgf = await mkAnchor("pssbadmgf", "PssMgfRoot");
  var leafBadMgf = await mkCert({ subject: "BadMgf", issuer: "PssMgfRoot", signWith: "pssbadmgf", subjectKeys: "ed25519leaf" });
  var resC7 = await run([leafBadMgf], { time: T2027, trustAnchor: anchorBadMgf });
  check("C7 PSS MGF1-hash mismatch rejected", resC7.valid === false && failCodes(resC7).indexOf("path/unsupported-algorithm") !== -1);

  // C10 (Codex :132) — a PSS AlgorithmIdentifier with a present-but-non-SEQUENCE
  // parameters field (a DER NULL) must be rejected, not defaulted to SHA-1.
  var anchorPssNull = await mkAnchor("pssnull", "PssNullRoot");
  var leafPssNull = await mkCert({ subject: "PssNull", issuer: "PssNullRoot", signWith: "pssnull", subjectKeys: "ed25519leaf" });
  var resC10 = await run([leafPssNull], { time: T2027, trustAnchor: anchorPssNull });
  check("C10 PSS non-SEQUENCE params rejected", resC10.valid === false && failCodes(resC10).indexOf("path/unsupported-algorithm") !== -1);

  // C9 (Codex :337) — a critical excluded nameConstraints of a form the
  // validator cannot compare (registeredID) plus a cert presenting that form
  // must fail closed, not be treated as "not excluded".
  var interRegId = await mkCert({ subject: "RegIdInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnRegisteredID("1.3.6.1.4.1.99999.5")])]) });
  var leafRegId = await mkCert({ subject: "RegIdLeaf", issuer: "RegIdInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnRegisteredID("1.3.6.1.4.1.99999.5")])] });
  var resC9 = await run([interRegId, leafRegId], { time: T2027, trustAnchor: anchor });
  check("C9 unsupported excluded name form fails closed", resC9.valid === false && failCodes(resC9).indexOf("path/name-constraint-unsupported") !== -1);

  // C11 (Codex :368) — an UNDECODED SAN form (x400Address [3]) must still be
  // preserved so a critical excluded constraint of that form fails closed.
  var interX400 = await mkCert({ subject: "X400Inter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnX400()])]) });
  var leafX400 = await mkCert({ subject: "X400Leaf", issuer: "X400Inter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnX400()])] });
  var resC11 = await run([interX400, leafX400], { time: T2027, trustAnchor: anchor });
  check("C11 undecoded SAN form preserved for constraints (fails closed)", resC11.valid === false && failCodes(resC11).indexOf("path/name-constraint-unsupported") !== -1);

  // C12 (Codex :645) — a CA asserting only anyPolicy plus a policyMappings
  // P1->P2 generates the P1 node from the anyPolicy node; a leaf asserting the
  // mapped-TO policy P2 validates under explicit policy.
  var interAnyMap = await mkCert({ subject: "AnyMap", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY]), pmExt([[P1m, P2m]])]) });
  var leafAnyMap = await mkCert({ subject: "AnyMapLeaf", issuer: "AnyMap", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resC12 = await run([interAnyMap, leafAnyMap], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("C12 policy mapping generates the ID-P node from anyPolicy", resC12.valid === true);

  // C13 (Codex :140) — a PSS params SEQUENCE with a malformed primitive [0]
  // field must be rejected, not skipped-and-defaulted.
  var anchorPssPrim = await mkAnchor("pssprim", "PssPrimRoot");
  var leafPssPrim = await mkCert({ subject: "PssPrim", issuer: "PssPrimRoot", signWith: "pssprim", subjectKeys: "ed25519leaf" });
  var resC13 = await run([leafPssPrim], { time: T2027, trustAnchor: anchorPssPrim });
  check("C13 malformed PSS parameter field rejected", resC13.valid === false && failCodes(resC13).indexOf("path/unsupported-algorithm") !== -1);

  // C14 (Codex :1010) — an indirect CRL (IDP indirectCRL) attributes entries by
  // the per-entry certificateIssuer (not tracked here), so it is unusable.
  var crlIndirect = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(6), idpExt({ indirect: true })] });
  var resC14 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlIndirect]) });
  check("C14 indirect CRL is unusable (undetermined)", resC14.valid === false && failCodes(resC14).indexOf("path/revocation-undetermined") !== -1);

  // C15 (preempt P1) — a CRL with NO nextUpdate has no bounded validity: its
  // currency cannot be confirmed, so it is unusable (a replayed old CRL must
  // not read good).
  var crlNoNext = await mkCrl({ issuer: "Root", signWith: "ed25519", nextUpdate: null });
  var resC15 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlNoNext]) });
  check("C15 CRL without nextUpdate is unusable (undetermined)", resC15.valid === false && failCodes(resC15).indexOf("path/revocation-undetermined") !== -1);

  // C16 (preempt P3) — a revoked entry marked removeFromCRL (reasonCode 8) is
  // NOT a revocation; the cert is good (covered, un-revoked).
  var crlRemove = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n, exts: [reasonCodeExt(8)] }] });
  var resC16 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlRemove]) });
  check("C16 removeFromCRL entry is not a revocation (good)", resC16.valid === true);

  // C17 (preempt P2) — a negative RSASSA-PSS saltLength must be rejected (the
  // OpenSSL shim would treat it as RSA_PSS_SALTLEN_AUTO, accepting any salt).
  var anchorNegSalt = await mkAnchor("pssnegsalt", "NegSaltRoot");
  var leafNegSalt = await mkCert({ subject: "NegSalt", issuer: "NegSaltRoot", signWith: "pssnegsalt", subjectKeys: "ed25519leaf" });
  var resC17 = await run([leafNegSalt], { time: T2027, trustAnchor: anchorNegSalt });
  check("C17 negative PSS saltLength rejected", resC17.valid === false && failCodes(resC17).indexOf("path/unsupported-algorithm") !== -1);

  // C18 (preempt P2) — a trailing-dot dNSName SAN must not escape an excluded
  // dNSName constraint (FQDN root-label normalization).
  var interTd = await mkCert({ subject: "TdInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnDns("evil.com")])]) });
  var leafTd = await mkCert({ subject: "TdLeaf", issuer: "TdInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnDns("host.evil.com.")])] });
  var resC18 = await run([interTd, leafTd], { time: T2027, trustAnchor: anchor });
  check("C18 trailing-dot dNSName does not escape the exclusion", resC18.valid === false && failCodes(resC18).indexOf("path/name-constraint-excluded") !== -1);

  // C19 (preempt P3) — a URI SAN with no authority component under a URI
  // constraint cannot be evaluated -> fail closed, not escape.
  var interUriC = await mkCert({ subject: "UriCInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("evil.example")])]) });
  var leafUriC = await mkCert({ subject: "UriCLeaf", issuer: "UriCInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("urn:example:resource")])] });
  var resC19 = await run([interUriC, leafUriC], { time: T2027, trustAnchor: anchor });
  check("C19 hostless URI under a URI constraint fails closed", resC19.valid === false && failCodes(resC19).indexOf("path/name-constraint-unsupported") !== -1);

  // C20 (Codex :949) — a CRL whose IDP carries a malformed IMPLICIT BOOLEAN
  // (onlyContainsCACerts [2] encoded CONSTRUCTED) has an unknown scope -> the
  // CRL is unusable, not treated as unrestricted-authoritative.
  var idpBadBool = ext("2.5.29.28", true, b.sequence([b.contextConstructed(2, b.octetString(Buffer.from([0xff])))]));
  var crlBadBool = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(7), idpBadBool] });
  var resC20 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlBadBool]) });
  check("C20 malformed IDP BOOLEAN makes the CRL unusable", resC20.valid === false && failCodes(resC20).indexOf("path/revocation-undetermined") !== -1);

  // C21 (Codex :219) — the validator's own octet-alignment guard fails a
  // signature with a non-zero unused-bit count (defense in depth: the strict
  // DER codec already rejects it at parse, so this drives a pre-parsed object).
  var leafC21 = pki.schema.x509.parse(await mkCert({ subject: "Aligned", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" }));
  leafC21.signatureValue = { unusedBits: 3, bytes: leafC21.signatureValue.bytes };
  var resC21 = await pki.path.validate([leafC21], { time: T2027, trustAnchor: anchor });
  check("C21 non-octet-aligned signature rejected by the validator guard", resC21.valid === false && failCodes(resC21).indexOf("path/bad-signature") !== -1);

  // C22 (Codex :179) — a fixed-parameter algorithm with the WRONG parameter
  // shape (ECDSA with a DER NULL where params must be absent) must be rejected.
  var ecNullParams = b.sequence([b.oid("1.3.101.112"), b.nullValue()]);   // Ed25519 OID + a stray NULL
  var leafWrongParams = await mkCert({ subject: "WrongP", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: ecNullParams });
  var resC22 = await run([leafWrongParams], { time: T2027, trustAnchor: anchor });
  check("C22 EdDSA with a stray NULL parameter rejected", resC22.valid === false && failCodes(resC22).indexOf("path/unsupported-algorithm") !== -1);

  // C23 (preempt A) — a SHA-1 PSS signature is rejected (SHA-1 is dropped from
  // the supported set, matching the no-sha1WithRSAEncryption posture).
  var anchorSha1 = await mkAnchor("psssha1", "Sha1Root");
  var leafSha1 = await mkCert({ subject: "Sha1Pss", issuer: "Sha1Root", signWith: "psssha1", subjectKeys: "ed25519leaf" });
  var resC23 = await run([leafSha1], { time: T2027, trustAnchor: anchorSha1 });
  check("C23 SHA-1 PSS signature rejected", resC23.valid === false && failCodes(resC23).indexOf("path/unsupported-algorithm") !== -1);

  // C24 (Codex :173) — a PSS AlgorithmIdentifier declaring an explicit SHA-256
  // hash but OMITTING maskGenAlgorithm (RFC 4055 default mgf1SHA1) must be
  // rejected, not verified as SHA-256/MGF1-SHA256.
  var anchorNoMgf = await mkAnchor("pssnomgf", "NoMgfRoot");
  var leafNoMgf = await mkCert({ subject: "NoMgf", issuer: "NoMgfRoot", signWith: "pssnomgf", subjectKeys: "ed25519leaf" });
  var resC24 = await run([leafNoMgf], { time: T2027, trustAnchor: anchorNoMgf });
  check("C24 PSS with absent maskGenAlgorithm rejected (SHA-1 default)", resC24.valid === false && failCodes(resC24).indexOf("path/unsupported-algorithm") !== -1);

  // C25 (preempt B) - a NUL byte in the leaf SUBJECT DN must not crash the
  // validate() promise (selfIssued's dnEqual throws on a NUL; the throw must
  // be swallowed to a structured verdict). A directoryName name constraint
  // over such a subject additionally fails the path closed.
  var nulRdn = [b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("a" + String.fromCharCode(0) + "b")])])];
  var nulLeaf = await mkCert({ subject: nulRdn, issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var res25threw = false;
  try { await run([nulLeaf], { time: T2027, trustAnchor: anchor }); }
  catch (_e) { res25threw = true; }
  check("C25 NUL in subject DN yields a verdict, not an uncaught throw", res25threw === false);
  var interDirNul = await mkCert({ subject: "DirNulInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt([gnDirectoryName(nameDer("X"))], null)]) });
  var nulLeaf2 = await mkCert({ subject: nulRdn, issuer: "DirNulInter", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var res25b = await run([interDirNul, nulLeaf2], { time: T2027, trustAnchor: anchor });
  check("C25 NUL subject under a directoryName constraint fails closed", res25b.valid === false);

  // C26 (preempt C) — a CRL with a revoked entry carrying an UNKNOWN CRITICAL
  // CRL-entry extension is unusable for any cert (§5.3) -> undetermined.
  var critEntryExt = ext("1.3.6.1.4.1.99999.43", true, b.octetString(Buffer.from([1])));
  var crlCritEntry = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1234n, exts: [critEntryExt] }] });
  var resC26 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlCritEntry]) });
  check("C26 unknown critical CRL-entry extension makes the CRL unusable", resC26.valid === false && failCodes(resC26).indexOf("path/revocation-undetermined") !== -1);

  // C27 (Codex :550) — the (d)(1)(ii) anyPolicy-fallback must be gated on the
  // inhibit counter: an intermediate asserting anyPolicy with inhibitAnyPolicy:0
  // then a leaf asserting P1 must NOT satisfy explicit policy (P1 is pruned).
  var interIapC = await mkCert({ subject: "IapC", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY]), iapExt(0)]) });
  var leafIapC = await mkCert({ subject: "IapCLeaf", issuer: "IapC", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1m])] });
  var resC27 = await run([interIapC, leafIapC], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("C27 anyPolicy fallback gated on inhibit counter", resC27.valid === false && failCodes(resC27).indexOf("path/policy-required") !== -1);

  // C28 (Codex :351) — a URI SAN with an empty authority cannot be evaluated
  // against a URI constraint -> fail closed, not escape.
  var interUriE = await mkCert({ subject: "UriEInter", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ncExt(null, [gnUri("evil.example")])]) });
  var leafUriE = await mkCert({ subject: "UriELeaf", issuer: "UriEInter", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [sanExt([gnUri("https:///path")])] });
  var resC28 = await run([interUriE, leafUriE], { time: T2027, trustAnchor: anchor });
  check("C28 empty-authority URI fails closed under a URI constraint", resC28.valid === false && failCodes(resC28).indexOf("path/name-constraint-unsupported") !== -1);

  // C29 (Codex :164) — a PSS params SEQUENCE with an unexpected [4] field is a
  // structural fault and must be rejected.
  var anchorPssX = await mkAnchor("pssextra", "PssXRoot");
  var leafPssX = await mkCert({ subject: "PssX", issuer: "PssXRoot", signWith: "pssextra", subjectKeys: "ed25519leaf" });
  var resC29 = await run([leafPssX], { time: T2027, trustAnchor: anchorPssX });
  check("C29 unexpected PSS parameter field rejected", resC29.valid === false && failCodes(resC29).indexOf("path/unsupported-algorithm") !== -1);

  // C30 (Codex :1058) — the unhandled-critical-entry check keys on the STABLE
  // OID, not the display name: a custom OID aliased to the name "reasonCode"
  // must still be treated as unhandled (the CRL is unusable). Registered last so
  // it cannot perturb earlier OID resolutions in this file.
  var FAKE_REASON = "1.3.6.1.4.1.99999.77";
  pki.oid.register(FAKE_REASON, "reasonCode");
  var fakeReasonEntryExt = ext(FAKE_REASON, true, b.octetString(Buffer.from([1])));
  var crlFakeReason = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1234n, exts: [fakeReasonEntryExt] }] });
  var resC30 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFakeReason]) });
  check("C30 critical entry ext keyed by OID not display name (unusable)", resC30.valid === false && failCodes(resC30).indexOf("path/revocation-undetermined") !== -1);

  // C31 (Codex :862) — a revocationChecker returning a status OUTSIDE
  // good/revoked/unknown (an OCSP tryLater/unauthorized, a typo) must be treated
  // as undetermined and fail closed, never as a pass.
  var oddChecker = { check: function () { return Promise.resolve({ status: "tryLater" }); } };
  var leafC31 = await mkCert({ subject: "C31", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  var resC31 = await run([leafC31], { time: T2027, trustAnchor: anchor, revocationChecker: oddChecker });
  check("C31 unexpected revocation status fails closed", resC31.valid === false && failCodes(resC31).indexOf("path/revocation-undetermined") !== -1);
  // ...and softFail opts the SAME unexpected status into a pass.
  var resC31s = await run([leafC31], { time: T2027, trustAnchor: anchor, revocationChecker: oddChecker, softFail: true });
  check("C31 softFail opts unexpected status into a pass", resC31s.valid === true);

  // C32 (Codex :124) — an RSASSA-PSS hashAlgorithm [0] EXPLICIT wrapping a BARE
  // OID (not an AlgorithmIdentifier SEQUENCE) is malformed and must fail closed,
  // never be read leniently as SHA-256. Same for the MGF1 hash parameter.
  var pssBareHash = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-bare-hash" });
  var leafC32a = await mkCert({ subject: "C32a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssBareHash });
  var resC32a = await run([leafC32a], { time: T2027, trustAnchor: anchor });
  check("C32 PSS hashAlgorithm as a bare OID (no AlgorithmIdentifier SEQUENCE) rejected", resC32a.valid === false && failCodes(resC32a).indexOf("path/unsupported-algorithm") !== -1);
  var pssBareMgf = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-bare-mgfhash" });
  var leafC32b = await mkCert({ subject: "C32b", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssBareMgf });
  var resC32b = await run([leafC32b], { time: T2027, trustAnchor: anchor });
  check("C32 PSS MGF1 hash as a bare OID rejected", resC32b.valid === false && failCodes(resC32b).indexOf("path/unsupported-algorithm") !== -1);

  // C33 (Codex :593) — the returned validPolicyTree must be acyclic: no internal
  // `parent` back-pointer, so a caller can JSON.stringify(result) on a
  // policy-bearing chain without throwing on a circular reference.
  var P33 = "1.3.6.1.4.1.99999.33";
  var interC33 = await mkCert({ subject: "C33i", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P33])]) });
  var leafC33 = await mkCert({ subject: "C33l", issuer: "C33i", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P33])] });
  var resC33 = await run([interC33, leafC33], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P33] });
  var c33Serialized = true;
  try { JSON.stringify(resC33.validPolicyTree); } catch (_e) { c33Serialized = false; }
  check("C33 policy tree is JSON-serializable (acyclic, no circular parent)", resC33.valid === true && resC33.validPolicyTree !== null && c33Serialized);
  var c33NoParent = (function noParent(node) { if (!node) return true; if ("parent" in node) return false; return node.children.every(noParent); });
  check("C33 returned policy tree carries no parent back-pointer", c33NoParent(resC33.validPolicyTree));

  // C34 (Codex :689) — RFC 5280 requires basicConstraints (4.2.1.9),
  // nameConstraints (4.2.1.10), policyConstraints (4.2.1.11) and
  // inhibitAnyPolicy (4.2.1.14) on a CA certificate to be marked CRITICAL. A
  // non-critical form is non-conforming: a relying party that skips
  // non-critical extensions would not see the constraint. Fail closed on each.
  var interNCBC = await mkCert({ subject: "NCBCi", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: [ext("2.5.29.19", false, bcVal(true)), kuExt([KU_KEY_CERT_SIGN])] });
  var leafNCBC = await mkCert({ subject: "NCBCl", issuer: "NCBCi", signWith: "ed25519i", subjectKeys: "ed25519leaf" });
  var resC34a = await run([interNCBC, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("C34 non-critical CA basicConstraints rejected", resC34a.valid === false && failCodes(resC34a).indexOf("path/extension-not-critical") !== -1);
  // control: the critical form of the SAME chain validates.
  var interCBC = await mkCert({ subject: "NCBCi", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([]) });
  var resC34ctl = await run([interCBC, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("C34 control: critical basicConstraints validates", resC34ctl.valid === true);

  var interNCnc = await mkCert({ subject: "NCnci", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ext("2.5.29.30", false, ncVal([gnDns("example.com")], null))]) });
  var resC34b = await run([interNCnc, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("C34 non-critical nameConstraints rejected", resC34b.valid === false && failCodes(resC34b).indexOf("path/extension-not-critical") !== -1);

  var interNCpc = await mkCert({ subject: "NCpci", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ext("2.5.29.36", false, b.sequence([b.contextPrimitive(0, intContent(0))]))]) });
  var resC34c = await run([interNCpc, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("C34 non-critical policyConstraints rejected", resC34c.valid === false && failCodes(resC34c).indexOf("path/extension-not-critical") !== -1);

  var interNCiap = await mkCert({ subject: "NCiapi", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([ext("2.5.29.54", false, b.integer(0n))]) });
  var resC34d = await run([interNCiap, leafNCBC], { time: T2027, trustAnchor: anchor });
  check("C34 non-critical inhibitAnyPolicy rejected", resC34d.valid === false && failCodes(resC34d).indexOf("path/extension-not-critical") !== -1);

  // C35 (Codex :1151) — a CRL entry takes effect as of its revocationDate
  // (RFC 5280 §5.3). At a validation instant BEFORE that date the certificate
  // was not yet revoked, so a current CRL listing a future revocation must not
  // read as revoked. thisUpdate(2027-01-01) <= T2027 <= nextUpdate(2028-06-01).
  var crlFutureRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, date: new Date("2027-12-01T00:00:00Z") }] });
  var resC35 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlFutureRev]) });
  check("C35 revocation not yet effective at the validation instant is not revoked", resC35.valid === true);
  // control: a revocationDate at/before the instant IS a revocation.
  var crlPastRev = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER, date: new Date("2027-03-01T00:00:00Z") }] });
  var resC35b = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlPastRev]) });
  check("C35 control: revocationDate at/before the instant is revoked", resC35b.valid === false && failCodes(resC35b).indexOf("path/revoked") !== -1);

  // C36 (Codex :126) — an AlgorithmIdentifier is { OID, parameters? }: at most
  // one optional parameters element, and a PSS hash's parameters must be NULL.
  // A spurious third element or non-NULL hash parameters is malformed and must
  // fail closed rather than be read leniently as its named hash.
  var pssHashExtra = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-hash-extra" });
  var resC36a = await run([await mkCert({ subject: "C36a", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssHashExtra })], { time: T2027, trustAnchor: anchor });
  check("C36 PSS hashAlgorithm with a spurious third element rejected", resC36a.valid === false && failCodes(resC36a).indexOf("path/unsupported-algorithm") !== -1);
  var pssHashBad = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-hash-badparams" });
  var resC36b = await run([await mkCert({ subject: "C36b", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssHashBad })], { time: T2027, trustAnchor: anchor });
  check("C36 PSS hashAlgorithm with non-NULL parameters rejected", resC36b.valid === false && failCodes(resC36b).indexOf("path/unsupported-algorithm") !== -1);
  var pssMgfExtra = algIdDer({ sigOid: "1.2.840.113549.1.1.10", sigParams: "pss-mgfhash-extra" });
  var resC36c = await run([await mkCert({ subject: "C36c", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", sigAlgOverride: pssMgfExtra })], { time: T2027, trustAnchor: anchor });
  check("C36 PSS MGF1 hash with a spurious third element rejected", resC36c.valid === false && failCodes(resC36c).indexOf("path/unsupported-algorithm") !== -1);

  // A7 — a missing check date fails closed (never silently disables the
  // always-on validity window).
  var leafA7 = await mkCert({ subject: "A7", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf" });
  check("A7 missing opts.time throws path/bad-input", (await codeOf(run([leafA7], { trustAnchor: anchor }))) === "path/bad-input");

  // A10 — the wrap-up sets workingPublicKeyAlgorithm to the leaf's key algorithm.
  var anchorEc = await mkAnchor("p256", "EcRoot2");
  var leafA10 = await mkCert({ subject: "A10", issuer: "EcRoot2", signWith: "p256", subjectKeys: "ed25519leaf" });
  var resA10 = await run([leafA10], { time: T2027, trustAnchor: anchorEc });
  check("A10 wrap-up carries the leaf key algorithm out", resA10.valid === true && resA10.workingPublicKeyAlgorithm === ALG.ed25519.sigOid);

  // A11 — §6.1.5(f): the user-constrained policy set is computed.
  var P1x = "1.3.6.1.4.1.99999.1";
  var interA11 = await mkCert({ subject: "A11i", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1x])]) });
  var leafA11 = await mkCert({ subject: "A11l", issuer: "A11i", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1x])] });
  var resA11 = await run([interA11, leafA11], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P1x] });
  check("A11 userConstrainedPolicySet computed", resA11.valid === true && Array.isArray(resA11.userConstrainedPolicySet) && resA11.userConstrainedPolicySet.indexOf(P1x) !== -1);

  // A12 — policy-mapping REPLACES the expected-policy set (§6.1.4(b)(1)): after
  // mapping P1->P2, a leaf asserting the mapped-FROM policy P1 must NOT satisfy
  // the chain (the pre-mapping policy is gone). Second-pass P1.
  var interMap = await mkCert({ subject: "MapFrom", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m]), pmExt([[P1m, P2m]])]) });
  var leafFrom = await mkCert({ subject: "LeafFrom", issuer: "MapFrom", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1m])] });
  var resA12 = await run([interMap, leafFrom], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("A12 leaf asserting the mapped-FROM policy is rejected", resA12.valid === false && failCodes(resA12).indexOf("path/policy-required") !== -1);
  // control: a leaf asserting the mapped-TO policy P2 IS accepted.
  var leafTo = await mkCert({ subject: "LeafTo", issuer: "MapFrom", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resA12ok = await run([interMap, leafTo], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("A12 control: leaf asserting the mapped-TO policy validates", resA12ok.valid === true);

  // A13 — two mappings in one extension arriving at policy_mapping==0: the
  // first empties the tree; the second must not crash on a null tree (typed
  // path/policy-required, never a raw TypeError). Second-pass P2.
  var interClamp2 = await mkCert({ subject: "Clamp2", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var interDbl = await mkCert({ subject: "DblMap", issuer: "Clamp2", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([P1m]), pmExt([[P1m, P2m], [P1m, P3m]])]) });
  var leafA13 = await mkCert({ subject: "LA13", issuer: "DblMap", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resA13 = await run([interClamp2, interDbl, leafA13], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("A13 double-mapping at policy_mapping==0 fails typed, not a crash", resA13.valid === false && failCodes(resA13).every(function (c) { return c.indexOf("path/") === 0; }) && failCodes(resA13).indexOf("path/policy-required") !== -1);

  // A15 — the policy_mapping==0 delete arm must delete ONLY the mapped-from
  // nodes, not over-prune surviving unmapped policies (§6.1.4(b)(2)). ClampX
  // sets policy_mapping=0 and seeds {P1,P2}; MapX maps P1->P3 (deleting the
  // depth-2 P1 node) but P2 must survive; the leaf asserts P2 -> valid.
  var clampA15 = await mkCert({ subject: "ClampA15", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m, P2m]), pcExt({ inhibitPolicyMapping: 0 })]) });
  var mapA15 = await mkCert({ subject: "MapA15", issuer: "ClampA15", signWith: "ed25519i", subjectKeys: "ed25519j", extensions: caExts([cpExt([P1m, P2m]), pmExt([[P1m, P3m]])]) });
  var leafA15 = await mkCert({ subject: "LA15", issuer: "MapA15", signWith: "ed25519j", subjectKeys: "ed25519leaf", extensions: [cpExt([P2m])] });
  var resA15 = await run([clampA15, mapA15, leafA15], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true });
  check("A15 delete arm keeps surviving unmapped policies (no over-prune)", resA15.valid === true && resA15.userConstrainedPolicySet.indexOf(P2m) !== -1);

  // A14 — §6.1.5(g) step 3: an all-anyPolicy chain under a restrictive user set
  // reports the user policies in userConstrainedPolicySet, not the empty set.
  var interAny14 = await mkCert({ subject: "Any14", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([ANY_POLICY])]) });
  var leafAny14 = await mkCert({ subject: "LAny14", issuer: "Any14", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([ANY_POLICY])] });
  var resA14 = await run([interAny14, leafAny14], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P1m] });
  check("A14 anyPolicy leaf under restrictive user set expands the policy set", resA14.valid === true && resA14.userConstrainedPolicySet.indexOf(P1m) !== -1);

  // A3-CRL (audit finding 3) — a clean CRL must not shadow a revoking one: with
  // both a clean and a revoking CRL for the issuer, the cert is REVOKED.
  var cleanCrl = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 1n }] });
  var revokingCrl = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: SER }] });
  var resCleanFirst = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([cleanCrl, revokingCrl]) });
  check("A3-CRL clean CRL does not shadow the revoking one (order A)", resCleanFirst.valid === false && failCodes(resCleanFirst).indexOf("path/revoked") !== -1);
  var resRevFirst = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([revokingCrl, cleanCrl]) });
  check("A3-CRL revoked regardless of CRL order (order B)", resRevFirst.valid === false && failCodes(resRevFirst).indexOf("path/revoked") !== -1);

  // C4 (Codex :807) — §6.1.5(g): with explicit policy required and a restrictive
  // userInitialPolicySet, a path whose surviving policies are OUTSIDE the user
  // set must FAIL (the tree is pruned against the user set before success). The
  // chain asserts P1m throughout; the user set is [P3m], disjoint.
  var interC4 = await mkCert({ subject: "C4i", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519i", extensions: caExts([cpExt([P1m])]) });
  var leafC4 = await mkCert({ subject: "C4l", issuer: "C4i", signWith: "ed25519i", subjectKeys: "ed25519leaf", extensions: [cpExt([P1m])] });
  var resC4 = await run([interC4, leafC4], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P3m] });
  check("C4 required policy with empty user-set intersection rejected", resC4.valid === false && failCodes(resC4).indexOf("path/policy-required") !== -1);
  // control: the SAME chain with the matching user set validates.
  var resC4ok = await run([interC4, leafC4], { time: T2027, trustAnchor: anchor, initialExplicitPolicy: true, userInitialPolicySet: [P1m] });
  check("C4 control: matching user set validates", resC4ok.valid === true && resC4ok.userConstrainedPolicySet.indexOf(P1m) !== -1);

  // C1 (Codex :65) — a LEAF with a critical MALFORMED keyUsage must fail
  // closed: the semantic gate is skipped on the leaf, but the structure is
  // still validated. keyUsage value here is an INTEGER, not a BIT STRING.
  var badKuLeaf = await mkCert({ subject: "BadKu", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [ext("2.5.29.15", true, b.integer(1n))] });
  var resC1 = await run([badKuLeaf], { time: T2027, trustAnchor: anchor });
  check("C1 leaf critical malformed keyUsage rejected", resC1.valid === false && failCodes(resC1).indexOf("path/bad-key-usage") !== -1);
  // control: a well-formed critical keyUsage on the leaf is accepted.
  var okKuLeaf = await mkCert({ subject: "OkKu", issuer: "Root", signWith: "ed25519", subjectKeys: "ed25519leaf", extensions: [kuExt([KU_DIGITAL_SIGNATURE])] });
  var resC1ok = await run([okKuLeaf], { time: T2027, trustAnchor: anchor });
  check("C1 control: well-formed critical keyUsage on the leaf accepted", resC1ok.valid === true);

  // C2 (Codex :845) — a CRL scoped to a specific distributionPoint cannot be
  // confirmed in-scope for this cert -> not authoritative -> undetermined.
  var dpName = b.contextConstructed(0, b.contextConstructed(0, gnUri("http://crl.example/partition/1")));
  var crlDp = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(1), idpExt({ distributionPoint: dpName })] });
  var resC2 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlDp]) });
  check("C2 partitioned CRL (distributionPoint IDP) yields undetermined", resC2.valid === false && failCodes(resC2).indexOf("path/revocation-undetermined") !== -1);

  // C3 (Codex :898) — a validly-signed CRL carrying an UNHANDLED critical
  // extension is unusable -> undetermined, never authoritative "good".
  var crlUnkCrit = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(2), unknownCriticalCrlExt()] });
  var resC3 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlUnkCrit]) });
  check("C3 CRL with unhandled critical extension yields undetermined", resC3.valid === false && failCodes(resC3).indexOf("path/revocation-undetermined") !== -1);

  // C5 (Codex :875) — a CRL scoped onlyContainsAttributeCerts is out of scope
  // for a public-key certificate -> undetermined, never authoritative "good".
  var crlAttrOnly = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(4), idpExt({ onlyAttr: true })] });
  var resC5 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlAttrOnly]) });
  check("C5 attribute-cert-only CRL out of scope for a public-key cert", resC5.valid === false && failCodes(resC5).indexOf("path/revocation-undetermined") !== -1);

  // C8 (Codex :872) — a critical IDP whose value is not a SEQUENCE leaves the
  // scope unknown: the CRL is unusable, not treated as unrestricted.
  var crlBadIdp = await mkCrl({ issuer: "Root", signWith: "ed25519", extensions: [crlNumberExt(5), ext("2.5.29.28", true, b.integer(1n))] });
  var resC8 = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlBadIdp]) });
  check("C8 malformed IDP CRL is unusable (undetermined)", resC8.valid === false && failCodes(resC8).indexOf("path/revocation-undetermined") !== -1);
  // ...and it must not let a revoked serial read good either — a revoking CRL
  // with an unhandled critical extension is unusable, so the cert is undetermined.
  var crlRevUnk = await mkCrl({ issuer: "Root", signWith: "ed25519", revoked: [{ serial: 9911n }], extensions: [crlNumberExt(3), unknownCriticalCrlExt()] });
  var resC3b = await run([leafCrl], { time: T2027, trustAnchor: anchor, revocationChecker: pki.path.crlChecker([crlRevUnk]) });
  check("C3 unusable revoking CRL does not read as revoked either (undetermined)", resC3b.valid === false && failCodes(resC3b).indexOf("path/revocation-undetermined") !== -1);
}

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

async function runSuite() {
  await testAcceptChains();
  await testSelfIssuedAndConstraints();
  await testCoreRejections();
  await testPolicyMachinery();
  await testConstraintOrderingAndAnchor();
  await testSignatureAndInputEdges();
  await testRevocation();
  await testLeafRulesAndParams();
  await testAuditRegressions();
}

module.exports = { run: runSuite };

if (require.main === module) {
  runSuite().then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
