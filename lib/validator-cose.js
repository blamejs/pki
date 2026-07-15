// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// verifiers whose credential-key handling composes this validator (pki.webauthn).
//
// validator-cose -- the SINGLE home for "is this a conformant WebAuthn credential
// COSE_Key" (RFC 9052 sec. 7 structure + RFC 9053 EC2/OKP/RSA key parameters + the
// CTAP2 canonical-CBOR profile WebAuthn sec. 6.5.1 imposes). Sibling to the guard
// family: where a guard owns a CVE-class fail-closed defence once, a validator owns a
// decoded TYPE's COMPLETE conformance rule set once, so a format module composes the
// family rather than re-deriving a partial subset inline (the drift that leaks MUSTs
// out one review round at a time). Enforced by the validator-shape-reinlined
// codebase-patterns detector: a lib function that re-inlines COSE-key validation fires.
//
// Interface mirrors the guard family: (subject, E, code) where E is the caller's typed
// error CONSTRUCTOR and code its domain code, so every boundary keeps its own
// domain/reason (a future COSE consumer passes its own E + code).
//
// Rule set (gap-checked verbatim against RFC 9052 sec. 7 + RFC 9053 sec. 2/6 +
// WebAuthn sec. 6.5.1 + the IANA COSE Key Type / Key Type Parameters registries):
//   - kty (label 1) REQUIRED; value an integer (CTAP2 canonical -- a tstr kty/alg is
//     rejected as non-canonical for the WebAuthn profile).
//   - alg (label 3) REQUIRED (the RP needs it to verify the later assertion).
//   - EC2 (kty 2): crv (-1), x (-2), y (-3) all present; x/y length == the curve field
//     size. OKP (kty 1): crv (-1) == Ed25519(6)/Ed448(7), x (-2) length == the key size.
//     RSA (kty 3): n (-1), e (-2) present + non-empty.
//   - CANONICAL: EXACTLY the type's parameters, nothing more (EC2 = 5, OKP/RSA = 4) --
//     rejects a padded key / a private "d" component / kid / key_ops (WebAuthn 6.5.1
//     CTAP2 canonical, stricter than open COSE `* label => values`).
//   - PROFILE: alg <-> kty (and, for EC2, alg <-> crv) consistent; -8 (EdDSA) is Ed25519
//     ONLY; the RFC 9864 fully-specified ids (-9/-51/-52/-19/-53) are accepted.
//   - COMPRESSED: an EC2 credential key MUST use the uncompressed point form (y is a full
//     coordinate byte string, never a CBOR bool sign bit) -- WebAuthn sec. alg identifier.
//   - ON-CURVE: the public key point MUST be valid for its curve. For EC2 the SPKI is
//     imported via node:crypto so OpenSSL validates the point (an off-curve or identity
//     point fails to parse). For OKP, OpenSSL does NOT validate the Edwards point on
//     import (an all-zeroes key parses, and even verifies a trivial signature), so the
//     point is checked explicitly via edwards-point (RFC 8032 decode + cofactor low-order
//     rejection) -- an off-curve, non-canonical, or low-order OKP key fails closed.

var cbor = require("./cbor-det");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var edwardsPoint = require("./edwards-point");
var nodeCrypto = require("crypto");

// COSE EC2 curve (label -1) -> the fixed field-element byte length x/y carry, and the
// named-curve OID a certificate on that curve declares.
var EC2_CRV_LEN = { 1: 32, 2: 48, 3: 66 };   // P-256 / P-384 / P-521
var EC2_CRV_OID = { 1: "prime256v1", 2: "secp384r1", 3: "secp521r1" };
// COSE OKP curve (label -1) -> its RFC 8410 named-key OID + fixed public-key length.
var OKP_CRV = { 6: { oid: "Ed25519", len: 32 }, 7: { oid: "Ed448", len: 57 } };
// alg (label 3) -> the key type (and, for EC2, curve) it pins. WebAuthn (sec. alg
// identifier) adds guarantees over the open COSE registry: an ECDSA alg fixes its curve,
// -8 (EdDSA) is Ed25519 ONLY, and the RFC 9864 fully-specified ids (-9 ESP256, -51 ESP384,
// -52 ESP512, -19 Ed25519, -53 Ed448) each pin key type + curve. A verifier accepts the
// fully-specified ids even though WebAuthn recommends against them for credential creation.
var ALG_PROFILE = {
  "-7": { kty: 2, crv: 1 }, "-35": { kty: 2, crv: 2 }, "-36": { kty: 2, crv: 3 },
  "-9": { kty: 2, crv: 1 }, "-51": { kty: 2, crv: 2 }, "-52": { kty: 2, crv: 3 },
  "-8": { kty: 1, crv: 6 }, "-19": { kty: 1, crv: 6 }, "-53": { kty: 1, crv: 7 },
  "-257": { kty: 3 }, "-258": { kty: 3 }, "-259": { kty: 3 }, "-37": { kty: 3 }, "-65535": { kty: 3 },
};

// credentialKey(node, E, code) -> the decoded + validated credential public key
// { kty, alg, crv?, x?, y?, n?, e? }, or throws new E(code, ...). The complete COSE_Key
// conformance gate for a WebAuthn credential key; a format module MUST route a credential
// key through here, never re-inline the kty/alg/crv/length/canonical/profile/on-curve
// checks.
// @enforced-by validator-shape-reinlined
// @validator-shape kty\s*===\s*2n
// @validator-shape EC2_CRV_LEN|ALG_PROFILE
function credentialKey(node, E, code) {
  function bad(msg, cause) { return new E(code, msg, cause); }
  if (!node || node.majorType !== 5) throw bad("a COSE_Key must be a CBOR map (RFC 9052 sec. 7)");
  // Every parameter read maps a wrong-type cbor/* fault to the caller's domain -- a
  // wrong-typed COSE label (x as an integer, kty as a string) is bad input, not a leak.
  function ib(label) { var n = cbor.read.mapGet(node, label); if (!n) return null; try { return cbor.read.byteString(n); } catch (e) { throw bad("COSE_Key parameter " + label + " must be a byte string", e); } }
  function ii(label) { var n = cbor.read.mapGet(node, label); if (!n) return null; try { return cbor.read.int(n); } catch (e) { throw bad("COSE_Key parameter " + label + " must be an integer", e); } }
  var ktyN = cbor.read.mapGet(node, 1), algN = cbor.read.mapGet(node, 3);
  if (!ktyN) throw bad("a COSE_Key is missing the kty (label 1) parameter");
  if (!algN) throw bad("a COSE_Key is missing the alg (label 3) parameter");
  var kty, algv;
  try { kty = cbor.read.int(ktyN); algv = cbor.read.int(algN); }
  catch (e) { throw bad("COSE_Key kty (label 1) and alg (label 3) must be integers", e); }
  var key = { kty: Number(kty), alg: Number(algv) };
  if (kty === 2n) {
    key.crv = ii(-1) != null ? Number(ii(-1)) : null;
    // WebAuthn EC2 credential keys MUST use the uncompressed point form: y (-3) is the full
    // y-coordinate byte string, never a CBOR bool sign bit (WebAuthn sec. alg identifier).
    var yNode = cbor.read.mapGet(node, -3);
    if (yNode && yNode.majorType === 7) throw bad("an EC2 credential key must use the uncompressed point form (a compressed y sign-bit is not permitted for WebAuthn)");
    key.x = ib(-2); key.y = ib(-3);
    if (key.crv == null || !key.x || !key.y) throw bad("an EC2 COSE_Key must carry crv (-1), x (-2), and y (-3)");
    var el = EC2_CRV_LEN[key.crv];
    if (!el || key.x.length !== el || key.y.length !== el) throw bad("an EC2 COSE_Key x/y length is inconsistent with its curve");
  } else if (kty === 1n) {
    key.crv = ii(-1) != null ? Number(ii(-1)) : null; key.x = ib(-2);
    var okp = OKP_CRV[key.crv];
    if (!okp || !key.x || key.x.length !== okp.len) throw bad("an OKP COSE_Key must be Ed25519 (crv 6) or Ed448 (crv 7) with a matching-length x (-2)");
  } else if (kty === 3n) {
    key.n = ib(-1); key.e = ib(-2);
    if (!key.n || !key.n.length || !key.e || !key.e.length) throw bad("an RSA COSE_Key must carry n (-1) and e (-2)");
  } else {
    throw bad("unsupported COSE_Key kty " + Number(kty));
  }
  // CANONICAL CTAP2 COSE_Key: exactly the type's parameters, nothing more.
  var expectedParams = kty === 2n ? 5 : 4;
  if (node.children.length !== expectedParams) throw bad("the COSE_Key carries parameters beyond the canonical set for its key type (WebAuthn sec. 6.5.1)");
  // PROFILE: the declared alg must match the key type (and, for EC2, the curve).
  var prof = ALG_PROFILE[String(key.alg)];
  if (!prof) throw bad("unsupported credential key algorithm " + key.alg);
  if (prof.kty !== key.kty) throw bad("credential key algorithm " + key.alg + " is inconsistent with key type " + key.kty);
  if (prof.crv != null && prof.crv !== key.crv) throw bad("credential key algorithm " + key.alg + " requires a different curve");
  // ON-CURVE: import the SPKI so OpenSSL validates the EC point on its curve. An off-curve
  // x/y or the identity point fails to parse here.
  try { nodeCrypto.createPublicKey({ key: toSpki(key, E, code), format: "der", type: "spki" }); }
  catch (e) { throw bad("the credential public key point is not valid for its curve", e); }
  // OpenSSL does NOT validate an OKP (Ed25519/Ed448) point on import -- an all-zeroes key
  // parses, and even verifies a trivial signature -- so an OKP point needs an explicit
  // on-curve + full-order (non-low-order) check (RFC 8032 decode + the cofactor check).
  if (kty === 1n && !edwardsPoint.validate(key.x, key.crv)) throw bad("the OKP credential public key is not a valid, full-order Edwards point");
  return key;
}

// toSpki(key, E, code) -> a self-contained SubjectPublicKeyInfo DER for a validated COSE
// key, so a credential key and a certificate key import/compare by one path.
// @enforced-by behavioral -- an SPKI encoding of a validated COSE key has no rename-proof
// code shape distinct from the ecPublicKey/rsaEncryption OID-name tokens that legitimately
// recur in the oid registry + inspect renderer; its consumers route through
// validatorCose.toSpki and credentialKey calls it on the on-curve path, so the webauthn
// KAT round-trip (a real SPKI imports + verifies) is the behavioral guard.
function toSpki(key, E, code) {
  function bad(msg) { return new E(code, msg); }
  if (key.kty === 2 && key.x && key.y) {
    var curveOid = EC2_CRV_OID[key.crv];
    // Coverage residual -- toSpki only receives a credentialKey-validated key; EC2 crv is
    // already gated to {1,2,3} by EC2_CRV_LEN, the exact EC2_CRV_OID keyset, so curveOid is
    // always defined.
    if (!curveOid) throw bad("unsupported EC2 curve " + key.crv);
    var b = asn1.build;
    return b.sequence([
      b.sequence([b.oid(oid.byName("ecPublicKey")), b.oid(oid.byName(curveOid))]),
      b.bitString(Buffer.concat([Buffer.from([0x04]), key.x, key.y])),
    ]);
  }
  if (key.kty === 3 && key.n && key.n.length && key.e && key.e.length) {
    var bb = asn1.build;
    return bb.sequence([
      bb.sequence([bb.oid(oid.byName("rsaEncryption")), bb.nullValue()]),
      bb.bitString(bb.sequence([bb.integer(BigInt("0x" + key.n.toString("hex"))), bb.integer(BigInt("0x" + key.e.toString("hex")))])),
    ]);
  }
  if (key.kty === 1 && OKP_CRV[key.crv] && key.x && key.x.length === OKP_CRV[key.crv].len) {
    var eb = asn1.build;
    return eb.sequence([eb.sequence([eb.oid(oid.byName(OKP_CRV[key.crv].oid))]), eb.bitString(key.x)]);
  }
  // Coverage residual -- a credentialKey-validated key always matches one of the three forms
  // above; this fallthrough is defensive depth.
  throw bad("cannot build an SPKI for this COSE key type");
}

module.exports = {
  credentialKey: credentialKey,
  toSpki: toSpki,
  EC2_CRV_LEN: EC2_CRV_LEN,
  EC2_CRV_OID: EC2_CRV_OID,
  OKP_CRV: OKP_CRV,
};
