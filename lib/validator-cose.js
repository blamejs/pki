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
// family: where a guard owns a CVE-class fail-closed defense once, a validator owns a
// decoded TYPE's COMPLETE conformance rule set once, so a format module composes the
// family instead of re-deriving a partial subset inline (the drift that leaks MUSTs
// out one review round at a time). Enforced by the validator-shape-reinlined
// codebase-patterns detector: a lib function that re-inlines COSE-key validation fires.
//
// Interface mirrors the guard family: (subject, E, code) where E is the caller's typed
// error CONSTRUCTOR and code its domain code, so every boundary keeps its own
// domain/reason (a future COSE consumer passes its own E + code).
//
// Rule set (gap-checked verbatim against RFC 9052 sec. 7 + RFC 9053 sec. 2/6 +
// WebAuthn sec. 6.5.1 + the IANA COSE Key Type / Key Type Parameters registries):
//   - kty (label 1) REQUIRED; value an integer (CTAP2 canonical, so a tstr kty/alg is
//     rejected as non-canonical for the WebAuthn profile).
//   - alg (label 3) REQUIRED (the RP needs it to verify the later assertion).
//   - EC2 (kty 2): crv (-1), x (-2), y (-3) all present; x/y length == the curve field
//     size. OKP (kty 1): crv (-1) == Ed25519(6)/Ed448(7), x (-2) length == the key size.
//     RSA (kty 3): n (-1), e (-2) present + non-empty.
//   - CANONICAL: EXACTLY the type's parameters, nothing more (EC2 = 5, OKP/RSA = 4) --
//     rejects a padded key / a private "d" component / kid / key_ops (WebAuthn 6.5.1
//     CTAP2 canonical, stricter than open COSE `* label => values`).
//   - PROFILE: alg <-> kty (and, for EC2, alg <-> crv) consistent; -8 (EdDSA) is only
//     Ed25519; the RFC 9864 fully-specified ids (-9/-51/-52/-19/-53) are accepted.
//   - COMPRESSED: an EC2 credential key MUST use the uncompressed point form, per WebAuthn
//     sec. alg identifier: y is a full coordinate byte string, never a CBOR bool sign bit.
//   - ON-CURVE: the public key point MUST be valid for its curve. For EC2 the SPKI is
//     imported via node:crypto so OpenSSL validates the point (an off-curve or identity
//     point fails to parse). For OKP, OpenSSL does not validate the Edwards point on
//     import (an all-zeroes key parses, and even verifies a trivial signature), so the
//     point is checked explicitly via edwards-point (RFC 8032 decode + cofactor low-order
//     rejection). An off-curve, non-canonical, or low-order OKP key fails closed.

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
// -8 (EdDSA) is only Ed25519, and the RFC 9864 fully-specified ids (-9 ESP256, -51 ESP384,
// -52 ESP512, -19 Ed25519, -53 Ed448) each pin key type + curve. A verifier accepts the
// fully-specified ids even though WebAuthn recommends against them for credential creation.
// The RSA credential-key bounds. 2048 bits is the floor every current FIDO authenticator and
// NIST SP 800-57 agree on; nothing in the field emits less, so the floor refuses forgeable keys
// without refusing real ones. The exponent bound is a work bound, not a security one.
var RSA_MIN_MODULUS_BITS = 2048;
var RSA_MAX_EXPONENT_BYTES = 8;
// The modulus BIT length. A byte count is not one: minimally encoded, a 256-byte modulus whose
// leading byte is 0x01 is 2041 bits, and would clear a floor expressed in bytes while sitting below
// the floor that floor exists to state. The leading byte is non-zero by the minimal-encoding check
// above, so its position fixes the total.
function _modulusBits(n) { return (n.length - 1) * 8 + (32 - Math.clz32(n[0])); }

var ALG_PROFILE = {
  "-7": { kty: 2, crv: 1 }, "-35": { kty: 2, crv: 2 }, "-36": { kty: 2, crv: 3 },
  "-9": { kty: 2, crv: 1 }, "-51": { kty: 2, crv: 2 }, "-52": { kty: 2, crv: 3 },
  "-8": { kty: 1, crv: 6 }, "-19": { kty: 1, crv: 6 }, "-53": { kty: 1, crv: 7 },
  // RSASSA-PSS at all three strengths. PS256 alone left PS384/PS512 refused at PARSE time on a key
  // that is perfectly well-formed (the same bytes accepted under -37), so the refusal blamed the
  // key instead of the algorithm, and a relying party migrating credential rows written by another
  // implementation could not tell which of its stored keys this verifier would decline, or why.
  "-257": { kty: 3 }, "-258": { kty: 3 }, "-259": { kty: 3 },
  "-37": { kty: 3 }, "-38": { kty: 3 }, "-39": { kty: 3 }, "-65535": { kty: 3 },
};

// credentialKey(node, E, code) -> the decoded + validated credential public key
// { kty, alg, crv?, x?, y?, n?, e? }, or throws new E(code, ...). The complete COSE_Key
// conformance gate for a WebAuthn credential key; a format module MUST route a credential
// key through here, never re-inline the kty/alg/crv/length/canonical/profile/on-curve
// checks.
// @enforced-by validator-shape-reinlined
// @validator-shape kty\s*===\s*2n
// @validator-shape EC2_CRV_LEN|ALG_PROFILE
// `unsupportedCode` is OPTIONAL and names the code raised when the key is well-formed but its
// algorithm is not one this verifier implements, a different fact from a malformed key. Omit it
// and that case keeps raising `code`, so an existing caller sees no change.
function credentialKey(node, E, code, unsupportedCode) {
  function bad(msg, cause) { return new E(code, msg, cause); }
  if (!node || node.majorType !== 5) throw bad("a COSE_Key must be a CBOR map (RFC 9052 sec. 7)");
  // Every parameter read maps a wrong-type cbor/* fault to the caller's domain: a
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
    // The material itself, not merely its presence: the same standard the other two key types are
    // held to, where EC2 pins x/y to the curve's field size and has the point validated on the curve,
    // and OKP pins x to an exact length. Checking only presence let a 1-byte modulus and an
    // exponent of 1 through as conformant credential public keys, and both reach the WebCrypto
    // import, so they reach real signature verification. e = 1 makes RSA the identity function:
    // the "signature" is the message, and it verifies under any modulus.
    // Both values first, before either is judged. RFC 8230 sec. 4 encodes n and e as unsigned
    // big-endian integers with no leading zero, and every check below reads a byte length as though
    // it were a magnitude: the modulus floor, the exponent bound, and the exponent's value. A
    // padded encoding decouples the two, so `00 01` would be read as a two-byte exponent and skip
    // the value check that refuses 1, the degenerate key the whole check exists to catch. (An EC2
    // coordinate is the opposite case, fixed-width and zero-padded by definition, which is why this
    // rule is stated for the RSA parameters and not for x/y.)
    if (key.n[0] === 0) throw bad("an RSA COSE_Key modulus (-1) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    if (key.e[0] === 0) throw bad("an RSA COSE_Key exponent (-2) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    var modulusBits = _modulusBits(key.n);
    if (modulusBits < RSA_MIN_MODULUS_BITS) {
      throw bad("an RSA COSE_Key modulus (-1) is " + modulusBits + " bits, below the " +
        RSA_MIN_MODULUS_BITS + "-bit minimum");
    }
    // e must be odd and greater than 1: RSA needs gcd(e, phi(n)) = 1, so an even exponent is not a
    // valid RSA public exponent at all, and 1 is the degenerate case above. Bounded on the way in
    // so a caller cannot hand over a megabyte of exponent for the modular exponentiation to chew.
    if (key.e.length > RSA_MAX_EXPONENT_BYTES) throw bad("an RSA COSE_Key exponent (-2) is longer than " + RSA_MAX_EXPONENT_BYTES + " bytes");
    if ((key.e[key.e.length - 1] & 1) === 0) throw bad("an RSA COSE_Key exponent (-2) must be odd");
    // Minimal encoding above makes a one-byte e the only way to express a value this small, so the
    // comparison is on the value and not on where it happens to sit.
    if (key.e.length === 1 && key.e[0] <= 1) throw bad("an RSA COSE_Key exponent (-2) must be greater than 1; e = 1 makes RSA the identity function");
  } else {
    throw bad("unsupported COSE_Key kty " + Number(kty));
  }
  // CANONICAL CTAP2 COSE_Key: exactly the type's parameters, nothing more.
  var expectedParams = kty === 2n ? 5 : 4;
  if (node.children.length !== expectedParams) throw bad("the COSE_Key carries parameters beyond the canonical set for its key type (WebAuthn sec. 6.5.1)");
  return assertKeyMaterial(key, E, code, unsupportedCode);
}

// assertKeyMaterial(key, E, code, unsupportedCode) -> key | throws
//
// The rules about the KEY, split from the rules about its CBOR encoding, because the
// toolkit accepts a stored credential key in two forms and both reach a signature
// verification. `pki.webauthn.verifyAssertion` takes the COSE bytes or the object
// `pki.webauthn.verify` returned; the bytes went through every check below and the
// object went through none, so the same 1-byte modulus was refused as a credential key
// in one form and imported for verification in the other. A caller stores whichever
// form their datastore round-trips, which is not a choice about how carefully their
// credential is checked.
//
// Everything above this line is about the encoding (a CBOR map, integer labels, byte
// strings, the canonical parameter count) and can only be asked of bytes. Everything
// here is about the key, and is asked of both.
//
// @enforced-by behavioral -- key-material rules have no rename-proof code shape distinct
//   from ordinary length and byte comparisons; the RED vectors that drive both accepted
//   forms of a stored credential key (the COSE bytes and the object) through
//   pki.webauthn.verifyAssertion with an undersized modulus, e = 1, a curve/length
//   mismatch and a short OKP x are the guard.
function assertKeyMaterial(key, E, code, unsupportedCode) {
  function bad(msg, cause) { return new E(code, msg, cause); }
  if (!key || typeof key !== "object") throw bad("a credential key must be a decoded COSE_Key object");
  // One read of each field, into a plain object, before anything is checked or used.
  //
  // The object form comes from the caller, so any of these can be an accessor. One that throws
  // turns a validation into a raw fault, the thing this function exists to prevent, and one
  // that returns different values on successive reads makes the field that was checked and the
  // field that is used two different values, which defeats the check outright. Reading each
  // exactly once settles both, for every field, not just the ones a particular branch reaches.
  try {
    key = { kty: key.kty, alg: key.alg, crv: key.crv, x: key.x, y: key.y, n: key.n, e: key.e };
  } catch (e) { throw bad("a credential key field could not be read", e); }
  // Then the type and the value. BigInt() throws a raw TypeError on a Symbol and on undefined, and
  // a raw RangeError on a fractional or non-finite number, so the check is not "it is a number";
  // it is "it is an integer". Every integer label the branches below read, not the two the
  // dispatch happens to need first:
  // crv indexes a lookup table, and a Symbol thrown at a property read is the same raw fault as a
  // Symbol thrown at BigInt(). The decoded form gets these from the CBOR reader, which has already
  // established them; the object form gets them from the caller, so this is where they are settled.
  // A BigInt is bounded too. COSE labels are small registry integers, and an unbounded one converts
  // to Infinity, which then throws a raw RangeError at the next conversion: the same defeat as a
  // fractional number, reached by a value that is an integer. So "it is an integer" is not the
  // whole check either; "it is an integer this code can carry" is.
  var MAX = BigInt(Number.MAX_SAFE_INTEGER);
  function _isInt(v) {
    if (typeof v === "bigint") return v <= MAX && v >= -MAX;
    return typeof v === "number" && Number.isSafeInteger(v);
  }
  if (!_isInt(key.kty)) throw bad("a COSE_Key kty (label 1) must be an integer");
  if (!_isInt(key.alg)) throw bad("a COSE_Key alg (label 3) must be an integer");
  if (key.crv !== undefined && key.crv !== null && !_isInt(key.crv)) throw bad("a COSE_Key crv (label -1) must be an integer");
  // One representation from here down. A label may arrive as a Number or a BigInt (a CBOR reader
  // hands out BigInt; an object built in JavaScript is likelier to hold Number), and everything
  // below compares with === against the Number-keyed profile table and the curve tables. Accepting
  // both forms at the gate and then comparing only one is a check that answers by how the caller
  // happened to spell the value; the decoded arm normalizes here too, for the same reason.
  key.kty = Number(key.kty);
  key.alg = Number(key.alg);
  if (key.crv !== undefined && key.crv !== null) key.crv = Number(key.crv);
  var kty = BigInt(key.kty);
  if (kty === 2n) {
    var el2 = EC2_CRV_LEN[key.crv];
    if (!Buffer.isBuffer(key.x) || !Buffer.isBuffer(key.y)) throw bad("an EC2 COSE_Key must carry crv (-1), x (-2), and y (-3)");
    if (!el2 || key.x.length !== el2 || key.y.length !== el2) throw bad("an EC2 COSE_Key x/y length is inconsistent with its curve");
  } else if (kty === 1n) {
    var okp2 = OKP_CRV[key.crv];
    if (!okp2 || !Buffer.isBuffer(key.x) || key.x.length !== okp2.len) throw bad("an OKP COSE_Key must be Ed25519 (crv 6) or Ed448 (crv 7) with a matching-length x (-2)");
  } else if (kty === 3n) {
    if (!Buffer.isBuffer(key.n) || !key.n.length || !Buffer.isBuffer(key.e) || !key.e.length) throw bad("an RSA COSE_Key must carry n (-1) and e (-2)");
    if (key.n[0] === 0) throw bad("an RSA COSE_Key modulus (-1) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    if (key.e[0] === 0) throw bad("an RSA COSE_Key exponent (-2) must be minimally encoded, with no leading zero byte (RFC 8230 sec. 4)");
    var bits = _modulusBits(key.n);
    if (bits < RSA_MIN_MODULUS_BITS) throw bad("an RSA COSE_Key modulus (-1) is " + bits + " bits, below the " + RSA_MIN_MODULUS_BITS + "-bit minimum");
    if (key.e.length > RSA_MAX_EXPONENT_BYTES) throw bad("an RSA COSE_Key exponent (-2) is longer than " + RSA_MAX_EXPONENT_BYTES + " bytes");
    if ((key.e[key.e.length - 1] & 1) === 0) throw bad("an RSA COSE_Key exponent (-2) must be odd");
    if (key.e.length === 1 && key.e[0] <= 1) throw bad("an RSA COSE_Key exponent (-2) must be greater than 1; e = 1 makes RSA the identity function");
  } else {
    throw bad("unsupported COSE_Key kty " + Number(key.kty));
  }
  // PROFILE: the declared alg must match the key type (and, for EC2, the curve).
  var prof = ALG_PROFILE[String(key.alg)];
  // An algorithm this verifier does not implement is not a malformed key. The key can be perfectly
  // well-formed (the same bytes may parse under a neighboring algorithm id), and a relying
  // party migrating credential rows written elsewhere needs to tell "I cannot check this
  // algorithm" from "these bytes are wrong", since only one of those is fixable by re-registering.
  // Callers that do not distinguish the two pass one code and keep the previous behavior.
  if (!prof) throw new E(unsupportedCode || code, "unsupported credential key algorithm " + key.alg);
  if (prof.kty !== key.kty) throw bad("credential key algorithm " + key.alg + " is inconsistent with key type " + key.kty);
  if (prof.crv != null && prof.crv !== key.crv) throw bad("credential key algorithm " + key.alg + " requires a different curve");
  // ON-CURVE: import the SPKI so OpenSSL validates the EC point on its curve. An off-curve
  // x/y or the identity point fails to parse here.
  try { nodeCrypto.createPublicKey({ key: toSpki(key, E, code), format: "der", type: "spki" }); }
  catch (e) { throw bad("the credential public key point is not valid for its curve", e); }
  // OpenSSL does not validate an OKP (Ed25519/Ed448) point on import. An all-zeroes key
  // parses, and even verifies a trivial signature, so an OKP point needs an explicit
  // on-curve + full-order (non-low-order) check (RFC 8032 decode + the cofactor check).
  if (Number(key.kty) === 1 && !edwardsPoint.validate(key.x, key.crv)) throw bad("the OKP credential public key is not a valid, full-order Edwards point");
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
  assertKeyMaterial: assertKeyMaterial,
  toSpki: toSpki,
  EC2_CRV_LEN: EC2_CRV_LEN,
  EC2_CRV_OID: EC2_CRV_OID,
  OKP_CRV: OKP_CRV,
};
