// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.webauthn
 * @nav        Validation
 * @title      WebAuthn
 * @intro Trust evaluation of a W3C WebAuthn (Level 3) / passkey attestation: parse
 *   the attestation object + authenticatorData, decode the COSE credential public
 *   key, and verify each defined attestation-statement format (packed, tpm,
 *   android-key, apple, fido-u2f, none) -- the attestation-statement signature and
 *   each format's structural bindings. The attestation CBOR is decoded by the strict,
 *   fail-closed `pki.cbor` codec (WebAuthn keys are CTAP2-canonical), the signature by
 *   `pki.webcrypto`. Chaining the returned x5c trust path to a caller-pinned root via
 *   `pki.path.validate` is the caller's step: this module verifies the statement, not
 *   the certificate chain. A verifier, not a ceremony client: the relying party
 *   supplies the clientDataHash + any trust anchors; this module never touches a
 *   socket. Fail-closed -- every malformed shape or failed check throws a typed
 *   `WebauthnError`, never a partial verdict.
 * @spec W3C WebAuthn Level 3 sec. 6.5 / 8, RFC 9052 (COSE)
 * @card Verify a WebAuthn / passkey attestation (packed / tpm / android-key / apple / fido-u2f / none).
 */

var frameworkError = require("./framework-error");
var cbor = require("./cbor-det");
var asn1 = require("./asn1-der");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var webcrypto = require("./webcrypto");
var constants = require("./constants");
var validator = require("./validator-all");
var edwardsPoint = require("./edwards-point");
var nodeCrypto = require("crypto");

var WebauthnError = frameworkError.WebauthnError;
function _err(code, message, cause) { return new WebauthnError(code, message, cause); }
// The shared certificate-extension decoder registry (keyed by OID), so an
// attestation-certificate extension (extKeyUsage, subjectAltName) is decoded by the
// same fail-closed pkix decoder every other format uses, not a local hand-roll.
var NS = pkix.makeNS("webauthn", WebauthnError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
function _decodeExt(cert, oidName) {
  var ext = _findExt(cert, oidName);
  if (!ext) return null;
  var dec = EXT_DECODERS[ext.oid];
  if (!dec) return null;
  return { critical: ext.critical, value: dec(ext.value) };
}
var subtle = webcrypto.webcrypto.subtle;

// A one-shot digest over a bounded buffer (the attestation nonce / TPM Name / TPM
// extraData preimages), by the node hash name the caller has already resolved.
function _sha(name, buf) { return nodeCrypto.createHash(name).update(buf).digest(); }
// Unsigned big-endian magnitude compare: strip leading zero octets, then byte-equal.
// TPM2B buffers and COSE fixed-length coordinates can differ by a leading 0x00, so a
// raw memcmp would spuriously reject an equal key (WebAuthn 8.3, item 22).
function _ucmp(a, b) {
  function strip(x) { var i = 0; while (i < x.length - 1 && x[i] === 0) i++; return x.subarray(i); }
  return Buffer.compare(strip(a), strip(b)) === 0;
}
// A decoded node is a primitive universal INTEGER (so `.content` is a real buffer,
// not null as it is for a constructed node).
function _isInteger(node) { return !!node && !node.constructed && node.tagClass === "universal" && node.tagNumber === asn1.TAGS.INTEGER; }
// alg -> the digest a TPM attestation's certInfo.extraData is taken under (the ONLY
// consumer). Every ECDSA/RSA algorithm a TPM AIK may sign with -- including the RFC 9864
// fully-specified ECDSA ids (ESP256/384/512) -- MUST appear here, or the TPM extraData
// step rejects the attestation before the signature is evaluated. EdDSA (-8/-19/-53) is
// absent by design: a TPM 2.0 AIK never signs with EdDSA, so such an attestation is
// correctly refused.
var COSE_ALG_HASH = { "-7": "sha256", "-9": "sha256", "-257": "sha256", "-37": "sha256", "-35": "sha384", "-51": "sha384", "-258": "sha384", "-36": "sha512", "-52": "sha512", "-259": "sha512", "-65535": "sha1" };
function _coseAlgHash(alg, E) {
  var h = COSE_ALG_HASH[String(alg)];
  if (!h) throw E("webauthn/unsupported-algorithm", "no hash mapping for COSE algorithm " + alg);
  return h;
}

// ---- CBOR map access over the strict pki.cbor node tree ----------------------

// A decoded CBOR map is a node whose `children` is an array of [keyNode, valNode].
// Look a text-keyed entry up, or null. The strict codec already rejected a
// duplicate map key, so at most one match exists.
function _mapGet(node, key) {
  if (!node || node.majorType !== 5 || !node.children) return null;
  for (var i = 0; i < node.children.length; i++) {
    var k = node.children[i][0];
    if (k.majorType === 3 && cbor.read.textString(k) === key) return node.children[i][1];
  }
  return null;
}

// ---- authenticatorData bounded reader (WebAuthn sec. 6.1) --------------------

// authData = rpIdHash[32] || flags[1] || signCount[4 BE] || (AT? attestedCredentialData) || (ED? extensions CBOR).
// A bounded big-endian read: every slice is length-checked before it is taken, so a
// truncated / oversize field fails closed rather than reading past the buffer.
var AAGUID_LEN = 16;
function _parseAuthData(buf, E) {
  if (!Buffer.isBuffer(buf) || buf.length < 37) throw E("webauthn/bad-auth-data", "authenticatorData is shorter than the 37-byte minimum (RFC WebAuthn sec. 6.1)");
  var flags = buf[32];
  var out = {
    rpIdHash: buf.subarray(0, 32),
    flags: { up: !!(flags & 0x01), uv: !!(flags & 0x04), be: !!(flags & 0x08), bs: !!(flags & 0x10), at: !!(flags & 0x40), ed: !!(flags & 0x80) },
    signCount: buf.readUInt32BE(33),
    aaguid: null, credentialId: null, credentialPublicKey: null, credentialPublicKeyBytes: null, extensions: null,
  };
  // Backup State is only valid when Backup Eligibility is set: a credential cannot be
  // "backed up" if it is not "backup eligible" (WebAuthn sec. 6.1).
  if (out.flags.bs && !out.flags.be) throw E("webauthn/bad-auth-data", "authenticatorData sets Backup State (BS) without Backup Eligibility (BE) (WebAuthn sec. 6.1)");
  // The reserved flag bits (bit 1 = 0x02, bit 5 = 0x20) are undefined; a conforming
  // authenticator leaves them 0. Reject a set reserved bit rather than ignore an
  // unknown flag (WebAuthn sec. 6.1, fail-closed on undefined structure).
  if (flags & 0x22) throw E("webauthn/bad-auth-data", "authenticatorData sets a reserved (RFU) flag bit (WebAuthn sec. 6.1)");
  var off = 37;
  if (out.flags.at) {
    if (buf.length < off + AAGUID_LEN + 2) throw E("webauthn/bad-auth-data", "attestedCredentialData is truncated before the credentialId length");
    out.aaguid = buf.subarray(off, off + AAGUID_LEN); off += AAGUID_LEN;
    var credLen = buf.readUInt16BE(off); off += 2;
    if (credLen < 1 || credLen > 1023) throw E("webauthn/bad-credential-id", "credentialIdLength " + credLen + " is outside 1..1023 (RFC WebAuthn sec. 6.1)");
    if (buf.length < off + credLen) throw E("webauthn/bad-auth-data", "credentialId overruns authenticatorData");
    out.credentialId = buf.subarray(off, off + credLen); off += credLen;
    // credentialPublicKey is a COSE_Key: a single CBOR map occupying [off, its end).
    var keyNode;
    try { keyNode = cbor.decode(buf.subarray(off), { allowTrailing: true }); }
    catch (e) { throw E("webauthn/bad-cose-key", "the credential public key is not well-formed CBOR", e); }
    out.credentialPublicKeyBytes = buf.subarray(off, off + keyNode.bytes.length);
    out.credentialPublicKey = _decodeCoseKey(keyNode);
    off += keyNode.bytes.length;
  }
  if (out.flags.ed) {
    // With the ED flag set, the remainder MUST be exactly one well-formed CBOR map
    // (the extensions); the strict decoder rejects a non-map, malformed bytes, an
    // empty remainder, or trailing bytes (RFC WebAuthn sec. 6.1).
    var extNode;
    try { extNode = cbor.decode(buf.subarray(off)); }
    catch (e) { throw E("webauthn/bad-auth-data", "the authenticatorData extensions are not a single well-formed CBOR map", e); }
    if (extNode.majorType !== 5) throw E("webauthn/bad-auth-data", "the authenticatorData extensions must be a CBOR map");
    out.extensions = buf.subarray(off);
  } else if (off < buf.length) {
    // authenticatorData is fixed-layout: with the ED flag clear there MUST be no
    // bytes after the attestedCredentialData (RFC WebAuthn sec. 6.1). Trailing
    // bytes are a malformed structure -- fail closed rather than ignore them.
    throw E("webauthn/bad-auth-data", "authenticatorData has trailing bytes after attestedCredentialData with the ED flag clear");
  }
  return out;
}

// ---- COSE_Key decode (WebAuthn sec. 6.5.1, RFC 9052 sec. 7) ------------------

// The complete COSE credential-key conformance rule set (kty/alg/crv/length/canonical/
// profile/on-curve) lives in validator-cose, composed here so every credential key
// routes through the one home -- never a per-format re-derivation of a partial subset.
function _decodeCoseKey(node) { return validator.cose.credentialKey(node, WebauthnError, "webauthn/bad-cose-key"); }

// ---- signature verification bridge ------------------------------------------

// COSE algorithm id -> the WebCrypto import + verify descriptor. WebAuthn packed /
// android-key / tpm ECDSA signatures are DER ECDSA-Sig-Value, so they are converted
// to the raw r||s form pki.webcrypto (ieee-p1363) expects.
var COSE_ALG = {
  "-7":   { imp: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, ecdsa: 32 },
  "-35":  { imp: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" }, ecdsa: 48 },
  "-36":  { imp: { name: "ECDSA", namedCurve: "P-521" }, verify: { name: "ECDSA", hash: "SHA-512" }, ecdsa: 66 },
  "-8":   { imp: { name: "Ed25519" }, verify: { name: "Ed25519" }, ecdsa: 0 },
  // RFC 9864 fully-specified ids. WebAuthn recommends against them for credential creation,
  // but a verifier MUST evaluate an assertion signed under one. ESP256/384/512 are the
  // curve-pinned ECDSA twins of ES256/384/512; Ed25519(-19)/Ed448(-53) are fully-specified
  // EdDSA (Ed448 is the ONLY WebAuthn path to Ed448 -- -8 is Ed25519 only).
  "-9":   { imp: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, ecdsa: 32 },
  "-51":  { imp: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" }, ecdsa: 48 },
  "-52":  { imp: { name: "ECDSA", namedCurve: "P-521" }, verify: { name: "ECDSA", hash: "SHA-512" }, ecdsa: 66 },
  "-19":  { imp: { name: "Ed25519" }, verify: { name: "Ed25519" }, ecdsa: 0 },
  "-53":  { imp: { name: "Ed448" }, verify: { name: "Ed448" }, ecdsa: 0 },
  "-257": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
  "-258": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
  "-259": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
  "-37":  { imp: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 }, ecdsa: 0 },
  // RS1 (RSASSA-PKCS1-v1_5 / SHA-1): a legacy COSE algorithm real Windows Hello TPM
  // authenticators emit in their attestation statement. VERIFY-only support -- the
  // toolkit never signs with SHA-1; it must still evaluate the attestations that
  // ship using it, or a large class of TPM authenticators cannot be verified.
  "-65535": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
};

// DER ECDSA-Sig-Value { r, s } -> raw r||s (the ieee-p1363 form WebCrypto verify expects).
// validator-sig owns the complete strict-DER conformance (primitive, minimal, positive,
// bounded r/s), composed here.
function _derEcdsaToRaw(der, coordLen) { return validator.sig.ecdsaSigToRaw(der, coordLen, WebauthnError, "webauthn/bad-signature"); }

// Verify `sig` over `message` with the SPKI public key `spkiBytes` under COSE `alg`.
// A wrong signature resolves `false` from subtle.verify without throwing (a false
// verdict is a verdict); a structural failure -- an unimportable key, a bad
// descriptor -- is re-thrown as a typed fail-closed error, never masked as false.
function _verifySig(alg, sig, spkiBytes, message, E) {
  var d = COSE_ALG[String(alg)];
  if (!d) throw _err("webauthn/unsupported-algorithm", "unsupported COSE algorithm " + alg);
  var imp = d.imp, ver = d.verify;
  // COSE alg -8 (EdDSA) covers Ed25519 and Ed448; the WebCrypto name follows the
  // signing key's own SPKI algorithm OID, not the (curve-agnostic) alg id.
  if (alg === -8) { var nm = _edName(spkiBytes, E); imp = { name: nm }; ver = { name: nm }; }
  // node/OpenSSL imports any Ed25519/Ed448 SPKI without validating the point, and a
  // low-order (e.g. all-zeroes) key verifies a trivial signature -- so validate the OKP
  // point before verify. This covers EVERY key that signs a WebAuthn statement: the x5c
  // attestation-certificate key (packed/tpm/apple) AND the self-attestation credential key.
  if (imp.name === "Ed25519" || imp.name === "Ed448") _requireValidEdPoint(spkiBytes, imp.name, E);
  var s = d.ecdsa ? _derEcdsaToRaw(sig, d.ecdsa) : sig;
  return subtle.importKey("spki", spkiBytes, imp, false, ["verify"])
    .then(function (key) { return subtle.verify(ver, key, s, message); })
    .catch(function (e) { throw _err("webauthn/verify-error", "the attestation signature could not be evaluated", e); });
}
// The WebCrypto EdDSA name (Ed25519 / Ed448) an SPKI declares via its algorithm OID.
var ED_OID_NAME = {};
ED_OID_NAME[oid.byName("Ed25519")] = "Ed25519";
ED_OID_NAME[oid.byName("Ed448")] = "Ed448";
function _edName(spkiBytes, E) {
  var algOid;
  try { algOid = asn1.read.oid(asn1.decode(spkiBytes).children[0].children[0]); }
  catch (e) { throw E("webauthn/bad-signature", "the EdDSA public key is not a well-formed SPKI", e); }
  var nm = ED_OID_NAME[algOid];
  if (!nm) throw E("webauthn/unsupported-algorithm", "unsupported EdDSA curve OID " + algOid);
  return nm;
}
// The raw Edwards point an OKP SPKI carries (its BIT STRING body, past the unused-bits
// octet) MUST be a valid, full-order point -- reject an off-curve or low-order key before it
// verifies a signature (WebCrypto import does not check it). Curve from the WebCrypto name.
function _requireValidEdPoint(spkiBytes, name, E) {
  var content;
  try { content = asn1.decode(spkiBytes).children[1].content; }
  catch (e) { throw E("webauthn/bad-signature", "the EdDSA public key is not a well-formed SPKI", e); }
  var point = content && content.length ? content.subarray(1) : Buffer.alloc(0);
  if (!edwardsPoint.validate(point, name === "Ed25519" ? 6 : 7)) {
    throw E("webauthn/bad-signature", "the EdDSA public key is not a valid, full-order Edwards point");
  }
}

// A validated COSE credential key -> a self-contained SPKI the WebCrypto import
// consumes, so a credential public key and a certificate key verify by one path.
// validator-cose owns the encoding (EC2 / RSA / OKP), composed here.
function _coseKeyToSpki(key) { return validator.cose.toSpki(key, WebauthnError, "webauthn/bad-cose-key"); }

// The attestation-certificate subject public key MUST equal the credential public
// key that authenticatorData carries (WebAuthn 8.4/8.8 item 30). Compare the raw
// key material unsigned: an EC2 uncompressed point's X/Y vs the COSE x/y; an RSA
// modulus/exponent vs the COSE n/e. `cert.subjectPublicKeyInfo.publicKey.bytes` is
// the BIT STRING key material the SPKI carries.
// The named-curve OID a certificate's EC SubjectPublicKeyInfo declares (the DER
// OBJECT IDENTIFIER in the algorithm parameters). Fail-closed: absent or malformed
// curve parameters throw a typed key-mismatch -- never swallowed to a null the
// caller would compare as "no match by default".
function _certEcCurveOid(cert, E) {
  var params = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.algorithm && cert.subjectPublicKeyInfo.algorithm.parameters;
  if (!Buffer.isBuffer(params)) throw E("webauthn/key-mismatch", "the attestation certificate EC key carries no named-curve parameters");
  try { return asn1.read.oid(asn1.decode(params)); }
  catch (e) { throw E("webauthn/key-mismatch", "the attestation certificate EC curve is not a valid OBJECT IDENTIFIER", e); }
}
// A void assert: throws webauthn/key-mismatch on any inequality, returns nothing on
// success (called for its throw side-effect, like the other _check* asserts).
function _certPubKeyEqualsCose(cert, cose, E) {
  var raw = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.publicKey && cert.subjectPublicKeyInfo.publicKey.bytes;
  if (!raw) throw E("webauthn/key-mismatch", "the attestation certificate exposes no public key");
  if (cose.kty === 2) {
    // The certificate's declared EC curve MUST equal the credential key's curve --
    // a curve substitution is a different key even if the coordinate bytes line up.
    var wantCurve = validator.cose.EC2_CRV_OID[cose.crv];
    if (!wantCurve) throw E("webauthn/key-mismatch", "unsupported credential EC curve " + cose.crv);
    if (_certEcCurveOid(cert, E) !== oid.byName(wantCurve)) throw E("webauthn/key-mismatch", "the attestation certificate EC curve does not equal the credential key curve");
    if (raw.length < 1 || raw[0] !== 0x04) throw E("webauthn/key-mismatch", "the attestation certificate key is not an uncompressed EC point");
    var coordLen = (raw.length - 1) >> 1;
    var cx = raw.subarray(1, 1 + coordLen), cy = raw.subarray(1 + coordLen);
    if (!cose.x || !cose.y || !_ucmp(cx, cose.x) || !_ucmp(cy, cose.y)) throw E("webauthn/key-mismatch", "the attestation certificate EC key does not equal the credential public key");
    return;
  }
  if (cose.kty === 3) {
    var seq;
    try { seq = asn1.decode(raw); } catch (e) { throw E("webauthn/key-mismatch", "the attestation certificate RSA key is not decodable", e); }
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }; both
    // MUST be primitive INTEGERs (a constructed child has a null content buffer).
    if (!seq.children || seq.children.length !== 2 || !_isInteger(seq.children[0]) || !_isInteger(seq.children[1])) {
      throw E("webauthn/key-mismatch", "the attestation certificate RSA key is malformed");
    }
    var n = seq.children[0].content, ee = seq.children[1].content;
    if (!cose.n || !cose.e || !_ucmp(n, cose.n) || !_ucmp(ee, cose.e)) throw E("webauthn/key-mismatch", "the attestation certificate RSA key does not equal the credential public key");
    return;
  }
  if (cose.kty === 1) {
    // OKP Ed25519 / Ed448: the SPKI BIT STRING body IS the raw public key (fixed
    // width, so a byte-exact compare, not a leading-zero-stripping unsigned compare).
    if (!cose.x || !Buffer.from(raw).equals(cose.x)) throw E("webauthn/key-mismatch", "the attestation certificate OKP key does not equal the credential public key");
    return;
  }
  throw E("webauthn/key-mismatch", "unsupported credential key type for the certificate comparison");
}

// ---- TPM structure conformance (WebAuthn 8.3; TCG TPM 2.0 Part 2) -------------
// The TPMT_PUBLIC (pubArea) + TPMS_ATTEST (certInfo) decode + the pubArea-key binding
// live in validator-tpm, composed here. A malformed structure is bad-tpm; a key that
// does not equal the credential key is key-mismatch.
function _parseTpmPubArea(buf) { return validator.tpm.parsePubArea(buf, WebauthnError, "webauthn/bad-tpm"); }
function _parseTpmCertInfo(buf) { return validator.tpm.parseCertInfo(buf, WebauthnError, "webauthn/bad-tpm"); }
function _tpmPubKeyEqualsCose(pub, cose) { validator.tpm.pubKeyEqualsCose(pub, cose, WebauthnError, "webauthn/key-mismatch", "webauthn/bad-tpm"); }

// ---- extension helpers -------------------------------------------------------
// `oidName` is a registered name (byName resolves it at call time); an unregistered
// name is a programming error that surfaces as an undefined target, never swallowed.
function _findExt(cert, oidName) {
  var target = oid.byName(oidName);
  return (cert.extensions || []).filter(function (e) { return e.oid === target; })[0] || null;
}

// ---- public: parseAttestationObject -----------------------------------------

/**
 * @primitive pki.webauthn.parseAttestationObject
 * @signature pki.webauthn.parseAttestationObject(bytes) -> { fmt, attStmt, authData, authDataBytes }
 * @since 0.2.5
 * @status experimental
 * @spec W3C WebAuthn Level 3 sec. 6.5.4 / 6.1
 * @related pki.webauthn.verify
 *
 * Structurally decode a WebAuthn attestation object (the CBOR `{fmt, attStmt,
 * authData}`) and its authenticatorData, fail-closed. `authData` carries the decoded
 * rpIdHash / flags / signCount and, when the AT flag is set, the attestedCredentialData
 * (aaguid, credentialId, and the decoded COSE `credentialPublicKey`). `authDataBytes`
 * is the raw authenticatorData -- the exact bytes an attestation signature covers.
 * A malformed object throws `webauthn/bad-attestation-object`.
 *
 * @example
 *   var att = pki.webauthn.parseAttestationObject(attestationObject);
 *   att.fmt;                               // "packed"
 *   att.authData.credentialPublicKey.kty;  // 2 (EC2)
 */
function parseAttestationObject(bytes) {
  var root;
  try { root = cbor.decode(bytes); } catch (e) { throw _err("webauthn/bad-attestation-object", "the attestation object is not well-formed CBOR", e); }
  if (root.majorType !== 5) throw _err("webauthn/bad-attestation-object", "the attestation object must be a CBOR map { fmt, attStmt, authData }");
  var fmtN = _mapGet(root, "fmt"), attStmtN = _mapGet(root, "attStmt"), authDataN = _mapGet(root, "authData");
  // The attestation object is EXACTLY { fmt, attStmt, authData } -- no more, no fewer
  // (WebAuthn 6.5.4); an extra top-level key is a non-canonical envelope, rejected.
  if (root.children.length !== 3 || !fmtN || !attStmtN || !authDataN) throw _err("webauthn/bad-attestation-object", "the attestation object must be exactly { fmt, attStmt, authData }");
  if (fmtN.majorType !== 3) throw _err("webauthn/bad-attestation-object", "attestation object 'fmt' must be a text string");
  if (authDataN.majorType !== 2) throw _err("webauthn/bad-attestation-object", "attestation object 'authData' must be a byte string");
  var authDataBytes = cbor.read.byteString(authDataN);
  return {
    fmt: cbor.read.textString(fmtN),
    attStmt: attStmtN,
    authData: _parseAuthData(authDataBytes, _err),
    authDataBytes: authDataBytes,
  };
}

// ---- attestation-format verifiers -------------------------------------------

function _reqAttr(map, key) {
  var n = _mapGet(map, key);
  if (!n) throw _err("webauthn/bad-att-stmt", "the attestation statement is missing the '" + key + "' field");
  return n;
}
// Read a required attStmt field of an expected CBOR type, mapping a wrong-type
// cbor/* fault to the webauthn domain (an attStmt field is not-well-formed input to
// this layer, so it is a webauthn/bad-att-stmt verdict, not a leaked codec error).
function _attRead(map, key, reader, what) {
  var n = _reqAttr(map, key);
  try { return reader(n); }
  catch (e) { throw _err("webauthn/bad-att-stmt", "the attestation statement '" + key + "' must be " + what, e); }
}
function _algOf(attStmt) { return Number(_attRead(attStmt, "alg", cbor.read.int, "an integer")); }
function _sigOf(attStmt) { return _attRead(attStmt, "sig", cbor.read.byteString, "a byte string"); }
// A format's attStmt is its CANONICAL field set: every present key must be in
// `allowed`, and every key in `required` must be present. An unexpected field is a
// non-canonical statement, rejected before any field is trusted (WebAuthn sec. 8.*).
function _requireAttShape(attStmt, allowed, required) {
  var have = {};
  if (attStmt && attStmt.children) attStmt.children.forEach(function (kv) {
    // attStmt keys are text strings; a non-text key is a malformed statement,
    // rejected (not silently skipped, which would evade the unexpected-field check).
    if (kv[0].majorType !== 3) throw _err("webauthn/bad-att-stmt", "the attestation statement has a non-text-string field key");
    have[cbor.read.textString(kv[0])] = true;
  });
  Object.keys(have).forEach(function (k) { if (allowed.indexOf(k) === -1) throw _err("webauthn/bad-att-stmt", "the attestation statement carries an unexpected field '" + k + "'"); });
  required.forEach(function (k) { if (!have[k]) throw _err("webauthn/bad-att-stmt", "the attestation statement is missing the '" + k + "' field"); });
}
function _readX5c(attStmt) {
  var x5cN = _mapGet(attStmt, "x5c");
  if (!x5cN || x5cN.majorType !== 4 || !x5cN.children || !x5cN.children.length) throw _err("webauthn/bad-att-stmt", "x5c must be a non-empty array of certificates");
  return x5cN.children.map(function (c) {
    var der;
    try { der = cbor.read.byteString(c); } catch (e) { throw _err("webauthn/bad-att-stmt", "an x5c entry must be a byte string", e); }
    try { return x509.parse(der); } catch (e) { throw _err("webauthn/bad-att-stmt", "an x5c certificate is not a well-formed X.509 certificate", e); }
  });
}
// The WebAuthn attestation-certificate profile checks (WebAuthn 8.2.1 packed / 8.3.1 TPM
// AIK / the id-fido-gen-ce-aaguid extension) live in validator-attcert, composed here. The
// extension-accessor object hands the validator this format's fail-closed extension
// decoders so it stays decoupled from the webauthn error namespace.
var _exts = { find: _findExt, decode: _decodeExt };
function _requireV3(cert) { validator.attcert.requireV3(cert, WebauthnError, "webauthn/bad-att-cert"); }
function _checkPackedCert(cert) { validator.attcert.packedCert(cert, _exts, WebauthnError, "webauthn/bad-att-cert"); }
function _checkAikCert(cert) { validator.attcert.aikCert(cert, _exts, WebauthnError, "webauthn/bad-att-cert"); }
function _checkAaguidExt(cert, aaguid) { validator.attcert.aaguidExt(cert, aaguid, _exts, WebauthnError, "webauthn/bad-att-cert", "webauthn/aaguid-mismatch"); }

var VERIFIERS = {
  // packed (WebAuthn 8.2): the x5c arm (Basic/AttCA) or self-attestation.
  packed: function (att, clientDataHash) {
    var isX5c = !!_mapGet(att.attStmt, "x5c");
    _requireAttShape(att.attStmt, isX5c ? ["alg", "sig", "x5c"] : ["alg", "sig"], isX5c ? ["alg", "sig", "x5c"] : ["alg", "sig"]);
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var message = Buffer.concat([att.authDataBytes, clientDataHash]);
    if (isX5c) {
      var chain = _readX5c(att.attStmt), leaf = chain[0];
      _checkPackedCert(leaf);   // 8.2.1: v3, non-CA, OU=Authenticator Attestation
      return _verifySig(alg, sig, leaf.subjectPublicKeyInfo.bytes, message, _err).then(function (ok) {
        if (!ok) throw _err("webauthn/verify-failed", "the packed attestation signature does not verify under the x5c leaf key");
        _checkAaguidExt(leaf, att.authData.aaguid);
        return _result("packed", "Basic", chain, att);
      });
    }
    // Self-attestation: the statement alg MUST equal the credential key's own alg
    // (WebAuthn 8.2), then sig verifies under the credential key itself.
    if (alg !== att.authData.credentialPublicKey.alg) throw _err("webauthn/bad-att-stmt", "the packed self-attestation alg does not match the credential public key algorithm (WebAuthn 8.2)");
    var spki = _coseKeyToSpki(att.authData.credentialPublicKey);
    return _verifySig(alg, sig, spki, message, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the packed self-attestation signature does not verify under the credential key");
      return _result("packed", "Self", [], att);
    });
  },

  // fido-u2f (WebAuthn 8.6): reconstruct the U2F verificationData and verify with
  // the single x5c cert. The credential key MUST be EC2/P-256.
  "fido-u2f": function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["sig", "x5c"], ["sig", "x5c"]);
    var chain = _readX5c(att.attStmt);
    if (chain.length !== 1) throw _err("webauthn/bad-att-stmt", "fido-u2f x5c MUST contain exactly one certificate (WebAuthn 8.6)");
    // WebAuthn 8.6 does not require a version-3 certificate for fido-u2f (unlike the
    // packed 8.2.1 / tpm 8.3.1 leaves), so a legacy v1 U2F attestation cert is valid.
    var leaf = chain[0];
    var sig = _sigOf(att.attStmt);
    var key = att.authData.credentialPublicKey;
    // WebAuthn 8.6: the fido-u2f credential public key MUST be alg -7 (ES256) on EC2 P-256 --
    // the newer ESP256 (-9) id, though the same curve, is not a valid fido-u2f credential.
    if (key.alg !== -7 || key.kty !== 2 || key.crv !== 1 || !key.x || !key.y || key.x.length !== 32 || key.y.length !== 32) {
      throw _err("webauthn/bad-att-stmt", "fido-u2f requires an ES256 (-7) EC2 P-256 credential public key (WebAuthn 8.6)");
    }
    var publicKeyU2F = Buffer.concat([Buffer.from([0x04]), key.x, key.y]);
    var verificationData = Buffer.concat([Buffer.from([0x00]), att.authData.rpIdHash, clientDataHash, att.authData.credentialId, publicKeyU2F]);
    return _verifySig(-7, sig, leaf.subjectPublicKeyInfo.bytes, verificationData, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the fido-u2f attestation signature does not verify under the x5c leaf key");
      return _result("fido-u2f", "Basic", chain, att);
    });
  },

  // apple (WebAuthn 8.8): the binding is the SHA-256 nonce over authData ||
  // clientDataHash embedded in the leaf cert; there is no signature field.
  apple: function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["alg", "x5c"], ["x5c"]);   // alg optional, ignored
    var chain = _readX5c(att.attStmt), leaf = chain[0];
    _requireV3(leaf);
    var nonce = _sha("sha256", Buffer.concat([att.authDataBytes, clientDataHash]));
    var ext = _findExt(leaf, "appleAnonymousAttestation");
    if (!ext) throw _err("webauthn/bad-att-cert", "the apple attestation certificate is missing the anonymous-attestation extension (WebAuthn 8.8)");
    var embedded = _appleNonce(ext.value);
    if (!embedded.equals(nonce)) throw _err("webauthn/verify-failed", "the apple attestation nonce does not equal SHA-256(authData || clientDataHash)");
    _certPubKeyEqualsCose(leaf, att.authData.credentialPublicKey, _err);   // 8.8 item 30
    return Promise.resolve(_result("apple", "AnonCA", chain, att));
  },

  // android-key (WebAuthn 8.4): verify sig with the leaf key, bind the leaf key to
  // the credential key, and enforce the four KeyDescription checks (8.4.1).
  "android-key": function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["alg", "sig", "x5c"], ["alg", "sig", "x5c"]);
    var chain = _readX5c(att.attStmt), leaf = chain[0];
    _requireV3(leaf);
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var message = Buffer.concat([att.authDataBytes, clientDataHash]);
    return _verifySig(alg, sig, leaf.subjectPublicKeyInfo.bytes, message, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the android-key attestation signature does not verify under the x5c leaf key");
      _certPubKeyEqualsCose(leaf, att.authData.credentialPublicKey, _err);
      _checkAndroidKeyDescription(leaf, clientDataHash);   // 8.4.1
      return _result("android-key", "Basic", chain, att);
    });
  },

  // tpm (WebAuthn 8.3): decode certInfo/pubArea, enforce magic/type/extraData/Name,
  // bind pubArea to the credential key, and verify sig over certInfo with the AIK.
  tpm: function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["ver", "alg", "sig", "certInfo", "pubArea", "x5c"], ["ver", "alg", "sig", "certInfo", "pubArea", "x5c"]);
    var verN = _mapGet(att.attStmt, "ver");
    if (!verN || verN.majorType !== 3 || cbor.read.textString(verN) !== "2.0") throw _err("webauthn/bad-att-stmt", "tpm attestation 'ver' MUST be \"2.0\" (WebAuthn 8.3)");
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var pubAreaBytes = _attRead(att.attStmt, "pubArea", cbor.read.byteString, "a byte string");
    var certInfoBytes = _attRead(att.attStmt, "certInfo", cbor.read.byteString, "a byte string");
    var chain = _readX5c(att.attStmt), aik = chain[0];

    var pub = _parseTpmPubArea(pubAreaBytes);
    _tpmPubKeyEqualsCose(pub, att.authData.credentialPublicKey);   // 8.3 item 22

    // validator-tpm decodes certInfo AND validates magic == TPM_GENERATED_VALUE / type ==
    // TPM_ST_ATTEST_CERTIFY, so the returned structure is already self-consistent.
    var certInfo = _parseTpmCertInfo(certInfoBytes);

    // extraData == hash_alg(authData || clientDataHash) (bare digest, no method id).
    var attToBeSigned = Buffer.concat([att.authDataBytes, clientDataHash]);
    if (!certInfo.extraData.equals(_sha(_coseAlgHash(alg, _err), attToBeSigned))) throw _err("webauthn/verify-failed", "certInfo extraData does not equal the hash of authData || clientDataHash");

    // attested.name == nameAlg || H_nameAlg(pubArea).
    var nameHash = validator.tpm.TPM_ALG_HASH[pub.nameAlg];
    if (!nameHash) throw _err("webauthn/bad-tpm", "unsupported TPM nameAlg 0x" + pub.nameAlg.toString(16));
    var computedName = Buffer.concat([pub.nameAlgBytes, _sha(nameHash, pubAreaBytes)]);
    if (!certInfo.attestedName.equals(computedName)) throw _err("webauthn/verify-failed", "certInfo attested Name does not match the pubArea TPM Name");

    // WebAuthn 8.3 verification step: "Verify the sig is a valid signature over
    // certInfo ... with the algorithm specified in alg" -- sig is verified DIRECTLY
    // with alg, not parsed as a TPMT_SIGNATURE and unwrapped. The attStmt-syntax
    // "in the form of a TPMT_SIGNATURE" is a description of the byte string; real
    // authenticators put the raw signature here (the interop KAT's tpm sig is a bare
    // 256-byte RSASSA signature that verifies as-is), and the reference verifier
    // (py_webauthn) verifies it directly with alg the same way.
    return _verifySig(alg, sig, aik.subjectPublicKeyInfo.bytes, certInfoBytes, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the tpm attestation signature does not verify over certInfo under the AIK");
      _checkAikCert(aik);   // 8.3.1
      _checkAaguidExt(aik, att.authData.aaguid);   // 8.3.1: aaguid ext, if present, MUST match
      return _result("tpm", "AttCA", chain, att);
    });
  },

  // none (WebAuthn 8.7): the authenticator provides no attestation. attStmt MUST be
  // an empty map; there is no statement to verify, so the result carries no trust
  // path. The credential public key still binds via authenticatorData (AT flag).
  none: function (att) {
    // attStmt MUST BE an empty CBOR map -- reject a missing, non-map, or non-empty
    // attStmt, not only a non-empty map (WebAuthn 8.7).
    if (!att.attStmt || att.attStmt.majorType !== 5 || (att.attStmt.children && att.attStmt.children.length !== 0)) {
      throw _err("webauthn/bad-att-stmt", "the none attestation statement MUST be an empty map (WebAuthn 8.7)");
    }
    return Promise.resolve(_result("none", "None", [], att));
  },
};

// `chain` is the x5c order (leaf-first); trustPath is surfaced in pki.path.validate
// order (anchor-adjacent first, target/leaf last) so the caller passes it straight
// to the path validator without re-ordering. The input array is not mutated.
function _result(fmt, attestationType, chain, att) {
  return { verified: true, fmt: fmt, attestationType: attestationType, trustPath: (chain || []).slice().reverse(), aaguid: att.authData.aaguid, credentialPublicKey: att.authData.credentialPublicKey };
}

// Decode the Apple extension AppleAnonymousAttestation ::= SEQUENCE { nonce [1]
// EXPLICIT OCTET STRING } (WebAuthn 8.8 item 29) and return the 32-byte nonce.
function _appleNonce(extValue) {
  var seq;
  try { seq = asn1.decode(extValue); } catch (e) { throw _err("webauthn/bad-att-cert", "the apple attestation extension is not decodable", e); }
  var tagged = seq.children && seq.children[0];
  if (!tagged || tagged.tagClass !== "context" || tagged.tagNumber !== 1 || !tagged.children || !tagged.children[0]) {
    throw _err("webauthn/bad-att-cert", "the apple attestation extension is not SEQUENCE { [1] OCTET STRING }");
  }
  try { return asn1.read.octetString(tagged.children[0]); } catch (e) { throw _err("webauthn/bad-att-cert", "the apple attestation nonce is not an OCTET STRING", e); }
}

// The complete Android Key Attestation KeyDescription conformance (AOSP schema + WebAuthn
// 8.4.1) lives in validator-keydesc, composed here. A structural fault is bad-att-cert; a
// well-formed description that fails an 8.4.1 MUST is verify-failed.
function _checkAndroidKeyDescription(cert, clientDataHash) {
  validator.keydesc.androidKeyDescription(cert, clientDataHash, _exts, WebauthnError, "webauthn/bad-att-cert", "webauthn/verify-failed");
}


/**
 * @primitive pki.webauthn.verify
 * @signature pki.webauthn.verify(attestationObject, clientDataHash, opts) -> Promise<{ verified, fmt, attestationType, trustPath, aaguid, credentialPublicKey }>
 * @since 0.2.5
 * @status experimental
 * @spec W3C WebAuthn Level 3 sec. 8
 * @related pki.webauthn.parseAttestationObject
 *
 * Verify a WebAuthn attestation statement: the attestation signature over
 * `authenticatorData || clientDataHash` and (for the x5c formats) the format's
 * certificate requirements. `clientDataHash` is the SHA-256 of the serialized client
 * data, supplied by the relying party. Resolves the attestation type + trust path or
 * throws a typed `webauthn/*` error; a signature that does not verify is a
 * `webauthn/verify-failed` verdict, never a silent pass.
 *
 * @intro This verifies the attestation STATEMENT -- the signature and the format's
 *   structural bindings (the x5c leaf key == credential key, the apple nonce, the tpm
 *   certInfo Name/extraData, the android KeyDescription, the fido-u2f verificationData).
 *   Chaining the returned `trustPath` (the x5c certificates in `pki.path.validate`
 *   order -- anchor-adjacent first, leaf last) to a trusted root is the caller's
 *   step: anchor it with `pki.path.validate` against roots you pin. Resolving an
 *   authenticator's root from its aaguid via the FIDO Metadata Service, plus the
 *   chain-to-anchor call, are not built in yet -- re-open when the caller supplies an
 *   explicit trusted-root set or a FIDO MDS BLOB (`opts.mdsBlob`) to bind the path.
 *
 * @example
 *   var res = await pki.webauthn.verify(attestationObject, clientDataHash, {});
 *   res.verified;         // true (statement signature + bindings hold)
 *   res.attestationType;  // "Basic"
 *   // anchor res.trustPath to your pinned roots with pki.path.validate
 */
function verify(attestationObject, clientDataHash, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(clientDataHash) || clientDataHash.length !== 32) {
    return Promise.reject(_err("webauthn/bad-input", "clientDataHash must be a 32-byte SHA-256 digest"));
  }
  var att;
  try { att = parseAttestationObject(attestationObject); } catch (e) { return Promise.reject(e); }
  // A registration attestation MUST carry attestedCredentialData (the AT flag): the
  // whole point is to bind the attestation to a credential public key. Reject an
  // AT-clear authenticatorData up front -- else the packed x5c arm could resolve a
  // positive verdict bound to NO credential, and every arm would dereference the
  // null credential key with a raw (untyped) throw (WebAuthn 6.1 / 7.1).
  if (!att.authData.flags.at || !att.authData.credentialPublicKey) {
    return Promise.reject(_err("webauthn/bad-auth-data", "attestation requires attestedCredentialData (the AT flag must be set)"));
  }
  var verifier = VERIFIERS[att.fmt];
  if (!verifier) return Promise.reject(_err("webauthn/unsupported-format", "attestation statement format '" + att.fmt + "' is not supported"));
  return Promise.resolve().then(function () { return verifier(att, clientDataHash, opts); });
}

void constants;

module.exports = {
  parseAttestationObject: parseAttestationObject,
  verify: verify,
};
