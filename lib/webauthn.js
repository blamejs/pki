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
 *   android-key, apple, fido-u2f, none, compound, and android-safetynet behind an
 *   opt-in) -- the attestation-statement signature and each format's structural
 *   bindings. The attestation CBOR is decoded by the strict,
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
var guard = require("./guard-all");
var jose = require("./jose");
var mds = require("./webauthn-mds");
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
var COSE_ALG_HASH = { "-7": "sha256", "-9": "sha256", "-257": "sha256", "-37": "sha256", "-35": "sha384", "-51": "sha384", "-258": "sha384", "-38": "sha384", "-36": "sha512", "-52": "sha512", "-259": "sha512", "-39": "sha512", "-65535": "sha1" };
function _coseAlgHash(alg, E) {
  var h = COSE_ALG_HASH[String(alg)];
  if (!h) throw E("webauthn/unsupported-algorithm", "no hash mapping for COSE algorithm " + alg);
  return h;
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
function _decodeCoseKey(node) {
  return validator.cose.credentialKey(node, WebauthnError, "webauthn/bad-cose-key", "webauthn/unsupported-algorithm");
}

/**
 * @primitive  pki.webauthn.parseCoseKey
 * @signature  pki.webauthn.parseCoseKey(bytes) -> object
 * @since      0.5.2
 * @status     stable
 * @spec       RFC 9052, W3C WebAuthn Level 3 sec. 6.5.1
 * @related    pki.webauthn.verify, pki.webauthn.verifyAssertion
 *
 * Decode a bare COSE_Key -- the credential public key a relying party stored at
 * registration -- back into the object `verifyAssertion` takes. `pki.webauthn.verify`
 * returns that object, but the durable form is bytes: the object carries `Buffer`
 * values, so a JSON round trip through a datastore yields
 * `{"type":"Buffer","data":[...]}` rather than the object that went in, and existing
 * credential stores already hold COSE bytes whoever wrote them. Without this the only
 * routes into the decoder were `parseAttestationObject` and `parseAuthenticatorData`,
 * both of which parse a CONTAINING structure -- so recovering a stored key meant
 * fabricating an authenticatorData that never existed.
 *
 * The same validation the attestation path applies: the key type, the algorithm, the
 * curve, and the coordinates are checked, and anything that is not a credential COSE
 * key is refused with `webauthn/bad-cose-key`. `verifyAssertion` accepts either form
 * for `credentialPublicKey`, so calling this first is a convenience rather than a step.
 *
 * @example
 *   // requires: `attestationObject` / `clientDataHash` -- what a browser returns from a
 *   // registration ceremony
 *   var reg = await pki.webauthn.verify(attestationObject, clientDataHash, {});
 *   var stored = reg.credentialPublicKeyBytes;   // the form a credential row holds
 *   // ... at a login months later, read it back:
 *   var key = pki.webauthn.parseCoseKey(stored);
 *   key.alg;   // -> -7 for ES256
 *   // verifyAssertion takes either form, so this parse is a convenience, not a step:
 *   // pass `stored` straight as its credentialPublicKey.
 */
function parseCoseKey(bytes) {
  var buf = _bytesArg(bytes, "the COSE key");
  var node;
  try { node = cbor.decode(buf); }
  catch (e) { throw _err("webauthn/bad-cose-key", "the stored credential key is not decodable CBOR", e); }
  return _decodeCoseKey(node);
}

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
  // RSASSA-PSS. The salt length is the hash length, the profile WebCrypto verifies and the one
  // RFC 8230 sec. 2 fixes for the COSE PS* identifiers -- 32 / 48 / 64 bytes for SHA-256/384/512.
  "-37":  { imp: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 }, ecdsa: 0 },
  "-38":  { imp: { name: "RSA-PSS", hash: "SHA-384" }, verify: { name: "RSA-PSS", saltLength: 48 }, ecdsa: 0 },
  "-39":  { imp: { name: "RSA-PSS", hash: "SHA-512" }, verify: { name: "RSA-PSS", saltLength: 64 }, ecdsa: 0 },
  // RS1 (RSASSA-PKCS1-v1_5 / SHA-1): a legacy COSE algorithm real Windows Hello TPM
  // authenticators emit in their attestation statement. VERIFY-only support -- the
  // toolkit never signs with SHA-1; it must still evaluate the attestations that
  // ship using it, or a large class of TPM authenticators cannot be verified.
  "-65535": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
};

// DER ECDSA-Sig-Value { r, s } -> raw r||s (the ieee-p1363 form WebCrypto verify expects).
// validator-sig owns the complete strict-DER conformance PLUS the FIPS 186-5 sec. 6.4.2 order bound
// (r,s in [1, n-1] -- the order-aware gate a curve-aware verifier MUST use), composed here.
function _derEcdsaToRaw(der, curve) { return validator.sig.ecdsaDerToP1363(der, curve, WebauthnError, "webauthn/bad-signature"); }

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
  var s = d.ecdsa ? _derEcdsaToRaw(sig, d.imp.namedCurve) : sig;
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
// Which certificate key ALGORITHMS a credential key of each COSE type may be carried by. Two keys
// are the same key only if they are the same KIND of key: the bytes alone do not say what a key is,
// and for the Edwards curves they cannot -- an X25519 key-agreement key and an Ed25519 signing key
// are both 32 raw bytes, so a certificate declaring the former would otherwise compare equal to a
// credential key declaring the latter and be accepted as its attestation certificate. The EC2
// branch already asked this question as a curve check; asking it only there left the two key types
// whose confusion is undetectable from the material to be decided on the material alone.
// A row per COSE key type, keyed the way every other algorithm decision in this toolkit is.
function _certKeyAlgNames(cose) {
  if (cose.kty === 2) return ["ecPublicKey"];
  // An RSA key may be carried under the general OID or under id-RSASSA-PSS, which restricts it to
  // PSS but is the same key (RFC 4055 sec. 1.2).
  if (cose.kty === 3) return ["rsaEncryption", "rsassaPss"];
  if (cose.kty === 1) {
    var okp = validator.cose.OKP_CRV[cose.crv];
    return okp ? [okp.oid] : [];
  }
  return [];
}
function _assertCertKeyAlgorithm(cert, cose, E) {
  var alg = (cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.algorithm) || {};
  var want = _certKeyAlgNames(cose);
  if (!want.length || want.indexOf(alg.name) < 0) {
    throw E("webauthn/key-mismatch", "the attestation certificate carries a " + JSON.stringify(alg.name) +
      " key, which is not the kind of key the credential public key declares");
  }
}
// A void assert: throws webauthn/key-mismatch on any inequality, returns nothing on
// success (called for its throw side-effect, like the other _check* asserts).
function _certPubKeyEqualsCose(cert, cose, E) {
  var raw = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.publicKey && cert.subjectPublicKeyInfo.publicKey.bytes;
  if (!raw) throw E("webauthn/key-mismatch", "the attestation certificate exposes no public key");
  _assertCertKeyAlgorithm(cert, cose, E);
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
 * @status stable
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
 *   // requires: `attestationObject` -- the CBOR bytes a browser returns from
 *   // navigator.credentials.create(), i.e. credential.response.attestationObject
 *   var att = pki.webauthn.parseAttestationObject(attestationObject);
 *   att.fmt;                               // "packed"
 *   att.authData.credentialPublicKey.kty;  // 2 (EC2)
 */
function parseAttestationObject(bytes) {
  var root;
  try { root = cbor.decode(bytes); } catch (e) { throw _err("webauthn/bad-attestation-object", "the attestation object is not well-formed CBOR", e); }
  if (root.majorType !== 5) throw _err("webauthn/bad-attestation-object", "the attestation object must be a CBOR map { fmt, attStmt, authData }");
  var fmtN = cbor.read.mapGet(root, "fmt"), attStmtN = cbor.read.mapGet(root, "attStmt"), authDataN = cbor.read.mapGet(root, "authData");
  // The attestation object is EXACTLY { fmt, attStmt, authData } -- no more, no fewer
  // (WebAuthn 6.5.4); an extra top-level key is a non-canonical envelope, rejected.
  if (root.children.length !== 3 || !fmtN || !attStmtN || !authDataN) throw _err("webauthn/bad-attestation-object", "the attestation object must be exactly { fmt, attStmt, authData }");
  if (fmtN.majorType !== 3) throw _err("webauthn/bad-attestation-object", "attestation object 'fmt' must be a text string");
  // attStmt is the attestation statement, a CBOR map keyed by field name (WebAuthn 6.5.4) for every
  // format but one: sec. 8.9 gives compound an ARRAY of nested statements. Which shape a format
  // takes is a registry row, not a branch, so adding a format cannot silently widen the envelope
  // for the others -- a non-map value (whose children are single nodes, not { key, value } pairs)
  // must never reach the per-field statement walk of a format that expects a map.
  var wantMajor = ATT_STMT_MAJOR[cbor.read.textString(fmtN)];
  if (wantMajor === undefined) wantMajor = 5;
  if (attStmtN.majorType !== wantMajor) {
    throw _err("webauthn/bad-attestation-object", "attestation object 'attStmt' must be a CBOR " + (wantMajor === 4 ? "array" : "map") + " for format " + JSON.stringify(cbor.read.textString(fmtN)));
  }
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
  var n = cbor.read.mapGet(map, key);
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
  // attStmt is the attestation-statement map (parseAttestationObject established it is a CBOR
  // map). cbor.read.map asserts the major type and yields the { key, value } pairs -- never a
  // raw .children walk, whose entries are single nodes (not pairs) for a non-map, so a pair
  // index would read undefined and throw a raw TypeError instead of failing closed.
  cbor.read.map(attStmt).forEach(function (kv) {
    // attStmt keys are text strings; a non-text key is a malformed statement,
    // rejected (not silently skipped, which would evade the unexpected-field check).
    if (kv[0].majorType !== 3) throw _err("webauthn/bad-att-stmt", "the attestation statement has a non-text-string field key");
    have[cbor.read.textString(kv[0])] = true;
  });
  Object.keys(have).forEach(function (k) { if (allowed.indexOf(k) === -1) throw _err("webauthn/bad-att-stmt", "the attestation statement carries an unexpected field '" + k + "'"); });
  required.forEach(function (k) { if (!have[k]) throw _err("webauthn/bad-att-stmt", "the attestation statement is missing the '" + k + "' field"); });
}
// The CBOR major type each format's attStmt takes. Every format uses a map (5) except compound,
// whose sec. 8.9 syntax is an array of nested statements. A data row rather than a branch, so a
// future format declares its shape here instead of loosening the shared envelope check.
var ATT_STMT_MAJOR = { compound: 4 };

// Which attestation formats put the AAGUID under their signature. A registry row rather than a
// branch, so adding a format forces the question to be answered for it rather than inheriting the
// permissive default. Every format signs over authenticatorData (which contains the AAGUID) except
// fido-u2f, whose sec. 8.6 verificationData is assembled from named fields and omits it.
// The question is asked PER FORMAT, and answered for the element being judged -- never once for a
// whole statement. A compound mixes formats, and a single answer would be wrong in both directions:
// it would either trust a u2f element's unsigned AAGUID, or refuse to look a packed element up by
// the very AAGUID its own signature covers.
var _AAGUID_SIGNED_BY_FMT = Object.assign(Object.create(null), { "fido-u2f": false });
function _aaguidIsSigned(fmt) { return _AAGUID_SIGNED_BY_FMT[fmt] !== false; }

// The options pki.webauthn.verify recognises. Null-prototype, so a caller-supplied key cannot
// resolve to an inherited Object member and read as recognised.
var _VERIFY_OPTS = Object.assign(Object.create(null), {
  time: 1, metadata: 1, tpmPolicy: 1, safetyNetRoots: 1, verifySafetyNetJws: 1, requireCtsProfileMatch: 1,
  expectedRpId: 1, requireUserPresence: 1, requireUserVerification: 1, allowedAlgorithms: 1,
  rootCertificates: 1,
  clientDataJSON: 1, expectedChallenge: 1, expectedOrigin: 1, expectedTopOrigin: 1,
});

// The boolean switches whose only reader sits inside ONE format's arm, so nothing else would ever
// examine them. The binding switches are absent because _applyBindings owns their type and runs on
// every format and on the assertion path too -- a second copy of that rule here would be a second
// place for it to drift.
var _FORMAT_SCOPED_BOOLEAN_OPTS = ["verifySafetyNetJws", "requireCtsProfileMatch"];

// Anchor an attestation's trust path to roots the CALLER pins. The metadata route
// resolves an authenticator's roots from the catalogue that registered it, which is
// the stronger source -- but it only reaches models the catalogue lists, and some
// are not there: Apple does not publish its authenticators to the FIDO Metadata
// Service, and the Google hardware-attestation roots are distributed by Google. For
// those formats the catalogue route resolves nothing, so without this there is no
// way to anchor them at all and a trust path comes back unchecked. (android-safetynet
// already had its own `safetyNetRoots` for the same reason; this is that carve-out
// made general.)
//
// PRECEDENCE, stated rather than implied: `metadata` governs when it is supplied,
// because a model's own registered roots are a stronger claim than a static pin, and
// its status reports can disqualify a model these roots would still accept.
// `rootCertificates` is the fallback for the models the catalogue does not cover.
// Supplying both is not an error -- it is the ordinary configuration for a relying
// party that accepts MDS-listed authenticators AND Apple.
// The caller's pinned roots are copied SYNCHRONOUSLY, at the entry point, because
// they are not read until the attestation verifier has resolved -- a later promise
// turn. Both the ARRAY and each DER buffer in it stay caller-owned across that gap,
// so a caller that recycles the array or overwrites a certificate's bytes in between
// would have the attestation anchored against the replacement roots while the verdict
// still reports `anchoredTo: "rootCertificates"` (CWE-367 reaching a wrong trust
// decision). Same defence, and the same reason, as the assertion input's snapshot.
// Shape faults are NOT raised here: the array is validated where it is consumed, so
// supplying a malformed pin alongside a metadata catalogue that answers keeps failing
// exactly where it did before.
// A parsed certificate is a tree of plain objects, arrays and Buffers, and the anchor
// comparison downstream reads its `subject` and `subjectPublicKeyInfo` -- both nested
// Buffers the caller still owns. Copying only the top-level array would leave those
// aliased, so the parsed form is deep-copied: every Buffer is duplicated and every
// container rebuilt, while the value types a parsed certificate carries (Date for a
// validity bound, BigInt for a serial) are preserved rather than flattened.
//
// The depth bound is a RECURSION BACKSTOP set far above any real certificate, never the
// precision mechanism -- a bound tuned to today's shapes silently rejects a legitimate root
// the moment a deeper one appears. A measured certificate reaches depth 5, and the deepest
// structure the profile allows -- a certificate policy whose qualifier carries a UserNotice
// with a noticeRef and its noticeNumbers -- lands near 12, so a cap of 12 would sit exactly
// on a conforming root. This is set well clear of that; it exists only so a cyclic or hostile
// object cannot recurse without end.
function _cloneParsed(v, depth) {
  if (depth > 64) throw _err("webauthn/bad-input", "opts.rootCertificates[] is nested too deeply to be a parsed certificate");
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.from(v);
  if (Array.isArray(v)) return v.map(function (x) { return _cloneParsed(x, depth + 1); });
  if (v instanceof Date) return new Date(v.getTime());
  if (v && typeof v === "object") {
    var out = {};
    Object.keys(v).forEach(function (k) { out[k] = _cloneParsed(v[k], depth + 1); });
    return out;
  }
  return v;   // string, number, boolean, bigint, null, undefined -- all immutable
}

// A caller-owned byte argument, copied so nothing downstream reads bytes the caller can still
// rewrite, and accepted in every form the W3C BufferSource contract defines.
//
// ONE accepted set, for every byte argument on this namespace. The forms differed per argument
// before -- an attestation object took an ArrayBuffer while the clientDataHash beside it took only
// a Buffer -- and the caller producing both is the same one: `crypto.subtle.digest` returns an
// ArrayBuffer, so the natural way to compute that hash produced a value this verb refused. Which
// forms an argument accepts is not a per-argument decision; it is the namespace's contract, and it
// is made once here.
//
// Anything that is not a BufferSource is refused BY NAME, rather than passed down to be described
// by whichever parser reaches it first.
function _isBufferSource(v) { return ArrayBuffer.isView(v) || v instanceof ArrayBuffer; }
function _bytesArg(v, label) {
  if (_isBufferSource(v)) {
    return guard.bytes.snapshotSource(v, WebauthnError, "webauthn/bad-input", label);
  }
  throw _err("webauthn/bad-input", label + " must be a BufferSource (a Buffer, a typed-array view, or an ArrayBuffer)");
}

function _snapshotRoots(supplied) {
  if (!Array.isArray(supplied)) return supplied;
  return supplied.map(function (root) {
    if (Buffer.isBuffer(root) || root instanceof Uint8Array) {
      return guard.bytes.snapshot(root, WebauthnError, "webauthn/bad-input", "opts.rootCertificates[]");
    }
    if (root && typeof root === "object") return _cloneParsed(root, 0);
    return root;   // a PEM string is immutable
  });
}

// `supplied` is the SNAPSHOT taken at the entry point, never `opts.rootCertificates`
// read afresh here -- that re-read is the window this guard closes. `opts` is still
// threaded for the non-aliasing options (the validation time).
// `vopts` is `verify`'s NORMALIZED options object, never the caller's -- the parameter is
// named for that so a future caller cannot hand it the live one without noticing. Everything
// it reads was captured synchronously at the entry.
function _applyCallerRoots(res, supplied, vopts, onlyPaths) {
  if (!Array.isArray(supplied) || !supplied.length) {
    throw _err("webauthn/bad-input", "opts.rootCertificates must be a non-empty array of root certificates (DER, PEM, or parsed)");
  }
  // DER, PEM or an already-parsed certificate, decoded HERE -- the anchor comparison
  // downstream reads a certificate's subject and key, so a raw buffer reaching it
  // would fault on a field it does not have rather than naming the caller's mistake.
  // The same three forms opts.safetyNetRoots takes, since it is the same question.
  var roots = supplied.map(function (root, i) {
    var cert;
    try { cert = (Buffer.isBuffer(root) || typeof root === "string") ? x509.parse(root) : root; }
    catch (e) { throw _err("webauthn/bad-input", "opts.rootCertificates[" + i + "] is not a decodable certificate", e); }
    if (!cert || !cert.subject || !cert.subjectPublicKeyInfo) {
      throw _err("webauthn/bad-input", "opts.rootCertificates[" + i + "] is not a certificate");
    }
    return cert;
  });
  // Same rule the metadata route applies: a compound element carrying no
  // certificates makes no claim there is anything to anchor, so it is not a reason to
  // refuse the statement -- but `anchoredTo` alone would then say "anchored" over a
  // statement it did not wholly cover. The coverage is reported instead.
  // `onlyPaths`, when given, is the set of paths the CATALOGUE did not cover -- the
  // fallback is for exactly those. Applying it to the whole statement instead would
  // re-judge an element the catalogue already governed against roots that have nothing
  // to do with it: a compound holding one listed element (chaining to the root its own
  // metadata entry registers) beside one unlisted element (chaining to a caller pin) would
  // be refused, because the listed element does not chain to the pin. That is the
  // documented "MDS-listed authenticators AND Apple" configuration, and each element is
  // still anchored to something the caller trusts -- just not all to the same thing.
  var paths = onlyPaths || ((res.fmt === "compound" && Array.isArray(res.compound))
    ? res.compound.filter(function (el) { return el.trustPath && el.trustPath.length; })
      .map(function (el) { return { tp: el.trustPath, at: el.chainValidatedAt }; })
    : (res.trustPath && res.trustPath.length ? [{ tp: res.trustPath, at: res.chainValidatedAt }] : []));
  // Coverage is ACCUMULATED across routes, not overwritten by whichever ran last. When
  // `onlyPaths` is given the metadata route already anchored the rest and recorded that here,
  // so reporting the fallback's own count would say 1 of 2 for a statement whose two elements
  // were both anchored -- one by the catalogue, one by the pin. A caller enforcing
  // `anchored === total` would then reject the mixed configuration this fallback exists to
  // support, and the verdict would understate the trust evaluation it actually performed.
  if (!onlyPaths) {
    res.anchoredElements = { total: (res.fmt === "compound" && Array.isArray(res.compound)) ? res.compound.length : 1,
      anchored: paths.length };
  }
  // `none` and a self-attestation carry no certificates, so there is nothing to
  // anchor -- and a caller who asked for anchoring is told it could not be applied
  // rather than handed a pass that looks like it was. Same rule the metadata route
  // states, for the same reason.
  if (!paths.length) {
    throw _err("webauthn/anchor-not-applicable",
      "opts.rootCertificates was supplied, but this attestation carries no trust path to anchor (format '" + res.fmt + "')");
  }
  var at = vopts.time !== undefined ? vopts.time : new Date();
  // EVERY path, not merely one: a compound's elements are independent claims, and
  // accepting the whole because one element anchored would let an unanchored element
  // ride along on its neighbour's trust.
  return paths.reduce(function (p, info) {
    return p.then(function () {
      var pathAt = vopts.time !== undefined ? vopts.time : (info.at || at);
      return mds.chainToAnchor(info.tp.slice().reverse(), roots, pathAt,
        "attestation trust path (against the roots supplied as opts.rootCertificates)");
    });
  }, Promise.resolve()).then(function () {
    res.anchoredTo = _anchoredRoutes(res, "rootCertificates");
    return res;
  });
}

// android-safetynet anchors through a route of its own. The verifier REQUIRES
// `opts.safetyNetRoots` (8.5) and refuses the statement unless the x5c chain validates to
// one of them, so by the time a verdict is composed that element's path HAS been anchored --
// without either `metadata` or `rootCertificates` being involved. Counting only those two
// routes reports `anchoredTo: null` over it, whose documented meaning is that nobody checked
// the path, so a caller enforcing `anchoredTo !== null` would refuse an attestation this
// library did in fact anchor. Every route that contributed is named.
function _safetyNetAnchored(res) {
  if (res.fmt === "android-safetynet") return 1;
  if (res.fmt === "compound" && Array.isArray(res.compound)) {
    return res.compound.filter(function (el) { return el && el.fmt === "android-safetynet"; }).length;
  }
  return 0;
}

// `base` is whichever of the two caller-selected routes ran, or null when neither did.
// Routes are named in a stable order so a caller may compare the string.
function _anchoredRoutes(res, base) {
  var routes = base ? base.split("+") : [];
  if (_safetyNetAnchored(res) && routes.indexOf("safetyNetRoots") < 0) routes.push("safetyNetRoots");
  return routes.length ? routes.join("+") : null;
}

// ---- ceremony binding (WebAuthn sec. 7.1 / 7.2) ------------------------------
//
// The attestation and assertion procedures verify a SIGNATURE. What makes a
// response acceptable is a separate set of checks the relying party owns, because
// only it knows what it asked for: the challenge it issued, the origin the browser
// reported, the RP ID it operates under, and the user-presence / user-verification
// policy it requires. A verifier that answers only the first question, under a name
// that sounds like the second, is the shape of every phishing-resistant login that
// turns out not to be -- an attestation naming ANOTHER RP, with user presence
// clear, is a perfectly sound statement about a credential the caller must not
// accept.
//
// So the checks this layer CAN make are offered here, opt-in, and every verdict
// reports which of them actually ran. The challenge and the origin stay with the
// caller: they live in clientDataJSON, which the caller already holds and compares
// against state only it has.
function _assertBool(v, name) {
  if (typeof v !== "boolean") throw _err("webauthn/bad-input", "opts." + name + " must be a boolean");
}

// Runs the bindings the caller asked for and reports EACH one's status: `true` it
// was checked and holds, `false` it was not asked for. A caller reading the verdict
// can therefore tell a check that passed from one that never ran -- the distinction
// the single `verified` boolean could not express.
function _applyBindings(authData, coseKey, opts) {
  var checked = { rpId: false, userPresence: false, userVerification: false, algorithm: false };
  if (opts.expectedRpId !== undefined) {
    if (typeof opts.expectedRpId !== "string" || !opts.expectedRpId.length) {
      throw _err("webauthn/bad-input", "opts.expectedRpId must be a non-empty RP ID string");
    }
    // Compared in constant time and by full value, like every other identity
    // comparison in this toolkit -- a prefix must not read as a match.
    if (!guard.crypto.constantTimeEqual(_sha("sha256", Buffer.from(opts.expectedRpId, "utf8")),
      Buffer.from(authData.rpIdHash))) {
      throw _err("webauthn/rp-id-mismatch",
        "the authenticatorData rpIdHash is not SHA-256 of opts.expectedRpId, so this response was " +
        "produced for a different relying party (WebAuthn sec. 7.1 step 13 / sec. 7.2 step 15)");
    }
    checked.rpId = true;
  }
  if (opts.requireUserPresence !== undefined) {
    _assertBool(opts.requireUserPresence, "requireUserPresence");
    if (opts.requireUserPresence && !authData.flags.up) {
      throw _err("webauthn/user-presence-required",
        "opts.requireUserPresence is set and the authenticatorData User Present (UP) flag is clear " +
        "(WebAuthn sec. 7.1 step 14 / sec. 7.2 step 16)");
    }
    checked.userPresence = opts.requireUserPresence;
  }
  if (opts.requireUserVerification !== undefined) {
    _assertBool(opts.requireUserVerification, "requireUserVerification");
    if (opts.requireUserVerification && !authData.flags.uv) {
      throw _err("webauthn/user-verification-required",
        "opts.requireUserVerification is set and the authenticatorData User Verified (UV) flag is clear " +
        "(WebAuthn sec. 7.1 step 15 / sec. 7.2 step 17)");
    }
    checked.userVerification = opts.requireUserVerification;
  }
  // COSE alg -65535 is RSASSA-PKCS1-v1_5 with SHA-1, and a credential key may name
  // it -- which would make SHA-1 the signature algorithm of every login that
  // credential ever performs. Refused unless the caller lists it, so supporting a
  // legacy authenticator is a decision someone wrote down rather than the default.
  // (This is the CREDENTIAL key's algorithm. A legacy TPM attestation STATEMENT
  // signed with RS1 is a different field and is still verified, since refusing it
  // would reject the authenticator's own evidence about itself.)
  var alg65535Allowed = Array.isArray(opts.allowedAlgorithms) && opts.allowedAlgorithms.indexOf(-65535) !== -1;
  if (coseKey && coseKey.alg === -65535 && !alg65535Allowed) {
    throw _err("webauthn/algorithm-not-allowed",
      "the credential public key declares COSE algorithm -65535 (RSASSA-PKCS1-v1_5 with SHA-1); every " +
      "signature made by this credential would use SHA-1, so it is refused unless opts.allowedAlgorithms " +
      "names -65535 explicitly");
  }
  // The rest of algorithm policy is the RP's, declared to the browser as
  // pubKeyCredParams, and nothing in the response proves what was offered -- so it
  // is checked only when the caller states the list.
  if (opts.allowedAlgorithms !== undefined) {
    if (!Array.isArray(opts.allowedAlgorithms) || !opts.allowedAlgorithms.length ||
        // isSafeInteger, not isInteger: a value above 2^53 is not held exactly as a
        // Number, so one written that way is not the identifier the caller meant --
        // and no COSE algorithm identifier lives out there anyway.
        !opts.allowedAlgorithms.every(function (a) { return typeof a === "number" && Number.isSafeInteger(a); })) {
      throw _err("webauthn/bad-input", "opts.allowedAlgorithms must be a non-empty array of COSE algorithm integers");
    }
    var alg = coseKey && coseKey.alg;
    if (opts.allowedAlgorithms.indexOf(alg) === -1) {
      throw _err("webauthn/algorithm-not-allowed",
        "the credential public key declares COSE algorithm " + alg + ", which is not in opts.allowedAlgorithms");
    }
    checked.algorithm = true;
  }
  return checked;
}

// One bound for every attestation certificate chain, wherever it arrives from -- an attStmt x5c
// array or a JWS x5c header. Capping the bytes of a single entry does not bound the COUNT, and the
// cost of an entry is a DER parse plus, downstream, a signature check or a path validation. Kept in
// one place so a new chain-bearing format cannot reintroduce the unbounded fanout.
function _requireX5cCount(n) {
  if (n > constants.LIMITS.WEBAUTHN_X5C_MAX_CERTS) {
    throw _err("webauthn/bad-att-stmt", "an attestation certificate chain carries " + n + " certificates, above the " + constants.LIMITS.WEBAUTHN_X5C_MAX_CERTS + " this toolkit will parse");
  }
}
function _readX5c(attStmt) {
  var x5cN = cbor.read.mapGet(attStmt, "x5c");
  if (!x5cN || x5cN.majorType !== 4 || !x5cN.children || !x5cN.children.length) throw _err("webauthn/bad-att-stmt", "x5c must be a non-empty array of certificates");
  _requireX5cCount(x5cN.children.length);
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
    var isX5c = !!cbor.read.mapGet(att.attStmt, "x5c");
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
  tpm: function (att, clientDataHash, opts) {
    // Config-time: a malformed or mistyped tpmPolicy is a caller error, caught before any parsing so
    // a typo cannot silently disable the check the caller believes they enabled.
    var tpmPolicy = validator.tpm.normalizeObjectAttributePolicy((opts || {}).tpmPolicy, WebauthnError, "webauthn/bad-input");
    _requireAttShape(att.attStmt, ["ver", "alg", "sig", "certInfo", "pubArea", "x5c"], ["ver", "alg", "sig", "certInfo", "pubArea", "x5c"]);
    var verN = cbor.read.mapGet(att.attStmt, "ver");
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
      // The TPMT_PUBLIC object attributes and authPolicy are properties of the credential key that
      // sec. 8.3 does not constrain -- it bounds only pubArea's `parameters` and `unique`. They are
      // surfaced for relying-party policy, and gated only when the caller supplies opts.tpmPolicy.
      // Applied AFTER the signature and Name checks, so the bytes being judged are ones the AIK
      // signature already covers rather than attacker-chosen input.
      validator.tpm.assertObjectAttributePolicy(pub, tpmPolicy, WebauthnError, "webauthn/tpm-policy", "webauthn/bad-tpm");
      var tpmRes = _result("tpm", "AttCA", chain, att);
      tpmRes.tpm = { objectAttributes: pub.objectAttributes, attributes: pub.attributes, authPolicy: pub.authPolicy };
      return tpmRes;
    });
  },

  // android-safetynet (WebAuthn 8.5): the attStmt carries a SafetyNet JWS ("response") whose payload
  // binds a nonce to this registration and whose x5c header chains to a Google root.
  //
  // OFF BY DEFAULT, and anchored only by the caller. Google retired the SafetyNet Attestation API, so
  // nothing mints these any more -- the surviving use is a relying party re-checking attestations it
  // stored years ago. Enabling a format whose producer is gone, against a root this library chose,
  // would widen what every caller trusts for no live benefit; so the caller opts in AND supplies the
  // root. With the opt off the verdict is byte-identical to the one this format had before the arm
  // existed. There is no bundled root and no trust-on-first-use.
  "android-safetynet": function (att, clientDataHash, opts) {
    opts = opts || {};
    // The type is settled at the entry point, so what remains here is the opt-in itself.
    if (opts.verifySafetyNetJws !== true) {
      throw _err("webauthn/unsupported-format", "attestation statement format 'android-safetynet' is not supported");
    }
    var roots = opts.safetyNetRoots;
    if (!Array.isArray(roots) || roots.length === 0) {
      throw _err("webauthn/safetynet-no-root", "verifying an android-safetynet attestation requires opts.safetyNetRoots -- the Google root(s) to anchor the x5c chain to; this library bundles none (WebAuthn 8.5)");
    }
    // The guard rejects through a (code, message) FACTORY. Handing it the error CLASS makes the
    // reject path raise "class constructor cannot be invoked without new" -- a raw, untyped throw
    // escaping a public verb, on the branch a valid-input test never takes.
    if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");

    // 8.5 attStmt syntax: safetynetStmtFormat = { ver: text, response: bytes }. `ver` is READ but
    // never gated on -- 8.5 states it is reserved for future use.
    _requireAttShape(att.attStmt, ["ver", "response"], ["ver", "response"]);
    _attRead(att.attStmt, "ver", cbor.read.textString, "a text string");
    var responseBytes = _attRead(att.attStmt, "response", cbor.read.byteString, "a byte string");
    if (!responseBytes.length) throw _err("webauthn/bad-att-stmt", "the android-safetynet response is empty");

    // RFC 7515 sec. 3.1 Compact Serialization: exactly three base64url segments.
    var segs = guard.text.decode(responseBytes, constants.LIMITS.SAFETYNET_JWS_MAX_BYTES, WebauthnError, "webauthn/bad-att-stmt", "the android-safetynet response").split(".");
    if (segs.length !== 3) throw _err("webauthn/bad-att-stmt", "the android-safetynet response is not a three-part JWS compact serialization (RFC 7515 sec. 3.1)");
    var header, payload, sigBytes;
    try {
      header = jose.parseJson(jose.base64url.decode(segs[0]));
      payload = jose.parseJson(jose.base64url.decode(segs[1]));
      sigBytes = Buffer.from(jose.base64url.decode(segs[2]));
    } catch (e) { throw _err("webauthn/bad-att-stmt", "the android-safetynet response is not a decodable JWS", e); }
    // A JWS segment must decode to a JSON OBJECT. `null`, a number, a string and an array are all
    // valid JSON, so the parse succeeds and every later field read would be a raw TypeError escaping
    // this module's typed contract -- the caller's error handling would never see a webauthn/* code.
    if (!_isPlainObject(header) || !_isPlainObject(payload)) {
      throw _err("webauthn/bad-att-stmt", "the android-safetynet JWS header and payload must each be a JSON object");
    }

    // Pin the algorithm rather than reading it from the token: an attacker-chosen alg is the JWS
    // algorithm-confusion class, and SafetyNet only ever signed RS256.
    if (header.alg !== "RS256") throw _err("webauthn/unsupported-algorithm", "the android-safetynet JWS alg must be RS256, got " + JSON.stringify(header.alg));
    if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
      throw _err("webauthn/bad-att-stmt", "the android-safetynet JWS header carries no x5c certificate chain (RFC 7515 sec. 4.1.6)");
    }
    _requireX5cCount(header.x5c.length);
    // x5c entries are STANDARD base64 (RFC 7515 sec. 4.1.6), not base64url like the segments.
    var chain = header.x5c.map(function (entry, i) {
      if (typeof entry !== "string") throw _err("webauthn/bad-att-stmt", "the android-safetynet x5c entry " + i + " is not a string");
      var der;
      try { der = guard.encoding.base64(entry, constants.LIMITS.SAFETYNET_CERT_MAX_BYTES, WebauthnError, "webauthn/bad-att-stmt", "an android-safetynet x5c entry"); }
      catch (e) { throw _err("webauthn/bad-att-stmt", "the android-safetynet x5c entry " + i + " is not canonical base64", e); }
      try { return x509.parse(der); }
      catch (e) { throw _err("webauthn/bad-att-cert", "the android-safetynet x5c entry " + i + " is not a decodable certificate", e); }
    });
    var leaf = chain[0];

    // 8.5 bullet 3: nonce == STANDARD Base64 of SHA-256(authenticatorData || clientDataHash). Note
    // standard base64 (+/=), NOT base64url -- and the digest is over the raw concatenation.
    var wantNonce = _sha("sha256", Buffer.concat([att.authDataBytes, clientDataHash])).toString("base64");
    if (typeof payload.nonce !== "string" || !guard.crypto.constantTimeEqual(Buffer.from(payload.nonce, "utf8"), Buffer.from(wantNonce, "utf8"))) {
      throw _err("webauthn/safetynet-nonce-mismatch", "the android-safetynet nonce does not bind this authenticatorData and clientDataHash (WebAuthn 8.5)");
    }

    // 8.5 bullet 4 (via the SafetyNet documentation): the response must come from the SafetyNet
    // service, which is established by the leaf being issued to attest.android.com AND the chain
    // validating to a Google root. The hostname alone proves nothing until the chain is anchored.
    if (!_safetyNetHostnameOk(leaf)) {
      throw _err("webauthn/safetynet-bad-hostname", "the android-safetynet x5c leaf is not issued to attest.android.com (WebAuthn 8.5)");
    }

    // The device-integrity signals are NOT part of the 8.5 verification procedure -- its five bullets
    // never mention them -- so gating the attestation verdict on them would invent a requirement the
    // specification does not state. They are relying-party policy, so they are surfaced on the result
    // for a caller to act on, and enforced here only when the caller explicitly asks. A caller that
    // asks and finds them missing or false gets a refusal, never a silent pass.
    // The instant the service chain is judged at, resolved below once the signature has authenticated
    // the timestamp it comes from, and carried out on the result so a later check of the same path
    // uses the same one rather than resetting to the current clock.
    var chainAt;
    var signals = {
      ctsProfileMatch: payload.ctsProfileMatch, basicIntegrity: payload.basicIntegrity,
      timestampMs: payload.timestampMs, apkPackageName: payload.apkPackageName,
      apkCertificateDigestSha256: payload.apkCertificateDigestSha256, advice: payload.advice,
    };
    if (opts.requireCtsProfileMatch === true && signals.ctsProfileMatch !== true) {
      throw _err("webauthn/safetynet-cts-profile", "the android-safetynet response reports ctsProfileMatch " + JSON.stringify(signals.ctsProfileMatch) + ", and opts.requireCtsProfileMatch demands true");
    }

    return _verifySig(-257, sigBytes, leaf.subjectPublicKeyInfo.bytes,
      Buffer.from(segs[0] + "." + segs[1], "ascii"), _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the android-safetynet JWS signature does not verify under the x5c leaf key");
      // WHEN to judge the chain. These attestations are historical by construction -- the service is
      // retired -- so a leaf that was valid when the response was signed is routinely expired now,
      // and judging it against the current clock would refuse every genuine stored registration.
      // The response carries its own signing time, and by this point that value is covered by the
      // signature just verified under the leaf, so it is authenticated rather than caller-asserted.
      // Precedence: an explicit opts.time (the caller knows when the registration happened) beats
      // the signed timestamp, which beats now (a response that carries no usable timestamp).
      chainAt = opts.time !== undefined ? opts.time
        : (typeof payload.timestampMs === "number" && isFinite(payload.timestampMs) && payload.timestampMs > 0
          ? new Date(payload.timestampMs) : undefined);
      return _safetyNetChainTrusted(chain, roots, chainAt);
    }).then(function () {
      // 8.5 bullet 5: attestation type Basic, trust path x5c.
      var res = _result("android-safetynet", "Basic", chain, att);
      res.safetyNet = signals;
      // The instant this chain was judged at, surfaced so any later check of the SAME path uses the
      // same one. A stored response's service chain has usually expired by now, and re-validating
      // it against the current clock would refuse a registration that was valid when it was made.
      if (chainAt !== undefined) res.chainValidatedAt = chainAt;
      return res;
    });
  },

  // compound (WebAuthn 8.9): the attStmt is an ARRAY of nested attestation statements, each
  // verified over the SAME authenticatorData and clientDataHash as the outer object. sec. 8.9
  // leaves the acceptance threshold to relying-party policy ("if validation fails for one or more
  // subStmt, decide the appropriate result based on RP policy"); this toolkit's policy is
  // fail-closed -- EVERY element must verify, because accepting a compound whose strong element
  // failed and whose `none` element passed would let a wrapper launder a failed attestation.
  compound: function (att, clientDataHash, opts) {
    var kids = att.attStmt.children || [];
    // sec. 8.9 syntax `2*`: at least two nested statements, or it is not a compound.
    if (kids.length < 2) throw _err("webauthn/bad-att-stmt", "a compound attestation statement must carry at least two nested statements (WebAuthn 8.9)");
    // Not a spec rule: a resource bound this toolkit chooses. The CBOR caps bound the PARSE; they
    // do not bound the crypto, and each element costs a signature verify plus, for some formats, a
    // certificate-chain path validation.
    if (kids.length > constants.LIMITS.WEBAUTHN_COMPOUND_MAX_STATEMENTS) {
      throw _err("webauthn/bad-att-stmt", "a compound attestation statement carries " + kids.length + " nested statements, above the " + constants.LIMITS.WEBAUTHN_COMPOUND_MAX_STATEMENTS + " this toolkit will verify");
    }
    var elements = kids.map(function (el, i) {
      // sec. 8.9: nonCompoundAttStmt = { $$attStmtType } -- each element is exactly { fmt, attStmt }.
      if (!el || el.majorType !== 5) throw _err("webauthn/bad-att-stmt", "compound element " + i + " must be a CBOR map { fmt, attStmt } (WebAuthn 8.9)");
      var fN = cbor.read.mapGet(el, "fmt"), sN = cbor.read.mapGet(el, "attStmt");
      if (el.children.length !== 2 || !fN || !sN) throw _err("webauthn/bad-att-stmt", "compound element " + i + " must be exactly { fmt, attStmt } (WebAuthn 8.9)");
      if (fN.majorType !== 3) throw _err("webauthn/bad-att-stmt", "compound element " + i + " 'fmt' must be a text string");
      var f = cbor.read.textString(fN);
      // sec. 8.9 spells the element type `.ne "compound"`: nesting is forbidden by the syntax
      // itself, which is what fixes the evaluation depth at one. No depth parameter is needed --
      // and adding one would imply a nesting this format does not have.
      if (f === "compound") throw _err("webauthn/bad-att-stmt", "a compound attestation statement must not nest another compound (WebAuthn 8.9)");
      // sec. 8.1: identifiers match case-sensitively, which the registry lookup already is.
      var v = VERIFIERS[f];
      if (!v) throw _err("webauthn/unsupported-format", "compound element " + i + " uses unsupported attestation statement format '" + f + "'");
      var wantMajor = ATT_STMT_MAJOR[f] === undefined ? 5 : ATT_STMT_MAJOR[f];
      if (sN.majorType !== wantMajor) throw _err("webauthn/bad-att-stmt", "compound element " + i + " 'attStmt' has the wrong CBOR shape for format '" + f + "'");
      // Each element verifies against the OUTER authenticatorData: sec. 8.9 passes the same
      // verification-procedure inputs down, so an element cannot bind a different credential.
      return { fmt: f, index: i, att: { fmt: f, attStmt: sN, authData: att.authData, authDataBytes: att.authDataBytes } };
    });
    // Sequential, not Promise.all: a compound may hold many elements, and each can cost a
    // signature verify plus a full path validation. Fanning them out concurrently would turn one
    // attestation into a burst of crypto work.
    var out = [];
    return elements.reduce(function (p, e) {
      return p.then(function () {
        // The verifier is CALLED inside the promise chain, not evaluated as an argument to
        // Promise.resolve: most arms do their structural checks synchronously, so an argument-
        // position call would let those throws escape the handler below and reach the caller
        // bare -- the same failure reported with the element's context or without it, depending
        // only on whether it happened before or after the first await.
        return Promise.resolve().then(function () { return VERIFIERS[e.fmt](e.att, clientDataHash, opts); })
          .then(function (r) { out.push(r); }, function (err) {
            throw _err("webauthn/compound-element-failed", "compound element " + e.index + " (format '" + e.fmt + "') did not verify", err);
          });
      });
    }, Promise.resolve()).then(function () {
      // sec. 8.9 lists the supported attestation type as "Any" and authorises returning
      // "implementation-specific values representing any combination of outputs". A distinct type
      // rather than a merge: collapsing to the strongest element would let a wrapper upgrade a
      // caller's attestationType check, and collapsing to the weakest would spuriously fail one.
      // The trust path is empty because two elements yield two independent chains and there is no
      // single ordered path -- each element's own path is on its entry in `compound`.
      var res = _result("compound", "Compound", [], att);
      res.compound = out;
      return res;
    });
  },

  // none (WebAuthn 8.7): the authenticator provides no attestation. attStmt MUST be
  // an empty map; there is no statement to verify, so the result carries no trust
  // path. The credential public key still binds via authenticatorData (AT flag).
  none: function (att) {
    // parseAttestationObject has already established attStmt is a CBOR map; the none format
    // additionally requires it be EMPTY -- there is no statement to verify (WebAuthn 8.7).
    if (att.attStmt.children.length !== 0) {
      throw _err("webauthn/bad-att-stmt", "the none attestation statement MUST be an empty map (WebAuthn 8.7)");
    }
    return Promise.resolve(_result("none", "None", [], att));
  },
};

// A decoded JSON value that is safe to read named members off. JSON.parse yields null, numbers,
// strings and arrays too, and a member read on any of those would leave this module's typed error
// contract as a raw TypeError.
function _isPlainObject(v) { return !!v && typeof v === "object" && !Array.isArray(v); }

// WebAuthn 8.5 (via the SafetyNet documentation): the JWS leaf is issued to attest.android.com.
// Checked on the SAN dNSName entries first -- the name a TLS-style certificate is actually issued
// to -- falling back to the commonName only when the certificate carries no SAN at all, the way a
// hostname match has been specified since RFC 6125. Compared case-insensitively (a DNS name is
// case-insensitive) and exactly: no wildcard, no suffix match, so attest.android.com.evil.test
// cannot pass.
function _safetyNetHostnameOk(leaf) {
  var want = "attest.android.com";
  // Decoded through the SAME shared pkix extension decoder every other format here uses, so the
  // general-name parse cannot drift from the rest of the toolkit.
  var san = _decodeExt(leaf, "subjectAltName");
  var entries = san && Array.isArray(san.value) ? san.value : [];
  var dns = entries.filter(function (gn) { return gn && gn.type === "dNSName" && typeof gn.value === "string"; });
  // A SAN carrying dNSName entries is authoritative: the commonName is not consulted at all.
  if (dns.length) return dns.some(function (gn) { return gn.value.toLowerCase() === want; });
  // rdns is a sequence of RDNs, each a set of attribute/value pairs -- hence the nested walk.
  return leaf.subject.rdns.some(function (rdn) {
    return rdn.some(function (atv) {
      return atv.name === "commonName" && typeof atv.value === "string" && atv.value.toLowerCase() === want;
    });
  });
}

// WebAuthn 8.5 (via the SafetyNet documentation): the x5c chain must validate to a Google root the
// CALLER supplied. Every anchor is tried because a caller may hold several Google roots across a
// rotation; the first that validates wins, and if none does the attestation is refused. The chain
// goes through the full path validator rather than a signature-only walk, so an expired, revoked-by-
// policy, or otherwise non-conforming intermediate cannot slip past on a signature alone.
// The caller's roots are the only thing this function owns: their SHAPE is its own config-time
// contract, so a root that is not a decodable certificate is named by its index here. Anchoring
// itself is the namespace's one walk (webauthn-mds), which every other chain in this module already
// reaches its anchors through -- including the anchor-stripping rule, which this had a slightly
// different and weaker copy of. Each root is resolved BEFORE the walk starts, so a malformed entry
// is a config fault whatever position it sits in, rather than one that only surfaces when the roots
// before it happen to fail.
function _safetyNetChainTrusted(chain, roots, time) {
  var anchors;
  try {
    anchors = roots.map(function (root, i) {
      var anchorCert;
      try { anchorCert = Buffer.isBuffer(root) || typeof root === "string" ? x509.parse(root) : root; }
      catch (e) { throw _err("webauthn/bad-input", "opts.safetyNetRoots[" + i + "] is not a decodable certificate", e); }
      if (!anchorCert || !anchorCert.subject || !anchorCert.subjectPublicKeyInfo) {
        throw _err("webauthn/bad-input", "opts.safetyNetRoots[" + i + "] is not a certificate");
      }
      return anchorCert;
    });
  } catch (e) { return Promise.reject(e); }
  return mds.chainToAnchor(chain, anchors, time === undefined ? new Date() : time,
    "android-safetynet x5c certificate chain", "webauthn/safetynet-cert-untrusted");
}

// `chain` is the x5c order (leaf-first); trustPath is surfaced in pki.path.validate
// order (anchor-adjacent first, target/leaf last) so the caller passes it straight
// to the path validator without re-ordering. The input array is not mutated.
// `attestationVerified`, not `verified`: this says the attestation STATEMENT is
// sound, which is not the same claim as "this registration is acceptable". The
// ceremony bindings the caller may also have asked for are reported separately, in
// `bindingChecked`, so a field that passed can be told from one that never ran.
// It also carries everything a relying party must STORE to finish registration and
// run a later login: the credentialId it will look the credential up by, the
// credential public key that will verify assertions, and the signCount that is the
// starting point for the sec. 7.2 step 21 counter rule. Leaving those out sent the
// caller back to parse the attestation object a second time for values this call
// had already decoded -- and a login cannot be verified without them.
function _result(fmt, attestationType, chain, att) {
  return {
    attestationVerified: true, fmt: fmt, attestationType: attestationType,
    trustPath: (chain || []).slice().reverse(),
    aaguid: att.authData.aaguid,
    credentialId: att.authData.credentialId,
    credentialPublicKey: att.authData.credentialPublicKey,
    // The same key in the form that SURVIVES STORAGE. The decoded object carries Buffers, so a JSON
    // round trip through a datastore returns {"type":"Buffer","data":[...]} rather than what went
    // in; the COSE bytes are what a credential row actually holds. Returning only the object left
    // the caller re-parsing the attestation object to recover bytes this call had already isolated.
    credentialPublicKeyBytes: att.authData.credentialPublicKeyBytes,
    signCount: att.authData.signCount,
    flags: att.authData.flags,
    // The RP ID hash and the authenticator extension outputs, for the same reason the key bytes
    // above are here: this call decoded them and the caller needs them. Extension outputs arrive
    // at REGISTRATION and nowhere else -- credProtect (whether this credential is
    // user-verification-required for the rest of its life), credProps.rk (whether it is
    // discoverable), credBlob, minPinLength, hmac-secret/prf -- so a relying party that must
    // persist them had to re-parse the attestation object to read values already in hand.
    // `verifyAssertion` returns both; the registration verdict returning less made the two halves
    // of one lifecycle disagree about what they hand back.
    rpIdHash: att.authData.rpIdHash,
    extensions: att.authData.extensions,
  };
}

// Decode the Apple extension AppleAnonymousAttestation ::= SEQUENCE { nonce [1]
// EXPLICIT OCTET STRING } (WebAuthn 8.8 item 29) and return the 32-byte nonce.
function _appleNonce(extValue) {
  var seq;
  try { seq = asn1.decode(extValue); } catch (e) { throw _err("webauthn/bad-att-cert", "the apple attestation extension is not decodable", e); }
  // ARITY IS PART OF THE DECLARED SHAPE. Reading the first child and ignoring the rest
  // accepts a certificate carrying a second, unchecked value beside the nonce -- and this
  // extension exists precisely to carry the value the attestation binds to, so an
  // ambiguous encoding of it is not a shape this verifier gets to pick a reading from.
  // The type is one SEQUENCE of exactly one field, and the EXPLICIT wrapper holds exactly
  // one value; anything else is refused rather than partially read.
  var isSeq = seq.tagClass === "universal" && seq.tagNumber === asn1.TAGS.SEQUENCE;
  if (!isSeq || !seq.children || seq.children.length !== 1) {
    throw _err("webauthn/bad-att-cert", "the apple attestation extension is not SEQUENCE { [1] OCTET STRING } (expected exactly one field)");
  }
  var tagged = seq.children[0];
  if (!tagged || tagged.tagClass !== "context" || tagged.tagNumber !== 1 || !tagged.children || tagged.children.length !== 1) {
    throw _err("webauthn/bad-att-cert", "the apple attestation extension is not SEQUENCE { [1] OCTET STRING } (expected one EXPLICIT [1] value)");
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
 * @signature pki.webauthn.verify(attestationObject, clientDataHash?, opts?) -> Promise<{ attestationVerified, fmt, attestationType, trustPath, anchoredTo, aaguid, credentialId, credentialPublicKey, credentialPublicKeyBytes, signCount, flags, rpIdHash, extensions, bindingChecked, clientData }>
 * @since 0.2.5
 * @status stable
 * @spec W3C WebAuthn Level 3 sec. 8 / sec. 7.1
 * @related pki.webauthn.parseAttestationObject, pki.webauthn.parseClientData, pki.webauthn.verifyAssertion
 *
 * Verify a WebAuthn attestation statement: the attestation signature over
 * `authenticatorData || clientDataHash` and (for the x5c formats) the format's
 * certificate requirements. Resolves the attestation type + trust path or
 * throws a typed `webauthn/*` error; a signature that does not verify is a
 * `webauthn/verify-failed` verdict, never a silent pass.
 *
 * Give it the client data in exactly one of the two forms, neither inferred from the
 * other's absence: the raw `opts.clientDataJSON`, or the SHA-256 digest of it as the
 * second argument. Given the JSON, this reads it -- the ceremony TYPE is checked
 * unconditionally, because which ceremony a response belongs to is fixed by the
 * specification rather than chosen by a caller, and a login response replayed into a
 * registration is exactly what that check stops. The challenge, origin and top-level
 * origin are checked when you supply what you issued, and `clientData.checked` reports
 * which ran. Given only the digest, nothing reads it and `clientData` is null.
 *
 * The verdict field is `attestationVerified`, and the name is the point: a sound
 * attestation statement is not the same claim as an acceptable registration. The
 * statement says nothing about WHICH relying party asked for it, or whether a user
 * was present -- so an attestation naming another origin's RP ID, with user presence
 * clear, is perfectly sound and must not be registered. Supply `expectedRpId`,
 * `requireUserPresence`, `requireUserVerification` and `allowedAlgorithms` and those
 * are checked here; `bindingChecked` reports which ran, so a check that passed can be
 * told from one that never happened.
 *
 * Four more fields appear only where they mean something, rather than as nulls on every
 * verdict: `metadata` when the catalogue governed, `anchoredElements` when a trust path
 * was anchored, `compound` for a sec. 8.9 statement's per-element results, and
 * `safetyNet` with `chainValidatedAt` for an android-safetynet response.
 *
 * The verdict also carries what a relying party must STORE to run a later login:
 * `credentialId`, `credentialPublicKey` and the initial `signCount`. The credential key
 * comes back in both forms: the decoded object, and `credentialPublicKeyBytes`, which is
 * what a credential row should hold -- the object carries `Buffer` values, so a JSON round
 * trip through a datastore returns `{"type":"Buffer","data":[...]}` rather than the object
 * that went in. `pki.webauthn.parseCoseKey` reads those bytes back, and
 * `verifyAssertion` accepts either form.
 *
 * @intro This verifies the attestation STATEMENT -- the signature and the format's
 *   structural bindings (the x5c leaf key == credential key, the apple nonce, the tpm
 *   certInfo Name/extraData, the android KeyDescription, the fido-u2f verificationData).
 *   Chaining the returned `trustPath` (the x5c certificates in `pki.path.validate`
 *   order -- anchor-adjacent first, leaf last) to a trusted root is a separate step,
 *   and there are three ways to take it. Pass `opts.metadata` -- a
 *   `pki.webauthn.verifyMetadataBlob` result -- and the authenticator's registered
 *   attestation roots are resolved from its own identifier and the trust path is
 *   required to reach one, so an unlisted or revoked model is refused rather than
 *   reported as verified. Pass `opts.rootCertificates` and the path is required to
 *   validate to a root you pin: this is what anchors the formats the catalogue does
 *   not cover, since Apple does not publish its authenticators to the FIDO Metadata
 *   Service and the Google hardware-attestation roots come from Google. Or anchor
 *   `trustPath` yourself with `pki.path.validate`. Supplying both options is the
 *   ordinary configuration for a relying party that accepts MDS-listed authenticators
 *   AND Apple; `metadata` governs when present, because a model's own registered
 *   roots are a stronger claim than a static pin and its status reports can
 *   disqualify a model those roots would still accept. `anchoredTo` reports which
 *   route ran, naming every route that contributed and joining them with `+` when more
 *   than one did -- `"metadata"`, `"rootCertificates"`, and `"safetyNetRoots"` for the
 *   android-safetynet chain, which anchors through the roots that format requires whether
 *   or not either other route was asked for. It is `null` only when nothing anchored the
 *   path. On the mixed metadata/pinned-root route `metadata` still carries the
 *   entries that governed, so the stronger half of the decision stays auditable rather
 *   than being flattened into the pinned-root half. `anchoredElements` reports how much of the
 *   statement it covered. That matters for a compound attestation (sec. 8.9), whose
 *   elements are independent claims: an element carrying no certificates makes no
 *   claim there is anything to anchor, so it is not a reason to refuse the statement,
 *   but it does mean "anchored" covered fewer elements than the statement holds.
 *
 * @opts
 *   clientDataJSON    -- the RAW clientDataJSON bytes; supply this OR the digest argument
 *   expectedChallenge -- the challenge bytes this ceremony issued (needs clientDataJSON)
 *   expectedOrigin    -- the origin string, or an array of acceptable origins
 *   expectedTopOrigin -- the acceptable top-level origin(s), or null to require an
 *                        unframed ceremony
 *   expectedRpId      -- the RP ID whose SHA-256 the authenticatorData must carry
 *   requireUserPresence / requireUserVerification -- the flags this registration requires
 *   allowedAlgorithms -- the COSE algorithms this relying party accepts
 *   metadata          -- a verifyMetadataBlob result; the model's own roots govern
 *   rootCertificates  -- trust anchors you pin, for the models no catalogue lists
 *   time              -- the instant certificate validity is judged at
 *   tpmPolicy         -- required TPM key properties; refuses a non-TPM attestation
 *   safetyNetRoots / verifySafetyNetJws / requireCtsProfileMatch -- the
 *                        android-safetynet opt-in, its Google roots, and the
 *                        device-integrity demand
 *
 * @example
 *   // requires: `attestationObject` and `clientDataJSON` from
 *   // navigator.credentials.create(), and `issuedChallenge` -- the bytes you sent
 *   var res = await pki.webauthn.verify(attestationObject, {
 *     clientDataJSON: clientDataJSON,
 *     expectedChallenge: issuedChallenge,
 *     expectedOrigin: "https://example.com",
 *     expectedRpId: "example.com", requireUserPresence: true,
 *   });
 *   res.attestationVerified;      // true (statement signature + bindings hold)
 *   res.clientData.checked.type;  // true -- this really is a registration response
 *   res.bindingChecked.rpId;      // true -- this response names example.com
 *   res.attestationType;          // "Basic"
 *   // store res.credentialId / res.credentialPublicKeyBytes / res.signCount for logins,
 *   // and anchor res.trustPath to your pinned roots with pki.path.validate
 */
function verify(attestationObject, clientDataHash, opts) {
  // Two call shapes, disjoint by shape so neither is guessed at: the digest positionally, or an
  // options object carrying the clientDataJSON it is computed from. A Buffer IS an object, so the
  // question has to be asked as "is this not bytes?" -- the disjointness is between a BufferSource
  // and everything else, and testing only the second half swallows the ordinary two-argument call.
  if (opts === undefined && clientDataHash !== undefined &&
      !_isBufferSource(clientDataHash) && _isPlainObject(clientDataHash)) {
    opts = clientDataHash; clientDataHash = undefined;
  }
  opts = opts || {};
  // Every option here either GATES the verdict or supplies the trust material a gate needs, so a
  // misspelled key is not a harmless no-op: `metdata` leaves the metadata gate switched off and the
  // call returns a pass the caller believes was checked against the catalogue. Reject an
  // unrecognised key at the boundary, and validate the one shared option every arm reads, so a bad
  // instant is a config fault here rather than a trust failure reported from deep inside a chain.
  try {
    if (!_isPlainObject(opts)) throw _err("webauthn/bad-input", "opts must be an object");
    guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "webauthn/bad-input", "opts has an unknown key ");
    // ONE read of the caller's object, HERE, and nothing below ever touches it again. Not a
    // precaution about mutation across the deferred verification -- that was already the reason for
    // the copy this replaces -- but about the reads themselves: a gate that reads `opts.x` to decide
    // whether a demand was made, and a later step that reads `opts.x` again to act on it, are two
    // reads of a value the caller still owns, and an accessor makes them disagree. The value that
    // was CHECKED must be the value that is USED, which means checking and using the same copy.
    // `Object.assign` takes every own enumerable field by value at this instant, which resolves any
    // accessor exactly once.
    opts = Object.assign({}, opts);
    if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");
    // The boolean switches are typed HERE rather than in the arm that reads them. Validated only
    // inside the android-safetynet arm, `requireCtsProfileMatch: "true"` reaching any other format
    // is never examined at all -- a truthy string that demands nothing, silently accepted. A
    // recognised key with an unusable value is the same class of caller mistake as an unrecognised
    // key, and belongs at the same boundary.
    _FORMAT_SCOPED_BOOLEAN_OPTS.forEach(function (k) {
      if (opts[k] !== undefined && typeof opts[k] !== "boolean") throw _err("webauthn/bad-input", "opts." + k + " must be a boolean");
    });
  } catch (e) { return Promise.reject(e); }
  var att;
  // Both byte inputs are snapshotted BEFORE anything reads them, for the same reason the trust
  // anchors are: the attestation statement is not evaluated until a later promise turn, and both
  // stay caller-owned across that gap. The attestation object is copied before it is parsed, not
  // after, because the parse surfaces its byte fields as VIEWS -- the authenticator data the
  // signature covers, the statement, the credential key -- so copying afterwards would leave every
  // one of them pointing at bytes the caller can still rewrite. The clientDataHash is what binds
  // the statement to this ceremony; a caller who overwrote it in that gap would have the signature
  // checked against a challenge and origin nobody agreed to, and the verdict would still report a
  // sound attestation. A DataView or ArrayBuffer comes in by the same door and is copied too.
  var attBytes, cdh, clientData = null;
  try {
    attBytes = _bytesArg(attestationObject, "attestationObject");
    // The two forms of the same input, and NEITHER is inferred from the other's absence -- the
    // same rule verifyAssertion applies, because it is the same question. Supplying both invites
    // them to disagree, and picking one would make the attestation cover something the caller did
    // not mean.
    var haveJson = opts.clientDataJSON !== undefined, haveHash = clientDataHash !== undefined;
    if (haveJson === haveHash) {
      throw _err("webauthn/bad-input", "verify takes exactly one of clientDataJSON or the clientDataHash argument");
    }
    if (haveJson) {
      // The bytes are taken ONCE and both the reading and the hashing use that copy. Checking one
      // value and hashing another would bind the attestation to client data the ceremony checks
      // never saw -- the check and the use have to be of the same bytes.
      var cdjBytes = _bytesArg(opts.clientDataJSON, "opts.clientDataJSON");
      // Given the JSON, the ceremony TYPE is checked unconditionally. Which ceremony a response
      // belongs to is fixed by the specification rather than chosen by the caller, and a login
      // response replayed into a registration is exactly what that check stops -- so registration
      // gets the same non-negotiable rule the login path already had. Without this door there was
      // no way to apply it at registration at all: the hash is opaque, and the caller was left to
      // compare a value the attestation never bound.
      clientData = parseClientData(cdjBytes, {
        expectedType: "webauthn.create",
        expectedChallenge: opts.expectedChallenge,
        expectedOrigin: opts.expectedOrigin,
        expectedTopOrigin: opts.expectedTopOrigin,
      });
      cdh = _sha("sha256", cdjBytes);
    } else {
      // Every expectation the clientData reader would have answered is unanswerable from a bare
      // digest, so each is refused rather than left silently uncompared.
      if (opts.expectedChallenge !== undefined || opts.expectedOrigin !== undefined ||
          opts.expectedTopOrigin !== undefined) {
        throw _err("webauthn/bad-input",
          "expectedChallenge / expectedOrigin / expectedTopOrigin are checked against clientDataJSON, which this call " +
          "did not supply -- pass opts.clientDataJSON instead of the clientDataHash argument, or check them yourself");
      }
      cdh = _bytesArg(clientDataHash, "clientDataHash");
      // The LENGTH is checked on the normalized copy, so the digest is 32 bytes whichever form it
      // arrived in -- not only when it arrived as a Buffer.
      if (cdh.length !== 32) throw _err("webauthn/bad-input", "clientDataHash must be a 32-byte SHA-256 digest");
    }
  } catch (e) { return Promise.reject(e); }
  attestationObject = attBytes;
  clientDataHash = cdh;
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
  // A policy about TPM key properties is checked INSIDE the tpm arm, so an attestation in any other
  // format would never reach it and the policy would silently apply to nothing -- a caller who
  // demanded a TPM-bound key would accept a `none` attestation instead. The requirement therefore
  // belongs at the dispatch, where it can refuse a format that cannot satisfy it, not in the arm
  // that only runs once that format was already chosen.
  if (opts.tpmPolicy !== undefined && !_formatCarries(att, "tpm")) {
    return Promise.reject(_err("webauthn/tpm-policy", "opts.tpmPolicy requires a TPM attestation, but this attestation is format '" + att.fmt + "', which carries no TPM public area"));
  }
  // The same rule, and the same reason, for the one other option that DEMANDS rather than supplies:
  // ctsProfileMatch is an android-safetynet device-integrity signal, so no other format's statement
  // carries one to test. Checked only inside that arm, a caller who demanded a CTS-matching device
  // would get a pass from a `packed` or `none` attestation that was never asked the question.
  // A caller who passes `false` demands nothing and is not refused.
  if (opts.requireCtsProfileMatch === true && !_formatCarries(att, "android-safetynet")) {
    return Promise.reject(_err("webauthn/safetynet-cts-profile", "opts.requireCtsProfileMatch requires an android-safetynet attestation, but this attestation is format '" + att.fmt + "', whose statement carries no device-integrity signals"));
  }
  // The ceremony bindings run BEFORE the statement is evaluated: a response
  // produced for another relying party, or without the user presence the caller
  // requires, is not a message this call should spend a signature verification on
  // -- and refusing it early keeps the "acceptable" question ahead of the "sound"
  // one, which is the order sec. 7.1 puts them in.
  // ONE normalized options object, built synchronously here. Nothing past this point reads
  // the caller's `opts` again -- not the values, and not the presence tests that pick which
  // trust policy runs.
  //
  // Fixing this per-field does not converge. The verifier resolves in a later turn, so every
  // field the deferred path touches stays caller-owned across that gap, and each repair that
  // snapshotted one more field left the next one aliased: the roots, then the safetynet
  // roots, then the routing test beside them, then the metadata routing test, then the
  // validation instant. They are not separate bugs, they are one window, and the way to
  // close a window is to stop reading through it rather than to copy one more thing across.
  //
  // `Object.assign` captures every own field by value at this instant, which fixes both the
  // values and the `!== undefined` presence tests derived from them. The two root arrays get
  // a deeper copy because their CONTENTS are caller-owned too. `metadata` is captured by
  // reference: a verified catalogue can hold thousands of entries and copying it per
  // registration is a real cost, so reassignment can no longer swap it, while mutation of
  // the object it points at remains open and is tracked separately.
  var bindingChecked, vopts;
  try {
    bindingChecked = _applyBindings(att.authData, att.authData.credentialPublicKey, opts);
    vopts = Object.assign({}, opts, {
      rootCertificates: _snapshotRoots(opts.rootCertificates),
      safetyNetRoots: _snapshotRoots(opts.safetyNetRoots),
    });
  } catch (e) { return Promise.reject(e); }
  return Promise.resolve().then(function () { return verifier(att, clientDataHash, vopts); })
    .then(function (res) {
      // What the clientData reader found, on the verdict rather than left for the caller to
      // recompute -- the same field the login verdict carries, for the same reason: `checked` is
      // where a comparison that ran is told from one that never did. Null when the caller supplied
      // only the digest, which is the honest answer: nothing read it.
      res.clientData = clientData;
      return res;
    })
    .then(function (res) {
      // Metadata governs when supplied; caller roots are the fallback for the models
      // the catalogue does not cover. Whichever ran, the verdict SAYS which -- so a
      // caller can tell an anchored trust path from one nobody checked, rather than
      // inferring it from which option they happened to pass.
      if (vopts.metadata === undefined) {
        if (vopts.rootCertificates !== undefined) return _applyCallerRoots(res, vopts.rootCertificates, vopts);
        res.anchoredTo = _anchoredRoutes(res, null);
        // Coverage is reported whenever anything WAS anchored, for the same reason the other
        // routes report it: `anchoredTo` alone cannot say how much of a compound it covered.
        var sn = _safetyNetAnchored(res);
        if (sn) {
          res.anchoredElements = { total: (res.fmt === "compound" && Array.isArray(res.compound)) ? res.compound.length : 1,
            anchored: sn };
        }
        return res;
      }
      return Promise.resolve().then(function () { return _applyMetadata(res, att, vopts); })
        .then(function (out) { out.anchoredTo = _anchoredRoutes(out, "metadata"); return out; }, function (e) {
          // A catalogue MISS is the case pinned roots exist for: the combined
          // configuration is exactly "MDS-listed authenticators AND Apple", and Apple
          // is in no catalogue, so failing here would make the documented pairing
          // unusable for the very models it was added to reach.
          //
          // A catalogue DENIAL is not a miss and never falls through. If the model IS
          // listed and its entry disqualifies it -- a revoked status report, a trust
          // path that does not reach the roots that model registered -- then the
          // catalogue has spoken about this authenticator, and letting a static pin
          // overrule it would turn the stronger source into the weaker one.
          if (!e || e.code !== "webauthn/metadata-not-found" || vopts.rootCertificates === undefined) throw e;
          // Only the elements the catalogue did not cover fall back. The listed ones were
          // already governed AND chain-validated to the roots their own entries register, so
          // re-judging them against an unrelated pin would refuse the combined configuration
          // this fallback exists to support.
          return Promise.resolve(_applyCallerRoots(res, vopts.rootCertificates, vopts, e.missedPaths))
            .then(function (out) {
              // Report BOTH routes. The pinned roots covered only the elements the catalogue
              // missed; the rest were governed by their metadata entries and chain-validated
              // against the roots those entries register. Saying "rootCertificates" alone
              // would attribute the whole evaluation to the weaker half and lose the entries
              // an auditor needs to see. `anchoredTo` names both, and the governed entries
              // are surfaced exactly as the pure-metadata route surfaces them.
              var applied = e.appliedEntries || [];
              if (!applied.length) return out;
              var primary = applied[0];
              out.metadata = { aaguid: primary.entry.aaguid, keyIdentifiers: primary.entry.keyIdentifiers || [],
                entry: primary.entry, entries: applied.map(function (a) { return a.entry; }),
                anchors: primary.anchors.length };
              out.anchoredTo = _anchoredRoutes(out, "metadata+rootCertificates");
              return out;
            });
        });
    })
    .then(function (res) { res.bindingChecked = bindingChecked; return res; });
}

// WebAuthn sec. 7.1 step 22-23: having verified the attestation, look the authenticator model up in
// the metadata and require its trust path to chain to one of the roots that model is registered
// with. The metadata must be a verifyMetadataBlob RESULT, never raw bytes -- accepting bytes here
// would let an unverified BLOB decide which roots are acceptable, which is the whole question.
function _applyMetadata(res, att, opts) {
  var md = opts.metadata;
  // Provenance, not shape: only a catalogue this toolkit actually verified may decide which roots
  // an authenticator is allowed to chain to. Recognising it by its property names would accept a
  // hand-built object, or one restored from a cache an attacker can write -- neither of which has
  // been through the signature and chain checks that give the catalogue its authority.
  if (!mds.isVerifiedResult(md)) {
    throw _err("webauthn/bad-input", "opts.metadata must be a pki.webauthn.verifyMetadataBlob result, not a raw BLOB");
  }
  // A compound attestation (sec. 8.9) deliberately carries an EMPTY top-level trust path, because
  // its elements yield independent chains with no single ordered path -- each element's own path is
  // on its entry in `compound`. Treating that empty path as "nothing to anchor" would refuse every
  // compound attestation outright, including ones whose certificate-bearing elements all chain to
  // the model's registered roots. So the paths to check are the elements'.
  // Each path travels WITH the format that produced it, because the format is what decides which
  // identifier may name its entry -- and a compound mixes formats. A compound's elements are
  // independent claims: a packed element's AAGUID is signed while a fido-u2f element's is not, so a
  // single choice for the whole statement is wrong in both directions. It would push the packed
  // element down the certificate-identifier path (where a conforming entry indexed only by its
  // AAGUID is not found), or trust the u2f element's unsigned AAGUID.
  // A compound's elements are independent claims (sec. 8.9), and one carrying no
  // certificates -- a `none` or self element -- makes no attestation claim there is
  // anything to anchor. Refusing the whole statement over it would reject a
  // conforming compound whose certificate-bearing elements do chain; enforcing over
  // the rest and saying nothing would report catalogue enforcement over a statement
  // it did not wholly reach. So the elements that CAN be governed are, and the
  // coverage is reported (`anchoredElements`) rather than left to be assumed.
  var paths = (res.fmt === "compound" && Array.isArray(res.compound))
    ? res.compound.filter(function (el) { return el.trustPath && el.trustPath.length; })
      .map(function (el) { return { tp: el.trustPath, fmt: el.fmt, at: el.chainValidatedAt }; })
    : (res.trustPath && res.trustPath.length ? [{ tp: res.trustPath, fmt: res.fmt, at: res.chainValidatedAt }] : []);
  res.anchoredElements = { total: (res.fmt === "compound" && Array.isArray(res.compound)) ? res.compound.length : 1,
    anchored: paths.length };
  // An attestation with no trust path at all (`none`, or a self-attestation) has nothing to anchor,
  // so a caller who asked for metadata enforcement must be told it could not be applied rather than
  // receiving a pass that looks like it was.
  if (!paths.length) {
    throw _err("webauthn/metadata-not-applicable", "opts.metadata was supplied, but this attestation carries no trust path to anchor (format '" + res.fmt + "')");
  }
  // The catalogue's two key spaces are DISJOINT, and which one applies is decided by what the
  // authenticator declares -- never by trying one and falling back to the other. An authenticator
  // that declares a signed model identity is looked up by it and by nothing else, so a model the
  // catalogue does not list is refused instead of being resolved out of the U2F key space under
  // some other authenticator's entry.
  var aaguid = mds.aaguidToString(att.authData.aaguid);
  // The aaguid may only select the entry when the attestation SIGNATURE covers it. For fido-u2f it
  // does not -- sec. 8.6 signs 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F,
  // which excludes the field entirely -- so those 16 bytes are attacker-editable. Trusting them
  // there does not merely misreport a model: setting them to a LISTED model that shares the
  // vendor's registered root makes the forged statement resolve to that model's entry, skipping the
  // real U2F entry's own key-identifier lookup and, with it, its status reports. A revoked
  // authenticator would present itself as its healthy sibling. So for that format the certificate
  // key identifier decides, whatever the field says.
  // Every path is resolved and enforced against ITS OWN entry, by the identifier ITS OWN format
  // allows. A compound carries independent claims and its element order is not signed, so choosing
  // one entry for the whole statement would let that order decide whose status report is consulted:
  // a healthy element listed first would suppress a revoked sibling's report while both still
  // anchor successfully. Each path answers for itself, and all of them must pass.
  var applied = [];
  function govern(info) {
    var tp = info.tp;
    var declared = _aaguidIsSigned(info.fmt) && aaguid && aaguid !== mds.ZERO_AAGUID;
    var entry, identifier;
    if (declared) {
      entry = mds.metadataFor(md, aaguid);
      identifier = "aaguid " + aaguid;
    } else {
      // No signed model identity: keyed by the attestation certificate instead. A path is
      // anchor-adjacent first, so that certificate is its LAST element -- the one whose key the
      // catalogue identifies, not the root it chains to.
      var keyId = mds.certKeyIdentifier(tp[tp.length - 1]);
      entry = mds.metadataForKeyIdentifier(md, keyId);
      identifier = "attestation certificate key identifier " + keyId;
    }
    if (!entry) throw _err("webauthn/metadata-not-found", "no metadata entry matches this authenticator (" + identifier + ")");
    // The attestation certificate is passed in so a report that names a single certificate is
    // judged against the one actually presented, rather than denying every device the entry covers.
    if (mds.statusDenied(entry, md, tp[tp.length - 1], at)) {
      throw _err("webauthn/metadata-status", "the metadata entry for " + identifier + " carries a disqualifying status report");
    }
    // The same three inputs the status check above used. metadataAnchors makes the same decision
    // for the callers who reach it directly, so handing it different inputs is how the two readings
    // would come to disagree about the same entry.
    var anchors = mds.metadataAnchors(entry, { metadata: md, time: at, certificate: tp[tp.length - 1] });
    if (!anchors.length) throw _err("webauthn/metadata-no-anchor", "the metadata entry for " + identifier + " supplies no attestation root certificate");
    applied.push({ entry: entry, anchors: anchors, identifier: identifier });
    return { anchors: anchors, identifier: identifier };
  }
  // A path must VALIDATE to one of the roots its own model registered -- signature chaining,
  // validity, constraints -- not merely resemble one. A name comparison against the top of the path
  // would accept any certificate asserting the registered issuer's name, which is the assertion an
  // attacker controls; and certificate equality is not the question either, since a registered root
  // normally ISSUES the attestation certificate rather than being it. So this composes the same
  // path validation the BLOB's own chain goes through. chainToAnchor takes leaf-first and a trust
  // path is anchor-adjacent first, so the order is reversed on the way in.
  //
  // opts.time was validated at the entry, so this instant is usable: an unusable one reaching the
  // path validator would be absorbed by the chain walk and reported as an authenticator trust
  // failure, which is the wrong verdict for a caller's configuration mistake.
  var at = opts.time !== undefined ? opts.time : new Date();
  // The catalogue's own freshness is re-established HERE, at the instant it is being used to decide
  // trust -- not only at the instant it was parsed. A verified result is a plain object a caller may
  // hold and reuse indefinitely, so a catalogue fetched before its nextUpdate and then reused a
  // month afterwards would otherwise keep authorizing an authenticator whose status reports have
  // since revoked it, which is exactly what nextUpdate exists to prevent. The caller's original
  // allowStale decision rides on the result, so opting out stays opted out.
  mds.assertFresh(md, at, "the metadata supplied as opts.metadata");
  // EVERY path must pass, not merely one of them: for a compound attestation each element is an
  // independent claim, and accepting the whole because one element anchored would let an
  // unanchored -- or revoked -- element ride along on its neighbour's trust.
  // Govern EVERY path BEFORE any is chain-validated, and let the SEVEREST outcome decide
  // rather than the first one reached. A compound's elements are independent claims and
  // its element order is NOT signed, so aborting on the first failure lets that order pick
  // which element the catalogue gets to speak about. The asymmetry that makes it exploitable
  // is that the errors are not equal: `metadata-not-found` is the one outcome the caller may
  // fall back to pinned roots on, and that fallback covers the WHOLE statement. So an element
  // the catalogue does not list, placed first, would raise the fallback error and a listed
  // sibling carrying a disqualifying status report would never be consulted -- the unlisted
  // element laundering the revoked one. A denial therefore outranks a miss wherever each sits:
  // a miss is only reported once every other path has been governed and none of them objected.
  var governed = [];
  var missed = null;
  var missedPaths = [];
  for (var gi = 0; gi < paths.length; gi++) {
    try {
      governed.push({ info: paths[gi], g: govern(paths[gi]) });
    } catch (ge) {
      // WHICH paths missed is carried with the error, not just THAT one did. The caller's
      // pinned-root fallback is for the elements the catalogue did not cover, and it cannot
      // tell which those were from the verdict alone -- every element looks the same there.
      if (ge && ge.code === "webauthn/metadata-not-found") { missed = missed || ge; missedPaths.push(paths[gi]); continue; }
      throw ge;   // a status denial, a missing anchor, any other governance failure: terminal
    }
  }
  // The miss carries BOTH halves: which paths the catalogue did not cover, and which entries
  // it did govern. Without the second the fallback can only describe its own half, so a
  // mixed-route verdict would attribute the whole evaluation to the pinned roots and drop the
  // metadata-backed part entirely -- the stronger half, and the one an auditor most needs.
  if (missed) { missed.missedPaths = missedPaths; missed.appliedEntries = applied; }
  // The miss is NOT reported yet. Resolving an entry is only half of governance: the other
  // half is that the path must actually VALIDATE to the roots that entry registers, and that
  // runs below. Reporting the miss here would skip it for every listed element -- so a listed
  // element whose path reaches the caller's pinned roots but NOT its own registered roots
  // would ride out on the unlisted sibling's fallback, which is that same bypass moved one
  // phase down. Every listed element is chain-validated first, and only then may a miss be
  // raised.
  return governed.reduce(function (p, item) {
    return p.then(function () {
      var g = item.g, info = item.info;
      // A path is re-validated at the instant its own format already judged it at, when the format
      // established one from signed data. An android-safetynet response carries its signing time and
      // its service chain has usually expired since; resetting to the current clock here would
      // refuse the very registration the format verifier just accepted. An explicit opts.time still
      // wins, since the caller knows when the registration happened. The catalogue's own expiry is a
      // separate question and is judged above, against the caller's instant rather than this one.
      var pathAt = opts.time !== undefined ? opts.time : (info.at || at);
      return mds.chainToAnchor(info.tp.slice().reverse(), g.anchors, pathAt,
        "attestation trust path for " + g.identifier + " (against the roots its metadata entry registers)");
    });
  }, Promise.resolve())
    .then(function () {
      // Every LISTED element has now been fully governed -- entry resolved, status checked, and its
      // path validated to that entry's own registered roots. A miss recorded above may finally be
      // reported, and the caller's pinned-roots fallback is reachable only from here: a statement
      // whose listed elements all satisfied their catalogue entries, with a sibling the catalogue
      // simply does not cover.
      if (missed) throw missed;
      // The ENTRY's aaguid, not the authenticator's raw field: for a U2F authenticator that field is
      // all zeroes, which means "no model identity" -- reporting it back as though it were one would
      // hand the caller a value that matches nothing and reads like an identifier. `entries` lists
      // every entry that governed a path, which for a compound is one per certificate-bearing
      // element; `entry` is the first, and equals the only one for every other format.
      var primary = applied[0];
      res.metadata = { aaguid: primary.entry.aaguid, keyIdentifiers: primary.entry.keyIdentifiers || [],
        entry: primary.entry, entries: applied.map(function (a) { return a.entry; }),
        anchors: primary.anchors.length };
      return res;
    });
}

// Does this attestation carry a statement of the named format -- as the whole statement, or as one
// element of a compound (sec. 8.9), whose own arm would apply a policy about that format?
//
// Every option that DEMANDS something only one format can produce asks this same question, so it is
// asked in one place: a demand about a TPM public area and a demand about an android-safetynet
// device-integrity signal differ only in the format they name. Answering it per option is how the
// second one comes to be answered only for the simple case and not for a compound.
function _formatCarries(att, fmt) {
  if (att.fmt === fmt) return true;
  if (att.fmt !== "compound") return false;
  return (att.attStmt.children || []).some(function (el) {
    if (!el || el.majorType !== 5) return false;
    var fN = cbor.read.mapGet(el, "fmt");
    return !!fN && fN.majorType === 3 && cbor.read.textString(fN) === fmt;
  });
}

void constants;

/**
 * @primitive pki.webauthn.verifyMetadataBlob
 * @signature pki.webauthn.verifyMetadataBlob(blob, opts) -> Promise<{ no, legalHeader, nextUpdate, stale, allowStale, rollbackChecked, previousNo, entries, byAaguid, byKeyIdentifier, statusPolicy, rejectUnknownStatus }>
 * @since 0.4.11
 * @status stable
 * @spec FIDO Metadata Service v3.0 sec. 3.1, RFC 7515
 * @related pki.webauthn.verify, pki.webauthn.metadataFor
 *
 * Verify a FIDO Metadata Service BLOB -- the signed catalogue of every registered
 * authenticator model, its attestation roots, and its certification status -- and
 * return its entries indexed by aaguid for lookup. `blob` is caller-supplied bytes or
 * a string; retrieval is out of scope, so this never touches the network.
 *
 * The BLOB is a JWS. Its signature is checked under the certificate in its own header,
 * that chain is validated to one of `opts.rootCertificates`, and only THEN is the
 * payload read -- a BLOB that does not verify never reaches the JSON parser. `no` must
 * exceed `opts.previousNo` (rollback) and `nextUpdate` must not have passed
 * (freshness). Every failure is a typed `webauthn/metadata-*` throw, never a partial
 * result.
 *
 * The result says which of those rules actually ran, so a catalogue held for a while can
 * still answer for itself: `stale` and `allowStale` for freshness, `rollbackChecked` and
 * the `previousNo` it was compared against for rollback, `statusPolicy` and
 * `rejectUnknownStatus` for the status reading every later lookup will use. A rule that
 * did not run reads as not-run rather than as passed.
 *
 * @intro No FIDO root ships with this toolkit and there is no trust-on-first-use:
 *   which metadata authority to trust is the operator's decision, exactly as a root
 *   store is for `pki.path.validate`. Supply the FIDO Alliance root you pin.
 *
 * @opts
 *   - `rootCertificates` -- REQUIRED. The trust anchors the BLOB's own signing chain
 *     must reach. A certificate, PEM, or DER bytes.
 *   - `time` -- the instant freshness is judged at. Defaults to now.
 *   - `previousNo` -- the sequence number of the BLOB you already hold. A BLOB whose
 *     `no` is not greater is refused as a rollback.
 *   - `requireRollbackCheck` -- require `previousNo`, so a caller cannot skip the
 *     rollback check by forgetting to pass it.
 *   - `allowStale` -- accept a BLOB past its `nextUpdate`. Off by default.
 *   - `statusPolicy` -- which status reports disqualify an authenticator: `"any"`
 *     (default -- any disqualifying report ever filed), `"latest-by-date"` (only the
 *     most recent report counts, so a later remediation clears an earlier revocation),
 *     or a function receiving the raw report array and returning true to deny.
 *   - `rejectUnknownStatus` -- treat a status this toolkit does not recognise as
 *     disqualifying. Off by default: the specification requires an unknown status be
 *     ignored rather than failed on.
 *
 * @example
 *   // requires: `mdsBlobBytes` -- the signed BLOB from https://mds3.fidoalliance.org/
 *   // -- and `fidoRootDer`, the FIDO Alliance root certificate it chains to
 *   var md = await pki.webauthn.verifyMetadataBlob(mdsBlobBytes, {
 *     rootCertificates: [fidoRootDer],
 *     previousNo: 41,          // refuse a replay of a BLOB you have already superseded
 *   });
 *   md.no;                     // 42 (the sequence number this BLOB carries)
 *   md.entries.length;         // every authenticator model the catalogue lists
 *   // then bind an attestation to the roots its own model registered:
 *   // await pki.webauthn.verify(attestationObject, clientDataHash, { metadata: md });
 */

/**
 * @primitive pki.webauthn.metadataFor
 * @signature pki.webauthn.metadataFor(metadata, identifier) -> entry | null
 * @since 0.4.11
 * @status stable
 * @spec FIDO Metadata Service v3.0 sec. 3.1.1
 * @related pki.webauthn.verifyMetadataBlob, pki.webauthn.metadataAnchors
 *
 * The verified metadata entry for an authenticator model, or `null` when the BLOB
 * lists none. `metadata` is a `verifyMetadataBlob` RESULT, never raw bytes -- so a
 * lookup can never be answered out of a BLOB nobody verified.
 *
 * `identifier` is whichever of the catalogue's two key spaces names the authenticator:
 * its aaguid, or -- for a U2F authenticator, which carries none -- the key identifier
 * of its attestation certificate (RFC 5280 sec. 4.2.1.2 method 1, 40 hex digits). The
 * two are disjoint by shape, so the form is dispatched on rather than guessed at, and
 * anything matching neither is a miss. The all-zero aaguid means "this authenticator
 * declares no model identity" and matches nothing.
 *
 * @example
 *   // requires: `mdsMetadata` -- a verifyMetadataBlob RESULT (never raw bytes, so a
 *   // lookup cannot be answered out of an unverified BLOB) -- and the model's aaguid
 *   var entry = pki.webauthn.metadataFor(mdsMetadata, mdsAaguid);
 *   entry.statusReports[0].status;   // "FIDO_CERTIFIED_L1"
 *   pki.webauthn.metadataFor(mdsMetadata, "00000000-0000-0000-0000-000000000000");   // null
 */

/**
 * @primitive pki.webauthn.metadataAnchors
 * @signature pki.webauthn.metadataAnchors(entry, opts?) -> [certificate]
 * @since 0.4.11
 * @status stable
 * @spec FIDO Metadata Service v3.0 sec. 3.1.1
 * @defends webauthn-revoked-authenticator-accepted (CWE-299)
 * @related pki.webauthn.metadataFor, pki.path.validate
 *
 * The parsed attestation root certificates a metadata entry registers -- the anchors an
 * attestation from that model must chain to. An entry whose status reports disqualify
 * the model registers none: the catalogue exists to say which authenticators are still
 * trusted, so handing back the roots of one it has revoked would answer a different
 * question than the caller asked. That refusal is `webauthn/metadata-status`.
 *
 * The judgement uses whatever the caller supplies and the strictest reading of what it
 * does not: pass the verified `metadata` and its own `statusPolicy` governs and its
 * freshness is re-checked, pass `time` and reports are judged as of that instant, pass
 * the `certificate` an attestation actually presented and a report naming a single
 * certificate is judged against that one rather than denying every device the entry
 * covers. With none of them: any disqualifying report denies, judged now.
 *
 * Decoding is per entry rather than for the
 * whole BLOB on purpose: a handful of certificates in the live metadata do not parse
 * under a strict decoder, and decoding everything up front would let one vendor's
 * malformed root refuse the entire catalogue for every other authenticator in it.
 *
 * @opts
 *   metadata    -- the verifyMetadataBlob result the entry came from
 *   time        -- the instant the status reports are judged at (default: now)
 *   certificate -- the attestation certificate presented, for a report that names one
 *
 * @example
 *   // requires: `mdsMetadata` -- a verifyMetadataBlob result; `mdsEntry` -- one of its
 *   // entries, as metadataFor returns; `mdsTime` -- the instant to judge at
 *   var anchors = pki.webauthn.metadataAnchors(mdsEntry, { metadata: mdsMetadata, time: mdsTime });
 *   anchors.length;              // the attestation roots this model registered
 *   anchors[0].subject;          // the decoded root DN
 *   // chain an attestation's trustPath to them:
 *   // await pki.path.validate(res.trustPath, { trustAnchors: anchors, time: mdsTime });
 */

// ---- public: parseClientData -------------------------------------------------

// The two ceremony types, fixed by the spec -- `webauthn.create` for registration
// and `webauthn.get` for authentication. This is NOT relying-party policy: a
// registration response replayed into a login (or the reverse) is a real attack,
// and which one a caller is finishing is known at the call site, never negotiated.
var CLIENT_DATA_TYPE = Object.assign(Object.create(null), { "webauthn.create": 1, "webauthn.get": 1 });

/**
 * @primitive pki.webauthn.parseClientData
 * @signature pki.webauthn.parseClientData(bytes, opts?) -> { type, challenge, origin, crossOrigin, topOrigin, checked }
 * @since 0.5.0
 * @status experimental
 * @spec W3C WebAuthn Level 3 sec. 5.8.1 / 7.1 / 7.2
 * @defends webauthn-ceremony-confusion (CWE-345)
 * @related pki.webauthn.verify, pki.webauthn.verifyAssertion
 *
 * Decode the `clientDataJSON` a ceremony returns -- the half of a WebAuthn response
 * the signature covers by digest but that no signature check ever looks inside.
 * Parsed through the shared fail-closed JSON guard (bounded bytes and depth,
 * fatal UTF-8, duplicate members refused, no prototype pollution), because these
 * are bytes an attacker chose. `challenge` is returned DECODED from base64url as a
 * Buffer, so a caller compares raw bytes and never two spellings of the same
 * value; `type`, `origin`, `crossOrigin` and `topOrigin` come back as they were.
 *
 * Supply `expectedType`, `expectedChallenge`, `expectedOrigin` and
 * `expectedTopOrigin` and each is checked here -- the challenge in constant time
 * and by full value, the origins whole and case-sensitively. `checked`
 * reports which ran, so a check that passed is distinguishable from one that never
 * happened. `expectedType` is worth setting on every call: the ceremony a response
 * belongs to is fixed, and accepting a `webauthn.create` where a `webauthn.get` was
 * expected is a credential-registration response replayed as a login.
 *
 * In a cross-origin ceremony `origin` is the framed document's and `topOrigin` is
 * the page that framed it, so a relying party that allows framing at all should say
 * which pages may do it. `expectedTopOrigin: null` requires an unframed ceremony,
 * which an origin list cannot express. Whether a ceremony was framed is stated by
 * BOTH `crossOrigin` and `topOrigin` and is only usable when they agree: a response
 * declaring itself cross-origin does not satisfy `null` by omitting the origin, and
 * one that does not declare itself cross-origin makes no framing claim for an origin
 * list to accept.
 *
 * @opts
 *   expectedType      -- "webauthn.create" or "webauthn.get"
 *   expectedChallenge -- the challenge bytes this ceremony issued (BufferSource)
 *   expectedOrigin    -- the origin string, or an array of acceptable origins
 *   expectedTopOrigin -- the acceptable top-level origin(s), or null to require an
 *                        unframed ceremony
 *
 * @example
 *   // requires: `clientDataJSON` -- credential.response.clientDataJSON;
 *   // `issuedChallenge` -- the random bytes this server sent
 *   var cd = pki.webauthn.parseClientData(clientDataJSON, {
 *     expectedType: "webauthn.get",
 *     expectedChallenge: issuedChallenge,
 *     expectedOrigin: "https://example.com",
 *   });
 *   cd.checked.challenge;   // true -- the issued challenge came back
 *   cd.crossOrigin;         // false
 */
function parseClientData(bytes, opts) {
  opts = opts || {};
  if (!_isPlainObject(opts)) throw _err("webauthn/bad-input", "opts must be an object");
  guard.identifier.assertKnownKeys(opts, _CLIENT_DATA_OPTS, _err, "webauthn/bad-input", "opts has an unknown key ");
  // The RAW bytes, not a parsed object: this reader decides on the exact octets the authenticator
  // signed over, and re-serializing a parsed object would decide on different ones.
  bytes = _bytesArg(bytes, "clientDataJSON");
  var doc = guard.json.parse(Buffer.from(bytes), _err, {
    maxBytes: constants.LIMITS.JSON_MAX_BYTES, maxDepth: constants.LIMITS.JSON_MAX_DEPTH,
    badJson: "webauthn/bad-client-data", tooDeep: "webauthn/bad-client-data",
    duplicateMember: "webauthn/bad-client-data", tooLarge: "webauthn/bad-client-data",
    badInput: "webauthn/bad-input", label: "clientDataJSON",
  });
  if (!_isPlainObject(doc)) throw _err("webauthn/bad-client-data", "clientDataJSON is not a JSON object (WebAuthn sec. 5.8.1)");
  if (typeof doc.type !== "string" || CLIENT_DATA_TYPE[doc.type] !== 1) {
    throw _err("webauthn/bad-client-data",
      "clientDataJSON type must be \"webauthn.create\" or \"webauthn.get\", got " + JSON.stringify(doc.type) +
      " (WebAuthn sec. 5.8.1)");
  }
  if (typeof doc.origin !== "string" || !doc.origin.length) {
    throw _err("webauthn/bad-client-data", "clientDataJSON carries no origin (WebAuthn sec. 5.8.1)");
  }
  if (typeof doc.challenge !== "string" || !doc.challenge.length) {
    throw _err("webauthn/bad-client-data", "clientDataJSON carries no challenge (WebAuthn sec. 5.8.1)");
  }
  // base64url, and STRICTLY: the challenge is a comparison key, so an encoding the
  // decoder had to guess at would let two spellings of one value both "match".
  var challenge;
  try {
    challenge = guard.encoding.base64url(doc.challenge, constants.LIMITS.JSON_MAX_BYTES, _err,
      "webauthn/bad-client-data", "the clientDataJSON challenge");
  } catch (e) {
    if (e && e.code === "webauthn/bad-client-data") throw e;
    throw _err("webauthn/bad-client-data", "the clientDataJSON challenge is not base64url (WebAuthn sec. 5.8.1)", e);
  }
  if (doc.crossOrigin !== undefined && typeof doc.crossOrigin !== "boolean") {
    throw _err("webauthn/bad-client-data", "clientDataJSON crossOrigin must be a boolean when present (WebAuthn sec. 5.8.1)");
  }
  // A present-but-malformed topOrigin is refused rather than reported as absent. It
  // is the top-level origin of a cross-origin ceremony -- something a caller makes a
  // policy decision on -- so "the sender wrote something that is not an origin" and
  // "the sender said nothing" must not arrive as the same `null`.
  if (doc.topOrigin !== undefined && (typeof doc.topOrigin !== "string" || !doc.topOrigin.length)) {
    throw _err("webauthn/bad-client-data", "clientDataJSON topOrigin must be a non-empty string when present (WebAuthn sec. 5.8.1)");
  }

  var checked = { type: false, challenge: false, origin: false, topOrigin: false };
  if (opts.expectedType !== undefined) {
    if (CLIENT_DATA_TYPE[opts.expectedType] !== 1) {
      throw _err("webauthn/bad-input", "opts.expectedType must be \"webauthn.create\" or \"webauthn.get\"");
    }
    if (doc.type !== opts.expectedType) {
      throw _err("webauthn/client-data-mismatch",
        "this is a " + doc.type + " response and a " + opts.expectedType + " one was expected -- a response " +
        "from the other ceremony (WebAuthn sec. 7.1 step 8 / sec. 7.2 step 11)");
    }
    checked.type = true;
  }
  if (opts.expectedChallenge !== undefined) {
    if (!guard.crypto.constantTimeEqual(_bytesArg(opts.expectedChallenge, "opts.expectedChallenge"), challenge)) {
      throw _err("webauthn/client-data-mismatch",
        "the clientDataJSON challenge is not the one this ceremony issued (WebAuthn sec. 7.1 step 9 / sec. 7.2 step 12)");
    }
    checked.challenge = true;
  }
  if (opts.expectedOrigin !== undefined) {
    var allowed = Array.isArray(opts.expectedOrigin) ? opts.expectedOrigin : [opts.expectedOrigin];
    if (!allowed.length || !allowed.every(function (o) { return typeof o === "string" && o.length; })) {
      throw _err("webauthn/bad-input", "opts.expectedOrigin must be a non-empty origin string, or an array of them");
    }
    // Compared WHOLE and case-sensitively as the serialization it is. A prefix or
    // suffix test is how "https://example.com.attacker.tld" passes for
    // "https://example.com".
    if (allowed.indexOf(doc.origin) === -1) {
      throw _err("webauthn/client-data-mismatch",
        "the clientDataJSON origin " + JSON.stringify(doc.origin) + " is not one this relying party accepts " +
        "(WebAuthn sec. 7.1 step 10 / sec. 7.2 step 13)");
    }
    checked.origin = true;
  }
  // The top-level origin of a cross-origin ceremony. It is surfaced either way, but a value a
  // relying party only READS is a value nobody compares: `origin` in a cross-origin ceremony is the
  // iframe's, and the top-level page that framed it is the one the security decision is actually
  // about. Given what it accepts, this compares it the same way as `origin` -- whole, case
  // sensitive, against a list -- so the two cannot drift into different matching rules.
  //
  // The three cases are kept apart rather than collapsed. An expectation of `null` means "this
  // ceremony must NOT be framed", which is a real policy and cannot be expressed by an origin list;
  // a response carrying no topOrigin against a list of acceptable ones is not framed at all, so the
  // list has nothing to accept and the ceremony is refused rather than passed.
  if (opts.expectedTopOrigin !== undefined) {
    var wantTop = opts.expectedTopOrigin;
    // Whether the ceremony was framed is stated by TWO fields, and the answer is only usable when
    // they agree. `crossOrigin` says a framing happened; `topOrigin` names the page that did it.
    // Reading one and not the other lets a response that declares itself cross-origin, but omits
    // the origin, satisfy a policy of "must not be framed" -- it answers the caller's question with
    // the field it left out rather than the one it filled in.
    var framed = doc.crossOrigin === true;
    if (wantTop === null) {
      if (framed || doc.topOrigin !== undefined) {
        throw _err("webauthn/client-data-mismatch",
          "the clientDataJSON describes a cross-origin ceremony (crossOrigin " + JSON.stringify(doc.crossOrigin) +
          ", topOrigin " + JSON.stringify(doc.topOrigin === undefined ? null : doc.topOrigin) +
          "), and this relying party requires an unframed one (WebAuthn sec. 5.8.1)");
      }
    } else {
      var allowedTop = Array.isArray(wantTop) ? wantTop : [wantTop];
      if (!allowedTop.length || !allowedTop.every(function (o) { return typeof o === "string" && o.length; })) {
        throw _err("webauthn/bad-input", "opts.expectedTopOrigin must be null, a non-empty origin string, or an array of them");
      }
      // Allow-listing the pages that may frame this ceremony is a statement about a framed one. A
      // response that does not say it was framed makes no such claim to match against, so the list
      // has nothing to accept -- and treating its absent topOrigin as a pass would report a check
      // that decided nothing.
      if (!framed || allowedTop.indexOf(doc.topOrigin) === -1) {
        throw _err("webauthn/client-data-mismatch",
          "the clientDataJSON topOrigin " + JSON.stringify(doc.topOrigin === undefined ? null : doc.topOrigin) +
          " (crossOrigin " + JSON.stringify(doc.crossOrigin) + ") is not a framing this relying party accepts (WebAuthn sec. 5.8.1)");
      }
    }
    checked.topOrigin = true;
  }
  return {
    type: doc.type, challenge: challenge, origin: doc.origin,
    crossOrigin: doc.crossOrigin === undefined ? false : doc.crossOrigin,
    topOrigin: doc.topOrigin === undefined ? null : doc.topOrigin,
    checked: checked,
  };
}
var _CLIENT_DATA_OPTS = Object.assign(Object.create(null), {
  expectedType: 1, expectedChallenge: 1, expectedOrigin: 1, expectedTopOrigin: 1,
});

// ---- public: parseAuthenticatorData / verifyAssertion ------------------------

/**
 * @primitive pki.webauthn.parseAuthenticatorData
 * @signature pki.webauthn.parseAuthenticatorData(bytes) -> { rpIdHash, flags, signCount, aaguid, credentialId, credentialPublicKey, credentialPublicKeyBytes, extensions }
 * @since 0.5.0
 * @status experimental
 * @spec W3C WebAuthn Level 3 sec. 6.1
 * @related pki.webauthn.verifyAssertion, pki.webauthn.parseAttestationObject
 *
 * Decode a BARE authenticatorData, fail-closed -- the form an authentication
 * assertion returns, with no attestation-object wrapper around it. Same parser the
 * registration path uses: the 37-byte minimum, the reserved (RFU) flag bits, the
 * Backup State / Backup Eligibility rule, the 1..1023 credentialId bound, a
 * credential public key that must be one well-formed COSE_Key, and extensions that
 * must be exactly one CBOR map when the ED flag is set and absent when it is clear.
 * `flags` is decoded to `{ up, uv, be, bs, at, ed }`. An assertion normally has the
 * AT flag clear, so `aaguid` / `credentialId` / `credentialPublicKey` are null.
 * Malformed input throws `webauthn/bad-auth-data`.
 *
 * @example
 *   // requires: `authenticatorData` -- credential.response.authenticatorData from
 *   // navigator.credentials.get()
 *   var ad = pki.webauthn.parseAuthenticatorData(authenticatorData);
 *   ad.flags.up;      // true when the user was present
 *   ad.signCount;     // the authenticator's counter for this credential
 */
function parseAuthenticatorData(bytes) {
  return _parseAuthData(_bytesArg(bytes, "authenticatorData"), _err);
}

// The options pki.webauthn.verifyAssertion recognises, null-prototype for the same
// reason _VERIFY_OPTS is.
var _ASSERT_OPTS = Object.assign(Object.create(null), {
  authenticatorData: 1, clientDataHash: 1, clientDataJSON: 1, signature: 1,
  credentialPublicKey: 1, previousSignCount: 1,
  expectedRpId: 1, requireUserPresence: 1, requireUserVerification: 1, allowedAlgorithms: 1,
  expectedChallenge: 1, expectedOrigin: 1, expectedTopOrigin: 1,
});

/**
 * @primitive pki.webauthn.verifyAssertion
 * @signature pki.webauthn.verifyAssertion(input) -> Promise<{ signatureVerified, signCount, signCountChecked, flags, rpIdHash, extensions, bindingChecked, clientData }>
 * @since 0.5.0
 * @status experimental
 * @spec W3C WebAuthn Level 3 sec. 7.2
 * @defends webauthn-assertion-forgery (CWE-347)
 * @related pki.webauthn.parseAuthenticatorData, pki.webauthn.verify
 *
 * Verify an authentication assertion's signature: the authenticator signs
 * `authenticatorData || SHA-256(clientDataJSON)` as RAW bytes with the credential
 * key registered earlier -- no COSE_Sign1 wrapper, so a COSE message verifier is
 * the wrong tool and fails on structure before it ever reaches the signature. An
 * ES256 assertion signature is an ASN.1 DER `SEQUENCE { r, s }`, converted here
 * with the same order-aware reader the attestation path uses, so an r or s outside
 * `[1, n-1]` is refused rather than normalized.
 *
 * `signatureVerified`, not `verified`: this establishes that the holder of the
 * registered credential key produced this response. What makes the response
 * ACCEPTABLE is the sec. 7.2 binding, and the caller owns most of it. Supply
 * `expectedRpId`, `requireUserPresence`, `requireUserVerification` and
 * `allowedAlgorithms` and they are checked here -- `bindingChecked` reports which
 * ones ran, so a check that passed is distinguishable from one that never
 * happened. The CHALLENGE and the ORIGIN stay with the caller: both live in
 * clientDataJSON and are compared against state only the relying party has.
 *
 * Pass `previousSignCount` (the value stored at registration or the last login) and
 * the sec. 7.2 step 21 counter rule is applied: a counter that fails to advance is
 * a cloned authenticator and is refused, except for the `0`/`0` case an
 * authenticator that does not implement a counter reports. Without it the counter
 * is surfaced and not judged, and `signCountChecked` says so.
 *
 * @opts
 *   authenticatorData -- the raw bytes from the assertion (Buffer)
 *   clientDataJSON    -- the raw clientDataJSON bytes; its SHA-256 is what the signature covers
 *   clientDataHash    -- the 32-byte digest instead, when the caller already has it
 *   signature         -- the assertion signature bytes
 *   credentialPublicKey -- the stored COSE key (as parseAttestationObject surfaced it)
 *   previousSignCount -- the stored counter, enabling the sec. 7.2 step 21 rule
 *   expectedRpId, requireUserPresence, requireUserVerification, allowedAlgorithms -- the bindings above
 *
 * @example
 *   // requires: `assertion` -- credential.response from navigator.credentials.get();
 *   // `storedKey` -- the COSE credentialPublicKey kept at registration
 *   var res = await pki.webauthn.verifyAssertion({
 *     authenticatorData: assertion.authenticatorData,
 *     clientDataJSON: assertion.clientDataJSON,
 *     signature: assertion.signature,
 *     credentialPublicKey: storedKey,
 *     expectedRpId: "example.com", requireUserPresence: true,
 *   });
 *   res.signatureVerified;      // true
 *   res.bindingChecked.rpId;    // true -- the rpIdHash matched example.com
 *   // the challenge and origin in clientDataJSON are still yours to compare
 */
// A private copy of the assertion inputs. Only what the caller can still write to
// is copied: the byte fields, the descriptor itself, and the option arrays. The
// COSE key is a decoded object the caller supplies from its own storage; it is
// shallow-copied so a swapped field cannot reach the verification, which is the
// mutation this can defend against without deep-copying an arbitrary object.
function _snapshotAssertion(input) {
  if (!_isPlainObject(input)) throw _err("webauthn/bad-input", "pki.webauthn.verifyAssertion takes an options object");
  guard.identifier.assertKnownKeys(input, _ASSERT_OPTS, _err, "webauthn/bad-input", "verifyAssertion input has an unknown key ");
  var out = {}, k;
  for (k in input) { if (Object.prototype.hasOwnProperty.call(input, k)) out[k] = input[k]; }
  // The SAME set of byte forms the arguments accept. A snapshot list narrower than the accept list
  // leaves whatever falls in the gap aliased across the yield -- which is the one input a widened
  // accept list newly admits, so the two must be written from one predicate.
  ["authenticatorData", "clientDataJSON", "clientDataHash", "signature", "expectedChallenge"].forEach(function (f) {
    if (_isBufferSource(out[f])) out[f] = guard.bytes.snapshotSource(out[f], WebauthnError, "webauthn/bad-input", f);
  });
  // The BYTES form first. A Buffer satisfies the plain-object test below, so leaving it to that
  // branch copies its numeric indices into a `{0:.., 1:..}` object that is no longer a key at all
  // -- the stored credential silently becoming something the SPKI builder cannot read. It is
  // snapshotted here for the same reason the other byte inputs are: it is read after a yield.
  if (_isBufferSource(out.credentialPublicKey)) {
    out.credentialPublicKey = guard.bytes.snapshotSource(out.credentialPublicKey, WebauthnError,
      "webauthn/bad-input", "credentialPublicKey");
  } else if (_isPlainObject(out.credentialPublicKey)) {
    var key = {}, kk;
    for (kk in out.credentialPublicKey) {
      if (!Object.prototype.hasOwnProperty.call(out.credentialPublicKey, kk)) continue;
      var v = out.credentialPublicKey[kk];
      key[kk] = _isBufferSource(v) ? guard.bytes.snapshotSource(v, WebauthnError, "webauthn/bad-input", "credentialPublicKey." + kk) : v;
    }
    out.credentialPublicKey = key;
  }
  if (Array.isArray(out.allowedAlgorithms)) out.allowedAlgorithms = out.allowedAlgorithms.slice();
  if (Array.isArray(out.expectedOrigin)) out.expectedOrigin = out.expectedOrigin.slice();
  if (Array.isArray(out.expectedTopOrigin)) out.expectedTopOrigin = out.expectedTopOrigin.slice();
  return out;
}

function verifyAssertion(input) {
  // Every byte this verdict depends on is COPIED here, synchronously, before
  // anything defers. The descriptor is the caller's object and the buffers in it
  // are the caller's memory: a caller that reuses or zeroizes them on the line
  // after this call has already changed them before the deferred body would run,
  // and an assertion that did not verify could be replaced by one that does. The
  // same rule pki.cmc.verify applies to a response, for the same reason.
  var frozen;
  try { frozen = _snapshotAssertion(input); } catch (e) { return Promise.reject(e); }
  return Promise.resolve().then(function () {
    input = frozen;
    var authData = parseAuthenticatorData(input.authenticatorData);
    input.signature = _bytesArg(input.signature, "signature");
    // The two forms of the same input, and NEITHER is inferred from the other's
    // absence: supplying both invites them to disagree, and picking one would make
    // the signature cover something the caller did not mean.
    var haveJson = input.clientDataJSON !== undefined, haveHash = input.clientDataHash !== undefined;
    if (haveJson === haveHash) {
      throw _err("webauthn/bad-input", "verifyAssertion takes exactly one of clientDataJSON or clientDataHash");
    }
    var clientDataHash, clientData = null;
    if (haveJson) {
      input.clientDataJSON = _bytesArg(input.clientDataJSON, "clientDataJSON");
      // Given the JSON, this verb reads it -- the ceremony TYPE is checked
      // unconditionally, because which ceremony a response belongs to is fixed by
      // the spec rather than chosen by the caller, and a registration response
      // replayed as a login is exactly what that check stops. The challenge and
      // origin are checked when the caller supplies what it issued.
      clientData = parseClientData(input.clientDataJSON, {
        expectedType: "webauthn.get",
        expectedChallenge: input.expectedChallenge,
        expectedOrigin: input.expectedOrigin,
        expectedTopOrigin: input.expectedTopOrigin,
      });
      clientDataHash = _sha("sha256", Buffer.from(input.clientDataJSON));
    } else {
      // Every expectation this verb forwards to the clientData reader is unanswerable without the
      // JSON, so each is refused here rather than silently going uncompared. The list is the
      // forwarded set above; a new expectation added there is added here too.
      if (input.expectedChallenge !== undefined || input.expectedOrigin !== undefined ||
          input.expectedTopOrigin !== undefined) {
        throw _err("webauthn/bad-input",
          "expectedChallenge / expectedOrigin / expectedTopOrigin are checked against clientDataJSON, which this call " +
          "did not supply -- pass clientDataJSON instead of clientDataHash, or check them yourself");
      }
      clientDataHash = _bytesArg(input.clientDataHash, "clientDataHash");
      if (clientDataHash.length !== 32) throw _err("webauthn/bad-input", "clientDataHash must be a 32-byte SHA-256 digest");
    }
    // Either form a relying party can be holding. `verify` hands back the parsed object, but the
    // durable form is BYTES: the object carries Buffers, so a JSON round trip through a datastore
    // returns {"type":"Buffer","data":[...]} rather than what went in, and every existing credential
    // store already holds the COSE bytes. Accepting only the object made a caller fabricate an
    // authenticatorData that never existed just to reach their own key.
    var coseKey = input.credentialPublicKey;
    if (Buffer.isBuffer(coseKey) || ArrayBuffer.isView(coseKey) || coseKey instanceof ArrayBuffer) {
      coseKey = parseCoseKey(coseKey);
    } else if (!_isPlainObject(coseKey)) {
      throw _err("webauthn/bad-input", "credentialPublicKey must be the stored COSE key -- the object pki.webauthn.verify returned, or its COSE bytes");
    }
    var bindingChecked = _applyBindings(authData, coseKey, input);
    // The counter's SHAPE is a config-time question and is answered here; whether it
    // advanced is a question about the message, and that is asked only after the
    // signature holds -- see below.
    var prev = input.previousSignCount;
    if (prev !== undefined && (typeof prev !== "number" || !Number.isSafeInteger(prev) || prev < 0 || prev > 0xFFFFFFFF)) {
      throw _err("webauthn/bad-input", "previousSignCount must be an integer in 0..4294967295");
    }
    // The signed message is the CONCATENATION, in that order, of the
    // authenticatorData exactly as it arrived and the clientDataJSON digest.
    var message = Buffer.concat([Buffer.from(input.authenticatorData), clientDataHash]);
    var spki = _coseKeyToSpki(coseKey);
    return _verifySig(coseKey.alg, Buffer.from(input.signature), spki, message, _err).then(function (ok) {
      if (!ok) {
        throw _err("webauthn/bad-signature",
          "the assertion signature does not verify under the stored credential public key (WebAuthn sec. 7.2 step 20)");
      }
      // sec. 7.2 step 21, and only NOW. A counter that fails to advance means two
      // authenticators hold one credential -- an alarm a relying party acts on, by
      // locking the account or revoking the credential. Judging it before the
      // signature would let anyone raise that alarm with arbitrary bytes, so the
      // counter is read only out of an assertion that proved to be authentic. The
      // 0/0 case is an authenticator that implements no counter, which is permitted.
      // THREE outcomes, kept apart, because this field's only purpose is to tell a relying party
      // whether it has cloned-authenticator detection on this credential:
      //   false           -- not requested; no previousSignCount was supplied
      //   "not-supported" -- requested, but the authenticator implements no counter (the 0/0 case
      //                      sec. 7.2 permits), so the comparison was deliberately skipped
      //   true            -- requested and performed
      // Reporting `true` for the waived case claimed a detection that cannot happen, and a bare
      // `false` there would be indistinguishable from never having asked.
      var signCountChecked = false;
      if (prev !== undefined) {
        if (prev === 0 && authData.signCount === 0) {
          signCountChecked = "not-supported";
        } else {
          if (authData.signCount <= prev) {
            throw _err("webauthn/sign-count-not-advanced",
              "the assertion signCount " + authData.signCount + " does not advance past the stored " + prev +
              ", which is the signal of a cloned authenticator (WebAuthn sec. 7.2 step 21)");
          }
          signCountChecked = true;
        }
      }
      return {
        signatureVerified: true,
        signCount: authData.signCount,
        signCountChecked: signCountChecked,
        flags: authData.flags,
        rpIdHash: authData.rpIdHash,
        extensions: authData.extensions,
        // The decoded clientData when this call was given the JSON, so a caller that
        // still owes itself a comparison has the values without re-parsing; null
        // when only the digest was supplied and there was nothing to read.
        clientData: clientData,
        bindingChecked: bindingChecked,
      };
    });
  });
}

module.exports = {
  parseAttestationObject: parseAttestationObject,
  parseAuthenticatorData: parseAuthenticatorData,
  parseClientData: parseClientData,
  parseCoseKey: parseCoseKey,
  verify: verify,
  verifyAssertion: verifyAssertion,
  verifyMetadataBlob: mds.verifyMetadataBlob,
  metadataFor: mds.metadataFor,
  metadataAnchors: mds.metadataAnchors,
};
