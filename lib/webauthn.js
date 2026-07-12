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
var ByteReader = require("./byte-reader");
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
// The minimal unsigned big-endian encoding of a non-negative integer (no sign octet,
// no leading zeros) -- for an unsigned compare against a COSE fixed-width field.
function _uintBytes(n) {
  var hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  var b = Buffer.from(hex, "hex"); var i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.subarray(i);
}
// COSE signature algorithm -> the node hash name of its signature scheme (the digest
// the TPM extraData / apple nonce is taken under).
var COSE_ALG_HASH = { "-7": "sha256", "-257": "sha256", "-37": "sha256", "-35": "sha384", "-258": "sha384", "-36": "sha512", "-259": "sha512", "-65535": "sha1" };
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
// An integer-keyed entry (COSE_Key labels are ints), by its signed value.
function _mapGetInt(node, key) {
  if (!node || node.majorType !== 5 || !node.children) return null;
  for (var i = 0; i < node.children.length; i++) {
    var k = node.children[i][0];
    if ((k.majorType === 0 || k.majorType === 1) && cbor.read.int(k) === BigInt(key)) return node.children[i][1];
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
    out.credentialPublicKey = _decodeCoseKey(keyNode, E);
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

// COSE EC2 curve (label -1) -> the fixed field-element byte length its x/y carry,
// and the named-curve OID a certificate on that curve declares.
var EC2_CRV_LEN = { 1: 32, 2: 48, 3: 66 };   // P-256 / P-384 / P-521
var EC2_CRV_OID = { 1: "prime256v1", 2: "secp384r1", 3: "secp521r1" };
// COSE OKP curve (label -1) -> its RFC 8410 named-key OID + fixed public-key length.
// Ed25519 (crv 6, 32-byte) and Ed448 (crv 7, 57-byte) both sign under COSE alg -8.
var OKP_CRV = { 6: { oid: "Ed25519", len: 32 }, 7: { oid: "Ed448", len: 57 } };
// The WebAuthn credential-key profile: a COSE signature algorithm (label 3) pins the
// key type (label 1) and, for EC2, the curve -- so an EC2 key claiming EdDSA, or an
// OKP key claiming ES256, is a profile violation (WebAuthn sec. 6.5.1, RFC 9052).
var ALG_PROFILE = {
  "-7": { kty: 2, crv: 1 }, "-35": { kty: 2, crv: 2 }, "-36": { kty: 2, crv: 3 },
  "-8": { kty: 1 },
  "-257": { kty: 3 }, "-258": { kty: 3 }, "-259": { kty: 3 }, "-37": { kty: 3 }, "-65535": { kty: 3 },
};

// kty 1 / alg 3; EC2 (kty 2): crv -1, x -2, y -3; OKP (kty 1): crv -1, x -2;
// RSA (kty 3): n -1, e -2. Surface the raw coordinate/modulus buffers.
function _decodeCoseKey(node, E) {
  if (!node || node.majorType !== 5) throw E("webauthn/bad-cose-key", "a COSE_Key must be a CBOR map (RFC 9052 sec. 7)");
  function ib(label) { var n = _mapGetInt(node, label); return n ? cbor.read.byteString(n) : null; }
  function ii(label) { var n = _mapGetInt(node, label); return n ? cbor.read.int(n) : null; }
  var ktyN = _mapGetInt(node, 1), algN = _mapGetInt(node, 3);
  if (!ktyN) throw E("webauthn/bad-cose-key", "a COSE_Key is missing the kty (label 1) parameter");
  // The credential public key MUST declare its algorithm (label 3): a relying party
  // needs it to verify the later assertion signature (WebAuthn sec. 6.5.1, COSE sec. 7).
  if (!algN) throw E("webauthn/bad-cose-key", "a COSE_Key is missing the alg (label 3) parameter");
  var kty = cbor.read.int(ktyN);
  var key = { kty: Number(kty), alg: Number(cbor.read.int(algN)) };
  // A credential key MUST carry every parameter its key type requires; an incomplete
  // key (or an unknown kty) is rejected at decode rather than surfaced with null
  // material a later binding check would have to defend against.
  if (kty === 2n) {
    key.crv = ii(-1) != null ? Number(ii(-1)) : null; key.x = ib(-2); key.y = ib(-3);
    if (key.crv == null || !key.x || !key.y) throw E("webauthn/bad-cose-key", "an EC2 COSE_Key must carry crv (-1), x (-2), and y (-3)");
    var el = EC2_CRV_LEN[key.crv];
    if (!el || key.x.length !== el || key.y.length !== el) throw E("webauthn/bad-cose-key", "an EC2 COSE_Key x/y length is inconsistent with its curve");
  } else if (kty === 1n) {
    key.crv = ii(-1) != null ? Number(ii(-1)) : null; key.x = ib(-2);
    var okp = OKP_CRV[key.crv];
    if (!okp || !key.x || key.x.length !== okp.len) throw E("webauthn/bad-cose-key", "an OKP COSE_Key must be Ed25519 (crv 6) or Ed448 (crv 7) with a matching-length x (-2)");
  } else if (kty === 3n) {
    key.n = ib(-1); key.e = ib(-2);
    if (!key.n || !key.n.length || !key.e || !key.e.length) throw E("webauthn/bad-cose-key", "an RSA COSE_Key must carry n (-1) and e (-2)");
  } else {
    throw E("webauthn/bad-cose-key", "unsupported COSE_Key kty " + Number(kty));
  }
  // A WebAuthn credential key is the CANONICAL CTAP2 COSE_Key for its type -- exactly
  // its defined parameters, nothing more: EC2 = { 1, 3, -1, -2, -3 } (5), OKP/RSA = 4.
  // Extra parameters are rejected (a padded key is a canonicalization ambiguity).
  var expectedParams = kty === 2n ? 5 : 4;
  if (node.children.length !== expectedParams) throw E("webauthn/bad-cose-key", "the COSE_Key carries parameters beyond the canonical set for its key type (WebAuthn sec. 6.5.1)");
  // Enforce the alg <-> kty/crv profile: the declared algorithm must match the key
  // type (and, for EC2, the curve) it is used with.
  var prof = ALG_PROFILE[String(key.alg)];
  if (!prof) throw E("webauthn/bad-cose-key", "unsupported credential key algorithm " + key.alg);
  if (prof.kty !== key.kty) throw E("webauthn/bad-cose-key", "credential key algorithm " + key.alg + " is inconsistent with key type " + key.kty);
  if (prof.crv != null && prof.crv !== key.crv) throw E("webauthn/bad-cose-key", "credential key algorithm " + key.alg + " requires a different curve");
  return key;
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

// DER ECDSA-Sig-Value SEQUENCE { r INTEGER, s INTEGER } -> raw r||s, each left-
// padded to `coordLen` (the ieee-p1363 form WebCrypto verify expects).
function _derEcdsaToRaw(der, coordLen, E) {
  var node;
  try { node = asn1.decode(der); } catch (e) { throw E("webauthn/bad-signature", "ECDSA signature is not a DER SEQUENCE", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length !== 2) {
    throw E("webauthn/bad-signature", "ECDSA signature must be a DER SEQUENCE { r, s }");
  }
  function coord(c) {
    // r and s MUST be primitive universal INTEGERs; a constructed child has a null
    // content buffer, so assert the shape before touching `.content` (else a crafted
    // SEQUENCE { SEQUENCE {}, SEQUENCE {} } would raw-throw instead of failing typed).
    if (c.constructed || c.tagClass !== "universal" || c.tagNumber !== asn1.TAGS.INTEGER) {
      throw E("webauthn/bad-signature", "ECDSA signature r/s must be a primitive INTEGER");
    }
    var b = c.content;
    // r and s MUST be positive: an empty INTEGER, or a DER-negative one (top bit of
    // the first content octet set, with no leading 0x00 sign octet), is not a valid
    // ECDSA signature coordinate.
    if (!b.length || (b[0] & 0x80)) throw E("webauthn/bad-signature", "ECDSA signature r/s must be a positive integer");
    while (b.length > 1 && b[0] === 0x00) b = b.subarray(1);   // strip the DER sign octet
    if (b.length === 1 && b[0] === 0x00) throw E("webauthn/bad-signature", "ECDSA signature r/s must be a positive integer");   // reject zero
    if (b.length > coordLen) throw E("webauthn/bad-signature", "ECDSA signature coordinate exceeds the curve field size");
    var out = Buffer.alloc(coordLen); b.copy(out, coordLen - b.length); return out;
  }
  return Buffer.concat([coord(node.children[0]), coord(node.children[1])]);
}

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
  var s = d.ecdsa ? _derEcdsaToRaw(sig, d.ecdsa, E) : sig;
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

// COSE EC2 / RSA credential key -> a self-contained SPKI the WebCrypto import
// consumes, so a credential public key and a certificate key verify by one path.
function _coseKeyToSpki(key, E) {
  if (key.kty === 2 && key.x && key.y) {
    var curveOid = key.crv === 1 ? "prime256v1" : key.crv === 2 ? "secp384r1" : key.crv === 3 ? "secp521r1" : null;
    if (!curveOid) throw E("webauthn/bad-cose-key", "unsupported EC2 curve " + key.crv);
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
    // OKP Ed25519 / Ed448: the SPKI is AlgorithmIdentifier { id-Ed* } (no parameters)
    // over the raw public key -- RFC 8410.
    var eb = asn1.build;
    return eb.sequence([eb.sequence([eb.oid(oid.byName(OKP_CRV[key.crv].oid))]), eb.bitString(key.x)]);
  }
  throw E("webauthn/bad-cose-key", "cannot build an SPKI for this COSE key type");
}

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
    var wantCurve = EC2_CRV_OID[cose.crv];
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

// ---- TPM structure readers (WebAuthn 8.3; TCG TPM 2.0 Part 2) ----------------
// Every field is unsigned big-endian, packed with no padding; every TPM2B_* is a
// UINT16 size followed by exactly `size` bytes. The bare certInfo (TPMS_ATTEST) and
// pubArea (TPMT_PUBLIC) carry NO outer TPM2B size prefix.
var TPM_GENERATED_VALUE = 0xff544347;
var TPM_ST_ATTEST_CERTIFY = 0x8017;
var TPM_ALG = { RSA: 0x0001, SHA1: 0x0004, SHA256: 0x000b, SHA384: 0x000c, SHA512: 0x000d, NULL: 0x0010, ECC: 0x0023 };
var TPM_ALG_HASH = {}; TPM_ALG_HASH[TPM_ALG.SHA1] = "sha1"; TPM_ALG_HASH[TPM_ALG.SHA256] = "sha256"; TPM_ALG_HASH[TPM_ALG.SHA384] = "sha384"; TPM_ALG_HASH[TPM_ALG.SHA512] = "sha512";
// TPM_ECC_CURVE -> COSE crv (the codepoints differ; this is a mapping, not equality).
var TPM_CURVE_TO_COSE = {}; TPM_CURVE_TO_COSE[0x0003] = 1; TPM_CURVE_TO_COSE[0x0004] = 2; TPM_CURVE_TO_COSE[0x0005] = 3;

function _tpmReader(buf) { return new ByteReader(buf, 0, buf.length, WebauthnError, "webauthn/bad-tpm"); }

// TPMT_PUBLIC (WebAuthn 8.3 item 17-20): decode type/nameAlg + the public key in
// `unique`, walking past `parameters` per the algorithm union.
function _parseTpmPubArea(buf) {
  var r = _tpmReader(buf);
  var type = r.u16(), nameAlg = r.u16();
  r.u32();                       // objectAttributes (full policy validation deferred)
  r.vector(2, 0, null);          // authPolicy TPM2B_DIGEST
  var pub = { type: type, nameAlg: nameAlg, nameAlgBytes: buf.subarray(2, 4) };
  if (type === TPM_ALG.RSA) {
    _tpmSymDef(r);               // symmetric TPMT_SYM_DEF_OBJECT
    _tpmScheme(r);               // scheme TPMT_RSA_SCHEME
    r.u16();                     // keyBits
    var exp = r.u32();           // exponent (0 => default 65537)
    pub.exponent = exp === 0 ? 65537 : exp;
    pub.rsa = r.vector(2, 0, null);   // unique TPM2B_PUBLIC_KEY_RSA (the modulus)
  } else if (type === TPM_ALG.ECC) {
    _tpmSymDef(r);               // symmetric
    _tpmScheme(r);               // scheme TPMT_ECC_SCHEME
    pub.curveId = r.u16();       // curveID TPMI_ECC_CURVE
    _tpmScheme(r);               // kdf TPMT_KDF_SCHEME
    pub.x = r.vector(2, 0, null);     // unique.ecc.x TPM2B_ECC_PARAMETER
    pub.y = r.vector(2, 0, null);     // unique.ecc.y TPM2B_ECC_PARAMETER
  } else {
    throw _err("webauthn/bad-tpm", "unsupported TPMT_PUBLIC type 0x" + type.toString(16));
  }
  // TPMT_PUBLIC ends with `unique`; trailing bytes mean a malformed pubArea (and
  // would perturb the TPM Name hash), so fail closed rather than silently ignore them.
  if (!r.atEnd()) throw _err("webauthn/bad-tpm", "pubArea has trailing bytes after the unique field (WebAuthn 8.3)");
  return pub;
}
// TPMT_SYM_DEF_OBJECT: algorithm UINT16; when not NULL, keyBits+mode follow. An
// attestation (restricted signing) key is NULL, so the non-NULL arm is defensive.
function _tpmSymDef(r) { if (r.u16() !== TPM_ALG.NULL) { r.u16(); r.u16(); } }
// TPMT_*_SCHEME / TPMT_KDF_SCHEME: scheme UINT16; when not NULL, a TPMS_SCHEME_HASH
// (a single UINT16 hashAlg) follows for the signing/kdf schemes in scope.
function _tpmScheme(r) { if (r.u16() !== TPM_ALG.NULL) { r.u16(); } }

// TPMS_ATTEST (WebAuthn 8.3 item 13-15): magic/type + extraData + attested.name.
// The whole certInfo is walked -- through qualifiedName and to the end -- so a
// certInfo with trailing bytes past the TPMS_CERTIFY_INFO union fails closed.
function _parseTpmCertInfo(buf) {
  var r = _tpmReader(buf);
  var magic = r.u32(), type = r.u16();
  r.vector(2, 0, null);          // qualifiedSigner TPM2B_NAME
  var extraData = r.vector(2, 0, null);   // extraData TPM2B_DATA
  r.u64(); r.u32(); r.u32(); r.u8();      // clockInfo TPMS_CLOCK_INFO (17 bytes)
  r.u64();                       // firmwareVersion
  var name = r.vector(2, 0, null);        // attested.name TPM2B_NAME (nameAlg||H)
  r.vector(2, 0, null);          // attested.qualifiedName TPM2B_NAME
  if (!r.atEnd()) throw _err("webauthn/bad-tpm", "certInfo has trailing bytes after the attested structure (WebAuthn 8.3)");
  return { magic: magic, type: type, extraData: extraData, attestedName: name };
}

// ---- extension helpers -------------------------------------------------------
// `oidName` is a registered name (byName resolves it at call time); an unregistered
// name is a programming error that surfaces as an undefined target, never swallowed.
function _findExt(cert, oidName) {
  var target = oid.byName(oidName);
  return (cert.extensions || []).filter(function (e) { return e.oid === target; })[0] || null;
}
// AuthorizationList (Android key attestation) is a SEQUENCE of [tag] EXPLICIT
// OPTIONAL fields with non-contiguous tag numbers; return the EXPLICIT-unwrapped
// value node for a tag, or null when absent (a tolerant, skip-unknown scan).
function _alGet(seqNode, tag) {
  if (!seqNode || !seqNode.children) return null;
  for (var i = 0; i < seqNode.children.length; i++) {
    var c = seqNode.children[i];
    if (c.tagClass === "context" && c.tagNumber === tag) return c.children && c.children[0] ? c.children[0] : c;
  }
  return null;
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
function _readX5c(attStmt) {
  var x5cN = _mapGet(attStmt, "x5c");
  if (!x5cN || x5cN.majorType !== 4 || !x5cN.children || !x5cN.children.length) throw _err("webauthn/bad-att-stmt", "x5c must be a non-empty array of certificates");
  return x5cN.children.map(function (c) {
    var der;
    try { der = cbor.read.byteString(c); } catch (e) { throw _err("webauthn/bad-att-stmt", "an x5c entry must be a byte string", e); }
    try { return x509.parse(der); } catch (e) { throw _err("webauthn/bad-att-stmt", "an x5c certificate is not a well-formed X.509 certificate", e); }
  });
}
// Every attestation leaf cert MUST be an X.509 v3 certificate (WebAuthn 8.2.1 /
// 8.3.1 / 8.4). The chain to a trust anchor is the caller's to run through
// pki.path.validate with a supplied root; a bare chain is surfaced in trustPath.
function _requireV3(cert) {
  if (cert.version !== 3) throw _err("webauthn/bad-att-cert", "an attestation certificate must be X.509 version 3");
}
// A packed / tpm attestation LEAF certificate MUST carry a basicConstraints
// extension asserting cA=false (WebAuthn 8.2.1 / 8.3.1). Requiring the extension --
// not merely rejecting a present cA=true -- is the gate that stops a genuine CA
// certificate under the caller's pinned root, or a leaf that simply omits the
// constraint, from being repurposed as an attestation leaf; RFC 5280 path validation
// does not reject a CA-asserting or unconstrained leaf.
function _assertNotCa(cert) {
  var bc = _decodeExt(cert, "basicConstraints");
  if (!bc) throw _err("webauthn/bad-att-cert", "an attestation leaf certificate MUST carry a basicConstraints extension (WebAuthn 8.2.1 / 8.3.1)");
  if (bc.value && bc.value.cA === true) throw _err("webauthn/bad-att-cert", "an attestation leaf certificate MUST NOT be a CA (basicConstraints cA=true)");
}
// Packed attestation certificate requirements (WebAuthn 8.2.1): v3, non-CA, and the
// subject set to C (country), O (organization), OU = "Authenticator Attestation",
// and CN (a vendor string).
function _checkPackedCert(cert) {
  _requireV3(cert);
  _assertNotCa(cert);
  var have = {};
  (cert.subject.rdns || []).forEach(function (rdn) { rdn.forEach(function (a) { have[a.type] = a.value; }); });
  if (have[oid.byName("countryName")] == null || have[oid.byName("organizationName")] == null || have[oid.byName("commonName")] == null) {
    throw _err("webauthn/bad-att-cert", "the packed attestation certificate subject MUST set C, O, OU, and CN (WebAuthn 8.2.1)");
  }
  if (have[oid.byName("organizationalUnitName")] !== "Authenticator Attestation") {
    throw _err("webauthn/bad-att-cert", "the packed attestation certificate subject OU MUST be \"Authenticator Attestation\" (WebAuthn 8.2.1)");
  }
}
var AAGUID_EXT_OID = oid.byName("idFidoGenCeAaguid");   // a registered name, resolved at load
// The id-fido-gen-ce-aaguid extension value (when present) MUST equal the
// attestedCredentialData aaguid, and it MUST NOT be critical (WebAuthn 8.2.1).
function _checkAaguidExt(cert, aaguid) {
  var ext = (cert.extensions || []).filter(function (e) { return e.oid === AAGUID_EXT_OID; })[0];
  if (!ext) return;   // absence is tolerated; presence must match
  if (ext.critical) throw _err("webauthn/bad-att-cert", "the id-fido-gen-ce-aaguid extension MUST NOT be critical (WebAuthn 8.2.1)");
  var val;
  try { val = asn1.read.octetString(asn1.decode(ext.value)); }
  catch (e) { throw _err("webauthn/bad-att-cert", "the id-fido-gen-ce-aaguid extension value is not a valid OCTET STRING", e); }
  if (!val.equals(aaguid)) throw _err("webauthn/aaguid-mismatch", "the id-fido-gen-ce-aaguid extension value does not equal the authenticatorData aaguid");
}

var VERIFIERS = {
  // packed (WebAuthn 8.2): the x5c arm (Basic/AttCA) or self-attestation.
  packed: function (att, clientDataHash) {
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var message = Buffer.concat([att.authDataBytes, clientDataHash]);
    if (_mapGet(att.attStmt, "x5c")) {
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
    var spki = _coseKeyToSpki(att.authData.credentialPublicKey, _err);
    return _verifySig(alg, sig, spki, message, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the packed self-attestation signature does not verify under the credential key");
      return _result("packed", "Self", [], att);
    });
  },

  // fido-u2f (WebAuthn 8.6): reconstruct the U2F verificationData and verify with
  // the single x5c cert. The credential key MUST be EC2/P-256.
  "fido-u2f": function (att, clientDataHash) {
    var chain = _readX5c(att.attStmt);
    if (chain.length !== 1) throw _err("webauthn/bad-att-stmt", "fido-u2f x5c MUST contain exactly one certificate (WebAuthn 8.6)");
    // WebAuthn 8.6 does not require a version-3 certificate for fido-u2f (unlike the
    // packed 8.2.1 / tpm 8.3.1 leaves), so a legacy v1 U2F attestation cert is valid.
    var leaf = chain[0];
    var sig = _sigOf(att.attStmt);
    var key = att.authData.credentialPublicKey;
    if (key.kty !== 2 || key.crv !== 1 || !key.x || !key.y || key.x.length !== 32 || key.y.length !== 32) {
      throw _err("webauthn/bad-att-stmt", "fido-u2f requires an EC2 P-256 credential public key (WebAuthn 8.6)");
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
    var verN = _mapGet(att.attStmt, "ver");
    if (!verN || verN.majorType !== 3 || cbor.read.textString(verN) !== "2.0") throw _err("webauthn/bad-att-stmt", "tpm attestation 'ver' MUST be \"2.0\" (WebAuthn 8.3)");
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var pubAreaBytes = _attRead(att.attStmt, "pubArea", cbor.read.byteString, "a byte string");
    var certInfoBytes = _attRead(att.attStmt, "certInfo", cbor.read.byteString, "a byte string");
    var chain = _readX5c(att.attStmt), aik = chain[0];
    _requireV3(aik);

    var pub = _parseTpmPubArea(pubAreaBytes);
    _tpmPubKeyEqualsCose(pub, att.authData.credentialPublicKey);   // 8.3 item 22

    var certInfo = _parseTpmCertInfo(certInfoBytes);
    if (certInfo.magic !== TPM_GENERATED_VALUE) throw _err("webauthn/bad-tpm", "certInfo magic is not TPM_GENERATED_VALUE (WebAuthn 8.3)");
    if (certInfo.type !== TPM_ST_ATTEST_CERTIFY) throw _err("webauthn/bad-tpm", "certInfo type is not TPM_ST_ATTEST_CERTIFY (WebAuthn 8.3)");

    // extraData == hash_alg(authData || clientDataHash) (bare digest, no method id).
    var attToBeSigned = Buffer.concat([att.authDataBytes, clientDataHash]);
    if (!certInfo.extraData.equals(_sha(_coseAlgHash(alg, _err), attToBeSigned))) throw _err("webauthn/verify-failed", "certInfo extraData does not equal the hash of authData || clientDataHash");

    // attested.name == nameAlg || H_nameAlg(pubArea).
    var nameHash = TPM_ALG_HASH[pub.nameAlg];
    if (!nameHash) throw _err("webauthn/bad-tpm", "unsupported TPM nameAlg 0x" + pub.nameAlg.toString(16));
    var computedName = Buffer.concat([pub.nameAlgBytes, _sha(nameHash, pubAreaBytes)]);
    if (!certInfo.attestedName.equals(computedName)) throw _err("webauthn/verify-failed", "certInfo attested Name does not match the pubArea TPM Name");

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

// pubArea public key == credentialPublicKey (unsigned compare; WebAuthn 8.3 item 22).
function _tpmPubKeyEqualsCose(pub, cose) {
  if (pub.type === TPM_ALG.ECC) {
    if (cose.kty !== 2 || TPM_CURVE_TO_COSE[pub.curveId] !== cose.crv || !_ucmp(pub.x, cose.x || Buffer.alloc(0)) || !_ucmp(pub.y, cose.y || Buffer.alloc(0))) {
      throw _err("webauthn/key-mismatch", "the TPM pubArea EC key does not equal the credential public key");
    }
    return;
  }
  if (pub.type === TPM_ALG.RSA) {
    // Compare the exponent as an unsigned integer over its FULL width (a UINT32 up to
    // 0xFFFFFFFF); a fixed 3-byte re-encode would silently truncate an exponent
    // > 0xFFFFFF and let a mismatched key pass (WebAuthn 8.3 item 22).
    var e = _uintBytes(pub.exponent >>> 0);
    if (cose.kty !== 3 || !_ucmp(pub.rsa, cose.n || Buffer.alloc(0)) || !_ucmp(e, cose.e || Buffer.alloc(0))) {
      throw _err("webauthn/key-mismatch", "the TPM pubArea RSA key does not equal the credential public key");
    }
    return;
  }
  throw _err("webauthn/bad-tpm", "unsupported TPM pubArea key type");
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

// The four Android KeyDescription checks (WebAuthn 8.4.1 item 28).
function _checkAndroidKeyDescription(cert, clientDataHash) {
  var ext = _findExt(cert, "keyDescription");
  if (!ext) throw _err("webauthn/bad-att-cert", "the android-key attestation certificate is missing the key-description extension (WebAuthn 8.4.1)");
  var kd;
  try { kd = asn1.decode(ext.value); } catch (e) { throw _err("webauthn/bad-att-cert", "the android KeyDescription is not decodable", e); }
  if (!kd.children || kd.children.length < 8) throw _err("webauthn/bad-att-cert", "the android KeyDescription is not a positional 8-field SEQUENCE");
  // (1) attestationChallenge (position 4) == clientDataHash.
  var challenge;
  try { challenge = asn1.read.octetString(kd.children[4]); } catch (e) { throw _err("webauthn/bad-att-cert", "the android attestationChallenge is not an OCTET STRING", e); }
  if (!challenge.equals(clientDataHash)) throw _err("webauthn/verify-failed", "the android attestationChallenge does not equal clientDataHash");
  var softwareEnforced = kd.children[6], hardwareEnforced = kd.children[7];
  // (2) [600] allApplications MUST be ABSENT in both lists.
  if (_alGet(softwareEnforced, 600) || _alGet(hardwareEnforced, 600)) throw _err("webauthn/verify-failed", "android allApplications MUST be absent (WebAuthn 8.4.1)");
  // (3)+(4) origin == KM_ORIGIN_GENERATED (0) and purpose == exactly {KM_PURPOSE_SIGN}
  // (2), evaluated over the UNION of the teeEnforced and softwareEnforced lists --
  // the WebAuthn 8.4.1 default (a teeEnforced-only policy is the caller's opt-in).
  // Origin: at least one list MUST declare it, and EVERY list that declares one MUST
  // say GENERATED -- a mixed teeEnforced=IMPORTED / softwareEnforced=GENERATED key is
  // contradictory and rejected, not accepted on the strength of one list.
  var origins = [_alGet(softwareEnforced, 702), _alGet(hardwareEnforced, 702)].filter(Boolean);
  if (!origins.length || !origins.every(function (o) { return asn1.read.integer(o) === 0n; })) {
    throw _err("webauthn/verify-failed", "android key origin is not KM_ORIGIN_GENERATED in every authorization list that declares it (WebAuthn 8.4.1)");
  }
  var purposes = _purposeUnion(softwareEnforced, hardwareEnforced);
  if (purposes.length !== 1 || purposes[0] !== 2n) {
    throw _err("webauthn/verify-failed", "android key purpose is not exactly KM_PURPOSE_SIGN (WebAuthn 8.4.1)");
  }
}
// The union of the [1] purpose (SET OF INTEGER) values across both authorization
// lists -- an attestation key MUST be usable for SIGN and nothing else.
function _purposeUnion(a, b) {
  var out = [];
  [a, b].forEach(function (list) {
    var p = _alGet(list, 1);
    if (p && p.children) p.children.forEach(function (c) { var v = asn1.read.integer(c); if (out.indexOf(v) === -1) out.push(v); });
  });
  return out;
}

// AIK-certificate requirements (WebAuthn 8.3.1): non-CA, an empty subject, the tcg
// AIK-certificate EKU, and the tcg tpmManufacturer/tpmModel/tpmVersion subjectAltName
// directory attributes.
function _checkAikCert(cert) {
  _assertNotCa(cert);
  if ((cert.subject.rdns || []).length !== 0) throw _err("webauthn/bad-att-cert", "the tpm AIK certificate subject MUST be empty (WebAuthn 8.3.1)");
  var eku = _decodeExt(cert, "extKeyUsage");
  if (!eku || !Array.isArray(eku.value) || eku.value.indexOf(oid.byName("tcgKpAikCertificate")) === -1) {
    throw _err("webauthn/bad-att-cert", "the tpm AIK certificate lacks the tcg-kp-AIKCertificate extended key purpose (WebAuthn 8.3.1)");
  }
  var san = _decodeExt(cert, "subjectAltName");
  var dirName = san && san.value && san.value.names && san.value.names.filter(function (n) { return n.tagNumber === 4; })[0];
  var types = {};
  if (dirName && dirName.value && dirName.value.rdns) {
    dirName.value.rdns.forEach(function (rdn) { rdn.forEach(function (a) { types[a.type] = true; }); });
  }
  if (!types[oid.byName("tpmManufacturer")] || !types[oid.byName("tpmModel")] || !types[oid.byName("tpmVersion")]) {
    throw _err("webauthn/bad-att-cert", "the tpm AIK certificate subjectAltName lacks the required tcg attributes (WebAuthn 8.3.1)");
  }
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
