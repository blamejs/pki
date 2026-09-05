// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.webauthn
 * @nav        Validation
 * @title      WebAuthn
 * @fullname   WebAuthn: verify registration attestation and assertions
 * @intro Trust evaluation of a W3C WebAuthn (Level 3) / passkey attestation: parse
 *   the attestation object + authenticatorData, decode the COSE credential public
 *   key, and verify each defined attestation-statement format (packed, tpm,
 *   android-key, apple, fido-u2f, none, compound, and android-safetynet behind an
 *   opt-in): the attestation-statement signature and each format's structural
 *   bindings. The attestation CBOR is decoded by the strict,
 *   fail-closed `pki.cbor` codec (WebAuthn keys are CTAP2-canonical), the signature by
 *   `pki.webcrypto`. Chaining the returned x5c trust path to a caller-pinned root via
 *   `pki.path.validate` is the caller's step: this module verifies the statement, not
 *   the certificate chain. A verifier, not a ceremony client: the relying party
 *   supplies the clientDataHash + any trust anchors; this module never touches a
 *   socket. Fail-closed: every malformed shape or failed check throws a typed
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
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var jose = require("./jose");
var mds = require("./webauthn-mds");
var nodeCrypto = require("crypto");

var WebauthnError = frameworkError.WebauthnError;
function _err(code, message, cause) { return new WebauthnError(code, message, cause); }
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

function _sha(name, buf) { return nodeCrypto.createHash(name).update(buf).digest(); }
function _ucmp(a, b) {
  function strip(x) { var i = 0; while (i < x.length - 1 && x[i] === 0) i++; return x.subarray(i); }
  return Buffer.compare(strip(a), strip(b)) === 0;
}
function _isInteger(node) { return !!node && !node.constructed && node.tagClass === "universal" && node.tagNumber === asn1.TAGS.INTEGER; }
var COSE_ALG_HASH = { "-7": "sha256", "-9": "sha256", "-257": "sha256", "-37": "sha256", "-35": "sha384", "-51": "sha384", "-258": "sha384", "-38": "sha384", "-36": "sha512", "-52": "sha512", "-259": "sha512", "-39": "sha512", "-65535": "sha1" };
function _coseAlgHash(alg, E) {
  var h = COSE_ALG_HASH[String(alg)];
  if (!h) throw E("webauthn/unsupported-algorithm", "no hash mapping for COSE algorithm " + alg);
  return h;
}


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
  if (out.flags.bs && !out.flags.be) throw E("webauthn/bad-auth-data", "authenticatorData sets Backup State (BS) without Backup Eligibility (BE) (WebAuthn sec. 6.1)");
  if (flags & 0x22) throw E("webauthn/bad-auth-data", "authenticatorData sets a reserved (RFU) flag bit (WebAuthn sec. 6.1)");
  var off = 37;
  if (out.flags.at) {
    if (buf.length < off + AAGUID_LEN + 2) throw E("webauthn/bad-auth-data", "attestedCredentialData is truncated before the credentialId length");
    out.aaguid = buf.subarray(off, off + AAGUID_LEN); off += AAGUID_LEN;
    var credLen = buf.readUInt16BE(off); off += 2;
    if (credLen < 1 || credLen > 1023) throw E("webauthn/bad-credential-id", "credentialIdLength " + credLen + " is outside 1..1023 (RFC WebAuthn sec. 6.1)");
    if (buf.length < off + credLen) throw E("webauthn/bad-auth-data", "credentialId overruns authenticatorData");
    out.credentialId = buf.subarray(off, off + credLen); off += credLen;
    var keyNode;
    try { keyNode = cbor.decode(buf.subarray(off), { allowTrailing: true }); }
    catch (e) { throw E("webauthn/bad-cose-key", "the credential public key is not well-formed CBOR", e); }
    out.credentialPublicKeyBytes = buf.subarray(off, off + keyNode.bytes.length);
    out.credentialPublicKey = _decodeCoseKey(keyNode);
    off += keyNode.bytes.length;
  }
  if (out.flags.ed) {
    var extNode;
    try { extNode = cbor.decode(buf.subarray(off)); }
    catch (e) { throw E("webauthn/bad-auth-data", "the authenticatorData extensions are not a single well-formed CBOR map", e); }
    if (extNode.majorType !== 5) throw E("webauthn/bad-auth-data", "the authenticatorData extensions must be a CBOR map");
    out.extensions = buf.subarray(off);
  } else if (off < buf.length) {
    throw E("webauthn/bad-auth-data", "authenticatorData has trailing bytes after attestedCredentialData with the ED flag clear");
  }
  return out;
}


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
 * Decode a bare COSE_Key, the credential public key a relying party stored at
 * registration, back into the object `verifyAssertion` takes. `pki.webauthn.verify`
 * returns that object, but the durable form is bytes: the object carries `Buffer`
 * values, so a JSON round trip through a datastore yields
 * `{"type":"Buffer","data":[...]}` in place of the object that went in, and existing
 * credential stores already hold COSE bytes whoever wrote them. Without this the only
 * routes into the decoder were `parseAttestationObject` and `parseAuthenticatorData`,
 * both of which parse a containing structure, so recovering a stored key meant
 * fabricating an authenticatorData that never existed.
 *
 * The same validation the attestation path applies: the key type, the algorithm, the
 * curve, and the coordinates are checked, and anything that is not a credential COSE
 * key is refused with `webauthn/bad-cose-key`. `verifyAssertion` accepts either form
 * for `credentialPublicKey`, so calling this first is a convenience, not a required step.
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


var COSE_ALG = {
  "-7":   { imp: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, ecdsa: 32 },
  "-35":  { imp: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" }, ecdsa: 48 },
  "-36":  { imp: { name: "ECDSA", namedCurve: "P-521" }, verify: { name: "ECDSA", hash: "SHA-512" }, ecdsa: 66 },
  "-8":   { imp: { name: "Ed25519" }, verify: { name: "Ed25519" }, ecdsa: 0 },
  "-9":   { imp: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, ecdsa: 32 },
  "-51":  { imp: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" }, ecdsa: 48 },
  "-52":  { imp: { name: "ECDSA", namedCurve: "P-521" }, verify: { name: "ECDSA", hash: "SHA-512" }, ecdsa: 66 },
  "-19":  { imp: { name: "Ed25519" }, verify: { name: "Ed25519" }, ecdsa: 0 },
  "-53":  { imp: { name: "Ed448" }, verify: { name: "Ed448" }, ecdsa: 0 },
  "-257": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
  "-258": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
  "-259": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
  "-37":  { imp: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 }, ecdsa: 0 },
  "-38":  { imp: { name: "RSA-PSS", hash: "SHA-384" }, verify: { name: "RSA-PSS", saltLength: 48 }, ecdsa: 0 },
  "-39":  { imp: { name: "RSA-PSS", hash: "SHA-512" }, verify: { name: "RSA-PSS", saltLength: 64 }, ecdsa: 0 },
  "-65535": { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, verify: { name: "RSASSA-PKCS1-v1_5" }, ecdsa: 0 },
};

function _derEcdsaToRaw(der, curve) { return validator.sig.ecdsaDerToP1363(der, curve, WebauthnError, "webauthn/bad-signature"); }

function _verifySig(alg, sig, spkiBytes, message, E) {
  var d = COSE_ALG[String(alg)];
  if (!d) throw _err("webauthn/unsupported-algorithm", "unsupported COSE algorithm " + alg);
  var imp = d.imp, ver = d.verify;
  if (alg === -8) { var nm = _edName(spkiBytes, E); imp = { name: nm }; ver = { name: nm }; }
  if (imp.name === "Ed25519" || imp.name === "Ed448") _requireValidEdPoint(spkiBytes, imp.name);
  var s = d.ecdsa ? _derEcdsaToRaw(sig, d.imp.namedCurve) : sig;
  return subtle.importKey("spki", spkiBytes, imp, false, ["verify"])
    .then(function (key) { return subtle.verify(ver, key, s, message); })
    .catch(function (e) { throw _err("webauthn/verify-error", "the attestation signature could not be evaluated", e); });
}
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
function _requireValidEdPoint(spkiBytes, name) {
  edwardsPoint.validateSpki(spkiBytes, name === "Ed25519" ? 6 : 7, WebauthnError, "webauthn/bad-signature");
}

function _coseKeyToSpki(key) { return validator.cose.toSpki(key, WebauthnError, "webauthn/bad-cose-key"); }

function _certEcCurveOid(cert, E) {
  var params = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.algorithm && cert.subjectPublicKeyInfo.algorithm.parameters;
  if (!Buffer.isBuffer(params)) throw E("webauthn/key-mismatch", "the attestation certificate EC key carries no named-curve parameters");
  try { return asn1.read.oid(asn1.decode(params)); }
  catch (e) { throw E("webauthn/key-mismatch", "the attestation certificate EC curve is not a valid OBJECT IDENTIFIER", e); }
}
function _certKeyAlgNames(cose) {
  if (cose.kty === 2) return ["ecPublicKey"];
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
function _certPubKeyEqualsCose(cert, cose, E) {
  var raw = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.publicKey && cert.subjectPublicKeyInfo.publicKey.bytes;
  if (!raw) throw E("webauthn/key-mismatch", "the attestation certificate exposes no public key");
  _assertCertKeyAlgorithm(cert, cose, E);
  if (cose.kty === 2) {
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
    if (!seq.children || seq.children.length !== 2 || !_isInteger(seq.children[0]) || !_isInteger(seq.children[1])) {
      throw E("webauthn/key-mismatch", "the attestation certificate RSA key is malformed");
    }
    var n = seq.children[0].content, ee = seq.children[1].content;
    if (!cose.n || !cose.e || !_ucmp(n, cose.n) || !_ucmp(ee, cose.e)) throw E("webauthn/key-mismatch", "the attestation certificate RSA key does not equal the credential public key");
    return;
  }
  if (cose.kty === 1) {
    if (!cose.x || !Buffer.from(raw).equals(cose.x)) throw E("webauthn/key-mismatch", "the attestation certificate OKP key does not equal the credential public key");
    return;
  }
  throw E("webauthn/key-mismatch", "unsupported credential key type for the certificate comparison");
}

function _parseTpmPubArea(buf) { return validator.tpm.parsePubArea(buf, WebauthnError, "webauthn/bad-tpm"); }
function _parseTpmCertInfo(buf) { return validator.tpm.parseCertInfo(buf, WebauthnError, "webauthn/bad-tpm"); }
function _tpmPubKeyEqualsCose(pub, cose) { validator.tpm.pubKeyEqualsCose(pub, cose, WebauthnError, "webauthn/key-mismatch", "webauthn/bad-tpm"); }

function _findExt(cert, oidName) {
  var target = oid.byName(oidName);
  return (cert.extensions || []).filter(function (e) { return e.oid === target; })[0] || null;
}


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
 * is the raw authenticatorData, the exact bytes an attestation signature covers.
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
  if (root.children.length !== 3 || !fmtN || !attStmtN || !authDataN) throw _err("webauthn/bad-attestation-object", "the attestation object must be exactly { fmt, attStmt, authData }");
  if (fmtN.majorType !== 3) throw _err("webauthn/bad-attestation-object", "attestation object 'fmt' must be a text string");
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


function _reqAttr(map, key) {
  var n = cbor.read.mapGet(map, key);
  if (!n) throw _err("webauthn/bad-att-stmt", "the attestation statement is missing the '" + key + "' field");
  return n;
}
function _attRead(map, key, reader, what) {
  var n = _reqAttr(map, key);
  try { return reader(n); }
  catch (e) { throw _err("webauthn/bad-att-stmt", "the attestation statement '" + key + "' must be " + what, e); }
}
function _algOf(attStmt) { return Number(_attRead(attStmt, "alg", cbor.read.int, "an integer")); }
function _sigOf(attStmt) { return _attRead(attStmt, "sig", cbor.read.byteString, "a byte string"); }
function _requireAttShape(attStmt, allowed, required) {
  var have = {};
  cbor.read.map(attStmt).forEach(function (kv) {
    if (kv[0].majorType !== 3) throw _err("webauthn/bad-att-stmt", "the attestation statement has a non-text-string field key");
    have[cbor.read.textString(kv[0])] = true;
  });
  Object.keys(have).forEach(function (k) { if (allowed.indexOf(k) === -1) throw _err("webauthn/bad-att-stmt", "the attestation statement carries an unexpected field '" + k + "'"); });
  required.forEach(function (k) { if (!have[k]) throw _err("webauthn/bad-att-stmt", "the attestation statement is missing the '" + k + "' field"); });
}
var ATT_STMT_MAJOR = { compound: 4 };

var _AAGUID_SIGNED_BY_FMT = Object.assign(Object.create(null), { "fido-u2f": false });
function _aaguidIsSigned(fmt) { return _AAGUID_SIGNED_BY_FMT[fmt] !== false; }

var _VERIFY_OPTS = Object.assign(Object.create(null), {
  time: 1, metadata: 1, tpmPolicy: 1, safetyNetRoots: 1, verifySafetyNetJws: 1, requireCtsProfileMatch: 1,
  expectedRpId: 1, requireUserPresence: 1, requireUserVerification: 1, allowedAlgorithms: 1,
  rootCertificates: 1,
  clientDataJSON: 1, expectedChallenge: 1, expectedOrigin: 1, expectedTopOrigin: 1,
});

var _FORMAT_SCOPED_BOOLEAN_OPTS = ["verifySafetyNetJws", "requireCtsProfileMatch"];

function _cloneParsed(v, depth) {
  if (depth > 64) throw _err("webauthn/bad-input", "opts.rootCertificates[] is nested too deeply to be a parsed certificate");
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, _err, "webauthn/bad-input", "a byte field of opts.rootCertificates[]");
  if (Array.isArray(v)) return v.map(function (x) { return _cloneParsed(x, depth + 1); });
  if (guard.time.isDate(v)) return new Date(guard.time.instantOf(v));
  if (v && typeof v === "object") {
    var out = {};
    Object.keys(v).forEach(function (k) { out[k] = _cloneParsed(v[k], depth + 1); });
    return out;
  }
  return v;
}

function _isBufferSource(v) { return guard.bytes.isByteSource(v); }
function _bytesArg(v, label) {
  if (_isBufferSource(v)) {
    return guard.bytes.snapshotSource(v, WebauthnError, "webauthn/bad-input", label);
  }
  throw _err("webauthn/bad-input", label + " must be a BufferSource (a Buffer, a typed-array view, or an ArrayBuffer)");
}

function _snapshotRoots(supplied) {
  if (!Array.isArray(supplied)) return supplied;
  return supplied.map(function (root) {
    if (_isBufferSource(root)) {
      return guard.bytes.snapshotSource(root, WebauthnError, "webauthn/bad-input", "opts.rootCertificates[]");
    }
    return root;
  });
}

function _applyCallerRoots(res, supplied, vopts, onlyPaths) {
  if (!Array.isArray(supplied) || !supplied.length) {
    throw _err("webauthn/bad-input", "opts.rootCertificates must be a non-empty array of root certificates (DER, PEM, or parsed)");
  }
  var roots = supplied.map(function (root, i) {
    var label = "opts.rootCertificates[" + i + "]";
    return guard.parsed.acceptDerived(root, "certificate", function (bytes) {
      try {
        return x509.parse(_isBufferSource(bytes) ? guard.bytes.source(bytes, WebauthnError, "webauthn/bad-input", label) : bytes);
      } catch (e) { throw _err("webauthn/bad-input", label + " is not a decodable certificate", e); }
    }, _err, "webauthn/bad-input", label);
  });
  var paths = onlyPaths || ((res.fmt === "compound" && Array.isArray(res.compound))
    ? res.compound.filter(function (el) { return el.trustPath && el.trustPath.length; })
      .map(function (el) { return { tp: el.trustPath, at: el.chainValidatedAt }; })
    : (res.trustPath && res.trustPath.length ? [{ tp: res.trustPath, at: res.chainValidatedAt }] : []));
  if (!onlyPaths) {
    res = guard.verdict.of(res, { anchoredElements: { total: (res.fmt === "compound" && Array.isArray(res.compound)) ? res.compound.length : 1,
      anchored: paths.length } });
  }
  if (!paths.length) {
    throw _err("webauthn/anchor-not-applicable",
      "opts.rootCertificates was supplied, but this attestation carries no trust path to anchor (format '" + res.fmt + "')");
  }
  var at = vopts.time !== undefined ? vopts.time : new Date();
  return paths.reduce(function (p, info) {
    return p.then(function () {
      var pathAt = vopts.time !== undefined ? vopts.time : (info.at || at);
      return mds.chainToAnchor(info.tp.slice().reverse(), roots, pathAt,
        "attestation trust path (against the roots supplied as opts.rootCertificates)");
    });
  }, Promise.resolve()).then(function () {
    return guard.verdict.of(res, { anchoredTo: _anchoredRoutes(res, "rootCertificates") });
  });
}

function _safetyNetAnchored(res) {
  if (res.fmt === "android-safetynet") return 1;
  if (res.fmt === "compound" && Array.isArray(res.compound)) {
    return res.compound.filter(function (el) { return el && el.fmt === "android-safetynet"; }).length;
  }
  return 0;
}

function _anchoredRoutes(res, base) {
  var routes = base ? base.split("+") : [];
  if (_safetyNetAnchored(res) && routes.indexOf("safetyNetRoots") < 0) routes.push("safetyNetRoots");
  return routes.length ? routes.join("+") : null;
}

function _assertBool(v, name) {
  if (typeof v !== "boolean") throw _err("webauthn/bad-input", "opts." + name + " must be a boolean");
}

function _applyBindings(authData, coseKey, opts) {
  var checked = { rpId: false, userPresence: false, userVerification: false, algorithm: false };
  if (opts.expectedRpId !== undefined) {
    if (typeof opts.expectedRpId !== "string" || !opts.expectedRpId.length) {
      throw _err("webauthn/bad-input", "opts.expectedRpId must be a non-empty RP ID string");
    }
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
  var alg65535Allowed = Array.isArray(opts.allowedAlgorithms) && opts.allowedAlgorithms.indexOf(-65535) !== -1;
  if (coseKey && coseKey.alg === -65535 && !alg65535Allowed) {
    throw _err("webauthn/algorithm-not-allowed",
      "the credential public key declares COSE algorithm -65535 (RSASSA-PKCS1-v1_5 with SHA-1); every " +
      "signature made by this credential would use SHA-1, so it is refused unless opts.allowedAlgorithms " +
      "names -65535 explicitly");
  }
  if (opts.allowedAlgorithms !== undefined) {
    if (!Array.isArray(opts.allowedAlgorithms) || !opts.allowedAlgorithms.length ||
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
var _exts = { find: _findExt, decode: _decodeExt };
function _requireV3(cert) { validator.attcert.requireV3(cert, WebauthnError, "webauthn/bad-att-cert"); }
function _checkPackedCert(cert) { validator.attcert.packedCert(cert, _exts, WebauthnError, "webauthn/bad-att-cert"); }
function _checkAikCert(cert) { validator.attcert.aikCert(cert, _exts, WebauthnError, "webauthn/bad-att-cert"); }
function _checkAaguidExt(cert, aaguid) { validator.attcert.aaguidExt(cert, aaguid, _exts, WebauthnError, "webauthn/bad-att-cert", "webauthn/aaguid-mismatch"); }

var VERIFIERS = {
  packed: function (att, clientDataHash) {
    var isX5c = !!cbor.read.mapGet(att.attStmt, "x5c");
    _requireAttShape(att.attStmt, isX5c ? ["alg", "sig", "x5c"] : ["alg", "sig"], isX5c ? ["alg", "sig", "x5c"] : ["alg", "sig"]);
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var message = Buffer.concat([att.authDataBytes, clientDataHash]);
    if (isX5c) {
      var chain = _readX5c(att.attStmt), leaf = chain[0];
      _checkPackedCert(leaf);
      return _verifySig(alg, sig, leaf.subjectPublicKeyInfo.bytes, message, _err).then(function (ok) {
        if (!ok) throw _err("webauthn/verify-failed", "the packed attestation signature does not verify under the x5c leaf key");
        _checkAaguidExt(leaf, att.authData.aaguid);
        return _result("packed", "Basic", chain, att);
      });
    }
    if (alg !== att.authData.credentialPublicKey.alg) throw _err("webauthn/bad-att-stmt", "the packed self-attestation alg does not match the credential public key algorithm (WebAuthn 8.2)");
    var spki = _coseKeyToSpki(att.authData.credentialPublicKey);
    return _verifySig(alg, sig, spki, message, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the packed self-attestation signature does not verify under the credential key");
      return _result("packed", "Self", [], att);
    });
  },

  "fido-u2f": function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["sig", "x5c"], ["sig", "x5c"]);
    var chain = _readX5c(att.attStmt);
    if (chain.length !== 1) throw _err("webauthn/bad-att-stmt", "fido-u2f x5c MUST contain exactly one certificate (WebAuthn 8.6)");
    var leaf = chain[0];
    var sig = _sigOf(att.attStmt);
    var key = att.authData.credentialPublicKey;
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

  apple: function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["alg", "x5c"], ["x5c"]);
    var chain = _readX5c(att.attStmt), leaf = chain[0];
    _requireV3(leaf);
    var nonce = _sha("sha256", Buffer.concat([att.authDataBytes, clientDataHash]));
    var ext = _findExt(leaf, "appleAnonymousAttestation");
    if (!ext) throw _err("webauthn/bad-att-cert", "the apple attestation certificate is missing the anonymous-attestation extension (WebAuthn 8.8)");
    var embedded = _appleNonce(ext.value);
    if (!embedded.equals(nonce)) throw _err("webauthn/verify-failed", "the apple attestation nonce does not equal SHA-256(authData || clientDataHash)");
    _certPubKeyEqualsCose(leaf, att.authData.credentialPublicKey, _err);
    return Promise.resolve(_result("apple", "AnonCA", chain, att));
  },

  "android-key": function (att, clientDataHash) {
    _requireAttShape(att.attStmt, ["alg", "sig", "x5c"], ["alg", "sig", "x5c"]);
    var chain = _readX5c(att.attStmt), leaf = chain[0];
    _requireV3(leaf);
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var message = Buffer.concat([att.authDataBytes, clientDataHash]);
    return _verifySig(alg, sig, leaf.subjectPublicKeyInfo.bytes, message, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the android-key attestation signature does not verify under the x5c leaf key");
      _certPubKeyEqualsCose(leaf, att.authData.credentialPublicKey, _err);
      _checkAndroidKeyDescription(leaf, clientDataHash);
      return _result("android-key", "Basic", chain, att);
    });
  },

  tpm: function (att, clientDataHash, opts) {
    var tpmPolicy = validator.tpm.normalizeObjectAttributePolicy((opts || {}).tpmPolicy, WebauthnError, "webauthn/bad-input");
    _requireAttShape(att.attStmt, ["ver", "alg", "sig", "certInfo", "pubArea", "x5c"], ["ver", "alg", "sig", "certInfo", "pubArea", "x5c"]);
    var verN = cbor.read.mapGet(att.attStmt, "ver");
    if (!verN || verN.majorType !== 3 || cbor.read.textString(verN) !== "2.0") throw _err("webauthn/bad-att-stmt", "tpm attestation 'ver' MUST be \"2.0\" (WebAuthn 8.3)");
    var alg = _algOf(att.attStmt), sig = _sigOf(att.attStmt);
    var pubAreaBytes = _attRead(att.attStmt, "pubArea", cbor.read.byteString, "a byte string");
    var certInfoBytes = _attRead(att.attStmt, "certInfo", cbor.read.byteString, "a byte string");
    var chain = _readX5c(att.attStmt), aik = chain[0];

    var pub = _parseTpmPubArea(pubAreaBytes);
    _tpmPubKeyEqualsCose(pub, att.authData.credentialPublicKey);

    var certInfo = _parseTpmCertInfo(certInfoBytes);

    var attToBeSigned = Buffer.concat([att.authDataBytes, clientDataHash]);
    if (!certInfo.extraData.equals(_sha(_coseAlgHash(alg, _err), attToBeSigned))) throw _err("webauthn/verify-failed", "certInfo extraData does not equal the hash of authData || clientDataHash");

    var nameHash = validator.tpm.TPM_ALG_HASH[pub.nameAlg];
    if (!nameHash) throw _err("webauthn/bad-tpm", "unsupported TPM nameAlg 0x" + pub.nameAlg.toString(16));
    var computedName = Buffer.concat([pub.nameAlgBytes, _sha(nameHash, pubAreaBytes)]);
    if (!certInfo.attestedName.equals(computedName)) throw _err("webauthn/verify-failed", "certInfo attested Name does not match the pubArea TPM Name");

    return _verifySig(alg, sig, aik.subjectPublicKeyInfo.bytes, certInfoBytes, _err).then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the tpm attestation signature does not verify over certInfo under the AIK");
      _checkAikCert(aik);
      _checkAaguidExt(aik, att.authData.aaguid);
      validator.tpm.assertObjectAttributePolicy(pub, tpmPolicy, WebauthnError, "webauthn/tpm-policy", "webauthn/bad-tpm");
      return guard.verdict.of(_result("tpm", "AttCA", chain, att),
        { tpm: { objectAttributes: pub.objectAttributes, attributes: pub.attributes, authPolicy: pub.authPolicy } });
    });
  },

  "android-safetynet": function (att, clientDataHash, opts) {
    opts = opts || {};
    if (opts.verifySafetyNetJws !== true) {
      throw _err("webauthn/unsupported-format", "attestation statement format 'android-safetynet' is not supported");
    }
    var roots = opts.safetyNetRoots;
    if (!Array.isArray(roots) || roots.length === 0) {
      throw _err("webauthn/safetynet-no-root", "verifying an android-safetynet attestation requires opts.safetyNetRoots -- the Google root(s) to anchor the x5c chain to; this library bundles none (WebAuthn 8.5)");
    }
    if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");

    _requireAttShape(att.attStmt, ["ver", "response"], ["ver", "response"]);
    _attRead(att.attStmt, "ver", cbor.read.textString, "a text string");
    var responseBytes = _attRead(att.attStmt, "response", cbor.read.byteString, "a byte string");
    if (!responseBytes.length) throw _err("webauthn/bad-att-stmt", "the android-safetynet response is empty");

    var segs = guard.text.decode(responseBytes, constants.LIMITS.SAFETYNET_JWS_MAX_BYTES, WebauthnError, "webauthn/bad-att-stmt", "the android-safetynet response").split(".");
    if (segs.length !== 3) throw _err("webauthn/bad-att-stmt", "the android-safetynet response is not a three-part JWS compact serialization (RFC 7515 sec. 3.1)");
    var header, payload, sigBytes;
    try {
      header = jose.parseJson(jose.base64url.decode(segs[0]));
      payload = jose.parseJson(jose.base64url.decode(segs[1]));
      sigBytes = Buffer.from(jose.base64url.decode(segs[2]));
    } catch (e) { throw _err("webauthn/bad-att-stmt", "the android-safetynet response is not a decodable JWS", e); }
    if (!_isPlainObject(header) || !_isPlainObject(payload)) {
      throw _err("webauthn/bad-att-stmt", "the android-safetynet JWS header and payload must each be a JSON object");
    }

    if (header.alg !== "RS256") throw _err("webauthn/unsupported-algorithm", "the android-safetynet JWS alg must be RS256, got " + JSON.stringify(header.alg));
    if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
      throw _err("webauthn/bad-att-stmt", "the android-safetynet JWS header carries no x5c certificate chain (RFC 7515 sec. 4.1.6)");
    }
    _requireX5cCount(header.x5c.length);
    var chain = header.x5c.map(function (entry, i) {
      if (typeof entry !== "string") throw _err("webauthn/bad-att-stmt", "the android-safetynet x5c entry " + i + " is not a string");
      var der;
      try { der = guard.encoding.base64(entry, constants.LIMITS.SAFETYNET_CERT_MAX_BYTES, _err, "webauthn/bad-att-stmt", "an android-safetynet x5c entry"); }
      catch (e) { throw _err("webauthn/bad-att-stmt", "the android-safetynet x5c entry " + i + " is not canonical base64", e); }
      try { return x509.parse(der); }
      catch (e) { throw _err("webauthn/bad-att-cert", "the android-safetynet x5c entry " + i + " is not a decodable certificate", e); }
    });
    var leaf = chain[0];

    var wantNonce = _sha("sha256", Buffer.concat([att.authDataBytes, clientDataHash])).toString("base64");
    if (typeof payload.nonce !== "string" || !guard.crypto.constantTimeEqual(Buffer.from(payload.nonce, "utf8"), Buffer.from(wantNonce, "utf8"))) {
      throw _err("webauthn/safetynet-nonce-mismatch", "the android-safetynet nonce does not bind this authenticatorData and clientDataHash (WebAuthn 8.5)");
    }

    if (!_safetyNetHostnameOk(leaf)) {
      throw _err("webauthn/safetynet-bad-hostname", "the android-safetynet x5c leaf is not issued to attest.android.com (WebAuthn 8.5)");
    }

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
      chainAt = opts.time !== undefined ? opts.time
        : (typeof payload.timestampMs === "number" && isFinite(payload.timestampMs) && payload.timestampMs > 0
          ? new Date(payload.timestampMs) : undefined);
      return _safetyNetChainTrusted(chain, roots, chainAt);
    }).then(function () {
      var res = guard.verdict.of(_result("android-safetynet", "Basic", chain, att), { safetyNet: signals });
      if (chainAt !== undefined) res = guard.verdict.of(res, { chainValidatedAt: chainAt });
      return res;
    });
  },

  compound: function (att, clientDataHash, opts) {
    var kids = att.attStmt.children || [];
    if (kids.length < 2) throw _err("webauthn/bad-att-stmt", "a compound attestation statement must carry at least two nested statements (WebAuthn 8.9)");
    if (kids.length > constants.LIMITS.WEBAUTHN_COMPOUND_MAX_STATEMENTS) {
      throw _err("webauthn/bad-att-stmt", "a compound attestation statement carries " + kids.length + " nested statements, above the " + constants.LIMITS.WEBAUTHN_COMPOUND_MAX_STATEMENTS + " this toolkit will verify");
    }
    var elements = kids.map(function (el, i) {
      if (!el || el.majorType !== 5) throw _err("webauthn/bad-att-stmt", "compound element " + i + " must be a CBOR map { fmt, attStmt } (WebAuthn 8.9)");
      var fN = cbor.read.mapGet(el, "fmt"), sN = cbor.read.mapGet(el, "attStmt");
      if (el.children.length !== 2 || !fN || !sN) throw _err("webauthn/bad-att-stmt", "compound element " + i + " must be exactly { fmt, attStmt } (WebAuthn 8.9)");
      if (fN.majorType !== 3) throw _err("webauthn/bad-att-stmt", "compound element " + i + " 'fmt' must be a text string");
      var f = cbor.read.textString(fN);
      if (f === "compound") throw _err("webauthn/bad-att-stmt", "a compound attestation statement must not nest another compound (WebAuthn 8.9)");
      var v = VERIFIERS[f];
      if (!v) throw _err("webauthn/unsupported-format", "compound element " + i + " uses unsupported attestation statement format '" + f + "'");
      var wantMajor = ATT_STMT_MAJOR[f] === undefined ? 5 : ATT_STMT_MAJOR[f];
      if (sN.majorType !== wantMajor) throw _err("webauthn/bad-att-stmt", "compound element " + i + " 'attStmt' has the wrong CBOR shape for format '" + f + "'");
      return { fmt: f, index: i, att: { fmt: f, attStmt: sN, authData: att.authData, authDataBytes: att.authDataBytes } };
    });
    var out = [];
    return elements.reduce(function (p, e) {
      return p.then(function () {
        return Promise.resolve().then(function () { return VERIFIERS[e.fmt](e.att, clientDataHash, opts); })
          .then(function (r) { guard.list.append(out, r); }, function (err) {
            throw _err("webauthn/compound-element-failed", "compound element " + e.index + " (format '" + e.fmt + "') did not verify", err);
          });
      });
    }, Promise.resolve()).then(function () {
      return guard.verdict.of(_result("compound", "Compound", [], att), { compound: out });
    });
  },

  none: function (att) {
    if (att.attStmt.children.length !== 0) {
      throw _err("webauthn/bad-att-stmt", "the none attestation statement MUST be an empty map (WebAuthn 8.7)");
    }
    return Promise.resolve(_result("none", "None", [], att));
  },
};

function _isPlainObject(v) { return !!v && typeof v === "object" && !Array.isArray(v); }

function _safetyNetHostnameOk(leaf) {
  var want = "attest.android.com";
  var san = _decodeExt(leaf, "subjectAltName");
  var entries = san && Array.isArray(san.value) ? san.value : [];
  var dns = entries.filter(function (gn) { return gn && gn.type === "dNSName" && typeof gn.value === "string"; });
  if (dns.length) return dns.some(function (gn) { return gn.value.toLowerCase() === want; });
  return leaf.subject.rdns.some(function (rdn) {
    return rdn.some(function (atv) {
      return atv.name === "commonName" && typeof atv.value === "string" && atv.value.toLowerCase() === want;
    });
  });
}

function _safetyNetChainTrusted(chain, roots, time) {
  var anchors;
  try {
    anchors = roots.map(function (root, i) {
      var label = "opts.safetyNetRoots[" + i + "]";
      return guard.parsed.acceptDerived(root, "certificate", function (bytes) {
        try {
          return x509.parse(_isBufferSource(bytes) ? guard.bytes.source(bytes, WebauthnError, "webauthn/bad-input", label) : bytes);
        } catch (e) { throw _err("webauthn/bad-input", label + " is not a decodable certificate", e); }
      }, _err, "webauthn/bad-input", label);
    });
  } catch (e) { return Promise.reject(e); }
  return mds.chainToAnchor(chain, anchors, time === undefined ? new Date() : time,
    "android-safetynet x5c certificate chain", "webauthn/safetynet-cert-untrusted");
}

function _result(fmt, attestationType, chain, att) {
  return guard.verdict.of({
    valid: true, attestationVerified: true, fmt: fmt, attestationType: attestationType,
    trustPath: (chain || []).slice().reverse(),
    aaguid: att.authData.aaguid,
    credentialId: att.authData.credentialId,
    credentialPublicKey: att.authData.credentialPublicKey,
    credentialPublicKeyBytes: att.authData.credentialPublicKeyBytes,
    signCount: att.authData.signCount,
    flags: att.authData.flags,
    rpIdHash: att.authData.rpIdHash,
    extensions: att.authData.extensions,
  });
}

function _appleNonce(extValue) {
  var seq;
  try { seq = asn1.decode(extValue); } catch (e) { throw _err("webauthn/bad-att-cert", "the apple attestation extension is not decodable", e); }
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

function _checkAndroidKeyDescription(cert, clientDataHash) {
  validator.keydesc.androidKeyDescription(cert, clientDataHash, _exts, WebauthnError, "webauthn/bad-att-cert", "webauthn/verify-failed");
}


/**
 * @primitive pki.webauthn.verify
 * @signature pki.webauthn.verify(attestationObject, clientDataHash?, opts?) -> Promise<{ valid, attestationVerified, fmt, attestationType, trustPath, anchoredTo, aaguid, credentialId, credentialPublicKey, credentialPublicKeyBytes, signCount, flags, rpIdHash, extensions, bindingChecked, clientData }>
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
 * second argument. Given the JSON, this reads it: the ceremony type is checked
 * unconditionally, because which ceremony a response belongs to is fixed by the
 * specification and never chosen by a caller, and a login response replayed into a
 * registration is exactly what that check stops. The challenge, origin and top-level
 * origin are checked when you supply what you issued, and `clientData.checked` reports
 * which ran. Given only the digest, nothing reads it and `clientData` is null.
 *
 * The verdict field is `attestationVerified`, and the name is the point: a sound
 * attestation statement is not the same claim as an acceptable registration. The
 * statement says nothing about which relying party asked for it, or whether a user
 * was present, so an attestation naming another origin's RP ID, with user presence
 * clear, is perfectly sound and must not be registered. Supply `expectedRpId`,
 * `requireUserPresence`, `requireUserVerification` and `allowedAlgorithms` and those
 * are checked here; `bindingChecked` reports which ran, so a check that passed can be
 * told from one that never happened.
 *
 * Four more fields appear only where they mean something, never as nulls on every
 * verdict: `metadata` when the catalogue governed, `anchoredElements` when a trust path
 * was anchored, `compound` for a sec. 8.9 statement's per-element results, and
 * `safetyNet` with `chainValidatedAt` for an android-safetynet response.
 *
 * The verdict also carries what a relying party must STORE to run a later login:
 * `credentialId`, `credentialPublicKey` and the initial `signCount`. The credential key
 * comes back in both forms: the decoded object, and `credentialPublicKeyBytes`, which is
 * what a credential row should hold. The object carries `Buffer` values, so a JSON round
 * trip through a datastore returns `{"type":"Buffer","data":[...]}` in place of the object
 * that went in. `pki.webauthn.parseCoseKey` reads those bytes back, and
 * `verifyAssertion` accepts either form.
 *
 * @intro This verifies the attestation STATEMENT: the signature and the format's
 *   structural bindings (the x5c leaf key == credential key, the apple nonce, the tpm
 *   certInfo Name/extraData, the android KeyDescription, the fido-u2f verificationData).
 *   Chaining the returned `trustPath` (the x5c certificates in `pki.path.validate`
 *   order: anchor-adjacent first, leaf last) to a trusted root is a separate step,
 *   and there are three ways to take it. Pass `opts.metadata`, a
 *   `pki.webauthn.verifyMetadataBlob` result. The authenticator's registered
 *   attestation roots are resolved from its own identifier and the trust path is
 *   required to reach one, so an unlisted or revoked model is refused and never
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
 *   than one did: `"metadata"`, `"rootCertificates"`, and `"safetyNetRoots"` for the
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
 *   clientDataJSON    the raw clientDataJSON bytes; supply this or the digest argument
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
  if (opts === undefined && clientDataHash !== undefined &&
      !_isBufferSource(clientDataHash) && _isPlainObject(clientDataHash)) {
    opts = clientDataHash; clientDataHash = undefined;
  }
  opts = opts || {};
  try {
    if (!_isPlainObject(opts)) throw _err("webauthn/bad-input", "opts must be an object");
    guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "webauthn/bad-input", "opts has an unknown key ");
    opts = Object.assign({}, opts);
    if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");
    _FORMAT_SCOPED_BOOLEAN_OPTS.forEach(function (k) {
      if (opts[k] !== undefined && typeof opts[k] !== "boolean") throw _err("webauthn/bad-input", "opts." + k + " must be a boolean");
    });
  } catch (e) { return Promise.reject(e); }
  var att;
  var attBytes, cdh, clientData = null;
  try {
    attBytes = _bytesArg(attestationObject, "attestationObject");
    var haveJson = opts.clientDataJSON !== undefined, haveHash = clientDataHash !== undefined;
    if (haveJson === haveHash) {
      throw _err("webauthn/bad-input", "verify takes exactly one of clientDataJSON or the clientDataHash argument");
    }
    if (haveJson) {
      var cdjBytes = _bytesArg(opts.clientDataJSON, "opts.clientDataJSON");
      clientData = parseClientData(cdjBytes, {
        expectedType: "webauthn.create",
        expectedChallenge: opts.expectedChallenge,
        expectedOrigin: opts.expectedOrigin,
        expectedTopOrigin: opts.expectedTopOrigin,
      });
      cdh = _sha("sha256", cdjBytes);
    } else {
      if (opts.expectedChallenge !== undefined || opts.expectedOrigin !== undefined ||
          opts.expectedTopOrigin !== undefined) {
        throw _err("webauthn/bad-input",
          "expectedChallenge / expectedOrigin / expectedTopOrigin are checked against clientDataJSON, which this call " +
          "did not supply -- pass opts.clientDataJSON instead of the clientDataHash argument, or check them yourself");
      }
      cdh = _bytesArg(clientDataHash, "clientDataHash");
      if (cdh.length !== 32) throw _err("webauthn/bad-input", "clientDataHash must be a 32-byte SHA-256 digest");
    }
  } catch (e) { return Promise.reject(e); }
  attestationObject = attBytes;
  clientDataHash = cdh;
  try { att = parseAttestationObject(attestationObject); } catch (e) { return Promise.reject(e); }
  if (!att.authData.flags.at || !att.authData.credentialPublicKey) {
    return Promise.reject(_err("webauthn/bad-auth-data", "attestation requires attestedCredentialData (the AT flag must be set)"));
  }
  var verifier = VERIFIERS[att.fmt];
  if (!verifier) return Promise.reject(_err("webauthn/unsupported-format", "attestation statement format '" + att.fmt + "' is not supported"));
  if (opts.tpmPolicy !== undefined && !_formatCarries(att, "tpm")) {
    return Promise.reject(_err("webauthn/tpm-policy", "opts.tpmPolicy requires a TPM attestation, but this attestation is format '" + att.fmt + "', which carries no TPM public area"));
  }
  if (opts.requireCtsProfileMatch === true && !_formatCarries(att, "android-safetynet")) {
    return Promise.reject(_err("webauthn/safetynet-cts-profile", "opts.requireCtsProfileMatch requires an android-safetynet attestation, but this attestation is format '" + att.fmt + "', whose statement carries no device-integrity signals"));
  }
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
      return guard.verdict.of(res, { clientData: clientData });
    })
    .then(function (res) {
      if (vopts.metadata === undefined) {
        if (vopts.rootCertificates !== undefined) return _applyCallerRoots(res, vopts.rootCertificates, vopts);
        var anchored = guard.verdict.of(res, { anchoredTo: _anchoredRoutes(res, null) });
        var sn = _safetyNetAnchored(anchored);
        if (sn) {
          anchored = guard.verdict.of(anchored, { anchoredElements: {
            total: (anchored.fmt === "compound" && Array.isArray(anchored.compound)) ? anchored.compound.length : 1,
            anchored: sn } });
        }
        return anchored;
      }
      return Promise.resolve().then(function () { return _applyMetadata(res, att, vopts); })
        .then(function (out) { return guard.verdict.of(out, { anchoredTo: _anchoredRoutes(out, "metadata") }); }, function (e) {
          if (!e || e.code !== "webauthn/metadata-not-found" || vopts.rootCertificates === undefined) throw e;
          return Promise.resolve(_applyCallerRoots(res, vopts.rootCertificates, vopts, e.missedPaths))
            .then(function (withRoots) {
              /** @internal The element coverage the metadata attempt measured is the whole
               * statement's, so it travels on the error rather than being recomputed from the
               * fallback's own paths. */
              var out = e.anchoredElements ? guard.verdict.of(withRoots, { anchoredElements: e.anchoredElements }) : withRoots;
              var applied = e.appliedEntries || [];
              if (!applied.length) return out;
              var primary = applied[0];
              var withMd = guard.verdict.of(out, { metadata: { aaguid: primary.entry.aaguid,
                keyIdentifiers: primary.entry.keyIdentifiers || [],
                entry: primary.entry, entries: applied.map(function (a) { return a.entry; }),
                anchors: primary.anchors.length } });
              return guard.verdict.of(withMd, { anchoredTo: _anchoredRoutes(withMd, "metadata+rootCertificates") });
            });
        });
    })
    .then(function (res) { return guard.verdict.of(res, { bindingChecked: bindingChecked }); });
}

function _applyMetadata(res, att, opts) {
  var md = opts.metadata;
  if (!mds.isVerifiedResult(md)) {
    throw _err("webauthn/bad-input", "opts.metadata must be a pki.webauthn.verifyMetadataBlob result, not a raw BLOB");
  }
  var paths = (res.fmt === "compound" && Array.isArray(res.compound))
    ? res.compound.filter(function (el) { return el.trustPath && el.trustPath.length; })
      .map(function (el) { return { tp: el.trustPath, fmt: el.fmt, at: el.chainValidatedAt }; })
    : (res.trustPath && res.trustPath.length ? [{ tp: res.trustPath, fmt: res.fmt, at: res.chainValidatedAt }] : []);
  res = guard.verdict.of(res, { anchoredElements: {
    total: (res.fmt === "compound" && Array.isArray(res.compound)) ? res.compound.length : 1,
    anchored: paths.length } });
  if (!paths.length) {
    throw _err("webauthn/metadata-not-applicable", "opts.metadata was supplied, but this attestation carries no trust path to anchor (format '" + res.fmt + "')");
  }
  var aaguid = mds.aaguidToString(att.authData.aaguid);
  var applied = [];
  function govern(info) {
    var tp = info.tp;
    var declared = _aaguidIsSigned(info.fmt) && aaguid && aaguid !== mds.ZERO_AAGUID;
    var entry, identifier;
    if (declared) {
      entry = mds.metadataFor(md, aaguid);
      identifier = "aaguid " + aaguid;
    } else {
      var keyId = mds.certKeyIdentifier(tp[tp.length - 1]);
      entry = mds.metadataForKeyIdentifier(md, keyId);
      identifier = "attestation certificate key identifier " + keyId;
    }
    if (!entry) throw _err("webauthn/metadata-not-found", "no metadata entry matches this authenticator (" + identifier + ")");
    if (mds.statusDenied(entry, md, tp[tp.length - 1], at)) {
      throw _err("webauthn/metadata-status", "the metadata entry for " + identifier + " carries a disqualifying status report");
    }
    var anchors = mds.metadataAnchors(entry, { metadata: md, time: at, certificate: tp[tp.length - 1] });
    if (!anchors.length) throw _err("webauthn/metadata-no-anchor", "the metadata entry for " + identifier + " supplies no attestation root certificate");
    applied.push({ entry: entry, anchors: anchors, identifier: identifier });
    return { anchors: anchors, identifier: identifier };
  }
  var at = opts.time !== undefined ? opts.time : new Date();
  mds.assertFresh(md, at, "the metadata supplied as opts.metadata");
  var governed = [];
  var missed = null;
  var missedPaths = [];
  for (var gi = 0; gi < paths.length; gi++) {
    try {
      governed.push({ info: paths[gi], g: govern(paths[gi]) });
    } catch (ge) {
      if (ge && ge.code === "webauthn/metadata-not-found") { missed = missed || ge; missedPaths.push(paths[gi]); continue; }
      throw ge;
    }
  }
  if (missed) {
    guard.verdict.set(missed, "missedPaths", missedPaths);
    guard.verdict.set(missed, "appliedEntries", applied);
    guard.verdict.set(missed, "anchoredElements", res.anchoredElements);
  }
  return governed.reduce(function (p, item) {
    return p.then(function () {
      var g = item.g, info = item.info;
      var pathAt = opts.time !== undefined ? opts.time : (info.at || at);
      return mds.chainToAnchor(info.tp.slice().reverse(), g.anchors, pathAt,
        "attestation trust path for " + g.identifier + " (against the roots its metadata entry registers)");
    });
  }, Promise.resolve())
    .then(function () {
      if (missed) throw missed;
      var primary = applied[0];
      return guard.verdict.of(res, { metadata: { aaguid: primary.entry.aaguid,
        keyIdentifiers: primary.entry.keyIdentifiers || [],
        entry: primary.entry, entries: applied.map(function (a) { return a.entry; }),
        anchors: primary.anchors.length } });
    });
}

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
 * Verify a FIDO Metadata Service BLOB (the signed catalogue of every registered
 * authenticator model, its attestation roots, and its certification status), and
 * return its entries indexed by aaguid for lookup. `blob` is caller-supplied bytes or
 * a string; retrieval is out of scope, so this never touches the network.
 *
 * The BLOB is a JWS. Its signature is checked under the certificate in its own header,
 * that chain is validated to one of `opts.rootCertificates`, and only THEN is the
 * payload read. A BLOB that does not verify never reaches the JSON parser. `no` must
 * exceed `opts.previousNo` (rollback) and `nextUpdate` must not have passed
 * (freshness). Every failure is a typed `webauthn/metadata-*` throw, never a partial
 * result.
 *
 * The result says which of those rules actually ran, so a catalogue held for a while can
 * still answer for itself: `stale` and `allowStale` for freshness, `rollbackChecked` and
 * the `previousNo` it was compared against for rollback, `statusPolicy` and
 * `rejectUnknownStatus` for the status reading every later lookup will use. A rule that
 * did not run reads as not-run, never as passed.
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
 *     (the default; any disqualifying report ever filed), `"latest-by-date"` (only the
 *     most recent report counts, so a later remediation clears an earlier revocation),
 *     or a function receiving the raw report array and returning true to deny.
 *   - `rejectUnknownStatus` -- treat a status this toolkit does not recognize as
 *     disqualifying. Off by default: the specification requires an unknown status be
 *     ignored, never failed on.
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
 * lists none. `metadata` is a `verifyMetadataBlob` result, never raw bytes, so a
 * lookup can never be answered out of a BLOB nobody verified.
 *
 * `identifier` is whichever of the catalogue's two key spaces names the authenticator:
 * its aaguid, or, for a U2F authenticator which carries none, the key identifier
 * of its attestation certificate (RFC 5280 sec. 4.2.1.2 method 1, 40 hex digits). The
 * two are disjoint by shape, so the form is dispatched on and never guessed at, and
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
 * The parsed attestation root certificates a metadata entry registers: the anchors an
 * attestation from that model must chain to. An entry whose status reports disqualify
 * the model registers none: the catalogue exists to say which authenticators are still
 * trusted, so handing back the roots of one it has revoked would answer a different
 * question than the caller asked. That refusal is `webauthn/metadata-status`.
 *
 * The judgement uses whatever the caller supplies and the strictest reading of what it
 * does not: pass the verified `metadata` and its own `statusPolicy` governs and its
 * freshness is re-checked, pass `time` and reports are judged as of that instant, pass
 * the `certificate` an attestation actually presented and a report naming a single
 * certificate is judged against that one, so the entry does not deny every device it
 * covers. With none of them: any disqualifying report denies, judged now.
 *
 * Decoding is per entry, and deliberately not for the
 * whole BLOB: a handful of certificates in the live metadata do not parse
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


var CLIENT_DATA_TYPE = Object.assign(Object.create(null), { "webauthn.create": 1, "webauthn.get": 1 });

/**
 * @primitive pki.webauthn.parseClientData
 * @signature pki.webauthn.parseClientData(bytes, opts?) -> { type, challenge, origin, crossOrigin, topOrigin, checked }
 * @since 0.5.0
 * @status stable
 * @spec W3C WebAuthn Level 3 sec. 5.8.1 / 7.1 / 7.2
 * @defends webauthn-ceremony-confusion (CWE-345)
 * @related pki.webauthn.verify, pki.webauthn.verifyAssertion
 *
 * Decode the `clientDataJSON` a ceremony returns, the half of a WebAuthn response
 * the signature covers by digest but that no signature check ever looks inside.
 * Parsed through the shared fail-closed JSON guard (bounded bytes and depth,
 * fatal UTF-8, duplicate members refused, no prototype pollution), because these
 * are bytes an attacker chose. `challenge` is returned DECODED from base64url as a
 * Buffer, so a caller compares raw bytes and never two spellings of the same
 * value; `type`, `origin`, `crossOrigin` and `topOrigin` come back as they were.
 *
 * Supply `expectedType`, `expectedChallenge`, `expectedOrigin` and
 * `expectedTopOrigin` and each is checked here: the challenge in constant time
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
 * both `crossOrigin` and `topOrigin` and is only usable when they agree: a response
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
    if (allowed.indexOf(doc.origin) === -1) {
      throw _err("webauthn/client-data-mismatch",
        "the clientDataJSON origin " + JSON.stringify(doc.origin) + " is not one this relying party accepts " +
        "(WebAuthn sec. 7.1 step 10 / sec. 7.2 step 13)");
    }
    checked.origin = true;
  }
  if (opts.expectedTopOrigin !== undefined) {
    var wantTop = opts.expectedTopOrigin;
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


/**
 * @primitive pki.webauthn.parseAuthenticatorData
 * @signature pki.webauthn.parseAuthenticatorData(bytes) -> { rpIdHash, flags, signCount, aaguid, credentialId, credentialPublicKey, credentialPublicKeyBytes, extensions }
 * @since 0.5.0
 * @status stable
 * @spec W3C WebAuthn Level 3 sec. 6.1
 * @related pki.webauthn.verifyAssertion, pki.webauthn.parseAttestationObject
 *
 * Decode a bare authenticatorData, fail-closed: the form an authentication
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

var _ASSERT_OPTS = Object.assign(Object.create(null), {
  authenticatorData: 1, clientDataHash: 1, clientDataJSON: 1, signature: 1,
  credentialPublicKey: 1, previousSignCount: 1,
  expectedRpId: 1, requireUserPresence: 1, requireUserVerification: 1, allowedAlgorithms: 1,
  expectedChallenge: 1, expectedOrigin: 1, expectedTopOrigin: 1,
});

/**
 * @primitive pki.webauthn.verifyAssertion
 * @signature pki.webauthn.verifyAssertion(input) -> Promise<{ valid, signatureVerified, signCount, signCountChecked, flags, rpIdHash, extensions, bindingChecked, clientData }>
 * @since 0.5.0
 * @status stable
 * @spec W3C WebAuthn Level 3 sec. 7.2
 * @defends webauthn-assertion-forgery (CWE-347)
 * @related pki.webauthn.parseAuthenticatorData, pki.webauthn.verify
 *
 * Verify an authentication assertion's signature: the authenticator signs
 * `authenticatorData || SHA-256(clientDataJSON)` as raw bytes with the credential
 * key registered earlier: no COSE_Sign1 wrapper, so a COSE message verifier is
 * the wrong tool and fails on structure before it ever reaches the signature. An
 * ES256 assertion signature is an ASN.1 DER `SEQUENCE { r, s }`, converted here
 * with the same order-aware reader the attestation path uses, so an r or s outside
 * `[1, n-1]` is refused, never normalized.
 *
 * `signatureVerified`, not `verified`: this establishes that the holder of the
 * registered credential key produced this response. What makes the response
 * ACCEPTABLE is the sec. 7.2 binding, and the caller owns most of it. Supply
 * `expectedRpId`, `requireUserPresence`, `requireUserVerification` and
 * `allowedAlgorithms` and they are checked here. `bindingChecked` reports which
 * ones ran, so a check that passed is distinguishable from one that never
 * happened. Supply `expectedChallenge`, `expectedOrigin`, or `expectedTopOrigin`
 * together with `clientDataJSON` and the challenge and origin are checked here
 * against it; omit them and they stay with the caller to compare against the
 * clientDataJSON this call surfaces. Passing them with only `clientDataHash`
 * throws, because there is no clientDataJSON to check them against.
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
 *   expectedRpId, requireUserPresence, requireUserVerification, allowedAlgorithms: the bindings above
 *   expectedChallenge, expectedOrigin, expectedTopOrigin -- checked against clientDataJSON when supplied (needs clientDataJSON, not clientDataHash)
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
function _snapshotAssertion(input) {
  if (!_isPlainObject(input)) throw _err("webauthn/bad-input", "pki.webauthn.verifyAssertion takes an options object");
  guard.identifier.assertKnownKeys(input, _ASSERT_OPTS, _err, "webauthn/bad-input", "verifyAssertion input has an unknown key ");
  var out = {}, k;
  for (k in input) { if (_hasOwn(input, k)) out[k] = input[k]; }
  ["authenticatorData", "clientDataJSON", "clientDataHash", "signature", "expectedChallenge"].forEach(function (f) {
    if (_isBufferSource(out[f])) out[f] = guard.bytes.snapshotSource(out[f], WebauthnError, "webauthn/bad-input", f);
  });
  if (_isBufferSource(out.credentialPublicKey)) {
    out.credentialPublicKey = guard.bytes.snapshotSource(out.credentialPublicKey, WebauthnError,
      "webauthn/bad-input", "credentialPublicKey");
  } else if (_isPlainObject(out.credentialPublicKey)) {
    var key = {}, kk;
    for (kk in out.credentialPublicKey) {
      if (!_hasOwn(out.credentialPublicKey, kk)) continue;
      var v;
      try { v = out.credentialPublicKey[kk]; }
      catch (e) { throw _err("webauthn/bad-cose-key", "credentialPublicKey." + kk + " could not be read", e); }
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
  var frozen;
  try { frozen = _snapshotAssertion(input); } catch (e) { return Promise.reject(e); }
  return Promise.resolve().then(function () {
    input = frozen;
    var authData = parseAuthenticatorData(input.authenticatorData);
    input.signature = _bytesArg(input.signature, "signature");
    var haveJson = input.clientDataJSON !== undefined, haveHash = input.clientDataHash !== undefined;
    if (haveJson === haveHash) {
      throw _err("webauthn/bad-input", "verifyAssertion takes exactly one of clientDataJSON or clientDataHash");
    }
    var clientDataHash, clientData = null;
    if (haveJson) {
      input.clientDataJSON = _bytesArg(input.clientDataJSON, "clientDataJSON");
      clientData = parseClientData(input.clientDataJSON, {
        expectedType: "webauthn.get",
        expectedChallenge: input.expectedChallenge,
        expectedOrigin: input.expectedOrigin,
        expectedTopOrigin: input.expectedTopOrigin,
      });
      clientDataHash = _sha("sha256", Buffer.from(input.clientDataJSON));
    } else {
      if (input.expectedChallenge !== undefined || input.expectedOrigin !== undefined ||
          input.expectedTopOrigin !== undefined) {
        throw _err("webauthn/bad-input",
          "expectedChallenge / expectedOrigin / expectedTopOrigin are checked against clientDataJSON, which this call " +
          "did not supply -- pass clientDataJSON instead of clientDataHash, or check them yourself");
      }
      clientDataHash = _bytesArg(input.clientDataHash, "clientDataHash");
      if (clientDataHash.length !== 32) throw _err("webauthn/bad-input", "clientDataHash must be a 32-byte SHA-256 digest");
    }
    var coseKey = input.credentialPublicKey;
    if (guard.bytes.isByteSource(coseKey)) {
      coseKey = parseCoseKey(coseKey);
    } else if (_isPlainObject(coseKey)) {
      coseKey = validator.cose.assertKeyMaterial(coseKey, WebauthnError, "webauthn/bad-cose-key", "webauthn/unsupported-algorithm");
    } else {
      throw _err("webauthn/bad-input", "credentialPublicKey must be the stored COSE key -- the object pki.webauthn.verify returned, or its COSE bytes");
    }
    var bindingChecked = _applyBindings(authData, coseKey, input);
    var prev = input.previousSignCount;
    if (prev !== undefined && (typeof prev !== "number" || !Number.isSafeInteger(prev) || prev < 0 || prev > 0xFFFFFFFF)) {
      throw _err("webauthn/bad-input", "previousSignCount must be an integer in 0..4294967295");
    }
    var message = Buffer.concat([Buffer.from(input.authenticatorData), clientDataHash]);
    var spki = _coseKeyToSpki(coseKey);
    return _verifySig(coseKey.alg, Buffer.from(input.signature), spki, message, _err).then(function (ok) {
      if (!ok) {
        throw _err("webauthn/bad-signature",
          "the assertion signature does not verify under the stored credential public key (WebAuthn sec. 7.2 step 20)");
      }
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
      return guard.verdict.of({
        valid: true,
        signatureVerified: true,
        signCount: authData.signCount,
        signCountChecked: signCountChecked,
        flags: authData.flags,
        rpIdHash: authData.rpIdHash,
        extensions: authData.extensions,
        clientData: clientData,
        bindingChecked: bindingChecked,
      });
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
