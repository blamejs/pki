// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cms.decrypt implementation. The operator-facing @module pki.cms + the
// @primitive pki.cms.decrypt block live in cms-verify.js, which re-exports this function.
//
// CMS EnvelopedData / AuthEnvelopedData / EncryptedData decryption (RFC 5652/5083/5084/3560/5753/
// 8418/9629/9936/3211/8018), the consuming side of pki.cms.encrypt. Three stages behind ONE
// oracle-free choke point: (1) SELECT the recipient (identifier matching -- typed + distinct),
// (2) ACQUIRE the CEK (per-arm unwrap/decap/derive), (3) OPEN the content (AEAD verify / CBC
// decrypt+unpad). Every secret-dependent failure in stages 2-3 collapses to the SINGLE uniform
// verdict `cms/decrypt-failed` (Bleichenbacher / EFAIL / PWRI-check-byte oracle freedom); the
// ktri v1.5 arm substitutes a random CEK on any decode fault (RFC 3218 implicit rejection) so its
// failure emerges at stage 3 identically to every other bad-key path.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkcs8 = require("./schema-pkcs8");
var schemaCms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var C = require("./constants");
var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var CmsError = frameworkError.CmsError;
var WRAP_KEK_LENGTHS = schemaCms.WRAP_KEK_LENGTHS;
var KEM_CT_LENGTHS = schemaCms.KEM_CT_LENGTHS;

function O(n) { return oid.byName(n); }
function _err(code, message, cause) { return new CmsError(code, message, cause); }
// The ONE uniform secret-dependent-failure verdict. No cause chaining that distinguishes the site.
function _fail() { return new CmsError("cms/decrypt-failed", "the CMS content could not be decrypted (uniform by design -- padding / integrity / key-unwrap failures are indistinguishable to defeat oracles)"); }

var CONTENT_KEYBITS = {}; // content-encryption OID -> key bits
[["aes128-CBC", 128], ["aes192-CBC", 192], ["aes256-CBC", 256], ["aes128-GCM", 128], ["aes192-GCM", 192], ["aes256-GCM", 256]].forEach(function (r) { CONTENT_KEYBITS[O(r[0])] = r[1]; });

// ---- entry -----------------------------------------------------------------
async function decrypt(input, keyMaterial, opts) {
  opts = opts || {};
  if (keyMaterial == null || typeof keyMaterial !== "object") throw _err("cms/bad-input", "decrypt requires a key-material object");
  var parsed = _parse(input);
  var ct = parsed.contentTypeName;
  if (ct === "encryptedData") return _decryptEncryptedData(parsed, keyMaterial, opts);
  if (ct !== "envelopedData" && ct !== "authEnvelopedData") throw _err("cms/bad-input", "input is not an EnvelopedData / AuthEnvelopedData / EncryptedData (got " + ct + ")");

  var recips = parsed.recipientInfos || [];
  var sel = _selectRecipient(recips, keyMaterial, opts);   // stage 1 (typed, distinct)
  var cek = await _acquireCek(sel.ri, keyMaterial, opts);   // stage 2 (uniform)
  var eci = parsed.encryptedContentInfo;
  var content = await _openContent(parsed, eci, cek, ct);   // stage 3 (uniform)
  return {
    content: content,
    contentType: eci.contentType, contentTypeName: oid.name(eci.contentType) || eci.contentType,
    recipientType: sel.ri.type, recipientIndex: sel.index,
    contentEncryptionAlgorithm: eci.contentEncryptionAlgorithm.name || eci.contentEncryptionAlgorithm.oid,
    authenticated: ct === "authEnvelopedData",
  };
}

function _parse(input) {
  if (input && input.contentTypeName) return input;             // already parsed
  var der = _toDer(input);
  return schemaCms.parse(der);
}
function _toDer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input === "string") { try { return schemaCms.pemDecode(input); } catch (e) { throw _err("cms/bad-input", "the CMS PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "input must be a DER Buffer, Uint8Array, or PEM string");
}

// ---- stage 1: recipient selection (NOT secret-dependent) -------------------
function _selectRecipient(recips, km, opts) {
  if (!recips.length) throw _err("cms/no-matching-recipient", "the message carries no RecipientInfos");
  if (opts.recipientIndex != null) {
    var i = opts.recipientIndex;
    if (typeof i !== "number" || i < 0 || i >= recips.length) throw _err("cms/bad-input", "recipientIndex is out of range");
    var ri = recips[i];
    _assertSupported(ri, km);
    return { ri: ri, index: i };
  }
  var want = _riKindForKey(km);
  var cert = km.cert != null ? x509.parse(_normCertDer(km.cert)) : null;
  for (var k = 0; k < recips.length; k++) {
    var r = recips[k];
    if (want === "asym" && (r.type === "ktri" || r.type === "kari" || r.type === "ori")) {
      if (cert && _ridMatches(r, cert)) { _assertSupported(r, km); return { ri: r, index: k }; }
    } else if (want === "pwri" && r.type === "pwri") { return { ri: r, index: k }; }
    else if (want === "kekri" && r.type === "kekri") {
      if (km.kekId == null || _kekIdMatches(r, km.kekId)) { return { ri: r, index: k }; }
    }
  }
  throw _err("cms/no-matching-recipient", "no recipient matches the supplied key material");
}
function _riKindForKey(km) {
  if (km.password != null) return "pwri";
  if (km.kek != null) return "kekri";
  if (km.key != null) return "asym";
  throw _err("cms/bad-input", "key material needs { key, cert }, { password }, { kek }, or { cek }");
}
function _assertSupported(ri, km) {
  if (ri.type === "kari" && ri.keyEncryptionAlgorithm && /mqv/i.test(ri.keyEncryptionAlgorithm.name || "")) throw _err("cms/unsupported-algorithm", "ECMQV kari is not supported");
  if (ri.type === "ori") {
    if (ri.oriType !== O("kem")) throw _err("cms/unsupported-recipient-type", "unsupported OtherRecipientInfo type " + ri.oriType);
    if (ri.kemri && ri.kemri.kem && ri.kemri.kem.oid === O("id-kem-rsa")) throw _err("cms/unsupported-algorithm", "RSA-KEM is not supported");
  }
  void km;
}

function _ridMatches(ri, cert) {
  // A kari carries a RecipientEncryptedKey per agreeing recipient (RFC 5652 sec. 6.2.2); this
  // recipient may be at ANY position, so match against every rek, not just element 0.
  if (ri.type === "kari") return !!_kariRekFor(ri, cert);
  var rid = ri.rid || (ri.kemri && ri.kemri.rid);
  if (!rid) return false;
  return _ridEq(rid, cert);
}
function _kariRekFor(ri, cert) {
  var reks = ri.recipientEncryptedKeys || [];
  for (var i = 0; i < reks.length; i++) if (reks[i].rid && _ridEq(reks[i].rid, cert)) return reks[i];
  return null;
}
function _ridEq(rid, cert) {
  if (rid.issuer && rid.serialNumber != null) {
    try { return guard.name.dnEqual(cert.issuer.rdns, rid.issuer.rdns, _err, "cms/bad-input", "recipient issuer") && cert.serialNumber === rid.serialNumber; }
    catch (_e) { return false; }
  }
  if (rid.subjectKeyIdentifier) { var ski = _skiOf(cert); return !!ski && Buffer.compare(ski, rid.subjectKeyIdentifier) === 0; }
  return false; // coverage residual: unreachable -- a parsed rid is always issuerAndSerialNumber or a SKI form
}
function _skiOf(cert) {
  var exts = cert.extensions || [];
  for (var i = 0; i < exts.length; i++) if (exts[i].name === "subjectKeyIdentifier" && exts[i].value != null) {
    try { return asn1.read.octetString(asn1.decode(exts[i].value)); } catch (e) { throw _err("cms/bad-input", "the certificate's subjectKeyIdentifier extension is malformed", e); }
  }
  return null;
}
function _kekIdMatches(ri, kekId) {
  var id = ri.kekid && ri.kekid.keyIdentifier;
  if (!id) return false;
  return Buffer.compare(id, guard.bytes.view(kekId, CmsError, "cms/bad-input", "kekId")) === 0;
}

// Codes that name a structural / resource / config fault and MUST NOT be masked by the uniform
// secret-dependent verdict (they leak nothing about the key or plaintext).
var _passThrough = { "cms/unsupported-algorithm": 1, "cms/unsupported-recipient-type": 1, "cms/bad-input": 1, "cms/iteration-limit": 1, "cms/missing-key-derivation": 1, "cms/no-encrypted-content": 1 };

// ---- stage 2: acquire the CEK (uniform failure) ----------------------------
async function _acquireCek(ri, km, opts) {
  try {
    if (ri.type === "ktri") return await _ktriCek(ri, km);
    if (ri.type === "kari") return await _kariCek(ri, km);
    if (ri.type === "kekri") return await _kekriCek(ri, km);
    if (ri.type === "pwri") return await _pwriCek(ri, km, opts);
    if (ri.type === "ori") return await _kemriCek(ri, km);
  } catch (e) {
    // Structural / resource / config faults keep their own code -- only SECRET-DEPENDENT failures
    // (a bad unwrap, a wrong key, a padding fault) collapse to the uniform verdict.
    if (e instanceof CmsError && _passThrough[e.code]) throw e;
    throw _fail();
  }
  // Coverage residual: unreachable -- _selectRecipient only returns one of the five handled types.
  throw _err("cms/unsupported-recipient-type", "unsupported recipient type " + ri.type);
}

// ktri: OAEP or PKCS#1 v1.5 (v1.5 = decrypt-only + RFC 3218 implicit rejection).
async function _ktriCek(ri, km) {
  var kea = ri.keyEncryptionAlgorithm;
  var keyDer = _normKeyDer(km.key);
  if (kea.oid === O("rsaesOaep")) {
    var hash = _oaepHashFromParams(kea.parameters);
    var pub = await subtle.importKey("pkcs8", keyDer, { name: "RSA-OAEP", hash: hash }, false, ["decrypt"]);
    return Buffer.from(await subtle.decrypt({ name: "RSA-OAEP" }, pub, ri.encryptedKey));
  }
  if (kea.oid === O("rsaEncryption")) {
    // RFC 3218 sec. 2.3.2 implicit rejection: NEVER surface a v1.5 failure here. Any decode fault
    // yields a fresh random CEK of the content-alg length; the mismatch emerges at stage 3.
    var keyObj = nodeCrypto.createPrivateKey({ key: keyDer, format: "der", type: "pkcs8" });
    try { return nodeCrypto.privateDecrypt({ key: keyObj, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, ri.encryptedKey); }
    catch (_e) { return null; } // signal: use a random CEK (length decided at open time)
  }
  // Coverage residual: reachable only from a hostile message (our encrypt emits only OAEP; OpenSSL
  // emits OAEP or rsaEncryption) -- a fail-closed reject the fuzz harness exercises.
  throw _err("cms/unsupported-algorithm", "unsupported ktri keyEncryptionAlgorithm " + kea.oid);
}

// kari: reconstruct Z from the originatorKey + recipient private key, KDF -> KEK, AES-KW unwrap.
async function _kariCek(ri, km) {
  var keyDer = _normKeyDer(km.key);
  var kea = ri.keyEncryptionAlgorithm;
  var wrapAlg = _kariWrap(kea);
  var scheme = kea.oid;
  var origSpki = _originatorSpki(ri.originator);
  // Unwrap THIS recipient's RecipientEncryptedKey (matched by rid), not element 0 -- a kari may list
  // several recipients under one ephemeral key.
  var rek = (km.cert != null && _kariRekFor(ri, x509.parse(_normCertDer(km.cert)))) || ri.recipientEncryptedKeys[0];
  var kekBytes = WRAP_KEK_LENGTHS[wrapAlg.oid];
  if (!kekBytes) throw _err("cms/unsupported-algorithm", "unsupported kari key-wrap");
  var ukm = ri.ukm || null;
  var kek;
  if (_isMont(origSpki)) {
    var mont = _montName(origSpki);
    var recipPriv = await subtle.importKey("pkcs8", keyDer, { name: mont.name }, false, ["deriveBits"]);
    var origPub = await subtle.importKey("spki", origSpki, { name: mont.name }, false, []);
    var mz = Buffer.from(await subtle.deriveBits({ name: mont.name, public: origPub }, recipPriv, null));
    if (mz.every(function (x) { return x === 0; })) throw _fail();
    var mzKey = await subtle.importKey("raw", mz, { name: "HKDF" }, false, ["deriveBits"]);
    // RFC 8418 sec. 2.2: a present ukm is used BOTH as the HKDF salt AND as the ECC-CMS-SharedInfo
    // entityUInfo -- mirror the producer so both sides derive the same KEK as a conformant peer.
    kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: mont.hkdf, salt: ukm || Buffer.alloc(0), info: _eccSharedInfo(wrapAlg.name, ukm, kekBytes) }, mzKey, kekBytes * 8));
  } else {
    // RFC 5753 sec. 7.1 permits the originator EC key to omit its curve parameters, inheriting the
    // curve from the recipient's certificate; resolve the curve from the recipient (authoritative)
    // and rebuild the originator SPKI with explicit parameters so importKey can consume it.
    var origAlg = asn1.decode(origSpki).children[0];
    var origHasParams = origAlg.children.length > 1;
    var curveOid = (km.cert != null && _ecCurveFromCert(km.cert)) || (origHasParams ? asn1.read.oid(origAlg.children[1]) : null);
    var curve = curveOid ? CURVE[curveOid] : null;
    if (!curve) throw _err("cms/unsupported-algorithm", "unsupported or missing originator EC curve");
    var origSpkiFull = origHasParams ? origSpki : _withEcCurveParams(origSpki, curveOid);
    var recipEc = await subtle.importKey("pkcs8", keyDer, { name: "ECDH", namedCurve: curve.curve }, false, ["deriveBits"]);
    var origEc = await subtle.importKey("spki", origSpkiFull, { name: "ECDH", namedCurve: curve.curve }, false, []);
    var z = Buffer.from(await subtle.deriveBits({ name: "ECDH", public: origEc }, recipEc, null));
    var zKey = await subtle.importKey("raw", z, { name: "X963KDF" }, false, ["deriveBits"]);
    kek = Buffer.from(await subtle.deriveBits({ name: "X963KDF", hash: _x963Hash(scheme), info: _eccSharedInfo(wrapAlg.name, ukm, kekBytes) }, zKey, kekBytes * 8));
  }
  return await _aesKwUnwrap(kek, rek.encryptedKey);
}

// kekri: AES-KW unwrap under the caller-supplied KEK.
async function _kekriCek(ri, km) {
  var kek = guard.bytes.view(km.kek, CmsError, "cms/bad-input", "kek");
  return await _aesKwUnwrap(kek, ri.encryptedKey);
}

// pwri: PBKDF2 -> KEK, RFC 3211 double-CBC unwrap.
async function _pwriCek(ri, km, opts) {
  var kdf = ri.keyDerivationAlgorithm;
  if (!kdf) throw _err("cms/missing-key-derivation", "the pwri recipient has no keyDerivationAlgorithm (externally-supplied KEK is not supported)");
  if (kdf.oid !== O("pbkdf2")) throw _err("cms/unsupported-algorithm", "unsupported pwri key-derivation " + kdf.oid);
  var pb = _pbkdf2Params(kdf.parameters, opts);
  var kea = ri.keyEncryptionAlgorithm;
  if (kea.oid !== O("id-alg-PWRI-KEK")) throw _err("cms/unsupported-algorithm", "unsupported pwri key-encryption " + kea.oid);
  var inner = asn1.decode(kea.parameters);                 // inner AES-CBC AlgorithmIdentifier
  var innerOid = asn1.read.oid(inner.children[0]);
  var innerBits = CONTENT_KEYBITS[innerOid];
  if (!innerBits || !/CBC/.test(oid.name(innerOid) || "")) throw _err("cms/unsupported-algorithm", "unsupported pwri inner cipher");
  var iv = asn1.read.octetString(inner.children[1]);
  var kek = nodeCrypto.pbkdf2Sync(_passwordBytes(km.password), pb.salt, pb.iterations, innerBits / 8, pb.prfNode);
  return _pwriUnwrap(kek, ri.encryptedKey, iv, innerBits);
}

// kemri (ML-KEM ori): decapsulate -> ss, HKDF(CMSORIforKEMOtherInfo) -> KEK, AES-KW unwrap.
async function _kemriCek(ri, km) {
  var k = ri.kemri;
  var wcName = _mlkemName(k.kem.oid);
  if (!wcName) throw _err("cms/unsupported-algorithm", "unsupported KEM " + k.kem.oid);
  var wantCt = KEM_CT_LENGTHS[k.kem.oid];
  var kemct = k.kemct;
  // Coverage residual (both _fail re-checks): unreachable via a parsed message -- the strict parser
  // already rejects a wrong kemct length (cms/bad-kem-ciphertext) and a kekLength != wrap size
  // (cms/kek-length-mismatch). These are defense-in-depth on the consumer path (M32 / M29).
  if (wantCt && kemct.length !== wantCt) throw _fail();          // M32: exact ct length BEFORE decap
  var kekBytes = Number(k.kekLength);
  var wrapAlg = k.wrap;
  if (WRAP_KEK_LENGTHS[wrapAlg.oid] !== kekBytes) throw _fail(); // M29 re-check on the consumer path
  var priv = await subtle.importKey("pkcs8", _normKeyDer(km.key), { name: wcName }, false, ["decapsulateBits"]);
  var ss = Buffer.from(await subtle.decapsulateBits({ name: wcName }, priv, kemct));
  var ssKey = await subtle.importKey("raw", ss, { name: "HKDF" }, false, ["deriveBits"]);
  var kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.alloc(0), info: _kemOtherInfo(wrapAlg.name, kekBytes, k.ukm || null) }, ssKey, kekBytes * 8));
  return await _aesKwUnwrap(kek, k.encryptedKey);
}

// ---- stage 3: open the content (uniform failure) ---------------------------
async function _openContent(parsed, eci, cek, ct) {
  var alg = eci.contentEncryptionAlgorithm;
  var keyBits = CONTENT_KEYBITS[alg.oid];
  if (!keyBits) throw _err("cms/unsupported-algorithm", "unsupported contentEncryptionAlgorithm " + alg.oid);
  if (eci.encryptedContent == null) throw _err("cms/no-encrypted-content", "the message has no encryptedContent (detached; supply it out of band)");
  // A null CEK (v1.5 implicit rejection) or a wrong-length CEK -> a fresh random key of the right
  // length, so the failure surfaces here as the uniform verdict, never earlier.
  if (cek == null || cek.length !== keyBits / 8) cek = nodeCrypto.randomBytes(keyBits / 8);
  try {
    if (ct === "authEnvelopedData") {
      var aad = parsed.authAttrsBytes != null ? _explicitSetOf(parsed.authAttrsBytes) : Buffer.alloc(0);
      return _gcmOpen(cek, parsed.aead.nonce, eci.encryptedContent, parsed.mac, aad, keyBits, parsed.aead.icvLen);
    }
    var iv = asn1.read.octetString(asn1.decode(alg.parameters));
    if (iv.length !== 16) throw _fail();
    return _cbcOpen(cek, iv, eci.encryptedContent, keyBits);
  } catch (e) {
    if (e instanceof CmsError && e.code !== "cms/decrypt-failed") throw e;
    throw _fail();
  }
}
function _gcmOpen(cek, nonce, ct, tag, aad, keyBits, icvLen) {
  // Coverage residual: unreachable via a parsed message -- the strict parser rejects any
  // AuthEnvelopedData whose mac length != aes-ICVlen (cms/mac-length-mismatch) before we get here.
  if (!tag || tag.length !== icvLen) throw _fail();
  var d = nodeCrypto.createDecipheriv("aes-" + keyBits + "-gcm", cek, nonce, { authTagLength: icvLen });
  d.setAuthTag(tag);
  if (aad && aad.length) d.setAAD(aad);
  return Buffer.concat([d.update(ct), d.final()]); // final() throws on tag mismatch -> uniform
}
function _cbcOpen(cek, iv, ct, keyBits) {
  var d = nodeCrypto.createDecipheriv("aes-" + keyBits + "-cbc", cek, iv);
  return Buffer.concat([d.update(ct), d.final()]); // final() throws on bad pad -> uniform
}

// ---- EncryptedData (sec. 8) ------------------------------------------------
async function _decryptEncryptedData(parsed, km, opts) {
  var eci = parsed.encryptedContentInfo;
  var alg = eci.contentEncryptionAlgorithm;
  if (eci.encryptedContent == null) throw _err("cms/no-encrypted-content", "the EncryptedData has no encryptedContent");
  if (alg.oid === O("pbes2")) return _decryptPbes2(parsed, eci, km, opts);
  var keyBits = CONTENT_KEYBITS[alg.oid];
  if (!keyBits) throw _err("cms/unsupported-algorithm", "unsupported EncryptedData content algorithm " + alg.oid);
  if (km.cek == null) throw _err("cms/bad-input", "this EncryptedData needs a raw { cek }");
  var cek = guard.bytes.view(km.cek, CmsError, "cms/bad-input", "cek");
  if (cek.length !== keyBits / 8) throw _err("cms/bad-input", "the supplied cek length does not match the content algorithm");
  var iv = asn1.read.octetString(asn1.decode(alg.parameters));
  try { return { content: _cbcOpen(cek, iv, eci.encryptedContent, keyBits), contentType: eci.contentType, contentTypeName: oid.name(eci.contentType) || eci.contentType, recipientType: "cek", recipientIndex: -1, contentEncryptionAlgorithm: alg.name || alg.oid, authenticated: false }; }
  catch (_e) { throw _fail(); }
}
async function _decryptPbes2(parsed, eci, km, opts) {
  if (km.password == null) throw _err("cms/bad-input", "this EncryptedData needs a { password }");
  // The PBES2 parameters are attacker-controlled structure the strict parser surfaces raw (PBES2 is
  // not an AEAD it validates): parse them behind a structural guard so a malformed shape is a typed
  // cms/bad-input, never a raw dereference fault (the PBES2 structure is public -- not a decrypt oracle).
  var kdf, encOid, iv, pb;
  try {
    var params = _seqChildren(eci.contentEncryptionAlgorithm.parameters, 2, "PBES2 parameters");
    kdf = _requireChildren(params[0], 2, "PBES2 keyDerivationFunc");
    var encScheme = _requireChildren(params[1], 2, "PBES2 encryptionScheme");
    if (asn1.read.oid(kdf[0]) !== O("pbkdf2")) throw _err("cms/unsupported-algorithm", "PBES2 keyDerivationFunc must be PBKDF2");
    pb = _pbkdf2Params(kdf[1].bytes, opts);
    encOid = asn1.read.oid(encScheme[0]);
    iv = asn1.read.octetString(encScheme[1]);
  } catch (e) {
    if (e instanceof CmsError) throw e;
    throw _err("cms/bad-input", "malformed PBES2 parameters", e);
  }
  var keyBits = CONTENT_KEYBITS[encOid];
  if (!keyBits) throw _err("cms/unsupported-algorithm", "unsupported PBES2 content cipher " + encOid);
  var key = nodeCrypto.pbkdf2Sync(_passwordBytes(km.password), pb.salt, pb.iterations, keyBits / 8, pb.prfNode);
  try { return { content: _cbcOpen(key, iv, eci.encryptedContent, keyBits), contentType: eci.contentType, contentTypeName: oid.name(eci.contentType) || eci.contentType, recipientType: "password", recipientIndex: -1, contentEncryptionAlgorithm: oid.name(encOid) || encOid, authenticated: false }; }
  catch (_e) { throw _fail(); }
}

// ---- shared helpers (mirror cms-encrypt's builders) ------------------------
async function _aesKwUnwrap(kek, wrapped) {
  var kekKey = await subtle.importKey("raw", kek, { name: "AES-KW" }, false, ["unwrapKey"]);
  var cekKey = await subtle.unwrapKey("raw", wrapped, kekKey, { name: "AES-KW" }, { name: "AES-CBC" }, true, ["decrypt"]);
  return Buffer.from(await subtle.exportKey("raw", cekKey));
}
function _eccSharedInfo(wrapName, ukm, kekBytes) {
  var kids = [b.sequence([b.oid(O(wrapName))])];
  if (ukm) kids.push(b.explicit(0, b.octetString(ukm)));
  var supp = Buffer.alloc(4); supp.writeUInt32BE(kekBytes * 8, 0);
  kids.push(b.explicit(2, b.octetString(supp)));
  return b.sequence(kids);
}
function _kemOtherInfo(wrapName, kekBytes, ukm) {
  var kids = [b.sequence([b.oid(O(wrapName))]), b.integer(BigInt(kekBytes))];
  if (ukm) kids.push(b.explicit(0, b.octetString(ukm)));
  return b.sequence(kids);
}
// RFC 3211 double-CBC unwrap (M26): decrypt pass 2 (IV = last block of pass 1), then pass 1
// (IV = first block), validate the count + complement check bytes -- uniform failure on mismatch.
function _pwriUnwrap(kek, wrapped, iv, keyBits) {
  var blk = 16, alg = "aes-" + keyBits + "-cbc";
  if (wrapped.length < 2 * blk || wrapped.length % blk !== 0) throw _fail();
  var n = wrapped.length;
  // pass2 = CBC(kek, iv2 = pass1[last block], pass1). Recover pass1's last block by decrypting the
  // last ciphertext block (ECB) and XORing the previous ciphertext block -- a standard CBC last-
  // block decrypt that needs no IV -- then CBC-decrypt pass2 under that recovered iv2 to get pass1.
  var ecb = nodeCrypto.createDecipheriv("aes-" + keyBits + "-ecb", kek, Buffer.alloc(0)); ecb.setAutoPadding(false);
  var lastDec = Buffer.concat([ecb.update(wrapped.subarray(n - blk)), ecb.final()]);
  var iv2 = Buffer.alloc(blk);
  for (var i = 0; i < blk; i++) iv2[i] = lastDec[i] ^ wrapped[n - 2 * blk + i];
  var d1 = nodeCrypto.createDecipheriv(alg, kek, iv2); d1.setAutoPadding(false);
  var pass1 = Buffer.concat([d1.update(wrapped), d1.final()]);
  var d2 = nodeCrypto.createDecipheriv(alg, kek, iv); d2.setAutoPadding(false);
  var body = Buffer.concat([d2.update(pass1), d2.final()]);
  var count = body[0];
  if (count < 1 || count + 4 > body.length) throw _fail();
  var cek = body.subarray(4, 4 + count);
  var bad = 0;
  for (var j = 0; j < 3; j++) bad |= (body[1 + j] ^ 0xff) ^ cek[j]; // complement check bytes
  if (bad !== 0) throw _fail();
  return Buffer.from(cek);
}
// SEQUENCE structural guards -- a malformed (primitive / too-short) attacker-controlled parameter
// SEQUENCE is a typed cms/bad-input, never a raw `.children` dereference fault.
function _requireChildren(node, minLen, what) {
  if (!node || !node.children || node.children.length < minLen) throw _err("cms/bad-input", "malformed " + what);
  return node.children;
}
function _seqChildren(paramsDer, minLen, what) {
  if (paramsDer == null) throw _err("cms/bad-input", "missing " + what);
  return _requireChildren(asn1.decode(paramsDer), minLen, what);
}
function _pbkdf2Params(paramsDer, opts) {
  var node = Buffer.isBuffer(paramsDer) ? asn1.decode(paramsDer) : paramsDer;
  var kids = _requireChildren(node, 2, "PBKDF2 parameters");
  var salt = asn1.read.octetString(kids[0]);
  if (salt.length > C.LIMITS.PBKDF2_MAX_SALT) throw _err("cms/bad-input", "PBKDF2 salt exceeds the " + C.LIMITS.PBKDF2_MAX_SALT + "-octet cap");
  var iterations = guard.range.positiveInt31(asn1.read.integer(kids[1]), _err, "cms/bad-input", "PBKDF2 iterationCount");
  // A caller-supplied maxIterations must be a positive integer -- a NaN / non-number would make
  // Math.min return NaN and silently disable the DoS cap (iterations > NaN is always false).
  var cap = C.LIMITS.PBKDF2_MAX_ITERATIONS;
  if (opts.maxIterations != null) {
    if (typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations) throw _err("cms/bad-input", "maxIterations must be a positive integer");
    cap = Math.min(opts.maxIterations, cap);
  }
  if (iterations > cap) throw _err("cms/iteration-limit", "PBKDF2 iterationCount " + iterations + " exceeds the cap " + cap);
  var prfNode = "sha1";
  for (var i = 2; i < node.children.length; i++) {
    var ch = node.children[i];
    if (ch.tagClass === "universal" && ch.tagNumber === asn1.TAGS.SEQUENCE) prfNode = _prfNode(asn1.read.oid(ch.children[0]));
  }
  return { salt: salt, iterations: iterations, prfNode: prfNode };
}
// Coverage residual (the unsupported-algorithm throw arm of each lookup below -- _prfNode, _hashW3c,
// _x963Hash, and _originatorSpki that follow): reachable only from a fully well-formed recipient that
// names an inner algorithm we do not implement (a non-registry prf / OAEP hash / kari scheme /
// originator form). The producer never emits one; the fuzz harness (fuzz/cms-decrypt.fuzz.js) drives
// these arms behaviorally under the PkiError-only contract.
var PRF_NODE = {}; PRF_NODE[O("hmacWithSHA1")] = "sha1"; PRF_NODE[O("hmacWithSHA256")] = "sha256"; PRF_NODE[O("hmacWithSHA384")] = "sha384"; PRF_NODE[O("hmacWithSHA512")] = "sha512";
function _prfNode(oidStr) { if (!PRF_NODE[oidStr]) throw _err("cms/unsupported-algorithm", "unsupported PBKDF2 prf " + oidStr); return PRF_NODE[oidStr]; }

function _oaepHashFromParams(paramsBytes) {
  if (paramsBytes == null) return "SHA-1"; // absent = the RFC 4055 defaults (accept floor)
  var node = asn1.decode(paramsBytes);
  var hashName = "SHA-1", mgfHash = null, label = null;
  (node.children || []).forEach(function (ch) {
    if (ch.tagClass !== "context") return;
    if (ch.tagNumber === 0) { hashName = _hashW3c(asn1.read.oid(ch.children[0].children[0])); }               // hashAlgorithm [0]
    else if (ch.tagNumber === 1) {                                                                            // maskGenAlgorithm [1]
      var mg = ch.children[0];
      if (asn1.read.oid(mg.children[0]) !== O("mgf1")) throw _err("cms/unsupported-algorithm", "unsupported OAEP mask generation function");
      mgfHash = _hashW3c(asn1.read.oid(mg.children[1].children[0]));
    } else if (ch.tagNumber === 2) { label = asn1.read.octetString(ch.children[0].children[1]); }             // pSourceAlgorithm [2]
  });
  // WebCrypto RSA-OAEP ties the MGF1 hash to the OAEP hash and supports only an empty label -- reject,
  // rather than silently ignore, any parameter set we cannot faithfully honor.
  if (mgfHash != null && mgfHash !== hashName) throw _err("cms/unsupported-algorithm", "the OAEP MGF1 hash must equal the OAEP hash");
  if (label != null && label.length > 0) throw _err("cms/unsupported-algorithm", "a non-empty OAEP label is not supported");
  return hashName;
}
var HASH_W3C = {}; HASH_W3C[O("sha1")] = "SHA-1"; HASH_W3C[O("sha256")] = "SHA-256"; HASH_W3C[O("sha384")] = "SHA-384"; HASH_W3C[O("sha512")] = "SHA-512";
function _hashW3c(o) { if (!HASH_W3C[o]) throw _err("cms/unsupported-algorithm", "unsupported OAEP hash " + o); return HASH_W3C[o]; }

var X963_HASH = {}; // kari stdDH scheme OID -> W3C hash
[["dhSinglePass-stdDH-sha1kdf-scheme", "SHA-1"], ["dhSinglePass-stdDH-sha224kdf-scheme", "SHA-224"], ["dhSinglePass-stdDH-sha256kdf-scheme", "SHA-256"], ["dhSinglePass-stdDH-sha384kdf-scheme", "SHA-384"], ["dhSinglePass-stdDH-sha512kdf-scheme", "SHA-512"],
 ["dhSinglePass-cofactorDH-sha1kdf-scheme", "SHA-1"], ["dhSinglePass-cofactorDH-sha224kdf-scheme", "SHA-224"], ["dhSinglePass-cofactorDH-sha256kdf-scheme", "SHA-256"], ["dhSinglePass-cofactorDH-sha384kdf-scheme", "SHA-384"], ["dhSinglePass-cofactorDH-sha512kdf-scheme", "SHA-512"]
].forEach(function (r) { X963_HASH[O(r[0])] = r[1]; });
function _x963Hash(scheme) { if (!X963_HASH[scheme]) throw _err("cms/unsupported-algorithm", "unsupported kari key-agreement scheme " + scheme); return X963_HASH[scheme]; }
function _kariWrap(kea) {
  var params = asn1.decode(kea.parameters);
  var wrapOid = asn1.read.oid(params.children[0]);
  return { oid: wrapOid, name: oid.name(wrapOid) };
}
function _originatorSpki(originator) {
  // originator OriginatorIdentifierOrKey CHOICE; we require originatorKey [1] (RFC 5753 MUST for
  // ephemeral-static). The parser surfaces { form, value:{ algorithm, publicKey } } -- reconstruct
  // the SPKI (SEQUENCE { algorithm, subjectPublicKey BIT STRING }) for importKey.
  if (!originator || originator.form !== "originatorKey") throw _err("cms/unsupported-algorithm", "kari requires an originatorKey (ephemeral-static ECDH)");
  var v = originator.value;
  var algKids = [b.oid(v.algorithm.oid)];
  if (v.algorithm.parameters != null) algKids.push(b.raw(v.algorithm.parameters));
  return b.sequence([b.sequence(algKids), b.bitString(v.publicKey.bytes, v.publicKey.unusedBits)]);
}
var MONT = {}; MONT[O("X25519")] = { name: "X25519", hkdf: "SHA-256" }; MONT[O("X448")] = { name: "X448", hkdf: "SHA-512" };
function _isMont(spki) { var o = asn1.read.oid(asn1.decode(spki).children[0].children[0]); return !!MONT[o]; }
function _montName(spki) { return MONT[asn1.read.oid(asn1.decode(spki).children[0].children[0])]; }
var CURVE = {}; CURVE[O("prime256v1")] = { curve: "P-256" }; CURVE[O("secp384r1")] = { curve: "P-384" }; CURVE[O("secp521r1")] = { curve: "P-521" };
// The recipient certificate's EC curve OID -- authoritative for the kari agreement (both keys share it).
function _ecCurveFromCert(cert) {
  var spki = x509.parse(_normCertDer(cert)).subjectPublicKeyInfo;
  if (spki.algorithm.oid !== O("ecPublicKey") || spki.algorithm.parameters == null) return null;
  return asn1.read.oid(asn1.decode(spki.algorithm.parameters));
}
// Rebuild an EC SPKI with explicit namedCurve parameters (for an originator key that omitted them).
function _withEcCurveParams(spki, curveOid) {
  var node = asn1.decode(spki);
  var alg = node.children[0];
  return b.sequence([b.sequence([b.raw(alg.children[0].bytes), b.oid(curveOid)]), b.raw(node.children[1].bytes)]);
}
var MLKEM = {}; MLKEM[O("id-ml-kem-512")] = "ML-KEM-512"; MLKEM[O("id-ml-kem-768")] = "ML-KEM-768"; MLKEM[O("id-ml-kem-1024")] = "ML-KEM-1024";
function _mlkemName(o) { return MLKEM[o]; }

function _explicitSetOf(implicitBytes) {
  // The AAD is the authAttrs re-encoded under the EXPLICIT SET OF tag (RFC 5083 sec. 2.2). The
  // parser surfaces authAttrsBytes as the transmitted [1] IMPLICIT form; retag 0xA1 -> 0x31.
  var out = Buffer.from(implicitBytes);
  out[0] = 0x31;
  return out;
}
function _normKeyDer(key) {
  if (Buffer.isBuffer(key)) return key;
  if (key instanceof Uint8Array) return Buffer.from(key);
  if (typeof key === "string") { try { return pkcs8.pemDecode(key); } catch (e) { throw _err("cms/bad-input", "the recipient private-key PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "the recipient private key must be a PKCS#8 DER Buffer or PEM string");
}
function _normCertDer(cert) {
  if (Buffer.isBuffer(cert)) return cert;
  if (cert instanceof Uint8Array) return Buffer.from(cert);
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("cms/bad-input", "the recipient certificate PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "the recipient certificate must be a DER Buffer or PEM string");
}
function _passwordBytes(p) {
  if (Buffer.isBuffer(p)) return p;
  if (p instanceof Uint8Array) return Buffer.from(p);
  if (typeof p === "string") return Buffer.from(p, "utf8");
  throw _err("cms/bad-input", "a password must be a string, Buffer, or Uint8Array");
}

module.exports = { decrypt: decrypt };
