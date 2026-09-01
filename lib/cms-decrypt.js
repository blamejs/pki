// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// @primitive pki.cms.decrypt block live in cms-verify.js, which re-exports this function.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkcs8 = require("./schema-pkcs8");
var schemaCms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var pbes2 = require("./pbes2");
var C = require("./constants");
var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var CmsError = frameworkError.CmsError;
var WRAP_KEK_LENGTHS = schemaCms.WRAP_KEK_LENGTHS;
var KEM_CT_LENGTHS = schemaCms.KEM_CT_LENGTHS;
var AEAD_ALGS = schemaCms.AEAD_ALGS;

function O(n) { return oid.byName(n); }
function _err(code, message, cause) { return new CmsError(code, message, cause); }
function _fail() { return new CmsError("cms/decrypt-failed", "the CMS content could not be decrypted (uniform by design -- padding / integrity / key-unwrap failures are indistinguishable to defeat oracles)"); }

var CONTENT_KEYBITS = pbes2.CONTENT_KEYBITS;
var CONTENT_MODE = pbes2.CONTENT_MODE;

async function decrypt(input, keyMaterial, opts) {
  opts = opts || {};
  if (keyMaterial == null || typeof keyMaterial !== "object") throw _err("cms/bad-input", "decrypt requires a key-material object");
  var parsed = _parse(input);
  var ct = parsed.contentTypeName;
  if (ct === "encryptedData") return _decryptEncryptedData(parsed, keyMaterial, opts);
  if (ct === "authData") return _verifyAuthenticatedData(parsed, keyMaterial, opts);
  if (ct !== "envelopedData" && ct !== "authEnvelopedData") throw _err("cms/bad-input", "input is not an EnvelopedData / AuthEnvelopedData / EncryptedData / AuthenticatedData (got " + ct + ")");
  return decryptEnvelopedData(parsed, keyMaterial, opts, ct);
}

// @internal
function _originFields(res, authenticatedBy, originatorInfo) {
  res.authenticatedBy = authenticatedBy || null;
  res.originAuthenticated = false;
  res.originatorInfo = originatorInfo || null;
  return res;
}

async function decryptEnvelopedData(parsed, keyMaterial, opts, contentTypeName) {
  opts = opts || {};
  if (keyMaterial == null || typeof keyMaterial !== "object") throw _err("cms/bad-input", "decrypt requires a key-material object");
  var ct = contentTypeName || "envelopedData";
  var recips = parsed.recipientInfos || [];
  var candidates = _selectCandidates(recips, keyMaterial, opts);
  var eci = parsed.encryptedContentInfo;
  _assertContentCipherMode(eci, ct);
  for (var ci = 0; ci < candidates.length; ci++) {
    try {
      _assertSupported(candidates[ci].ri, keyMaterial);
      var cek = await _acquireCek(candidates[ci].ri, keyMaterial, opts);
      try {
        var streamMode = opts.stream === true ? (candidates.length > 1 ? "eager" : "lazy") : null;
        var content = await _openContent(parsed, eci, cek, ct, streamMode);
        return _originFields({
          content: content,
          contentType: eci.contentType, contentTypeName: oid.name(eci.contentType) || eci.contentType,
          recipientType: candidates[ci].ri.type, recipientIndex: candidates[ci].index,
          contentEncryptionAlgorithm: eci.contentEncryptionAlgorithm.name || eci.contentEncryptionAlgorithm.oid,
          authenticated: ct === "authEnvelopedData",
        }, ct === "authEnvelopedData" ? "content-encryption-key" : null, parsed.originatorInfo);
      } finally {
        guard.secret.zeroize(cek, CmsError, "cms/bad-input", "the recovered content-encryption key");
      }
    } catch (e) {
      if (candidates.length === 1) throw e;
    }
  }
  throw _fail();
}

function _parse(input) {
  return schemaCms.parse(_toDer(input));
}
function _toDer(input) {
  if (guard.bytes.isByteSource(input)) return guard.bytes.snapshotSource(input, CmsError, "cms/bad-input", "input");
  if (typeof input === "string") { try { return schemaCms.pemDecode(input); } catch (e) { throw _err("cms/bad-input", "the CMS PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "input must be a DER Buffer, Uint8Array, or PEM string");
}

function _selectCandidates(recips, km, opts) {
  if (!recips.length) throw _err("cms/no-matching-recipient", "the message carries no RecipientInfos");
  if (opts.recipientIndex != null) {
    var i = opts.recipientIndex;
    if (typeof i !== "number" || !isFinite(i) || i < 0 || i >= recips.length || Math.floor(i) !== i) throw _err("cms/bad-input", "recipientIndex must be an in-range integer");
    return [{ ri: recips[i], index: i }];
  }
  var want = _riKindForKey(km);
  var cert = km.cert != null ? x509.parse(_normCertDer(km.cert)) : null;
  var out = [];
  for (var k = 0; k < recips.length; k++) {
    var r = recips[k];
    if (want === "asym" && (r.type === "ktri" || r.type === "kari" || r.type === "ori")) {
      if (cert && _ridMatches(r, cert)) out.push({ ri: r, index: k });
    } else if (want === "pwri" && r.type === "pwri") { out.push({ ri: r, index: k }); }
    else if (want === "kekri" && r.type === "kekri") {
      if (km.kekId == null || _kekIdMatches(r, km.kekId)) out.push({ ri: r, index: k });
    }
  }
  if (!out.length) throw _err("cms/no-matching-recipient", "no recipient matches the supplied key material");
  return out;
}
function _riKindForKey(km) {
  if (km.password != null) return "pwri";
  if (km.kek != null) return "kekri";
  if (km.key != null) return "asym";
  throw _err("cms/bad-input", "key material needs { key, cert }, { password }, { kek }, or { cek }");
}
function _assertSupported(ri, km) {
  if (ri.type === "kari" && ri.keyEncryptionAlgorithm && intrinsic.stringIndexOf(intrinsic.toLowerCase(ri.keyEncryptionAlgorithm.name || ""), "mqv") !== -1) throw _err("cms/unsupported-algorithm", "ECMQV kari is not supported");
  if (ri.type === "ori") {
    if (ri.oriType !== O("kem")) throw _err("cms/unsupported-recipient-type", "unsupported OtherRecipientInfo type " + ri.oriType);
    if (ri.kemri && ri.kemri.kem && ri.kemri.kem.oid === O("id-kem-rsa")) throw _err("cms/unsupported-algorithm", "RSA-KEM is not supported");
  }
  void km;
}

function _ridMatches(ri, cert) {
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
  return false;
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

var _passThrough = { "cms/unsupported-algorithm": 1, "cms/unsupported-recipient-type": 1, "cms/bad-input": 1, "cms/iteration-limit": 1, "cms/missing-key-derivation": 1, "cms/no-encrypted-content": 1 };

async function _acquireCek(ri, km, opts) {
  try {
    if (ri.type === "ktri") return await _ktriCek(ri, km);
    if (ri.type === "kari") return await _kariCek(ri, km);
    if (ri.type === "kekri") return await _kekriCek(ri, km);
    if (ri.type === "pwri") return await _pwriCek(ri, km, opts);
    if (ri.type === "ori") return await _kemriCek(ri, km);
  } catch (e) {
    if (e instanceof CmsError && _passThrough[e.code]) throw e;
    throw _fail();
  }
  throw _err("cms/unsupported-recipient-type", "unsupported recipient type " + ri.type);
}

async function _ktriCek(ri, km) {
  var kea = ri.keyEncryptionAlgorithm;
  var k = _normKeyDer(km.key);
  try {
    if (kea.oid === O("rsaesOaep")) {
      var hash = _oaepHashFromParams(kea.parameters);
      var pub = await subtle.importKey("pkcs8", k.der, { name: "RSA-OAEP", hash: hash }, false, ["decrypt"]);
      return Buffer.from(await subtle.decrypt({ name: "RSA-OAEP" }, pub, ri.encryptedKey));
    }
    if (kea.oid === O("rsaEncryption")) {
      var keyObj = nodeCrypto.createPrivateKey({ key: k.der, format: "der", type: "pkcs8" });
      try { return nodeCrypto.privateDecrypt({ key: keyObj, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, ri.encryptedKey); }
      catch (_e) {
        return null;
      }
    }
    throw _err("cms/unsupported-algorithm", "unsupported ktri keyEncryptionAlgorithm " + kea.oid);
  } finally {
    _releaseKeyDer(k);
  }
}

async function _kariCek(ri, km) {
  var k = _normKeyDer(km.key);
  var kek, z, mz;
  try {
    var keyDer = k.der;
    var kea = ri.keyEncryptionAlgorithm;
    var wrapAlg = _kariWrap(kea);
    var scheme = kea.oid;
    var origSpki = _originatorSpki(ri.originator);
    var rek = (km.cert != null && _kariRekFor(ri, x509.parse(_normCertDer(km.cert)))) || ri.recipientEncryptedKeys[0];
    var kekBytes = WRAP_KEK_LENGTHS[wrapAlg.oid];
    if (!kekBytes) throw _err("cms/unsupported-algorithm", "unsupported kari key-wrap");
    var ukm = ri.ukm || null;
    if (_isMont(origSpki)) {
      var mont = _montName(origSpki);
      var recipPriv = await subtle.importKey("pkcs8", keyDer, { name: mont.name }, false, ["deriveBits"]);
      var origPub = await subtle.importKey("spki", origSpki, { name: mont.name }, false, []);
      mz = Buffer.from(await subtle.deriveBits({ name: mont.name, public: origPub }, recipPriv, null));
      if (mz.every(function (x) { return x === 0; })) throw _fail();
      var mzKey = await subtle.importKey("raw", mz, { name: "HKDF" }, false, ["deriveBits"]);
      kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: mont.hkdf, salt: ukm || Buffer.alloc(0), info: _eccSharedInfo(wrapAlg.name, ukm, kekBytes) }, mzKey, kekBytes * 8));
    } else {
      var origAlg = asn1.decode(origSpki).children[0];
      var origHasParams = origAlg.children.length > 1;
      var curveOid = (km.cert != null && _ecCurveFromCert(km.cert)) || (origHasParams ? asn1.read.oid(origAlg.children[1]) : null);
      var curve = curveOid ? CURVE[curveOid] : null;
      if (!curve) throw _err("cms/unsupported-algorithm", "unsupported or missing originator EC curve");
      var origSpkiFull = origHasParams ? origSpki : _withEcCurveParams(origSpki, curveOid);
      var recipEc = await subtle.importKey("pkcs8", keyDer, { name: "ECDH", namedCurve: curve.curve }, false, ["deriveBits"]);
      var origEc = await subtle.importKey("spki", origSpkiFull, { name: "ECDH", namedCurve: curve.curve }, false, []);
      z = Buffer.from(await subtle.deriveBits({ name: "ECDH", public: origEc }, recipEc, null));
      var zKey = await subtle.importKey("raw", z, { name: "X963KDF" }, false, ["deriveBits"]);
      kek = Buffer.from(await subtle.deriveBits({ name: "X963KDF", hash: _x963Hash(scheme), info: _eccSharedInfo(wrapAlg.name, ukm, kekBytes) }, zKey, kekBytes * 8));
    }
    return await _aesKwUnwrap(kek, rek.encryptedKey);
  } finally {
    guard.secret.zeroizeAll([z, mz, kek], CmsError, "cms/bad-input", "the key-agreement shared secret");
    _releaseKeyDer(k);
  }
}

async function _kekriCek(ri, km) {
  var kek = guard.bytes.view(km.kek, CmsError, "cms/bad-input", "kek");
  return await _aesKwUnwrap(kek, ri.encryptedKey);
}

async function _pwriCek(ri, km, opts) {
  var kdf = ri.keyDerivationAlgorithm;
  if (!kdf) throw _err("cms/missing-key-derivation", "the pwri recipient has no keyDerivationAlgorithm (externally-supplied KEK is not supported)");
  if (kdf.oid !== O("pbkdf2")) throw _err("cms/unsupported-algorithm", "unsupported pwri key-derivation " + kdf.oid);
  var pb = pbes2.parsePbkdf2Params(kdf.parameters, opts, _err, "cms");
  var kea = ri.keyEncryptionAlgorithm;
  if (kea.oid !== O("id-alg-PWRI-KEK")) throw _err("cms/unsupported-algorithm", "unsupported pwri key-encryption " + kea.oid);
  var inner = asn1.decode(kea.parameters);
  var innerOid = asn1.read.oid(inner.children[0]);
  var innerBits = CONTENT_KEYBITS[innerOid];
  if (!innerBits || CONTENT_MODE[innerOid] !== "cbc") throw _err("cms/unsupported-algorithm", "unsupported pwri inner cipher");
  var iv = asn1.read.octetString(inner.children[1]);
  var pw = pbes2.passwordBytesOwned(km.password, _err, "cms");
  var kek;
  try { kek = nodeCrypto.pbkdf2Sync(pw.bytes, pb.salt, pb.iterations, innerBits / 8, pb.prfNode); }
  finally { if (pw.owned) guard.secret.zeroize(pw.bytes, CmsError, "cms/bad-input", "the password encoding"); }
  try {
    return _pwriUnwrap(kek, ri.encryptedKey, iv, innerBits);
  } finally {
    guard.secret.zeroize(kek, CmsError, "cms/bad-input", "the password-derived key-encryption key");
  }
}

async function _kemriCek(ri, km) {
  var k = ri.kemri;
  var wcName = _mlkemName(k.kem.oid);
  if (!wcName) throw _err("cms/unsupported-algorithm", "unsupported KEM " + k.kem.oid);
  if (k.kdf.oid !== O("hkdfWithSha256")) throw _err("cms/unsupported-algorithm", "unsupported KEM key-derivation " + k.kdf.oid);
  var wantCt = KEM_CT_LENGTHS[k.kem.oid];
  var kemct = k.kemct;
  if (wantCt && kemct.length !== wantCt) throw _fail();
  var kekBytes = Number(k.kekLength);
  var wrapAlg = k.wrap;
  if (WRAP_KEK_LENGTHS[wrapAlg.oid] !== kekBytes) throw _fail();
  var keyCopy = _normKeyDer(km.key);
  var priv;
  try { priv = await subtle.importKey("pkcs8", keyCopy.der, { name: wcName }, false, ["decapsulateBits"]); }
  finally { _releaseKeyDer(keyCopy); }
  var ss = null, kek = null, ssAb = null, kekAb = null;
  try {
    ssAb = await subtle.decapsulateBits({ name: wcName }, priv, kemct);
    ss = Buffer.from(ssAb);
    var ssKey = await subtle.importKey("raw", ss, { name: "HKDF" }, false, ["deriveBits"]);
    kekAb = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.alloc(0), info: _kemOtherInfo(wrapAlg.name, kekBytes, k.ukm || null) }, ssKey, kekBytes * 8);
    kek = Buffer.from(kekAb);
    return await _aesKwUnwrap(kek, k.encryptedKey);
  } finally {
    guard.secret.zeroizeAll([ss, kek, ssAb ? new Uint8Array(ssAb) : null, kekAb ? new Uint8Array(kekAb) : null],
      CmsError, "cms/bad-input", "the KEM shared secret");
  }
}

function _assertContentCipherMode(eci, ct) {
  var oidStr = eci.contentEncryptionAlgorithm.oid;
  var isAead = intrinsic.hasOwn(AEAD_ALGS, oidStr);
  if (!isAead && !intrinsic.hasOwn(CONTENT_MODE, oidStr)) return;
  if (ct === "authEnvelopedData") {
    if (isAead) return;
    throw _err("cms/unsupported-algorithm", "contentEncryptionAlgorithm " + oidStr + " is not an authenticated encryption algorithm, which authEnvelopedData requires (RFC 5083 sec. 2)");
  }
  if (!isAead) return;
  throw _err("cms/unsupported-algorithm", "contentEncryptionAlgorithm " + oidStr + " is an authenticated encryption algorithm, which belongs in an authEnvelopedData rather than a " + ct + " (RFC 5083 sec. 2)");
}

async function _openContent(parsed, eci, cek, ct, streamMode) {
  var alg = eci.contentEncryptionAlgorithm;
  var keyBits = intrinsic.hasOwn(CONTENT_KEYBITS, alg.oid) ? CONTENT_KEYBITS[alg.oid] : 0;
  if (!keyBits) {
    if (intrinsic.hasOwn(AEAD_ALGS, alg.oid) && AEAD_ALGS[alg.oid] === "ccm") {
      throw _err("cms/unsupported-algorithm", "contentEncryptionAlgorithm " + alg.oid + " is AES-CCM. RFC 5084 sec. 3.1 permits it for this content type; this toolkit implements AES-GCM only for content encryption");
    }
    throw _err("cms/unsupported-algorithm", "unsupported contentEncryptionAlgorithm " + alg.oid);
  }
  if (eci.encryptedContent == null) throw _err("cms/no-encrypted-content", "the message has no encryptedContent (detached; supply it out of band)");
  var substitute = null;
  if (cek == null || cek.length !== keyBits / 8) { substitute = nodeCrypto.randomBytes(keyBits / 8); cek = substitute; }
  try {
    if (ct === "authEnvelopedData") {
      var aad = parsed.authAttrsBytes != null ? _explicitSetOf(parsed.authAttrsBytes) : Buffer.alloc(0);
      var pt = _gcmOpen(cek, parsed.aead.nonce, eci.encryptedContent, parsed.mac, aad, keyBits, parsed.aead.icvLen);
      return streamMode ? _bufferChunks(pt) : pt;
    }
    var iv = asn1.read.octetString(asn1.decode(alg.parameters));
    if (iv.length !== 16) throw _fail();
    if (streamMode === "lazy") return _cbcStream(cek, iv, eci.encryptedContent, keyBits);
    if (streamMode === "eager") return _bufferChunks(pbes2.cbcDecrypt(cek, iv, eci.encryptedContent, keyBits, CmsError, "cms/decrypt-failed"));
    return pbes2.cbcDecrypt(cek, iv, eci.encryptedContent, keyBits, CmsError, "cms/decrypt-failed");
  } catch (e) {
    if (e instanceof CmsError && e.code !== "cms/decrypt-failed") throw e;
    throw _fail();
  } finally {
    guard.secret.zeroize(substitute, CmsError, "cms/bad-input", "the implicit-rejection substitute content key");
  }
}
function _gcmOpen(cek, nonce, ct, tag, aad, keyBits, icvLen) {
  if (!tag || tag.length !== icvLen) throw _fail();
  var d = nodeCrypto.createDecipheriv("aes-" + keyBits + "-gcm", cek, nonce, { authTagLength: icvLen });
  d.setAuthTag(tag);
  if (aad && aad.length) d.setAAD(aad);
  return guard.secret.cipherFinish(d, ct, CmsError, "cms/decrypt-failed", "the recovered content");
}

async function* _bufferChunks(buf) {
  var chunk = C.BYTES.kib(64);
  for (var off = 0; off < buf.length; off += chunk) {
    var end = off + chunk;
    yield intrinsic.subarray(buf, off, end < buf.length ? end : buf.length);
  }
}
function _cbcStream(key, iv, ct, keyBits) {
  return _translateCbcStream(subtle.decryptStream({ algNode: "aes-" + keyBits + "-cbc", key: key, iv: iv }, ct));
}
async function* _translateCbcStream(engineIter) {
  try { for await (var chunk of engineIter) yield chunk; }
  catch (_e) { throw _fail(); }
}

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
  try { return _originFields({ content: opts.stream === true ? _cbcStream(cek, iv, eci.encryptedContent, keyBits) : pbes2.cbcDecrypt(cek, iv, eci.encryptedContent, keyBits, CmsError, "cms/decrypt-failed"), contentType: eci.contentType, contentTypeName: oid.name(eci.contentType) || eci.contentType, recipientType: "cek", recipientIndex: -1, contentEncryptionAlgorithm: alg.name || alg.oid, authenticated: false }, null, null); }
  catch (_e) { throw _fail(); }
}
async function _decryptPbes2(parsed, eci, km, opts) {
  if (km.password == null) throw _err("cms/bad-input", "this EncryptedData needs a { password }");
  var kdf, encOid, iv, pb;
  try {
    var params = pbes2.seqChildren(eci.contentEncryptionAlgorithm.parameters, 2, "PBES2 parameters", _err, "cms");
    kdf = pbes2.requireChildren(params[0], 2, "PBES2 keyDerivationFunc", _err, "cms");
    var encScheme = pbes2.requireChildren(params[1], 2, "PBES2 encryptionScheme", _err, "cms");
    if (asn1.read.oid(kdf[0]) !== O("pbkdf2")) throw _err("cms/unsupported-algorithm", "PBES2 keyDerivationFunc must be PBKDF2");
    pb = pbes2.parsePbkdf2Params(kdf[1].bytes, opts, _err, "cms");
    encOid = asn1.read.oid(encScheme[0]);
    iv = asn1.read.octetString(encScheme[1]);
  } catch (e) {
    if (e instanceof CmsError) throw e;
    throw _err("cms/bad-input", "malformed PBES2 parameters", e);
  }
  var keyBits = CONTENT_KEYBITS[encOid];
  if (!keyBits) throw _err("cms/unsupported-algorithm", "unsupported PBES2 content cipher " + encOid);
  var pwE = pbes2.passwordBytesOwned(km.password, _err, "cms");
  var key;
  try { key = nodeCrypto.pbkdf2Sync(pwE.bytes, pb.salt, pb.iterations, keyBits / 8, pb.prfNode); }
  finally { if (pwE.owned) guard.secret.zeroize(pwE.bytes, CmsError, "cms/bad-input", "the password encoding"); }
  try { return _originFields({ content: opts.stream === true ? _cbcStream(key, iv, eci.encryptedContent, keyBits) : pbes2.cbcDecrypt(key, iv, eci.encryptedContent, keyBits, CmsError, "cms/decrypt-failed"), contentType: eci.contentType, contentTypeName: oid.name(eci.contentType) || eci.contentType, recipientType: "password", recipientIndex: -1, contentEncryptionAlgorithm: oid.name(encOid) || encOid, authenticated: false }, null, null); }
  catch (_e) { throw _fail(); }
  finally { guard.secret.zeroize(key, CmsError, "cms/bad-input", "the password-derived content-encryption key"); }
}

async function _aesKwUnwrap(kek, wrapped) {
  var kekKey = await subtle.importKey("raw", kek, { name: "AES-KW" }, false, ["unwrapKey"]);
  var raw = await subtle.unwrapKey("raw", wrapped, kekKey, { name: "AES-KW" }, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
  var rawAb = await subtle.exportKey("raw", raw);
  try {
    var view = new Uint8Array(rawAb);
    var out = Buffer.alloc(view.length);
    out.set(view);
    return out;
  } finally {
    guard.secret.zeroize(new Uint8Array(rawAb), CmsError, "cms/bad-input", "the unwrapped content key");
  }
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
function _pwriUnwrap(kek, wrapped, iv, keyBits) {
  var blk = 16, alg = "aes-" + keyBits + "-cbc";
  if (wrapped.length < 2 * blk || wrapped.length % blk !== 0) throw _fail();
  var n = wrapped.length;
  var lastDec = null, pass1 = null, body = null;
  try {
    var ecb = nodeCrypto.createDecipheriv("aes-" + keyBits + "-ecb", kek, Buffer.alloc(0)); ecb.setAutoPadding(false);
    lastDec = guard.secret.cipherFinish(ecb, wrapped.subarray(n - blk), CmsError, "cms/decrypt-failed", "the recovered CBC last block");
    var iv2 = Buffer.alloc(blk);
    for (var i = 0; i < blk; i++) iv2[i] = lastDec[i] ^ wrapped[n - 2 * blk + i];
    var d1 = nodeCrypto.createDecipheriv(alg, kek, iv2); d1.setAutoPadding(false);
    pass1 = guard.secret.cipherFinish(d1, wrapped, CmsError, "cms/decrypt-failed", "the PWRI first-pass plaintext");
    var d2 = nodeCrypto.createDecipheriv(alg, kek, iv); d2.setAutoPadding(false);
    body = guard.secret.cipherFinish(d2, pass1, CmsError, "cms/decrypt-failed", "the PWRI plaintext block");
    var count = body[0];
    if (count < 1 || count + 4 > body.length) throw _fail();
    var cek = body.subarray(4, 4 + count);
    var bad = 0;
    for (var j = 0; j < 3; j++) bad |= (body[1 + j] ^ 0xff) ^ cek[j];
    if (bad !== 0) throw _fail();
    return Buffer.from(cek);
  } finally {
    guard.secret.zeroizeAll([body, pass1, lastDec], CmsError, "cms/bad-input", "the PWRI plaintext block");
  }
}

function _oaepHashFromParams(paramsBytes) {
  if (paramsBytes == null) return "SHA-1";
  var node = asn1.decode(paramsBytes);
  var hashName = "SHA-1", mgfHash = null, label = null;
  (node.children || []).forEach(function (ch) {
    if (ch.tagClass !== "context") return;
    if (ch.tagNumber === 0) { hashName = _hashW3c(asn1.read.oid(ch.children[0].children[0])); }
    else if (ch.tagNumber === 1) {
      var mg = ch.children[0];
      if (asn1.read.oid(mg.children[0]) !== O("mgf1")) throw _err("cms/unsupported-algorithm", "unsupported OAEP mask generation function");
      mgfHash = _hashW3c(asn1.read.oid(mg.children[1].children[0]));
    } else if (ch.tagNumber === 2) { label = asn1.read.octetString(ch.children[0].children[1]); }
  });
  if (mgfHash != null && mgfHash !== hashName) throw _err("cms/unsupported-algorithm", "the OAEP MGF1 hash must equal the OAEP hash");
  if (label != null && label.length > 0) throw _err("cms/unsupported-algorithm", "a non-empty OAEP label is not supported");
  return hashName;
}
var HASH_W3C = {}; HASH_W3C[O("sha1")] = "SHA-1"; HASH_W3C[O("sha256")] = "SHA-256"; HASH_W3C[O("sha384")] = "SHA-384"; HASH_W3C[O("sha512")] = "SHA-512";
function _hashW3c(o) { if (!HASH_W3C[o]) throw _err("cms/unsupported-algorithm", "unsupported OAEP hash " + o); return HASH_W3C[o]; }

var X963_HASH = {};
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
function _ecCurveFromCert(cert) {
  var spki = x509.parse(_normCertDer(cert)).subjectPublicKeyInfo;
  if (spki.algorithm.oid !== O("ecPublicKey") || spki.algorithm.parameters == null) return null;
  return asn1.read.oid(asn1.decode(spki.algorithm.parameters));
}
function _withEcCurveParams(spki, curveOid) {
  var node = asn1.decode(spki);
  var alg = node.children[0];
  return b.sequence([b.sequence([b.raw(alg.children[0].bytes), b.oid(curveOid)]), b.raw(node.children[1].bytes)]);
}
var MLKEM = {}; MLKEM[O("id-ml-kem-512")] = "ML-KEM-512"; MLKEM[O("id-ml-kem-768")] = "ML-KEM-768"; MLKEM[O("id-ml-kem-1024")] = "ML-KEM-1024";
function _mlkemName(o) { return MLKEM[o]; }

function _explicitSetOf(implicitBytes) {
  var out = Buffer.from(implicitBytes);
  out[0] = 0x31;
  return out;
}

var MAC_HASH = { hmacWithSHA256: "SHA-256", hmacWithSHA384: "SHA-384", hmacWithSHA512: "SHA-512" };
var DIGEST_WC = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
var MAC_KEY_MIN_OCTETS = 16;
function _isDerNull(p) { return Buffer.isBuffer(p) && p.length === 2 && p[0] === 0x05 && p[1] === 0x00; }

async function _verifyAuthenticatedData(parsed, km, opts) {
  var macAlg = parsed.macAlgorithm;
  var hash = MAC_HASH[macAlg.name];
  if (!hash) throw _err("cms/unsupported-algorithm", "unsupported macAlgorithm " + JSON.stringify(macAlg.name || macAlg.oid) + " (HMAC-SHA-256/384/512 only)");
  if (macAlg.parameters != null && !_isDerNull(macAlg.parameters)) throw _err("cms/unsupported-algorithm", "the macAlgorithm parameters must be absent or DER NULL (RFC 3370)");
  var content = parsed.encapContentInfo.eContent;
  if (content == null) throw _err("cms/bad-input", "a detached AuthenticatedData (absent eContent) is not supported");

  var preimage, mdCheck = null;
  if (parsed.authAttrsBytes) {
    var dHash = DIGEST_WC[parsed.digestAlgorithm && parsed.digestAlgorithm.name];
    if (!dHash) throw _err("cms/unsupported-algorithm", "unsupported digestAlgorithm " + JSON.stringify(parsed.digestAlgorithm && parsed.digestAlgorithm.name));
    preimage = _explicitSetOf(parsed.authAttrsBytes);
    var mdAttr = (parsed.authAttrs || []).filter(function (a) { return a.type === O("messageDigest"); })[0];
    mdCheck = { hash: dHash, declared: asn1.read.octetString(asn1.decode(mdAttr.values[0])) };
  } else {
    preimage = Buffer.from(content);
  }

  var candidates = _selectCandidates(parsed.recipientInfos || [], km, opts);
  for (var ci = 0; ci < candidates.length; ci++) {
    try {
      _assertSupported(candidates[ci].ri, km);
      var macKey = await _acquireCek(candidates[ci].ri, km, opts);
      var macSubstitute = null;
      if (macKey == null || macKey.length < MAC_KEY_MIN_OCTETS) macSubstitute = nodeCrypto.randomBytes(MAC_KEY_MIN_OCTETS);
      try {
        var key = await subtle.importKey("raw", macSubstitute || macKey, { name: "HMAC", hash: hash }, false, ["verify"]);
        if (!(await subtle.verify({ name: "HMAC" }, key, Buffer.from(parsed.mac), preimage))) throw _fail();
        if (mdCheck) {
          var actual = Buffer.from(await subtle.digest(mdCheck.hash, content));
          if (!actual.equals(mdCheck.declared)) throw _fail();
        }
        var authedContent = Buffer.from(content);
        return _originFields({
          content: opts.stream === true ? _bufferChunks(authedContent) : authedContent,
          contentType: parsed.encapContentInfo.eContentType, contentTypeName: oid.name(parsed.encapContentInfo.eContentType) || parsed.encapContentInfo.eContentType,
          recipientType: candidates[ci].ri.type, recipientIndex: candidates[ci].index,
          macAlgorithm: macAlg.name || macAlg.oid,
          digestAlgorithm: parsed.digestAlgorithm ? (parsed.digestAlgorithm.name || parsed.digestAlgorithm.oid) : null,
          authenticated: true,
        }, "message-authentication-key", parsed.originatorInfo);
      } finally {
        guard.secret.zeroizeAll([macKey, macSubstitute], CmsError, "cms/bad-input", "the message-authentication key");
      }
    } catch (e) {
      if (candidates.length === 1) throw e;
    }
  }
  throw _fail();
}
function _normKeyDer(key) {
  if (Buffer.isBuffer(key)) return { der: key, owned: false };
  if (key instanceof Uint8Array) return { der: Buffer.from(key), owned: true };
  if (typeof key === "string") {
    var der;
    try { der = pkcs8.pemDecode(key); }
    catch (e) { throw _err("cms/bad-input", "the recipient private-key PEM could not be decoded", e); }
    return { der: der, owned: true };
  }
  throw _err("cms/bad-input", "the recipient private key must be a PKCS#8 DER Buffer or PEM string");
}
function _releaseKeyDer(k) {
  if (k && k.owned) guard.secret.zeroize(k.der, CmsError, "cms/bad-input", "the recipient private-key copy");
}
function _normCertDer(cert) {
  if (guard.bytes.isByteSource(cert)) return guard.bytes.snapshotSource(cert, CmsError, "cms/bad-input", "the recipient certificate");
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("cms/bad-input", "the recipient certificate PEM could not be decoded", e); } }
  throw _err("cms/bad-input", "the recipient certificate must be a DER Buffer or PEM string");
}

module.exports = { decrypt: decrypt, decryptEnvelopedData: decryptEnvelopedData };
