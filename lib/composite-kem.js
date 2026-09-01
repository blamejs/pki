// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.kem
 * @nav        Protocols
 * @title      Composite ML-KEM
 * @fullname   Composite ML-KEM (draft-ietf-lamps-pq-composite-kem)
 * @intro Composite ML-KEM key establishment (draft-ietf-lamps-pq-composite-kem): a post-quantum
 *   ML-KEM hybridized with a traditional RSA-OAEP, ECDH, X25519, or X448, so the established shared
 *   secret stays secure as long as EITHER component is unbroken. pki.kem.encapsulate turns a
 *   recipient's composite public key into a 256-bit shared secret and a ciphertext; pki.kem.decapsulate
 *   recovers the same secret from that ciphertext and the composite private key. Each component KEM
 *   runs independently, and the two secrets are mixed through the SHA3-256 combiner that also binds the
 *   traditional ciphertext, the traditional public key, and a per-algorithm label. All twelve registered
 *   algorithms -- ML-KEM-768 and ML-KEM-1024 paired with RSA-OAEP 2048/3072/4096, ECDH over
 *   P-256/P-384/P-521 and brainpool, X25519, and X448 -- are verified against the draft Appendix G
 *   known-answer vectors.
 * @spec draft-ietf-lamps-pq-composite-kem
 * @card Establish a shared secret with a hybrid post-quantum plus traditional KEM.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var webcrypto = require("./webcrypto");
var nodeCrypto = require("node:crypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var pkix = require("./schema-pkix");
var schemaPkcs8 = require("./schema-pkcs8");
var subtle = webcrypto.webcrypto.subtle;
var _b = asn1.build;
var KemError = frameworkError.KemError;
var PemError = frameworkError.PemError;
function _err(code, message, cause) { return new KemError(code, message, cause); }

function _toDer(input, pemLabel, what) {
  if (typeof input === "string") return _pemToDer(input, pemLabel);
  var buf = guard.bytes.snapshotSource(input, KemError, "kem/bad-input", what);
  if (pkix.isPemArmor(buf)) return _pemToDer(buf, pemLabel);
  return buf;
}
function _pemToDer(text, label) {
  try { return pkix.pemDecode(text, label, PemError); }
  catch (e) { throw _err("kem/bad-key", "the PEM input is not a valid " + label + " block", e); }
}

var COMPOSITE_KEM = {};
function _comp(name, mlkemBits, label, trad) {
  var mlOidName = "id-ml-kem-" + mlkemBits;
  var kp = oid.kemParams(mlOidName);
  COMPOSITE_KEM[oid.byName(name)] = {
    name: name, mlkemWc: "ML-KEM-" + mlkemBits, mlkemOidName: mlOidName,
    mlkemCt: kp.ct, mlkemEk: kp.ek, label: label, trad: trad,
  };
}
_comp("id-MLKEM768-RSA2048-SHA3-256", 768, Buffer.from("MLKEM768-RSAOAEP2048", "ascii"), { kind: "rsa", bits: 2048, ctLen: 256 });
_comp("id-MLKEM768-RSA3072-SHA3-256", 768, Buffer.from("MLKEM768-RSAOAEP3072", "ascii"), { kind: "rsa", bits: 3072, ctLen: 384 });
_comp("id-MLKEM768-RSA4096-SHA3-256", 768, Buffer.from("MLKEM768-RSAOAEP4096", "ascii"), { kind: "rsa", bits: 4096, ctLen: 512 });
_comp("id-MLKEM768-X25519-SHA3-256", 768, Buffer.from("5c2e2f2f5e5c", "hex"), { kind: "okp", curve: "X25519", ctLen: 32 });
_comp("id-MLKEM768-ECDH-P256-SHA3-256", 768, Buffer.from("MLKEM768-P256", "ascii"), { kind: "ec", node: "prime256v1", curve: "prime256v1", ctLen: 65 });
_comp("id-MLKEM768-ECDH-P384-SHA3-256", 768, Buffer.from("MLKEM768-P384", "ascii"), { kind: "ec", node: "secp384r1", curve: "secp384r1", ctLen: 97 });
_comp("id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256", 768, Buffer.from("MLKEM768-BP256", "ascii"), { kind: "ec", node: "brainpoolP256r1", curve: "brainpoolP256r1", ctLen: 65 });
_comp("id-MLKEM1024-RSA3072-SHA3-256", 1024, Buffer.from("MLKEM1024-RSAOAEP3072", "ascii"), { kind: "rsa", bits: 3072, ctLen: 384 });
_comp("id-MLKEM1024-ECDH-P384-SHA3-256", 1024, Buffer.from("MLKEM1024-P384", "ascii"), { kind: "ec", node: "secp384r1", curve: "secp384r1", ctLen: 97 });
_comp("id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", 1024, Buffer.from("MLKEM1024-BP384", "ascii"), { kind: "ec", node: "brainpoolP384r1", curve: "brainpoolP384r1", ctLen: 97 });
_comp("id-MLKEM1024-X448-SHA3-256", 1024, Buffer.from("MLKEM1024-X448", "ascii"), { kind: "okp", curve: "X448", ctLen: 56 });
_comp("id-MLKEM1024-ECDH-P521-SHA3-256", 1024, Buffer.from("MLKEM1024-P521", "ascii"), { kind: "ec", node: "secp521r1", curve: "secp521r1", ctLen: 133 });

var MLKEM_SEED = 64;
var RSA_SS = 32;

function _mlkemSeedPkcs8(d, seed) {
  return _b.sequence([
    _b.integer(0n),
    _b.sequence([_b.oid(oid.byName(d.mlkemOidName))]),
    _b.octetString(_b.implicit(0, _b.octetString(seed))),
  ]);
}
function _mlkemSpki(d, ek) {
  return _b.sequence([_b.sequence([_b.oid(oid.byName(d.mlkemOidName))]), _b.bitString(ek, 0)]);
}
function _mlkemEncaps(d, mlkemEK) {
  return subtle.importKey("spki", _mlkemSpki(d, mlkemEK), { name: d.mlkemWc }, false, ["encapsulateBits"])
    .then(function (k) { return subtle.encapsulateBits({ name: d.mlkemWc }, k); })
    .then(function (r) { return { ss: Buffer.from(r.sharedKey), ct: Buffer.from(r.ciphertext) }; })
    .catch(function (e) { throw _err("kem/bad-key", "the ML-KEM component public key is invalid", e); });
}
function _mlkemDecaps(d, seed, mlkemCT) {
  return subtle.importKey("pkcs8", _mlkemSeedPkcs8(d, seed), { name: d.mlkemWc }, false, ["decapsulateBits"])
    .then(function (k) { return subtle.decapsulateBits({ name: d.mlkemWc }, k, mlkemCT); })
    .then(function (ss) { return Buffer.from(ss); })
    .catch(function (e) { throw _err("kem/bad-key", "the ML-KEM component private key is invalid", e); });
}

function _ecPubFromPoint(d, point) {
  if (point.length < 1 || point[0] !== 0x04) throw _err("kem/bad-key", "the EC component point is not in uncompressed form");
  var spki = _b.sequence([_b.sequence([_b.oid(oid.byName("ecPublicKey")), _b.oid(oid.byName(d.trad.curve))]), _b.bitString(point, 0)]);
  return nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}
function _okpPubFromRaw(d, raw) {
  var spki = _b.sequence([_b.sequence([_b.oid(oid.byName(d.trad.curve))]), _b.bitString(raw, 0)]);
  return nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}
function _okpPrivFromRaw(d, raw) {
  var p8 = _b.sequence([_b.integer(0n), _b.sequence([_b.oid(oid.byName(d.trad.curve))]), _b.octetString(_b.octetString(raw))]);
  return nodeCrypto.createPrivateKey({ key: p8, format: "der", type: "pkcs8" });
}
function _rawPubOf(keyObject) {
  var spki = keyObject.export({ format: "der", type: "spki" });
  return Buffer.from(asn1.read.bitString(asn1.decode(spki).children[1]).bytes);
}

function _tradEncaps(d, tradPK) {
  var trad = d.trad;
  if (trad.kind === "rsa") {
    var pub;
    try {
      asn1.decode(tradPK);
      pub = nodeCrypto.createPublicKey({ key: tradPK, format: "der", type: "pkcs1" });
    } catch (e) { return Promise.reject(_err("kem/bad-key", "the RSA component public key is not a valid RSAPublicKey", e)); }
    if (pub.asymmetricKeyDetails.modulusLength !== trad.bits) return Promise.reject(_err("kem/bad-key", "the RSA component modulus is not " + trad.bits + " bits (draft sec. 6)"));
    var ss = Buffer.from(nodeCrypto.randomBytes(RSA_SS));
    var ct;
    try { ct = Buffer.from(nodeCrypto.publicEncrypt({ key: pub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, ss)); }
    catch (e) {
      guard.secret.zeroize(ss, KemError, "kem/bad-input", "the RSA-OAEP component secret");
      return Promise.reject(_err("kem/bad-key", "the RSA-OAEP component encryption failed", e));
    }
    return Promise.resolve({ ss: ss, ct: ct });
  }
  var dh, dhCt;
  try {
    var recip = trad.kind === "ec" ? _ecPubFromPoint(d, tradPK) : _okpPubFromRaw(d, tradPK);
    var eph = trad.kind === "ec" ? nodeCrypto.generateKeyPairSync("ec", { namedCurve: trad.node }) : nodeCrypto.generateKeyPairSync(trad.curve.toLowerCase());
    dh = Buffer.from(nodeCrypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recip }));
    dhCt = _rawPubOf(eph.publicKey);
  } catch (e) { return Promise.reject(_err("kem/bad-key", "the " + trad.curve + " public key is invalid", e)); }
  return Promise.resolve({ ss: dh, ct: dhCt });
}

function _tradDecaps(d, tradSK, tradCT) {
  var trad = d.trad;
  if (trad.kind === "rsa") {
    var priv;
    try {
      asn1.decode(tradSK);
      priv = nodeCrypto.createPrivateKey({ key: tradSK, format: "der", type: "pkcs1" });
    } catch (e) { return Promise.reject(_err("kem/bad-key", "the RSA component private key is not a valid RSAPrivateKey", e)); }
    if (priv.asymmetricKeyDetails.modulusLength !== trad.bits) return Promise.reject(_err("kem/bad-key", "the RSA component modulus is not " + trad.bits + " bits (draft sec. 6)"));
    var ss;
    try { ss = Buffer.from(nodeCrypto.privateDecrypt({ key: priv, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, tradCT)); }
    catch (_e) { return Promise.reject(_err("kem/decapsulation-failed", "the RSA-OAEP component decryption failed")); }
    if (ss.length !== RSA_SS) {
      guard.secret.zeroize(ss, KemError, "kem/bad-input", "the RSA-OAEP component secret");
      return Promise.reject(_err("kem/decapsulation-failed", "the RSA-OAEP component decryption failed"));
    }
    return Promise.resolve({ ss: ss, tradPK: Buffer.from(nodeCrypto.createPublicKey(priv).export({ format: "der", type: "pkcs1" })) });
  }
  var priv2, eph;
  try {
    if (trad.kind === "ec") {
      asn1.decode(tradSK);
      priv2 = nodeCrypto.createPrivateKey({ key: tradSK, format: "der", type: "sec1" });
    } else {
      priv2 = _okpPrivFromRaw(d, tradSK);
    }
    eph = trad.kind === "ec" ? _ecPubFromPoint(d, tradCT) : _okpPubFromRaw(d, tradCT);
  } catch (e) { return Promise.reject(_err("kem/bad-key", "the " + trad.curve + " key material is invalid", e)); }
  var dh;
  try { dh = Buffer.from(nodeCrypto.diffieHellman({ privateKey: priv2, publicKey: eph })); }
  catch (e) { return Promise.reject(_err("kem/decapsulation-failed", "the " + trad.curve + " Diffie-Hellman failed", e)); }
  return Promise.resolve({ ss: dh, tradPK: _rawPubOf(nodeCrypto.createPublicKey(priv2)) });
}

function _combine(d, mlkemSS, tradSS, tradCT, tradPK) {
  var preimage = Buffer.concat([mlkemSS, tradSS, tradCT, tradPK, d.label]);
  return subtle.digest("SHA3-256", preimage).then(function (h) {
    return Buffer.from(h);
  }).finally(function () {
    guard.secret.zeroizeAll([preimage, mlkemSS, tradSS], KemError, "kem/bad-input", "a KEM combiner secret");
  });
}

async function _settleOrWipe(pA, pB, secA, secB) {
  var s = await Promise.allSettled([pA, pB]);
  if (s[0].status === "rejected" || s[1].status === "rejected") {
    if (s[0].status === "fulfilled") guard.secret.zeroize(secA(s[0].value), KemError, "kem/bad-input", "an ML-KEM shared secret");
    if (s[1].status === "fulfilled") guard.secret.zeroize(secB(s[1].value), KemError, "kem/bad-input", "a traditional shared secret");
    throw s[0].status === "rejected" ? s[0].reason : s[1].reason;
  }
  return [s[0].value, s[1].value];
}

function _descriptor(algOid) {
  var d = COMPOSITE_KEM[algOid];
  if (!d) throw _err("kem/unsupported-algorithm", "not a composite ML-KEM algorithm: " + (oid.name(algOid) || algOid));
  return d;
}
function _descriptorForAlg(algOid, hasParams) {
  if (hasParams) throw _err("kem/bad-algorithm", "a composite ML-KEM AlgorithmIdentifier MUST have absent parameters (draft sec. 5.3)");
  return _descriptor(algOid);
}
function _isSequence(node) {
  return !!node && node.tagClass === "universal" && node.tagNumber === asn1.TAGS.SEQUENCE && !!node.children;
}
function _fromAlgId(algNode) {
  if (!_isSequence(algNode) || algNode.children.length < 1) throw _err("kem/bad-algorithm", "the AlgorithmIdentifier is malformed");
  var algOid;
  try { algOid = asn1.read.oid(algNode.children[0]); }
  catch (e) { throw _err("kem/bad-algorithm", "the AlgorithmIdentifier algorithm is not an OBJECT IDENTIFIER", e); }
  return _descriptorForAlg(algOid, algNode.children.length > 1);
}


/**
 * @primitive pki.kem.decapsulate
 * @signature pki.kem.decapsulate(privateKey, ciphertext) -> Promise<Buffer>
 * @since 0.6.6
 * @status stable
 * @spec draft-ietf-lamps-pq-composite-kem
 * @defends harvest-now-decrypt-later (CWE-327)
 * @related pki.kem.encapsulate
 *
 * Recover the 256-bit composite shared secret from a ciphertext. `privateKey` is the composite PKCS#8
 * (a `OneAsymmetricKey` DER `Buffer` or `PRIVATE KEY` PEM whose `privateKeyAlgorithm` is a composite
 * ML-KEM OID and whose `privateKey` octets are the raw `mlkemSeed || tradSK`, draft sec. 4.2);
 * `ciphertext` is the composite ciphertext (`mlkemCT || tradCT`, sec. 4.3). The ML-KEM half and the
 * traditional half are decapsulated independently and combined with SHA3-256, so the secret is
 * recovered only when both components agree. A malformed key or ciphertext, an unsupported algorithm,
 * or a component decapsulation failure throws a typed `KemError`.
 *
 * @example
 *   // requires: privatePkcs8Der -- the composite ML-KEM PKCS#8 private key (DER)
 *   // requires: ciphertext -- the composite KEM ciphertext received from the sender
 *   var secret = await pki.kem.decapsulate(privatePkcs8Der, ciphertext);   // 32-byte Buffer
 */
async function _decapsulate(privateKey, ciphertext) {
  var pkcs8 = _toDer(privateKey, "PRIVATE KEY", "the composite ML-KEM private key");
  var ct = guard.bytes.snapshotSource(ciphertext, KemError, "kem/bad-input", "the composite ML-KEM ciphertext");
  var d, sk;
  try {
    try {
      var info = schemaPkcs8.parse(pkcs8);
      var alg = info.privateKeyAlgorithm;
      d = _descriptorForAlg(alg.oid, alg.parameters !== null);
      sk = Buffer.from(info.privateKey);
    } catch (e) {
      if (e instanceof KemError) throw e;
      if (e && e.code === "pkcs8/bad-algorithm-parameters") throw _err("kem/bad-algorithm", "a composite ML-KEM AlgorithmIdentifier MUST have absent parameters (draft sec. 5.3)", e);
      throw _err("kem/bad-key", "the composite ML-KEM private key is not a well-formed OneAsymmetricKey", e);
    }
    try {
      if (sk.length <= MLKEM_SEED) throw _err("kem/bad-key", "the composite private key is shorter than the ML-KEM seed");
      if (ct.length !== d.mlkemCt + d.trad.ctLen) throw _err("kem/bad-ciphertext", "the composite ciphertext is not the expected " + (d.mlkemCt + d.trad.ctLen) + " bytes for " + d.name);
      var seed = sk.subarray(0, MLKEM_SEED), tradSK = sk.subarray(MLKEM_SEED);
      var mlkemCT = ct.subarray(0, d.mlkemCt), tradCT = ct.subarray(d.mlkemCt);
      var r = await _settleOrWipe(_mlkemDecaps(d, seed, mlkemCT), _tradDecaps(d, tradSK, tradCT),
        function (v) { return v; }, function (v) { return v.ss; });
      return await _combine(d, r[0], r[1].ss, tradCT, r[1].tradPK);
    } finally {
      guard.secret.zeroize(sk, KemError, "kem/bad-input", "the composite private key material");
    }
  } finally {
    guard.secret.zeroize(pkcs8, KemError, "kem/bad-input", "the composite private key DER");
  }
}

/**
 * @primitive pki.kem.encapsulate
 * @signature pki.kem.encapsulate(publicKey) -> Promise<{ sharedSecret: Buffer, ciphertext: Buffer }>
 * @since 0.6.6
 * @status stable
 * @spec draft-ietf-lamps-pq-composite-kem
 * @defends harvest-now-decrypt-later (CWE-327)
 * @related pki.kem.decapsulate
 *
 * Establish a 256-bit shared secret for a recipient's composite ML-KEM public key. `publicKey` is the
 * composite `SubjectPublicKeyInfo` (a DER `Buffer` or `PUBLIC KEY` PEM whose algorithm is a composite
 * ML-KEM OID and whose subjectPublicKey octets are the raw `mlkemEK || tradPK`, draft sec. 4.1).
 * Returns the `sharedSecret` (a 32-byte `Buffer`) and the `ciphertext` (`mlkemCT || tradCT`) to send to
 * the recipient, who recovers the same secret with `pki.kem.decapsulate`. The ML-KEM and traditional
 * component encapsulations run independently and are mixed through SHA3-256. A malformed or unsupported
 * public key throws a typed `KemError`.
 *
 * @example
 *   // requires: recipientSpkiDer -- the recipient's composite ML-KEM SubjectPublicKeyInfo (DER)
 *   var out = await pki.kem.encapsulate(recipientSpkiDer);
 *   out.sharedSecret.length === 32;   // send out.ciphertext to the recipient
 */
async function _encapsulate(publicKey) {
  var spki = _toDer(publicKey, "PUBLIC KEY", "the composite ML-KEM public key");
  var d, ek;
  try {
    var node = asn1.decode(spki);
    if (!_isSequence(node) || node.children.length !== 2) throw _err("kem/bad-key", "the public key is not a well-formed SubjectPublicKeyInfo");
    d = _fromAlgId(node.children[0]);
    var bs = asn1.read.bitString(node.children[1]);
    if (bs.unusedBits !== 0) throw _err("kem/bad-key", "the composite subjectPublicKey has unused bits");
    ek = Buffer.from(bs.bytes);
  } catch (e) { throw e instanceof KemError ? e : _err("kem/bad-key", "the composite ML-KEM public key is not valid DER", e); }
  if (ek.length <= d.mlkemEk) throw _err("kem/bad-key", "the composite public key is shorter than the ML-KEM component");
  var mlkemEK = ek.subarray(0, d.mlkemEk), tradPK = ek.subarray(d.mlkemEk);
  var r = await _settleOrWipe(_mlkemEncaps(d, mlkemEK), _tradEncaps(d, tradPK),
    function (v) { return v.ss; }, function (v) { return v.ss; });
  var ss = await _combine(d, r[0].ss, r[1].ss, r[1].ct, tradPK);
  return { sharedSecret: ss, ciphertext: Buffer.concat([r[0].ct, r[1].ct]) };
}

module.exports = {
  encapsulate: _encapsulate,
  decapsulate: _decapsulate,
};
