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
//
// ML-KEM runs on the toolkit's hardened WebCrypto surface (the FIPS 203 ciphertext-length check +
// shared-secret zeroization ride along); the traditional component uses node:crypto directly, as the
// sibling KEM module lib/hpke.js does, promoting RSA-OAEP into a KEM (a fresh random secret encrypted,
// draft sec. 2.1) and ECDH / X25519 / X448 into a KEM (an ephemeral public key as the ciphertext,
// draft sec. 2.2). The public key is mlkemEK || tradPK (sec. 4.1) in the SPKI BIT STRING; the private
// key is mlkemSeed || tradSK (sec. 4.2, a 64-byte ML-KEM seed) in the PKCS#8 privateKey OCTET STRING;
// the ciphertext is mlkemCT || tradCT (sec. 4.3). The ML-KEM component is the fixed-length first half,
// and the split point is its parameter-set length.

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

// Accept a composite key as DER (any BufferSource, snapshotted at the door) or as a PEM block with the
// given label. A PEM decode fault is re-typed into the module's own KemError so the verb's documented
// "throws a typed KemError" contract holds for every input shape. PEM is detected with the shared armor
// check (so leading text before "-----BEGIN" is tolerated as elsewhere in the toolkit), and the byte
// source is snapshot-COPIED first: the async verbs read the key across await points, so it must not alias
// a caller buffer that can change underneath them (guard.bytes.source, which coerceToDer uses, aliases).
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

// ---- registry (draft sec. 6) -------------------------------------------------
//
// One row per composite algorithm, keyed by the composite OID. `trad` is exactly one component shape,
// each carrying `ctLen`, the exact byte length of its traditional ciphertext component (RSA-OAEP block,
// EC uncompressed point, or raw OKP ephemeral key), so the composite ciphertext length is fixed and an
// oversized attacker-controlled component is refused before any key is built:
//   { kind: "rsa", bits, ctLen }        RSA-OAEP-KEM, OAEP SHA-256 / MGF1-SHA256 / empty label (sec. 6.1)
//   { kind: "ec",  node, curve, ctLen } ECDH DHKEM, `node` the node namedCurve, `curve` the curve OID name
//   { kind: "okp", curve, ctLen }       X25519 / X448 DHKEM, `curve` the registered OID name
// `label` is stored as the AUTHORITATIVE per-row bytes (draft sec. 6): most are ASCII, but the
// id-MLKEM768-X25519 label is the raw six bytes 5c2e2f2f5e5c and MUST NOT be derived from the name.
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

var MLKEM_SEED = 64;   // d || z, both 32 bytes (draft sec. 4.2)
var RSA_SS = 32;       // ss_len for RSA-OAEP-KEM (draft sec. 6.1)

// ---- ML-KEM component (toolkit WebCrypto) ------------------------------------
//
// The private key is the 64-byte seed; node reconstructs the decapsulation key from a PKCS#8 whose
// privateKey OCTET STRING wraps the seed as a context-[0] primitive (the OpenSSL / draft seed form),
// not from node's own { seed } keygen option, whose seed convention differs.
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
    // a malformed ML-KEM public-key half surfaces from the engine as a WebCryptoError; re-type it into
    // the module's own KemError so the verb's typed-error contract holds. The chain runs only the
    // WebCrypto component operations, which never raise a KemError, so the re-type is unconditional.
    .catch(function (e) { throw _err("kem/bad-key", "the ML-KEM component public key is invalid", e); });
}
function _mlkemDecaps(d, seed, mlkemCT) {
  return subtle.importKey("pkcs8", _mlkemSeedPkcs8(d, seed), { name: d.mlkemWc }, false, ["decapsulateBits"])
    .then(function (k) { return subtle.decapsulateBits({ name: d.mlkemWc }, k, mlkemCT); })
    .then(function (ss) { return Buffer.from(ss); })
    // Defensive re-type mirroring _mlkemEncaps. Verified-unreachable from the shipped decapsulate path:
    // the caller-checked split always supplies a valid 64-byte ML-KEM seed (any 64 bytes are a valid
    // key) and an exact-parameter-set-length ML-KEM ciphertext, and ML-KEM decapsulation is implicitly
    // rejecting, so neither the import nor the decapsulation of the ML-KEM half can fail here. Kept for
    // node's experimental ML-KEM surface and for symmetry with the reachable encapsulate catch.
    .catch(function (e) { throw _err("kem/bad-key", "the ML-KEM component private key is invalid", e); });
}

// ---- traditional component (node:crypto, like lib/hpke.js) -------------------
//
// The traditional public key encodings mixed into the combiner (draft sec. 4.1 / Appendix B): RSA is
// the RSAPublicKey DER, EC is the uncompressed X9.62 point, X25519 / X448 is the raw curve point.
function _ecPubFromPoint(d, point) {
  // draft Appendix B: the EC component is the uncompressed X9.62 point (0x04 || X || Y). node would
  // silently decompress a 0x02/0x03 point, so a compressed or hybrid form is refused here as non-canonical;
  // createPublicKey then validates the length and that the point is on the curve.
  if (point.length < 1 || point[0] !== 0x04) throw _err("kem/bad-key", "the EC component point is not in uncompressed form");
  // SubjectPublicKeyInfo { AlgorithmIdentifier { ecPublicKey, namedCurve }, BIT STRING point }.
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
// The subjectPublicKey octets of a public KeyObject (the uncompressed EC point / raw OKP key), read
// off the SPKI export rather than a JWK export, which node cannot produce for the brainpool curves.
function _rawPubOf(keyObject) {
  var spki = keyObject.export({ format: "der", type: "spki" });
  return Buffer.from(asn1.read.bitString(asn1.decode(spki).children[1]).bytes);
}

function _tradEncaps(d, tradPK) {
  var trad = d.trad;
  if (trad.kind === "rsa") {
    var pub;
    try {
      // node's createPublicKey ignores trailing bytes after the RSAPublicKey; decode strictly first so a
      // composite key carrying extra bytes after the RSA component is refused (draft sec. 4.1: exact encoding).
      asn1.decode(tradPK);
      pub = nodeCrypto.createPublicKey({ key: tradPK, format: "der", type: "pkcs1" });
    } catch (e) { return Promise.reject(_err("kem/bad-key", "the RSA component public key is not a valid RSAPublicKey", e)); }
    if (pub.asymmetricKeyDetails.modulusLength !== trad.bits) return Promise.reject(_err("kem/bad-key", "the RSA component modulus is not " + trad.bits + " bits (draft sec. 6)"));
    var ss = Buffer.from(nodeCrypto.randomBytes(RSA_SS));
    var ct;
    try { ct = Buffer.from(nodeCrypto.publicEncrypt({ key: pub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, ss)); }
    catch (e) {
      // the random secret is already allocated; wipe it before rejecting if the RSA public operation fails
      // (draft sec. 3.5). On success it is returned and wiped by the combiner.
      guard.secret.zeroize(ss, KemError, "kem/bad-input", "the RSA-OAEP component secret");
      return Promise.reject(_err("kem/bad-key", "the RSA-OAEP component encryption failed", e));
    }
    return Promise.resolve({ ss: ss, ct: ct });
  }
  // DHKEM: an ephemeral keypair, the shared secret is DH(ephemeral, recipient), the ciphertext is the
  // ephemeral public key in the component's own encoding (draft sec. 2.2). The Diffie-Hellman is inside
  // the try: a structurally valid but low-order recipient point (e.g. an all-zero X25519 key) imports
  // cleanly but makes node's diffieHellman throw, which must surface as a typed fault rather than a raw
  // OpenSSL error escaping the encapsulation.
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
      // node's createPrivateKey ignores trailing bytes after the RSAPrivateKey; decode strictly first so a
      // composite key carrying extra bytes after the RSA component is refused (draft sec. 4.2: exact encoding).
      asn1.decode(tradSK);
      priv = nodeCrypto.createPrivateKey({ key: tradSK, format: "der", type: "pkcs1" });
    } catch (e) { return Promise.reject(_err("kem/bad-key", "the RSA component private key is not a valid RSAPrivateKey", e)); }
    if (priv.asymmetricKeyDetails.modulusLength !== trad.bits) return Promise.reject(_err("kem/bad-key", "the RSA component modulus is not " + trad.bits + " bits (draft sec. 6)"));
    var ss;
    // OAEP-invalid ciphertext and valid-padding-wrong-length plaintext MUST fail identically: a distinct
    // verdict for either is an RSA-OAEP padding-validity oracle (Manger). Both reject with the same code
    // and message AND no cause (the OpenSSL error is dropped, since it too would tell the paths apart), so
    // the caller cannot tell the failure reason apart. draft sec. 2.1 fixes the transported secret at 32
    // bytes; a plaintext of any other length is wiped and rejected here with that same verdict (sec. 3.5).
    try { ss = Buffer.from(nodeCrypto.privateDecrypt({ key: priv, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, tradCT)); }
    catch (_e) { return Promise.reject(_err("kem/decapsulation-failed", "the RSA-OAEP component decryption failed")); }
    if (ss.length !== RSA_SS) {
      guard.secret.zeroize(ss, KemError, "kem/bad-input", "the RSA-OAEP component secret");
      return Promise.reject(_err("kem/decapsulation-failed", "the RSA-OAEP component decryption failed"));
    }
    // The combiner input tradPK is the RSAPublicKey DER (n, e), draft sec. 4.1, taken from the key object.
    return Promise.resolve({ ss: ss, tradPK: Buffer.from(nodeCrypto.createPublicKey(priv).export({ format: "der", type: "pkcs1" })) });
  }
  var priv2, eph;
  try {
    if (trad.kind === "ec") {
      // node's SEC1 reader ignores trailing bytes after the ECPrivateKey; decode strictly first so a
      // composite key carrying extra bytes after the EC component is refused (draft sec. 4.2, exact encoding).
      asn1.decode(tradSK);
      priv2 = nodeCrypto.createPrivateKey({ key: tradSK, format: "der", type: "sec1" });
    } else {
      // the OKP private key is a fixed-length raw scalar; node rejects any wrong length, trailing included.
      priv2 = _okpPrivFromRaw(d, tradSK);
    }
    eph = trad.kind === "ec" ? _ecPubFromPoint(d, tradCT) : _okpPubFromRaw(d, tradCT);
  } catch (e) { return Promise.reject(_err("kem/bad-key", "the " + trad.curve + " key material is invalid", e)); }
  var dh;
  try { dh = Buffer.from(nodeCrypto.diffieHellman({ privateKey: priv2, publicKey: eph })); }
  catch (e) { return Promise.reject(_err("kem/decapsulation-failed", "the " + trad.curve + " Diffie-Hellman failed", e)); }
  return Promise.resolve({ ss: dh, tradPK: _rawPubOf(nodeCrypto.createPublicKey(priv2)) });
}

// ---- combiner (draft sec. 3.4) -----------------------------------------------
function _combine(d, mlkemSS, tradSS, tradCT, tradPK) {
  var preimage = Buffer.concat([mlkemSS, tradSS, tradCT, tradPK, d.label]);
  return subtle.digest("SHA3-256", preimage).then(function (h) {
    return Buffer.from(h);
  }).finally(function () {
    // draft sec. 3.5: clear the intermediate key material on every path, whether the digest resolves or
    // fails. Only the returned composite secret survives. tradCT / tradPK are public, but the preimage
    // holds copies of both component shared secrets, and mlkemSS / tradSS are the component secrets.
    guard.secret.zeroizeAll([preimage, mlkemSS, tradSS], KemError, "kem/bad-input", "a KEM combiner secret");
  });
}

// Run the two component operations; if EITHER rejects, wipe the shared secret the OTHER already produced
// before re-throwing, so a component failure leaves no key material readable (draft sec. 3.5 -- clear all
// buffers and forward the error). On success the combiner wipes both component secrets. `secA` / `secB`
// extract the secret Buffer from each component's result.
async function _settleOrWipe(pA, pB, secA, secB) {
  var s = await Promise.allSettled([pA, pB]);
  if (s[0].status === "rejected" || s[1].status === "rejected") {
    if (s[0].status === "fulfilled") guard.secret.zeroize(secA(s[0].value), KemError, "kem/bad-input", "an ML-KEM shared secret");
    if (s[1].status === "fulfilled") guard.secret.zeroize(secB(s[1].value), KemError, "kem/bad-input", "a traditional shared secret");
    throw s[0].status === "rejected" ? s[0].reason : s[1].reason;
  }
  return [s[0].value, s[1].value];
}

// ---- descriptor resolution ---------------------------------------------------
function _descriptor(algOid) {
  var d = COMPOSITE_KEM[algOid];
  if (!d) throw _err("kem/unsupported-algorithm", "not a composite ML-KEM algorithm: " + (oid.name(algOid) || algOid));
  return d;
}
// Resolve the composite descriptor from an algorithm OID, enforcing the draft sec. 5.3 parameters-absent
// rule. Both verbs feed the same (oid, hasParams) here so the dispatch and the parameters rule live once,
// whether the AlgorithmIdentifier was read from a hand-decoded SPKI or a schema-parsed OneAsymmetricKey.
function _descriptorForAlg(algOid, hasParams) {
  if (hasParams) throw _err("kem/bad-algorithm", "a composite ML-KEM AlgorithmIdentifier MUST have absent parameters (draft sec. 5.3)");
  return _descriptor(algOid);
}
// A DER node is a universal SEQUENCE (SubjectPublicKeyInfo and AlgorithmIdentifier are both SEQUENCE, not
// SET or any other constructed tag): a SET carrying the same children is not a canonical encoding.
function _isSequence(node) {
  return !!node && node.tagClass === "universal" && node.tagNumber === asn1.TAGS.SEQUENCE && !!node.children;
}
// Resolve the composite descriptor from a raw AlgorithmIdentifier node (the SPKI encapsulation path).
function _fromAlgId(algNode) {
  if (!_isSequence(algNode) || algNode.children.length < 1) throw _err("kem/bad-algorithm", "the AlgorithmIdentifier is malformed");
  var algOid;
  try { algOid = asn1.read.oid(algNode.children[0]); }
  catch (e) { throw _err("kem/bad-algorithm", "the AlgorithmIdentifier algorithm is not an OBJECT IDENTIFIER", e); }
  return _descriptorForAlg(algOid, algNode.children.length > 1);
}

// ---- public verbs ------------------------------------------------------------

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
// async so any synchronous fault (an argument that is not a BufferSource, a malformed DER structure)
// leaves as a rejected promise rather than a synchronous throw, keeping the Promise-returning contract.
async function _decapsulate(privateKey, ciphertext) {
  var pkcs8 = _toDer(privateKey, "PRIVATE KEY", "the composite ML-KEM private key");
  var ct = guard.bytes.snapshotSource(ciphertext, KemError, "kem/bad-input", "the composite ML-KEM ciphertext");
  var d, sk;
  try {
    try {
      // Compose the shared strict OneAsymmetricKey parser so the version, the algorithm, and the optional
      // [0]/[1] trailing fields are all validated once, rather than reading fixed positions and trusting
      // the rest. The privateKey octets are the raw composite mlkemSeed || tradSK (draft sec. 4.2).
      var info = schemaPkcs8.parse(pkcs8);
      var alg = info.privateKeyAlgorithm;
      d = _descriptorForAlg(alg.oid, alg.parameters !== null);
      sk = Buffer.from(info.privateKey);
    } catch (e) {
      if (e instanceof KemError) throw e;
      // the shared parser rejects a present `parameters` at the envelope; re-map it to the module's own
      // parameters-absent verdict so both verbs report draft sec. 5.3 the same way.
      if (e && e.code === "pkcs8/bad-algorithm-parameters") throw _err("kem/bad-algorithm", "a composite ML-KEM AlgorithmIdentifier MUST have absent parameters (draft sec. 5.3)", e);
      throw _err("kem/bad-key", "the composite ML-KEM private key is not a well-formed OneAsymmetricKey", e);
    }
    try {
      if (sk.length <= MLKEM_SEED) throw _err("kem/bad-key", "the composite private key is shorter than the ML-KEM seed");
      // the composite ciphertext is a fixed length (the ML-KEM ciphertext plus the exact traditional
      // component); reject any other length before building a key, so an attacker-controlled oversized
      // traditional component cannot force an unbounded allocation (CWE-770).
      if (ct.length !== d.mlkemCt + d.trad.ctLen) throw _err("kem/bad-ciphertext", "the composite ciphertext is not the expected " + (d.mlkemCt + d.trad.ctLen) + " bytes for " + d.name);
      var seed = sk.subarray(0, MLKEM_SEED), tradSK = sk.subarray(MLKEM_SEED);
      var mlkemCT = ct.subarray(0, d.mlkemCt), tradCT = ct.subarray(d.mlkemCt);
      var r = await _settleOrWipe(_mlkemDecaps(d, seed, mlkemCT), _tradDecaps(d, tradSK, tradCT),
        function (v) { return v; }, function (v) { return v.ss; });
      return await _combine(d, r[0], r[1].ss, tradCT, r[1].tradPK);
    } finally {
      // the reconstructed private-key copy (ML-KEM seed || traditional private key) is wiped on every path,
      // including the length-validation exits above.
      guard.secret.zeroize(sk, KemError, "kem/bad-input", "the composite private key material");
    }
  } finally {
    // the snapshotted PKCS#8 copy still holds the private-key octets; wipe it on every path (draft sec. 3.5).
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

// Only the two verbs are public: this module IS the pki.kem namespace, so the internal registry stays
// unexported to keep it off the operator surface and immutable from outside.
module.exports = {
  encapsulate: _encapsulate,
  decapsulate: _decapsulate,
};
