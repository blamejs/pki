// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.hpke
 * @nav        Protocols
 * @title      HPKE
 * @fullname   HPKE (Hybrid Public Key Encryption, RFC 9180)
 * @intro Hybrid Public Key Encryption (RFC 9180): the standard construction
 *   behind TLS Encrypted Client Hello, MLS, and OHTTP that turns a recipient KEM
 *   public key into an encapsulated key plus an AEAD-encrypting context. Three KEM
 *   families run the RFC 9180 key schedule: the DHKEM suites P-256, P-384, P-521,
 *   X25519, and X448 in all four modes (base / psk / auth / auth-psk), proven against
 *   the RFC 9180 Appendix A known-answer vectors, the post-quantum ML-KEM-512 /
 *   -768 / -1024 KEMs (IANA code points 0x0040 to 0x0042, draft-ietf-hpke-pq) in
 *   the base and psk modes, proven against that draft's Appendix A vectors, and the
 *   PQ/T hybrid KEMs MLKEM768-P256 (0x0050), MLKEM1024-P384 (0x0051) and
 *   MLKEM768-X25519 (0x647a, X-Wing) in the base and psk modes, each pairing an
 *   ML-KEM with a nominal group under the CFRG C2PRI combiner and proven against
 *   the draft-irtf-cfrg-concrete-hybrid-kems Appendix B vectors. The KDFs are
 *   HKDF-SHA256 / HKDF-SHA384 / HKDF-SHA512, which run the two-stage key schedule,
 *   and SHAKE128 (0x0010) / SHAKE256 (0x0011) of draft-ietf-hpke-pq, which are
 *   single-stage and run the one-stage key schedule of draft-ietf-hpke-hpke,
 *   proven against Appendix A.7, A.8, A.11 and A.12 of the first draft. On a
 *   single-stage KDF the psk, psk_id and info inputs are capped at 65535 bytes and
 *   an export is capped at the same, each length being encoded in two bytes.
 *   TurboSHAKE128 (0x0012) and TurboSHAKE256 (0x0013) are registered in the same
 *   table and not offered, because no released OpenSSL exposes the XOF; a request
 *   for either fails closed. The AEADs are AES-128-GCM, AES-256-GCM,
 *   ChaCha20Poly1305, and export-only. deriveKeyPair, generateKeyPair, encap and
 *   decap reach a KEM on its own, for a caller driving its own key schedule. Pure
 *   composition over node:crypto: no ASN.1, no schema engine.
 *   The RFC 9180 sec. 7 registry code points live in pki.hpke.suites
 *   (KEM / KDF / AEAD / MODE), passed to the setup functions to select a suite.
 * @spec RFC 9180
 * @card Encrypt to a KEM public key (RFC 9180; the ECH / MLS / OHTTP primitive).
 */

var nodeCrypto = require("crypto");
/** @internal Bound at load, like every other operation this module decides with: a replacement installed
 *  later would otherwise choose the bytes a fresh key pair is generated from. */
var _randomBytes = nodeCrypto.randomBytes;
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var oid = require("./oid");
var _hasOwn = intrinsic.hasOwn;
var _isBuffer = intrinsic.isBuffer, _bufferFrom = intrinsic.bufferFrom, _bufferAlloc = intrinsic.bufferAlloc;
var _bufferConcat = intrinsic.bufferConcat, _bufferEquals = intrinsic.bufferEquals, _compare = intrinsic.compare;
var _push = intrinsic.push;
var _subarray = intrinsic.subarray;

var HpkeError = frameworkError.HpkeError;
function _err(code, message, cause) { return new HpkeError(code, message, cause); }


function i2osp(n, len) {
  var b = Buffer.alloc(len);
  var v = BigInt(n);
  for (var i = len - 1; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  /** @internal A value wider than `len` bytes leaves a non-zero residue here. Returning the truncated
   *  encoding would let two ends of an exchange derive different secrets from inputs each accepted. */
  if (v !== 0n) throw _err("hpke/input-length", "the value " + n + " does not fit in " + len + " bytes");
  return b;
}
/** @internal draft-ietf-hpke-hpke-05 sec. 3 lengthPrefixed(x): a two-byte big-endian length, then the
 *  value. The limit is the width of that prefix, which sec. 7.2.1 states as a MUST for the psk, psk_id
 *  and info inputs of a single-stage KDF.
 *  It appends onto `parts` instead of returning a buffer, for two reasons. A returned buffer would be a
 *  second copy of a secret, which the caller would then have to wipe alongside the concatenation it ends
 *  up in; here the secret is copied once, when `parts` is concatenated. And every length is checked while
 *  the parts are collected, before any of them is joined, so a refused input leaves nothing allocated. */
var MAX_PREFIXED = 0xffff;
function _pushPrefixed(parts, b, what) {
  if (b.length > MAX_PREFIXED) {
    throw _err("hpke/input-length", what + " is " + b.length + " bytes; a single-stage KDF accepts at " +
      "most " + MAX_PREFIXED + " (draft-ietf-hpke-hpke-05 sec. 7.2.1)");
  }
  _push(parts, i2osp(b.length, 2), b);
  return parts;
}
/** @internal Through the capture, which is the whole point of this helper existing: every
 *  concatenation in the module goes through it, including the hybrid combiner's
 *  `[ssPQ, ssT, ctT, ekT, label]`. Reaching `Buffer.concat` live, a replacement that answered a
 *  five-part array with a constant made both sides hash the same public value instead of combining the
 *  two shared secrets, and the HPKE keys derived from it were then predictable. */
function concat(arr) { return _bufferConcat(arr); }
function xor(a, b) { var o = Buffer.alloc(a.length); for (var i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }

var HPKE_V1 = Buffer.from("HPKE-v1", "ascii");
var _EMPTY = _bufferAlloc(0);
function L(s) { return Buffer.from(s, "ascii"); }


/** @internal A row carries `hash` for a two-stage KDF (Extract then Expand, so Nh is the Extract width)
 *  or `xof` for a single-stage one (a lone Derive, so Nh comes from the KDF's definition:
 *  draft-ietf-hpke-hpke-05 sec. 4.2). The two are exclusive and which one is present selects the key
 *  schedule and the export, so a row cannot reach the wrong one by omitting a flag.
 *  draft-ietf-hpke-pq-05 sec. 5 also registers TurboSHAKE128 (0x0012) and TurboSHAKE256 (0x0013). They
 *  are absent because no released OpenSSL exposes the XOF; `node:crypto` answers
 *  "Digest method not supported" for both on OpenSSL 3.5.8. Add the rows when it does. */
var KDFS = intrinsic.assign(intrinsic.create(null), {
  0x0001: { hash: "sha256", Nh: 32 },
  0x0002: { hash: "sha384", Nh: 48 },
  0x0003: { hash: "sha512", Nh: 64 },
  0x0010: { xof: "shake128", Nh: 32 },
  0x0011: { xof: "shake256", Nh: 64 },
});
function _isOneStage(kdf) { return typeof kdf.xof === "string"; }
var AEADS = intrinsic.assign(intrinsic.create(null), {
  0x0001: { cipher: "aes-128-gcm", Nk: 16, Nn: 12, Nt: 16 },
  0x0002: { cipher: "aes-256-gcm", Nk: 32, Nn: 12, Nt: 16 },
  0x0003: { cipher: "chacha20-poly1305", Nk: 32, Nn: 12, Nt: 16 },
  0xFFFF: { exportOnly: true, Nn: 12 },
});
function _mlKemRow(name, oidName, node) {
  var p = oid.kemParams(oidName);
  return { kind: "mlkem", name: name, node: node, Nsecret: p.ss, Npub: p.ek, Nenc: p.ct, Nsk: 64 };
}
/** @internal A PQ/T hybrid KEM of the CG framework (draft-irtf-cfrg-hybrid-kems sec. 5.1.1): an ML-KEM
 *  alongside a nominal group, both key pairs expanded from ONE seed, which is the decapsulation key.
 *  `group` names the traditional half; `groupNseed` is the seed slice it takes, which for P-256 is 128
 *  because RandomScalar rejection-samples up to four 32-byte chunks and not 32 as the scalar width
 *  alone would suggest. `label` separates one combination from another and is registered by the draft. */
var NOMINAL_GROUPS = intrinsic.assign(intrinsic.create(null), {
  /** @internal P-256's Nseed is 128, four times its scalar width, because RandomScalar rejection-samples
   *  32-byte chunks and the draft budgets four attempts. No published vector reaches the second attempt:
   *  a first chunk at or above the order has probability about 2^-32, and because SHAKE is an XOF the
   *  first 96 bytes of a 192-byte squeeze are the same bytes, so shortening Nseed to 32 changes nothing
   *  observable on the Appendix B seed. The width is therefore asserted directly in the vectors rather
   *  than inferred from an output. P-384's Nseed equals its scalar width, so it has one attempt and
   *  cannot reject at all. */
  "P-256": { kind: "ec", curve: "P-256", nodeCurve: "prime256v1", Nseed: 128, Nscalar: 32, Nelem: 65, Nss: 32 },
  "P-384": { kind: "ec", curve: "P-384", nodeCurve: "secp384r1", Nseed: 48, Nscalar: 48, Nelem: 97, Nss: 48 },
  "X25519": { kind: "okp", curve: "X25519", Nseed: 32, Nscalar: 32, Nelem: 32, Nss: 32 },
});
function _hybridRow(name, pqName, pqNode, groupName, label) {
  var pq = _mlKemRow(pqName, "id-" + pqNode, pqNode);
  var g = NOMINAL_GROUPS[groupName];
  return {
    kind: "hybrid", name: name, pq: pq, groupName: groupName, group: g,
    label: _bufferFrom(label, "latin1"),
    /** @internal The seed is the decapsulation key, so Nsk is the seed width and not a scalar width. */
    Nsecret: 32, Npub: pq.Npub + g.Nelem, Nenc: pq.Nenc + g.Nelem, Nsk: 32,
  };
}
var KEMS = intrinsic.assign(intrinsic.create(null), {
  0x0010: { kind: "ec", name: "P-256", curve: "P-256", nodeCurve: "prime256v1", kdf: 0x0001, Nsecret: 32, Npub: 65, Nsk: 32 },
  0x0011: { kind: "ec", name: "P-384", curve: "P-384", nodeCurve: "secp384r1", kdf: 0x0002, Nsecret: 48, Npub: 97, Nsk: 48 },
  0x0012: { kind: "ec", name: "P-521", curve: "P-521", nodeCurve: "secp521r1", kdf: 0x0003, Nsecret: 64, Npub: 133, Nsk: 66 },
  0x0020: { kind: "okp", name: "X25519", curve: "X25519", kdf: 0x0001, Nsecret: 32, Npub: 32, Nsk: 32 },
  0x0021: { kind: "okp", name: "X448", curve: "X448", kdf: 0x0003, Nsecret: 64, Npub: 56, Nsk: 56 },
  0x0040: _mlKemRow("ML-KEM-512", "id-ml-kem-512", "ml-kem-512"),
  0x0041: _mlKemRow("ML-KEM-768", "id-ml-kem-768", "ml-kem-768"),
  0x0042: _mlKemRow("ML-KEM-1024", "id-ml-kem-1024", "ml-kem-1024"),
  0x0050: _hybridRow("MLKEM768-P256", "ML-KEM-768", "ml-kem-768", "P-256", "MLKEM768-P256"),
  0x0051: _hybridRow("MLKEM1024-P384", "ML-KEM-1024", "ml-kem-1024", "P-384", "MLKEM1024-P384"),
  /** @internal The label is X-Wing's own, because X-Wing is what this suite became when it was folded
   *  into draft-irtf-cfrg-concrete-hybrid-kems. The id is not adjacent to the other two. */
  0x647a: _hybridRow("MLKEM768-X25519", "ML-KEM-768", "ml-kem-768", "X25519", "\\.//^\\"),
});

var MODE_BASE = 0x00, MODE_PSK = 0x01, MODE_AUTH = 0x02, MODE_AUTH_PSK = 0x03;

function _idStr(id) { return typeof id === "number" ? "0x" + id.toString(16) : guard.text.showValue(id); }
function _kem(id) { var s = KEMS[guard.text.keyOf(id)]; if (!s) throw _err("hpke/unknown-suite", "unsupported KEM id " + _idStr(id)); return s; }
function _kdf(id) { var s = KDFS[guard.text.keyOf(id)]; if (!s) throw _err("hpke/unknown-suite", "unsupported KDF id " + _idStr(id)); return s; }
function _aead(id) { var s = AEADS[guard.text.keyOf(id)]; if (!s) throw _err("hpke/unknown-suite", "unsupported AEAD id " + _idStr(id)); return s; }


function _extract(hash, Nh, salt, ikm) {
  var key = (salt && salt.length) ? salt : Buffer.alloc(Nh);
  return guard.crypto.hmac(hash, key, ikm);
}
/** @internal A two-stage Expand yields at most 255 blocks (RFC 5869 sec. 2.3). The check has two callers
 *  because `_labeledExpand` builds the labeled info before it hands over, and that construction encodes
 *  the length in two bytes: asked for an unencodable length, the caller would otherwise be told its
 *  length does not fit rather than that it exceeds 255*Nh. */
function _assertExpandLength(Nh, len) {
  if (len > 255 * Nh) throw _err("hpke/export-length", "requested length " + len + " exceeds 255*Nh");
}
function _expand(hash, Nh, prk, info, len) {
  _assertExpandLength(Nh, len);
  var out = [], t = Buffer.alloc(0), n = Math.ceil(len / Nh), fed = null, joined = null;
  try {
    for (var i = 1; i <= n; i++) {
      fed = concat([t, info, Buffer.from([i])]);
      t = guard.crypto.hmac(hash, prk, fed);
      guard.secret.zeroize(fed, HpkeError, "hpke/bad-input", "an expand feedback input");
      fed = null;
      _push(out, t);
    }
    joined = concat(out);
    var exact = Buffer.alloc(len);
    joined.copy(exact, 0, 0, len);
    return exact;
  } finally {
    guard.secret.zeroize(fed, HpkeError, "hpke/bad-input", "an expand feedback input");
    guard.secret.zeroize(joined, HpkeError, "hpke/bad-input", "the KDF accumulator");
    for (var oi = 0; oi < out.length; oi++) guard.secret.zeroize(out[oi], HpkeError, "hpke/bad-input", "a KDF block");
  }
}
function _labeledExtract(kdf, suiteId, salt, label, ikm) {
  var labeled = concat([HPKE_V1, suiteId, L(label), ikm]);
  try { return _extract(kdf.hash, kdf.Nh, salt, labeled); }
  finally { guard.secret.zeroize(labeled, HpkeError, "hpke/bad-input", "the labeled extract input"); }
}
function _labeledExpand(kdf, suiteId, prk, label, info, len) {
  _assertExpandLength(kdf.Nh, len);
  return _expand(kdf.hash, kdf.Nh, prk, concat([i2osp(len, 2), HPKE_V1, suiteId, L(label), info]), len);
}


var OKP_SPKI = intrinsic.assign(intrinsic.create(null), { X25519: "302a300506032b656e032100", X448: "3042300506032b656f033900" });
var OKP_PKCS8 = intrinsic.assign(intrinsic.create(null), { X25519: "302e020100300506032b656e04220420", X448: "3046020100300506032b656f043a0438" });
var EC_SEC1 = intrinsic.assign(intrinsic.create(null), {
  "P-256": { head: "30310201010420", tail: "a00a06082a8648ce3d030107",
    order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" },
  "P-521": { head: "30500201010442", tail: "a00706052b81040023",
    order: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409" },
  /** @internal P-384 is here for the traditional half of MLKEM1024-P384. It is not a registered HPKE
   *  DHKEM on its own, so no KEM row names it; the hybrid row reaches it through its nominal group. */
  "P-384": { head: "303e0201010430", tail: "a00706052b81040022",
    order: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973" },
});
var ML_KEM_SPKI = intrinsic.assign(intrinsic.create(null), {
  "ML-KEM-512": "30820332300b06096086480165030404010382032100",
  "ML-KEM-768": "308204b2300b0609608648016503040402038204a100",
  "ML-KEM-1024": "30820632300b06096086480165030404030382062100",
});
var ML_KEM_PKCS8 = intrinsic.assign(intrinsic.create(null), {
  "ML-KEM-512": "3054020100300b060960864801650304040104428040",
  "ML-KEM-768": "3054020100300b060960864801650304040204428040",
  "ML-KEM-1024": "3054020100300b060960864801650304040304428040",
});
function _hex(h) { return _bufferFrom(h, "hex"); }

function _importPublic(kem, raw) {
  if (!_isBuffer(raw) || raw.length !== kem.Npub) {
    throw _err("hpke/bad-key", kem.name + " public key must be " + kem.Npub + " bytes");
  }
  try {
    if (kem.kind === "ec") {
      if (raw[0] !== 0x04) throw _err("hpke/bad-key", "EC public key must be an uncompressed 0x04 point (RFC 9180 sec. 7.1.4)");
      var half = (raw.length - 1) / 2;
      var jwk = { kty: "EC", crv: kem.curve, x: raw.subarray(1, 1 + half).toString("base64url"), y: raw.subarray(1 + half).toString("base64url") };
      return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    }
    var prefix = kem.kind === "mlkem" ? ML_KEM_SPKI[kem.name] : OKP_SPKI[kem.curve];
    return nodeCrypto.createPublicKey({ key: _bufferConcat([_hex(prefix), raw]), format: "der", type: "spki" });
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid " + kem.name + " public key" +
      (kem.kind === "mlkem" ? " (FIPS 203 sec. 7.2 encapsulation key check)" : ""), e);
  }
}
function _exportPublic(kem, keyObject) {
  var pub = keyObject.type === "public" ? keyObject : nodeCrypto.createPublicKey(keyObject);
  if (kem.kind === "mlkem") {
    var der = pub.export({ format: "der", type: "spki" }), prefix = _hex(ML_KEM_SPKI[kem.name]);
    if (der.length !== prefix.length + kem.Npub || !_bufferEquals(_subarray(der, 0, prefix.length), prefix)) {
      throw _err("hpke/bad-key", "the KeyObject is not an " + kem.name + " key");
    }
    return _subarray(der, prefix.length);
  }
  var jwk = pub.export({ format: "jwk" });
  if (jwk.crv !== kem.curve) throw _err("hpke/bad-key", "the KeyObject is not a " + kem.name + " key");
  if (kem.kind === "ec") return concat([Buffer.from([0x04]), _b64u(jwk.x), _b64u(jwk.y)]);
  return _b64u(jwk.x);
}
function _b64u(s) { return guard.encoding.base64url(s, null, _err, "hpke/bad-key", "JWK coordinate"); }

function _scalarInRange(d, order) {
  return _compare(d, _bufferAlloc(d.length)) > 0 && _compare(d, order) < 0;
}
function _importPrivate(kem, rawSk) {
  if (!_isBuffer(rawSk) || rawSk.length !== kem.Nsk) {
    throw _err("hpke/bad-key", kem.name + " private key must be " +
      (kem.kind === "mlkem" ? "the 64-byte seed" : "the " + kem.Nsk + "-byte scalar") + " as a Buffer");
  }
  var der;
  if (kem.kind === "ec") {
    var sec1 = EC_SEC1[kem.curve];
    if (!_scalarInRange(rawSk, _hex(sec1.order))) throw _err("hpke/bad-key", kem.name + " private scalar is outside [1, n-1]");
    der = _bufferConcat([_hex(sec1.head), rawSk, _hex(sec1.tail)]);
  } else {
    der = _bufferConcat([_hex(kem.kind === "mlkem" ? ML_KEM_PKCS8[kem.name] : OKP_PKCS8[kem.curve]), rawSk]);
  }
  try {
    return nodeCrypto.createPrivateKey({ key: der, format: "der", type: kem.kind === "ec" ? "sec1" : "pkcs8" });
  } catch (e) {
    throw _err("hpke/bad-key", "invalid " + kem.name + " private key", e);
  } finally {
    guard.secret.zeroize(der, HpkeError, "hpke/bad-input", "the private key envelope");
  }
}
function _boundPublic(kem, privateKey, pkm) {
  var derived = _exportPublic(kem, nodeCrypto.createPublicKey(privateKey));
  if (pkm === undefined) return derived;
  if (!_isBuffer(pkm) || !_bufferEquals(derived, pkm)) {
    throw _err("hpke/bad-key", "pkm is not the " + kem.name + " public key derived from skm");
  }
  return derived;
}
function _dh(privateKey, publicKey) {
  try {
    return nodeCrypto.diffieHellman({ privateKey: privateKey, publicKey: publicKey });
  } catch (e) {
    throw _err("hpke/bad-key", "KEM Diffie-Hellman failed: invalid or low-order public key", e);
  }
}
/** @internal A DHKEM key pair. Only the ec and okp kinds reach here: an ML-KEM or hybrid key is a seed,
 *  drawn and expanded by generateKeyPair, and an ML-KEM encapsulation takes its randomness from the
 *  runtime rather than from an ephemeral key pair. */
function _generate(kem) {
  if (kem.kind === "ec") return nodeCrypto.generateKeyPairSync("ec", { namedCurve: kem.nodeCurve });
  return nodeCrypto.generateKeyPairSync(kem.curve.toLowerCase());
}


/** @internal The traditional half of a hybrid, as a KEM row the existing import paths already read. The
 *  group is not a registered DHKEM, so it has no row of its own; this borrows the shape rather than
 *  duplicating the import logic for it. */
function _groupRow(kem) {
  var g = kem.group;
  return { kind: g.kind, name: kem.name + " " + kem.groupName, curve: g.curve, nodeCurve: g.nodeCurve,
    Npub: g.Nelem, Nsk: g.Nscalar, Nsecret: g.Nss };
}
/** @internal A single-stage KDF's Derive: an extendable-output function squeezed to `outLen` bytes
 *  (draft-ietf-hpke-pq-05 sec. 5, `SHAKE<SIZE>.Derive(ikm, L) = SHAKE<SIZE>(M = ikm, d = 8*L)`). */
function _derive(xof, input, outLen) {
  return guard.crypto.xof(xof, input, outLen);
}
/** @internal LabeledDerive over a single-stage KDF (draft-ietf-hpke-hpke-05 sec. 4.4):
 *
 *    labeled_ikm = concat(ikm, "HPKE-v1", suite_id, lengthPrefixed(label), I2OSP(L, 2), context)
 *    return Derive(labeled_ikm, L)
 *
 *  The order is NOT LabeledExtract's. The ikm comes FIRST, the label carries a two-byte big-endian
 *  length prefix (sec. 3), and the output length is encoded after it rather than at the front. Getting
 *  any of that wrong yields a key pair no other implementation derives from the same input, which is why
 *  the published ikm-to-key vectors drive it rather than a round trip through this module.
 *  Both consumers reach it here: the KEM's DeriveKeyPair, whose suite_id is the KEM one and whose XOF the
 *  KEM fixes, and the HPKE key schedule, whose suite_id names the whole suite and whose XOF is the
 *  registered KDF's. */
function _labeledDerive(xof, suiteId, ikm, label, context, outLen) {
  var lab = _bufferFrom(label, "latin1");
  var parts = _pushPrefixed([ikm, HPKE_V1, suiteId], lab, "a derive label");
  _push(parts, i2osp(outLen, 2), context);
  var labeledIkm = concat(parts);
  try { return _derive(xof, labeledIkm, outLen); }
  finally { guard.secret.zeroize(labeledIkm, HpkeError, "hpke/bad-input", "the labeled derive input"); }
}
/** @internal RandomScalar (draft-irtf-cfrg-concrete-hybrid-kems sec. 3.1.1): rejection sampling over
 *  Nscalar-byte chunks of the seed, taking the first that is in [1, order). A chunk at or above the
 *  order would be a biased scalar, so it is skipped rather than reduced. */
function _randomScalar(kem, seedT) {
  var g = kem.group;
  if (g.kind === "okp") return _subarray(seedT, 0, g.Nscalar);
  var order = _hex(EC_SEC1[g.curve].order);
  for (var start = 0; start + g.Nscalar <= seedT.length; start += g.Nscalar) {
    var chunk = _subarray(seedT, start, start + g.Nscalar);
    if (_scalarInRange(chunk, order)) return chunk;
  }
  throw _err("hpke/bad-key", kem.name + " rejection sampling found no scalar in the seed");
}
/** @internal expandDecapsKeyG (draft-irtf-cfrg-hybrid-kems sec. 5.1.1). One seed expands, through
 *  SHAKE-256, into the ML-KEM seed and the group's scalar seed. The ML-KEM half goes in as the FIPS 203
 *  seed form, which is what makes this deterministic: Node's own `seed` generation option is ignored
 *  silently, so a key derived through it would differ on every call. */
function _hybridExpand(kem, seed) {
  if (!_isBuffer(seed) || seed.length !== kem.Nsk) {
    throw _err("hpke/bad-key", kem.name + " private key must be the " + kem.Nsk + "-byte seed as a Buffer");
  }
  var full = _derive("shake256", seed, kem.pq.Nsk + kem.group.Nseed);
  try {
    var skPQ = _importPrivate(kem.pq, _subarray(full, 0, kem.pq.Nsk));
    var skT = _importPrivate(_groupRow(kem), _randomScalar(kem, _subarray(full, kem.pq.Nsk)));
    return {
      skPQ: skPQ, skT: skT,
      ekPQ: _exportPublic(kem.pq, nodeCrypto.createPublicKey(skPQ)),
      ekT: _exportPublic(_groupRow(kem), nodeCrypto.createPublicKey(skT)),
    };
  } finally {
    guard.secret.zeroize(full, HpkeError, "hpke/bad-input", "the hybrid seed expansion");
  }
}
/** @internal The C2PRI combiner (draft-irtf-cfrg-hybrid-kems sec. 5.2). The PQ ciphertext and
 *  encapsulation key are deliberately ABSENT: the PQ KEM is already ciphertext-collision-resistant, so
 *  only the traditional half needs binding. Adding them would be the UniversalCombiner and would derive
 *  a different secret from the same exchange. */
function _hybridCombine(kem, ssPQ, ssT, ctT, ekT) {
  var input = concat([ssPQ, ssT, ctT, ekT, kem.label]);
  /** @internal The digest through the captured operations too. This one IS the shared secret, so the
   *  hash prototype's `update` deciding what it covers is the same defect as the concatenation's. */
  try { return guard.crypto.digest("sha3-256", input); }
  finally { guard.secret.zeroize(input, HpkeError, "hpke/bad-input", "the hybrid combiner input"); }
}
function _hybridSplitPublic(kem, raw) {
  if (!_isBuffer(raw) || raw.length !== kem.Npub) {
    throw _err("hpke/bad-key", kem.name + " public key must be " + kem.Npub + " bytes: the " +
      kem.pq.Npub + "-byte " + kem.pq.name + " key then the " + kem.group.Nelem + "-byte " + kem.groupName + " key");
  }
  return { pq: _subarray(raw, 0, kem.pq.Npub), t: _subarray(raw, kem.pq.Npub) };
}
function _hybridEncap(kem, pkRaw, eph) {
  _refuseEph(kem, eph);
  var halves = _hybridSplitPublic(kem, pkRaw);
  var pqPub = _importPublic(kem.pq, halves.pq);
  var gRow = _groupRow(kem);
  var tPub = _importPublic(gRow, halves.t);
  var pqOut = _mlKemEncap(kem.pq, pqPub, undefined);
  var e, ssT = null;
  try {
    /** @internal Inside the try, so a key-generation fault still wipes the PQ shared secret above it. */
    e = _ephemeral(gRow, undefined);
    ssT = _elementToSharedSecret(kem, _dh(e.skE, tPub));
    return {
      sharedSecret: _hybridCombine(kem, pqOut.sharedSecret, ssT, e.enc, halves.t),
      enc: concat([pqOut.enc, e.enc]),
    };
  } finally {
    _wipeDh(ssT);
    guard.secret.zeroize(pqOut.sharedSecret, HpkeError, "hpke/bad-input", "the hybrid PQ shared secret");
  }
}
function _hybridDecap(kem, enc, seed) {
  if (!_isBuffer(enc) || enc.length !== kem.Nenc) {
    throw _err("hpke/bad-key", kem.name + " encapsulated key must be " + kem.Nenc + " bytes: the " +
      kem.pq.Nenc + "-byte " + kem.pq.name + " ciphertext then the " + kem.group.Nelem + "-byte " + kem.groupName + " element");
  }
  var ctPQ = _subarray(enc, 0, kem.pq.Nenc);
  var ctT = _subarray(enc, kem.pq.Nenc);
  var st = _hybridExpand(kem, seed);
  var ssPQ = null, ssT = null;
  try {
    ssPQ = _mlKemDecap(kem.pq, ctPQ, st.skPQ);
    ssT = _elementToSharedSecret(kem, _dh(st.skT, _importPublic(_groupRow(kem), ctT)));
    return _hybridCombine(kem, ssPQ, ssT, ctT, st.ekT);
  } finally { _wipeDh(ssPQ); _wipeDh(ssT); }
}
/** @internal ElementToSharedSecret: the X coordinate for a NIST curve, the value itself for Curve25519.
 *  Node's diffieHellman already yields the X coordinate for an EC curve and the raw output for X25519,
 *  so both are already the value the specification names, and the length is asserted rather than
 *  assumed. */
function _elementToSharedSecret(kem, dh) {
  if (dh.length !== kem.group.Nss) {
    throw _err("hpke/bad-key", kem.name + " " + kem.groupName + " shared secret must be " + kem.group.Nss + " bytes");
  }
  return dh;
}

function _kemSuiteId(kemId) { return concat([L("KEM"), i2osp(kemId, 2)]); }
function _extractAndExpand(kem, dh, kemContext) {
  var kdf = _kdf(kem.kdf), sid = _kemSuiteId(_kemId(kem));
  var eaePrk = _labeledExtract(kdf, sid, Buffer.alloc(0), "eae_prk", dh);
  try { return _labeledExpand(kdf, sid, eaePrk, "shared_secret", kemContext, kem.Nsecret); }
  finally { guard.secret.zeroize(eaePrk, HpkeError, "hpke/bad-input", "the KEM extract PRK"); }
}
function _kemId(kem) {
  var names = guard.identifier.optionNames(KEMS);
  for (var i = 0; i < names.length; i++) if (KEMS[names[i]] === kem) return Number(names[i]);
  return 0;
}

function _ephemeral(kem, eph) {
  if (eph != null) {
    if (typeof eph !== "object") throw _err("hpke/bad-input", "eph must be { skm, pkm } (a fixed ephemeral key pair), got " + guard.text.showValue(eph));
    var skE = _importPrivate(kem, _rawKey(eph.skm, kem.Nsk));
    return { skE: skE, enc: _boundPublic(kem, skE, _rawKey(eph.pkm, kem.Npub)) };
  }
  var kp = _generate(kem);
  return { skE: kp.privateKey, enc: _exportPublic(kem, kp.publicKey) };
}
function _wipeDh(dh) { guard.secret.zeroize(dh, HpkeError, "hpke/bad-input", "the KEM shared secret"); }
/** @internal A fixed ephemeral key pair applies to a DHKEM suite only, the ML-KEM and hybrid KEMs taking
 *  their encapsulation randomness from the runtime. One refusal for both, because a caller that supplied
 *  an `eph` and got a success would believe the key it named was the one used. */
function _refuseEph(kem, eph) {
  if (eph == null) return;
  throw _err("hpke/bad-input", "eph (a fixed ephemeral key pair) applies to a DHKEM suite; " + kem.name +
    " encapsulation takes its randomness from the runtime");
}
function _mlKemEncap(kem, pkR, eph) {
  _refuseEph(kem, eph);
  var r;
  try { r = nodeCrypto.encapsulate(pkR); }
  catch (e) { throw _err("hpke/bad-key", kem.name + " encapsulation failed", e); }
  return { sharedSecret: r.sharedKey, enc: r.ciphertext };
}
function _mlKemDecap(kem, enc, skR) {
  if (enc.length !== kem.Nenc) {
    throw _err("hpke/bad-key", kem.name + " encapsulated key must be " + kem.Nenc + " bytes (FIPS 203 sec. 7.3 ciphertext check)");
  }
  try { return nodeCrypto.decapsulate(skR, enc); }
  catch (e) { throw _err("hpke/bad-key", kem.name + " decapsulation failed", e); }
}
function _encap(kem, pkR, pkRm, eph) {
  if (kem.kind === "hybrid") return _hybridEncap(kem, pkRm, eph);
  if (kem.kind === "mlkem") return _mlKemEncap(kem, pkR, eph);
  var e = _ephemeral(kem, eph);
  var dh = null;
  try {
    dh = _dh(e.skE, pkR);
    return { sharedSecret: _extractAndExpand(kem, dh, concat([e.enc, pkRm])), enc: e.enc };
  } finally { _wipeDh(dh); }
}
/** @internal The width an encapsulated key is, for the bound the decapsulations read before they copy.
 *  A KEM that produces a ciphertext states `Nenc`; for a Diffie-Hellman KEM the encapsulated key IS an
 *  ephemeral public key, so its width is `Npub` and no `Nenc` is stated. Reading `Nenc` alone left the
 *  bound undefined for every DH suite, which is most of them, so the copy went ahead unbounded. */
function _encWidth(kem) { return kem.Nenc === undefined ? kem.Npub : kem.Nenc; }

function _decap(kem, enc, skR, pkRm) {
  /** @internal Snapshotted here rather than at each caller, so the standalone verb and the setup path are
   *  held to it alike: `_importPublic` and `_mlKemDecap` read a width off this buffer, and the KEM context
   *  concatenates it, so the two must be the same bytes. */
  /** @internal Bounded at the KEM's encapsulation width before the copy. An encapsulated key is a fixed
   *  width and the checks enforcing it (`_importPublic`, `_mlKemDecap`) read it off the copy, so a value
   *  handed where a 32-byte key belongs was duplicated in full and only then refused. */
  enc = _rawKey(enc, _encWidth(kem));
  if (kem.kind === "hybrid") return _hybridDecap(kem, enc, skR);
  if (kem.kind === "mlkem") return _mlKemDecap(kem, enc, skR);
  var pkE = _importPublic(kem, enc);
  var dh = null;
  try {
    dh = _dh(skR, pkE);
    return _extractAndExpand(kem, dh, concat([enc, pkRm]));
  } finally { _wipeDh(dh); }
}
function _authEncap(kem, pkR, pkRm, skS, pkSm, eph) {
  var e = _ephemeral(kem, eph);
  var dh1 = null, dh2 = null, dh = null;
  try {
    dh1 = _dh(e.skE, pkR);
    dh2 = _dh(skS, pkR);
    dh = concat([dh1, dh2]);
    return { sharedSecret: _extractAndExpand(kem, dh, concat([e.enc, pkRm, pkSm])), enc: e.enc };
  } finally { _wipeDh(dh1); _wipeDh(dh2); _wipeDh(dh); }
}
function _authDecap(kem, enc, skR, pkRm, pkS, pkSm) {
  /** @internal Bounded before the copy, for the reason at `_decap`. */
  enc = _rawKey(enc, _encWidth(kem));
  var pkE = _importPublic(kem, enc);
  var dh1 = null, dh2 = null, dh = null;
  try {
    dh1 = _dh(skR, pkE);
    dh2 = _dh(skR, pkS);
    dh = concat([dh1, dh2]);
    return _extractAndExpand(kem, dh, concat([enc, pkRm, pkSm]));
  } finally { _wipeDh(dh1); _wipeDh(dh2); _wipeDh(dh); }
}


function _hpkeSuiteId(kemId, kdfId, aeadId) { return concat([L("HPKE"), i2osp(kemId, 2), i2osp(kdfId, 2), i2osp(aeadId, 2)]); }

function _verifyPsk(mode, psk, pskId) {
  var gotPsk = psk.length > 0, gotId = pskId.length > 0;
  if (gotPsk !== gotId) throw _err("hpke/inconsistent-psk", "psk and psk_id must be provided together (RFC 9180 sec. 5.1)");
  if (gotPsk && (mode === MODE_BASE || mode === MODE_AUTH)) throw _err("hpke/inconsistent-psk", "a PSK was provided for a non-PSK mode");
  if (!gotPsk && (mode === MODE_PSK || mode === MODE_AUTH_PSK)) throw _err("hpke/inconsistent-psk", "mode requires a PSK");
}

/** @internal CombineSecrets_OneStage (draft-ietf-hpke-hpke-05 sec. 5.1). One derive of Nk + Nn + Nh bytes
 *  replaces the two-stage schedule's five Extract / Expand calls, and the key, the base nonce and the
 *  exporter secret are consecutive slices of it. The export-only AEAD has Nk and Nn of 0 (sec. 7.3
 *  Table 5), so the derive is Nh bytes and all of it is the exporter secret; no published vector pairs
 *  export-only with a single-stage KDF, so that combination follows from the two tables.
 *  Each slice is copied out because the derive buffer is wiped on the way out. */
function _keyScheduleOneStage(suite, mode, sharedSecret, info, psk, pskId, role) {
  var kdf = suite.kdf, aead = suite.aead;
  var nk = aead.exportOnly ? 0 : aead.Nk, nn = aead.exportOnly ? 0 : aead.Nn;
  /** @internal Both lists hold references to the caller's buffers rather than copies of them, and every
   *  length is checked as the lists are built, so an over-long input is refused before anything carrying
   *  secret material exists. The two joins below are the only buffers that do, and both are wiped. */
  var secretParts = _pushPrefixed([], psk, "psk");
  _pushPrefixed(secretParts, sharedSecret, "the KEM shared secret");
  var kscParts = _pushPrefixed([_bufferFrom([mode])], pskId, "pskId");
  _pushPrefixed(kscParts, info, "info");
  var secrets = null, secret = null;
  try {
    secrets = concat(secretParts);
    secret = _labeledDerive(kdf.xof, suite.suiteId, secrets, "secret", concat(kscParts), nk + nn + kdf.Nh);
    var key = nk ? _bufferFrom(_subarray(secret, 0, nk)) : null;
    var baseNonce = nn ? _bufferFrom(_subarray(secret, nk, nk + nn)) : null;
    return new Context(suite, key, baseNonce, _bufferFrom(_subarray(secret, nk + nn)), role);
  } finally {
    guard.secret.zeroize(secrets, HpkeError, "hpke/bad-input", "the key-schedule secrets input");
    guard.secret.zeroize(secret, HpkeError, "hpke/bad-input", "the key-schedule derive output");
  }
}

function _keySchedule(suite, mode, sharedSecret, info, psk, pskId, role) {
  _verifyPsk(mode, psk, pskId);
  var kdf = suite.kdf, sid = suite.suiteId, aead = suite.aead;
  if (_isOneStage(kdf)) return _keyScheduleOneStage(suite, mode, sharedSecret, info, psk, pskId, role);
  var pskIdHash = _labeledExtract(kdf, sid, Buffer.alloc(0), "psk_id_hash", pskId);
  var infoHash = _labeledExtract(kdf, sid, Buffer.alloc(0), "info_hash", info);
  var ksc = concat([_bufferFrom([mode]), pskIdHash, infoHash]);
  var secret = _labeledExtract(kdf, sid, sharedSecret, "secret", psk);
  try {
    var exporterSecret = _labeledExpand(kdf, sid, secret, "exp", ksc, kdf.Nh);
    var key = null, baseNonce = null;
    if (!aead.exportOnly) {
      key = _labeledExpand(kdf, sid, secret, "key", ksc, aead.Nk);
      baseNonce = _labeledExpand(kdf, sid, secret, "base_nonce", ksc, aead.Nn);
    }
    return new Context(suite, key, baseNonce, exporterSecret, role);
  } finally {
    guard.secret.zeroize(secret, HpkeError, "hpke/bad-input", "the key-schedule PRK");
  }
}


function Context(suite, key, baseNonce, exporterSecret, role) {
  this._suite = suite; this._key = key; this._baseNonce = baseNonce;
  this._exporterSecret = exporterSecret; this._seq = 0n; this._role = role;
}
Context.prototype._dispose = function () {
  guard.secret.zeroizeAll([this._key, this._baseNonce, this._exporterSecret], HpkeError, "hpke/bad-input", "the HPKE context key material");
};
Context.prototype._nonce = function () {
  var aead = this._suite.aead;
  var seqBytes = i2osp(this._seq, aead.Nn);
  return xor(this._baseNonce, seqBytes);
};
Context.prototype._inc = function () {
  var aead = this._suite.aead;
  if (this._seq >= (1n << BigInt(8 * aead.Nn)) - 1n) throw _err("hpke/message-limit", "AEAD sequence number would overflow (RFC 9180 sec. 5.2)");
  this._seq += 1n;
};
Context.prototype.seal = function (aad, pt) {
  var aead = this._suite.aead;
  if (this._role !== "S") throw _err("hpke/wrong-role", "seal is only available on a sender context (RFC 9180 sec. 5.2)");
  if (aead.exportOnly) throw _err("hpke/export-only", "seal is not available for an export-only AEAD");
  /** @internal The AAD is normalized like every other byte input before its width decides anything.
   *  Read as `aad.length`, a DataView and an ArrayBuffer answer `undefined`, so the test was falsy and
   *  `setAAD` was never called: the additional data was SILENTLY DROPPED and the tag authenticated
   *  nothing. Both sides dropped it, so the message still opened and a caller testing their own code saw
   *  it work while the binding they relied on was absent. An empty AAD still means no additional data,
   *  which is what RFC 9180 sec. 5.2 uses. */
  var aadBytes = _buf(aad);
  var nonce = this._nonce();
  var c = nodeCrypto.createCipheriv(aead.cipher, this._key, nonce, { authTagLength: aead.Nt });
  if (aadBytes.length) c.setAAD(aadBytes);
  var body = guard.secret.cipherFinish(c, _buf(pt), HpkeError, "hpke/bad-input", "a seal intermediate");
  var ct = concat([body, c.getAuthTag()]);
  this._inc();
  return ct;
};
Context.prototype.open = function (aad, ct) {
  var aead = this._suite.aead;
  if (this._role !== "R") throw _err("hpke/wrong-role", "open is only available on a recipient context (RFC 9180 sec. 5.2)");
  if (aead.exportOnly) throw _err("hpke/export-only", "open is not available for an export-only AEAD");
  ct = _buf(ct);
  if (ct.length < aead.Nt) throw _err("hpke/open-failed", "ciphertext is shorter than the AEAD tag");
  /** @internal Normalized for the reason at `seal`: read as `aad.length` a DataView answered `undefined`,
   *  so the AAD was dropped on this side too and the pair round-tripped with nothing bound. */
  var aadBytes = _buf(aad);
  var nonce = this._nonce();
  var d = nodeCrypto.createDecipheriv(aead.cipher, this._key, nonce, { authTagLength: aead.Nt });
  if (aadBytes.length) d.setAAD(aadBytes);
  d.setAuthTag(ct.subarray(ct.length - aead.Nt));
  var pt;
  try { pt = guard.secret.cipherFinish(d, ct.subarray(0, ct.length - aead.Nt), HpkeError, "hpke/bad-input", "the recovered plaintext"); }
  catch (e) { throw _err("hpke/open-failed", "AEAD authentication failed (RFC 9180 sec. 5.2)", e); }
  this._inc();
  return pt;
};
Context.prototype.export = function (exporterContext, len) {
  if (!Number.isInteger(len) || len < 0) throw _err("hpke/export-length", "export length must be a non-negative integer");
  var kdf = this._suite.kdf;
  if (_isOneStage(kdf)) {
    /** @internal LabeledDerive encodes L in two bytes (sec. 4.4), so 65535 is the longest export a
     *  single-stage KDF can name. SHAKE has no input length limit, so sec. 7.2.1's further cap on
     *  exporter_context does not bind for these two KDFs. */
    if (len > MAX_PREFIXED) {
      throw _err("hpke/export-length", "requested length " + len + " exceeds " + MAX_PREFIXED +
        ", the longest a single-stage KDF encodes (draft-ietf-hpke-hpke-05 sec. 4.4)");
    }
    return _labeledDerive(kdf.xof, this._suite.suiteId, this._exporterSecret, "sec", _buf(exporterContext), len);
  }
  return _labeledExpand(kdf, this._suite.suiteId, this._exporterSecret, "sec", _buf(exporterContext), len);
};
/** @internal Every caller-supplied byte input is snapshotted here rather than used where it lies. A Buffer
 *  can shadow `length` with an own property while `byteLength` still reports its real size, so a check
 *  reading `length` and a copy reading `byteLength` see different values: that is how a 65536-byte `info`
 *  passed the single-stage limit and still reached the derive. `guard.bytes.snapshot` re-views the source
 *  and copies it, so every later read is of the bytes actually used, and a caller holding a reference can
 *  no longer change them after they are checked. */
/** @internal A caller's byte source as a byte VIEW, before anything measures or copies it. The admitted set
 *  is `guard.bytes.isByteSource`'s, which `deriveKeyPair` names in its own refusal: Buffer, TypedArray,
 *  DataView and ArrayBuffer. `guard.bytes.snapshot` takes Buffer and Uint8Array only, so handing it the raw
 *  input refused half the set the message promises, and `Response.arrayBuffer()` and
 *  `subtle.exportKey("raw", ...)` both return the refused half. `guard.bytes.source` shares the caller's
 *  backing store rather than copying it, so normalizing first leaves every cap ahead of every allocation. */
function _view(x, code, label) {
  return guard.bytes.source(x, _err, code, label);
}
function _buf(x, maxBytes) {
  if (x == null) return _EMPTY;
  var v = _view(x, "hpke/bad-input", "a byte input");
  /** @internal When the caller's own limit is known here, it is checked BEFORE the copy: the snapshot
   *  allocates, so a 256 MiB `info` was copied in full and only then refused for exceeding 65535. The size
   *  comes from `guard.bytes.lengthOf`, the same authoritative byte count the copy uses, not from `.length`,
   *  so this early check cannot be told a different size than the copy sees. */
  if (maxBytes !== undefined && guard.bytes.lengthOf(v) > maxBytes) {
    throw _err("hpke/input-length", "an input of " + guard.bytes.lengthOf(v) + " bytes exceeds the " +
      maxBytes + "-byte limit a single-stage KDF imposes (draft-ietf-hpke-hpke-05 sec. 7.2.1)");
  }
  return guard.bytes.snapshot(v, _err, "hpke/bad-input", "a byte input");
}
/** @internal Raw key material, snapshotted for the same reason as `_buf` and bound to a local so the width
 *  check and the import read one value. A node KeyObject is not a byte source and passes through. */
function _rawKey(x, maxBytes) {
  if (x == null || !guard.bytes.isByteSource(x)) return x;
  var keyView = _view(x, "hpke/bad-key", "raw key material");
  /** @internal `maxBytes` is the width the suite's keys are, read BEFORE the copy. Every key reaching
   *  here is a fixed width and the check enforcing it ran on the copy, so a value handed where a
   *  32-byte key belongs was duplicated in full and only then refused: measured, 64 MiB copied to
   *  reject a key. A value within the width falls through unchanged to the checks that own it, whose
   *  messages name the form each key takes. Viewing costs no copy. */
  if (maxBytes !== undefined) {
    var size = guard.bytes.lengthOf(keyView);
    if (size > maxBytes) {
      throw _err("hpke/bad-key", "raw key material of " + size + " bytes is wider than the " +
        maxBytes + " bytes this suite's keys are");
    }
  }
  return guard.bytes.snapshot(keyView, _err, "hpke/bad-key", "raw key material");
}


function _suite(ids) {
  if (!ids || typeof ids !== "object") throw _err("hpke/unknown-suite", "suiteIds must be an object { kem, kdf, aead } from pki.hpke.suites");
  var kemId = ids.kem, kdfId = ids.kdf, aeadId = ids.aead;
  var kem = _kem(kemId), kdf = _kdf(kdfId), aead = _aead(aeadId);
  return { kem: kem, kdf: kdf, aead: aead, kemId: kemId, kdfId: kdfId, aeadId: aeadId, suiteId: _hpkeSuiteId(kemId, kdfId, aeadId) };
}

function _recipPublic(suite, pk) {
  /** @internal A hybrid public key is two keys concatenated, so there is no single KeyObject for it. The
   *  raw form is the canonical one and each half is imported inside the KEM, where the split is known. */
  var supplied = _rawKey(_isBuffer(pk) ? pk : (pk && pk.pkm), suite.kem.Npub);
  if (suite.kem.kind === "hybrid") {
    if (!_isBuffer(supplied)) {
      throw _err("hpke/bad-key", suite.kem.name + " public key must be the " + suite.kem.Npub +
        "-byte concatenation as a Buffer or { pkm }, there being no single KeyObject for two keys");
    }
    _hybridSplitPublic(suite.kem, supplied);
    return { key: null, pkm: supplied };
  }
  if (_isBuffer(supplied)) return { key: _importPublic(suite.kem, supplied), pkm: supplied };
  try {
    return { key: pk, pkm: _exportPublic(suite.kem, pk) };
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    /** @internal The forms are named exactly, because "a raw buffer" reads as any byte view and a bare
     *  TypedArray is NOT one of them: for a key the alternative to a Buffer is a KeyObject, and a value
     *  that is neither reaches the KeyObject export and fails there rather than at the door. A caller
     *  holding a Uint8Array is told to wrap it rather than left to infer which reading was meant. */
    throw _err("hpke/bad-key", "invalid KEM public key (expected a node KeyObject, a Buffer, or " +
      "{ pkm: Buffer }; a bare TypedArray, DataView or ArrayBuffer is not a key here, so wrap it with " +
      "Buffer.from first)", e);
  }
}
function _recipPrivate(suite, sk) {
  var kem = suite.kem;
  /** @internal A hybrid decapsulation key IS the seed, so it stays a Buffer and the component keys are
   *  expanded inside the KEM. Deriving the public key here also checks the seed before anything else
   *  runs, so a wrong-length seed is refused at the door. */
  /** @internal Both members are read ONCE, into a local, and every test below asks the local. Written as
   *  `sk.skm != null ? sk.skm : sk` the member was read twice in that one expression and a third time to
   *  pick the branch further down, so an accessor answering differently across those reads chose a
   *  branch for one value and ran it on another. The outcomes were refusals rather than substitutions,
   *  and the shape is still one read: whether a member is PRESENT and what it HOLDS are one question
   *  asked once.
   *  Each is bounded at the width the suite's keys are before it is copied, and `pkm` is read the same
   *  way `skm` is. An own-property test on `pkm` alone made the two fields disagree about what counts
   *  as supplied: one on the key pair's PROTOTYPE was treated as absent, so the rule that a supplied
   *  `pkm` must match `skm` was skipped rather than applied, and a key pair carrying a mismatching one
   *  passed a check that never ran. */
  var suppliedSkm = sk ? sk.skm : undefined;
  var hasSkm = suppliedSkm != null;
  var suppliedSk = _rawKey(hasSkm ? suppliedSkm : sk, kem.Nsk);
  var suppliedPkm = sk == null ? undefined : sk.pkm;
  var suppliedPk = suppliedPkm == null ? undefined : _rawKey(suppliedPkm, kem.Npub);
  if (kem.kind === "hybrid") {
    if (!_isBuffer(suppliedSk)) {
      throw _err("hpke/bad-key", kem.name + " private key must be the " + kem.Nsk +
        "-byte seed, as { skm } or a Buffer");
    }
    var st = _hybridExpand(kem, suppliedSk);
    var derivedPkm = concat([st.ekPQ, st.ekT]);
    if (suppliedPk !== undefined && (!_isBuffer(suppliedPk) || !_bufferEquals(derivedPkm, suppliedPk))) {
      throw _err("hpke/bad-key", "pkm is not the " + kem.name + " public key derived from skm");
    }
    return { key: suppliedSk, pkm: derivedPkm };
  }
  if (hasSkm) {
    var key = _importPrivate(kem, suppliedSk);
    return { key: key, pkm: _boundPublic(kem, key, suppliedPk) };
  }
  if (_isBuffer(sk)) {
    throw _err("hpke/bad-key", "a serialized " + kem.name + " private key must be provided as { skm" +
      (kem.kind === "mlkem" ? " } holding the 64-byte seed" : ", pkm } (the raw scalar, and optionally its public key)") + ", not a bare buffer");
  }
  try {
    if (sk.type !== "private") throw _err("hpke/bad-key", "the private key must be a private KeyObject or { skm, pkm }, got a " + guard.text.showValue(sk.type) + " KeyObject");
    var pkm = _exportPublic(kem, nodeCrypto.createPublicKey(sk));
    return { key: sk, pkm: pkm };
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid private key (expected a node KeyObject or { skm, pkm })", e);
  }
}
function _requireAuthCapable(kem) {
  /** @internal The auth modes need a static-static Diffie-Hellman, which a KEM interface does not offer.
   *  A hybrid is a KEM for the same reason its PQ half is, so it is refused alongside it rather than
   *  having the check apply to only one of the two KEM kinds. */
  if (kem.kind === "mlkem" || kem.kind === "hybrid") {
    throw _err("hpke/auth-unsupported", kem.name + " defines no AuthEncap / AuthDecap (draft-ietf-hpke-pq sec. 7.2); use the psk mode or a signature");
  }
}
function _refuseUnusedAuthKey(value, name, mode) {
  if (value != null) {
    throw _err("hpke/bad-input", name + " applies to the auth and auth-psk modes; mode " + mode + " would leave it unused, so the exchange it was meant to authenticate would not be");
  }
}

var _COMMON_KEYS = intrinsic.assign(intrinsic.create(null), { mode: 1, info: 1, psk: 1, pskId: 1 });
function _withCommon(extra) {
  var out = intrinsic.create(null);
  Object.keys(_COMMON_KEYS).forEach(function (k) { out[k] = 1; });
  var en = guard.identifier.optionNames(extra);
  for (var ei = 0; ei < en.length; ei++) out[en[ei]] = 1;
  return out;
}
var _SETUP_S_KEYS = _withCommon({
  senderKey: 1,
  eph: 1,
});
var _SETUP_R_KEYS = _withCommon({
  senderPublicKey: 1,
});
function _options(opts, keys, who) {
  guard.identifier.assertKnownKeys(opts, keys, _err, "hpke/bad-input", function (k) {
    var other = (keys === _SETUP_S_KEYS ? _SETUP_R_KEYS : _SETUP_S_KEYS);
    return "unknown HPKE " + who + " option " + JSON.stringify(k) +
      (_hasOwn(other, k)
        ? " -- that option belongs to the other end of the exchange, where it would authenticate or seed; here it would do nothing"
        : "") + " -- accepted: " + Object.keys(keys).sort().join(", ");
  });
  var o = guard.identifier.snapshotOptions(opts, keys);
  if (o.mode == null) o.mode = MODE_BASE;
  if (o.mode !== MODE_BASE && o.mode !== MODE_PSK && o.mode !== MODE_AUTH && o.mode !== MODE_AUTH_PSK) {
    throw _err("hpke/unknown-mode", "unsupported HPKE mode " + guard.text.showValue(o.mode) + " (RFC 9180 sec. 5.1 defines base / psk / auth / auth-psk)");
  }
  return o;
}

// @module @intro; a data registry, not a callable primitive).
var suites = intrinsic.assign(intrinsic.create(null), {
  KEM: intrinsic.assign(intrinsic.create(null), {
    DHKEM_P256_HKDF_SHA256: 0x0010, DHKEM_P384_HKDF_SHA384: 0x0011, DHKEM_P521_HKDF_SHA512: 0x0012,
    DHKEM_X25519_HKDF_SHA256: 0x0020, DHKEM_X448_HKDF_SHA512: 0x0021,
    ML_KEM_512: 0x0040, ML_KEM_768: 0x0041, ML_KEM_1024: 0x0042,
    MLKEM768_P256: 0x0050, MLKEM1024_P384: 0x0051, MLKEM768_X25519: 0x647a,
  }),
  KDF: intrinsic.assign(intrinsic.create(null), {
    HKDF_SHA256: 0x0001, HKDF_SHA384: 0x0002, HKDF_SHA512: 0x0003,
    SHAKE128: 0x0010, SHAKE256: 0x0011,
  }),
  AEAD: intrinsic.assign(intrinsic.create(null), { AES_128_GCM: 0x0001, AES_256_GCM: 0x0002, CHACHA20_POLY1305: 0x0003, EXPORT_ONLY: 0xFFFF }),
  MODE: intrinsic.assign(intrinsic.create(null), { BASE: MODE_BASE, PSK: MODE_PSK, AUTH: MODE_AUTH, AUTH_PSK: MODE_AUTH_PSK }),
});


/**
 * @primitive pki.hpke.setupS
 * @signature pki.hpke.setupS(suiteIds, recipientPublicKey, opts?) -> { enc, context, sharedSecret }
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.setupR, pki.hpke.seal
 *
 * Establish a sender HPKE context for a recipient KEM public key: encapsulate a
 * shared secret and run the key schedule, returning the encapsulated key `enc`
 * (send it to the recipient) and a `context` whose `.seal(aad, pt)` /
 * `.export(ctx, L)` encrypt and derive further secrets. `suiteIds` is
 * `{ kem, kdf, aead }` from `pki.hpke.suites`; `recipientPublicKey` is a node
 * KeyObject or the serialized public key bytes (the uncompressed point, the raw
 * Montgomery coordinate, or the ML-KEM encapsulation key). `opts.mode` selects
 * base / psk / auth / auth-psk (default base); `opts.info`, `opts.psk`/`opts.pskId`,
 * and `opts.senderKey` (auth modes) supply the corresponding inputs; an option that
 * belongs to another mode, such as `senderKey` in base mode, is refused with
 * `hpke/bad-input` rather than left unused. The auth modes exist for the DHKEM
 * suites only: an ML-KEM suite throws `hpke/auth-unsupported`. On a single-stage
 * KDF (SHAKE128, SHAKE256) `opts.info`, `opts.psk` and `opts.pskId` are capped at
 * 65535 bytes each and a longer one throws `hpke/input-length`.
 *
 * @example
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.DHKEM_X25519_HKDF_SHA256, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_128_GCM };
 *   var pkR = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
 *   var sender = pki.hpke.setupS(ids, pkR, { info: Buffer.from("app") });
 *   var ct = sender.context.seal(Buffer.from("aad"), Buffer.from("secret"));
 */
function _setupS(ids, pkR, opts) {
  var suite = _suite(ids);
  opts = _options(opts || {}, _SETUP_S_KEYS, "sender setup");
  var mode = opts.mode;
  var r = _recipPublic(suite, pkR);
  var kem = suite.kem, k;
  if (mode === MODE_AUTH || mode === MODE_AUTH_PSK) {
    _requireAuthCapable(kem);
    if (opts.senderKey == null) throw _err("hpke/auth-key-required", "an authenticated mode requires opts.senderKey (the sender's KEM private key, RFC 9180 sec. 5.1.3)");
    var s = _recipPrivate(suite, opts.senderKey);
    k = _authEncap(kem, r.key, r.pkm, s.key, s.pkm, opts.eph);
  } else {
    _refuseUnusedAuthKey(opts.senderKey, "senderKey", mode);
    k = _encap(kem, r.key, r.pkm, opts.eph);
  }
  var cap = _isOneStage(suite.kdf) ? MAX_PREFIXED : undefined;
  var ctx = _keySchedule(suite, mode, k.sharedSecret, _buf(opts.info, cap), _buf(opts.psk, cap), _buf(opts.pskId, cap), "S");
  return { enc: k.enc, context: ctx, sharedSecret: k.sharedSecret };
}
/**
 * @primitive pki.hpke.setupR
 * @signature pki.hpke.setupR(suiteIds, enc, recipientPrivateKey, opts?) -> context
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.setupS, pki.hpke.open
 *
 * Establish the recipient HPKE context from the sender's encapsulated key `enc`
 * and the recipient KEM private key, recovering the same shared secret and key
 * schedule. The private key is a node KeyObject, or `{ skm, pkm }` where `skm` is
 * the raw private scalar of a DHKEM suite or the 64-byte seed of an ML-KEM suite;
 * `pkm` is optional, and when given it must be the public key derived from `skm`
 * or the call throws `hpke/bad-key`. The returned `context` `.open(aad, ct)`
 * decrypts and `.export(ctx, L)` derives secrets. `opts` mirrors `setupS` (mode /
 * info / psk / pskId), with `opts.senderPublicKey` for the auth modes (DHKEM
 * suites only). A ciphertext whose tag does not verify throws `hpke/open-failed`.
 *
 * @example
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.DHKEM_X25519_HKDF_SHA256, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_128_GCM };
 *   var pkR = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
 *   var skR = Buffer.from("009f2181fba5f8908632c10ea1137c40a849728fde016c4602458b943a5dc048", "hex");
 *   var sender = pki.hpke.setupS(ids, pkR);
 *   var recipient = pki.hpke.setupR(ids, sender.enc, { skm: skR, pkm: pkR });
 *   var pt = recipient.open(Buffer.alloc(0), sender.context.seal(Buffer.alloc(0), Buffer.from("hi")));
 */
function _setupR(ids, enc, skR, opts) {
  var suite = _suite(ids);
  /** @internal The CIPHERTEXT is copied before the OPTIONS bag and the KEY RECORD are read, because
   *  reading either runs caller code: an `skm` accessor on the private key, or one on
   *  `opts.senderPublicKey`, fires while the encapsulation is still the caller's buffer, and one that
   *  copies a DIFFERENT encapsulation over it has this setup derive the secret for the other
   *  ciphertext. Copied once here and used by both arms below, so the bytes the KEM context commits to
   *  are the bytes that arrived. `_suite(ids)` above it reads the caller's identifier record first, by
   *  necessity: which KEM this is decides the width the copy is held to. Bounded at that width as it
   *  is taken, so the early copy that closes the substitution window is not itself an allocation the
   *  size of whatever was supplied: a 64 MiB value handed where a 32-byte encapsulation belongs was
   *  copied in full and only then refused. */
  var sealed = _rawKey(enc, _encWidth(suite.kem));
  opts = _options(opts || {}, _SETUP_R_KEYS, "recipient setup");
  var mode = opts.mode;
  var r = _recipPrivate(suite, skR);
  var kem = suite.kem, ss;
  if (mode === MODE_AUTH || mode === MODE_AUTH_PSK) {
    _requireAuthCapable(kem);
    if (opts.senderPublicKey == null) throw _err("hpke/auth-key-required", "an authenticated mode requires opts.senderPublicKey (the sender's KEM public key, RFC 9180 sec. 5.1.3)");
    var pkS = _recipPublic(suite, opts.senderPublicKey);
    ss = _authDecap(kem, sealed, r.key, r.pkm, pkS.key, pkS.pkm);
  } else {
    _refuseUnusedAuthKey(opts.senderPublicKey, "senderPublicKey", mode);
    ss = _decap(kem, sealed, r.key, r.pkm);
  }
  var rCap = _isOneStage(suite.kdf) ? MAX_PREFIXED : undefined;
  try { return _keySchedule(suite, mode, ss, _buf(opts.info, rCap), _buf(opts.psk, rCap), _buf(opts.pskId, rCap), "R"); }
  finally { guard.secret.zeroize(ss, HpkeError, "hpke/bad-input", "the KEM shared secret"); }
}

/**
 * @primitive pki.hpke.seal
 * @signature pki.hpke.seal(suiteIds, recipientPublicKey, opts, aad, pt) -> { enc, ct }
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.open, pki.hpke.setupS
 *
 * Single-shot HPKE encryption (RFC 9180 sec. 6): set up a sender context and
 * encrypt one plaintext, returning the encapsulated key `enc` and ciphertext
 * `ct`. Equivalent to `setupS` followed by one `context.seal`. `opts` is the
 * `setupS` options object (mode / info / psk / senderKey).
 *
 * @example
 *   // requires: mlKemPkR -- the recipient's ML-KEM-768 encapsulation key (1184 bytes)
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.ML_KEM_768, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_256_GCM };
 *   var out = pki.hpke.seal(ids, mlKemPkR, {}, Buffer.from("aad"), Buffer.from("msg"));
 */
function seal(ids, pkR, opts, aad, pt) {
  /** @internal The PAYLOAD is copied before the setup runs. The setup reads the suite identifiers, the
   *  options bag and the recipient's key record, and reading any of them runs caller code, so a getter
   *  there could overwrite the plaintext or the additional data this verb goes on to encrypt and
   *  authenticate. Both are taken here, at the door, before anything the caller controls is consulted. */
  var authData = _buf(aad);
  var plain = _buf(pt);
  var s = null;
  try {
  s = _setupS(ids, pkR, opts);
  return { enc: s.enc, ct: s.context.seal(authData, plain) };
  } finally {
    if (s) {
      s.context._dispose();
      guard.secret.zeroize(s.sharedSecret, HpkeError, "hpke/bad-input", "the KEM shared secret");
    }
  }
}

/**
 * @primitive pki.hpke.open
 * @signature pki.hpke.open(suiteIds, enc, recipientPrivateKey, opts, aad, ct) -> pt
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.seal, pki.hpke.setupR
 *
 * Single-shot HPKE decryption (RFC 9180 sec. 6): set up a recipient context from
 * `enc` and decrypt one ciphertext, returning the plaintext. A tag that does not
 * verify throws `hpke/open-failed` and returns no plaintext.
 *
 * @example
 *   // requires: mlKemPkR -- the recipient's ML-KEM-768 encapsulation key (1184 bytes)
 *   // requires: mlKemSkR -- { skm } holding the recipient's 64-byte ML-KEM-768 seed
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.ML_KEM_768, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_256_GCM };
 *   var o = pki.hpke.seal(ids, mlKemPkR, {}, Buffer.alloc(0), Buffer.from("m"));
 *   var pt = pki.hpke.open(ids, o.enc, mlKemSkR, {}, Buffer.alloc(0), o.ct);
 */
function open(ids, enc, skR, opts, aad, ct) {
  /** @internal The CIPHERTEXT and its additional data are copied before the setup runs, for the reason
   *  `seal` copies its payload first: the setup reads the suite identifiers, the options bag and the
   *  key record, and a getter on any of them could overwrite what this verb goes on to authenticate.
   *  The encapsulation is copied inside the setup, which is where both its callers reach it. */
  var authData = _buf(aad);
  var sealed = _buf(ct);
  var ctx = _setupR(ids, enc, skR, opts);
  try { return ctx.open(authData, sealed); }
  finally { ctx._dispose(); }
}

/**
 * @primitive pki.hpke.deriveKeyPair
 * @signature pki.hpke.deriveKeyPair(kemId, ikm) -> { publicKey, privateKey }
 * @since 0.8.45
 * @status stable
 * @spec RFC 9180 sec. 7.1.3, draft-ietf-hpke-pq sec. 3, draft-ietf-hpke-pq sec. 4
 * @defends kem-key-nondeterminism (CWE-330)
 * @related pki.hpke.generateKeyPair, pki.hpke.encap, pki.hpke.setupS
 *
 * The KEM's `DeriveKeyPair`: a key pair derived deterministically from input keying material, returned as
 * raw byte strings in the encodings the KEM registers. The same `ikm` always gives the same pair, so a
 * key can be rebuilt from backed-up material instead of stored in full, and the pair matches what any
 * other conforming implementation derives from the same input.
 *
 * `ikm` is keying material, not a private key. Each KEM runs it through its own derivation first: a
 * DHKEM through `LabeledExtract` and `LabeledExpand`, with the prime curves rejection-sampling
 * candidates until one lands in [1, order) (RFC 9180 section 7.1.3); an ML-KEM and a PQ/T hybrid through
 * `SHAKE256.LabeledDerive` to the KEM's seed, which is then expanded (draft-ietf-hpke-pq sections 3 and
 * 4). To use a private key you already hold, pass it as `{ skm }` to `decap`, `setupR` or `open`
 * instead; that door takes the KEM's own private encoding and checks its width.
 *
 * Any length of `ikm` is accepted. The hybrid suites state a 32-byte minimum as a SHOULD, which is not
 * enforced here, and an ML-KEM takes input of any length.
 *
 * `privateKey` is the KEM's private encoding: the 32-byte seed for a hybrid suite, the 64-byte seed for
 * a bare ML-KEM, and the scalar for a DHKEM.
 *
 * @example
 *   var ikm = Buffer.alloc(32, 7);
 *   var kp = pki.hpke.deriveKeyPair(pki.hpke.suites.KEM.MLKEM768_X25519, ikm);
 *   kp.publicKey.length;    // -> 1216, the ML-KEM-768 key then the X25519 key
 *   kp.privateKey.length;   // -> 32, the seed the ikm derived
 */
function deriveKeyPair(kemId, ikm) {
  var kem = _kem(kemId);
  if (!_isBuffer(ikm) && !guard.bytes.isByteSource(ikm)) {
    throw _err("hpke/bad-input", "ikm must be a byte source (Buffer / TypedArray / DataView / ArrayBuffer)");
  }
  /** @internal Viewed then copied, so the four forms the message above names are the four forms this
   *  takes: `guard.bytes.snapshot` alone wants a Buffer or a Uint8Array, and the two the message names
   *  last were refused by the line after the one that admitted them. */
  var input = guard.bytes.snapshot(_view(ikm, "hpke/bad-input", "ikm"), _err, "hpke/bad-input", "ikm");
  if (kem.kind === "hybrid") {
    /** @internal draft-ietf-hpke-pq sec. 4: the ikm is derived down to the KEM's 32-byte seed, and the
     *  CG framework then expands both component keys from THAT. The seed is not the ikm. */
    var seed = _labeledDerive("shake256", _kemSuiteId(_kemId(kem)), input, "DeriveKeyPair", _EMPTY, kem.Nsk);
    var st = _hybridExpand(kem, seed);
    return { publicKey: concat([st.ekPQ, st.ekT]), privateKey: seed };
  }
  if (kem.kind === "mlkem") {
    /** @internal draft-ietf-hpke-pq sec. 3: dk = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 64),
     *  and the decapsulation key returned is that 64-byte value. */
    var dk = _labeledDerive("shake256", _kemSuiteId(_kemId(kem)), input, "DeriveKeyPair", _EMPTY, kem.Nsk);
    var mlSk = _importPrivate(kem, dk);
    return { publicKey: _exportPublic(kem, nodeCrypto.createPublicKey(mlSk)), privateKey: dk };
  }
  var raw = _deriveKeyPairDhkem(kem, input);
  var sk = _importPrivate(kem, raw);
  return { publicKey: _exportPublic(kem, nodeCrypto.createPublicKey(sk)), privateKey: raw };
}

/** @internal DeriveKeyPair for a DHKEM (RFC 9180 sec. 7.1.3). X25519 and X448 expand the extract output
 *  straight to a scalar; the prime curves reject-sample candidates until one lands in [1, order), which
 *  is what keeps the scalar uniform rather than a reduction of a wider value:
 *
 *    dkp_prk = LabeledExtract("", "dkp_prk", ikm)
 *    sk = LabeledExpand(dkp_prk, "sk", "", Nsk)                      -- X25519 / X448
 *    bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter,1), Nsk); bytes[0] &= bitmask   -- NIST
 *
 *  The bitmask is 0xFF for P-256 and P-384 and 0x01 for P-521, which is what makes the 66-byte P-521
 *  candidate a 521-bit value rather than a 528-bit one. The counter is bounded at 255 by the text. */
function _deriveKeyPairDhkem(kem, ikm) {
  var kdf = _kdf(kem.kdf), sid = _kemSuiteId(_kemId(kem));
  var dkpPrk = _labeledExtract(kdf, sid, _EMPTY, "dkp_prk", ikm);
  try {
    if (kem.kind !== "ec") return _labeledExpand(kdf, sid, dkpPrk, "sk", _EMPTY, kem.Nsk);
    var order = _hex(EC_SEC1[kem.curve].order);
    var bitmask = kem.curve === "P-521" ? 0x01 : 0xff;
    for (var counter = 0; counter <= 255; counter++) {
      var candidate = _labeledExpand(kdf, sid, dkpPrk, "candidate", i2osp(counter, 1), kem.Nsk);
      candidate[0] = candidate[0] & bitmask;
      if (_scalarInRange(candidate, order)) return candidate;
      guard.secret.zeroize(candidate, HpkeError, "hpke/bad-input", "a rejected DeriveKeyPair candidate");
    }
    throw _err("hpke/bad-key",
      "DeriveKeyPair found no scalar in [1, order) in 256 candidates (RFC 9180 sec. 7.1.3)");
  } finally {
    guard.secret.zeroize(dkpPrk, HpkeError, "hpke/bad-input", "the DeriveKeyPair extract PRK");
  }
}

/**
 * @primitive pki.hpke.generateKeyPair
 * @signature pki.hpke.generateKeyPair(kemId) -> { publicKey, privateKey }
 * @since 0.8.45
 * @status stable
 * @spec RFC 9180 sec. 4, draft-ietf-hpke-pq sec. 3
 * @defends kem-key-reuse (CWE-330)
 * @related pki.hpke.deriveKeyPair, pki.hpke.setupR
 *
 * A fresh KEM key pair, as raw byte strings in the encodings the KEM registers. For a hybrid suite the
 * private key is a 32-byte seed the whole pair expands from, and for the others it is the KEM's own
 * private encoding.
 *
 * @example
 *   var kp = pki.hpke.generateKeyPair(pki.hpke.suites.KEM.MLKEM768_P256);
 *   kp.publicKey.length;    // -> 1249
 *   kp.privateKey.length;   // -> 32
 */
function generateKeyPair(kemId) {
  var kem = _kem(kemId);
  /** @internal A hybrid key and an ML-KEM key are both a SEED, so both are drawn here and expanded
   *  through the deterministic derivation rather than read back out of a generated key. Reading it back
   *  is not merely awkward for ML-KEM, it is impossible on some of the Node versions this toolkit runs
   *  on: the PKCS#8 an ML-KEM generation emits is the seed form on one and the EXPANDED key on another,
   *  and a seed cannot be recovered from an expanded key. Drawing it is the same value either way. */
  if (kem.kind === "hybrid" || kem.kind === "mlkem") return deriveKeyPair(kemId, _randomBytes(kem.Nsk));
  var kp = _generate(kem);
  return {
    publicKey: _exportPublic(kem, kp.publicKey),
    privateKey: _exportPrivateRaw(kem, kp.privateKey),
  };
}

/**
 * @primitive pki.hpke.encap
 * @signature pki.hpke.encap(kemId, recipientPublicKey) -> { enc, sharedSecret }
 * @since 0.8.45
 * @status stable
 * @spec RFC 9180 sec. 4, draft-irtf-cfrg-hybrid-kems sec. 5.2
 * @defends kem-shared-secret-confusion (CWE-347)
 * @related pki.hpke.decap, pki.hpke.setupS
 *
 * The KEM half of HPKE on its own: encapsulate to a recipient public key, returning the encapsulated
 * key to send and the shared secret it establishes. `pki.hpke.setupS` runs this and then the key
 * schedule; this verb is for a caller driving its own.
 *
 * For a hybrid KEM the encapsulated key is the PQ ciphertext followed by the traditional group element,
 * and the shared secret is the two component secrets combined with the traditional ciphertext, the
 * traditional public key and the suite label, which is the C2PRI combiner that framework specifies.
 *
 * @example
 *   var kp = pki.hpke.generateKeyPair(pki.hpke.suites.KEM.MLKEM768_X25519);
 *   var e = pki.hpke.encap(pki.hpke.suites.KEM.MLKEM768_X25519, kp.publicKey);
 *   e.enc.length;            // -> 1120
 *   e.sharedSecret.length;   // -> 32
 */
function encap(kemId, recipientPublicKey) {
  var kem = _kem(kemId);
  var r = _recipPublic({ kem: kem }, recipientPublicKey);
  return _encap(kem, r.key, r.pkm, undefined);
}

/**
 * @primitive pki.hpke.decap
 * @signature pki.hpke.decap(kemId, enc, recipientPrivateKey) -> sharedSecret
 * @since 0.8.45
 * @status stable
 * @spec RFC 9180 sec. 4, draft-irtf-cfrg-hybrid-kems sec. 5.2
 * @defends kem-shared-secret-confusion (CWE-347)
 * @related pki.hpke.encap, pki.hpke.setupR
 *
 * The receiving half of the KEM: recover the shared secret from an encapsulated key. A KEM does not
 * report failure by throwing where the specification says it returns a value, so a ciphertext this key
 * did not receive yields a different secret rather than an error, and the AEAD above it is what refuses.
 * A structurally wrong input, such as an encapsulated key of the wrong length, is refused.
 *
 * @example
 *   var id = pki.hpke.suites.KEM.MLKEM768_X25519;
 *   var kp = pki.hpke.generateKeyPair(id);
 *   var e = pki.hpke.encap(id, kp.publicKey);
 *   pki.hpke.decap(id, e.enc, { skm: kp.privateKey }).equals(e.sharedSecret);   // -> true
 */
function decap(kemId, enc, recipientPrivateKey) {
  var kem = _kem(kemId);
  /** @internal The CIPHERTEXT is copied before the key record is read, because reading that record runs
   *  caller code: an `skm` accessor fired while the encapsulation was still the caller's buffer, and one
   *  that copied a DIFFERENT encapsulation over it had this verb return the shared secret for the other
   *  ciphertext. `_decap` snapshots too, which is the right place for the setup path, and by then the
   *  substitution has already happened. The subject is taken first, here, at the door, and bounded at
   *  the KEM's encapsulation width as it is taken so the copy is not the size of whatever arrived. */
  var sealed = _rawKey(enc, _encWidth(kem));
  var r = _recipPrivate({ kem: kem }, recipientPrivateKey);
  return _decap(kem, sealed, r.key, r.pkm);
}

/** @internal The raw scalar of a generated DHKEM key. It comes from the JWK the producer emits, whose
 *  `d` is the fixed-width big-endian value, and NOT from an offset into a DER: the SEC1 head in EC_SEC1
 *  is what this module BUILDS around a scalar, and a built SEC1 carries no public key and fits a
 *  short-form length while the one node exports carries both and needs a long-form one, so the two
 *  differ by a byte wherever the content passes 127 octets. The width is asserted against the KEM's own
 *  Nsk rather than trusted. An ML-KEM or hybrid key never reaches here, its private half being a seed
 *  that generateKeyPair draws. */
function _exportPrivateRaw(kem, privateKey) {
  var raw = _b64u(privateKey.export({ format: "jwk" }).d);
  if (!_isBuffer(raw) || raw.length !== kem.Nsk) {
    throw _err("hpke/bad-key", "the generated " + kem.name + " private key is not the " +
      kem.Nsk + "-byte scalar this verb returns");
  }
  return raw;
}

module.exports = {
  suites: suites,
  setupS: _setupS, setupR: _setupR,
  seal: seal, open: open,
  deriveKeyPair: deriveKeyPair, generateKeyPair: generateKeyPair,
  encap: encap, decap: decap,
  /** @internal The nominal-group constants, so the vectors can assert the seed widths the draft states
   *  where no published vector makes the difference observable. Not on the curated surface. */
  nominalGroups: NOMINAL_GROUPS,
};
