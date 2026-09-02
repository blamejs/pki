// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var ByteReader = require("./byte-reader");
var guard = require("./guard-all");

var TPM_GENERATED_VALUE = 0xff544347;
var TPM_ST_ATTEST_CERTIFY = 0x8017;
var TPM_ALG = { RSA: 0x0001, SHA1: 0x0004, SHA256: 0x000b, SHA384: 0x000c, SHA512: 0x000d, NULL: 0x0010, ECC: 0x0023 };
var TPM_ALG_HASH = {}; TPM_ALG_HASH[TPM_ALG.SHA1] = "sha1"; TPM_ALG_HASH[TPM_ALG.SHA256] = "sha256"; TPM_ALG_HASH[TPM_ALG.SHA384] = "sha384"; TPM_ALG_HASH[TPM_ALG.SHA512] = "sha512";
var TPM_CURVE_TO_COSE = {}; TPM_CURVE_TO_COSE[0x0003] = 1; TPM_CURVE_TO_COSE[0x0004] = 2; TPM_CURVE_TO_COSE[0x0005] = 3;

function _ucmp(a, b) {
  function strip(x) { var i = 0; while (i < x.length - 1 && x[i] === 0) i++; return x.subarray(i); }
  return Buffer.compare(strip(a), strip(b)) === 0;
}
function _uintBytes(n) {
  var hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  var b = Buffer.from(hex, "hex"); var i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.subarray(i);
}
function _symDef(r) { if (r.u16() !== TPM_ALG.NULL) { r.u16(); r.u16(); } }
function _scheme(r) { if (r.u16() !== TPM_ALG.NULL) { r.u16(); } }

var TPMA_OBJECT_BITS = Object.assign(Object.create(null), {
  fixedTPM: 1, stClear: 2, fixedParent: 4, sensitiveDataOrigin: 5, userWithAuth: 6,
  adminWithPolicy: 7, firmwareLimited: 8, svnLimited: 9, noDA: 10,
  encryptedDuplication: 11, restricted: 16, decrypt: 17, sign: 18, x509sign: 19,
});
var TPMA_OBJECT_RESERVED = 0xfff0f009;

// @enforced-by behavioral -- a bit-position table lookup has no rename-proof code shape; the RED
function _decodeAttributes(oa) {
  var out = {};
  Object.keys(TPMA_OBJECT_BITS).forEach(function (n) { out[n] = ((oa >>> TPMA_OBJECT_BITS[n]) & 1) === 1; });
  return out;
}

// @enforced-by behavioral -- a packed TPM structure decode has no rename-proof code shape;
function parsePubArea(buf, E, code) {
  var r = new ByteReader(buf, 0, buf.length, E, code);
  var type = r.u16(), nameAlg = r.u16();
  var objectAttributes = r.u32();
  var authPolicy = r.vector(2, 0, null);
  var pub = { type: type, nameAlg: nameAlg, nameAlgBytes: buf.subarray(2, 4),
    objectAttributes: objectAttributes >>> 0, attributes: _decodeAttributes(objectAttributes),
    authPolicy: authPolicy };
  if (type === TPM_ALG.RSA) {
    _symDef(r);
    _scheme(r);
    r.u16();
    var exp = r.u32();
    pub.exponent = exp === 0 ? 65537 : exp;
    pub.rsa = r.vector(2, 0, null);
  } else if (type === TPM_ALG.ECC) {
    _symDef(r);
    _scheme(r);
    pub.curveId = r.u16();
    _scheme(r);
    pub.x = r.vector(2, 0, null);
    pub.y = r.vector(2, 0, null);
  } else {
    throw new E(code, "unsupported TPMT_PUBLIC type 0x" + type.toString(16));
  }
  if (!r.atEnd()) throw new E(code, "pubArea has trailing bytes after the unique field (WebAuthn 8.3)");
  return pub;
}

// @enforced-by behavioral -- a packed TPM structure decode has no rename-proof code shape;
function parseCertInfo(buf, E, code) {
  var r = new ByteReader(buf, 0, buf.length, E, code);
  var magic = r.u32(), type = r.u16();
  if (magic !== TPM_GENERATED_VALUE) throw new E(code, "certInfo magic is not TPM_GENERATED_VALUE (WebAuthn 8.3)");
  if (type !== TPM_ST_ATTEST_CERTIFY) throw new E(code, "certInfo type is not TPM_ST_ATTEST_CERTIFY (WebAuthn 8.3)");
  r.vector(2, 0, null);
  var extraData = r.vector(2, 0, null);
  r.u64(); r.u32(); r.u32(); r.u8();
  r.u64();
  var name = r.vector(2, 0, null);
  r.vector(2, 0, null);
  if (!r.atEnd()) throw new E(code, "certInfo has trailing bytes after the attested structure (WebAuthn 8.3)");
  return { extraData: extraData, attestedName: name };
}

// @enforced-by behavioral -- a decoded-key equality check has no rename-proof code shape; the
function pubKeyEqualsCose(pub, cose, E, mismatchCode, code) {
  if (pub.type === TPM_ALG.ECC) {
    if (cose.kty !== 2 || TPM_CURVE_TO_COSE[pub.curveId] !== cose.crv || !_ucmp(pub.x, cose.x || Buffer.alloc(0)) || !_ucmp(pub.y, cose.y || Buffer.alloc(0))) {
      throw new E(mismatchCode, "the TPM pubArea EC key does not equal the credential public key");
    }
    return;
  }
  if (pub.type === TPM_ALG.RSA) {
    var e = _uintBytes(pub.exponent >>> 0);
    if (cose.kty !== 3 || !_ucmp(pub.rsa, cose.n || Buffer.alloc(0)) || !_ucmp(e, cose.e || Buffer.alloc(0))) {
      throw new E(mismatchCode, "the TPM pubArea RSA key does not equal the credential public key");
    }
    return;
  }
  throw new E(code, "unsupported TPM pubArea key type");
}

var TPM_POLICY_PROFILES = Object.assign(Object.create(null), {
  "hardware-bound": { fixedTPM: true, fixedParent: true, sensitiveDataOrigin: true, sign: true, restricted: false, x509sign: false },
});
var _TPM_POLICY_KEYS = Object.assign(Object.create(null), { profile: 1, objectAttributes: 1, reservedBitsClear: 1, consistency: 1, authPolicy: 1 });
var _AUTH_POLICY_KEYS = Object.assign(Object.create(null), { present: 1, allow: 1 });

// @enforced-by behavioral -- an opts-shape validator has no rename-proof code shape; the RED
function normalizeObjectAttributePolicy(policy, E, code) {
  if (policy === undefined) return null;
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) throw new E(code, "opts.tpmPolicy must be an object");
  guard.identifier.assertKnownKeys(policy, _TPM_POLICY_KEYS, function (c, m) { return new E(c, m); }, code, "opts.tpmPolicy has an unknown key ");
  var want = {};
  if (policy.profile !== undefined) {
    var preset = TPM_POLICY_PROFILES[policy.profile];
    if (!preset) throw new E(code, "opts.tpmPolicy.profile " + guard.text.showValue(policy.profile) + " is not a defined profile");
    Object.keys(preset).forEach(function (n) { want[n] = preset[n]; });
  }
  var explicit = policy.objectAttributes;
  if (explicit !== undefined) {
    if (!explicit || typeof explicit !== "object" || Array.isArray(explicit)) throw new E(code, "opts.tpmPolicy.objectAttributes must be an object");
    Object.keys(explicit).forEach(function (n) {
      if (TPMA_OBJECT_BITS[n] === undefined) throw new E(code, "opts.tpmPolicy.objectAttributes has an unknown attribute " + JSON.stringify(n));
      if (typeof explicit[n] !== "boolean") throw new E(code, "opts.tpmPolicy.objectAttributes." + n + " must be a boolean");
      want[n] = explicit[n];
    });
  }
  if (want.sensitiveDataOrigin === true && want.fixedTPM !== true) {
    throw new E(code, "opts.tpmPolicy requires sensitiveDataOrigin without fixedTPM; on its own it does not establish that the TPM generated the key (TPM 2.0 Part 2 sec. 8.3.3.5)");
  }
  ["reservedBitsClear", "consistency"].forEach(function (k) {
    if (policy[k] !== undefined && typeof policy[k] !== "boolean") throw new E(code, "opts.tpmPolicy." + k + " must be a boolean");
  });
  var ap = policy.authPolicy;
  var allow = null;
  if (ap !== undefined) {
    if (!ap || typeof ap !== "object" || Array.isArray(ap)) throw new E(code, "opts.tpmPolicy.authPolicy must be an object");
    guard.identifier.assertKnownKeys(ap, _AUTH_POLICY_KEYS, function (c, m) { return new E(c, m); }, code, "opts.tpmPolicy.authPolicy has an unknown key ");
    if (ap.present !== undefined && typeof ap.present !== "boolean") throw new E(code, "opts.tpmPolicy.authPolicy.present must be a boolean");
    if (ap.allow !== undefined) {
      if (!Array.isArray(ap.allow)) throw new E(code, "opts.tpmPolicy.authPolicy.allow must be an array");
      allow = ap.allow.map(function (entry, i) {
        if (guard.bytes.isByteSource(entry)) return guard.bytes.snapshotSource(entry, E, code, "opts.tpmPolicy.authPolicy.allow[" + i + "]");
        var label = "opts.tpmPolicy.authPolicy.allow[" + i + "]";
        if (typeof entry !== "string" || entry.length === 0) {
          throw new E(code, label + " must be a BufferSource or an even-length hex string");
        }
        return guard.encoding.hex(entry, null, function (c, m) { return new E(c, m); }, code,
          label + " must be a Buffer or an even-length hex string --");
      });
    }
  }
  return { objectAttributes: want, reservedBitsClear: policy.reservedBitsClear === true,
    consistency: policy.consistency === true,
    authPolicy: ap ? { present: ap.present === true, allow: allow } : null };
}

// @enforced-by behavioral -- an opt-gated policy gate has no rename-proof code shape, and there is
function assertObjectAttributePolicy(pub, policy, E, policyCode, structuralCode) {
  if (!policy) return;
  var oa = pub.objectAttributes >>> 0;
  if (policy.reservedBitsClear && ((oa & TPMA_OBJECT_RESERVED) >>> 0) !== 0) {
    throw new E(structuralCode, "the TPMT_PUBLIC objectAttributes sets a reserved bit (TPM 2.0 Part 2 sec. 8.3.2 Table 33: shall be zero)");
  }
  if (policy.consistency) {
    if (pub.attributes.encryptedDuplication && pub.attributes.fixedTPM) {
      throw new E(structuralCode, "the TPMT_PUBLIC objectAttributes sets encryptedDuplication on an object with fixedTPM SET (TPM 2.0 Part 2 sec. 8.3.3.11)");
    }
    if (pub.attributes.sign && pub.attributes.decrypt && pub.attributes.restricted) {
      throw new E(structuralCode, "the TPMT_PUBLIC objectAttributes sets restricted with both sign and decrypt (TPM 2.0 Part 2 sec. 8.3.3)");
    }
    if (pub.authPolicy.length > 64) {
      throw new E(structuralCode, "the TPMT_PUBLIC authPolicy is " + pub.authPolicy.length + " octets, above the 64-octet TPM2B_DIGEST maximum");
    }
  }
  Object.keys(policy.objectAttributes).forEach(function (name) {
    var want = policy.objectAttributes[name];
    if (pub.attributes[name] !== want) {
      throw new E(policyCode, "the TPM credential key has " + name + " " + (pub.attributes[name] ? "SET" : "CLEAR") +
        "; opts.tpmPolicy requires it " + (want ? "SET" : "CLEAR"));
    }
  });
  var ap = policy.authPolicy;
  if (!ap) return;
  if (ap.present === true && pub.authPolicy.length === 0) {
    throw new E(policyCode, "the TPM credential key carries the Empty Policy; opts.tpmPolicy.authPolicy.present requires a policy digest");
  }
  if (ap.allow) {
    var got = pub.authPolicy;
    var ok = ap.allow.some(function (want) {
      return want.length === got.length && guard.crypto.constantTimeEqual(want, got);
    });
    if (!ok) throw new E(policyCode, "the TPM credential key authPolicy is not in opts.tpmPolicy.authPolicy.allow");
  }
}

module.exports = {
  parsePubArea: parsePubArea,
  TPMA_OBJECT_BITS: TPMA_OBJECT_BITS,
  decodeObjectAttributes: _decodeAttributes,
  normalizeObjectAttributePolicy: normalizeObjectAttributePolicy,
  assertObjectAttributePolicy: assertObjectAttributePolicy,
  parseCertInfo: parseCertInfo,
  pubKeyEqualsCose: pubKeyEqualsCose,
  TPM_ALG_HASH: TPM_ALG_HASH,
};
