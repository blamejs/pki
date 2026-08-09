// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the verifier whose
// tpm handling composes this validator (pki.webauthn).
//
// validator-tpm -- the SINGLE home for the TPM 2.0 structure conformance a WebAuthn tpm
// attestation carries: the TPMT_PUBLIC (pubArea) and TPMS_ATTEST (certInfo) decode, plus the
// pubArea-key == credential-key binding (WebAuthn sec. 8.3 + TCG TPM 2.0 Part 2). Sibling to
// the guard family: a validator owns a decoded TYPE's COMPLETE conformance rule set once, so
// the strict TPM2B sizing / algorithm-union walking / trailing-byte rejection cannot drift.
//
// Every field is unsigned big-endian, packed with no padding; every TPM2B_* is a UINT16 size
// followed by exactly `size` bytes. The bare certInfo and pubArea carry NO outer TPM2B size
// prefix. The caller supplies its typed error CONSTRUCTOR E + a structural `code` (a
// malformed structure is bad input) and, for the key binding, a `mismatchCode`.
//
// Rule set (gap-checked verbatim against WebAuthn sec. 8.3 + TCG TPM 2.0 Part 2 sec. 10.12 /
// 12.2):
//   - parsePubArea: decode type/nameAlg, walk parameters per the algorithm union, read the
//     public key in `unique`; reject trailing bytes (they perturb the TPM Name hash).
//   - parseCertInfo: magic == TPM_GENERATED_VALUE, type == TPM_ST_ATTEST_CERTIFY; read
//     extraData + attested.name; reject trailing bytes past the attested structure.
//   - pubKeyEqualsCose: the pubArea key (EC curve+x+y, or RSA modulus+exponent) equals the
//     credential COSE key, compared as unsigned magnitudes (a TPM2B may differ from a COSE
//     coordinate by a leading 0x00), the RSA exponent over its full UINT32 width.

var ByteReader = require("./byte-reader");
var guard = require("./guard-all");

var TPM_GENERATED_VALUE = 0xff544347;
var TPM_ST_ATTEST_CERTIFY = 0x8017;
var TPM_ALG = { RSA: 0x0001, SHA1: 0x0004, SHA256: 0x000b, SHA384: 0x000c, SHA512: 0x000d, NULL: 0x0010, ECC: 0x0023 };
var TPM_ALG_HASH = {}; TPM_ALG_HASH[TPM_ALG.SHA1] = "sha1"; TPM_ALG_HASH[TPM_ALG.SHA256] = "sha256"; TPM_ALG_HASH[TPM_ALG.SHA384] = "sha384"; TPM_ALG_HASH[TPM_ALG.SHA512] = "sha512";
// TPM_ECC_CURVE -> COSE crv (the codepoints differ; this is a mapping, not equality).
var TPM_CURVE_TO_COSE = {}; TPM_CURVE_TO_COSE[0x0003] = 1; TPM_CURVE_TO_COSE[0x0004] = 2; TPM_CURVE_TO_COSE[0x0005] = 3;

// Unsigned big-endian magnitude compare: strip leading zero octets, then byte-equal. TPM2B
// buffers and COSE fixed-length coordinates can differ by a leading 0x00.
function _ucmp(a, b) {
  function strip(x) { var i = 0; while (i < x.length - 1 && x[i] === 0) i++; return x.subarray(i); }
  return Buffer.compare(strip(a), strip(b)) === 0;
}
function _uintBytes(n) {
  var hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  var b = Buffer.from(hex, "hex"); var i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.subarray(i);
}
// TPMT_SYM_DEF_OBJECT: algorithm UINT16; when not NULL, keyBits+mode follow. An attestation
// (restricted signing) key is NULL, so the non-NULL arm is defensive.
function _symDef(r) { if (r.u16() !== TPM_ALG.NULL) { r.u16(); r.u16(); } }
// TPMT_*_SCHEME / TPMT_KDF_SCHEME: scheme UINT16; when not NULL, a TPMS_SCHEME_HASH (a single
// UINT16 hashAlg) follows for the signing/kdf schemes in scope.
function _scheme(r) { if (r.u16() !== TPM_ALG.NULL) { r.u16(); } }

// TPMA_OBJECT bit positions (TPM 2.0 Part 2 sec. 8.3.2, Table 33). A data row set, not a switch:
// a bit index absent here is reserved by definition, and the reserved mask below is its complement
// over the positions Table 33 marks "shall be zero" (bits 0, 3, 15:12 and 31:20).
// Null-prototype: every one of these tables is indexed by a CALLER-SUPPLIED name, and an inherited
// member ("constructor", "toString", "__proto__") would resolve to a truthy non-value. In a lookup
// that decides whether a name is known, that reads as "known" and the caller's policy silently
// applies nothing at all -- a fail-open. Applied to all three tables here, not only the one where
// it was noticed.
var TPMA_OBJECT_BITS = Object.assign(Object.create(null), {
  fixedTPM: 1, stClear: 2, fixedParent: 4, sensitiveDataOrigin: 5, userWithAuth: 6,
  adminWithPolicy: 7, firmwareLimited: 8, svnLimited: 9, noDA: 10,
  encryptedDuplication: 11, restricted: 16, decrypt: 17, sign: 18, x509sign: 19,
});
var TPMA_OBJECT_RESERVED = 0xfff0f009;

// _decodeAttributes(oa) -> the named booleans of a TPMA_OBJECT word.
// @enforced-by behavioral -- a bit-position table lookup has no rename-proof code shape; the RED
// vectors (each named bit read off a real attestation, and the sign-bit case) are the guard.
function _decodeAttributes(oa) {
  var out = {};
  Object.keys(TPMA_OBJECT_BITS).forEach(function (n) { out[n] = ((oa >>> TPMA_OBJECT_BITS[n]) & 1) === 1; });
  return out;
}

// parsePubArea(buf, E, code) -> the decoded TPMT_PUBLIC (WebAuthn 8.3 item 17-20).
// @enforced-by behavioral -- a packed TPM structure decode has no rename-proof code shape;
// the RED vectors (trailing bytes, an unsupported type, a truncated TPM2B) are the guard.
function parsePubArea(buf, E, code) {
  var r = new ByteReader(buf, 0, buf.length, E, code);
  var type = r.u16(), nameAlg = r.u16();
  // objectAttributes (TPM 2.0 Part 2 sec. 8.3.2 Table 33) and authPolicy (Table 87) are SURFACED,
  // not gated: WebAuthn sec. 8.3 constrains only the `parameters` and `unique` fields of pubArea,
  // so enforcing these would invent a conformance rule. A relying party that wants them applies its
  // own policy, which it cannot do to a field it never sees. The bytes are trustworthy by the time
  // a caller reads them -- pubArea is hashed into certInfo.attested.name, which the AIK signature
  // covers, and both are verified before the result is built.
  var objectAttributes = r.u32();
  var authPolicy = r.vector(2, 0, null);   // a zero-length digest IS the Empty Policy, not "absent"
  var pub = { type: type, nameAlg: nameAlg, nameAlgBytes: buf.subarray(2, 4),
    objectAttributes: objectAttributes >>> 0, attributes: _decodeAttributes(objectAttributes),
    authPolicy: authPolicy };
  if (type === TPM_ALG.RSA) {
    _symDef(r);                  // symmetric TPMT_SYM_DEF_OBJECT
    _scheme(r);                  // scheme TPMT_RSA_SCHEME
    r.u16();                     // keyBits
    var exp = r.u32();           // exponent (0 => default 65537)
    pub.exponent = exp === 0 ? 65537 : exp;
    pub.rsa = r.vector(2, 0, null);   // unique TPM2B_PUBLIC_KEY_RSA (the modulus)
  } else if (type === TPM_ALG.ECC) {
    _symDef(r);                  // symmetric
    _scheme(r);                  // scheme TPMT_ECC_SCHEME
    pub.curveId = r.u16();       // curveID TPMI_ECC_CURVE
    _scheme(r);                  // kdf TPMT_KDF_SCHEME
    pub.x = r.vector(2, 0, null);     // unique.ecc.x TPM2B_ECC_PARAMETER
    pub.y = r.vector(2, 0, null);     // unique.ecc.y TPM2B_ECC_PARAMETER
  } else {
    throw new E(code, "unsupported TPMT_PUBLIC type 0x" + type.toString(16));
  }
  // TPMT_PUBLIC ends with `unique`; trailing bytes mean a malformed pubArea (and would
  // perturb the TPM Name hash), so fail closed rather than silently ignore them.
  if (!r.atEnd()) throw new E(code, "pubArea has trailing bytes after the unique field (WebAuthn 8.3)");
  return pub;
}

// parseCertInfo(buf, E, code) -> the decoded + magic/type-validated TPMS_ATTEST
// { extraData, attestedName } (WebAuthn 8.3 item 13-15).
// @enforced-by behavioral -- a packed TPM structure decode has no rename-proof code shape;
// the RED vectors (wrong magic, wrong type, trailing bytes) are the guard.
function parseCertInfo(buf, E, code) {
  var r = new ByteReader(buf, 0, buf.length, E, code);
  var magic = r.u32(), type = r.u16();
  if (magic !== TPM_GENERATED_VALUE) throw new E(code, "certInfo magic is not TPM_GENERATED_VALUE (WebAuthn 8.3)");
  if (type !== TPM_ST_ATTEST_CERTIFY) throw new E(code, "certInfo type is not TPM_ST_ATTEST_CERTIFY (WebAuthn 8.3)");
  r.vector(2, 0, null);          // qualifiedSigner TPM2B_NAME
  var extraData = r.vector(2, 0, null);   // extraData TPM2B_DATA
  r.u64(); r.u32(); r.u32(); r.u8();      // clockInfo TPMS_CLOCK_INFO (17 bytes)
  r.u64();                       // firmwareVersion
  var name = r.vector(2, 0, null);        // attested.name TPM2B_NAME (nameAlg||H)
  r.vector(2, 0, null);          // attested.qualifiedName TPM2B_NAME
  if (!r.atEnd()) throw new E(code, "certInfo has trailing bytes after the attested structure (WebAuthn 8.3)");
  return { extraData: extraData, attestedName: name };
}

// pubKeyEqualsCose(pub, cose, E, mismatchCode, code) -- the pubArea public key MUST equal the
// credential COSE key (WebAuthn 8.3 item 22).
// @enforced-by behavioral -- a decoded-key equality check has no rename-proof code shape; the
// RED vectors (a mismatched EC curve/coordinate, a mismatched RSA modulus/exponent) are the guard.
function pubKeyEqualsCose(pub, cose, E, mismatchCode, code) {
  if (pub.type === TPM_ALG.ECC) {
    if (cose.kty !== 2 || TPM_CURVE_TO_COSE[pub.curveId] !== cose.crv || !_ucmp(pub.x, cose.x || Buffer.alloc(0)) || !_ucmp(pub.y, cose.y || Buffer.alloc(0))) {
      throw new E(mismatchCode, "the TPM pubArea EC key does not equal the credential public key");
    }
    return;
  }
  if (pub.type === TPM_ALG.RSA) {
    // Compare the exponent as an unsigned integer over its FULL width (a UINT32 up to
    // 0xFFFFFFFF); a fixed 3-byte re-encode would silently truncate an exponent > 0xFFFFFF
    // and let a mismatched key pass (WebAuthn 8.3 item 22).
    var e = _uintBytes(pub.exponent >>> 0);
    if (cose.kty !== 3 || !_ucmp(pub.rsa, cose.n || Buffer.alloc(0)) || !_ucmp(e, cose.e || Buffer.alloc(0))) {
      throw new E(mismatchCode, "the TPM pubArea RSA key does not equal the credential public key");
    }
    return;
  }
  throw new E(code, "unsupported TPM pubArea key type");
}

// The one defined preset: the six TPMA_OBJECT bits every genuine attestation observed sets the same
// way. `decrypt`, `noDA` and `userWithAuth` are deliberately absent -- they DIFFER across real
// Windows Hello statements, so requiring any of them rejects working hardware. A second preset
// would be policy invention; a caller who wants different bits spells them out.
var TPM_POLICY_PROFILES = Object.assign(Object.create(null), {
  "hardware-bound": { fixedTPM: true, fixedParent: true, sensitiveDataOrigin: true, sign: true, restricted: false, x509sign: false },
});
var _TPM_POLICY_KEYS = Object.assign(Object.create(null), { profile: 1, objectAttributes: 1, reservedBitsClear: 1, consistency: 1, authPolicy: 1 });

// Config-time validation of opts.tpmPolicy: a typo must never silently disable a check, so an
// unknown key or attribute name throws at the boundary rather than being ignored.
// @enforced-by behavioral -- an opts-shape validator has no rename-proof code shape; the RED
// vectors (unknown key, unknown profile, unknown attribute, non-boolean value, and the
// sensitiveDataOrigin-without-fixedTPM rule) are the guard.
function normalizeObjectAttributePolicy(policy, E, code) {
  if (policy === undefined) return null;
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) throw new E(code, "opts.tpmPolicy must be an object");
  Object.keys(policy).forEach(function (k) {
    if (!_TPM_POLICY_KEYS[k]) throw new E(code, "opts.tpmPolicy has an unknown key " + JSON.stringify(k));
  });
  var want = {};
  if (policy.profile !== undefined) {
    var preset = TPM_POLICY_PROFILES[policy.profile];
    if (!preset) throw new E(code, "opts.tpmPolicy.profile " + JSON.stringify(policy.profile) + " is not a defined profile");
    Object.keys(preset).forEach(function (n) { want[n] = preset[n]; });
  }
  // An explicit map layers OVER the preset, so a caller can keep the profile and override one bit.
  var explicit = policy.objectAttributes;
  if (explicit !== undefined) {
    if (!explicit || typeof explicit !== "object" || Array.isArray(explicit)) throw new E(code, "opts.tpmPolicy.objectAttributes must be an object");
    Object.keys(explicit).forEach(function (n) {
      if (TPMA_OBJECT_BITS[n] === undefined) throw new E(code, "opts.tpmPolicy.objectAttributes has an unknown attribute " + JSON.stringify(n));
      if (typeof explicit[n] !== "boolean") throw new E(code, "opts.tpmPolicy.objectAttributes." + n + " must be a boolean");
      want[n] = explicit[n];
    });
  }
  // sec. 8.3.3.5 NOTE 1: sensitiveDataOrigin only asserts the TPM generated the key when fixedTPM
  // is also SET -- otherwise the object could have been imported. Demanding it alone asserts
  // nothing, so say so at config time rather than letting a caller believe it is protected.
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
    // The nested keys are enumerated for the same reason the top-level ones are: a misspelled
    // `alow` would leave the allow-list unset, and the assertion would then impose no digest
    // restriction at all -- the caller's policy silently doing nothing.
    Object.keys(ap).forEach(function (k) {
      if (k !== "present" && k !== "allow") throw new E(code, "opts.tpmPolicy.authPolicy has an unknown key " + JSON.stringify(k));
    });
    if (ap.present !== undefined && typeof ap.present !== "boolean") throw new E(code, "opts.tpmPolicy.authPolicy.present must be a boolean");
    if (ap.allow !== undefined) {
      if (!Array.isArray(ap.allow)) throw new E(code, "opts.tpmPolicy.authPolicy.allow must be an array");
      // Decode every entry HERE, at config time, rather than inside the comparison. Node's hex
      // decoder is permissive: it stops at the first character that is not a hex digit, so
      // "<digest>zz" decodes back to the digest and a non-string decodes to an empty buffer --
      // either of which could match a key this policy was written to exclude, including the
      // Empty Policy. An entry that is not a Buffer or a canonical even-length hex string is a
      // caller error, and it fails here rather than becoming a digest nobody intended.
      allow = ap.allow.map(function (entry, i) {
        if (Buffer.isBuffer(entry)) return entry;
        if (typeof entry !== "string" || entry.length === 0 || entry.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(entry)) {
          throw new E(code, "opts.tpmPolicy.authPolicy.allow[" + i + "] must be a Buffer or an even-length hex string");
        }
        return Buffer.from(entry, "hex");
      });
    }
  }
  return { objectAttributes: want, reservedBitsClear: policy.reservedBitsClear === true,
    consistency: policy.consistency === true,
    authPolicy: ap ? { present: ap.present === true, allow: allow } : null };
}

// Apply a normalized policy to a parsed pubArea. Nothing here is a WebAuthn sec. 8.3 requirement --
// that section constrains only pubArea's `parameters` and `unique` fields -- so every rule runs
// only because a caller asked for it by name.
// @enforced-by behavioral -- an opt-gated policy gate has no rename-proof code shape, and there is
// no general vector shape to detect: the RED vectors (each required bit in both directions, the
// reserved-bit mask across the sign bit, the restricted sign+decrypt combination, the over-long
// digest, the Empty Policy, and the allow-list miss) are the guard.
function assertObjectAttributePolicy(pub, policy, E, policyCode, structuralCode) {
  if (!policy) return;
  var oa = pub.objectAttributes >>> 0;
  // Bit 31 lies inside the reserved mask, so the AND must be coerced back to unsigned: a bare
  // `oa & 0xfff0f009` is a signed int32 and would read negative rather than "a bit is set".
  if (policy.reservedBitsClear && ((oa & TPMA_OBJECT_RESERVED) >>> 0) !== 0) {
    throw new E(structuralCode, "the TPMT_PUBLIC objectAttributes sets a reserved bit (TPM 2.0 Part 2 sec. 8.3.2 Table 33: shall be zero)");
  }
  if (policy.consistency) {
    // sec. 8.3.3.11, verbatim: "This attribute shall not be SET in any object that has fixedTPM
    // SET." A key that cannot leave its TPM cannot be duplicated, so requiring its duplication be
    // encrypted describes an object that cannot exist.
    if (pub.attributes.encryptedDuplication && pub.attributes.fixedTPM) {
      throw new E(structuralCode, "the TPMT_PUBLIC objectAttributes sets encryptedDuplication on an object with fixedTPM SET (TPM 2.0 Part 2 sec. 8.3.3.11)");
    }
    // sec. 8.3.3.16/.17: a restricted key is a TPM-internal key, and the two use bits are a choice
    // -- a restricted object that both signs and decrypts is not a defined combination.
    if (pub.attributes.sign && pub.attributes.decrypt && pub.attributes.restricted) {
      throw new E(structuralCode, "the TPMT_PUBLIC objectAttributes sets restricted with both sign and decrypt (TPM 2.0 Part 2 sec. 8.3.3)");
    }
    // A TPM2B_DIGEST carries at most a SHA-512 digest.
    if (pub.authPolicy.length > 64) {
      throw new E(structuralCode, "the TPMT_PUBLIC authPolicy is " + pub.authPolicy.length + " octets, above the 64-octet TPM2B_DIGEST maximum");
    }
    // The REMAINING sec. 8.3.3 "shall" statements are all parent-relative -- fixedTPM, stClear and
    // encryptedDuplication are each constrained against the value the object's PARENT carries. An
    // attestation presents one public area and no parent, so a verifier cannot evaluate them at
    // all; they are not omitted by oversight, they are unverifiable from what is on the wire.
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
    // Every entry was decoded and validated at config time, so this compares digests only.
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
