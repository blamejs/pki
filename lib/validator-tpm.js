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

// parsePubArea(buf, E, code) -> the decoded TPMT_PUBLIC (WebAuthn 8.3 item 17-20).
// @enforced-by behavioral -- a packed TPM structure decode has no rename-proof code shape;
// the RED vectors (trailing bytes, an unsupported type, a truncated TPM2B) are the guard.
function parsePubArea(buf, E, code) {
  var r = new ByteReader(buf, 0, buf.length, E, code);
  var type = r.u16(), nameAlg = r.u16();
  r.u32();                       // objectAttributes (full policy validation deferred)
  r.vector(2, 0, null);          // authPolicy TPM2B_DIGEST
  var pub = { type: type, nameAlg: nameAlg, nameAlgBytes: buf.subarray(2, 4) };
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

module.exports = {
  parsePubArea: parsePubArea,
  parseCertInfo: parseCertInfo,
  pubKeyEqualsCose: pubKeyEqualsCose,
  TPM_ALG_HASH: TPM_ALG_HASH,
};
