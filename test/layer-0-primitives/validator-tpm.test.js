// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- validator-tpm (@internal): the TPM 2.0 structure conformance a WebAuthn tpm
 * attestation carries -- TPMT_PUBLIC (pubArea) + TPMS_ATTEST (certInfo) strict packed
 * decode, plus the pubArea-key == credential-COSE-key binding (WebAuthn sec. 8.3 + TCG
 * TPM 2.0 Part 2). Oracle: hand-packed big-endian TPM structures, each of which either
 * decodes to the exact expected fields or fails closed with the caller's typed error --
 * an unsupported object type, a wrong magic/type, a non-NULL symmetric/scheme arm, and a
 * mismatched EC/RSA credential key are each driven to their branch.
 */

var tpm = require("../../lib/validator-tpm");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

// Mirror validator-sig: the caller threads a typed error CONSTRUCTOR (validator-tpm does
// `new E(code, msg)`); a factory that returns a TestError satisfies `new E(...)` because a
// constructor returning an object yields that object.
var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message, cause) { return new TestError(code, message, cause); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// --- packed big-endian TPM builders (no ASN.1, no padding) ---
function be(n, w) { var b = Buffer.alloc(w); for (var i = w - 1; i >= 0; i--) { b[i] = n % 256; n = Math.floor(n / 256); } return b; }
function u8(n) { return be(n, 1); }
function u16(n) { return be(n, 2); }
function u32(n) { return be(n, 4); }
function u64z() { return Buffer.alloc(8); }
function t2b(buf) { return Buffer.concat([u16(buf.length), buf]); } // TPM2B_*: UINT16 size || bytes
function cat() { return Buffer.concat(Array.prototype.slice.call(arguments)); }

// TPM algorithm codepoints (TCG TPM 2.0 Part 2 sec. 6.3).
var ALG_RSA = 0x0001, ALG_ECC = 0x0023, ALG_NULL = 0x0010, ALG_SHA256 = 0x000b;
var ALG_AES = 0x0006, ALG_CFB = 0x0043, ALG_RSASSA = 0x0014;
var CURVE_NIST_P256 = 0x0003; // -> COSE crv 1
var GENERATED = 0xff544347, ST_ATTEST_CERTIFY = 0x8017;
var PCODE = "tpm/bad", MCODE = "tpm/key-mismatch";

// A restricted-signing (attestation) key uses NULL symmetric+scheme; these builders let a
// test flip an arm to non-NULL to exercise the defensive read-and-discard path.
function rsaPubArea(opts) {
  opts = opts || {};
  var sym = opts.sym ? cat(u16(ALG_AES), u16(128), u16(ALG_CFB)) : u16(ALG_NULL);
  var scheme = opts.scheme ? cat(u16(ALG_RSASSA), u16(ALG_SHA256)) : u16(ALG_NULL);
  var exp = "exponent" in opts ? opts.exponent : 65537;
  var mod = opts.modulus || Buffer.from("c0ffee", "hex");
  return cat(u16(ALG_RSA), u16(ALG_SHA256), u32(0), t2b(Buffer.alloc(0)),
    sym, scheme, u16(2048), u32(exp), t2b(mod));
}
function eccPubArea(opts) {
  opts = opts || {};
  var x = opts.x || Buffer.from("aabb", "hex"), y = opts.y || Buffer.from("ccdd", "hex");
  return cat(u16(ALG_ECC), u16(ALG_SHA256), u32(0), t2b(Buffer.alloc(0)),
    u16(ALG_NULL), u16(ALG_NULL), u16(CURVE_NIST_P256), u16(ALG_NULL), t2b(x), t2b(y));
}
function certInfo(opts) {
  opts = opts || {};
  var magic = "magic" in opts ? opts.magic : GENERATED;
  var type = "type" in opts ? opts.type : ST_ATTEST_CERTIFY;
  var extra = opts.extraData || Buffer.from("deadbeef", "hex");
  var name = opts.name || Buffer.from("000bcafe", "hex");
  return cat(u32(magic), u16(type), t2b(Buffer.alloc(0)), t2b(extra),
    u64z(), u32(0), u32(0), u8(0), u64z(), t2b(name), t2b(Buffer.alloc(0)));
}

function run() {
  // ---- parsePubArea: RSA parameters union (lines 64-70) ----
  var rp = tpm.parsePubArea(rsaPubArea({ exponent: 3, modulus: Buffer.from("c0ffee", "hex") }), E, PCODE);
  check("parsePubArea RSA: type/exponent/modulus decoded", rp.type === ALG_RSA && rp.exponent === 3 && rp.rsa.toString("hex") === "c0ffee");
  // exponent 0 => the TPM default 65537 (line 69 default arm).
  check("parsePubArea RSA: exponent 0 defaults to 65537", tpm.parsePubArea(rsaPubArea({ exponent: 0 }), E, PCODE).exponent === 65537);
  // Non-NULL symmetric TPMT_SYM_DEF_OBJECT + non-NULL TPMT_RSA_SCHEME: the defensive arms
  // read+discard keyBits/mode and hashAlg, and the structure still ends exactly at `unique`
  // (lines 50, 53).
  var rpDef = tpm.parsePubArea(rsaPubArea({ sym: true, scheme: true }), E, PCODE);
  check("parsePubArea RSA: non-NULL symmetric+scheme arms consumed, unique still decoded", rpDef.type === ALG_RSA && rpDef.exponent === 65537 && rpDef.rsa.toString("hex") === "c0ffee");

  // ---- parsePubArea: ECC parameters union (lines 71-77) ----
  var ep = tpm.parsePubArea(eccPubArea({ x: Buffer.from("aabb", "hex"), y: Buffer.from("ccdd", "hex") }), E, PCODE);
  check("parsePubArea ECC: curveId/x/y decoded", ep.type === ALG_ECC && ep.curveId === CURVE_NIST_P256 && ep.x.toString("hex") === "aabb" && ep.y.toString("hex") === "ccdd");

  // ---- parsePubArea: unsupported TPMT_PUBLIC type (line 78) ----
  // type 0x0008 is neither RSA nor ECC -> fail closed, never a partial/default key.
  var unsupported = cat(u16(0x0008), u16(ALG_SHA256), u32(0), t2b(Buffer.alloc(0)));
  check("parsePubArea: unsupported object type -> caller code", code(function () { tpm.parsePubArea(unsupported, E, PCODE); }) === PCODE);
  // Trailing bytes past `unique` perturb the TPM Name hash -> rejected (line 83).
  check("parsePubArea: trailing bytes after unique -> caller code", code(function () { tpm.parsePubArea(cat(eccPubArea({}), u8(0)), E, PCODE); }) === PCODE);

  // ---- parseCertInfo: magic + type gates (lines 94, 95) ----
  var ci = tpm.parseCertInfo(certInfo({}), E, PCODE);
  check("parseCertInfo: valid TPMS_ATTEST -> extraData + attestedName", ci.extraData.toString("hex") === "deadbeef" && ci.attestedName.toString("hex") === "000bcafe");
  // magic != TPM_GENERATED_VALUE -> reject (a non-TPM-originated blob).
  check("parseCertInfo: wrong magic -> caller code", code(function () { tpm.parseCertInfo(certInfo({ magic: 0x00000000 }), E, PCODE); }) === PCODE);
  // type != TPM_ST_ATTEST_CERTIFY -> reject (a non-certify attestation).
  check("parseCertInfo: wrong type -> caller code", code(function () { tpm.parseCertInfo(certInfo({ type: 0x0000 }), E, PCODE); }) === PCODE);

  // ---- pubKeyEqualsCose: ECC binding (lines 111-115, 41) ----
  // A TPM2B coordinate may carry a leading 0x00 the COSE fixed-length coordinate omits; the
  // unsigned-magnitude compare strips it (line 41) and still matches.
  var epLead = tpm.parsePubArea(eccPubArea({ x: Buffer.from("00aabb", "hex"), y: Buffer.from("00ccdd", "hex") }), E, PCODE);
  check("pubKeyEqualsCose ECC: leading-0x00 TPM2B matches COSE coordinate", code(function () {
    tpm.pubKeyEqualsCose(epLead, { kty: 2, crv: 1, x: Buffer.from("aabb", "hex"), y: Buffer.from("ccdd", "hex") }, E, MCODE, PCODE);
  }) === "NO-THROW");
  // A curve mismatch (COSE crv 2 vs TPM P-256 -> crv 1) fails with the mismatch code (line 112).
  check("pubKeyEqualsCose ECC: curve mismatch -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(ep, { kty: 2, crv: 2, x: Buffer.from("aabb", "hex"), y: Buffer.from("ccdd", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // A coordinate mismatch fails with the mismatch code (line 112).
  check("pubKeyEqualsCose ECC: x mismatch -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(ep, { kty: 2, crv: 1, x: Buffer.from("9999", "hex"), y: Buffer.from("ccdd", "hex") }, E, MCODE, PCODE);
  }) === MCODE);

  // ---- pubKeyEqualsCose: RSA binding (lines 117-125, 46) ----
  // A matching modulus + exponent (65537 -> the 3-byte 0x010001) equals the COSE key.
  check("pubKeyEqualsCose RSA: matching modulus+exponent -> equal", code(function () {
    tpm.pubKeyEqualsCose(rp.type === ALG_RSA ? tpm.parsePubArea(rsaPubArea({ exponent: 65537 }), E, PCODE) : rp,
      { kty: 3, n: Buffer.from("c0ffee", "hex"), e: Buffer.from("010001", "hex") }, E, MCODE, PCODE);
  }) === "NO-THROW");
  // A modulus mismatch (kty stays 3 so the exponent width path at line 121 still runs) -> mismatch (line 122).
  check("pubKeyEqualsCose RSA: modulus mismatch -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(tpm.parsePubArea(rsaPubArea({ exponent: 65537 }), E, PCODE),
      { kty: 3, n: Buffer.from("bad0", "hex"), e: Buffer.from("010001", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // Wrong COSE kty for an RSA pubArea -> mismatch (line 122).
  check("pubKeyEqualsCose RSA: wrong COSE kty -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(tpm.parsePubArea(rsaPubArea({ exponent: 65537 }), E, PCODE),
      { kty: 2, n: Buffer.from("c0ffee", "hex"), e: Buffer.from("010001", "hex") }, E, MCODE, PCODE);
  }) === MCODE);

  // A wrong COSE kty for an ECC pubArea (kty 3) -> mismatch (line 112, the kty arm).
  check("pubKeyEqualsCose ECC: wrong COSE kty -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(ep, { kty: 3, crv: 1, x: Buffer.from("aabb", "hex"), y: Buffer.from("ccdd", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // A y-coordinate mismatch (x matches) -> mismatch (line 112, the y arm).
  check("pubKeyEqualsCose ECC: y mismatch -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(ep, { kty: 2, crv: 1, x: Buffer.from("aabb", "hex"), y: Buffer.from("9999", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // An absent COSE x-coordinate is compared as empty, never accepted-on-missing -> mismatch.
  check("pubKeyEqualsCose ECC: absent COSE x -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(ep, { kty: 2, crv: 1, y: Buffer.from("ccdd", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // x matches but the COSE y-coordinate is absent: the y comparison IS reached (x did not
  // short-circuit) and the absent y defaults to empty -> mismatch (never accept-on-missing).
  check("pubKeyEqualsCose ECC: matching x, absent COSE y -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(ep, { kty: 2, crv: 1, x: Buffer.from("aabb", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // An exponent mismatch (modulus matches, kty stays 3) -> mismatch (line 122, the e arm).
  check("pubKeyEqualsCose RSA: exponent mismatch -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(tpm.parsePubArea(rsaPubArea({ exponent: 65537 }), E, PCODE),
      { kty: 3, n: Buffer.from("c0ffee", "hex"), e: Buffer.from("03", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // An absent COSE exponent is compared as empty -> mismatch (never accept-on-missing).
  check("pubKeyEqualsCose RSA: absent COSE e -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(tpm.parsePubArea(rsaPubArea({ exponent: 65537 }), E, PCODE),
      { kty: 3, n: Buffer.from("c0ffee", "hex") }, E, MCODE, PCODE);
  }) === MCODE);
  // An absent COSE modulus (kty stays 3) defaults to empty at the first comparison -> mismatch.
  check("pubKeyEqualsCose RSA: absent COSE n -> mismatch code", code(function () {
    tpm.pubKeyEqualsCose(tpm.parsePubArea(rsaPubArea({ exponent: 65537 }), E, PCODE),
      { kty: 3, e: Buffer.from("010001", "hex") }, E, MCODE, PCODE);
  }) === MCODE);

  // ---- pubKeyEqualsCose: unsupported pubArea key type (line 127) ----
  // A pub whose type is neither ECC nor RSA reaches the fail-closed default rather than any
  // accept path (defensive: parsePubArea already rejects such types upstream).
  check("pubKeyEqualsCose: unsupported pub type -> structural code", code(function () {
    tpm.pubKeyEqualsCose({ type: 0x0008 }, { kty: 2 }, E, MCODE, PCODE);
  }) === PCODE);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
