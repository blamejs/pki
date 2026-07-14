// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the verifiers
// whose ECDSA signature handling composes this validator (pki.webauthn).
//
// validator-sig -- the SINGLE home for "is this a conformant DER ECDSA-Sig-Value", and
// its conversion to the raw r||s (IEEE P1363) form a WebCrypto verify expects. Sibling to
// the guard family: a validator owns a decoded TYPE's COMPLETE conformance rule set once,
// so a format module composes it rather than hand-decoding a 2-INTEGER SEQUENCE into r/s
// and forgetting a strict-DER check (the drift a validator exists to prevent).
//
// Interface mirrors the guard family: (subject, ..., E, code) where E is the caller's
// typed error CONSTRUCTOR and code its domain code.
//
// Rule set (gap-checked verbatim against RFC 3279 sec. 2.2.3 + X.690 sec. 8.3 + SEC1):
//   - ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } -- a universal SEQUENCE with
//     EXACTLY two children.
//   - r and s are each a PRIMITIVE, MINIMALLY-ENCODED (X.690 sec. 8.3.2 -- no redundant
//     leading 0x00/0xFF), POSITIVE integer. Reading through the strict DER integer reader
//     enforces the primitive + minimal-encoding rules; the value is then range-checked
//     positive (r,s >= 1) and bounded by the curve field size. A non-minimal, zero,
//     negative, or over-size coordinate fails closed -- never normalized-and-accepted.

var asn1 = require("./asn1-der");

// ecdsaSigToRaw(der, coordLen, E, code) -> the validated signature as raw r||s, each
// coordinate left-padded to coordLen bytes, or throws new E(code, ...). The complete DER
// ECDSA-Sig-Value conformance gate; a verifier MUST route an ECDSA signature through here,
// never hand-decode the SEQUENCE and read r/s content raw (which skips minimality).
// @enforced-by behavioral -- a DER ECDSA-Sig-Value decode has no rename-proof code shape
// distinct from generic 2-child-SEQUENCE content access; the RED conformance vectors
// (non-minimal / negative / zero / over-size r or s rejected) and the webauthn ECDSA KATs
// are the guard.
function ecdsaSigToRaw(der, coordLen, E, code) {
  var node;
  try { node = asn1.decode(der); } catch (e) { throw new E(code, "ECDSA signature is not a DER SEQUENCE", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length !== 2) {
    throw new E(code, "ECDSA signature must be a DER SEQUENCE { r, s }");
  }
  function coord(c, label) {
    // The strict DER integer reader enforces PRIMITIVE + MINIMAL encoding (a constructed
    // child, an empty INTEGER, or a redundant 0x00/0xFF sign octet all throw). The value
    // is then range-checked: r and s MUST be positive (>= 1) and fit the curve field size.
    var v;
    try { v = asn1.read.integer(c); } catch (e) { throw new E(code, "ECDSA signature " + label + " is not a minimally-encoded DER INTEGER", e); }
    if (v <= 0n) throw new E(code, "ECDSA signature " + label + " must be a positive integer");
    var hex = v.toString(16); if (hex.length % 2) hex = "0" + hex;
    var b = Buffer.from(hex, "hex");
    if (b.length > coordLen) throw new E(code, "ECDSA signature " + label + " exceeds the curve field size");
    var out = Buffer.alloc(coordLen); b.copy(out, coordLen - b.length); return out;
  }
  return Buffer.concat([coord(node.children[0], "r"), coord(node.children[1], "s")]);
}

// rawToEcdsaDer(raw, coordLen) -> the canonical DER ECDSA-Sig-Value SEQUENCE { r, s } for a raw
// r||s signature (IEEE P1363, the WebCrypto sign() output). The inverse of ecdsaSigToRaw: a
// signer composes this so the emitted ECDSA signature is canonical DER (minimally-encoded
// INTEGERs via the build layer), never a hand-built SEQUENCE that could re-introduce a
// non-minimal encoding. A config-time TypeError guards a mis-sized raw signature at entry.
// @enforced-by behavioral -- a DER ECDSA-Sig-Value BUILD has no rename-proof code shape distinct
// from generic sequence([integer,integer]); the round-trip vectors (build -> ecdsaSigToRaw
// identity) and the cms.sign ECDSA KATs are the guard.
function rawToEcdsaDer(raw, coordLen) {
  if (!Buffer.isBuffer(raw) || typeof coordLen !== "number" || coordLen <= 0 || raw.length !== coordLen * 2) {
    throw new TypeError("rawToEcdsaDer: raw signature must be a Buffer of exactly 2*coordLen bytes");
  }
  var r = BigInt("0x" + raw.subarray(0, coordLen).toString("hex"));
  var s = BigInt("0x" + raw.subarray(coordLen).toString("hex"));
  return asn1.build.sequence([asn1.build.integer(r), asn1.build.integer(s)]);
}

// The curve group orders n -- a valid ECDSA signature has r, s in [1, n-1].
var CURVE_FIELD_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 };
var CURVE_ORDER = {
  "P-256": BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  "P-384": BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
  "P-521": BigInt("0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
};

// ecdsaDerToP1363(der, curve, E, code) -> the DER ECDSA-Sig-Value converted to raw r||s (P1363),
// each coordinate left-padded to the curve field width, rejecting r or s outside [1, n-1] against
// the curve ORDER (CVE-2022-21449 "Psychic Signatures" -- the r/s = 0 case AND the >= n upper
// bound). `curve` is a WebCrypto namedCurve (P-256/384/521). This is the ORDER-AWARE gate a
// verifier that knows the curve order MUST use; it is STRICTER than ecdsaSigToRaw above, which
// bounds r/s only by the field SIZE (>= 1, <= coordLen bytes) and does not know the order. A
// signature whose r or s is >= n is rejected here but passes ecdsaSigToRaw -- do not conflate them.
// @enforced-by behavioral -- the RED conformance vectors (r/s = 0, r/s >= n, non-minimal, over-size)
// and the composite-signature + path-validation KATs are the guard.
function ecdsaDerToP1363(der, curve, E, code) {
  var width = CURVE_FIELD_BYTES[curve];
  var order = CURVE_ORDER[curve];
  if (!width || !order) throw new E(code, "unsupported ECDSA curve " + curve);
  var n;
  try { n = asn1.decode(der); }
  catch (e) { throw new E(code, "ECDSA signature is not a DER SEQUENCE(r,s)", e); }
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children || n.children.length !== 2) {
    throw new E(code, "ECDSA signature must be a SEQUENCE of exactly two INTEGERs");
  }
  var r = asn1.read.integer(n.children[0]);
  var s = asn1.read.integer(n.children[1]);
  if (r < 1n || s < 1n || r >= order || s >= order) {
    throw new E(code, "ECDSA signature component out of range [1, n-1] (CVE-2022-21449)");
  }
  function pad(v) {
    var hex = v.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    var buf = Buffer.from(hex, "hex");
    // Coverage residual -- unreachable: a component needing more than `width` bytes is >=
    // 2^(8*width) > n (the curve order n < 2^(8*width) for P-256/384/521), so it is already
    // rejected by the r/s >= order check above; this width guard is a defense-in-depth backstop.
    if (buf.length > width) throw new E(code, "ECDSA signature component wider than the curve field");
    var out = Buffer.alloc(width);
    buf.copy(out, width - buf.length);
    return out;
  }
  return Buffer.concat([pad(r), pad(s)]);
}

module.exports = { ecdsaSigToRaw: ecdsaSigToRaw, rawToEcdsaDer: rawToEcdsaDer, ecdsaDerToP1363: ecdsaDerToP1363 };
