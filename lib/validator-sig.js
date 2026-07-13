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

module.exports = { ecdsaSigToRaw: ecdsaSigToRaw };
