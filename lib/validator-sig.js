// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");

// @enforced-by behavioral -- a DER ECDSA-Sig-Value BUILD has no rename-proof code shape distinct
function rawToEcdsaDer(raw, coordLen) {
  if (!Buffer.isBuffer(raw) || typeof coordLen !== "number" || coordLen <= 0 || raw.length !== coordLen * 2) {
    throw new TypeError("rawToEcdsaDer: raw signature must be a Buffer of exactly 2*coordLen bytes");
  }
  var r = BigInt("0x" + raw.subarray(0, coordLen).toString("hex"));
  var s = BigInt("0x" + raw.subarray(coordLen).toString("hex"));
  return asn1.build.sequence([asn1.build.integer(r), asn1.build.integer(s)]);
}

var CURVE_FIELD_BYTES = Object.assign(Object.create(null), { "P-256": 32, "P-384": 48, "P-521": 66 });
var CURVE_ORDER = Object.assign(Object.create(null), {
  "P-256": BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  "P-384": BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
  "P-521": BigInt("0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
});

// @enforced-by behavioral -- a DER ECDSA-Sig-Value decode has no rename-proof code shape distinct
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
  var r, s;
  try { r = asn1.read.integer(n.children[0]); } catch (e) { throw new E(code, "ECDSA signature r is not a minimally-encoded DER INTEGER", e); }
  try { s = asn1.read.integer(n.children[1]); } catch (e) { throw new E(code, "ECDSA signature s is not a minimally-encoded DER INTEGER", e); }
  if (r < 1n || s < 1n || r >= order || s >= order) {
    throw new E(code, "ECDSA signature component out of range [1, n-1] (CVE-2022-21449)");
  }
  function pad(v) {
    var hex = v.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    var buf = Buffer.from(hex, "hex");
    if (buf.length > width) throw new E(code, "ECDSA signature component wider than the curve field");
    var out = Buffer.alloc(width);
    buf.copy(out, width - buf.length);
    return out;
  }
  return Buffer.concat([pad(r), pad(s)]);
}

module.exports = { rawToEcdsaDer: rawToEcdsaDer, ecdsaDerToP1363: ecdsaDerToP1363 };
