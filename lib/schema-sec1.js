// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.sec1
 * @nav        Schema
 * @title      SEC1
 * @fullname   SEC1 EC private keys, the EC PRIVATE KEY encoding
 * @order      146
 * @slug       sec1
 *
 * @intro
 *   The elliptic-curve private-key encoding of RFC 5915: `ECPrivateKey`, the
 *   `EC PRIVATE KEY` PEM block OpenSSL writes and appliances still emit. `parse`
 *   reads one into its version, scalar, curve and stored public point, and
 *   `encode` writes it back.
 *
 *   The curve is what fixes the scalar's width, so the parameters field is
 *   required here even though the ASN.1 marks it optional: without it there is no
 *   width to hold the scalar to, and a scalar of the wrong width is a different
 *   key. RFC 5915 sec. 3 states the scalar as `ceiling(log2(n)/8)` octets with its
 *   leading zeros intact, so a short one is refused and never padded into place.
 *
 *   The parameters field carries a named curve and nothing else. RFC 5480
 *   sec. 2.1.1 says a specified curve and an implicit curve MUST NOT appear, and
 *   each is refused by name, so the message says which one arrived.
 *
 *   The stored public key is surfaced as the bytes it carries. It is the
 *   encoding's own copy of the public half, not the key's identity: a verb that
 *   needs that half derives it from the scalar, so a stored point that disagrees
 *   cannot decide anything.
 *
 * @card
 *   Read and write the RFC 5915 `ECPrivateKey`, DER or PEM, with the scalar held
 *   to its curve's width and the parameters field held to a named curve.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");

var Sec1Error = frameworkError.Sec1Error;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("sec1", Sec1Error, oid);

var LABEL = "EC PRIVATE KEY";

/** @internal The scalar width each curve fixes, `ceiling(log2(n)/8)` over the curve's order
 * (RFC 5915 sec. 3). A curve with no row here is one this toolkit cannot hold a scalar to, which
 * is a refusal, since guessing the width would accept a key of the wrong size. */
var CURVE_SCALAR_BYTES = intrinsic.assign(intrinsic.create(null), {
  "prime256v1": 32,
  "secp384r1": 48,
  "secp521r1": 66,
  "secp256k1": 32,
  "brainpoolP256r1": 32,
  "brainpoolP384r1": 48,
  "brainpoolP512r1": 64,
});

/** @internal RFC 5480 sec. 2.2 writes the point's first octet as the form: 0x04 uncompressed,
 * 0x02 and 0x03 compressed. The hybrid forms 0x06 and 0x07 are named there as MUST NOT, and every
 * other value names no form at all. The width follows from the form and the curve. */
function _assertPoint(point, scalarBytes) {
  if (point.length === 0) {
    throw NS.E("sec1/bad-public-key", "the stored public key is empty (RFC 5480 sec. 2.2)");
  }
  var form = point[0];
  if (form === 0x06 || form === 0x07) {
    throw NS.E("sec1/bad-public-key", "the hybrid point forms 0x06 and 0x07 are refused (RFC 5480 sec. 2.2)");
  }
  if (form === 0x04) {
    if (point.length !== 1 + 2 * scalarBytes) {
      throw NS.E("sec1/bad-public-key", "an uncompressed point is 1 + 2 * " + scalarBytes + " octets on this curve, got " + point.length);
    }
    return;
  }
  if (form === 0x02 || form === 0x03) {
    if (point.length !== 1 + scalarBytes) {
      throw NS.E("sec1/bad-public-key", "a compressed point is 1 + " + scalarBytes + " octets on this curve, got " + point.length);
    }
    return;
  }
  throw NS.E("sec1/bad-public-key", "the stored public key's first octet names no point form (RFC 5480 sec. 2.2)");
}

var EC_PRIVATE_KEY = schema.seq([
  schema.field("version", schema.integerLeaf()),
  schema.field("privateKey", schema.octetString()),
  /** @internal RFC 5915's module is DEFINITIONS EXPLICIT TAGS, so `[0]` and `[1]` wrap their
   * values, and do not replace their tags. */
  /** @internal Read as ANY so the two shapes RFC 5480 sec. 2.1.1 names as MUST NOT, a SEQUENCE
   * (specifiedCurve) and a NULL (implicitCurve), each get a verdict naming it. The OID reader
   * would answer both with "expected tag 6", which says nothing about which one arrived. */
  schema.optional("parameters", schema.any(), { tag: 0, explicit: true }),
  schema.optional("publicKey", schema.bitString(), { tag: 1, explicit: true }),
], {
  assert: "sequence", arity: { min: 2, max: 4 }, code: "sec1/not-an-ec-private-key", what: "ECPrivateKey",
  build: function (m) {
    var version = m.fields.version.value;
    /** @internal RFC 5915 sec. 3 fixes the version at 1. A PKCS#8 PrivateKeyInfo opens with a
     * version 0 INTEGER and an OCTET STRING too, so this is also what keeps one from reading as
     * the other. */
    if (version !== 1n) {
      throw NS.E("sec1/bad-version", "an ECPrivateKey is version 1 (RFC 5915 sec. 3), got " + version);
    }
    if (!m.fields.parameters.present) {
      throw NS.E("sec1/missing-curve", "an ECPrivateKey read on its own carries its [0] parameters, since the curve is what fixes the scalar's width (RFC 5915 sec. 3)");
    }
    var paramNode = m.fields.parameters.value;
    if (paramNode.tagClass !== "universal" || paramNode.tagNumber !== asn1.TAGS.OBJECT_IDENTIFIER) {
      throw NS.E("sec1/bad-curve", paramNode.tagClass === "universal" && paramNode.tagNumber === asn1.TAGS.SEQUENCE
        ? "the parameters field carries a specified curve, which RFC 5480 sec. 2.1.1 refuses; name the curve instead"
        : (paramNode.tagClass === "universal" && paramNode.tagNumber === asn1.TAGS.NULL
          ? "the parameters field carries an implicit curve, which RFC 5480 sec. 2.1.1 refuses; name the curve instead"
          : "the parameters field carries a named curve OBJECT IDENTIFIER and nothing else (RFC 5480 sec. 2.1.1)"));
    }
    var curveOid = asn1.read.oid(paramNode);
    var curve = oid.name(curveOid);
    var scalarBytes = curve === undefined ? undefined : CURVE_SCALAR_BYTES[curve];
    if (scalarBytes === undefined) {
      throw NS.E("sec1/unsupported-curve", "this toolkit holds no scalar width for the curve " + curveOid +
        (curve === undefined ? "" : " (" + curve + ")"));
    }
    var scalar = m.fields.privateKey.value;
    if (scalar.length !== scalarBytes) {
      throw NS.E("sec1/bad-private-key", "the private key is " + scalarBytes + " octets on " + curve +
        ", with its leading zeros (RFC 5915 sec. 3), got " + scalar.length);
    }
    var out = { version: intrinsic.Number(version), privateKey: scalar, curve: curve, curveOid: curveOid };
    if (m.fields.publicKey.present) {
      var bits = m.fields.publicKey.value;
      if (bits.unusedBits !== 0) {
        throw NS.E("sec1/bad-public-key", "the stored public key's BIT STRING holds whole octets");
      }
      _assertPoint(bits.bytes, scalarBytes);
      out.publicKey = bits.bytes;
    }
    return out;
  },
});

var PARSE_OPTS = intrinsic.assign(intrinsic.create(null), {
  pemLabel: LABEL, PemError: PemError, ErrorClass: Sec1Error, prefix: "sec1",
  what: "EC private key", topSchema: EC_PRIVATE_KEY, ns: NS,
});

/**
 * @primitive  pki.schema.sec1.parse
 * @signature  pki.schema.sec1.parse(input, opts) -> key
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 5915
 * @related    pki.schema.sec1.encode, pki.schema.pkcs8.parse
 *
 * Read an RFC 5915 `ECPrivateKey`, as DER bytes or an `EC PRIVATE KEY` PEM block,
 * into `{ version, privateKey, curve, curveOid, publicKey }`. The scalar and the
 * stored point are `Buffer`s, and `curve` is the registry name of the named curve
 * the key carries.
 *
 * The parameters field is required, because the curve is what fixes the scalar's
 * width and a scalar of the wrong width is a different key. It carries a named
 * curve and nothing else: a specified curve and an implicit curve are both refused
 * with `sec1/bad-curve`, which RFC 5480 sec. 2.1.1 states as a MUST NOT.
 *
 * The stored public key is the encoding's own copy of the public half, not the key's
 * identity. A verb that needs that half derives it from the scalar.
 *
 * @example
 *   // requires: der -- an ECPrivateKey, from `openssl ecparam -genkey` or an appliance
 *   var key = pki.schema.sec1.parse(der);
 *   key.version;    // 1
 *   key.curve;      // "prime256v1"
 */
var parse = pkix.makeParser(PARSE_OPTS);

/**
 * @primitive  pki.schema.sec1.encode
 * @signature  pki.schema.sec1.encode(key) -> Buffer
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 5915
 * @related    pki.schema.sec1.parse
 *
 * Write an `ECPrivateKey` back to DER from the shape `parse` returns, with the
 * parameters field always present, which RFC 5915 sec. 3 asks of a generator. A key
 * read and written again produces the bytes it came from.
 *
 * @example
 *   // requires: der -- an ECPrivateKey, from `openssl ecparam -genkey` or an appliance
 *   pki.schema.sec1.encode(pki.schema.sec1.parse(der)).equals(der);   // true
 */
function encode(key) {
  if (key === null || typeof key !== "object") {
    throw NS.E("sec1/bad-input", "encode takes the object parse returns");
  }
  var curveOid = key.curveOid;
  if (typeof curveOid !== "string") {
    var named = typeof key.curve === "string" ? oid.byName(key.curve) : undefined;
    if (typeof named !== "string") {
      throw NS.E("sec1/bad-input", "encode needs the key's named curve, as curveOid or a registered curve name");
    }
    curveOid = named;
  }
  var kids = [asn1.build.integer(intrinsic.BigInt(key.version === undefined ? 1 : key.version)),
    asn1.build.octetString(key.privateKey),
    asn1.build.explicit(0, asn1.build.oid(curveOid))];
  if (key.publicKey !== undefined && key.publicKey !== null) {
    kids[3] = asn1.build.explicit(1, asn1.build.bitString(key.publicKey, 0));
  }
  return asn1.build.sequence(kids);
}

function pemDecode(text) { return pkix.pemDecode(text, LABEL, PemError); }
function pemEncode(der) { return pkix.pemEncode(der, LABEL, PemError); }

/** @internal RFC 5915 sec. 3: `ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET
 * STRING, parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`. Structure
 * alone does not separate this from every other SEQUENCE opening that way, which is why nothing
 * routes to it from bare bytes; it answers for a caller that already has the armor label. */
function matches(root) {
  var k = pkix.rootSequenceChildren(root, 2, 4);
  if (!k) return false;
  if (!schema.isUniversal(k[0], asn1.TAGS.INTEGER)) return false;
  if (!schema.isUniversal(k[1], asn1.TAGS.OCTET_STRING)) return false;
  var last = -1;
  for (var i = 2; i < k.length; i++) {
    if (!schema.isContextInRange(k[i], 0, 1) || k[i].tagNumber <= last) return false;
    last = k[i].tagNumber;
  }
  return true;
}

module.exports = {
  parse: parse,
  matches: matches,
  encode: encode,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
};
