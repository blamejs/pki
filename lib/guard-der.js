// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
var _compare = require("./guard-intrinsic").compare;
var _freeze = require("./guard-intrinsic").freeze;
var _forEach = require("./guard-intrinsic").forEach;
var _sizeOf = require("./guard-intrinsic").sizeOf;
var _create = require("./guard-intrinsic").create;
var _isBuffer = require("./guard-intrinsic").isBuffer;

var asn1 = null;
function _asn1() { if (asn1 === null) asn1 = require("./asn1-der"); return asn1; }

var VALUE_READERS = null;
function _readers() {
  if (VALUE_READERS !== null) return VALUE_READERS;
  var asn1 = _asn1();
  var m = _create(null), R = asn1.read, T = asn1.TAGS;
  m[T.BOOLEAN] = R.boolean; m[T.INTEGER] = R.integer; m[T.ENUMERATED] = R.enumerated;
  m[T.BIT_STRING] = R.bitString; m[T.OCTET_STRING] = R.octetString; m[T.NULL] = R.nullValue;
  m[T.OBJECT_IDENTIFIER] = R.oid; m[T.UTC_TIME] = R.time; m[T.GENERALIZED_TIME] = R.time;
  m[T.NUMERIC_STRING] = R.numericString;
  _forEach([T.UTF8_STRING, T.PRINTABLE_STRING, T.IA5_STRING, T.TELETEX_STRING, T.VISIBLE_STRING,
    T.BMP_STRING, T.UNIVERSAL_STRING], function (t) { m[t] = R.string; });
  VALUE_READERS = m;
  return VALUE_READERS;
}

var TAG_CLASS_RANK = _create(null);
TAG_CLASS_RANK.universal = 0;
TAG_CLASS_RANK.application = 1;
TAG_CLASS_RANK.context = 2;
TAG_CLASS_RANK["private"] = 3;
function setOrderOk(kids) {
  var i, dup = false, seen = _create(null);
  for (i = 0; i < kids.length; i++) {
    var key = kids[i].tagClass + ":" + kids[i].tagNumber;
    if (seen[key]) { dup = true; break; }
    seen[key] = true;
  }
  var octetAsc = true, tagAsc = true;
  for (i = 1; i < kids.length; i++) {
    if (_compare(kids[i - 1].bytes, kids[i].bytes) > 0) octetAsc = false;
    var pc = TAG_CLASS_RANK[kids[i - 1].tagClass], cc = TAG_CLASS_RANK[kids[i].tagClass];
    if (pc !== cc ? pc > cc : kids[i - 1].tagNumber > kids[i].tagNumber) tagAsc = false;
  }
  return dup ? octetAsc : (octetAsc || tagAsc);
}

// @enforced-by guard-shape-reinlined
// @guard-shape _ANY_VALUE_READERS\[
function element(node, E, code, label) {
  if (node.tagClass === "universal" && node.tagNumber === 0) {
    throw E(code, label + " must not use the reserved end-of-contents encoding (tag 0)");
  }
  /** @internal The other reserved rows, asked of the codec's own predicate so the two cannot
   *  disagree about which universal tags X.680 Table 1 assigns to no type. The codec door refuses
   *  these before a node exists, so this answers for a node that reached here by another route. */
  if (node.tagClass === "universal" && _asn1().reservedUniversalTag(node.tagNumber)) {
    throw E(code, label + " must not use universal tag " + node.tagNumber +
      ", which X.680 Table 1 reserves and assigns to no type");
  }
  var T = _asn1().TAGS;
  if (node.constructed) {
    if (node.tagClass === "universal" && node.tagNumber !== T.SEQUENCE && node.tagNumber !== T.SET) {
      throw E(code, label + " of universal constructed type " + node.tagNumber + " has no strict DER structure validator here");
    }
    var kids = node.children;
    for (var i = 0; i < kids.length; i++) element(kids[i], E, code, label);
    if (node.tagClass === "universal" && node.tagNumber === T.SET && !setOrderOk(kids)) {
      throw E(code, label + " has a SET whose members are in no canonical DER order (X.690 sec. 11.6 / X.680 sec. 8.6)");
    }
    return;
  }
  if (node.tagClass === "universal") {
    var reader = _readers()[node.tagNumber];
    if (!reader) throw E(code, label + " of universal type " + node.tagNumber + " has no strict DER content validator here");
    try { reader(node); }
    catch (e) { throw E(code, label + " is not a valid DER element for its type", e); }
  }
}

// @enforced-by guard-shape-reinlined
// @guard-shape must be exactly one well-formed DER element
function tlv(content, E, code, label) {
  if (!content || _sizeOf(content) === 0) throw E(code, label + " must be a non-empty DER element");
  var node;
  try { node = _asn1().decode(content); }
  catch (e) { throw E(code, label + " must be exactly one well-formed DER element (no trailing data)", e); }
  element(node, E, code, label);
  return content;
}

// @enforced-by guard-shape-reinlined
// @guard-shape \[0\] === 0x05
function isNull(params) {
  return _isBuffer(params) && _sizeOf(params) === 2 && params[0] === 0x05 && params[1] === 0x00;
}

// @enforced-by behavioral -- absence has no rename-proof shape; the RED vector per verb is the guard
function paramsAbsentOrNull(params) {
  return params === null || params === undefined || isNull(params);
}

/** Whether two decoded `AlgorithmIdentifier` records name the same algorithm with the same
 *  parameters, comparing the parameters AS THEY ARE: absent equals absent, and an explicit DER NULL
 *  is a different identifier from one with no parameters field.
 *
 *  This is the comparison for an identifier whose parameters carry meaning. A digest identifier has
 *  the opposite rule, because RFC 3370 clause 2.1 and RFC 5754 clause 2 require an implementation to
 *  accept both spellings of the same digest, and `schema-cms.sameDigestAlgorithm` grants that. A
 *  signature identifier does not: RFC 4055 requires the `*WithRSAEncryption` identifiers to carry a
 *  NULL, RFC 5758 and RFC 8410 require the `ecdsaWith*` and the Edwards and post-quantum ones to omit
 *  the field, and RSASSA-PSS carries its hash, mask generator, salt length and trailer field there
 *  under RFC 4056 clause 2.2. Collapsing the two spellings for one of those is admitting a different
 *  algorithm, which is why the grant does not travel.
 *
 * @enforced-by behavioral -- an equality that is too permissive has no rename-proof shape; the RED
 * vector is an identifier pair differing only in an explicit NULL, which must compare unequal here
 * and equal through the digest helper.
 */
function sameAlgorithmExactly(a, c) {
  if (!a || !c || a.oid !== c.oid) return false;
  var ap = a.parameters === undefined ? null : a.parameters;
  var cp = c.parameters === undefined ? null : c.parameters;
  if (ap === null || cp === null) return ap === cp;
  return _isBuffer(ap) && _isBuffer(cp) && _sizeOf(ap) === _sizeOf(cp) && _compare(ap, cp) === 0;
}

// @enforced-by behavioral -- see paramsAbsentOrNull.
function assertParams(params, shape, E, code, label) {
  var ok = shape === "null" ? isNull(params) : (shape === "absent"
    ? (params === null || params === undefined)
    : paramsAbsentOrNull(params));
  if (ok) return params;
  throw E(code, "the " + label + " parameters must be " + (shape === "null"
    ? "DER NULL" : (shape === "absent" ? "absent" : "absent or DER NULL")));
}

module.exports = _freeze({
  element: element, tlv: tlv,
  isNull: isNull, paramsAbsentOrNull: paramsAbsentOrNull, assertParams: assertParams,
  sameAlgorithmExactly: sameAlgorithmExactly,
});
