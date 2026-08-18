// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the consumers
// whose encoding integrity composes this guard (pki.schema.c509 reconstruct sites,
// pki.x509.sign and its sibling builders on any subjectAltName otherName value).
//
// guard-der: the single choke point for "these raw bytes are exactly one strictly-valid
// DER element", for every site that splices caller-supplied ANY bytes verbatim into
// something it then signs or reconstructs.
//
// The bug class is framing mistaken for validation. asn1.decode checks TLV framing and
// rejects trailing data, and stopping there feels sufficient. It is not: framing accepts
// a BOOLEAN whose content octet is 0x01 where DER requires 0xFF, a NumericString holding
// "@", and a SET whose members sit in no canonical order. None of those is DER. Spliced
// into a certificate and signed, the issuer emits a structure that strict relying parties
// reject, under a real signature, while the producing verb reported success (CWE-20).
//
// The rule is validate-or-refuse. A universal primitive runs through its strict content
// reader, and a universal type with no reader here is REFUSED, so the table is exhaustive
// by refusal and adding a type is a deliberate act. A non-universal element (a
// legitimately context- or application-tagged ANY) passes on its framing because no
// content rule is knowable for it, and its constructed children are still walked.
//
// Every entry point takes the CALLER's error factory and code, so a c509 splice reports in
// the c509 domain and a certificate builder in the x509 domain.
// asn1-der composes this guard family, so requiring the codec at module scope would read its
// exports mid-initialisation and see an empty object. The require and the table it builds are
// therefore both deferred to first use -- the documented circular-load exception to top-of-file
// requires. Guards sit BELOW the codec in the dependency order; this is the one place that
// order is inverted, and it is inverted lazily.
var asn1 = null;
function _asn1() { if (asn1 === null) asn1 = require("./asn1-der"); return asn1; }

// The strict content reader per universal primitive tag. A tag absent from this table has no
// validator here and is refused by `element` below -- that refusal is the point.
var VALUE_READERS = null;
function _readers() {
  if (VALUE_READERS !== null) return VALUE_READERS;
  var asn1 = _asn1();
  var m = {}, R = asn1.read, T = asn1.TAGS;
  // ENUMERATED shares INTEGER's content rules and is NOT constrained to non-negative
  // values. X.680 (02/2021) sec. 20.2 requires each NamedNumber's SignedNumber to be
  // distinct, and sec. 19 defines SignedNumber ::= number | "-" number; the non-negativity
  // in sec. 20.3 governs only an EnumerationItem written as a bare identifier, which is
  // auto-assigned. `ENUMERATED { lowPriority(-1), normal(0) }` is well-formed, so rejecting
  // a negative here would refuse valid input. This guard validates the ENCODING; which
  // values a particular ENUMERATED admits lives in a type definition an opaque ANY does
  // not carry.
  m[T.BOOLEAN] = R.boolean; m[T.INTEGER] = R.integer; m[T.ENUMERATED] = R.enumerated;
  m[T.BIT_STRING] = R.bitString; m[T.OCTET_STRING] = R.octetString; m[T.NULL] = R.nullValue;
  m[T.OBJECT_IDENTIFIER] = R.oid; m[T.UTC_TIME] = R.time; m[T.GENERALIZED_TIME] = R.time;
  // NumericString reads through its own reader: it is not a DirectoryString type, and routing
  // it through read.string would fold it into the RFC 5280 sec. 7.1 name-comparison identity
  // class (see asn1-der.js).
  m[T.NUMERIC_STRING] = R.numericString;
  [T.UTF8_STRING, T.PRINTABLE_STRING, T.IA5_STRING, T.TELETEX_STRING, T.VISIBLE_STRING,
    T.BMP_STRING, T.UNIVERSAL_STRING].forEach(function (t) { m[t] = R.string; });
  VALUE_READERS = m;
  return VALUE_READERS;
}

// A universal SET's required member order depends on a type the ANY does not carry: X.690
// sec. 11.6 orders a SET OF by the members' full encodings, while a structured SET is ordered
// by TAG (X.680 sec. 8.6), and the two differ whenever the constructed bit does (a SEQUENCE
// member, tag 16, sorts before a PrintableString, tag 19, by tag but after it by octets). A
// structured SET cannot repeat a tag, so a repeated tag proves SET OF and the octet rule binds;
// with all-distinct tags either reading is possible, so accept a value that satisfies EITHER
// (rejecting only what is non-canonical under both readings: sound in both directions, never a
// guess).
//
// KNOWN LIMITATION, and the two consumers do not weigh it identically. The either-reading rule
// admits a SET OF that is tag-ordered but not octet-ordered, which is not canonical DER. On a
// RECONSTRUCT path the input already exists and the alternative would refuse a valid structured
// SET, so accepting is the sound direction. On a SIGNING path the caller composes the bytes and
// could be held to octet order, so the same permissiveness lets a signer emit a non-canonical
// SET under a real signature. Tightening it for signers alone would mean a mode flag on a
// security posture, which this family avoids, and tightening it for both would reject valid
// structured SETs that c509 round-trips today. The rule is therefore unchanged and the cost is
// written down rather than discovered later.
var TAG_CLASS_RANK = { universal: 0, application: 1, context: 2, private: 3 };
function setOrderOk(kids) {
  var i, dup = false, seen = {};
  for (i = 0; i < kids.length; i++) {
    var key = kids[i].tagClass + ":" + kids[i].tagNumber;
    if (seen[key]) { dup = true; break; }
    seen[key] = true;
  }
  var octetAsc = true, tagAsc = true;
  for (i = 1; i < kids.length; i++) {
    if (Buffer.compare(kids[i - 1].bytes, kids[i].bytes) > 0) octetAsc = false;
    // Tag order ranks by CLASS first (universal < application < context < private, X.680
    // sec. 8.6), then by tag number. Compare the class's NUMBER: the names do not sort in
    // class order.
    var pc = TAG_CLASS_RANK[kids[i - 1].tagClass], cc = TAG_CLASS_RANK[kids[i].tagClass];
    if (pc !== cc ? pc > cc : kids[i - 1].tagNumber > kids[i].tagNumber) tagAsc = false;
  }
  return dup ? octetAsc : (octetAsc || tagAsc);
}

// element(node, E, code, label). Strict-validate an already-decoded DER element at ANY depth.
// Rejects the reserved EOC tag 0; runs a universal primitive through its strict content reader
// (or refuses a type with none); recurses into a constructed element's children; holds a
// universal SET to a canonical order. Only SEQUENCE and SET are accepted as universal
// CONSTRUCTED types -- an EXTERNAL / EMBEDDED PDV / CHARACTER STRING has mandatory components
// this gate cannot verify (the degenerate empty form is not a valid encoding of any of them),
// so it is refused for the same reason an unvalidatable primitive is.
//
// @enforced-by guard-shape-reinlined
// @guard-shape _ANY_VALUE_READERS\[
function element(node, E, code, label) {
  if (node.tagClass === "universal" && node.tagNumber === 0) {
    throw E(code, label + " must not use the reserved end-of-contents encoding (tag 0)");
  }
  var T = _asn1().TAGS;
  if (node.constructed) {
    if (node.tagClass === "universal" && node.tagNumber !== T.SEQUENCE && node.tagNumber !== T.SET) {
      throw E(code, label + " of universal constructed type " + node.tagNumber + " has no strict DER structure validator here");
    }
    var kids = node.children;   // asn1.decode always sets a (possibly empty) children array
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

// tlv(content, E, code, label) -> content. Raw ANY bytes about to be spliced verbatim must be
// exactly one non-empty, well-formed AND strictly-valid DER element: framing + no-trailing-data
// via asn1.decode, then content / structure / SET order via `element`. Returns the bytes so a
// call site can wrap a splice inline.
//
// @enforced-by guard-shape-reinlined
// @guard-shape must be exactly one well-formed DER element
function tlv(content, E, code, label) {
  if (!content || content.length === 0) throw E(code, label + " must be a non-empty DER element");
  var node;
  try { node = _asn1().decode(content); }
  catch (e) { throw E(code, label + " must be exactly one well-formed DER element (no trailing data)", e); }
  element(node, E, code, label);
  return content;
}

module.exports = { element: element, tlv: tlv };
