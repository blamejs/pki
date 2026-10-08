// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.asn1
 * @nav        Core
 * @title      ASN.1 / DER
 * @fullname   ASN.1 and DER: a strict encoder and decoder
 * @order      30
 * @featured   true
 * @slug       asn1
 *
 * @intro
 *   A strict DER (Distinguished Encoding Rules) codec: the byte layer
 *   every X.509 / PKCS / CMS structure is built on. The decoder is
 *   fail-closed: it rejects the BER shapes DER forbids (indefinite
 *   length, non-minimal length or integer encodings, trailing garbage,
 *   constructed strings) and refuses input past a size or nesting cap
 *   before it walks a single byte, so a hostile length prefix can't turn
 *   into a decoder denial-of-service.
 *
 *   `decode(bytes)` returns a navigable node tree; the `read.*` helpers
 *   turn a node into a JS value (BigInt, dotted OID, Date, string); the
 *   `build.*` helpers construct canonical DER from JS values. Because DER
 *   is canonical, each value the `build.*` helpers emit has exactly one
 *   valid encoding, byte-identical to any other conformant DER encoder's
 *   output, and decoding it reproduces the value it was built from.
 *   `build.generalizedTime(date)` emits whole seconds, the RFC 5280 form;
 *   `build.generalizedTime(date, { fractional: true })` keeps the Date's
 *   milliseconds in the X.690 DER fraction (no trailing zeros, no empty
 *   fraction), the form RFC 3161 allows a timestamp's genTime, which
 *   `read.time(node, { allowFractional: true })` reads back.
 *
 * @card
 *   Strict, fail-closed DER decode / encode with a navigable node tree
 *   and typed readers + builders.
 */

var constants = require("./constants");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
/** @internal A Date's fields are read through the prototype's own getters, captured at load, so
 * a getter the instance carries or one replaced later cannot change what a time encodes to or
 * what the reader's own Date reports back. */
var _dateGetUTCFullYear = intrinsic.uncurry(Date.prototype.getUTCFullYear);
var _dateGetUTCMonth = intrinsic.uncurry(Date.prototype.getUTCMonth);
var _dateGetUTCDate = intrinsic.uncurry(Date.prototype.getUTCDate);
var _dateGetUTCHours = intrinsic.uncurry(Date.prototype.getUTCHours);
var _dateGetUTCMinutes = intrinsic.uncurry(Date.prototype.getUTCMinutes);
var _dateGetUTCSeconds = intrinsic.uncurry(Date.prototype.getUTCSeconds);
var _dateGetUTCMilliseconds = intrinsic.uncurry(Date.prototype.getUTCMilliseconds);
var _dateSetUTCFullYear = intrinsic.uncurry(Date.prototype.setUTCFullYear);
var _dateSetUTCHours = intrinsic.uncurry(Date.prototype.setUTCHours);

var Asn1Error = frameworkError.Asn1Error;
var OidError = frameworkError.OidError;

function _asn1Error(c, m) { return new Asn1Error(c, m); }

function _oidErr(c, m) { return new OidError(c, m); }


/**
 * @primitive  pki.asn1.reservedUniversalTag
 * @signature  pki.asn1.reservedUniversalTag(tagNumber) -> boolean
 * @since      0.8.54
 * @status     stable
 * @spec       X.680, ISO/IEC 8824-1
 * @related    pki.asn1.decode
 *
 * Whether X.680 reserves this universal tag number, which means no ASN.1 type is assigned to it and
 * no DER encoding of any type uses it. Table 1 reserves three rows: tag 0 for the encoding rules,
 * tag 15 for future editions of the Recommendation, and tag 37 upward for its addenda. `decode`
 * refuses an element carrying any of them with `asn1/reserved-tag`, so this answers the same
 * question ahead of the attempt.
 *
 * The question is not "does this codec have a reader for the tag", which is a smaller set:
 * ObjectDescriptor (7), REAL (9), RELATIVE-OID (13), the time type (14), VideotexString (21),
 * GraphicString (25) and GeneralString (27) are all assigned by X.680 and all arrive here as opaque
 * values, and each is legitimate inside an `ANY`. This returns `false` for every one of them.
 *
 * @example
 *   pki.asn1.reservedUniversalTag(0);    // -> true   (the encoding rules)
 *   pki.asn1.reservedUniversalTag(15);   // -> true   (future editions)
 *   pki.asn1.reservedUniversalTag(37);   // -> true   (addenda)
 *   pki.asn1.reservedUniversalTag(9);    // -> false  (REAL, assigned, no reader here)
 *   pki.asn1.reservedUniversalTag(31);   // -> false  (DATE, assigned)
 */
function reservedUniversalTag(tagNumber) {
  /** @internal The type check comes FIRST, and a value that is not a tag number answers `false`
   *  rather than throwing, which is how the other public predicates here answer: `isPrintableString`
   *  and `oid.isDottedDecimal` both say "not that" of a value of the wrong type. A range test alone
   *  calls `37.5` and `Infinity` reserved, since both sit inside the addenda range while being no
   *  tag at all, and `tagNumber >= 37` against a caller's object runs that object's `valueOf`, so a
   *  comparison reached before this check runs caller code inside a predicate.
   *
   *  Then all three rows the table reserves, tag 0 included: this answers what X.680 says, and it
   *  says tag 0 is reserved. The decode door keeps a separate branch for tag 0 ahead of the general
   *  one so its refusal can cite the end-of-contents encoding X.690 sec. 8.1.5 gives that octet
   *  pair, which is the useful thing to tell whoever sent it; the answer to "is it reserved" is the
   *  same from either place. */
  if (typeof tagNumber !== "number" || !intrinsic.isInteger(tagNumber) || tagNumber < 0) return false;
  return tagNumber === 0 || tagNumber === 15 || tagNumber >= 37;
}

var UNIVERSAL_TYPES = intrinsic.assign(intrinsic.create(null), {
  BOOLEAN:           { tag: 0x01, form: "primitive" },
  INTEGER:           { tag: 0x02, form: "primitive" },
  BIT_STRING:        { tag: 0x03, form: "primitive" },
  OCTET_STRING:      { tag: 0x04, form: "primitive" },
  NULL:              { tag: 0x05, form: "primitive" },
  OBJECT_IDENTIFIER: { tag: 0x06, form: "primitive" },
  EXTERNAL:          { tag: 0x08, form: "constructed" },
  ENUMERATED:        { tag: 0x0a, form: "primitive" },
  EMBEDDED_PDV:      { tag: 0x0b, form: "constructed" },
  UTF8_STRING:       { tag: 0x0c, form: "primitive" },
  SEQUENCE:          { tag: 0x10, form: "constructed" },
  SET:               { tag: 0x11, form: "constructed" },
  NUMERIC_STRING:    { tag: 0x12, form: "primitive" },
  PRINTABLE_STRING:  { tag: 0x13, form: "primitive" },
  TELETEX_STRING:    { tag: 0x14, form: "primitive" },
  IA5_STRING:        { tag: 0x16, form: "primitive" },
  UTC_TIME:          { tag: 0x17, form: "primitive" },
  GENERALIZED_TIME:  { tag: 0x18, form: "primitive" },
  VISIBLE_STRING:    { tag: 0x1a, form: "primitive" },
  UNIVERSAL_STRING:  { tag: 0x1c, form: "primitive" },
  CHARACTER_STRING:  { tag: 0x1d, form: "constructed" },
  BMP_STRING:        { tag: 0x1e, form: "primitive" },
});

/** @internal Frozen, because it is exported and every structure in the toolkit names its tags
 *  through it. Left writable, `pki.asn1.TAGS.SEQUENCE = 15` reached the encoders that compose an
 *  identifier from it and the guard that compares one against it, so one assignment by anything
 *  sharing the process moved what a SEQUENCE is for the whole process. The numbers are X.680's and
 *  no caller has a reason to change one. */
var TAGS = intrinsic.create(null);
Object.keys(UNIVERSAL_TYPES).forEach(function (k) { TAGS[k] = UNIVERSAL_TYPES[k].tag; });
intrinsic.freeze(TAGS);

var CLASS_UNIVERSAL   = 0x00;
var CLASS_APPLICATION = 0x40;
var CLASS_CONTEXT     = 0x80;
var CLASS_PRIVATE     = 0xc0;
var CONSTRUCTED_BIT   = 0x20;
var CLASS_MASK        = 0xc0;

var CONSTRUCTED_ONLY_UNIVERSAL_TAGS = Object.create(null);
Object.keys(UNIVERSAL_TYPES).forEach(function (k) {
  var d = UNIVERSAL_TYPES[k];
  if (d.form === "constructed") CONSTRUCTED_ONLY_UNIVERSAL_TAGS[d.tag] = true;
});

function _className(bits) {
  switch (bits) {
    case CLASS_UNIVERSAL:   return "universal";
    case CLASS_APPLICATION: return "application";
    case CLASS_CONTEXT:     return "context";
    case CLASS_PRIVATE:     return "private";
    default:                return "universal";
  }
}

function _asBuffer(input, who) {
  return guard.bytes.view(input, Asn1Error, "asn1/not-buffer", who);
}


/**
 * @primitive  pki.asn1.decode
 * @signature  pki.asn1.decode(bytes, opts?) -> node
 * @since      0.1.0
 * @status     stable
 * @spec       X.690, ISO/IEC 8825-1
 * @defends    ASN.1-parser-DoS (CWE-400)
 * @related    pki.asn1.encode
 *
 * Parse DER into a node tree. Each node is
 * `{ tagClass, constructed, tagNumber, header, length, content, children,
 * bytes, contentStart, contentEnd }`, where `content` is the primitive value slice, `children` the
 * decoded sub-nodes of a constructed node, `bytes` the full TLV slice, and
 * `contentStart` / `contentEnd` the content slice's byte offsets in the input
 * (all slices are zero-copy views over the input).
 *
 * Throws `Asn1Error` on any non-DER shape: indefinite length, a
 * non-minimal length or a length that overruns the buffer, trailing bytes
 * after the top-level value (unless `allowTrailing`), or exceeding the
 * size / depth caps.
 *
 * `ber: true` is a scoped relaxation for formats whose content regions are
 * normatively BER (RFC 7292 PKCS#12): it accepts an indefinite length on a
 * constructed value and a constructed OCTET STRING, whose segments are
 * reassembled into one primitive `content`. Nothing else is relaxed:
 * definite lengths stay minimal, an indefinite length on a primitive value
 * and a foreign-type segment still reject, and the size / depth caps hold.
 *
 * @opts
 *   maxBytes:       number,   // default: C.LIMITS.DER_MAX_BYTES (16 MiB)
 *   maxDepth:       number,   // default: C.LIMITS.DER_MAX_DEPTH (64)
 *   maxItems:       number,   // default: C.LIMITS.DER_MAX_ITEMS (total decoded node cap)
 *   allowTrailing:  boolean,  // default false; allow bytes after the top TLV
 *   ber:            boolean,  // default false; accept indefinite lengths +
 *                             // constructed OCTET STRINGs (BER content regions)
 *
 * @example
 *   var der = pki.asn1.build.sequence([pki.asn1.build.integer(1n)]);
 *   var node = pki.asn1.decode(der);
 *   node.tagNumber === pki.asn1.TAGS.SEQUENCE;
 */
function decode(input, opts) {
  opts = opts || intrinsic.create(null);
  var buf = _asBuffer(input, "decode");
  var maxBytes = guard.limits.cap(opts.maxBytes, "maxBytes", constants.LIMITS.DER_MAX_BYTES);
  var maxDepth = guard.limits.depthCap(opts.maxDepth, "maxDepth", constants.LIMITS.DER_MAX_DEPTH);
  var maxItems = guard.limits.cap(opts.maxItems, "maxItems", constants.LIMITS.DER_MAX_ITEMS);
  if (buf.length > maxBytes) {
    throw new Asn1Error("asn1/too-large", "input " + buf.length + " bytes exceeds cap " + maxBytes);
  }
  var ctr = guard.limits.counter(maxItems, _asn1Error, "asn1/too-many-items", "decoded DER node");
  var r = _decodeTLV(buf, 0, buf.length, 0, maxDepth, opts.ber === true, undefined, ctr);
  if (!opts.allowTrailing && r.end !== buf.length) {
    throw new Asn1Error("asn1/trailing-bytes", (buf.length - r.end) + " trailing byte(s) after the top-level value");
  }
  return r.node;
}

function _decodeTLV(buf, start, limit, depth, maxDepth, ber, strDepth, ctr) {
  if (depth > maxDepth) {
    throw new Asn1Error("asn1/too-deep", "nesting exceeds depth cap " + maxDepth);
  }
  if (ctr) ctr.tick();
  var p = start;
  if (p >= limit) throw new Asn1Error("asn1/truncated", "expected an identifier octet");
  var first = buf[p]; p += 1;
  var tagClassBits = first & CLASS_MASK;
  var constructed = (first & CONSTRUCTED_BIT) !== 0;
  var tagNumber = first & 0x1f;

  if (tagNumber === 0x1f) {
    tagNumber = 0;
    var seen = 0;
    for (;;) {
      if (p >= limit) throw new Asn1Error("asn1/truncated", "truncated high-tag-number");
      var tb = buf[p]; p += 1;
      if (seen === 0 && tb === 0x80) {
        throw new Asn1Error("asn1/non-minimal-tag", "leading 0x80 in high-tag-number form");
      }
      tagNumber = (tagNumber * 128) + (tb & 0x7f);
      seen += 1;
      if (seen > 4) throw new Asn1Error("asn1/tag-too-large", "high-tag-number too large");
      if ((tb & 0x80) === 0) break;
    }
    if (tagNumber < 0x1f) {
      throw new Asn1Error("asn1/non-minimal-tag", "high-tag-number form used for a low tag");
    }
  }

  /** @internal UNIVERSAL tag 0 is reserved. X.690 sec. 8.1.5 gives the `00 00` octet pair one meaning,
   *  the terminator of an indefinite-length encoding, and nothing this decoder accepts uses indefinite
   *  length: the strict door refuses it outright, and the BER door consumes the pair as a terminator
   *  rather than as an element. So a universal tag-0 element is never part of a well-formed input on
   *  either door, and it was being handed back as an ordinary zero-length element. The rule is refused
   *  HERE, at the TLV, because `guard.der.element` already carried it and a reader that did not route
   *  through that guard inherited nothing. The class matters: a context-specific [0] is how most of
   *  X.509 and CMS write an optional field, so this is universal-class only. */
  if (tagClassBits === CLASS_UNIVERSAL && tagNumber === 0) {
    throw new Asn1Error("asn1/reserved-tag",
      "universal tag 0 is the reserved end-of-contents encoding (X.690 sec. 8.1.5) and is not an element");
  }

  if (tagClassBits === CLASS_UNIVERSAL && reservedUniversalTag(tagNumber)) {
    throw new Asn1Error("asn1/reserved-tag",
      "universal tag " + tagNumber + " is reserved by X.680 Table 1 (" + (tagNumber === 15
        ? "for future editions" : "for addenda") + ") and is not assigned to any type");
  }

  if (tagClassBits === CLASS_UNIVERSAL && CONSTRUCTED_ONLY_UNIVERSAL_TAGS[tagNumber] && !constructed) {
    throw new Asn1Error("asn1/bad-tlv", "a universal constructed-only type (SEQUENCE/SET/EXTERNAL/EMBEDDED PDV/CHARACTER STRING) must be constructed");
  }

  if (tagClassBits === CLASS_UNIVERSAL && constructed && !CONSTRUCTED_ONLY_UNIVERSAL_TAGS[tagNumber]) {
    if (!(ber && tagNumber === TAGS.OCTET_STRING)) {
      throw new Asn1Error("asn1/constructed-primitive-type", "a universal primitive-only type must be encoded primitive in DER");
    }
    strDepth = (strDepth || 0) + 1;
    if (strDepth > constants.LIMITS.BER_MAX_STRING_NESTING) {
      throw new Asn1Error("asn1/bad-constructed-string", "constructed OCTET STRING nesting exceeds the cap " + constants.LIMITS.BER_MAX_STRING_NESTING);
    }
  }

  if (p >= limit) throw new Asn1Error("asn1/truncated", "expected a length octet");
  var lenByte = buf[p]; p += 1;
  var length;
  if (lenByte < 0x80) {
    length = lenByte;
  } else if (lenByte === 0x80) {
    if (!ber || !constructed) {
      throw new Asn1Error("asn1/indefinite-length", "indefinite length is not valid DER");
    }
    length = -1;
  } else {
    var numLenBytes = lenByte & 0x7f;
    if (numLenBytes > 6) throw new Asn1Error("asn1/length-too-large", "length uses more than 6 octets");
    if (p + numLenBytes > limit) throw new Asn1Error("asn1/truncated", "truncated long-form length");
    if (buf[p] === 0x00) throw new Asn1Error("asn1/non-minimal-length", "leading zero in long-form length");
    length = 0;
    for (var i = 0; i < numLenBytes; i++) length = (length * 256) + buf[p + i];
    p += numLenBytes;
    if (length < 0x80) throw new Asn1Error("asn1/non-minimal-length", "long form used for a length < 128");
  }

  var contentStart = p;
  var indefinite = length === -1;
  var contentEnd = indefinite ? -1 : contentStart + length;
  if (!indefinite && contentEnd > limit) throw new Asn1Error("asn1/truncated", "content length overruns the buffer");

  var children = null;
  var content = null;
  var child;
  var end;
  if (constructed) {
    children = [];
    var cp = contentStart;
    if (indefinite) {
      for (;;) {
        if (cp + 2 > limit) throw new Asn1Error("asn1/truncated", "indefinite-length value is missing its end-of-contents octets");
        if (buf[cp] === 0x00 && buf[cp + 1] === 0x00) break;
        child = _decodeTLV(buf, cp, limit, depth + 1, maxDepth, ber, strDepth, ctr);
        /** @internal The decoded child is APPENDED by defining its index. Stored with `push`, the
         *  store walks the prototype chain for a setter, so an accessor at an array index received
         *  each child as it was decoded and could define another node in its place: measured, a
         *  SEQUENCE of two INTEGERs decoded with its first value changed from 1 to 9. Every format
         *  module in this toolkit reads its fields out of this list. */
        intrinsic.append(children, child.node);
        cp = child.end;
      }
      contentEnd = cp;
      end = cp + 2;
    } else {
      while (cp < contentEnd) {
        child = _decodeTLV(buf, cp, contentEnd, depth + 1, maxDepth, ber, strDepth, ctr);
        intrinsic.append(children, child.node);
        cp = child.end;
      }
      end = contentEnd;
    }
  } else {
    content = buf.subarray(contentStart, contentEnd);
    end = contentEnd;
  }

  var node = {
    tagClass:     _className(tagClassBits),
    constructed:  constructed,
    tagNumber:    tagNumber,
    length:       contentEnd - contentStart,
    header:       { start: start, end: contentStart },
    contentStart: contentStart,
    contentEnd:   contentEnd,
    content:      content,
    children:     children,
    bytes:        buf.subarray(start, end),
  };

  if (ber && constructed && tagClassBits === CLASS_UNIVERSAL && tagNumber === TAGS.OCTET_STRING) {
    var segments = [];
    for (var s = 0; s < children.length; s++) {
      if (children[s].tagClass !== "universal" || children[s].tagNumber !== TAGS.OCTET_STRING) {
        throw new Asn1Error("asn1/bad-constructed-string", "a constructed OCTET STRING segment must itself be an OCTET STRING");
      }
      intrinsic.append(segments, children[s].content);
    }
    node.content = intrinsic.bufferConcat(segments);
    node.constructed = false;
    node.children = null;
  }
  if (ber && constructed && tagClassBits === CLASS_CONTEXT && node.children) {
    node.ber = true;
  }
  return { node: node, end: end };
}


function _expectUniversal(node, tag, who) {
  if (node.tagClass !== "universal" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", who + ": expected universal tag " + tag +
      ", got " + node.tagClass + "/" + node.tagNumber);
  }
}

function _expectPrimitive(node, who) {
  if (node.constructed) throw new Asn1Error("asn1/expected-primitive", who + ": expected a primitive encoding");
}


function readBoolean(node) {
  _expectUniversal(node, TAGS.BOOLEAN, "readBoolean");
  _expectPrimitive(node, "readBoolean");
  if (node.content.length !== 1) throw new Asn1Error("asn1/bad-boolean", "BOOLEAN content must be 1 octet");
  var v = node.content[0];
  if (v === 0x00) return false;
  if (v === 0xff) return true;
  throw new Asn1Error("asn1/bad-boolean", "DER BOOLEAN must be 0x00 or 0xFF, got 0x" + v.toString(16));
}

function _readIntegerLikeContent(node, typeName, who) {
  _expectPrimitive(node, who);
  var c = node.content;
  if (c.length === 0) throw new Asn1Error("asn1/bad-integer", typeName + " must have at least 1 content octet");
  if (c.length > constants.LIMITS.DER_MAX_INTEGER_BYTES + 1) {
    throw new Asn1Error("asn1/integer-too-large",
      typeName + " content " + c.length + " bytes exceeds cap " + (constants.LIMITS.DER_MAX_INTEGER_BYTES + 1));
  }
  if (c.length > 1) {
    if (c[0] === 0x00 && (c[1] & 0x80) === 0) throw new Asn1Error("asn1/non-minimal-integer", "non-minimal positive " + typeName);
    if (c[0] === 0xff && (c[1] & 0x80) !== 0) throw new Asn1Error("asn1/non-minimal-integer", "non-minimal negative " + typeName);
  }
  var neg = (c[0] & 0x80) !== 0;
  var mag = c.length ? BigInt("0x" + Buffer.from(c).toString("hex")) : 0n;
  return neg ? mag - (1n << BigInt(c.length * 8)) : mag;
}

function readInteger(node) {
  _expectUniversal(node, TAGS.INTEGER, "readInteger");
  return _readIntegerLikeContent(node, "INTEGER", "readInteger");
}

function readEnumerated(node) {
  _expectUniversal(node, TAGS.ENUMERATED, "readEnumerated");
  return _readIntegerLikeContent(node, "ENUMERATED", "readEnumerated");
}

function readIntegerImplicit(node, tag) {
  if (node.tagClass !== "context" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", "readIntegerImplicit: expected context tag [" + tag +
      "], got " + node.tagClass + "/" + node.tagNumber);
  }
  return _readIntegerLikeContent(node, "INTEGER", "readIntegerImplicit");
}

function _readBitStringContent(node, who) {
  _expectPrimitive(node, who);
  var c = node.content;
  if (c.length === 0) throw new Asn1Error("asn1/bad-bit-string", "BIT STRING must have >= 1 content octet");
  var unusedBits = c[0];
  if (unusedBits > 7) throw new Asn1Error("asn1/bad-bit-string", "unused-bit count " + unusedBits + " > 7");
  if (unusedBits > 0 && c.length === 1) throw new Asn1Error("asn1/bad-bit-string", "unused bits declared over an empty body");
  if (unusedBits > 0 && c.length > 1) {
    var mask = (1 << unusedBits) - 1;
    if ((c[c.length - 1] & mask) !== 0) throw new Asn1Error("asn1/bad-bit-string", "DER requires unused bits to be zero");
  }
  return { unusedBits: unusedBits, bytes: c.subarray(1) };
}

function readBitString(node) {
  _expectUniversal(node, TAGS.BIT_STRING, "readBitString");
  return _readBitStringContent(node, "readBitString");
}

function readBitStringImplicit(node, tag) {
  if (node.tagClass !== "context" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", "readBitStringImplicit: expected context tag [" + tag +
      "], got " + node.tagClass + "/" + node.tagNumber);
  }
  return _readBitStringContent(node, "readBitStringImplicit");
}

function readOctetString(node) {
  _expectUniversal(node, TAGS.OCTET_STRING, "readOctetString");
  _expectPrimitive(node, "readOctetString");
  return node.content;
}

function readOctetStringImplicit(node, tag) {
  if (node.tagClass !== "context" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", "readOctetStringImplicit: expected context tag [" + tag +
      "], got " + node.tagClass + "/" + node.tagNumber);
  }
  if (node.constructed && node.ber === true) {
    var segments = [];
    for (var s = 0; s < node.children.length; s++) {
      var seg = node.children[s];
      if (seg.tagClass !== "universal" || seg.tagNumber !== TAGS.OCTET_STRING || seg.constructed || !seg.content) {
        throw new Asn1Error("asn1/bad-constructed-string", "a constructed OCTET STRING segment must itself be an OCTET STRING");
      }
      intrinsic.append(segments, seg.content);
    }
    return intrinsic.bufferConcat(segments);
  }
  _expectPrimitive(node, "readOctetStringImplicit");
  return node.content;
}

function readNull(node) {
  _expectUniversal(node, TAGS.NULL, "readNull");
  _expectPrimitive(node, "readNull");
  if (node.content.length !== 0) throw new Asn1Error("asn1/bad-null", "NULL must have empty content");
  return null;
}

function readBooleanImplicit(node, tag) {
  if (node.tagClass !== "context" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", "readBooleanImplicit: expected context tag [" + tag +
      "], got " + node.tagClass + "/" + node.tagNumber);
  }
  _expectPrimitive(node, "readBooleanImplicit");
  if (node.content.length !== 1) throw new Asn1Error("asn1/bad-boolean", "BOOLEAN content must be 1 octet");
  var v = node.content[0];
  if (v === 0x00) return false;
  if (v === 0xff) return true;
  throw new Asn1Error("asn1/bad-boolean", "DER BOOLEAN must be 0x00 or 0xFF, got 0x" + v.toString(16));
}

function readNullImplicit(node, tag) {
  if (node.tagClass !== "context" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", "readNullImplicit: expected context tag [" + tag +
      "], got " + node.tagClass + "/" + node.tagNumber);
  }
  _expectPrimitive(node, "readNullImplicit");
  if (node.content.length !== 0) throw new Asn1Error("asn1/bad-null", "IMPLICIT NULL must have empty content");
  return null;
}

/**
 * @primitive  pki.asn1.read.oid
 * @signature  pki.asn1.read.oid(node) -> "1.2.840.113549.1.1.11"
 * @since      0.1.15
 * @originated 0.1.0
 * @status     stable
 * @spec       X.690 sec. 8.19
 * @related    pki.oid.name
 *
 * Decode an OBJECT IDENTIFIER node to its dotted-decimal string, enforcing
 * the minimal base-128 sub-identifier encoding DER requires.
 *
 * @example
 *   var node = pki.asn1.decode(pki.asn1.build.oid("2.5.4.3"));
 *   pki.asn1.read.oid(node); // -> "2.5.4.3"
 */
function readOid(node) {
  _expectUniversal(node, TAGS.OBJECT_IDENTIFIER, "readOid");
  _expectPrimitive(node, "readOid");
  return decodeOidContent(node.content);
}

function decodeOidContent(buf) {
  /** @internal This verb is exported, so `buf` is a caller's object. `guard.bytes.view` refuses anything
   *  whose indexed elements are not its bytes, and `guard.bytes.lengthOf` reads the count through the
   *  captured TypedArray prototype getter, so the count and the bytes come from the same view. A Buffer
   *  accepts an own `length` property that differs from its real size, and read from `.length` a buffer
   *  whose bytes encode 1.2.840.3 and whose `length` says 3 decoded as 1.2.840. An OID selects a signature
   *  algorithm and an extension decoder, so the bytes have to decide. */
  buf = guard.bytes.view(buf, OidError, "oid/bad-input", "OBJECT IDENTIFIER content");
  var len = guard.bytes.lengthOf(buf);
  if (len === 0) throw new OidError("oid/empty", "OBJECT IDENTIFIER content is empty");
  var arcs = [];
  var arcStart = 0;
  for (var i = 0; i < len; i++) {
    var b = buf[i];
    if (i === arcStart && b === 0x80) throw new OidError("oid/non-minimal", "non-minimal sub-identifier (leading 0x80)");
    if (i - arcStart >= constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES) {
      throw new OidError("oid/subidentifier-too-large",
        "OID sub-identifier exceeds " + constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES + " octets");
    }
    if ((b & 0x80) === 0) {
      if (arcs.length >= constants.LIMITS.OID_MAX_SUBIDENTIFIERS) {
        throw new OidError("oid/too-many-subidentifiers",
          "OBJECT IDENTIFIER carries more than " + constants.LIMITS.OID_MAX_SUBIDENTIFIERS + " sub-identifiers");
      }
      var value = 0n;
      /** @internal The arc is accumulated through the captured conversion. Read off the global, a
       *  replacement decides the sub-identifier, and therefore the dotted string every algorithm and
       *  extension decision in this toolkit is made on: measured, the same two bytes rendered as
       *  `1.2.3` and as `1.2.4`. */
      for (var k = arcStart; k <= i; k++) value = value * 128n + intrinsic.BigInt(buf[k] & 0x7f);
      /** @internal `append`, not a captured `push`: appending with `push` STORES at the index, and a
       *  store walks the prototype chain for a setter, so an accessor installed at
       *  `Array.prototype[0]` took the arc and answered with another. `append` defines the index on
       *  the array itself. */
      intrinsic.append(arcs, value);
      arcStart = i + 1;
    }
  }
  if (arcStart !== len) throw new OidError("oid/truncated", "OBJECT IDENTIFIER ends mid sub-identifier");
  var first = arcs[0];
  var a1, a2;
  if (first < 40n) { a1 = 0n; a2 = first; }
  else if (first < 80n) { a1 = 1n; a2 = first - 40n; }
  else { a1 = 2n; a2 = first - 80n; }
  /** @internal Each arc is rendered through the captured conversion. Read off the prototype, the
   *  value that becomes the dotted identifier is whatever a replacement returns, and the identifier
   *  is what every algorithm and extension decision in this toolkit is made on. */
  var out = [intrinsic.bigIntToString(a1, 10), intrinsic.bigIntToString(a2, 10)];
  for (var j = 1; j < arcs.length; j++) intrinsic.append(out, intrinsic.bigIntToString(arcs[j], 10));
  return intrinsic.join(out, ".");
}

function _decodeText(buf, encoding) {
  return buf.toString(encoding);
}

function _decodeIa5(buf) {
  for (var i = 0; i < buf.length; i++) {
    if (buf[i] > 0x7F) throw new Asn1Error("asn1/bad-ia5-string", "IA5String requires 7-bit ASCII");
  }
  return buf.toString("latin1");
}

function _decodeVisible(buf) {
  for (var i = 0; i < buf.length; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7E) throw new Asn1Error("asn1/bad-visible-string", "VisibleString must be 0x20..0x7E");
  }
  return buf.toString("latin1");
}

function _decodePrintable(buf) {
  var s = buf.toString("latin1");
  if (!isPrintableString(s)) throw new Asn1Error("asn1/bad-printable-string", "PrintableString has characters outside the restricted set");
  return s;
}

function readNumericString(node) {
  _expectUniversal(node, TAGS.NUMERIC_STRING, "readNumericString");
  _expectPrimitive(node, "readNumericString");
  var s = node.content.toString("latin1");
  if (!_isNumericString(s)) throw new Asn1Error("asn1/bad-numeric-string", "NumericString has characters outside the digits-and-space set");
  return s;
}

/** @internal An unpaired surrogate has no UTF-8 encoding. Converting one anyway substitutes U+FFFD,
 *  so the bytes written would not carry the string the caller handed in, and `_decodeUtf8Strict`
 *  refuses exactly those bytes on the way back. The builder answers the same way rather than
 *  silently changing the text, which is the rule `_decodeUtf16be` already applies to BMPString. */
/** @internal @guard-via guard\.text\.assertWellFormedUtf16\( */
function _assertWellFormedUtf16(s) {
  return guard.text.assertWellFormedUtf16(s, Asn1Error, "asn1/bad-utf8-string", "UTF8String");
}

function _decodeUtf8Strict(buf) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf);
  } catch (_e) {
    throw new Asn1Error("asn1/bad-utf8-string", "invalid UTF-8 in UTF8String");
  }
}

function readString(node) {
  if (node.tagClass !== "universal") throw new Asn1Error("asn1/expected-string", "readString: not a universal string type");
  _expectPrimitive(node, "readString");
  switch (node.tagNumber) {
    case TAGS.UTF8_STRING:      return _decodeUtf8Strict(node.content);
    case TAGS.PRINTABLE_STRING: return _decodePrintable(node.content);
    case TAGS.IA5_STRING:       return _decodeIa5(node.content);
    case TAGS.TELETEX_STRING:   return _decodeText(node.content, "latin1");
    case TAGS.VISIBLE_STRING:   return _decodeVisible(node.content);
    case TAGS.BMP_STRING:       return _decodeUtf16be(node.content);
    case TAGS.UNIVERSAL_STRING: return _decodeUtf32be(node.content);
    default:
      throw new Asn1Error("asn1/expected-string", "readString: tag " + node.tagNumber + " is not a known string type");
  }
}

function _decodeUtf16be(buf) {
  if (buf.length % 2 !== 0) throw new Asn1Error("asn1/bad-bmp-string", "BMPString length must be even");
  for (var i = 0; i < buf.length; i += 2) {
    var u = (buf[i] << 8) | buf[i + 1];
    if (u >= 0xD800 && u <= 0xDFFF) throw new Asn1Error("asn1/bad-bmp-string", "code point out of range");
  }
  var swapped = Buffer.from(buf);
  swapped.swap16();
  return swapped.toString("utf16le");
}

function _decodeUtf32be(buf) {
  if (buf.length % 4 !== 0) throw new Asn1Error("asn1/bad-universal-string", "UniversalString length must be a multiple of 4");
  var out = "";
  for (var i = 0; i < buf.length; i += 4) {
    var cp = (buf[i] * 0x1000000) + (buf[i + 1] << 16) + (buf[i + 2] << 8) + buf[i + 3];
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
      throw new Asn1Error("asn1/bad-universal-string", "code point out of range");
    }
    out += String.fromCodePoint(cp);
  }
  return out;
}

function _digitsToInt(s, start, count) {
  if (start + count > s.length) return null;
  var v = 0;
  for (var i = 0; i < count; i++) {
    var c = _charCodeAt(s, start + i);
    if (c < 48 || c > 57) return null;
    v = v * 10 + (c - 48);
  }
  return v;
}

function _scanTimeFields(s, yearLen, allowFrac) {
  var pos = 0;
  var year = _digitsToInt(s, pos, yearLen); if (year === null) return null; pos += yearLen;
  var month = _digitsToInt(s, pos, 2); if (month === null) return null; pos += 2;
  var day = _digitsToInt(s, pos, 2); if (day === null) return null; pos += 2;
  var hour = _digitsToInt(s, pos, 2); if (hour === null) return null; pos += 2;
  var min = _digitsToInt(s, pos, 2); if (min === null) return null; pos += 2;
  var sec = _digitsToInt(s, pos, 2); if (sec === null) return null; pos += 2;
  var hasFrac = false, ms = 0, fracLastIsZero = false;
  if (allowFrac) {
    if (_charCodeAt(s, pos) !== 46) return null;
    pos += 1;
    var f = [0, 0, 0], fi = 0;
    while (pos < s.length) {
      var c = _charCodeAt(s, pos);
      if (c < 48 || c > 57) break;
      if (fi < 3) f[fi] = c - 48;
      fi += 1; pos += 1;
    }
    if (fi === 0) return null;
    hasFrac = true;
    fracLastIsZero = _charCodeAt(s, pos - 1) === 48;
    ms = f[0] * 100 + f[1] * 10 + f[2];
  }
  if (pos !== s.length - 1 || _charCodeAt(s, pos) !== 90) return null;
  return { year: year, month: month, day: day, hour: hour, min: min, sec: sec,
           hasFrac: hasFrac, ms: ms, fracLastIsZero: fracLastIsZero };
}

function readTime(node, opts) {
  if (node.tagClass !== "universal") throw new Asn1Error("asn1/expected-time", "readTime: not a universal time type");
  _expectPrimitive(node, "readTime");
  var s = node.content.toString("latin1");
  var t, year;
  if (node.tagNumber === TAGS.UTC_TIME) {
    t = _scanTimeFields(s, 2, false);
    if (!t) throw new Asn1Error("asn1/bad-utctime", "UTCTime must be YYMMDDHHMMSSZ, got " + JSON.stringify(s));
    year = t.year;
    year += (year < 50) ? 2000 : 1900;
  } else if (node.tagNumber === TAGS.GENERALIZED_TIME) {
    t = _scanTimeFields(s, 4, false);
    if (!t) {
      if (!(opts && opts.allowFractional)) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime must be YYYYMMDDHHMMSSZ, got " + JSON.stringify(s));
      t = _scanTimeFields(s, 4, true);
      if (!t) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime must be YYYYMMDDHHMMSS[.fraction]Z, got " + JSON.stringify(s));
      if (t.fracLastIsZero) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime fraction must not have trailing zeros, got " + JSON.stringify(s));
    }
    year = t.year;
  } else {
    throw new Asn1Error("asn1/expected-time", "readTime: tag " + node.tagNumber + " is not a time type");
  }
  var month = t.month;
  var day   = t.day;
  var hour  = t.hour;
  var min   = t.min;
  var sec   = t.sec;
  var ms = (node.tagNumber === TAGS.GENERALIZED_TIME && t.hasFrac) ? t.ms : 0;
  var d = new Date(0);
  _dateSetUTCFullYear(d, year, month - 1, day);
  _dateSetUTCHours(d, hour, min, sec, ms);
  if (isNaN(guard.time.instantOf(d))) throw new Asn1Error("asn1/bad-time", "unparseable time " + JSON.stringify(s));
  if (_dateGetUTCFullYear(d) !== year || _dateGetUTCMonth(d) !== month - 1 || _dateGetUTCDate(d) !== day ||
      _dateGetUTCHours(d) !== hour || _dateGetUTCMinutes(d) !== min || _dateGetUTCSeconds(d) !== sec) {
    throw new Asn1Error("asn1/bad-time", "time component out of range " + JSON.stringify(s));
  }
  return d;
}


function encodeLength(n) {
  if (typeof n !== "number" || !isFinite(n) || n < 0 || Math.floor(n) !== n) {
    throw new Asn1Error("asn1/bad-length", "length must be a non-negative integer");
  }
  if (n < 0x80) return intrinsic.bufferFrom([n]);
  /** @internal The octets are counted and then written into the output from its end, rather than
   *  prepended into an array. A prepend STORES at an index, and a store walks the prototype chain
   *  for a setter, so an accessor at an array index took each octet as it was produced and left the
   *  list reading back whatever its getter answers. These are the length octets of every DER element
   *  longer than 127 bytes: measured, a SEQUENCE wrapping a 300-byte OCTET STRING emitted as `3000`,
   *  an empty SEQUENCE. A typed array handles its own integer-indexed writes and consults no
   *  prototype accessor, which is why the output is filled directly. */
  var count = 0;
  for (var probe = n; probe > 0; probe = intrinsic.floor(probe / 256)) count++;
  if (count > 126) throw new Asn1Error("asn1/length-too-large", "length needs more than 126 octets");
  var out = intrinsic.bufferAlloc(count + 1);
  out[0] = 0x80 | count;
  var v = n;
  for (var i = count; i >= 1; i--) { out[i] = v & 0xff; v = intrinsic.floor(v / 256); }
  return out;
}

/** @internal The identifier comes from the one function that composes one. Writing the octet here
 *  instead put a second author of an identifier in the file, and it answered differently: with
 *  `TAGS.SEQUENCE` reassigned to 15 this emitted `2f00`, which `decode` refuses, while every
 *  `build.*` helper routed through `encodeIdentifier` and refused it. */
function sequenceTlv(node) {
  var content = node.content != null ? node.content : Buffer.concat((node.children || []).map(function (c) { return c.bytes; }));
  return Buffer.concat([encodeIdentifier(CLASS_UNIVERSAL, true, TAGS.SEQUENCE), encodeLength(content.length), content]);
}

/** @internal A constructed value written into ONE allocation, rather than concatenating the children
 * and then concatenating that with the header. The two-step form leaves an intermediate holding
 * everything the children carry; where they carry private material that intermediate is a copy of it
 * no caller can reach to clear, since it is a local here and becomes garbage on return. Its output is
 * byte-identical to the two-step form: the same identifier, the same length, the same children in
 * the same order. */
function encodeConstructed(classBits, tagNumber, parts) {
  var total = 0;
  for (var i = 0; i < parts.length; i++) total += parts[i].length;
  var id = encodeIdentifier(classBits, true, tagNumber);
  var len = encodeLength(total);
  var out = intrinsic.bufferAlloc(id.length + len.length + total);
  intrinsic.typedArraySet(out, id, 0);
  intrinsic.typedArraySet(out, len, id.length);
  var at = id.length + len.length;
  for (var j = 0; j < parts.length; j++) {
    intrinsic.typedArraySet(out, parts[j], at);
    at += parts[j].length;
  }
  return out;
}

function encodeIdentifier(classBits, constructed, tagNumber) {
  if (typeof tagNumber !== "number" || !isFinite(tagNumber) || tagNumber < 0 || Math.floor(tagNumber) !== tagNumber) {
    throw new Asn1Error("asn1/bad-tag", "tag number must be a non-negative integer");
  }
  /** @internal The class bits are taken ONCE, into the number the checks and the emitted octet all
   *  use, and then checked to be a class. The low five bits of this argument are OR'd into the
   *  single-octet identifier, so a `classBits` carrying any of them emits a DIFFERENT tag than the
   *  one handed in: `encodeIdentifier(0x0e, false, 1)` wrote `0f`, universal 15, past a reserved-tag
   *  check that had been shown tag 1. The four class values are the whole domain, with the
   *  constructed bit allowed alongside because a caller may fold it in rather than pass it. */
  var cls = classBits | 0;
  if (typeof classBits !== "number" || cls !== classBits ||
      (cls & ~(CLASS_MASK | CONSTRUCTED_BIT)) !== 0) {
    throw new Asn1Error("asn1/bad-tag", "class bits must be one of 0x00 universal, 0x40 application, " +
      "0x80 context or 0xc0 private, optionally with 0x20 constructed, got " + _typeOf(classBits));
  }
  /** @internal The size bound before the reserved rows, which is the order the decoder refuses them
   *  in: a tag past the four-octet high-tag form it reads is unreadable whatever the table says
   *  about the number, so both directions name `asn1/tag-too-large` for it and the reserved code
   *  keeps meaning that X.680 reserved the row. 0x0fffffff is the largest number four 7-bit octets
   *  hold, so this is the bound the body-length check below expressed. */
  if (tagNumber > 0x0fffffff) throw new Asn1Error("asn1/tag-too-large", "high-tag-number too large");
  /** @internal The reserved rows, refused in BOTH directions. X.680 Table 1 assigns no type to
   *  universal 0, 15, or 37 upward, so there is no encoding of any type for `decode` to accept and
   *  it refuses all three; emitting them anyway hands a caller bytes this codec's own decoder calls
   *  malformed. The DER FORM rules are deliberately NOT enforced here: a constructed OCTET STRING or
   *  string type is a legitimate BER encoding (X.690 sec. 8.21.1) that DER alone restricts to the
   *  primitive form (sec. 10.2), and this encoder is the escape hatch those bytes are minted through
   *  for the BER door that reads them. A tag number that encodes nothing is a different thing from a
   *  form one encoding rule allows and another does not. */
  if ((cls & CLASS_MASK) === CLASS_UNIVERSAL && reservedUniversalTag(tagNumber)) {
    throw new Asn1Error("asn1/reserved-tag", "universal tag " + tagNumber + " is reserved by X.680 " +
      "Table 1 (" + (tagNumber === 0 ? "for the encoding rules, which give 00 00 to the " +
      "end-of-contents marker" : tagNumber === 15 ? "for future editions" : "for addenda") +
      ") and is not assigned to any type, so no encoding of it is a DER element");
  }
  var lead = cls | (constructed ? CONSTRUCTED_BIT : 0);
  if (tagNumber < 0x1f) return intrinsic.bufferFrom([lead | tagNumber]);
  /** @internal Counted, then written into the output from its end, for the reason `encodeLength` is:
   *  a prepend stores at an index and a store consults a setter inherited there. These are the
   *  identifier octets of a high-tag-number element, so they name the type every reader dispatches
   *  on: measured, tag 31 emitted as `1f00`. Every octet but the last carries the continuation bit. */
  var count = 0;
  for (var probe = tagNumber; ; probe = intrinsic.floor(probe / 128)) {
    count++;
    if (probe < 128) break;
  }
  var out = intrinsic.bufferAlloc(count + 1);
  out[0] = lead | 0x1f;
  var v = tagNumber;
  for (var i = count; i >= 1; i--) {
    out[i] = (v & 0x7f) | (i === count ? 0x00 : 0x80);
    v = intrinsic.floor(v / 128);
  }
  return out;
}

/**
 * @primitive  pki.asn1.encode
 * @signature  pki.asn1.encode(classBits, constructed, tagNumber, content) -> Buffer
 * @since      0.1.0
 * @status     stable
 * @spec       X.690, ISO/IEC 8825-1
 * @related    pki.asn1.decode
 *
 * Low-level TLV encoder: prepend the identifier + DER length to a content
 * buffer. Most callers use the higher-level `build.*` helpers; this is the
 * escape hatch for context-tagged and implicitly-tagged constructions.
 *
 * `classBits` is a number naming a class: `0x00` universal, `0x40`
 * application, `0x80` context or `0xc0` private, with `0x20` constructed
 * allowed alongside. Anything else is `asn1/bad-tag`, because the low five
 * bits of this argument are written into a single-octet identifier and a
 * value carrying any of them emits a tag other than the one passed.
 *
 * A universal-class tag number that X.680 Table 1 reserves is refused with
 * `asn1/reserved-tag`, the code `pki.asn1.decode` gives the same bytes, so the
 * escape hatch cannot author an element the decoder calls malformed. Ask
 * `pki.asn1.reservedUniversalTag` which numbers those are. Every other class
 * takes any tag number the 4-octet high-tag form holds, a context `[15]`
 * included; past that form the code is `asn1/tag-too-large`, as it is on the
 * way in. The DER form restrictions are not applied here: a constructed
 * OCTET STRING or character string is a legal BER encoding, and this is the
 * door it is written through.
 *
 * @example
 *   pki.asn1.encode(0x00, false, pki.asn1.TAGS.NULL, Buffer.alloc(0));
 */
function encodeTLV(classBits, constructed, tagNumber, content) {
  var body = _contentBytes(content);
  var id = encodeIdentifier(classBits, constructed, tagNumber);
  return Buffer.concat([id, encodeLength(body.length), body]);
}

function _universal(tagNumber, constructed, content) {
  return encodeTLV(CLASS_UNIVERSAL, constructed, tagNumber, content);
}

/** @internal Content is bytes. A value that is not bytes reaches the structure as whatever the
 *  byte conversion makes of it: a string as its UTF-8 encoding, an object through its `valueOf`,
 *  an array element past 255 as that element modulo 256. A byte source and a list of byte values
 *  are the two spellings this takes; an omitted content is the empty one. */
function _contentBytes(content) {
  if (content == null) return intrinsic.bufferAlloc(0);
  if (guard.bytes.isByteSource(content)) {
    return guard.bytes.source(content, Asn1Error, "asn1/not-buffer", "encodeTLV content");
  }
  if (!intrinsic.isArray(content)) {
    throw new Asn1Error("asn1/not-buffer", "encodeTLV content: the content must be bytes, got " + _typeOf(content));
  }
  /** @internal Each element is read ONCE, into the byte the check and the content both use. Read
   *  again to copy, an element answering from a getter could pass the check as 2 and be written
   *  as 300, which the copy would narrow to 44. */
  var n = content.length;
  var out = intrinsic.bufferAlloc(n);
  for (var i = 0; i < n; i++) {
    var b = content[i];
    if (typeof b !== "number" || !intrinsic.isSafeInteger(b) || b < 0 || b > 255) {
      throw new Asn1Error("asn1/not-buffer", "encodeTLV content: element " + i + " is not a byte value 0 to 255");
    }
    out[i] = b;
  }
  return out;
}

/** @internal A string builder encodes the caller's text. Turning something else into text encodes
 *  a value the caller never named: an object arrives as its default string form, a list as its
 *  members joined with a comma, and the structure carries that. The value is required to be a
 *  string rather than made into one, which also settles what a value with a `toString` answers,
 *  since a string cannot answer differently between a check and the encoding. */
function _asString(s, who) {
  if (typeof s !== "string") {
    throw new Asn1Error("asn1/bad-string", who + ": the value must be a string, got " + _typeOf(s));
  }
  return s;
}

function _typeOf(v) {
  if (v === null) return "null";
  if (intrinsic.isBuffer(v)) return "a Buffer";
  if (intrinsic.isArray(v)) return "an array";
  var t = typeof v;
  return (t === "object" || t === "undefined" ? "an " : "a ") + t;
}

function intToDer(v) {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Asn1Error("asn1/bad-integer", "unsafe integer; pass a BigInt");
    v = BigInt(v);
  }
  if (typeof v !== "bigint") throw new Asn1Error("asn1/bad-integer", "integer must be number or BigInt");
  if (v === 0n) return intrinsic.bufferFrom([0]);
  /** @internal The content octets are written into the output directly, in both signs. The positive
   *  branch prepended into an array and then read `bytes[0]` to decide whether the value needed a
   *  leading zero to read as positive, and the negative branch stored at each index; both are stores,
   *  so an accessor inherited at an array index took the octets and answered the decision. Measured:
   *  128 encoded as the INTEGER 0, a nine-digit value as all zeroes, and -300 as +212. A typed array
   *  consults no prototype accessor for an integer-indexed write, and `bufferAlloc` zero-fills, so
   *  the leading zero is the allocation rather than a second prepend. */
  if (v > 0n) {
    var n = 0;
    for (var t = v; t > 0n; t >>= 8n) n++;
    var pad = ((v >> intrinsic.BigInt(8 * (n - 1))) & 0xffn) >= 0x80n ? 1 : 0;
    var outP = intrinsic.bufferAlloc(n + pad);
    var tp = v;
    for (var i = n + pad - 1; i >= pad; i--) { outP[i] = intrinsic.Number(tp & 0xffn); tp >>= 8n; }
    return outP;
  }
  var len = 1;
  while (v < -(1n << intrinsic.BigInt(8 * len - 1))) len += 1;
  var tc = (1n << intrinsic.BigInt(8 * len)) + v;
  var outN = intrinsic.bufferAlloc(len);
  for (var j = len - 1; j >= 0; j--) { outN[j] = intrinsic.Number(tc & 0xffn); tc >>= 8n; }
  return outN;
}

function encodeOidContent(dotted) {
  guard.identifier.assertCanonicalOid(dotted, _oidErr, "oid/bad-input", "OID", "oid/bad-arc", "oid/too-many-subidentifiers");
  var arcs = dotted.split(".").map(function (p) { return BigInt(p); });
  var a1 = arcs[0], a2 = arcs[1];
  /** @internal The sub-identifier list through the capture: assembled by a live
   *  `Array.prototype.concat`, the arcs this encodes were that method's to choose, and the result is
   *  the OID a signature or an algorithm is named by. */
  var subids = intrinsic.concat([a1 * 40n + a2], arcs.slice(2));
  var out = [];
  for (var s = 0; s < subids.length; s++) {
    var v = subids[s];
    /** @internal Each sub-identifier's octets are counted and then appended most-significant first,
     *  rather than prepended into a list and patched in place. A prepend stores at an index, and the
     *  continuation bit was then set by a read-modify-write that read back through the hole a store
     *  leaves under an inherited setter. This is the OID an algorithm or a signature is named by:
     *  measured, sha256WithRSAEncryption emitted as `0609000000008000000000`, a different OID. */
    var count = 1;
    for (var probe = v >> 7n; probe > 0n; probe >>= 7n) count++;
    if (count > constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES) {
      throw new OidError("oid/subidentifier-too-large",
        "OID sub-identifier exceeds " + constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES + " octets");
    }
    for (var k = count - 1; k >= 0; k--) {
      var octet = intrinsic.Number((v >> intrinsic.BigInt(7 * k)) & 0x7fn);
      intrinsic.append(out, k === 0 ? octet : octet | 0x80);
    }
  }
  return Buffer.from(out);
}

function _isPrintableChar(c) {
  if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57)) return true;
  switch (c) {
    case 32: case 39: case 40: case 41: case 43: case 44: case 45: case 46: case 47:
    case 58: case 61: case 63:
      return true;
    default: return false;
  }
}
function isPrintableString(s) {
  if (typeof s !== "string") return false;
  for (var i = 0; i < s.length; i += 1) if (!_isPrintableChar(_charCodeAt(s, i))) return false;
  return true;
}
function _isNumericString(s) {
  for (var i = 0, c; i < s.length; i += 1) { c = _charCodeAt(s, i); if (!((c >= 48 && c <= 57) || c === 32)) return false; }
  return true;
}

function _fmtTwo(n) { return (n < 10 ? "0" : "") + n; }

function _generalizedTimeString(date, fractional) {
  var y = _dateGetUTCFullYear(date);
  if (y < 0 || y > 9999) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime year " + y + " outside 0000..9999");
  var yyyy = ("000" + y).slice(-4);
  return yyyy +
    _fmtTwo(_dateGetUTCMonth(date) + 1) + _fmtTwo(_dateGetUTCDate(date)) +
    _fmtTwo(_dateGetUTCHours(date)) + _fmtTwo(_dateGetUTCMinutes(date)) + _fmtTwo(_dateGetUTCSeconds(date)) +
    (fractional ? _fractionString(_dateGetUTCMilliseconds(date)) : "") + "Z";
}
/** @internal X.690 sec. 11.7 as RFC 3161 sec. 2.4.2 restates it for a DER GeneralizedTime: the
 * fraction, when present, follows a point and carries no trailing zeros; a zero fraction and its
 * point are omitted. A Date resolves to milliseconds, so the fraction is at most three digits. */
function _fractionString(ms) {
  if (ms === 0) return "";
  var digits = (ms < 10 ? "00" : ms < 100 ? "0" : "") + ms;
  var end = digits.length;
  while (end > 0 && _charCodeAt(digits, end - 1) === 0x30) end--;
  var out = ".";
  for (var i = 0; i < end; i++) out += digits[i];
  return out;
}
var _GENERALIZED_TIME_OPTS = intrinsic.create(null);
_GENERALIZED_TIME_OPTS.fractional = 1;
function _generalizedTimeOptions(opts) {
  if (opts === undefined || opts === null) return false;
  if (typeof opts !== "object") throw new Asn1Error("asn1/bad-generalizedtime", "build.generalizedTime options must be an object");
  guard.identifier.assertKnownKeys(opts, _GENERALIZED_TIME_OPTS, function (code, message) { return new Asn1Error(code, message); },
    "asn1/bad-generalizedtime", "build.generalizedTime has an unknown option ");
  var fractional = opts.fractional;
  if (fractional !== undefined && typeof fractional !== "boolean") throw new Asn1Error("asn1/bad-generalizedtime", "build.generalizedTime fractional must be a boolean");
  return fractional === true;
}

function _utcTimeString(date) {
  var y = _dateGetUTCFullYear(date);
  if (y < 1950 || y > 2049) throw new Asn1Error("asn1/bad-utctime", "UTCTime year " + y + " outside 1950..2049; use GeneralizedTime");
  var yy = y % 100;
  return _fmtTwo(yy) +
    _fmtTwo(_dateGetUTCMonth(date) + 1) + _fmtTwo(_dateGetUTCDate(date)) +
    _fmtTwo(_dateGetUTCHours(date)) + _fmtTwo(_dateGetUTCMinutes(date)) + _fmtTwo(_dateGetUTCSeconds(date)) + "Z";
}

/**
 * @primitive  pki.asn1.build
 * @signature  pki.asn1.build.sequence([ ...tlvBuffers ]) -> Buffer
 * @since      0.1.0
 * @status     stable
 * @spec       X.690, ISO/IEC 8825-1
 * @related    pki.asn1.encode
 *
 * Canonical-DER value builders. Each returns the full TLV Buffer for one
 * value; `sequence` / `set` / `setOf` take arrays of already-built child
 * TLVs. `setOf` sorts its members by their DER encoding as X.690 requires.
 *
 * @example
 *   var rdn = pki.asn1.build.sequence([
 *     pki.asn1.build.oid("2.5.4.3"),
 *     pki.asn1.build.utf8("example.com"),
 *   ]);
 */
var build = intrinsic.assign(intrinsic.create(null), {
  boolean:  function (v) { return _universal(TAGS.BOOLEAN, false, Buffer.from([v ? 0xff : 0x00])); },
  integer:  function (v) { return _universal(TAGS.INTEGER, false, _intContent(v, "build.integer")); },
  enumerated: function (v) { return _universal(TAGS.ENUMERATED, false, _intContent(v, "build.enumerated")); },
  nullValue: function () { return _universal(TAGS.NULL, false, Buffer.alloc(0)); },
  oid:      function (dotted) { return _universal(TAGS.OBJECT_IDENTIFIER, false, encodeOidContent(dotted)); },
  octetString: function (buf) { return _universal(TAGS.OCTET_STRING, false, _asBuffer(buf, "build.octetString")); },
  bitString: function (buf, unusedBits) {
    var u = guard.limits.cap(unusedBits == null ? 0 : unusedBits, "unusedBits", 0, { E: _asn1Error, code: "asn1/bad-bit-string", min: 0, max: 7 });
    var body = _asBuffer(buf, "build.bitString");
    if (u > 0 && body.length === 0) throw new Asn1Error("asn1/bad-bit-string", "empty BIT STRING must declare zero unused bits");
    if (u > 0 && body.length > 0) {
      var mask = (1 << u) - 1;
      if ((body[body.length - 1] & mask) !== 0) throw new Asn1Error("asn1/bad-bit-string", "unused bits must be zero");
    }
    return _universal(TAGS.BIT_STRING, false, Buffer.concat([Buffer.from([u]), body]));
  },
  namedBitString: function (positions) {
    if (!_isArray(positions)) throw new Asn1Error("asn1/bad-bit-string", "namedBitString requires an array of bit positions");
    var hi = -1, i, p;
    for (i = 0; i < positions.length; i++) {
      p = positions[i];
      if (typeof p !== "number" || !isFinite(p) || p < 0 || (p | 0) !== p) throw new Asn1Error("asn1/bad-bit-string", "a named-bit position must be a non-negative integer");
      if (p > hi) hi = p;
    }
    if (hi < 0) return build.bitString(Buffer.alloc(0), 0);
    var buf = Buffer.alloc((hi >> 3) + 1);
    for (i = 0; i < positions.length; i++) { p = positions[i]; buf[p >> 3] |= 0x80 >> (p & 7); }
    return build.bitString(buf, 7 - (hi & 7));
  },
  utf8:     function (s) { var v = _asString(s, "build.utf8"); _assertWellFormedUtf16(v); return _universal(TAGS.UTF8_STRING, false, Buffer.from(v, "utf8")); },
  ia5:      function (s) {
    s = _asString(s, "build.ia5");
    for (var i = 0; i < s.length; i++) {
      if (_charCodeAt(s, i) > 0x7F) throw new Asn1Error("asn1/bad-ia5-string", "IA5String requires 7-bit ASCII");
    }
    return _universal(TAGS.IA5_STRING, false, Buffer.from(s, "latin1"));
  },
  printable: function (s) {
    s = _asString(s, "build.printable");
    if (!isPrintableString(s)) throw new Asn1Error("asn1/bad-printable-string", "value has characters outside the PrintableString set");
    return _universal(TAGS.PRINTABLE_STRING, false, Buffer.from(s, "latin1"));
  },
  bmpString: function (s) {
    s = _asString(s, "build.bmpString");
    var out = Buffer.alloc(s.length * 2);
    for (var i = 0; i < s.length; i++) {
      var u = _charCodeAt(s, i);
      if (u >= 0xD800 && u <= 0xDFFF) throw new Asn1Error("asn1/bad-bmp-string", "BMPString cannot encode a surrogate code point (non-BMP characters are unsupported)");
      out[i * 2] = (u >> 8) & 0xFF;
      out[i * 2 + 1] = u & 0xFF;
    }
    return _universal(TAGS.BMP_STRING, false, out);
  },
  utcTime:  function (date) { return _universal(TAGS.UTC_TIME, false, Buffer.from(_utcTimeString(date), "latin1")); },
  generalizedTime: function (date, opts) { return _universal(TAGS.GENERALIZED_TIME, false, Buffer.from(_generalizedTimeString(date, _generalizedTimeOptions(opts)), "latin1")); },
  sequence: function (children) {
    return encodeConstructed(CLASS_UNIVERSAL, TAGS.SEQUENCE, _asBufferArray(children, "build.sequence"));
  },
  /** @internal The DER SET ordering goes through the captured copy-and-sort. Read off
   *  `Array.prototype`, `slice` and `sort` decide the bytes every SET OF in the toolkit emits, and these
   *  two builders are where nearly all of them are built: a replacement reorders or substitutes members
   *  after whatever validated them, on content a caller goes on to sign. */
  /** @internal The COMPARATOR goes through the captured operation, as the copy and the sort beside it
   *  do. A DER SET OF is ordered by its members' encoded bytes, so whatever decides "before" decides
   *  the bytes emitted: a replacement answering a fixed order sets the order of every SET and SET OF
   *  this toolkit builds, after whatever validated the members and on bytes a verb then signs. */
  set:      function (children) {
    return encodeConstructed(CLASS_UNIVERSAL, TAGS.SET,
      guard.list.sortedCopy(_asBufferArray(children, "build.set"), intrinsic.compare));
  },
  setOf:    function (children) {
    return encodeConstructed(CLASS_UNIVERSAL, TAGS.SET,
      guard.list.sortedCopy(_asBufferArray(children, "build.setOf"), intrinsic.compare));
  },
  explicit: function (tagNumber, inner) { return encodeTLV(CLASS_CONTEXT, true, tagNumber, _asBuffer(inner, "build.explicit")); },
  contextPrimitive:   function (tagNumber, content) { return encodeTLV(CLASS_CONTEXT, false, tagNumber, _asBuffer(content, "build.contextPrimitive")); },
  contextConstructed: function (tagNumber, content) { return encodeTLV(CLASS_CONTEXT, true, tagNumber, _asBuffer(content, "build.contextConstructed")); },
  implicit: function (tagNumber, tlv) {
    var buf = _asBuffer(tlv, "build.implicit");
    var node = decode(buf);
    return encodeTLV(CLASS_CONTEXT, node.constructed, tagNumber, buf.slice(buf.length - node.length));
  },
  raw:      function (buf) { return _asBuffer(buf, "build.raw"); },
});
intrinsic.freeze(build);

function _intContent(v, who) {
  if (Buffer.isBuffer(v)) {
    if (v.length === 0) throw new Asn1Error("asn1/bad-integer", who + ": INTEGER content is empty");
    if (v.length > 1) {
      if (v[0] === 0x00 && (v[1] & 0x80) === 0) throw new Asn1Error("asn1/non-minimal-integer", who + ": non-minimal positive INTEGER");
      if (v[0] === 0xff && (v[1] & 0x80) !== 0) throw new Asn1Error("asn1/non-minimal-integer", who + ": non-minimal negative INTEGER");
    }
  }
  var content = Buffer.isBuffer(v) ? v : intToDer(v);
  if (content.length > constants.LIMITS.DER_MAX_INTEGER_BYTES + 1) {
    throw new Asn1Error("asn1/integer-too-large", who + ": INTEGER content " + content.length + " bytes exceeds cap " + (constants.LIMITS.DER_MAX_INTEGER_BYTES + 1));
  }
  return content;
}

/** @internal Walked by index rather than through the array's own `map`, which a caller can define
 *  to answer with children this never checked. Each element is read once, into the buffer the
 *  check and the encoding both use. */
function _asBufferArray(arr, who) {
  if (!_isArray(arr)) throw new Asn1Error("asn1/bad-children", who + ": expected an array of TLV buffers");
  var n = arr.length, out = [];
  /** @internal Each checked child is APPENDED by defining its index. Assigning at the index is a
   *  store, and a store walks the prototype chain for a setter, so an accessor inherited at an array
   *  index took the child and left the list reading back its getter's value instead. This list is
   *  every constructed element's children: measured, a SEQUENCE wrapping a 300-byte OCTET STRING
   *  emitted as `3000`, an empty SEQUENCE, with the checked child discarded. */
  for (var i = 0; i < n; i++) intrinsic.append(out, _asBuffer(arr[i], who));
  return out;
}

/** @internal Frozen, not merely holding frozen tables. Freezing `read` and `build` leaves the
 *  PROPERTIES that name them writable, so the whole table can be swapped for a copy carrying one
 *  changed reader: assigning `asn1.read = assign({}, asn1.read, { time: fake })` moved a stated
 *  distrust date into the future through `trust`'s time decoder. Every verb here is reached by name
 *  from another module at the call, so the object itself has to be closed. */
module.exports = intrinsic.freeze({
  TAGS:          TAGS,
  reservedUniversalTag: reservedUniversalTag,
  decode:        decode,
  isPrintableString: isPrintableString,
  encode:        encodeTLV,
  encodeTLV:     encodeTLV,
  encodeLength:  encodeLength,
  sequenceTlv:   sequenceTlv,
  encodeIdentifier: encodeIdentifier,
  decodeOidContent: decodeOidContent,
  encodeOidContent: encodeOidContent,
  build:         intrinsic.freeze(build),
  /** @internal The reader table is frozen, because every module in this toolkit reads a leaf reader
   *  off it BY NAME at the call: `asn1.read.time`, `asn1.read.oid`, `asn1.read.integer` and the rest
   *  are reached through this object hundreds of times across sixty-odd modules, and each one is the
   *  step that turns bytes into the value a check compares. A replaced `time` made a CCADB row
   *  stating a 2020 distrust date produce an anchor with a 2099 cutoff, so a root stayed trusted long
   *  past the date the row names. Freezing the table closes that for every consumer at once, which
   *  capturing the readers one module at a time cannot. */
  read: intrinsic.freeze({
    boolean:      readBoolean,
    integer:      readInteger,
    integerImplicit: readIntegerImplicit,
    enumerated:   readEnumerated,
    bitString:    readBitString,
    bitStringImplicit: readBitStringImplicit,
    octetString:  readOctetString,
    octetStringImplicit: readOctetStringImplicit,
    nullValue:    readNull,
    nullImplicit: readNullImplicit,
    booleanImplicit: readBooleanImplicit,
    oid:          readOid,
    string:       readString,
    numericString: readNumericString,
    time:         readTime,
  }),
});
