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

var Asn1Error = frameworkError.Asn1Error;
var OidError = frameworkError.OidError;

function _asn1Error(c, m) { return new Asn1Error(c, m); }

function _oidErr(c, m) { return new OidError(c, m); }


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

var TAGS = intrinsic.create(null);
Object.keys(UNIVERSAL_TYPES).forEach(function (k) { TAGS[k] = UNIVERSAL_TYPES[k].tag; });

var CLASS_UNIVERSAL   = 0x00;
var CLASS_APPLICATION = 0x40;
var CLASS_CONTEXT     = 0x80;
var CLASS_PRIVATE     = 0xc0;
var CONSTRUCTED_BIT   = 0x20;

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
  opts = opts || {};
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
  var tagClassBits = first & 0xc0;
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
        children.push(child.node);
        cp = child.end;
      }
      contentEnd = cp;
      end = cp + 2;
    } else {
      while (cp < contentEnd) {
        child = _decodeTLV(buf, cp, contentEnd, depth + 1, maxDepth, ber, strDepth, ctr);
        children.push(child.node);
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
      segments.push(children[s].content);
    }
    node.content = Buffer.concat(segments);
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
      segments.push(seg.content);
    }
    return Buffer.concat(segments);
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
  if (buf.length === 0) throw new OidError("oid/empty", "OBJECT IDENTIFIER content is empty");
  var arcs = [];
  var arcStart = 0;
  for (var i = 0; i < buf.length; i++) {
    var b = buf[i];
    if (i === arcStart && b === 0x80) throw new OidError("oid/non-minimal", "non-minimal sub-identifier (leading 0x80)");
    if (i - arcStart >= constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES) {
      throw new OidError("oid/subidentifier-too-large",
        "OID sub-identifier exceeds " + constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES + " octets");
    }
    if ((b & 0x80) === 0) {
      var value = 0n;
      for (var k = arcStart; k <= i; k++) value = value * 128n + BigInt(buf[k] & 0x7f);
      arcs.push(value);
      arcStart = i + 1;
    }
  }
  if (arcStart !== buf.length) throw new OidError("oid/truncated", "OBJECT IDENTIFIER ends mid sub-identifier");
  var first = arcs[0];
  var a1, a2;
  if (first < 40n) { a1 = 0n; a2 = first; }
  else if (first < 80n) { a1 = 1n; a2 = first - 40n; }
  else { a1 = 2n; a2 = first - 80n; }
  var out = [a1.toString(), a2.toString()];
  for (var j = 1; j < arcs.length; j++) out.push(arcs[j].toString());
  return out.join(".");
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

function _decodeUtf8Strict(buf) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buf);
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
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, min, sec, ms);
  if (isNaN(guard.time.instantOf(d))) throw new Asn1Error("asn1/bad-time", "unparseable time " + JSON.stringify(s));
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day ||
      d.getUTCHours() !== hour || d.getUTCMinutes() !== min || d.getUTCSeconds() !== sec) {
    throw new Asn1Error("asn1/bad-time", "time component out of range " + JSON.stringify(s));
  }
  return d;
}


function encodeLength(n) {
  if (typeof n !== "number" || !isFinite(n) || n < 0 || Math.floor(n) !== n) {
    throw new Asn1Error("asn1/bad-length", "length must be a non-negative integer");
  }
  if (n < 0x80) return Buffer.from([n]);
  var bytes = [];
  var v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  if (bytes.length > 126) throw new Asn1Error("asn1/length-too-large", "length needs more than 126 octets");
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

function sequenceTlv(node) {
  var content = node.content != null ? node.content : Buffer.concat((node.children || []).map(function (c) { return c.bytes; }));
  return Buffer.concat([Buffer.from([TAGS.SEQUENCE | CONSTRUCTED_BIT]), encodeLength(content.length), content]);
}

function encodeIdentifier(classBits, constructed, tagNumber) {
  if (typeof tagNumber !== "number" || !isFinite(tagNumber) || tagNumber < 0 || Math.floor(tagNumber) !== tagNumber) {
    throw new Asn1Error("asn1/bad-tag", "tag number must be a non-negative integer");
  }
  var lead = classBits | (constructed ? CONSTRUCTED_BIT : 0);
  if (tagNumber < 0x1f) return Buffer.from([lead | tagNumber]);
  var body = [];
  var v = tagNumber;
  do { body.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
  if (body.length > 4) throw new Asn1Error("asn1/tag-too-large", "high-tag-number too large");
  for (var i = 0; i < body.length - 1; i++) body[i] |= 0x80;
  return Buffer.concat([Buffer.from([lead | 0x1f]), Buffer.from(body)]);
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
 * @example
 *   pki.asn1.encode(0x00, false, pki.asn1.TAGS.NULL, Buffer.alloc(0));
 */
function encodeTLV(classBits, constructed, tagNumber, content) {
  var body = Buffer.isBuffer(content) ? guard.bytes.view(content, Asn1Error, "asn1/not-buffer", "encodeTLV content") : Buffer.from(content || []);
  var id = encodeIdentifier(classBits, constructed, tagNumber);
  return Buffer.concat([id, encodeLength(body.length), body]);
}

function _universal(tagNumber, constructed, content) {
  return encodeTLV(CLASS_UNIVERSAL, constructed, tagNumber, content);
}

function intToDer(v) {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Asn1Error("asn1/bad-integer", "unsafe integer; pass a BigInt");
    v = BigInt(v);
  }
  if (typeof v !== "bigint") throw new Asn1Error("asn1/bad-integer", "integer must be number or BigInt");
  if (v === 0n) return Buffer.from([0]);
  var bytes = [];
  if (v > 0n) {
    var t = v;
    while (t > 0n) { bytes.unshift(Number(t & 0xffn)); t >>= 8n; }
    if (bytes[0] & 0x80) bytes.unshift(0x00);
  } else {
    var len = 1;
    while (v < -(1n << BigInt(8 * len - 1))) len += 1;
    var tc = (1n << BigInt(8 * len)) + v;
    for (var i = len - 1; i >= 0; i--) { bytes[i] = Number(tc & 0xffn); tc >>= 8n; }
  }
  return Buffer.from(bytes);
}

function encodeOidContent(dotted) {
  guard.identifier.assertCanonicalOid(dotted, _oidErr, "oid/bad-input", "OID", "oid/bad-arc");
  var arcs = dotted.split(".").map(function (p) { return BigInt(p); });
  var a1 = arcs[0], a2 = arcs[1];
  var subids = [a1 * 40n + a2].concat(arcs.slice(2));
  var out = [];
  for (var s = 0; s < subids.length; s++) {
    var body = [];
    var v = subids[s];
    do { body.unshift(Number(v & 0x7fn)); v >>= 7n; } while (v > 0n);
    if (body.length > constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES) {
      throw new OidError("oid/subidentifier-too-large",
        "OID sub-identifier exceeds " + constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES + " octets");
    }
    for (var k = 0; k < body.length - 1; k++) body[k] |= 0x80;
    for (var j = 0; j < body.length; j++) out.push(body[j]);
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

function _generalizedTimeString(date) {
  var y = date.getUTCFullYear();
  if (y < 0 || y > 9999) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime year " + y + " outside 0000..9999");
  var yyyy = ("000" + y).slice(-4);
  return yyyy +
    _fmtTwo(date.getUTCMonth() + 1) + _fmtTwo(date.getUTCDate()) +
    _fmtTwo(date.getUTCHours()) + _fmtTwo(date.getUTCMinutes()) + _fmtTwo(date.getUTCSeconds()) + "Z";
}

function _utcTimeString(date) {
  var y = date.getUTCFullYear();
  if (y < 1950 || y > 2049) throw new Asn1Error("asn1/bad-utctime", "UTCTime year " + y + " outside 1950..2049; use GeneralizedTime");
  var yy = y % 100;
  return _fmtTwo(yy) +
    _fmtTwo(date.getUTCMonth() + 1) + _fmtTwo(date.getUTCDate()) +
    _fmtTwo(date.getUTCHours()) + _fmtTwo(date.getUTCMinutes()) + _fmtTwo(date.getUTCSeconds()) + "Z";
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
var build = {
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
  utf8:     function (s) { return _universal(TAGS.UTF8_STRING, false, Buffer.from(String(s), "utf8")); },
  ia5:      function (s) {
    s = String(s);
    for (var i = 0; i < s.length; i++) {
      if (_charCodeAt(s, i) > 0x7F) throw new Asn1Error("asn1/bad-ia5-string", "IA5String requires 7-bit ASCII");
    }
    return _universal(TAGS.IA5_STRING, false, Buffer.from(s, "latin1"));
  },
  printable: function (s) {
    s = String(s);
    if (!isPrintableString(s)) throw new Asn1Error("asn1/bad-printable-string", "value has characters outside the PrintableString set");
    return _universal(TAGS.PRINTABLE_STRING, false, Buffer.from(s, "latin1"));
  },
  bmpString: function (s) {
    s = String(s);
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
  generalizedTime: function (date) { return _universal(TAGS.GENERALIZED_TIME, false, Buffer.from(_generalizedTimeString(date), "latin1")); },
  sequence: function (children) { return _universal(TAGS.SEQUENCE, true, Buffer.concat(_asBufferArray(children, "build.sequence"))); },
  set:      function (children) {
    var arr = _asBufferArray(children, "build.set").slice();
    arr.sort(Buffer.compare);
    return _universal(TAGS.SET, true, Buffer.concat(arr));
  },
  setOf:    function (children) {
    var arr = _asBufferArray(children, "build.setOf").slice();
    arr.sort(Buffer.compare);
    return _universal(TAGS.SET, true, Buffer.concat(arr));
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
};
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

function _asBufferArray(arr, who) {
  if (!_isArray(arr)) throw new Asn1Error("asn1/bad-children", who + ": expected an array of TLV buffers");
  return arr.map(function (b) { return _asBuffer(b, who); });
}

module.exports = {
  TAGS:          TAGS,
  decode:        decode,
  isPrintableString: isPrintableString,
  encode:        encodeTLV,
  encodeTLV:     encodeTLV,
  encodeLength:  encodeLength,
  sequenceTlv:   sequenceTlv,
  encodeIdentifier: encodeIdentifier,
  decodeOidContent: decodeOidContent,
  encodeOidContent: encodeOidContent,
  build:         build,
  read: {
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
  },
};
