// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.asn1
 * @nav        Core
 * @title      ASN.1 / DER
 * @order      30
 * @featured   true
 * @slug       asn1
 *
 * @intro
 *   A strict DER (Distinguished Encoding Rules) codec -- the byte layer
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
 *   valid encoding -- byte-identical to any other conformant DER encoder's
 *   output -- and decoding it reproduces the value it was built from.
 *
 * @card
 *   Strict, fail-closed DER decode / encode with a navigable node tree
 *   and typed readers + builders.
 */

var constants = require("./constants");
var frameworkError = require("./framework-error");

var Asn1Error = frameworkError.Asn1Error;
var OidError = frameworkError.OidError;

// ---- Tag constants (universal class) --------------------------------

// L1 -- the ASN.1 universal-type descriptor registry: the single source of
// truth for the codec's type metadata. Each entry is DECLARATIVE DATA --
// { tag, form } where form is the DER encoding form ("primitive" or
// "constructed", X.690 sec. 8/sec. 10.2). TAGS and the two structural type-sets below
// are all DERIVED from it, so registering a universal type is one descriptor
// entry and the decoder's form checks (below) cover it automatically.
var UNIVERSAL_TYPES = {
  BOOLEAN:           { tag: 0x01, form: "primitive" },
  INTEGER:           { tag: 0x02, form: "primitive" },
  BIT_STRING:        { tag: 0x03, form: "primitive" },
  OCTET_STRING:      { tag: 0x04, form: "primitive" },
  NULL:              { tag: 0x05, form: "primitive" },
  OBJECT_IDENTIFIER: { tag: 0x06, form: "primitive" },
  ENUMERATED:        { tag: 0x0a, form: "primitive" },
  UTF8_STRING:       { tag: 0x0c, form: "primitive" },
  SEQUENCE:          { tag: 0x10, form: "constructed" },
  SET:               { tag: 0x11, form: "constructed" },
  PRINTABLE_STRING:  { tag: 0x13, form: "primitive" },
  TELETEX_STRING:    { tag: 0x14, form: "primitive" },
  IA5_STRING:        { tag: 0x16, form: "primitive" },
  UTC_TIME:          { tag: 0x17, form: "primitive" },
  GENERALIZED_TIME:  { tag: 0x18, form: "primitive" },
  VISIBLE_STRING:    { tag: 0x1a, form: "primitive" },
  UNIVERSAL_STRING:  { tag: 0x1c, form: "primitive" },
  BMP_STRING:        { tag: 0x1e, form: "primitive" },
};

// TAGS { name: tag } -- derived from the registry; the public constant consumers
// read (pki.asn1.TAGS.INTEGER, ...).
var TAGS = {};
Object.keys(UNIVERSAL_TYPES).forEach(function (k) { TAGS[k] = UNIVERSAL_TYPES[k].tag; });

var CLASS_UNIVERSAL   = 0x00;
var CLASS_APPLICATION = 0x40;
var CLASS_CONTEXT     = 0x80;
var CLASS_PRIVATE     = 0xc0;
var CONSTRUCTED_BIT   = 0x20;

// X.690 sec. 8.9.1 / sec. 8.11.1 / sec. 10.2 (DER), the mirror rules -- a constructed-only
// universal type (SEQUENCE/SET) MUST be encoded constructed, and every other
// universal type MUST be encoded primitive. The constructed-capable set is
// DERIVED from the registry above and keyed by tag for an O(1) decode-time form
// check. It is a WHITELIST: a universal tag outside it -- a registered primitive
// type and an unregistered one (NumericString, GeneralString, ObjectDescriptor,
// REAL, ...) alike -- has no DER constructed form, so the default is reject.
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
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  throw new Asn1Error("asn1/not-buffer", who + ": expected a Buffer / Uint8Array");
}

// ---- Decoder --------------------------------------------------------

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
 * bytes }` -- `content` is the primitive value slice, `children` the
 * decoded sub-nodes of a constructed node, and `bytes` the full TLV slice
 * (all zero-copy views over the input).
 *
 * Throws `Asn1Error` on any non-DER shape: indefinite length, a
 * non-minimal length or a length that overruns the buffer, trailing bytes
 * after the top-level value (unless `allowTrailing`), or exceeding the
 * size / depth caps.
 *
 * `ber: true` is a scoped relaxation for formats whose content regions are
 * normatively BER (RFC 7292 PKCS#12): it accepts an indefinite length on a
 * constructed value and a constructed OCTET STRING, whose segments are
 * reassembled into one primitive `content`. Nothing else is relaxed --
 * definite lengths stay minimal, an indefinite length on a primitive value
 * and a foreign-type segment still reject, and the size / depth caps hold.
 *
 * @opts
 *   maxBytes:       number,   // default: C.LIMITS.DER_MAX_BYTES (16 MiB)
 *   maxDepth:       number,   // default: C.LIMITS.DER_MAX_DEPTH (64)
 *   allowTrailing:  boolean,  // default: false -- allow bytes after the top TLV
 *   ber:            boolean,  // default: false -- accept indefinite lengths +
 *                             // constructed OCTET STRINGs (BER content regions)
 *
 * @example
 *   var node = pki.asn1.decode(der);
 *   node.tagNumber === pki.asn1.TAGS.SEQUENCE;
 */
// A size/depth cap opt: absent means the constants.LIMITS default; a provided
// value must be a non-negative finite integer. A non-finite cap (NaN, Infinity)
// silently DISABLES the guard -- every `>` compare against it is false -- so a
// deeply nested input would run to a bare RangeError instead of the typed
// asn1/too-deep verdict. A bad cap is a config fault: throw at entry.
function _capOpt(v, key, dflt) {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !isFinite(v) || v < 0 || Math.floor(v) !== v) {
    throw new TypeError("decode: " + key + " must be a non-negative integer");
  }
  return v;
}

function decode(input, opts) {
  opts = opts || {};
  var buf = _asBuffer(input, "decode");
  var maxBytes = _capOpt(opts.maxBytes, "maxBytes", constants.LIMITS.DER_MAX_BYTES);
  var maxDepth = _capOpt(opts.maxDepth, "maxDepth", constants.LIMITS.DER_MAX_DEPTH);
  if (buf.length > maxBytes) {
    throw new Asn1Error("asn1/too-large", "input " + buf.length + " bytes exceeds cap " + maxBytes);
  }
  var r = _decodeTLV(buf, 0, buf.length, 0, maxDepth, opts.ber === true);
  if (!opts.allowTrailing && r.end !== buf.length) {
    throw new Asn1Error("asn1/trailing-bytes", (buf.length - r.end) + " trailing byte(s) after the top-level value");
  }
  return r.node;
}

function _decodeTLV(buf, start, limit, depth, maxDepth, ber, strDepth) {
  if (depth > maxDepth) {
    throw new Asn1Error("asn1/too-deep", "nesting exceeds depth cap " + maxDepth);
  }
  var p = start;
  if (p >= limit) throw new Asn1Error("asn1/truncated", "expected an identifier octet");
  var first = buf[p]; p += 1;
  var tagClassBits = first & 0xc0;
  var constructed = (first & CONSTRUCTED_BIT) !== 0;
  var tagNumber = first & 0x1f;

  if (tagNumber === 0x1f) {
    // High-tag-number form: base-128, minimal (no leading 0x80).
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

  // X.690 8.9.1 / 8.11.1 -- a universal constructed-only type (SEQUENCE / SET)
  // is always constructed; a primitive-tagged one is not valid DER (and would
  // decode to a leaf that constructed-structure consumers dereference as a
  // parent). Driven by the registry-derived set, not a hardcoded tag list.
  if (tagClassBits === CLASS_UNIVERSAL && CONSTRUCTED_ONLY_UNIVERSAL_TAGS[tagNumber] && !constructed) {
    throw new Asn1Error("asn1/bad-tlv", "a universal constructed-only type (SEQUENCE/SET) must be constructed");
  }

  // X.690 sec. 8.x / sec. 10.2 -- the mirror rule: a universal type other than
  // SEQUENCE/SET (INTEGER, OID, BOOLEAN, every restricted string type --
  // registered or not -- times, BIT/OCTET STRING, REAL, ...) encoded
  // constructed is not valid DER. Without this a constructed string tag
  // decodes to a childless node that later paths (an X.509 DN attribute
  // value) would hex-render or dereference instead of failing closed; the
  // constructed-capable set is a whitelist so an UNREGISTERED string type
  // (a constructed GeneralString) cannot slip past the form check either.
  // The ber mode licenses exactly one constructed primitive-only type -- the
  // OCTET STRING (the streamed content carrier RFC 7292 sec. 4.1 permits); its
  // segments are reassembled below. Every other primitive-only type stays
  // primitive even in BER. Reassembly re-copies each nesting level's payload,
  // so nesting is capped on the way down: real producers segment one level
  // deep, and a deep chain multiplies transient memory without carrying data.
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
    // X.690 sec. 8.1.3.6 -- indefinite length is only defined for a constructed
    // encoding; the value runs to the end-of-contents octets.
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
        child = _decodeTLV(buf, cp, limit, depth + 1, maxDepth, ber, strDepth);
        children.push(child.node);
        cp = child.end;
      }
      contentEnd = cp;
      end = cp + 2;
    } else {
      while (cp < contentEnd) {
        child = _decodeTLV(buf, cp, contentEnd, depth + 1, maxDepth, ber, strDepth);
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

  // BER reassembly: a constructed OCTET STRING's segments concatenate into
  // one primitive content, so every downstream reader sees the value a
  // single-segment encoding would carry; `bytes` keeps the original wire
  // range for raw round-trip surfaces. Nested constructed segments arrive
  // already reassembled by the recursion (their nesting depth is capped on
  // the way down -- see the strDepth check above).
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
  // A context-tagged constructed node from a ber decode may be an IMPLICIT
  // streamed string (the tag hides the underlying type), which only the
  // schema-driven typed reader can identify -- mark it so readers reassemble
  // exactly those nodes and a strict decode's verdicts never change.
  if (ber && constructed && tagClassBits === CLASS_CONTEXT && node.children) {
    node.ber = true;
  }
  return { node: node, end: end };
}

// ---- Node assertions ------------------------------------------------

function _expectUniversal(node, tag, who) {
  if (node.tagClass !== "universal" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", who + ": expected universal tag " + tag +
      ", got " + node.tagClass + "/" + node.tagNumber);
  }
}

function _expectPrimitive(node, who) {
  if (node.constructed) throw new Asn1Error("asn1/expected-primitive", who + ": expected a primitive encoding");
}

// ---- Typed readers --------------------------------------------------

function readBoolean(node) {
  _expectUniversal(node, TAGS.BOOLEAN, "readBoolean");
  _expectPrimitive(node, "readBoolean");
  if (node.content.length !== 1) throw new Asn1Error("asn1/bad-boolean", "BOOLEAN content must be 1 octet");
  var v = node.content[0];
  if (v === 0x00) return false;
  if (v === 0xff) return true;
  throw new Asn1Error("asn1/bad-boolean", "DER BOOLEAN must be 0x00 or 0xFF, got 0x" + v.toString(16));
}

// INTEGER and ENUMERATED share DER content encoding (a two's-complement big-endian
// value) but are DISTINCT universal types. This decodes that shared content -- the
// caller asserts the tag first. `typeName` names the type in error messages; the
// stable error codes stay the integer family (a caller switching on `code` treats
// both alike since the encoding is identical).
function _readIntegerLikeContent(node, typeName, who) {
  _expectPrimitive(node, who);
  var c = node.content;
  if (c.length === 0) throw new Asn1Error("asn1/bad-integer", typeName + " must have at least 1 content octet");
  // Defense-in-depth: refuse an over-cap magnitude before touching BigInt.
  // A one-shot hex parse is linear, but the length still bounds worst-case
  // work -- reject a hostile length prefix up front. The cap bounds the
  // MAGNITUDE; a positive INTEGER whose top bit is set carries one leading
  // 0x00 DER sign octet, so allow cap + 1 content bytes (an RSA-131072
  // modulus is 16384 magnitude bytes plus that sign pad).
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

// read.integer is STRICT on the tag: an ENUMERATED node (which shares INTEGER's
// content encoding) is NOT accepted here. Coercing an ENUMERATED to an INTEGER is a
// type confusion -- an INTEGER-pinned field (a certificate/CSR version, a serial
// number, a cRLNumber) encoded as ENUMERATED would slip past a lenient reader.
// Read ENUMERATED values with read.enumerated.
function readInteger(node) {
  _expectUniversal(node, TAGS.INTEGER, "readInteger");
  return _readIntegerLikeContent(node, "INTEGER", "readInteger");
}

// read.enumerated reads an ENUMERATED value; its content rules are identical to
// INTEGER (non-empty, minimally encoded, magnitude within the cap).
function readEnumerated(node) {
  _expectUniversal(node, TAGS.ENUMERATED, "readEnumerated");
  return _readIntegerLikeContent(node, "ENUMERATED", "readEnumerated");
}

// Read a [tag] IMPLICIT INTEGER -- a context-class PRIMITIVE node whose content is an
// integer body (the IMPLICIT tag replaces the universal INTEGER tag). Same minimal
// two's-complement content rules as a universal INTEGER. The integer counterpart of
// readBitStringImplicit, for the RFC 3161 Accuracy millis [0] / micros [1] fields.
function readIntegerImplicit(node, tag) {
  if (node.tagClass !== "context" || node.tagNumber !== tag) {
    throw new Asn1Error("asn1/unexpected-tag", "readIntegerImplicit: expected context tag [" + tag +
      "], got " + node.tagClass + "/" + node.tagNumber);
  }
  return _readIntegerLikeContent(node, "INTEGER", "readIntegerImplicit");
}

// The BIT STRING content decoder (the leading unused-bit octet + body, with the
// DER zero-pad rule). Shared by the universal reader and the IMPLICIT
// context-tagged reader -- the caller asserts the tag first.
function _readBitStringContent(node, who) {
  _expectPrimitive(node, who);
  var c = node.content;
  if (c.length === 0) throw new Asn1Error("asn1/bad-bit-string", "BIT STRING must have >= 1 content octet");
  var unusedBits = c[0];
  if (unusedBits > 7) throw new Asn1Error("asn1/bad-bit-string", "unused-bit count " + unusedBits + " > 7");
  if (unusedBits > 0 && c.length === 1) throw new Asn1Error("asn1/bad-bit-string", "unused bits declared over an empty body");
  // X.690 11.2.1 -- the declared unused low bits of the final octet must be
  // zero in DER.
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

// Read a [tag] IMPLICIT BIT STRING -- a context-class PRIMITIVE node whose content
// is a bit-string body (identical content rules to a universal BIT STRING). The
// IMPLICIT tag replaces the universal one, so there is no inner universal node.
// Used for the PKCS#8 OneAsymmetricKey publicKey [1] (RFC 5958 sec. 2).
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

// Read a [tag] IMPLICIT OCTET STRING -- a context-class PRIMITIVE node whose
// content is the octet-string body (the IMPLICIT tag replaces the universal one,
// so there is no inner universal node). Primitive-only, like its universal
// counterpart, so a strict decode's constructed/streamed form is rejected.
// A node from a ber decode (the `ber` marker) may carry the streamed form --
// the context tag hides the underlying type from the decoder, so THIS reader
// is where a [tag] IMPLICIT OCTET STRING's segments reassemble (the shape CMS
// ciphertext streams as). Used for the CMS SignerIdentifier
// subjectKeyIdentifier [0] (RFC 5652 sec. 5.3) and EncryptedContentInfo
// encryptedContent [0] (sec. 6.1).
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

// Read a [tag] IMPLICIT BOOLEAN -- a context-class PRIMITIVE node whose single
// content octet obeys the DER BOOLEAN rules (0x00 FALSE / 0xFF TRUE; anything
// else rejected). The IMPLICIT tag replaces the universal BOOLEAN tag. Used for
// the RFC 5280 sec. 5.2.5 IssuingDistributionPoint scope flags.
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

// Read a [tag] IMPLICIT NULL -- a context-class PRIMITIVE node with empty content.
// The IMPLICIT tag replaces the universal NULL tag, so there is no inner universal
// node. The empty-content and primitive-form rules of a universal NULL still hold.
// Used for the OCSP CertStatus good [0] / unknown [2] arms (RFC 6960 sec. 4.2.1).
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
    // Cap the continuation-byte run so a single arc can't drive unbounded
    // BigInt growth before it terminates.
    if (i - arcStart >= constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES) {
      throw new OidError("oid/subidentifier-too-large",
        "OID sub-identifier exceeds " + constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES + " octets");
    }
    if ((b & 0x80) === 0) {
      // Terminal octet: fold the whole [arcStart..i] slice base-128 in one
      // bounded pass (the run is capped above), no per-bit accumulation
      // across the full OID content.
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

// IA5String is 7-bit ASCII (T.50 / IA5) -- every content octet is 0x00..0x7F.
function _decodeIa5(buf) {
  for (var i = 0; i < buf.length; i++) {
    if (buf[i] > 0x7F) throw new Asn1Error("asn1/bad-ia5-string", "IA5String requires 7-bit ASCII");
  }
  return buf.toString("latin1");
}

// VisibleString (ISO 646 IRV / X.690) is the printable ASCII range 0x20..0x7E
// -- no control characters and no bytes with the high bit set.
function _decodeVisible(buf) {
  for (var i = 0; i < buf.length; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7E) throw new Asn1Error("asn1/bad-visible-string", "VisibleString must be 0x20..0x7E");
  }
  return buf.toString("latin1");
}

// PrintableString is restricted to A-Z a-z 0-9 space and ' ( ) + , - . / : = ?
function _decodePrintable(buf) {
  var s = buf.toString("latin1");
  if (!PRINTABLE_RE.test(s)) throw new Asn1Error("asn1/bad-printable-string", "PrintableString has characters outside the restricted set");
  return s;
}

// UTF8String must be well-formed UTF-8; a lenient decoder substitutes U+FFFD
// for invalid sequences, silently mangling hostile input into valid text.
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
  // BMPString encodes BMP scalar values only; a UTF-16 surrogate code unit
  // here is a lone surrogate, not valid text.
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
    // Reject non-scalar values (> U+10FFFF or a surrogate) before
    // String.fromCodePoint would throw a bare RangeError / emit a lone surrogate.
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
      throw new Asn1Error("asn1/bad-universal-string", "code point out of range");
    }
    out += String.fromCodePoint(cp);
  }
  return out;
}

var UTC_RE = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
var GEN_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/;
// The X.690 sec. 11.7 DER fractional-seconds GeneralizedTime profile: seconds present,
// a `.` decimal separator (never `,`), a non-empty fraction, Z-terminated. The
// trailing-zeros rule (sec. 11.7.3) is enforced separately. Used by RFC 3161 genTime.
var GEN_FRAC_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d+)Z$/;

// readTime(node, opts?) -- opts.allowFractional enables the RFC 3161 / X.690 sec. 11.7
// fractional-seconds GeneralizedTime profile. Fractional is OFF by default because
// most profiles (RFC 5280 certificate/CRL Validity, sec. 4.1.2.5.2) require the integer-
// second YYYYMMDDHHMMSSZ form and MUST NOT include a fraction; only callers that
// permit sub-second precision (TSP genTime) pass allowFractional.
function readTime(node, opts) {
  if (node.tagClass !== "universal") throw new Asn1Error("asn1/expected-time", "readTime: not a universal time type");
  _expectPrimitive(node, "readTime");
  var s = node.content.toString("latin1");
  var m, year;
  if (node.tagNumber === TAGS.UTC_TIME) {
    m = UTC_RE.exec(s);
    if (!m) throw new Asn1Error("asn1/bad-utctime", "UTCTime must be YYMMDDHHMMSSZ, got " + JSON.stringify(s));
    year = parseInt(m[1], 10);
    // RFC 5280 sec. 4.1.2.5.1 -- YY < 50 => 20YY, else 19YY.
    year += (year < 50) ? 2000 : 1900;
  } else if (node.tagNumber === TAGS.GENERALIZED_TIME) {
    m = GEN_RE.exec(s);
    if (!m) {
      if (!(opts && opts.allowFractional)) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime must be YYYYMMDDHHMMSSZ, got " + JSON.stringify(s));
      m = GEN_FRAC_RE.exec(s);
      if (!m) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime must be YYYYMMDDHHMMSS[.fraction]Z, got " + JSON.stringify(s));
      // X.690 sec. 11.7.3 -- the fractional part MUST NOT end in a zero (and is non-empty
      // by the regex). ".5Z" is valid; ".50Z" and ".500Z" are non-canonical. X.690
      // sec. 11.7 places NO cap on the fraction length (RFC 3161 sec. 2.4.2 gives the 5-digit
      // example 19990609001326.34352Z), so a fraction of any length is accepted; the
      // returned Date is millisecond-precision, and a caller needing the exact fraction
      // reads it from node.content (the raw bytes, surfaced losslessly like the OID /
      // serial paths).
      if (m[7].charAt(m[7].length - 1) === "0") throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime fraction must not have trailing zeros, got " + JSON.stringify(s));
    }
    year = parseInt(m[1], 10);
  } else {
    throw new Asn1Error("asn1/expected-time", "readTime: tag " + node.tagNumber + " is not a time type");
  }
  // The month is capture group 2 in UTC_RE, GEN_RE, and GEN_FRAC_RE alike
  // (the groups diverge only at 1, the year, and 7, the fraction).
  var month = parseInt(m[2], 10);
  var day   = parseInt(m[3], 10);
  var hour  = parseInt(m[4], 10);
  var min   = parseInt(m[5], 10);
  var sec   = parseInt(m[6], 10);
  // Build from the LITERAL year via setUTCFullYear: the Date.UTC() / new Date()
  // constructors remap a year in 0..99 to 1900..1999, which would corrupt a
  // GeneralizedTime year below 100 (0099 -> 1999). setUTCFullYear(year, ...)
  // takes the year literally and uses that year's own calendar, so years
  // below 100 and proleptic leap years are handled correctly.
  // A fractional GeneralizedTime carries sub-second precision; surface it on the
  // Date at millisecond resolution (the first three fraction digits, zero-padded).
  var ms = (node.tagNumber === TAGS.GENERALIZED_TIME && m[7]) ? parseInt((m[7] + "000").slice(0, 3), 10) : 0;
  var d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, min, sec, ms);
  if (isNaN(d.getTime())) throw new Asn1Error("asn1/bad-time", "unparseable time " + JSON.stringify(s));
  // Date/setUTC* silently roll over out-of-range fields (Feb 30 -> Mar 2,
  // month 13 -> next Jan, hour 25 -> +1 day). Reject unless every component
  // round-trips exactly.
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day ||
      d.getUTCHours() !== hour || d.getUTCMinutes() !== min || d.getUTCSeconds() !== sec) {
    throw new Asn1Error("asn1/bad-time", "time component out of range " + JSON.stringify(s));
  }
  return d;
}

// ---- Encoder / builders ---------------------------------------------

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

// The DER of a universal SEQUENCE recovered from a decoded IMPLICIT [n] SEQUENCE
// `node`, whose context tag replaced the universal 0x30 on the wire (e.g. an RFC
// 4211 CertTemplate publicKey [6] SubjectPublicKeyInfo, or a POPOSigningKey
// poposkInput [0]): the field's value is imported / signed as a standalone SEQUENCE,
// not as the context-tagged wire form. A constructed node exposes its content as
// `children` (not `content`), so the content is those children's DER concatenated;
// the identifier becomes the SEQUENCE tag and the length is canonical DER.
function sequenceTlv(node) {
  var content = node.content != null ? node.content : Buffer.concat((node.children || []).map(function (c) { return c.bytes; }));
  return Buffer.concat([Buffer.from([TAGS.SEQUENCE | CONSTRUCTED_BIT]), encodeLength(content.length), content]);
}

function encodeIdentifier(classBits, constructed, tagNumber) {
  // Mirror encodeLength's input guard: a negative tag corrupts the identifier
  // octet (-1 emits 0xff..), and a fractional tag is silently bit-truncated to
  // a DIFFERENT tag -- an entry-point builder handed a bad tag throws instead
  // of emitting malformed or non-round-trippable DER.
  if (typeof tagNumber !== "number" || !isFinite(tagNumber) || tagNumber < 0 || Math.floor(tagNumber) !== tagNumber) {
    throw new Asn1Error("asn1/bad-tag", "tag number must be a non-negative integer");
  }
  var lead = classBits | (constructed ? CONSTRUCTED_BIT : 0);
  if (tagNumber < 0x1f) return Buffer.from([lead | tagNumber]);
  var body = [];
  var v = tagNumber;
  do { body.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
  // Symmetric with the decoder's 4-octet high-tag-number cap, so the encoder
  // can't emit an identifier decode() refuses as hostile.
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
 * Low-level TLV encoder -- prepend the identifier + DER length to a content
 * buffer. Most callers use the higher-level `build.*` helpers; this is the
 * escape hatch for context-tagged and implicitly-tagged constructions.
 *
 * @example
 *   pki.asn1.encode(0x00, false, pki.asn1.TAGS.NULL, Buffer.alloc(0));
 */
function encodeTLV(classBits, constructed, tagNumber, content) {
  var body = Buffer.isBuffer(content) ? content : Buffer.from(content || []);
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
  if (typeof dotted !== "string" || dotted.length === 0) throw new OidError("oid/bad-input", "OID must be a dotted-decimal string");
  var parts = dotted.split(".");
  if (parts.length < 2) throw new OidError("oid/too-short", "OID needs at least two arcs");
  var arcs = [];
  for (var i = 0; i < parts.length; i++) {
    if (!/^\d+$/.test(parts[i])) throw new OidError("oid/bad-arc", "arc " + JSON.stringify(parts[i]) + " is not a non-negative integer");
    arcs.push(BigInt(parts[i]));
  }
  var a1 = arcs[0], a2 = arcs[1];
  if (a1 > 2n) throw new OidError("oid/bad-arc", "first arc must be 0, 1, or 2");
  if (a1 < 2n && a2 >= 40n) throw new OidError("oid/bad-arc", "second arc must be < 40 when the first arc is 0 or 1");
  var subids = [a1 * 40n + a2].concat(arcs.slice(2));
  var out = [];
  for (var s = 0; s < subids.length; s++) {
    var body = [];
    var v = subids[s];
    do { body.unshift(Number(v & 0x7fn)); v >>= 7n; } while (v > 0n);
    // Keep the encoder symmetric with the decoder's per-arc cap so build.oid
    // can't emit a sub-identifier read.oid would reject as hostile.
    if (body.length > constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES) {
      throw new OidError("oid/subidentifier-too-large",
        "OID sub-identifier exceeds " + constants.LIMITS.OID_MAX_SUBIDENTIFIER_BYTES + " octets");
    }
    for (var k = 0; k < body.length - 1; k++) body[k] |= 0x80;
    for (var j = 0; j < body.length; j++) out.push(body[j]);
  }
  return Buffer.from(out);
}

var PRINTABLE_RE = /^[A-Za-z0-9 '()+,\-./:=?]*$/;

function _fmtTwo(n) { return (n < 10 ? "0" : "") + n; }

function _generalizedTimeString(date) {
  // GeneralizedTime is YYYYMMDDHHMMSSZ -- a year below 1000 must still emit
  // four digits, or read.time rejects the short (12-14 char) content.
  var y = date.getUTCFullYear();
  if (y < 0 || y > 9999) throw new Asn1Error("asn1/bad-generalizedtime", "GeneralizedTime year " + y + " outside 0000..9999");
  var yyyy = ("000" + y).slice(-4);
  return yyyy +
    _fmtTwo(date.getUTCMonth() + 1) + _fmtTwo(date.getUTCDate()) +
    _fmtTwo(date.getUTCHours()) + _fmtTwo(date.getUTCMinutes()) + _fmtTwo(date.getUTCSeconds()) + "Z";
}

function _utcTimeString(date) {
  // RFC 5280 sec. 4.1.2.5.1 restricts UTCTime to 1950..2049; a year outside that
  // wraps to the wrong century (2050 -> "50" -> decodes as 1950).
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
    var u = unusedBits == null ? 0 : unusedBits;
    // An integer in 0..7 (X.690 sec. 8.6.2.2). A fractional / non-finite count
    // would be silently bit-truncated into a DIFFERENT value when written
    // into the leading octet -- reject it like the other numeric builder
    // inputs (encodeLength, the tag number).
    if (typeof u !== "number" || !Number.isInteger(u) || u < 0 || u > 7) {
      throw new Asn1Error("asn1/bad-bit-string", "unusedBits must be an integer 0..7");
    }
    var body = _asBuffer(buf, "build.bitString");
    // X.690 8.6.2.3: an empty BIT STRING has no content octets, so its
    // unused-bit count must be zero -- there are no bits to leave unused.
    if (u > 0 && body.length === 0) throw new Asn1Error("asn1/bad-bit-string", "empty BIT STRING must declare zero unused bits");
    // Stay canonical: refuse a tail whose declared unused low bits are set.
    if (u > 0 && body.length > 0) {
      var mask = (1 << u) - 1;
      if ((body[body.length - 1] & mask) !== 0) throw new Asn1Error("asn1/bad-bit-string", "unused bits must be zero");
    }
    return _universal(TAGS.BIT_STRING, false, Buffer.concat([Buffer.from([u]), body]));
  },
  utf8:     function (s) { return _universal(TAGS.UTF8_STRING, false, Buffer.from(String(s), "utf8")); },
  ia5:      function (s) {
    // Validate the INPUT code points, not the latin1 output bytes: latin1
    // truncates a code point > 0xFF to its low byte (U+0141 -> 0x41), which
    // would silently pass a non-IA5 character through as a different one.
    s = String(s);
    for (var i = 0; i < s.length; i++) {
      if (s.charCodeAt(i) > 0x7F) throw new Asn1Error("asn1/bad-ia5-string", "IA5String requires 7-bit ASCII");
    }
    return _universal(TAGS.IA5_STRING, false, Buffer.from(s, "latin1"));
  },
  printable: function (s) {
    s = String(s);
    if (!PRINTABLE_RE.test(s)) throw new Asn1Error("asn1/bad-printable-string", "value has characters outside the PrintableString set");
    return _universal(TAGS.PRINTABLE_STRING, false, Buffer.from(s, "latin1"));
  },
  utcTime:  function (date) { return _universal(TAGS.UTC_TIME, false, Buffer.from(_utcTimeString(date), "latin1")); },
  generalizedTime: function (date) { return _universal(TAGS.GENERALIZED_TIME, false, Buffer.from(_generalizedTimeString(date), "latin1")); },
  sequence: function (children) { return _universal(TAGS.SEQUENCE, true, Buffer.concat(_asBufferArray(children, "build.sequence"))); },
  set:      function (children) {
    // DER (X.690 11.6) requires SET component encodings in ascending order.
    var arr = _asBufferArray(children, "build.set").slice();
    arr.sort(Buffer.compare);
    return _universal(TAGS.SET, true, Buffer.concat(arr));
  },
  setOf:    function (children) {
    var arr = _asBufferArray(children, "build.setOf").slice();
    arr.sort(Buffer.compare);
    return _universal(TAGS.SET, true, Buffer.concat(arr));
  },
  // Context-tagged constructions for [n] EXPLICIT / IMPLICIT tagging.
  explicit: function (tagNumber, inner) { return encodeTLV(CLASS_CONTEXT, true, tagNumber, _asBuffer(inner, "build.explicit")); },
  contextPrimitive:   function (tagNumber, content) { return encodeTLV(CLASS_CONTEXT, false, tagNumber, _asBuffer(content, "build.contextPrimitive")); },
  contextConstructed: function (tagNumber, content) { return encodeTLV(CLASS_CONTEXT, true, tagNumber, _asBuffer(content, "build.contextConstructed")); },
  raw:      function (buf) { return _asBuffer(buf, "build.raw"); },
};

// A raw INTEGER/ENUMERATED content Buffer must satisfy the same DER shape
// read.integer enforces: non-empty and minimally encoded (no redundant sign
// octet). A BigInt/number goes through intToDer, which is minimal by build.
function _intContent(v, who) {
  if (Buffer.isBuffer(v)) {
    if (v.length === 0) throw new Asn1Error("asn1/bad-integer", who + ": INTEGER content is empty");
    if (v.length > 1) {
      if (v[0] === 0x00 && (v[1] & 0x80) === 0) throw new Asn1Error("asn1/non-minimal-integer", who + ": non-minimal positive INTEGER");
      if (v[0] === 0xff && (v[1] & 0x80) !== 0) throw new Asn1Error("asn1/non-minimal-integer", who + ": non-minimal negative INTEGER");
    }
  }
  var content = Buffer.isBuffer(v) ? v : intToDer(v);
  // Symmetric with read.integer's per-value ceiling (magnitude + DER sign
  // octet), so a builder can't emit an INTEGER the decoder would refuse.
  if (content.length > constants.LIMITS.DER_MAX_INTEGER_BYTES + 1) {
    throw new Asn1Error("asn1/integer-too-large", who + ": INTEGER content " + content.length + " bytes exceeds cap " + (constants.LIMITS.DER_MAX_INTEGER_BYTES + 1));
  }
  return content;
}

function _asBufferArray(arr, who) {
  if (!Array.isArray(arr)) throw new Asn1Error("asn1/bad-children", who + ": expected an array of TLV buffers");
  return arr.map(function (b) { return _asBuffer(b, who); });
}

module.exports = {
  TAGS:          TAGS,
  decode:        decode,
  // `encode` is the documented public name for the low-level TLV encoder;
  // `encodeTLV` remains as the descriptive alias.
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
    time:         readTime,
  },
};
