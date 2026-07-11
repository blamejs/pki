// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.cbor
 * @nav        Core
 * @title      CBOR (deterministic)
 * @order      35
 * @slug       cbor
 *
 * @intro
 *   A strict, fail-closed decoder for RFC 8949 Concise Binary Object
 *   Representation, restricted to the Core Deterministic Encoding profile
 *   (RFC 8949 sec. 4.2). It is the binary sibling of `pki.asn1`: an in-house
 *   codec that owns its stack, rejects every non-canonical shape before it
 *   returns a value, and bounds size and depth before it walks a byte.
 *
 *   Anything a lenient CBOR reader would tolerate -- an indefinite-length
 *   item, a non-minimal ("preferred") integer / length / tag argument, a
 *   non-shortest or non-canonical-NaN float, out-of-order or duplicate map
 *   keys, ill-formed UTF-8, or trailing bytes -- is a permanent `CborError`
 *   here, because deterministic CBOR is a canonical encoding and a producer
 *   that violates it produced invalid bytes. There is no lenient mode.
 *
 *   `decode` returns a navigable node tree with zero-copy `bytes` / `content`
 *   views (the raw ranges an external verifier hashes); the `read.*` leaf
 *   readers turn a node into a JS value (a `BigInt` for every integer, a
 *   `Buffer` for a byte string, a `Date` for an epoch time, a dotted string
 *   for a tagged OID). It is the primitive the CBOR-encoded PKI surfaces
 *   (C509 certificates, COSE / CWT) will compose.
 *
 * @card
 *   `decode` (bounded, fail-closed, deterministic-only) + the `read.*` typed
 *   leaf readers over its node tree.
 */

var constants = require("./constants");
var frameworkError = require("./framework-error");
var asn1 = require("./asn1-der");

var CborError = frameworkError.CborError;

// Reusable little-work scratch for IEEE-754 float decode + the shortest-form
// round-trip checks. Single-threaded synchronous use, reset on every write.
var _fbuf = new ArrayBuffer(8);
var _fdv = new DataView(_fbuf);

// Strict UTF-8 validator (fatal); a lone continuation / truncated sequence
// throws instead of substituting U+FFFD -- the fail-open class the toolkit
// refuses, mirroring asn1-der's strict text decode.
var _utf8 = new TextDecoder("utf-8", { fatal: true });

// The ECMAScript Date-valid window is +/- 8,640,000,000,000,000 ms; in seconds
// that is +/- 8.64e12. read.time bounds an epoch value to this window BEFORE
// narrowing the BigInt to a Number, so the narrowing is lossless (well under
// 2^53) and the millisecond result stays a safe integer.
var _MAX_EPOCH_SECONDS = 8640000000000n;

function _asBuffer(input, who) {
  // A Buffer is itself a Uint8Array, so it goes through the same guarded re-view
  // -- NOT a `Buffer.isBuffer` fast-path that would return it as-is. A detached
  // backing ArrayBuffer (a transferred / structuredClone'd view) has had its
  // bytes removed and reads as zero-length; the fast-path would hand the byte
  // walk an empty buffer. Always re-view through Buffer.from so a detached input
  // fails closed here as a typed error rather than a raw TypeError deeper in the
  // walk (or a misleading truncated-input verdict).
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    try {
      return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    } catch (e) {
      throw new CborError("cbor/not-buffer", who + ": input is not a usable byte view (detached backing buffer?)", e);
    }
  }
  throw new CborError("cbor/not-buffer", who + ": expected a Buffer / Uint8Array");
}

// Config-time cap validation: a bad cap is an authoring bug, so it throws a
// TypeError (not a CborError) exactly like asn1-der's _capOpt.
function _capOpt(v, key, dflt) {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new TypeError("decode: " + key + " must be a non-negative integer");
  }
  return v;
}

// Determinism profile -> a ruleset. v1 whitelists only "deterministic"
// (RFC 8949 sec. 4.2 core); an unknown profile is a config-time TypeError, so
// there is no path to a lenient decode. A future "ctap2" (length-first map
// ordering) is a data row here, not a switch through the decoder.
function _profile(name) {
  var p = name === undefined ? "deterministic" : name;
  if (p === "deterministic") return { mapKeyCompare: Buffer.compare };
  throw new TypeError("decode: unknown profile " + JSON.stringify(p) + " (only \"deterministic\" is supported)");
}

function _assertUtf8(buf) {
  try {
    _utf8.decode(buf);
  } catch (_e) {
    throw new CborError("cbor/bad-utf8", "text string is not well-formed UTF-8");
  }
}

// Decode the raw IEEE-754 bits (carried in the argument) to a JS double, per
// the additional-info width: 25 half, 26 single, 27 double.
function _readFloatBits(argument, ai) {
  if (ai === 25) { _fdv.setUint16(0, Number(argument)); return _fdv.getFloat16(0); }
  if (ai === 26) { _fdv.setUint32(0, Number(argument)); return _fdv.getFloat32(0); }
  _fdv.setBigUint64(0, argument); return _fdv.getFloat64(0);
}

// Is d exactly representable as a half float? (round-trip through float16;
// Object.is keeps -0 and the NaN/Inf cases honest).
function _halfRoundtrips(d) {
  _fdv.setFloat16(0, d);
  return Object.is(_fdv.getFloat16(0), d);
}

// Is d exactly representable as a single float?
function _singleRoundtrips(d) {
  return Object.is(Math.fround(d), d);
}

// Recursive-descent decode of one CBOR item over [start, limit): fail-closed,
// depth-budgeted, zero-copy. Mirrors asn1-der's _decodeTLV.
function _decodeItem(buf, start, limit, depth, maxD, rules, state) {
  if (depth > maxD) throw new CborError("cbor/too-deep", "nesting exceeds depth cap " + maxD);
  state.n += 1;
  if (state.n > state.max) throw new CborError("cbor/too-many-items", "decoded item count exceeds cap " + state.max);
  var p = start;
  if (p >= limit) throw new CborError("cbor/truncated", "expected an initial byte");
  var ib = buf[p]; p += 1;
  var mt = ib >> 5;
  var ai = ib & 0x1f;

  // Head well-formedness, before reading the argument.
  if (ib === 0xff) throw new CborError("cbor/unexpected-break", "stray break byte (0xff) at an item head");
  if (ai === 28 || ai === 29 || ai === 30) throw new CborError("cbor/reserved-ai", "reserved additional-info " + ai);
  if (ai === 31) {
    if (mt === 2 || mt === 3 || mt === 4 || mt === 5) {
      throw new CborError("cbor/indefinite-length", "indefinite-length items are not valid deterministic CBOR");
    }
    throw new CborError("cbor/reserved-ai", "additional-info 31 is undefined for major type " + mt);
  }

  // The argument, minimal-checked, as a lossless BigInt.
  var argument;
  var contentStart;
  if (ai <= 23) {
    argument = BigInt(ai);
    contentStart = p;
  } else {
    var nBytes = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : 8;
    if (p + nBytes > limit) throw new CborError("cbor/truncated", "truncated " + nBytes + "-byte argument");
    if (nBytes === 1) argument = BigInt(buf[p]);
    else if (nBytes === 2) argument = BigInt(buf.readUInt16BE(p));
    else if (nBytes === 4) argument = BigInt(buf.readUInt32BE(p));
    else argument = buf.readBigUInt64BE(p);
    p += nBytes;
    // Preferred (shortest) argument -- for every major type but 7, where the
    // "argument" is raw float bits governed by the shortest-float rule instead.
    if (mt !== 7) {
      var minForWidth = nBytes === 1 ? 24n : nBytes === 2 ? 256n : nBytes === 4 ? 65536n : 4294967296n;
      if (argument < minForWidth) {
        throw new CborError("cbor/non-minimal-argument", "argument " + argument + " is not in the shortest head form");
      }
    }
    contentStart = p;
  }

  var content = null;
  var children = null;
  var end;

  if (mt === 0 || mt === 1) {
    end = contentStart;
  } else if (mt === 2 || mt === 3) {
    var len = Number(argument);
    if (contentStart + len > limit) throw new CborError("cbor/truncated", "string content overruns the buffer");
    content = buf.subarray(contentStart, contentStart + len);
    if (mt === 3) _assertUtf8(content);
    end = contentStart + len;
  } else if (mt === 4) {
    children = [];
    var cp = contentStart;
    for (var i = 0n; i < argument; i++) {
      var el = _decodeItem(buf, cp, limit, depth + 1, maxD, rules, state);
      children.push(el.node);
      cp = el.end;
    }
    end = cp;
  } else if (mt === 5) {
    children = [];
    var mp = contentStart;
    for (var j = 0n; j < argument; j++) {
      var k = _decodeItem(buf, mp, limit, depth + 1, maxD, rules, state);
      mp = k.end;
      var v = _decodeItem(buf, mp, limit, depth + 1, maxD, rules, state);
      mp = v.end;
      if (children.length > 0) {
        var cmp = rules.mapKeyCompare(children[children.length - 1][0].bytes, k.node.bytes);
        if (cmp > 0) throw new CborError("cbor/unsorted-map-keys", "map keys are not in bytewise-ascending order");
        if (cmp === 0) throw new CborError("cbor/duplicate-map-key", "duplicate map key");
      }
      children.push([k.node, v.node]);
    }
    end = mp;
  } else if (mt === 6) {
    var inner = _decodeItem(buf, contentStart, limit, depth + 1, maxD, rules, state);
    children = [inner.node];
    end = inner.end;
  } else {
    // mt === 7: simple value or float.
    if (ai <= 23) {
      end = contentStart;
    } else if (ai === 24) {
      if (argument < 32n) {
        throw new CborError("cbor/reserved-simple", "simple value " + argument + " must use the single-byte immediate form");
      }
      end = contentStart;
    } else {
      var d = _readFloatBits(argument, ai);
      if (Number.isNaN(d)) {
        if (!(ai === 25 && argument === 0x7e00n)) {
          throw new CborError("cbor/non-canonical-nan", "a NaN must be the canonical half float 0xf97e00");
        }
      } else if (ai === 26) {
        if (_halfRoundtrips(d)) throw new CborError("cbor/non-minimal-float", "a half-representable value must use the half form");
      } else if (ai === 27) {
        if (_halfRoundtrips(d) || _singleRoundtrips(d)) {
          throw new CborError("cbor/non-minimal-float", "a value representable in a narrower float must use it");
        }
      }
      end = contentStart;
    }
  }

  var node = {
    majorType: mt,
    ai: ai,
    argument: argument,
    content: content,
    children: children,
    header: { start: start, end: contentStart },
    contentStart: contentStart,
    contentEnd: end,
    length: end - contentStart,
    bytes: buf.subarray(start, end),
  };
  return { node: node, end: end };
}

/**
 * @primitive  pki.cbor.decode
 * @signature  pki.cbor.decode(bytes, opts?) -> node
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 4.2 (core deterministic encoding)
 *
 * Decode one Deterministically Encoded CBOR item into a navigable node tree.
 * Every non-canonical shape is refused: an indefinite length, a non-minimal
 * argument, unsorted or duplicate map keys, a non-shortest or non-canonical-
 * NaN float, ill-formed UTF-8, a reserved additional-info value, or (unless
 * `allowTrailing`) leftover bytes after the top-level item. Size, depth, and
 * total item count are bounded, so a high-fanout container fails closed rather
 * than exhausting memory. A node carries `majorType`, the `argument`
 * (a lossless BigInt), a zero-copy `content` / `bytes` view, and `children`
 * (array elements, map key/value pairs, or a tag's one inner item).
 *
 * @opts
 *   maxBytes:       number,   // default: C.LIMITS.CBOR_MAX_BYTES (16 MiB)
 *   maxDepth:       number,   // default: C.LIMITS.CBOR_MAX_DEPTH (64)
 *   maxItems:       number,   // default: C.LIMITS.CBOR_MAX_ITEMS (1,000,000 total decoded items)
 *   allowTrailing:  boolean,  // default: false -- true returns the first item and permits bytes after it (CBOR Sequence)
 *   profile:        string,   // default: "deterministic" (the only value v1 accepts)
 *
 * @example
 *   var node = pki.cbor.decode(Buffer.from("83010203", "hex"));
 *   node.majorType;                       // 4 (array)
 *   pki.cbor.read.uint(node.children[0]); // 1n
 */
function decode(input, opts) {
  opts = opts || {};
  var buf = _asBuffer(input, "decode");
  var maxBytes = _capOpt(opts.maxBytes, "maxBytes", constants.LIMITS.CBOR_MAX_BYTES);
  var maxDepth = _capOpt(opts.maxDepth, "maxDepth", constants.LIMITS.CBOR_MAX_DEPTH);
  if (maxDepth > constants.LIMITS.MAX_DECODE_DEPTH_CEILING) {
    throw new TypeError("decode: maxDepth " + maxDepth + " exceeds the stack-safe ceiling " + constants.LIMITS.MAX_DECODE_DEPTH_CEILING);
  }
  var maxItems = _capOpt(opts.maxItems, "maxItems", constants.LIMITS.CBOR_MAX_ITEMS);
  var rules = _profile(opts.profile);
  if (buf.length > maxBytes) throw new CborError("cbor/too-large", "input " + buf.length + " bytes exceeds cap " + maxBytes);
  var r = _decodeItem(buf, 0, buf.length, 0, maxDepth, rules, { n: 0, max: maxItems });
  if (!opts.allowTrailing && r.end !== buf.length) {
    throw new CborError("cbor/trailing-bytes", (buf.length - r.end) + " trailing byte(s) after the top-level item");
  }
  return r.node;
}

function _expectMajor(node, mt, who) {
  if (!node || node.majorType !== mt) {
    throw new CborError("cbor/unexpected-major", who + ": expected major type " + mt);
  }
}

// Assert a tag node with a specific tag number, and return its one inner item.
function _tagInner(node, tagNum, who) {
  if (!node || node.majorType !== 6 || node.argument !== BigInt(tagNum)) {
    throw new CborError("cbor/unexpected-tag", who + ": expected tag " + tagNum);
  }
  return node.children[0];
}

/**
 * @primitive  pki.cbor.read.uint
 * @signature  pki.cbor.read.uint(node) -> 0n
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 0)
 *
 * The unsigned integer value of a major-type-0 node, as a BigInt (uniform
 * for every magnitude, so the type never varies with the value). Throws
 * `cbor/unexpected-major` on any other major type.
 *
 * @example
 *   pki.cbor.read.uint(node); // -> 0n
 */
function readUint(node) {
  _expectMajor(node, 0, "read.uint");
  return node.argument;
}

/**
 * @primitive  pki.cbor.read.nint
 * @signature  pki.cbor.read.nint(node) -> -1n
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 1)
 *
 * The negative integer value of a major-type-1 node, as a BigInt
 * (value = -1 - argument). Throws `cbor/unexpected-major` otherwise.
 *
 * @example
 *   pki.cbor.read.nint(node); // -> -1n
 */
function readNint(node) {
  _expectMajor(node, 1, "read.nint");
  return -1n - node.argument;
}

/**
 * @primitive  pki.cbor.read.int
 * @signature  pki.cbor.read.int(node) -> -1n
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major types 0 and 1)
 *
 * The signed integer value of a major-type-0 or -1 node, as a BigInt. Throws
 * `cbor/unexpected-major` on any other major type.
 *
 * @example
 *   pki.cbor.read.int(node); // -> -1n
 */
function readInt(node) {
  if (node && node.majorType === 0) return node.argument;
  if (node && node.majorType === 1) return -1n - node.argument;
  throw new CborError("cbor/unexpected-major", "read.int: expected major type 0 or 1");
}

/**
 * @primitive  pki.cbor.read.byteString
 * @signature  pki.cbor.read.byteString(node) -> Buffer
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 2)
 *
 * The zero-copy `Buffer` content of a major-type-2 byte string. Throws
 * `cbor/unexpected-major` otherwise.
 *
 * @example
 *   pki.cbor.read.byteString(node); // -> <Buffer 01 02 03 04>
 */
function readByteString(node) {
  _expectMajor(node, 2, "read.byteString");
  return node.content;
}

/**
 * @primitive  pki.cbor.read.textString
 * @signature  pki.cbor.read.textString(node) -> "text"
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 3)
 *
 * The string value of a major-type-3 text string (already validated as
 * well-formed UTF-8 at decode). Throws `cbor/unexpected-major` otherwise.
 *
 * @example
 *   pki.cbor.read.textString(node); // -> "a"
 */
function readTextString(node) {
  _expectMajor(node, 3, "read.textString");
  return node.content.toString("utf8");
}

/**
 * @primitive  pki.cbor.read.array
 * @signature  pki.cbor.read.array(node) -> [node, ...]
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 4)
 *
 * The element nodes of a major-type-4 array. Throws `cbor/unexpected-major`
 * otherwise.
 *
 * @example
 *   pki.cbor.read.array(node); // -> [node, node, node]
 */
function readArray(node) {
  _expectMajor(node, 4, "read.array");
  return node.children;
}

/**
 * @primitive  pki.cbor.read.map
 * @signature  pki.cbor.read.map(node) -> [[keyNode, valueNode], ...]
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 5)
 *
 * The ordered key/value node pairs of a major-type-5 map (ordering and
 * uniqueness already enforced at decode). Throws `cbor/unexpected-major`
 * otherwise.
 *
 * @example
 *   pki.cbor.read.map(node); // -> [[keyNode, valueNode]]
 */
function readMap(node) {
  _expectMajor(node, 5, "read.map");
  return node.children;
}

/**
 * @primitive  pki.cbor.read.boolean
 * @signature  pki.cbor.read.boolean(node) -> false
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.3 (simple values 20 / 21)
 *
 * The boolean value of a simple-value node (false=20, true=21). Throws
 * `cbor/unexpected-major` on a non-simple node, `cbor/bad-simple` on any
 * other simple value.
 *
 * @example
 *   pki.cbor.read.boolean(node); // -> true
 */
function readBoolean(node) {
  _expectMajor(node, 7, "read.boolean");
  if (node.ai === 20) return false;
  if (node.ai === 21) return true;
  throw new CborError("cbor/bad-simple", "read.boolean: simple value " + node.ai + " is not a boolean");
}

/**
 * @primitive  pki.cbor.read.nullValue
 * @signature  pki.cbor.read.nullValue(node) -> null
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.3 (simple value 22)
 *
 * `null` for a simple-value-22 node. Throws `cbor/unexpected-major` on a
 * non-simple node, `cbor/bad-simple` on any other simple value.
 *
 * @example
 *   pki.cbor.read.nullValue(node); // -> null
 */
function readNull(node) {
  _expectMajor(node, 7, "read.nullValue");
  if (node.ai !== 22) throw new CborError("cbor/bad-simple", "read.nullValue: simple value " + node.ai + " is not null");
  return null;
}

/**
 * @primitive  pki.cbor.read.undefinedValue
 * @signature  pki.cbor.read.undefinedValue(node) -> undefined
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.3 (simple value 23)
 *
 * `undefined` for a simple-value-23 node. Throws `cbor/unexpected-major` on a
 * non-simple node, `cbor/bad-simple` on any other simple value.
 *
 * @example
 *   pki.cbor.read.undefinedValue(node); // -> undefined
 */
function readUndefined(node) {
  _expectMajor(node, 7, "read.undefinedValue");
  if (node.ai !== 23) throw new CborError("cbor/bad-simple", "read.undefinedValue: simple value " + node.ai + " is not undefined");
  return undefined;
}

/**
 * @primitive  pki.cbor.read.float
 * @signature  pki.cbor.read.float(node) -> 1.5
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.1 (major type 7 floats)
 *
 * The JS number (double) of a half / single / double float node (the
 * shortest-form and canonical-NaN rules already enforced at decode). Throws
 * `cbor/unexpected-major` on a non-major-7 node, `cbor/bad-simple` on a
 * simple value that is not a float.
 *
 * @example
 *   pki.cbor.read.float(node); // -> 1.5
 */
function readFloat(node) {
  _expectMajor(node, 7, "read.float");
  if (node.ai !== 25 && node.ai !== 26 && node.ai !== 27) {
    throw new CborError("cbor/bad-simple", "read.float: node is a simple value, not a float");
  }
  return _readFloatBits(node.argument, node.ai);
}

/**
 * @primitive  pki.cbor.read.biguint
 * @signature  pki.cbor.read.biguint(node) -> 18446744073709551616n
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.4.3 (tag 2 unsigned bignum)
 *
 * The BigInt value of a tag-2 unsigned bignum (a big-endian magnitude byte
 * string, no sign octet). Enforces the byte cap
 * (`cbor/biguint-too-large`), the no-leading-zero and prefer-basic-int
 * minimality rules (`cbor/non-minimal-biguint`), and the wrapped content type
 * (`cbor/bad-tag-content`); a wrong / absent tag throws `cbor/unexpected-tag`.
 *
 * @example
 *   pki.cbor.read.biguint(node); // -> 18446744073709551616n
 */
function readBiguint(node) {
  var inner = _tagInner(node, 2, "read.biguint");
  if (inner.majorType !== 2) throw new CborError("cbor/bad-tag-content", "read.biguint: tag 2 must wrap a byte string");
  var c = inner.content;
  if (c.length > constants.LIMITS.CBOR_MAX_BIGUINT_BYTES) {
    throw new CborError("cbor/biguint-too-large", "bignum " + c.length + " bytes exceeds cap " + constants.LIMITS.CBOR_MAX_BIGUINT_BYTES);
  }
  if (c.length > 0 && c[0] === 0x00) throw new CborError("cbor/non-minimal-biguint", "bignum has a leading zero byte");
  if (c.length <= 8) throw new CborError("cbor/non-minimal-biguint", "a value that fits a basic integer must not use a bignum");
  return BigInt("0x" + c.toString("hex"));
}

/**
 * @primitive  pki.cbor.read.time
 * @signature  pki.cbor.read.time(node) -> Date
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 8949 sec. 3.4.2 (tag 1 epoch date/time)
 *
 * The `Date` of a tag-1 epoch time (seconds since 1970-01-01T00:00Z, integer).
 * Throws `cbor/unexpected-tag` on a wrong / absent tag, `cbor/bad-tag-content`
 * when tag 1 does not wrap an integer, `cbor/bad-time` on an out-of-range value.
 *
 * @example
 *   pki.cbor.read.time(node); // -> Date 2013-03-21T20:04:00.000Z
 */
function readTime(node) {
  var inner = _tagInner(node, 1, "read.time");
  if (inner.majorType !== 0 && inner.majorType !== 1) {
    throw new CborError("cbor/bad-tag-content", "read.time: tag 1 must wrap an integer");
  }
  var secs = inner.majorType === 0 ? inner.argument : (-1n - inner.argument);
  if (secs < -_MAX_EPOCH_SECONDS || secs > _MAX_EPOCH_SECONDS) {
    throw new CborError("cbor/bad-time", "epoch time out of range");
  }
  var ns = Number(secs);
  var d = new Date(ns < 0 ? -constants.TIME.seconds(-ns) : constants.TIME.seconds(ns));
  if (isNaN(d.getTime())) throw new CborError("cbor/bad-time", "epoch time out of range");
  return d;
}

/**
 * @primitive  pki.cbor.read.oid
 * @signature  pki.cbor.read.oid(node) -> "2.5.4.3"
 * @since      0.1.27
 * @status     experimental
 * @spec       RFC 9090 (tag 111 CBOR OID)
 *
 * The dotted OID string of a tag-111 CBOR OID (a byte string carrying the BER
 * object-identifier content octets, decoded through the shared
 * `asn1.decodeOidContent`, so a malformed body surfaces the existing `oid/*`
 * codes). Throws `cbor/unexpected-tag` on a wrong / absent tag,
 * `cbor/bad-tag-content` when tag 111 does not wrap a byte string.
 *
 * @example
 *   pki.cbor.read.oid(node); // -> "2.5.4.3"
 */
function readOid(node) {
  var inner = _tagInner(node, 111, "read.oid");
  if (inner.majorType !== 2) throw new CborError("cbor/bad-tag-content", "read.oid: tag 111 must wrap a byte string");
  return asn1.decodeOidContent(inner.content);
}

module.exports = {
  decode: decode,
  read: {
    uint:           readUint,
    nint:           readNint,
    int:            readInt,
    byteString:     readByteString,
    textString:     readTextString,
    array:          readArray,
    map:            readMap,
    boolean:        readBoolean,
    nullValue:      readNull,
    undefinedValue: readUndefined,
    float:          readFloat,
    biguint:        readBiguint,
    time:           readTime,
    oid:            readOid,
  },
};
