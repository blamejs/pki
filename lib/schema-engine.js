// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.engine
 * @nav        Schema
 * @title      Schema engine
 * @fullname   ASN.1 schema engine: one definition drives encode and decode
 * @order      60
 *
 * @intro
 *   L2 of the ASN.1 stack: a declarative structure-schema engine. A schema is
 *   plain data (`{kind, ...}` descriptors built by the combinators here) and
 *   `walk(schema, node, ctx)` interprets it against a decoded DER node. The
 *   engine is where every cross-cutting structural rule lives ONCE: the shape
 *   assertion (SEQUENCE / SET / bare-constructed), bounds-checked positional
 *   reads, optional and context-tagged fields in strictly-increasing tag order,
 *   SET-OF uniqueness, and fail-closed typed errors. A format module declares a
 *   schema and calls `walk` under an error namespace `ctx = { E, prefix, oid }`;
 *   it never hand-rolls `children[idx++]`, so the positional-read and
 *   duplicate-field bug classes are structurally retired. This is the shared
 *   base the certificate parser (and, later, CRL / CMS) composes.
 *
 * @card
 *   Declarative ASN.1 structure schemas plus one walk engine: the shared base the
 *   certificate / CRL / CMS parsers compose instead of hand-writing.
 */

var asn1 = require("./asn1-der.js");

var TAGS = asn1.TAGS;


function _fail(ctx, code, message) {
  throw ctx.E(code, message);
}


function _assertShape(schema, node, ctx) {
  var mode = schema.assert || "sequence";
  if (mode === "sequence") {
    if (node.tagClass !== "universal" || node.tagNumber !== TAGS.SEQUENCE || !node.children) {
      _fail(ctx, schema.code, (schema.what || "value") + " must be a SEQUENCE");
    }
  } else if (mode === "set") {
    if (node.tagClass !== "universal" || node.tagNumber !== TAGS.SET || !node.children) {
      _fail(ctx, schema.code, (schema.what || "value") + " must be a SET");
    }
  } else if (mode === "constructed") {
    if (!node.children) {
      _fail(ctx, schema.code, (schema.what || "value") + " must be a constructed value");
    }
  } else if (mode === "implicit") {
    if (node.tagClass !== "context" || node.tagNumber !== schema.implicitTag || !node.children) {
      _fail(ctx, schema.code, (schema.what || "value") + " must be an IMPLICIT [" + schema.implicitTag + "] constructed value");
    }
  } else {
    _fail(ctx, schema.code, "unknown assert mode " + JSON.stringify(mode));
  }
  return node.children;
}

function _assertArity(schema, kids, ctx) {
  var a = schema.arity;
  if (!a) return;
  if (a.exact != null && kids.length !== a.exact) {
    _fail(ctx, schema.code, (schema.what || "value") + " must have exactly " + a.exact + " elements");
  }
  if (a.min != null && kids.length < a.min) {
    _fail(ctx, schema.code, (schema.what || "value") + " must have at least " + a.min + " elements");
  }
  if (a.max != null && kids.length > a.max) {
    _fail(ctx, schema.code, (schema.what || "value") + " must have at most " + a.max + " elements");
  }
}


function _implicitIntContent(v) { return asn1.decode(asn1.build.integer(v)).content; }
function oidLeaf()        { return { kind: "leaf", read: asn1.read.oid, write: function (v) { return asn1.build.oid(v); } }; }
function integerLeaf()    { return { kind: "leaf", read: asn1.read.integer, write: function (v) { return asn1.build.integer(v); } }; }
function boolean()        { return { kind: "leaf", read: asn1.read.boolean, write: function (v) { return asn1.build.boolean(v); } }; }
function octetString()    { return { kind: "leaf", read: asn1.read.octetString, write: function (v) { return asn1.build.octetString(v); } }; }
function bitString()      { return { kind: "leaf", read: function (n) { var b = asn1.read.bitString(n); return { unusedBits: b.unusedBits, bytes: b.bytes }; }, write: function (v) { return asn1.build.bitString(v.bytes, v.unusedBits); } }; }
function implicitBitString(tag) { return { kind: "leaf", read: function (n) { var b = asn1.read.bitStringImplicit(n, tag); return { unusedBits: b.unusedBits, bytes: b.bytes }; }, write: function (v) { return asn1.build.contextPrimitive(tag, Buffer.concat([Buffer.from([v.unusedBits]), v.bytes])); } }; }
function implicitOctetString(tag) { return { kind: "leaf", read: function (n) { return asn1.read.octetStringImplicit(n, tag); }, write: function (v) { return asn1.build.contextPrimitive(tag, v); } }; }
function implicitNull(tag) { return { kind: "leaf", read: function (n) { return asn1.read.nullImplicit(n, tag); }, write: function () { return asn1.build.contextPrimitive(tag, Buffer.alloc(0)); } }; }
function implicitInteger(tag) { return { kind: "leaf", read: function (n) { return asn1.read.integerImplicit(n, tag); }, write: function (v) { return asn1.build.contextPrimitive(tag, _implicitIntContent(v)); } }; }
function implicitBoolean(tag) { return { kind: "leaf", read: function (n) { return asn1.read.booleanImplicit(n, tag); }, write: function (v) { return asn1.build.contextPrimitive(tag, Buffer.from([v ? 0xff : 0x00])); } }; }
function any()            { return { kind: "any" }; }
function decode(fn, write) { return { kind: "decode", fn: fn, write: write }; }

function time(ns) {
  return decode(function (n, ctx) {
    if (n.tagClass !== "universal" || (n.tagNumber !== TAGS.UTC_TIME && n.tagNumber !== TAGS.GENERALIZED_TIME)) {
      _fail(ctx, ns.prefix + "/bad-time", "time must be UTCTime or GeneralizedTime");
    }
    return asn1.read.time(n);
  }, function (date) {
    var y = date.getUTCFullYear();
    return (y >= 1950 && y < 2050) ? asn1.build.utcTime(date) : asn1.build.generalizedTime(date);
  });
}


function field(name, schema)          { return { fkind: "required", name: name, schema: schema }; }
function optional(name, schema, opts) {
  opts = opts || {};
  var match = opts.whenAny
    ? function () { return true; }
    : opts.whenUniversal
      ? function (n) { return isUniversalOneOf(n, opts.whenUniversal); }
      : opts.tags
        ? function (n) { return isContextOneOf(n, opts.tags); }
        : function (n) { return isContext(n, opts.tag); };
  return { fkind: "optional", name: name, schema: schema, tag: opts.tag, match: match,
           explicit: !!opts.explicit, emptyCode: opts.emptyCode, hasDefault: ("default" in opts), def: opts.default,
           defaultCode: opts.defaultCode };
}
function trailing(members, opts) {
  opts = opts || {};
  return { fkind: "trailing", members: members, minTag: opts.minTag, maxTag: opts.maxTag,
           unexpectedCode: opts.unexpectedCode, orderCode: opts.orderCode };
}


function seq(fields, opts) {
  opts = opts || {};
  return { kind: "seq", fields: fields, assert: opts.assert || "sequence", implicitTag: opts.implicitTag, arity: opts.arity,
           code: opts.code, what: opts.what, build: opts.build, checks: opts.checks || [] };
}

function explicit(tag, schema, opts) {
  opts = opts || {};
  return { kind: "explicit", tag: tag, schema: schema, emptyCode: opts.emptyCode, code: opts.code, what: opts.what };
}

function choice(alts, opts) {
  opts = opts || {};
  return { kind: "choice", alts: alts, code: opts.code, what: opts.what };
}

function seqOf(item, opts) {
  opts = opts || {};
  return { kind: "repeat", item: item, assert: opts.assert || "sequence", code: opts.code, what: opts.what,
           min: opts.min, max: opts.max, maxCode: opts.maxCode,
           unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}
function setOf(item, opts) {
  opts = opts || {};
  return { kind: "repeat", item: item, assert: opts.assert || "set", derSetOrder: true, code: opts.code, what: opts.what,
           min: opts.min, max: opts.max, maxCode: opts.maxCode,
           unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}
function setOfUnique(item, keyFn, opts) {
  return setOf(item, Object.assign({ unique: keyFn }, opts || {}));
}
function implicitSetOf(tag, item, opts) {
  opts = opts || {};
  return { kind: "repeat", item: item, assert: "implicit", implicitTag: tag, derSetOrder: true, code: opts.code, what: opts.what,
           min: opts.min, max: opts.max, maxCode: opts.maxCode,
           unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}
function implicitSeqOf(tag, item, opts) {
  opts = opts || {};
  return { kind: "repeat", item: item, assert: "implicit", implicitTag: tag, code: opts.code, what: opts.what,
           min: opts.min, max: opts.max, maxCode: opts.maxCode,
           unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}


/**
 * @primitive  pki.schema.engine.walk
 * @signature  pki.schema.engine.walk(schema, node, ctx) -> value
 * @since      0.1.7
 * @status     stable
 * @spec       X.690, X.680
 * @related    pki.asn1.decode, pki.schema.x509.parse
 *
 * Interpret a declarative schema against a decoded DER node, enforcing the
 * schema's structural rules (shape assertion, arity, optional / context-tagged
 * fields in increasing tag order, SET-OF uniqueness) and returning the built
 * value, or the match tree (`{ node, fields | items }`, with the build output
 * on `.result`) for a structure with no build fn. `ctx = { E, prefix, oid }`
 * supplies the typed-error constructor, the error-code family prefix, and the
 * OID registry a build fn resolves names through.
 *
 * The schema is assembled from the combinators this module exports: structural
 * (`seq` / `field` / `optional` / `explicit` / `trailing` / `seqOf` / `setOf` /
 * `setOfUnique` / `implicitSeqOf` / `implicitSetOf` / `choice`) and value
 * (`oidLeaf` / `integerLeaf` / `boolean` / `octetString` / `bitString` /
 * `implicitBitString` / `implicitOctetString` / `implicitNull` /
 * `implicitInteger` / `any` / `decode` / `time`).
 *
 * @example
 *   var S = pki.schema.engine;
 *   // `E` is an error FACTORY (called without `new`), so a domain can raise its own type
 *   var MyError = function (code, msg) { var e = new Error(msg); e.code = code; return e; };
 *   var der = pki.asn1.build.sequence([pki.asn1.build.oid("1.3.101.112")]);
 *   var ALGID = S.seq([S.field("algorithm", S.oidLeaf())],
 *     { assert: "sequence", arity: { min: 1 }, code: "app/bad-alg" });
 *   S.walk(ALGID, pki.asn1.decode(der), { prefix: "app", E: MyError, oid: pki.oid });
 */
function walk(schema, node, ctx) {
  switch (schema.kind) {
    case "leaf":   return schema.read(node);
    case "any":    return node;
    case "decode": return schema.fn(node, ctx);
    case "seq":    return _walkSeq(schema, node, ctx);
    case "explicit": return _walkExplicit(schema, node, ctx);
    case "repeat": return _walkRepeat(schema, node, ctx);
    case "choice": return _walkChoice(schema, node, ctx);
    default: _fail(ctx, (ctx.prefix || "schema") + "/bad-schema", "unknown schema kind " + JSON.stringify(schema.kind));
  }
  return undefined;
}

function _explicitInner(node, tag, ctx, code) {
  if (!node.children || node.children.length !== 1) {
    _fail(ctx, code, "EXPLICIT [" + tag + "] must wrap exactly one value");
  }
  return node.children[0];
}

function _walkExplicit(schema, node, ctx) {
  if (node.tagClass !== "context" || node.tagNumber !== schema.tag) {
    _fail(ctx, schema.emptyCode || schema.code, "expected an EXPLICIT [" + schema.tag + "] wrapper");
  }
  return walk(schema.schema, _explicitInner(node, schema.tag, ctx, schema.emptyCode || schema.code), ctx);
}

function _walkChoice(schema, node, ctx) {
  for (var i = 0; i < schema.alts.length; i++) {
    var w = schema.alts[i].when;
    if (node.tagClass === w.tagClass && node.tagNumber === w.tagNumber) {
      return walk(schema.alts[i].schema, node, ctx);
    }
  }
  _fail(ctx, schema.code, "no CHOICE alternative matched " + node.tagClass + "/" + node.tagNumber);
  return undefined;
}

function _walkRepeat(schema, node, ctx) {
  var kids = _assertShape(schema, node, ctx);
  if (schema.min != null && kids.length < schema.min) {
    _fail(ctx, schema.code, (schema.what || "value") + " must contain at least " + schema.min + " element(s)");
  }
  if (schema.max != null && kids.length > schema.max) {
    _fail(ctx, schema.maxCode || schema.code, (schema.what || "value") + " exceeds the element cap " + schema.max);
  }
  if (schema.derSetOrder) {
    for (var s = 1; s < kids.length; s++) {
      if (Buffer.compare(kids[s - 1].bytes, kids[s].bytes) > 0) {
        _fail(ctx, schema.code, (schema.what || "value") + " components must be in ascending DER order (X.690 sec. 11.6)");
      }
    }
  }
  var items = [];
  var seen = schema.unique ? new Set() : null;
  for (var i = 0; i < kids.length; i++) {
    var item = { node: kids[i], value: walk(schema.item, kids[i], ctx) };
    if (seen) {
      var key = schema.unique(item);
      if (seen.has(key)) _fail(ctx, schema.dupCode || schema.code, "duplicate element " + key);
      seen.add(key);
    }
    items.push(item);
  }
  var match = { kind: "repeat", node: node, items: items };
  if (schema.build) match.result = schema.build(match, ctx);
  return match;
}

function _equalsDefault(value, def) {
  if (Buffer.isBuffer(value) && Buffer.isBuffer(def)) return value.equals(def);
  return value === def;
}

function _walkSeq(schema, node, ctx) {
  var kids = _assertShape(schema, node, ctx);
  _assertArity(schema, kids, ctx);

  var fields = {};
  var idx = 0;
  for (var f = 0; f < schema.fields.length; f++) {
    var fld = schema.fields[f];
    if (fld.fkind === "required") {
      if (idx >= kids.length) _fail(ctx, schema.code, "missing required field " + JSON.stringify(fld.name));
      var child = kids[idx++];
      fields[fld.name] = { node: child, value: walk(fld.schema, child, ctx) };
    } else if (fld.fkind === "optional") {
      var next = idx < kids.length ? kids[idx] : null;
      if (next && fld.match(next)) {
        idx++;
        var inner = next;
        if (fld.explicit) {
          inner = _explicitInner(next, fld.tag, ctx, fld.emptyCode || schema.code);
        }
        var val = walk(fld.schema, inner, ctx);
        if (fld.defaultCode != null && fld.hasDefault && _equalsDefault(val, fld.def)) {
          _fail(ctx, fld.defaultCode, "field " + JSON.stringify(fld.name) + " explicitly encodes its DEFAULT value (X.690 sec. 11.5)");
        }
        fields[fld.name] = { node: next, present: true, value: val };
      } else {
        fields[fld.name] = { present: false, value: fld.hasDefault ? fld.def : undefined };
      }
    } else if (fld.fkind === "trailing") {
      _consumeTrailing(fld, kids, idx, fields, ctx);
      idx = kids.length;
    } else {
      _fail(ctx, (ctx.prefix || "schema") + "/bad-schema", "unknown field kind " + JSON.stringify(fld && fld.fkind));
    }
  }

  if (idx < kids.length) {
    _fail(ctx, schema.code, (schema.what || "value") + " has an unexpected element after its last field");
  }

  var match = { kind: "seq", node: node, fields: fields };
  for (var c = 0; c < schema.checks.length; c++) schema.checks[c](match, ctx);
  if (schema.build) match.result = schema.build(match, ctx);
  return match;
}

function _consumeTrailing(fld, kids, start, fields, ctx) {
  var byTag = {};
  for (var m = 0; m < fld.members.length; m++) byTag[fld.members[m].tag] = fld.members[m];
  var last = fld.minTag != null ? fld.minTag - 1 : -1;
  for (var i = start; i < kids.length; i++) {
    var t = kids[i];
    if (t.tagClass !== "context" || (fld.minTag != null && t.tagNumber < fld.minTag) || (fld.maxTag != null && t.tagNumber > fld.maxTag) || !byTag[t.tagNumber]) {
      _fail(ctx, fld.unexpectedCode, "unexpected trailing field [" + (t.tagClass === "context" ? t.tagNumber : t.tagClass) + "]");
    }
    if (t.tagNumber <= last) _fail(ctx, fld.orderCode, "trailing field [" + t.tagNumber + "] is repeated or out of order");
    last = t.tagNumber;
    var member = byTag[t.tagNumber];
    var inner = t;
    if (member.explicit) {
      inner = _explicitInner(t, t.tagNumber, ctx, member.emptyCode);
    }
    fields[member.name] = { node: t, present: true, value: walk(member.schema, inner, ctx) };
  }
  for (var n = 0; n < fld.members.length; n++) {
    if (!fields[fld.members[n].name]) fields[fld.members[n].name] = { present: false, value: undefined };
  }
}


function _encFail(message) { throw new Error("schema.encode: " + message); }

/**
 * @primitive  pki.schema.engine.encode
 * @signature  pki.schema.engine.encode(schema, value, ctx) -> Buffer
 * @since      0.1.17
 * @status     stable
 * @spec       X.690, X.680
 * @related    pki.schema.engine.walk
 *
 * Encode a structural value to canonical DER by interpreting the same schema
 * `walk` decodes, in the constructor direction. `value` mirrors the schema: a `seq`
 * takes `{ fieldName: value }`, a leaf its natural JS value (an OID string, a
 * BigInt, a `{ unusedBits, bytes }` BIT STRING, a `Date`), a `repeat` an array, a
 * `choice` `{ arm, value }`. EXPLICIT wrappers and IMPLICIT `[tag]` retagging are
 * applied by the engine, so `walk(schema, decode(encode(schema, v)))` round-trips.
 *
 * @example
 *   var S = pki.schema.engine;
 *   var der = S.encode(S.seq([S.field("n", S.integerLeaf())]), { n: 42n });
 */
function encode(schema, value, ctx) {
  switch (schema.kind) {
    case "leaf":     return schema.write(value);
    case "any":      return Buffer.isBuffer(value) ? value : value.bytes;
    case "decode":
      if (typeof schema.write !== "function") _encFail("this decode leaf has no paired encoder (decode(fn, write))");
      return schema.write(value, ctx);
    case "seq":      return _encodeSeq(schema, value, ctx);
    case "explicit": return asn1.build.explicit(schema.tag, encode(schema.schema, value, ctx));
    case "repeat":   return _encodeRepeat(schema, value, ctx);
    case "choice":   return _encodeChoice(schema, value, ctx);
    default:         _encFail("cannot encode schema kind " + JSON.stringify(schema.kind));
  }
  return undefined;
}

function _wrapConstructed(schema, parts) {
  if (schema.implicitTag != null) return asn1.build.contextConstructed(schema.implicitTag, Buffer.concat(parts));
  var mode = schema.assert || "sequence";
  if (mode === "set") return asn1.build.set(parts);
  if (mode === "sequence" || mode === "constructed") return asn1.build.sequence(parts);
  _encFail("cannot encode a seq/repeat with assert " + JSON.stringify(mode));
  return undefined;
}

function _present(v) { return v !== undefined && v !== null; }

function _encodeSeq(schema, value, ctx) {
  value = value || {};
  var parts = [];
  for (var f = 0; f < schema.fields.length; f++) {
    var fld = schema.fields[f];
    if (fld.fkind === "required") {
      parts.push(encode(fld.schema, value[fld.name], ctx));
    } else if (fld.fkind === "optional") {
      if (_present(value[fld.name])) {
        var enc = encode(fld.schema, value[fld.name], ctx);
        var isDefault = fld.hasDefault && fld.def !== undefined &&
          enc.equals(encode(fld.schema, fld.def, ctx));
        if (!isDefault) parts.push(fld.explicit ? asn1.build.explicit(fld.tag, enc) : enc);
      }
    } else if (fld.fkind === "trailing") {
      var members = fld.members.slice().sort(function (a, b) { return a.tag - b.tag; });
      for (var i = 0; i < members.length; i++) {
        var mm = members[i];
        if (_present(value[mm.name])) {
          var menc = encode(mm.schema, value[mm.name], ctx);
          parts.push(mm.explicit ? asn1.build.explicit(mm.tag, menc) : menc);
        }
      }
    } else {
      _encFail("unknown field kind " + JSON.stringify(fld && fld.fkind));
    }
  }
  return _wrapConstructed(schema, parts);
}

function _encodeRepeat(schema, items, ctx) {
  if (!Array.isArray(items)) _encFail("a repeat value must be an array");
  if (schema.min != null && items.length < schema.min) {
    _encFail("this repeat requires at least " + schema.min + " element(s) but got " + items.length);
  }
  if (schema.max != null && items.length > schema.max) {
    _encFail("this repeat caps at " + schema.max + " element(s) but got " + items.length);
  }
  var parts = items.map(function (it) { return encode(schema.item, it, ctx); });
  if (schema.unique) {
    var seen = new Set();
    parts.forEach(function (tlv) {
      var item = { node: asn1.decode(tlv) };
      item.value = walk(schema.item, item.node, ctx);
      var key = schema.unique(item);
      if (seen.has(key)) _encFail("this repeat requires unique elements but got a duplicate key: " + key);
      seen.add(key);
    });
  }
  if (schema.derSetOrder) parts = parts.slice().sort(Buffer.compare);
  if (schema.implicitTag != null) return asn1.build.contextConstructed(schema.implicitTag, Buffer.concat(parts));
  return schema.assert === "set" ? asn1.build.set(parts) : asn1.build.sequence(parts);
}

function _encodeChoice(schema, value, ctx) {
  if (!value || !Number.isInteger(value.arm) || value.arm < 0 || value.arm >= schema.alts.length) {
    _encFail("a choice value must be { arm: <index>, value: <arm value> }");
  }
  return encode(schema.alts[value.arm].schema, value.value, ctx);
}

/**
 * @primitive  pki.schema.engine.embeddedDer
 * @signature  pki.schema.engine.embeddedDer(schema, bytes, ctx, opts?) -> value
 * @since      0.1.18
 * @status     stable
 * @spec       X.690
 * @defends    ASN.1-parser-DoS (CWE-400)
 * @related    pki.schema.engine.walk, pki.asn1.decode
 *
 * Decode a fresh DER (or, with `ber: true`, BER) blob carried inside an
 * already-decoded value (an OCTET STRING whose content is itself an encoded
 * structure) and walk it against a schema. A codec failure is wrapped in the
 * caller's typed `code`; a schema rejection keeps its own code. This is the
 * one named form of the re-decode idiom, so the caps that a fresh
 * `pki.asn1.decode` would restart from zero can be carried across re-decode
 * boundaries: a shared `budget` (`{ remaining: n }`) decrements on every call
 * and fails with `budgetCode` at zero, bounding how many nested blobs one
 * parse may unwrap however deeply a container chains them.
 *
 * @opts
 *   code:       string,   // typed code wrapping a codec failure (required)
 *   what:       string,   // human label for the wrapped message
 *   ber:        boolean,  // default false; BER content region (RFC 7292 sec. 4.1)
 *   budget:     object,   // { remaining: n } shared across a parse's re-decodes
 *   budgetCode: string,   // typed code when the budget is exhausted
 *
 * @example
 *   var S = pki.schema.engine;
 *   var MyError = function (code, msg) { var e = new Error(msg); e.code = code; return e; };
 *   var INNER = S.seq([S.field("version", S.integerLeaf())], { code: "app/bad-inner" });
 *   var ns = { prefix: "app", E: MyError, oid: pki.oid };
 *   S.embeddedDer(INNER, pki.asn1.build.sequence([pki.asn1.build.integer(3n)]), ns,
 *     { code: "app/bad-der", what: "the embedded structure" });
 */
function embeddedDer(schema, bytes, ctx, opts) {
  opts = opts || {};
  if (opts.budget) {
    if (!(opts.budget.remaining > 0)) {
      throw ctx.E(opts.budgetCode || opts.code, (opts.what || "embedded DER") +
        ": the cross-decode budget is exhausted (nesting chained across too many re-decode boundaries)");
    }
    opts.budget.remaining -= 1;
  }
  var node;
  try {
    node = asn1.decode(bytes, opts.ber ? { ber: true } : undefined);
  } catch (e) {
    throw ctx.E(opts.code, (opts.what || "embedded DER") + " did not decode: " + e.message, e);
  }
  return walk(schema, node, ctx);
}

function isUniversal(node, tagNumber) {
  return !!node && node.tagClass === "universal" && node.tagNumber === tagNumber;
}
function isContext(node, tagNumber) {
  return !!node && node.tagClass === "context" && node.tagNumber === tagNumber;
}
function isUniversalOneOf(node, tagNumbers) {
  return !!node && node.tagClass === "universal" && tagNumbers.indexOf(node.tagNumber) !== -1;
}
function isContextOneOf(node, tagNumbers) {
  return !!node && node.tagClass === "context" && tagNumbers.indexOf(node.tagNumber) !== -1;
}
function isContextInRange(node, min, max) {
  return !!node && node.tagClass === "context" && node.tagNumber >= min && node.tagNumber <= max;
}

function assertMinimalNamedBits(unusedBits, bytes, fail) {
  if (bytes.length === 0) {
    if (unusedBits !== 0) fail("an empty NamedBitList must encode with 0 unused bits (X.690 sec. 11.2.2)");
    return;
  }
  var last = bytes[bytes.length - 1];
  if (last === 0) fail("a NamedBitList must not carry a trailing all-zero octet (X.690 sec. 11.2.2)");
  if (((last >> unusedBits) & 1) !== 1) fail("a NamedBitList must drop all trailing zero bits (X.690 sec. 11.2.2)");
}

module.exports = {
  seq: seq, field: field, optional: optional, explicit: explicit, trailing: trailing,
  seqOf: seqOf, setOf: setOf, setOfUnique: setOfUnique, implicitSetOf: implicitSetOf, implicitSeqOf: implicitSeqOf, choice: choice,
  oidLeaf: oidLeaf, integerLeaf: integerLeaf, boolean: boolean, octetString: octetString,
  bitString: bitString, implicitBitString: implicitBitString, implicitOctetString: implicitOctetString,
  implicitNull: implicitNull, implicitInteger: implicitInteger, implicitBoolean: implicitBoolean,
  any: any, decode: decode, time: time,
  walk: walk, encode: encode, embeddedDer: embeddedDer, assertMinimalNamedBits: assertMinimalNamedBits,
  isUniversal: isUniversal, isContext: isContext,
  isUniversalOneOf: isUniversalOneOf, isContextOneOf: isContextOneOf, isContextInRange: isContextInRange,
};
