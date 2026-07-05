// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.engine
 * @nav        Schema
 * @title      Schema engine
 * @order      60
 *
 * @intro
 *   L2 of the ASN.1 stack — a declarative structure-schema engine. A schema is
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
 *   Declarative ASN.1 structure schemas + one walk engine — the shared base the
 *   certificate / CRL / CMS parsers compose instead of hand-writing.
 */

var asn1 = require("./asn1-der.js");

var TAGS = asn1.TAGS;

// ---- context ---------------------------------------------------------
// A walk receives ctx = { E, prefix, oid } where E(code, message) constructs
// (does not throw) the format's typed error, prefix names the error family
// ("x509", "crl", ...) and oid is the OID registry (for name resolution in a
// build fn). _fail throws so a schema node reads as a single expression.

function _fail(ctx, code, message) {
  throw ctx.E(code, message);
}

// ---- shape assertions ------------------------------------------------
// A schema's `assert` mode is a real behaviour-preservation control: some
// hand-written guards checked the universal SEQUENCE tag (algorithmIdentifier,
// Name), others checked only that the node had children (Validity, SPKI, the
// tbs body, an AttributeTypeAndValue). Collapsing them to one "is a SEQUENCE"
// check would silently change behaviour on SET-wrapped input, so each is kept.

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
    // Bare constructed: the historical guards only required decoded children,
    // never a specific universal tag.
    if (!node.children) {
      _fail(ctx, schema.code, (schema.what || "value") + " must be a constructed value");
    }
  } else if (mode === "implicit") {
    // IMPLICIT [tag] SET/SEQUENCE OF: the context tag replaces the universal
    // tag, so the node is a context-class constructed [tag] and its direct
    // children are the items (no inner universal SET, no EXPLICIT unwrap).
    if (node.tagClass !== "context" || node.tagNumber !== schema.implicitTag || !node.children) {
      _fail(ctx, schema.code, (schema.what || "value") + " must be an IMPLICIT [" + schema.implicitTag + "] SET OF");
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
}

// ---- leaf / value combinators ---------------------------------------
// Leaves read a primitive off a node via the L1 codec; the codec's own
// asn1/* errors propagate unchanged (the frozen oracle expects those codes on
// the OID / INTEGER / string reads). `decode(fn)` hands the whole node to fn,
// which owns its try/catch and code mapping. `any()` yields the node itself.

function oidLeaf()        { return { kind: "leaf", read: asn1.read.oid }; }
function integerLeaf()    { return { kind: "leaf", read: asn1.read.integer }; }
function boolean()        { return { kind: "leaf", read: asn1.read.boolean }; }
function octetString()    { return { kind: "leaf", read: asn1.read.octetString }; }
function bitString()      { return { kind: "leaf", read: function (n) { var b = asn1.read.bitString(n); return { unusedBits: b.unusedBits, bytes: b.bytes }; } }; }
function any()            { return { kind: "any" }; }
function decode(fn)       { return { kind: "decode", fn: fn }; }

// time(ns): a UTCTime / GeneralizedTime value, asserting the tag before the
// codec reads it (mirrors _parseValidityTime's x509/bad-time guard).
function time(ns) {
  return decode(function (n, ctx) {
    if (n.tagClass !== "universal" || (n.tagNumber !== TAGS.UTC_TIME && n.tagNumber !== TAGS.GENERALIZED_TIME)) {
      _fail(ctx, ns.prefix + "/bad-time", "time must be UTCTime or GeneralizedTime");
    }
    return asn1.read.time(n);
  });
}

// ---- field descriptors (members of a seq) ---------------------------

function field(name, schema)          { return { fkind: "required", name: name, schema: schema }; }
function optional(name, schema, opts) {
  opts = opts || {};
  // How the optional field is recognized at its position:
  //   - default:       a context [tag] (the certificate version [0] shape).
  //   - whenUniversal: the next element iff its UNIVERSAL tag is in the set —
  //     the CRL TBSCertList shape (bare INTEGER version, Time nextUpdate,
  //     SEQUENCE revokedCertificates), disambiguated by tag, not a context [n].
  //   - whenAny:       the next element whatever its tag — an OPTIONAL ANY like
  //     AlgorithmIdentifier.parameters.
  // The recognizer lets _walkSeq CONSUME the element so a closed sequence can
  // reject whatever is left over (without it, a trailing ANY looks unconsumed).
  var match = opts.whenAny
    ? function () { return true; }
    : opts.whenUniversal
      ? function (n) { return n.tagClass === "universal" && opts.whenUniversal.indexOf(n.tagNumber) !== -1; }
      : function (n) { return n.tagClass === "context" && n.tagNumber === opts.tag; };
  return { fkind: "optional", name: name, schema: schema, tag: opts.tag, match: match,
           explicit: !!opts.explicit, emptyCode: opts.emptyCode, hasDefault: ("default" in opts), def: opts.default };
}
// trailing: the [minTag..maxTag] optional context fields, each at most once in
// strictly-increasing tag order (the tbs issuerUniqueID[1]/subjectUniqueID[2]/
// extensions[3] block). members: [{ tag, name, schema, explicit? }].
function trailing(members, opts) {
  opts = opts || {};
  return { fkind: "trailing", members: members, minTag: opts.minTag, maxTag: opts.maxTag,
           unexpectedCode: opts.unexpectedCode, orderCode: opts.orderCode };
}

// ---- structural combinators -----------------------------------------

function seq(fields, opts) {
  opts = opts || {};
  return { kind: "seq", fields: fields, assert: opts.assert || "sequence", arity: opts.arity,
           code: opts.code, what: opts.what, build: opts.build, checks: opts.checks || [] };
}

// A NON-optional EXPLICIT context wrapper (CMS ContentInfo; the tbs [3] uses it
// inside `trailing`). Asserts context class + tag, constructed, >=1 child, then
// walks the inner schema on children[0].
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
           min: opts.min, unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}
function setOf(item, opts) {
  opts = opts || {};
  return { kind: "repeat", item: item, assert: opts.assert || "set", code: opts.code, what: opts.what,
           min: opts.min, unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}
function setOfUnique(item, keyFn, opts) {
  return setOf(item, Object.assign({ unique: keyFn }, opts || {}));
}
// [tag] IMPLICIT SET OF item — the context tag REPLACES the universal SET tag,
// so the node is a context-class constructed [tag] whose direct children are the
// items (RFC 2986 §4.1 CSR attributes). No inner SET, no EXPLICIT unwrap.
function implicitSetOf(tag, item, opts) {
  opts = opts || {};
  return { kind: "repeat", item: item, assert: "implicit", implicitTag: tag, code: opts.code, what: opts.what,
           min: opts.min, unique: opts.unique, dupCode: opts.dupCode, build: opts.build };
}

// ---- the walk engine -------------------------------------------------

/**
 * @primitive  pki.schema.engine.walk
 * @signature  pki.schema.engine.walk(schema, node, ctx) -> value
 * @since      0.1.7
 * @status     experimental
 * @spec       X.690, X.680
 * @related    pki.asn1.decode, pki.schema.x509.parse
 *
 * Interpret a declarative schema against a decoded DER node, enforcing the
 * schema's structural rules (shape assertion, arity, optional / context-tagged
 * fields in increasing tag order, SET-OF uniqueness) and returning the built
 * value — or the match tree (`{ node, fields | items }`, with the build output
 * on `.result`) for a structure with no build fn. `ctx = { E, prefix, oid }`
 * supplies the typed-error constructor, the error-code family prefix, and the
 * OID registry a build fn resolves names through.
 *
 * The schema is assembled from the combinators this module exports — structural
 * (`seq` / `field` / `optional` / `explicit` / `trailing` / `seqOf` / `setOf` /
 * `setOfUnique` / `choice`) and value (`oidLeaf` / `integerLeaf` / `boolean` /
 * `octetString` / `bitString` / `any` / `decode` / `time`).
 *
 * @example
 *   var S = pki.schema.engine;
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

// An EXPLICIT [tag] wrapper carries EXACTLY ONE inner value; 0 children is
// empty and 2+ would silently drop all but the first (the same drop-extra
// fail-open the seq guard closes). Assert exactly one, return it.
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
  var items = [];
  var seen = schema.unique ? new Set() : null;
  for (var i = 0; i < kids.length; i++) {
    // The item wrapper is the SAME shape unique() and build() see: { node,
    // value: <walk result> }. keyFn reads off item.value just like build does.
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
        fields[fld.name] = { node: next, present: true, value: walk(fld.schema, inner, ctx) };
      } else {
        fields[fld.name] = { present: false, value: fld.hasDefault ? fld.def : undefined };
      }
    } else if (fld.fkind === "trailing") {
      _consumeTrailing(fld, kids, idx, fields, ctx);
      idx = kids.length;
    }
  }

  // Every child must be consumed by a field. A leftover element (no trailing
  // field ran to absorb it) is malformed — dropping it silently would let a
  // closed sequence of optional fields accept a duplicate/extra element.
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
  // The monotonic-order sentinel must start below the lowest accepted tag.
  // Context tag numbers are non-negative, so -1 is below any member tag when
  // minTag is absent — otherwise a trailing block whose first member is [0]
  // would reject that field (0 <= last==0) as repeated/out-of-order.
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

module.exports = {
  // structural
  seq: seq, field: field, optional: optional, explicit: explicit, trailing: trailing,
  seqOf: seqOf, setOf: setOf, setOfUnique: setOfUnique, implicitSetOf: implicitSetOf, choice: choice,
  // leaves
  oidLeaf: oidLeaf, integerLeaf: integerLeaf, boolean: boolean, octetString: octetString,
  bitString: bitString, any: any, decode: decode, time: time,
  // engine
  walk: walk,
};
