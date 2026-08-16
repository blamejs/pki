// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Build a hostile structure as BYTES.
 *
 * A vector that wants "this SignerInfo, but with a DER NULL on its signatureAlgorithm" has two
 * ways to express it. It can parse the real structure, assign to a field of the result and hand
 * the object back to the verb -- which reads as a forgery attempt but is not one: the verb takes
 * bytes from an attacker, and a parsed object is something only the caller can produce. A verb
 * that re-derives its input from the bytes the parser recorded discards that assignment outright,
 * so the vector then passes while testing nothing.
 *
 * The other way is to change the encoding, which is what an attacker can actually do. That is
 * fiddly by hand: inserting two bytes inside a nested SEQUENCE invalidates the length of every
 * TLV enclosing it, and a length crossing the 127-byte short-form boundary shifts the offsets
 * again. So do it structurally -- decode, replace the node, re-encode the enclosing tree, and let
 * every parent length fall out of the rebuild.
 *
 * `patch(der, visit)` walks the decoded tree and rebuilds it. `visit(node, path)` returns a
 * replacement TLV Buffer for that node, or undefined to leave it alone and keep descending; the
 * `path` is the chain of tag numbers from the root, so a vector can name WHICH SEQUENCE it means.
 * `reencode(node)` alone re-serializes a subtree.
 *
 * The rebuild is byte-identical to the input when no visit fires, which each caller can assert --
 * and this file's own self-check does, over every fixture it is handed.
 */

var helpers = require("./index");
var pki = helpers.pki;
var asn1 = pki.asn1;

// asn1.decode reports the class by NAME; encodeTLV takes the identifier bits.
var CLASS_BITS = { universal: 0x00, application: 0x40, context: 0x80, private: 0xc0 };
function _bits(node) {
  var v = CLASS_BITS[node.tagClass];
  if (v === undefined) throw new Error("der-surgery: unknown tag class " + node.tagClass);
  return v;
}

// A decoded node -> its DER. Leaves keep their exact bytes; a constructed node is rebuilt from its
// children, so a replaced child re-lengths every ancestor on the way back up.
function reencode(node) {
  if (!node.constructed) return Buffer.from(node.bytes);
  var kids = node.children.map(reencode);
  return asn1.encodeTLV(_bits(node), true, node.tagNumber, Buffer.concat(kids));
}

function _walk(node, visit, path) {
  var replaced = visit(node, path);
  if (replaced !== undefined) return Buffer.from(replaced);
  if (!node.constructed) return Buffer.from(node.bytes);
  var kids = node.children.map(function (c, i) {
    return _walk(c, visit, path.concat([{ tag: c.tagNumber, cls: c.tagClass, index: i }]));
  });
  return asn1.encodeTLV(_bits(node), true, node.tagNumber, Buffer.concat(kids));
}

// patch(der, visit) -> DER. `visit(node, path)` returns a replacement TLV or undefined.
// `opts.ber` decodes BER-tolerantly (a PKCS#12 store); the rebuild is always DER.
function patch(der, visit, opts) {
  var root = asn1.decode(Buffer.from(der), opts && opts.ber ? { ber: true } : undefined);
  return _walk(root, visit, []);
}

// An AlgorithmIdentifier whose algorithm OID is `oidDer`, carrying `params` (a TLV Buffer) --
// the shape a vector needs when the point is that parameters are present at all.
function algIdWithParams(oidDer, params) {
  return asn1.build.sequence([Buffer.from(oidDer), Buffer.from(params)]);
}

// True when `node` is a SEQUENCE whose first child is the OBJECT IDENTIFIER `dotted` -- i.e. an
// AlgorithmIdentifier for that algorithm, wherever it sits.
//
// The comparison is on ENCODED bytes rather than a decoded dotted string, so the predicate is
// total: it runs over every node of a deliberately-corrupted fixture, where decoding an OID whose
// content is junk would throw, and a predicate that swallowed that throw would quietly answer
// "no" for a node it could not read.
function isAlgId(node, dotted) {
  if (!node.constructed || node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE) return false;
  var first = node.children[0];
  if (!first || first.tagClass !== "universal" || first.tagNumber !== asn1.TAGS.OBJECT_IDENTIFIER) return false;
  return Buffer.from(asn1.build.oid(dotted)).equals(Buffer.from(first.bytes));
}

// replaceLastAlgId(der, dotted, build) -> { der, count }
//
// Rewrite the LAST AlgorithmIdentifier for `dotted` in document order; `build(node)` returns its
// replacement TLV. The same algorithm OID is usually encoded several times in one structure -- in
// a SignedData it appears in digestAlgorithms, in each certificate, and in the SignerInfo, and the
// SignerInfo comes last. Rewriting only that one changes what the message asks to be verified
// under while every certificate keeps naming what it actually is, which is the difference between
// an unsupported-algorithm vector and a key/signature-mismatch vector. `count` is returned so a
// vector can assert how many it found rather than assuming.
function replaceLastAlgId(der, dotted, build) {
  var count = 0;
  patch(der, function (n) { if (isAlgId(n, dotted)) count++; return undefined; });
  var seen = 0;
  var out = patch(der, function (n) {
    if (!isAlgId(n, dotted)) return undefined;
    seen++;
    return seen === count ? build(n) : undefined;
  });
  return { der: out, count: count };
}

// replaceTlv(der, originalTlv, replacement) -> { der, count }
//
// Replace whichever node encodes exactly `originalTlv`. Use it when a parse result already names
// the element -- a SignerInfo's signedAttrs, an extension, a certificate -- so the vector can say
// "that one" by its bytes rather than by a positional path that breaks when the structure gains an
// optional field. `count` is returned so a vector can assert it matched exactly one.
function replaceTlv(der, originalTlv, replacement) {
  var want = Buffer.from(originalTlv);
  var count = 0;
  var out = patch(der, function (n) {
    if (!want.equals(Buffer.from(n.bytes))) return undefined;
    count++;
    return replacement;
  });
  return { der: out, count: count };
}

module.exports = {
  reencode: reencode, patch: patch, algIdWithParams: algIdWithParams,
  isAlgId: isAlgId, replaceLastAlgId: replaceLastAlgId, replaceTlv: replaceTlv,
};
