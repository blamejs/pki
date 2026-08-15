// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the verbs
// whose "a DER Buffer, a PEM string, or a parsed X" argument composes this guard
// (pki.path.validate / build, pki.crl.verify / isRevoked, pki.x509.sign,
// pki.attrcert.sign, pki.ocsp.*, pki.cmp.session).
//
// guard-parsed -- fail-closed acceptance of a CLAIMED-parsed structure.
//
// Every verb that takes bytes also takes the parser's output, so a caller holding
// a parsed certificate need not re-encode and re-parse it. The convenience carries
// a trust boundary: the object arrives from the caller, not from the parser, and
// the code downstream reads its fields as though the parser had produced them.
//
// Defends the type-confusion / unverified-provenance class (CWE-843, CWE-345).
// Two distinct failures follow from accepting a claimed-parsed object on a partial
// duck-type test, and the toolkit has had both:
//
//   - A MISSING field reads as an absent feature rather than as a malformed input.
//     `crlExtensions` omitted altogether made a scope-restricted CRL answer as an
//     unrestricted one, because every scope guard reads the list as `(list || [])`.
//     The guard cannot fire on a list that is not there.
//   - A partial object reaches code that dereferences a field it lacks, and the
//     verb throws a raw TypeError instead of its own typed error -- a fault an
//     operator cannot catch by code and a fuzz harness reports as a finding.
//
// The rule is completeness, checked at the DOOR: an object claiming to be parser
// output must carry EVERY field the consuming code dereferences, each with the type
// that code assumes. It is not a signature check and does not pretend to be -- an
// object can still describe a certificate that never existed, which is why the
// fields a decision depends on are re-derived from `tbsBytes` where that matters.
// What it buys is that "parsed" means one thing at every door, so a shape refused
// by `pki.path.build` is not accepted by `pki.path.validate`.
//
// Each entry point keeps its own typed error: `E` is the caller's (code, message)
// factory and `code` its own domain reason, so routing a door through this guard
// changes what is checked, never what the operator reads.

var bytes = require("./guard-bytes");

// A parsed CERTIFICATE extension entry: dispatched on `.oid`, and its `.value` the
// RAW extension bytes, which the certificate parser leaves undecoded. An entry
// carrying a `.name` but no `.oid` is the shape that slips past an OID-keyed lookup
// while reading as present to a human.
function _isExtensionEntry(e) { return !!e && typeof e.oid === "string" && Buffer.isBuffer(e.value); }

// A parsed CRL extension entry. The CRL parser DECODES the values it knows -- a
// cRLNumber surfaces as a BigInt, a reasonCode as a Number -- so the value type
// varies by extension and only its PRESENCE can be asserted here. The dispatch key
// is the same, and it is the part that decides anything.
function _isCrlExtensionEntry(e) { return !!e && typeof e.oid === "string" && e.value !== undefined; }

function _isAlgorithmIdentifier(a) { return !!a && typeof a.oid === "string"; }
function _isBitString(b) { return !!b && Buffer.isBuffer(b.bytes); }
function _isName(n) { return !!n && Array.isArray(n.rdns); }

// isCert(o) -- the COMPLETE parsed-certificate shape, every top-level field the
// path validator, the signing verbs and the revocation verbs dereference, each with
// the type they assume. Grep-verified against those consumers; a field added to a
// consumer's dereference set belongs here in the same change.
//
// Exported as a PREDICATE beside the throwing door because a caller deriving a
// DEDUPE KEY (cmp's extraCerts pool) must answer "not usable" rather than throw --
// a non-deduped entry is a redundant slot, while a key derived from a partial object
// could collapse two different certificates onto one.
//
// @enforced-by guard-shape-reinlined -- shares the `accept` shape below: any door
//   testing tbsBytes and returning the object is the re-inline this replaces.
function isCert(o) {
  return !!o && typeof o === "object" &&
    Buffer.isBuffer(o.tbsBytes) &&
    typeof o.serialNumberHex === "string" &&
    _isAlgorithmIdentifier(o.signatureAlgorithm) &&
    _isBitString(o.signatureValue) &&
    !!o.validity && o.validity.notBefore instanceof Date && o.validity.notAfter instanceof Date &&
    _isName(o.issuer) &&
    _isName(o.subject) && Buffer.isBuffer(o.subject.bytes) &&
    !!o.subjectPublicKeyInfo && Buffer.isBuffer(o.subjectPublicKeyInfo.bytes) &&
    _isAlgorithmIdentifier(o.subjectPublicKeyInfo.algorithm) &&
    _isBitString(o.subjectPublicKeyInfo.publicKey) &&
    typeof o.subjectPublicKeyInfo.publicKey.unusedBits === "number" &&
    Array.isArray(o.extensions) && o.extensions.every(_isExtensionEntry);
}

// isCrl(o) -- the COMPLETE parsed-CertificateList shape. `crlExtensions` and each
// entry's `crlEntryExtensions` are REQUIRED arrays rather than optional ones: the
// scope guards read them as `(list || [])`, so an omitted list is indistinguishable
// from an empty one and the difference decides whether a serial may be answered.
//
// @enforced-by guard-shape-reinlined -- shares the `accept` shape below.
function isCrl(o) {
  return !!o && typeof o === "object" &&
    Buffer.isBuffer(o.tbsBytes) &&
    _isAlgorithmIdentifier(o.signatureAlgorithm) &&
    _isBitString(o.signatureValue) &&
    _isName(o.issuer) &&
    o.thisUpdate instanceof Date &&
    (o.nextUpdate === undefined || o.nextUpdate === null || o.nextUpdate instanceof Date) &&
    Array.isArray(o.crlExtensions) && o.crlExtensions.every(_isCrlExtensionEntry) &&
    Array.isArray(o.revokedCertificates) && o.revokedCertificates.every(function (e) {
      return !!e && typeof e.serialNumberHex === "string" &&
        e.revocationDate instanceof Date &&
        Array.isArray(e.crlEntryExtensions) && e.crlEntryExtensions.every(_isCrlExtensionEntry);
    });
}

// Neither predicate may THROW. A caller-supplied object can define an accessor that
// throws on read, and a raw fault escaping a completeness CHECK defeats the point of
// checking -- the composing verb's contract is that every failure is its own typed
// error, and a dedupe caller using the predicate directly would get a raw fault where
// it expects a boolean. A property that cannot be read is not one the parser produced,
// so a throw is simply "not the shape". Wrapped HERE rather than at the door, because
// both are exported and the rule has to hold for both.
function _safe(shape) {
  return function (o) {
    try { return shape(o) === true; }
    catch (_e) {
      return false;   // a field that cannot be read is not a field the parser produced
    }
  };
}
var certShape = _safe(isCert);
var crlShape = _safe(isCrl);

var _SHAPES = { certificate: certShape, crl: crlShape };

// accept(input, kind, parse, E, code, label) -> the parsed structure | throws
//
// The DOOR every "bytes or a parsed X" argument goes through. Bytes and PEM are
// handed to `parse`; an object CLAIMING to be parser output (it carries the
// `tbsBytes` the parser always produces) must satisfy the complete shape for
// `kind`; anything else is a typed input fault naming what the argument accepts.
//
// The claim test is `tbsBytes !== undefined`, not a truthiness test: an object
// carrying `tbsBytes: null` is claiming to be parsed and failing, and must be told
// so rather than being sent to a byte parser that reports something unrelated.
//
// @enforced-by guard-shape-reinlined
// The shape is the partial duck-type acceptance this guard replaces: testing
// tbsBytes (with or without one companion field) and returning the object.
// @guard-shape (?:if\s*\(|return\s*\(?)[^;\n]*\.tbsBytes[^;\n]*\)\s*(?:\{\s*)?return\s+\w+\s*;
// @guard-via guard\.parsed\.(?:accept|isCert|isCrl)\(
function accept(input, kind, parse, E, code, label) {
  var who = label || "the argument";
  var shape = _SHAPES[kind];
  if (!shape) throw new TypeError("guard.parsed.accept: unknown kind " + kind);
  if (Buffer.isBuffer(input) || input instanceof Uint8Array || typeof input === "string") return parse(input);
  if (input && typeof input === "object" && input.tbsBytes !== undefined) {
    if (!shape(input)) {
      throw E(code, who + " claims to be a parsed " + kind + " (it carries tbsBytes) but is not a complete one -- pass the bytes, or the unmodified output of the matching pki.schema parser, since a partial object would be read as though the parser had produced it");
    }
    return input;
  }
  throw E(code, who + " must be a " + kind + " DER Buffer, a PEM string, or a parsed " + kind);
}

// ---- provenance: the parser's own mark -------------------------------------
//
// Some verbs cannot be satisfied by completeness alone. A signature check has three
// parts -- the signature, the algorithm that verifies it, and the byte range it
// covers -- and on a parsed object all three are separate properties, each of them
// individually well-formed. Pair a real CA's signature over a certificate it issued
// with that certificate's own signed bytes and algorithm, relabel the three, and
// every part of the check passes for a structure that never existed. A MAC check has
// the same shape: the range MACed and the content returned as verified are two
// properties, so one object can say "verify this" and "return that".
//
// What those verbs need is not a shape but a PROVENANCE: these fields were derived
// together, from one byte string, by the parser. So the parser records the bytes it
// derived the object from, and the door derives the structure it verifies from those
// bytes again.
//
// Recording the bytes rather than a boolean is what makes this hold. A flag saying
// "this came from the parser" is defeated by keeping a legitimately parsed object and
// then assigning over its fields -- the flag is still there and now describes
// something else. Re-deriving from the recorded bytes discards every later edit,
// because the verdict is computed from the byte string and not from the object the
// caller is holding. The object a caller passes is therefore a way of NAMING bytes,
// which is all it was ever safe for it to be.
//
// The record is kept OFF the object, in a WeakMap the parser owns, keyed by the
// returned object itself. Nothing about the record is reachable through the object,
// which is what makes it unforgeable:
//
//   - A property, however hidden, is READ through the object, and every read of an
//     object is interceptable. A Proxy's getOwnPropertyDescriptor and get traps are
//     handed whatever key they are asked about -- the symbol need not be known to be
//     answered for -- so a Proxy could claim any mark and name any bytes. A WeakMap
//     lookup is on IDENTITY: a Proxy is a different object from the parser's result
//     and simply is not a key.
//   - `Object.create(parsed)` is likewise a different object, so it inherits no
//     record, while `Object.assign({}, parsed)` and `{...parsed}` are different
//     objects too. All three -- the ways a mixed structure is actually assembled --
//     fall out of the same rule rather than needing three checks.
//
// The recorded bytes are COPIED. Recording the caller's Buffer by reference would let
// it be overwritten between the parse and the verify, which is the same defeat by
// another route: the door would faithfully re-derive from bytes that had changed
// underneath it. A PEM string needs no copy, strings being immutable.
//
// This is not a signature check and does not pretend to be. It says only "verify the
// bytes this object was parsed from", which is precisely the claim the three-part
// check was resting on without ever asking for it.
var PROVENANCE = new WeakMap();

// recordingParser(kind, parse) -> a parser that records what it parsed.
//
// Recording is not a separate step a caller could perform, and the record is not a
// value a caller can read back. Both follow from the same requirement: the record has
// to mean "the parser derived this object from these exact bytes", and every way of
// exposing it weakens that to something else.
//
//   - An exported `mark(obj, kind, bytes)` would let any code assert provenance for an
//     object it did not parse, or overwrite the provenance of one it did not produce.
//     The only way to obtain a record is therefore to actually run the parse.
//   - An exported `sourceOf(obj)` would hand back the recorded Buffer, which the caller
//     could then overwrite -- defeating the copy by writing through the value the copy
//     was made to protect.
//
// The SNAPSHOT is taken before the parse and the parser is given the snapshot, so the
// bytes the parser reads and the bytes the record names are the same object by
// construction. Taking it afterwards from the caller's argument would leave a window:
// a typed-array subclass with stateful `byteOffset` / `byteLength` getters, or any
// SharedArrayBuffer, can present one set of bytes to the parser and another to a later
// copy. guard.bytes.snapshot reads through the BufferSource contract and copies.
//
// @enforced-by guard-shape-reinlined -- shares the fromTrustedSource shape below; a
//   door re-testing the claim fields itself is the re-inline both replace.
function recordingParser(kind, parse, ErrorClass, code, label) {
  return function (input) {
    var snap = (typeof input === "string") ? input   // strings are immutable; nothing to snapshot
      : bytes.snapshotSource(input, ErrorClass, code, label);
    var out = parse(snap);
    if (out && typeof out === "object") PROVENANCE.set(out, { kind: kind, source: snap });
    return out;
  };
}

// The recorded bytes for `obj`, or undefined. @internal to this module: touches no
// property of `obj` at all -- the lookup is on the object's identity.
function _sourceOf(obj, kind) {
  if (!obj || typeof obj !== "object") return undefined;
  var rec = PROVENANCE.get(obj);
  return (rec && rec.kind === kind) ? rec.source : undefined;
}

// fromTrustedSource(input, kind, claimFields, parse, E, code, why) -> the parsed
// structure | throws.
//
// The door for a verb that decides INTEGRITY. Bytes are parsed. An object carrying
// the parser's record is RE-PARSED from the bytes that record names -- so a caller
// may keep passing the parsed form, and anything done to that object since it was
// parsed is discarded rather than trusted. An object that CLAIMS to be parser output
// -- it carries a field only a parsed structure of this kind has -- but carries no
// record was not produced by the parser, and is refused with the caller's own reason.
//
// `claimFields` exist so that refusal names what happened, rather than handing the
// object to a byte parser that would report something about its type instead.
//
// @enforced-by guard-shape-reinlined
// @guard-shape (?:responseStatus|integrityMode|macedBytes|tbsResponseDataBytes)\s*!==\s*undefined
// @guard-via guard\.parsed\.(?:fromTrustedSource|recordingParser)\(
function fromTrustedSource(input, kind, claimFields, parse, E, code, why) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
    var source = _sourceOf(input, kind);
    if (source !== undefined) return parse(source);
    for (var i = 0; i < claimFields.length; i++) {
      // A claim field can be an accessor that throws; a guard answers, it does not relay.
      var claims;
      try { claims = input[claimFields[i]] !== undefined; }
      catch (_e) {
        claims = true;   // a claim that cannot be read is certainly not the parser's own result
      }
      if (claims) throw E(code, why);
    }
  }
  return parse(input);
}

module.exports = {
  accept: accept, fromTrustedSource: fromTrustedSource, recordingParser: recordingParser,
  isCert: certShape, isCrl: crlShape,
};
