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
  return function (o) { try { return shape(o) === true; } catch (_e) { return false; } };
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

module.exports = { accept: accept, isCert: certShape, isCrl: crlShape };
