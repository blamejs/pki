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
//   - A missing field reads as an absent feature, never as a malformed input.
//     `crlExtensions` omitted altogether made a scope-restricted CRL answer as an
//     unrestricted one, because every scope guard reads the list as `(list || [])`.
//     The guard cannot fire on a list that is not there.
//   - A partial object reaches code that dereferences a field it lacks, and the
//     verb throws a raw TypeError instead of its own typed error: a fault an
//     operator cannot catch by code and a fuzz harness reports as a finding.
//
// The rule is completeness, checked at the door: an object claiming to be parser
// output must carry every field the consuming code dereferences, each with the type
// that code assumes. It is not a signature check and does not pretend to be. An
// object can still describe a certificate that never existed, which is why the
// fields a decision depends on are re-derived from `tbsBytes` where that matters.
// What it buys is that "parsed" means one thing at every door, so a shape refused
// by `pki.path.build` is not accepted by `pki.path.validate`.
//
// Each entry point keeps its own typed error: `E` is the caller's (code, message)
// factory and `code` its own domain reason, so routing a door through this guard
// changes what is checked, never what the operator reads.

var bytes = require("./guard-bytes");
var time = require("./guard-time");

// Every form the toolkit calls "bytes": a Buffer, any typed-array view, a DataView, or a bare
// ArrayBuffer. Testing `Buffer.isBuffer(x) || x instanceof Uint8Array` is narrower than what the
// verbs document, and the narrowness is invisible in the good case: an ArrayBuffer would fall
// through to the object branch and be refused as a rebuilt structure, which reads to the caller as
// "your certificate is malformed" when what happened is that their container was not recognized.
// guard.bytes is what finally reads them, and it accepts all four, so the door has to as well.
// Asked of guard.bytes rather than restated here, because a restatement is what drifts. An
// `x instanceof ArrayBuffer` here turns away a real buffer built in another realm that guard.bytes
// goes on to accept, so one container gets opposite answers from the two doors it passes through.
function _isBytes(x) {
  return bytes.isByteSource(x);
}

// The shapes below assert the parser's complete output: every field
// pki.schema.x509.parse and pki.schema.crl.parse assign, with the type each is
// assigned, and not the subset some consumer happens to dereference today.
//
// The distinction is the whole point. A shape derived from one consumer's reads is
// correct for that consumer and silently incomplete at every other door it gets
// reused at, and the gap is invisible: the missing field is not named
// anywhere, so nothing fails until a caller supplies an object without it. This
// guard shipped derived from the path validator's reads, and three fields the other
// doors depend on were absent: `serialNumber`, which pki.ocsp.buildRequest encodes
// into the request; `issuer.bytes`, which the OCSP responder-identity comparison
// reads; and an extension entry's `critical`, whose ABSENCE reads as non-critical to
// `if (!ext.critical) continue`, so an unknown critical extension passes unhandled.
//
// Anchoring on the parser removes the enumeration step that produced those gaps: the
// only sanctioned way to obtain one of these objects is to run the parser, the parser
// assigns every field unconditionally, and so "complete" needs no consumer census and
// does not drift when a new consumer reads a new field. Adding a field to a parser's
// output belongs here in the same change; the api-snapshot pins that surface, so
// the two move together.

// A directory name. `dn` is the RFC 4514 string, `bytes` the raw encoded Name that a
// byte-level issuer/subject comparison hashes, and `rdns` the structure the RFC 5280
// sec. 7.1 comparison walks.
//
// The walk goes all the way to the attributes. `rdns` being an array is not the
// property anything downstream depends on: guard-name's dnEqual compares each
// attribute's `type` and canonicalizes its `value`, and the WebAuthn subject-CN
// lookup reads `name` and `value`, so an array of anything would pass a
// shallow test and reach code that dereferences three fields it does not have.
// Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName, and an RDN is a
// SET SIZE (1..MAX), so the parser produces an array of non-empty arrays; the
// attribute value is always a string, either the decoded directory string or the
// RFC 4514 "#hex" form the parser falls back to for a type it does not decode.
function _isAttributeTypeAndValue(a) {
  return !!a && typeof a.type === "string" && _isOptName(a.name) && typeof a.value === "string";
}
function _isRdnSequence(rdns) {
  if (!Array.isArray(rdns)) return false;
  for (var i = 0; i < rdns.length; i++) {
    if (!Array.isArray(rdns[i]) || rdns[i].length === 0) return false;
    if (!rdns[i].every(_isAttributeTypeAndValue)) return false;
  }
  return true;
}
function _isName(n) {
  return !!n && _isRdnSequence(n.rdns) && Buffer.isBuffer(n.bytes) && typeof n.dn === "string";
}

// `name` is the registry lookup of the OID and is null for an OID the registry does
// not carry, so the assertion is on the KEY's presence with the parser's own type.
function _isOptName(v) { return typeof v === "string" || v === null; }

function _isAlgorithmIdentifier(a) {
  return !!a && typeof a.oid === "string" && _isOptName(a.name) &&
    (Buffer.isBuffer(a.parameters) || a.parameters === null);
}

function _isBitString(b) {
  return !!b && Buffer.isBuffer(b.bytes) && typeof b.unusedBits === "number";
}

// A parsed certificate extension entry: dispatched on `.oid`, gated on `.critical`,
// and its `.value` the raw extension bytes, which the certificate parser leaves
// undecoded. An entry carrying a `.name` but no `.oid` is the shape that slips past
// an OID-keyed lookup while reading as present to a human; one carrying no
// `.critical` is the shape that turns a fail-closed unknown-critical check into a
// skipped iteration.
function _isExtensionEntry(e) {
  return !!e && typeof e.oid === "string" && _isOptName(e.name) &&
    typeof e.critical === "boolean" && Buffer.isBuffer(e.value);
}

// A parsed CRL extension entry. The CRL parser decodes the values it knows (a
// cRLNumber surfaces as a BigInt, a reasonCode as a Number), so the value type
// varies by extension and only its presence can be asserted here. The dispatch key
// and the criticality flag are the same as a certificate's, and both decide.
function _isCrlExtensionEntry(e) {
  return !!e && typeof e.oid === "string" && _isOptName(e.name) &&
    typeof e.critical === "boolean" && e.value !== undefined;
}

// isCert(o) -- the complete parsed-certificate shape.
//
// Exported as a predicate beside the throwing door because a caller deriving a
// dedupe key (cmp's extraCerts pool) must answer "not usable" and never throw:
// a non-deduped entry is a redundant slot, while a key derived from a partial object
// could collapse two different certificates onto one.
//
// @enforced-by guard-shape-reinlined -- shares the `accept` shape below: any door
//   testing tbsBytes and returning the object is the re-inline this replaces.
function isCert(o) {
  return !!o && typeof o === "object" &&
    Buffer.isBuffer(o.tbsBytes) &&
    typeof o.version === "number" &&
    typeof o.serialNumber === "bigint" &&
    typeof o.serialNumberHex === "string" &&
    _isAlgorithmIdentifier(o.signatureAlgorithm) &&
    _isAlgorithmIdentifier(o.tbsSignatureAlgorithm) &&
    _isBitString(o.signatureValue) &&
    !!o.validity && time.isDate(o.validity.notBefore) && time.isDate(o.validity.notAfter) &&
    _isName(o.issuer) &&
    _isName(o.subject) &&
    !!o.subjectPublicKeyInfo && Buffer.isBuffer(o.subjectPublicKeyInfo.bytes) &&
    _isAlgorithmIdentifier(o.subjectPublicKeyInfo.algorithm) &&
    _isBitString(o.subjectPublicKeyInfo.publicKey) &&
    Array.isArray(o.extensions) && o.extensions.every(_isExtensionEntry);
}

// isCrl(o) -- the complete parsed-CertificateList shape. `crlExtensions` and each
// entry's `crlEntryExtensions` are required arrays, never optional ones: the
// scope guards read them as `(list || [])`, so an omitted list is indistinguishable
// from an empty one and the difference decides whether a serial may be answered.
// `nextUpdate` is the one genuinely optional field; the parser assigns null when
// the CRL omits it, and a validator distinguishes the two.
//
// @enforced-by guard-shape-reinlined -- shares the `accept` shape below.
function isCrl(o) {
  return !!o && typeof o === "object" &&
    Buffer.isBuffer(o.tbsBytes) &&
    typeof o.version === "number" &&
    _isAlgorithmIdentifier(o.signatureAlgorithm) &&
    _isBitString(o.signatureValue) &&
    _isName(o.issuer) &&
    time.isDate(o.thisUpdate) &&
    (o.nextUpdate === null || time.isDate(o.nextUpdate)) &&
    Array.isArray(o.crlExtensions) && o.crlExtensions.every(_isCrlExtensionEntry) &&
    Array.isArray(o.revokedCertificates) && o.revokedCertificates.every(function (e) {
      return !!e && typeof e.serialNumber === "bigint" &&
        typeof e.serialNumberHex === "string" &&
        time.isDate(e.revocationDate) &&
        Array.isArray(e.crlEntryExtensions) && e.crlEntryExtensions.every(_isCrlExtensionEntry);
    });
}

// Neither predicate may throw. A caller-supplied object can define an accessor that
// throws on read, and a raw fault escaping a completeness check defeats the point of
// checking: the composing verb's contract is that every failure is its own typed
// error, and a dedupe caller using the predicate directly would get a raw fault where
// it expects a boolean. A property that cannot be read is not one the parser produced,
// so a throw is simply "not the shape". Wrapped here, and not at the door, because
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
// The door every "bytes or a parsed X" argument goes through. Bytes and PEM are
// handed to `parse`; an object claiming to be parser output (it carries the
// `tbsBytes` the parser always produces) must satisfy the complete shape for
// `kind`; anything else is a typed input fault naming what the argument accepts.
//
// The claim test is `tbsBytes !== undefined`, not a truthiness test: an object
// carrying `tbsBytes: null` is claiming to be parsed and failing, and must be told
// so, never sent to a byte parser that reports something unrelated.
//
// Reading the claim is itself a read of a caller-supplied object, so it goes through
// the same try/catch the shape walk does. A getter or Proxy trap that throws would
// otherwise escape from outside the guarded walk and reach the operator as a raw
// fault at every door composing this: the failure the walk is wrapped to prevent,
// one property earlier. An unreadable claim is treated as a claim made and failed,
// matching fromTrustedSource below: an object that cannot answer what it is has not
// come from the parser, and saying so is more useful than reporting its type.
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
  if (_isBytes(input) || typeof input === "string") return parse(input);
  var claimsParsed = false;
  if (input && typeof input === "object") {
    try { claimsParsed = input.tbsBytes !== undefined; }
    catch (_e) {
      claimsParsed = true;   // an object that cannot answer what it is did not come from the parser
    }
  }
  if (claimsParsed) {
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
// Recording the bytes, and not a boolean, is what makes this hold. A flag saying
// "this came from the parser" is defeated by keeping a legitimately parsed object and
// then assigning over its fields: the flag is still there and now describes
// something else. Re-deriving from the recorded bytes discards every later edit,
// because the verdict is computed from the byte string and not from the object the
// caller is holding. The object a caller passes is therefore a way of naming bytes,
// which is all it was ever safe for it to be.
//
// The record is kept off the object, in a WeakMap the parser owns, keyed by the
// returned object itself. Nothing about the record is reachable through the object,
// which is what makes it unforgeable:
//
//   - A property, however hidden, is read through the object, and every read of an
//     object is interceptable. A Proxy's getOwnPropertyDescriptor and get traps are
//     handed whatever key they are asked about (the symbol need not be known to be
//     answered for), so a Proxy could claim any mark and name any bytes. A WeakMap
//     lookup is on identity: a Proxy is a different object from the parser's result
//     and simply is not a key.
//   - `Object.create(parsed)` is likewise a different object, so it inherits no
//     record, while `Object.assign({}, parsed)` and `{...parsed}` are different
//     objects too. All three, the ways a mixed structure is actually assembled,
//     fall out of the same rule, with no need for three checks.
//
// The recorded bytes are copied. Recording the caller's Buffer by reference would let
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
//     could then overwrite, defeating the copy by writing through the value the copy
//     was made to protect.
//
// The snapshot is taken before the parse and the parser is given the snapshot, so the
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
    var isText = typeof input === "string";   // strings are immutable; nothing to snapshot
    var snap = isText ? input : bytes.snapshotSource(input, ErrorClass, code, label);
    var out = parse(snap);
    // The record gets its own copy, not the buffer the parser just read.
    //
    // A parser surfaces raw byte ranges (tbsBytes, a Name's encoded form, an extension's value)
    // as views onto the buffer it parsed, which is what makes them exact and cheap. So the object
    // handed back reaches into that buffer, and a caller holding it can write through those views:
    // `parsed.tbsBytes.fill(0)` would then overwrite the very bytes the record names, and the
    // re-derivation would faithfully reproduce whatever was written. A record the object can reach
    // is not a record of anything. This copy is never handed out and nothing aliases it.
    if (out && typeof out === "object") {
      PROVENANCE.set(out, { kind: kind, source: isText ? snap : Buffer.from(snap),
        shape: _shapeOf(out) });
    }
    return out;
  };
}

// recordingWalker(kind, walkNode, decodeBytes) -> function (node) -> the walked structure.
//
// The recordingParser sibling for a producer handed an already-decoded node, not bytes.
// One structure needs it: the RFC 7292 authSafe's SignedData. A PFX is decoded BER-tolerantly
// because real stores carry the indefinite-length encoding, so its inner SignedData cannot be
// re-derived by the strict `parse` entry the byte doors use; that entry would refuse a store
// this toolkit accepts today. The record therefore names the bytes and how to walk them again.
//
// The same three properties hold as for recordingParser, and for the same reasons. The record can
// only be obtained by actually running the walk, so no code can assert provenance for a structure
// it did not produce. The recorded bytes are a private copy of the node's, because the walked
// result surfaces views onto the buffer the PFX was decoded from and a caller holding one could
// otherwise write through it into the very bytes the record names. And `derive` re-runs this same
// walker over that copy, so a re-derivation reproduces the structure exactly: the decode is the
// producer's own, never a stricter one substituted at the door.
//
// @enforced-by guard-shape-reinlined -- shares recordingParser's shape below: the PROVENANCE.set
//   that binds a structure to the bytes it was derived from appears only in this module, so no
//   producer elsewhere can mint a record for a structure it did not itself walk.
function recordingWalker(kind, walkNode, decodeBytes) {
  return function (node) {
    var out = walkNode(node);
    if (out && typeof out === "object" && node && _isBytes(node.bytes)) {
      PROVENANCE.set(out, {
        kind: kind,
        source: Buffer.from(node.bytes),
        shape: _shapeOf(out),
        derive: function (src) { return walkNode(decodeBytes(src)); },
      });
    }
    return out;
  };
}

// The provenance record for `obj`, or undefined. @internal to this module: touches no
// property of `obj` at all -- the lookup is on the object's identity.
function _recordOf(obj, kind) {
  if (!obj || typeof obj !== "object") return undefined;
  var rec = PROVENANCE.get(obj);
  return (rec && rec.kind === kind) ? rec : undefined;
}

// isRecorded(obj) -> whether this exact object carries a provenance record, of any kind.
//
// The record is keyed on identity, so a copy of a parsed structure, however faithful, is
// not the parsed structure: it carries no record and every door that decides integrity refuses
// it. That makes a recorded object a handle, not data, and anything that walks a caller's
// spec taking copies has to leave it alone. guard-bytes.snapshotDeep asks this before descending.
// @enforced-by behavioral -- a predicate has no rename-proof shape to detect, and re-inlining it is
//   not possible outside this module: the registry it reads is a module-private WeakMap. The guard
//   is the RED vector that passes a parsed certificate through a producing verb's spec and asserts
//   the integrity door still accepts it, which fails the moment a copy is taken instead.
function isRecorded(obj) {
  return !!obj && typeof obj === "object" && PROVENANCE.has(obj);
}

// isRecordedAsProduced(obj) -> whether this is a recorded structure that still has the field set
// the parser gave it.
//
// A recorded structure is safe to hand on by identity, because the doors that decide integrity
// re-derive it from the bytes the record names and ignore whatever the object says. That reasoning
// covers it as a parsed value. It does not cover a caller who takes a parse result, adds an option
// to it, and passes it where a verb reads options by name: those fields no door re-derives, so
// they stay the caller's to change. The record therefore also names the shape the parser produced,
// and a structure that has grown fields since is no longer only a parse result.
// Only an added field matters. Deleting one changes nothing (the door re-derives the structure
// from the bytes the record names, so a missing property is not a missing value), and a caller
// pruning a parse result is a case the shipped vectors cover deliberately. What re-derivation does
// not reach is a name the parser never produced, which is exactly what an option added to a parse
// result is.
// @enforced-by behavioral -- a predicate has no rename-proof shape to detect, and the registry it
//   reads is a module-private WeakMap so nothing outside can re-inline it. The guard is the RED
//   vector that adds an option to a parse result, passes it where options are read by name, and
//   asserts the value the verb used is the one that was there at entry.
function isRecordedAsProduced(obj) {
  if (!isRecorded(obj)) return false;
  var shape = PROVENANCE.get(obj).shape;
  var keys = _allNames(obj);
  for (var i = 0; i < keys.length; i++) {
    if (!shape[keys[i]]) return false;
  }
  return true;
}

function _shapeOf(obj) {
  var shape = Object.create(null);
  var keys = _allNames(obj);
  for (var i = 0; i < keys.length; i++) shape[keys[i]] = true;
  return shape;
}

// Every name a `obj.field` lookup could resolve: own and inherited, enumerable or not. A verb
// reads an option by name and does not care how it was defined, so a comparison that only saw
// `Object.keys` would miss a field added with defineProperty and call the object unchanged.
function _allNames(obj) {
  var names = [];
  var seen = Object.create(null);
  for (var o = obj; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
    var own = Object.getOwnPropertyNames(o);
    for (var i = 0; i < own.length; i++) {
      if (seen[own[i]]) continue;
      seen[own[i]] = true;
      names.push(own[i]);
    }
  }
  return names;
}

// fromTrustedSource(input, kind, claimFields, parse, E, code, why) -> the parsed
// structure | throws.
//
// The door for a verb that decides integrity. Bytes are parsed. An object carrying
// the parser's record is re-parsed from the bytes that record names, so a caller
// may keep passing the parsed form, and anything done to that object since it was
// parsed is discarded, never trusted. An object that claims to be parser output
// (it carries a field only a parsed structure of this kind has) but carries no
// record was not produced by the parser, and is refused with the caller's own reason.
//
// `claimFields` exist so that refusal names what happened, instead of handing the
// object to a byte parser that would report something about its type.
//
// @enforced-by guard-shape-reinlined
// @guard-shape (?:responseStatus|integrityMode|macedBytes|tbsResponseDataBytes)\s*!==\s*undefined
// @guard-via guard\.parsed\.(?:fromTrustedSource|recordingParser)\(
function fromTrustedSource(input, kind, claimFields, parse, E, code, why) {
  if (input && typeof input === "object" && !_isBytes(input)) {
    // A structure the walker recorded carries its own way back; the byte doors re-derive with the
    // parser they were given.
    var rec = _recordOf(input, kind);
    if (rec !== undefined) return (rec.derive || parse)(rec.source);
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

// ---- the certificate / CRL door --------------------------------------------
//
// acceptDerived(input, kind, parse, E, code, label) -> the parsed structure | throws.
//
// The single door for a certificate or a CRL, at every boundary that takes one. Bytes and PEM are
// parsed; the parser's own result is re-derived from the bytes it recorded; an object that claims to
// be one without that record is refused.
//
// It is one rule for every door, and never a rule for the doors that "reach a verdict", because
// that judgment is the thing that keeps being got wrong. A certificate is a trust decision wherever
// it appears: an issuer certificate handed to a signer names who the new certificate says issued it;
// a root handed to an attestation check is the anchor; a certificate handed to a request builder
// names what the request asks about. Sorting them into verdict and non-verdict doors invites exactly
// the substitution this prevents at whichever door was sorted wrong, so no door is sorted at all.
//
// The claim fields are the ones a parsed structure has and a byte input does not, so an object that
// was rebuilt is told what happened, never handed to a byte parser that would report something
// about its type.
var _CLAIMS = {
  certificate: ["tbsBytes", "subjectPublicKeyInfo", "serialNumberHex"],
  crl: ["tbsBytes", "revokedCertificates", "crlExtensions"],
  cms: ["signerInfos", "encapContentInfo"],
  csr: ["certificationRequestInfoBytes", "subjectPublicKeyInfo", "attributes"],
};
var _WHY = {
  certificate: "the signed byte range, the signature and the fields that range encodes are separate properties of a parsed object, so a rebuilt certificate (Object.assign, spread, a JSON round-trip) could have them describe different certificates: keep a real CA certificate's signed bytes and signature, replace only its public key, and every field is still well-formed",
  crl: "the signed byte range, the revocation list and the scope extensions are separate properties of a parsed object, so a rebuilt CRL could have them describe different CRLs: empty the revocation list and a correctly signed CRL reports a revoked certificate as good",
  cms: "the signed attribute bytes, the signature, the encapsulated content and the certificates that verify it are separate properties of a parsed object, so a rebuilt SignedData could have them describe different messages: keep a genuine signer's signature and signed attributes, put other content beside them, and every part of the check passes for content that signer never signed",
  csr: "the signed byte range, the key it proves possession of and the subject and requested extensions that range encodes are separate properties of a parsed object, so a rebuilt request could have them describe different requests: keep a genuine requester's signed bytes and signature, replace only the subject or the extensionRequest, and the proof of possession still verifies while the certificate a CA issues from those fields is for a name and a set of extensions nobody signed",
};
// @enforced-by guard-shape-reinlined -- shares the fromTrustedSource shape it composes: a door that
//   tests the claim fields itself, instead of routing here, is the re-inline both replace.
function acceptDerived(input, kind, parse, E, code, label) {
  var claims = _CLAIMS[kind];
  if (!claims) throw new TypeError("guard.parsed.acceptDerived: unknown kind " + kind);
  var who = label || "the argument";
  // An object that is neither bytes nor a claim is named as the wrong type here, never handed
  // to the byte parser. The parser would refuse it too, but with its own domain's code: a caller
  // who passed the wrong thing to pki.path.validate should read a path/* fault, not an x509/* one
  // from a layer they did not call.
  if (input !== null && input !== undefined && typeof input === "object" && !_isBytes(input)) {
    var claimsSomething = false;
    for (var i = 0; i < claims.length && !claimsSomething; i++) {
      try { claimsSomething = input[claims[i]] !== undefined; }
      catch (_e) {
        claimsSomething = true;   // a claim that cannot be read is certainly not the parser's result
      }
    }
    if (!claimsSomething) {
      throw E(code, who + " must be a " + kind + " DER Buffer, a PEM string, or a parsed " + kind);
    }
  }
  var ns = { certificate: "x509", crl: "crl", cms: "cms", csr: "csr" }[kind];
  return fromTrustedSource(input, kind, claims, parse, E, code,
    who + " must be its DER bytes, a PEM string, or an unmodified pki.schema." + ns +
    ".parse result: " + _WHY[kind]);
}

module.exports = {
  accept: accept, acceptDerived: acceptDerived,
  fromTrustedSource: fromTrustedSource, recordingParser: recordingParser,
  recordingWalker: recordingWalker,
  isCert: certShape, isCrl: crlShape, isRecorded: isRecorded,
  isRecordedAsProduced: isRecordedAsProduced,
};
