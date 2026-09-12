// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.sigstore
 * @nav        Supply chain
 * @title      Sigstore
 * @fullname   Sigstore bundles: keyless signing and provenance
 * @intro Zero-dependency verifier for a Sigstore bundle, the exact artifact
 *   `npm publish --provenance` produces and the npm registry serves at its
 *   attestations API. A bundle is a keyless (Fulcio) signature with a Rekor
 *   transparency-log inclusion proof, over one of two content arms: a DSSE-wrapped
 *   in-toto attestation, which `cosign attest` and npm provenance produce, or a
 *   message signature over an artifact's own bytes, which `cosign sign-blob`
 *   produces. `verifyBundle` composes five fail-closed legs against caller-supplied
 *   trust material (the Fulcio CA roots + Rekor log keys, never trusted from the
 *   bundle): the signature under the Fulcio leaf key, over the DSSE PAE preimage or
 *   over the artifact `opts.artifact` supplies; the Fulcio certificate chain,
 *   validated as of the Rekor log time (the cert is ephemeral, ~10 minutes); the
 *   Rekor inclusion proof folded to a Rekor-signed tree root; the log entry binding
 *   to this exact signature and certificate; and the artifact binding, which is the
 *   in-toto subject digest the caller confirms for a DSSE bundle and the entry's own
 *   authenticated hash for a message signature. Verify-only and offline: every input
 *   is in the bundle or a caller argument. Reuses the shipped X.509 parser, RFC 5280
 *   path validator, RFC 9162 Merkle verifier, and native crypto engine; the net-new
 *   codecs are the DSSE PAE byte-builder and a fail-closed JSON bundle reader.
 * @spec DSSE, Sigstore bundle v0.3, RFC 9162, SLSA provenance v1
 * @card Verify an npm --provenance Sigstore bundle offline (DSSE + Fulcio + Rekor + SLSA).
 */

var nodeCrypto = require("crypto");
var frameworkError = require("./framework-error");
var constants = require("./constants");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var pathValidate = require("./path-validate");
var merkle = require("./merkle");
var oid = require("./oid");
var ct = require("./ct");
var edwardsPoint = require("./edwards-point");

/** @internal The operations this module decides with, taken at load. The bundle copy every later
 * check runs on settles what is verified, so which function answers "what does this object own" and
 * "what does it hold" is fixed before any caller code runs; one replaced after this module loads
 * would otherwise be asked at the moment of the call. An emptied key list alone turns a bundle into
 * one carrying no content arm. */
var _ownNames = intrinsic.getOwnPropertyNames;
var _ownDescriptor = intrinsic.getOwnPropertyDescriptor;
var _isArray = intrinsic.isArray;
var _create = intrinsic.create;
var _assign = intrinsic.assign;
var _freeze = intrinsic.freeze;
var _stringOf = intrinsic.String;
var _numberOf = intrinsic.Number;
var _bigIntOf = intrinsic.BigInt;
var _Date = intrinsic.Date;
var _dateParse = intrinsic.dateParse;
var _isNaN = intrinsic.numberIsNaN;
/** @internal Whether an object OWNS a name. The oneof rules are written on this question, so a
 * replacement answering no for one arm hides it and a bundle setting two is read as setting one. */
var _hasOwn = intrinsic.hasOwn;
var _isFiniteNumber = intrinsic.numberIsFinite;
var _isSafeInt = intrinsic.isSafeInteger;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferConcat = intrinsic.bufferConcat;
var _bufToString = intrinsic.bufToString;
var _bufferEquals = intrinsic.bufferEquals;
var _subarray = intrinsic.subarray;
var _bufIndexOf = intrinsic.uncurry(Buffer.prototype.indexOf);
/** @internal The canonical form a Rekor signed entry timestamp is verified over. A replacement
 * writing different bytes decides what that signature is checked against. */
var _jsonStringify = intrinsic.stringify;
/** @internal Every field the copy holds is DEFINED as its own, never assigned. An assignment consults
 * the target's prototype for a setter, and something that installs one sees each field the copy
 * writes and can hand back a different one, so a malformed value arrives valid and the checks read
 * what the caller never sent. Defining reaches no prototype. */
var _defineProp = intrinsic.defineProperty;
var _isFiniteNum = intrinsic.isFinite;
/** @internal Uncurried, so the copy reads a character's code through the operation taken at load
 * rather than through whatever the string it is walking offers under that name. What a character
 * costs decides whether a bundle passes the size limit. */
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _strIndexOf = intrinsic.stringIndexOf;
var _split = intrinsic.uncurry(String.prototype.split);
var _join = intrinsic.join;
var _map = intrinsic.map;
var _forEach = intrinsic.forEach;
var _filter = intrinsic.filter;
var _arraySlice = intrinsic.arraySlice;
var _fromCharCode = intrinsic.fromCharCode;

var C = constants;
var SigstoreError = frameworkError.SigstoreError;
function _err(code, message, cause) { return new SigstoreError(code, message, cause); }

/** @internal Whether a oneof arm is PRESENT, which is not the same as whether it is truthy. A bundle
 * setting an arm to false or to an empty string has set it: reading presence as truthiness lets a
 * second arm sit beside the one being read, which is the state the oneof rule exists to refuse. Own
 * properties only, so a polluted prototype cannot conjure an arm the bundle does not carry. */
function _armPresent(obj, name) {
  return !!obj && typeof obj === "object" &&
    _hasOwn(obj, name) && obj[name] !== undefined && obj[name] !== null;
}

/** @internal The HashAlgorithm enum members a message signature may name its digest under, keyed by
 * the name protojson writes. All five members that name an algorithm are here, the two SHA-3
 * members included: they
 * are marked deprecated, which says a producer should not choose one, not that a bundle carrying one
 * is malformed, and this digest names its own algorithm independently of the one the log entry
 * records. A member this table does not carry is refused rather than mapped by guessing at its name,
 * so a member added to the enum later cannot be read as one of these.
 * HASH_ALGORITHM_UNSPECIFIED is absent for the reason it exists: it names no algorithm. */
var _HASH_BY_ENUM = _freeze(_assign(_create(null), {
  SHA2_256: { node: "sha256", bytes: 32 },
  SHA2_384: { node: "sha384", bytes: 48 },
  SHA2_512: { node: "sha512", bytes: 64 },
  SHA3_256: { node: "sha3-256", bytes: 32 },
  SHA3_384: { node: "sha3-384", bytes: 48 },
}));

/** @internal The same members under the numbers the enum assigns them. The JSON mapping states that
 * a parser "accept[s] both enum names and integer values", so a bundle naming its digest algorithm as
 * 1 is one a conforming producer may write and this reads it as the name it stands for. Zero is
 * absent for the reason the name it belongs to is: HASH_ALGORITHM_UNSPECIFIED names no algorithm. */
var _HASH_BY_NUMBER = _freeze(_assign(_create(null), {
  1: _HASH_BY_ENUM.SHA2_256,
  2: _HASH_BY_ENUM.SHA2_384,
  3: _HASH_BY_ENUM.SHA2_512,
  4: _HASH_BY_ENUM.SHA3_256,
  5: _HASH_BY_ENUM.SHA3_384,
}));

/** @internal The algorithm a HashAlgorithm field names, in either encoding, or null when it names
 * none this build verifies under. A number that is not one of the members is refused rather than
 * rounded or coerced into one. */
function _hashOf(algorithm) {
  if (typeof algorithm === "string") return _HASH_BY_ENUM[algorithm] || null;
  if (typeof algorithm === "number" && _isSafeInt(algorithm)) {
    return _HASH_BY_NUMBER[algorithm] || null;
  }
  return null;
}

/** @internal The same three algorithms keyed the way a hashedrekord names them. The entry is the
 * authenticated statement of what was signed, so its algorithm is the one the artifact is digested
 * under; the schema enumerates exactly these three. */
var _HASH_BY_REKOR = _freeze(_assign(_create(null), {
  sha256: { node: "sha256", bytes: 32 },
  sha384: { node: "sha384", bytes: 48 },
  sha512: { node: "sha512", bytes: 64 },
}));

var JSON_MAX = C.LIMITS.JSON_MAX_BYTES;

/** @internal How deeply a bundle may nest, stated once and read by both routes into it. A bundle
 * given as text and the same bundle given as an object are the same document, so a limit either one
 * applied alone would admit it one way and refuse it the other. */
var BUNDLE_MAX_DEPTH = 64;

var SP = _bufferFrom(" ", "ascii");
var DSSEV1 = _bufferFrom("DSSEv1", "ascii");
var _EM_DASH = _fromCharCode(0x2014);

function _parseNoteSig(line) {
  var prefix = _EM_DASH + " ";
  if (_strSlice(line, 0, prefix.length) !== prefix) return null;
  var p = prefix.length, n = line.length;
  var t1s = p;
  while (p < n && !pkix.isJsWhitespace(_charCodeAt(line, p))) p += 1;
  if (p === t1s) return null;
  var keyId = _strSlice(line, t1s, p);
  if (_charAt(line, p) !== " ") return null;
  p += 1;
  var t2s = p;
  while (p < n && !pkix.isJsWhitespace(_charCodeAt(line, p))) p += 1;
  if (p === t2s) return null;
  var sig = _strSlice(line, t2s, p);
  if (p !== n) return null;
  return { keyId: keyId, sig: sig };
}

function _stripTrailingEquals(s) {
  var i = s.length;
  while (i > 0 && _charAt(s, i - 1) === "=") i -= 1;
  return _strSlice(s, 0, i);
}

var _BUNDLE_MEDIA_TYPES = _assign(_create(null), {
  "application/vnd.dev.sigstore.bundle.v0.1+json": 1,
  "application/vnd.dev.sigstore.bundle.v0.2+json": 1,
  "application/vnd.dev.sigstore.bundle.v0.3+json": 1,
  "application/vnd.dev.sigstore.bundle+json;version=0.1": 1,
  "application/vnd.dev.sigstore.bundle+json;version=0.2": 1,
  "application/vnd.dev.sigstore.bundle+json;version=0.3": 1
});
function _isBundleMediaType(mt) {
  return typeof mt === "string" && _hasOwn(_BUNDLE_MEDIA_TYPES, mt);
}

function _jsonParse(input, code, label) {
  return guard.json.parse(input, _err, {
    maxBytes: JSON_MAX, maxDepth: BUNDLE_MAX_DEPTH,
    badJson: code, tooDeep: code, duplicateMember: code, tooLarge: code, badInput: code, label: label,
  });
}


/**
 * @primitive pki.sigstore.pae
 * @signature pki.sigstore.pae(payloadType, payloadBytes) -> Buffer
 * @since 0.2.3
 * @status stable
 * @spec DSSE
 * @related pki.sigstore.verifyBundle
 *
 * The DSSE Pre-Authentication Encoding: `"DSSEv1" SP LEN(type) SP type SP
 * LEN(body) SP body`, where `LEN` is the ASCII-decimal byte length (no leading
 * zeros) and `type` is the UTF-8 `payloadType`. This is the exact preimage a DSSE
 * signature covers; `LEN` is over the decoded body byte length, never the base64
 * length. Any deviation is a signature-verify bypass.
 *
 * @example
 *   var b = pki.sigstore.pae("application/vnd.in-toto+json", Buffer.from("{}"));
 *   b.slice(0, 6).toString(); // "DSSEv1"
 */
function pae(payloadType, payloadBytes) {
  if (typeof payloadType !== "string") throw new TypeError("pae: payloadType must be a string");
  var type = _bufferFrom(payloadType, "utf8");
  var body = _isBuffer(payloadBytes) ? payloadBytes : _bufferFrom(payloadBytes || []);
  return _bufferConcat([
    DSSEV1, SP,
    _bufferFrom(_stringOf(type.length), "ascii"), SP, type, SP,
    _bufferFrom(_stringOf(body.length), "ascii"), SP, body,
  ]);
}


function _b64(s, label) {
  if (typeof s !== "string") throw _err("sigstore/bad-bundle", label + " must be a base64 string");
  var urlSafe = _strIndexOf(s, "-") !== -1 || _strIndexOf(s, "_") !== -1;
  var enc = urlSafe ? "base64url" : "base64";
  var buf = _bufferFrom(s, enc);
  if (_stripTrailingEquals(_bufToString(buf, enc)) !== _stripTrailingEquals(s)) {
    throw _err("sigstore/bad-bundle", label + " is not canonical base64");
  }
  return buf;
}


/**
 * @primitive pki.sigstore.parseBundle
 * @signature pki.sigstore.parseBundle(input) -> bundle
 * @since 0.2.3
 * @status stable
 * @spec Sigstore bundle v0.3
 * @related pki.sigstore.verifyBundle
 *
 * Decode + structurally validate a Sigstore bundle (a JSON object, string, or
 * Buffer) fail-closed: a non-object, malformed JSON, an oversize input, an
 * unknown `mediaType`, or a missing required member throws a typed
 * `sigstore/bad-bundle` / `sigstore/bad-bundle-version`. Returns the validated
 * bundle (structure only, no cryptographic verification).
 *
 * An object is copied into plain data and read back before any rule runs on it,
 * and the copy is what comes back, so a caller reads what was checked. A field
 * reached through an accessor is refused rather than called, and so is a value
 * JSON does not carry: a bundle is data, and a field that computes its value can
 * remove another the walk has already counted. `pki.sigstore.verifyBundle` takes
 * the same copy, so the two verbs cannot answer differently about one bundle.
 *
 * @example
 *   // requires: `bundle` -- a Sigstore bundle as cosign or npm provenance emits it
 *   // (the JSON object, a JSON string, or its raw bytes)
 *   var b = pki.sigstore.parseBundle(bundle);
 *   b.mediaType; // "application/vnd.dev.sigstore.bundle.v0.3+json"
 */
function parseBundle(input) {
  var obj;
  if (_isBuffer(input) || typeof input === "string") {
    obj = _jsonParse(input, "sigstore/bad-bundle", "bundle");
  } else if (input && typeof input === "object") {
    /** @internal An object is copied and read back before a single rule runs on it, so this verb
     * decides what the verifying one decides. Checking the caller's object in place would run its
     * accessors, and one of those can remove a field a check has already counted: a bundle owning
     * two content arms passes the oneof rule when reading the first deletes the second. */
    obj = _snapshotBundle(input);
  } else {
    throw _err("sigstore/bad-bundle", "bundle must be a JSON object, string, or Buffer");
  }
  if (!obj || typeof obj !== "object" || _isArray(obj)) throw _err("sigstore/bad-bundle", "bundle must be a JSON object");
  var mt = obj.mediaType;
  if (!_isBundleMediaType(mt)) {
    throw _err("sigstore/bad-bundle-version", "unsupported or unknown bundle media type: " + (mt === undefined ? "(none)" : guard.text.showValue(mt)));
  }
  if (!obj.verificationMaterial || typeof obj.verificationMaterial !== "object") {
    throw _err("sigstore/bad-bundle", "bundle is missing verificationMaterial");
  }
  _assertMaterialOneOf(obj.verificationMaterial);
  _assertContentOneOf(obj);
  if (_armPresent(obj, "messageSignature")) {
    _parseMessageSignature(obj.messageSignature);
    return obj;
  }
  if (!obj.dsseEnvelope || typeof obj.dsseEnvelope !== "object") {
    throw _err("sigstore/bad-bundle", "bundle is missing a dsseEnvelope");
  }
  var d = obj.dsseEnvelope;
  if (typeof d.payload !== "string" || typeof d.payloadType !== "string" || !_isArray(d.signatures) || !d.signatures.length ||
      !d.signatures[0] || typeof d.signatures[0] !== "object" || typeof d.signatures[0].sig !== "string") {
    throw _err("sigstore/bad-dsse", "the DSSE envelope is missing a required field (payload / payloadType / signatures[].sig)");
  }
  /** @internal The bundle specification states this on the producer and again on the verifier: an
   * envelope in a bundle carries exactly one signature, and a verifier rejects one whose count is
   * not one. Only `signatures[0]` is ever read, so admitting a second would return a verdict that
   * says nothing about content the envelope carries. */
  if (d.signatures.length !== 1) {
    throw _err("sigstore/bad-dsse", "a bundle's DSSE envelope carries exactly one signature; this one carries " + d.signatures.length);
  }
  return obj;
}

/** @internal The bundle's content is a protobuf oneof, so a bundle setting both arms is malformed
 * and is refused rather than read as whichever arm this build happens to support: verifying the
 * envelope and passing over the other arm reports a verdict that says nothing about content the
 * bundle carries. */
function _assertContentOneOf(obj) {
  if (_armPresent(obj, "messageSignature") && _armPresent(obj, "dsseEnvelope")) {
    throw _err("sigstore/bad-bundle", "bundle carries both dsse_envelope and message_signature; the bundle content is a oneof and exactly one arm may be present");
  }
}

/** @internal The verification material's certificate is a oneof of the same kind. Both arms set draws
 * the leaf from one and the chain it is validated through from the other, so the certificate whose
 * key is checked and the certificates it is checked through come from different statements about the
 * same signer. The two refusals are separate because a caller can act on one and not the other. */
function _assertMaterialOneOf(vm) {
  var arms = 0;
  if (_armPresent(vm, "certificate")) arms++;
  if (_armPresent(vm, "x509CertificateChain")) arms++;
  if (_armPresent(vm, "publicKey")) arms++;
  if (arms > 1) {
    throw _err("sigstore/bad-bundle", "verificationMaterial carries more than one of certificate, x509CertificateChain and publicKey; it is a oneof and exactly one arm may be present");
  }
}

/** @internal The bytes a string costs in the JSON a document would be written as, charged while it is
 * scanned so a long one is refused part-way rather than measured whole. Counted as JSON writes it: an
 * escape costs the characters it takes, a character outside ASCII costs its UTF-8 bytes, a surrogate
 * pair costs the four its code point takes, and an unpaired surrogate costs the six a \u escape
 * takes. Charging the string's own length instead charges UTF-16 units, which is fewer than the text
 * form for anything escaped or non-ASCII, and would admit an object the same document as text is
 * refused for. Scanned by character code, since a pattern here would be matched through a replaceable
 * protocol. */
function _chargeString(budget, s) {
  _charge(budget, 2);
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    var cost;
    if (c === 0x22 || c === 0x5c) cost = 2;
    else if (c === 0x08 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d) cost = 2;
    else if (c < 0x20) cost = 6;
    else if (c < 0x80) cost = 1;
    else if (c < 0x800) cost = 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      var next = i + 1 < s.length ? _charCodeAt(s, i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) { cost = 4; i++; } else { cost = 6; }
    } else if (c >= 0xdc00 && c <= 0xdfff) { cost = 6; } else { cost = 3; }
    _charge(budget, cost);
  }
}

/** @internal A bundle field read as a number, without asking the value to convert itself. A log entry
 * carries its time and index as JSON numbers, and a document may write either as a string, so both
 * are read; anything else is not a number and reads as one that is not finite, which the caller of
 * this already refuses. Converting an arbitrary value would ask it for a primitive, and a value that
 * has no way to give one throws where this module's contract is a typed refusal. */
function _numOf(v) {
  var t = typeof v;
  if (t === "number") return v;
  if (t === "string" || t === "boolean") return _numberOf(v);
  return NaN;
}

/** @internal Charge the copy's running size, refusing the moment it passes what the reader admits.
 * What is counted is the size the same document costs as text, exactly: the punctuation JSON writes
 * around a value, the digits a number takes, and the bytes a string takes once escaped. Counting
 * less would admit an object the text reader refuses; counting more would refuse one it admits. */
function _charge(budget, cost) {
  budget.n += cost;
  if (budget.n > JSON_MAX) {
    throw _err("sigstore/bad-bundle", "the bundle is larger than the " + JSON_MAX + " byte limit");
  }
}

/** @internal Bound the WALK, which is a separate question from the size. A property whose value is
 * skipped costs the walk a step while costing the document nothing, so a structure made of them is
 * bounded here rather than by the byte count, which would have to overstate the document to do it. */
function _step(budget) {
  budget.steps++;
  if (budget.steps > JSON_MAX) {
    throw _err("sigstore/bad-bundle", "the bundle holds more values than a bundle of the maximum size can");
  }
}

/** @internal One property of the caller's structure, copied. Taken from the property's DESCRIPTOR,
 * which does not run an accessor, and an accessor is refused rather than called. A bundle is data; a
 * field that computes its value is not one. Reading through the object would run the caller's code in
 * the middle of the walk, and that code can change the object being walked: a getter on one property
 * deleting another leaves a key this already listed reading as absent, so an object carrying two
 * content arms would be copied with one. Not calling anything is what makes that unreachable, rather
 * than another rule about what a second read may say. Named properties and array elements both come
 * through here, because an indexed accessor runs the same code a named one does.
 * Returns `undefined` for a property that is absent or holds `undefined`, which is what a bundle
 * without that field means. */
function _valueOf(obj, key, depth, budget) {
  var d = _ownDescriptor(obj, key);
  if (d === undefined) return undefined;
  if (typeof d.get === "function" || typeof d.set === "function") {
    throw _err("sigstore/bad-bundle", "the bundle reaches " + guard.text.showValue(key) +
      " through an accessor rather than holding a value; a bundle is data");
  }
  if (d.value === undefined) return undefined;
  return _plainCopy(d.value, depth + 1, budget);
}

/** @internal A bundle object copied into plain data, reading each own enumerable property EXACTLY
 * ONCE. That single read is the whole guarantee: an accessor has no second answer to give, so no two
 * observations of the same field can disagree and no check can be shown one value while another is
 * used. Serializing the object instead would read it a second time, which is how a field could be
 * checked in one place and used in another.
 * A value JSON does not carry is refused rather than skipped. Skipping is what serializing does, and
 * a dropped value turns a bundle setting two content arms into one setting a single arm: a refusal
 * sanitized into an accept. A bundle is JSON data, so a function, a symbol or a non-finite number
 * anywhere in it means the object is not one. `undefined` is the exception and is skipped, since that
 * is what a bundle absent a field means and what the presence test already reads it as. */
function _plainCopy(v, depth, budget) {
  /** @internal The size the copy would serialize to, charged AS IT IS BUILT so the refusal comes
   * before the allocation rather than after it. Two shapes both need this and neither is bounded by
   * a depth limit: one sub-object shared between two properties is copied twice, so a few hundred
   * bytes describes hundreds of millions of values, and a modest array of long strings is a handful
   * of values holding tens of megabytes. Each value is charged what JSON writes it as, so the object
   * path admits and refuses exactly what the text path does. */
  _step(budget);
  if (depth > BUNDLE_MAX_DEPTH) {
    throw _err("sigstore/bad-bundle", "the bundle nests deeper than " + BUNDLE_MAX_DEPTH + " levels");
  }
  if (v === null) { _charge(budget, 4); return null; }
  var t = typeof v;
  if (t === "string") { _chargeString(budget, v); return v; }
  if (t === "boolean") { _charge(budget, v ? 4 : 5); return v; }
  if (t === "number") {
    if (!_isFiniteNum(v)) throw _err("sigstore/bad-bundle", "the bundle carries a number JSON cannot represent");
    /** @internal A finite number is written by JSON exactly as the language writes it, so the digits
     * it takes are the bytes it costs. One in exponent form is long and would otherwise be counted
     * as a single byte. */
    _charge(budget, _stringOf(v).length);
    return v;
  }
  if (t !== "object") {
    throw _err("sigstore/bad-bundle", "the bundle carries a " + t + " where JSON carries only objects, arrays, strings, numbers, booleans and null");
  }
  /** @internal The two brackets or braces this value is written between. */
  _charge(budget, 2);
  var out, i;
  if (_isArray(v)) {
    out = [];
    for (i = 0; i < v.length; i++) {
      if (i > 0) _charge(budget, 1);
      /** @internal An element is a property, and is taken the same way a named one is. An indexed
       * accessor runs the caller's code exactly as a named accessor does, and can do the same thing
       * with it: deleting a content arm the walk has already listed. A hole is written as null, and
       * costs what null costs. */
      var el = _valueOf(v, _stringOf(i), depth, budget);
      if (el === undefined) _charge(budget, 4);
      _defineProp(out, _stringOf(out.length), { value: el, writable: true, enumerable: true, configurable: true });
    }
    return out;
  }
  /** @internal Built with no prototype, so a property named __proto__ is copied as a field of that
   * name. Assigning it onto an ordinary object runs the inherited setter instead, which sets the
   * copy's prototype rather than one of its fields: an object owning nothing but __proto__ would
   * then read as whatever it holds, and the same document as JSON text is refused. The reader this
   * module parses text with states the same rule, so both routes agree. */
  out = _create(null);
  /** @internal EVERY own string-keyed property, not only the enumerable ones, because that is what
   * the presence test the oneof rules are built on reads. Enumerating a narrower set than the test
   * does is how a second content arm gets counted where the bundle is parsed and dropped where it is
   * copied, which is a refusal turned into an acceptance. */
  var keys = _ownNames(v);
  var kept = 0;
  for (i = 0; i < keys.length; i++) {
    /** @internal Every enumerated property costs the walk a step, whether or not its value is kept.
     * Its SIZE is charged only if it is kept, since JSON omits a property whose value is not
     * written and charging one would refuse a document the text reader admits. */
    _step(budget);
    /** @internal Taken from the property's DESCRIPTOR, which does not run an accessor, and an
     * accessor is refused rather than called. A bundle is data; a field that computes its value is
     * not one. Reading through the object would run the caller's code in the middle of the walk,
     * and that code can change the object being walked: a getter on one property deleting another
     * leaves a key this already listed reading as absent, so an object carrying two content arms
     * would be copied with one. Not calling anything is what makes that unreachable, rather than
     * another rule about what a second read may say. */
    var val = _valueOf(v, keys[i], depth, budget);
    if (val === undefined) continue;
    /** @internal What JSON writes around a kept property: the comma before it once one has been
     * written, its name in quotes, and the colon. */
    if (kept > 0) _charge(budget, 1);
    _chargeString(budget, keys[i]);
    _charge(budget, 1);
    kept++;
    _defineProp(out, keys[i], { value: val, writable: true, enumerable: true, configurable: true });
  }
  return out;
}

/** @internal The bundle a verdict is computed from: JSON text as it came, or an object copied once
 * into plain data and re-read through the same reader, so the caps that bound a text bundle bound an
 * object one too. Every check below runs on that copy and none of them consults the original again,
 * which is what makes the verdict a statement about one fixed set of bytes.
 * The scope this cannot reach, stated so it is not mistaken for an oversight: an exotic object whose
 * own descriptors say one thing while a direct property read says another, which a Proxy can be
 * written to do. There is no truer answer to prefer between the two, and the verdict describes the
 * one the copy took, so it remains a statement about what was actually verified. A caller comparing
 * a separate parseBundle of the same object may see the other answer. */
function _snapshotBundle(bundle) {
  /** @internal The copy IS the snapshot. It is plain data already, and the size and depth the reader
   * bounds a text bundle by were charged while it was built, so serializing it and reading it back
   * would repeat work that is already done. It would also put a step between the copy and the checks
   * that is not this module's: a serializer replaced after this module loaded is read at the moment
   * it is called, and one that drops a field would hand the checks a bundle carrying one content arm
   * where the copy holds two. Nothing here converts the copy to text, so there is no such step.
   * Reading a caller's object runs the caller's own accessors, and one that throws must arrive as
   * this module's refusal rather than as whatever it threw: a bundle this cannot read is refused with
   * a typed error like any other it cannot read. This module's own refusals pass through unchanged,
   * so a size or depth verdict keeps its own message. */
  try {
    return _plainCopy(bundle, 0, { n: 0, steps: 0 });
  } catch (e) {
    if (e instanceof SigstoreError) throw e;
    throw _err("sigstore/bad-bundle", "the bundle object could not be read", e);
  }
}

/** @internal Which content arm a parsed bundle carries. parseBundle has already refused a bundle
 * setting both or neither, so this reads the one that is there. */
function _contentTypeOf(obj) {
  return _armPresent(obj, "messageSignature") ? "messageSignature" : "dsseEnvelope";
}

/** @internal The shape of a MessageSignature (sigstore_common.proto). `signature` is REQUIRED;
 * `message_digest` is not, and the bundle format states why: a verifier is given the artifact, so the
 * digest is a hint rather than an input. The field comment says so outright, "Clients MUST NOT attempt
 * to use this digest to verify the associated signature; it is intended solely for identification",
 * which is why nothing here derives a verification input from it. What it IS held to is describing
 * itself: an algorithm this build knows, and a digest of that algorithm's own length. */
function _parseMessageSignature(ms) {
  if (!ms || typeof ms !== "object" || _isArray(ms)) {
    throw _err("sigstore/bad-message-signature", "messageSignature is not an object");
  }
  var sig = ms.signature;
  if (typeof sig !== "string" || sig === "") {
    throw _err("sigstore/bad-message-signature", "messageSignature is missing its signature");
  }
  if (!_armPresent(ms, "messageDigest")) return { signature: sig, digestAlg: null, digest: null };
  var md = ms.messageDigest;
  if (typeof md !== "object" || _isArray(md)) {
    throw _err("sigstore/bad-message-signature", "messageSignature.messageDigest is not an object");
  }
  /** @internal Read for being a string or an integer BEFORE it is used as a key. A value whose own
   * conversion throws would otherwise escape as an untyped error out of a verb whose contract is that
   * malformed input is refused with a typed one, and a bundle is caller-supplied JSON. */
  var alg = _hashOf(md.algorithm);
  if (!alg) {
    throw _err("sigstore/bad-message-signature", "messageSignature.messageDigest names a hash algorithm this build does not verify under: " +
      (md.algorithm === undefined ? "(none)" : guard.text.showValue(md.algorithm)));
  }
  if (typeof md.digest !== "string") {
    throw _err("sigstore/bad-message-signature", "messageSignature.messageDigest is missing its digest");
  }
  var raw = _b64(md.digest, "messageSignature.messageDigest.digest");
  if (raw.length !== alg.bytes) {
    throw _err("sigstore/bad-message-signature", "messageSignature.messageDigest states " + md.algorithm +
      " and carries " + raw.length + " bytes, which that algorithm does not produce");
  }
  /** @internal The checked values are RETURNED rather than left to be read again. A bundle is a
   * caller-supplied object, so a second read of the same field is a second chance to answer
   * differently; everything downstream uses what was validated here. */
  return { signature: sig, digestAlg: alg, digest: raw };
}


function _certBytes(c, label) {
  if (!c || typeof c !== "object" || typeof c.rawBytes !== "string") throw _err("sigstore/bad-bundle", label + " is not a { rawBytes } certificate");
  return _b64(c.rawBytes, label);
}
function _leafCertDer(vm) {
  if (vm.certificate) return _certBytes(vm.certificate, "verificationMaterial.certificate");
  if (vm.x509CertificateChain && _isArray(vm.x509CertificateChain.certificates) && vm.x509CertificateChain.certificates.length) {
    return _certBytes(vm.x509CertificateChain.certificates[0], "verificationMaterial.x509CertificateChain[0]");
  }
  throw _err("sigstore/bad-bundle", "bundle has no Fulcio certificate (public_key bundles are not supported)");
}
function _chainDers(vm) {
  if (vm.x509CertificateChain && _isArray(vm.x509CertificateChain.certificates)) {
    return _map(vm.x509CertificateChain.certificates, function (c, i) { return _certBytes(c, "x509CertificateChain[" + i + "]"); });
  }
  return [_leafCertDer(vm)];
}

function _rawVerify(keyObj, data, derSig) {
  var t = keyObj.asymmetricKeyType;
  if (t === "ed25519" || t === "ed448") {
    edwardsPoint.validateSpki(keyObj.export({ type: "spki", format: "der" }), t === "ed25519" ? 6 : 7, SigstoreError, "sigstore/bad-key");
    return nodeCrypto.verify(null, data, keyObj, derSig);
  }
  var crv = keyObj.asymmetricKeyDetails && keyObj.asymmetricKeyDetails.namedCurve;
  var hash = crv === "secp384r1" ? "sha384" : (crv === "secp521r1" ? "sha512" : "sha256");
  return nodeCrypto.verify(hash, data, { key: keyObj, dsaEncoding: "der" }, derSig);
}
function _pubFromSpki(spkiDer, label) {
  var key;
  try { key = nodeCrypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" }); }
  catch (e) { throw _err("sigstore/bad-key", "invalid " + label + " public key", e); }
  var t = key.asymmetricKeyType;
  if (t === "ed25519" || t === "ed448") {
    edwardsPoint.validateSpki(spkiDer, t === "ed25519" ? 6 : 7, SigstoreError, "sigstore/bad-key");
  }
  return key;
}
function _parseCert(der, label) {
  try { return x509.parse(der); }
  catch (e) { throw _err("sigstore/bad-certificate", "invalid " + label, e); }
}


function _sha256(buf) { return nodeCrypto.createHash("sha256").update(buf).digest(); }

function _toMs(x) {
  if (x == null) return null;
  if (typeof x === "number") return _isFiniteNumber(x) ? x : null;
  if (guard.time.isDate(x)) { var d = guard.time.instantOf(x); return _isNaN(d) ? null : d; }
  if (typeof x === "string") { var t = _dateParse(x); return _isNaN(t) ? null : t; }
  return null;
}
function _inWindow(timeMs, vf) {
  if (!vf) return true;
  if (vf.start != null) { var s = _toMs(vf.start); if (s === null || !(timeMs >= s)) return false; }
  if (vf.end != null) { var e = _toMs(vf.end); if (e === null || !(timeMs <= e)) return false; }
  return true;
}
function _rekorKey(rekorKeys, keyIdBuf, hint, timeMs) {
  for (var i = 0; i < rekorKeys.length; i++) {
    var k = rekorKeys[i];
    var match = (keyIdBuf && k.keyId && _bufferEquals(k.keyId, keyIdBuf)) ||
      (hint && k.keyId && k.keyId.length >= 4 && _bufferEquals(_subarray(k.keyId, 0, 4), hint));
    if (match && _inWindow(timeMs, k.validFor)) return k;
  }
  return null;
}

function _verifyCheckpoint(envelope, ip, rekorKeys, timeMs) {
  var buf = _bufferFrom(envelope, "utf8");
  var sep = _bufIndexOf(buf, "\n\n");
  if (sep < 0) throw _err("sigstore/bad-checkpoint", "the checkpoint has no note/signature separator");
  var body = _subarray(buf, 0, sep + 1);
  var lines = _split(_bufToString(body, "utf8"), "\n");
  if (_bufToString(_b64(lines[2], "checkpoint root"), "hex") !== _bufToString(_b64(ip.rootHash, "inclusionProof.rootHash"), "hex")) {
    throw _err("sigstore/inclusion-proof-mismatch", "the checkpoint root does not match the inclusion-proof root");
  }
  var sigBlock = _split(_bufToString(_subarray(buf, sep + 2), "utf8"), "\n");
  for (var i = 0; i < sigBlock.length; i++) {
    var note = _parseNoteSig(sigBlock[i]);
    if (!note) continue;
    var blob = _b64(note.sig, "checkpoint signature");
    if (blob.length < 5) continue;
    var hint = _subarray(blob, 0, 4), derSig = _subarray(blob, 4);
    var k = _rekorKey(rekorKeys, null, hint, timeMs);
    if (!k) continue;
    if (_rawVerify(_pubFromSpki(k.spki, "Rekor log"), body, derSig)) return true;
  }
  return false;
}

function _verifySet(te, rekorKeys, timeMs, canonBody) {
  var promise = te.inclusionPromise;
  if (!promise || typeof promise.signedEntryTimestamp !== "string") return false;
  var keyId = te.logId && te.logId.keyId ? _b64(te.logId.keyId, "logId.keyId") : null;
  var k = _rekorKey(rekorKeys, keyId, null, timeMs);
  if (!k) return false;
  var canonical = _jsonStringify({
    body: canonBody,
    integratedTime: _numOf(te.integratedTime),
    logID: _bufToString(keyId, "hex"),
    logIndex: _numOf(te.logIndex),
  });
  var sig = _b64(promise.signedEntryTimestamp, "signedEntryTimestamp");
  return _rawVerify(_pubFromSpki(k.spki, "Rekor log"), _bufferFrom(canonical, "utf8"), sig);
}

/** @internal The entry rows this build reads, keyed on the entry's OWN kind and apiVersion together.
 * A version is not a detail of a kind here: a hashedrekord v0.0.2 body names its fields differently
 * (`spec.hashedRekordV002`, a raw certificate in place of a PEM), so dispatching on the kind alone
 * would read one shape's field names out of the other and report a mismatch rather than an
 * unsupported entry. Each row states which content arm it may accompany, because an entry describing
 * a DSSE envelope says nothing about a message signature and the two must agree. */
var _ENTRY_ROWS = _freeze(_assign(_create(null), {
  "dsse@0.0.1": { content: "dsseEnvelope", bind: _bindDsseEntry },
  "hashedrekord@0.0.1": { content: "messageSignature", bind: _bindHashedRekordEntry },
}));

function _entryBody(canonBytes) {
  var body = _jsonParse(canonBytes, "sigstore/bad-tlog-entry", "Rekor entry body");
  if (!body || typeof body !== "object" || _isArray(body)) throw _err("sigstore/bad-tlog-entry", "the Rekor entry body is not a JSON object");
  return body;
}

/** @internal The row for an entry, refused when the body names a kind and version this build does not
 * read or one that does not go with the arm the bundle carries. */
function _entryRow(body, contentType) {
  /** @internal Both halves are read for being strings before either is joined into a key, since the
   * body is caller-supplied JSON and a value whose own conversion throws would escape untyped. */
  if (typeof body.kind !== "string" || typeof body.apiVersion !== "string") {
    throw _err("sigstore/unsupported-content", "the Rekor entry does not name its kind and apiVersion as strings");
  }
  var key = body.kind + "@" + body.apiVersion;
  var row = _ENTRY_ROWS[key];
  if (!row) {
    throw _err("sigstore/unsupported-content", "unsupported Rekor entry kind and version: " + guard.text.showValue(key));
  }
  if (row.content !== contentType) {
    throw _err("sigstore/unsupported-content", "the Rekor entry is a " + guard.text.showValue(key) +
      " while the bundle carries a " + contentType + "; the entry and the content arm must describe the same signature");
  }
  return row;
}

function _bindDsseEntry(body, envelope, leafDer) {
  var spec = body.spec;
  if (!spec || typeof spec !== "object" || !_isArray(spec.signatures) || !spec.signatures.length ||
      !spec.signatures[0] || typeof spec.signatures[0] !== "object" || typeof spec.signatures[0].signature !== "string") {
    throw _err("sigstore/bad-tlog-entry", "the Rekor dsse entry is missing its signature");
  }
  var envSig = _b64(envelope.signatures[0].sig, "dsseEnvelope.signatures[0].sig");
  var bodySig = _b64(spec.signatures[0].signature, "Rekor entry signature");
  if (!_bufferEquals(envSig, bodySig)) throw _err("sigstore/entry-mismatch", "the Rekor entry signature does not match the bundle signature");
  var payload = _b64(envelope.payload, "dsseEnvelope.payload");
  if (!spec.payloadHash || typeof spec.payloadHash.value !== "string") throw _err("sigstore/bad-tlog-entry", "the Rekor dsse entry is missing its payloadHash");
  if (spec.payloadHash.value !== _bufToString(_sha256(payload), "hex")) {
    throw _err("sigstore/entry-mismatch", "the Rekor entry payloadHash does not match the bundle payload");
  }
  var vf = spec.signatures[0].verifier;
  if (typeof vf !== "string") throw _err("sigstore/bad-tlog-entry", "the Rekor dsse entry is missing its verifier certificate");
  var vDer;
  try { vDer = x509.pemDecode(_bufToString(_b64(vf, "Rekor entry verifier"), "utf8"), "CERTIFICATE"); }
  catch (e) { throw _err("sigstore/bad-tlog-entry", "the Rekor entry verifier is not a valid certificate", e); }
  if (!_bufferEquals(vDer, leafDer)) throw _err("sigstore/entry-mismatch", "the Rekor entry verifier certificate does not match the bundle leaf certificate");
}

/** @internal The entry's verifier, bound to the bundle's leaf. The Rekor field is "the public key
 * that can verify the signature; this can also be an X509 code signing certificate that contains the
 * raw public key information", so an entry states one or the other and both are read. A certificate
 * binds as the same certificate; a bare key binds as the same key, which is what the entry claims
 * about it, and the certificate's own identity is settled by the chain leg rather than here. Neither
 * form is guessed at from the bytes: the armor names which one the entry wrote. */
function _bindVerifier(content, leafDer) {
  var text = _bufToString(_b64(content, "Rekor entry verifier"), "utf8");
  var vDer;
  try { vDer = x509.pemDecode(text, "CERTIFICATE"); } catch (_e) { vDer = null; } // allow:swallow-unverified the other armor is tried next and a value carrying neither is refused below
  if (vDer !== null) {
    if (!_bufferEquals(vDer, leafDer)) {
      throw _err("sigstore/entry-mismatch", "the Rekor entry verifier certificate does not match the bundle leaf certificate");
    }
    return;
  }
  var spki;
  try { spki = x509.pemDecode(text, "PUBLIC KEY"); }
  catch (e) { throw _err("sigstore/bad-tlog-entry", "the Rekor entry verifier is neither a certificate nor a public key", e); }
  var leafSpki = _parseCert(leafDer, "Fulcio leaf certificate").subjectPublicKeyInfo.bytes;
  if (!_bufferEquals(spki, _bufferFrom(leafSpki))) {
    throw _err("sigstore/entry-mismatch", "the Rekor entry verifier public key does not match the bundle leaf certificate's key");
  }
}

/** @internal Whether a string is a run of lowercase hexadecimal digits. The Rekor schema states the
 * artifact hash that way, and the comparison it feeds comes from a hex encoder that emits lowercase,
 * so an uppercase or non-hex value would compare unequal and be reported as a mismatched artifact
 * rather than as the malformed entry it is. Scanned by character code, since a pattern here would be
 * matched through a replaceable protocol. */
function _isLowerHex(s) {
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return s.length > 0;
}

/** @internal The hashedrekord v0.0.1 sibling of the row above. It answers the same three questions
 * the client specification states for binding an entry to the material being verified: the signature
 * in the body is the one the bundle carries, the certificate in the body is the bundle's leaf, and
 * the body names the artifact. The third is what makes this entry worth having, because
 * `data.hash` sits inside the canonicalized body that the inclusion proof folds to a signed root,
 * while the bundle's own messageDigest is covered by no signature at all. Returns that authenticated
 * hash, which is the statement the artifact is then held to. */
function _bindHashedRekordEntry(body, ms, leafDer) {
  var spec = body.spec;
  if (!spec || typeof spec !== "object" || !spec.signature || typeof spec.signature !== "object") {
    throw _err("sigstore/bad-tlog-entry", "the Rekor hashedrekord entry has no signature object");
  }
  if (typeof spec.signature.content !== "string") {
    throw _err("sigstore/bad-tlog-entry", "the Rekor hashedrekord entry is missing its signature content");
  }
  var bodySig = _b64(spec.signature.content, "Rekor entry signature");
  var armSig = _b64(ms.signature, "messageSignature.signature");
  if (!_bufferEquals(armSig, bodySig)) {
    throw _err("sigstore/entry-mismatch", "the Rekor entry signature does not match the bundle signature");
  }
  var pk = spec.signature.publicKey;
  if (!pk || typeof pk !== "object" || typeof pk.content !== "string") {
    throw _err("sigstore/bad-tlog-entry", "the Rekor hashedrekord entry is missing its verifier public key");
  }
  _bindVerifier(pk.content, leafDer);
  var data = spec.data;
  if (!data || typeof data !== "object" || !data.hash || typeof data.hash !== "object") {
    throw _err("sigstore/bad-tlog-entry", "the Rekor hashedrekord entry has no data hash");
  }
  var alg = typeof data.hash.algorithm === "string" ? _HASH_BY_REKOR[data.hash.algorithm] : null;
  if (!alg) {
    throw _err("sigstore/bad-tlog-entry", "the Rekor entry names a hash algorithm outside the schema's own three: " +
      (data.hash.algorithm === undefined ? "(none)" : guard.text.showValue(data.hash.algorithm)));
  }
  if (typeof data.hash.value !== "string" || data.hash.value.length !== alg.bytes * 2 ||
      !_isLowerHex(data.hash.value)) {
    throw _err("sigstore/bad-tlog-entry", "the Rekor entry's artifact hash is not a lowercase hex digest of its own algorithm");
  }
  return { algorithm: data.hash.algorithm, node: alg.node, value: data.hash.value };
}

function _verifyRekor(te, envelope, rekorKeys, leafDer) {
  return _verifyRekorEntry(te, rekorKeys, leafDer, "dsseEnvelope", function (body) {
    _bindDsseEntry(body, envelope, leafDer);
    return null;
  });
}

/** @internal The message-signature route through the same entry verification. Only the binding
 * differs, so the inclusion proof, the checkpoint and the SET are checked in one place for both arms
 * rather than in a copy per arm. */
function _verifyRekorMessage(te, ms, rekorKeys, leafDer) {
  return _verifyRekorEntry(te, rekorKeys, leafDer, "messageSignature", function (body) {
    return _bindHashedRekordEntry(body, ms, leafDer);
  });
}

function _verifyRekorEntry(te, rekorKeys, leafDer, contentType, bind) {
  var ip = te.inclusionProof;
  if (!ip || typeof ip.rootHash !== "string" || !_isArray(ip.hashes)) {
    throw _err("sigstore/bad-inclusion-proof", "the transparency-log entry has no inclusion proof");
  }
  var claimedSec = _numOf(te.integratedTime);
  var claimedMs = _isFiniteNumber(claimedSec) ? C.TIME.seconds(claimedSec) : NaN;
  /** @internal The canonicalized body is read ONCE and every check below runs on that one copy: the
   * signature and certificate it binds, the leaf hash the inclusion proof folds, and the bytes the
   * signed entry timestamp covers. A transparency-log entry is a caller-supplied object, so reading
   * the field again would let one body be bound while a different one is proven, and the verdict
   * would then attest an entry that never recorded what was verified. */
  var canonB64 = te.canonicalizedBody;
  if (typeof canonB64 !== "string") {
    throw _err("sigstore/bad-tlog-entry", "the transparency-log entry has no canonicalizedBody");
  }
  var canonBytes = _b64(canonB64, "canonicalizedBody");
  var body = _entryBody(canonBytes);
  _entryRow(body, contentType);
  var artifactHash = bind(body);
  var included;
  try {
    included = merkle.verifyInclusion({
      leafIndex: _bigIntOf(ip.logIndex),
      treeSize: _bigIntOf(ip.treeSize),
      leafHash: merkle.leafHash(canonBytes),
      proof: _map(ip.hashes, function (h, i) { return _b64(h, "inclusionProof.hashes[" + i + "]"); }),
      rootHash: _b64(ip.rootHash, "inclusionProof.rootHash"),
    });
  } catch (e) {
    throw _err("sigstore/bad-inclusion-proof", "the inclusion proof is malformed: " + e.message, e);
  }
  if (!included) throw _err("sigstore/inclusion-proof-mismatch", "the inclusion proof does not reconstruct the tree root");
  var checkpointOk = ip.checkpoint && typeof ip.checkpoint.envelope === "string" && _verifyCheckpoint(ip.checkpoint.envelope, ip, rekorKeys, claimedMs);
  if (!checkpointOk) throw _err("sigstore/unsigned-root", "the Rekor checkpoint (the signed tree root) did not verify under the caller Rekor key -- the inclusion-proof root is not attested");
  var setOk = _verifySet(te, rekorKeys, claimedMs, canonB64);
  if (!setOk) throw _err("sigstore/unattested-time", "the Rekor SET (the signed source of integratedTime) did not verify -- the log time is not attested and cannot date the Fulcio certificate");
  var t = _numOf(te.integratedTime);
  if (!_isFiniteNumber(t) || t < 0) throw _err("sigstore/bad-tlog-entry", "the transparency-log entry has a malformed integratedTime");
  var li = _numOf(te.logIndex);
  return {
    integratedTime: t, logIndex: _isFiniteNumber(li) ? li : null,
    logId: te.logId && te.logId.keyId ? _bufToString(_b64(te.logId.keyId, "logId.keyId"), "hex") : null,
    artifactHash: artifactHash,
  };
}


function _dn(cert, which) { return cert[which] && cert[which].dn; }

function _normRoots(fulcioRoots) {
  return _map(fulcioRoots, function (r, i) {
    var der = _isBuffer(r) ? r : (r && (r.der || r.rawBytes));
    if (!_isBuffer(der)) throw _err("sigstore/bad-input", "fulcioRoots[" + i + "] must be a DER Buffer or { der, validFor }");
    return { cert: _parseCert(der, "Fulcio CA root [" + i + "]"), validFor: (r && r.validFor) || null };
  });
}

function _pathToAnchor(leaf, anchor, intBySubject) {
  var anchorSubj = _dn(anchor, "subject");
  /** @internal Issuers are collected leaf-first and the path is assembled once, so no element is
   * ever moved to a new index: an indexed setter has nothing to intercept and cannot replace the
   * leaf the preceding signature checks authenticated. */
  var above = [], cur = leaf, seen = _create(null), guardN = 0;
  function assemble() {
    var path = [];
    for (var k = above.length - 1; k >= 0; k--) guard.list.append(path, above[k]);
    guard.list.append(path, leaf);
    return path;
  }
  while (guardN++ < 16) {
    var issuerDn = _dn(cur, "issuer");
    if (issuerDn === anchorSubj) return assemble();
    var cands = intBySubject[issuerDn] || [];
    var next = null;
    for (var j = 0; j < cands.length; j++) {
      if (cands[j] === anchor || seen[_dn(cands[j], "subject")]) continue;
      next = cands[j]; break;
    }
    if (!next) return null;
    seen[_dn(next, "subject")] = 1;
    guard.list.append(above, next);
    cur = next;
  }
  return null;
}

var OID_SCT_LIST = oid.byName("signedCertificateTimestampList");

/** @internal The certificate-transparency logs a caller pins, in the shape the Rekor keys take: an
 * operator builds both from the one trusted-root document. An empty array is refused rather than read
 * as "no logs to check against", which would turn an opted-in check into a silent pass. */
function _normCtLogs(ctLogs) {
  if (!_isArray(ctLogs)) throw _err("sigstore/bad-input", "ctLogs must be an array of { keyId, spki, validFor? }");
  if (ctLogs.length === 0) throw _err("sigstore/bad-input", "ctLogs is empty; omit the option to skip the certificate-transparency check rather than supplying no logs");
  return _map(ctLogs, function (l, i) {
    if (l === null || typeof l !== "object") throw _err("sigstore/bad-input", "ctLogs[" + i + "] must be { keyId, spki, validFor? }");
    if (!_isBuffer(l.keyId)) throw _err("sigstore/bad-input", "ctLogs[" + i + "].keyId must be the log id as a Buffer");
    if (!_isBuffer(l.spki)) throw _err("sigstore/bad-input", "ctLogs[" + i + "].spki must be the log's SubjectPublicKeyInfo DER");
    return { keyId: l.keyId, spki: l.spki, validFor: l.validFor || null };
  });
}

/** @internal RFC 6962 sec. 3.2: Fulcio logs the certificate as it issues it and embeds the log's
 * receipt, so the receipt covers the certificate WITHOUT that extension, under the issuer's key hash.
 * `pki.ct.x509CertEntry` reconstructs exactly that entry from the final certificate, and each receipt
 * is checked against the log the caller pinned for it. At least one must verify, which is the sec. 3.3
 * floor; a receipt from a log the caller did not pin counts for nothing. */
async function _verifyEmbeddedScts(leaf, leafDer, issuer, ctLogs, timeMs, atMs) {
  if (ctLogs === undefined || ctLogs === null) return { checked: false, validScts: 0 };
  var logs = _normCtLogs(ctLogs);
  var ext = null;
  var exts = leaf.extensions || [];
  for (var i = 0; i < exts.length; i++) { if (exts[i].oid === OID_SCT_LIST) { ext = exts[i]; break; } }
  if (!ext) {
    throw _err("sigstore/sct-missing", "ctLogs was supplied but the Fulcio certificate carries no signedCertificateTimestampList extension (RFC 6962 sec. 3.3)");
  }
  var entry, list;
  try {
    entry = ct.x509CertEntry(leafDer, issuer);
    list = ct.parseSctList(ext.value);
  } catch (e) { throw _err("sigstore/sct-unverified", "the embedded certificate-transparency receipt could not be read: " + e.message, e); }
  var valid = 0;
  for (var s = 0; s < list.scts.length; s++) {
    var sct = list.scts[s];
    /** @internal A log key's window says when that key was the log's, so the receipt is held to the
     * window as it stood when the receipt was signed, not when the artifact was later logged. */
    var log = _ctLogFor(logs, sct.logId, _sctMs(sct));
    if (!log) continue;
    /** @internal RFC 6962 sec. 5.2: a client rejects a receipt dated after the instant it is checking
     * at, which a log cannot have issued yet. The reference is the caller's own `opts.time` and never
     * the Rekor entry time, which records whole seconds while a receipt carries milliseconds, so a
     * receipt issued in the same second as the entry would read as dated after it. The bound is the end
     * of that second instead, so the granularity is allowed for and nothing later is. The timestamp is a
     * BigInt and a relational comparison against a Number is exact for both. */
    if (sct.timestamp != null && sct.timestamp > atMs) continue;
    if (await _sctVerifies(entry, sct, log.spki)) valid += 1;
  }
  if (valid < 1) {
    throw _err("sigstore/sct-unverified", "no embedded certificate-transparency receipt verified against a pinned log (RFC 6962 sec. 3.3)");
  }
  return { checked: true, validScts: valid };
}

/** @internal A receipt the verifier refuses structurally counted as verified would be the whole leg
 * lost, so a fault is an unverified receipt and the next one is still tried. */
function _sctVerifies(entry, sct, spki) {
  return ct.verifySct(entry, sct, spki).then(function (ok) { return ok === true; }, function () { return false; });
}

/** @internal A receipt's own instant, in milliseconds. The parser's `timestampMs` is this same value
 * wherever it is representable, and above 2^53 there is no reachable instant either way. */
function _sctMs(sct) { return _numberOf(sct.timestamp || 0); }

function _ctLogFor(logs, logIdBytes, timeMs) {
  var want = _isBuffer(logIdBytes) ? logIdBytes : _bufferFrom(logIdBytes || []);
  for (var i = 0; i < logs.length; i++) {
    if (_bufferEquals(logs[i].keyId, want) && _inWindow(timeMs, logs[i].validFor)) return logs[i];
  }
  return null;
}

async function _verifyChain(leaf, chainDers, fulcioRoots, timeMs) {
  var roots = _normRoots(fulcioRoots);
  var bundleLinks = _map(_arraySlice(chainDers, 1), function (d, i) { return _parseCert(d, "bundle intermediate [" + i + "]"); });
  var intBySubject = _create(null);
  function addInt(c) { guard.list.append(intBySubject[_dn(c, "subject")] = intBySubject[_dn(c, "subject")] || [], c); }
  _forEach(roots, function (r) { addInt(r.cert); });
  _forEach(bundleLinks, addInt);
  var candidates = _filter(roots, function (r) { return _inWindow(timeMs, r.validFor); });
  var lastErr = _err("sigstore/chain-incomplete", "no caller-supplied Fulcio anchor (within its validity window) issues the chain");
  for (var i = 0; i < candidates.length; i++) {
    var anchor = candidates[i].cert;
    var path = _pathToAnchor(leaf, anchor, intBySubject);
    if (!path) continue;
    var spki = anchor.subjectPublicKeyInfo;
    try {
      var res = await pathValidate.validate(path, {
        time: new _Date(timeMs),
        historicalMode: true,
        trustAnchors: { name: anchor.subject, publicKey: spki.bytes, algorithm: spki.algorithm.oid, parameters: spki.algorithm.parameters },
        requiredEku: ["codeSigning"],
      });
      /** @internal The path is anchor-proximal first and leaf last, so the certificate directly above
       * the leaf issued it, and the anchor did when the leaf sits alone. Returning it here is what lets
       * the certificate-transparency leg reconstruct the logged entry without resolving the issuer a
       * second time, from a chain this leg has already validated. */
      if (res.valid) return { issuer: path.length > 1 ? path[path.length - 2] : anchor };
      lastErr = _err("sigstore/chain-invalid", "the Fulcio certificate chain is not valid as of the log time");
    } catch (e) {
      lastErr = _err("sigstore/chain-invalid", "the Fulcio certificate chain failed validation: " + e.message, e);
    }
  }
  throw lastErr;
}


var SAN_OID = oid.byName("subjectAltName");
var FULCIO_PREFIX = _join(_arraySlice(_split(oid.byName("otherName"), "."), 0, -1), ".") + ".";
function _identity(leaf) {
  var out = { san: null, extensions: _create(null) };
  try {
    _forEach(leaf.extensions || [], function (ext) {
      if (ext.oid === SAN_OID) { out.san = _sanValue(ext); return; }
      if (_strIndexOf(ext.oid, FULCIO_PREFIX) === 0) {
        out.extensions[ext.name || ext.oid] = _fulcioExtValue(ext, _numberOf(_strSlice(ext.oid, FULCIO_PREFIX.length)));
      }
    });
  } catch (e) {
    if (e instanceof SigstoreError) throw e;
    throw _err("sigstore/bad-certificate", "the Fulcio certificate identity could not be decoded", e);
  }
  return out;
}
var GN_TYPE = _assign(_create(null), { 1: "rfc822Name", 2: "dNSName", 6: "uri" });
function _sanValue(ext) {
  var seq = asn1.decode(ext.value);
  var names = [];
  for (var i = 0; i < (seq.children || []).length; i++) {
    var n = seq.children[i];
    if (n.tagClass !== "context") continue;
    var val = null;
    if (!n.constructed && GN_TYPE[n.tagNumber]) {
      val = { type: GN_TYPE[n.tagNumber], value: _bufToString(asn1.read.octetStringImplicit(n, n.tagNumber), "utf8") };
    } else if (n.constructed && n.tagNumber === 0 && (n.children || []).length >= 2) {
      var inner = (n.children[1].children || [])[0] || n.children[1];
      var v;
      try {
        v = asn1.read.string(inner);
      } catch (_e) {
        v = null;
      }
      val = { type: "otherName", oid: asn1.read.oid(n.children[0]), value: v };
    }
    if (val) guard.list.append(names, val);
  }
  if (names.length > 1) throw _err("sigstore/bad-certificate", "the Fulcio certificate carries multiple SAN identities");
  return names[0] || null;
}
function _fulcioExtValue(ext, leafArc) {
  if (!_isBuffer(ext.value)) throw _err("sigstore/bad-certificate", "Fulcio extension " + ext.oid + " has no value");
  if (leafArc >= 1 && leafArc <= 6) return _bufToString(ext.value, "utf8");
  return asn1.read.string(asn1.decode(ext.value));
}

var IDENTITY_FIELDS = ["san", "issuer", "sourceRepositoryURI"];
var IDENTITY_KEYS = _assign(_create(null), { san: 1, issuer: 1, sourceRepositoryURI: 1 });
var _VERIFY_BUNDLE_OPTS = _assign(_create(null), { fulcioRoots: 1, rekorKeys: 1, ctLogs: 1, identity: 1, predicateType: 1, time: 1, artifact: 1 });

/** @internal The bytes a message signature covers, taken once. There is no shape here in which a
 * caller hands over a precomputed digest: the arm's own field comment forbids using one as a
 * verification input, and the client specification asks a verifier to accept the artifact and compute
 * the digest itself so the two cannot be confused. So this takes a byte source and nothing else, and
 * a hex string or a digest-shaped object is refused at the door rather than hashed as if it were the
 * artifact. Snapshotted, because both the digest and the signature read these bytes and a view whose
 * backing store changes between the two would be verified in one form and reported in the other. */
function _artifactBytes(v) {
  if (!guard.bytes.isByteSource(v)) {
    throw _err("sigstore/bad-input", "opts.artifact must be the artifact's bytes (a Buffer, TypedArray, DataView or ArrayBuffer); " +
      "a digest is not accepted in its place, since the signature covers the artifact itself");
  }
  return guard.bytes.snapshotSource(v, SigstoreError, "sigstore/bad-input", "opts.artifact");
}

function _checkIdentity(id, policy) {
  // allow:registry-table-inherits-object-prototype -- the identityChecked record an operator reads by field name, whose three keys are the fixed IDENTITY_FIELDS rather than anything the bundle supplies
  var ran = { san: false, issuer: false, sourceRepositoryURI: false };
  if (policy === undefined || policy === null) return ran;
  if (typeof policy !== "object" || _isArray(policy)) {
    throw _err("sigstore/bad-input", "opts.identity must be an object naming the identity fields to pin (" + _join(IDENTITY_FIELDS, ", ") + ")");
  }
  guard.identifier.assertKnownKeys(policy, IDENTITY_KEYS, _err, "sigstore/bad-input", "opts.identity has an unknown key ");
  var asked = _filter(IDENTITY_FIELDS, function (f) { return policy[f] !== undefined; });
  if (!asked.length) {
    throw _err("sigstore/bad-input", "opts.identity constrains nothing -- name at least one of " + _join(IDENTITY_FIELDS, ", ") + ", or omit it to state that the signer is not being checked");
  }
  _forEach(asked, function (f) {
    if (typeof policy[f] !== "string" || policy[f] === "") {
      throw _err("sigstore/bad-input", "opts.identity." + f + " must be a non-empty string -- a value that cannot be compared would leave the signer unchecked under a policy that names it");
    }
    ran[f] = true;
  });
  var sanValue = id.san && id.san.value;
  if (policy.san && sanValue !== policy.san) throw _err("sigstore/identity-mismatch", "the certificate SAN " + _jsonStringify(sanValue) + " does not match the expected identity");
  if (policy.issuer && policy.issuer !== id.extensions.issuer && policy.issuer !== id.extensions.issuerLegacy) throw _err("sigstore/identity-mismatch", "the certificate OIDC issuer does not match the expected issuer");
  if (policy.sourceRepositoryURI && id.extensions.sourceRepositoryURI !== policy.sourceRepositoryURI) throw _err("sigstore/identity-mismatch", "the certificate source-repository URI does not match");
  return ran;
}


function _statement(payload, payloadType, expectedPredicate) {
  if (payloadType !== "application/vnd.in-toto+json") {
    throw _err("sigstore/bad-statement", "unsupported DSSE payloadType: " + payloadType);
  }
  var st = _jsonParse(payload, "sigstore/bad-statement", "in-toto statement");
  if (!st || typeof st !== "object" || st._type !== "https://in-toto.io/Statement/v1") throw _err("sigstore/bad-statement", "the payload is not an in-toto Statement v1");
  if (!_isArray(st.subject) || !st.subject.length) throw _err("sigstore/bad-statement", "the in-toto statement has no subject");
  if (expectedPredicate && st.predicateType !== expectedPredicate) {
    throw _err("sigstore/predicate-mismatch", "the statement predicateType " + _jsonStringify(st.predicateType) + " does not match the expected " + _jsonStringify(expectedPredicate));
  }
  return st;
}


/**
 * @primitive pki.sigstore.verifyBundle
 * @signature pki.sigstore.verifyBundle(bundle, opts) -> Promise<result>
 * @since 0.2.3
 * @status stable
 * @spec DSSE, Sigstore bundle v0.3, RFC 9162, SLSA provenance v1
 * @related pki.sigstore.parseBundle, pki.sigstore.pae
 *
 * Verify a Sigstore bundle (an npm `--provenance` artifact) offline against
 * caller-supplied trust material, composing five fail-closed legs: the DSSE
 * signature over its PAE under the Fulcio leaf key; the Fulcio chain validated as
 * of the Rekor log time; the Rekor inclusion proof folded to a Rekor-signed root;
 * the log entry bound to this exact signature; and the in-toto SLSA statement.
 * Any leg failing throws a typed `sigstore/*` error. On success returns
 * `{ valid: true, verified: true, payload, statement, subjects, predicateType, predicate,
 * identity, identityChecked, predicateTypeChecked, sctChecked, validScts, integratedTime, logIndex, logId }` (`valid` is the
 * canonical toolkit-wide verdict alias of `verified`, `predicateTypeChecked` says whether a pinned
 * `opts.predicateType` was checked, and `logIndex` / `logId` identify the attested Rekor log entry).
 * `payload` is the raw verified
 * envelope bytes (never a re-serialization), and the caller confirms a
 * `subjects[].digest` matches the published artifact.
 *
 * Fulcio logs every certificate it issues to a certificate-transparency log and
 * embeds the log's receipt in the certificate (RFC 6962 sec. 3.2). Supplying
 * `opts.ctLogs` checks it: the receipt is verified over the certificate as it
 * stood before the receipt was added, under the key of the log that issued it,
 * and at least one receipt must verify against a pinned log (sec. 3.3). It is
 * what says the signing certificate was public when it was issued rather than
 * handed out quietly. The option is opt-in, so a caller that pins no log is
 * unaffected and `sctChecked` reports `false`; supplying an empty array is
 * refused rather than read as a policy that checks nothing. `validScts` counts
 * the receipts that verified.
 *
 * A log's `validFor` window is read at the instant the receipt was signed, since
 * that is when the key was the log's, not at the time the artifact was later
 * logged. A receipt dated after the instant being validated at is not counted
 * (RFC 6962 sec. 5.2); with no `opts.time` that instant is the end of the Rekor
 * entry's own second, which allows for the entry recording whole seconds while a
 * receipt carries milliseconds, and accepts nothing beyond it.
 *
 * `verified: true` says the artifact was signed and logged; it says nothing about
 * who. Fulcio issues a certificate to anyone who completes an OIDC flow, so who
 * signed is decided only by `opts.identity`, and `identityChecked` reports which of
 * its fields were compared (`{ san, issuer, sourceRepositoryURI }`, each a boolean).
 * An `identity` naming none of them is refused, since it would accept every signer
 * while reading as a policy; so is an unrecognized field name, which would otherwise
 * pin nothing under a spelling the operator believes constrains the signer.
 *
 * A bundle carrying a `message_signature` is verified against the artifact itself,
 * which `opts.artifact` supplies as bytes and which this hashes. It is required for
 * that arm: the `messageDigest` the bundle carries is covered by no signature, and
 * the arm's own definition says a client must not use it to verify the signature, so
 * there is no shape here in which a caller hands over a digest instead. The artifact
 * is held to the hash the Rekor entry records, which the inclusion proof covers, and
 * then the signature is checked over its bytes. `artifactDigest` reports the digest
 * this computed and `digestAlgorithm` the algorithm the entry named;
 * `messageDigestChecked` says whether the bundle's own digest was there to agree with.
 * `opts.predicateType` is refused for that arm, and `opts.artifact` for a DSSE one,
 * rather than being read and ignored.
 *
 * The verdict has one shape for both arms. `contentType` names the arm, and the
 * fields the other arm has nothing to report are present and `null`.
 *
 * @opts
 *   fulcioRoots:   Array,      // the Fulcio CA anchors: a DER Buffer or { der, validFor } each
 *   rekorKeys:     Array,      // [{ keyId, spki, validFor? }] the Rekor log public keys
 *   ctLogs:        Array,      // optional [{ keyId, spki, validFor? }] certificate-transparency logs; when given, the certificate's embedded receipt is checked
 *   identity:      object,     // optional policy: { san, issuer, sourceRepositoryURI }; at least one required when present
 *   predicateType: string,     // optional: require this in-toto predicateType (e.g. the SLSA URI); dsse_envelope bundles only
 *   artifact:      BufferSource, // the bytes a message_signature covers; required for that arm, refused for a dsse_envelope
 *   time:          Date,       // optional check-date override (default: the Rekor integratedTime)
 *
 * @example
 *   // requires: `bundle` from cosign / npm provenance, and `sigstoreTrust` built from
 *   // the public-good trusted_root.json (the Fulcio + Rekor material it pins)
 *   var out = await pki.sigstore.verifyBundle(bundle, sigstoreTrust);
 *   out.verified;            // true
 *   out.subjects[0].digest;  // { sha512: "..." } -- confirm against your tarball
 */
async function verifyBundle(bundle, opts) {
  if (bundle === null || typeof bundle !== "object" && typeof bundle !== "string" && !_isBuffer(bundle)) {
    throw new TypeError("verifyBundle: bundle must be an object, JSON string, or Buffer");
  }
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _VERIFY_BUNDLE_OPTS, _err, "sigstore/bad-input", "pki.sigstore.verifyBundle has an unknown option ");
  /** @internal parseBundle takes the copy, so every check below runs on plain data that cannot change
   * under it, whichever field it reads and however many times. */
  var b = parseBundle(bundle);
  var vm = b.verificationMaterial;
  var contentType = _contentTypeOf(b);
  var isMsg = contentType === "messageSignature";
  var env = b.dsseEnvelope;
  /** @internal Every option is read once, into a snapshot the checks and the verdict both read. An
   * option reached through an accessor answers each read separately, so a second read is a second
   * answer: one that passed a refusal could be reported by the verdict as a different value, and a
   * verdict that names an option is naming the value the check ran on. */
  var o = guard.identifier.snapshotOptions(opts, _VERIFY_BUNDLE_OPTS);
  var rekorKeys = o.rekorKeys || [];
  var fulcioRoots = o.fulcioRoots || [];

  /** @internal Each option belongs to one arm, and one supplied for the other is refused rather than
   * passed over. An ignored option reads as a check that ran: opts.artifact on a DSSE bundle names
   * bytes nothing here compares, and opts.predicateType on a message signature names a statement
   * there is none of. */
  if (!isMsg && o.artifact != null) {
    throw _err("sigstore/bad-input", "opts.artifact is only read for a message_signature bundle; this bundle carries a dsse_envelope, whose artifact binding is the statement's own subject digest");
  }
  if (isMsg && o.predicateType != null) {
    throw _err("sigstore/bad-input", "opts.predicateType is only read for a dsse_envelope bundle; a message_signature carries no statement to pin a predicate type on");
  }
  var artifact = null;
  if (isMsg) {
    if (o.artifact == null) {
      throw _err("sigstore/artifact-required", "verifying a message_signature bundle requires opts.artifact, the bytes the signature covers; the bundle's own messageDigest is unauthenticated and is not a substitute");
    }
    artifact = _artifactBytes(o.artifact);
  }

  var leafDer = _leafCertDer(vm);
  var leaf = _parseCert(leafDer, "Fulcio leaf certificate");
  var leafKey = _pubFromSpki(leaf.subjectPublicKeyInfo.bytes, "Fulcio leaf");
  /** @internal Read once, validated once, used from the validated copy everywhere below. */
  var msParsed = isMsg ? _parseMessageSignature(b.messageSignature) : null;
  var payload = null, derSig;
  if (isMsg) {
    derSig = _b64(msParsed.signature, "messageSignature.signature");
  } else {
    payload = _b64(env.payload, "dsseEnvelope.payload");
    derSig = _b64(env.signatures[0].sig, "dsseEnvelope.signatures[0].sig");
    if (!_rawVerify(leafKey, pae(env.payloadType, payload), derSig)) throw _err("sigstore/dsse-verify-failed", "the DSSE signature does not verify under the Fulcio leaf key");
  }

  var tlogs = _isArray(vm.tlogEntries) ? vm.tlogEntries : [];
  if (!tlogs.length) throw _err("sigstore/bad-bundle", "a keyless bundle requires at least one transparency-log entry");
  /** @internal An entry is tried until one passes every check that depends on which entry it is,
   * and those checks include a certification-path validation whose instant comes from the entry
   * itself unless the caller pins one. The count is therefore a work multiplier, and the byte
   * budget alone leaves room for far more entries than any real bundle carries. This is a local
   * resource bound rather than a rule the bundle specification states. */
  if (tlogs.length > C.LIMITS.TLOG_MAX_COUNT) {
    throw _err("sigstore/bad-bundle", "a bundle offers at most " + C.LIMITS.TLOG_MAX_COUNT
      + " transparency-log entries; this one offers " + tlogs.length);
  }
  /** @internal Selecting an entry means finding one that passes EVERY check deciding WHICH entry it
   * is: that it binds to this signature and certificate, that it records this artifact, and that the
   * certificate chain and the embedded timestamps hold at the instant it attests. Any of those
   * failing is a reason to try the next entry rather than to refuse the bundle, because a log can
   * hold several entries for one signature. Each check left after the loop refused a bundle whose
   * later entry would have passed it, once for the artifact hash and again for the chain instant.
   * Passing over an entry is not accepting a weaker one: the selected entry has passed all of them,
   * and when none does the last failure is what the caller is told. */
  var haveCallerTime = guard.time.isDate(o.time);
  var callerTime = haveCallerTime ? guard.time.instantOf(o.time) : null;
  var chainDers = _chainDers(vm);
  /** @internal A caller-pinned instant is the same for every candidate, so the chain it decides is
   * computed on the first candidate and reused rather than rebuilt per entry. Without one the instant
   * comes from the entry and every candidate is its own question. The timestamps are not cached
   * beside it: a candidate that reaches them and passes is selected immediately, so no later
   * candidate could read the result. */
  var pinnedChain = null;
  var rekor = null, lastErr = null, artifactComputed = null, sctResult = null;
  for (var ti = 0; ti < tlogs.length; ti++) {
    if (!tlogs[ti] || typeof tlogs[ti] !== "object") { lastErr = _err("sigstore/bad-bundle", "a transparency-log entry is not an object"); continue; }
    try {
      var candidate = isMsg ? _verifyRekorMessage(tlogs[ti], msParsed, rekorKeys, leafDer)
        : _verifyRekor(tlogs[ti], env, rekorKeys, leafDer);
      var candidateDigest = null;
      if (isMsg) {
        candidateDigest = nodeCrypto.createHash(candidate.artifactHash.node).update(artifact).digest();
        if (!guard.crypto.constantTimeEqual(candidateDigest, _bufferFrom(candidate.artifactHash.value, "hex"))) {
          throw _err("sigstore/artifact-mismatch", "the artifact does not match the one the transparency-log entry records; its " +
            candidate.artifactHash.algorithm + " digest is " + _bufToString(candidateDigest, "hex") + " and the entry names " + candidate.artifactHash.value);
        }
      }
      var candidateTime = haveCallerTime ? callerTime : C.TIME.seconds(candidate.integratedTime);
      var candidateChain = pinnedChain !== null ? pinnedChain
        : await _verifyChain(leaf, chainDers, fulcioRoots, candidateTime);
      if (haveCallerTime) pinnedChain = candidateChain;
      /** @internal With no caller instant the reference is the authenticated log-entry time, whose
       * whole second is inclusive: a certificate logged in the same second as its entry is not dated
       * after it, and nothing beyond that second is accepted. */
      var candidateBound = haveCallerTime ? candidateTime : C.TIME.seconds(candidate.integratedTime) + 999;
      var candidateScts = await _verifyEmbeddedScts(leaf, leafDer, candidateChain.issuer, o.ctLogs, candidateTime, candidateBound);
      rekor = candidate;
      artifactComputed = candidateDigest;
      sctResult = candidateScts;
      break;
    } catch (e) { lastErr = e; }
  }
  if (rekor === null) throw lastErr;
  var integratedTime = rekor.integratedTime;

  /** @internal The order the client specification states: the entry is verified first, because it is
   * what supplies both the time the certificate is checked at and the authenticated statement of what
   * was signed. The artifact is held to THAT hash rather than to the digest the bundle carries, which
   * no signature covers, and that comparison is what selected the entry above. Only after the
   * artifact is the one the log recorded is the signature checked over its bytes. */
  var artifactDigest = null, digestAlgorithm = null, messageDigestChecked = false;
  if (isMsg) {
    digestAlgorithm = rekor.artifactHash.algorithm;
    var computed = artifactComputed;
    artifactDigest = _bufToString(computed, "hex");
    if (msParsed.digest !== null) {
      var againstClaim = msParsed.digestAlg.node === rekor.artifactHash.node ? computed
        : nodeCrypto.createHash(msParsed.digestAlg.node).update(artifact).digest();
      if (!guard.crypto.constantTimeEqual(againstClaim, msParsed.digest)) {
        throw _err("sigstore/artifact-mismatch", "the artifact does not match the messageDigest the bundle carries");
      }
      messageDigestChecked = true;
    }
    if (!_rawVerify(leafKey, artifact, derSig)) {
      throw _err("sigstore/signature-verify-failed", "the message signature does not verify over the artifact under the Fulcio leaf key");
    }
  }

  var identity = _identity(leaf);
  var identityChecked = _checkIdentity(identity, o.identity);

  /** @internal One verdict shape for both arms, so a caller reads the same fields whichever a bundle
   * carries and a missing key never has to be told apart from a false one. The fields the other arm
   * has nothing to report are present and null. */
  var st = isMsg ? null : _statement(payload, env.payloadType, o.predicateType);

  return guard.verdict.of({
    valid: true,
    verified: true,
    contentType: contentType,
    payload: payload,
    statement: st,
    subjects: st === null ? null : st.subject,
    predicateType: st === null ? null : st.predicateType,
    predicate: st === null ? null : st.predicate,
    artifactDigest: artifactDigest,
    digestAlgorithm: digestAlgorithm,
    messageDigestChecked: messageDigestChecked,
    identity: identity,
    identityChecked: identityChecked,
    predicateTypeChecked: o.predicateType != null,
    sctChecked: sctResult.checked,
    validScts: sctResult.validScts,
    integratedTime: integratedTime,
    logIndex: rekor.logIndex,
    logId: rekor.logId,
  });
}

module.exports = {
  pae: pae,
  parseBundle: parseBundle,
  verifyBundle: verifyBundle,
};
