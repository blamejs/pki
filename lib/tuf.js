// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.tuf
 * @nav        Transparency
 * @title      TUF
 * @fullname   The Update Framework: metadata verification and root rotation
 * @order      230
 * @slug       tuf
 *
 * @intro
 *   The Update Framework's metadata layer: the signed documents a repository
 *   publishes to say which keys may sign what, and the rules a client applies
 *   before believing any of it. This is the trust root a sigstore verifier
 *   would otherwise have pinned by hand.
 *
 *   TUF signs the canonical JSON form of a document's `signed` object, so
 *   `canonicalJson` is the wire format rather than a convenience: it sorts
 *   object keys by code point, emits no whitespace, and escapes only backslash
 *   and quote, leaving a literal control character as itself. `JSON.stringify`
 *   would write `\n` where this writes a newline byte, so the two produce
 *   different signatures over the same document. A float is refused rather than
 *   rounded, because the reference encoder cannot write one.
 *
 *   `keyId` derives a key's identifier as the hex SHA-256 of its own canonical
 *   form, and `verifySignatures` recomputes it for every key a role names, so a
 *   document cannot list one key under another's identifier. A threshold counts
 *   one verified signature per distinct identifier, which is what the
 *   specification requires of a client meeting the same key twice.
 *
 *   `updateRoot` walks the root chain: each new root must be signed by a
 *   threshold of the keys the trusted root names AND a threshold of its own, and
 *   its version must be exactly one more than the trusted one. That pair of
 *   rules is what makes a key rotation safe and a skipped intermediate
 *   impossible. Verifying only, and transport-free: nothing here fetches.
 *
 * @card
 *   Canonical JSON signing preimage, key-identifier binding, threshold
 *   verification, and the root-rotation chain walk. Fail-closed, no transport.
 */

var constants = require("./constants");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var rfc3339 = require("./rfc3339");

var TufError = frameworkError.TufError;
function _err(code, message, cause) { return new TufError(code, message, cause); }

var _isArray = intrinsic.isArray;
var _isSafeInteger = intrinsic.isSafeInteger;
var _keys = intrinsic.keys;
var _create = intrinsic.create;
var _hasOwn = intrinsic.hasOwn;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferConcat = intrinsic.bufferConcat;
var _bufToString = intrinsic.bufToString;
/** @internal `append`, not a captured `push`: a store at an index walks the prototype chain for a
 *  setter, so an accessor there takes the element being appended. `append` defines it. */
var _push = intrinsic.append;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _codePointAt = intrinsic.uncurry(String.prototype.codePointAt);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _numToString = intrinsic.uncurry(Number.prototype.toString);
var _dateParse = intrinsic.dateParse;
var _byteLength = intrinsic.byteLength;
var _sort = intrinsic.sort;
var _join = intrinsic.join;

var CANONICAL_MAX_DEPTH = constants.LIMITS.JSON_MAX_DEPTH;
var KEY_ID_HEX_LEN = 64;
var TUF_ROLES = ["root", "timestamp", "snapshot", "targets"];

/** @internal Canonical JSON escapes ONLY these two, each with a single backslash. Everything else,
 *  including a byte below 0x20, is emitted as itself. A generic JSON writer escapes far more, and
 *  would produce a different preimage for the same document. */
function _canonicalString(s, out, budget) {
  /** @internal Every string reaching the encoding passes here, keys and values alike, so the
   *  well-formed check is made once. Canonical JSON is the preimage a TUF signature covers, and an
   *  unpaired surrogate would be converted to U+FFFD, so two documents differing only in that code unit
   *  would have the same signing bytes.
   *  @guard-via guard\.text\.assertWellFormedUtf16\( */
  guard.text.assertWellFormedUtf16(s, TufError, "tuf/bad-input", "a canonical JSON string");
  _emit(out, "\"", budget);
  var start = 0;
  for (var i = 0; i < s.length; i++) {
    var c = _codePointAt(s, i);
    if (c === 0x5c || c === 0x22) {
      if (i > start) _emit(out, _strSlice(s, start, i), budget);
      _emit(out, c === 0x5c ? "\\\\" : "\\\"", budget);
      start = i + 1;
    }
  }
  if (start < s.length) _emit(out, _strSlice(s, start), budget);
  _emit(out, "\"", budget);
}

/** @internal Keys compared by CODE POINT. A default sort compares UTF-16 code units, which orders a
 *  surrogate pair below U+FFFF where the code point orders it above, so the two disagree on any
 *  document carrying a key outside the basic plane. */
function _byCodePoint(a, b) {
  var n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    var ca = _codePointAt(a, i), cb = _codePointAt(b, i);
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

/** @internal Whether a value is a plain record: an object whose prototype is `Object.prototype` or null.
 *  Canonical JSON encodes an object by its own enumerable keys, which is only the whole value when the
 *  value has no state anywhere else, and the line is drawn by PROTOTYPE rather than by naming the classes
 *  to refuse. A denylist of the JS built-ins left every HOST object admitted: a Blob, a stream, a
 *  CryptoKey, an X509Certificate, a WebAssembly module and a collection iterator each have internal state
 *  and no enumerable keys, so each encoded as `{}` after the named built-ins were already refused.
 *  Drawn this way it also refuses a class nobody has written yet.
 *
 *  A revoked Proxy throws on the prototype read itself, so the read is guarded and the refusal is this
 *  module's own rather than whatever the Proxy raised. */
function _isPlainRecordByPrototype(value) {
  var proto;
  try { proto = intrinsic.getPrototypeOf(value); }
  catch (e) { void e; return false; }
  return proto === null || proto === _OBJECT_PROTOTYPE;
}
/** @internal The sentinel comes from `guard.intrinsic`, captured at load, rather than from a live
 *  `Object.prototype` read: comparing against the live global would let a replacement decide what counts
 *  as a plain record, and the whole point of this check is that nothing but a plain record is signed. */
var _OBJECT_PROTOTYPE = intrinsic.ObjectProto;

/** @internal Whether a value can be inspected at all. A revoked Proxy throws on every operation, so the
 *  first thing to touch it raises its TypeError rather than this module's typed refusal. */
function _isProbeable(value) {
  try { intrinsic.getPrototypeOf(value); return true; }
  catch (e) { void e; return false; }
}

/** @internal Every fragment is charged to a budget shared across the whole walk, and the budget is what
 *  bounds the work. The depth cap bounds the RECURSION and says nothing about the output, because a value
 *  that shares a subobject with itself is a graph rather than a tree and each reference is expanded
 *  independently: `v = [v, v]` repeated n times is n levels deep and 2 to the n leaves wide. MEASURED on
 *  the unbudgeted walk, 24 levels produced 67,108,861 bytes in 1.8 seconds and 25 ended the process with a
 *  fatal out-of-memory on a 2 GiB heap, from an input of 25 arrays (CWE-770). Charging each fragment
 *  refuses before the next doubling is accumulated, so the cost follows the budget rather than the shape
 *  of the input. The bound is the same `C.LIMITS.JSON_MAX_BYTES` a TUF document itself is read under: a
 *  canonical form larger than any document this module will parse cannot be the preimage of one. */
function _emit(out, text, budget) {
  /** @internal The charge is in UTF-8 BYTES, which is the unit the budget is in and the unit the returned
   *  buffer is measured in. `text.length` counts UTF-16 code units, so a string outside the Basic Latin
   *  range undercharged by its encoded width: MEASURED, 1,048,574 CJK code points produced 3,145,724 bytes
   *  against a 1,048,576-byte budget, because each costs three bytes and was charged as one. */
  budget.spend(_byteLength(text, "utf8"), "the canonical form");
  _push(out, text);
}

function _canonical(value, out, depth, budget) {
  if (depth > CANONICAL_MAX_DEPTH) {
    throw _err("tuf/too-deep", "the document nests deeper than " + CANONICAL_MAX_DEPTH + " levels");
  }
  if (value === null) { _emit(out, "null", budget); return; }
  if (value === true) { _emit(out, "true", budget); return; }
  if (value === false) { _emit(out, "false", budget); return; }
  if (typeof value === "string") { _canonicalString(value, out, budget); return; }
  if (typeof value === "number") {
    /** @internal A float has no canonical form here: the reference encoder refuses one outright, so
     *  a document a conforming signer produced contains none. A value past the exactly-representable
     *  range is refused for the same reason a narrowed one would be wrong: the digits written would
     *  not be the digits signed. */
    if (!_isSafeInteger(value)) {
      throw _err("tuf/bad-input", "canonical JSON encodes only exact integers; " +
        guard.text.showValue(value) + " is not one");
    }
    _emit(out, _numToString(value, 10), budget);
    return;
  }
  /** @internal A revoked Proxy throws on EVERY operation, `Array.isArray` among them, so the array test
   *  below would raise the Proxy's own TypeError before any check of this module's ran. Probing it once
   *  here, inside a guard, makes the refusal this module's own with its own code. */
  if (typeof value === "object" && !_isProbeable(value)) {
    throw _err("tuf/bad-input", "canonical JSON cannot read this value: it is a revoked Proxy, which " +
      "throws on every operation, so there is nothing to encode");
  }
  if (_isArray(value)) {
    _emit(out, "[", budget);
    for (var i = 0; i < value.length; i++) {
      if (i > 0) _emit(out, ",", budget);
      _canonical(value[i], out, depth + 1, budget);
    }
    _emit(out, "]", budget);
    return;
  }
  if (typeof value === "object") {
    /** @internal Canonical JSON admits an object, an array, a string, an integer, a boolean and null.
     *  A built-in exotic is none of them, and encoding it as "every own enumerable key" silently made a
     *  Date and a Map into `{}` and a Buffer into an index map of its bytes. This output is the preimage
     *  a TUF signature covers, so a field encoding to `{}` is a field the signature does not cover while
     *  it is still in the caller's object: the signed form and the document the caller believes they
     *  signed would differ with nothing reporting it. The encoder already refuses a float, a function,
     *  undefined and a BigInt, so admitting these was the same rule applied to part of its range. */
    if (!_isPlainRecordByPrototype(value)) {
      throw _err("tuf/bad-input", "canonical JSON encodes a plain object, an array, a string, an " +
        "integer, a boolean or null; " + guard.text.showValue(value) + " carries a prototype other than " +
        "Object.prototype, so it is a class instance whose state is not in its own keys, and encoding it " +
        "by those keys would sign a different document than the one it stands for");
    }
    var names = _sort(_keys(value), _byCodePoint);
    _emit(out, "{", budget);
    for (var k = 0; k < names.length; k++) {
      if (k > 0) _emit(out, ",", budget);
      _canonicalString(names[k], out, budget);
      _emit(out, ":", budget);
      _canonical(value[names[k]], out, depth + 1, budget);
    }
    _emit(out, "}", budget);
    return;
  }
  throw _err("tuf/bad-input", "canonical JSON has no encoding for " + guard.text.showValue(typeof value));
}

/**
 * @primitive  pki.tuf.canonicalJson
 * @signature  pki.tuf.canonicalJson(value) -> Buffer
 * @since      0.8.41
 * @status     stable
 * @spec       TUF
 * @related    pki.tuf.keyId, pki.tuf.verifySignatures
 *
 * The canonical JSON encoding of a value, as UTF-8 bytes. This is the preimage TUF signatures cover,
 * so it is a wire format and not a formatting choice: object keys are sorted by code point, no
 * whitespace is emitted, and inside a string only backslash and quote are escaped. A literal control
 * character is emitted as itself, which is where `JSON.stringify` differs: it would write `\n` and the
 * signature would be over other bytes.
 *
 * Only strings, exact integers, booleans, null, arrays and plain objects have an encoding. A float,
 * a number outside the exactly-representable integers, `undefined` and a function are refused with
 * `tuf/bad-input` rather than approximated, and a document nesting past `C.LIMITS.JSON_MAX_DEPTH` is
 * `tuf/too-deep`.
 *
 * @example
 *   pki.tuf.canonicalJson({ b: 2, a: 1 }).toString("utf8");   // '{"a":1,"b":2}'
 */
function canonicalJson(value) {
  var out = [];
  var budget = guard.limits.budget({ maxBytes: constants.LIMITS.JSON_MAX_BYTES });
  try {
    _canonical(value, out, 0, budget);
  } catch (e) {
    if (guard.limits.isBudgetExceeded(e)) {
      throw _err("tuf/too-large", "the canonical form of this document exceeds " +
        constants.LIMITS.JSON_MAX_BYTES + " bytes; a value that shares a subobject with itself expands " +
        "once per reference, so a document of a few dozen fields can encode to gigabytes", e);
    }
    throw e;
  }
  return _bufferFrom(_join(out, ""), "utf8");
}

/**
 * @primitive  pki.tuf.keyId
 * @signature  pki.tuf.keyId(key) -> string
 * @since      0.8.41
 * @status     stable
 * @spec       TUF
 * @related    pki.tuf.canonicalJson, pki.tuf.verifySignatures
 *
 * A key's identifier: the lowercase hex SHA-256 of the key's own canonical JSON form. The
 * specification says a client must calculate each identifier to check it is correct for its key,
 * which is what stops a document listing one key under another's identifier, so this is a
 * verification input rather than a label.
 *
 * A key object carries `keytype`, `scheme` and `keyval`; a value missing any of them is `tuf/bad-key`.
 *
 * @example
 *   pki.tuf.keyId({ keytype: "ed25519", scheme: "ed25519",
 *     keyval: { public: "00".repeat(32) } }).length;   // -> 64
 */
function keyId(key) {
  if (!key || typeof key !== "object" || _isArray(key)) {
    throw _err("tuf/bad-key", "a TUF key is an object carrying keytype, scheme and keyval");
  }
  /** @internal The key is COPIED before it is validated, and the copy is what gets hashed. Validating the
   *  caller's object and then handing that same object to `canonicalJson` is two reads of every field, and
   *  an accessor answers each separately: a key could validate as `keytype: "ed25519"` and be hashed as
   *  `keytype: 42`, so the identifier returned would name a shape that never passed validation. The
   *  identifier is the identity a role's `keyids` list matches against, which is what makes that a
   *  question of which key is authorized rather than of tidiness.
   *
   *  `snapshotDeep` refuses an accessor-backed member outright rather than reading it once, which is the
   *  stronger answer and the one `verifySignatures` already takes for the same records. */
  var copied = guard.bytes.snapshotDeep(key, TufError, "tuf/bad-key", "a TUF key");
  if (typeof copied.keytype !== "string" || typeof copied.scheme !== "string" ||
      !copied.keyval || typeof copied.keyval !== "object") {
    throw _err("tuf/bad-key", "a TUF key carries keytype, scheme and keyval; one of them is missing " +
      "or is not of its stated type");
  }
  /** @internal Through the captured digest, which is what binds a key to the identifier a role names.
   *  Reached off the live hash prototype, a replacement decided that binding: a different Ed25519 key
   *  filed under an authorized key's identifier was accepted, and metadata it signed reported
   *  `verified: true` where the check otherwise throws `tuf/bad-key`. */
  return _bufToString(guard.crypto.digest("sha256", canonicalJson(copied)), "hex");
}

/** @internal The major version this build implements, as the TEXT a conforming document carries. The
 *  comparison is made on that text rather than on a converted number, so there is no width a major
 *  version may not have: converted, a long one needed a digit cap, and the cap reported `1000000.0.0`
 *  as malformed when it is a well-formed version this build simply does not implement. A numeric
 *  identifier carries no leading zeros, so one spelling per value and a text comparison is exact. */
var SUPPORTED_SPEC_MAJOR = "1";

/** @internal Does an RFC 3339 date-time state UTC? `Z` and `+00:00` do: RFC 3339 sec. 4.3 says those two
 *  "imply that UTC is the preferred reference point for the specified time", which is the assertion the
 *  TUF specification sec. 4.2.3 makes when it says time is always in UTC. `-00:00` is reserved by that
 *  same clause for "the time in UTC is known, but the offset to local time is unknown", which it calls
 *  semantically different, so it names the right instant while declining to state UTC as the reference
 *  and is refused here. Every other offset states a different reference point. The string has already
 *  passed the RFC 3339 scanner, so this reads only the offset at its end. */
function _isUtcOffset(v) {
  var n = v.length;
  if (n === 0) return false;
  var last = _charCodeAt(v, n - 1);
  if (last === 0x5a || last === 0x7a) return true;
  if (n < 6) return false;
  if (_charCodeAt(v, n - 6) !== 0x2b) return false;
  return _charCodeAt(v, n - 5) === 0x30 && _charCodeAt(v, n - 4) === 0x30 &&
    _charCodeAt(v, n - 3) === 0x3a &&
    _charCodeAt(v, n - 2) === 0x30 && last === 0x30;
}

/** @internal A semver NUMERIC IDENTIFIER starting at `i`: the index after it, or -1. "A numeric
 *  identifier MUST NOT include leading zeroes", so "0" is one and "01" is not. */
function _numericId(v, i, n) {
  if (i >= n) return -1;
  var first = _charCodeAt(v, i);
  if (first < 0x30 || first > 0x39) return -1;
  var j = i + 1;
  while (j < n) { var c = _charCodeAt(v, j); if (c < 0x30 || c > 0x39) break; j++; }
  if (first === 0x30 && j - i > 1) return -1;
  return j;
}

/** @internal The dot-separated identifiers of a pre-release or build part: the index after the last
 *  one, or -1. Each is alphanumerics and hyphens and may not be empty. The parts differ in one rule:
 *  a pre-release identifier that is all digits "MUST NOT include leading zeroes", while a build
 *  identifier carries no such restriction, so `1.2.3+0010` is a version and `1.2.3-0010` is not. */
function _dotSeparatedIds(v, i, n, isPreRelease) {
  for (;;) {
    var start = i, allDigits = true;
    while (i < n) {
      var c = _charCodeAt(v, i);
      var digit = c >= 0x30 && c <= 0x39;
      if (!digit && !((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x2d)) break;
      if (!digit) allDigits = false;
      i++;
    }
    if (i === start) return -1;
    if (isPreRelease && allDigits && _charCodeAt(v, start) === 0x30 && i - start > 1) return -1;
    if (i < n && _charCodeAt(v, i) === 0x2e) { i++; continue; }
    return i;
  }
}

/** @internal The MAJOR component of a semantic version, or null where the string is not one. The WHOLE
 *  string is held to the grammar, because the specification sec. 4.3 states the field's format: "A
 *  string that contains the version number of the TUF specification. Its format follows the Semantic
 *  Versioning 2.0.0 (semver) specification". Reading the leading digits alone accepted a field that is
 *  not a version at all: "1.", "1.0", "1.foo", "1.0.0oops", "1.0.0.0" and a trailing space all passed
 *  as supported 1.x metadata. Scanned by character rather than split or matched, `lib/` taking no
 *  regular expressions.
 *
 *  Shape: three numeric identifiers separated by dots, then an optional "-" pre-release and an
 *  optional "+" build, and nothing after either. */
function _specMajor(v) {
  var n = v.length;
  var end = _numericId(v, 0, n);
  if (end < 0) return null;
  var major = _strSlice(v, 0, end);
  var i = end;
  for (var part = 0; part < 2; part++) {
    if (i >= n || _charCodeAt(v, i) !== 0x2e) return null;
    i = _numericId(v, i + 1, n);
    if (i < 0) return null;
  }
  if (i === n) return major;
  if (_charCodeAt(v, i) === 0x2d) {
    i = _dotSeparatedIds(v, i + 1, n, true);
    if (i < 0) return null;
    if (i === n) return major;
  }
  if (_charCodeAt(v, i) !== 0x2b) return null;
  i = _dotSeparatedIds(v, i + 1, n, false);
  return i === n ? major : null;
}

/** @internal The specification version decides whether this build's rules apply to the document at all:
 *  "Metadata is written according to version "spec_version" of the specification, and clients MUST verify
 *  that "spec_version" matches the expected version number", with adopters free to decide what counts as
 *  a match. This build implements 1.x, so the MAJOR version is the match and the minor and patch are not:
 *  a 1.x document a later minor version produced is read under rules that are a subset of its own, which
 *  is what semantic versioning promises, while a 2.x document is written to rules this build does not
 *  have. A document with no `spec_version` at all states no version to match, and TAP 6 makes the field
 *  mandatory, so it is refused rather than assumed to be this one.
 *
 *  The clause binds metadata rather than root metadata, so it holds for every role, and it is enforced
 *  at this one door every document comes through. The verbs a client drives next answer under 1.x rules:
 *  a key identifier is a hash of the canonical form this version defines, and an expiry is read in the
 *  format this version states. A verdict from either about a document written to another major version
 *  is an answer about rules the document does not claim. The validated string is returned so the check
 *  and the reported value are one read.
 *
 *  It runs as soon as the signed body is reachable, ahead of the field rules below it, because `_type`,
 *  `version` and `expires` are themselves rules of this version: reading them first decides a document
 *  under rules it may not be written to. What precedes it is the JSON read and the wrapper shape, since
 *  the document has to tokenize and the body has to exist before the field inside it can be read. A
 *  document carrying a fractional number is therefore `tuf/bad-json` whatever version it declares, the
 *  canonical form admitting no floating point at any version this build reads. */
function _assertSupportedMajor(spec, where, malformedCode) {
  if (typeof spec !== "string") {
    throw _err(malformedCode, where + " names no spec_version, which a client must match against the " +
      "version it implements (TUF specification sec. 4.3, TAP 6)");
  }
  /** @internal A value that is not a semantic version is MALFORMED rather than a version this build
   *  does not implement, and the two are different answers: the first says the field is not a version,
   *  the second that the version is one this build cannot read. Only a well-formed version reaches the
   *  comparison. */
  var major = _specMajor(spec);
  if (major === null) {
    throw _err(malformedCode, where + " states spec_version " + guard.text.showValue(spec) +
      ", which is not a Semantic Versioning 2.0.0 value, the format the TUF specification sec. 4.3 " +
      "states for the field");
  }
  if (major !== SUPPORTED_SPEC_MAJOR) {
    throw _err("tuf/unsupported-spec-version", where + " declares spec_version " +
      guard.text.showValue(spec) + ", and this build implements " + SUPPORTED_SPEC_MAJOR +
      ".x: a document written to another major version states rules this build does not have");
  }
  return spec;
}

/** @internal The fields the two object-taking verbs read off a metadata object. None may be an
 *  accessor: see the refusal in `verifySignatures` for what reading one lets a caller steer. */
var _METADATA_FIELDS = ["signed", "signedBytes", "specVersion", "expires", "type", "version",
  "signatures"];
/** @internal The fields a signature record carries, held to the same rule for the same reason. */
var _SIGNATURE_FIELDS = ["keyid", "sig"];

/** @internal The convenience copies a parsed object carries beside the signed body, as
 *  [outer field, the body member it copies]. Each is checked against the body rather than trusted,
 *  because the body is what the signature covers and a copy that disagrees describes a document the
 *  caller does not hold. Checking ONE of them was the defect: `specVersion` was cross-checked while
 *  `type` and `version` were not, and a caller reads `version` for a rollback comparison and `type` to
 *  choose which role a document belongs to, so both decide something. Absent is accepted, an object
 *  assembled by hand being free to carry only what it uses; present and contradicting is refused. */
var _BODY_COPIES = [["type", "_type"], ["specVersion", "spec_version"], ["version", "version"],
  ["expires", "expires"]];

function _assertCopiesAgree(metadata, body, label) {
  for (var ci = 0; ci < _BODY_COPIES.length; ci++) {
    var outer = _BODY_COPIES[ci][0], inner = _BODY_COPIES[ci][1];
    var stated = metadata[outer];
    if (stated === undefined || stated === null) continue;
    if (stated !== body[inner]) {
      throw _err("tuf/bad-input", label + " states " + outer + " " + guard.text.showValue(stated) +
        " while the signed body it carries states " + guard.text.showValue(body[inner]));
    }
  }
}

/** @internal The roles a root states a record for. `mirrors` is deliberately absent: the
 *  specification sec. 4.3 calls it OPTIONAL where it calls these four mandatory. */
var TOP_LEVEL_ROLES = ["root", "targets", "snapshot", "timestamp"];
/** @internal The same four as text for the refusal, joined through the capture at load so the list has
 *  one source. */
var TOP_LEVEL_ROLES_TEXT = intrinsic.join(TOP_LEVEL_ROLES, ", ");

/** @internal The parse's own use of the rule, over the raw field, read once. */
function _assertSpecVersion(signed) {
  return _assertSupportedMajor(signed.spec_version, "the signed body", "tuf/bad-metadata");
}

/** @internal The rule carried to the two verbs that take a metadata OBJECT rather than bytes. Both are
 *  documented as taking what `parseMetadata` returns, and both are reachable with one a caller
 *  assembled, which is why `checkExpiry` already re-enforces the `expires` format rather than trusting
 *  it. The version match is the same situation: without it, each answered about a document declaring a
 *  version this build does not implement, `verifySignatures` reporting `verified` and `checkExpiry`
 *  returning true. Absence is the caller's object being incomplete rather than a document being
 *  malformed, so it is `tuf/bad-input` here and `tuf/bad-metadata` at the parse; an unsupported version
 *  is the same code on every route. */
function _assertMetadataSpecVersion(spec) {
  return _assertSupportedMajor(spec, "opts.metadata", "tuf/bad-input");
}


/**
 * @primitive  pki.tuf.parseMetadata
 * @signature  pki.tuf.parseMetadata(input) -> { type, specVersion, version, expires, signed, signatures, signedBytes }
 * @since      0.8.41
 * @status     stable
 * @spec       TUF
 * @related    pki.tuf.verifySignatures, pki.tuf.checkExpiry
 *
 * Read a TUF metadata document: the `signatures` wrapper and the `signed` body, with `signedBytes`
 * the canonical form the signatures cover. A duplicate JSON member is refused before any field is
 * read, because the canonical form would carry only one of them and the signature would then cover a
 * document different from the one delivered.
 *
 * `_type`, a `spec_version`, a `version` that is a positive integer, and an `expires` that parses as a
 * date-time are required; a document missing any is `tuf/bad-metadata`.
 *
 * `spec_version` must name a specification version this build implements, which is 1.x, and the major
 * component is the match: a later 1.x minor is read, another major version is `tuf/unsupported-spec-
 * version`. The rule is here rather than in each verb because a key identifier and an expiry are both
 * read under the rules of this version.
 *
 * @example
 *   var m = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [],
 *     signed: { _type: "root", spec_version: "1.0.31", version: 1, expires: "2030-01-01T00:00:00Z" } })));
 *   m.type;   // -> "root"
 */
function parseMetadata(input) {
  var bytes = guard.bytes.source(input, TufError, "tuf/bad-input", "the TUF metadata");
  var doc = guard.json.parse(bytes, _err, {
    maxBytes: constants.LIMITS.JSON_MAX_BYTES, maxDepth: constants.LIMITS.JSON_MAX_DEPTH,
    badJson: "tuf/bad-json", tooDeep: "tuf/too-deep", duplicateMember: "tuf/duplicate-member",
    tooLarge: "tuf/too-large", badInput: "tuf/bad-input", label: "the TUF metadata",
    /** @internal TUF's canonical JSON admits no floating point, and every number the format carries is a
     *  version, a threshold or a length. A fractional token is refused while it is still text: converted
     *  first, 1.0000000000000001 becomes 1 and the integer checks below see a conforming document. */
    integersOnly: true,
  });
  if (!doc || typeof doc !== "object" || _isArray(doc)) {
    throw _err("tuf/bad-metadata", "TUF metadata is a JSON object carrying signatures and signed");
  }
  if (!_isArray(doc.signatures)) {
    throw _err("tuf/bad-metadata", "TUF metadata carries a signatures array");
  }
  var signed = doc.signed;
  if (!signed || typeof signed !== "object" || _isArray(signed)) {
    throw _err("tuf/bad-metadata", "TUF metadata carries a signed object");
  }
  var specVersion = _assertSpecVersion(signed);
  if (typeof signed._type !== "string" || signed._type.length === 0) {
    throw _err("tuf/bad-metadata", "the signed body names no _type");
  }
  if (typeof signed.version !== "number" || !_isSafeInteger(signed.version) || signed.version < 1) {
    throw _err("tuf/bad-metadata", "the signed body's version is not a positive integer");
  }
  /** @internal The OFFSET has to denote UTC, which the shared scanner does not decide: RFC 3339 admits
   *  every numeric offset, so `2030-01-01T01:00:00+01:00` passes it. Section 4.2.3 says "Time is always
   *  in UTC", and such a value names a real instant while not being the form the specification requires,
   *  so a conforming client refuses the document and adopting it here would trust metadata that client
   *  would not. `Z` and a zero numeric offset denote the same instant and both pass. */
  /** @internal The FORMAT decides, not `Date.parse`. The specification sec. 4.2.3 states it exactly:
   *  "Metadata date-time follows the ISO 8601 standard. The expected format of the combined date and time
   *  string is "YYYY-MM-DDTHH:MM:SSZ". Time is always in UTC". `Date.parse` is far looser. It ROLLS an
   *  impossible date forward rather than refusing it, so an expires of 2026-02-30 read as March 2 and the
   *  metadata was usable for two days it does not state; and it accepts a date with no time and a time
   *  with no zone, where the instant then depends on the reader's own timezone rather than on the
   *  document. The shared RFC 3339 scanner answers the format, calendar validity and leap years included.
   *  A zero numeric offset is accepted along with `Z`, both denoting the same instant: the clause states
   *  the expected form rather than forbidding an equivalent one. */
  if (typeof signed.expires !== "string" || !rfc3339.isValid(signed.expires) || !_isUtcOffset(signed.expires)) {
    throw _err("tuf/bad-metadata", "the signed body's expires is not an RFC 3339 date-time in the " +
      "form the TUF specification sec. 4.2.3 states, \"YYYY-MM-DDTHH:MM:SSZ\"");
  }
  var sigs = [];
  for (var i = 0; i < doc.signatures.length; i++) {
    var s = doc.signatures[i];
    if (!s || typeof s !== "object" || typeof s.keyid !== "string" || typeof s.sig !== "string") {
      throw _err("tuf/bad-metadata", "signatures[" + i + "] carries a keyid and a sig, both strings");
    }
    _push(sigs, { keyid: s.keyid, sig: s.sig });
  }
  return guard.verdict.of({
    type: signed._type,
    specVersion: specVersion,
    version: signed.version,
    expires: signed.expires,
    signed: signed,
    signatures: sigs,
    signedBytes: canonicalJson(signed),
  });
}

function _isFiniteTime(ms) { return typeof ms === "number" && intrinsic.numberIsFinite(ms); }

/**
 * @primitive  pki.tuf.checkExpiry
 * @signature  pki.tuf.checkExpiry(metadata, now) -> true
 * @since      0.8.41
 * @status     stable
 * @spec       TUF
 * @related    pki.tuf.parseMetadata, pki.tuf.updateRoot
 *
 * Assert that metadata has not expired at `now`, which is the freeze-attack check: a repository that
 * stops publishing leaves a client holding metadata that stays valid forever unless its expiry is
 * read. Returns `true`, or throws `tuf/expired` naming both instants. The instant is a caller value,
 * never the system clock read inside the check, so a verdict is reproducible.
 *
 * The expiry read is `metadata.signed.expires`, the field the signature covers, and not the `expires`
 * beside it: the signature check and this one have to be about one document, and an object carrying a
 * lapsed expiry in the body and a future one in the copy otherwise verified and passed here at the
 * same instant. Every copy the object states beside the body must agree with it, `type`, `version`,
 * `expires` and `specVersion` alike, and so must a `signedBytes` it carries; any of them contradicting
 * the body is `tuf/bad-input`. An object carrying no `signedBytes` is still read, a caller being free
 * to ask only about an expiry.
 *
 * The body's `spec_version` must name a specification version this build implements, the expiry format
 * being one this version states. A document `parseMetadata` returned always carries it; an object
 * assembled by hand without it is `tuf/bad-input`, and one naming another major version is
 * `tuf/unsupported-spec-version`.
 *
 * @example
 *   var meta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [],
 *     signed: { _type: "root", spec_version: "1.0.31", version: 1, expires: "2030-01-01T00:00:00Z" } })));
 *   pki.tuf.checkExpiry(meta, new Date("2027-01-01T00:00:00Z"));   // -> true
 */
function checkExpiry(metadata, now) {
  if (!metadata || typeof metadata !== "object") {
    throw _err("tuf/bad-input", "checkExpiry takes a parsed metadata object from pki.tuf.parseMetadata");
  }
  /** @internal ONE read of the signed BODY, and the expiry is taken from it rather than from the
   *  `expires` beside it. The signature covers the body, so those are two values: an object carrying a
   *  lapsed expiry in the body and a future one in the copy had `verifySignatures` answer about the
   *  signed document while this answered about the copy, and metadata correctly signed with an expiry
   *  in 2020 then both verified and passed this check at a 2026 instant. Expiry is the freeze-attack
   *  check, so the two verbs have to be about one document. A copy the caller also states must agree
   *  with the body, and `snapshotDeep` refuses an accessor-backed member outright, so no field can
   *  answer the comparison differently from the check. The fields of the object itself are held to the
   *  same rule, for the reason the refusal in `verifySignatures` gives, and so is the object itself
   *  being a plain record rather than a Proxy. */
  guard.identifier.assertPlainRecord(metadata, _err, "tuf/bad-input", "opts.metadata");
  guard.identifier.refuseAccessorFields(metadata, _METADATA_FIELDS, _err, "tuf/bad-input",
    "opts.metadata");
  var body = guard.bytes.snapshotDeep(metadata.signed, TufError, "tuf/bad-input", "metadata.signed");
  if (!body || typeof body !== "object" || _isArray(body)) {
    throw _err("tuf/bad-input", "checkExpiry takes a parsed metadata object from pki.tuf.parseMetadata");
  }
  var expires = body.expires;
  var type = body._type;
  _assertMetadataSpecVersion(body.spec_version);
  if (typeof expires !== "string") {
    throw _err("tuf/bad-input", "checkExpiry takes a parsed metadata object from pki.tuf.parseMetadata");
  }
  _assertCopiesAgree(metadata, body, "the metadata object");
  /** @internal `signedBytes` is a copy of the body too, in bytes rather than in a field, and the two
   *  verbs have to agree about which objects they answer for at all: this read the body while the bytes
   *  beside it encoded another document, and returned true for it. This verb does not USE those bytes,
   *  which is why it went unnoticed, and that is the point, since an object the signature check refuses
   *  should not be one the expiry check answers about. Absent bytes stay acceptable, a caller being
   *  free to ask only about an expiry. */
  var statedBytes = metadata.signedBytes;
  if (statedBytes !== undefined && statedBytes !== null) {
    /** @internal Bounded before the copy, as `verifySignatures` bounds the same field: these bytes must
     *  equal the canonical form of a body that came from a document no larger than the cap, so anything
     *  above it cannot match and copying it first paid an allocation the size of whatever arrived to
     *  reach that conclusion. */
    var statedView = guard.bytes.isByteSource(statedBytes)
      ? guard.bytes.source(statedBytes, _err, "tuf/bad-input", "metadata.signedBytes") : null;
    if (statedView !== null) {
      guard.limits.byteCap(statedView, constants.LIMITS.JSON_MAX_BYTES, _err, "tuf/too-large",
        "metadata.signedBytes");
    }
    if (statedView === null ||
        !guard.crypto.constantTimeEqual(canonicalJson(body),
          guard.bytes.snapshot(statedView, _err, "tuf/bad-input", "metadata.signedBytes"))) {
      throw _err("tuf/bad-input", "metadata.signedBytes is not the canonical form of metadata.signed, " +
        "so the expiry asked about is not the document the object carries");
    }
  }
  if (!guard.time.isDate(now)) throw _err("tuf/bad-input", "now must be a Date");
  var atMs = guard.time.instantOf(now);
  /** @internal The same format rule as the parse, the UTC offset included, because this verb is reachable
   *  with a metadata object a caller assembled rather than one `parseMetadata` produced: the looser
   *  reading is what rolled an impossible date forward into extra days of trust, and a rule enforced at
   *  one of two doors is a document this verb accepts and that one refuses. */
  if (!rfc3339.isValid(expires) || !_isUtcOffset(expires)) {
    throw _err("tuf/bad-metadata", "the metadata's expires is not an RFC 3339 date-time in the form the " +
      "TUF specification sec. 4.2.3 states, \"YYYY-MM-DDTHH:MM:SSZ\"");
  }
  var expiresMs = _dateParse(expires);
  if (!_isFiniteTime(expiresMs)) throw _err("tuf/bad-metadata", "the metadata's expires is not a date-time");
  if (!(atMs < expiresMs)) {
    throw _err("tuf/expired", "the " + type + " metadata expired at " + expires +
      ", which is at or before the instant it was checked at");
  }
  return true;
}

/** @internal The SPKI an ed25519 TUF key encodes, with the raw length and the point validated. Shared
 *  by the verify and by adoption, so a root naming a key that is the wrong length or not a full-order
 *  point is refused in both places rather than in whichever one happens to read it. */
function _ed25519Spki(key) {
  var raw = guard.encoding.hex(key.keyval.public, 64, _err, "tuf/bad-key", "an ed25519 public key");
  if (raw.length !== 32) {
    throw _err("tuf/bad-key", "an ed25519 public key is 32 bytes, got " + raw.length);
  }
  var spki = _bufferConcat([ED25519_SPKI_PREFIX, raw]);
  edwardsPoint.validateSpki(spki, ED25519_CRV, TufError, "tuf/bad-key");
  return spki;
}

/** @internal Everything that must hold for a key to verify anything, with no signature involved: the
 *  keytype and scheme are ones this build reads, the material imports, the declared type matches what
 *  imported, the curve and modulus match the scheme, and an ed25519 point is on the curve. An
 *  identifier is a hash of the key's canonical form and says nothing about any of that, so a role
 *  could name a key filed under its own identifier that verifies nothing. Only the ROOT role is
 *  verified during a rotation, so such a key in any other role was adopted and the client found out at
 *  first use. The same checks the verify makes before it looks at a signature, made at adoption.
 *  THE ONE IMPORT, AND THE ONE PLACE A SIGNATURE UNDER IT IS CHECKED. The identity a threshold counts
 *  and the key a signature is checked under come from this single import, so they cannot be two
 *  different keys and `keyval.public` is read once. Derived and verified separately, a key was imported
 *  twice per identifier, which doubled the asymmetric work a document can ask for before anything had
 *  authenticated it. `check` closes over the imported key and over the algorithm the declaration
 *  resolved, so no caller re-reads the record's own `keytype` to decide how to verify, and the
 *  low-order point gate on the ed25519 arm sits in the same function as the verify it protects rather
 *  than one call away from it. */
function _usableKey(key) {
  var d = _declarationOf(key);
  var imported = _checkedPublicKey(key, d);
  if (d.nodeType === "ed25519") {
    imported = guard.crypto.publicKey({ key: _ed25519Spki(key), format: "der", type: "spki" });
    return { d: d, key: imported, check: function (sig, preimage) {
      return guard.crypto.verify(null, preimage, imported, sig);
    } };
  }
  if (d.nodeType === "ec") {
    return { d: d, key: imported, check: function (sig, preimage) {
      return guard.crypto.verify("sha256", preimage, { key: imported, dsaEncoding: "der" }, sig);
    } };
  }
  /** @internal The rsa arm. The scheme the specification pairs with an rsa key is RSASSA-PSS over
   *  SHA-256, so that is the padding a signature is checked under; reading the padding from the document
   *  would let it name the one its forgery happens to satisfy. Every other keytype was refused by
   *  `_declarationOf`, whose table is the one list of what this build reads.
   *  THE SALT LENGTH IS READ FROM THE SIGNATURE, not pinned, and that is the one part of this the
   *  scheme name does not fix. `rsassa-pss-sha256` states the hash and the padding and says nothing
   *  about the salt, which is the signer's to choose, and the reference implementation signs with the
   *  longest salt the modulus allows. Pinning the digest length rejected those, so metadata that
   *  verifies everywhere else failed here and the root rotation it carried stopped. The salt is public
   *  and carried in the encoding, so recovering it concedes nothing: what a verifier must not take from
   *  the document is the hash or the padding, and both are still fixed here. Elsewhere in the toolkit
   *  the salt length IS pinned, because every other format declares it and the declaration is
   *  authenticated: `cms-verify` reads it from the RSASSA-PSS AlgorithmIdentifier, `path-validate` from
   *  the certificate, `jose` from the RFC 7518 row. TUF declares none, so there is nothing to read. */
  return { d: d, key: imported, check: function (sig, preimage) {
    return guard.crypto.verify("sha256", preimage, {
      key: imported, padding: guard.crypto.padding.RSA_PKCS1_PSS,
      saltLength: guard.crypto.saltLength.AUTO,
    }, sig);
  } };
}

/** @internal The keytype and scheme a key declares, and what the key material must then be. A key's
 *  identifier is the hash of the whole key object, so `keytype` and `scheme` are as authenticated as the
 *  material itself, and verification has to run under the algorithm they name rather than under whatever
 *  the material happens to support. Importing a PEM and verifying does the latter: an RSA public key
 *  filed under `keytype: "ecdsa"` imports fine and then satisfies an RSA PKCS#1 v1.5 signature, so a
 *  forger picks the algorithm by choosing the key they publish. The pairs are the ones the specification
 *  lists in section 4.2.2; `ecdsa-sha2-nistp256` is also accepted as a keytype, which is the spelling
 *  some published roots use for the same key.
 *
 *  `nodeType` is what the imported key must report, and `curve` what an EC key's parameters must be: the
 *  scheme names its curve, so a P-384 key under `ecdsa-sha2-nistp256` is a key that does not match its
 *  own declaration. `minBits` carries the section 4.2.2 floor, "All RSA keys MUST be at least 2048 bits".
 */
var KEY_DECLARATIONS = intrinsic.assign(intrinsic.create(null), {
  "ed25519": { schemes: ["ed25519"], nodeType: "ed25519", curve: null, minBits: 0 },
  "ecdsa": { schemes: ["ecdsa-sha2-nistp256"], nodeType: "ec", curve: "prime256v1", minBits: 0 },
  "ecdsa-sha2-nistp256": { schemes: ["ecdsa-sha2-nistp256"], nodeType: "ec", curve: "prime256v1", minBits: 0 },
  "rsa": { schemes: ["rsassa-pss-sha256"], nodeType: "rsa", curve: null, minBits: 2048 },
});

function _declarationOf(key) {
  var d = KEY_DECLARATIONS[guard.text.keyOf(key.keytype)];
  if (d === undefined) {
    throw _err("tuf/unsupported-key", "this build reads ed25519, ecdsa and rsa keys; the metadata names " +
      guard.text.showValue(key.keytype));
  }
  var scheme = guard.text.keyOf(key.scheme);
  var ok = false;
  for (var i = 0; i < d.schemes.length; i++) if (d.schemes[i] === scheme) ok = true;
  if (!ok) {
    throw _err("tuf/bad-key", "a " + key.keytype + " key pairs with the scheme " +
      _join(d.schemes, " or ") + " (TUF sec. 4.2.2); this one declares " + guard.text.showValue(key.scheme));
  }
  return d;
}

/** @internal The resolved declaration, checked against the key material before anything verifies under
 *  it, and the imported key RETURNED so the caller verifies with the very object that was checked.
 *  Importing it again at the call site would read `keyval.public` a second time, and a caller-supplied
 *  accessor can answer differently on the second read, which would leave the checked key and the
 *  verifying key two
 *  different keys. An ed25519 key carries raw bytes rather than a PEM and its own arm holds the length
 *  and the point, so there is nothing to import for it. */
function _checkedPublicKey(key, d) {
  if (d.nodeType === "ed25519") return null;
  var imported = _publicFromPem(key.keyval.public, "a " + key.keytype + " public key");
  if (imported.asymmetricKeyType !== d.nodeType) {
    throw _err("tuf/bad-key", "the key declared as " + key.keytype + " holds a " +
      guard.text.showValue(imported.asymmetricKeyType) + " public key, so the signature would be checked " +
      "under an algorithm the metadata does not name");
  }
  var details = imported.asymmetricKeyDetails || {};
  if (d.curve !== null && details.namedCurve !== d.curve) {
    throw _err("tuf/bad-key", "the scheme " + key.scheme + " names the " + d.curve +
      " curve; the key is on " + guard.text.showValue(details.namedCurve));
  }
  if (d.minBits > 0 && !(details.modulusLength >= d.minBits)) {
    throw _err("tuf/bad-key", "an " + key.keytype + " key must be at least " + d.minBits +
      " bits (TUF sec. 4.2.2); this one is " + guard.text.showValue(details.modulusLength));
  }
  return imported;
}

var ED25519_SPKI_PREFIX = _bufferFrom([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
var ED25519_CRV = 6;
var edwardsPoint = require("./edwards-point");

function _publicFromPem(pem, label) {
  if (typeof pem !== "string" || pem.length === 0) {
    throw _err("tuf/bad-key", label + " is stated as a non-empty PEM string");
  }
  try { return guard.crypto.publicKey({ key: pem, format: "pem" }); }
  catch (e) { throw _err("tuf/bad-key", label + " did not parse", e); }
}

/**
 * @primitive  pki.tuf.verifySignatures
 * @signature  pki.tuf.verifySignatures(opts) -> Promise<{ verified, keyIds, threshold }>
 * @since      0.8.41
 * @status     stable
 * @spec       TUF
 * @defends    signature-bypass (CWE-347)
 * @related    pki.tuf.parseMetadata, pki.tuf.updateRoot
 *
 * Verify a role's threshold over parsed metadata. Resolves `verified` and the distinct `keyIds` that
 * counted: whether a threshold was met is a verdict about the metadata, so a shortfall resolves
 * `false` rather than throwing. A KEY the build cannot read throws, the role naming a signer it cannot
 * identify; a SIGNATURE it cannot read counts for nothing, that being one signer short rather than a
 * malformed document.
 *
 * Three rules the specification states, each applied here:
 *
 * - A signature counts only if its `keyid` is one the role names. One from any other key contributes
 *   nothing, whatever it verifies over.
 * - One verified signature per DISTINCT key identifier. A key listed twice, or signing twice, counts
 *   once, so a threshold cannot be met by repetition. Where an identifier carries more than one
 *   signature the FIRST is the one asked: a second cannot raise a count already capped at one, and
 *   asking it would let a document choose how many times the signed body is hashed.
 * - Every key's identifier is recomputed from the key itself and must equal the identifier it is
 *   listed under. A key filed under another's identifier is `tuf/bad-key`, not a key that fails to
 *   verify: the document is malformed rather than unsigned.
 *
 * The document verified is derived from one read of `metadata.signed`, and `metadata.signedBytes` must
 * equal that canonical form, so the bytes the signatures are checked over are the ones the object
 * states. A `signedBytes` holding anything else is `tuf/bad-input`, which is what a parsed object whose
 * Buffer was overwritten after the parse reports.
 *
 * That body's `spec_version` must name a specification version this build implements, a key identifier
 * being a hash of the canonical form this version defines. Another major version is
 * `tuf/unsupported-spec-version`. No `spec_version` at all, or a `metadata.specVersion` that contradicts
 * the body's, is `tuf/bad-input`.
 *
 * @opts
 *   metadata:  object,  // from pki.tuf.parseMetadata
 *   keys:      object,  // the KEYID -> key map the root states
 *   role:      object,  // { keyids, threshold } for the role being checked
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var raw = pki.asn1.decode(await pki.key.export(pair.publicKey)).children[1].content.subarray(1);
 *   var key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: raw.toString("hex") } };
 *   var id = pki.tuf.keyId(key), keys = {}; keys[id] = key;
 *   var signed = { _type: "root", spec_version: "1.0.31", version: 1, expires: "2030-01-01T00:00:00Z",
 *     keys: keys, roles: { root: { keyids: [id], threshold: 1 },
 *       targets: { keyids: [id], threshold: 1 }, snapshot: { keyids: [id], threshold: 1 },
 *       timestamp: { keyids: [id], threshold: 1 } } };
 *   var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey,
 *     pki.tuf.canonicalJson(signed)));
 *   var rootBytes = Buffer.from(JSON.stringify({
 *     signatures: [{ keyid: id, sig: sig.toString("hex") }], signed: signed }));
 *   var v = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(rootBytes),
 *     keys: signed.keys, role: signed.roles.root });
 *   v.verified;   // -> true
 */
var _VERIFY_KEYS = intrinsic.assign(_create(null), { metadata: 1, keys: 1, role: 1 });
async function verifySignatures(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _VERIFY_KEYS, _err, "tuf/bad-input", "unknown verifySignatures option ");
  /** @internal Every caller-owned input is taken ONCE, at the top, and everything below reads the copy.
   *  Validating the caller's object and then reading it again is two reads, and a member reached through an
   *  accessor can answer the two differently, so the value that was checked need not be the value that is
   *  used. The verification also awaits once per signature, which is the window in which a caller can
   *  change what it still holds. So the shape checks below run against the COPIES. */
  var metadata = opts.metadata;
  if (!metadata || typeof metadata !== "object") {
    throw _err("tuf/bad-input", "opts.metadata is a parsed document from pki.tuf.parseMetadata");
  }
  /** @internal No field of the metadata object may be an accessor. Reading one is caller code running
   *  mid-verb, and with several fields read in sequence that was a lever rather than a nuisance: a
   *  getter on `signedBytes` set a supported version on the body for the duration of the copy while a
   *  getter on `specVersion` put the unsupported one back, and the verb reported `verified` about a
   *  document the object declared neither before nor after. Ordering the reads moved the lever to
   *  whichever field is read first, and the field read first is the subject, so there is no order that
   *  closes it. Refusing accessors does, and it costs a conforming caller nothing: a document
   *  `parseMetadata` returned carries plain values. This is the door an options bag already goes
   *  through, applied to the record. */
  /** @internal A Proxy answers from a trap rather than from a descriptor, so a field check cannot see
   *  it: one supplying a supported body on the read and carrying an unsupported one otherwise had both
   *  verbs answer positively about a document the object never held. `assertPlainRecord` is the
   *  toolkit's own refusal for a caller record, and it covers an inherited Proxy and a built-in exotic
   *  along with it. */
  guard.identifier.assertPlainRecord(metadata, _err, "tuf/bad-input", "opts.metadata");
  guard.identifier.refuseAccessorFields(metadata, _METADATA_FIELDS, _err, "tuf/bad-input",
    "opts.metadata");
  /** @internal The BODY is copied first regardless, being the authority every check below reads. */
  var body = guard.bytes.snapshotDeep(metadata.signed, TufError, "tuf/bad-input", "metadata.signed");
  if (!body || typeof body !== "object" || _isArray(body)) {
    throw _err("tuf/bad-input", "opts.metadata is a parsed document from pki.tuf.parseMetadata");
  }
  var rawSignedBytes = metadata.signedBytes;
  if (!guard.bytes.isByteSource(rawSignedBytes)) {
    throw _err("tuf/bad-input", "opts.metadata is a parsed document from pki.tuf.parseMetadata");
  }
  /** @internal Normalized to a byte view before it is copied. The test above admits what
   *  `guard.bytes.isByteSource` admits, which includes a DataView and an ArrayBuffer, and
   *  `guard.bytes.snapshot` takes neither, so canonical bytes held as the ArrayBuffer a fetch returns
   *  were refused for their container by the same verb that had just called them acceptable.
   *  `snapshotSource` views and copies in one call; the view shares the caller's store, so the snapshot
   *  is still the only copy, which is what the read-once reasoning below depends on.
   *  Bounded at the document cap before that copy. These bytes must equal the canonical form of a body
   *  that itself came from a document no larger than the cap, so anything above it cannot match and is
   *  refused rather than copied: measured, a 32 MiB value allocated 32 MiB before the comparison
   *  rejected it. */
  var signedView = guard.bytes.source(rawSignedBytes, _err, "tuf/bad-input", "metadata.signedBytes");
  guard.limits.byteCap(signedView, constants.LIMITS.JSON_MAX_BYTES, _err, "tuf/too-large",
    "metadata.signedBytes");
  var signedBytes = guard.bytes.snapshot(signedView, _err, "tuf/bad-input", "metadata.signedBytes");
  /** @internal ONE read of the signed body, which both the version match and the bytes are taken from.
   *  `specVersion` beside the bytes is a SECOND value, filled at parse time, so it names the document
   *  that was parsed while `signedBytes` names the document that gets verified, and a parsed object is
   *  the caller's once it is returned: its Buffer can be overwritten. Measured, a 1.x document whose
   *  bytes were replaced with a validly signed 2.x one reported `verified` while the field still read
   *  1.0.31. Reading the version back out of the bytes is not available, canonical JSON escaping only
   *  backslash and quote so that a key held as a PEM puts raw newlines inside a string and the signed
   *  form of any real root is not a document a strict JSON reader accepts. So the body is the source:
   *  the canonical form derived from it must equal the bytes the caller carries, and the version is read
   *  from the same copy. A stated `specVersion` that contradicts it is a caller describing a document it
   *  does not hold. This is the `version` swap A16 pins, answered for `spec_version` the same way.
   *
   *  Read after both copies are taken, never before: an accessor on this field runs while the bytes and
   *  the body would still be the caller's, and the field is only a cross-check. */
  _assertMetadataSpecVersion(body.spec_version);
  if (!guard.crypto.constantTimeEqual(canonicalJson(body), signedBytes)) {
    throw _err("tuf/bad-input", "metadata.signedBytes is not the canonical form of metadata.signed, so " +
      "the document the signatures would be checked over is not the one the object states");
  }
  _assertCopiesAgree(metadata, body, "opts.metadata");
  var keys = opts.keys;
  if (!keys || typeof keys !== "object" || _isArray(keys)) {
    throw _err("tuf/bad-input", "opts.keys is the KEYID to key map the root states");
  }
  /** @internal ONE read of the role, which carries the authorization: which key ids may sign, and how
   *  many must. It was read four times, for the presence check, the typeof, and then each field, and an
   *  accessor answers every read separately: a getter could present a strict role to the checks and a lax
   *  one to the field reads, combining one role's authorized keys with another's threshold. The verdict
   *  then reported a document as meeting a threshold no role had stated. */
  var suppliedRole = opts.role;
  if (!suppliedRole || typeof suppliedRole !== "object") {
    throw _err("tuf/bad-input", "opts.role carries a keyids array and a threshold that is a positive integer");
  }
  var role = { keyids: suppliedRole.keyids, threshold: suppliedRole.threshold };
  if (!_isArray(role.keyids) || typeof role.threshold !== "number" ||
      !_isSafeInteger(role.threshold) || role.threshold < 1) {
    throw _err("tuf/bad-input", "opts.role carries a keyids array and a threshold that is a positive integer");
  }
  role.keyids = guard.bytes.snapshotDeep(role.keyids, TufError, "tuf/bad-input", "opts.role.keyids");
  /** @internal The keys MAP is a caller record whose members are read inside a loop that awaits, so it
   *  gets the door the other caller records here already have rather than a defensive second read. Held
   *  to being a plain object, which refuses a Proxy, and to carrying plain values at every identifier
   *  the role names, which refuses an accessor: either would otherwise answer each read separately, and
   *  the identifier filed under a key is checked against the copy the first read produced. An
   *  identifier the role repeats is resolved once now, so a getter answering correctly first and
   *  incorrectly afterwards had its later answer go unread, which is a check on a value nothing used.
   *  Closing the door removes the question instead of restoring the read. */
  guard.identifier.assertPlainRecord(keys, _err, "tuf/bad-input", "opts.keys");
  guard.identifier.refuseAccessorFields(keys, role.keyids, _err, "tuf/bad-input", "opts.keys");
  /** @internal The role's identifiers are resolved to keys FIRST, and each key's identifier is
   *  recomputed, so the whole key set a role names is held to being correctly filed before any
   *  signature is checked. A document that mislabels a key is refused whether or not its signatures
   *  would have verified. */
  var authorized = _create(null);
  for (var i = 0; i < role.keyids.length; i++) {
    var id = role.keyids[i];
    if (typeof id !== "string" || id.length !== KEY_ID_HEX_LEN) {
      throw _err("tuf/bad-metadata", "role.keyids[" + i + "] is not a 64-character key identifier");
    }
    if (!_hasOwn(keys, id)) {
      throw _err("tuf/bad-metadata", "the role names key " + id + ", which the key map does not carry");
    }
    /** @internal An identifier the role repeats resolves to the same key, and the resolution below
     *  deep-copies that key and hashes its canonical form. Done per OCCURRENCE, a role could ask for
     *  that work as many times as the size cap admits identifiers: measured, 7500 repetitions of one
     *  identifier beside a 500 KB key took 14.9 seconds inside a one-megabyte document, synchronously,
     *  before the first await and before anything had authenticated a byte of it. The answer is already
     *  filed, so the repeat is a lookup. This is the same per-occurrence shape the signature walk below
     *  and the role walk in `updateRoot` both carry, and the third one found. */
    if (_hasOwn(authorized, id)) continue;
    /** @internal The key is COPIED before its identifier is computed, and the COPY is what verifies. The
     *  signature loop below awaits a verification per signature while this map is held, so a caller that
     *  replaces a later key's `keyval.public` in that window would have the identifier checked against one
     *  key and the signature verified under another: a threshold could then be met by material nobody
     *  authorized, the identifier naming one key while the bytes are another's. Deriving the identifier
     *  from the copy makes the two one read of one value. */
    var key = guard.bytes.snapshotDeep(keys[id], TufError, "tuf/bad-key", "the key filed under " + id);
    var computed = keyId(key);
    if (computed !== id) {
      throw _err("tuf/bad-key", "the key filed under " + id + " has identifier " + computed +
        "; a key must be listed under its own");
    }
    authorized[id] = key;
  }
  /** @internal The signature records, one read each. The loop below awaits a verification per signature and
   *  re-read them on every pass, so two signatures over DIFFERENT documents could each verify against the
   *  bytes present on their own turn and together meet a threshold no single document ever met. The signed
   *  bytes were copied at the top for the same reason. */
  /** @internal Filed by key identifier, because an identifier names at most one signature. The
   *  reference implementation the format points at builds the same map and refuses a document
   *  carrying two entries for one identifier ("Multiple signatures found for keyid"), then verifies by
   *  walking the ROLE's keys and looking up the one signature each names. Reading the document's list
   *  instead let it decide how many verifications ran: distinct signatures for one authorized key
   *  share no memo, and each costs a hash of the whole signed body, so a 500 KB body under 2400
   *  signatures made with a key nobody authorized bought 2400 checks and about a second, synchronously,
   *  inside the one-megabyte size cap and before anything had authenticated a byte. Walking the keys
   *  the ROLE names leaves the verifications at the number of keys that role lists, so the signature
   *  count is no longer a multiplier on the body: the work follows the document's own size rather than
   *  the product of its body and its signature list. The role is the caller's argument, and in a root
   *  rotation a candidate is also verified against the root role it states itself, which is the check
   *  the specification requires of a new root, so that one call's count is the candidate's to state. */
  var sigOf = _create(null);
  var rawSigs = metadata.signatures;
  if (!_isArray(rawSigs)) throw _err("tuf/bad-input", "opts.metadata carries a signatures array");
  for (var r = 0; r < rawSigs.length; r++) {
    var rec = rawSigs[r];
    if (!rec || typeof rec !== "object") throw _err("tuf/bad-metadata", "signatures[" + r + "] is not an object");
    /** @internal Each record is a plain object with plain fields, held to it before either field is
     *  read. These are copied into the list above so no field is read twice, and reading one at all is
     *  caller code running inside the loop: a getter on `sig` fired while the body was still the
     *  caller's and could change the document mid-verification. The copies make the verdict about one
     *  document, and this makes the reads themselves inert. */
    guard.identifier.assertPlainRecord(rec, _err, "tuf/bad-metadata", "signatures[" + r + "]");
    guard.identifier.refuseAccessorFields(rec, _SIGNATURE_FIELDS, _err, "tuf/bad-metadata",
      "signatures[" + r + "]");
    var recKeyid = rec.keyid, recSig = rec.sig;
    /** @internal A keyid that is not a string names no key in the map, so such a record can never be
     *  counted and never costs a verification; it is filed under nothing rather than refused. */
    if (typeof recKeyid !== "string") continue;
    /** @internal The FIRST entry an identifier carries is the one asked, and a later entry for that
     *  same identifier is passed over. The two authorities differ on a repeated identifier and this
     *  satisfies both. The specification admits one: "each SIGNATURE which is counted towards the
     *  THRESHOLD MUST have a unique KEYID. Even if a KEYID is listed more than once ... a client MUST
     *  NOT count more than one verified SIGNATURE from that KEYID", which caps the COUNT and leaves
     *  the document readable, so refusing it would be stricter than the document this parser cites.
     *  The reference implementation refuses it outright ("Multiple signatures found for keyid"). A
     *  second entry cannot raise the count the specification caps at one, so the only thing asking it
     *  could do is succeed where the first failed, which takes a document that lists a wrong signature
     *  for a key ahead of a right one. Passing it over keeps the verdict the specification requires and
     *  leaves the number of verifications at the number of keys the ROLE names. */
    if (_hasOwn(sigOf, recKeyid)) continue;
    sigOf[recKeyid] = recSig;
  }
  /** @internal Counted by key MATERIAL, not by identifier. A threshold is a number of KEYS, and an
   *  identifier is a hash of the whole key object, so one public key can hold two identifiers and be
   *  counted twice: a role naming both with a threshold of two was met by one key, the same signature
   *  bytes verifying under each entry. `keyIds` still reports the identifiers that counted, which is
   *  what names the signers; what the threshold is compared against is how many distinct keys they
   *  are. */
  var countedMaterial = _create(null);
  var keyIds = [];
  /** @internal The keys the ROLE names, each visited once, which is what bounds the work: an identifier
   *  the role repeats was filed once above, and a key the role names and the document signed for is the
   *  only thing that reaches a verification. The signature list decides WHICH signature each key
   *  offers, never how many are asked. */
  var ids = _keys(authorized);
  for (var s = 0; s < ids.length; s++) {
    var signerId = ids[s];
    if (!_hasOwn(sigOf, signerId)) continue;
    var use = _usableKey(authorized[signerId]);
    var materialId = _materialIdOf(use.key);
    /** @internal Counted material is skipped, since a second identifier over the same key cannot raise
     *  the count. Filed on SUCCESS alone: two identifiers can name one key, and if the first one's
     *  signature does not verify the second's still has to be asked, the key having signed once under
     *  whichever identifier the signer used. */
    if (_hasOwn(countedMaterial, materialId)) continue;
    /** @internal A signature this build cannot read is a verdict about the metadata rather than a
     *  fault: the record counts for nothing and the walk goes on, which is what it did when the decode
     *  sat inside the verify and threw. */
    var sigBytes = null;
    try {
      sigBytes = guard.encoding.hex(sigOf[signerId], constants.LIMITS.JSON_MAX_BYTES, _err,
        "tuf/bad-signature", "a signature");
    } catch (e) {
      if (!(e instanceof TufError && e.code === "tuf/bad-signature")) throw e;
    }
    if (sigBytes === null) continue;
    var ok = await use.check(sigBytes, signedBytes);
    if (ok === true) {
      countedMaterial[materialId] = 1;
      _push(keyIds, signerId);
    }
  }
  return guard.verdict.of({ verified: keyIds.length >= role.threshold, keyIds: keyIds,
    threshold: role.threshold });
}

/** @internal The identity of the public KEY, independent of how the metadata spells it. A threshold
 *  counts keys, and a key identifier is a hash of the whole key object, so one public key can hold
 *  many identifiers: a member the hash covers and the cryptography ignores (a `comment`), a PEM with
 *  CRLF line endings or a space before each newline, an EC point written compressed rather than
 *  uncompressed, or `ecdsa-sha2-nistp256` where another entry says `ecdsa`. Each yields a different
 *  identifier for the same key, and a role naming two of them with a threshold of two was met by ONE
 *  key, the same signature bytes verifying under each entry.
 *
 *  So the fingerprint is taken from the IMPORTED key's JWK, which is the mathematical form: the
 *  coordinates, fixed-width. MEASURED, that is what collapses the four spellings above, where the
 *  exported SPKI does not: Node preserves a compressed point on export, 59 bytes against 91, while the
 *  JWK coordinates of the two are identical. The scheme is deliberately not part of it, one key listed
 *  under two schemes still being one key. */
function _materialIdOf(imported) {
  /** @internal The export goes through the captured operation. Reached off the key's own prototype, a
   *  replacement returning one fixed value gave two distinct authorized keys the same identifier, and a
   *  two-key threshold then counted one signature. */
  return _bufToString(guard.crypto.digest("sha256",
    canonicalJson(guard.crypto.exportKey(imported, { format: "jwk" }))), "hex");
}

/** @internal A root document, parsed and held to being a root that states who may sign it. */
function _asRoot(input, label) {
  var meta = parseMetadata(input);
  if (meta.type !== "root") {
    throw _err("tuf/bad-metadata", label + " has _type " + guard.text.showValue(meta.type) + ", not root");
  }
  var signed = meta.signed;
  if (!signed.keys || typeof signed.keys !== "object" || _isArray(signed.keys)) {
    throw _err("tuf/bad-metadata", label + " carries no keys map");
  }
  if (!signed.roles || typeof signed.roles !== "object" || _isArray(signed.roles)) {
    throw _err("tuf/bad-metadata", label + " carries no roles map");
  }
  /** @internal Every top-level role, not only the one that signs the root. The specification sec. 4.3
   *  states it exactly: "A role for each of "root", "snapshot", "targets", and "timestamp" MUST be
   *  specified in the roles object", with "The role of "mirror" is OPTIONAL". A root carrying only its
   *  own role was adopted, and what that leaves is a trust anchor that cannot authenticate anything
   *  else the repository publishes: no keyids and no threshold to check a targets, snapshot or
   *  timestamp document against. Each record is held to carrying both, since a role that names neither
   *  is present without being usable. */
  /** @internal One verdict per KEYID for the whole walk, not per occurrence. Each occurrence
   *  canonicalized and hashed the whole key twice, imported it, and derived its material identity, and
   *  all of that runs on UNAUTHENTICATED metadata before any candidate signature is checked: measured,
   *  a 184 KB root carrying a 50 KB key comment and repeating one keyid 500 times per role spent 3.2
   *  seconds inside this walk before answering `tuf/root-unsigned`, with the document well under the
   *  size cap. The work is a pure function of the key filed under the identifier, and the body is
   *  already a snapshot nothing can change under the walk, so the second occurrence of an identifier
   *  reuses the first one's answer. A FAILING identifier throws, so only verdicts that passed are
   *  held. */
  var keyVerdict = _create(null);
  for (var r = 0; r < TOP_LEVEL_ROLES.length; r++) {
    var roleName = TOP_LEVEL_ROLES[r];
    var record = signed.roles[roleName];
    if (!record || typeof record !== "object" || _isArray(record)) {
      throw _err("tuf/bad-metadata", label + " names no " + roleName + " role, and a root states a " +
        "role for each of " + TOP_LEVEL_ROLES_TEXT + " (TUF specification sec. 4.3)");
    }
    /** @internal A record can be present and still name no signer this root carries, which is the same
     *  gap wearing a well-formed shape. Two of these checks are the specification's own words and two
     *  are this build refusing an unusable record with the specification silent, which the messages
     *  distinguish. A KEYID is "a hexdigest of the SHA-256 hash of the canonical form of the key", so
     *  one that is not a string is not a KEYID; a threshold is "A positive integer number of keys
     *  (>=1)". Nothing states that the keyids must appear in this root's own `keys` map or that the
     *  threshold must be reachable, and a role failing either can never be satisfied: it names keys
     *  the root does not carry, or asks for more signatures than it names keys. */
    if (!_isArray(record.keyids) || record.keyids.length === 0) {
      throw _err("tuf/bad-metadata", label + "'s " + roleName + " role names no keyids, so it does " +
        "not state who may sign for it");
    }
    /** @internal The threshold is compared against the DISTINCT key ids, not the list length. A
     *  verdict counts each key id once, so a role naming one key twice for a threshold of two reads as
     *  reachable and is not: one signature is all that list can ever produce. */
    var distinct = _create(null);
    for (var ki = 0; ki < record.keyids.length; ki++) {
      var keyid = record.keyids[ki];
      if (typeof keyid !== "string" || keyid.length === 0) {
        throw _err("tuf/bad-metadata", label + "'s " + roleName + " role names a keyid that is not a " +
          "string, where a KEYID is the hexdigest of a hash (TUF specification sec. 4.3)");
      }
      if (_hasOwn(keyVerdict, keyid)) { distinct[keyVerdict[keyid]] = 1; continue; }
      if (!_hasOwn(signed.keys, keyid)) {
        throw _err("tuf/bad-metadata", label + "'s " + roleName + " role names keyid " +
          guard.text.showValue(keyid) + ", which this root's keys map does not carry, so the role " +
          "states a signer the root cannot identify");
      }
      /** @internal EXISTENCE IS NOT IDENTITY. A role can name an identifier the keys map carries while
       *  the key filed there hashes to a different one, which is the "key listed under an identifier
       *  that is not its own" `verifySignatures` refuses. Only the ROOT role is verified during a
       *  rotation, so a mis-filed key in any other role was adopted and failed later, where the client
       *  had already trusted the root. Recomputed here, at adoption, for every role. The code is the
       *  one that condition already has, so a caller branching on it sees one answer wherever the
       *  mis-filing is found. */
      if (keyId(signed.keys[keyid]) !== keyid) {
        throw _err("tuf/bad-key", label + "'s " + roleName + " role names keyid " +
          guard.text.showValue(keyid) + ", and the key filed under it derives a different identifier, " +
          "so the role names a key the root does not carry");
      }
      /** @internal Keyed on the MATERIAL, so two identifiers for one public key count once. A role
       *  naming a key under two identifiers for a threshold of two states two signers and has one, and
       *  the verdict counts the same way. The identity comes from the key `_usableKey` imported, so
       *  holding the key to being usable and deriving what it is cost one import between them rather
       *  than one each. */
      var mid = _materialIdOf(_usableKey(signed.keys[keyid]).key);
      keyVerdict[keyid] = mid;
      distinct[mid] = 1;
    }
    var distinctCount = intrinsic.keys(distinct).length;
    if (typeof record.threshold !== "number" || !_isSafeInteger(record.threshold) ||
        record.threshold < 1) {
      throw _err("tuf/bad-metadata", label + "'s " + roleName + " role states no threshold that is a " +
        "positive integer, so it does not state how many signatures it takes");
    }
    if (record.threshold > distinctCount) {
      throw _err("tuf/bad-metadata", label + "'s " + roleName + " role asks for " + record.threshold +
        " signatures and names " + distinctCount + " distinct key(s), so the role can never be met");
    }
  }
  return meta;
}

/**
 * @primitive  pki.tuf.updateRoot
 * @signature  pki.tuf.updateRoot(opts) -> Promise<{ root, version, updated, walked }>
 * @since      0.8.41
 * @status     stable
 * @spec       TUF
 * @defends    signature-bypass (CWE-347)
 * @related    pki.tuf.verifySignatures, pki.tuf.checkExpiry
 *
 * Walk the root chain from a trusted root to the latest candidate, applying the two rules that make a
 * key rotation safe. Each new root must be signed by a threshold of the keys the PREVIOUS root names
 * and a threshold of the keys it names ITSELF: the first says the rotation was authorized by whoever
 * held the old keys, the second that the new keys can actually sign. A root meeting only one is
 * `tuf/root-unsigned`.
 *
 * Its version must be exactly one more than the trusted one. A candidate that skips a version is
 * `tuf/bad-root-version`, so no intermediate root can be passed over, and one at or below the trusted
 * version is refused by the same rule, which is the rollback check.
 *
 * The trusted root is itself verified against its own role before any candidate is read, because a chain
 * anchored in something unchecked proves nothing.
 *
 * Expiry is judged once, at the end, on the root the chain finishes on, at the `now` the caller supplies.
 * That is where the specification puts the freeze-attack check, and it is what lets a client whose pinned
 * root has lapsed catch up through the successors it is handed instead of needing its trust anchor
 * replaced by some other means. An intermediate root's own expiry is not checked, and with no candidates
 * the root the chain finishes on is the trusted root, so a lapsed root with nothing to move to is
 * `tuf/expired`.
 *
 * `candidates` are the intermediate roots in any order; `walked` reports the versions adopted, and
 * `updated` whether any candidate was.
 *
 * @opts
 *   trustedRoot: BufferSource,  // the root the caller already trusts
 *   candidates:  Array,         // the later root documents, each a BufferSource
 *   now:         Date,          // the instant expiry is judged at
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var raw = pki.asn1.decode(await pki.key.export(pair.publicKey)).children[1].content.subarray(1);
 *   var key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: raw.toString("hex") } };
 *   var id = pki.tuf.keyId(key), keys = {}; keys[id] = key;
 *   // `spec_version` is mandatory on a root this verb adopts, and its major version has to be one this
 *   // build implements: another major version states rules these checks do not have, and naming none
 *   // states nothing to match against.
 *   var signed = { _type: "root", spec_version: "1.0.31", version: 1, expires: "2030-01-01T00:00:00Z",
 *     keys: keys, roles: { root: { keyids: [id], threshold: 1 },
 *       targets: { keyids: [id], threshold: 1 }, snapshot: { keyids: [id], threshold: 1 },
 *       timestamp: { keyids: [id], threshold: 1 } } };
 *   var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey,
 *     pki.tuf.canonicalJson(signed)));
 *   var rootBytes = Buffer.from(JSON.stringify({
 *     signatures: [{ keyid: id, sig: sig.toString("hex") }], signed: signed }));
 *   var r = await pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: [],
 *     now: new Date("2027-01-01T00:00:00Z") });
 *   r.updated;   // -> false
 */
var _UPDATE_KEYS = intrinsic.assign(_create(null), { trustedRoot: 1, candidates: 1, now: 1 });
async function updateRoot(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _UPDATE_KEYS, _err, "tuf/bad-input", "unknown updateRoot option ");
  /** @internal The instant is CAPTURED here, at the call, into a Date this function owns. A Date is
   *  mutable and the caller keeps theirs, and the freeze-attack check runs at the END, after a signature
   *  verification has been awaited for every root in the chain: read from the caller's object at that
   *  point, a root that had expired by the instant supplied would pass if that Date were moved back while
   *  the chain was walked. Expiry is judged at the instant validation began at. */
  var suppliedNow = opts.now;
  if (!guard.time.isDate(suppliedNow)) throw _err("tuf/bad-input", "opts.now must be a Date");
  var now = guard.time.toDate(guard.time.instantOf(suppliedNow));
  /** @internal One read: `opts.candidates === undefined ? [] : opts.candidates` reads it twice, and a
   *  member reached through an accessor can answer the presence test and the value differently, so the
   *  array whose length is checked need not be the array that is walked. */
  var suppliedCandidates = opts.candidates;
  var candidates = suppliedCandidates === undefined ? [] : suppliedCandidates;
  if (!_isArray(candidates)) throw _err("tuf/bad-input", "opts.candidates must be an array of root documents");
  var candidateCount = candidates.length;
  if (candidateCount > constants.LIMITS.TUF_MAX_ROOT_CHAIN) {
    throw _err("tuf/bad-input", "a root chain of " + candidateCount + " exceeds the " +
      constants.LIMITS.TUF_MAX_ROOT_CHAIN + "-document cap");
  }
  var trusted = _asRoot(opts.trustedRoot, "the trusted root");
  /** @internal Every candidate is read and parsed HERE, before the first await, and the walk below reads
   *  only what this produced. Indexing after the await read the caller's array as it stood then, so a call
   *  made with an empty list could be handed a whole chain while the trusted root was being checked, and
   *  the cap above would have been applied to the empty one. The length is bound for the same reason. */
  /** @internal The trusted root is verified against its OWN role before it is used to judge
   *  anything. A caller may have been handed it by any means, and a chain anchored in a document
   *  nobody checked carries the whole chain's weight on nothing. */
  /** @internal Candidates are indexed by version so the walk asks for exactly N+1 at each step. A
   *  list in any order therefore walks in version order, and a gap stops the walk rather than
   *  letting a later root be adopted without the one before it. */
  var byVersion = _create(null);
  for (var i = 0; i < candidateCount; i++) {
    var cand = _asRoot(candidates[i], "candidates[" + i + "]");
    if (_hasOwn(byVersion, cand.version)) {
      throw _err("tuf/bad-root-version", "two candidate roots state version " + cand.version);
    }
    byVersion[cand.version] = cand;
  }
  var self = await verifySignatures({ metadata: trusted, keys: trusted.signed.keys, role: trusted.signed.roles.root });
  if (self.verified !== true) {
    throw _err("tuf/root-unsigned", "the trusted root does not meet its own root-role threshold of " +
      self.threshold + "; " + self.keyIds.length + " of its own keys signed it");
  }
  var walked = [];
  var current = trusted;
  for (;;) {
    var next = byVersion[current.version + 1];
    if (next === undefined) break;
    var byOld = await verifySignatures({ metadata: next, keys: current.signed.keys, role: current.signed.roles.root });
    if (byOld.verified !== true) {
      throw _err("tuf/root-unsigned", "root version " + next.version + " is not signed by a threshold of " +
        "the keys the trusted root version " + current.version + " names");
    }
    var byNew = await verifySignatures({ metadata: next, keys: next.signed.keys, role: next.signed.roles.root });
    if (byNew.verified !== true) {
      throw _err("tuf/root-unsigned", "root version " + next.version + " is not signed by a threshold of " +
        "the keys it names itself, so its own keys could not sign for it");
    }
    _push(walked, next.version);
    current = next;
  }
  /** @internal A candidate the walk never reached is a gap or a rollback, and is reported rather
   *  than ignored: a client that silently stops at a gap would keep trusting an older root while a
   *  newer one it was handed says otherwise. */
  var versions = _keys(byVersion);
  for (var v = 0; v < versions.length; v++) {
    var num = +versions[v];
    if (num > current.version) {
      throw _err("tuf/bad-root-version", "candidate root version " + num + " was not reached: the chain " +
        "stops at version " + current.version + ", so a root between them is missing");
    }
    if (num <= trusted.version) {
      throw _err("tuf/bad-root-version", "candidate root version " + num + " is not newer than the " +
        "trusted version " + trusted.version + "; a root may only move forward");
    }
  }
  /** @internal The freeze-attack check, LAST, and on the root the walk ended on. The specification puts
   *  it at step 5.3.10, after the walk of steps 5.3.2 to 5.3.9, and no step checks an intermediate
   *  root's expiry: a client that has been offline long enough for its pinned root to lapse is meant to
   *  catch up through the successors it is handed, and checking the anchor first is what stops it,
   *  leaving the only way forward a replacement of the trust anchor by some other means. With no
   *  candidates the root the walk ends on is the trusted root itself, so a lapsed root with nothing to
   *  move to is still refused here. */
  checkExpiry(current, now);
  return guard.verdict.of({ root: current.signed, version: current.version,
    updated: walked.length > 0, walked: walked });
}

module.exports = {
  canonicalJson: canonicalJson,
  keyId: keyId,
  parseMetadata: parseMetadata,
  checkExpiry: checkExpiry,
  verifySignatures: verifySignatures,
  updateRoot: updateRoot,
  ROLES: TUF_ROLES,
};
