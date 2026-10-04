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

var nodeCrypto = require("crypto");
var constants = require("./constants");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");

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
var _push = intrinsic.push;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _codePointAt = intrinsic.uncurry(String.prototype.codePointAt);
var _numToString = intrinsic.uncurry(Number.prototype.toString);
var _dateParse = intrinsic.dateParse;
var _sort = intrinsic.sort;
var _join = intrinsic.join;

var CANONICAL_MAX_DEPTH = constants.LIMITS.JSON_MAX_DEPTH;
var KEY_ID_HEX_LEN = 64;
var TUF_ROLES = ["root", "timestamp", "snapshot", "targets"];

/** @internal Canonical JSON escapes ONLY these two, each with a single backslash. Everything else,
 *  including a byte below 0x20, is emitted as itself. A generic JSON writer escapes far more, and
 *  would produce a different preimage for the same document. */
function _canonicalString(s, out) {
  /** @internal Every string reaching the encoding passes here, keys and values alike, so the
   *  well-formed check is made once. Canonical JSON is the preimage a TUF signature covers, and an
   *  unpaired surrogate would be converted to U+FFFD, so two documents differing only in that code unit
   *  would have the same signing bytes.
   *  @guard-via guard\.text\.assertWellFormedUtf16\( */
  guard.text.assertWellFormedUtf16(s, TufError, "tuf/bad-input", "a canonical JSON string");
  _push(out, "\"");
  var start = 0;
  for (var i = 0; i < s.length; i++) {
    var c = _codePointAt(s, i);
    if (c === 0x5c || c === 0x22) {
      if (i > start) _push(out, _strSlice(s, start, i));
      _push(out, c === 0x5c ? "\\\\" : "\\\"");
      start = i + 1;
    }
  }
  if (start < s.length) _push(out, _strSlice(s, start));
  _push(out, "\"");
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

function _canonical(value, out, depth) {
  if (depth > CANONICAL_MAX_DEPTH) {
    throw _err("tuf/too-deep", "the document nests deeper than " + CANONICAL_MAX_DEPTH + " levels");
  }
  if (value === null) { _push(out, "null"); return; }
  if (value === true) { _push(out, "true"); return; }
  if (value === false) { _push(out, "false"); return; }
  if (typeof value === "string") { _canonicalString(value, out); return; }
  if (typeof value === "number") {
    /** @internal A float has no canonical form here: the reference encoder refuses one outright, so
     *  a document a conforming signer produced contains none. A value past the exactly-representable
     *  range is refused for the same reason a narrowed one would be wrong: the digits written would
     *  not be the digits signed. */
    if (!_isSafeInteger(value)) {
      throw _err("tuf/bad-input", "canonical JSON encodes only exact integers; " +
        guard.text.showValue(value) + " is not one");
    }
    _push(out, _numToString(value, 10));
    return;
  }
  if (_isArray(value)) {
    _push(out, "[");
    for (var i = 0; i < value.length; i++) {
      if (i > 0) _push(out, ",");
      _canonical(value[i], out, depth + 1);
    }
    _push(out, "]");
    return;
  }
  if (typeof value === "object") {
    var names = _sort(_keys(value), _byCodePoint);
    _push(out, "{");
    for (var k = 0; k < names.length; k++) {
      if (k > 0) _push(out, ",");
      _canonicalString(names[k], out);
      _push(out, ":");
      _canonical(value[names[k]], out, depth + 1);
    }
    _push(out, "}");
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
  _canonical(value, out, 0);
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
  if (typeof key.keytype !== "string" || typeof key.scheme !== "string" ||
      !key.keyval || typeof key.keyval !== "object") {
    throw _err("tuf/bad-key", "a TUF key carries keytype, scheme and keyval; one of them is missing " +
      "or is not of its stated type");
  }
  return _bufToString(nodeCrypto.createHash("sha256").update(canonicalJson(key)).digest(), "hex");
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
 * `_type`, a `version` that is a positive integer, and an `expires` that parses as a date-time are
 * required; a document missing any is `tuf/bad-metadata`.
 *
 * @example
 *   var m = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [],
 *     signed: { _type: "root", version: 1, expires: "2030-01-01T00:00:00Z" } })));
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
  if (typeof signed._type !== "string" || signed._type.length === 0) {
    throw _err("tuf/bad-metadata", "the signed body names no _type");
  }
  if (typeof signed.version !== "number" || !_isSafeInteger(signed.version) || signed.version < 1) {
    throw _err("tuf/bad-metadata", "the signed body's version is not a positive integer");
  }
  if (typeof signed.expires !== "string" || !_isFiniteTime(_dateParse(signed.expires))) {
    throw _err("tuf/bad-metadata", "the signed body's expires is not a date-time");
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
    specVersion: typeof signed.spec_version === "string" ? signed.spec_version : null,
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
 * @example
 *   var meta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [],
 *     signed: { _type: "root", version: 1, expires: "2030-01-01T00:00:00Z" } })));
 *   pki.tuf.checkExpiry(meta, new Date("2027-01-01T00:00:00Z"));   // -> true
 */
function checkExpiry(metadata, now) {
  if (!metadata || typeof metadata !== "object" || typeof metadata.expires !== "string") {
    throw _err("tuf/bad-input", "checkExpiry takes a parsed metadata object from pki.tuf.parseMetadata");
  }
  if (!guard.time.isDate(now)) throw _err("tuf/bad-input", "now must be a Date");
  var atMs = guard.time.instantOf(now);
  var expiresMs = _dateParse(metadata.expires);
  if (!_isFiniteTime(expiresMs)) throw _err("tuf/bad-metadata", "the metadata's expires is not a date-time");
  if (!(atMs < expiresMs)) {
    throw _err("tuf/expired", "the " + metadata.type + " metadata expired at " + metadata.expires +
      ", which is at or before the instant it was checked at");
  }
  return true;
}

/** @internal One signature checked under one key. Resolves a boolean: whether a key signed a
 *  preimage is a verdict, and a key or signature this build cannot read is a fault in the metadata
 *  rather than a failed verification, so it throws. */
async function _verifyOne(key, sigHex, preimage) {
  var sig = guard.encoding.hex(sigHex, constants.LIMITS.JSON_MAX_BYTES, _err, "tuf/bad-signature", "a signature");
  var checked = _checkedPublicKey(key);
  if (key.keytype === "ed25519") {
    var raw = guard.encoding.hex(key.keyval.public, 64, _err, "tuf/bad-key", "an ed25519 public key");
    if (raw.length !== 32) {
      throw _err("tuf/bad-key", "an ed25519 public key is 32 bytes, got " + raw.length);
    }
    var spki = _bufferConcat([ED25519_SPKI_PREFIX, raw]);
    edwardsPoint.validateSpki(spki, ED25519_CRV, TufError, "tuf/bad-key");
    var edKey = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    return nodeCrypto.verify(null, preimage, edKey, sig);
  }
  if (key.keytype === "ecdsa" || key.keytype === "ecdsa-sha2-nistp256") {
    return nodeCrypto.verify("sha256", preimage, { key: checked, dsaEncoding: "der" }, sig);
  }
  /** @internal The rsa arm. The scheme the specification pairs with an rsa key is RSASSA-PSS over
   *  SHA-256, so that is the padding a signature is checked under; reading the padding from the document
   *  would let it name the one its forgery happens to satisfy. Every other keytype was refused by
   *  _checkedPublicKey above, whose table is the one list of what this build reads. */
  return nodeCrypto.verify("sha256", preimage, {
    key: checked, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }, sig);
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

/** @internal The declared algorithm, checked against the key material before anything verifies under it,
 *  and the imported key RETURNED so the caller verifies with the very object that was checked. Importing
 *  it again at the call site would read `keyval.public` a second time, and a caller-supplied accessor can
 *  answer differently on the second read, which would leave the checked key and the verifying key two
 *  different keys. An ed25519 key carries raw bytes rather than a PEM and its own arm holds the length
 *  and the point, so there is nothing to import for it. */
function _checkedPublicKey(key) {
  var d = _declarationOf(key);
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
  try { return nodeCrypto.createPublicKey({ key: pem, format: "pem" }); }
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
 * `false` rather than throwing, while a key or signature the build cannot read throws.
 *
 * Three rules the specification states, each applied here:
 *
 * - A signature counts only if its `keyid` is one the role names. One from any other key contributes
 *   nothing, whatever it verifies over.
 * - One verified signature per DISTINCT key identifier. A key listed twice, or signing twice, counts
 *   once, so a threshold cannot be met by repetition.
 * - Every key's identifier is recomputed from the key itself and must equal the identifier it is
 *   listed under. A key filed under another's identifier is `tuf/bad-key`, not a key that fails to
 *   verify: the document is malformed rather than unsigned.
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
 *   var signed = { _type: "root", version: 1, expires: "2030-01-01T00:00:00Z",
 *     keys: keys, roles: { root: { keyids: [id], threshold: 1 } } };
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
  var rawSignedBytes = metadata.signedBytes;
  if (!guard.bytes.isByteSource(rawSignedBytes)) {
    throw _err("tuf/bad-input", "opts.metadata is a parsed document from pki.tuf.parseMetadata");
  }
  /** @internal `snapshotSource`, so the set this copies is the set the check above admits: `snapshot`
   *  wants a Buffer or a Uint8Array, so an ArrayBuffer or a DataView was refused one line after being
   *  accepted. */
  var signedBytes = guard.bytes.snapshotSource(rawSignedBytes, _err, "tuf/bad-input", "metadata.signedBytes");
  var keys = opts.keys;
  if (!keys || typeof keys !== "object" || _isArray(keys)) {
    throw _err("tuf/bad-input", "opts.keys is the KEYID to key map the root states");
  }
  if (!opts.role || typeof opts.role !== "object") {
    throw _err("tuf/bad-input", "opts.role carries a keyids array and a threshold that is a positive integer");
  }
  var role = { keyids: opts.role.keyids, threshold: opts.role.threshold };
  if (!_isArray(role.keyids) || typeof role.threshold !== "number" ||
      !_isSafeInteger(role.threshold) || role.threshold < 1) {
    throw _err("tuf/bad-input", "opts.role carries a keyids array and a threshold that is a positive integer");
  }
  role.keyids = guard.bytes.snapshotDeep(role.keyids, TufError, "tuf/bad-input", "opts.role.keyids");
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
  var sigRecords = [];
  var rawSigs = metadata.signatures;
  if (!_isArray(rawSigs)) throw _err("tuf/bad-input", "opts.metadata carries a signatures array");
  for (var r = 0; r < rawSigs.length; r++) {
    var rec = rawSigs[r];
    if (!rec || typeof rec !== "object") throw _err("tuf/bad-metadata", "signatures[" + r + "] is not an object");
    _push(sigRecords, { keyid: rec.keyid, sig: rec.sig });
  }
  var counted = _create(null);
  var keyIds = [];
  for (var s = 0; s < sigRecords.length; s++) {
    var sig = sigRecords[s];
    if (!_hasOwn(authorized, sig.keyid)) continue;
    if (_hasOwn(counted, sig.keyid)) continue;
    var ok;
    try { ok = await _verifyOne(authorized[sig.keyid], sig.sig, signedBytes); }
    catch (e) {
      if (e instanceof TufError && e.code === "tuf/bad-signature") { ok = false; }
      else throw e;
    }
    if (ok === true) { counted[sig.keyid] = 1; _push(keyIds, sig.keyid); }
  }
  return guard.verdict.of({ verified: keyIds.length >= role.threshold, keyIds: keyIds,
    threshold: role.threshold });
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
  if (!signed.roles.root || typeof signed.roles.root !== "object") {
    throw _err("tuf/bad-metadata", label + " names no root role, so it does not state who may sign it");
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
 *   var signed = { _type: "root", version: 1, expires: "2030-01-01T00:00:00Z",
 *     keys: keys, roles: { root: { keyids: [id], threshold: 1 } } };
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
