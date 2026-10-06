// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.tlog
 * @nav        Transparency
 * @title      Tlog
 * @fullname   Transparency-log envelope: signed notes, checkpoints, tiles (C2SP)
 * @order      221
 * @slug       tlog
 *
 * @intro
 *   The C2SP envelope every tiled transparency log speaks, over the hashes
 *   `pki.merkle` already verifies: a signed note (`c2sp.org/signed-note`), the
 *   checkpoint body a log signs into one (`c2sp.org/tlog-checkpoint`), and the
 *   tile addressing a static log serves them beside (`c2sp.org/tlog-tiles`).
 *   Static-CT, Merkle Tree Certificates and Rekor v2 differ in what they put in
 *   the origin line and what they do with the root, not in this layer.
 *
 *   A note is text, a blank line, then one signature line per signer. The
 *   signature is over the text INCLUDING its trailing newline, so `parseNote`
 *   surfaces `signedBytes` as a view of the input, never a re-serialization:
 *   a verifier that rebuilt the text from its parsed lines would accept a note
 *   altered in the delimiter. A key ID is four bytes and the specification says
 *   it identifies rather than proves, so `verifyNote` tries every supplied key
 *   whose ID matches and reports a verdict only after all of them. An unknown
 *   signature is ignored; a note carrying no signature from a supplied key is
 *   rejected.
 *
 *   A checkpoint is that note with a body of origin, tree size and root hash,
 *   plus opaque extension lines. The tree size is carried as a `BigInt`, the
 *   root as 32 raw bytes ready for `pki.merkle.verifyInclusion`. Decoding is
 *   fail-closed: a leading zero in the tree size, an empty origin, an empty
 *   extension line, a root that is not 32 bytes, or non-canonical base64
 *   anywhere is a typed `tlog/*` refusal.
 *
 *   `tilePath` / `entryBundlePath` build the paths a log serves, and
 *   `parseTilePath` reads one back. Verifying only: nothing here signs, and
 *   nothing fetches.
 *
 * @card
 *   Signed notes, checkpoints and tile paths over `pki.merkle`, fail-closed and
 *   transport-free.
 */

var constants = require("./constants");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var subtle = require("./webcrypto").webcrypto.subtle;
var edwardsPoint = require("./edwards-point");
var merkle = require("./merkle");
var intrinsic = require("./guard-intrinsic");

/** @internal The two SubtleCrypto operations an Ed25519 note verdict rests on, captured at load. The
 * object was held and its METHODS fetched per call, which leaves them replaceable: a `verify`
 * answering true accepts a note no key signed. */
var _subtleImportKey = intrinsic.uncurry(subtle.importKey);
var _subtleVerify = intrinsic.uncurry(subtle.verify);

/** @internal The string and array operations this module parses with, taken at load. A note, a
 * checkpoint body and a tile path are all split and sliced to reach the values a verdict rests on,
 * and `String.prototype` `split` / `indexOf` / `slice` are replaceable: one swapped after this
 * module loads would otherwise be asked at the moment of the parse and could steer which line reads
 * as the origin, the tree size or the root. `pki.sigstore` composes this module inside a verifier
 * already hardened that way, so the strictest consumer sets the rule here. */
var _split = intrinsic.uncurry(String.prototype.split);
var _strIndexOf = intrinsic.stringIndexOf;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _arrSlice = intrinsic.arraySlice;
var _join = intrinsic.join;
var _push = intrinsic.push;
var _pop = intrinsic.pop;
var _unshift = intrinsic.unshift;
var _bufToString = intrinsic.bufToString;
var _bufferFrom = intrinsic.bufferFrom;
var _byteLength = intrinsic.byteLength;
var _bufferConcat = intrinsic.bufferConcat;
var _bufferCompare = intrinsic.compare;
var _subarray = intrinsic.subarray;
var _create = intrinsic.create;
var _assign = intrinsic.assign;
var _isArray = intrinsic.isArray;
var _isInteger = intrinsic.isInteger;
var _fromCharCode = intrinsic.fromCharCode;
var _jsonStringify = intrinsic.stringify;
var _stringOf = intrinsic.String;
var _numberOf = intrinsic.Number;
var _bigIntOf = intrinsic.BigInt;
var _numToString = intrinsic.uncurry(Number.prototype.toString);

var TlogError = frameworkError.TlogError;
function _err(code, message, cause) { return new TlogError(code, message, cause); }

var SHA256_BYTES = 32;
var KEY_ID_BYTES = 4;
var ED25519_ALG_ID = 0x01;
var ED25519_RAW_BYTES = 32;
var TILE_HEIGHT_HASHES = 256;
var TILE_SEGMENT_DIGITS = 3;
var TILE_MAX_LEVEL = 63;
var MIN_CHECKPOINT_LINES = 3;

/** @internal The signature line's first character is an em dash, U+2014, which the wire format
 *  requires. It is built from its codepoint so the byte cannot drift through an editor, and it is
 *  the only place in this codebase where that character is data rather than prose. */
var SIG_LINE_PREFIX = _fromCharCode(0x2014) + " ";

var LF = 0x0a;

/** @internal A caller's byte source as a byte VIEW, before anything measures or copies it. Every door here
 *  admits what `guard.bytes.isByteSource` admits and says so, which is Buffer, TypedArray, DataView and
 *  ArrayBuffer. `guard.bytes.lengthOf` and `guard.bytes.snapshot` do not take that whole set, so measuring
 *  or copying the raw input left the admitted set wider than the handled one: an ArrayBuffer reached
 *  `lengthOf` and raised a bare TypeError carrying no code, and a DataView over valid bytes was refused as
 *  though its content were wrong. `Response.arrayBuffer()` is the ordinary way a tile arrives, so the gap
 *  was on the path a caller actually takes.
 *
 *  `guard.bytes.source` shares the caller's backing store rather than copying it, so normalizing FIRST
 *  leaves the cap ahead of every allocation, which is the order `_binary` explains and depends on. */
function _normalized(input, field) {
  return guard.bytes.source(input, TlogError, "tlog/bad-input", field);
}

function _bytes(input, field, maxBytes) {
  /** @internal The cap is checked BEFORE either conversion allocates, for the reason at `_binary`. A string
   *  is measured as the UTF-8 it will encode to rather than as its code-unit count. */
  if (typeof input === "string") {
    var utf8 = _byteLength(input, "utf8");
    if (utf8 > maxBytes) throw _err("tlog/bad-input", field + " " + utf8 + " bytes exceeds the cap " + maxBytes);
    return _bufferFrom(input, "utf8");
  }
  var view = _normalized(input, field);
  var size = guard.bytes.lengthOf(view);
  if (size > maxBytes) throw _err("tlog/bad-input", field + " " + size + " bytes exceeds the cap " + maxBytes);
  /** @internal A note's `signedBytes` is a view of this, which the docstring states, and the note itself is
   *  re-read by nothing after parsing, so this one keeps its view. */
  return view;
}

/** @internal The same coercion, but a COPY, for a verb that reads the input more than once or holds a
 *  view of it across an await. `guard.bytes.source` returns a view of the caller's buffer: a caller that
 *  reuses or overwrites that buffer while an Ed25519 key import is pending changes the bytes between the
 *  decode and the verification, so the verdict describes one document and the values reported come from
 *  another. A string is already immutable and is copied by the UTF-8 decode. Taking the copy ONCE at the
 *  entry point is what makes the decode and the signature check read the same bytes. */
function _bytesSnapshot(input, field, maxBytes) {
  /** @internal The cap is checked BEFORE the copy, for the reason at `_binary`: the verify verbs snapshot
   *  their note so the bytes verified are the bytes reported, and an oversized one was copied in full before
   *  the parser read the limit that refuses it. A string is measured as the UTF-8 it will encode to. */
  if (typeof input === "string") {
    var utf8 = _byteLength(input, "utf8");
    if (utf8 > maxBytes) throw _err("tlog/bad-input", field + " " + utf8 + " bytes exceeds the cap " + maxBytes);
    return _bufferFrom(input, "utf8");
  }
  var view = _normalized(input, field);
  var size = guard.bytes.lengthOf(view);
  if (size > maxBytes) throw _err("tlog/bad-input", field + " " + size + " bytes exceeds the cap " + maxBytes);
  return guard.bytes.snapshot(view, _err, "tlog/bad-input", field);
}

/** @internal A tile, an entry bundle and a key are binary, where a note is text. Reading a string
 *  as one of them decodes it as UTF-8, which rewrites every byte above 0x7f, so the result is never
 *  the data it stands for; a 32-character string is the length of one hash and would parse as one.
 *  A string here is a caller that read a response as text rather than bytes, and is told so. */
function _binary(input, field, maxBytes, tooLargeCode) {
  if (typeof input === "string") {
    throw _err("tlog/bad-input", field + " is binary and must be a byte source, not a string: " +
      "read the response as bytes rather than as text");
  }
  /** @internal COPIES rather than views. A tile's hashes and an entry bundle's entries are returned as
   *  slices of what arrives here, and the bytes arrive from a caller's `read` callback: a callback reusing
   *  one scratch buffer across fetches would have a later tile overwrite hashes and proof nodes already
   *  collected, so the proof verified would not be the proof that was served.
   *  The cap is checked BEFORE the copy, on the input's authoritative byte length. Copying first would cost
   *  a second allocation the size of a hostile response before the limit that refuses it was read: a 64 MiB
   *  buffer handed to a parser whose tiles are 8192 bytes. Same order as `guard.text.decode`. */
  var view = _normalized(input, field);
  var size = guard.bytes.lengthOf(view);
  if (size > maxBytes) {
    /** @internal The CALLER's code, so moving the cap ahead of the copy did not move the verdict: an
     *  over-wide tile is still `tlog/bad-tile` and not the door's own error. */
    throw _err(tooLargeCode, field + " " + size + " bytes exceeds the cap " + maxBytes);
  }
  return guard.bytes.snapshot(view, TlogError, "tlog/bad-input", field);
}

/** @internal A note is UTF-8 text carrying no ASCII control byte other than newline. The scan is by
 *  character code, not a pattern, and it runs before anything is split, so a control byte is
 *  refused instead of being carried into a line. */
function _assertNoteText(buf) {
  for (var i = 0; i < buf.length; i++) {
    var c = buf[i];
    if (c < 0x20 && c !== LF) {
      throw _err("tlog/bad-note", "a note carries no ASCII control byte other than newline; found 0x" +
        _numToString(c, 16) + " at offset " + i);
    }
  }
}

/** @internal Canonical base64 through the shared encoding guard, which is where the alphabet, the
 *  group-length rule and the re-encode check live; a bare decode accepts text that is not the text
 *  it claims to be. Every base64 field in this module reads through here. */
function _base64(text, field) {
  return guard.encoding.base64(text, constants.LIMITS.TLOG_MAX_NOTE_BYTES, _err, "tlog/bad-note", field);
}

/** @internal An ASCII decimal string with no leading zero, as a BigInt. "0" alone is the empty
 *  tree and is the one value whose first digit may be zero. Bounded to a uint64, which is the
 *  width pki.merkle carries a tree coordinate at, so a size this accepts is one the fold takes. */
function _decimal(text, field, code) {
  return guard.range.decimalUint64(text, _err, code, field);
}

/**
 * @primitive  pki.tlog.keyId
 * @signature  pki.tlog.keyId(keyName, publicKey) -> Buffer
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP signed-note
 * @related    pki.tlog.verifyNote
 *
 * The four-byte key ID a signed note carries in front of its signature. The derivation is fixed per
 * algorithm and they are not variations on one form, so it is read from the key material rather than
 * from anything the caller declares:
 *
 * - **Ed25519:** `SHA-256(keyName || 0x0A || 0x01 || raw32)[:4]`. Pass the raw 32 bytes or an
 *   Ed25519 SubjectPublicKeyInfo; both give the same ID, because one key has one ID.
 * - **ECDSA** over P-256, P-384 or P-521: `SHA-256(spkiDer)[:4]`, with neither the key name nor a
 *   type byte in the preimage. The same key therefore has one ID under any name.
 * - **RSA:** `SHA-256(keyName || 0x0A || 0xFF || "PKIX-RSA-PKCS#1v1.5" || spkiDer)[:4]`.
 *
 * An algorithm with no stated derivation is `tlog/bad-input` rather than hashed under an assumed
 * one, which would produce an identifier no log would ever state.
 *
 * The specification calls these identifiers rather than cryptographically strong hashes, and four
 * bytes is short enough that two keys can share one. A match therefore selects a candidate and
 * never decides a verdict; `pki.tlog.verifyNote` checks every key whose ID matches.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var raw = pki.asn1.decode(spki).children[1].content.subarray(1);   // the 32 key bytes
 *   pki.tlog.keyId("example.com/log", raw).length;   // -> 4
 */
function keyId(keyName, publicKey) {
  return _resolveKey(keyName, publicKey).id;
}

var ECDSA_ALG_ID = 0x02;
var RSA_ALG_ID = 0xff;
var RSA_FORMAT_TAG = _bufferFrom("PKIX-RSA-PKCS#1v1.5", "utf8");
/** @internal The curves signature type 0x02 admits. c2sp.org/signed-note states "The ECDSA curve MUST be
 *  one of NIST P-256, NIST P-384, or NIST P-521", so a key on any other curve has no type to be carried
 *  under and is refused rather than signed for under an assumed one.
 *
 *  The DIGEST is not read from this list. The same clause defines the type as "ECDSA signatures as
 *  implemented by github.com/transparency-dev/witness", whose constant for the byte is named
 *  `algECDSAWithSHA256` and whose verifier computes `sha256.Sum256(msg)` for every key it accepts, with no
 *  branch on the curve. The digest belongs to the signature TYPE, and taking it from the curve instead
 *  rejected every conforming P-384 and P-521 note with `tlog/bad-signature`. */
var EC_CURVES = _assign(_create(null), {
  prime256v1: 1, secp384r1: 1, secp521r1: 1,
});
var EC_HASH = "sha256";

/** @internal A supplied key resolved to the one identity the specification gives it: its signature
 *  type, its SubjectPublicKeyInfo, and the four-byte ID a note would carry for it.
 *
 *  The algorithm is read off the key material through the engine rather than taken from the caller,
 *  so a key cannot be hashed under a type it is not. A 32-byte input is raw Ed25519: no
 *  SubjectPublicKeyInfo is that short, the shortest being 44 bytes for this same algorithm, so the
 *  two readings cannot collide. Anything else must be an SPKI the engine accepts.
 *
 *  The ECDSA preimage is the SPKI alone, which is the specification's own departure from the other
 *  two forms, so the name never reaches the hash for that algorithm. */
function _resolveKey(keyName, publicKey) {
  if (typeof keyName !== "string" || keyName.length === 0) {
    throw _err("tlog/bad-input", "keyName must be a non-empty string");
  }
  /** @internal COPIED. This is the one door every key enters through, and what it returns is BOTH the
   *  material the key ID is derived from and the material a signature is later verified under. A note with
   *  several signature lines awaits a key import per line, so a view would let a caller replace a later
   *  key's bytes after its ID was computed: the ID that decides which key a line is checked against would
   *  come from one key and the verification from another, and a line could be attributed to a signer whose
   *  key never signed it. Copying here makes the ID and the verification one read of one value. */
  /** @internal A verifier key is a raw Ed25519 key or an SPKI, so the note cap is far above any real one and
   *  is here only so an oversized input is refused before it is copied. `_binary` already snapshots, so it
   *  is not wrapped a second time. */
  var bytes = _binary(publicKey, "publicKey", constants.LIMITS.TLOG_MAX_NOTE_BYTES, "tlog/bad-input");
  var name = _bufferFrom(keyName, "utf8");
  if (bytes.length === ED25519_RAW_BYTES) {
    return _edKey(name, _bufferConcat([ED25519_SPKI_PREFIX, bytes]), bytes);
  }
  var key;
  try { key = guard.crypto.publicKey({ key: bytes, format: "der", type: "spki" }); }
  catch (e) {
    throw _err("tlog/bad-input", "publicKey must be the raw " + ED25519_RAW_BYTES +
      " Ed25519 bytes or a SubjectPublicKeyInfo, got " + bytes.length + " bytes", e);
  }
  var type = key.asymmetricKeyType;
  if (type === "ed25519") {
    return _edKey(name, bytes, _subarray(bytes, bytes.length - ED25519_RAW_BYTES));
  }
  if (type === "ec") {
    var curve = key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve;
    if (EC_CURVES[curve] !== 1) {
      throw _err("tlog/bad-input", "a signed note names no key-ID derivation for the elliptic curve " +
        guard.text.showValue(_stringOf(curve)));
    }
    return { type: ECDSA_ALG_ID, spki: bytes, raw: null, hash: EC_HASH, key: key,
      id: _idOf([bytes]) };
  }
  if (type === "rsa") {
    return { type: RSA_ALG_ID, spki: bytes, raw: null, hash: "sha256", key: key,
      id: _idOf([name, _bufferFrom([LF, RSA_ALG_ID]), RSA_FORMAT_TAG, bytes]) };
  }
  throw _err("tlog/bad-input", "a signed note names no key-ID derivation for a " +
    guard.text.showValue(_stringOf(type)) + " key");
}

function _edKey(name, spki, raw) {
  /** @internal The shared Edwards-point gate runs where the key is resolved, not only where it is
   *  used: Node imports a low-order key without complaint and such a key verifies a FORGED
   *  signature, so one must never become a candidate or be given an identifier at all. */
  edwardsPoint.validateSpki(spki, ED25519_CRV, TlogError, "tlog/bad-input");
  return { type: ED25519_ALG_ID, spki: spki, raw: raw, hash: null, key: null,
    id: _idOf([name, _bufferFrom([LF, ED25519_ALG_ID]), raw]) };
}

/** @internal The identifier is what matches a signature line to a caller's key, so the digest over its
 *  parts goes through the operations captured at load: a replaced `update` changed the four bytes a
 *  line is matched on, and a note a key really did sign then reported `verified: false`. */
function _idOf(parts) { return _subarray(guard.crypto.digestParts("sha256", parts), 0, KEY_ID_BYTES); }

/** @internal The offset one past the text's terminating newline, which is where the blank line
 *  begins. The text runs to the first "\n\n", so the signed range ENDS with that first newline and
 *  the second one opens the signature block. Returns -1 when the note carries no blank line. */
function _textEnd(buf) {
  /** @internal Scanned from the END. The specification says "the note text MAY contain empty lines;
   *  the text is separated from the signatures by the LAST empty line in the note", so taking the
   *  first would make the signed range a PREFIX of what the signer signed: the remainder would then
   *  be read as signature lines and a conforming note refused, and a verifier that did accept the
   *  prefix would be checking a signature over less text than the log committed to. */
  for (var i = buf.length - 2; i >= 0; i--) {
    if (buf[i] === LF && buf[i + 1] === LF) return i + 1;
  }
  return -1;
}

/**
 * @primitive  pki.tlog.parseNote
 * @signature  pki.tlog.parseNote(input) -> { text, signedBytes, signatures }
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP signed-note
 * @defends    signature-bypass (CWE-347)
 * @related    pki.tlog.verifyNote, pki.tlog.parseCheckpoint
 *
 * Read a signed note: the text, the exact bytes a signature covers, and one entry per signature
 * line carrying `keyName`, the four-byte `keyId` and the `signature` after it.
 *
 * `signedBytes` is a view of the input, not a re-serialization. The signature covers the text
 * including its trailing newline, so a parser that rebuilt that text from its parsed lines would
 * verify a note against bytes the signer never saw. Everything a verifier hashes comes from here.
 *
 * A note carrying an ASCII control byte other than newline, no blank line, a signature line that is
 * not an em dash, a space, a key name, a space and canonical base64, a signature shorter than its
 * key ID, or more signatures than `C.LIMITS.TLOG_MAX_SIGNATURES` is refused with `tlog/bad-note`.
 *
 * @example
 *   var DASH = String.fromCharCode(0x2014);   // the em dash a signature line opens with
 *   var noteText = "example.com/log\n5\n" + Buffer.alloc(32).toString("base64") + "\n" +
 *     "\n" + DASH + " example.com/log " + Buffer.alloc(68).toString("base64") + "\n";
 *   var note = pki.tlog.parseNote(noteText);
 *   note.signatures[0].keyName;        // -> "example.com/log"
 *   note.signedBytes.length === Buffer.byteLength(note.text);   // -> true
 */
function parseNote(input) {
  var buf = _bytes(input, "note", constants.LIMITS.TLOG_MAX_NOTE_BYTES);
  /** @internal The WHOLE note is decoded strictly before any of it is read as text. C2SP signed-note is
   *  UTF-8, and a lossy conversion replaces a malformed byte with U+FFFD: a note beginning 0xFF verified
   *  with its origin reported as U+FFFD, and the text reported did not encode back to the bytes signed. */
  guard.text.decode(buf, constants.LIMITS.TLOG_MAX_NOTE_BYTES, TlogError, {
    charset: "utf-8", fatal: true, tooLarge: "tlog/bad-input", badDecode: "tlog/bad-note",
    badInput: "tlog/bad-input", label: "the note",
  });
  _assertNoteText(buf);
  var end = _textEnd(buf);
  if (end < 0) throw _err("tlog/bad-note", "a note separates its text from its signatures with a blank line");
  var signedBytes = _subarray(buf, 0, end);
  var rest = _bufToString(_subarray(buf, end + 1), "utf8");
  var signatures = [];
  var lines = rest.length === 0 ? [] : _split(rest, "\n");
  /** @internal A note ends with a newline, so the split leaves one empty tail element; anything
   *  else after it is a line the format does not have. The drop goes through the capture: dispatching
   *  through `Array.prototype.pop` let a replacement pop TWICE, taking the last signature line with the
   *  tail element, and a forged signature under a known key was then never checked. */
  if (lines.length > 0 && lines[lines.length - 1] === "") _pop(lines);
  else if (lines.length > 0) throw _err("tlog/bad-note", "a note's last signature line ends with a newline");
  if (lines.length > constants.LIMITS.TLOG_MAX_SIGNATURES) {
    throw _err("tlog/bad-note", lines.length + " signature lines exceeds the cap " +
      constants.LIMITS.TLOG_MAX_SIGNATURES);
  }
  for (var i = 0; i < lines.length; i++) {
    _push(signatures, _parseSignatureLine(lines[i]));
  }
  return {
    text: _bufToString(signedBytes, "utf8"),
    signedBytes: signedBytes,
    signatures: signatures,
  };
}

/** @internal One signature line: the em-dash prefix, a key name with no space in it, a space, and
 *  canonical base64 whose first four bytes are the key ID. */
function _parseSignatureLine(line) {
  if (_strIndexOf(line, SIG_LINE_PREFIX) !== 0) {
    throw _err("tlog/bad-note", "a signature line begins with an em dash and a space");
  }
  var body = _strSlice(line, SIG_LINE_PREFIX.length);
  var space = _strIndexOf(body, " ");
  if (space <= 0 || space === body.length - 1) {
    throw _err("tlog/bad-note", "a signature line is an em dash, a space, a key name, a space, and base64");
  }
  var name = _strSlice(body, 0, space);
  var encoded = _strSlice(body, space + 1);
  if (_strIndexOf(encoded, " ") !== -1) {
    throw _err("tlog/bad-note", "a signature line carries one key name and one base64 field");
  }
  var raw = _base64(encoded, "a signature");
  if (raw.length <= KEY_ID_BYTES) {
    throw _err("tlog/bad-note", "a signature carries a " + KEY_ID_BYTES +
      "-byte key id and a signature after it, got " + raw.length + " bytes");
  }
  return {
    keyName: name,
    keyId: _subarray(raw, 0, KEY_ID_BYTES),
    signature: _subarray(raw, KEY_ID_BYTES),
  };
}

/**
 * @primitive  pki.tlog.verifyNote
 * @signature  pki.tlog.verifyNote(input, keys) -> Promise<{ verified, signers, note }>
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP signed-note, RFC 8032
 * @defends    signature-bypass (CWE-347)
 * @related    pki.tlog.parseNote, pki.tlog.verifyCheckpoint
 *
 * Verify a signed note against a list of `{ name, publicKey }` keys, where `publicKey` is the raw
 * 32 Ed25519 bytes or a SubjectPublicKeyInfo for any algorithm `pki.tlog.keyId` derives an ID for.
 * Resolves `{ verified, signers, note }`: `signers` is one entry per signature that verified under a
 * supplied key, and `verified` is whether there was at least one.
 *
 * The specification states two separate rules about failure and this draws the line between them:
 *
 * - A signature from a key not in the list is **ignored**, which is what a verifier must do with a
 *   co-signature it does not know. It carries no claim to check.
 * - A note carrying no signature from a supplied key resolves **`verified: false`** without
 *   throwing, because that is a verdict about the note and not a fault in it.
 * - A signature line naming a supplied key by BOTH name and ID, which no such key verifies,
 *   **rejects the whole note** with `tlog/bad-signature`. Reporting another line's success instead
 *   would let a forged line from a known signer pass unnoticed behind a valid one.
 *
 * Every supplied key whose ID matches is tried before that refusal. A key ID is four bytes and
 * identifies rather than proves, so stopping at the first candidate would reject a note a later key
 * with the same ID verifies.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var raw = pki.asn1.decode(await pki.key.export(pair.publicKey)).children[1].content.subarray(1);
 *   var text = "example.com/log\n0\n" + pki.merkle.emptyRootHash().toString("base64") + "\n";
 *   var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey,
 *     Buffer.from(text, "utf8")));
 *   var line = String.fromCharCode(0x2014) + " example.com/log " +
 *     Buffer.concat([pki.tlog.keyId("example.com/log", raw), sig]).toString("base64");
 *   var v = await pki.tlog.verifyNote(text + "\n" + line + "\n",
 *     [{ name: "example.com/log", publicKey: raw }]);
 *   v.verified;   // -> true
 */
async function verifyNote(input, keys) {
  /** @internal Each caller key's `name` and `publicKey` are read ONCE, into the candidate the rest of this
   *  function uses. They were read by the validator, again to resolve the key, and again to record the
   *  candidate's name, and a member reached through an accessor answers every read separately: the name the
   *  identifier was derived under need not be the name a signature line is matched against. `_resolveKey`
   *  copies the key bytes, so what the candidate holds cannot change afterwards either. */
  if (!_isArray(keys)) throw _err("tlog/bad-input", "keys must be an array");
  /** @internal The note is copied BEFORE any key record is read. A key's `name` or `publicKey` reached
   *  through an accessor runs while the caller's buffer is still the caller's, and it can overwrite the
   *  note with another one: the verdict then reports on a document that was not the argument. Measured,
   *  a getter that copied a validly signed note over an invalidly signed one turned `tlog/bad-signature`
   *  into `verified`. Reading each key once bounds what a key can say about ITSELF and says nothing
   *  about what reading it can do to the subject, so the subject is taken first. */
  var noteBytes = _bytesSnapshot(input, "note", constants.LIMITS.TLOG_MAX_NOTE_BYTES);
  var candidates = [];
  for (var k = 0; k < keys.length; k++) {
    var entry = keys[k];
    if (entry === null || typeof entry !== "object") throw _err("tlog/bad-input", "each key is an object");
    var kName = entry.name, kPublic = entry.publicKey;
    if (typeof kName !== "string" || kName.length === 0) {
      throw _err("tlog/bad-input", "each key carries a non-empty name");
    }
    if (kPublic === undefined || kPublic === null) {
      throw _err("tlog/bad-input", "each key carries a publicKey");
    }
    var resolved = _resolveKey(kName, kPublic);
    _push(candidates, { name: kName, resolved: resolved, id: resolved.id });
  }
  /** @internal Parsed from the snapshot taken above, so the signed range this holds cannot change under
   *  the key import the verification awaits. */
  var note = parseNote(noteBytes);
  var signers = [];
  for (var s = 0; s < note.signatures.length; s++) {
    var sig = note.signatures[s];
    var matched = false, lineVerified = false;
    for (var c = 0; c < candidates.length; c++) {
      var cand = candidates[c];
      if (cand.name !== sig.keyName || _bufferCompare(cand.id, sig.keyId) !== 0) continue;
      /** @internal Every matching candidate is tried rather than the first: a four-byte id can be
       *  shared, and reporting the first one's failure would refuse a note a later key signed. */
      matched = true;
      if (await _verifyUnder(cand.resolved, sig.signature, note.signedBytes)) { lineVerified = true; break; }
    }
    /** @internal A line naming a key the caller supplied, by BOTH name and id, that no such key
     *  verifies rejects the whole note. Skipping it and reporting another line's success would let a
     *  forged line from a known signer pass unnoticed behind a valid one. A line naming a key the
     *  caller did not supply is ignored, which is a different case: it carries no claim to check. */
    if (matched && !lineVerified) {
      throw _err("tlog/bad-signature", "the note carries a signature from " +
        guard.text.showValue(sig.keyName) + " with a matching key id that does not verify");
    }
    if (lineVerified) _push(signers, { keyName: sig.keyName, keyId: sig.keyId });
  }
  return guard.verdict.of({ verified: signers.length > 0, signers: signers, note: note });
}

/** @internal An Ed25519 verify over the raw public key, which the engine takes as a
 *  SubjectPublicKeyInfo: the 12 bytes below are the fixed header of an Ed25519 one, so the key
 *  becomes an SPKI by concatenation, with no builder involved.
 *
 *  An import failure is NOT caught. A key the caller supplied that does not import is a caller
 *  fault, and turning it into `false` would report "this note is not signed by you" for a key that
 *  was never usable. Only the verify itself answers false, which is a verdict about the signature. */
var ED25519_SPKI_PREFIX = _bufferFrom([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
var ED25519_CRV = 6;
var ED25519_ALG = _assign(_create(null), { name: "Ed25519" });
/** @internal The verify for a resolved key, under the algorithm its material named. An ECDSA
 *  signature is DER, which is what a log writes, and the digest comes from the signature TYPE rather
 *  than from the curve, so a P-384 and a P-521 log key are both checked with SHA-256. */
async function _verifyUnder(resolved, signature, message) {
  if (resolved.type === ED25519_ALG_ID) return await _verifyEd25519(resolved.raw, signature, message);
  if (resolved.type === ECDSA_ALG_ID) {
    return guard.crypto.verify(resolved.hash, message, { key: resolved.key, dsaEncoding: "der" }, signature);
  }
  return guard.crypto.verify(resolved.hash, message, resolved.key, signature);
}

async function _verifyEd25519(raw, signature, message) {
  var spki = _bufferConcat([ED25519_SPKI_PREFIX, raw]);
  /** @internal The shared Edwards-point gate runs before the key reaches a verify. Node imports a
   *  low-order key without complaint and such a key verifies a FORGED signature, so a caller whose
   *  trusted key list picked one up would have every note verify under it. */
  edwardsPoint.validateSpki(spki, ED25519_CRV, TlogError, "tlog/bad-input");
  var key;
  try {
    key = await _subtleImportKey(subtle, "spki", spki, ED25519_ALG, true, ["verify"]);
  } catch (e) {
    throw _err("tlog/bad-input", "a supplied publicKey is not an Ed25519 key", e);
  }
  return await _subtleVerify(subtle, ED25519_ALG, key, signature, message);
}

/**
 * @primitive  pki.tlog.parseCheckpoint
 * @signature  pki.tlog.parseCheckpoint(input) -> { origin, treeSize, rootHash, extensions, note }
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-checkpoint, RFC 6962
 * @related    pki.tlog.verifyCheckpoint, pki.merkle.verifyInclusion
 *
 * Read the checkpoint a log signed into a note: the `origin` that names the log, the `treeSize` as
 * a `BigInt`, the 32-byte `rootHash` ready for `pki.merkle`, any opaque `extensions`, and the
 * `note` beneath, whose `signedBytes` remain reachable for verification.
 *
 * The origin is not validated as a URL. The specification recommends a schema-less one and then
 * says outright that a client must not assume the origin follows that shape or names a reachable
 * endpoint, so only an empty origin is refused.
 *
 * A tree size with a leading zero, a root hash that is not 32 bytes, an empty extension line, or a
 * body of fewer than three lines is refused with `tlog/bad-checkpoint`.
 *
 * @example
 *   var DASH = String.fromCharCode(0x2014);
 *   var checkpointText = "example.com/log\n5\n" + Buffer.alloc(32, 1).toString("base64") + "\n" +
 *     "\n" + DASH + " example.com/log " + Buffer.alloc(68).toString("base64") + "\n";
 *   var cp = pki.tlog.parseCheckpoint(checkpointText);
 *   cp.treeSize;           // -> 5n
 *   cp.rootHash.length;    // -> 32, ready for pki.merkle.verifyInclusion
 */
function parseCheckpoint(input) {
  var note = parseNote(input);
  var text = note.text;
  /** @internal The text ends with a newline, so the split leaves an empty tail that is not a line. */
  var lines = _split(text, "\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") _pop(lines);
  if (lines.length < MIN_CHECKPOINT_LINES) {
    throw _err("tlog/bad-checkpoint", "a checkpoint body is an origin, a tree size and a root hash, got " +
      lines.length + " line(s)");
  }
  var origin = lines[0];
  if (origin.length === 0) throw _err("tlog/bad-checkpoint", "the origin line is non-empty");
  var treeSize = _decimal(lines[1], "the tree size", "tlog/bad-checkpoint");
  var rootHash;
  try { rootHash = _base64(lines[2], "the root hash"); }
  catch (e) { throw _err("tlog/bad-checkpoint", "the root hash is not canonical base64", e); }
  if (rootHash.length !== SHA256_BYTES) {
    throw _err("tlog/bad-checkpoint", "the root hash is " + SHA256_BYTES + " bytes, got " + rootHash.length);
  }
  var extensions = _arrSlice(lines, MIN_CHECKPOINT_LINES);
  if (extensions.length > constants.LIMITS.TLOG_MAX_EXTENSION_LINES) {
    throw _err("tlog/bad-checkpoint", extensions.length + " extension lines exceeds the cap " +
      constants.LIMITS.TLOG_MAX_EXTENSION_LINES);
  }
  /** @internal "Extension lines, if any, MUST be non-empty." A note's text is separated from its
   *  signatures at the LAST empty line, so an empty line where an extension would sit is inside the
   *  text and reaches here as an empty extension. Reading it as one would let a checkpoint carry a
   *  line the specification forbids. */
  for (var x = 0; x < extensions.length; x++) {
    if (extensions[x].length === 0) {
      throw _err("tlog/bad-checkpoint", "extension line " + (x + 1) + " is empty, and an extension " +
        "line must not be");
    }
  }
  return { origin: origin, treeSize: treeSize, rootHash: rootHash, extensions: extensions, note: note };
}

/**
 * @primitive  pki.tlog.verifyCheckpoint
 * @signature  pki.tlog.verifyCheckpoint(input, keys, opts?) -> Promise<{ verified, signers, checkpoint }>
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-checkpoint
 * @defends    signature-bypass (CWE-347)
 * @related    pki.tlog.verifyNote, pki.merkle.verifyInclusion
 *
 * Verify a checkpoint's signatures and read its body in one call: `pki.tlog.verifyNote` over the
 * note, and `pki.tlog.parseCheckpoint` over the text it signed. A `verified: false` result still
 * carries the parsed `checkpoint`, since a caller auditing a log needs to see what was claimed.
 *
 * The root hash it returns is what `pki.merkle.verifyInclusion` checks a proof against, and that is
 * the whole point of the pairing: a proof against an unverified root proves nothing.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var raw = pki.asn1.decode(await pki.key.export(pair.publicKey)).children[1].content.subarray(1);
 *   var leaves = [pki.merkle.leafHash(Buffer.from("a")), pki.merkle.leafHash(Buffer.from("b"))];
 *   var body = "example.com/log\n2\n" +
 *     pki.merkle.nodeHash(leaves[0], leaves[1]).toString("base64") + "\n";
 *   var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey,
 *     Buffer.from(body, "utf8")));
 *   var note = body + "\n" + String.fromCharCode(0x2014) + " example.com/log " +
 *     Buffer.concat([pki.tlog.keyId("example.com/log", raw), sig]).toString("base64") + "\n";
 *   var v = await pki.tlog.verifyCheckpoint(note, [{ name: "example.com/log", publicKey: raw }]);
 *   v.verified && pki.merkle.verifyInclusion({ leafHash: leaves[0], leafIndex: 0n,
 *     treeSize: v.checkpoint.treeSize, rootHash: v.checkpoint.rootHash, proof: [leaves[1]] });
 *   // -> true
 */
var _CHECKPOINT_OPTS = _assign(_create(null), { origin: 1 });
async function verifyCheckpoint(input, keys, opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _CHECKPOINT_OPTS, _err,
    "tlog/bad-input", "unknown verifyCheckpoint option ");
  /** @internal ONE read of the caller's input, shared by the decode and the verification below. Reading
   *  it twice let the checkpoint be decoded from one document and its signature checked over another,
   *  since the verification awaits a key import and the caller's buffer can change in that window. */
  var bytes = _bytesSnapshot(input, "note", constants.LIMITS.TLOG_MAX_NOTE_BYTES);
  var checkpoint = parseCheckpoint(bytes);
  /** @internal ONE read of the pinned origin, which the checks and the comparison both read. An accessor
   *  answers every read separately, and this was read four times: whether it was supplied, its type, its
   *  length, and the comparison. A getter could therefore pass all three checks as one value and be
   *  compared as another, so the origin the caller pinned was not the origin enforced and the verdict
   *  reported a match against a log the checkpoint does not name. */
  var expectedOrigin = opts.origin;
  if (expectedOrigin !== undefined) {
    if (typeof expectedOrigin !== "string" || expectedOrigin.length === 0) {
      throw _err("tlog/bad-input", "opts.origin must be a non-empty string");
    }
    /** @internal A valid signature from one log over its own tree is not evidence about another
     *  log's tree, and with more than one log pinned that is the whole difference. The expected
     *  origin is the caller's value and never the key name off the signature line: a Rekor v1 origin
     *  appends the tree ID after a space, which a key name may not contain, so reading one from the
     *  other would refuse every v1 checkpoint. */
    if (checkpoint.origin !== expectedOrigin) {
      throw _err("tlog/origin-mismatch", "the checkpoint states origin " +
        guard.text.showValue(checkpoint.origin) + " where the caller pinned " +
        guard.text.showValue(expectedOrigin));
    }
  }
  var v = await verifyNote(bytes, keys);
  return guard.verdict.of({ verified: v.verified, signers: v.signers, checkpoint: checkpoint });
}

/**
 * @primitive  pki.tlog.parseVkey
 * @signature  pki.tlog.parseVkey(text) -> { name, keyId, signatureType, publicKey }
 * @since      0.8.37
 * @status     stable
 * @spec       C2SP signed-note
 * @related    pki.tlog.keyId, pki.tlog.verifyNote
 *
 * Read the verifier-key text form a log publishes to identify itself,
 * `<name>+<hex key ID>+<base64 of signature type || public key>`, as in
 * `example.com/foo+530d903a+Aeky...`. Returns the name, the four-byte `keyId`, the `signatureType`
 * byte, and the `publicKey`: the raw 32 bytes for Ed25519, or the SubjectPublicKeyInfo for ECDSA and
 * RSA. The `publicKey` is what `verifyNote` takes for that key.
 *
 * The stated key ID is checked against the one the key material derives, and the stated signature
 * type against the algorithm that material actually is, so a vkey cannot name a key it does not
 * carry or claim an algorithm its key is not. A key name may not contain a plus, so the name ends at
 * the first separator; a text with three of them is refused rather than read as a name containing
 * one.
 *
 * @example
 *   var v = pki.tlog.parseVkey("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k");
 *   v.name;                        // "example.com/foo"
 *   v.keyId.toString("hex");       // "530d903a"
 *   v.signatureType;               // 1
 */
function parseVkey(text) {
  if (typeof text !== "string" || text.length === 0) {
    throw _err("tlog/bad-input", "a verifier key is a non-empty string");
  }
  var first = _strIndexOf(text, "+");
  if (first <= 0) {
    throw _err("tlog/bad-input", "a verifier key is <name>+<hex key id>+<base64 key>, and the name " +
      "must be non-empty");
  }
  var second = _strIndexOf(text, "+", first + 1);
  if (second < 0) throw _err("tlog/bad-input", "a verifier key carries two plus separators");
  /** @internal Only the FIRST TWO pluses are separators, and a later one belongs to the key material:
   *  standard base64's alphabet includes `+`, and a 44-character Ed25519 blob carries one more often than
   *  not, so refusing a third plus rejects most real verifier keys. A name containing a plus is still
   *  unparseable, which is what the format requires: everything between the first two separators has to
   *  be the eight hex digits of a key ID, and a name fragment is not. The blob is left to the base64
   *  decoder, which is what decides whether the remaining field is well formed. */
  var name = _strSlice(text, 0, first);
  var hexId = _strSlice(text, first + 1, second);
  var blobText = _strSlice(text, second + 1);
  if (hexId.length !== KEY_ID_BYTES * 2) {
    throw _err("tlog/bad-input", "a verifier key states its key ID as " + (KEY_ID_BYTES * 2) +
      " hex digits, got " + hexId.length);
  }
  var stated = guard.encoding.hex(hexId, KEY_ID_BYTES, _err, "tlog/bad-input", "the stated key ID");
  if (blobText.length === 0) throw _err("tlog/bad-input", "a verifier key carries key material");
  var blob = guard.encoding.base64(blobText, constants.LIMITS.TLOG_MAX_NOTE_BYTES, _err,
    "tlog/bad-input", "the verifier key material");
  if (blob.length < 2) throw _err("tlog/bad-input", "a verifier key is a signature type byte then a key");
  var type = blob[0];
  var publicKey = _subarray(blob, 1);
  var resolved = _resolveKey(name, publicKey);
  if (resolved.type !== type) {
    throw _err("tlog/bad-input", "the verifier key states signature type " + type +
      " where its key material is type " + resolved.type);
  }
  if (_bufferCompare(resolved.id, stated) !== 0) {
    throw _err("tlog/bad-input", "the verifier key states key ID " + _bufToString(stated, "hex") +
      " where its own key material derives " + _bufToString(resolved.id, "hex"));
  }
  return { name: name, keyId: resolved.id, signatureType: type, publicKey: publicKey };
}

function _assertLevel(level) {
  if (typeof level !== "number" || !_isInteger(level) || level < 0 || level > TILE_MAX_LEVEL) {
    throw _err("tlog/bad-tile", "a tile level is an integer 0 to " + TILE_MAX_LEVEL + ", got " + level);
  }
}

function _assertWidth(width) {
  if (width === undefined || width === null) return null;
  if (typeof width !== "number" || !_isInteger(width) || width < 1 || width > TILE_HEIGHT_HASHES - 1) {
    throw _err("tlog/bad-tile", "a partial tile width is an integer 1 to " + (TILE_HEIGHT_HASHES - 1) +
      ", got " + width);
  }
  return width;
}

/** @internal The index path: zero-padded three-digit segments, every one but the last carrying an
 *  `x`. The specification's own example is 1234067 -> x001/x234/067. Built from the low digits up,
 *  so an index of any size produces the right number of segments. */
/** @internal How many three-digit segments the largest index a writer emits occupies, DERIVED from the
 *  writer itself rather than written down: a uint64 index is at most 20 decimal digits, and the segments
 *  carry three each. Deriving it means the reader's bound cannot drift from the writer's range. */
var MAX_INDEX_SEGMENTS = (function () {
  var n = 18446744073709551615n, count = 1;
  while (n >= 1000n) { n = n / 1000n; count += 1; }
  return count;
})();

function _indexPath(index) {
  var n = guard.range.uint64(index, _err, "tlog/bad-tile", "a tile index");
  var segments = [];
  var rest = n;
  var thousand = 1000n;
  for (;;) {
    var part = rest % thousand;
    var text = _stringOf(part);
    while (text.length < TILE_SEGMENT_DIGITS) text = "0" + text;
    _unshift(segments, text);
    rest = rest / thousand;
    if (rest === 0n) break;
  }
  for (var i = 0; i < segments.length - 1; i++) segments[i] = "x" + segments[i];
  return _join(segments, "/");
}

/**
 * @primitive  pki.tlog.tilePath
 * @signature  pki.tlog.tilePath(level, index, width?) -> string
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @related    pki.tlog.parseTilePath, pki.tlog.entryBundlePath
 *
 * The path a tiled log serves one Merkle tile at, relative to the log's prefix:
 * `tile/<level>/<index>` with the index in zero-padded three-digit segments, every one but the last
 * carrying an `x`. A `width` of 1 to 255 appends the `.p/<width>` suffix a partial tile has.
 *
 * The segmented form is what lets a log hold its tiles in a filesystem without a directory and a
 * file colliding on one name.
 *
 * @example
 *   pki.tlog.tilePath(0, 1234067n);      // "tile/0/x001/x234/067"
 *   pki.tlog.tilePath(0, 1234067n, 42);  // "tile/0/x001/x234/067.p/42"
 */
function tilePath(level, index, width) {
  _assertLevel(level);
  var w = _assertWidth(width);
  return "tile/" + level + "/" + _indexPath(index) + (w === null ? "" : ".p/" + w);
}

/**
 * @primitive  pki.tlog.entryBundlePath
 * @signature  pki.tlog.entryBundlePath(index, width?) -> string
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @related    pki.tlog.parseEntryBundle
 *
 * The path a tiled log serves one entry bundle at: `tile/entries/<index>`, with the same segmented
 * index and `.p/<width>` suffix a tile path uses. The bundle holds the entries whose leaf hashes
 * are the level-0 tile at the same index.
 *
 * @example
 *   pki.tlog.entryBundlePath(1234067n);   // "tile/entries/x001/x234/067"
 */
function entryBundlePath(index, width) {
  var w = _assertWidth(width);
  return "tile/entries/" + _indexPath(index) + (w === null ? "" : ".p/" + w);
}

/**
 * @primitive  pki.tlog.checkpointPath
 * @signature  pki.tlog.checkpointPath() -> string
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @related    pki.tlog.verifyCheckpoint
 *
 * The path a tiled log serves its checkpoint at, relative to the log's prefix. Fixed by the
 * specification, and given as a verb so a caller composes a URL without writing the literal.
 *
 * @example
 *   pki.tlog.checkpointPath();   // "checkpoint"
 */
function checkpointPath() { return "checkpoint"; }

/** @internal Three ASCII digits, optionally behind an `x`. Scanned by character code, not
 *  matched, and the `x` is required on every segment but the last. */
function _segmentDigits(segment, expectX) {
  var body = segment;
  if (expectX) {
    if (_charCodeAt(body, 0) !== 0x78) throw _err("tlog/bad-tile", "a leading index segment begins with x");
    body = _strSlice(body, 1);
  } else if (_charCodeAt(segment, 0) === 0x78) {
    throw _err("tlog/bad-tile", "the final index segment carries no x prefix");
  }
  if (body.length !== TILE_SEGMENT_DIGITS) {
    throw _err("tlog/bad-tile", "an index segment is " + TILE_SEGMENT_DIGITS + " digits, got " +
      _jsonStringify(segment));
  }
  for (var i = 0; i < body.length; i++) {
    var c = _charCodeAt(body, i);
    if (c < 0x30 || c > 0x39) throw _err("tlog/bad-tile", "an index segment is digits, got " + _jsonStringify(segment));
  }
  return _bigIntOf(body);
}

/**
 * @primitive  pki.tlog.parseTilePath
 * @signature  pki.tlog.parseTilePath(path) -> { level, index, width }
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @related    pki.tlog.tilePath
 *
 * Read a tile path back into its `level`, its `index` as a `BigInt`, and its `width`, which is
 * `null` for a full tile. The inverse of `pki.tlog.tilePath`.
 *
 * Fail-closed on every shape the specification forbids: a level with a leading zero or above 63, a
 * segment that is not three digits, a leading segment without its `x`, a final segment with one, or
 * a partial width outside 1 to 255.
 *
 * @example
 *   pki.tlog.parseTilePath("tile/0/x001/x234/067.p/42");
 *   // { level: 0, index: 1234067n, width: 42 }
 */
function parseTilePath(path) {
  if (typeof path !== "string") throw _err("tlog/bad-input", "a tile path is a string");
  var parts = _split(path, "/");
  if (parts.length < 3 || parts[0] !== "tile") {
    throw _err("tlog/bad-tile", "a tile path begins tile/<level>/<index>");
  }
  var width = null;
  /** @internal The partial suffix is its own two segments: ".p" attached to the final index
   *  segment, then the width. Reading it off the tail first leaves a clean index to walk. */
  var tailSeg = parts.length >= 2 ? parts[parts.length - 2] : "";
  if (parts.length >= 2 && _strIndexOf(tailSeg, ".p") === tailSeg.length - 2 && tailSeg.length > 2) {
    var widthText = parts[parts.length - 1];
    width = _numberOf(_decimal(widthText, "a partial tile width", "tlog/bad-tile"));
    _assertWidth(width);
    parts = _arrSlice(parts, 0, parts.length - 1);
    parts[parts.length - 1] = _strSlice(parts[parts.length - 1], 0, -2);
  }
  var levelText = parts[1];
  var level = _numberOf(_decimal(levelText, "a tile level", "tlog/bad-tile"));
  _assertLevel(level);
  var segments = _arrSlice(parts, 2);
  if (segments.length === 0) throw _err("tlog/bad-tile", "a tile path carries an index");
  /** @internal The reader is bounded to the range the writer emits. `_indexPath` holds an index to
   *  uint64, so the widest path a writer can produce has MAX_INDEX_SEGMENTS segments; accepting more both
   *  admits an index no writer could emit and multiplies an ever-growing BigInt once per segment, so a
   *  long untrusted path becomes superlinear synchronous work. The count is checked BEFORE the loop, so
   *  the work a hostile path can ask for is bounded rather than merely rejected afterwards. */
  if (segments.length > MAX_INDEX_SEGMENTS) {
    throw _err("tlog/bad-tile", "a tile path carries at most " + MAX_INDEX_SEGMENTS +
      " index segments, which is what a uint64 index occupies; this one has " + segments.length);
  }
  var index = 0n;
  for (var i = 0; i < segments.length; i++) {
    index = index * 1000n + _segmentDigits(segments[i], i < segments.length - 1);
  }
  /** @internal And the value itself, since the segment count allows a little more than uint64 does. */
  guard.range.uint64(index, _err, "tlog/bad-tile", "a tile index");
  return { level: level, index: index, width: width };
}

/**
 * @primitive  pki.tlog.parseTile
 * @signature  pki.tlog.parseTile(bytes, opts?) -> Buffer[]
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @related    pki.tlog.parseTilePath, pki.merkle.nodeHash
 *
 * Split a tile into its 32-byte hashes. A full tile is exactly 256 of them, 8192 bytes; a partial
 * tile carries 1 to 255. Bytes that are not a whole number of hashes, or more than a full tile, are
 * refused with `tlog/bad-tile`.
 *
 * A tile is binary. A string is refused with `tlog/bad-input` rather than decoded, because reading
 * a response as text rewrites every byte above 0x7f.
 *
 * Pass `opts.full` when the caller asked the log for a full tile: a short answer is then refused
 * and is not read as a partial one, which is the difference between a truncated response and a
 * tile the log meant to serve.
 *
 * @example
 *   var tileBytes = Buffer.concat([pki.merkle.leafHash(Buffer.from("a")),
 *     pki.merkle.leafHash(Buffer.from("b"))]);
 *   var hashes = pki.tlog.parseTile(tileBytes);
 *   hashes.length;      // -> 2, a partial tile; a full one holds 256
 *   hashes[0].length;   // -> 32
 */
function parseTile(bytes, opts) {
  var buf = _binary(bytes, "a tile", TILE_HEIGHT_HASHES * SHA256_BYTES, "tlog/bad-tile");
  if (buf.length === 0) throw _err("tlog/bad-tile", "a tile carries at least one hash");
  if (buf.length % SHA256_BYTES !== 0) {
    throw _err("tlog/bad-tile", "a tile is a whole number of " + SHA256_BYTES + "-byte hashes, got " +
      buf.length + " bytes");
  }
  var count = buf.length / SHA256_BYTES;
  if (count > TILE_HEIGHT_HASHES) {
    throw _err("tlog/bad-tile", "a tile is at most " + TILE_HEIGHT_HASHES + " hashes, got " + count);
  }
  if (opts && opts.full === true && count !== TILE_HEIGHT_HASHES) {
    throw _err("tlog/bad-tile", "a full tile is exactly " + TILE_HEIGHT_HASHES + " hashes, got " + count);
  }
  var out = [];
  for (var i = 0; i < count; i++) _push(out, _subarray(buf, i * SHA256_BYTES, (i + 1) * SHA256_BYTES));
  return out;
}

/**
 * @primitive  pki.tlog.parseEntryBundle
 * @signature  pki.tlog.parseEntryBundle(bytes) -> Buffer[]
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @defends    parser-DoS (CWE-400)
 * @related    pki.tlog.entryBundlePath, pki.merkle.leafHash
 *
 * Split an entry bundle into its entries. The wire form is big-endian uint16 length-prefixed
 * entries, and each entry's `pki.merkle.leafHash` is the corresponding hash in the level-0 tile at
 * the same index, which is what makes a bundle checkable against the tree.
 *
 * A length prefix that overruns the buffer, or a trailing byte that is not a whole prefix, is
 * refused with `tlog/bad-bundle` rather than read as a short final entry. An empty bundle is an
 * empty list.
 *
 * @example
 *   var first = Buffer.from("the first entry");
 *   var len = Buffer.alloc(2);
 *   len.writeUInt16BE(first.length, 0);
 *   var entries = pki.tlog.parseEntryBundle(Buffer.concat([len, first]));
 *   entries[0].toString();                                       // -> "the first entry"
 *   pki.merkle.leafHash(entries[0]).equals(pki.merkle.leafHash(first));   // -> true
 */
function parseEntryBundle(bytes) {
  var buf = _binary(bytes, "an entry bundle", constants.LIMITS.TLOG_MAX_ENTRY_BUNDLE_BYTES, "tlog/bad-input");
  var out = [];
  var p = 0;
  while (p < buf.length) {
    if (p + 2 > buf.length) {
      throw _err("tlog/bad-bundle", "a trailing byte at offset " + p + " is not a whole length prefix");
    }
    /** @internal The length prefix comes from the capture. It decides where this entry ends and the
     *  next begins, so a replaced reader hands the bounds check below a length the bundle does not
     *  state and the entry that is parsed is a different run of bytes. */
    var len = intrinsic.readUInt16BE(buf, p);
    p += 2;
    if (p + len > buf.length) {
      throw _err("tlog/bad-bundle", "the entry at offset " + (p - 2) + " declares " + len +
        " bytes and " + (buf.length - p) + " remain");
    }
    /** @internal The COUNT is capped, not only the byte length. A zero-length entry costs two bytes on the
     *  wire and an object in memory, so the byte cap alone admits half a million of them from a megabyte. */
    if (out.length >= constants.LIMITS.TLOG_MAX_ENTRY_BUNDLE_ENTRIES) {
      throw _err("tlog/bad-bundle", "an entry bundle carries at most " +
        constants.LIMITS.TLOG_MAX_ENTRY_BUNDLE_ENTRIES + " entries, one tile's width (C2SP tlog-tiles)");
    }
    _push(out, _subarray(buf, p, p + len));
    p += len;
  }
  return out;
}

/**
 * @primitive  pki.tlog.tileWidth
 * @signature  pki.tlog.tileWidth(treeSize, level, index) -> number | null
 * @since      0.8.36
 * @status     stable
 * @spec       C2SP tlog-tiles
 * @related    pki.tlog.tilePath, pki.tlog.inclusionProof
 *
 * How wide the tile at `level` and `index` is in a tree of `treeSize` leaves: `null` when it is
 * full, which is the form `tilePath` takes for a full tile, or 1 to 255 when it is partial. The two
 * compose directly, so `tilePath(l, i, tileWidth(size, l, i))` is the path the log serves.
 *
 * A client has to know this before it asks. A tiled log serves a full tile and a partial tile at
 * different paths, so requesting the full path for a tile that is partial is a request for a
 * resource the log does not have.
 *
 * A tile the tree does not reach is `tlog/bad-tile` rather than a width of zero: the specification
 * says empty tiles must not be served, so there is no path to build.
 *
 * @example
 *   pki.tlog.tileWidth(300n, 0, 0n);   // null, a full tile
 *   pki.tlog.tileWidth(300n, 0, 1n);   // 44
 */
function tileWidth(treeSize, level, index) {
  var size = guard.range.uint64(treeSize, _err, "tlog/bad-tile", "a tree size");
  _assertLevel(level);
  var n = guard.range.uint64(index, _err, "tlog/bad-tile", "a tile index");
  /** @internal A level-l unit is a COMPLETE subtree of 256**l leaves, so the units that exist at
   *  that level are the whole ones the tree reaches. What the tile holds is however many of its
   *  own 256 units remain. */
  var units = size / (_bigIntOf(TILE_HEIGHT_HASHES) ** _bigIntOf(level));
  var avail = units - n * _bigIntOf(TILE_HEIGHT_HASHES);
  if (avail <= 0n) {
    throw _err("tlog/bad-tile", "a tree of " + size + " leaves has no tile " + n + " at level " +
      level + ", and an empty tile is not served");
  }
  return avail >= _bigIntOf(TILE_HEIGHT_HASHES) ? null : _numberOf(avail);
}

/** @internal One level-l unit hash, read out of the tile that carries it. Tiles are cached for the
 *  life of one assembly: a tile holds 256 unit hashes and an audit path walks neighbors, so reading
 *  per unit would ask the log for the same tile over and over.
 *
 *  The slot check below cannot fire while the width check above it holds: a full tile is held to
 *  exactly 256 hashes and a slot is `unit % 256`, and a partial tile is held to the width the tree
 *  size requires, which is `units - tile * 256` and so is greater than the slot of any unit the
 *  recursion asks for. It is kept because the width and the slot are checked by separate steps, and
 *  a change to either should not turn a short tile into a hash read from the wrong position. */
function _unitReader(size, read) {
  var cache = _create(null);
  return async function (level, unit) {
    var tile = unit / _bigIntOf(TILE_HEIGHT_HASHES);
    var slot = _numberOf(unit % _bigIntOf(TILE_HEIGHT_HASHES));
    var key = level + ":" + tile;
    var hashes = cache[key];
    if (hashes === undefined) {
      var width = tileWidth(size, level, tile);
      var bytes = await read(level, tile, width);
      hashes = parseTile(bytes, { full: width === null });
      if (width !== null && hashes.length !== width) {
        throw _err("tlog/bad-tile", "the tile at level " + level + " index " + tile + " was served " +
          hashes.length + " hashes where the tree size requires " + width);
      }
      cache[key] = hashes;
    }
    if (slot >= hashes.length) {
      throw _err("tlog/bad-tile", "the tile at level " + level + " index " + tile +
        " carries no unit at position " + slot);
    }
    return hashes[slot];
  };
}

/** @internal MTH(D[lo:hi]) with a tile read standing in for a whole subtree. A range that is
 *  exactly one COMPLETE level-l unit is one read; anything else splits at the largest power of two
 *  below its length, which is the RFC 6962 sec. 2.1 shape. Every leaf is a level-0 unit, so the
 *  recursion always terminates on a read. */
async function _subtree(lo, hi, size, unitAt) {
  var n = hi - lo;
  if (hi <= size) {
    var span = 1n, level = 0;
    while (span < n && level < TILE_MAX_LEVEL) { span *= _bigIntOf(TILE_HEIGHT_HASHES); level += 1; }
    if (span === n && lo % n === 0n) return await unitAt(level, lo / n);
  }
  var k = 1n;
  while (k * 2n < n) k *= 2n;
  var left = await _subtree(lo, lo + k, size, unitAt);
  var right = await _subtree(lo + k, hi, size, unitAt);
  return merkle.nodeHash(left, right);
}

/** @internal PATH(m, D[lo:hi]) of RFC 6962 sec. 2.1.1 over the same tile-backed subtrees. */
async function _tilePath(lo, hi, m, size, unitAt) {
  if (hi - lo === 1n) return [];
  var k = 1n;
  while (k * 2n < hi - lo) k *= 2n;
  if (m < k) {
    var a = await _tilePath(lo, lo + k, m, size, unitAt);
    _push(a, await _subtree(lo + k, hi, size, unitAt));
    return a;
  }
  var b = await _tilePath(lo + k, hi, m - k, size, unitAt);
  _push(b, await _subtree(lo, lo + k, size, unitAt));
  return b;
}

/**
 * @primitive  pki.tlog.inclusionProof
 * @signature  pki.tlog.inclusionProof(opts) -> Promise<Buffer[]>
 * @since      0.8.36
 * @status     stable
 * @spec       C2SP tlog-tiles, RFC 6962
 * @related    pki.merkle.verifyInclusion, pki.tlog.tileWidth, pki.tlog.verifyCheckpoint
 *
 * Assemble the RFC 6962 audit path for one leaf of a tiled log. A tiled log serves no proof
 * endpoint, so a client fetches tiles and computes the path itself; this is that computation, with
 * the fetching left to `read`. The returned array is what `pki.merkle.verifyInclusion` folds
 * against the root a verified checkpoint carries.
 *
 * `read(level, index, width)` takes the same three values `tilePath` takes and returns that tile's
 * bytes, or a promise of them, so a caller wires it straight to a fetch of
 * `tilePath(level, index, width)`. Tiles are cached for the life of one call.
 *
 * Take `size` from a checkpoint you have verified. The specification says a client must not fetch
 * arbitrary partial tiles without a checkpoint whose size requires them, and the width of every
 * tile this reads follows from that size.
 *
 * A tile served narrower than the tree size requires is `tlog/bad-tile` rather than a path folded
 * from short data; an `index` at or above `size` is `tlog/index-out-of-range`, refused before any
 * tile is read.
 *
 * @opts
 *   index:  number | bigint,  // 0-based leaf position to prove
 *   size:   number | bigint,  // tree size from a VERIFIED checkpoint
 *   read:   function,         // (level, index, width) -> Buffer | Promise<Buffer>
 *
 * @example
 *   var leaves = [];
 *   for (var i = 0; i < 5; i++) leaves.push(pki.merkle.leafHash(Buffer.from([i])));
 *   var tile = Buffer.concat(leaves);
 *   var proof = await pki.tlog.inclusionProof({ index: 2n, size: 5n,
 *     read: function () { return tile; } });
 *   pki.merkle.verifyInclusion({ leafIndex: 2, treeSize: 5, leafHash: leaves[2],
 *     proof: proof, rootHash: pki.merkle.root(leaves) });   // -> true
 */
var _INCLUSION_PROOF_KEYS = _assign(_create(null), { index: 1, size: 1, read: 1 });
async function inclusionProof(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _INCLUSION_PROOF_KEYS, _err,
    "tlog/bad-input", "unknown inclusionProof option ");
  var size = guard.range.uint64(opts.size, _err, "tlog/bad-input", "size");
  var index = guard.range.uint64(opts.index, _err, "tlog/bad-input", "index");
  /** @internal ONE read of the callback, which the type check and the reader both use. Read twice, the
   *  function held to being a function need not be the function that serves the tiles: an accessor
   *  answers each read separately, so the proof returned would be assembled from a source the check never
   *  saw. */
  var read = opts.read;
  if (typeof read !== "function") throw _err("tlog/bad-input", "read must be a function");
  if (size === 0n) throw _err("tlog/empty-tree", "an empty tree has no leaf to prove");
  if (index >= size) {
    throw _err("tlog/index-out-of-range", "index " + index + " is not less than the tree size " + size);
  }
  return await _tilePath(0n, size, index, size, _unitReader(size, read));
}

module.exports = {
  keyId: keyId,
  parseNote: parseNote,
  verifyNote: verifyNote,
  parseCheckpoint: parseCheckpoint,
  verifyCheckpoint: verifyCheckpoint,
  tilePath: tilePath,
  entryBundlePath: entryBundlePath,
  checkpointPath: checkpointPath,
  parseTilePath: parseTilePath,
  parseTile: parseTile,
  parseEntryBundle: parseEntryBundle,
  tileWidth: tileWidth,
  inclusionProof: inclusionProof,
  parseVkey: parseVkey,
};
