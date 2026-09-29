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

var nodeCrypto = require("node:crypto");
var constants = require("./constants");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var subtle = require("./webcrypto").webcrypto.subtle;
var edwardsPoint = require("./edwards-point");

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
var SIG_LINE_PREFIX = String.fromCharCode(0x2014) + " ";

var LF = 0x0a;

function _bytes(input, field) {
  if (typeof input === "string") return Buffer.from(input, "utf8");
  if (guard.bytes.isByteSource(input)) return guard.bytes.source(input, TlogError, "tlog/bad-input", field);
  throw _err("tlog/bad-input", field + " must be a string or a byte source");
}

/** @internal A note is UTF-8 text carrying no ASCII control byte other than newline. The scan is by
 *  character code, not a pattern, and it runs before anything is split, so a control byte is
 *  refused instead of being carried into a line. */
function _assertNoteText(buf) {
  for (var i = 0; i < buf.length; i++) {
    var c = buf[i];
    if (c < 0x20 && c !== LF) {
      throw _err("tlog/bad-note", "a note carries no ASCII control byte other than newline; found 0x" +
        c.toString(16) + " at offset " + i);
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
 *  tree and is the one value whose first digit may be zero. */
function _decimal(text, field, code) {
  if (text.length === 0) throw _err(code, field + " is empty");
  for (var i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i);
    if (c < 0x30 || c > 0x39) throw _err(code, field + " must be ASCII decimal digits, got " + JSON.stringify(text));
  }
  if (text.length > 1 && text.charCodeAt(0) === 0x30) {
    throw _err(code, field + " must not carry a leading zero, got " + JSON.stringify(text));
  }
  return BigInt(text);
}

/**
 * @primitive  pki.tlog.keyId
 * @signature  pki.tlog.keyId(keyName, publicKey) -> Buffer
 * @since      0.8.33
 * @status     stable
 * @spec       C2SP signed-note
 * @related    pki.tlog.verifyNote
 *
 * The four-byte key ID a signed note carries in front of its signature, derived as
 * `SHA-256(keyName || 0x0A || 0x01 || publicKey)[:4]` for an Ed25519 key, where `publicKey` is the
 * raw 32 bytes, not a SubjectPublicKeyInfo.
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
  if (typeof keyName !== "string" || keyName.length === 0) {
    throw _err("tlog/bad-input", "keyName must be a non-empty string");
  }
  var raw = _bytes(publicKey, "publicKey");
  if (raw.length !== ED25519_RAW_BYTES) {
    throw _err("tlog/bad-input", "publicKey must be the raw " + ED25519_RAW_BYTES +
      " Ed25519 bytes, got " + raw.length);
  }
  var h = nodeCrypto.createHash("sha256")
    .update(Buffer.from(keyName, "utf8"))
    .update(Buffer.from([LF, ED25519_ALG_ID]))
    .update(raw)
    .digest();
  return h.subarray(0, KEY_ID_BYTES);
}

/** @internal The offset one past the text's terminating newline, which is where the blank line
 *  begins. The text runs to the first "\n\n", so the signed range ENDS with that first newline and
 *  the second one opens the signature block. Returns -1 when the note carries no blank line. */
function _textEnd(buf) {
  for (var i = 0; i + 1 < buf.length; i++) {
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
  var buf = _bytes(input, "note");
  if (buf.length > constants.LIMITS.TLOG_MAX_NOTE_BYTES) {
    throw _err("tlog/bad-input", "note " + buf.length + " bytes exceeds the cap " +
      constants.LIMITS.TLOG_MAX_NOTE_BYTES);
  }
  _assertNoteText(buf);
  var end = _textEnd(buf);
  if (end < 0) throw _err("tlog/bad-note", "a note separates its text from its signatures with a blank line");
  var signedBytes = buf.subarray(0, end);
  var rest = buf.subarray(end + 1).toString("utf8");
  var signatures = [];
  var lines = rest.length === 0 ? [] : rest.split("\n");
  /** @internal A note ends with a newline, so the split leaves one empty tail element; anything
   *  else after it is a line the format does not have. */
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  else if (lines.length > 0) throw _err("tlog/bad-note", "a note's last signature line ends with a newline");
  if (lines.length > constants.LIMITS.TLOG_MAX_SIGNATURES) {
    throw _err("tlog/bad-note", lines.length + " signature lines exceeds the cap " +
      constants.LIMITS.TLOG_MAX_SIGNATURES);
  }
  for (var i = 0; i < lines.length; i++) {
    signatures.push(_parseSignatureLine(lines[i]));
  }
  return {
    text: signedBytes.toString("utf8"),
    signedBytes: signedBytes,
    signatures: signatures,
  };
}

/** @internal One signature line: the em-dash prefix, a key name with no space in it, a space, and
 *  canonical base64 whose first four bytes are the key ID. */
function _parseSignatureLine(line) {
  if (line.indexOf(SIG_LINE_PREFIX) !== 0) {
    throw _err("tlog/bad-note", "a signature line begins with an em dash and a space");
  }
  var body = line.slice(SIG_LINE_PREFIX.length);
  var space = body.indexOf(" ");
  if (space <= 0 || space === body.length - 1) {
    throw _err("tlog/bad-note", "a signature line is an em dash, a space, a key name, a space, and base64");
  }
  var name = body.slice(0, space);
  var encoded = body.slice(space + 1);
  if (encoded.indexOf(" ") !== -1) {
    throw _err("tlog/bad-note", "a signature line carries one key name and one base64 field");
  }
  var raw = _base64(encoded, "a signature");
  if (raw.length <= KEY_ID_BYTES) {
    throw _err("tlog/bad-note", "a signature carries a " + KEY_ID_BYTES +
      "-byte key id and a signature after it, got " + raw.length + " bytes");
  }
  return {
    keyName: name,
    keyId: raw.subarray(0, KEY_ID_BYTES),
    signature: raw.subarray(KEY_ID_BYTES),
  };
}

function _assertKeyList(keys) {
  if (!Array.isArray(keys)) throw _err("tlog/bad-input", "keys must be an array");
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (k === null || typeof k !== "object") throw _err("tlog/bad-input", "each key is an object");
    if (typeof k.name !== "string" || k.name.length === 0) {
      throw _err("tlog/bad-input", "each key carries a non-empty name");
    }
    if (k.publicKey === undefined || k.publicKey === null) {
      throw _err("tlog/bad-input", "each key carries a publicKey");
    }
  }
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
 * 32 Ed25519 bytes. Resolves `{ verified, signers, note }`: `signers` is one entry per signature
 * that verified under a supplied key, and `verified` is whether there was at least one.
 *
 * A signature from a key not in the list is ignored, not refused, which is what the
 * specification requires of a verifier meeting a co-signature it does not know. A note carrying no
 * signature from a supplied key resolves `verified: false` and does not throw, because that is a
 * verdict about the note and not a fault in it.
 *
 * Every supplied key whose ID matches is tried. A key ID is four bytes and identifies rather than
 * proves, so stopping at the first candidate would report failure for a note a later key verifies.
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
  _assertKeyList(keys);
  var note = parseNote(input);
  var candidates = [];
  for (var k = 0; k < keys.length; k++) {
    var raw = _bytes(keys[k].publicKey, "publicKey");
    if (raw.length !== ED25519_RAW_BYTES) {
      throw _err("tlog/bad-input", "publicKey must be the raw " + ED25519_RAW_BYTES +
        " Ed25519 bytes, got " + raw.length);
    }
    candidates.push({ name: keys[k].name, raw: raw, id: keyId(keys[k].name, raw) });
  }
  var signers = [];
  for (var s = 0; s < note.signatures.length; s++) {
    var sig = note.signatures[s];
    for (var c = 0; c < candidates.length; c++) {
      var cand = candidates[c];
      if (cand.name !== sig.keyName || Buffer.compare(cand.id, sig.keyId) !== 0) continue;
      /** @internal Every matching candidate is tried rather than the first: a four-byte id can be
       *  shared, and reporting the first one's failure would refuse a note a later key signed. */
      var ok = await _verifyEd25519(cand.raw, sig.signature, note.signedBytes);
      if (ok) { signers.push({ keyName: sig.keyName, keyId: sig.keyId }); break; }
    }
  }
  return { verified: signers.length > 0, signers: signers, note: note };
}

/** @internal An Ed25519 verify over the raw public key, which the engine takes as a
 *  SubjectPublicKeyInfo: the 12 bytes below are the fixed header of an Ed25519 one, so the key
 *  becomes an SPKI by concatenation, with no builder involved.
 *
 *  An import failure is NOT caught. A key the caller supplied that does not import is a caller
 *  fault, and turning it into `false` would report "this note is not signed by you" for a key that
 *  was never usable. Only the verify itself answers false, which is a verdict about the signature. */
var ED25519_SPKI_PREFIX = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
var ED25519_CRV = 6;
var ED25519_ALG = Object.assign(Object.create(null), { name: "Ed25519" });
async function _verifyEd25519(raw, signature, message) {
  var spki = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  /** @internal The shared Edwards-point gate runs before the key reaches a verify. Node imports a
   *  low-order key without complaint and such a key verifies a FORGED signature, so a caller whose
   *  trusted key list picked one up would have every note verify under it. */
  edwardsPoint.validateSpki(spki, ED25519_CRV, TlogError, "tlog/bad-input");
  var key;
  try {
    key = await subtle.importKey("spki", spki, ED25519_ALG, true, ["verify"]);
  } catch (e) {
    throw _err("tlog/bad-input", "a supplied publicKey is not an Ed25519 key", e);
  }
  return await subtle.verify(ED25519_ALG, key, signature, message);
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
  var lines = text.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
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
  /** @internal The specification requires a non-empty extension line, and the note framing already
   *  guarantees it: the text ends at the first blank line, so a blank line where an extension would
   *  be terminates the body instead, and what follows is read as a signature line and refused. There
   *  is no check here because there is no input that would reach one. */
  var extensions = lines.slice(MIN_CHECKPOINT_LINES);
  if (extensions.length > constants.LIMITS.TLOG_MAX_EXTENSION_LINES) {
    throw _err("tlog/bad-checkpoint", extensions.length + " extension lines exceeds the cap " +
      constants.LIMITS.TLOG_MAX_EXTENSION_LINES);
  }
  return { origin: origin, treeSize: treeSize, rootHash: rootHash, extensions: extensions, note: note };
}

/**
 * @primitive  pki.tlog.verifyCheckpoint
 * @signature  pki.tlog.verifyCheckpoint(input, keys) -> Promise<{ verified, signers, checkpoint }>
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
async function verifyCheckpoint(input, keys) {
  var checkpoint = parseCheckpoint(input);
  var v = await verifyNote(input, keys);
  return { verified: v.verified, signers: v.signers, checkpoint: checkpoint };
}

function _assertLevel(level) {
  if (typeof level !== "number" || !Number.isInteger(level) || level < 0 || level > TILE_MAX_LEVEL) {
    throw _err("tlog/bad-tile", "a tile level is an integer 0 to " + TILE_MAX_LEVEL + ", got " + level);
  }
}

function _assertWidth(width) {
  if (width === undefined || width === null) return null;
  if (typeof width !== "number" || !Number.isInteger(width) || width < 1 || width > TILE_HEIGHT_HASHES - 1) {
    throw _err("tlog/bad-tile", "a partial tile width is an integer 1 to " + (TILE_HEIGHT_HASHES - 1) +
      ", got " + width);
  }
  return width;
}

/** @internal The index path: zero-padded three-digit segments, every one but the last carrying an
 *  `x`. The specification's own example is 1234067 -> x001/x234/067. Built from the low digits up,
 *  so an index of any size produces the right number of segments. */
function _indexPath(index) {
  var n = guard.range.uint64(index, _err, "tlog/bad-tile", "a tile index");
  var segments = [];
  var rest = n;
  var thousand = 1000n;
  for (;;) {
    var part = rest % thousand;
    var text = part.toString();
    while (text.length < TILE_SEGMENT_DIGITS) text = "0" + text;
    segments.unshift(text);
    rest = rest / thousand;
    if (rest === 0n) break;
  }
  for (var i = 0; i < segments.length - 1; i++) segments[i] = "x" + segments[i];
  return segments.join("/");
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
    if (body.charCodeAt(0) !== 0x78) throw _err("tlog/bad-tile", "a leading index segment begins with x");
    body = body.slice(1);
  } else if (segment.charCodeAt(0) === 0x78) {
    throw _err("tlog/bad-tile", "the final index segment carries no x prefix");
  }
  if (body.length !== TILE_SEGMENT_DIGITS) {
    throw _err("tlog/bad-tile", "an index segment is " + TILE_SEGMENT_DIGITS + " digits, got " +
      JSON.stringify(segment));
  }
  for (var i = 0; i < body.length; i++) {
    var c = body.charCodeAt(i);
    if (c < 0x30 || c > 0x39) throw _err("tlog/bad-tile", "an index segment is digits, got " + JSON.stringify(segment));
  }
  return BigInt(body);
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
  var parts = path.split("/");
  if (parts.length < 3 || parts[0] !== "tile") {
    throw _err("tlog/bad-tile", "a tile path begins tile/<level>/<index>");
  }
  var width = null;
  /** @internal The partial suffix is its own two segments: ".p" attached to the final index
   *  segment, then the width. Reading it off the tail first leaves a clean index to walk. */
  if (parts.length >= 2 && parts[parts.length - 2].indexOf(".p") === parts[parts.length - 2].length - 2 &&
      parts[parts.length - 2].length > 2) {
    var widthText = parts[parts.length - 1];
    width = Number(_decimal(widthText, "a partial tile width", "tlog/bad-tile"));
    _assertWidth(width);
    parts = parts.slice(0, parts.length - 1);
    parts[parts.length - 1] = parts[parts.length - 1].slice(0, -2);
  }
  var levelText = parts[1];
  var level = Number(_decimal(levelText, "a tile level", "tlog/bad-tile"));
  _assertLevel(level);
  var segments = parts.slice(2);
  if (segments.length === 0) throw _err("tlog/bad-tile", "a tile path carries an index");
  var index = 0n;
  for (var i = 0; i < segments.length; i++) {
    index = index * 1000n + _segmentDigits(segments[i], i < segments.length - 1);
  }
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
  var buf = _bytes(bytes, "a tile");
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
  for (var i = 0; i < count; i++) out.push(buf.subarray(i * SHA256_BYTES, (i + 1) * SHA256_BYTES));
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
  var buf = _bytes(bytes, "an entry bundle");
  if (buf.length > constants.LIMITS.TLOG_MAX_ENTRY_BUNDLE_BYTES) {
    throw _err("tlog/bad-input", "entry bundle " + buf.length + " bytes exceeds the cap " +
      constants.LIMITS.TLOG_MAX_ENTRY_BUNDLE_BYTES);
  }
  var out = [];
  var p = 0;
  while (p < buf.length) {
    if (p + 2 > buf.length) {
      throw _err("tlog/bad-bundle", "a trailing byte at offset " + p + " is not a whole length prefix");
    }
    var len = buf.readUInt16BE(p);
    p += 2;
    if (p + len > buf.length) {
      throw _err("tlog/bad-bundle", "the entry at offset " + (p - 2) + " declares " + len +
        " bytes and " + (buf.length - p) + " remain");
    }
    out.push(buf.subarray(p, p + len));
    p += len;
  }
  return out;
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
};
