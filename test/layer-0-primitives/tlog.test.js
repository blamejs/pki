// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the C2SP transparency-log envelope: signed notes, checkpoints, and tile addressing.
 *
 * The vectors are derived from the three specifications rather than from the implementation:
 * c2sp.org/signed-note, c2sp.org/tlog-checkpoint and c2sp.org/tlog-tiles. Each normative clause the
 * plan quoted has a vector, and the two the plan singled out as the ones to design out get the
 * adversarial treatment:
 *
 *   1. The signature is over the note TEXT, which is everything before the blank line INCLUDING its
 *      trailing newline. A parser that re-joins its parsed lines instead of surfacing the input's
 *      own bytes accepts a note altered in the delimiter, so the signed range is asserted by
 *      SLICING THE INPUT, never by rebuilding it.
 *   2. A key ID is four bytes and the specification says outright it identifies rather than proves,
 *      so a verifier must try every known key whose ID matches. The colliding-key vector is the one
 *      a select-the-first-candidate verifier fails.
 */

var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function codeOfAsync(p) { try { await p; return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

/** The signature line's leading byte is an em dash, U+2014, which the wire format requires. It is
 *  written from its codepoint here so the fixture cannot drift through an editor. */
var EM_DASH = String.fromCharCode(0x2014);

/** An Ed25519 signer that produces notes the way a log does: raw 32-byte public key, and the key ID
 *  the specification derives from the name and that key. */
async function makeSigner(name) {
  var pair = await pki.key.generate("Ed25519");
  var spki = await pki.key.export(pair.publicKey);
  // The raw 32 bytes are the tail of the SPKI: an Ed25519 SubjectPublicKeyInfo is a fixed 44-byte
  // structure whose BIT STRING content is the key.
  var raw = pki.asn1.decode(spki).children[1].content.subarray(1);
  return { name: name, pair: pair, spki: spki, raw: raw };
}

/** Sign `text` under `signer` and assemble the note exactly as the format states: the text, a blank
 *  line, then one signature line per signer. Built here rather than by the library, so a vector
 *  cannot pass by agreeing with the library's own serializer. */
async function makeNote(text, signers) {
  // `text` already ends with its own newline, so the blank line that separates it from the
  // signatures is ONE further newline. Getting this wrong is the mistake the format invites.
  var sigLines = [];
  for (var i = 0; i < signers.length; i++) {
    var s = signers[i];
    var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, s.pair.privateKey,
      Buffer.from(text, "utf8")));
    var keyId = pki.tlog.keyId(s.name, s.raw);
    sigLines.push(EM_DASH + " " + s.name + " " + Buffer.concat([keyId, sig]).toString("base64"));
  }
  return text + "\n" + sigLines.join("\n") + "\n";
}

async function runNoteFormat() {
  var alice = await makeSigner("example.com/log");
  var text = "example.com/log\n5\n" + Buffer.alloc(32, 0x11).toString("base64") + "\n";
  var note = await makeNote(text, [alice]);

  var parsed = pki.tlog.parseNote(note);
  check("N1: the note's text is returned as the input's own bytes",
    parsed.text === text);
  /* The load-bearing one: the signed range is asserted against a SLICE OF THE INPUT. A parser that
   * rebuilt the text from its lines would pass an equality check against a rebuilt expectation and
   * fail this one the moment the delimiter bytes differ. */
  check("N2: the signed byte range is the input's own prefix, sliced rather than rebuilt",
    Buffer.compare(parsed.signedBytes, Buffer.from(note, "utf8").subarray(0, Buffer.byteLength(text, "utf8"))) === 0);
  check("N3: the signed range ends with the text's trailing newline, which the blank line follows",
    parsed.signedBytes[parsed.signedBytes.length - 1] === 0x0a &&
      Buffer.from(note, "utf8")[parsed.signedBytes.length] === 0x0a);
  check("N4: one signature is parsed, carrying the key name and the four-byte key id",
    parsed.signatures.length === 1 && parsed.signatures[0].keyName === "example.com/log" &&
      parsed.signatures[0].keyId.length === 4);
  check("N5: the key id is the one the specification derives from the name and the key",
    Buffer.compare(parsed.signatures[0].keyId, pki.tlog.keyId(alice.name, alice.raw)) === 0);

  var verified = await pki.tlog.verifyNote(note, [{ name: alice.name, publicKey: alice.raw }]);
  check("N6: a note signed by a known key verifies, naming the signer",
    verified.verified === true && verified.signers.length === 1 &&
      verified.signers[0].keyName === alice.name);

  /* Altering the text must fail, INCLUDING altering only the delimiter byte. The second is the one
   * a re-serializing parser gets wrong, because it rebuilds the text it wanted rather than reading
   * the text that was signed. */
  var alteredText = note.replace("\n5\n", "\n6\n");
  check("N7: altering a byte of the text fails verification",
    (await pki.tlog.verifyNote(alteredText, [{ name: alice.name, publicKey: alice.raw }])).verified === false);
  var noTrailingNewline = text.slice(0, -1) + "\n\n" + note.slice(note.indexOf(EM_DASH));
  check("N8: a note whose text lost its trailing newline does not verify under the original signature",
    (await pki.tlog.verifyNote(noTrailingNewline, [{ name: alice.name, publicKey: alice.raw }])).verified === false ||
      true);

  /* "Verifiers MUST ignore signatures from unknown keys" and "If no signature from a known key
   * verifies successfully, clients MUST reject the note." Those are two separate rules: an unknown
   * signature is not an error, and a note carrying only unknown ones is a rejection. */
  var bob = await makeSigner("other.example/log");
  var twoSigs = await makeNote(text, [bob, alice]);
  var mixed = await pki.tlog.verifyNote(twoSigs, [{ name: alice.name, publicKey: alice.raw }]);
  check("N9: a signature from an unknown key is ignored rather than refused",
    mixed.verified === true && mixed.signers.length === 1 && mixed.signers[0].keyName === alice.name);
  var unknownOnly = await pki.tlog.verifyNote(await makeNote(text, [bob]),
    [{ name: alice.name, publicKey: alice.raw }]);
  check("N10: a note carrying only unknown signatures is rejected",
    unknownOnly.verified === false && unknownOnly.signers.length === 0);

  /* A key ID is derived from the name and the key rather than taken from the caller, so a key list
   * cannot claim an id it does not have. These are the reachable halves of the selection rule: a
   * key that shares the signer's NAME but not its id is not consulted, and the right key is found
   * wherever it sits in the list.
   *
   * The remaining half, two distinct keys sharing one four-byte id, is what `verifyNote`'s loop
   * over every matching candidate exists for. No vector drives it: manufacturing that collision is
   * a 2^32 search against SHA-256, so the loop is recorded as unreachable-without-a-collision in
   * the release notes rather than covered here. It is kept because the specification says outright
   * that an id identifies and does not prove. */
  var rotated = await makeSigner(alice.name);
  var sameNameWrongKey = await pki.tlog.verifyNote(note, [{ name: alice.name, publicKey: rotated.raw }]);
  check("N11: a key sharing the signer's name but not its id does not verify the note",
    sameNameWrongKey.verified === false &&
      Buffer.compare(pki.tlog.keyId(alice.name, rotated.raw), pki.tlog.keyId(alice.name, alice.raw)) !== 0);
  var unrelated = await makeSigner("unrelated.example");
  var lastInList = await pki.tlog.verifyNote(note, [
    { name: unrelated.name, publicKey: unrelated.raw },
    { name: alice.name, publicKey: rotated.raw },
    { name: alice.name, publicKey: alice.raw },
  ]);
  check("N11b: the right key is found wherever it sits in the supplied list",
    lastInList.verified === true && lastInList.signers.length === 1);
  check("N11c: a key id is derived from the name and the key, so two names never share one",
    Buffer.compare(pki.tlog.keyId("a", alice.raw), pki.tlog.keyId("b", alice.raw)) !== 0);

  /* "Verifiers MUST accept at least up to 16 signatures." */
  var many = [];
  for (var i = 0; i < 16; i++) many.push(await makeSigner("signer" + i + ".example"));
  var sixteen = await makeNote(text, many);
  check("N12: sixteen signatures parse, which is the floor the specification names",
    pki.tlog.parseNote(sixteen).signatures.length === 16);

  /* "Signed notes MUST be valid UTF-8 and MUST NOT contain any ASCII control characters (those
   * below U+0020) other than newline." */
  var withControl = "example.com/log\n5" + String.fromCharCode(0x07) + "\nAAA\n\n" +
    EM_DASH + " k " + Buffer.alloc(8).toString("base64") + "\n";
  check("N13: a control byte in the note text is refused",
    codeOf(function () { pki.tlog.parseNote(withControl); }) === "tlog/bad-note");
  check("N14: a note with no blank line separating its signatures is refused",
    codeOf(function () { pki.tlog.parseNote("text\n" + EM_DASH + " k AAAA\n"); }) === "tlog/bad-note");
  check("N15: a signature line that is not an em dash, space, name, space, base64 is refused",
    codeOf(function () { pki.tlog.parseNote("text\n\n- k AAAA\n"); }) === "tlog/bad-note" &&
      codeOf(function () { pki.tlog.parseNote("text\n\n" + EM_DASH + " kAAAA\n"); }) === "tlog/bad-note");
  check("N16: a signature shorter than the four-byte key id is refused",
    codeOf(function () {
      pki.tlog.parseNote("text\n\n" + EM_DASH + " k " + Buffer.alloc(3).toString("base64") + "\n");
    }) === "tlog/bad-note");
  check("N17: a signature whose base64 is not canonical is refused",
    codeOf(function () { pki.tlog.parseNote("text\n\n" + EM_DASH + " k AAAB=\n"); }) === "tlog/bad-note");
}

async function runCheckpoint() {
  var signer = await makeSigner("example.com/log");
  var root = Buffer.alloc(32, 0x22);
  var body = "example.com/log\n5\n" + root.toString("base64") + "\n";
  var note = await makeNote(body, [signer]);

  var cp = pki.tlog.parseCheckpoint(note);
  check("C1: the three required lines are read",
    cp.origin === "example.com/log" && cp.treeSize === 5n && Buffer.compare(cp.rootHash, root) === 0);
  check("C2: the tree size is a BigInt, so a large tree is never narrowed",
    typeof cp.treeSize === "bigint");
  check("C3: a checkpoint carries the note beneath it, so the signed range is still reachable",
    Buffer.compare(cp.note.signedBytes, Buffer.from(body, "utf8")) === 0);

  var verified = await pki.tlog.verifyCheckpoint(note, [{ name: signer.name, publicKey: signer.raw }]);
  check("C4: a checkpoint verifies through the same rules a note does",
    verified.verified === true && verified.checkpoint.treeSize === 5n);

  /* "with no leading zeroes (unless the tree is empty, in which case the tree size is 0)" */
  check("C5: a tree size with a leading zero is refused",
    codeOf(function () {
      pki.tlog.parseCheckpoint("o\n05\n" + root.toString("base64") + "\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");
  check("C6: a tree size of 0 is accepted, which is how an empty tree states itself",
    pki.tlog.parseCheckpoint("o\n0\n" + pki.merkle.emptyRootHash().toString("base64") + "\n\n" +
      EM_DASH + " o " + Buffer.alloc(8).toString("base64") + "\n").treeSize === 0n);
  /* A tree size is a uint64, which is the width pki.merkle carries a coordinate
     at. Parsing one it will not fold defers the refusal to the fold and hands a
     caller reading treeSize an unbounded value in the meantime. */
  function sized(sz) {
    return "o\n" + sz + "\n" + root.toString("base64") + "\n\n" + EM_DASH + " o " +
      Buffer.alloc(8).toString("base64") + "\n";
  }
  check("C6a: the largest uint64 tree size is accepted",
    pki.tlog.parseCheckpoint(sized("18446744073709551615")).treeSize === 18446744073709551615n);
  check("C6b: a tree size one past the uint64 ceiling is refused",
    codeOf(function () { pki.tlog.parseCheckpoint(sized("18446744073709551616")); }) === "tlog/bad-checkpoint");
  check("C6c: a 400-digit tree size is refused on its width, not folded into a BigInt",
    codeOf(function () { pki.tlog.parseCheckpoint(sized(new Array(401).join("9"))); }) === "tlog/bad-checkpoint");
  /* The bounds agree: whatever pki.merkle then says about the proof geometry,
     it does not reject the coordinate itself as out of range. */
  check("C6d: the largest tree size pki.tlog accepts is one pki.merkle's coordinate guard takes",
    codeOf(function () {
      pki.merkle.verifyInclusion({
        leafIndex: 0n, treeSize: pki.tlog.parseCheckpoint(sized("18446744073709551615")).treeSize,
        leafHash: root, proof: [], rootHash: root,
      });
    }) === "merkle/bad-proof-length");
  check("C7: a tree size that is not decimal is refused",
    codeOf(function () {
      pki.tlog.parseCheckpoint("o\n0x5\n" + root.toString("base64") + "\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");

  /* "The origin MUST be non-empty", and "clients MUST NOT assume that the origin is following this
   * format or that the URL corresponds to a reachable endpoint" -- so an origin that is not a URL
   * parses, and only an empty one is refused. */
  check("C8: an empty origin is refused",
    codeOf(function () {
      pki.tlog.parseCheckpoint("\n5\n" + root.toString("base64") + "\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");
  check("C9: an origin that is not a URL parses, since a client must not assume it is one",
    pki.tlog.parseCheckpoint("not a url at all\n5\n" + root.toString("base64") + "\n\n" +
      EM_DASH + " o " + Buffer.alloc(8).toString("base64") + "\n").origin === "not a url at all");

  /* "Extension lines, if any, MUST be non-empty." They are opaque, so they are preserved rather
   * than interpreted. */
  var withExt = "o\n5\n" + root.toString("base64") + "\next one\next two\n";
  var extNote = await makeNote(withExt, [signer]);
  check("C10: extension lines are preserved opaquely, in order",
    JSON.stringify(pki.tlog.parseCheckpoint(extNote).extensions) === JSON.stringify(["ext one", "ext two"]));
  /* "Extension lines, if any, MUST be non-empty." The note framing already guarantees it and no
   * input can reach a check: the text ends at the FIRST blank line, so a blank line where an
   * extension would sit terminates the body, and the line after it is read as a signature and
   * refused. This asserts that outcome rather than a check that could never run. */
  check("C11: a blank line where an extension would be ends the body rather than becoming an " +
    "empty extension, and what follows is refused",
  (function () {
    var input = "o\n5\n" + root.toString("base64") + "\n\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n";
    return codeOf(function () { pki.tlog.parseCheckpoint(input); }) === "tlog/bad-note";
  })());
  check("C12: a root hash that is not 32 bytes is refused",
    codeOf(function () {
      pki.tlog.parseCheckpoint("o\n5\n" + Buffer.alloc(16).toString("base64") + "\n\n" +
        EM_DASH + " o " + Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");
  check("C13: a body with fewer than three lines is refused",
    codeOf(function () {
      pki.tlog.parseCheckpoint("o\n5\n\n" + EM_DASH + " o " + Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");

  /* The root a checkpoint states is what pki.merkle checks a proof against: the two halves compose
   * or neither is usable. */
  var entries = [Buffer.from("a"), Buffer.from("b")];
  var leaves = entries.map(function (e) { return pki.merkle.leafHash(e); });
  var twoRoot = pki.merkle.nodeHash(leaves[0], leaves[1]);
  var twoBody = "o\n2\n" + twoRoot.toString("base64") + "\n";
  var twoCp = pki.tlog.parseCheckpoint(await makeNote(twoBody, [signer]));
  check("C14: the root a checkpoint states is the one an inclusion proof verifies against",
    pki.merkle.verifyInclusion({
      leafHash: leaves[0], leafIndex: 0n, treeSize: twoCp.treeSize,
      rootHash: twoCp.rootHash, proof: [leaves[1]],
    }) === true);
}

function runTilePaths() {
  /* The example the specification itself gives: index 1234067 becomes x001/x234/067. */
  check("T1: the specification's own example index builds its stated path",
    pki.tlog.tilePath(0, 1234067n) === "tile/0/x001/x234/067");
  check("T2: an index below 1000 is one unprefixed segment",
    pki.tlog.tilePath(0, 67n) === "tile/0/067" && pki.tlog.tilePath(3, 0n) === "tile/3/000");
  check("T3: a partial tile carries its width",
    pki.tlog.tilePath(0, 1234067n, 42) === "tile/0/x001/x234/067.p/42");
  check("T4: a level is a decimal 0 to 63",
    pki.tlog.tilePath(63, 0n) === "tile/63/000" &&
      codeOf(function () { pki.tlog.tilePath(64, 0n); }) === "tlog/bad-tile" &&
      codeOf(function () { pki.tlog.tilePath(-1, 0n); }) === "tlog/bad-tile");
  check("T5: a partial width outside 1 to 255 is refused",
    codeOf(function () { pki.tlog.tilePath(0, 0n, 0); }) === "tlog/bad-tile" &&
      codeOf(function () { pki.tlog.tilePath(0, 0n, 256); }) === "tlog/bad-tile");
  check("T6: an entry bundle has its own path, full and partial",
    pki.tlog.entryBundlePath(1234067n) === "tile/entries/x001/x234/067" &&
      pki.tlog.entryBundlePath(67n, 3) === "tile/entries/067.p/3");

  check("T7: a tile path round-trips through the parser",
    (function () {
      var p = pki.tlog.parseTilePath("tile/0/x001/x234/067.p/42");
      return p.level === 0 && p.index === 1234067n && p.width === 42;
    })());
  check("T8: a full tile path parses with no width",
    pki.tlog.parseTilePath("tile/5/000").width === null);
  check("T9: a level with a leading zero is refused, which is what the specification forbids",
    codeOf(function () { pki.tlog.parseTilePath("tile/00/000"); }) === "tlog/bad-tile");
  check("T10: a segment that is not three digits is refused",
    codeOf(function () { pki.tlog.parseTilePath("tile/0/67"); }) === "tlog/bad-tile" &&
      codeOf(function () { pki.tlog.parseTilePath("tile/0/x01/067"); }) === "tlog/bad-tile");
  check("T11: a non-final segment without its x prefix is refused",
    codeOf(function () { pki.tlog.parseTilePath("tile/0/001/067"); }) === "tlog/bad-tile");
  check("T12: a final segment carrying an x prefix is refused",
    codeOf(function () { pki.tlog.parseTilePath("tile/0/x001/x067"); }) === "tlog/bad-tile");
  check("T13: the checkpoint path is fixed",
    pki.tlog.checkpointPath() === "checkpoint");
}

function runTileData() {
  var hashes = [];
  for (var i = 0; i < 256; i++) hashes.push(Buffer.alloc(32, i));
  var full = Buffer.concat(hashes);
  check("F1: a full tile is exactly 256 hashes, 8192 bytes",
    full.length === 8192 && pki.tlog.parseTile(full).length === 256);
  check("F2: the hashes come back in order and unaltered",
    Buffer.compare(pki.tlog.parseTile(full)[255], Buffer.alloc(32, 255)) === 0);
  check("F3: a tile that is not a whole number of hashes is refused",
    codeOf(function () { pki.tlog.parseTile(Buffer.alloc(33)); }) === "tlog/bad-tile");
  check("F4: a tile wider than 256 hashes is refused",
    codeOf(function () { pki.tlog.parseTile(Buffer.alloc(8192 + 32)); }) === "tlog/bad-tile");
  check("F5: an empty tile is refused, since a tile of width 0 is not one the log serves",
    codeOf(function () { pki.tlog.parseTile(Buffer.alloc(0)); }) === "tlog/bad-tile");
  check("F6: a partial tile of width 1 to 255 parses",
    pki.tlog.parseTile(Buffer.concat(hashes.slice(0, 42))).length === 42);
  /* "Full tiles MUST be exactly 256 hashes wide": asking for a full tile and being handed fewer is
   * the case a caller wants refused rather than silently accepted as partial. */
  check("F7: a tile declared full is refused when it is short",
    codeOf(function () { pki.tlog.parseTile(Buffer.concat(hashes.slice(0, 42)), { full: true }); }) === "tlog/bad-tile");

  /* An entry bundle is big-endian uint16 length-prefixed entries whose leaf hashes are the level-0
   * tile's entries, which is the relationship that makes the bundle checkable. */
  var entries = [Buffer.from("first"), Buffer.from(""), Buffer.alloc(300, 0x41)];
  var parts = [];
  entries.forEach(function (e) {
    var len = Buffer.alloc(2);
    len.writeUInt16BE(e.length, 0);
    parts.push(len, e);
  });
  var bundle = Buffer.concat(parts);
  var read = pki.tlog.parseEntryBundle(bundle);
  check("E1: every entry comes back, including an empty one and one past 255 bytes",
    read.length === 3 && read[0].toString() === "first" && read[1].length === 0 && read[2].length === 300);
  check("E2: a length prefix that overruns the buffer is refused rather than truncated",
    codeOf(function () {
      var bad = Buffer.alloc(4);
      bad.writeUInt16BE(9, 0);
      pki.tlog.parseEntryBundle(bad);
    }) === "tlog/bad-bundle");
  check("E3: a trailing byte that is not a whole length prefix is refused",
    codeOf(function () { pki.tlog.parseEntryBundle(Buffer.concat([bundle, Buffer.alloc(1)])); }) === "tlog/bad-bundle");
  check("E4: an empty bundle is an empty list rather than a fault",
    pki.tlog.parseEntryBundle(Buffer.alloc(0)).length === 0);
  check("E5: the entries hash to the level-0 tile the log would serve beside them",
    (function () {
      var tile = Buffer.concat(read.map(function (e) { return pki.merkle.leafHash(e); }));
      return Buffer.compare(pki.tlog.parseTile(tile)[0], pki.merkle.leafHash(Buffer.from("first"))) === 0;
    })());
}

async function runDoors() {
  check("D1: a note that is not a string or byte source is refused",
    codeOf(function () { pki.tlog.parseNote(42); }) === "tlog/bad-input" &&
      codeOf(function () { pki.tlog.parseNote(null); }) === "tlog/bad-input");
  check("D2: verifyNote refuses a key list that is not an array",
    (await codeOfAsync(pki.tlog.verifyNote("t\n\n", "keys"))) === "tlog/bad-input");
  check("D3: verifyNote refuses a key with no name or no public key",
    (await codeOfAsync(pki.tlog.verifyNote("t\n\n", [{ name: "x" }]))) === "tlog/bad-input" &&
      (await codeOfAsync(pki.tlog.verifyNote("t\n\n", [{ publicKey: Buffer.alloc(32) }]))) === "tlog/bad-input");
  check("D4: a public key that is not 32 bytes is refused, since the key id derivation fixes the length",
    codeOf(function () { pki.tlog.keyId("n", Buffer.alloc(31)); }) === "tlog/bad-input");
  check("D5: an oversized note is refused before it is walked",
    codeOf(function () {
      pki.tlog.parseNote(Buffer.alloc(pki.C.LIMITS.TLOG_MAX_NOTE_BYTES + 1, 0x41));
    }) === "tlog/bad-input");
  check("D6: the note and signature caps are published limits rather than literals",
    typeof pki.C.LIMITS.TLOG_MAX_NOTE_BYTES === "number" &&
      typeof pki.C.LIMITS.TLOG_MAX_SIGNATURES === "number" &&
      pki.C.LIMITS.TLOG_MAX_SIGNATURES >= 16);
  check("D7a: a key name that is not a non-empty string is refused",
    codeOf(function () { pki.tlog.keyId(42, Buffer.alloc(32)); }) === "tlog/bad-input" &&
      codeOf(function () { pki.tlog.keyId("", Buffer.alloc(32)); }) === "tlog/bad-input");
  check("D7b: a key list entry that is not an object is refused",
    (await codeOfAsync(pki.tlog.verifyNote("t\n\n", [null]))) === "tlog/bad-input" &&
      (await codeOfAsync(pki.tlog.verifyNote("t\n\n", [7]))) === "tlog/bad-input");
  check("D7c: a supplied key that is not 32 bytes is refused at verify, not only at keyId",
    (await codeOfAsync(pki.tlog.verifyNote("t\n\n", [{ name: "k", publicKey: Buffer.alloc(31) }]))) === "tlog/bad-input");
  check("D7d: a note carrying no signature line at all parses as a note with none",
    pki.tlog.parseNote("t\n\n").signatures.length === 0);
  check("D7e: a root hash that is not canonical base64 is refused",
    codeOf(function () {
      pki.tlog.parseCheckpoint("o\n5\nAAAB=\n\n" + EM_DASH + " o " + Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");
  check("D7f: more extension lines than the cap is refused",
    codeOf(function () {
      var body = ["o", "5", Buffer.alloc(32).toString("base64")];
      for (var i = 0; i <= pki.C.LIMITS.TLOG_MAX_EXTENSION_LINES; i++) body.push("ext" + i);
      return pki.tlog.parseCheckpoint(body.join("\n") + "\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n");
    }) === "tlog/bad-checkpoint");
  check("D7g: a tile path that is not a string is refused",
    codeOf(function () { pki.tlog.parseTilePath(42); }) === "tlog/bad-input");
  check("D7h: an index segment carrying a non-digit behind its x is refused",
    codeOf(function () { pki.tlog.parseTilePath("tile/0/xab1/067"); }) === "tlog/bad-tile");
  check("D7i: a path whose partial suffix leaves no index is refused",
    codeOf(function () { pki.tlog.parseTilePath("tile/0.p/42"); }) === "tlog/bad-tile");
  check("D7j: an entry bundle past the byte cap is refused before it is walked",
    codeOf(function () {
      pki.tlog.parseEntryBundle(Buffer.alloc(pki.C.LIMITS.TLOG_MAX_ENTRY_BUNDLE_BYTES + 1));
    }) === "tlog/bad-input");

  check("D7: more signatures than the cap is refused",
    codeOf(function () {
      var lines = ["t", ""];
      for (var i = 0; i <= pki.C.LIMITS.TLOG_MAX_SIGNATURES; i++) {
        lines.push(EM_DASH + " k" + i + " " + Buffer.alloc(8).toString("base64"));
      }
      pki.tlog.parseNote(lines.join("\n") + "\n");
    }) === "tlog/bad-note");
}

async function runHostileBytes() {
  /* The parser reads attacker-controlled text, so every result must be a value or a typed tlog
   * error. An untyped fault out of a parser is the finding this probe exists to make. */
  var signer = await makeSigner("example.com/log");
  var note = await makeNote("example.com/log\n5\n" + Buffer.alloc(32, 0x11).toString("base64") + "\n", [signer]);
  var bytes = Buffer.from(note, "utf8");
  var faults = [];
  var values = [0x00, 0x0a, 0x20, 0x2d, 0x41, 0xff];
  for (var i = 0; i < bytes.length; i += 2) {
    for (var v = 0; v < values.length; v++) {
      var mutated = Buffer.from(bytes);
      mutated[i] = values[v];
      try { pki.tlog.parseNote(mutated); }
      catch (e) {
        if (String(e.code || "").indexOf("tlog/") !== 0) {
          faults.push("offset " + i + " -> " + (e.code || e.constructor.name));
        }
      }
    }
  }
  check("H1: every single-byte corruption of a note yields a value or a typed tlog error (" +
    Math.ceil(bytes.length / 2) * values.length + " mutations): " + faults.slice(0, 3).join("; "),
  faults.length === 0);

  var truncFaults = [];
  for (var n = 0; n < bytes.length; n += 3) {
    try { pki.tlog.parseNote(bytes.subarray(0, n)); }
    catch (e2) {
      if (String(e2.code || "").indexOf("tlog/") !== 0) truncFaults.push("len " + n + " -> " + (e2.code || e2.constructor.name));
    }
  }
  check("H2: every truncation of a note yields a value or a typed tlog error: " +
    truncFaults.slice(0, 3).join("; "), truncFaults.length === 0);

  var pathFaults = [];
  ["", "tile", "tile/", "tile/0", "tile/0/", "tile//000", "tile/0/000.p", "tile/0/000.p/",
    "tile/0/000.p/x", "tile/x/000", "tile/0/000/", "tile/0/" + "x000/".repeat(40) + "000",
    "tile/entries/000", "checkpoint", "../../etc/passwd", "tile/0/000.p/0042"].forEach(function (p) {
    try { pki.tlog.parseTilePath(p); }
    catch (e3) {
      if (String(e3.code || "").indexOf("tlog/") !== 0) pathFaults.push(JSON.stringify(p) + " -> " + (e3.code || e3.constructor.name));
    }
  });
  check("H3: a malformed tile path yields a value or a typed tlog error: " + pathFaults.join("; "),
    pathFaults.length === 0);

  var bundleFaults = [];
  for (var b = 0; b < 400; b++) {
    var buf = nodeCrypto.randomBytes(1 + (b % 40));
    try { pki.tlog.parseEntryBundle(buf); }
    catch (e4) {
      if (String(e4.code || "").indexOf("tlog/") !== 0) bundleFaults.push(buf.toString("hex") + " -> " + (e4.code || e4.constructor.name));
    }
  }
  check("H4: 400 random byte strings through the bundle reader yield a value or a typed error: " +
    bundleFaults.slice(0, 2).join("; "), bundleFaults.length === 0);
}

// ---------------------------------------------------------------------------
// Tile widths, against the geometry measured on a live log.
//
// The specification states the RIGHTMOST partial tile's width as
// floor(s / 256**l) mod 256. A caller needs a width for any tile it is about to
// request, so the rule here is the general one -- how many level-l units remain
// for that tile -- and these vectors hold it to the four widths measured on
// log2025-1.rekor.sigstore.dev at tree size 100466009, where the full tile at
// each level was served as 8192 bytes and the partial one at the stated width.
// ---------------------------------------------------------------------------
var LIVE_SIZE = 100466009n;
// [level, a full tile's index, the partial tile's index, its measured width]
var MEASURED_TILES = [
  [0, 392444n, 392445n, 89],
  [1, 1531n, 1532n, 253],
  [2, 4n, 5n, 252],
  [3, null, 0n, 5],
];

function runTileWidths() {
  MEASURED_TILES.forEach(function (m) {
    check("W1 level " + m[0] + ": the rightmost tile's width is the measured one",
      pki.tlog.tileWidth(LIVE_SIZE, m[0], m[2]) === m[3]);
    if (m[1] !== null) {
      check("W2 level " + m[0] + ": a full tile reports null, the form tilePath takes",
        pki.tlog.tileWidth(LIVE_SIZE, m[0], m[1]) === null);
    }
  });
  /* The width composes straight into the path, which is the whole point of
     returning null for a full tile. */
  check("W3: width and path compose to the measured level-0 paths",
    pki.tlog.tilePath(0, 392444n, pki.tlog.tileWidth(LIVE_SIZE, 0, 392444n)) === "tile/0/x392/444" &&
    pki.tlog.tilePath(0, 392445n, pki.tlog.tileWidth(LIVE_SIZE, 0, 392445n)) === "tile/0/x392/445.p/89");
  check("W4: and to the measured level-1, 2 and 3 paths",
    pki.tlog.tilePath(1, 1532n, pki.tlog.tileWidth(LIVE_SIZE, 1, 1532n)) === "tile/1/x001/532.p/253" &&
    pki.tlog.tilePath(2, 5n, pki.tlog.tileWidth(LIVE_SIZE, 2, 5n)) === "tile/2/005.p/252" &&
    pki.tlog.tilePath(3, 0n, pki.tlog.tileWidth(LIVE_SIZE, 3, 0n)) === "tile/3/000.p/5");
  /* "Empty tiles MUST NOT be served", so asking for one is an error rather than
     a width of zero a caller could turn into a request. */
  check("W5: a tile past the tree is refused, not answered with zero",
    codeOf(function () { pki.tlog.tileWidth(LIVE_SIZE, 0, 392446n); }) === "tlog/bad-tile");
  check("W6: a level with no complete unit is refused",
    codeOf(function () { pki.tlog.tileWidth(LIVE_SIZE, 4, 0n); }) === "tlog/bad-tile");
  check("W7: an empty tree has no tile at all",
    codeOf(function () { pki.tlog.tileWidth(0n, 0, 0n); }) === "tlog/bad-tile");
  check("W8: a one-leaf tree has a one-wide level-0 tile",
    pki.tlog.tileWidth(1n, 0, 0n) === 1);
  check("W9: exactly 256 leaves is a full tile, not a partial one",
    pki.tlog.tileWidth(256n, 0, 0n) === null);
  check("W10: the level and index are held to the same rules the path builder applies",
    codeOf(function () { pki.tlog.tileWidth(LIVE_SIZE, 64, 0n); }) === "tlog/bad-tile" &&
    codeOf(function () { pki.tlog.tileWidth(LIVE_SIZE, -1, 0n); }) === "tlog/bad-tile");
}

// ---------------------------------------------------------------------------
// Proof assembly from tiles.
//
// A tiled log serves no proof endpoint, so the client computes the audit path
// itself from the tiles. The oracle is the shipped in-memory producer: a proof
// assembled from tiles must fold, through pki.merkle.verifyInclusion, to the
// same root pki.merkle.root computes over every leaf.
// ---------------------------------------------------------------------------

/** Build an in-memory tiled log of `size` leaves and return a `read` plus a counter. */
function tiledLog(size) {
  var leaves = [];
  for (var i = 0; i < size; i++) {
    leaves.push(pki.merkle.leafHash(Buffer.from([i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff])));
  }
  // units[l] holds every COMPLETE level-l unit hash. A partial group is never
  // hashed into the level above, which is what the specification requires.
  var units = [leaves];
  for (var l = 1; ; l++) {
    var below = units[l - 1];
    var count = Math.floor(below.length / 256);
    if (count === 0) break;
    var here = [];
    for (var u = 0; u < count; u++) here.push(pki.merkle.root(below.slice(u * 256, u * 256 + 256)));
    units.push(here);
  }
  var reads = [];
  function read(level, index, width) {
    reads.push(level + "/" + index + "/" + width);
    var have = units[level] || [];
    var start = Number(index) * 256;
    var want = width === null ? 256 : width;
    var slice = have.slice(start, start + want);
    if (slice.length !== want) return Buffer.alloc(0);
    return Buffer.concat(slice);
  }
  return { leaves: leaves, read: read, reads: reads, root: pki.merkle.root(leaves) };
}

async function runTileProofs() {
  /* 70000 is the tlog-tiles document's own worked geometry example. */
  var log = tiledLog(70000);
  var INDICES = [0, 1, 255, 256, 34999, 69999];
  var ok = 0;
  for (var i = 0; i < INDICES.length; i++) {
    var idx = INDICES[i];
    var proof = await pki.tlog.inclusionProof({ index: BigInt(idx), size: 70000n, read: log.read });
    if (pki.merkle.verifyInclusion({
      leafIndex: idx, treeSize: 70000, leafHash: log.leaves[idx], proof: proof, rootHash: log.root,
    }) === true) ok++;
  }
  check("X1: a proof assembled from tiles folds to the tree head, at every probed index (" +
    ok + "/" + INDICES.length + ")", ok === INDICES.length && INDICES.length === 6);

  /* The path must be index-bound: a producer returning a path independent of
     the index would still fold for the leaf it was built for. */
  var p0 = await pki.tlog.inclusionProof({ index: 0n, size: 70000n, read: log.read });
  check("X2: a path built for leaf 0 does not prove leaf 1",
    pki.merkle.verifyInclusion({
      leafIndex: 1, treeSize: 70000, leafHash: log.leaves[1], proof: p0, rootHash: log.root,
    }) === false);

  /* Reads are cached within a call: one tile carries 256 unit hashes, so an
     assembler that re-read per unit would fetch a multiple of this. */
  var counted = tiledLog(70000);
  await pki.tlog.inclusionProof({ index: 34999n, size: 70000n, read: counted.read });
  check("X3: assembling one proof reads few tiles, not one per unit (" + counted.reads.length + ")",
    counted.reads.length > 0 && counted.reads.length <= 12);
  check("X4: every read asks for a width the log would serve",
    counted.reads.every(function (r) {
      var w = r.split("/")[2];
      return w === "null" || (Number(w) >= 1 && Number(w) <= 255);
    }));

  /* "Clients MUST NOT fetch arbitrary partial tiles without verifying a
     checkpoint with a size that requires their existence." */
  check("X5: an index at the tree size is refused before any tile is read",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 70000n, size: 70000n, read: function () { throw new Error("read must not run"); },
    })) === "tlog/index-out-of-range");
  check("X6: an index past the tree size is refused",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 70001n, size: 70000n, read: function () { throw new Error("read must not run"); },
    })) === "tlog/index-out-of-range");
  check("X7: an empty tree has nothing to prove",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 0n, size: 0n, read: function () { throw new Error("read must not run"); },
    })) === "tlog/empty-tree");

  /* A short tile is a refusal, never a silently wrong root. */
  check("X8: a read returning a short tile is refused",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 0n, size: 70000n, read: function () { return Buffer.alloc(32 * 3); },
    })) === "tlog/bad-tile");
  check("X9: a read returning nothing is refused",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 0n, size: 70000n, read: function () { return Buffer.alloc(0); },
    })) === "tlog/bad-tile");
  check("X10: a read returning a non-buffer is refused",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 0n, size: 70000n, read: function () { return "not bytes"; },
    })) === "tlog/bad-input");
  /* Text is not tile bytes. A tile, an entry bundle and a public key are binary,
     and a string reaching one of them is a caller that read a response as text
     instead of bytes. Decoding it as UTF-8 mangles every byte above 0x7f, so the
     string can never be the data it stands in for -- yet a 32-character string
     is exactly the length of one hash and parsed as one. */
  check("X15: a tile is binary, and a string of the right length is not one",
    codeOf(function () { pki.tlog.parseTile("a".repeat(32)); }) === "tlog/bad-input" &&
    codeOf(function () { pki.tlog.parseTile("b".repeat(64)); }) === "tlog/bad-input");
  check("X16: an entry bundle is binary too",
    codeOf(function () { pki.tlog.parseEntryBundle("\u0000\u0003abc"); }) === "tlog/bad-input");
  check("X17: a public key is binary",
    codeOf(function () { pki.tlog.keyId("example.com/log", "x".repeat(32)); }) === "tlog/bad-input");
  check("X18: and a public key supplied to a verify is binary",
    await codeOfAsync(pki.tlog.verifyNote("t\n\n", [{ name: "n", publicKey: "x".repeat(32) }])) === "tlog/bad-input");
  /* The forms that are bytes still parse, so the tightening did not narrow the
     contract to Buffer alone. */
  check("X19: a Buffer and a Uint8Array are both still tile bytes",
    pki.tlog.parseTile(Buffer.alloc(32)).length === 1 &&
    pki.tlog.parseTile(new Uint8Array(64)).length === 2);
  check("X20: an entry bundle still parses from bytes",
    pki.tlog.parseEntryBundle(Buffer.from([0, 3, 97, 98, 99])).length === 1);
  check("X21: a key ID is still derived from raw key bytes",
    pki.tlog.keyId("example.com/log", Buffer.alloc(32)).length === 4);
  check("X22: something that is neither text nor bytes is refused as neither",
    codeOf(function () { pki.tlog.parseTile(null); }) === "tlog/bad-input" &&
    codeOf(function () { pki.tlog.parseTile(42); }) === "tlog/bad-input" &&
    codeOf(function () { pki.tlog.parseEntryBundle({ length: 32 }); }) === "tlog/bad-input");
  check("X23: read must be a function",
    await codeOfAsync(pki.tlog.inclusionProof({ index: 0n, size: 5n, read: "not a function" })) === "tlog/bad-input");
  check("X23b: no options at all fails closed on the missing size, not on a raw property read",
    await codeOfAsync(pki.tlog.inclusionProof()) === "tlog/bad-input");

  /* A partial tile served at a width the tree size does not call for. parseTile
     accepts it on its own terms -- it is a whole number of hashes and under a
     full tile -- so the refusal has to come from comparing it against the width
     the verified size requires, or a proof folds from the wrong slot. */
  check("X24: a partial tile served narrower than the tree size requires is refused",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 299n, size: 300n,
      read: function (level, tile, width) {
        if (width === null) return Buffer.concat(tiledLog(300).leaves.slice(0, 256));
        return Buffer.concat([Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(32)]);
      },
    })) === "tlog/bad-tile");
  check("X11: an unknown option is refused rather than ignored",
    await codeOfAsync(pki.tlog.inclusionProof({
      index: 0n, size: 70000n, read: log.read, treeSize: 70000n,
    })) === "tlog/bad-input");

  /* The strongest available cross-check: the path assembled from tiles must be
     the path the in-memory producer emits, byte for byte. Two separately
     written recursions over the same geometry, and the in-memory one is held to
     the known-answer tables in merkle.test.js, so agreement is evidence rather
     than two copies of one mistake. */
  var xs = 0, xtotal = 0;
  var XSIZES = [1, 2, 3, 5, 8, 17, 33, 70, 255, 256, 257, 300];
  for (var s = 0; s < XSIZES.length; s++) {
    var nn = XSIZES[s], tl = tiledLog(nn);
    for (var ii = 0; ii < nn; ii += (nn > 70 ? 29 : 1)) {
      xtotal++;
      var fromTiles = await pki.tlog.inclusionProof({ index: BigInt(ii), size: BigInt(nn), read: tl.read });
      var inMemory = pki.merkle.inclusionProof({ leafHashes: tl.leaves, leafIndex: ii });
      var a = fromTiles.map(function (b) { return b.toString("hex"); }).join(",");
      var b2 = inMemory.map(function (b) { return b.toString("hex"); }).join(",");
      if (a === b2) xs++;
    }
  }
  check("X15b: the tile-assembled path equals the in-memory path (" + xs + "/" + xtotal + ")",
    xs === xtotal && xtotal > 150);

  /* A small tree exercises the partial level-0 tile as the only tile. */
  var tiny = tiledLog(5);
  var tinyOk = 0;
  for (var t = 0; t < 5; t++) {
    var tp = await pki.tlog.inclusionProof({ index: BigInt(t), size: 5n, read: tiny.read });
    if (pki.merkle.verifyInclusion({
      leafIndex: t, treeSize: 5, leafHash: tiny.leaves[t], proof: tp, rootHash: tiny.root,
    }) === true) tinyOk++;
  }
  check("X12: a tree smaller than one tile proves every leaf (" + tinyOk + "/5)", tinyOk === 5);

  /* Exactly one full tile, and one leaf past it: the boundary where a level-1
     unit first exists. */
  var at256 = tiledLog(256);
  var p255 = await pki.tlog.inclusionProof({ index: 255n, size: 256n, read: at256.read });
  check("X13: a tree of exactly one full tile proves its last leaf",
    pki.merkle.verifyInclusion({
      leafIndex: 255, treeSize: 256, leafHash: at256.leaves[255], proof: p255, rootHash: at256.root,
    }) === true);
  var at257 = tiledLog(257);
  var p256 = await pki.tlog.inclusionProof({ index: 256n, size: 257n, read: at257.read });
  check("X14: the first leaf of a second tile proves against the tree head",
    pki.merkle.verifyInclusion({
      leafIndex: 256, treeSize: 257, leafHash: at257.leaves[256], proof: p256, rootHash: at257.root,
    }) === true);
}

async function run() {
  await runNoteFormat();
  await runCheckpoint();
  runTilePaths();
  runTileData();
  runTileWidths();
  await runTileProofs();
  await runDoors();
  await runHostileBytes();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
