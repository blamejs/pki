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

  /* N6a: EVERY BufferSource these verbs admit reaches the same answer. Each door asks
     `guard.bytes.isByteSource`, which accepts an ArrayBuffer and a DataView, while the measurement
     wanted a view and the copy wanted a Buffer or a Uint8Array: so the admitted set was wider than the
     handled one, and an ArrayBuffer left an UNTYPED TypeError out of a public verb while a DataView or a
     Uint16Array drew a refusal for input the door had accepted. A caller handing over
     `await response.arrayBuffer()` could not read a tile at all. Every form is driven through the
     shipped verb, and the string and number cases are the controls: those are still refused, typed, so
     the fix widened the set to what the door states rather than to anything at all. */
  var noteBuf = Buffer.from(note, "utf8");
  function asForms(buf) {
    var ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
    var forms = [["Buffer", buf], ["Uint8Array", new Uint8Array(ab.slice(0))],
      ["ArrayBuffer", ab.slice(0)], ["DataView", new DataView(ab.slice(0))]];
    // A non-byte typed array views the same memory with a wider element, which is still a BufferSource.
    if (buf.length % 2 === 0) forms.push(["Uint16Array", new Uint16Array(ab.slice(0))]);
    return forms;
  }
  var formGaps = [];
  for (var nf = 0; nf < asForms(noteBuf).length; nf++) {
    var pair = asForms(noteBuf)[nf], label = pair[0], value = pair[1];
    try {
      var p = pki.tlog.parseNote(value);
      if (p.signatures.length !== 1) formGaps.push("parseNote(" + label + ") read " + p.signatures.length + " signatures");
      var v = await pki.tlog.verifyNote(value, [{ name: alice.name, publicKey: alice.raw }]);
      if (v.verified !== true) formGaps.push("verifyNote(" + label + ") -> " + v.verified);
    } catch (e) { formGaps.push("parseNote/verifyNote(" + label + ") threw " + (e.code || e.name)); }
  }
  var tileBuf = Buffer.alloc(64, 0x11);
  for (var tf = 0; tf < asForms(tileBuf).length; tf++) {
    var tp = asForms(tileBuf)[tf];
    try {
      var hashes = pki.tlog.parseTile(tp[1]);
      if (hashes.length !== 2) formGaps.push("parseTile(" + tp[0] + ") read " + hashes.length + " hashes");
    } catch (e2) { formGaps.push("parseTile(" + tp[0] + ") threw " + (e2.code || e2.name)); }
  }
  check("N6a: every BufferSource form the door admits is read by parseNote, verifyNote and parseTile: " +
    formGaps.join("; "), formGaps.length === 0);
  check("N6b: CONTROL a string and a number are still refused, typed, by each of those doors",
    (function () {
      var codes = [];
      [["parseTile", function (x) { return pki.tlog.parseTile(x); }],
        ["parseNote", function (x) { return pki.tlog.parseNote(x); }]].forEach(function (door) {
        [7, {}, null].forEach(function (bad) {
          try { door[1](bad); codes.push(door[0] + " accepted " + JSON.stringify(bad)); }
          catch (e3) { if (e3.code !== "tlog/bad-input") codes.push(door[0] + "(" + JSON.stringify(bad) + ") -> " + (e3.code || e3.name)); }
        });
      });
      // A string is a note's own form, so it is only the binary doors that refuse one.
      try { pki.tlog.parseTile("x".repeat(64)); codes.push("parseTile accepted a string"); }
      catch (e4) { if (e4.code !== "tlog/bad-input") codes.push("parseTile(string) -> " + (e4.code || e4.name)); }
      return codes.length === 0;
    })());
  /* N6c: widening the set to every BufferSource did not widen it to anything else, and did not move
     where the byte count comes from. A detached buffer and shared memory are each refused typed rather
     than read, and a Buffer whose own `length` property lies about its byte count is still measured by
     the authoritative count: 64 bytes read as two hashes, not as the eight its shadowed length claims. */
  var lying = Buffer.alloc(64, 0x11);
  Object.defineProperty(lying, "length", { value: 8, configurable: true });
  var detached = new ArrayBuffer(64);
  try { structuredClone(detached, { transfer: [detached] }); } catch (_dt) { /* allow:swallow-unverified the transfer is the point; a runtime without it leaves the buffer attached and the check below still answers */ }
  check("N6c: the widened set stops at BufferSource, and the byte count is still the authoritative one",
    (function () {
      var notes = [];
      try {
        var h = pki.tlog.parseTile(lying);
        if (h.length !== 2) notes.push("a shadowed length changed the count to " + h.length);
      } catch (e5) { notes.push("a shadowed length threw " + (e5.code || e5.name)); }
      try { pki.tlog.parseTile(detached); notes.push("a detached buffer was read"); }
      catch (e6) { if (e6.code !== "tlog/bad-input") notes.push("detached -> " + (e6.code || e6.name)); }
      try {
        pki.tlog.parseTile(new Uint8Array(new SharedArrayBuffer(64)));
        notes.push("shared memory was read");
      } catch (e7) { if (e7.code !== "tlog/bad-input") notes.push("shared -> " + (e7.code || e7.name)); }
      return notes.length === 0;
    })());

  /* Altering the text must fail, INCLUDING altering only the delimiter byte. The second is the one
   * a re-serializing parser gets wrong, because it rebuilds the text it wanted rather than reading
   * the text that was signed. */
  var alteredText = note.replace("\n5\n", "\n6\n");
  /* The signature line still names a key the caller supplied, by name and by id,
     so this is the specification's "a signature from a known key fails to verify"
     case and the whole note is rejected. That is a different rule from "no
     signature from a known key verifies", which resolves a false verdict. */
  check("N7: altering a byte of the text rejects the note",
    await codeOfAsync(pki.tlog.verifyNote(alteredText, [{ name: alice.name, publicKey: alice.raw }])) === "tlog/bad-signature");

  /* The signed range includes the text's trailing newline. Proven by signing the
     text WITHOUT it and offering that signature on a well-formed note: the
     verifier hashes the newline the signer did not, so it must not verify.

     The previous form of this vector built its input as
     `text.slice(0, -1) + "\n\n"`, which is byte-identical to `text + "\n"`, so it
     re-signed and re-checked the same note and could only pass; its assertion was
     also written `x === false || true`, which is true whatever x is. Both are
     replaced here. */
  var sigOverShortText = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" },
    alice.pair.privateKey, Buffer.from(text.slice(0, -1), "utf8")));
  var shortSigNote = text + "\n" + EM_DASH + " " + alice.name + " " +
    Buffer.concat([pki.tlog.keyId(alice.name, alice.raw), sigOverShortText]).toString("base64") + "\n";
  check("N8: a signature made over the text without its trailing newline is rejected",
    await codeOfAsync(pki.tlog.verifyNote(shortSigNote, [{ name: alice.name, publicKey: alice.raw }])) === "tlog/bad-signature");

  /* "The note text MAY contain empty lines; the text is separated from the
     signatures by the LAST empty line in the note."
     The distinction is only visible on a note that has more than one empty line:
     splitting at the first makes the text a PREFIX of what the signer signed, so
     the remainder is read as signature lines and the note is refused even though
     it conforms. The signature here is over the FULL text, which is what a log
     would produce. */
  var multiText = "example.com/log\n5\n" + pki.merkle.emptyRootHash().toString("base64") + "\n" +
    "\nan extension line after an empty one\n";
  var multiSig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" },
    alice.pair.privateKey, Buffer.from(multiText, "utf8")));
  var multiNote = multiText + "\n" + EM_DASH + " " + alice.name + " " +
    Buffer.concat([pki.tlog.keyId(alice.name, alice.raw), multiSig]).toString("base64") + "\n";
  check("N8b: the text is separated at the LAST empty line, so an empty line inside it is text",
    pki.tlog.parseNote(multiNote).signedBytes.length === Buffer.byteLength(multiText));
  check("N8c: and a note carrying one verifies under the signature over its whole text",
    (await pki.tlog.verifyNote(multiNote, [{ name: alice.name, publicKey: alice.raw }])).verified === true);
  /* The converse: a signature over only the prefix up to the FIRST empty line is
     what a verifier splitting there would accept, and it must not verify. */
  var prefixText = "example.com/log\n5\n" + pki.merkle.emptyRootHash().toString("base64") + "\n";
  var prefixSig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" },
    alice.pair.privateKey, Buffer.from(prefixText, "utf8")));
  var prefixNote = multiText + "\n" + EM_DASH + " " + alice.name + " " +
    Buffer.concat([pki.tlog.keyId(alice.name, alice.raw), prefixSig]).toString("base64") + "\n";
  check("N8d: a signature over only the prefix before the first empty line is rejected",
    await codeOfAsync(pki.tlog.verifyNote(prefixNote, [{ name: alice.name, publicKey: alice.raw }])) === "tlog/bad-signature");

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
  /* The UTF-8 half of that same clause. A lossy conversion turns a malformed byte into U+FFFD, so the note
     verified and the origin it reported did not encode back to the bytes signed. The bytes are built here
     rather than written as a string, because a string cannot hold a lone 0xFF. */
  var goodNote = Buffer.from("example.com/log\n5\nAAA\n\n" + EM_DASH + " k " + Buffer.alloc(8).toString("base64") + "\n", "utf8");
  check("N13a: control -- the same note as valid UTF-8 parses",
    pki.tlog.parseNote(goodNote).text.indexOf("example.com/log") === 0);
  /* The verify entry points snapshot their note so the bytes verified are the bytes reported, so they owe
     the same cap-before-copy as the parsers: an oversized note was copied in full before the 1 MiB limit
     was read. Measured on `arrayBuffers`, where Buffer data lives. */
  var oversizeNote = Buffer.alloc(64 * 1024 * 1024);
  var beforeAb = process.memoryUsage().arrayBuffers;
  var vnCode = await codeOfAsync(pki.tlog.verifyNote(oversizeNote, []));
  var vcCode = await codeOfAsync(pki.tlog.verifyCheckpoint(oversizeNote, []));
  var grewBy = process.memoryUsage().arrayBuffers - beforeAb;
  check("N13d: verifyNote and verifyCheckpoint refuse an oversized note before copying it (" +
    vnCode + ", " + vcCode + ", " + Math.round(grewBy / 1024) + " KiB for a 65536 KiB input)",
    vnCode === "tlog/bad-input" && vcCode === "tlog/bad-input" && grewBy < 8 * 1024 * 1024);
  var badUtf8 = Buffer.concat([Buffer.from([0xff]), goodNote.subarray(1)]);
  check("N13b: a note that is not valid UTF-8 is refused rather than decoded lossily",
    codeOf(function () { return pki.tlog.parseNote(badUtf8); }) === "tlog/bad-note");
  var badInSig = Buffer.concat([goodNote.subarray(0, goodNote.length - 2), Buffer.from([0xc0]), goodNote.subarray(goodNote.length - 1)]);
  check("N13c: and a malformed byte in the signature half is refused too, the whole note being checked",
    codeOf(function () { return pki.tlog.parseNote(badInSig); }) === "tlog/bad-note");
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

  /* The bytes verified are the bytes reported, even when the caller's buffer changes while the
     verification is pending. Both verbs read the input more than once (the checkpoint is decoded, then
     the note beneath it is verified) and the verification awaits a key import, so a caller that reuses
     or overwrites its buffer in that window could be handed a verdict about one document and a decoded
     root from another. The signed document here is the size-1 one; the buffer starts out holding an
     UNSIGNED size-2 body carrying the size-1 signature, and is overwritten with the signed text as soon
     as the call is made. Nothing may come back that says a size-2 root was signed. */
  var signedBody = "example.com/log\n1\n" + root.toString("base64") + "\n";
  var signedNote = await makeNote(signedBody, [signer]);
  var forgedNote = signedNote.replace("example.com/log\n1\n", "example.com/log\n2\n");
  check("C4a: the two notes are the same length, so one can overwrite the other in place",
    Buffer.byteLength(signedNote, "utf8") === Buffer.byteLength(forgedNote, "utf8"));

  var live = Buffer.from(forgedNote, "utf8");
  var pending = pki.tlog.verifyCheckpoint(live, [{ name: signer.name, publicKey: signer.raw }]);
  Buffer.from(signedNote, "utf8").copy(live);          // swap the bytes while the verify is in flight
  var raced = null, racedCode = null;
  try { raced = await pending; } catch (e) { racedCode = e.code || e.message; }
  var attestedUnsigned = raced !== null && raced.verified === true && raced.checkpoint.treeSize === 2n;
  check("C4b: a buffer swapped during verification cannot yield a verified size-2 root" +
    (racedCode ? " (refused with " + racedCode + ")" : ""), attestedUnsigned === false);
  check("C4c: and whatever it reports, the size it reports is one the signature covers",
    raced === null || raced.verified !== true || raced.checkpoint.treeSize === 1n);

  /* The KEYS are caller-owned too, not just the note. A note carrying several signature lines verifies
     them one at a time, awaiting a key import for each, while the candidate list holds the key material
     the caller passed. A later candidate's buffer can therefore be replaced after its key ID was computed
     from the original, so the ID that decides WHICH key a line is checked against comes from one key and
     the verification from another: a line labeled with B's name and ID gets verified with whatever
     bytes B's buffer holds by the time its turn comes. Here the second line is signed by C, labeled as
     B, and B's buffer becomes C's key while the first line is still being checked. B must not be
     reported as a verified signer. */
  var kA = await makeSigner("log/a");
  var kB = await makeSigner("log/b");
  var kC = await makeSigner("log/c");
  var multiBody = "log/multi\n1\n" + root.toString("base64") + "\n";
  var sigA = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, kA.pair.privateKey,
    Buffer.from(multiBody, "utf8")));
  var sigC = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, kC.pair.privateKey,
    Buffer.from(multiBody, "utf8")));
  // The second line names B and carries B's key ID, but the signature is C's.
  var multiNote = multiBody + "\n" +
    EM_DASH + " " + kA.name + " " + Buffer.concat([pki.tlog.keyId(kA.name, kA.raw), sigA]).toString("base64") + "\n" +
    EM_DASH + " " + kB.name + " " + Buffer.concat([pki.tlog.keyId(kB.name, kB.raw), sigC]).toString("base64") + "\n";
  var liveB = Buffer.from(kB.raw);
  var multiPending = pki.tlog.verifyNote(multiNote, [
    { name: kA.name, publicKey: kA.raw },
    { name: kB.name, publicKey: liveB },
  ]);
  kC.raw.copy(liveB);                     // B's key material becomes C's, mid-verification
  var multi;
  try { multi = await multiPending; } catch (_e) { multi = null; }
  var namedB = multi === null ? [] : multi.signers.filter(function (s) { return s.keyName === kB.name; });
  check("C4g: a key buffer replaced during verification cannot make its line a verified signer",
    namedB.length === 0);
  /* CONTROLS: A alone verifies, and the same note verifies for B when B's key really is C's key from the
     start, so C4g is about the replacement rather than about the note or the keys. */
  var aOnly = await pki.tlog.verifyNote(multiBody + "\n" +
    EM_DASH + " " + kA.name + " " + Buffer.concat([pki.tlog.keyId(kA.name, kA.raw), sigA]).toString("base64") + "\n",
    [{ name: kA.name, publicKey: kA.raw }]);
  check("C4h: CONTROL the first line verifies on its own", aOnly.verified === true && aOnly.signers.length === 1);
  var asC = multiBody + "\n" +
    EM_DASH + " " + kC.name + " " + Buffer.concat([pki.tlog.keyId(kC.name, kC.raw), sigC]).toString("base64") + "\n";
  var cOnly = await pki.tlog.verifyNote(asC, [{ name: kC.name, publicKey: kC.raw }]);
  check("C4i: CONTROL C's signature verifies under C's own name and key",
    cOnly.verified === true && cOnly.signers.length === 1);

  /* The same for verifyNote on its own, which is the verb verifyCheckpoint is built on. */
  var live2 = Buffer.from(forgedNote, "utf8");
  var pending2 = pki.tlog.verifyNote(live2, [{ name: signer.name, publicKey: signer.raw }]);
  Buffer.from(signedNote, "utf8").copy(live2);
  var raced2;
  try { raced2 = await pending2; } catch (_e) { raced2 = null; }
  check("C4d: verifyNote does not report a signature over bytes it did not verify",
    raced2 === null || raced2.verified === false ||
    Buffer.compare(raced2.note.signedBytes, Buffer.from(forgedNote.slice(0, signedBody.length), "utf8")) !== 0);

  /* CONTROL: the untouched signed note verifies, so the refusals above are about the swap. */
  var cleanV = await pki.tlog.verifyCheckpoint(Buffer.from(signedNote, "utf8"),
    [{ name: signer.name, publicKey: signer.raw }]);
  check("C4e: CONTROL the signed size-1 checkpoint verifies on its own",
    cleanV.verified === true && cleanV.checkpoint.treeSize === 1n);
  /* And the forged one is refused on its own. A line naming a key the caller supplied, by name AND id,
     that the key does not verify rejects the whole note rather than reporting false, so the refusal is a
     throw. That is the same verdict the swapped buffer now reaches. */
  var cleanFCode = "NO-THROW";
  try {
    await pki.tlog.verifyCheckpoint(Buffer.from(forgedNote, "utf8"),
      [{ name: signer.name, publicKey: signer.raw }]);
  } catch (e) { cleanFCode = e.code || e.message; }
  check("C4f: CONTROL the unsigned size-2 checkpoint is refused on its own (" + cleanFCode + ")",
    cleanFCode === "tlog/bad-signature" || cleanFCode.indexOf("tlog/") === 0);

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
  /* "Extension lines, if any, MUST be non-empty." A note's text is separated from its signatures at
   * the LAST empty line, so an empty line where an extension would sit is INSIDE the text and does
   * reach the check.
   *
   * This vector previously asserted the opposite outcome and said no input could reach a check,
   * reasoning from the text ending at the FIRST empty line. That was the defect, not the framing:
   * with the split at the last empty line the line is an empty extension and is refused as one. */
  check("C11: an empty extension line is refused as an empty extension",
  (function () {
    var input = "o\n5\n" + root.toString("base64") + "\n\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n";
    return codeOf(function () { pki.tlog.parseCheckpoint(input); }) === "tlog/bad-checkpoint";
  })());
  check("C11b: and an empty line before a real extension is refused too, not skipped",
  (function () {
    var input = "o\n5\n" + root.toString("base64") + "\n\next one\n\n" + EM_DASH + " o " +
        Buffer.alloc(8).toString("base64") + "\n";
    return codeOf(function () { pki.tlog.parseCheckpoint(input); }) === "tlog/bad-checkpoint";
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

  /* The reader is held to the same index range as the writer. `tilePath` bounds an index to uint64, so a
     path it can produce has a fixed maximum number of index segments; the reader accepted any number of
     them and multiplied an ever-growing BigInt for each, which both accepts indices no writer can emit
     and turns a long untrusted path into superlinear synchronous work. */
  var MAX_U64 = 18446744073709551615n;
  var maxPath = pki.tlog.tilePath(0, MAX_U64);
  var maxSegments = maxPath.split("/").length - 2;
  check("T14: the largest index a writer emits round-trips through the reader",
    pki.tlog.parseTilePath(maxPath).index === MAX_U64);
  check("T14a: and it takes " + maxSegments + " index segments, which is the reader's bound",
    maxSegments >= 1 && maxSegments <= 16);

  /* One segment past what a uint64 index can occupy. */
  var tooManyText = "tile/0";
  for (var s = 0; s < maxSegments; s++) tooManyText += "/x000";
  tooManyText += "/001";
  check("T15: a path carrying more index segments than a uint64 index can occupy is refused",
    codeOf(function () { pki.tlog.parseTilePath(tooManyText); }) === "tlog/bad-tile");

  /* In-count but out-of-range: the right number of segments naming a value above 2^64-1. */
  var overText = "tile/0";
  for (var t = 0; t < maxSegments - 1; t++) overText += "/x999";
  overText += "/999";
  var over = codeOf(function () { return pki.tlog.parseTilePath(overText); });
  check("T16: an index within the segment count but above uint64 is refused (" + over + ")",
    over === "tlog/bad-tile");

  /* And a long hostile path is refused rather than walked. Asserted as a refusal on ONE large input
     rather than as a timing ratio, which would be a measurement of the machine. */
  var longText = "tile/0";
  for (var u = 0; u < 50000; u++) longText += "/x000";
  longText += "/001";
  check("T17: a 50001-segment path is refused",
    codeOf(function () { pki.tlog.parseTilePath(longText); }) === "tlog/bad-tile");
  check("T18: the same bound applies to an entry bundle path, which shares the segmented index",
    codeOf(function () { pki.tlog.parseEntryBundlePath(longText.replace("tile/0", "tile/entries")); }) === "tlog/bad-tile" ||
    typeof pki.tlog.parseEntryBundlePath !== "function");
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
  /* And refused BEFORE it is copied. The parser snapshots its input, so an oversized one would otherwise
     cost a second allocation its own size before the limit that rejects it was read. Measured rather than
     asserted, on `arrayBuffers`, which is where Buffer data lives: `heapUsed` does not move for a large
     Buffer and would report a pass either way. A 64 MiB input is 8192 times the tile limit. */
  var oversize = Buffer.alloc(64 * 1024 * 1024);
  var beforeAb = process.memoryUsage().arrayBuffers;
  var oversizeCode = codeOf(function () { return pki.tlog.parseTile(oversize); });
  var grewBy = process.memoryUsage().arrayBuffers - beforeAb;
  check("F4a: an oversized tile is refused with the tile's own code (" + oversizeCode + ")",
    oversizeCode === "tlog/bad-tile");
  check("F4b: and refused before it is copied, the buffer pool growing far less than the input (" +
    Math.round(grewBy / 1024) + " KiB for a 65536 KiB input)", grewBy < 8 * 1024 * 1024);
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
  /* The COUNT is capped, not only the byte length. A zero-length entry costs two bytes on the wire and an
     object in memory, so a megabyte of zeroes is half a million entries: the byte cap admits an input that
     allocates hundreds of megabytes. A tile is 256 wide, which is the bound C2SP tlog-tiles states. */
  var maxEntries = pki.C.LIMITS.TLOG_MAX_ENTRY_BUNDLE_ENTRIES;
  check("E4a: exactly the cap of zero-length entries is accepted",
    pki.tlog.parseEntryBundle(Buffer.alloc(maxEntries * 2)).length === maxEntries);
  check("E4b: one past the cap is refused, though it is far under the byte cap",
    codeOf(function () { return pki.tlog.parseEntryBundle(Buffer.alloc((maxEntries + 1) * 2)); }) === "tlog/bad-bundle");
  check("E4c: and a megabyte of zeroes is refused rather than decoded into half a million entries",
    codeOf(function () { return pki.tlog.parseEntryBundle(Buffer.alloc(1024 * 1024)); }) === "tlog/bad-bundle");
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

  /* A `read` callback is the caller's, and a real one may hand back a SCRATCH buffer it reuses between
     fetches. The hashes a tile is parsed into must be copies, not views into what arrived, or a later fetch
     overwrites proof nodes already collected and the proof folded is not the proof that was served. The
     scratch log below returns the same buffer object every time, refilled. */
  var scratchSrc = tiledLog(70000);
  var scratch = Buffer.alloc(0);
  var scratchReads = 0;
  async function scratchRead(level, index, width) {
    var served = await scratchSrc.read(level, index, width);
    scratchReads += 1;
    if (scratch.length < served.length) scratch = Buffer.alloc(served.length);
    var view = scratch.subarray(0, served.length);
    view.fill(0);
    served.copy(view);
    return view;
  }
  var scratchProof = await pki.tlog.inclusionProof({ index: 0n, size: 70000n, read: scratchRead });
  check("X4a: the scratch log served more than one tile, so the reuse actually happened (" +
    scratchReads + " read(s))", scratchReads >= 2);
  check("X4b: a proof assembled through a read callback that reuses one buffer still folds to the tree head",
    pki.merkle.verifyInclusion({
      leafIndex: 0, treeSize: 70000, leafHash: scratchSrc.leaves[0], proof: scratchProof,
      rootHash: scratchSrc.root,
    }) === true);
  /* The control: the same index through a log that returns a fresh buffer each time folds too, so X4b is
     the copying and not the index being one that needs no second tile. */
  check("X4c: control -- the same index through fresh buffers folds as well",
    pki.merkle.verifyInclusion({
      leafIndex: 0, treeSize: 70000, leafHash: log.leaves[0],
      proof: await pki.tlog.inclusionProof({ index: 0n, size: 70000n, read: log.read }),
      rootHash: log.root,
    }) === true);

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
  /* A real key, not a placeholder: 32 zero bytes are not a valid Edwards point,
     and the low-order gate refuses them at resolution rather than letting an
     unusable key be given an identifier. */
  var realEd = await makeSigner("x21.example");
  check("X21: a key ID is still derived from raw key bytes",
    pki.tlog.keyId("example.com/log", realEd.raw).length === 4);
  check("X21b: and a key that is not a full-order Edwards point never gets one",
    codeOf(function () { pki.tlog.keyId("example.com/log", Buffer.alloc(32)); }) === "tlog/bad-input");
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

// ---------------------------------------------------------------------------
// The three signed-note signature types, and the verifier key text form.
//
// signed-note fixes one derivation per algorithm, and they are NOT variations
// on a theme: Ed25519 hashes the name, a newline, the type byte and the raw 32
// key bytes, while ECDSA hashes the DER SPKI ALONE -- no name, no type byte.
// Sigstore adds an RSA form with type 0xFF and a literal format tag. A verifier
// that applied one derivation to every key would match no key at all on a log
// that does not use its assumed algorithm.
// ---------------------------------------------------------------------------
var RSA_FORMAT_TAG = "PKIX-RSA-PKCS#1v1.5";

function rawOf(spki) {
  return pki.asn1.decode(spki).children[1].content.subarray(1);
}
function sha4(buf) { return nodeCrypto.createHash("sha256").update(buf).digest().subarray(0, 4); }

async function runKeyTypes() {
  /* The specification's own worked verifier key. Confirmed to reproduce before
     this vector was written, so it is a control minted from the spec rather than
     from the implementation. */
  var VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
  var parsed = pki.tlog.parseVkey(VKEY);
  check("K1: the specification's own vkey parses into its three parts",
    parsed.name === "example.com/foo" && parsed.signatureType === 0x01 &&
    parsed.publicKey.length === 32 && parsed.keyId.toString("hex") === "530d903a");
  check("K1b: and the ID it states is the ID its key material derives",
    pki.tlog.keyId(parsed.name, parsed.publicKey).toString("hex") === "530d903a");

  /* Ed25519: name, newline, the type byte, then the RAW key. */
  var ed = await pki.key.generate("Ed25519");
  var edSpki = await pki.key.export(ed.publicKey);
  var edRaw = rawOf(edSpki);
  var expectEd = sha4(Buffer.concat([Buffer.from("a.example\n", "utf8"), Buffer.from([0x01]), edRaw]));
  check("K2: an Ed25519 key ID is SHA-256(name || 0x0A || 0x01 || raw32)[:4]",
    pki.tlog.keyId("a.example", edRaw).toString("hex") === expectEd.toString("hex"));
  /* One key must have one ID however the caller holds it. */
  check("K3: the same Ed25519 key gives the same ID from its SPKI as from its raw bytes",
    pki.tlog.keyId("a.example", edSpki).toString("hex") === expectEd.toString("hex"));

  /* ECDSA: the SPKI alone. The name and the type byte are absent, which is the
     departure the specification calls out, and the point of this vector. */
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecSpki = ec.publicKey.export({ format: "der", type: "spki" });
  check("K4: an ECDSA key ID is SHA-256(spkiDer)[:4], with no name and no type byte",
    pki.tlog.keyId("a.example", ecSpki).toString("hex") === sha4(ecSpki).toString("hex"));
  check("K4b: so the same ECDSA key has one ID under two different names",
    pki.tlog.keyId("a.example", ecSpki).toString("hex") ===
    pki.tlog.keyId("b.example", ecSpki).toString("hex"));
  check("K4c: while an Ed25519 key's ID does depend on its name",
    pki.tlog.keyId("a.example", edRaw).toString("hex") !==
    pki.tlog.keyId("b.example", edRaw).toString("hex"));

  /* RSA: type 0xFF and a literal format tag between it and the SPKI. */
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaSpki = rsa.publicKey.export({ format: "der", type: "spki" });
  var expectRsa = sha4(Buffer.concat([Buffer.from("a.example\n", "utf8"), Buffer.from([0xff]),
    Buffer.from(RSA_FORMAT_TAG, "utf8"), rsaSpki]));
  check("K5: an RSA key ID carries type 0xFF and the PKIX-RSA format tag",
    pki.tlog.keyId("a.example", rsaSpki).toString("hex") === expectRsa.toString("hex"));

  /* An algorithm with no stated derivation is refused, not hashed anyway. */
  var x = nodeCrypto.generateKeyPairSync("x25519");
  check("K6: a key whose algorithm has no stated derivation is refused",
    codeOf(function () { pki.tlog.keyId("a.example", x.publicKey.export({ format: "der", type: "spki" })); }) === "tlog/bad-input");
  check("K6b: and so is a byte string that is neither raw Ed25519 nor an SPKI",
    codeOf(function () { pki.tlog.keyId("a.example", Buffer.alloc(40)); }) === "tlog/bad-input");

  /* parseVkey refusals. The stated ID is checked against the derived one, so a
     vkey cannot name a key it does not carry. */
  check("K7: a vkey with no separators is refused",
    codeOf(function () { pki.tlog.parseVkey("example.com/foo"); }) === "tlog/bad-input");
  check("K7b: a vkey whose stated ID is not 8 hex digits is refused",
    codeOf(function () { pki.tlog.parseVkey("n+53+" + Buffer.from([1]).toString("base64")); }) === "tlog/bad-input");
  check("K7c: a vkey whose stated ID is not the one its key derives is refused",
    codeOf(function () {
      pki.tlog.parseVkey("example.com/foo+deadbeef+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k");
    }) === "tlog/bad-input");
  check("K7d: a vkey with an empty name is refused",
    codeOf(function () { pki.tlog.parseVkey("+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"); }) === "tlog/bad-input");
  check("K7e: a vkey whose blob is empty is refused",
    codeOf(function () { pki.tlog.parseVkey("n+530d903a+"); }) === "tlog/bad-input");
  /* A key name may not carry a plus, so the name is everything before the FIRST
     separator rather than the last; a vkey with three pluses is not a name
     containing one. */
  check("K7f: a name may not carry a plus",
    codeOf(function () {
      pki.tlog.parseVkey("a+b+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k");
    }) === "tlog/bad-input");

  /* The KEY MATERIAL is base64, and standard base64's alphabet includes `+`. The name is everything
     before the FIRST separator and the key ID everything to the SECOND, so only those two pluses are
     separators; a plus after them belongs to the blob. Refusing them rejects roughly half of all real
     Ed25519 verifier keys, since a 44-character base64 field carries a plus more often than not. Built
     by generating keys until one's blob carries a plus, with the search asserted so the vector cannot
     pass by never finding one. */
  var plusVkey = null, searched = 0;
  for (var attempt = 0; attempt < 200 && plusVkey === null; attempt++) {
    searched += 1;
    var plusKp = nodeCrypto.generateKeyPairSync("ed25519");
    var spkiBytes = plusKp.publicKey.export({ format: "der", type: "spki" });
    var rawKey = pki.asn1.decode(spkiBytes).children[1].content.subarray(1);
    var blobB64 = Buffer.concat([Buffer.from([1]), rawKey]).toString("base64");
    if (blobB64.indexOf("+") === -1) continue;
    plusVkey = { name: "example.com/plus", raw: rawKey, b64: blobB64 };
  }
  check("K7g: a key whose base64 material carries a plus was found to test with (after " + searched + ")",
    plusVkey !== null);
  if (plusVkey !== null) {
    var vk = plusVkey.name + "+" + pki.tlog.keyId(plusVkey.name, plusVkey.raw).toString("hex") +
      "+" + plusVkey.b64;
    var parsedPlus = null, plusCode = null;
    try { parsedPlus = pki.tlog.parseVkey(vk); } catch (e) { plusCode = e.code || e.message; }
    check("K7h: and it parses, the plus belonging to the base64 rather than being a third separator" +
      (plusCode ? " (refused with " + plusCode + ")" : ""),
      parsedPlus !== null && Buffer.compare(parsedPlus.publicKey, plusVkey.raw) === 0);
    check("K7i: a note signed under that key verifies, so the parsed key is the usable one",
      parsedPlus !== null && parsedPlus.name === plusVkey.name &&
      parsedPlus.keyId.length === 4);
  }

  /* A note signed under each algorithm verifies, which is what says the key ID
     derivation and the signature check agree about which key is which. */
  var text = "example.com/log\n0\n" + pki.merkle.emptyRootHash().toString("base64") + "\n";
  var msg = Buffer.from(text, "utf8");

  var ecSig = nodeCrypto.sign("sha256", msg, { key: ec.privateKey, dsaEncoding: "der" });
  var ecNote = text + "\n" + EM_DASH + " example.com/log " +
    Buffer.concat([pki.tlog.keyId("example.com/log", ecSpki), ecSig]).toString("base64") + "\n";
  var ecV = await pki.tlog.verifyNote(ecNote, [{ name: "example.com/log", publicKey: ecSpki }]);
  check("K8: a note signed by an ECDSA P-256 log key verifies", ecV.verified === true);

  /* All three curves the specification names, not just the one Rekor happens to
     use: the hash follows the curve, so a P-384 key checked with SHA-256 would
     fail and a claim of three curves tested on one says nothing about the other
     two. */
  var CURVES = [["prime256v1", "sha256"], ["secp384r1", "sha384"], ["secp521r1", "sha512"]];
  var curveOk = 0;
  for (var ci = 0; ci < CURVES.length; ci++) {
    var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: CURVES[ci][0] });
    var spki = kp.publicKey.export({ format: "der", type: "spki" });
    var sg = nodeCrypto.sign(CURVES[ci][1], msg, { key: kp.privateKey, dsaEncoding: "der" });
    var nt = text + "\n" + EM_DASH + " example.com/log " +
      Buffer.concat([pki.tlog.keyId("example.com/log", spki), sg]).toString("base64") + "\n";
    var vv = await pki.tlog.verifyNote(nt, [{ name: "example.com/log", publicKey: spki }]);
    if (vv.verified === true) curveOk++;
  }
  check("K8b: every ECDSA curve the specification names verifies (" + curveOk + "/3)", curveOk === 3);
  /* And the hash is not fixed: a P-384 key whose signature was made with SHA-256
     does not verify, which is what says the curve chose the hash. */
  var p384 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  var p384Spki = p384.publicKey.export({ format: "der", type: "spki" });
  var wrongHashSig = nodeCrypto.sign("sha256", msg, { key: p384.privateKey, dsaEncoding: "der" });
  var wrongHashNote = text + "\n" + EM_DASH + " example.com/log " +
    Buffer.concat([pki.tlog.keyId("example.com/log", p384Spki), wrongHashSig]).toString("base64") + "\n";
  check("K8c: a P-384 signature made with SHA-256 is rejected, so the curve chose the hash",
    await codeOfAsync(pki.tlog.verifyNote(wrongHashNote,
      [{ name: "example.com/log", publicKey: p384Spki }])) === "tlog/bad-signature");

  var rsaSig = nodeCrypto.sign("sha256", msg, rsa.privateKey);
  var rsaNote = text + "\n" + EM_DASH + " example.com/log " +
    Buffer.concat([pki.tlog.keyId("example.com/log", rsaSpki), rsaSig]).toString("base64") + "\n";
  var rsaV = await pki.tlog.verifyNote(rsaNote, [{ name: "example.com/log", publicKey: rsaSpki }]);
  check("K9: a note signed by an RSA log key verifies", rsaV.verified === true);

  /* A signature that does not verify under a key whose name AND ID both match
     rejects the note, per the specification, rather than being skipped. */
  var badEc = Buffer.from(ecSig); badEc[badEc.length - 1] ^= 0x01;
  var badNote = text + "\n" + EM_DASH + " example.com/log " +
    Buffer.concat([pki.tlog.keyId("example.com/log", ecSpki), badEc]).toString("base64") + "\n";
  check("K10: a matched ECDSA key whose signature fails rejects the note",
    await codeOfAsync(pki.tlog.verifyNote(badNote, [{ name: "example.com/log", publicKey: ecSpki }])) === "tlog/bad-signature");
  /* The load-bearing form: a FAILING matched line beside a VALID matched line.
     Without the second line this tests only "nothing verified"; with it, it tests
     that a forged line from a known signer is not masked by a real one. */
  var ed2Sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "Ed25519" }, ed.privateKey, msg));
  var goodEdLine = EM_DASH + " second.example " +
    Buffer.concat([pki.tlog.keyId("second.example", edRaw), ed2Sig]).toString("base64");
  var badThenGood = text + "\n" +
    EM_DASH + " example.com/log " + Buffer.concat([pki.tlog.keyId("example.com/log", ecSpki), badEc]).toString("base64") + "\n" +
    goodEdLine + "\n";
  check("K10b: a valid line does not rescue a note carrying a failing matched line",
    await codeOfAsync(pki.tlog.verifyNote(badThenGood, [
      { name: "example.com/log", publicKey: ecSpki },
      { name: "second.example", publicKey: edRaw },
    ])) === "tlog/bad-signature");
  /* And the control: the same note without the failing line verifies, so the
     refusal above is about that line and not about the note's shape. */
  check("K10c: the same note without the failing line verifies",
    (await pki.tlog.verifyNote(text + "\n" + goodEdLine + "\n",
      [{ name: "second.example", publicKey: edRaw }])).verified === true);
  /* A line naming a key the caller never supplied is ignored, not a failure:
     that is the cosignature case, and it carries no claim to check. */
  var unknownLine = EM_DASH + " witness.example " + Buffer.concat([Buffer.from([1, 2, 3, 4]), Buffer.alloc(64)]).toString("base64");
  check("K10d: a line from a key the caller did not supply is ignored, not a rejection",
    (await pki.tlog.verifyNote(text + "\n" + goodEdLine + "\n" + unknownLine + "\n",
      [{ name: "second.example", publicKey: edRaw }])).verified === true);

  /* The origin binding. A valid signature from log A over log A's tree is not
     evidence about log B, and with two logs pinned that is the whole difference. */
  var okOrigin = await pki.tlog.verifyCheckpoint(ecNote,
    [{ name: "example.com/log", publicKey: ecSpki }], { origin: "example.com/log" });
  check("K11: a checkpoint whose origin is the one pinned for the signing key verifies",
    okOrigin.verified === true && okOrigin.checkpoint.origin === "example.com/log");
  check("K12: a checkpoint whose origin is not the pinned one is refused even though it verifies",
    await codeOfAsync(pki.tlog.verifyCheckpoint(ecNote,
      [{ name: "example.com/log", publicKey: ecSpki }], { origin: "other.example/log" })) === "tlog/origin-mismatch");
  check("K13: with no expected origin the origin is read but not judged",
    (await pki.tlog.verifyCheckpoint(ecNote, [{ name: "example.com/log", publicKey: ecSpki }])).verified === true);
  /* A Rekor v1 origin carries the tree ID after a space, so it is not the key
     name. Reading the origin off the key name would reject every v1 checkpoint. */
  var v1Text = "rekor.sigstore.dev - 1193050959916656506\n0\n" +
    pki.merkle.emptyRootHash().toString("base64") + "\n";
  var v1Sig = nodeCrypto.sign("sha256", Buffer.from(v1Text, "utf8"), { key: ec.privateKey, dsaEncoding: "der" });
  var v1Note = v1Text + "\n" + EM_DASH + " rekor.sigstore.dev " +
    Buffer.concat([pki.tlog.keyId("rekor.sigstore.dev", ecSpki), v1Sig]).toString("base64") + "\n";
  var v1 = await pki.tlog.verifyCheckpoint(v1Note, [{ name: "rekor.sigstore.dev", publicKey: ecSpki }],
    { origin: "rekor.sigstore.dev - 1193050959916656506" });
  check("K14: an origin that is not the key name, as Rekor v1 writes it, still verifies",
    v1.verified === true);
  check("K15: an unknown verifyCheckpoint option is refused",
    await codeOfAsync(pki.tlog.verifyCheckpoint(ecNote,
      [{ name: "example.com/log", publicKey: ecSpki }], { Origin: "x" })) === "tlog/bad-input");
}

async function run() {
  await runNoteFormat();
  await runCheckpoint();
  runTilePaths();
  runTileData();
  runTileWidths();
  await runTileProofs();
  await runKeyTypes();
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
