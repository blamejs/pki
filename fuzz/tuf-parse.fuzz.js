// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.tuf.parseMetadata + pki.tuf.canonicalJson + pki.tuf.keyId +
 * pki.tuf.verifySignatures + pki.tuf.updateRoot
 *
 * Runs under libFuzzer via jazzer.js. The contract for the TUF metadata surface:
 * feeding attacker-controlled bytes -- as a raw metadata document, or spliced into
 * a real root's fields against fixed caller key material -- may only ever RESOLVE
 * (a structured verdict) or THROW a pki.errors.PkiError (TufError -- tuf/bad-json,
 * tuf/bad-metadata, tuf/bad-input, tuf/bad-key, tuf/bad-signature, tuf/bad-role,
 * tuf/expired, tuf/rollback, tuf/threshold-unmet, tuf/bad-version). Any other
 * throw -- a raw SyntaxError from the JSON reader, a bare RangeError, a
 * node:crypto assertion, an unhandled rejection, a hang -- is a finding and is
 * rethrown so the fuzzer records a reproducer.
 *
 * The verification side is driven as well as the reader, because the work a
 * document asks for is part of its contract: the signature list, the key map and
 * the role's key list are all attacker-chosen, and the number of signature checks
 * follows the keys the ROLE names rather than the signatures the document lists.
 * The mutator explores the reader (unbalanced braces, deep nesting, duplicate
 * members, numbers that are not integers, non-UTF-8 bytes), the canonical-JSON
 * writer, the key-identifier hash, and each verify leg (a key filed under another
 * key's identifier, a signature that is not readable hexadecimal, a role naming a
 * key the map does not carry, a repeated key identifier, a threshold that cannot
 * be met).
 */
var crypto = require("crypto");
var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

// One real signed root, built once, so the mutator splices into a document whose
// other fields are valid rather than one refused on the first field read.
var PAIR = crypto.generateKeyPairSync("ed25519");
var RAW = PAIR.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
var KEY = { keytype: "ed25519", scheme: "ed25519", keyval: { public: RAW } };
var KEY_ID = pki.tuf.keyId(KEY);
var KEYS = {};
KEYS[KEY_ID] = KEY;
var ROLES = {};
["root", "snapshot", "targets", "timestamp"].forEach(function (r) {
  ROLES[r] = { keyids: [KEY_ID], threshold: 1 };
});
var BODY = { _type: "root", spec_version: "1.0.31", version: 1,
  expires: "2038-01-01T00:00:00Z", consistent_snapshot: true, keys: KEYS, roles: ROLES };
var SIG = crypto.sign(null, Buffer.from(pki.tuf.canonicalJson(BODY)), PAIR.privateKey).toString("hex");
var REAL = JSON.stringify({ signatures: [{ keyid: KEY_ID, sig: SIG }], signed: BODY });

module.exports.fuzz = async function (data) {
  // Target A -- the JSON reader and the metadata shape on raw hostile bytes.
  var parsed = null;
  try { parsed = pki.tuf.parseMetadata(data); } catch (e) { if (!isPki(e)) throw e; }

  // Target B -- the canonical writer and the key-identifier hash on whatever that
  // produced. A document that parsed is re-serialized, which is where a value the
  // reader admitted and the writer cannot spell would surface.
  if (parsed !== null) {
    try { pki.tuf.canonicalJson(parsed.signed); } catch (e) { if (!isPki(e)) throw e; }
    try { pki.tuf.keyId(parsed.signed); } catch (e) { if (!isPki(e)) throw e; }
  }

  if (data.length < 3) return;
  var doc;
  try { doc = JSON.parse(REAL); } catch (_e) { return; }
  var pick = data[0] % 8;
  var text = data.subarray(1).toString("latin1");
  var hex = data.subarray(1).toString("hex");

  // Target C -- verifySignatures with one fuzzer-chosen field overwritten. Each pick
  // drives a different door: the signature's bytes and its spelling, the key the map
  // files, the identifier it is filed under, the role's key list and its threshold.
  if (pick === 0) doc.signatures[0].sig = hex;
  else if (pick === 1) doc.signatures[0].sig = text;
  else if (pick === 2) doc.signatures[0].keyid = text;
  else if (pick === 3) doc.signed.keys[KEY_ID].keyval.public = hex;
  else if (pick === 4) doc.signed.keys[KEY_ID].scheme = text;
  else if (pick === 5) doc.signed.roles.root.keyids = [text, KEY_ID];
  else if (pick === 6) doc.signed.roles.root.threshold = data[1];
  else doc.signatures.push({ keyid: KEY_ID, sig: hex });

  var meta = null;
  try { meta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify(doc))); }
  catch (e) { if (!isPki(e)) throw e; }
  if (meta !== null) {
    try {
      await pki.tuf.verifySignatures({ metadata: meta, keys: doc.signed.keys,
        role: doc.signed.roles.root });
    } catch (e) { if (!isPki(e)) throw e; }

    // Target D -- the root rotation, whose verdict depends on BOTH the trusted root
    // and the candidate, so a mutated candidate drives the version, expiry and
    // threshold rules against a root the caller already trusts.
    //
    // `updateRoot` takes ENCODED documents: it parses each one itself, so handing it
    // the already-parsed metadata refuses on `tuf/bad-input` before a single rotation
    // rule runs, and the catch below accepts that silently. The control under this
    // target exists because an inert target reads as coverage it does not provide.
    await _assertRotationReachable();
    try {
      await pki.tuf.updateRoot({ trustedRoot: Buffer.from(REAL),
        candidates: [Buffer.from(JSON.stringify(doc))],
        now: new Date("2030-01-01T00:00:00Z") });
    } catch (e) { if (!isPki(e)) throw e; }
  }
};

// The PASSING control for Target D, run once. The unmutated document as both the trusted
// root and the candidate must get PAST input validation: it still fails a rotation rule,
// because a candidate at the trusted root's own version is not a rotation, but the code it
// fails in is the code this target exists to drive. A `tuf/bad-input` here means the target
// is refusing its own arguments and fuzzing nothing, which is a finding, not a pass.
var _rotationChecked = false;
async function _assertRotationReachable() {
  if (_rotationChecked) return;
  _rotationChecked = true;
  var code = null;
  try {
    await pki.tuf.updateRoot({ trustedRoot: Buffer.from(REAL), candidates: [Buffer.from(REAL)],
      now: new Date("2030-01-01T00:00:00Z") });
  } catch (e) {
    if (!isPki(e)) throw e;
    code = e.code;
  }
  if (code === "tuf/bad-input") {
    throw new Error("fuzz/tuf-parse Target D is inert: updateRoot refused its own arguments with " +
      "tuf/bad-input, so no rotation rule is being fuzzed");
  }
}
