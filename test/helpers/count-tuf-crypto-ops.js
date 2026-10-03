// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Counts the key imports and signature checks one `pki.tuf.verifySignatures` call performs, for tests
 * that need the WORK a document asks for rather than the verdict it gets.
 *
 * Spawned as its own process, because the toolkit captures the operations it calls when it loads: they
 * have to be wrapped before the require, and a suite that has already loaded the toolkit cannot do
 * that. Run as `node test/helpers/count-tuf-crypto-ops.js <shape> <count>` and it prints one line,
 * `OPS imports=<n> checks=<n> verified=<bool> records=<n>`.
 *
 * A time budget cannot stand in for this. An ed25519 signature whose S is not canonical is refused
 * before the message is hashed, so the cheapest hostile value measures nothing, and the cost of the
 * expensive one is bounded by the metadata size cap at a couple of hundred milliseconds, which is too
 * close to a passing run to assert on. A count separates the two by three orders of magnitude.
 *
 * The shapes:
 *
 *   - `repeats`   one signature value, repeated, each occurrence spelled identically.
 *   - `spellings` one signature VALUE, each occurrence spelled differently by the case of its hex.
 *   - `distinct`  genuinely different signature values, which are different questions and must all be
 *                 asked. This is the control: a memo that answered it from a cache would be dropping
 *                 verifications.
 */

var crypto = require("node:crypto");
var imports = 0, checks = 0;
var realImport = crypto.createPublicKey, realVerify = crypto.verify;
crypto.createPublicKey = function () { imports++; return realImport.apply(crypto, arguments); };
crypto.verify = function () { checks++; return realVerify.apply(crypto, arguments); };

var pki = require("../../index.js");

var shape = process.argv[2];
var count = Number(process.argv[3]);

(async function () {
  var kp = crypto.generateKeyPairSync("ed25519");
  var raw = kp.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  var key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: raw } };
  var id = pki.tuf.keyId(key);
  var keys = {}; keys[id] = key;
  var body = { _type: "targets", spec_version: "1.0.31", version: 1,
    expires: "2030-01-01T00:00:00Z", targets: {}, padding: "p".repeat(200000) };

  // A REAL signature over the body with one byte of R flipped: S stays canonical, so every check hashes
  // the whole body rather than being refused on the encoding.
  var pre = pki.tuf.canonicalJson(body);
  var near = Buffer.from(crypto.sign(null, pre, kp.privateKey));
  near[0] = near[0] ^ 0x01;
  var base = near.toString("hex");

  var letters = [];
  for (var p = 0; p < base.length && letters.length < 16; p++) {
    var c = base.charCodeAt(p);
    if (c >= 0x61 && c <= 0x66) letters.push(p);
  }

  var sigs = [];
  for (var i = 0; i < count; i++) {
    if (shape === "repeats") { sigs.push({ keyid: id, sig: base }); continue; }
    if (shape === "spellings") {
      var out = base.split("");
      for (var j = 0; j < letters.length; j++) {
        if (i & (1 << j)) out[letters[j]] = out[letters[j]].toUpperCase();
      }
      sigs.push({ keyid: id, sig: out.join("") });
      continue;
    }
    if (shape === "distinct") {
      var one = Buffer.from(near);
      one[1] = (one[1] + i) & 0xff;
      one[2] = (one[2] + ((i >> 8) & 0xff)) & 0xff;
      sigs.push({ keyid: id, sig: one.toString("hex") });
      continue;
    }
    throw new Error("unknown shape " + shape);
  }

  var meta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signed: body, signatures: sigs })));
  imports = 0; checks = 0;
  var v = await pki.tuf.verifySignatures({ metadata: meta, keys: keys,
    role: { keyids: [id], threshold: 1 } });
  process.stdout.write("OPS imports=" + imports + " checks=" + checks +
    " verified=" + v.verified + " records=" + sigs.length + "\n");
})().catch(function (e) {
  process.stdout.write("OPS error=" + ((e && e.code) || (e && e.message) || String(e)) + "\n");
  process.exitCode = 1;
});
