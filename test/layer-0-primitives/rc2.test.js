// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lib/rc2.js, the in-tree RFC 2268 RC2-CBC used only by pki.pkcs12.open's legacy-PBE bag
 * decryption (RFC 7292 App. C). The load-bearing contract is the RFC 2268 sec. 5 known-answer vectors: the
 * cipher core (key expansion with the effective-key-bits reduction + the 16-mix/2-mash schedule) must match
 * the published (key, effective-bits, plaintext, ciphertext) tuples byte-for-byte, and CBC must round-trip
 * with PKCS#7 padding and fail closed on a bad length / invalid pad.
 */

var helpers = require("../helpers");
var check = helpers.check;
var rc2 = require("../../lib/rc2.js");

function E(code, message) { var e = new Error(message); e.code = code; return e; }   // a (code, msg) FACTORY, matching pkcs12's _err (rc2.cbcDecrypt throws E(...) no-new)
function fault(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || "RAW"; } }
function h(s) { return Buffer.from(s.replace(/ /g, ""), "hex"); }

function run() {
  // RFC 2268 sec. 5 test vectors: [key, effective-bits, plaintext, ciphertext].
  var V = [
    ["0000000000000000", 63, "0000000000000000", "ebb773f993278eff"],
    ["ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"],
    ["3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"],
    ["88", 64, "0000000000000000", "61a8a244adacccf0"],
    ["88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"],
    ["88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"],
    ["88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"],
    ["88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", 129, "0000000000000000", "5b78d3a43dfff1f1"],
  ];
  V.forEach(function (v, i) {
    check((i + 1) + ". RFC 2268 sec. 5 vector " + (i + 1) + " encrypts to the published ciphertext", rc2.encryptBlock(h(v[0]), v[1], h(v[2])).toString("hex") === v[3]);
    check((i + 1) + "d. RFC 2268 sec. 5 vector " + (i + 1) + " decrypts back to the plaintext", rc2.decryptBlock(h(v[0]), v[1], h(v[3])).toString("hex") === v[2]);
  });

  // ---- CBC round-trip (PKCS#7 padding) ----
  var key = h("0102030405"), iv = h("a0a1a2a3a4a5a6a7");   // 40-bit key + 8-byte IV, as a legacy RC2-40 bag uses
  ["", "x", "8 bytes!", "exactly sixteen!", "an odd length string of some size"].forEach(function (s, i) {
    var pt = Buffer.from(s);
    var ct = rc2.cbcEncrypt(key, 40, iv, pt);
    check("9." + i + " RC2-40-CBC round-trips a " + pt.length + "-byte message", ct.length % 8 === 0 && rc2.cbcDecrypt(key, 40, iv, ct, E, "rc2/bad").equals(pt));
  });
  var ct128 = rc2.cbcEncrypt(h("0102030405060708090a0b0c0d0e0f10"), 128, iv, Buffer.from("128-bit RC2 body"));
  check("10. RC2-128-CBC round-trips", rc2.cbcDecrypt(h("0102030405060708090a0b0c0d0e0f10"), 128, iv, ct128, E, "rc2/bad").toString() === "128-bit RC2 body");

  // ---- fail-closed ----
  check("11. a non-multiple-of-8 ciphertext -> typed fault", fault(function () { rc2.cbcDecrypt(key, 40, iv, h("0011223344"), E, "rc2/bad"); }) === "rc2/bad");
  check("12. an empty ciphertext -> typed fault", fault(function () { rc2.cbcDecrypt(key, 40, iv, Buffer.alloc(0), E, "rc2/bad"); }) === "rc2/bad");
  // a block whose decrypt yields an invalid PKCS#7 pad (wrong key) -> typed fault (the pkcs12 caller collapses this to its uniform verdict)
  check("13. an out-of-range PKCS#7 pad length -> typed fault", fault(function () { rc2.cbcDecrypt(h("ffffffffff"), 40, iv, ct128, E, "rc2/bad"); }) === "rc2/bad");
  // an 8-byte message pads to a full 0x08*8 block; flipping a byte in the PRIOR ciphertext block flips one byte
  // of that pad plaintext (CBC chaining) while the last byte (pad length 8) stays valid -> an inconsistent pad.
  var full = rc2.cbcEncrypt(key, 40, iv, Buffer.from("8bytes!!"));
  var tampered = Buffer.from(full); tampered[0] ^= 1;
  check("14. an inconsistent multi-byte PKCS#7 pad -> typed fault", fault(function () { rc2.cbcDecrypt(key, 40, iv, tampered, E, "rc2/bad"); }) === "rc2/bad");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
