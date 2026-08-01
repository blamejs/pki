// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: lib/http-digest.js parseChallenge (+ answer on a parsed result)
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). http-digest is @internal (not on pki.*),
 * so it is required directly and handed a PkiError factory as its E argument. The
 * contract for this hostile-input HTTP-header parser: parsing an attacker-controlled
 * WWW-Authenticate challenge either returns a challenge object (answered without a
 * raw crash) or throws the supplied PkiError -- any other throw (a bare TypeError /
 * RangeError, a ReDoS hang) is a finding and is rethrown so the fuzzer records a
 * reproducer. Exercises the RFC 7616 sec. 3.3 quoted-string tokenizer (a comma /
 * scheme / '=' inside a quoted value, escapes, duplicate params, the length cap, the
 * control-octet reject) and the sec. 3.4 A1/A2/response computation.
 */
var httpDigest = require("../lib/http-digest");
var pki = require("..");

function E(code, msg) { return new pki.errors.PkiError(msg, code); }

module.exports.fuzz = function (data) {
  var s = data.toString("latin1");
  try {
    var ch = httpDigest.parseChallenge(s, E, "digest/bad-challenge");
    if (ch) {
      // A structurally valid challenge must yield a header or a typed PkiError, never a raw crash. Opt into the
      // weak-algorithm / no-qop paths so the answer branches are reachable; the cnonce rng is deterministic.
      httpDigest.answer(ch, {
        method: "POST", uri: "/x", username: "u", password: "p", body: s.slice(0, 32),
        policy: { allowMD5: true, allowLegacyQop: true }, rng: function () { return "Y2Nvbm9uY2U"; },
      }, E);
    }
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
