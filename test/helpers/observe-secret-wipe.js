// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Observes, from OUTSIDE the toolkit, that a verb clears every copy of a secret it allocated.
//
// It runs as a child process because the observation has to be installed BEFORE the toolkit loads.
// The wipe goes through a fill captured at module load and the guard family freezes its exports, so
// nothing a caller does afterwards can see or divert it -- which is what both defenses are for, and
// the reason a test cannot reach in and wrap the guard. Patching the prototype method first makes
// the capture the toolkit takes the recording one, so every wipe reports the buffer it cleared and
// whether that buffer held anything to clear. It is also the attacker's own seam, which is what
// makes it the honest one to measure through.
//
// Input: a JSON payload on stdin -- { op, ...base64 fields }. Output: one JSON line on stdout,
// { code, wiped: [{ hadContent, allZeroAfter }], callerKeyIntact }. Exit 0 on a completed run.

var chunks = [];
process.stdin.on("data", function (c) { chunks.push(c); });
process.stdin.on("end", function () { run(Buffer.concat(chunks).toString("utf8")); });

var records = [];

function install() {
  // Uint8Array.prototype.fill, not Buffer's: that is the one the wipe captures, and Buffer
  // overrides fill with its own, so patching the subclass would record nothing.
  var realFill = Uint8Array.prototype.fill;
  Object.defineProperty(Uint8Array.prototype, "fill", {
    value: function (value) {
      var hadContent = false;
      for (var i = 0; i < this.length; i++) { if (this[i] !== 0) { hadContent = true; break; } }
      var out = realFill.apply(this, arguments);
      var allZeroAfter = true;
      for (var j = 0; j < this.length; j++) { if (this[j] !== 0) { allZeroAfter = false; break; } }
      if (value === 0) records.push({ hadContent: hadContent, allZeroAfter: allZeroAfter });
      return out;
    },
    writable: true, configurable: true,
  });
}

function b64(s) { return Buffer.from(s, "base64"); }

function run(input) {
  var p = JSON.parse(input);
  install();
  var pki = require("../../index.js");
  var callerKey = b64(p.key);
  var keyBefore = Buffer.from(callerKey);
  var work;
  if (p.op === "ocsp-sign-early-fail") {
    // A response list with no SingleResponse is refused long before signing -- the window a
    // cleanup attached to the signing call alone would miss.
    work = pki.ocsp.sign({ responderID: "byName", responses: [] }, { cert: b64(p.cert), key: callerKey });
  } else if (p.op === "cmc-build") {
    work = pki.cmc.build({ requests: [{ tcr: b64(p.csr) }] }, { cert: b64(p.cert), key: callerKey });
  } else if (p.op === "cmc-build-identity") {
    work = pki.cmc.build({ requests: [{ tcr: b64(p.csr) }],
      identityProof: { secret: b64(p.secret), identity: b64(p.identity) } },
    { cert: b64(p.cert), key: callerKey });
  } else {
    report("RAW:unknown op " + p.op, keyBefore, callerKey);
    return;
  }
  work.then(function () { report("NO-THROW", keyBefore, callerKey); })
    .catch(function (e) { report((e && e.code) || ("RAW:" + (e && e.message)), keyBefore, callerKey); });
}

function report(code, keyBefore, callerKey) {
  process.stdout.write(JSON.stringify({
    code: code, wiped: records, callerKeyIntact: Buffer.compare(keyBefore, callerKey) === 0,
  }) + "\n");
}
