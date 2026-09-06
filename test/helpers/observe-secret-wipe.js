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
      var before = Buffer.from(this);
      var out = realFill.apply(this, arguments);
      var allZeroAfter = true;
      for (var j = 0; j < this.length; j++) { if (this[j] !== 0) { allZeroAfter = false; break; } }
      // `before` lets a caller count how many DISTINCT copies of one secret were cleared. The
      // argument boundary deep-copies and clears its own copy, whose bytes are identical to a copy a
      // verb takes internally, so a boolean cannot tell the two apart and a count can.
      if (value === 0) records.push({ hadContent: hadContent, allZeroAfter: allZeroAfter, before: before.toString("base64") });
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
  } else if (p.op === "crmf-encryptedkey-sync-fail") {
    // An encryptedKey proof whose validation fails SYNCHRONOUSLY, after the arm has taken its own
    // plaintext copy of the private key. Cleanup attached only to the promise runs on none of these.
    work = pki.crmf.build({ certReqId: 1n, certTemplate: { subject: [{ commonName: "d" }], publicKey: b64(p.spki) },
      pop: { type: "keyEncipherment", method: "encryptedKey", privateKey: callerKey, identifier: "d",
        recipients: [], archive: true } });
  } else if (p.op === "cmc-verify-mac") {
    // A shared-secret recipient given as BYTES. The options snapshot copies it before anything is
    // parsed, so the copy exists on every exit -- including this one, where the response never
    // parses and the MAC is never reached.
    work = pki.cmc.verify(b64(p.csr), { recipient: { identifier: "cmc-client-17", secret: b64(p.secret) } });
  } else if (p.op === "cmc-verify-mac-detached") {
    // The response is a DETACHED ArrayBuffer, so the options snapshot copies the secret and the very
    // next step of the prologue throws. Cleanup attached to the verification promise runs on none of
    // this, because there is no promise yet.
    var ab = new ArrayBuffer(8);
    structuredClone(ab, { transfer: [ab] });
    work = pki.cmc.verify(ab, { recipient: { identifier: "cmc-client-17", secret: b64(p.secret) } });
  } else if (p.op === "cmc-verify-mac-late-throw") {
    // The LAST option the snapshot reads, throwing. The secret copy was taken several steps earlier,
    // so a cleanup guarding only the copying steps never runs.
    // The snapshot reads every own field once to copy it, and reads this one AGAIN at the end, so a
    // getter that answers the first read and throws on the second fails after the copy exists.
    var late = { recipient: { identifier: "cmc-client-17", secret: b64(p.secret) } };
    var lateReads = 0;
    Object.defineProperty(late, "allowUnbound", {
      enumerable: true,
      get: function () { lateReads += 1; if (lateReads > 1) throw new Error("caller getter"); return true; },
    });
    work = pki.cmc.verify(b64(p.csr), late);
  } else if (p.op === "cmc-build-mac-compare-reject") {
    // The comparison copies both secrets, then one input turns out unusable. The copy of the OTHER one
    // still exists and is the one an early return would leave behind.
    work = pki.cmc.build({ requests: [{ tcr: b64(p.csr) }], identityProof: { secret: String(b64(p.secret)) } },
      { mac: { identifier: "cmc-client-17" } });
  } else if (p.op === "cmc-build-mac") {
    work = pki.cmc.build({ requests: [{ tcr: b64(p.csr) }] },
      { mac: { identifier: "cmc-client-17", secret: b64(p.secret) } });
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
