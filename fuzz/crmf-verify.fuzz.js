// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 4211 sec. 4 proof-of-possession verification via pki.crmf.verifyPop.
 *
 * The hostile surface is the DECODER plus the signature engine over attacker-supplied bytes: a
 * certificate request message arrives from whoever wants a certificate, so pki.crmf.verifyPop must,
 * for ANY input, EITHER settle to a well-formed verdict OR reject with a typed pki.errors.PkiError.
 * Each round drives two inputs, the raw fuzz bytes and those bytes spliced into a genuine request,
 * so the target reaches both the parse rejections and the paths past them.
 *
 * Contract: any other throw, any verdict missing a documented field, and any mutation of a genuine
 * request's signed range that still verifies is an unguarded invariant break, so it propagates for
 * jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var S = signing.makeSigner("ec-p256");

var HONEST = null;       // built on the first round, since the harness entry point is async
var HONEST_REQ = null;   // its signed certReq range, the bytes a verdict is about

function isPki(e) { return e instanceof pki.errors.PkiError; }

async function verdictOf(input) {
  var r;
  try {
    r = await pki.crmf.verifyPop(input);
  } catch (e) {
    if (isPki(e)) return null;
    throw e;
  }
  if (r === null || typeof r !== "object") throw new Error("crmf-verify fuzz: verifyPop settled to a non-object");
  if (typeof r.verified !== "boolean") throw new Error("crmf-verify fuzz: the top-level `verified` is not a boolean");
  if (!Array.isArray(r.messages)) throw new Error("crmf-verify fuzz: the verdict carries no messages array");
  for (var i = 0; i < r.messages.length; i++) {
    var m = r.messages[i];
    if (typeof m.verified !== "boolean") throw new Error("crmf-verify fuzz: a message verdict's `verified` is not a boolean");
    if (typeof m.cryptographicallyVerified !== "boolean") throw new Error("crmf-verify fuzz: a message verdict's `cryptographicallyVerified` is not a boolean");
    if (!("method" in m) || !("certReqId" in m) || !("subject" in m) || !("publicKey" in m)) {
      throw new Error("crmf-verify fuzz: a message verdict omits a field it documents");
    }
    // A verdict that says verified must have said so about a signature it actually checked.
    if (m.verified === true && m.cryptographicallyVerified !== true) {
      throw new Error("crmf-verify fuzz: a verdict reports verified without a cryptographic check");
    }
  }
  return r;
}

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  if (!HONEST) {
    HONEST = await pki.crmf.build({
      certReqId: 1n, certTemplate: { subject: "fuzz.example", publicKey: S.spki },
    }, { key: S.key });
    var h = await pki.crmf.verifyPop(HONEST);
    if (h.verified !== true) throw new Error("crmf-verify fuzz: a genuine request failed to verify");
    HONEST_REQ = Buffer.from(pki.schema.crmf.parse(HONEST).messages[0].certReq.certReqBytes);
  }

  // The raw bytes: almost always a parse rejection, occasionally a structurally valid message. Only
  // the shape contract is enforced here, since a genuine message reaching this path verifies
  // correctly and asserting otherwise would report the right answer as a crash.
  await verdictOf(d);

  if (!d.length) return;
  var mutated = Buffer.from(HONEST);
  var at = d[0] % mutated.length;
  var n = Math.min(d.length, mutated.length - at);
  d.copy(mutated, at, 0, n);
  if (mutated.equals(HONEST)) return;   // the overwrite was a no-op; the genuine request rightly verifies

  // Where the overwrite landed decides which invariant applies. Only the signed certReq range makes
  // a `true` a forgery: an edit confined to the signature can still verify legitimately, because
  // ECDSA admits the equivalent (r, n-s) encoding of the same signature.
  var mutatedReq = null;
  try {
    mutatedReq = Buffer.from(pki.schema.crmf.parse(mutated).messages[0].certReq.certReqBytes);
  } catch (e) {
    if (!isPki(e)) throw e;   // unparseable: verdictOf below still holds it to the contract
  }

  var r = await verdictOf(mutated);
  if (r && r.verified === true && mutatedReq && !mutatedReq.equals(HONEST_REQ)) {
    throw new Error("crmf-verify fuzz: a request whose signed certReq bytes were altered after " +
      "signing verified as its own proof of possession");
  }
};
