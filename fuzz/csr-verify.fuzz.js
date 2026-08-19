// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 2986 sec. 4.2 proof-of-possession verification via pki.csr.verify.
 *
 * The hostile surface is the DECODER plus the signature engine over attacker-supplied bytes: a
 * certification request arrives from whoever wants a certificate, so pki.csr.verify must, for ANY
 * input, EITHER settle to a boolean verdict OR reject with a typed pki.errors.PkiError. Each round
 * drives two inputs -- the raw fuzz bytes, and those bytes spliced into a genuine request -- so the
 * target reaches both the parse rejections and the paths past them.
 *
 * Contract: any other throw, any non-boolean resolution, and any mutation of a genuine request that
 * still verifies `true` is an unguarded invariant break, so it propagates for jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var S = signing.makeSigner("ec-p256");

var HONEST = null;       // built on the first round, since the harness entry point is async
var HONEST_CRI = null;   // its signed certificationRequestInfo range, the bytes a verdict is about

function isPki(e) { return e instanceof pki.errors.PkiError; }

async function verdictOf(input) {
  var r;
  try {
    r = await pki.csr.verify(input);
  } catch (e) {
    if (isPki(e)) return null;
    throw e;
  }
  if (r === null || typeof r !== "object") throw new Error("csr-verify fuzz: verify settled to a non-object verdict");
  if (typeof r.verified !== "boolean") throw new Error("csr-verify fuzz: the verdict's `verified` is not a boolean");
  // A verdict reports the fields it read, so a caller acting on it is never handed a hole.
  if (r.subject === undefined || r.subjectPublicKeyInfo === undefined ||
    r.attributes === undefined || r.certificationRequestInfoBytes === undefined) {
    throw new Error("csr-verify fuzz: the verdict omits a field it documents");
  }
  return r.verified;
}

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  if (!HONEST) {
    HONEST = await pki.csr.sign({ subject: "fuzz.example", subjectPublicKey: S.spki }, { key: S.key });
    if ((await pki.csr.verify(HONEST)).verified !== true) throw new Error("csr-verify fuzz: a genuine request failed to verify");
    HONEST_CRI = Buffer.from(pki.schema.csr.parse(HONEST).certificationRequestInfoBytes);
  }

  // The raw bytes: almost always a parse rejection, occasionally a structurally valid request. Only
  // the boolean-or-typed-error contract is enforced here. Untrusted is not the same as invalid, and
  // a genuine request reaching this path -- a corpus seed, or one the mutator reassembled -- verifies
  // `true` correctly; asserting otherwise would report the right answer as a crash.
  await verdictOf(d);

  if (!d.length) return;
  // The same bytes overwritten into a genuine request, so the target reaches the paths past parsing.
  var mutated = Buffer.from(HONEST);
  var at = d[0] % mutated.length;
  var n = Math.min(d.length, mutated.length - at);
  d.copy(mutated, at, 0, n);
  if (mutated.equals(HONEST)) return;   // the overwrite was a no-op; the genuine request rightly verifies

  // Which invariant applies depends on WHERE the overwrite landed, and the signed range is the only
  // place a `true` would be a forgery. An edit confined to the outer signatureAlgorithm or
  // signatureValue can still verify legitimately: ECDSA admits the equivalent (r, n-s) encoding of
  // the same signature, so a mutated signature that verifies over unchanged content is the right
  // answer rather than a finding. Comparing the parsed CRI to the honest one separates the two.
  var mutatedCri = null;
  try {
    mutatedCri = Buffer.from(pki.schema.csr.parse(mutated).certificationRequestInfoBytes);
  } catch (e) {
    if (!isPki(e)) throw e;   // unparseable: verdictOf below still holds it to the contract
  }

  var v = await verdictOf(mutated);
  if (v === true && mutatedCri && !mutatedCri.equals(HONEST_CRI)) {
    throw new Error("csr-verify fuzz: a request whose signed certificationRequestInfo bytes were altered " +
      "after signing verified as its own proof of possession");
  }
};
