// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 5755 sec. 5 attribute-certificate validation via pki.attrcert.verify.
 *
 * The hostile surface is the DECODER plus the signature engine over attacker-supplied bytes: an
 * attribute certificate arrives from whoever holds it, so pki.attrcert.verify must, for ANY input,
 * EITHER settle to a well-formed verdict OR reject with a typed pki.errors.PkiError. Each round
 * drives the raw fuzz bytes and those bytes spliced into a genuine AC, so the target reaches both
 * the parse rejections and the paths past them.
 *
 * Contract: any other throw, any verdict missing a documented field, any verdict that reports
 * `verified` without having checked the signature and the validity, and any mutation of a genuine
 * AC's signed range that still verifies is an unguarded invariant break, so it propagates for
 * jazzer to record.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");
var S = signing.makeSigner("ec-p256");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");
var AT = new Date("2026-06-01T00:00:00Z");
var TRUST = { name: "CN=Example AA", publicKey: S.spki };

var HONEST = null;      // built on the first round, since the harness entry point is async
var HONEST_TBS = null;  // its signed AttributeCertificateInfo range

function isPki(e) { return e instanceof pki.errors.PkiError; }

async function verdictOf(input) {
  var r;
  try {
    r = await pki.attrcert.verify(input, TRUST, { time: AT });
  } catch (e) {
    if (isPki(e)) return null;
    throw e;
  }
  if (r === null || typeof r !== "object") throw new Error("attrcert-verify fuzz: verify settled to a non-object");
  var flags = ["verified", "signatureValid", "validityChecked", "targetingChecked",
    "holderBindingChecked", "issuerPathChecked"];
  for (var i = 0; i < flags.length; i++) {
    if (typeof r[flags[i]] !== "boolean") throw new Error("attrcert-verify fuzz: `" + flags[i] + "` is not a boolean");
  }
  if (!("holder" in r) || !("issuer" in r) || !("attributes" in r) ||
      !("notBefore" in r) || !("notAfter" in r) || !("serialNumberHex" in r)) {
    throw new Error("attrcert-verify fuzz: the verdict omits a field it documents");
  }
  // A verdict that says verified must have said so about checks it actually ran.
  if (r.verified === true && !(r.signatureValid && r.validityChecked && r.targetingChecked)) {
    throw new Error("attrcert-verify fuzz: verified is true while a check it depends on was not performed");
  }
  return r;
}

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  if (!HONEST) {
    HONEST = await pki.attrcert.sign({
      holder: { entityName: { directoryName: "CN=Alice" } },
      notBeforeTime: NB, notAfterTime: NA,
      attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } },
    }, { name: "CN=Example AA", publicKey: S.spki, key: S.key });
    var h = await pki.attrcert.verify(HONEST, TRUST, { time: AT });
    if (h.verified !== true) throw new Error("attrcert-verify fuzz: a genuine attribute certificate failed to verify");
    HONEST_TBS = Buffer.from(pki.schema.attrcert.parse(HONEST).tbsBytes);
  }

  await verdictOf(d);

  if (!d.length) return;
  var mutated = Buffer.from(HONEST);
  var at = d[0] % mutated.length;
  var n = Math.min(d.length, mutated.length - at);
  d.copy(mutated, at, 0, n);
  if (mutated.equals(HONEST)) return;   // the overwrite was a no-op; the genuine AC rightly verifies

  // Only the signed range makes a `true` a forgery. An edit confined to the signature can still
  // verify legitimately, because ECDSA admits the equivalent (r, n-s) encoding of the same value.
  var mutatedTbs = null;
  try {
    mutatedTbs = Buffer.from(pki.schema.attrcert.parse(mutated).tbsBytes);
  } catch (e) {
    if (!isPki(e)) throw e;   // unparseable: verdictOf below still holds it to the contract
  }

  var r = await verdictOf(mutated);
  if (r && r.verified === true && mutatedTbs && !mutatedTbs.equals(HONEST_TBS)) {
    throw new Error("attrcert-verify fuzz: an attribute certificate whose signed bytes were altered " +
      "after signing verified as authentic");
  }
};
