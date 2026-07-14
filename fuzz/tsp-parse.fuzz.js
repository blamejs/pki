// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.tsp.parse + parseRequest + parseTstInfo +
 * parseToken, plus pki.tsp.verify when the surface exports it.
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. All four RFC 3161 entry
 * points are driven on the same input — a TimeStampReq, a TimeStampResp,
 * a bare TSTInfo, and a TimeStampToken are all DER SEQUENCEs, so every
 * seed in fuzz/tsp-parse_seed_corpus/ exercises every front door; the
 * token path additionally drives the CMS composition and the nested
 * TSTInfo re-decode.
 *
 * When the toolkit exports pki.tsp.verify, every iteration also drives
 * one of two verification modes selected by input parity (the
 * cms-verify.fuzz.js dispatch): an even-length input is hostile
 * TimeStampToken bytes verified against fixed data; an odd-length input
 * is hostile data verified against a valid token built once over the
 * fixed data's sha256 imprint, so the hostile bytes flow through the
 * message-imprint hash + comparison behind a verified CMS signature.
 *
 * Contract: parsing or verifying an attacker-controlled timestamp
 * structure has exactly two acceptable outcomes — a successful parse (or
 * a resolved verdict object), or a thrown/rejected `pki.errors.PkiError`
 * (TspError / CmsError / Asn1Error / OidError / PemError). Any other
 * throw (RangeError, a stack overflow from the nested walk, a bare
 * TypeError, a hang) means the parser surfaced an unguarded invariant
 * break on hostile input: rethrow it so jazzer records the reproducer.
 */

var crypto = require("node:crypto");
var pki = require("..");
var TSA = require("../test/helpers/signing").makeSigner("ec-p256");

// The verification modes run only when the surface exports
// pki.tsp.verify; the parse entry points are the core target either way.
var HAS_VERIFY = typeof pki.tsp.verify === "function";

// Fixed content (odd length, so the corpus can reach the matching-imprint
// verify path): mode A verifies hostile token bytes against it; the
// mode-B token covers its sha256 imprint.
var DATA = Buffer.from("tsp-parse fuzz: the timestamped document.");
var tokenPromise = null;
function validToken() {
  if (tokenPromise === null) {
    var imprint = { hashAlgorithm: "sha256", hashedMessage: crypto.createHash("sha256").update(DATA).digest() };
    tokenPromise = pki.tsp.sign(imprint, TSA, { policy: "1.3.6.1.4.1.1", serialNumber: 1 }).catch(function (e) {
      // A fixed valid input must sign: surface a harness-fixture break as
      // a non-PkiError finding instead of masking mode B forever.
      throw new Error("tsp-parse harness: fixed-input pki.tsp.sign failed: " + e.message);
    });
  }
  return tokenPromise;
}

function drive(fn, data) {
  try {
    fn(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
}

module.exports.fuzz = async function (data) {
  drive(pki.schema.tsp.parse, data);
  drive(pki.schema.tsp.parseRequest, data);
  drive(pki.schema.tsp.parseTstInfo, data);
  drive(pki.schema.tsp.parseToken, data);
  if (!HAS_VERIFY) return;
  var buf = Buffer.from(data);
  try {
    if (buf.length & 1) {
      // Mode B: valid token, attacker-controlled data.
      await pki.tsp.verify(await validToken(), buf);
    } else {
      // Mode A: the whole TimeStampToken DER is hostile.
      await pki.tsp.verify(buf, DATA);
    }
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
