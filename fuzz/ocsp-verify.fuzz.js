// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: OCSP response verification via pki.ocsp.verify.
 *
 * libFuzzer / jazzer.js harness. verify parses an OCSPResponse over the strict
 * pki.schema.ocsp codec, then runs the full relying-party gate set against the
 * attacker-controlled bytes: the ResponseBytes OID-dispatch, the nested
 * BasicOCSPResponse re-decode, the embedded responder certificate (attacker-
 * chosen), the responder-authorization decision, the signature over
 * tbsResponseDataBytes, the CertID match, and the currency window. Every one of
 * those surfaces is driven from the fuzzer's bytes; the cert/issuer the caller
 * pins are fixed valid certificates, so the mutated response is the whole attack.
 *
 * Contract: verifying an attacker-controlled response has exactly two acceptable
 * outcomes -- a resolved verdict object ({ status, ... }; a fail-closed "unknown"
 * for any unmet gate is a resolve, not a throw), or a thrown/rejected
 * `pki.errors.PkiError` (OcspError / Asn1Error / OidError / PemError). Any other
 * throw (RangeError, a stack overflow from the nested walk, a bare TypeError, a
 * hang) is an unguarded invariant break: rethrow so jazzer records the reproducer.
 */

var fs = require("fs");
var path = require("path");
var pki = require("..");

// A fixed valid certificate stands in for both the checked cert and its issuer,
// so verify reaches the hostile-response parse + gate path (the pinned inputs are
// never the fuzzed surface). A fixed evaluation time keeps runs deterministic.
var CERT = pki.schema.x509.pemDecode(fs.readFileSync(path.join(__dirname, "..", "test", "fixtures", "inspect", "rich-cert.pem"), "utf8"), "CERTIFICATE");
var TIME = new Date("2023-06-01T00:00:00Z");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  try {
    await pki.ocsp.verify(Buffer.from(data), { cert: CERT, issuer: CERT, time: TIME });
  } catch (e) { if (!isPki(e)) throw e; }
};
