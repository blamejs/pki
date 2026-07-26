// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.smime.verify (RFC 8551 S/MIME message layer).
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = async function (data). The contract: verifying hostile
 * message bytes either resolves or rejects/throws a pki.errors.PkiError -- any
 * other throw (or a hang) is a finding and is rethrown so the fuzzer records a
 * reproducer. This exercises the MIME frame parse (header split, folding,
 * multipart boundary walk), the RFC 8551 sec. 3.1.1 canonicalizer, the base64
 * transfer-encoding decode, and the delegation into the CMS verify path -- a
 * distinct surface from fuzz/smime-parse.fuzz.js (the ESS attribute decoders).
 * With opts.legacyHeaderProtection it also drives the RFC 9788 sec. 4.10 legacy
 * detection path, which parses the recovered Cryptographic Payload as a nested
 * message/rfc822 (part C) and its inner message (part D) -- both attacker-shaped.
 */
var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var buf = Buffer.from(data);
  // Two INDEPENDENT invocations: the legacy-enabled call must run even when the baseline verify throws on
  // malformed MIME/CMS, or the sec. 4.10 nested message/rfc822 parse would be unreachable (a thrown baseline
  // would jump straight past it). The `legacy_rfc8551hp.bin` seed carries a valid signature over a message/rfc822
  // wrap, so this path reaches the nested part-C/part-D parse and the outer-header confidentiality/mismatch scan;
  // mutating its unsigned outer section keeps the signature valid and fuzzes that surface.
  try { await pki.smime.verify(buf); }
  catch (e) { if (!isPki(e)) throw e; }
  try { await pki.smime.verify(buf, { legacyHeaderProtection: true }); }
  catch (e) { if (!isPki(e)) throw e; }
};
