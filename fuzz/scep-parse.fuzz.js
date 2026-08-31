// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: SCEP pkiMessage disassembly via pki.scep.parse (RFC 8894).
 *
 * libFuzzer / jazzer.js harness. parse runs the outer SignedData through pki.cms.verify, refuses
 * a message whose signature does not verify, then reads the transaction attributes (messageType,
 * transactionID, pkiStatus, failInfo, the nonces) BOUND to the verified signer -- every byte of
 * which is attacker-controlled: the DER envelope, the embedded certificates, the signed
 * attributes, the attribute values decoded as PrintableString / OCTET STRING, and the enumerant
 * strings mapped through the message-type / status / failInfo tables.
 *
 * Contract: parsing attacker-controlled input has exactly two acceptable outcomes -- a resolved
 * verdict object, or a thrown/rejected `pki.errors.PkiError`. Any other throw (RangeError, a bare
 * TypeError, a hang) is an unguarded invariant break: rethrow so jazzer records the reproducer.
 *
 * The GetCACaps response parser is fuzzed on the same bytes: it is the other attacker-controlled SCEP
 * text (a CA's capability advertisement, sec. 3.5.2), and its contract is stricter -- it must never
 * throw and must always return a plain object (unknown keywords are ignored, sec. 3.5.2).
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var buf = Buffer.from(data);
  var caps = pki.scep.parseCapabilities(buf);   // MUST NOT throw on any input (sec. 3.5.2)
  if (caps === null || typeof caps !== "object") throw new Error("parseCapabilities returned a non-object");
  try {
    await pki.scep.parse(buf);
  } catch (e) { if (!isPki(e)) throw e; }
};
