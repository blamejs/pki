// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: CMS SignedData signature verification via pki.cms.verify.
 *
 * libFuzzer / jazzer.js harness. verify parses a SignedData over the strict pki.schema.cms
 * codec, locates each signer certificate, and checks the signature over the RFC 5652 sec. 5.4
 * preimage through the WebCrypto engine -- every byte of which (the encapsulated or detached
 * content, the embedded certificates, the signed attributes, the signature) is attacker-
 * controlled. This target drives two hostile surfaces: the whole SignedData DER, and, against
 * a valid detached SignedData, an attacker-chosen external content (which flows into the
 * message-digest comparison and the signature preimage).
 *
 * Contract: verifying attacker-controlled input has exactly two acceptable outcomes -- a
 * resolved verdict object ({ valid, signers }), or a thrown/rejected `pki.errors.PkiError`.
 * Any other throw (RangeError, a bare TypeError, a hang) is an unguarded invariant break:
 * rethrow so jazzer records the reproducer.
 */

var fs = require("fs");
var path = require("path");
var pki = require("..");

// A valid detached SignedData, loaded once. Mode B splices the fuzzer's bytes in as the
// external content so the digest + preimage path runs on hostile input.
var DETACHED = fs.readFileSync(path.join(__dirname, "..", "test", "fixtures", "cms", "rsa-detached.p7s"));

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var buf = Buffer.from(data);
  try {
    if (data.length & 1) {
      // Mode B: valid detached envelope, attacker-controlled content.
      await pki.cms.verify(DETACHED, { content: buf });
    } else {
      // Mode A: the whole SignedData DER is hostile.
      await pki.cms.verify(buf);
    }
  } catch (e) { if (!isPki(e)) throw e; }
};
