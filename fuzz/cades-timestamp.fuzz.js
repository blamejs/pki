// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the CAdES signature-timestamp verbs, pki.cms.timestampImprint and
 * pki.cms.attachTimestamp, plus the timestamp row pki.cms.verify builds.
 *
 * libFuzzer / jazzer.js harness. Each of the four modes puts attacker bytes where an operator's
 * input goes: the message an imprint is taken over, the token handed to the attach verb, the
 * message spliced into, and the attribute value a verifier reads back. The attribute value is the
 * one an attacker reaches without touching a signature: it lives in `unsignedAttrs`, which no
 * signature covers, so a verifier reads hostile bytes out of an otherwise valid message.
 *
 * Contract: attacker-controlled input has exactly two acceptable outcomes -- a resolved value (a
 * Buffer, an imprint record, or a verdict carrying the failure on its timestamp row), or a
 * thrown/rejected `pki.errors.PkiError`. Any other throw (RangeError, a bare TypeError, a hang) is
 * an unguarded invariant break: rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var signing = require("../test/helpers/signing");

var b = pki.asn1.build;
var CONTENT = Buffer.from("CAdES fuzz content");
var SIGNER = signing.makeSigner("ec-p256");
var TSA = signing.makeTsa("ec-p256");

// The valid material each mode splices hostile bytes into, minted once on the first call.
var _ready = null;
function ready() {
  if (_ready === null) {
    _ready = (async function () {
      var base = await pki.cms.sign(CONTENT, { cert: SIGNER.cert, key: SIGNER.key });
      var imprint = await pki.cms.timestampImprint(base);
      var token = await pki.tsp.sign({ hashAlgorithm: imprint.hashAlgorithm, hashedMessage: imprint.hashedMessage },
        TSA, { policy: "1.2.3.4.1", serialNumber: 3 });
      return { base: base, token: token, stamped: await pki.cms.attachTimestamp(base, token) };
    })();
  }
  return _ready;
}

// Replace the single signature-timestamp attribute's value with `value`, leaving every byte a
// signature covers alone. This is the splice an attacker performs on a message in transit.
function withTimestampValue(baseDer, value) {
  var root = pki.asn1.decode(baseDer);
  var sd = root.children[1].children[0];
  var siSet = sd.children[sd.children.length - 1];
  var kids = siSet.children[0].children.map(function (k) { return k.bytes; });
  var attr = b.sequence([b.oid(pki.oid.byName("timeStampToken")), b.set([value])]);
  var tagged = Buffer.from(b.set([attr]));
  tagged[0] = 0xA1;                       // [1] IMPLICIT unsignedAttrs
  kids.push(tagged);
  var sdKids = sd.children.map(function (k, i) {
    return i === sd.children.length - 1 ? b.set([b.sequence(kids)]) : k.bytes;
  });
  return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
}

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var buf = Buffer.from(data);
  var fixed = await ready();
  try {
    var mode = data.length % 4;
    if (mode === 0) {
      // The message an imprint is taken over.
      await pki.cms.timestampImprint(buf);
    } else if (mode === 1) {
      // The token an operator received from an authority.
      await pki.cms.attachTimestamp(fixed.base, buf);
    } else if (mode === 2) {
      // The message being stamped, with a token that is valid for a different one.
      await pki.cms.attachTimestamp(buf, fixed.token);
    } else {
      // The attribute value a verifier reads back out of unsignedAttrs, which no signature covers.
      var res = await pki.cms.verify(withTimestampValue(fixed.base, buf), { certs: [SIGNER.cert] });
      var rows = res.signers[0].signatureTimeStamps;
      if (rows.length === 1 && rows[0].valid !== false && rows[0].valid !== true) {
        throw new Error("a signature-timestamp row resolved without a verdict");
      }
    }
  } catch (e) { if (!isPki(e)) throw e; }
};
