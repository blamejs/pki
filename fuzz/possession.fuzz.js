// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 9883, the statement of possession. `pki.possession.parse` over hostile bytes, the
 * PKCS#10 attribute value and the CRMF control value reached through the shipped parsers, and
 * `pki.possession.verifyRequest` over a request whose statement came from the fuzzer.
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: every one of these on hostile input either
 * returns or throws a pki.errors.PkiError -- any other throw is a finding and is rethrown so the
 * fuzzer records a reproducer.
 *
 * `parse` is the interesting target and the reason the whole surface hangs off it: it reads an
 * IssuerAndSerialNumber, then an OPTIONAL whole Certificate, then compares the two for agreement. The
 * comparison walks a decoded certificate's issuer RDNs against a decoded Name's, so a malformed
 * certificate inside a well-formed statement is the shape that reaches furthest, and a statement whose
 * two halves disagree is the one the refusal exists for.
 */
var pki = require("..");
var b = pki.asn1.build;

function guard(fn) {
  try { return fn(); } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}
async function guardAsync(p) {
  try { return await p; } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}
function O(n) { return pki.oid.byName(n); }

var SOP = O("statementOfPossession");
var NAME = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("Fuzz")])])]);
var ALG = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
var SIG = b.bitString(Buffer.alloc(64, 1), 0);
var VALIDITY = b.sequence([
  b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z")),
]);
var SPKI = b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]),
  b.bitString(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 7)]), 0)]);
/** @internal A well-formed certificate whose issuer and serial are known, so a statement can name it
 *  truthfully and the agreement check is reached on its accepting path as well as its refusing one. */
var CERT = b.sequence([
  b.sequence([b.explicit(0, b.integer(2n)), b.integer(0x22n), ALG, NAME, VALIDITY, NAME, b.raw(SPKI)]),
  ALG, SIG,
]);
var CERT_ISN = b.sequence([b.raw(NAME), b.integer(0x22n)]);

module.exports.fuzz = async function (data) {
  /** @internal The fuzzer's bytes as the whole statement. */
  guard(function () { return pki.possession.parse(data); });

  /** @internal And as each half of one, so a well-formed wrapper carries a hostile part. */
  guard(function () { return pki.possession.parse(b.sequence([b.raw(data)])); });
  guard(function () { return pki.possession.parse(b.sequence([CERT_ISN, b.raw(data)])); });
  guard(function () { return pki.possession.parse(b.sequence([b.raw(data), b.raw(CERT)])); });

  /** @internal A statement whose serial comes from the input, which is what drives the agreement check
   *  through both outcomes: most inputs disagree with the certificate and one agrees. */
  var serial = data.length > 1 ? BigInt(data[0]) * 256n + BigInt(data[1]) : 0x22n;
  guard(function () {
    return pki.possession.parse(b.sequence([b.sequence([b.raw(NAME), b.integer(serial)]), b.raw(CERT)]));
  });

  /** @internal Through the shipped PKCS#10 parser, which decodes the attribute in place. */
  var csr = guard(function () {
    var attr = b.sequence([b.oid(SOP), b.set([b.raw(data.length ? data : CERT_ISN)])]);
    var cri = b.sequence([b.integer(0n), NAME, b.raw(SPKI), b.contextConstructed(0, attr)]);
    return b.sequence([cri, ALG, SIG]);
  });
  if (csr) {
    guard(function () { return pki.schema.csr.parse(csr); });
    guard(function () { return pki.lint.csr(csr, { profile: "rfc9883" }); });
    await guardAsync(pki.possession.verifyRequest(csr, { trustAnchors: [CERT], time: new Date(0) }));
  }

  /** @internal And through the CRMF parser, where the same value is a registration control whose bytes
   *  the parser leaves opaque for the statement reader to take. */
  var crmf = guard(function () {
    var ctl = b.sequence([b.oid(SOP), b.raw(data.length ? data : CERT_ISN)]);
    var certReq = b.sequence([b.integer(1n), b.sequence([]), b.sequence([ctl])]);
    return b.sequence([b.sequence([certReq])]);
  });
  if (crmf) {
    var parsedCrmf = guard(function () { return pki.schema.crmf.parse(crmf); });
    if (parsedCrmf) {
      await guardAsync(pki.crmf.verifyPop(crmf));
      guard(function () {
        var controls = parsedCrmf.messages[0].certReq.controls || [];
        return controls.length ? pki.possession.parse(controls[0].value) : null;
      });
    }
  }

  /** @internal The verifier over the fuzzer's bytes as the request and as the supplied certificate. */
  await guardAsync(pki.possession.verifyRequest(data, { trustAnchors: [CERT], time: new Date(0) }));
  if (csr) {
    await guardAsync(pki.possession.verifyRequest(csr,
      { trustAnchors: [CERT], time: new Date(0), signatureCertificate: data }));
  }
};
