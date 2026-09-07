// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: a centrally generated private key delivered in a CMP response, via
 * pki.cmp.openKeyPackage (RFC 9483 sec. 4.1.6).
 *
 * libFuzzer / jazzer.js harness. The verb undoes two attacker-controlled layers and then reads a
 * third structure: a CMS EnvelopedData (or the bare EnvelopedData the CMP wire carries) whose
 * recipient infos, wrapped key, algorithm parameters and ciphertext are all mutated bytes; the CMS
 * SignedData inside it, with its certificate bag, signer infos and signed attributes; and the RFC
 * 5958 AsymmetricKeyPackage the signature covers. The fixed inputs are one recipient keypair, one
 * shared secret and one trust anchor; everything the message carries is the attack surface.
 *
 * Contract: opening attacker-controlled bytes has exactly two acceptable outcomes -- a resolved
 * result object, or a thrown/rejected `pki.errors.PkiError` (CmpError / CmsError / Asn1Error /
 * OidError / PemError / PathError). Any other throw (RangeError, a bare TypeError, a stack
 * overflow, a hang) is an unguarded invariant break -- rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var makeRecipient = require("../test/helpers/signing").makeRecipient;
var makeSigner = require("../test/helpers/signing").makeSigner;

// A recipient set and anchor generated once per process, so no private key is committed. What the
// committed seeds reach follows from that: the password technique opens, since the secret below is
// fixed, and the shared-secret exemption authorizes, so a seed drives the CMS decrypt, the SignedData
// signature and the key package all the way through. The key transport and key agreement techniques
// cannot decrypt a committed seed, because the keys differ every run, and a seed naming a chain to an
// anchor cannot authorize against an anchor minted this run. Mutations reach those arms as malformed
// input rather than as a container that opens. Closing that needs containers built in-process from
// these credentials; `.references/backlog/fuzz-key-package-live-containers.md` carries the plan.
var RSA = makeRecipient("rsa");
var EC = makeRecipient("ec-p256");
var ANCHOR = makeSigner("ec-p256").cert;
var OPTS = [
  { key: RSA.key, cert: RSA.cert, trustAnchors: [ANCHOR] },
  { key: RSA.key, trustAnchors: [ANCHOR] },
  { key: EC.key, cert: EC.cert, trustAnchors: [ANCHOR] },
  { password: "fuzz-password", trustAnchors: [ANCHOR] },
  { password: "fuzz-password", authorizedBySharedSecret: true },
];

function isPki(e) { return e instanceof pki.errors.PkiError; }

// The FIRST byte selects the key material and the REST is the container, so the selector is a byte the
// fuzzer owns rather than one the input format fixes. Selecting on the container's own first byte
// reached one arm only: every input that survives the DER decode opens with 0x30, so the remaining
// arms were entered by nothing that got as far as the key-management code. Each committed seed carries
// its selector prefix.
module.exports.fuzz = async function (data) {
  if (data.length < 2) return;
  var buf = Buffer.from(data.subarray(1));
  var opts = OPTS[data[0] % OPTS.length];
  try {
    await pki.cmp.openKeyPackage(buf, opts);
  } catch (e) { if (!isPki(e)) throw e; }
};
