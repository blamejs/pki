// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- validator-keydesc (@internal): the Android Key Attestation KeyDescription
 * conformance (AOSP schema + WebAuthn sec. 8.4.1 authorization-list checks). The
 * `@enforced-by behavioral` contract is that the MUST-reject vectors ARE the guard, so this
 * drives androidKeyDescription() directly with a crafted KeyDescription DER for each
 * rejection, exactly as the cose/attcert/sig/tpm validators are pinned.
 *
 * The validator reads its bytes through the caller's `exts` { find(cert, name) -> {value} }
 * accessor, so a plain stub returns the crafted extension. Two error codes are threaded: a
 * STRUCTURAL `code` (a malformed KeyDescription is bad input) and a semantic `failCode` (a
 * well-formed description that fails an 8.4.1 MUST is a failed verification).
 */

var keydesc = require("../../lib/validator-keydesc");
var asn1 = require("../../lib/asn1-der");
var b = asn1.build;
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message, cause) { return new TestError(code, message, cause); }
var CDH = Buffer.alloc(32, 0x5a);   // the clientDataHash the challenge must equal.

// exts stub: find(cert,"keyDescription") answers with { value: der } (or null when absent).
function exts(der) { return { find: function () { return der ? { value: der } : null; } }; }
function run1(der) { try { keydesc.androidKeyDescription({}, CDH, exts(der), E, "kd/bad", "kd/fail"); return "NO-THROW"; } catch (e) { return e.code; } }

// AuthorizationList field builders: [tag] EXPLICIT <value>.
function purpose(vals) { return b.explicit(1, b.set(vals.map(function (v) { return b.integer(BigInt(v)); }))); }
function origin(v) { return b.explicit(702, b.integer(BigInt(v))); }
function allApplications() { return b.explicit(600, b.nullValue()); }
function al(fields) { return b.sequence(fields); }

// KeyDescription: an 8-field positional SEQUENCE. Only positions 4/6/7 are read; 0-3 and 5
// are placeholder TLVs. `over` overrides { challenge, sw, tee, short }.
function kd(over) {
  over = over || {};
  var kids = [
    b.integer(1n), b.integer(1n), b.integer(1n), b.integer(1n),
    b.octetString(over.challenge || CDH),
    b.octetString(Buffer.alloc(0)),
    over.sw !== undefined ? over.sw : al([purpose([2]), origin(0)]),
    over.tee !== undefined ? over.tee : al([]),
  ];
  if (over.short) kids = kids.slice(0, 6);
  return b.sequence(kids);
}

function run() {
  // Accept: challenge matches, purpose == {SIGN}, origin == GENERATED, no allApplications.
  check("androidKeyDescription accepts a conformant KeyDescription", run1(kd()) === "NO-THROW");
  // The purpose/origin may be split across the two lists (union semantics).
  check("androidKeyDescription accepts purpose/origin split across the two lists",
    run1(kd({ sw: al([purpose([2])]), tee: al([origin(0)]) })) === "NO-THROW");

  // --- structural faults (code) --------------------------------------------------
  check("a missing key-description extension is a structural fault", run1(null) === "kd/bad");
  check("an undecodable extension value is a structural fault", run1(Buffer.from([0x30, 0x82, 0xff, 0xff])) === "kd/bad");
  check("a KeyDescription that is not an 8-field SEQUENCE is a structural fault", run1(kd({ short: true })) === "kd/bad");
  check("a KeyDescription that decodes to a non-constructed node is a structural fault", run1(b.integer(1n)) === "kd/bad");
  check("a KeyDescription whose challenge is not an OCTET STRING is a structural fault",
    run1(b.sequence([b.integer(1n), b.integer(1n), b.integer(1n), b.integer(1n), b.integer(1n), b.octetString(Buffer.alloc(0)), al([purpose([2]), origin(0)]), al([])])) === "kd/bad");
  check("a non-INTEGER origin value is a structural fault",
    run1(kd({ sw: al([purpose([2]), b.explicit(702, b.octetString(Buffer.from([0])))]) })) === "kd/bad");
  check("a non-INTEGER purpose value is a structural fault",
    run1(kd({ sw: al([b.explicit(1, b.set([b.octetString(Buffer.from([2]))])), origin(0)]) })) === "kd/bad");
  check("an empty EXPLICIT origin wrapper (no inner value) is a structural fault",
    run1(kd({ sw: al([purpose([2]), b.explicit(702, Buffer.alloc(0))]) })) === "kd/bad");
  // An authorization list that is not a SEQUENCE (a primitive at position 6/7) declares no
  // authorizations -> the origin MUST-check then fails closed rather than crashing.
  check("a non-SEQUENCE authorization list declares nothing and fails the origin check",
    run1(kd({ sw: b.integer(5n) })) === "kd/fail");

  // --- 8.4.1 semantic faults (failCode) -----------------------------------------
  check("a challenge != clientDataHash fails verification",
    run1(kd({ challenge: Buffer.alloc(32, 0x00) })) === "kd/fail");
  check("allApplications present in the software list fails verification",
    run1(kd({ sw: al([purpose([2]), origin(0), allApplications()]) })) === "kd/fail");
  check("allApplications present in the tee list fails verification",
    run1(kd({ tee: al([allApplications()]) })) === "kd/fail");
  check("no origin declared in either list fails verification",
    run1(kd({ sw: al([purpose([2])]), tee: al([]) })) === "kd/fail");
  check("origin IMPORTED (not GENERATED) fails verification",
    run1(kd({ sw: al([purpose([2]), origin(1)]) })) === "kd/fail");
  check("a mixed GENERATED/IMPORTED origin fails verification",
    run1(kd({ sw: al([purpose([2]), origin(0)]), tee: al([origin(1)]) })) === "kd/fail");
  check("a purpose beyond exactly {SIGN} fails verification",
    run1(kd({ sw: al([purpose([2, 3]), origin(0)]) })) === "kd/fail");
  check("an empty purpose set fails verification",
    run1(kd({ sw: al([origin(0)]) })) === "kd/fail");
  check("a purpose that is not SIGN fails verification",
    run1(kd({ sw: al([purpose([3]), origin(0)]) })) === "kd/fail");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
