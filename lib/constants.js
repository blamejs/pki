// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.C
 * @nav        Core
 * @title      Constants
 * @order      10
 * @featured   true
 * @slug       constants
 *
 * @intro
 *   Version-stable constant namespace for the toolkit. Scale values are
 *   FUNCTIONS, not pre-baked discrete numbers: `C.TIME.days(30)` reads
 *   at the call site and computes at boot, so a caller never hand-writes
 *   `30 * 24 * 60 * 60 * 1000` (a raw-literal the codebase gate refuses)
 *   and a reviewer never has to decode it.
 *
 *   Every scale helper is config-time / entry-point validation: it THROWS
 *   `ConstantsError` on a non-finite or negative argument, so an operator
 *   catches the typo at boot rather than shipping a silently-wrong window.
 *
 * @card
 *   Functional scale helpers (`C.TIME.*`, `C.BYTES.*`) plus the toolkit
 *   version and shared codec limits.
 */

var frameworkError = require("./framework-error");

var ConstantsError = frameworkError.ConstantsError;

// _positive(n, who) — the shared guard every scale helper runs. Config-
// time tier: a bad scale argument is an authoring bug, so it throws.
function _positive(n, who) {
  if (typeof n !== "number" || !isFinite(n) || n < 0) {
    throw new ConstantsError(
      "constants/bad-scale",
      who + ": expected a finite number >= 0, got " + String(n)
    );
  }
  return n;
}

var MS_PER_SECOND = 1000;
var SECONDS_PER_MINUTE = 60;
var MINUTES_PER_HOUR = 60;
var HOURS_PER_DAY = 24;
var DAYS_PER_WEEK = 7;

/**
 * @primitive  pki.C.TIME
 * @signature  C.TIME.days(n) -> milliseconds
 * @since      0.1.0
 * @status     stable
 * @spec       internal (design: functional time-scale helpers)
 *
 * Duration helpers. Each returns an integer count of milliseconds so the
 * value drops straight into `setTimeout`, a validity window, or an OCSP
 * `nextUpdate` computation. Composing reads naturally:
 * `C.TIME.days(365)` for a one-year certificate lifetime.
 *
 * @example
 *   var oneYear = pki.C.TIME.days(365);
 *   // -> 31536000000
 */
var TIME = {
  milliseconds: function (n) { return Math.round(_positive(n, "C.TIME.milliseconds")); },
  seconds: function (n) { return Math.round(_positive(n, "C.TIME.seconds") * MS_PER_SECOND); },
  minutes: function (n) { return Math.round(_positive(n, "C.TIME.minutes") * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  hours:   function (n) { return Math.round(_positive(n, "C.TIME.hours") * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  days:    function (n) { return Math.round(_positive(n, "C.TIME.days") * HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
  weeks:   function (n) { return Math.round(_positive(n, "C.TIME.weeks") * DAYS_PER_WEEK * HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND); },
};

var BYTES_PER_KIB = 1024;

/**
 * @primitive  pki.C.BYTES
 * @signature  C.BYTES.mib(n) -> bytes
 * @since      0.1.0
 * @status     stable
 * @spec       IEC 80000-13
 *
 * Binary-magnitude size helpers. Each returns an integer byte count for
 * codec limits (max DER input, max PEM block) so a size bound reads as
 * `C.BYTES.mib(16)` instead of `16 * 1024 * 1024`.
 *
 * @example
 *   var cap = pki.C.BYTES.mib(16);
 *   // -> 16777216
 */
var BYTES = {
  b:   function (n) { return Math.round(_positive(n, "C.BYTES.b")); },
  kib: function (n) { return Math.round(_positive(n, "C.BYTES.kib") * BYTES_PER_KIB); },
  mib: function (n) { return Math.round(_positive(n, "C.BYTES.mib") * BYTES_PER_KIB * BYTES_PER_KIB); },
  gib: function (n) { return Math.round(_positive(n, "C.BYTES.gib") * BYTES_PER_KIB * BYTES_PER_KIB * BYTES_PER_KIB); },
};

// LIMITS — shared codec ceilings. A DER document larger than this, or
// nested deeper than this, is refused before the parser walks it: an
// unbounded length prefix or a pathologically-nested SEQUENCE is a
// classic decoder-DoS, so the bound is a fail-closed default rather
// than a tunable an operator must remember to set.
//
// DER_MAX_INTEGER_BYTES and OID_MAX_SUBIDENTIFIER_BYTES are per-value
// ceilings the whole-document cap can't provide: a single INTEGER or OID
// sub-identifier under the 16 MiB limit can still carry hundreds of KiB,
// so a value reader that scales super-linearly in its content length is a
// decoder-DoS the document cap does not stop. 16 KiB covers any real key
// material (an RSA-131072 modulus), and 32 bytes covers any real OID arc:
// the largest standard sub-identifier is a 128-bit UUID-based arc (X.667,
// e.g. 2.25.<uuid>), which is 19 base-128 bytes — so the cap must exceed
// that, not sit at 16. Anything larger than 32 bytes is refused as hostile.
var LIMITS = {
  DER_MAX_BYTES: BYTES.mib(16),
  DER_MAX_DEPTH: 64,
  PEM_MAX_BYTES: BYTES.mib(16),
  DER_MAX_INTEGER_BYTES: BYTES.kib(16),
  OID_MAX_SUBIDENTIFIER_BYTES: 32,
  // Certificate Transparency SCT-list bounds (RFC 6962 §3.3). The 2-byte outer
  // vector header structurally caps a well-formed list at 65535 bytes, but the
  // input-size and per-list count caps are asserted BEFORE iteration so a
  // hostile length prefix cannot drive unbounded work (the CVE-2022-0778 class:
  // crafted bytes inside a certificate extension pinning a validator). A real
  // chain carries 2–5 SCTs; 256 is far above any policy requirement.
  SCT_MAX_BYTES: BYTES.kib(64),
  SCT_MAX_COUNT: 256,
  // Certification-path length ceiling: bounds the per-cert asymmetric verify
  // work on an untrusted certificate bundle (a real chain is well under this;
  // the operator may override via opts.maxPathCerts).
  PATH_MAX_CERTS: 100,
  // PKCS#12 container ceilings. A PFX carries lists at three altitudes
  // (ContentInfos per AuthenticatedSafe, SafeBags per SafeContents,
  // attributes per bag) and can chain fresh DER blobs inside OCTET STRINGs,
  // where every re-decode would otherwise restart the depth cap from zero.
  // A real keystore holds a handful of keys and certificates; thousands of
  // elements or dozens of chained re-decodes is hostile input, not a store.
  PKCS12_MAX_ELEMENTS: 1024,
  PKCS12_MAX_REDECODES: 64,
  PKCS12_MAX_BAG_DEPTH: 16,
  // BER constructed-string reassembly copies each nesting level's payload, so
  // nesting multiplies transient memory. Real producers segment one level
  // deep; nesting past this cap is amplification, not a store.
  BER_MAX_STRING_NESTING: 8,
  // A single attribute's value SET — no deployed attribute carries more than
  // a handful of values; a list at this scale is amplification.
  ATTRIBUTE_MAX_VALUES: 256,
};

// Single-sourced from the package manifest so the reported version can
// never drift from the published package (package.json is always present
// in the installed tarball). A hand-maintained literal here silently
// shipped 0.1.0 on a 0.1.1 release.
var VERSION = require("../package.json").version;

module.exports = {
  TIME:    TIME,
  BYTES:   BYTES,
  LIMITS:  LIMITS,
  version: VERSION,
};
