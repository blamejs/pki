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
