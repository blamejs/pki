// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lib/guard-header.assertField (the emitted MIME/RFC 5322 header-field injection guard, CWE-93).
 * Pins the contract: reject CR / LF / NUL in a field value and a non-RFC-5322-ftext field name, throwing the
 * caller's typed-error CLASS (new E(code, msg), the lib/mime.js convention); allow TAB (folding whitespace)
 * and printable non-ASCII (RFC 6532 internationalized headers) in a value; coerce a non-string value. Source
 * stays pure ASCII -- every control / non-ASCII byte is built at runtime with String.fromCharCode.
 */

var helpers = require("../helpers");
var check = helpers.check;
var guard = require("../../lib/guard-all");
var SmimeError = require("../../lib/framework-error").SmimeError;

var E = SmimeError, C = "smime/bad-header";
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function CH(n) { return String.fromCharCode(n); }

function run() {
  // ---- accept ----
  check("1. a plain field name + value passes and returns the value", guard.header.assertField("Subject", "Hello there", E, C) === "Hello there");
  check("2. a TAB in a value is allowed (folding whitespace)", code(function () { guard.header.assertField("Subject", "a" + CH(9) + "b", E, C); }) === "NO-THROW");
  check("3. printable non-ASCII in a value is allowed (RFC 6532)", code(function () { guard.header.assertField("Subject", "caf" + CH(0xe9), E, C); }) === "NO-THROW");
  check("4. a non-string value is coerced to a string", guard.header.assertField("X-Count", 42, E, C) === "42");

  // ---- value rejects (the injection bytes) ----
  check("5. a CR (0x0d) in a value rejects", code(function () { guard.header.assertField("Subject", "a" + CH(13) + "b", E, C); }) === C);
  check("6. an LF (0x0a) in a value rejects", code(function () { guard.header.assertField("Subject", "a" + CH(10) + "b", E, C); }) === C);
  check("7. a NUL (0x00) in a value rejects", code(function () { guard.header.assertField("Subject", "a" + CH(0) + "b", E, C); }) === C);

  // ---- name rejects (not RFC 5322 ftext) ----
  check("8. an empty name rejects", code(function () { guard.header.assertField("", "v", E, C); }) === C);
  check("9. a non-string name rejects", code(function () { guard.header.assertField(null, "v", E, C); }) === C);
  check("10. a name with a space rejects", code(function () { guard.header.assertField("Bad Name", "v", E, C); }) === C);
  check("11. a name with a ':' rejects", code(function () { guard.header.assertField("Sub:ject", "v", E, C); }) === C);
  check("12. a name with a control byte rejects", code(function () { guard.header.assertField("Sub" + CH(9) + "ject", "v", E, C); }) === C);
  check("13. a name with a non-ASCII byte rejects", code(function () { guard.header.assertField("Subj" + CH(0xe9) + "ct", "v", E, C); }) === C);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };
if (require.main === module) { try { run(); } catch (e) { console.error(e && e.stack || e); process.exit(1); } }
