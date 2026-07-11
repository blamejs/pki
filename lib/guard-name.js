// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose name-string integrity composes this guard (pki.path.validate
// DN chaining, pki.schema.x509 GeneralName / SAN decode).
//
// guard-name -- fail-closed rejection of an embedded control byte in a
// distinguished-name / SAN string. Two policies over one concern.
//
// Defends the name-truncation / display-confusion class (CVE-2009-2408): a NUL
// or control byte embedded in a decoded name lets an attacker make two different
// names compare equal (or a UI truncate at the NUL), so a cert issued for
// "good.example.com\0.evil.com" is treated as "good.example.com". CWE-158
// (improper neutralization of null byte) / CWE-20. The reject is at decode, so a
// truncation name never reaches a comparison or a display.

// assertNoControlBytes(str, E, code, label) -> str | throws E(code, ...)
// DirectoryString policy (a DN attribute value): reject NUL and C0 control bytes
// in a DECODED name string. TAB (0x09) is exempt; printable non-ASCII (a
// UTF8String CN carries accented / CJK characters) is allowed. `str` is assumed a
// string (the caller guards typeof). E is the (code, message) typed-error factory.
// @enforced-by behavioral -- the control-byte reject has no rename-proof code
//   shape distinct from the ASN.1 charset readers; the CVE-2009-2408 RED vectors
//   (a DN string with an embedded NUL / control byte rejects) are the guard.
function assertNoControlBytes(str, E, code, label) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c === 0 || (c < 0x20 && c !== 0x09)) {
      throw E(code, label + " contains an embedded control byte (CVE-2009-2408)");
    }
  }
  return str;
}

// assertPrintableIa5(buf, E, code, label) -> buf | throws E(code, ...)
// IA5String policy (a dNSName / rfc822Name / URI GeneralName): every byte must be
// printable 7-bit ASCII [0x20, 0x7e] -- an embedded NUL / control byte enables the
// same name-truncation bypass downstream. `buf` is the raw GeneralName content.
// @enforced-by behavioral -- the printable-IA5 byte-range reject has no rename-proof
//   code shape distinct from the ASN.1 IA5 reader; the CVE-2009-2408 RED vectors
//   (a SAN with a control byte rejects) are the guard.
function assertPrintableIa5(buf, E, code, label) {
  for (var i = 0; i < buf.length; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7e) {
      throw E(code, label + " must be a printable IA5String (no control bytes)");
    }
  }
  return buf;
}

module.exports = { assertNoControlBytes: assertNoControlBytes, assertPrintableIa5: assertPrintableIa5 };
