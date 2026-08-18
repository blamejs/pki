// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumer whose emitted-header integrity composes this guard (pki.smime header
// protection, RFC 9788).
//
// guard-header -- fail-closed header-field integrity for a MIME / RFC 5322 header
// a composer EMITS. Defends the HEADER INJECTION class (CWE-93): a caller-supplied
// header field name or value carrying a CR (0x0d) / LF (0x0a) / NUL (0x00) could
// inject an extra header (a Bcc, an HP-Outer record), split the message, or forge
// a multipart boundary; a field name outside RFC 5322 ftext could break the
// "Name: value" header grammar. It also caps the serialized line length (RFC 5322
// sec. 2.1.1, 998 octets) so an over-long emitted field cannot be re-folded by a
// relay into different signed bytes. Every field a composer inlines routes through
// this one guard, so an emission site cannot re-inline a weaker check and
// reintroduce the injection.

var C = require("./constants");

// assertField(name, value, E, code) -> value | throws new E(code, ...)
// name: RFC 5322 ftext, printable ASCII [0x21, 0x7e] except ':' (0x3a), non-empty
//   (a space, control byte, or ':' in a field name breaks the "Name: value" grammar).
// value: reject CR (0x0d), LF (0x0a) and NUL (0x00), the injection bytes; TAB
//   (0x09, folding whitespace) and printable non-ASCII (a UTF-8 header value, RFC
//   6532) pass. E is the caller's typed-error CLASS, thrown `new E(code, message)`
//   -- the same convention lib/mime.js (this guard's caller) and guard.bytes/text use.
// @enforced-by behavioral -- the CR/LF/NUL value reject + the ftext name check have
//   no rename-proof code shape distinct from the guard-name control-byte loop / the
//   ASN.1 charset readers; the header-injection RED vectors (a CR / LF / NUL value
//   or a non-ftext field name rejects smime/bad-header) are the guard.
function assertField(name, value, E, code) {
  if (typeof name !== "string" || name.length === 0) throw new E(code, "a header field name must be a non-empty string");
  for (var i = 0; i < name.length; i++) {
    var nc = name.charCodeAt(i);
    if (nc < 0x21 || nc > 0x7e || nc === 0x3a) throw new E(code, "a header field name must be RFC 5322 ftext (printable ASCII, no space / ':' / control): " + JSON.stringify(name));
  }
  var v = typeof value === "string" ? value : String(value);
  for (var j = 0; j < v.length; j++) {
    var vc = v.charCodeAt(j);
    if (vc === 0x00 || vc === 0x0d || vc === 0x0a) throw new E(code, "a header field value must not contain CR / LF / NUL (header injection) in " + JSON.stringify(name));
  }
  // RFC 5322 sec. 2.1.1: the serialized "Name: value" line (UTF-8 octets, excluding CRLF) must not exceed
  // the line limit, or a relay may re-fold it and silently change the signed bytes of a protected header.
  if (Buffer.byteLength(name, "utf8") + 2 + Buffer.byteLength(v, "utf8") > C.LIMITS.HEADER_LINE_MAX_OCTETS) {
    throw new E(code, "a header field line exceeds RFC 5322's " + C.LIMITS.HEADER_LINE_MAX_OCTETS + "-octet limit: " + JSON.stringify(name));
  }
  return v;
}

module.exports = { assertField: assertField };
