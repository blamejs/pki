// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/mime.js -- a minimal MIME entity framer + canonicalizer, the message-layer engine primitive
 * under pki.smime (RFC 8551 S/MIME) and any future MIME-carrying feature. It parses an entity into
 * its headers + body, canonicalizes a text entity to the RFC 8551 sec. 3.1.1 form (CRLF line endings),
 * splits a multipart body on its boundary, and builds an entity/multipart back. There is NO crypto
 * here -- the CMS layer signs/verifies the canonical bytes this module produces.
 *
 * The LOAD-BEARING rule is canonicalization: the detached signature over a multipart/signed first part
 * is computed over that part's canonical MIME form, so the signer and verifier MUST share ONE
 * canonicalizer -- this module. It carries the caller's typed ErrorClass `E` (constructed
 * `new E(code, message)`), exactly as the byte-reader / guard family do, so every consumer keeps its
 * own `domain/reason` fault code.
 */

var C = require("./constants.js");
var guard = require("./guard-all.js");

var CRLF = Buffer.from("\r\n");

// A byte source -> a Buffer view, capped before any copy (CWE-770/400).
function _buf(v, E, code, label) { return guard.bytes.view(v, E, code, label); }

// Locate the header/body separator: the first empty line (a bare LF-LF or CRLF-CRLF, or a mix).
// Returns { headerEnd, bodyStart } offsets, or null when there is no blank-line separator.
function _splitPoint(bytes) {
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) {                                   // LF
      if (i + 1 < bytes.length && bytes[i + 1] === 0x0a) return { headerEnd: i, bodyStart: i + 2 };           // LF LF
      if (i + 2 < bytes.length && bytes[i + 1] === 0x0d && bytes[i + 2] === 0x0a) return { headerEnd: i, bodyStart: i + 3 };  // LF CRLF
    }
  }
  return null;
}

// Split a header block into unfolded logical lines (RFC 5322 folding: a continuation line begins with
// SP/HTAB and joins the previous). Returns the raw header strings (each "Name: value").
function _unfoldHeaders(headerText) {
  var lines = headerText.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (ln === "") continue;
    if ((ln[0] === " " || ln[0] === "\t") && out.length) out[out.length - 1] += " " + ln.replace(/^[ \t]+/, "");
    else out.push(ln);
  }
  return out;
}

// Parse a Content-Type / any structured header value into { value, type, params } -- the media type
// (lowercased) plus its parameters (names lowercased, quotes stripped). Tolerant of extra whitespace.
function _parseStructured(headerValue) {
  var parts = _splitSemicolons(headerValue);   // always >= 1 element
  var type = parts[0].trim().toLowerCase();
  var params = {};
  for (var i = 1; i < parts.length; i++) {
    var eq = parts[i].indexOf("=");
    if (eq < 0) continue;
    var name = parts[i].slice(0, eq).trim().toLowerCase();
    var val = parts[i].slice(eq + 1).trim();
    if (val.length >= 2 && val[0] === '"' && val[val.length - 1] === '"') val = val.slice(1, -1);
    params[name] = val;
  }
  return { value: headerValue.trim(), type: type, params: params };
}

// Split on ";" while respecting double-quoted spans (a boundary/protocol value may be quoted).
function _splitSemicolons(s) {
  var out = [], cur = "", inQ = false;
  for (var i = 0; i < s.length; i++) {
    var ch = s[i];
    if (ch === '"') { inQ = !inQ; cur += ch; }
    else if (ch === ";" && !inQ) { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

// Parse a MIME entity (headers + body). `contentType` / `cte` are decoded; `header(name)` looks up a
// header case-insensitively; `body` is the raw body Buffer. `headerBytes` / `bodyBytes` are the exact
// slices (a signature over a first part must reference exact bytes, never a re-serialization).
function parse(input, E, code) {
  var bytes = _buf(input, E, code, "the MIME entity");
  // Coverage residual: the DoS ceiling only fires on a >16 MiB message (a real cap, exercised by no
  // unit vector -- driving it would allocate 16 MiB).
  if (bytes.length > C.LIMITS.MIME_MAX_BYTES) throw new E(code, "MIME entity exceeds the size cap");
  var sp = _splitPoint(bytes);
  var headerBytes = sp ? bytes.subarray(0, sp.headerEnd) : bytes;
  var bodyBytes = sp ? bytes.subarray(sp.bodyStart) : Buffer.alloc(0);
  var headerText = guard.text.decode(headerBytes, C.LIMITS.MIME_MAX_BYTES, E, { charset: "latin1", tooLarge: code, badInput: code, label: "the MIME headers" });
  var rawHeaders = _unfoldHeaders(headerText);
  var headers = [];
  for (var i = 0; i < rawHeaders.length; i++) {
    var colon = rawHeaders[i].indexOf(":");
    if (colon < 0) throw new E(code, "a MIME header line has no colon: " + JSON.stringify(rawHeaders[i].slice(0, 40)));
    headers.push({ name: rawHeaders[i].slice(0, colon).trim(), lname: rawHeaders[i].slice(0, colon).trim().toLowerCase(), value: rawHeaders[i].slice(colon + 1).trim() });
  }
  function header(name) { var l = name.toLowerCase(); for (var j = 0; j < headers.length; j++) if (headers[j].lname === l) return headers[j].value; return null; }
  var ctv = header("content-type");
  var cte = (header("content-transfer-encoding") || "").trim().toLowerCase() || "7bit";
  return {
    headers: headers, header: header,
    contentType: ctv != null ? _parseStructured(ctv) : { value: "text/plain", type: "text/plain", params: {} },
    cte: cte,
    headerBytes: headerBytes, bodyBytes: bodyBytes, body: bodyBytes, bytes: bytes,
  };
}

// Normalize a text body's line endings to the RFC 8551 sec. 3.1.1 canonical CRLF pair (any bare CR or
// LF becomes CRLF; an existing CRLF is preserved).
function canonicalizeText(bodyBytes) {
  var s = bodyBytes.toString("latin1").replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
  return Buffer.from(s, "latin1");
}

// The canonical MIME form of a part for signing (RFC 8551 sec. 3.1.1): line endings normalized to the
// CRLF pair over the EXACT bytes -- never a header re-serialization, which would diverge from the
// signer's digest (and would break a header-less clear-signed part, as OpenSSL's `smime -sign` emits).
// The signer and verifier both call THIS, so their digests cannot diverge; a transport that mangles
// CR/LF is repaired identically on both sides. (A binary clear-signed part must carry a base64
// Content-Transfer-Encoding first -- line-ending canonicalization is defined for text, sec. 3.1.1.)
function canonicalize(input, E, code) {
  return canonicalizeText(_buf(input, E, code, "the MIME part"));
}

// Split a multipart body on its boundary into the exact bytes of each part (RFC 2046 sec. 5.1.1). A
// part runs from after the "--boundary CRLF" delimiter to just before the "CRLF--boundary" that ends
// it; the CRLF preceding a boundary is part of the delimiter, not the part (the S/MIME signing rule).
function splitMultipart(bodyBytes, boundary, E, code) {
  if (!boundary) throw new E(code, "a multipart entity is missing its boundary parameter");
  var delim = Buffer.from("--" + boundary);
  var body = bodyBytes;
  var parts = [], idx = _indexOf(body, delim, 0);
  if (idx < 0) throw new E(code, "no boundary delimiter found in the multipart body");
  // Advance past the opening delimiter line.
  var pos = _afterLine(body, idx + delim.length, E, code);
  while (true) {
    var next = _indexOf(body, delim, pos);
    if (next < 0) throw new E(code, "an unterminated multipart body part (no closing boundary)");
    // The part ends at the CRLF (or LF) that immediately precedes this boundary delimiter.
    var partEnd = next;
    if (partEnd >= 2 && body[partEnd - 2] === 0x0d && body[partEnd - 1] === 0x0a) partEnd -= 2;
    else if (partEnd >= 1 && body[partEnd - 1] === 0x0a) partEnd -= 1;
    parts.push(body.subarray(pos, partEnd));
    // A closing delimiter is "--boundary--"; otherwise advance past this delimiter line to the next part.
    var afterDelim = next + delim.length;
    if (afterDelim + 1 < body.length && body[afterDelim] === 0x2d && body[afterDelim + 1] === 0x2d) break;   // "--"
    pos = _afterLine(body, afterDelim, E, code);
  }
  return parts;
}

// The offset just past the end of the current line (skipping to after the next LF).
function _afterLine(buf, from, E, code) {
  for (var i = from; i < buf.length; i++) if (buf[i] === 0x0a) return i + 1;
  throw new E(code, "a multipart boundary line is not terminated");
}

function _indexOf(haystack, needle, from) {
  return haystack.indexOf(needle, from);
}

module.exports = {
  parse: parse,
  canonicalize: canonicalize,
  canonicalizeText: canonicalizeText,
  splitMultipart: splitMultipart,
  CRLF: CRLF,
};
