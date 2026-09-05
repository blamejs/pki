// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/mime.js: a minimal MIME entity framer + canonicalizer, the message-layer engine primitive
 * under pki.smime (RFC 8551 S/MIME) and any future MIME-carrying feature. It parses an entity into
 * its headers + body, canonicalizes a text entity to the RFC 8551 sec. 3.1.1 form (CRLF line endings),
 * splits a multipart body on its boundary, and builds an entity/multipart back. There is NO crypto
 * here. The CMS layer signs/verifies the canonical bytes this module produces.
 *
 * The load-bearing rule is canonicalization: the detached signature over a multipart/signed first part
 * is computed over that part's canonical MIME form, so the signer and verifier MUST share one
 * canonicalizer, this module. It carries the caller's typed ErrorClass `E` (constructed
 * `new E(code, message)`), exactly as the byte-reader / guard family do, so every consumer keeps its
 * own `domain/reason` fault code.
 */

var C = require("./constants.js");
var guard = require("./guard-all.js");

var CRLF = Buffer.from("\r\n");

function _buf(v, E, code, label) { return guard.bytes.view(v, E, code, label); }

function _splitPoint(bytes) {
  for (var i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) {
      if (i + 1 < bytes.length && bytes[i + 1] === 0x0a) return { headerEnd: i, bodyStart: i + 2 };
      if (i + 2 < bytes.length && bytes[i + 1] === 0x0d && bytes[i + 2] === 0x0a) return { headerEnd: i, bodyStart: i + 3 };
    }
  }
  return null;
}

function _toLf(s) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (c === "\r") { if (s.charAt(i + 1) === "\n") continue; out += "\n"; }
    else out += c;
  }
  return out;
}
function _toCrlf(s) {
  var lf = _toLf(s), out = "";
  for (var i = 0; i < lf.length; i++) { var c = lf.charAt(i); out += (c === "\n") ? "\r\n" : c; }
  return out;
}
function _stripLeadingHtab(s) {
  var i = 0;
  while (i < s.length && (s.charAt(i) === " " || s.charAt(i) === "\t")) i += 1;
  return s.slice(i);
}

function _unfoldHeaders(headerText) {
  var lines = _toLf(headerText).split("\n");
  var out = [];
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (ln === "") continue;
    if ((ln[0] === " " || ln[0] === "\t") && out.length) out[out.length - 1] += " " + _stripLeadingHtab(ln);
    else out.push(ln);
  }
  return out;
}

function _parseStructured(headerValue) {
  var parts = _splitSemicolons(headerValue);
  var type = _stripComments(parts[0]).trim().toLowerCase();
  var params = Object.create(null);
  for (var i = 1; i < parts.length; i++) {
    var p = _stripComments(parts[i]);
    var eq = p.indexOf("=");
    if (eq < 0) continue;
    var name = p.slice(0, eq).trim().toLowerCase();
    var val = p.slice(eq + 1).trim();
    if (val.length >= 2 && val[0] === '"' && val[val.length - 1] === '"') val = val.slice(1, -1);
    params[name] = val;
  }
  return { value: headerValue.trim(), type: type, params: params };
}

function _stripComments(s) {
  var out = "", inQ = false, depth = 0;
  for (var i = 0; i < s.length; i++) {
    var ch = s[i];
    if (inQ && ch === "\\" && i + 1 < s.length) { out += ch + s[i + 1]; i++; }
    else if (depth > 0 && ch === "\\" && i + 1 < s.length) { i++; }
    else if (ch === '"' && depth === 0) { inQ = !inQ; out += ch; }
    else if (ch === "(" && !inQ) { depth++; }
    else if (ch === ")" && !inQ && depth > 0) { depth--; }
    else if (depth === 0) { out += ch; }
  }
  return out;
}

function _splitSemicolons(s) {
  var out = [], cur = "", inQ = false, depth = 0;
  for (var i = 0; i < s.length; i++) {
    var ch = s[i];
    if ((inQ || depth > 0) && ch === "\\" && i + 1 < s.length) { cur += ch + s[i + 1]; i++; }
    else if (ch === '"' && depth === 0) { inQ = !inQ; cur += ch; }
    else if (ch === "(" && !inQ) { depth++; cur += ch; }
    else if (ch === ")" && !inQ && depth > 0) { depth--; cur += ch; }
    else if (ch === ";" && !inQ && depth === 0) { out.push(cur); cur = ""; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

function parse(input, E, code) {
  var bytes = _buf(input, E, code, "the MIME entity");
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
    var nm = rawHeaders[i].slice(0, colon).trim();
    var body = rawHeaders[i].slice(colon + 1);
    headers.push({ name: nm, lname: nm.toLowerCase(), value: body.trim(), rawValue: body.charAt(0) === " " ? body.slice(1) : body });
  }
  function header(name) { var l = name.toLowerCase(); for (var j = 0; j < headers.length; j++) if (headers[j].lname === l) return headers[j].value; return null; }
  var ctv = header("content-type");
  var cte = (header("content-transfer-encoding") || "").trim().toLowerCase() || "7bit";
  return {
    headers: headers, header: header,
    contentType: ctv != null ? _parseStructured(ctv) : { value: "text/plain", type: "text/plain", params: Object.create(null) },
    cte: cte,
    headerBytes: headerBytes, bodyBytes: bodyBytes, body: bodyBytes, bytes: bytes,
  };
}

function canonicalizeText(bodyBytes) {
  var s = _toCrlf(bodyBytes.toString("latin1"));
  return Buffer.from(s, "latin1");
}

function canonicalize(input, E, code) {
  return canonicalizeText(_buf(input, E, code, "the MIME part"));
}

function splitMultipart(bodyBytes, boundary, E, code) {
  if (!boundary) throw new E(code, "a multipart entity is missing its boundary parameter");
  var delim = Buffer.from("--" + boundary);
  var body = bodyBytes;
  var idx = _findDelim(body, delim, 0);
  if (idx < 0) throw new E(code, "no boundary delimiter found in the multipart body");
  var pos = _afterLine(body, idx + delim.length, E, code);
  var parts = [];
  while (true) {
    var next = _findDelim(body, delim, pos);
    if (next < 0) throw new E(code, "an unterminated multipart body part (no closing boundary)");
    var partEnd = next;
    if (partEnd >= 2 && body[partEnd - 2] === 0x0d && body[partEnd - 1] === 0x0a) partEnd -= 2;
    else if (partEnd >= 1 && body[partEnd - 1] === 0x0a) partEnd -= 1;
    parts.push(body.subarray(pos, partEnd));
    var afterDelim = next + delim.length;
    if (body[afterDelim] === 0x2d && body[afterDelim + 1] === 0x2d) break;
    pos = _afterLine(body, afterDelim, E, code);
  }
  return parts;
}

function _findDelim(body, delim, from) {
  for (var at = body.indexOf(delim, from); at >= 0; at = body.indexOf(delim, at + delim.length)) {
    if ((at === 0 || body[at - 1] === 0x0a) && _delimLineOk(body, at + delim.length)) return at;
  }
  return -1;
}
function _delimLineOk(body, i) {
  if (body[i] === 0x2d && body[i + 1] === 0x2d) i += 2;
  while (body[i] === 0x20 || body[i] === 0x09) i++;
  return i >= body.length || body[i] === 0x0d || body[i] === 0x0a;
}

function _afterLine(buf, from, E, code) {
  for (var i = from; i < buf.length; i++) if (buf[i] === 0x0a) return i + 1;
  throw new E(code, "a multipart boundary line is not terminated");
}

function buildEntity(fields, body, E, code) {
  var head = "";
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    var v = guard.header.assertField(f.name, f.value, E, code);
    head += f.name + ": " + v + "\r\n";
  }
  var bodyBuf = (body == null) ? Buffer.alloc(0) : _buf(body, E, code, "the MIME body");
  return canonicalizeText(Buffer.concat([Buffer.from(head + "\r\n", "utf8"), bodyBuf]));
}

function paramCount(headerValue, name) {
  var ln = name.toLowerCase(), n = 0;
  _splitSemicolons(headerValue).forEach(function (part) {
    var p = _stripComments(part);
    var eq = p.indexOf("=");
    if (eq >= 0 && p.slice(0, eq).trim().toLowerCase() === ln) n++;
  });
  return n;
}

function paramNameCount(headerValue, name) {
  var ln = name.toLowerCase(), n = 0;
  var parts = _splitSemicolons(headerValue);
  for (var i = 1; i < parts.length; i++) {
    var p = _stripComments(parts[i]);
    var eq = p.indexOf("=");
    if ((eq >= 0 ? p.slice(0, eq) : p).trim().toLowerCase() === ln) n++;
  }
  return n;
}

function hasParam(headerValue, name) { return paramNameCount(headerValue, name) > 0; }

module.exports = {
  parse: parse,
  canonicalize: canonicalize,
  canonicalizeText: canonicalizeText,
  splitMultipart: splitMultipart,
  buildEntity: buildEntity,
  paramCount: paramCount,
  hasParam: hasParam,
  paramNameCount: paramNameCount,
  CRLF: CRLF,
};
