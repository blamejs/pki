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
/** @internal The append every list here is built with: `push` stores at the index and a store
 *  consults a setter inherited there, and these lists become the headers and parts of a message
 *  body a signature is computed over. */
var _push = guard.list.append;

var CRLF = Buffer.from("\r\n");

function _buf(v, E, code, label) { return guard.bytes.view(v, E, code, label); }
/** @internal `guard.limits.counter` throws `E(code, ...)`, and every consumer of this module hands in
 *  its error CLASS. */
function _factory(E) { return function (c, m) { return new E(c, m); }; }

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

/** @internal The end of the line starting at `from`, and where the next one starts. A line is ended by
 *  CRLF, by a lone CR or by LF, which is the separator set `_toLf` followed by a split produces. */
function _lineEnd(s, from) {
  for (var i = from; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c === 0x0a) return { end: i, next: i + 1 };
    if (c === 0x0d) return { end: i, next: (s.charCodeAt(i + 1) === 0x0a) ? i + 2 : i + 1 };
  }
  return { end: s.length, next: s.length };
}

/** @internal One line is cut at a time and EVERY line is charged, folded continuations and empty lines
 *  included, so the refusal costs the cap rather than the input. Splitting the whole header area first
 *  and counting fields afterwards read a 16 MiB area of 2,097,150 one-line fields in 1114 ms and
 *  653 MiB of resident memory before the count refused it, and charging only fields left a 16 MiB area
 *  of 1,864,130 continuation lines folding into one 13 MB value in 1648 ms without the count ever
 *  reaching two. */
function _unfoldHeaders(headerText, counted) {
  var out = [];
  for (var at = 0; at < headerText.length;) {
    var cut = _lineEnd(headerText, at);
    var ln = headerText.slice(at, cut.end);
    at = cut.next;
    counted.tick();
    if (ln === "") continue;
    if ((ln.charAt(0) === " " || ln.charAt(0) === "\t") && out.length) {
      out[out.length - 1] += " " + _stripLeadingHtab(ln);
    } else {
      _push(out, ln);
    }
  }
  return out;
}

/**
 * @internal
 * RFC 2045 sec. 5.1 gives a parameter one occurrence, so a header naming one twice has no value this
 * function can resolve: reading the last occurrence and reading the first are both conforming, and they
 * disagree. These values decide what a signature covers (`boundary` sets where the parts begin),
 * whether the entity is accepted (`protocol`, `smime-type`) and which digest is reported (`micalg`), so
 * a repeat is refused here, where the record is built, rather than per parameter at each reader. An
 * occurrence counts whether or not it carries a value, which is the `hp; hp="clear"` form; a single
 * bare attribute still reaches the reader that owns it.
 */
function _parseStructured(headerValue, E, code, label) {
  var counted = guard.limits.counter(C.LIMITS.MIME_MAX_PARAMS, _factory(E), code, label + " parameter");
  var parts = _splitSemicolons(headerValue, counted);
  var type = _stripComments(parts[0]).trim().toLowerCase();
  var params = Object.create(null);
  var seen = Object.create(null);
  for (var i = 1; i < parts.length; i++) {
    var p = _stripComments(parts[i]);
    var eq = p.indexOf("=");
    var name = (eq < 0 ? p : p.slice(0, eq)).trim().toLowerCase();
    if (name === "") continue;
    var base = _baseAttribute(name);
    if (seen[base] === true) {
      throw new E(code, label + " declares the " + JSON.stringify(base) +
        " parameter more than once, so its value is ambiguous (RFC 2045 sec. 5.1)");
    }
    seen[base] = true;
    if (eq < 0) continue;
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

/** @internal The attribute an RFC 2231 name belongs to. Sections 3 and 4 spell one parameter three
 *  ways, `name`, `name*` for an extended value and `name*0` / `name*1` for a continuation, and
 *  section 7 makes them the same logical parameter. This module assembles neither starred form, so a
 *  reader that does takes a different value from the same bytes: measured, `boundary*=us-ascii''DECOY;
 *  boundary=REAL` verified here while an RFC 2231 reader splits the body on DECOY. Comparing the
 *  attribute rather than the spelling is what makes the two the same occurrence. A leading asterisk
 *  is a name in its own right and keeps it. */
function _baseAttribute(name) {
  var star = name.indexOf("*");
  return star > 0 ? name.slice(0, star) : name;
}

/** @internal The first segment is the media type rather than a parameter, so it is not charged. The
 *  charge comes BEFORE the segment is stored, so the refusal costs the cap and not the input: charging
 *  the segments after the split instead read a 3.8 MiB Content-Type of 1,000,000 parameters in 192 ms
 *  and 73 MiB of resident memory before the same cap refused it. */
function _pushSegment(out, seg, counted) {
  if (counted !== undefined && out.length > 0) counted.tick();
  _push(out, seg);
}

function _splitSemicolons(s, counted) {
  var out = [], cur = "", inQ = false, depth = 0;
  for (var i = 0; i < s.length; i++) {
    var ch = s[i];
    if ((inQ || depth > 0) && ch === "\\" && i + 1 < s.length) { cur += ch + s[i + 1]; i++; }
    else if (ch === '"' && depth === 0) { inQ = !inQ; cur += ch; }
    else if (ch === "(" && !inQ) { depth++; cur += ch; }
    else if (ch === ")" && !inQ && depth > 0) { depth--; cur += ch; }
    else if (ch === ";" && !inQ && depth === 0) { _pushSegment(out, cur, counted); cur = ""; }
    else cur += ch;
  }
  _pushSegment(out, cur, counted);
  return out;
}

function parse(input, E, code) {
  /** @internal A snapshot, not a view: the record below holds `subarray`s of these bytes and a caller
   *  reads them back after the parse returns, so a view would let the caller's own later write change
   *  what the record says the entity was. Measured on the shipped verb: `pki.smime.verify` returned
   *  `valid: true` with `content` sharing the caller's store, and a write into that store afterwards
   *  changed the bytes the caller read as verified. The copy is byte-identical, so the octets a
   *  signature covers are unchanged. */
  var viewed = _buf(input, E, code, "the MIME entity");
  guard.limits.byteCap(viewed, C.LIMITS.MIME_MAX_BYTES, _factory(E), code, "the MIME entity");
  var bytes = guard.bytes.snapshot(viewed, E, code, "the MIME entity");
  var sp = _splitPoint(bytes);
  var headerBytes = sp ? bytes.subarray(0, sp.headerEnd) : bytes;
  var bodyBytes = sp ? bytes.subarray(sp.bodyStart) : Buffer.alloc(0);
  var headerText = guard.text.decode(headerBytes, C.LIMITS.MIME_MAX_BYTES, E, { charset: "latin1", tooLarge: code, badInput: code, label: "the MIME headers" });
  var countedHeaders = guard.limits.counter(C.LIMITS.MIME_MAX_HEADERS, _factory(E), code, "the MIME header line");
  var rawHeaders = _unfoldHeaders(headerText, countedHeaders);
  var headers = [];
  for (var i = 0; i < rawHeaders.length; i++) {
    var colon = rawHeaders[i].indexOf(":");
    if (colon < 0) throw new E(code, "a MIME header line has no colon: " + JSON.stringify(rawHeaders[i].slice(0, 40)));
    var nm = rawHeaders[i].slice(0, colon).trim();
    var body = rawHeaders[i].slice(colon + 1);
    _push(headers,{ name: nm, lname: nm.toLowerCase(), value: body.trim(), rawValue: body.charAt(0) === " " ? body.slice(1) : body });
  }
  /** @internal Resolving a field that occurs more than once means choosing an occurrence, and reading
   *  the first and reading the last are both conforming (RFC 5322 sec. 3.6 gives a singleton field one
   *  occurrence). The media type decides which reader a body goes to and the transfer encoding decides
   *  how its octets are recovered, so a repeat is refused rather than resolved by position. Every
   *  occurrence stays in `headers`, where a field that may legally repeat, such as `Received`, is
   *  read instead. */
  function header(name) {
    var l = name.toLowerCase(), found = null;
    for (var j = 0; j < headers.length; j++) {
      if (headers[j].lname !== l) continue;
      if (found !== null) {
        throw new E(code, "the entity declares the " + JSON.stringify(headers[j].name) +
          " field more than once, so resolving it to a single value is ambiguous (RFC 5322 sec. 3.6)");
      }
      found = headers[j];
    }
    return found === null ? null : found.value;
  }
  var ctv = header("content-type");
  var cte = (header("content-transfer-encoding") || "").trim().toLowerCase() || "7bit";
  return {
    headers: headers, header: header,
    contentType: ctv != null ? _parseStructured(ctv, E, code, "the Content-Type") : { value: "text/plain", type: "text/plain", params: Object.create(null) },
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
  var counted = guard.limits.counter(C.LIMITS.MIME_MAX_PARTS, _factory(E), code, "the multipart body part");
  while (true) {
    counted.tick();
    var next = _findDelim(body, delim, pos);
    if (next < 0) throw new E(code, "an unterminated multipart body part (no closing boundary)");
    var partEnd = next;
    if (partEnd >= 2 && body[partEnd - 2] === 0x0d && body[partEnd - 1] === 0x0a) partEnd -= 2;
    else if (partEnd >= 1 && body[partEnd - 1] === 0x0a) partEnd -= 1;
    _push(parts,body.subarray(pos, partEnd));
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
