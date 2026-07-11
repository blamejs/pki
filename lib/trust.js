// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.trust
 * @nav        Path validation
 * @title      Trust-store ingestion
 * @order      230
 * @slug       trust
 *
 * @intro
 *   Mozilla / CCADB root-program ingestion into constraint-carrying trust
 *   anchors. The bare root list (`tls.rootCertificates`) throws away exactly
 *   the metadata that decides WHICH roots may vouch for WHAT: the per-purpose
 *   trust bits (a root trusted for TLS is not thereby trusted for S/MIME) and
 *   the per-purpose distrust-after dates (a sunsetting root keeps validating
 *   already-issued certificates while certificates issued after the cutoff are
 *   rejected). `parseCertdata` reads the NSS `certdata.txt` object stream and
 *   `parseCcadbCsv` the CCADB CSV export into one identical `Anchor` shape, so
 *   enforcement downstream is source-agnostic; `anchor()` hands an entry to
 *   `pki.path.validate({ trustAnchor, checkPurpose })`.
 *
 *   Everything is fail-closed and offline: the caller supplies the text (no
 *   network fetch); every malformed or oversized input throws a typed
 *   `trust/*` error before the offending allocation; a certificate object and
 *   its trust object are paired by byte-exact (CKA_ISSUER, CKA_SERIAL_NUMBER)
 *   -- never by adjacency -- and cross-checked against the parsed DER, so
 *   trust metadata can never attach to the wrong root; only
 *   `CKT_NSS_TRUSTED_DELEGATOR` grants a purpose (everything else, including
 *   an absent bit, is untrusted).
 *
 * @card
 *   `parseCertdata` / `parseCcadbCsv` -> constraint-carrying trust anchors
 *   (per-purpose trust bits + distrust-after dates); `anchor()` feeds
 *   `pki.path.validate`. Fail-closed, offline, source-agnostic.
 */

var constants = require("./constants");
var errors = require("./framework-error");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var x509 = require("./schema-x509");

var TrustError = errors.TrustError;
var LIMITS = constants.LIMITS;

function E(code, message, cause) { return new TrustError(code, message, cause); }

// The three NSS purposes an anchor carries; the keys double as the
// `opts.checkPurpose` vocabulary `pki.path.validate` consumes.
var PURPOSES = ["serverAuth", "emailProtection", "codeSigning"];

// CKA_TRUST_* attribute -> purpose key.
var PURPOSE_ATTRS = [
  ["CKA_TRUST_SERVER_AUTH", "serverAuth"],
  ["CKA_TRUST_EMAIL_PROTECTION", "emailProtection"],
  ["CKA_TRUST_CODE_SIGNING", "codeSigning"],
];

// The recognized CK_TRUST vocabulary. ONLY CKT_NSS_TRUSTED_DELEGATOR grants a
// purpose; the rest are recognized-but-untrusted (fail-closed: an absent or
// non-delegator bit never defaults to trusted). A token outside this set is a
// typed trust/bad-trust-value, never a silent false.
var CKT_RECOGNIZED = Object.create(null);
["CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED", "CKT_NSS_MUST_VERIFY_TRUST",
  "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_VALID_DELEGATOR"]
  .forEach(function (t) { CKT_RECOGNIZED[t] = true; });
var CKT_DELEGATOR = "CKT_NSS_TRUSTED_DELEGATOR";

// An attribute line: `CKA_<NAME> <type> [<value>]`. The value grammar is
// per-type (a quoted UTF8 string, a single token, or nothing for
// MULTILINE_OCTAL whose payload follows on its own lines).
var ATTR_RE = /^(CKA_[A-Z0-9_]+)(?:\s+(\S+)(?:\s+(.*))?)?$/;

// ---------------------------------------------------------------------------
// certdata.txt lexer -- line-oriented, C.LIMITS-bounded, fail-closed
// ---------------------------------------------------------------------------

// Decode a MULTILINE_OCTAL body: whitespace-separated runs of `\ooo` escapes
// (exactly a backslash + three octal digits, \000..\377), terminated by a line
// that is exactly `END`. Every fault is refused before the byte lands: an
// escape past \377, a short or non-octal escape, a stray token, a blank line
// or EOF before END, or a blob past TRUST_MAX_OCTAL_BYTES.
function _readOctalBody(lines, idx) {
  var out = [];
  var cap = LIMITS.TRUST_MAX_OCTAL_BYTES;
  for (var i = idx; i < lines.length; i++) {
    var t = lines[i].trim();
    if (t === "END") return { bytes: Buffer.from(out), next: i + 1 };
    if (t === "") throw E("trust/bad-octal", "MULTILINE_OCTAL body interrupted by a blank line before END");
    var chunks = t.split(/\s+/);
    for (var c = 0; c < chunks.length; c++) {
      var chunk = chunks[c];
      for (var k = 0; k < chunk.length; k += 4) {
        if (chunk.charCodeAt(k) !== 92 /* backslash */) {
          throw E("trust/bad-octal", "MULTILINE_OCTAL expects \\ooo escapes, got " + JSON.stringify(chunk.slice(k, k + 4)));
        }
        var d = chunk.slice(k + 1, k + 4);
        if (!/^[0-7]{3}$/.test(d)) {
          throw E("trust/bad-octal", "a MULTILINE_OCTAL escape is a backslash + exactly three octal digits, got " + JSON.stringify("\\" + d));
        }
        if (d.charCodeAt(0) > 51 /* '3' */) {
          throw E("trust/bad-octal", "octal escape \\" + d + " exceeds \\377 (one byte)");
        }
        if (out.length >= cap) throw E("trust/bad-block", "MULTILINE_OCTAL blob exceeds LIMITS.TRUST_MAX_OCTAL_BYTES");
        out.push(parseInt(d, 8));
      }
    }
  }
  throw E("trust/bad-octal", "MULTILINE_OCTAL body reached end of input before END");
}

// Lex the object stream: a `#` line is a comment, the preamble ends at
// BEGINDATA, blank lines delimit object blocks, each block is typed
// `CKA_* <type> <value>` attribute lines. Returns [{ attrs }] where attrs maps
// the attribute name to { type, value | bytes }.
function _lexObjects(text) {
  var lines = text.split(/\r\n|\n|\r/);
  var n = lines.length;
  var i = 0, sawBegin = false;
  for (; i < n; i++) {
    if (lines[i].trim() === "BEGINDATA") { sawBegin = true; i++; break; }
  }
  if (!sawBegin) throw E("trust/bad-input", "not a certdata stream: no BEGINDATA line");

  var objects = [];
  var cur = null;
  while (i < n) {
    var t = lines[i].trim();
    if (t === "") {
      if (cur) { objects.push(cur); cur = null; }
      i++; continue;
    }
    if (t.charAt(0) === "#") { i++; continue; }
    var m = ATTR_RE.exec(t);
    if (!m) throw E("trust/bad-block", "unexpected line in the certdata object stream: " + JSON.stringify(t.slice(0, 64)));
    var name = m[1], type = m[2];
    var rawVal = m[3] !== undefined ? m[3].trim() : undefined;
    if (!type) throw E("trust/bad-block", "attribute line is missing its type token: " + name);
    if (!cur) {
      // Refuse the block bomb BEFORE lexing another block's payloads.
      if (objects.length >= LIMITS.TRUST_MAX_OBJECTS) throw E("trust/bad-block", "certdata object count exceeds LIMITS.TRUST_MAX_OBJECTS");
      cur = { attrs: Object.create(null) };
    }
    if (cur.attrs[name]) throw E("trust/bad-block", "duplicate attribute " + name + " within one object block");

    var entry;
    if (type === "MULTILINE_OCTAL") {
      if (rawVal !== undefined && rawVal !== "") throw E("trust/bad-block", name + " MULTILINE_OCTAL carries an unexpected inline value");
      var r = _readOctalBody(lines, i + 1);
      cur.attrs[name] = { type: type, bytes: r.bytes };
      i = r.next;
      continue;
    }
    if (type === "CK_BBOOL") {
      if (rawVal !== "CK_TRUE" && rawVal !== "CK_FALSE") throw E("trust/bad-block", name + " CK_BBOOL must be CK_TRUE or CK_FALSE");
      entry = { type: type, value: rawVal === "CK_TRUE" };
    } else if (type === "UTF8") {
      var q = rawVal !== undefined ? /^"([^"]*)"$/.exec(rawVal) : null;
      if (!q) throw E("trust/bad-block", name + " UTF8 must carry one double-quoted value");
      entry = { type: type, value: q[1] };
    } else if (type === "CK_TRUST") {
      if (rawVal === undefined || /\s/.test(rawVal)) throw E("trust/bad-block", name + " CK_TRUST must carry a single token value");
      if (!CKT_RECOGNIZED[rawVal]) throw E("trust/bad-trust-value", "unrecognized CK_TRUST value " + JSON.stringify(rawVal) + " on " + name);
      entry = { type: type, value: rawVal };
    } else if (type === "CK_OBJECT_CLASS" || type === "CK_CERTIFICATE_TYPE") {
      if (rawVal === undefined || /\s/.test(rawVal)) throw E("trust/bad-block", name + " " + type + " must carry a single token value");
      entry = { type: type, value: rawVal };
    } else {
      // An unknown value TYPE cannot be lexed safely (its value grammar is
      // unknown) -- fail closed rather than guess past it.
      throw E("trust/bad-block", "unrecognized attribute type " + JSON.stringify(type) + " on " + name);
    }
    cur.attrs[name] = entry;
    i++;
  }
  if (cur) objects.push(cur);
  return objects;
}

// ---------------------------------------------------------------------------
// certdata semantics -- pairing, distrust-after, purpose bits
// ---------------------------------------------------------------------------

function _requireOctal(obj, name, what) {
  var a = obj.attrs[name];
  if (!a || a.type !== "MULTILINE_OCTAL") {
    throw E("trust/bad-block", what + " object is missing its " + name + " MULTILINE_OCTAL attribute");
  }
  return a.bytes;
}

// The NSS distrust-after payload is the BARE ASCII of a YYMMDDHHMMSSZ UTCTime
// (13 bytes) or a YYYYMMDDHHMMSSZ GeneralizedTime (15 bytes) -- no DER tag or
// length. Synthesize the minimal TLV and route it through the strict asn1
// time reader so the Z-terminator / mandatory-seconds / component-rollover /
// RFC 5280 sec. 4.1.2.5.1 2050-pivot rules are enforced once, never re-derived.
function _strictTime(payload, code, label) {
  var tlv;
  if (payload.length === 13) tlv = Buffer.concat([Buffer.from([0x17, 0x0d]), payload]);
  else if (payload.length === 15) tlv = Buffer.concat([Buffer.from([0x18, 0x0f]), payload]);
  else throw E(code, label + " must be a 13-byte UTCTime or a 15-byte GeneralizedTime payload, got " + payload.length + " bytes");
  try { return asn1.read.time(asn1.decode(tlv)); }
  catch (e) { throw E(code, label + " does not decode as a strict time", e); }
}

// CKA_NSS_*_DISTRUST_AFTER: either `CK_BBOOL CK_FALSE` (no distrust-after in
// force) or a MULTILINE_OCTAL bare-ASCII time. Anything else fails closed.
function _distrustDate(obj, name) {
  var a = obj.attrs[name];
  if (!a) return null;
  if (a.type === "CK_BBOOL") {
    if (a.value === false) return null;
    throw E("trust/bad-distrust-after", name + " CK_BBOOL may only be CK_FALSE");
  }
  if (a.type !== "MULTILINE_OCTAL") throw E("trust/bad-distrust-after", name + " must be CK_BBOOL CK_FALSE or MULTILINE_OCTAL");
  return _strictTime(a.bytes, "trust/bad-distrust-after", name);
}

function _certEntry(obj) {
  var der = _requireOctal(obj, "CKA_VALUE", "certificate");
  var cert;
  try { cert = x509.parse(der); }
  catch (e) { throw E("trust/not-a-certificate", "CKA_VALUE does not parse as an X.509 certificate", e); }

  var issuer = _requireOctal(obj, "CKA_ISSUER", "certificate");
  var serial = _requireOctal(obj, "CKA_SERIAL_NUMBER", "certificate");

  // Fail-closed cross-check (the pairing key vs the parsed DER): a block whose
  // own identity octets disagree with its certificate would let trust metadata
  // attach to the wrong root -- a trust-elevation bug, not a tolerable skew.
  if (!issuer.equals(cert.issuer.bytes)) {
    throw E("trust/pairing-mismatch", "CKA_ISSUER disagrees with the certificate's issuer DER");
  }
  var serialContentHex;
  try {
    var sn = asn1.decode(serial);
    asn1.read.integer(sn); // strict INTEGER (tag + minimal content)
    serialContentHex = sn.content.toString("hex");
  } catch (e) {
    throw E("trust/pairing-mismatch", "CKA_SERIAL_NUMBER is not a DER INTEGER", e);
  }
  if (serialContentHex !== cert.serialNumberHex) {
    throw E("trust/pairing-mismatch", "CKA_SERIAL_NUMBER disagrees with the certificate's serial");
  }
  var subject = obj.attrs["CKA_SUBJECT"];
  if (subject && (subject.type !== "MULTILINE_OCTAL" || !subject.bytes.equals(cert.subject.bytes))) {
    throw E("trust/pairing-mismatch", "CKA_SUBJECT disagrees with the certificate's subject DER");
  }

  var label = obj.attrs["CKA_LABEL"];
  if (label && label.type !== "UTF8") throw E("trust/bad-block", "CKA_LABEL must be UTF8");
  var policy = obj.attrs["CKA_NSS_MOZILLA_CA_POLICY"];
  if (policy && policy.type !== "CK_BBOOL") throw E("trust/bad-block", "CKA_NSS_MOZILLA_CA_POLICY must be CK_BBOOL");

  var distrustAfter = {};
  var server = _distrustDate(obj, "CKA_NSS_SERVER_DISTRUST_AFTER");
  if (server) distrustAfter.serverAuth = server;
  var email = _distrustDate(obj, "CKA_NSS_EMAIL_DISTRUST_AFTER");
  if (email) distrustAfter.emailProtection = email;

  return {
    key: issuer.toString("hex") + "/" + serial.toString("hex"),
    der: der,
    cert: cert,
    label: label ? label.value : null,
    mozillaCaPolicy: !!(policy && policy.value === true),
    distrustAfter: distrustAfter,
    purposes: null, // attached by the paired CKO_NSS_TRUST object
  };
}

function _trustEntry(obj) {
  var issuer = _requireOctal(obj, "CKA_ISSUER", "trust");
  var serial = _requireOctal(obj, "CKA_SERIAL_NUMBER", "trust");
  var purposes = { serverAuth: false, emailProtection: false, codeSigning: false };
  PURPOSE_ATTRS.forEach(function (pair) {
    var a = obj.attrs[pair[0]];
    if (!a) return; // an absent bit is untrusted (fail-closed)
    if (a.type !== "CK_TRUST") throw E("trust/bad-block", pair[0] + " must be CK_TRUST");
    purposes[pair[1]] = a.value === CKT_DELEGATOR;
  });
  return { key: issuer.toString("hex") + "/" + serial.toString("hex"), purposes: purposes };
}

// ---------------------------------------------------------------------------
// Anchor assembly + dedup (shared by both sources)
// ---------------------------------------------------------------------------

function _mkAnchor(cert, meta) {
  var spki = cert.subjectPublicKeyInfo;
  return {
    name: cert.subject,                    // the object with .rdns (name chaining)
    publicKey: spki.bytes,                 // the full SPKI SEQUENCE TLV
    algorithm: spki.algorithm.oid,         // the SPKI public-key algorithm OID
    parameters: spki.algorithm.parameters, // e.g. an EC namedCurve (Buffer|null)
    subjectDer: cert.subject.bytes,
    distrustAfter: meta.distrustAfter,
    purposes: meta.purposes,
    label: meta.label,
    mozillaCaPolicy: meta.mozillaCaPolicy,
  };
}

function _datesEqual(x, y) {
  var kx = Object.keys(x).sort(), ky = Object.keys(y).sort();
  if (kx.join(",") !== ky.join(",")) return false;
  return kx.every(function (k) { return x[k].getTime() === y[k].getTime(); });
}

function _purposesEqual(x, y) {
  return PURPOSES.every(function (p) { return x[p] === y[p]; });
}

function _paramsEqual(x, y) {
  if (x === null || y === null) return x === y;
  return Buffer.isBuffer(x) && Buffer.isBuffer(y) && x.equals(y);
}

function _anchorsAgree(x, y) {
  return x.label === y.label &&
    x.mozillaCaPolicy === y.mozillaCaPolicy &&
    x.algorithm === y.algorithm &&
    _paramsEqual(x.parameters, y.parameters) &&
    _purposesEqual(x.purposes, y.purposes) &&
    _datesEqual(x.distrustAfter, y.distrustAfter);
}

// Dedup by (subjectDer, publicKey): the SAME root appearing twice (a
// duplicated block, or certdata + CCADB merged by the operator) collapses to
// one anchor; a DISTINCT root that merely shares a subject DN has a different
// key and survives. Two entries for one root that DISAGREE on trust metadata
// are ambiguous -- fail closed rather than silently pick one.
function _dedupAnchors(anchors) {
  var seen = Object.create(null);
  var out = [];
  anchors.forEach(function (a) {
    var key = a.subjectDer.toString("hex") + "/" + a.publicKey.toString("hex");
    var prev = seen[key];
    if (!prev) { seen[key] = a; out.push(a); return; }
    if (!_anchorsAgree(prev, a)) {
      throw E("trust/pairing-mismatch", "two entries for one root (same subject + key) disagree on trust metadata");
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/**
 * @primitive  pki.trust.parseCertdata
 * @signature  pki.trust.parseCertdata(text) -> { anchors }
 * @since      0.2.0
 * @status     experimental
 * @spec       RFC 5280 (NSS certdata.txt object stream)
 * @defends    trust-metadata-misattribution (CWE-345), trust-store-parser-DoS (CWE-770)
 * @related    pki.trust.parseCcadbCsv, pki.trust.anchor, pki.path.validate
 *
 * Parse the Mozilla/NSS `certdata.txt` root-store object stream into
 * constraint-carrying trust anchors. Each CKO_CERTIFICATE object's
 * MULTILINE_OCTAL `CKA_VALUE` is decoded and parsed as a DER certificate; the
 * paired CKO_NSS_TRUST object -- joined by byte-exact CKA_ISSUER +
 * CKA_SERIAL_NUMBER, never adjacency, and cross-checked against the parsed
 * DER -- contributes the purpose trust bits (only CKT_NSS_TRUSTED_DELEGATOR
 * grants a purpose); the per-purpose distrust-after dates ride in the
 * certificate object as bare ASCII times routed through the strict DER time
 * reader. Every anchor carries the exact `{ name, publicKey, algorithm,
 * parameters }` shape `pki.path.validate` consumes plus `distrustAfter`,
 * `purposes`, `subjectDer`, `label`, `mozillaCaPolicy`. A certificate with no
 * trust object becomes an anchor trusted for nothing (never silently
 * dropped); a trust object with no certificate grants nothing. Malformed
 * octal, an oversized block, an unrecognized trust value, a mispaired or
 * ambiguous-duplicate block, or an undecodable distrust-after time throws a
 * typed `trust/*` error -- never a silently truncated or misattributed root.
 *
 * @example
 *   // Real input is the NSS certdata.txt read from disk; a one-root stream is
 *   // synthesized here from a DER certificate to show the object shape.
 *   var cert = pki.schema.x509.parse(der);
 *   var oct = function (buf) { return Array.prototype.map.call(buf, function (b) { return "\\" + ("000" + b.toString(8)).slice(-3); }).join(""); };
 *   var blk = function (n, v) { return n + " MULTILINE_OCTAL\n" + oct(v) + "\nEND\n"; };
 *   var store = pki.trust.parseCertdata("BEGINDATA\n\n" +
 *     "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" +
 *     blk("CKA_ISSUER", cert.issuer.bytes) +
 *     blk("CKA_SERIAL_NUMBER", pki.asn1.build.integer(cert.serialNumber)) +
 *     blk("CKA_VALUE", der));
 *   store.anchors[0].purposes.serverAuth;   // -> false (no trust object: trusted for nothing)
 */
function parseCertdata(text) {
  text = guard.text.decode(text, LIMITS.TRUST_MAX_BYTES, TrustError, {
    charset: "latin1", tooLarge: "trust/bad-block", badInput: "trust/bad-input", label: "certdata input",
  });
  var objects = _lexObjects(text);

  var certs = [];
  var byKey = Object.create(null);
  var trusts = [];
  objects.forEach(function (obj) {
    var cls = obj.attrs["CKA_CLASS"];
    if (!cls || cls.type !== "CK_OBJECT_CLASS") {
      throw E("trust/bad-block", "object block is missing CKA_CLASS CK_OBJECT_CLASS");
    }
    if (cls.value === "CKO_CERTIFICATE") {
      var e = _certEntry(obj);
      var prev = byKey[e.key];
      if (prev) {
        // A byte-identical duplicated block collapses; two certificate
        // objects claiming one (issuer, serial) with different content are a
        // forged identity -- fail closed.
        if (!prev.der.equals(e.der) || prev.label !== e.label ||
            prev.mozillaCaPolicy !== e.mozillaCaPolicy ||
            !_datesEqual(prev.distrustAfter, e.distrustAfter)) {
          throw E("trust/pairing-mismatch", "two certificate objects share an (issuer, serial) but disagree");
        }
        return;
      }
      byKey[e.key] = e;
      certs.push(e);
    } else if (cls.value === "CKO_NSS_TRUST") {
      trusts.push(_trustEntry(obj));
    }
    // Any other class (CKO_NSS_BUILTIN_ROOT_LIST, ...) is not a root: skipped.
  });

  trusts.forEach(function (t) {
    var c = byKey[t.key];
    if (!c) return; // a trust object with no certificate object grants nothing
    if (c.purposes) {
      if (!_purposesEqual(c.purposes, t.purposes)) {
        throw E("trust/pairing-mismatch", "two trust objects for one certificate disagree on purpose bits");
      }
      return;
    }
    c.purposes = t.purposes;
  });

  return {
    anchors: _dedupAnchors(certs.map(function (c) {
      return _mkAnchor(c.cert, {
        distrustAfter: c.distrustAfter,
        purposes: c.purposes || { serverAuth: false, emailProtection: false, codeSigning: false },
        label: c.label,
        mozillaCaPolicy: c.mozillaCaPolicy,
      });
    })),
  };
}

// ---------------------------------------------------------------------------
// CCADB CSV -- a small RFC 4180 sub-lexer + header-keyed column mapping
// ---------------------------------------------------------------------------

var CSV_REQUIRED = [
  "Common Name or Certificate Name",
  "Trust Bits",
  "Distrust for TLS After Date",
  "Distrust for S/MIME After Date",
  "PEM Info",
];

// RFC 4180 field lexer: quoted fields, embedded commas / newlines, `""`
// escapes. Strict: a quote may only open at the start of a field, nothing may
// follow a closing quote but a separator, and an unterminated quote at EOF is
// a framing violation. Row and field ceilings are refused as they are hit.
function _csvRows(text) {
  var rows = [], row = [], field = "";
  var inQuotes = false, quoted = false, closed = false;
  var fieldCap = LIMITS.TRUST_MAX_CSV_FIELD_BYTES;

  function appendChar(c) {
    if (field.length >= fieldCap) throw E("trust/bad-csv", "a CSV field exceeds LIMITS.TRUST_MAX_CSV_FIELD_BYTES");
    field += c;
  }
  function endField() { row.push(field); field = ""; quoted = false; closed = false; }
  function endRow() {
    endField();
    if (rows.length >= LIMITS.TRUST_MAX_CSV_ROWS) throw E("trust/bad-csv", "CSV row count exceeds LIMITS.TRUST_MAX_CSV_ROWS");
    rows.push(row); row = [];
  }

  var i = 0, n = text.length;
  while (i < n) {
    var ch = text.charAt(i);
    if (inQuotes) {
      if (ch === "\"") {
        if (text.charAt(i + 1) === "\"") { appendChar("\""); i += 2; continue; }
        inQuotes = false; closed = true; i++; continue;
      }
      appendChar(ch); i++; continue;
    }
    if (ch === "\"") {
      if (field !== "" || quoted) throw E("trust/bad-csv", "a quote may only open at the start of a field (RFC 4180)");
      inQuotes = true; quoted = true; i++; continue;
    }
    if (ch === ",") { endField(); i++; continue; }
    if (ch === "\r" && text.charAt(i + 1) === "\n") { endRow(); i += 2; continue; }
    if (ch === "\n" || ch === "\r") { endRow(); i++; continue; }
    if (closed) throw E("trust/bad-csv", "content after a closing quote (RFC 4180)");
    appendChar(ch); i++;
  }
  if (inQuotes) throw E("trust/bad-csv", "unterminated quoted field at end of input");
  if (field !== "" || quoted || row.length > 0) endRow();
  return rows;
}

// `Trust Bits` is set-valued (`Websites; Email`): Websites -> serverAuth,
// Email -> emailProtection, Code / Code Signing -> codeSigning. An empty cell
// grants nothing; an unrecognized token is surfaced (a silently-skipped new
// bit would hide program drift), never guessed.
function _trustBits(cell) {
  var purposes = { serverAuth: false, emailProtection: false, codeSigning: false };
  String(cell).split(";").forEach(function (tok) {
    var t = tok.trim();
    if (t === "") return;
    var l = t.toLowerCase();
    if (l === "websites") purposes.serverAuth = true;
    else if (l === "email") purposes.emailProtection = true;
    else if (l === "code" || l === "code signing") purposes.codeSigning = true;
    else throw E("trust/bad-csv", "unrecognized Trust Bits token " + JSON.stringify(t));
  });
  return purposes;
}

// The CCADB distrust columns are DATE-only. Expand Y-M-D to the end-of-day
// ...T23:59:59Z instant -- the same instant NSS encodes as `...235959Z` -- by
// synthesizing a GeneralizedTime and routing through the strict reader (which
// also rejects a rolled-over calendar date). Dotted, dashed, and slashed
// separators are accepted (the export format has drifted between them).
function _csvDate(cell, label) {
  var s = String(cell).trim();
  if (s === "") return null;
  var m = /^(\d{4})[./-](\d{1,2})[./-](\d{1,2})$/.exec(s);
  if (!m) throw E("trust/bad-csv", label + " must be a Y-M-D date, got " + JSON.stringify(s));
  var pad = function (x) { return x.length === 1 ? "0" + x : x; };
  var payload = Buffer.from(m[1] + pad(m[2]) + pad(m[3]) + "235959Z", "latin1");
  try { return _strictTime(payload, "trust/bad-csv", label); }
  catch (e) {
    if (e && e.code === "trust/bad-csv") throw e;
    throw E("trust/bad-csv", label + " is not a real calendar date: " + JSON.stringify(s), e);
  }
}

// A CCADB `PEM Info` cell: the PEM certificate, commonly wrapped in one layer
// of single quotes (a spreadsheet-import guard) -- strip that layer, then
// parse strictly.
function _pemCell(cell) {
  var s = String(cell).trim();
  if (s.charAt(0) === "'") s = s.slice(1);
  if (s.charAt(s.length - 1) === "'") s = s.slice(0, -1);
  s = s.trim();
  if (s === "") throw E("trust/bad-csv", "PEM Info cell is empty");
  try { return x509.parse(s); }
  catch (e) { throw E("trust/not-a-certificate", "PEM Info does not parse as an X.509 certificate", e); }
}

/**
 * @primitive  pki.trust.parseCcadbCsv
 * @signature  pki.trust.parseCcadbCsv(text) -> { anchors }
 * @since      0.2.0
 * @status     experimental
 * @spec       RFC 4180, RFC 5280 (CCADB certificate-records CSV)
 * @defends    trust-metadata-misattribution (CWE-345), trust-store-parser-DoS (CWE-770)
 * @related    pki.trust.parseCertdata, pki.trust.anchor, pki.path.validate
 *
 * Parse a CCADB certificate-records CSV export into the SAME `Anchor` shape
 * `parseCertdata` produces, so downstream enforcement is source-agnostic.
 * Columns are located by header NAME -- never by position -- and unknown,
 * reordered, or extra columns are tolerated; a MISSING required column
 * (`Common Name or Certificate Name`, `Trust Bits`, `Distrust for TLS After
 * Date`, `Distrust for S/MIME After Date`, `PEM Info`) fails closed with
 * `trust/bad-csv`. Fields follow RFC 4180 quoting (embedded commas, newlines,
 * doubled-quote escapes -- the PEM Info column depends on it). `Trust Bits`
 * is set-valued (Websites -> serverAuth, Email -> emailProtection, Code ->
 * codeSigning; absent -> untrusted). A DATE-only distrust cell expands to the
 * end-of-day `...T23:59:59Z` instant, matching the NSS `...235959Z`
 * encoding, through the same strict time reader.
 *
 * @example
 *   var csv = "Common Name or Certificate Name,Trust Bits," +
 *             "Distrust for TLS After Date,Distrust for S/MIME After Date,PEM Info\n" +
 *             'Example Root,"Websites; Email",2027.06.01,,"' + pemText + '"';
 *   var store = pki.trust.parseCcadbCsv(csv);
 *   store.anchors[0].purposes.serverAuth;                    // -> true
 *   store.anchors[0].distrustAfter.serverAuth.toISOString(); // -> "2027-06-01T23:59:59.000Z"
 */
function parseCcadbCsv(text) {
  text = guard.text.decode(text, LIMITS.TRUST_MAX_BYTES, TrustError, {
    charset: "utf-8", fatal: true,
    tooLarge: "trust/bad-block", badDecode: "trust/bad-csv", badInput: "trust/bad-input",
    label: "CCADB CSV input",
  });
  var rows = _csvRows(text);
  if (rows.length === 0) throw E("trust/bad-csv", "CSV input carries no header row");

  // trim() also strips a leading U+FEFF, so a BOM-prefixed export resolves
  // its first header cell normally.
  var header = rows[0].map(function (h) { return h.trim(); });
  var col = Object.create(null);
  header.forEach(function (h, idx) {
    if (col[h] !== undefined) {
      // Two columns with one REQUIRED name make the mapping ambiguous (which
      // Trust Bits column binds?) -- fail closed rather than silently pick.
      if (CSV_REQUIRED.indexOf(h) !== -1) throw E("trust/bad-csv", "duplicate required column " + JSON.stringify(h));
      return;
    }
    col[h] = idx;
  });
  CSV_REQUIRED.forEach(function (r) {
    if (col[r] === undefined) throw E("trust/bad-csv", "CSV is missing the required column " + JSON.stringify(r));
  });

  var anchors = [];
  for (var i = 1; i < rows.length; i++) {
    var row = rows[i];
    if (row.length !== header.length) {
      throw E("trust/bad-csv", "CSV row " + (i + 1) + " has " + row.length + " fields; the header has " + header.length);
    }
    var distrustAfter = {};
    var tls = _csvDate(row[col["Distrust for TLS After Date"]], "Distrust for TLS After Date");
    if (tls) distrustAfter.serverAuth = tls;
    var smime = _csvDate(row[col["Distrust for S/MIME After Date"]], "Distrust for S/MIME After Date");
    if (smime) distrustAfter.emailProtection = smime;
    var label = row[col["Common Name or Certificate Name"]].trim();
    anchors.push(_mkAnchor(_pemCell(row[col["PEM Info"]]), {
      distrustAfter: distrustAfter,
      purposes: _trustBits(row[col["Trust Bits"]]),
      label: label === "" ? null : label,
      mozillaCaPolicy: false, // certdata-only metadata
    }));
  }
  return { anchors: _dedupAnchors(anchors) };
}

/**
 * @primitive  pki.trust.anchor
 * @signature  pki.trust.anchor(entry, opts?) -> trustAnchor
 * @since      0.2.0
 * @status     experimental
 * @spec       RFC 5280 sec. 6.1.1 (NSS trust-bit semantics)
 * @related    pki.trust.parseCertdata, pki.trust.parseCcadbCsv, pki.path.validate
 *
 * Turn a parsed trust-store entry into the `trustAnchor` object
 * `pki.path.validate` consumes: `{ name, publicKey, algorithm, parameters,
 * distrustAfter, purposes }` -- a straight hand-off (validate reads
 * `distrustAfter` as a per-purpose map and `purposes` as the delegator set,
 * selected by its own `opts.checkPurpose`). With `opts.purpose` it
 * fail-fasts: an entry that is not a trusted delegator for that purpose
 * throws `trust/purpose-not-trusted` at build time, so an operator wiring a
 * store catches the wrong root before a single validation runs (the
 * authoritative gate stays inside `validate`).
 *
 * @opts
 *   purpose: string   // "serverAuth" | "emailProtection" | "codeSigning" -- fail-fast purpose check
 *
 * @example
 *   var csv = "Common Name or Certificate Name,Trust Bits," +
 *             "Distrust for TLS After Date,Distrust for S/MIME After Date,PEM Info\n" +
 *             'Example Root,Websites,,,"' + pemText + '"';
 *   var entry = pki.trust.parseCcadbCsv(csv).anchors[0];
 *   var anchor = pki.trust.anchor(entry, { purpose: "serverAuth" });
 *   await pki.path.validate([pki.schema.x509.parse(der)], { time: new Date(), trustAnchor: anchor, checkPurpose: "serverAuth" });
 */
function anchor(entry, opts) {
  if (!entry || typeof entry !== "object" || !Buffer.isBuffer(entry.publicKey) ||
      typeof entry.algorithm !== "string" || !entry.name || !Array.isArray(entry.name.rdns)) {
    throw E("trust/bad-input", "anchor expects a trust-store entry ({ name, publicKey, algorithm, ... })");
  }
  opts = opts || {};
  if (opts.purpose !== undefined) {
    if (PURPOSES.indexOf(opts.purpose) === -1) {
      throw E("trust/bad-input", "anchor: opts.purpose must be one of " + PURPOSES.join(" | "));
    }
    if (!entry.purposes || entry.purposes[opts.purpose] !== true) {
      throw E("trust/purpose-not-trusted", "this root is not a trusted delegator for " + opts.purpose);
    }
  }
  return {
    name: entry.name,
    publicKey: entry.publicKey,
    algorithm: entry.algorithm,
    parameters: entry.parameters !== undefined ? entry.parameters : null,
    distrustAfter: entry.distrustAfter || {},
    purposes: entry.purposes || { serverAuth: false, emailProtection: false, codeSigning: false },
  };
}

module.exports = {
  parseCertdata: parseCertdata,
  parseCcadbCsv: parseCcadbCsv,
  anchor: anchor,
};
