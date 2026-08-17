// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.smime
 * @nav        Messaging
 * @title      S/MIME
 * @order      175
 * @slug       smime
 *
 * @intro
 *   RFC 8551 S/MIME assembly + verification + encryption over the shipped CMS
 *   layer. `sign` wraps a MIME entity as a signed S/MIME message and `verify`
 *   unwraps and verifies one, in both forms: `multipart/signed` (clear-signed --
 *   the content stays readable, a detached CMS signature rides alongside) and
 *   `application/pkcs7-mime` (opaque, where the whole entity is a base64 CMS
 *   SignedData). `encrypt` envelopes a MIME entity as an opaque
 *   `application/pkcs7-mime` message and `decrypt` opens one -- `authEnveloped-data`
 *   (AES-GCM, confidentiality AND integrity, the default) or `enveloped-data`
 *   (AES-CBC, confidentiality only, so `decrypt` surfaces `authenticated:false`,
 *   the EFAIL / RFC 8551 sec. 3.3 no-integrity caveat). The crypto is entirely
 *   `pki.cms.sign` / `verify` / `encrypt` / `decrypt`; the new work is the MIME
 *   frame and the RFC 8551 sec. 3.1.1 canonicalization signer and verifier share
 *   one canonicalizer (`lib/mime.js`) so their digests cannot diverge. Like
 *   `cms.verify`, `verify` returns the per-signer cryptographic verdict; chaining
 *   a signer to a trust anchor is the caller's `pki.path.validate` step.
 *
 * @card
 *   Assemble, verify, and encrypt RFC 8551 S/MIME messages (signed:
 *   multipart/signed + application/pkcs7-mime; encrypted: enveloped-data +
 *   authEnveloped-data) over any CMS signer / recipient, fail-closed,
 *   algorithm-agnostic.
 */

var frameworkError = require("./framework-error.js");
var mime = require("./mime.js");
var cms = require("./cms-verify.js");
var schemaCms = require("./schema-cms.js");
var schemaX509 = require("./schema-x509.js");
var pkix = require("./schema-pkix.js");
var oid = require("./oid.js");
var guard = require("./guard-all.js");
var C = require("./constants.js");
var nodeCrypto = require("crypto");

var SmimeError = frameworkError.SmimeError;

function _err(code, msg, cause) { return new SmimeError(code, msg, cause); }

// ---- the option surface each verb accepts -----------------------------------
//
// A misspelled option is the one input that reads as an omission, never as a value: nothing is
// out of range, nothing fails to parse, and the caller who asked for something stricter silently
// gets the looser default. `protectHeaders` misspelled sends the headers a caller meant to protect
// as ordinary display copies; `strictMicalg` misspelled accepts the mismatch it was set to reject;
// `entity` misspelled wraps a caller's complete MIME entity inside another one.
//
// The tables are per verb, not per module, because the surfaces genuinely differ (`form` means
// something on sign and nothing on encrypt) and a merged table would accept each verb's options at
// every other one, which is the same silence in a wider form. Each is the keys that verb's body and
// the helpers it hands `opts` to actually read: the value goes through _entityBytes, _cmsSignOpts or
// _cmsEncryptOpts as readily as it is read here, so a table built from the verb's own lines alone
// would refuse options that work.
var SIGN_OPTS = {
  form: 1, entity: 1, contentType: 1, signingTime: 1, protectHeaders: 1, headers: 1, hcp: 1,
  sid: 1, signedAttributes: 1, additionalSignedAttributes: 1,
};
var VERIFY_OPTS = {
  certs: 1, trustAnchors: 1, time: 1, requiredEku: 1, checkPurpose: 1, strictMicalg: 1,
  legacyHeaderProtection: 1, expectedSender: 1,
};
var ENCRYPT_OPTS = {
  entity: 1, contentType: 1, protectHeaders: 1, headers: 1, hcp: 1,
  contentEncryptionAlgorithm: 1, oaepHash: 1, keyIdentifier: 1, ukm: 1,
};
var DECRYPT_OPTS = { recipientIndex: 1, maxIterations: 1, strictSmimeType: 1, legacyHeaderProtection: 1 };
var COMPRESS_OPTS = { entity: 1, contentType: 1, level: 1 };
var DECOMPRESS_OPTS = { maxOutputBytes: 1 };

function _knownOpts(opts, known, verb) {
  guard.identifier.assertKnownKeys(opts, known, _err, "smime/bad-input", function (k) {
    return "unknown option " + JSON.stringify(k) + " for pki.smime." + verb + " -- accepted: " +
      Object.keys(known).sort().join(", ");
  });
}

// RFC 8551 uses application/pkcs7-<kind>; OpenSSL's legacy `smime` command emits the PKCS#7
// application/x-pkcs7-<kind>. Accept both on the RECEIVE side (we always EMIT the RFC 8551 form).
function _isPkcs7(type, kind) {
  var t = (type || "").toLowerCase();
  return t === "application/pkcs7-" + kind || t === "application/x-pkcs7-" + kind;
}

// The RFC 8551 sec. 3.4.3.2 micalg name for a CMS digest (schema-cms surfaces "sha256" etc.).
// RFC 8551 sec. 3.4.3.2 micalg names, extended with the SHAKE names FIPS 204/205 CMS signers digest
// with (RFC 8702). An unknown digest passes through verbatim and is never regex-mangled (a blind
// `sha`->`sha-` would corrupt "shake256" into "sha-ke256").
var MICALG = { sha1: "sha-1", sha224: "sha-224", sha256: "sha-256", sha384: "sha-384", sha512: "sha-512", md5: "md5", shake128: "shake128", shake256: "shake256" };

// The exact bytes to sign: the caller's content wrapped as a MIME entity (text/plain by default) in
// its canonical form, or, when opts.entity is set, the caller's own complete MIME entity, canonical.
function _entityBytes(content, opts) {
  var raw = guard.bytes.view(content, SmimeError, "smime/bad-input", "content");
  if (opts.entity) return mime.canonicalize(raw, SmimeError, "smime/bad-mime");
  // Declare the honest Content-Transfer-Encoding: "7bit" requires every byte <= 127 (RFC 2045); a body
  // with any 8-bit byte is "8bit". Declaring 7bit for 8-bit content is a false claim a transport could act on.
  var cte = _is7bit(raw) ? "7bit" : "8bit";
  // Build through the guarded serializer so a CRLF / NUL in opts.contentType cannot inject a header field.
  return mime.buildEntity([{ name: "Content-Type", value: opts.contentType || "text/plain; charset=utf-8" }, { name: "Content-Transfer-Encoding", value: cte }], raw, SmimeError, "smime/bad-header");
}
function _is7bit(buf) { for (var i = 0; i < buf.length; i++) if (buf[i] > 0x7f) return false; return true; }

// ---- RFC 9788 header protection (an opts.protectHeaders-gated MIME transform over the shipped CMS path) ----
// The protected header fields are inlined on the Cryptographic Payload root (its Content-Type gains an `hp`
// parameter: "clear" for signed-only, "cipher" for encrypted); the outer display headers are copied as-is
// (signed) or passed through a Header Confidentiality Policy (encrypted). The CMS crypto is UNCHANGED.

// Is this (lowercased) header field name Structural? RFC 9787 sec. 1.1.1 defines a Structural Header Field as
// MIME-Version OR any field whose name begins with "Content-" (Content-Type / -Transfer-Encoding /
// -Disposition / -ID / -Description / -Language / -Location / ...). These describe the specific MIME part --
// the library sets them -- so they are never protected as Non-Structural fields (rejected at the producer) nor
// surfaced in the authenticated protectedHeaders set on verify. The prefix rule is the RFC definition itself,
// so it matches every Content-* field (not just an enumerated subset) and is not a prototype-key lookup (a
// field named "constructor" / "toString" is simply not Structural).
function _isStructural(lname) {
  return lname === "mime-version" || lname.indexOf("content-") === 0;
}

// Normalize opts.headers (an object { Name: value } or an array [{ name, value }]) to an ordered list. A
// malformed shape is a config-time smime/bad-input (the value's byte integrity is guarded at emission).
function _hpHeaderList(headers) {
  if (headers == null) return [];
  var out = [];
  if (Array.isArray(headers)) {
    headers.forEach(function (h) {
      if (!h || typeof h !== "object") throw _err("smime/bad-input", "each opts.headers entry must be { name, value }");
      // Read name + value once each: an accessor / Proxy could return a different value on a second read, so
      // the snapshot (not the live property) is what both the signed inner header and the outer display copy use.
      var name = h.name, v = h.value;
      if (typeof name !== "string") throw _err("smime/bad-input", "each opts.headers entry must be { name, value }");
      out.push({ name: name, value: v == null ? "" : String(v) });
    });
  } else if (typeof headers === "object") {
    Object.keys(headers).forEach(function (k) { var v = headers[k]; out.push({ name: k, value: v == null ? "" : String(v) }); });
  } else {
    throw _err("smime/bad-input", "opts.headers must be an object or an array of { name, value }");
  }
  // Only Non-Structural fields are protected (RFC 9787): a Structural header (Content-Type, MIME-Version, ...)
  // describes the MIME structure -- the library sets it -- so a caller passing one would duplicate it on the
  // payload root. And a REPEATED field name is rejected here at the PRODUCER: a repeated protected field is an
  // unsupported shape (verify fails closed on the ambiguity), so the library never emits a message it cannot
  // re-consume. Reject both; never emit a malformed / self-inconsistent entity.
  var seen = Object.create(null);
  out.forEach(function (h) {
    var ln = h.name.toLowerCase();
    if (_isStructural(ln)) throw _err("smime/bad-input", "opts.headers must not include the Structural header " + JSON.stringify(h.name) + " (RFC 9787); only Non-Structural fields (Subject / From / To / ...) are protected");
    // HP-Outer is a reserved field the library emits itself (RFC 9788 sec. 2.2) to document outer-header
    // confidentiality; a caller-supplied one would be mistaken for that machinery, so reject it.
    if (ln === "hp-outer") throw _err("smime/bad-input", "opts.headers must not include the reserved HP-Outer field (RFC 9788 sec. 2.2); the library emits it");
    if (seen[ln]) throw _err("smime/bad-input", "opts.headers must not repeat a protected field name (" + JSON.stringify(h.name) + "); a repeated protected field is not supported");
    seen[ln] = 1;
  });
  return out;
}

// The Header Confidentiality Policy for an OUTER header of an encrypted-HP message. hcp_baseline (RFC 9788
// sec. 3.2.1, the default) obscures Subject to "[...]" and REMOVES Comments / Keywords (null);
// hcp_no_confidentiality leaves every field visible (opt-in only). This is the sec. 3.2.1 pseudocode
// Verbatim: Bcc is intentionally not stripped. RFC 9788 sec. 11.4 explains that removing Bcc during
// encryption can break deliverability to a Bcc'd recipient, so the choice is left to the caller (omit Bcc
// from opts.headers to keep it out of the plaintext outer headers).
function _applyHcp(name, value, hcp) {
  if (hcp === "hcp_no_confidentiality") return value;
  var ln = name.toLowerCase();
  if (ln === "subject") return "[...]";
  if (ln === "comments" || ln === "keywords") return null;
  return value;
}

// The outer display header list: for "clear" (signed) the fields are copied verbatim; for "cipher"
// (encrypted) each passes through the HCP, where a null result removes the field (it lives only in the ciphertext).
function _outerHeaderList(list, mode, hcp) {
  var policy = hcp == null ? "hcp_baseline" : hcp;
  if (policy !== "hcp_baseline" && policy !== "hcp_no_confidentiality") throw _err("smime/bad-input", "unknown opts.hcp policy " + JSON.stringify(hcp) + " (only \"hcp_baseline\" or \"hcp_no_confidentiality\")");
  var out = [];
  list.forEach(function (h) {
    if (mode === "cipher") {
      var v = _applyHcp(h.name, h.value, policy);
      if (v !== null) out.push({ name: h.name, value: v });
    } else {
      out.push({ name: h.name, value: h.value });
    }
  });
  return out;
}

// Build the inner Cryptographic Payload for a header-protected message: the caller's body wrapped with its
// Content-Type (gaining ; hp="<mode>") + Content-Transfer-Encoding + the protected fields inlined, canonical.
// hpList is the single normalized snapshot of opts.headers (see the caller), and that same list feeds the signed/
// encrypted inner header set here and the outer display copy, so an accessor / Proxy cannot make them diverge.
// outerList is the HCP-processed outer set (_outerHeaderList) -- for a cipher payload it also drives the
// HP-Outer records embedded here.
function _protectedInnerEntity(content, opts, mode, hpList, outerList) {
  // Header protection inlines the protected fields on the payload ROOT it builds, so a caller-supplied
  // complete entity (opts.entity) is an unsupported combination: reject it, and never silently bury the
  // caller's entity (its own Content-Type + headers) beneath a new default text/plain wrapper.
  if (opts.entity) throw _err("smime/bad-input", "opts.entity is not supported with protectHeaders -- pass raw content + opts.contentType");
  var raw = guard.bytes.view(content, SmimeError, "smime/bad-input", "content");
  // Header protection sets the hp parameter itself; a caller hp in opts.contentType (with OR without a value)
  // would emit two hp attributes (Content-Type: ...; hp; hp="clear"), an unconsumable non-interoperable
  // message -- reject it here (hasParam catches a bare "hp" that paramCount would miss).
  if (opts.contentType != null && mime.hasParam(String(opts.contentType), "hp")) throw _err("smime/bad-input", "opts.contentType must not set the hp parameter -- header protection sets it (hp=" + JSON.stringify(mode) + ")");
  var ct = (opts.contentType || "text/plain; charset=utf-8") + "; hp=\"" + mode + "\"";
  var fields = [{ name: "Content-Type", value: ct }, { name: "Content-Transfer-Encoding", value: _is7bit(raw) ? "7bit" : "8bit" }];
  hpList.forEach(function (h) { fields.push(h); });
  // RFC 9788 sec. 2.2 / sec. 5.2.1 step 5.v: an ENCRYPTED header-protected payload documents inside the
  // ciphertext, as HP-Outer records, every Non-Structural field it deliberately left visible in the outer
  // (unprotected) header section, as "HP-Outer: <name>: <outer-value>". A field the HCP removed has no HP-Outer
  // record; its absence authenticates that it was made confidential by removal. Signed-only (clear) payloads
  // carry no HP-Outer (sec. 2.2: "not relevant for signed-only messages").
  if (mode === "cipher") {
    outerList.forEach(function (h) { fields.push({ name: "HP-Outer", value: h.name + ": " + h.value }); });
  }
  return mime.buildEntity(fields, raw, SmimeError, "smime/bad-header");
}

// The outer header prefix (display copies + MIME-Version) that precedes the Cryptographic Envelope's
// Content-Type in a header-protected message. Each field is guard-validated (no CR/LF/NUL injection). list is
// the same HCP-processed outer set the inner entity's HP-Outer records were built from.
function _outerPrefix(list) {
  var s = "";
  for (var i = 0; i < list.length; i++) {
    guard.header.assertField(list[i].name, list[i].value, SmimeError, "smime/bad-header");
    s += list[i].name + ": " + list[i].value + "\r\n";
  }
  return s + "MIME-Version: 1.0\r\n";
}

// Does the payload header region declare an hp Content-Type parameter? A cheap raw scan (unfold the header
// block, then look for a Content-Type line carrying an hp= parameter) so a NON-HP payload is never parsed --
// no swallow -- and only a payload that CLAIMS hp is validated (a malformed such payload then fails closed,
// never a silent downgrade to unprotected).
// Re-decode a header value that mime.parse latin1-decoded (byte-preserving) as UTF-8 (RFC 6532), so a
// non-ASCII protected value round-trips intact -- a latin1 string maps 1:1 to bytes, recovering the emitted UTF-8.
function _utf8Header(s) { return Buffer.from(s, "latin1").toString("utf8"); }

function _declaresHp(content) {
  // content is the CANONICAL entity bytes -- the caller (_hpSurface) runs mime.canonicalizeText ONCE so
  // detection here and the subsequent mime.parse see the identical normalized form (bare CR / LF -> CRLF).
  // Detecting hp on the canonical form -- the bytes the signature covers -- is what stops a fold/line-ending
  // transport rewrite from stripping the hp signal from a still-valid signed message.
  var s = content.toString("latin1");
  var m = s.match(/\r\n\r\n/);
  var head = (m ? s.slice(0, m.index) : s).replace(/\r\n[ \t]+/g, " ");
  // Detect hp by composing mime.paramCount, the same comment- + quoted-string-aware tokenizer the parser
  // uses -- over each Content-Type field, so the probe never diverges from mime.parse: a leading-whitespace
  // or before-colon field name is matched (the parser trims it), while an hp= inside a MIME comment or a
  // quoted value is not a parameter (so an ordinary Content-Type cannot opt a message into HP processing). A
  // real hp on ANY Content-Type line is detected; a duplicate Content-Type is rejected downstream.
  var cts = head.match(/^[ \t]*content-type[ \t]*:[^\r\n]*/gim);
  if (!cts) return false;
  for (var i = 0; i < cts.length; i++) {
    // hasParam (not paramCount): a payload that names the hp attribute without a value ("...; hp") still
    // CLAIMS header protection -- detect it so _hpSurface fails closed on the malformed declaration rather
    // than silently downgrading it to unprotected.
    if (mime.hasParam(cts[i].replace(/^[ \t]*content-type[ \t]*:/i, ""), "hp")) return true;
  }
  return false;
}

// A fresh not-protected surface (returned when no header protection is present or detection fails soft). A NEW
// object each call -- the caller Object.assign()s it onto the verify/decrypt result, so it must not be shared.
// `present` + `protectedHeaders` describe only cryptographically-declared (hp=) protection; `legacy` is null
// unless an opt-in legacy RFC8551HP inference succeeded (then it carries its own headers/mode/etc.; see below).
// No header protection means no protected From to compare the outer one against, so the
// mismatch question is unanswered rather than answered "no" -- null, matching every other
// field here that reports an absent property.
function _noneSurface() { return { protectedHeaders: null, headerProtection: { present: false, mode: null, fromMismatch: null, confidential: [], legacy: null } }; }

// Count the Content-Type fields in a parsed header list. A structure with more than one is AMBIGUOUS: mime.parse
// surfaces only the first via contentType, so an hp= parameter or a Cryptographic-Layer media type on a later
// field would be invisible to the classification, and both the standard HP path and the legacy path fail closed on it.
function _contentTypeCount(headers) { var n = 0; headers.forEach(function (h) { if (h.lname === "content-type") n++; }); return n; }

// Header fields that must not sensibly repeat: the RFC 5322 sec. 3.6 max-1 originator/destination/identification
// fields, plus Return-Path (the envelope sender; RFC 5322 sec. 3.6 groups it under trace, but RFC 5321 sec. 4.4
// restricts a delivered message to a single one). A duplicate of one of these is a malformed / ambiguous set (a
// consumer could pick a different sender / subject); a duplicate of any OTHER field (Received and the other
// trace fields, Resent-*, Comments, Keywords, and optional / X-* fields) is legitimately repeatable in a real
// message. A Set (not a plain object) so an attacker-chosen field name like "constructor" / "__proto__" cannot
// match an inherited Object.prototype member and false-trip the singleton reject.
var RFC5322_SINGLETON = new Set(["date", "from", "sender", "reply-to", "to", "cc", "bcc", "message-id", "in-reply-to", "references", "subject", "return-path"]);

// Extract the Non-Structural protected fields from a recovered inner header list. Shared by the standard HP path
// (over the Cryptographic Payload root) and the legacy path (over the message/rfc822 inner message, sec. 4.10).
// Returns { protectedHeaders (UTF-8 map, last-wins, the ergonomic single-value view surfaced by the standard
// path), entries (an ordered array of every { name, value, raw } occurrence, since a real message repeats trace
// fields, and a last-wins collapse would drop all but one), innerFrom, refouter (HP-Outer records), dup (any
// duplicate field name), dupSingleton (a duplicate of an RFC 5322 singleton field) }.
function _extractProtected(headerList) {
  // mime.parse decodes the header block as latin1 (byte-preserving), so a protected value emitted as UTF-8
  // (RFC 6532, the guard permits it) is re-decoded latin1->UTF-8 here to round-trip intact. protectedHeaders
  // surfaces the exact authenticated field body (rawValue: leading/trailing whitespace preserved), and not a
  // trimmed value that would diverge from the signed octets.
  var protectedHeaders = Object.create(null), innerFrom = null, seen = Object.create(null), dup = null, dupSingleton = null;
  var entries = [];    // every Non-Structural { name, value } occurrence, in order -- retains legally-repeated fields
  var refouter = [];   // RFC 9788 sec. 4.2.1: the HP-Outer records (name + the value the field had in the outer section)
  headerList.forEach(function (h) {
    if (_isStructural(h.lname)) return;
    if (h.lname === "hp-outer") {
      // RFC 9788 sec. 4.2.1 step 4.i: split the HP-Outer value on the first colon into (name, outer-value)
      // -> refouter. The value is kept BYTE-PRESERVING (latin1), never UTF-8-decoded, because the sec. 4.3.1
      // confidentiality comparison must be octet-exact (a lossy decode maps distinct invalid octets 0x80/0x81
      // to one replacement char, which would mis-classify an obscured field as exposed and drop it from the
      // confidential set). HP-Outer is never surfaced as a protected header nor counted toward the duplicate
      // check (sec. 2.2: it "can appear multiple times"). A valueless HP-Outer (no inner colon) is ignored.
      var ci = h.rawValue.indexOf(":");
      if (ci >= 0) refouter.push({ name: h.rawValue.slice(0, ci).trim().toLowerCase(), value: h.rawValue.slice(ci + 1).trim() });
      return;
    }
    var val = _utf8Header(h.rawValue);                    // the exact authenticated field body (RFC 6532 UTF-8)
    entries.push({ name: h.name, value: val, raw: h.rawValue });   // EVERY occurrence: `value` (UTF-8) for surfacing, `raw` (latin1) for the octet-exact confidentiality match
    if (seen[h.lname]) { dup = h.name; if (RFC5322_SINGLETON.has(h.lname)) dupSingleton = h.name; }
    seen[h.lname] = 1;
    protectedHeaders[h.name] = val;                       // SURFACE (map, last-wins -- the ergonomic single-value view; `entries` keeps every occurrence + the octet-exact `raw`)
    // innerFrom uses the byte-preserving value: a lossy UTF-8 decode maps distinct invalid 8-bit sequences (0x80
    // vs 0x81) to the same replacement char, which would let an attacker alter the displayed From without
    // tripping fromMismatch. Compare the raw octets instead.
    if (h.lname === "from") innerFrom = h.value;
  });
  return { protectedHeaders: protectedHeaders, entries: entries, innerFrom: innerFrom, refouter: refouter, dup: dup, dupSingleton: dupSingleton };
}

// RFC 9788 sec. 4.3.1: a protected field occurrence is end-to-end confidential (encrypted-only) unless a
// `refouter` record carries its EXACT name + value, meaning that value was copied verbatim to the visible outer
// section. The match is per-OCCURRENCE and MULTISET (each outer record accounts for at most one inside
// occurrence), so a legally-repeated field with one obscured value and one exposed value (Keywords: secret then
// Keywords: public, outer exposing only "public") still reports the name confidential, because a last-wins collapse
// would drop the hidden "secret" and let a caller leak it. A field name is confidential if ANY of its
// occurrences is unexposed. The comparison is octet-exact (latin1 raw), never lossy-decoded. For the standard
// path `refouter` is the HP-Outer records; for the legacy path it is the actual outer Header Section (part A).
function _computeConfidential(entries, refouter) {
  // Index the outer occurrences by (normalized name -> value -> available count) so the multiset comparison is
  // O(N + M), not a per-occurrence rescan of the outer array: matching N identical exposed occurrences would
  // otherwise be N(N+1)/2 comparisons: a DoS an attacker could drive toward the 16 MiB section cap. A two-level
  // Map (never a plain object) so an attacker-chosen name/value like "__proto__" cannot confuse the lookup.
  var byName = new Map();
  refouter.forEach(function (r) {
    var m = byName.get(r.name); if (!m) { m = new Map(); byName.set(r.name, m); }
    m.set(r.value, (m.get(r.value) || 0) + 1);
  });
  var confidential = [], seen = Object.create(null);
  entries.forEach(function (e) {
    var m = byName.get(e.name.toLowerCase()), val = e.raw.trim(), n = (m && m.get(val)) || 0;
    if (n > 0) { m.set(val, n - 1); return; }   // an outer occurrence accounts for (exposes) this one
    if (!seen[e.name]) { seen[e.name] = 1; confidential.push(e.name); }
  });
  return confidential;
}

// Inspect every outer From (outerEnt.header returns only the first; an attacker may append a second, forged From
// that a MUA displays). A mismatch is ANYTHING but exactly one outer From equal to the protected one: a removed
// outer From, a duplicate, or a differing value all flag tampering of the displayed sender.
// null when there was nothing to compare, true/false only when a comparison ran. A bare
// false cannot distinguish "the outer From agrees with the protected one" from "no inner
// From was protected, so no comparison happened" -- and the second is the common case,
// which is how `!fromMismatch` came to read as a passed check on a message where nothing
// was checked at all.
function _computeFromMismatch(innerFrom, outerEnt) {
  if (innerFrom == null) return null;
  var outerFroms = [];
  outerEnt.headers.forEach(function (h) { if (h.lname === "from") outerFroms.push(h.value.trim()); });   // byte-preserving (latin1)
  return outerFroms.length !== 1 || outerFroms[0] !== innerFrom.trim();
}

// Is this (lowercased) media type a Cryptographic Layer (RFC 9788 sec. 4.10.1)? Conservative: any
// application/pkcs7-mime (incl. an OpenSSL x-pkcs7-mime, or a compressed-data layer) plus multipart/signed and
// multipart/encrypted. Mis-classifying part D as a layer only degrades legacy detection to none, the safe direction.
function _isCryptoLayer(type) {
  // `type` is the already-lowercased media type from mime.parse's _parseStructured; _isPkcs7 guards the
  // null/undefined case internally, so no local `|| ""` fallback is needed (and no dead branch is introduced).
  return _isPkcs7(type, "mime") || type === "multipart/signed" || type === "multipart/encrypted";
}

// The legacy `refouter`: the actual visible outer Header Section (part A) as name+value records, so the sec.
// 4.3.1 confidentiality comparison runs against the real outer values (a legacy message carries no HP-Outer).
function _outerRefouter(outerEnt) {
  var r = [];
  outerEnt.headers.forEach(function (h) { if (!_isStructural(h.lname) && h.lname !== "hp-outer") r.push({ name: h.lname, value: h.rawValue.trim() }); });
  return r;
}

// RFC 9788 sec. 4.10 backward compatibility: identify + surface a legacy RFC8551HP message, a Cryptographic
// Envelope whose payload is a bare message/rfc822 object carrying the real headers, with NO hp= parameter. This
// is detect-only (sec. 4.10: "An MUA MUST NOT generate an RFC8551HP message ... MAY try to render") and opt-in
// (`enabled`). Identification (sec. 4.10.1) is the four conjunctive conditions C1-C4; every failure (an
// unparseable inner message, a non-message/rfc822 payload, a nested Cryptographic Layer, an hp= on part D, or an
// ambiguous/empty protected set -- fails SOFT to none (never throws), because the message is not PRECISELY
// identified. On identification (sec. 4.10.2) the inner message's (part D's) Non-Structural fields are surfaced,
// the mode is inferred from the envelope (clear for signed, cipher for encrypted), and the confidential set is
// derived from the actual outer section (part A). CRUCIAL: a legacy RFC8551HP message is structurally
// INDISTINGUISHABLE from an ordinary signed/forwarded message/rfc822 (sec. 4.10.2: the inference is "not based
// on any strong end-to-end guarantees"), so the inferred set is never placed in `protectedHeaders` and never
// sets `present:true`; those describe only cryptographically-declared hp= protection a caller may trust. The
// inference is surfaced only under `headerProtection.legacy` (its own { headers, mode, fromMismatch, confidential }
// object), so a caller keying trust off `present` / `protectedHeaders` can never mistake an opted-in heuristic --
// possibly a forwarded attachment -- for this message's authenticated headers; consuming it is an explicit choice.
function _legacyHpSurface(canon, outerEnt, mode, enabled) {
  if (!enabled) return _noneSurface();
  var partC, partD;
  try {
    // C1 (outermost object is a Cryptographic Layer) holds by construction: _hpSurface only reaches here after a
    // successful, AUTHENTICATED verify/decrypt. C2: the Cryptographic Payload must be a SINGLE message/rfc822 object.
    partC = mime.parse(canon, SmimeError, "smime/bad-header-protection");
    if (partC.contentType.type !== "message/rfc822") return _noneSurface();
    partD = mime.parse(partC.body, SmimeError, "smime/bad-header-protection");
  } catch (_e) { return _noneSurface(); }   // an unparseable legacy candidate is not precisely identified -- fail soft
  // The C2-C4 classification reads only the first Content-Type of each part (mime.parse surfaces that one). A
  // duplicate Content-Type on part C or part D is ambiguous, since a later field could carry hp= or a
  // Cryptographic Layer media type the checks below would miss. Fail soft there, matching the standard path's
  // duplicate reject.
  if (_contentTypeCount(partC.headers) > 1 || _contentTypeCount(partD.headers) > 1) return _noneSurface();
  // C4: an hp= on part D means the message is not legacy (sec. 4.1: a consumer MUST ignore hp outside the payload
  // root). C3: part D must not itself be a Cryptographic Layer (a genuinely nested signed/encrypted message).
  if (mime.hasParam(partD.contentType.value, "hp")) return _noneSurface();
  if (_isCryptoLayer(partD.contentType.type)) return _noneSurface();
  var ex = _extractProtected(partD.headers);
  // Only a duplicate SINGLETON field (RFC 5322 sec. 3.6) is the ambiguous case. Part D is an ordinary received
  // message whose trace fields (Received, ...) and other repeatable fields legitimately recur, so a repeatable
  // duplicate must not reject the inference (else legacy detection fails on essentially all delivered mail).
  if (ex.dupSingleton) return _noneSurface();
  if (!ex.entries.length) return _noneSurface();   // no Non-Structural fields -- nothing to surface
  var confidential = mode === "cipher" ? _computeConfidential(ex.entries, _outerRefouter(outerEnt)) : [];
  // present stays false + protectedHeaders stays null: the inferred set is surfaced only under `legacy` so a
  // caller cannot mistake an opt-in heuristic (indistinguishable from a forwarded message/rfc822) for authenticated
  // headers. `headers` is the ORDERED [{ name, value }] list (every occurrence; a real message repeats trace
  // fields); the internal `raw` per occurrence is dropped from the public shape.
  var headers = ex.entries.map(function (e) { return { name: e.name, value: e.value }; });
  // The OUTER fromMismatch stays unanswered here: a legacy wrap is an inference, never
  // declared protection, so the top-level field must not report a comparison the message
  // did not authenticate. The legacy block carries its own, clearly opt-in.
  return { protectedHeaders: null, headerProtection: { present: false, mode: null, fromMismatch: null, confidential: [], legacy: { headers: headers, mode: mode, fromMismatch: _computeFromMismatch(ex.innerFrom, outerEnt), confidential: confidential } } };
}

// Detect + surface RFC 9788 header protection on a recovered inner entity, FAIL-CLOSED. A payload that does
// not declare hp surfaces protectedHeaders:null, unless opts.legacyHeaderProtection is set and it is a legacy
// RFC8551HP message/rfc822 wrap (sec. 4.10), which _legacyHpSurface then surfaces (opt-in, fail-soft). A payload
// that DECLARES hp is validated: a malformed block, an invalid hp value, or an hp mode that CONTRADICTS the
// cryptographic envelope (expectedMode "clear" for a signed message, "cipher" for a decrypted one) throws
// smime/bad-header-protection -- never a silent downgrade. Otherwise the inline Non-Structural fields ARE the
// authenticated set; a From that differs from the untrusted OUTER From is flagged fromMismatch.
// The email identities a signer certificate actually asserts. RFC 8550 sec. 4.4.3 makes
// subjectAltName the carrier: an ASCII local-part rides the rfc822Name CHOICE, and a
// certificate MAY assert several addresses, so this collects every one rather than the
// first. A non-ASCII local-part rides otherName / SmtpUTF8Mailbox (RFC 8398 sec. 3); those
// are counted as PRESENT but not returned as comparable strings, so a certificate that
// carries only internationalized identities reports "there is an identity here that this
// comparison cannot read" instead of the indistinguishable "no identities".
var SAN_OID = oid.byName("subjectAltName");
var _extNs = pkix.makeNS("smime", SmimeError, oid);
var _extDecoders = pkix.certExtensionDecoders(_extNs);
var _extCtx = { E: function (c, m, cause) { return new SmimeError(c, m, cause); }, oid: oid };
function _signerEmails(certDer) {
  var out = { addresses: [], unreadable: 0 };
  var parsed = null;
  // A failure here is COUNTED, never absorbed: it raises `unreadable`, which drives the
  // sender verdict to null (undecidable) rather than to a clean "no identities". Returning
  // early on the error would make an unreadable certificate indistinguishable from one
  // that genuinely asserts no address, and the caller would read "nothing to match" as a
  // finished comparison instead of one that never happened.
  try { parsed = schemaX509.parse(certDer); }
  catch (parseFailed) { out.unreadable++; out.reason = parseFailed.code || "unparseable"; }
  if (parsed === null) return out;
  (parsed.extensions || []).forEach(function (e) {
    if (e.oid !== SAN_OID) return;
    var dec = null;
    try { dec = _extDecoders.byOid[SAN_OID](e.value, _extCtx); }
    catch (sanFailed) { out.unreadable++; out.reason = sanFailed.code || "bad-san"; }
    if (dec === null) return;
    (dec.names || []).forEach(function (n) {
      if (n.tagNumber === 1) out.addresses.push(String(n.value));   // rfc822Name
      else if (n.tagNumber === 0) out.unreadable++;                 // otherName: possibly SmtpUTF8Mailbox
    });
  });
  return out;
}

// What the signer's certificate says about who sent this, and whether anyone asked.
//
// `match` is THREE-valued and never collapses: true only when an identity in the signer's
// certificate matches under RFC 5280 sec. 7.5; false when every identity was comparable and
// none matched; null when the question was not asked, or was asked and could not be decided
// (no readable identity, or an address needing an IDNA transform this toolkit will not do).
// A boolean here would make "nobody checked" indistinguishable from "checked and agreed",
// which is the defect this field exists to remove -- so a caller enforcing sender binding
// tests `match === true`, and null fails that test exactly as false does.
//
// `expectedSender` is the authoritative input. The outer From is attacker-controlled on an
// unprotected message, so comparing against it is reported as advisory (`source: "from"`)
// and never presented as a verified binding.
function _senderSurface(signers, outerEnt, expectedSender) {
  var expected = null, source = null;
  // Entry-tier: a mistyped option is a caller bug and throws, never a coercion. String()
  // would accept any object with a toString, so `{ toString: () => "alice@example.com" }`
  // would drive a sender binding the caller never actually stated -- the authoritative
  // input to this comparison must be the string it claims to be.
  if (expectedSender != null) {
    if (typeof expectedSender !== "string") {
      throw _err("smime/bad-input", "expectedSender must be a string email address, got " + typeof expectedSender);
    }
    expected = expectedSender; source = "expectedSender";
  }
  else {
    var froms = [];
    outerEnt.headers.forEach(function (h) { if (h.lname === "from") froms.push(h.value.trim()); });
    // Exactly one From, or there is no unambiguous address to compare against.
    if (froms.length === 1) { expected = _addrSpec(froms[0]); source = expected === null ? null : "from"; }
  }
  var identities = [], undecidable = false, sawIdentity = false;
  (signers || []).forEach(function (s) {
    var e = s && s.cert ? _signerEmails(s.cert) : null;
    if (e === null) { undecidable = true; return; }   // no certificate to read at all
    if (e.unreadable > 0) { undecidable = true; sawIdentity = true; }
    e.addresses.forEach(function (a) { sawIdentity = true; if (identities.indexOf(a) === -1) identities.push(a); });
  });
  if (expected === null) return { checked: false, expected: null, source: null, identities: identities, match: null };
  if (!sawIdentity) return { checked: true, expected: expected, source: source, identities: identities, match: null };
  // No early return on the first match. A match is only the answer once nothing else has
  // made the result undecidable: a failed co-signer, an unreadable certificate or an
  // address this toolkit cannot canonicalize all mean the verdict is unsettled, and
  // reporting true from inside the loop would let that be read as a clean binding.
  // Undecidable always wins over a positive.
  var sawMatch = false, sawNotComparable = false;
  for (var i = 0; i < identities.length; i++) {
    var v = guard.name.emailEqual(identities[i], expected);
    if (v === "match") sawMatch = true;
    else if (v === "not-comparable") sawNotComparable = true;
  }
  var verdict;
  if (undecidable || sawNotComparable) verdict = null;
  else verdict = sawMatch;
  return { checked: true, expected: expected, source: source, identities: identities, match: verdict };
}

// The addr-spec inside an RFC 5322 From. A display-name form ("Bob <bob@x>") yields the
// angle-addr; a bare address yields itself. Anything else (a group, a second address, an
// unclosed angle bracket) returns null so the caller reports "not compared" rather than
// comparing against a fragment.
function _addrSpec(v) {
  var lt = v.indexOf("<"), gt = v.lastIndexOf(">");
  if (lt === -1 && gt === -1) return v.indexOf(",") === -1 ? v.trim() : null;
  if (lt === -1 || gt < lt) return null;
  var inner = v.slice(lt + 1, gt).trim();
  return inner.length && inner.indexOf(",") === -1 && inner.indexOf("<") === -1 ? inner : null;
}

function _hpSurface(content, outerEnt, expectedMode, authenticated, legacyEnabled) {
  // Header protection is an AUTHENTICATED property: surface the inner headers as protected only when the
  // cryptographic verdict succeeded (a valid signature, or an authenticated-encryption decrypt). An invalid
  // signature or an unauthenticated (AES-CBC, no integrity) decrypt yields attacker-influenced bytes, and those
  // are never marked or exposed as protected (a caller must not treat protectedHeaders as a trust signal
  // unless integrity held).
  if (!authenticated) return _noneSurface();
  // Detect + parse the CANONICAL entity: the exact bytes the signature covers. A transport may rewrite a
  // CRLF fold OR the header/body separator to bare CR/LF; canonicalize repairs them (so verification still
  // succeeds), and both the hp detection and the parse must run on the repaired bytes, or they diverge from
  // the signed content -- stripping the signal, or false-rejecting a valid message as an unparseable block.
  // The returned `content` stays the raw recovered bytes; only this HP inspection uses the canonical copy.
  var canon = mime.canonicalizeText(content);
  // A payload that does not declare hp is either non-protected (protectedHeaders:null) or a legacy RFC8551HP
  // message/rfc822 wrap the caller opted into detecting (sec. 4.10). Both are mutually exclusive with the
  // standard path below by construction: it runs only when a real hp= is present on the payload root.
  if (!_declaresHp(canon)) return _legacyHpSurface(canon, outerEnt, expectedMode, legacyEnabled);
  var inner = mime.parse(canon, SmimeError, "smime/bad-header-protection");   // a malformed HP block fails closed
  // A duplicate Content-Type makes the hp declaration ambiguous (a parser reads params from the first field,
  // but an hp= may sit on a later one), so the wrap is malformed and fails closed, never a silent downgrade.
  var ctCount = _contentTypeCount(inner.headers);
  if (ctCount > 1) throw _err("smime/bad-header-protection", "a header-protected payload must carry exactly one Content-Type field (found " + ctCount + ")");
  // A duplicate hp attribute is ambiguous (mime.parse keeps the last value, but a recipient honoring the
  // first would see a different mode); fail closed, like the duplicate Content-Type. Counted by attribute
  // name (bare OR valued) so a bare+valued pair ("hp; hp=x") is caught too, and quote-/comment-aware (an hp=
  // inside a quoted value or comment is not the hp parameter, so a message we emit is never self-rejected).
  if (mime.paramNameCount(inner.contentType.value, "hp") > 1) throw _err("smime/bad-header-protection", "a header-protected payload declares the hp parameter more than once");
  // _declaresHp composes the same comment/quoted-string-aware tokenizer (mime.paramCount) mime.parse uses, so
  // reaching here means the single Content-Type carries a real hp parameter (a duplicate is rejected above) --
  // hp is defined. A malformed value fails CLOSED at the mode checks below, never a silent downgrade.
  // The hp keyword values clear / cipher are an enumerated Content-Type parameter. Per RFC 2045 sec. 5.1 a
  // value of this kind is compared case-insensitively for its intended use, so a peer that emits hp="Clear"
  // or hp=CIPHER is still recognized. (We always EMIT lowercase; we ACCEPT any case. The value is inside the
  // signed/encrypted payload, so normalizing it enables no attack; the mode-contradiction check still runs.)
  // _declaresHp detected the hp attribute (hasParam); a bare "hp" with no value is a malformed HP declaration
  // and fails closed (mime.parse skips a valueless parameter, so params.hp is undefined here only for that
  // malformed case).
  var raw = inner.contentType.params.hp;
  if (raw === undefined) throw _err("smime/bad-header-protection", "a header-protected payload declares a bare hp parameter with no value (expected hp=\"clear\" or hp=\"cipher\")");
  var hp = raw.toLowerCase();
  if (hp !== "clear" && hp !== "cipher") throw _err("smime/bad-header-protection", "the header-protected payload declares an invalid hp value " + JSON.stringify(raw) + " (only clear / cipher)");
  if (hp !== expectedMode) throw _err("smime/bad-header-protection", "the payload hp=" + JSON.stringify(hp) + " contradicts the cryptographic envelope (a " + (expectedMode === "cipher" ? "decrypted" : "signed") + " message requires hp=" + JSON.stringify(expectedMode) + ")");
  var ex = _extractProtected(inner.headers);
  // A duplicate protected field is ambiguous (the last-wins overwrite hides an earlier value a different
  // parser might select), so the payload fails closed.
  if (ex.dup) throw _err("smime/bad-header-protection", "a header-protected payload has a duplicate protected header field " + JSON.stringify(ex.dup));
  // RFC 9788 sec. 4.3.1: for an ENCRYPTED payload (hp="cipher") the confidential set is the fields not copied
  // verbatim to the outer section via an HP-Outer record. Signed-only (clear) payloads carry no HP-Outer.
  var confidential = hp === "cipher" ? _computeConfidential(ex.entries, ex.refouter) : [];
  return { protectedHeaders: ex.protectedHeaders, headerProtection: { present: true, mode: hp, fromMismatch: _computeFromMismatch(ex.innerFrom, outerEnt), confidential: confidential, legacy: null } };
}

// Map smime opts to cms.sign opts (the S/MIME layer is algorithm-agnostic and forwards any signer).
function _cmsSignOpts(opts, detached) {
  var o = { detached: detached };
  if (opts.signingTime !== undefined) o.signingTime = opts.signingTime;
  if (opts.sid) o.sid = opts.sid;
  if (opts.signedAttributes !== undefined) o.signedAttributes = opts.signedAttributes;
  if (opts.additionalSignedAttributes) o.additionalSignedAttributes = opts.additionalSignedAttributes;
  return o;
}

// Coverage residual: the defensive `|| default` fallbacks in the helpers below (a null media type, a
// non-standard SignerInfo digest name -> a derived micalg, an absent micalg -> "sha-256"/null, a
// non-Buffer cms.sign result) and the two catch arms (a CMS body that passed cms.verify yet fails a
// second schema-cms.parse) are belt-and-braces around the primary path the round-trips exercise; the
// producer never emits any of them.
function _micName(name) { return name ? (MICALG[name] || name) : null; }
// Normalize a micalg header value into the same sorted-distinct comma-joined form _micalgOf emits.
function _micalgSet(value) {
  var seen = [];
  String(value).split(",").forEach(function (m) { var t = m.trim().toLowerCase(); if (t && seen.indexOf(t) < 0) seen.push(t); });
  return seen.sort().join(",");
}
// The micalg for the SignedData -- RFC 8551 sec. 3.4.3.2: EVERY signer's message-digest algorithm,
// distinct, sorted, comma-separated (a multi-signer message with mixed digests lists them all).
function _micalgOf(p7Der) {
  var parsed;
  try { parsed = schemaCms.parse(guard.bytes.view(p7Der, SmimeError, "smime/bad-mime", "the CMS body")); }
  catch (e) { throw _err("smime/bad-mime", "the CMS SignedData body could not be parsed", e); }
  var out = [];
  (parsed.signerInfos || []).forEach(function (si) {
    var mic = _micName(si.digestAlgorithm && si.digestAlgorithm.name);
    if (mic && out.indexOf(mic) < 0) out.push(mic);
  });
  return out.length ? out.sort().join(",") : null;
}

// A fresh multipart boundary that cannot collide with the content (random, dashed, unique per call).
function _boundary() { return "----=_pki_smime_" + nodeCrypto.randomBytes(18).toString("hex"); }

function _base64Body(der) {
  return Buffer.from(der.toString("base64").replace(/(.{64})/g, "$1\r\n").replace(/\r\n$/, ""), "latin1");
}

/**
 * @primitive  pki.smime.sign
 * @signature  pki.smime.sign(content, signers, opts?) -> Promise<Buffer>
 * @since      0.2.25
 * @status     stable
 * @spec       RFC 8551, RFC 5652
 * @related    pki.smime.verify, pki.cms.sign
 *
 * Assemble a signed S/MIME message (RFC 8551). `content` is the payload: a raw body wrapped as a
 * `text/plain` entity by default, or the caller's own complete MIME entity when `opts.entity` is set;
 * `signers` is the `pki.cms.sign` signer array (any RSA / RSASSA-PSS / ECDSA / EdDSA / ML-DSA / SLH-DSA
 * signer -- the S/MIME layer is algorithm-agnostic). Two forms via `opts.form`:
 *   - `"multipart"` (default, clear-signed): a `multipart/signed` message carrying the canonical entity
 *     verbatim in the first part and a DETACHED CMS SignedData (`application/pkcs7-signature`) over its
 *     canonical form in the second, with `protocol="application/pkcs7-signature"` + a matching `micalg`.
 *   - `"pkcs7-mime"` (opaque): one `application/pkcs7-mime; smime-type=signed-data` entity whose base64
 *     body is an ATTACHED CMS SignedData over the canonical entity.
 * The signed bytes are the entity's RFC 8551 sec. 3.1.1 canonical form (CRLF line endings); the same
 * canonicalizer runs on verify. With `opts.protectHeaders`, the message is header-protected (RFC 9788): the
 * caller's `opts.headers` are inlined on the Cryptographic Payload root (its Content-Type gains `hp="clear"`),
 * so the signature covers them, and copied to the outer display headers; `verify` surfaces the
 * authenticated inner set. Returns the assembled message bytes. Fail-closed with `SmimeError`.
 *
 * @opts form        `"multipart"` (default) or `"pkcs7-mime"`.
 * @opts entity      treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType the wrapped entity's Content-Type (default `text/plain; charset=utf-8`).
 * @opts signingTime a `Date` for the CMS signing-time attribute, or false to omit it.
 * @opts protectHeaders enable RFC 9788 header protection (`hp="clear"`), inlining `opts.headers` on the signed payload + the outer display headers.
 * @opts headers     the Non-Structural fields to protect + display: an object `{ Name: value }` or an array `[{ name, value }]` (Subject / From / To / Date / ...); used with `protectHeaders`.
 * @opts hcp         the Header Confidentiality Policy applied to the OUTER display copies: `"hcp_baseline"` (default) or `"hcp_no_confidentiality"`. A signed message's payload is not encrypted, so this governs presentation, not secrecy; used with `protectHeaders`.
 * @opts sid                       forwarded to cms.sign: the SignerIdentifier form, `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts signedAttributes          forwarded: `false` omits the signed-attributes set entirely (a bare-signature SignedData).
 * @opts additionalSignedAttributes forwarded: extra signed attributes to carry, as `[{ oid, values }]`.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var msg = await pki.smime.sign(Buffer.from("hello"), [{ cert: signerCertDer, key: signerKeyPkcs8 }]);
 */
async function sign(content, signers, opts) {
  opts = opts || {};
  _knownOpts(opts, SIGN_OPTS, "sign");
  // RFC 9788 header protection (opts.protectHeaders): the inner Cryptographic Payload gains hp="clear" +
  // the inlined protected fields, and the outer frame carries the display copies. Off by default => the
  // shipped path, byte-for-byte.
  var hp = opts.protectHeaders === true;
  var hpList = hp ? _hpHeaderList(opts.headers) : null;   // ONE snapshot for both the signed inner + outer display copies
  var outerList = hp ? _outerHeaderList(hpList, "clear", opts.hcp) : null;
  var entity = hp ? _protectedInnerEntity(content, opts, "clear", hpList, outerList) : _entityBytes(content, opts);
  var outer = hp ? _outerPrefix(outerList) : "";
  var form = opts.form || "multipart";
  if (form === "pkcs7-mime") {
    var p7m = await cms.sign(entity, signers, _cmsSignOpts(opts, false));
    var head = Buffer.from(outer + "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7m\r\n\r\n", "utf8");
    return _capped(Buffer.concat([head, _base64Body(_toBuf(p7m)), mime.CRLF]));
  }
  if (form !== "multipart") throw _err("smime/bad-input", "form must be \"multipart\" or \"pkcs7-mime\"");
  var p7s = _toBuf(await cms.sign(entity, signers, _cmsSignOpts(opts, true)));
  var micalg = _micalgOf(p7s) || "sha-256";
  var boundary = _boundary();
  var head2 = Buffer.from(outer + "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=" + micalg + "; boundary=\"" + boundary + "\"\r\n\r\n", "utf8");
  var sigPart = Buffer.concat([
    Buffer.from("Content-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7s\r\n\r\n", "latin1"),
    _base64Body(p7s),
  ]);
  var dl = Buffer.from("--" + boundary + "\r\n", "latin1"), close = Buffer.from("--" + boundary + "--\r\n", "latin1");
  return _capped(Buffer.concat([head2, dl, entity, mime.CRLF, dl, sigPart, mime.CRLF, close]));
}

// A produced message MUST stay within the same size ceiling verify enforces on receive, so sign never
// emits an S/MIME message our own verify would reject as too large (producer/consumer symmetry).
// Coverage residual: the throw only fires on a >16 MiB assembled message -- a real cap, exercised by no
// unit vector (driving it would sign 16 MiB).
function _capped(msg) {
  guard.limits.byteCap(msg, C.LIMITS.MIME_MAX_BYTES, _err, "smime/too-large", "the assembled S/MIME message");
  return msg;
}

/**
 * @primitive  pki.smime.verify
 * @signature  pki.smime.verify(message, opts?) -> Promise<{ valid, trusted, signers, form, content, micalg, sender, protectedHeaders, headerProtection }>
 * @since      0.2.25
 * @status     stable
 * @spec       RFC 8551, RFC 5652, RFC 9788
 * @related    pki.smime.sign, pki.cms.verify, pki.path.validate
 *
 * Unwrap and verify a signed S/MIME message (RFC 8551), both `multipart/signed` and
 * `application/pkcs7-mime; smime-type=signed-data`. For `multipart/signed` the detached CMS signature
 * is recomputed over the first part's RFC 8551 sec. 3.1.1 canonical form (the same canonicalizer the
 * signer used); for `application/pkcs7-mime` the base64 body is the attached CMS SignedData. Returns
 * `pki.cms.verify`'s `{ valid, trusted, signers }` verdict PLUS `form`, the recovered `content` (the
 * signed MIME entity bytes), and the `micalg`.
 *
 * `valid` and `trusted` are separate claims, exactly as in `cms.verify`: a SignedData carries its own
 * certificates, so `valid` says the signature is sound under one of them and nothing about who signed.
 * Name the roots you accept in `opts.trustAnchors` and `trusted` says every signer chained to one --
 * validated for EMAIL, at both ends of the chain. The signer certificate must carry the
 * `emailProtection` key purpose (RFC 8551 sec. 4.4.4), because a certificate restricted to `serverAuth`
 * chains to its root perfectly well and is still the wrong key to have signed a message; and the anchor's
 * own trust metadata must permit that purpose, because a root distributed with NSS trust bits can be
 * marked untrusted for email while remaining a good TLS root. Override either with `opts.requiredEku`
 * and `opts.checkPurpose`. Supply no anchors and `trusted` is `false`, since there was nothing to chain to.
 * A `micalg`
 * that disagrees with the actual digest is advisory unless `opts.strictMicalg` (then `smime/micalg-mismatch`).
 * If the message is header-protected (RFC 9788), `protectedHeaders` is the AUTHENTICATED inner header set (a
 * tampered outer header cannot alter it) and `headerProtection` is `{ present, mode, fromMismatch, confidential, legacy }`
 * -- `present` is `true` only for cryptographically-DECLARED (`hp=`) protection you may trust; `fromMismatch` is
 * `true` when the outer From differs from the protected one, `false` when they agree, and `null` when there was
 * no protected From to compare against, which is every message without header protection. Test it against
 * `false` rather than for falsiness: `!fromMismatch` treats the unanswered case as a passed check, and that is
 * the common case. For a binding that does not depend on the composer having protected headers, use `sender`
 * with `opts.expectedSender`; `confidential` lists the protected fields the composer kept
 * end-to-end confidential (per the authenticated HP-Outer records, RFC 9788 sec. 4.3; only for an encrypted
 * `hp="cipher"` payload). A non-protected message reports `protectedHeaders: null`, `present: false`. A payload
 * whose declared `hp` is malformed, invalid, or contradicts the envelope fails closed (`smime/bad-header-protection`),
 * never a silent downgrade. `legacy` is `null` unless `opts.legacyHeaderProtection` detected a legacy RFC 8551
 * `message/rfc822` wrap (see that option), in which case it is its own `{ headers, mode, fromMismatch, confidential }`
 * object (`headers` an ordered `[{ name, value }]` array that retains legally-repeated fields like `Received`) -- a
 * legacy inference is never placed in `protectedHeaders` and never sets `present: true`, because it is
 * indistinguishable from an ordinary forwarded `message/rfc822`, so a caller keying trust off `present` /
 * `protectedHeaders` cannot mistake the opt-in heuristic for authenticated headers.
 *
 * `sender` answers who the message is from, which `valid` does not: a signature proves a key signed,
 * never that the message came from the mailbox the reader sees. Name the address you expect in
 * `opts.expectedSender` and `sender.match` is `true` only when the signer certificate asserts it as an
 * `rfc822Name` (RFC 8550 sec. 4.4.3), compared under RFC 5280 sec. 7.5: the local-part exactly, the
 * host-part case-insensitively. `match` is THREE-valued and a caller enforcing sender binding tests
 * `match === true` -- `false` means every identity was comparable and none matched, and `null` means the
 * question was not answered (no `expectedSender` and no single outer `From`, a signer certificate
 * asserting no readable email identity, or an internationalized address needing an IDNA transform this
 * toolkit does not perform). `null` is not a pass. `sender.identities` lists what the certificate
 * actually asserts, `sender.checked` whether a comparison ran, and `sender.source` which input it ran
 * against -- `"from"` is ADVISORY, because on a message without header protection the outer From is
 * attacker-controlled.
 *
 * @opts certs        extra signer certificates (DER `Buffer`s) to match, forwarded to `cms.verify`.
 * @opts expectedSender  the email address the signer's certificate must assert for `sender.match` to be
 *                    `true`. Without it the outer `From` is used when there is exactly one, and reported
 *                    as `source: "from"` -- advisory, never a verified binding.
 * @opts trustAnchors the roots you accept, forwarded to `cms.verify`; supplying them is what makes
 *                    `trusted` answerable. Certificate DER or anchor tuples.
 * @opts time         the instant the signer's chain is judged at (default now). Only read with `trustAnchors`.
 * @opts requiredEku  key purposes the SIGNER certificate must carry. Defaults to `["emailProtection"]`.
 * @opts checkPurpose the purpose the ANCHOR's own trust metadata must permit. Defaults to `"emailProtection"`.
 * @opts strictMicalg reject a `multipart/signed` whose `micalg` disagrees with the SignerInfo digest.
 * @opts legacyHeaderProtection  opt in to detecting a LEGACY RFC 8551 header-protected message (RFC 9788 sec. 4.10): a Cryptographic Payload that is a bare `message/rfc822` wrap with no `hp=` parameter. When set, a precisely-identified legacy message surfaces the inner message's headers under `headerProtection.legacy = { headers, mode, fromMismatch, confidential }`, where `headers` is an ordered `[{ name, value }]` array (retaining legally-repeated fields such as `Received`) and the mode is inferred from the envelope (`clear` here). They are not placed under `protectedHeaders`, and `present` stays `false`. Consuming `headerProtection.legacy.headers` is an explicit choice: a legacy message is structurally indistinguishable from an ordinary forwarded `message/rfc822`, so this is a heuristic (RFC 9788 sec. 4.10.2: "not based on any strong end-to-end guarantees"); cross-check `legacy.fromMismatch`. Anything not precisely identified (a nested crypto layer, an `hp=` on the inner message, a non-`message/rfc822` payload, a duplicate of a singleton field, or a duplicate Content-Type) reports `legacy: null`. Off by default. The signed-and-encrypted form (RFC 9788 Appendix C.3.17) is a documented gap (`legacy: null` at `decrypt`; surfaces as `clear` only via the caller's re-`verify` step), because the non-recursive layered API exposes no single seam holding both the inner signature verdict and the outer header section.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var smimeMessageBytes = await pki.smime.sign(Buffer.from("hello"), [{ cert: cert, key: key }]);
 *   var res = await pki.smime.verify(smimeMessageBytes);
 *   if (res.valid) { res.content; res.signers[0].sid; }
 */
async function verify(message, opts) {
  opts = opts || {};
  _knownOpts(opts, VERIFY_OPTS, "verify");
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  // Forwarded, not re-decided here. This verb documents itself as pki.cms.verify's verdict plus the
  // MIME surface, so the trust seam that verb offers has to reach it: building the options from
  // scratch and passing only `certs` would leave a caller naming trust anchors with no way to have
  // them applied, and a `trusted` that read false for want of ever being asked.
  var vOpts = {};
  if (opts.certs) vOpts.certs = opts.certs;
  if (opts.trustAnchors != null) {
    vOpts.trustAnchors = opts.trustAnchors;
    // Trusted FOR THIS PURPOSE. A chain alone does not make a signer right for email: a
    // certificate restricted to serverAuth chains to its root perfectly well and is still the
    // wrong key to have signed a message. RFC 8551 sec. 4.4.4 names emailProtection as the purpose
    // an S/MIME signer's certificate must carry, so this verb asks for it rather than accepting the
    // purpose-neutral answer. A caller who means something else says so with `requiredEku`.
    vOpts.requiredEku = opts.requiredEku != null ? opts.requiredEku : ["emailProtection"];
    // Both ends of the chain. The EKU above constrains the LEAF; this selects the anchor's own
    // trust metadata, which pki.path consults only when a purpose is named. A root distributed
    // with NSS trust bits can be marked untrusted for email while remaining a good TLS root, so
    // asking only the leaf would let a root explicitly distrusted for email still answer
    // "trusted" for an email message.
    vOpts.checkPurpose = opts.checkPurpose != null ? opts.checkPurpose : "emailProtection";
  }
  if (opts.time !== undefined) vOpts.time = opts.time;
  if (_isPkcs7(ct.type, "mime")) {
    if (ct.params["smime-type"] && ct.params["smime-type"] !== "signed-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(ct.params["smime-type"]) + " (only signed-data)");
    var p7m = _decodeCms(ent);
    var res = await cms.verify(p7m, vOpts);
    var inner;
    try { inner = _toBuf(schemaCms.parse(p7m).encapContentInfo.eContent); }
    catch (e) { throw _err("smime/bad-mime", "the pkcs7-mime SignedData has no encapsulated content", e); }
    return Object.assign({ valid: res.valid, trusted: res.trusted, signers: res.signers, form: "pkcs7-mime", content: inner, micalg: null, sender: _senderSurface(res.signers, ent, opts.expectedSender) }, _hpSurface(inner, ent, "clear", res.valid, opts.legacyHeaderProtection === true));
  }
  if (ct.type === "multipart/signed") {
    if (ct.params.protocol && !_isPkcs7(ct.params.protocol, "signature")) throw _err("smime/bad-multipart", "multipart/signed protocol must be application/pkcs7-signature");
    var parts = mime.splitMultipart(ent.body, ct.params.boundary, SmimeError, "smime/bad-multipart");
    if (parts.length !== 2) throw _err("smime/bad-multipart", "multipart/signed must have exactly two body parts, got " + parts.length);
    var sigEnt = mime.parse(parts[1], SmimeError, "smime/bad-mime");
    if (!_isPkcs7(sigEnt.contentType.type, "signature")) throw _err("smime/bad-multipart", "the second part must be application/pkcs7-signature");
    var p7s = _decodeCms(sigEnt);
    // RFC 8551 sec. 3.4 / RFC 1847: the multipart/signed signature is DETACHED -- the SignedData carries
    // NO encapsulated content, the first MIME part IS the signed unit. Reject an ATTACHED SignedData:
    // otherwise cms.verify would verify over the embedded eContent and IGNORE the first part, so an
    // attacker could pair any validly-signed attached blob with an arbitrary first part (a forgery).
    var sd;
    try { sd = schemaCms.parse(p7s); }
    catch (e) { throw _err("smime/bad-mime", "the pkcs7-signature part is not a CMS SignedData", e); }
    if (sd.encapContentInfo && sd.encapContentInfo.eContent != null) {
      throw _err("smime/bad-multipart", "the pkcs7-signature part must carry a DETACHED SignedData (no encapsulated content) (RFC 8551 sec. 3.4)");
    }
    var canon = mime.canonicalize(parts[0], SmimeError, "smime/bad-mime");
    var res2 = await cms.verify(p7s, Object.assign({}, vOpts, { content: canon }));
    var micalg = ct.params.micalg || null;
    // Compare micalg as an ORDER-INDEPENDENT set of digest names (RFC 8551 sec. 3.4.3.2 lists them
    // comma-separated, in no required order, possibly with whitespace).
    if (opts.strictMicalg && micalg && _micalgSet(micalg) !== (_micalgOf(p7s) || "")) {
      throw _err("smime/micalg-mismatch", "the multipart/signed micalg " + JSON.stringify(micalg) + " disagrees with the SignerInfo digests");
    }
    return Object.assign({ valid: res2.valid, trusted: res2.trusted, signers: res2.signers, form: "multipart/signed", content: parts[0], micalg: micalg, sender: _senderSurface(res2.signers, ent, opts.expectedSender) }, _hpSurface(parts[0], ent, "clear", res2.valid, opts.legacyHeaderProtection === true));
  }
  throw _err("smime/unsupported-type", "not a signed S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
}

// The application/pkcs7-mime header for an opaque S/MIME message (RFC 8551 sec. 3.2 / sec. 3.2.2). `name`
// is the smime.p7m (enveloped) / smime.p7z (compressed) file name for the media type + Content-Disposition.
function _pkcs7MimeHead(smimeType, name) {
  return Buffer.from("Content-Type: application/pkcs7-mime; smime-type=" + smimeType + "; name=" + name + "\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=" + name + "\r\n\r\n", "latin1");
}

// The smime-type for a CMS enveloped body, DERIVED from its OUTER content type (RFC 8551 sec. 3.2.2) --
// the single source of truth, never an opts guess: AuthEnvelopedData -> "authEnveloped-data" (AEAD,
// integrity), EnvelopedData -> "enveloped-data" (no integrity). Anything else is not an S/MIME enveloped
// message. Returns { smimeType, name } (name is the parsed contentTypeName). Throws smime/unsupported-type
// for a non-enveloped body (EncryptedData / SignedData carries no smime-type mapping here).
function _envelopedTypeOf(der, badParseCode) {
  var name;
  try { name = schemaCms.parse(guard.bytes.view(der, SmimeError, "smime/bad-mime", "the CMS body")).contentTypeName; }
  catch (e) { throw _err("smime/bad-mime", "the pkcs7-mime body is not a parseable CMS structure", e); }
  if (name === "authEnvelopedData") return "authEnveloped-data";
  if (name === "envelopedData") return "enveloped-data";
  throw _err(badParseCode, "the pkcs7-mime body is a " + name + ", not an EnvelopedData / AuthEnvelopedData");
}

// Map smime opts to cms.encrypt opts. The S/MIME layer is recipient-agnostic: it forwards the content
// -encryption choice + every recipient-shaping opt unchanged, and never emits PEM (the CMS body is base64
// inside a MIME frame). opts.contentType is the MIME media type of the INNER entity (handled by
// _entityBytes), NOT the CMS encapsulated content type -- it is deliberately not forwarded here.
function _cmsEncryptOpts(opts) {
  var o = {};
  if (opts.contentEncryptionAlgorithm !== undefined) o.contentEncryptionAlgorithm = opts.contentEncryptionAlgorithm;
  if (opts.oaepHash !== undefined) o.oaepHash = opts.oaepHash;
  if (opts.keyIdentifier !== undefined) o.keyIdentifier = opts.keyIdentifier;
  if (opts.ukm !== undefined) o.ukm = opts.ukm;
  return o;
}

/**
 * @primitive  pki.smime.encrypt
 * @signature  pki.smime.encrypt(content, recipients, opts?) -> Promise<Buffer>
 * @since      0.2.26
 * @status     stable
 * @spec       RFC 8551, RFC 5652, RFC 5083
 * @related    pki.smime.decrypt, pki.cms.encrypt
 *
 * Envelope a MIME entity as an encrypted S/MIME message (RFC 8551 sec. 3.3 / sec. 3.4). `content` is the
 * payload -- a raw body wrapped as a `text/plain` entity by default, or the caller's own complete MIME
 * entity when `opts.entity` is set; `recipients` is the `pki.cms.encrypt` recipient array (any RSA-OAEP
 * ktri / EC or X25519/X448 kari / ML-KEM ori-KEM / password pwri / kek kekri: the S/MIME layer is
 * recipient-agnostic; a single descriptor is accepted and normalized to a one-element array). Enveloping
 * has a single form, opaque `application/pkcs7-mime` with the whole entity base64-encoded. The `smime-type`
 * is derived from the produced CMS: AES-GCM (the default) yields an AuthEnvelopedData with
 * `smime-type=authEnveloped-data` (confidentiality AND integrity); a CBC choice yields an EnvelopedData
 * with `smime-type=enveloped-data` (confidentiality only, no integrity, RFC 8551 sec. 3.3). With
 * `opts.protectHeaders`, the message is header-protected (RFC 9788): the real `opts.headers` are inlined
 * inside the ciphertext (the payload Content-Type gains `hp="cipher"`), and only the Header-Confidentiality-
 * Policy-processed display copies appear outside -- the default `hcp_baseline` obscures Subject to `[...]`
 * and removes Comments / Keywords, so those values live only in the ciphertext; `decrypt` recovers the real
 * inner set. Returns the assembled message bytes. Fail-closed with `SmimeError`.
 *
 * @opts entity                     treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType                the wrapped entity's MIME Content-Type (default `text/plain; charset=utf-8`).
 * @opts protectHeaders             enable RFC 9788 header protection (`hp="cipher"`): inline `opts.headers` inside the ciphertext, emit HCP-processed outer copies, and embed the authenticated HP-Outer records (RFC 9788 sec. 2.2) documenting which fields were left visible outside.
 * @opts headers                    the Non-Structural fields to protect (object `{ Name: value }` or array `[{ name, value }]`); the real values, hidden by the HCP.
 * @opts hcp                        the Header Confidentiality Policy: `"hcp_baseline"` (the default, obscuring Subject and removing Comments/Keywords) or `"hcp_no_confidentiality"` (leave all outer values visible). Per RFC 9788 sec. 3.2.1 / sec. 11.4, `hcp_baseline` deliberately does not strip `Bcc` (removing it can break deliverability to a Bcc'd recipient); to keep a blind recipient out of the plaintext outer headers, omit `Bcc` from `opts.headers`.
 * @opts contentEncryptionAlgorithm forwarded to cms.encrypt: `"aes-256-gcm"` (default) / `"aes-128-gcm"` / `"aes-256-cbc"` / `"aes-128-cbc"`.
 * @opts oaepHash                   forwarded: the RSAES-OAEP hash for ktri recipients.
 * @opts keyIdentifier              forwarded: `"issuerAndSerial"` (default) or `"subjectKeyIdentifier"`.
 * @opts ukm                        forwarded: user keying material for kari / kemri recipients.
 * @example
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var enc = await pki.smime.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 */
async function encrypt(content, recipients, opts) {
  opts = opts || {};
  _knownOpts(opts, ENCRYPT_OPTS, "encrypt");
  // RFC 9788 header protection (opts.protectHeaders): the inner payload carries hp="cipher" + the REAL
  // headers (inside the ciphertext); the outer frame carries only the Header-Confidentiality-Policy-processed
  // display copies (hcp_baseline obscures Subject to [...], removes Comments/Keywords). Off => shipped path.
  var hp = opts.protectHeaders === true;
  var hpList = hp ? _hpHeaderList(opts.headers) : null;   // ONE snapshot for both the encrypted inner + outer display copies
  var outerList = hp ? _outerHeaderList(hpList, "cipher", opts.hcp) : null;
  var entity = hp ? _protectedInnerEntity(content, opts, "cipher", hpList, outerList) : _entityBytes(content, opts);
  // Build the outer prefix (opts.headers + opts.hcp were validated when outerList was computed) BEFORE the
  // expensive cms.encrypt, so a bad policy / header fails closed without doing the crypto.
  var outer = hp ? Buffer.from(_outerPrefix(outerList), "utf8") : Buffer.alloc(0);
  // Normalize a single descriptor to an array so cms.encrypt always takes the ENVELOPED path (an array of
  // RecipientInfos), never bare EncryptedData -- which is not an S/MIME construct (no smime-type maps to it).
  var recips = Array.isArray(recipients) ? recipients : [recipients];
  var der = _toBuf(await cms.encrypt(entity, recips, _cmsEncryptOpts(opts)));
  var head = _pkcs7MimeHead(_envelopedTypeOf(der, "smime/bad-mime"), "smime.p7m");
  return _capped(Buffer.concat([outer, head, _base64Body(der), mime.CRLF]));
}

/**
 * @primitive  pki.smime.decrypt
 * @signature  pki.smime.decrypt(message, keyMaterial, opts?) -> Promise<{ content, smimeType, authenticated, recipientType, recipientIndex, contentEncryptionAlgorithm, protectedHeaders, headerProtection }>
 * @since      0.2.26
 * @status     stable
 * @spec       RFC 8551, RFC 5652, RFC 5083, RFC 9788
 * @related    pki.smime.encrypt, pki.cms.decrypt, pki.smime.verify
 *
 * Open an encrypted S/MIME message (RFC 8551 sec. 3.3 / sec. 3.4) -- an `application/pkcs7-mime` entity
 * whose base64 body is a CMS EnvelopedData or AuthEnvelopedData. `keyMaterial` is the `pki.cms.decrypt`
 * key material (`{ key, cert }`, `{ password }`, or `{ kek, kekId? }`). Returns the recovered inner MIME
 * entity as `content`, the `smimeType`, `authenticated` (true only for AuthEnvelopedData; a CBC
 * `enveloped-data` message reports `false`, the RFC 8551 sec. 3.3 / EFAIL no-integrity caveat), and the
 * `recipientType` / `recipientIndex` / `contentEncryptionAlgorithm` from the CMS layer. Fail-closed and
 * oracle-free: every secret-dependent failure collapses to the uniform `cms/decrypt-failed` the CMS layer
 * emits (this layer only propagates it). A recovered `content` that is itself a signed S/MIME message is
 * returned as-is for the caller to feed back to `pki.smime.verify` (no auto-recursion). Accepts OpenSSL's
 * legacy `application/x-pkcs7-mime` and a missing `smime-type`. If the decrypted payload is header-protected
 * (RFC 9788, `hp="cipher"`), `protectedHeaders` is the recovered real inner header set (the values the outer
 * Header Confidentiality Policy hid) and `headerProtection` is `{ present, mode, fromMismatch, confidential, legacy }`,
 * where `present` is `true` only for a declared `hp=` payload, and `confidential` names the fields the composer
 * kept end-to-end confidential (via the authenticated HP-Outer records, RFC 9788 sec. 4.3) -- so a caller can
 * reply/forward without leaking them (sec. 6.1); a payload whose `hp` is malformed or contradicts the envelope
 * fails closed (`smime/bad-header-protection`). `legacy` is `null` unless `opts.legacyHeaderProtection` detected a
 * legacy RFC 8551 `message/rfc822` wrap (its own `{ headers, mode, fromMismatch, confidential }` object, where `headers`
 * is an ordered `[{ name, value }]` array; it is never merged into `protectedHeaders` / `present`).
 *
 * @opts recipientIndex  forwarded to cms.decrypt: explicitly select the recipient by index.
 * @opts maxIterations   forwarded to cms.decrypt: lower the PBKDF2 iteration cap (downward only).
 * @opts strictSmimeType reject a header `smime-type` that disagrees with the CMS body (`smime/smime-type-mismatch`).
 * @opts legacyHeaderProtection  opt in to detecting a LEGACY RFC 8551 header-protected message (RFC 9788 sec. 4.10): an encrypted Cryptographic Payload that is a bare `message/rfc822` wrap with no `hp=` parameter. When set, a precisely-identified legacy message surfaces the inner headers under `headerProtection.legacy = { headers, mode: "cipher", fromMismatch, confidential }`, with `headers` an ordered `[{ name, value }]` array (retaining repeated fields) and the `confidential` set derived from the actual visible outer Header Section. They are not placed under `protectedHeaders`, and `present` stays `false`, since a legacy message is structurally indistinguishable from a forwarded `message/rfc822` (a heuristic; cross-check `legacy.fromMismatch`). Anything not precisely identified reports `legacy: null`. Off by default.
 * @example
 *   var rsa = { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
 *   var pair = await pki.key.generate(rsa);
 *   var recipientKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var recipientCertDer = await pki.x509.sign({ subject: "Recipient", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: recipientKeyPkcs8 });
 *   var smimeMessageBytes = await pki.smime.encrypt(Buffer.from("secret"), [{ cert: recipientCertDer }]);
 *   var res = await pki.smime.decrypt(smimeMessageBytes, { key: recipientKeyPkcs8, cert: recipientCertDer });
 *   res.content;        // the recovered inner MIME entity
 *   res.authenticated;  // true here (an AEAD content cipher); false for an enveloped-only CBC message, which carries no integrity
 */
async function decrypt(message, keyMaterial, opts) {
  opts = opts || {};
  _knownOpts(opts, DECRYPT_OPTS, "decrypt");
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  if (!_isPkcs7(ct.type, "mime")) throw _err("smime/unsupported-type", "not an encrypted S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
  // The smime-type header is advisory (the CMS body is authoritative), so compare it case-insensitively --
  // liberal on accept, strict on emit -- rather than rejecting a legitimate message over its parameter casing.
  var st = ct.params["smime-type"];
  var stLower = st ? st.toLowerCase() : st;
  if (st && stLower !== "enveloped-data" && stLower !== "authenveloped-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(st) + " (only enveloped-data / authEnveloped-data)");
  var der = _decodeCms(ent);
  var smimeType = _envelopedTypeOf(der, "smime/unsupported-type");
  if (opts.strictSmimeType && st && stLower !== smimeType.toLowerCase()) throw _err("smime/smime-type-mismatch", "the header smime-type " + JSON.stringify(st) + " disagrees with the CMS body (" + smimeType + ")");
  var cmsOpts = {};
  if (opts.recipientIndex !== undefined) cmsOpts.recipientIndex = opts.recipientIndex;
  if (opts.maxIterations !== undefined) cmsOpts.maxIterations = opts.maxIterations;
  var res = await cms.decrypt(der, keyMaterial, cmsOpts);
  return Object.assign({
    content: res.content, smimeType: smimeType, authenticated: res.authenticated,
    recipientType: res.recipientType, recipientIndex: res.recipientIndex,
    contentEncryptionAlgorithm: res.contentEncryptionAlgorithm,
  }, _hpSurface(res.content, ent, "cipher", res.authenticated, opts.legacyHeaderProtection === true));
}

/**
 * @primitive  pki.smime.compress
 * @signature  pki.smime.compress(content, opts?) -> Promise<Buffer>
 * @since      0.2.27
 * @status     stable
 * @spec       RFC 8551, RFC 3274
 * @related    pki.smime.decompress, pki.cms.compress
 *
 * Compress a MIME entity as an opaque compressed S/MIME message (RFC 8551 sec. 3.6). `content` is the
 * payload -- a raw body wrapped as a `text/plain` entity by default, or the caller's own complete MIME
 * entity when `opts.entity` is set. The entity is canonicalized (RFC 8551 sec. 3.1) and ZLIB-compressed
 * into a CMS `CompressedData` (`pki.cms.compress`), carried opaque in one `application/pkcs7-mime;
 * smime-type=compressed-data; name=smime.p7z` entity (base64). Compression is a size transform with NO
 * integrity, confidentiality, or authentication (RFC 8551 sec. 2.4.5). Sign or encrypt the result if
 * you need protection. Returns the assembled message bytes; fail-closed with `SmimeError`.
 *
 * @opts entity      treat `content` as a complete MIME entity (default: wrap it as text/plain).
 * @opts contentType the wrapped entity's MIME Content-Type (default `text/plain; charset=utf-8`).
 * @opts level       forwarded to cms.compress: the DEFLATE compression level (an integer).
 * @example
 *   var z = await pki.smime.compress(Buffer.from("compress this message"));
 */
async function compress(content, opts) {
  opts = opts || {};
  _knownOpts(opts, COMPRESS_OPTS, "compress");
  var entity = _entityBytes(content, opts);
  var cOpts = {};
  if (opts.level !== undefined) cOpts.level = opts.level;
  var der = _toBuf(await cms.compress(entity, cOpts));
  var head = _pkcs7MimeHead("compressed-data", "smime.p7z");
  return _capped(Buffer.concat([head, _base64Body(der), mime.CRLF]));
}

/**
 * @primitive  pki.smime.decompress
 * @signature  pki.smime.decompress(message, opts?) -> Promise<{ content, contentType, contentTypeName, compressionAlgorithm }>
 * @since      0.2.27
 * @status     stable
 * @spec       RFC 8551, RFC 3274
 * @related    pki.smime.compress, pki.cms.decompress, pki.smime.verify, pki.smime.decrypt
 *
 * Decompress a compressed S/MIME message (RFC 8551 sec. 3.6) -- an `application/pkcs7-mime` entity whose
 * base64 body is a CMS `CompressedData`. Returns the recovered inner MIME entity as `content` plus the
 * inner `contentType` / `contentTypeName` and the `compressionAlgorithm`. The inflate is BOUNDED (a
 * decompression-bomb defense, `cms/decompress-too-large`; `opts.maxOutputBytes` tightens it downward).
 * The verdict carries NO `authenticated` / `valid` field, because CompressedData is not a security assertion
 * (RFC 8551 sec. 2.4.5). A recovered content that is itself a signed or enveloped S/MIME message is
 * returned as-is for the caller to feed back to `pki.smime.verify` / `pki.smime.decrypt` (no
 * auto-recursion). Accepts OpenSSL's legacy `application/x-pkcs7-mime` and a missing `smime-type`.
 *
 * @opts maxOutputBytes forwarded to cms.decompress: lower the decompressed-output cap (a DoS bound; downward only).
 * @example
 *   var compressedSmimeBytes = await pki.smime.compress(Buffer.from("compress me"));
 *   var res = await pki.smime.decompress(compressedSmimeBytes);
 *   res.content;   // the recovered inner MIME entity
 */
async function decompress(message, opts) {
  opts = opts || {};
  _knownOpts(opts, DECOMPRESS_OPTS, "decompress");
  var ent = mime.parse(message, SmimeError, "smime/bad-mime");
  var ct = ent.contentType;
  if (!_isPkcs7(ct.type, "mime")) throw _err("smime/unsupported-type", "not a compressed S/MIME message (Content-Type " + JSON.stringify(ct.type) + ")");
  // The smime-type header is advisory (the CMS body is authoritative) -- compare case-insensitively.
  var st = ct.params["smime-type"];
  if (st && st.toLowerCase() !== "compressed-data") throw _err("smime/unsupported-type", "unsupported smime-type " + JSON.stringify(st) + " (only compressed-data)");
  var der = _decodeCms(ent);
  var dOpts = {};
  if (opts.maxOutputBytes !== undefined) dOpts.maxOutputBytes = opts.maxOutputBytes;
  var res = await cms.decompress(der, dOpts);
  return { content: res.content, contentType: res.contentType, contentTypeName: res.contentTypeName, compressionAlgorithm: res.compressionAlgorithm };
}

// Decode a CMS body per its Content-Transfer-Encoding (base64 is the S/MIME norm; 7bit/8bit/binary pass through).
function _decodeCms(ent) {
  // guard.encoding.base64 is strict (no whitespace) and rejects via a (code,msg) FACTORY -- strip the
  // MIME line-wrapping whitespace first, and pass _err (not the SmimeError class).
  if (ent.cte === "base64") return guard.encoding.base64(ent.body.toString("latin1").replace(/[\r\n\t ]/g, ""), C.LIMITS.MIME_MAX_BYTES, _err, "smime/bad-mime", "the CMS body");
  return ent.body;
}

function _toBuf(v) { return Buffer.isBuffer(v) ? v : Buffer.from(v); }

module.exports = { sign: sign, verify: verify, encrypt: encrypt, decrypt: decrypt, compress: compress, decompress: decompress };
