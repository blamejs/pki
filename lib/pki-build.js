// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the ENCODE-direction sibling of schema-pkix.js (which is decode-only). `makeBuilder(ctx)`
// binds a domain namespace once and returns the shared PKIX producing primitives every signer module
// composes: the distinguished-name encoder, the GeneralName + RFC 5280 sec. 4.2.1 extension-value
// encoders, the embedded-input validators (a raw Name / a SubjectPublicKeyInfo / a pre-encoded Extension
// run through the same parser the decoder uses), the sign-scheme bridge, and the post-sign signature
// self-check (the key-match / proof-of-possession verify). Each is parameterized on the CALLER's error
// class + code prefix, so pki.x509.sign keeps x509/* codes and pki.csr.sign keeps csr/*.

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var compositeSig = require("./composite-sig");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
// Each of these doors refuses a caller argument that is not a list. Read live, a replacement
// answering true lets a non-list through the check written to stop it.
var _isArray = intrinsic.isArray;
// Taken at load for the reason every capture here is: the question "do these two encodings name the
// same key" decides whether a proof of possession is accepted, and a caller who replaces the copy or
// the comparison afterwards decides it instead.
var _bufferFrom = intrinsic.bufferFrom;
var _bufferEquals = intrinsic.bufferEquals;
var oid = require("./oid");
var ipUtils = require("./ip-utils");
// packIpLiteral decides a GeneralName form (a bare string -> iPAddress or not), so its binding is taken at
// load: calling it through the exports object would be a live property read, and code that reassigned that
// property could steer the form decision without touching a regex.
var _packIpLiteral = ipUtils.packIpLiteral;
var nodeCrypto = require("crypto");
// The key-material comparison, taken at load like every other operation a decision here rests on.
var _keyEquals = intrinsic.uncurry(nodeCrypto.KeyObject.prototype.equals);
// The bare-string GeneralName classifier (_classifyBareGeneralName) decides which name FORM a SAN string
// becomes. It uses no regular expression: a regex is matched through a live, replaceable protocol
// (RegExp.prototype.exec / test, String.prototype.match / split consult the regex's own `exec` and the
// `[Symbol.match]` / `[Symbol.split]` hooks, and RegExp.prototype.compile can mutate a pattern in place),
// so co-resident code could steer a form decision without our seeing it -- and the structural URI/email
// rules a regex cannot state cleanly are what kept drawing edge-case escapes. Instead every form is
// decided by scanning the string one character code at a time through these captured string primitives,
// which read the value directly and have no per-character dispatch to replace.
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _stringIndexOf = intrinsic.stringIndexOf;
var _stringLastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _sliceStr = intrinsic.uncurry(String.prototype.slice);
var _String = intrinsic.String;
var _objectKeys = intrinsic.keys;
var _isBufferChk = intrinsic.isBuffer;
var _stringify = intrinsic.stringify;

// --- bare-string GeneralName form detection, by character-code scan (no regex) ---
// Each predicate answers "is this string syntactically THIS name form", reading the string one code unit
// at a time; a caller cannot steer the answer by replacing a prototype method. The classifier below tries
// the forms in a fixed precedence and refuses anything none of them accepts (the object form is the escape).
function _isAlphaCode(c) { return (c >= 65 && c <= 90) || (c >= 97 && c <= 122); }          // A-Z a-z
function _isDigitCode(c) { return c >= 48 && c <= 57; }                                      // 0-9
function _isHexCode(c) { return (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70); }

// RFC 3986 sec. 2.3 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~".
function _isUnreserved(c) { return _isAlphaCode(c) || _isDigitCode(c) || c === 45 || c === 46 || c === 95 || c === 126; }
// RFC 3986 sec. 2.2 sub-delims: ! $ & ' ( ) * + , ; =
function _isSubDelim(c) {
  switch (c) {
    case 33: case 36: case 38: case 39: case 40: case 41: case 42: case 43: case 44: case 59: case 61: return true;
    default: return false;
  }
}
// A userinfo byte: unreserved / sub-delim / ":" (percent-encoding handled separately). No "@".
function _isUserinfoByte(c) { return _isUnreserved(c) || _isSubDelim(c) || c === 58; }
// A path/query/fragment byte: unreserved / sub-delim / a non-bracket gen-delim (":" "/" "?" "#" "@").
// "%" is handled separately (it must open a "%HEXHEX" triplet); the IP-literal brackets "[" "]" are
// excluded here because they are authority syntax -- a bracketed IPv6 host is validated in
// _validUriAuthority (RFC 3986 sec. 3.2.2), never in the path.
function _isUriByte(c) {
  return _isUnreserved(c) || _isSubDelim(c) || c === 58 || c === 47 || c === 63 || c === 35 || c === 64;
}

// An RFC 5322 sec. 3.2.3 "atext" byte: ALPHA / DIGIT and a fixed set of specials, used for an unquoted
// email local part. "." is deliberately excluded so the dot-atom structure is enforced by the scan.
function _isAtextByte(c) {
  if (_isAlphaCode(c) || _isDigitCode(c)) return true;
  switch (c) {
    case 33: case 35: case 36: case 37: case 38: case 39:         // ! # $ % & '
    case 42: case 43: case 45: case 47: case 61: case 63:         // * + - / = ?
    case 94: case 95: case 96: case 123: case 124: case 125: case 126:   // ^ _ ` { | } ~
      return true;
    default: return false;
  }
}

// IPv4 SHAPE: one or more digit groups joined by single dots (only digits and dots, no leading/trailing/
// doubled dot, at least one dot). This is the "looks like an address" test, not a valid-address test --
// packIpLiteral decides validity; a shape match that is not a valid address is refused as ambiguous.
function _looksLikeIPv4Shape(s) {
  var n = s.length, i, c, sawDot = false, atomEmpty = true;
  if (n === 0) return false;
  for (i = 0; i < n; i += 1) {
    c = _charCodeAt(s, i);
    if (c === 46) { if (atomEmpty) return false; sawDot = true; atomEmpty = true; }   // "."
    else if (_isDigitCode(c)) { atomEmpty = false; }
    else return false;
  }
  return sawDot && !atomEmpty;
}

// Every byte in [from,to) is an allowed component byte (per `byteOk`) or opens a "%HEXHEX" triplet.
function _componentBytesOk(s, from, to, byteOk) {
  var i = from, c;
  while (i < to) {
    c = _charCodeAt(s, i);
    if (c === 37) {                                                                    // "%" -> %HEXHEX
      if (i + 2 >= to || !_isHexCode(_charCodeAt(s, i + 1)) || !_isHexCode(_charCodeAt(s, i + 2))) return false;
      i += 3;
    } else if (byteOk(c)) { i += 1; }
    else return false;
  }
  return true;
}

// The URI host in [from,to): RFC 5280 sec. 4.2.1.6 requires a URI SAN authority to carry a fully-qualified
// domain name or IP host, stricter than an RFC 3986 reg-name. So the host is either a valid IPv4 literal,
// or an FQDN of strict-LDH labels (the email-domain grammar: no underscore, no hyphen at a label edge) with
// at least one dot -- a single-label host such as "localhost" is not fully qualified and uses the object
// form, matching the email domain. An IPv4-SHAPED host that is not a valid address is refused as ambiguous
// (the same rule the top-level classifier uses). An IPv6-literal host is written in "[" "]" and validated
// by _validUriIp6Host from _validUriAuthority, never reaching this unbracketed-host check.
function _validUriHost(s, from, to) {
  if (to <= from) return false;                                                        // empty host
  var host = _sliceStr(s, from, to), len = host.length;
  if (_looksLikeIPv4Shape(host)) return _packIpLiteral(host) !== null;                  // IPv4 (first-match-wins)
  var end = _charCodeAt(host, len - 1) === 46 ? len - 1 : len;                          // ignore an absolute-root "."
  if (end > 253) return false;                                                         // RFC 1035 name length (root dot excluded)
  var firstDot = _stringIndexOf(host, ".", 0);
  if (firstDot === -1 || firstDot >= end) return false;                                // multi-label FQDN ("localhost" is not)
  return _labelsValid(host, 0, len, _isHostLabelRange, true);                           // strict-LDH FQDN, root "." allowed
}

// A bracketed IPv6-literal URI host (RFC 3986 sec. 3.2.2): the bytes between "[" and "]" must be a valid
// IPv6 address (16 packed octets), never an IPv4 literal (which uses the unbracketed IPv4address form). The
// bracket is the ONLY way to write an IPv6 host in a URI, and an IPv6 host is a valid iPAddress per RFC 5280
// sec. 4.2.1.6, so the shorthand accepts it rather than forcing the object form.
function _validUriIp6Host(s, from, to) {
  if (to <= from) return false;                                                        // empty "[ ]"
  var packed = _packIpLiteral(_sliceStr(s, from, to));
  return packed !== null && intrinsic.sizeOf(packed) === 16;                            // IPv6 literal only (16 octets)
}

// The authority in [from,to) is "[ userinfo "@" ] host [ ":" port ]" (RFC 3986 sec. 3.2): at most one "@"
// (userinfo and reg-name each exclude it), a host that is an RFC 5280 FQDN or IPv4 (_validUriHost) or a
// bracketed IPv6 literal (_validUriIp6Host), and an all-digit -- possibly empty -- port after the host's
// ":". A bracketed host is taken as ONE unit before the port, so a ":" inside the IPv6 literal is not read
// as the port separator. The userinfo bytes are validated against the RFC 3986 userinfo class.
function _validUriAuthority(s, from, to) {
  var i, c, at = -1;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    if (c === 64) { if (at !== -1) return false; at = i; }                             // "@" -- at most one
  }
  var hostStart = at === -1 ? from : at + 1;
  if (at !== -1 && !_componentBytesOk(s, from, at, _isUserinfoByte)) return false;      // userinfo
  if (hostStart < to && _charCodeAt(s, hostStart) === 91) {                             // "[" -> bracketed IPv6 host
    var close = -1;
    for (i = hostStart + 1; i < to; i += 1) { if (_charCodeAt(s, i) === 93) { close = i; break; } }   // "]"
    if (close === -1) return false;                                                    // unterminated "["
    if (!_validUriIp6Host(s, hostStart + 1, close)) return false;                       // IPv6 literal in "[ ]"
    var after = close + 1;
    if (after === to) return true;                                                     // "[ ipv6 ]" with no port
    if (_charCodeAt(s, after) !== 58) return false;                                    // only a ":" port may follow "]"
    for (i = after + 1; i < to; i += 1) { if (!_isDigitCode(_charCodeAt(s, i))) return false; }   // port = *DIGIT
    return true;
  }
  var colon = -1;
  for (i = hostStart; i < to; i += 1) { if (_charCodeAt(s, i) === 58) { colon = i; break; } }   // ":" -> port
  var hostEnd = colon === -1 ? to : colon;
  if (!_validUriHost(s, hostStart, hostEnd)) return false;                              // FQDN or IPv4 host
  if (colon !== -1) {
    for (i = colon + 1; i < to; i += 1) { if (!_isDigitCode(_charCodeAt(s, i))) return false; }   // port = *DIGIT
  }
  return true;
}

// scheme "://" authority [ path ] [ "?" query ] [ "#" fragment ], parsed by RFC 3986 component. The
// authority is validated by _validUriAuthority; the remainder is path/query/fragment bytes with at most
// one "#" (its single fragment delimiter). A structurally malformed URL is refused; the object form is
// the escape for one the shorthand does not accept.
function _looksLikeUri(s) {
  var n = s.length, i, c;
  if (n === 0 || !_isAlphaCode(_charCodeAt(s, 0))) return false;                       // scheme starts ALPHA
  i = 1;
  while (i < n) {
    c = _charCodeAt(s, i);
    if (_isAlphaCode(c) || _isDigitCode(c) || c === 43 || c === 45 || c === 46) i += 1;   // + - . in scheme
    else break;
  }
  if (i + 3 > n || _charCodeAt(s, i) !== 58 || _charCodeAt(s, i + 1) !== 47 || _charCodeAt(s, i + 2) !== 47) return false;
  i += 3;
  var authStart = i, authEnd = n;
  for (; i < n; i += 1) { c = _charCodeAt(s, i); if (c === 47 || c === 63 || c === 35) { authEnd = i; break; } }
  if (authEnd === authStart) return false;                                             // empty authority
  if (!_validUriAuthority(s, authStart, authEnd)) return false;
  var sawHash = false;                                                                 // path / query / fragment
  i = authEnd;
  while (i < n) {
    c = _charCodeAt(s, i);
    if (c === 37) {                                                                    // "%" -> %HEXHEX
      if (i + 2 >= n || !_isHexCode(_charCodeAt(s, i + 1)) || !_isHexCode(_charCodeAt(s, i + 2))) return false;
      i += 3;
      continue;
    }
    if (c === 35) { if (sawHash) return false; sawHash = true; }                        // one "#" fragment delimiter
    if (!_isUriByte(c)) return false;
    i += 1;
  }
  return true;
}

// A single dNSName label over [from,to): 1-63 bytes, LDH plus a LEADING or EMBEDDED underscore, no hyphen
// at either edge, and no underscore at the trailing edge. The underscore tolerance is deliberate and
// leading/embedded only: the real forms are _acme-challenge, _dmarc, _25._tcp (a label-initial "_"); a
// label ending in "_" has no such use. An email DOMAIN is stricter still -- see _isHostLabelRange.
function _isDnsLabelRange(s, from, to) {
  var len = to - from, i, c;
  if (len < 1 || len > 63) return false;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    if (_isAlphaCode(c) || _isDigitCode(c)) continue;                                  // A-Z a-z 0-9 anywhere
    if (i === to - 1) return false;                                                    // last byte must be alnum
    if (c === 95) continue;                                                            // "_" leading or embedded
    if (c === 45 && i !== from) continue;                                              // "-" embedded (not leading)
    return false;
  }
  return true;
}

// A single RFC 5321 sec. 2.3.5 hostname label over [from,to): the strict letter-digit-hyphen grammar with
// no hyphen at either edge and NO underscore. This is the email-domain label rule (a mail domain is a real
// hostname), stricter than the underscore-tolerant dNSName label above.
function _isHostLabelRange(s, from, to) {
  var len = to - from, i, c, edge;
  if (len < 1 || len > 63) return false;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    edge = (i === from || i === to - 1);
    if (_isAlphaCode(c) || _isDigitCode(c)) continue;                                  // A-Z a-z 0-9
    if (c === 45 && !edge) continue;                                                   // "-" not at an edge
    return false;
  }
  return true;
}

// Every dot-separated label in [from,to) satisfies `labelFn`. Scans with indexOf; no split allocation. When
// `allowRootDot` is set, a single trailing "." (the absolute-FQDN root) is stripped before validating, so
// "example.com." checks as "example.com"; an interior empty label (a doubled or leading dot) still fails.
function _labelsValid(s, from, to, labelFn, allowRootDot) {
  if (allowRootDot && to - from >= 1 && _charCodeAt(s, to - 1) === 46) to -= 1;         // an absolute-root "."
  if (to <= from) return false;                                                        // nothing (a lone ".")
  var start = from, dot;
  for (;;) {
    dot = _stringIndexOf(s, ".", start);
    var end = (dot === -1 || dot >= to) ? to : dot;
    if (!labelFn(s, start, end)) return false;
    if (end === to) return true;
    start = end + 1;
  }
}

// A dNSName: at most 253 bytes, an optional single leading "*." wildcard, then dot-separated dNSName labels
// (underscore-tolerant), with an optional trailing absolute-root ".".
function _looksLikeDnsName(s) {
  var n = s.length, start = 0;
  if (n < 1) return false;
  var end = _charCodeAt(s, n - 1) === 46 ? n - 1 : n;                                   // exclude an absolute-root "."
  if (end < 1 || end > 253) return false;                                              // RFC 1035 name length (root dot excluded)
  if (end >= 2 && _charCodeAt(s, 0) === 42 && _charCodeAt(s, 1) === 46) start = 2;      // "*."
  if (start >= end) return false;
  return _labelsValid(s, start, n, _isDnsLabelRange, true);
}

// An rfc822Name: an unquoted RFC 5321 dot-atom local part (atext runs joined by single dots), one "@",
// and a dotted hostname domain (at least one dot -- an FQDN, no wildcard, strict LDH labels, no underscore).
function _looksLikeEmail(s) {
  if (s.length > 254) return false;                                                    // the whole mailbox <= 254 octets (RFC 5321 sec. 4.5.3.1.3)
  var at = _stringIndexOf(s, "@", 0);
  if (at < 1 || at > 64 || _stringLastIndexOf(s, "@") !== at) return false;            // one "@", a 1-64 octet local part (RFC 5321 sec. 4.5.3.1.1)
  var i, c, atomEmpty = true;
  for (i = 0; i < at; i += 1) {                                                        // local part = dot-atom
    c = _charCodeAt(s, i);
    if (c === 46) { if (atomEmpty) return false; atomEmpty = true; }                   // no leading/doubled dot
    else if (_isAtextByte(c)) { atomEmpty = false; }
    else return false;
  }
  if (atomEmpty) return false;                                                         // no trailing dot / empty
  var dStart = at + 1, dLen = s.length - dStart;
  if (dLen < 1 || dLen > 253 || _stringIndexOf(s, ".", dStart) === -1) return false;   // domain must be dotted
  return _labelsValid(s, dStart, s.length, _isHostLabelRange, false);                   // strict LDH, no underscore or root dot
}

// A well-formed dotted-decimal OID SHAPE (no regex, by the same character scan the name forms use): a first
// arc 0-2, then one or more arcs each introduced by "." and written without a leading zero ("0" alone, or a
// non-zero digit followed by more digits). Used to accept a raw OID string (an unregistered KeyPurposeId /
// policy OID) where a registered name would go; the encoder (encodeOidContent) remains the authoritative
// validator of the arc-value bounds.
function _isDottedOid(s) {
  var n = s.length, i, c, d0, arcs = 0;
  if (n < 3) return false;                              // shortest is "X.Y"
  c = _charCodeAt(s, 0);
  if (c < 48 || c > 50) return false;                  // first arc is a single digit 0-2
  i = 1;
  while (i < n) {
    if (_charCodeAt(s, i) !== 46) return false;         // every following arc is introduced by "."
    i += 1;
    if (i >= n) return false;                           // a trailing "." has no arc
    d0 = _charCodeAt(s, i);
    if (d0 === 48) { i += 1; }                           // "0" is a complete arc; a leading zero is refused
    else if (d0 >= 49 && d0 <= 57) { i += 1; while (i < n && _isDigitCode(_charCodeAt(s, i))) i += 1; }
    else { return false; }                              // an arc must start with a digit
    arcs += 1;
  }
  return arcs >= 1;
}

var b = asn1.build;

// KeyUsage named-bit positions (RFC 5280 sec. 4.2.1.3); contentCommitment is the RFC 5280 rename of the
// X.509 nonRepudiation bit (1).
var KU_BIT = {
  digitalSignature: 0, nonRepudiation: 1, contentCommitment: 1, keyEncipherment: 2,
  dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8,
};

// makeBuilder(ctx) -> the bound producing primitives. ctx = { ErrorClass, prefix, O, NS, NAME_SCHEMA,
// SPKI_SCHEMA, EXT_DECODERS }. `E(kind, msg, cause)` builds a `<prefix>/<kind>` typed error.
function makeBuilder(ctx) {
  var ErrorClass = ctx.ErrorClass, O = ctx.O, NS = ctx.NS;
  var NAME_SCHEMA = ctx.NAME_SCHEMA, SPKI_SCHEMA = ctx.SPKI_SCHEMA;
  function E(kind, message, cause) { return new ErrorClass(ctx.prefix + "/" + kind, message, cause); }
  function code(kind) { return ctx.prefix + "/" + kind; }
  // A full-code error factory (guard.* helpers invoke E as `E(fullCode, msg)`, not `E(kind, msg)`).
  function rawErr(fullCode, message, cause) { return new ErrorClass(fullCode, message, cause); }

  // RFC 5280 sec. 4.1.2.5 -- UTCTime for 1950..2049, GeneralizedTime otherwise (UTCTime's two-digit year
  // only represents that window). The shared cutover so a certificate / CRMF / any validity encoder cannot
  // drift on the boundary. `which` labels the instant in a validation error.
  function timeDer(date, which) {
    guard.time.assertValid(date, rawErr, code("bad-input"), which);
    var y = date.getUTCFullYear();
    return (y >= 1950 && y <= 2049) ? b.utcTime(date) : b.generalizedTime(date);
  }

  // ---- distinguished name encoding (RFC 5280 sec. 4.1.2.4) ----
  // countryName is a PrintableString SIZE(2), emailAddress an IA5String; every other new-name attribute
  // is a UTF8String (Teletex/BMP/Universal are backward-compat only and never emitted).
  function atvString(attrName, value) {
    if (attrName === "countryName") {
      if (String(value).length !== 2) throw E("bad-name", "countryName must be a two-letter ISO 3166 code (PrintableString SIZE(2))");
      return b.printable(value);
    }
    if (attrName === "emailAddress") return b.ia5(value);
    return b.utf8(value);
  }
  function encodeAtv(attrName, value) {
    if (value == null || value === "") throw E("bad-name", "the " + attrName + " attribute value must be a non-empty string");
    // For an unrecognized name oid.byName returns undefined and does not throw, so reject explicitly.
    var typeOid = O(attrName);
    if (typeOid == null) throw E("bad-name", "unknown distinguished-name attribute " + JSON.stringify(attrName));
    var valueTlv;
    try { valueTlv = atvString(attrName, value); }
    catch (e) { if (e instanceof ErrorClass) throw e; throw E("bad-name", "the " + attrName + " value has characters invalid for its string type", e); }
    return b.sequence([b.oid(typeOid), valueTlv]);
  }
  function encodeRdn(rdnSpec) {
    if (!rdnSpec || typeof rdnSpec !== "object" || Buffer.isBuffer(rdnSpec)) throw E("bad-name", "each RDN must be an object of { attributeName: value }");
    var keys = Object.keys(rdnSpec);
    if (!keys.length) throw E("bad-name", "an RDN must carry at least one attribute");
    return b.set(keys.map(function (k) { return encodeAtv(k, rdnSpec[k]); }));
  }
  // A DN spec -> RDNSequence DER. A string is shorthand for a single commonName RDN; a Buffer is raw
  // pre-encoded Name DER (validated through the parser). An empty array yields an empty RDNSequence.
  function encodeName(spec) {
    if (guard.bytes.isByteSource(spec)) { var _nd = guard.bytes.snapshotSource(spec, ErrorClass, ctx.prefix + "/bad-name", "raw Name DER"); assertValidNameDer(_nd); return _nd; }
    if (typeof spec === "string") spec = [{ commonName: spec }];
    if (!_isArray(spec)) throw E("bad-name", "a name must be a string, an array of RDNs, or raw Name DER");
    return b.sequence(spec.map(encodeRdn));
  }
  // Full validation of a raw Name DER: walk it through the exact RDNSequence parser the decoder uses.
  function assertValidNameDer(der) {
    var node;
    try { node = asn1.decode(der); }
    catch (e) { throw E("bad-name", "the raw Name DER is not valid DER", e); }
    try { schema.walk(NAME_SCHEMA, node, NS); }
    catch (e) {
      if (e instanceof ErrorClass || (e && e.name === "Asn1Error")) throw e;
      throw E("bad-name", "the raw Name DER is not a well-formed distinguished name", e);
    }
  }
  function isEmptyName(nameDer) { return asn1.decode(nameDer).children.length === 0; }

  // ---- GeneralName encoding (RFC 5280 sec. 4.2.1.6) ----
  function ia5Content(s) {
    // Captured String / charCodeAt / bufferFrom: this converts a GeneralName value (a classified bare
    // string or an object-form value) to the emitted IA5String bytes, so co-resident code replacing any of
    // them after load could otherwise change which host the certificate names from the one that was checked.
    s = _String(s);
    for (var i = 0; i < s.length; i++) {
      if (_charCodeAt(s, i) > 0x7F) throw E("bad-input", "value requires 7-bit ASCII (IA5String): " + _stringify(s));
    }
    return _bufferFrom(s, "latin1");
  }
  // A bare-string GeneralName shorthand: classify a string into exactly one form, FAIL-CLOSED. RFC 5280
  // sec. 4.2.1.6 GeneralName is a CHOICE, so an input that does not UNAMBIGUOUSLY match one form throws
  // rather than being guessed -- the explicit object form ({ dNSName: s } etc.) is always the escape. The
  // per-form syntax is decided by the character-scan predicates above (no regex). Precedence resolves the
  // overlaps of the later tests: an IP literal is also LDH-with-dots (so it is tested first), and a
  // scheme://authority URL can carry userinfo that reads like an email (so URI is tested before rfc822Name).
  // Form detection only -- IA5String (7-bit) enforcement stays at ia5Content, so a non-ASCII value still
  // throws at encode.
  function _classifyBareGeneralName(s) {
    if (_packIpLiteral(s) !== null) return { iPAddress: s };
    // A string of only digit groups separated by dots is an IPv4 ATTEMPT; if packIpLiteral rejected it,
    // it is a MALFORMED address, not a dNSName. It reads two ways (an invalid IP and a syntactically
    // valid all-numeric name), so it is ambiguous and refused rather than silently encoded as a name the
    // caller did not intend -- a genuine all-numeric name uses the explicit { dNSName: ... } form.
    if (_looksLikeIPv4Shape(s)) {
      throw E("bad-input", "the bare GeneralName string " + _stringify(s) + " looks like an IPv4 address but is not a valid one; pass { iPAddress: ... } for an address or { dNSName: ... } for a name");
    }
    if (_looksLikeUri(s)) return { uniformResourceIdentifier: s };
    if (_looksLikeEmail(s)) return { rfc822Name: s };
    if (_looksLikeDnsName(s)) return { dNSName: s };
    var _qs = _stringify(s);
    throw E("bad-input", "cannot classify the bare GeneralName string " + _qs +
      " as a dNSName, rfc822Name, iPAddress, or URI; pass an explicit form object, e.g. { dNSName: " + _qs + " }");
  }
  function encodeGeneralName(entry) {
    // A bare non-empty string is shorthand -- normalized to its single-key object form, fail-closed,
    // before the object checks below; an empty string is refused here (never classified).
    if (typeof entry === "string") {
      if (entry === "") throw E("bad-input", "an empty GeneralName value is not permitted (RFC 5280 sec. 4.2.1.6)");
      entry = _classifyBareGeneralName(entry);
    }
    if (!entry || typeof entry !== "object" || _isBufferChk(entry)) throw E("bad-input", "a GeneralName must be an object with exactly one name form");
    // Captured Object.keys / property read: this reads which form and value the certificate will emit for a
    // GeneralName (a freshly classified bare string, or a caller object), so a replaced Object.keys must not
    // be able to relabel the classified result into a different, attacker-chosen form after validation.
    var keys = _objectKeys(entry);
    if (keys.length !== 1) throw E("bad-input", "a GeneralName entry must have exactly one form, got " + keys.length);
    var k = keys[0], v = entry[k];
    if (v == null || v === "") throw E("bad-input", "an empty GeneralName value is not permitted (RFC 5280 sec. 4.2.1.6)");
    switch (k) {
      case "rfc822Name": return b.contextPrimitive(1, ia5Content(v));
      case "dNSName": return b.contextPrimitive(2, ia5Content(v));
      case "uniformResourceIdentifier": case "uri": return b.contextPrimitive(6, ia5Content(v));
      case "iPAddress":
        // Accept a dotted-quad / colon-hex string (packed to its 4/16 network octets) as well as a
        // pre-packed Buffer, so an iPAddress SAN reads like dNSName/URI and the caller does not pack
        // octets by hand (a GeneralName iPAddress is a bare host address, RFC 5280 sec. 4.2.1.6).
        var ipBuf = v;
        if (typeof v === "string") {
          ipBuf = _packIpLiteral(v);
          if (ipBuf === null) throw E("bad-input", "iPAddress string is not a valid IPv4 or IPv6 literal: " + _stringify(v));
        }
        if (!_isBufferChk(ipBuf) || (ipBuf.length !== 4 && ipBuf.length !== 16)) throw E("bad-input", "iPAddress must be a 4- or 16-octet Buffer or an IPv4/IPv6 string");
        return b.contextPrimitive(7, ipBuf);
      case "directoryName": return b.explicit(4, encodeName(v));   // Name is a CHOICE -> the context tag is EXPLICIT
      case "otherName":
        // otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }, tagged
        // [0] IMPLICIT (RFC 5280 sec. 4.2.1.6). The value is EXPLICIT because ANY carries no tag
        // of its own, so the wrapper is what makes the encoding unambiguous -- the same shape the
        // decoder requires, and without it an SmtpUTF8Mailbox (RFC 8398 sec. 3) could be read but
        // never written.
        if (typeof v !== "object" || Buffer.isBuffer(v)) throw E("bad-input", "otherName must be an object { typeId, value }");
        if (typeof v.typeId !== "string" || !v.typeId) throw E("bad-input", "otherName requires a `typeId` OID string");
        if (!Buffer.isBuffer(v.value) || v.value.length === 0) {
          throw E("bad-input", "otherName requires a `value` Buffer holding one DER element");
        }
        // The value is spliced in raw and this verb SIGNS the result, so it is strictly
        // validated rather than taken on the caller's word. Framing alone is not DER: a
        // BOOLEAN whose content octet is 0x01, a NumericString holding "@", or a SET in no
        // canonical order all frame cleanly and would ship inside a [0] EXPLICIT wrapper
        // under a real signature. guard.der.tlv is the one place that rule lives.
        guard.der.tlv(v.value, E, "bad-input", "otherName `value`");
        // [0] IMPLICIT on a SEQUENCE replaces the SEQUENCE tag, so the content is the two
        // members concatenated -- build.contextConstructed takes content bytes, not elements.
        // The type-id encode is wrapped so a malformed OID reports in the CALLER's namespace
        // (x509/bad-input, csr/bad-input, ...) like every other raw-OID path here, rather than
        // surfacing the codec's own oid/* code from a shared builder the caller never named.
        var typeIdDer;
        try { typeIdDer = b.oid(v.typeId); }
        catch (e) { throw E("bad-input", "invalid otherName type-id OID " + JSON.stringify(v.typeId) + " (violates the X.660 arc bounds)", e); }
        return b.contextConstructed(0, Buffer.concat([typeIdDer, b.explicit(0, v.value)]));
      default: throw E("bad-input", "unsupported GeneralName form " + JSON.stringify(k) + " (supported: rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, directoryName, otherName)");
    }
  }

  // ---- extension-value encoders (the inverse of certExtensionDecoders) ----
  function extKeyUsage(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "keyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
    var positions = names.map(function (n) {
      var pos = KU_BIT[n];
      if (pos == null) throw E("bad-input", "unknown keyUsage bit " + JSON.stringify(n));
      return pos;
    });
    return b.namedBitString(positions);
  }
  // Resolve an OID token to a dotted-decimal OID: a registered name via the registry, OR a raw dotted-OID
  // string accepted directly (an unregistered KeyPurposeId / policy OID for BIMI, document-signing or a
  // vendor purpose is a common valid input). A token that is neither fails closed (never silently accept a
  // typo'd name); a dotted string that passes the shape check is still arc-validated by b.oid's encoder.
  function _resolveOid(n, label) {
    var dotted = O(n);
    if (dotted != null) return dotted;
    if (typeof n === "string" && _isDottedOid(n)) {
      // The shape scan fixes the general form; b.oid's encoder is the authoritative X.660 arc-bounds check
      // (a first arc 0/1 caps the second at 39; an arc must DER-encode). A failure there is this producer's
      // bad-input, not a leaked oid/* code, so every shared-builder consumer keeps its own error contract.
      try { b.oid(n); }
      catch (e) { throw E("bad-input", "invalid " + label + " OID " + JSON.stringify(n) + " (violates the X.660 arc bounds)", e); }
      return n;
    }
    throw E("bad-input", "unknown " + label + " " + JSON.stringify(n) + " (expected a registered name or a dotted-decimal OID)");
  }
  function extExtKeyUsage(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "extendedKeyUsage must list at least one KeyPurposeId");
    return b.sequence(names.map(function (n) { return b.oid(_resolveOid(n, "extendedKeyUsage purpose")); }));
  }
  function validateBcSpec(bc) {
    if (bc.cA != null && typeof bc.cA !== "boolean") throw E("bad-input", "basicConstraints cA must be a boolean");
    if (bc.critical != null && typeof bc.critical !== "boolean") throw E("bad-input", "basicConstraints critical must be a boolean");
    if (bc.pathLen != null) pathLen(bc.pathLen);
    guard.identifier.assertKnownKeys(bc, BC_KEYS, E, "bad-input", "unknown basicConstraints field ");
  }
  function extBasicConstraints(spec) {
    var children = [];
    if (spec.cA === true) children.push(b.boolean(true));   // cA=FALSE omitted (DER DEFAULT)
    if (spec.pathLen != null) children.push(b.integer(pathLen(spec.pathLen)));
    return b.sequence(children);
  }
  function pathLen(v) {
    if (typeof v !== "number" || !isFinite(v) || v < 0 || (v | 0) !== v) throw E("bad-input", "basicConstraints pathLenConstraint must be a non-negative integer");
    return BigInt(v);
  }
  function extSki(keyid) { return b.octetString(keyid); }
  function extAki(keyid) { return b.sequence([b.contextPrimitive(0, keyid)]); }   // keyIdentifier [0] IMPLICIT OCTET STRING
  // GeneralNames ::= SEQUENCE SIZE(1..MAX) OF GeneralName. With no implicitTag it is a universal SEQUENCE
  // (subjectAltName / issuerAltName / IssuerSerial.issuer). With an implicitTag it is a context-constructed
  // [n] whose tag REPLACES the SEQUENCE tag (RFC 5755 IMPLICIT TAGS: Holder.entityName [1],
  // RoleSyntax.roleAuthority [0], IetfAttrSyntax.policyAuthority [0]); the [n] node's children ARE the
  // GeneralName members, no inner SEQUENCE wrapper.
  function encodeGeneralNames(entries, implicitTag) {
    if (!_isArray(entries) || !entries.length) throw E("bad-input", "a GeneralNames must carry at least one GeneralName");
    var members = entries.map(encodeGeneralName);
    if (implicitTag == null) return b.sequence(members);
    return b.contextConstructed(implicitTag, Buffer.concat(members));
  }
  function extSan(entries) { return encodeGeneralNames(entries); }
  function extCertPolicies(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "certificatePolicies must list at least one policy OID");
    var seen = {};
    return b.sequence(names.map(function (n) {
      var pOid = _resolveOid(n, "certificate policy");
      if (seen[pOid]) throw E("bad-input", "duplicate certificate policy " + JSON.stringify(n) + " (RFC 5280 sec. 4.2.1.4)");
      seen[pOid] = true;
      return b.sequence([b.oid(pOid)]);
    }));
  }
  // Wrap a value in Extension ::= SEQUENCE { extnID, critical?, extnValue }; a FALSE critical is omitted.
  function ext(oidStr, critical, valueDer) {
    var children = [b.oid(oidStr)];
    if (critical) children.push(b.boolean(true));
    children.push(b.octetString(valueDer));
    return b.sequence(children);
  }

  // The SHA-1 subjectKeyIdentifier (RFC 5280 sec. 4.2.1.2 method 1): SHA-1 of the subjectPublicKey BIT
  // STRING content, taken past the unused-bits octet. Hashing the whole SPKI or the BIT STRING TLV
  // gives a different, wrong identifier.
  function spkiKeyId(spkiDer) {
    var keyBytes = asn1.read.bitString(asn1.decode(spkiDer).children[1]).bytes;
    // RFC 5280 sec. 4.2.1.2 method 1 DEFINES the subjectKeyIdentifier as the SHA-1 of the
    // subjectPublicKey; this is a key identifier, not a signature or a collision-resistance use,
    // and the algorithm is fixed by the standard.
    // nosemgrep: pki-weak-hash-md5-sha1
    return nodeCrypto.createHash("sha1").update(keyBytes).digest();
  }
  function skiKeyId(val, spkiDer) {
    if (guard.bytes.isByteSource(val)) return guard.bytes.snapshotSource(val, ErrorClass, ctx.prefix + "/bad-input", "subjectKeyIdentifier");
    if (val === true) return spkiKeyId(spkiDer);
    throw E("bad-input", "subjectKeyIdentifier must be true (auto-derive) or a BufferSource key id");
  }

  // ---- embedded-input validators ----
  function reqDer(v, what) {
    if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, ErrorClass, ctx.prefix + "/bad-input", what);
    throw E("bad-input", what + " must be a DER Buffer");
  }
  // Full validation of an embedded SubjectPublicKeyInfo, walked through the parser the decoder uses.
  function assertValidSpki(spkiDer, what) {
    var node;
    try { node = asn1.decode(spkiDer); }
    catch (e) { throw E("bad-input", what + " is not valid DER", e); }
    try { schema.walk(SPKI_SCHEMA, node, NS); }
    catch (e) {
      if (e instanceof ErrorClass || (e && e.name === "Asn1Error")) throw e;
      throw E("bad-input", what + " is not a well-formed SubjectPublicKeyInfo", e);
    }
  }
  // A pre-encoded Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING };
  // an explicit critical=FALSE is non-canonical (DER DEFAULT) and rejected.
  function assertValidExtension(der, idx) {
    var n;
    try { n = asn1.decode(der); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] is not valid DER", e); }
    if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length < 2 || n.children.length > 3) throw E("bad-input", "pre-encoded extension [" + idx + "] must be an Extension SEQUENCE { extnID, critical?, extnValue }");
    try { asn1.read.oid(n.children[0]); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] extnID is not an OBJECT IDENTIFIER", e); }
    if (n.children.length === 3) {
      var crit;
      try { crit = asn1.read.boolean(n.children[1]); }
      catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] critical must be a BOOLEAN", e); }
      if (crit !== true) throw E("bad-input", "pre-encoded extension [" + idx + "] critical=FALSE must be omitted (DER DEFAULT)");
    }
    var last = n.children[n.children.length - 1];
    if (last.tagNumber !== asn1.TAGS.OCTET_STRING || last.tagClass !== "universal") throw E("bad-input", "pre-encoded extension [" + idx + "] extnValue must be an OCTET STRING");
  }
  // The requested v3 Extensions (a bare SEQUENCE OF Extension) from an object of the recognized keys, or
  // an array of pre-encoded Extension DER (shape- + recognized-value-validated). Shared by every enrollment
  // request that carries requested extensions (a PKCS#10 extensionRequest attribute, a CRMF CertTemplate
  // extensions [9]); a request REQUESTS extensions, so there are no CA cross-field gates. `spki` feeds the
  // subjectKeyIdentifier auto-derive.
  var BC_KEYS = { cA: 1, pathLen: 1, critical: 1 };
  var REQ_EXT_KEYS = {
    subjectAltName: 1, keyUsage: 1, keyUsageCritical: 1, extendedKeyUsage: 1, extendedKeyUsageCritical: 1,
    basicConstraints: 1, certificatePolicies: 1, certificatePoliciesCritical: 1, subjectKeyIdentifier: 1,
  };
  function requestedExtensions(extSpec, spki) {
    var EXT_DECODERS = ctx.EXT_DECODERS;
    if (_isArray(extSpec)) {
      if (!extSpec.length) throw E("bad-input", "the requested extensions list must carry at least one extension");
      var seen = {};
      return b.sequence(extSpec.map(function (e, i) {
        var der = reqDer(e, "extension");
        assertValidExtension(der, i);
        var n = asn1.decode(der);
        var extnId = asn1.read.oid(n.children[0]);
        if (seen[extnId]) throw E("bad-input", "duplicate requested extension " + extnId + " (RFC 5280 sec. 4.2)");
        seen[extnId] = true;
        var dec = EXT_DECODERS && EXT_DECODERS[extnId];
        if (dec) {
          try { dec(asn1.read.octetString(n.children[n.children.length - 1])); }
          catch (err) { if (err instanceof ErrorClass) throw err; throw E("bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", err); }
        }
        return b.raw(der);
      }));
    }
    if (!extSpec || typeof extSpec !== "object") throw E("bad-input", "requested extensions must be an object or an array of pre-encoded Extension DER");
    guard.identifier.assertKnownKeys(extSpec, REQ_EXT_KEYS, E, "bad-input", function (k) {
      return "unknown requested extension " + JSON.stringify(k) + "; pass a pre-encoded Extension DER via the array form for a custom extension";
    });
    var out = [];
    if (extSpec.subjectKeyIdentifier != null) {
      // Auto-deriving the SKI (subjectKeyIdentifier: true) hashes the subject public key, so it needs one;
      // reject the request when no public key is available (supply a Buffer key id instead).
      if (extSpec.subjectKeyIdentifier === true && spki == null) throw E("bad-input", "subjectKeyIdentifier auto-derive (true) requires the public key -- supply a Buffer key id, or include the public key");
      out.push(ext(O("subjectKeyIdentifier"), false, extSki(skiKeyId(extSpec.subjectKeyIdentifier, spki))));
    }
    if (extSpec.keyUsage != null) out.push(ext(O("keyUsage"), extSpec.keyUsageCritical !== false, extKeyUsage(extSpec.keyUsage)));
    if (extSpec.extendedKeyUsage != null) out.push(ext(O("extKeyUsage"), !!extSpec.extendedKeyUsageCritical, extExtKeyUsage(extSpec.extendedKeyUsage)));
    if (extSpec.basicConstraints != null) { validateBcSpec(extSpec.basicConstraints); out.push(ext(O("basicConstraints"), extSpec.basicConstraints.critical !== false, extBasicConstraints(extSpec.basicConstraints))); }
    if (extSpec.subjectAltName != null) out.push(ext(O("subjectAltName"), false, extSan(extSpec.subjectAltName)));
    if (extSpec.certificatePolicies != null) out.push(ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, extCertPolicies(extSpec.certificatePolicies)));
    if (!out.length) throw E("bad-input", "the requested extensions object must request at least one extension");
    return b.sequence(out);
  }

  // A positive, non-zero INTEGER of at most 20 content octets (RFC 5280 sec. 4.1.2.2 / RFC 5755 sec.
  // 4.2.5 -- the identical serial rule for a certificate and an attribute certificate). A random 20-octet
  // positive serial is generated when none is supplied. Accepts a BigInt, a safe integer, a decimal /
  // 0x-hex string, or a raw magnitude Buffer.
  function serialInteger(serial) {
    var v;
    if (serial == null) {
      var rnd = nodeCrypto.randomBytes(20);
      rnd[0] &= 0x7f;                      // keep the top bit clear so the magnitude stays <= 20 octets and positive
      if (rnd[0] === 0) rnd[0] = 0x01;     // never all-zero leading -> non-zero and no redundant sign octet
      v = BigInt("0x" + rnd.toString("hex"));
    } else if (typeof serial === "bigint") { v = serial; }
    else if (typeof serial === "number") { if (!Number.isSafeInteger(serial)) throw E("bad-serial", "serialNumber number must be a safe integer (pass a BigInt, hex string, or Buffer for a value above 2^53-1)"); v = BigInt(serial); }
    else if (typeof serial === "string") { try { v = BigInt(serial); } catch (e) { throw E("bad-serial", "serialNumber string must be a decimal or 0x-hex integer", e); } }
    else if (guard.bytes.isByteSource(serial)) { var _sb = guard.bytes.source(serial, ErrorClass, ctx.prefix + "/bad-serial", "serialNumber"); v = _sb.length ? BigInt("0x" + _sb.toString("hex")) : 0n; }
    else { throw E("bad-serial", "serialNumber must be a BigInt, integer, hex string, or BufferSource"); }
    if (v <= 0n) throw E("bad-serial", "serialNumber must be a positive integer (RFC 5280 sec. 4.1.2.2)");
    var tlv = b.integer(v);
    if (asn1.decode(tlv).content.length > 20) throw E("bad-serial", "serialNumber must not exceed 20 octets (RFC 5280 sec. 4.1.2.2)");
    return tlv;
  }
  // Synthesize the parsed-cert shape resolveSignScheme reads (subjectPublicKeyInfo.algorithm) from a raw SPKI.
  function certLikeFromSpki(spkiDer) {
    var spki = asn1.decode(spkiDer);
    if (!spki.children || !spki.children.length) throw E("bad-input", "the signing key SPKI is not a SubjectPublicKeyInfo");
    var alg = spki.children[0];
    var keyOid;
    try { keyOid = asn1.read.oid(alg.children[0]); }
    catch (e) { throw E("bad-input", "the signing key SPKI algorithm is not an OID", e); }
    return { subjectPublicKeyInfo: { algorithm: { oid: keyOid, parameters: alg.children.length > 1 ? alg.children[1].bytes : undefined } } };
  }

  // Confirm the produced signature verifies under `spki`. This works for any key type (a PKCS#8
  // key, a WebCrypto CryptoKey, or any signer), where deriving-and-comparing the public key cannot
  // (a non-extractable CryptoKey has no exportable public half). This is the x509 chain self-check
  // AND the CSR proof of possession. Composite verifies both components. Returns a promise for
  // composite, sync-throws for classical.
  function assertSignatureVerifies(preimage, sig, spki, scheme) {
    if (scheme.composite) {
      return compositeSig.compositeVerify(spki, sig, preimage, scheme.composite, ErrorClass, code("unsupported-algorithm"), code("bad-input")).then(function (r) {
        if (!r.ok) throw E("bad-input", "the composite signing key does not correspond to the public key -- the signature would not verify");
      });
    }
    var pub;
    try { pub = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" }); }
    catch (e) { throw E("bad-input", "the public key could not be imported for the signature self-check", e); }
    var s = scheme.sign, ok;
    try {
      if (s.name === "ECDSA") ok = nodeCrypto.verify(scheme.digest, preimage, { key: pub, dsaEncoding: "der" }, sig);
      else if (s.name === "RSA-PSS") ok = nodeCrypto.verify(scheme.digest, preimage, { key: pub, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: s.saltLength }, sig);
      else if (s.name === "RSASSA-PKCS1-v1_5") ok = nodeCrypto.verify(scheme.digest, preimage, pub, sig);
      // allow:eddsa-verify-without-loworder-gate -- a self-check that OUR just-produced signature verifies
      // under the key the caller controls, not a security verify of an untrusted EdDSA signature, so the
      // low-order-point gate (a forged-signature defense) does not apply.
      else ok = nodeCrypto.verify(null, preimage, pub, sig);   // Ed25519 / Ed448 / ML-DSA / SLH-DSA
    } catch (e) { throw E("bad-input", "the signature self-check could not run against the public key", e); }
    if (!ok) throw E("bad-input", "the signing key does not correspond to the public key -- the signature would not verify");
  }

  // Do two SubjectPublicKeyInfo encodings name the same key? Bytes first, because that is the answer
  // almost always and it costs nothing. When they differ the question is still open, since one key has
  // more than one legal SPKI: an EC point may be carried compressed or uncompressed, so a P-256 key
  // written the compressed way is byte-unequal to the same key written the other. Comparing the DER
  // alone would refuse a proof of possession over a key the requester genuinely holds, while the
  // sibling arms of the same verb accept that template. The fallback asks the key layer, which
  // compares key material and still answers false for a different key, a different curve, or a
  // different algorithm. A key neither side can import is equal to nothing, so the refusal stands.
  function samePublicKey(spkiA, spkiB) {
    var a = _bufferFrom(spkiA), bb = _bufferFrom(spkiB);
    if (_bufferEquals(a, bb)) return true;
    var ka, kb;
    // allow:swallow-unverified an SPKI the key layer cannot import matches nothing, which is the
    // refusal the caller wants; the caller raises its own typed error on the false.
    try {
      ka = nodeCrypto.createPublicKey({ key: a, format: "der", type: "spki" });
      kb = nodeCrypto.createPublicKey({ key: bb, format: "der", type: "spki" });
    } catch (_e) { return false; }
    return _keyEquals(ka, kb) === true;
  }

  return {
    E: E, code: code, KU_BIT: KU_BIT,
    encodeName: encodeName, isEmptyName: isEmptyName, encodeGeneralName: encodeGeneralName,
    encodeGeneralNames: encodeGeneralNames, serialInteger: serialInteger, timeDer: timeDer,
    requestedExtensions: requestedExtensions,
    extKeyUsage: extKeyUsage, extExtKeyUsage: extExtKeyUsage, validateBcSpec: validateBcSpec,
    extBasicConstraints: extBasicConstraints, pathLen: pathLen, extSki: extSki, extAki: extAki,
    extSan: extSan, extCertPolicies: extCertPolicies, ext: ext,
    spkiKeyId: spkiKeyId, skiKeyId: skiKeyId,
    reqDer: reqDer, assertValidSpki: assertValidSpki, assertValidExtension: assertValidExtension,
    certLikeFromSpki: certLikeFromSpki, assertSignatureVerifies: assertSignatureVerifies,
    samePublicKey: samePublicKey,
  };
}

// The raw issuer / subject Name TLV of a parsed X.509 certificate (byte-identical). tbs field layout:
// [version?] serial(0) signature(1) issuer(2) validity(3) subject(4). Used where a producer must chain a
// name to an existing certificate exactly -- an issued certificate's issuer, a CMS SignerInfo issuer, an
// attribute certificate's issuerName / holder baseCertificateID.
function tbsNameField(cert, which) {
  var tbs = asn1.decode(cert.tbsBytes);
  var hasVersion = tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0;
  return tbs.children[(hasVersion ? 1 : 0) + (which === "subject" ? 4 : 2)].bytes;
}

// The serialNumber of a parsed X.509 certificate, read from the SIGNED bytes. Same tbs layout as
// above, and the same reason: where a producer binds an identity to an existing certificate, that
// identity is issuer AND serial together. Deriving one from the bytes and reading the other from
// the object lets the halves name different certificates, producing a Holder whose issuer is
// genuine and whose serial is whatever the caller wrote.
function tbsSerialNumber(cert) {
  var tbs = asn1.decode(cert.tbsBytes);
  var hasVersion = tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0;
  return asn1.read.integer(tbs.children[hasVersion ? 1 : 0]);
}

module.exports = { makeBuilder: makeBuilder, KU_BIT: KU_BIT, tbsNameField: tbsNameField, tbsSerialNumber: tbsSerialNumber };
