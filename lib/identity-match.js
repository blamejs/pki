// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.identity
 * @since  0.8.8
 * @spec   RFC 9525
 * @nav Path validation
 * @title Service identity (RFC 9525)
 *
 * @intro
 * Service identity: whether a certificate presents a name the client was trying to reach.
 * RFC 9525 calls the names the client builds reference identities and the names the
 * certificate carries presented identifiers, and the check is whether any of the first
 * matches any of the second.
 *
 * This is a separate answer from path validation, and RFC 9525 sec. 1.2 says so: it does not
 * supersede certificate validation, and an application needs both. `pki.path.validate` takes
 * `opts.identity` to run the two together and report each.
 *
 * @card
 * | Reference form | Reads | Compared against |
 * |---|---|---|
 * | `"www.example.com"` | DNS-ID | `dNSName` entries, label by label |
 * | `"192.0.2.1"`, `"2001:db8::1"`, a 4- or 16-octet BufferSource | IP-ID | `iPAddress` entries, octet for octet |
 * | `{ type: "srv", service: "_imap", value: "example.com" }` | SRV-ID | an `otherName` carrying an RFC 4985 SRVName |
 * | `{ type: "uri", scheme: "https", value: "www.example.com" }` | URI-ID | the scheme and host of a `uniformResourceIdentifier` |
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var constants = require("./constants");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");
var ip = require("./ip-utils");
var x509 = require("./schema-x509");

var IdentityError = frameworkError.IdentityError;
function E(code, message, cause) { return new IdentityError(code, message, cause); }

var NS = pkix.makeNS("identity", IdentityError, oid);
var OID_SAN = oid.byName("subjectAltName");
var OID_DNS_SRV = oid.byName("dnsSRV");
var SAN_DECODER = pkix.certExtensionDecoders(NS).byOid[OID_SAN];

var _append = guard.list.append;
var _lowerAscii = guard.name.lowerAscii;
var _stripTrailingDot = guard.name.stripTrailingDot;
var _hostLabels = guard.name.hostLabels;
var _isFqdnHost = guard.name.isFqdnHost;
var _uriParts = guard.name.uriParts;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _indexOf = intrinsic.uncurry(String.prototype.indexOf);
var _isArray = intrinsic.isArray;

var MATCH_OPTS = intrinsic.assign(intrinsic.create(null), { wildcards: 1 });
var REFERENCE_KEYS = intrinsic.assign(intrinsic.create(null), { type: 1, value: 1, service: 1, scheme: 1 });

var MAX_LABEL = 63;
var MAX_HOST = 253;

/** @internal Every character of a reference identity is printable ASCII. A byte above 0x7E cannot
 * be compared, because RFC 9525 sec. 6.3 requires a U-label to be converted to an A-label first and
 * this toolkit carries no IDNA implementation; a byte below 0x20 is the CVE-2009-2408 shape the
 * presented side already refuses at decode. The two are separate codes because one is a gap in what
 * the toolkit can do and the other is malformed input. */
function _assertAsciiReference(s, what) {
  guard.name.assertNoControlBytes(s, E, "identity/bad-reference", what);
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c === 0x7f) throw E("identity/bad-reference", what + " carries a DELETE byte at offset " + i);
    if (c > 0x7e) {
      throw E("identity/unsupported-reference", what + " carries a character outside ASCII at offset " + i +
        ". RFC 9525 sec. 6.3 requires a U-label to be converted to an A-label before it is compared, and this " +
        "toolkit carries no IDNA implementation: pass the name already converted to A-labels");
    }
  }
}

/** @internal A reference identity carries no wildcard. RFC 9525 sec. 6.3 covers a wildcard in a
 * presented identifier only, so one on this side is a caller mistake and not a name. */
function _assertNoWildcard(s, what) {
  if (_indexOf(s, "*") !== -1) {
    throw E("identity/bad-reference", what + " carries a wildcard character. RFC 9525 sec. 6.3 covers " +
      "wildcards in a presented identifier only, never in a reference identity");
  }
}

/** @internal The domain of a reference identity, normalized the way both sides are normalized: one
 * trailing dot stripped, then held to the label rules so an empty label or a label past 63
 * characters is a caller mistake, not a name that can never match. */
function _referenceDomain(v, what) {
  if (typeof v !== "string" || v === "") throw E("identity/bad-reference", what + " must be a non-empty string");
  _assertAsciiReference(v, what);
  _assertNoWildcard(v, what);
  var d = _stripTrailingDot(v);
  if (d === "" || d.length > MAX_HOST) {
    throw E("identity/bad-reference", what + " must be a domain name of 1 to " + MAX_HOST + " characters");
  }
  var labels = _hostLabels(d);
  for (var i = 0; i < labels.length; i++) {
    if (labels[i].length === 0 || labels[i].length > MAX_LABEL) {
      throw E("identity/bad-reference", what + " has a label at position " + i + " that is empty or longer than " + MAX_LABEL + " characters");
    }
  }
  return d;
}

/** @internal One reference identity, classified once. RFC 9525 sec. 3 has an IPv4 address read as
 * an IP-ID and not as a name, and sec. 7.4 has the classification carried forward instead of
 * re-derived, so a value that is an address is never also tried as a domain. A record form states
 * its own type, and carries its service type and its domain as ONE value, which is what makes
 * sec. 6.5's prohibition on combining a service from one reference with a domain from another
 * structural instead of a check that could be forgotten. */
function _reference(r, index) {
  var what = "reference identity [" + index + "]";
  if (guard.bytes.isByteSource(r)) {
    var octets = guard.bytes.snapshotSource(r, IdentityError, "identity/bad-reference", what);
    if (octets.length !== 4 && octets.length !== 16) {
      throw E("identity/bad-reference", what + " is a " + octets.length + "-octet address. RFC 9525 sec. 2 " +
        "has an IP-ID carry exactly 4 octets for IPv4 or 16 for IPv6; an address plus a mask is a name " +
        "constraint rather than a reference identity");
    }
    return { kind: "ip", octets: octets, service: null, text: ip.textFromOctets(octets),
      input: _reported({ type: "ip", value: ip.textFromOctets(octets), octets: octets }) };
  }
  if (typeof r === "string") {
    if (r === "") throw E("identity/bad-reference", what + " must be a non-empty string");
    _assertAsciiReference(r, what);
    if (ip.isIPv4(r) || ip.isIpLiteral(r)) {
      var packed = ip.packIpLiteral(r);
      if (packed === null) throw E("identity/bad-reference", what + " is not a textual IP address this toolkit reads");
      return { kind: "ip", octets: packed, service: null, text: r, input: r };
    }
    return { kind: "dns", domain: _referenceDomain(r, what), service: null, input: r };
  }
  if (!r || typeof r !== "object") {
    throw E("identity/bad-reference", what + " must be a domain name, a textual IP address, a 4- or 16-octet " +
      "BufferSource, or a { type, value } record");
  }
  guard.identifier.assertKnownKeys(r, REFERENCE_KEYS, E, "identity/bad-reference",
    what + " has an unknown key (a reference record is { type, value } plus `service` for srv or `scheme` for uri): ");
  if (r.type === "dns") {
    var dnsDomain = _referenceDomain(r.value, what + " value");
    return { kind: "dns", domain: dnsDomain, service: null, input: _reported({ type: "dns", value: dnsDomain }) };
  }
  if (r.type === "ip") {
    /** @internal The record STATES the type, so the type decides what the value may be.
     * Classifying the value again would let a name inside an `ip` record be compared as a
     * name, which is RFC 9525 sec. 3's consistent classification read backwards: what the
     * caller asked for is an address, so anything else is a caller mistake. */
    var addr = _reference(r.value, index);
    if (addr.kind !== "ip") {
      throw E("identity/bad-reference", what + " of type ip carries " + guard.text.showValue(r.value) +
        ", which is no address. RFC 9525 sec. 3 has an identifier classified once, so a name here is " +
        "a mistake and is never compared as a DNS-ID");
    }
    return { kind: "ip", octets: addr.octets, service: null, text: addr.text,
      input: _reported({ type: "ip", value: addr.text, octets: addr.octets }) };
  }
  if (r.type === "srv") {
    if (typeof r.service !== "string" || r.service === "") throw E("identity/bad-reference", what + " of type srv needs a `service`");
    _assertAsciiReference(r.service, what + " service");
    if (_charCodeAt(r.service, 0) !== 0x5f) {
      throw E("identity/bad-reference", what + " service must open with an underscore. RFC 4985 sec. 2 makes the " +
        "underscore part of the service name rather than a separator, so `_imap` is the value and `imap` is not");
    }
    if (r.service.length < 2) throw E("identity/bad-reference", what + " service must name a service after its underscore");
    var srvDomain = _referenceDomain(r.value, what + " value");
    var srvService = _lowerAscii(r.service);
    return { kind: "srv", domain: srvDomain, service: srvService,
      input: _reported({ type: "srv", service: srvService, value: srvDomain }) };
  }
  if (r.type === "uri") {
    if (typeof r.scheme !== "string" || r.scheme === "") throw E("identity/bad-reference", what + " of type uri needs a `scheme`");
    _assertAsciiReference(r.scheme, what + " scheme");
    if (_indexOf(r.scheme, ":") !== -1) {
      throw E("identity/bad-reference", what + " scheme carries a colon. RFC 3986 sec. 3.1 makes the colon a " +
        "separator rather than part of the scheme");
    }
    var uriDomain = _referenceDomain(r.value, what + " value");
    var uriScheme = _lowerAscii(r.scheme);
    return { kind: "uri", domain: uriDomain, service: uriScheme,
      input: _reported({ type: "uri", scheme: uriScheme, value: uriDomain }) };
  }
  throw E("identity/unsupported-reference", what + " names the type " + guard.text.showValue(r.type) +
    ". The types this verb reads are dns, ip, srv and uri (RFC 9525 sec. 1.3)");
}

/** @internal The caller's reference list, read once and bounded at the door. An empty list is
 * refused, not treated as "match anything", because a check that constrains nothing reads to
 * a caller as a policy in force. */
/** @internal What the verdict hands back as the matched reference. RFC 9525 sec. 6.6 has the
 * caller use it as the validated identity of the service, so it is built from the values that were
 * checked and frozen, rather than being the caller's own object: a record the caller rewrites
 * afterwards would otherwise name an identity nothing compared. A string is already a value; bytes
 * are the copy taken at the door. */
function _reported(record) {
  var out = intrinsic.create(null), k;
  for (k in record) {
    if (intrinsic.hasOwn(record, k) && record[k] !== undefined) out[k] = record[k];
  }
  return intrinsic.freeze(out);
}

var _SNAPSHOTS = new WeakSet();

/** @internal Whether this list is one `snapshotReferences` produced. The record is kept off the
 * value, so a caller cannot make an arbitrary array pass by writing a field on it. */
function _isSnapshot(v) {
  return _isArray(v) && _SNAPSHOTS.has(v);
}

/** @internal The reference identities, read and copied in one pass, so a caller that mutates its
 * array or its records afterwards changes nothing the verdict answers for. A verb with awaits
 * between the call and the comparison calls this in its synchronous prologue and passes the
 * result to `match`, which is what makes the policy the verdict answers for the policy the call
 * was made with. */
function snapshotReferences(references) {
  if (_isSnapshot(references)) return references;
  var parsed = _references(references);
  /** @internal Every part of a settled reference is frozen, the list and each record alike, so
   * what the comparison reads is what the door checked. The octets are held as a frozen list of
   * numbers rather than a Buffer, because a Buffer's elements stay writable however the object
   * around them is sealed, and an address rewritten after the door would be compared against
   * without having been checked. */
  for (var i = 0; i < parsed.length; i++) {
    if (parsed[i].octets) parsed[i].octets = _frozenOctets(parsed[i].octets);
    intrinsic.freeze(parsed[i]);
  }
  intrinsic.freeze(parsed);
  _SNAPSHOTS.add(parsed);
  return parsed;
}

function _frozenOctets(buf) {
  var out = [];
  for (var i = 0; i < buf.length; i++) _append(out, buf[i]);
  return intrinsic.freeze(out);
}

function _references(references) {
  var list = _isArray(references) ? references : [references];
  if (list.length === 0) {
    throw E("identity/bad-input", "the reference identity list is empty. A list that constrains nothing would " +
      "read as an identity check that passed; pass at least one name, address or record");
  }
  if (list.length > constants.LIMITS.IDENTITY_MAX_REFERENCES) {
    throw E("identity/too-many-references", "the reference identity list holds " + list.length +
      " entries and at most " + constants.LIMITS.IDENTITY_MAX_REFERENCES + " are read");
  }
  var out = [];
  for (var i = 0; i < list.length; i++) _append(out, _reference(list[i], i));
  return out;
}

/** @internal Whether a presented `dNSName` is shaped like a name at all. This is deliberately not
 * `guard.name.isFqdnHost` and not the certificate-quality test `lint` applies: RFC 9525 says nothing
 * about an underscore label, and a name this check refuses is a name that can never match rather
 * than a certificate fault. Only the structure the label comparison needs is required. */
function _presentedNameShape(s) {
  if (s.length === 0 || s.length > MAX_HOST) return false;
  var labels = _hostLabels(s);
  for (var i = 0; i < labels.length; i++) {
    if (labels[i].length === 0 || labels[i].length > MAX_LABEL) return false;
  }
  return true;
}

/** @internal Whether a presented name carries a wildcard RFC 9525 sec. 6.3 admits: exactly one
 * wildcard character, and that character the complete content of the left-most label. A name
 * carrying a wildcard that fails either test is invalid and is IGNORED rather than refused, which
 * sec. 6.3 states and which is why this answers three ways. */
function _wildcardShape(labels) {
  var total = 0, i, j;
  for (i = 0; i < labels.length; i++) {
    for (j = 0; j < labels[i].length; j++) if (_charCodeAt(labels[i], j) === 0x2a) total += 1;
  }
  if (total === 0) return "none";
  if (total > 1) return "invalid";
  if (labels.length < 2) return "invalid";
  return labels[0] === "*" ? "valid" : "invalid";
}

/** @internal Two names compared label by label (RFC 9525 sec. 6.3): equal label counts, every label
 * equal under an ASCII-only case fold. A wildcard in the left-most presented label matches exactly
 * one reference label, which is where this differs from the suffix relation a name constraint uses. */
function _dnsMatch(presented, referenceDomain, wildcardsAllowed) {
  var p = _stripTrailingDot(presented);
  if (!_presentedNameShape(p)) return { disposition: "ignored", reason: "the presented name is not shaped like a domain name" };
  var pl = _hostLabels(p), rl = _hostLabels(referenceDomain);
  var shape = _wildcardShape(pl);
  if (shape === "invalid") {
    return { disposition: "ignored", reason: "the presented name carries a wildcard that is not the whole of its left-most label, or carries more than one (RFC 9525 sec. 6.3)" };
  }
  if (shape === "valid") {
    if (!wildcardsAllowed) return { disposition: "ignored", reason: "wildcard matching is off for this call" };
    if (pl.length !== rl.length) return { disposition: "no-match" };
    for (var w = 1; w < pl.length; w++) {
      if (_lowerAscii(pl[w]) !== _lowerAscii(rl[w])) return { disposition: "no-match" };
    }
    return rl[0].length === 0 ? { disposition: "no-match" } : { disposition: "match" };
  }
  if (pl.length !== rl.length) return { disposition: "no-match" };
  for (var i = 0; i < pl.length; i++) {
    if (_lowerAscii(pl[i]) !== _lowerAscii(rl[i])) return { disposition: "no-match" };
  }
  return { disposition: "match" };
}

/** @internal RFC 9525 sec. 6.4 compares an IP-ID octet for octet. A length difference is a
 * non-match, not a truncated comparison, because length is the only thing that tells the two
 * address versions apart (RFC 9110 sec. 4.3.5). */
function _ipMatch(refOctets, entryOctets) {
  if (refOctets.length !== entryOctets.length) return false;
  var same = 0;
  for (var i = 0; i < refOctets.length; i++) same |= refOctets[i] ^ entryOctets[i];
  return same === 0;
}

/** @internal The `_Service.Name` an RFC 4985 SRVName carries. The value arrives as the inner
 * element's own DER, so it is decoded here with its own universal-tag, primitive and printable
 * checks, not trusted because the OID said what it would be. */
function _srvName(entryValue) {
  var node;
  try { node = asn1.decode(entryValue.valueBytes); }
  catch (e) { return { reason: "the SRVName value is not valid DER", cause: e }; }
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.IA5_STRING) {
    return { reason: "the SRVName value is not an IA5String (RFC 4985 sec. 2)" };
  }
  if (node.constructed) return { reason: "the SRVName value is a constructed IA5String" };
  var content = node.content;
  if (!content || content.length === 0) return { reason: "the SRVName value is empty, and RFC 4985 sec. 2 writes SIZE (1..MAX)" };
  try { guard.name.assertPrintableIa5(content, E, "identity/bad-reference", "the SRVName value"); }
  catch (e) { return { reason: "the SRVName value carries a byte outside printable ASCII", cause: e }; }
  var text = intrinsic.bufToString(content, "latin1");
  if (_charCodeAt(text, 0) !== 0x5f) {
    return { reason: "the SRVName does not open with an underscore, so it names no service (RFC 4985 sec. 2)" };
  }
  var dot = _indexOf(text, ".");
  if (dot < 2 || dot === text.length - 1) {
    return { reason: "the SRVName is not _Service.Name with both parts present (RFC 4985 sec. 2)" };
  }
  return { service: _strSlice(text, 0, dot), domain: _strSlice(text, dot + 1) };
}

/** @internal The scheme and host a URI-ID presents. RFC 9525 sec. 7.2 uses an entry only when it
 * carries both, and requires an entry missing either to be IGNORED with the search continuing.
 * Sec. 6.2 narrows the host to the `reg-name` rule, which excludes an IP literal, so a bracketed
 * address is not a URI-ID. A percent-escape is not decoded: decoding one here would reintroduce the
 * byte the IA5 assertion refused at the certificate's door. */
function _uriId(text) {
  var parts = _uriParts(text);
  if (parts === null) return { reason: "the presented URI has no scheme (RFC 3986 sec. 3.1)" };
  if (!parts.hasAuthority || parts.host === null) {
    return { reason: "the presented URI carries no host, and RFC 9525 sec. 7.2 requires an entry without both a scheme and a host to be ignored" };
  }
  if (parts.bracketed) {
    return { reason: "the presented URI names an IP literal, and RFC 9525 sec. 6.2 narrows a URI-ID host to the reg-name rule" };
  }
  if (_indexOf(parts.host, "%") !== -1) {
    return { reason: "the presented URI host carries a percent-escape, which is not decoded before comparison" };
  }
  /** @internal A wildcard belongs to a presented identifier (sec. 6.3) and not to one entry
   * form, so a URI-ID host carrying one reaches the same comparison a `dNSName` does. The
   * host is still narrowed to a reg-name that is not an address, which is what sec. 6.2 asks
   * of it, so the wildcard label is set aside for that test and the rest is held to it. */
  var bare = _charCodeAt(parts.host, 0) === 0x2a && _charCodeAt(parts.host, 1) === 0x2e
    ? _strSlice(parts.host, 2) : parts.host;
  if (!_isFqdnHost(bare)) {
    return { reason: "the presented URI host is not a domain name (RFC 9525 sec. 6.2 narrows it to the reg-name rule, which excludes an address)" };
  }
  return { scheme: _lowerAscii(parts.scheme), domain: parts.host };
}

/** @internal The identifiers a certificate presents, read from subjectAltName and from nowhere
 * else. RFC 9525 sec. 2 forbids the subject commonName and every other RDN as a source of identity,
 * so this reads the extension and never the subject. */
function _presented(cert) {
  var ext = null;
  for (var i = 0; i < cert.extensions.length; i++) {
    if (cert.extensions[i].oid === OID_SAN) { ext = cert.extensions[i]; break; }
  }
  if (ext === null) return [];
  var decoded = SAN_DECODER(ext.value);
  var names = decoded.names || [];
  if (names.length > constants.LIMITS.SAN_MAX_ENTRIES) {
    throw E("identity/too-many-names", "the certificate presents " + names.length +
      " subjectAltName entries and at most " + constants.LIMITS.SAN_MAX_ENTRIES + " are read");
  }
  return names;
}

function _entryLabel(entry) {
  if (entry.tagNumber === 2) return "dNSName " + guard.text.showValue(entry.value);
  if (entry.tagNumber === 6) return "uniformResourceIdentifier " + guard.text.showValue(entry.value);
  if (entry.tagNumber === 7) return "iPAddress " + guard.text.showValue(ip.textFromOctets(entry.value));
  if (entry.tagNumber === 0) return "otherName " + guard.text.showValue(entry.value && entry.value.typeId);
  return "GeneralName [" + entry.tagNumber + "]";
}

/** @internal One presented entry against one reference identity. The dispatch is on the GeneralName
 * tag the decoder already assigned, which is total over the CHOICE, and each arm answers `match`,
 * `no-match`, or `ignored` with the reason it could not be read. A reference that names a service
 * type carries its domain with it, so no arm can pair a service from one reference with a domain
 * from another. */
function _compare(ref, entry, wildcardsAllowed) {
  var t = entry.tagNumber;
  if (ref.kind === "ip") {
    if (t !== 7) return { disposition: "no-match" };
    return { disposition: _ipMatch(ref.octets, entry.value) ? "match" : "no-match" };
  }
  if (ref.kind === "dns") {
    if (t !== 2) return { disposition: "no-match" };
    return _dnsMatch(entry.value, ref.domain, wildcardsAllowed);
  }
  if (ref.kind === "srv") {
    if (t !== 0) return { disposition: "no-match" };
    if (!entry.value || entry.value.typeId !== OID_DNS_SRV) return { disposition: "no-match" };
    var srv = _srvName(entry.value);
    if (srv.reason) return { disposition: "ignored", reason: srv.reason };
    if (_lowerAscii(srv.service) !== ref.service) return { disposition: "no-match" };
    return _dnsMatch(srv.domain, ref.domain, wildcardsAllowed);
  }
  if (t !== 6) return { disposition: "no-match" };
  var uriId = _uriId(entry.value);
  if (uriId.reason) return { disposition: "ignored", reason: uriId.reason };
  if (uriId.scheme !== ref.service) return { disposition: "no-match" };
  return _dnsMatch(uriId.domain, ref.domain, wildcardsAllowed);
}

/** @internal The search RFC 9525 sec. 6.2 describes: every reference against every presented
 * identifier, stopping at the first match, and failing only once the cross product is exhausted.
 * One counter bounds the pairs, not the two lists independently, because the work is the
 * product. */
function _search(refs, entries, wildcardsAllowed) {
  var pairs = guard.limits.counter(constants.LIMITS.SAN_MAX_ENTRIES * constants.LIMITS.IDENTITY_MAX_REFERENCES,
    E, "identity/too-many-names", "identity comparison");
  var ignored = [], seenIgnored = intrinsic.create(null);
  for (var r = 0; r < refs.length; r++) {
    for (var e = 0; e < entries.length; e++) {
      pairs.tick();
      var got = _compare(refs[r], entries[e], wildcardsAllowed);
      if (got.disposition === "match") {
        return { matched: true, matchedReference: refs[r].input, matchedEntry: _entryLabel(entries[e]),
          ignored: ignored, reason: null };
      }
      if (got.disposition === "ignored") {
        var key = e + "|" + got.reason;
        if (!intrinsic.hasOwn(seenIgnored, key)) {
          seenIgnored[key] = 1;
          _append(ignored, { entry: _entryLabel(entries[e]), reason: got.reason });
        }
      }
    }
  }
  return { matched: false, matchedReference: null, matchedEntry: null, ignored: ignored,
    reason: entries.length === 0
      ? "the certificate presents no subjectAltName entry, and RFC 9525 sec. 2 forbids reading an identity from the subject"
      : "no presented identifier matched a reference identity" };
}

/**
 * @primitive  pki.identity.match
 * @signature  pki.identity.match(cert, references, opts?) -> verdict
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 9525, RFC 4985
 * @related    pki.path.validate, pki.schema.x509.parse
 *
 * Check a certificate against the names a client expected to reach, which RFC 9525 calls
 * reference identities. This answers a different question from path validation and stands in
 * for none of it: a certificate that matches here may still chain to nothing, and
 * `pki.path.validate` is what says whether it chains.
 *
 * `references` is one reference identity or an array of them, and the caller builds that list
 * from what it was trying to reach rather than from the certificate (sec. 6.1.1). Four forms
 * are read. A domain name, `"www.example.com"`, is a DNS-ID. A textual IP address,
 * `"192.0.2.1"` or `"2001:db8::1"`, or a 4- or 16-octet `BufferSource`, is an IP-ID. A record
 * `{ type: "srv", service: "_imap", value: "example.com" }` is an SRV-ID, where the leading
 * underscore is part of the service name (RFC 4985 sec. 2). A record
 * `{ type: "uri", scheme: "https", value: "www.example.com" }` is a URI-ID. A record carries
 * its service type and its domain together, so no comparison can pair the service of one
 * reference with the domain of another (sec. 6.5).
 *
 * The subject distinguished name is never a source of identity. The `commonName` is not read
 * under any option or fallback, including when the certificate carries no subjectAltName at
 * all, and neither is any other RDN (sec. 2, RFC 9110 sec. 4.3.4). A certificate presenting
 * nothing this check reads fails with `reason` naming that, never with an absent field.
 *
 * An IP-ID is compared octet for octet against an `iPAddress` entry and never against a
 * `dNSName` carrying the same address as text, and no prefix or mask applies (sec. 6.2,
 * sec. 6.4). `::ffff:192.0.2.1` and `192.0.2.1` pack to sixteen and four octets, so under that
 * comparison they do not match.
 *
 * A name is compared label by label under an ASCII-only case fold, with one trailing dot
 * normalized on both sides. An A-label is compared as the ASCII it is and is not decoded
 * (sec. 7.3), so a reference identity carrying a character outside ASCII is refused with
 * `identity/unsupported-reference`: RFC 9525 sec. 6.3 requires a U-label to be converted first
 * and this toolkit carries no IDNA implementation. Pass a name already in A-labels.
 *
 * Wildcards are ON, and `opts.wildcards: false` turns them off, which sec. 3 requires a
 * specification to state either way. A wildcard matches when it is the complete content of the
 * left-most label and there is exactly one of them, and it reaches exactly one label:
 * `*.example.com` matches `foo.example.com`, and matches neither `example.com` nor
 * `a.b.example.com`. A presented name carrying a wildcard that fails those rules is ignored
 * and the search continues, which is what sec. 6.3 directs; it does not refuse the
 * certificate. A wildcard in a reference identity is a caller mistake and is refused.
 *
 * On a match the verdict's `matchedReference` is what sec. 6.6 has the caller use as the
 * validated identity of the service. A reference given as a string comes back as that string; a
 * record or a `BufferSource` comes back as a frozen `{ type, value, ... }` built from the values
 * that were compared, with an address in its textual form, so what the verdict names is the
 * identity that was checked rather than an object the caller can still write to.
 *
 * Protection against a wildcard that spans an administrative boundary, such as `*.co.uk`, is
 * out of scope here as it is in sec. 7.1: this toolkit ships no public-suffix list.
 *
 * A name constraint and an identity check read the same subjectAltName entries to answer
 * different questions, and neither is evidence for the other. A `dNSName` name constraint on
 * an issuer says nothing about whether an SRV-ID or a URI-ID in a leaf is constrained
 * (sec. 7.6); a client wanting that correspondence layers it on top of both.
 *
 * @opts  wildcards  Whether a presented identifier may carry a wildcard (RFC 9525 sec. 6.3),
 *                   default `true`; `false` puts every wildcard entry in `ignored`.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { subjectAltName: [{ dNSName: "www.example.com" }] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var v = pki.identity.match(der, "www.example.com");
 *   console.log(v.matched, v.matchedReference);
 */
function match(cert, references, opts) {
  opts = guard.identifier.optionsObject(opts, E, "identity/bad-input", "match: opts");
  guard.identifier.assertKnownKeys(opts, MATCH_OPTS, E, "identity/bad-input",
    "pki.identity.match has an unknown option (the only option is `wildcards`). The unknown option was: ");
  var snap = guard.identifier.snapshotOptions(opts, MATCH_OPTS);
  if (snap.wildcards !== undefined && typeof snap.wildcards !== "boolean") {
    throw E("identity/bad-input", "match: opts.wildcards must be a boolean");
  }
  var wildcardsAllowed = snap.wildcards === undefined ? true : snap.wildcards;
  var parsed = guard.parsed.acceptDerived(cert, "certificate", x509.parse, E, "identity/bad-input", "a certificate");
  var refs = _isSnapshot(references) ? references : snapshotReferences(references);
  var entries = _presented(parsed);
  var found = _search(refs, entries, wildcardsAllowed);
  return guard.verdict.of({
    matched: found.matched,
    matchedReference: found.matchedReference,
    matchedEntry: found.matchedEntry,
    presented: entries.length,
    ignored: found.ignored,
    reason: found.reason,
  });
}

module.exports = intrinsic.freeze({ match: match, snapshotReferences: snapshotReferences });
