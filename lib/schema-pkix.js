// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// parsers that compose these factories (pki.schema.x509, pki.schema.crl, ...).
//
// Shared PKIX structure-schema factories (RFC 5280). Each is a namespace-
// parameterized FACTORY: given an error namespace `ns` ({ prefix, E, oid }) it
// returns an asn1-schema that walks the corresponding ASN.1 structure and emits
// the caller's own <prefix>/* error codes. x509.js, crl.js, and future CMS/CSR
// parsers compose these so AlgorithmIdentifier / Name / Extension are defined
// once, not re-derived per format. This module is internal infrastructure -- the
// operator-facing surface is the parsers that consume it.

var asn1 = require("./asn1-der");
var constants = require("./constants");
var schema = require("./schema-engine");
// ct is a leaf format module (requires only the codec / oid / constants / error
// core, never pkix) so the SCT-list extension VALUE decoder registers here as a
// registry row, not a switch. The one-directional edge keeps the layering acyclic.
var ct = require("./ct");

var PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

// ---- shared parse-entry ----------------------------------------------
// Input handling, PEM unwrapping (with the size cap), DER-decode wrapping, and
// the walk are defined ONCE here so no format can diverge on a guard. Each
// format supplies only its labels, error class, code prefix, and top schema.

// pemDecode(text, label, PemError): `label` (when truthy) is enforced, else the
// first block is taken. Applies the LIMITS.PEM_MAX_BYTES cap before scanning.
// The body must be CANONICAL base64 (RFC 4648 sec. 3.5): whole 4-character
// groups, no stray padding, zero trailing bits in the final symbol. Node's
// lenient Buffer.from would otherwise let several distinct PEM texts alias one
// DER (PEM-layer malleability) and silently drop trailing content bits.
function pemDecode(text, label, PemError) {
  // The size cap is enforced on the raw byte length BEFORE the latin1 string
  // copy: converting first would allocate a full-size string for an input the
  // cap is about to reject, and a buffer above Node's max string length would
  // escape as an untyped ERR_STRING_TOO_LONG instead of pem/too-large.
  if (Buffer.isBuffer(text)) {
    if (text.length > constants.LIMITS.PEM_MAX_BYTES) throw new PemError("pem/too-large", "PEM input exceeds size cap");
    text = text.toString("latin1");
  }
  if (typeof text !== "string") throw new PemError("pem/bad-input", "pemDecode expects a string or Buffer");
  if (text.length > constants.LIMITS.PEM_MAX_BYTES) throw new PemError("pem/too-large", "PEM input exceeds size cap");
  var m = PEM_RE.exec(text);
  if (!m) throw new PemError("pem/no-block", "no PEM block found");
  if (label && m[1] !== label) throw new PemError("pem/label-mismatch", "expected " + JSON.stringify(label) + " block, got " + JSON.stringify(m[1]));
  var b64 = m[2].replace(/[\r\n\t ]+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new PemError("pem/bad-base64", "PEM body is not valid base64");
  if (b64.length % 4 !== 0) throw new PemError("pem/bad-base64", "PEM base64 body must be whole 4-character groups (RFC 4648 sec. 3.5)");
  var der = Buffer.from(b64, "base64");
  if (der.toString("base64") !== b64) throw new PemError("pem/bad-base64", "PEM base64 body is not canonical (RFC 4648 sec. 3.5)");
  return der;
}

// The label must be re-readable by this module's own PEM_RE (uppercase
// alphanumeric words separated by single spaces, a subset of the RFC 7468
// sec. 3 label grammar). Anything else (lowercase, a leading/trailing space,
// an embedded "-----" or newline) would emit armor pemDecode itself rejects
// or corrupt the armor grammar -- a config-time authoring fault, thrown here.
function pemEncode(der, label, PemError) {
  if (typeof label !== "string" || !/^[A-Z0-9]+( [A-Z0-9]+)*$/.test(label)) {
    throw new PemError("pem/bad-label", "pemEncode requires an uppercase A-Z0-9 label with single spaces");
  }
  var buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  var b64 = buf.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
}

// Coerce parse input to DER bytes. A PEM string OR a PEM Buffer (a .pem file
// read with fs.readFileSync) is unwrapped with opts.pemLabel; a DER Buffer or
// Uint8Array is taken as bytes. opts: { pemLabel, PemError, ErrorClass, prefix }.
function coerceToDer(input, opts) {
  if (typeof input === "string") return pemDecode(input, opts.pemLabel, opts.PemError);
  if (input instanceof Uint8Array && !Buffer.isBuffer(input)) input = Buffer.from(input);
  if (Buffer.isBuffer(input)) {
    return _isPemArmor(input) ? pemDecode(input, opts.pemLabel, opts.PemError) : input;
  }
  throw new opts.ErrorClass(opts.prefix + "/bad-input", "parse expects a DER Buffer or a PEM string");
}

// Does a Buffer carry PEM armor (a .pem read with fs.readFileSync) rather than
// raw DER? It does iff "-----BEGIN" appears and everything before it is TEXT
// (UTF-8 BOM / whitespace / RFC 7468 explanatory preamble). DER is binary -- its
// leading tag+length bytes are non-printable -- so a non-SEQUENCE DER (a bare
// SET / INTEGER) is NOT misrouted here; it decodes and fails closed structurally.
function _isPemArmor(buf) {
  var head = buf.slice(0, 4096).toString("latin1");
  var idx = head.indexOf("-----BEGIN");
  if (idx === -1) return false;
  for (var i = 0; i < idx; i++) {
    var c = buf[i];
    var textByte = (c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d ||
      c === 0xef || c === 0xbb || c === 0xbf; // printable ASCII, tab/newlines, UTF-8 BOM
    if (!textByte) return false;
  }
  return true;
}

// Decode the DER root, wrapping a codec fault in the caller's <prefix>/bad-der.
function decodeRoot(der, opts) {
  // A format whose wire encoding is normatively BER (RFC 7292 PKCS#12) opts
  // in to the codec's ber mode for the WHOLE decode. BER-vs-DER divergence is
  // not always a decode-time throw -- a definite-length constructed IMPLICIT
  // OCTET STRING decodes strictly and only diverges at the typed reader -- so
  // a strict-first-retry-on-throw boundary would miss legal BER shapes. A
  // strict-DER input decodes identically under the ber mode, every other
  // strictness verdict included.
  try { return asn1.decode(der, opts.ber ? { ber: true } : undefined); }
  catch (e) {
    throw new opts.ErrorClass(opts.prefix + "/bad-der", (opts.what || "input") + " DER did not decode: " + ((e && e.message) || String(e)), e);
  }
}

// The shared parse entry: coerce -> decode -> walk the top schema. A format's
// parse() is one call to this; the guard-parity bug class (a new format not
// mirroring an existing format's input handling) is structurally impossible.
function runParse(input, opts) {
  return schema.walk(opts.topSchema, decodeRoot(coerceToDer(input, opts), opts), opts.ns).result;
}

// Distinguished-name attribute short labels (RFC 4514 sec. 3 + common use).
var DN_SHORT = {
  commonName:             "CN",
  countryName:            "C",
  localityName:           "L",
  stateOrProvinceName:    "ST",
  streetAddress:          "STREET",
  organizationName:       "O",
  organizationalUnitName: "OU",
  domainComponent:        "DC",
  surname:                "SN",
  givenName:              "GN",
  serialNumber:           "SERIALNUMBER",
  emailAddress:           "emailAddress",
};

// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
// The error/OID namespace every format module walks its schema under:
// { prefix, E:(code,message,cause)=>new ErrorClass(...), oid }. Factored so a
// format declares it in one line instead of repeating the error-constructor
// closure (a caller that never passes a cause is unaffected -- withCause ignores
// an undefined third arg).
function makeNS(prefix, ErrorClass, oidModule) {
  return { prefix: prefix, E: function (code, message, cause) { return new ErrorClass(code, message, cause); }, oid: oidModule };
}

// A bounded universal-INTEGER version reader. `accept` maps each legal wire value
// (as a decimal string) to its surfaced version number; any other value is a
// <prefix>/bad-version fault. The one genuine per-format divergence -- the cert
// rejects 0 and maps 1->2/2->3, a CRL accepts only 1->2, a CSR only 0->1, a PKCS#8
// 0->1/1->2 -- is expressed purely as the accept map (RFC 5280 sec. 4.1.2.1 / sec. 5.1.2.1,
// RFC 2986 sec. 4.1, RFC 5958 sec. 2). read.integer is strict, so an ENUMERATED-tagged
// version is rejected at the leaf (asn1/*).
function versionReader(ns, accept) {
  return schema.decode(function (n) {
    var key = asn1.read.integer(n).toString();
    if (Object.prototype.hasOwnProperty.call(accept, key)) return accept[key];
    throw ns.E(ns.prefix + "/bad-version", "unsupported version " + key);
  });
}

// opts.implicitTag (optional): read the AlgorithmIdentifier as a [tag] IMPLICIT
// SEQUENCE (a context-class constructed node whose children are algorithm + parameters),
// for the RFC 5652 sec. 6.2.4 pwri.keyDerivationAlgorithm [0]. With no opts the shape is a
// universal SEQUENCE, byte-identical to every existing caller.
//
// Parameter-rule tiering: only the params-MUST-BE-ABSENT families (ML-DSA,
// SLH-DSA, the Edwards/Montgomery curves -- new registrations with no legacy
// corpus) are enforced at parse time, in the build below. The CLASSICAL
// per-OID rules (RSA parameters MUST be NULL, RFC 3279 sec. 2.2.1/2.3.1;
// ecdsa-with-SHA2 parameters MUST be omitted, RFC 5758 sec. 3.2) are
// deliberately NOT parse-time rejects: a long tail of deployed certificates
// omits the RSA NULL, so the parse tier stays interop-lenient for those
// families and the strict classical check runs on the signature-verification
// path (path-validate's signature-algorithm registry), where the verdict
// matters. SPKI key AlgorithmIdentifiers follow the same tiering: lenient at
// parse, validated by the key-import layer that consumes them.
function algorithmIdentifier(ns, opts) {
  opts = opts || {};
  return schema.seq([
    schema.field("algorithm", schema.oidLeaf()),
    schema.optional("parameters", schema.any(), { whenAny: true }),
  ], {
    assert: opts.implicitTag != null ? "implicit" : "sequence", implicitTag: opts.implicitTag,
    arity: { min: 1 }, code: ns.prefix + "/bad-algorithm-identifier", what: "AlgorithmIdentifier",
    build: function (m, ctx) {
      var dotted = m.fields.algorithm.value;
      // For every algorithm the registry marks parameters-absent -- the PQC
      // signature families (ML-DSA RFC 9881, SLH-DSA RFC 9909/9814), the
      // Edwards/Montgomery curves (RFC 8410), ML-KEM (RFC 9936), and the HKDF
      // identifiers (RFC 8619) -- the `parameters` field MUST be absent: no
      // explicit NULL, no bytes. Enforced ONCE here so every consumer of the
      // shared AlgorithmIdentifier inherits the rule; the guard-parity bug
      // class is structurally impossible.
      if (m.fields.parameters.present && ctx.oid.paramsMustBeAbsent(dotted)) {
        throw ctx.E(ctx.prefix + "/bad-algorithm-parameters",
          "the " + (ctx.oid.name(dotted) || dotted) + " AlgorithmIdentifier parameters field MUST be absent");
      }
      return { oid: dotted, name: ctx.oid.name(dotted) || null, parameters: m.fields.parameters.present ? m.fields.parameters.node.bytes : null };
    },
  });
}

// attrValueToString(ns): the AttributeValue decode-leaf. A malformed KNOWN
// string type (invalid UTF-8, a non-IA5 byte, a PrintableString character
// outside its set, ...) surfaces as an asn1/bad-* content error and must fail
// closed -- do NOT hex-encode it away, or the decoder's strict string validation
// is silently bypassed on the DN path. A value that is simply not a decodable
// primitive string is NOT malformed and stays representable: an ANY-typed
// non-string tag (asn1/expected-string) or a constructed universal type such as
// a SEQUENCE (asn1/expected-primitive) renders per RFC 4514 sec. 2.4 as "#" plus the
// hex of its FULL DER encoding (node.bytes), round-tripping intact.
// A GENUINE string whose first character is '#' or '\' is surfaced with a
// leading '\' escape (RFC 4514 sec. 2.4) so it can never collide with the
// '#'+hex form; the encode direction strips that one leading escape back off.
function attrValueToString(ns) {
  return schema.decode(function (node) {
    var s;
    try { s = asn1.read.string(node); }
    catch (e) {
      if (!e || (e.code !== "asn1/expected-string" && e.code !== "asn1/expected-primitive")) {
        throw ns.E(ns.prefix + "/bad-atv", "malformed string in attribute value: " + ((e && e.message) || String(e)));
      }
      return "#" + node.bytes.toString("hex");
    }
    if (s.charAt(0) === "#" || s.charAt(0) === "\\") return "\\" + s;
    return s;
  }, function (value) {
    // encode: a leading '\' escapes the next character (the decode's escape of a
    // literal '#'/'\'); a "#hex" form (RFC 4514 sec. 2.4) round-trips its raw DER
    // verbatim -- the hex is validated (even-length hex digits encoding exactly one
    // DER TLV) and throws rather than silently emitting truncated bytes, since
    // Buffer.from(str, "hex") stops at the first invalid character. Any other
    // string encodes as UTF8String (the decode does not preserve the original
    // string type, so this is the canonical re-encoding, not a byte-exact one).
    if (typeof value === "string" && value.charAt(0) === "\\") return asn1.build.utf8(value.slice(1));
    if (typeof value === "string" && value.charAt(0) === "#") {
      var hex = value.slice(1);
      if (!/^(?:[0-9A-Fa-f]{2})+$/.test(hex)) {
        throw ns.E(ns.prefix + "/bad-atv", "a #hex attribute value must be a non-empty even run of hex digits (RFC 4514 sec. 2.4)");
      }
      var raw = Buffer.from(hex, "hex");
      try { asn1.decode(raw); }
      catch (e) { throw ns.E(ns.prefix + "/bad-atv", "a #hex attribute value must encode exactly one DER TLV", e); }
      return raw;
    }
    return asn1.build.utf8(value);
  });
}

// The always-escape specials of RFC 4514 sec. 2.4, plus its positional rules:
// NUL escapes as \00, a trailing space as '\ ', and a leading '#' or space as
// '\#' / '\ ' -- without them the rendered dn is ambiguous (a literal '#0500'
// value would be indistinguishable from the hexstring form) and leading /
// trailing spaces would be silently significant.
function _escapeDnValue(v) {
  var s = v.replace(/([,+"\\<>;])/g, "\\$1").split("\u0000").join("\\00");
  if (s.length && s.charAt(s.length - 1) === " ") s = s.slice(0, -1) + "\\ ";
  if (s.charAt(0) === "#" || s.charAt(0) === " ") s = "\\" + s;
  return s;
}

// The dn RENDERING of a surfaced AttributeValue: the '#'-leading hex form (a
// non-string value) renders bare -- escaping its '#' would turn the RFC 4514
// hexstring form into an escaped literal -- while a genuine string (surfaced
// with its leading '#'/'\' escape, see attrValueToString) is unescaped back to
// the semantic string and then rendered with the full escape set.
function _dnDisplayValue(v) {
  if (typeof v !== "string") return v;
  if (v.charAt(0) === "#") return v;
  return _escapeDnValue(v.charAt(0) === "\\" ? v.slice(1) : v);
}

// time(ns): the RFC 5280 Time production under its profile encoding rule
// (sec. 4.1.2.5 for certificate validity, restated for the CRL fields in
// sec. 5.1.2.4-5.1.2.6): a date through the year 2049 MUST be UTCTime and
// GeneralizedTime is reserved for 2050 onward, so a GeneralizedTime carrying a
// 1950..2049 date is a non-conforming second encoding of a representable value
// and is rejected (<prefix>/bad-time) -- accepting it would let two wire forms
// alias one abstract time (a parser-differential channel). The engine's
// schema.time already applies the cutover on ENCODE; this leaf composes it and
// enforces the same rule on DECODE. A GeneralizedTime-only field (an RFC 3161
// genTime, a CRL invalidityDate, an RFC 5755 AttCertValidityPeriod) must NOT
// take this leaf -- its syntax has no UTCTime alternative to cut over to.
function time(ns) {
  var base = schema.time(ns);
  return schema.decode(function (n, ctx) {
    var d = base.fn(n, ctx);
    if (n.tagNumber === asn1.TAGS.GENERALIZED_TIME) {
      var y = d.getUTCFullYear();
      if (y >= 1950 && y < 2050) {
        throw ctx.E(ctx.prefix + "/bad-time", "a date through 2049 must be encoded as UTCTime, not GeneralizedTime (RFC 5280 sec. 4.1.2.5)");
      }
    }
    return d;
  }, base.write);
}

// Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName; RDN ::= SET OF
// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }. The atv asserts
// its SEQUENCE tag (a SET-tagged body is a different ASN.1 type), and repeated
// RDN attribute types stay legal (no uniqueness).
function attributeTypeAndValue(ns) {
  return schema.seq([
    schema.field("type", schema.oidLeaf()),
    schema.field("value", attrValueToString(ns)),
  ], {
    assert: "sequence", arity: { min: 2 }, code: ns.prefix + "/bad-atv", what: "AttributeTypeAndValue",
    build: function (m, ctx) {
      var typeOid = m.fields.type.value;
      return { type: typeOid, name: ctx.oid.name(typeOid) || null, value: m.fields.value.value };
    },
  });
}
function relativeDistinguishedName(ns) {
  // RelativeDistinguishedName ::= SET SIZE (1..MAX) -- an empty SET {} is malformed.
  return schema.setOf(attributeTypeAndValue(ns), { assert: "set", min: 1, code: ns.prefix + "/bad-rdn", what: "RelativeDistinguishedName" });
}
// opts.implicitTag (optional): read the Name as a [tag] IMPLICIT RDNSequence -- the
// context tag REPLACES the universal SEQUENCE tag, so the node is a context-class
// constructed [tag] whose children ARE the RDN SETs (the CRMF CertTemplate issuer
// [3] / subject [5] IMPLICIT arm, RFC 4211 sec. 5). With no opts the shape is a bare
// universal SEQUENCE OF, byte-identical to every existing caller.
function name(ns, opts) {
  opts = opts || {};
  function nameBuild(m) {
    var rdns = [], parts = [];
    m.items.forEach(function (rdnItem) {
      var atvs = [], atvParts = [];
      rdnItem.value.items.forEach(function (atvItem) {
        var a = atvItem.value.result; // atvItem.value = the atv seq-match; .result = its build result
        atvs.push(a);
        var label = (a.name && DN_SHORT[a.name]) || a.name || a.type;
        atvParts.push(label + "=" + _dnDisplayValue(a.value));
      });
      rdns.push(atvs);
      parts.push(atvParts.join("+"));
    });
    return { rdns: rdns, dn: parts.join(", ") };
  }
  if (opts.implicitTag != null) {
    return schema.implicitSeqOf(opts.implicitTag, relativeDistinguishedName(ns), {
      code: ns.prefix + "/bad-name", what: "Name", build: nameBuild });
  }
  return schema.seqOf(relativeDistinguishedName(ns), {
    assert: "sequence", code: ns.prefix + "/bad-name", what: "Name", build: nameBuild });
}

// GeneralName ::= CHOICE (RFC 5280 sec. 4.2.1.6). A validate-and-surface-raw leaf for a
// caller that keeps the value RAW but needs it to be a well-formed GeneralName: it
// checks the chosen alternative's tag, form (constructed vs primitive per X.690
// sec. 10.2), and content -- otherName [0] is a SEQUENCE { type-id OID, value [0] EXPLICIT
// }; x400Address [3] / ediPartyName [5] are non-empty constructed; directoryName [4]
// EXPLICIT wraps a valid Name; rfc822Name [1] / dNSName [2] / uniformResourceIdentifier
// [6] are primitive non-empty IA5String (7-bit); iPAddress [7] is a 4- or 16-octet
// OCTET STRING; registeredID [8] is a primitive OBJECT IDENTIFIER -- then surfaces the
// value RAW ({ bytes, tagClass, tagNumber }). `opts.code` is the caller's error code
// (e.g. ocsp/bad-requestor-name, tsp/bad-tsa). Shared so the two parsers cannot drift.
// opts.decodeValue (default false): in addition to the raw { bytes, tagClass,
//   tagNumber }, surface the DECODED `value` per arm -- IA5 text (string), an
//   iPAddress Buffer, a directoryName { rdns, dn }, a registeredID OID string,
//   or an otherName { typeId, valueBytes }. The path validator's name-constraint
//   matcher needs the decoded value; the tsp/ocsp/attrcert consumers pass no
//   flag and get the byte-identical raw-only shape.
// opts.subtreeBase (default false): the GeneralSubtree.base form (RFC 5280
//   sec. 4.2.1.10) -- an iPAddress base is an address+mask (8 octets IPv4 / 32 IPv6),
//   NOT the 4/16-octet SAN address form. Only the iPAddress size rule changes.
// A GeneralizedTime-only leaf. Several formats fix their times to
// GeneralizedTime and reject UTCTime (OCSP RFC 6960, TSP RFC 3161 sec. 2.4.2,
// CMP RFC 9810 sec. 5.1.1, attribute-certificate validity RFC 5755 sec. 4.2.6);
// ONE ns-parameterized factory owns the tag assert so the per-format code and
// message differ but the check cannot drift. opts.allowFractional enables the
// X.690 sec. 11.7 fractional-seconds profile (the RFC 3161 genTime).
function generalizedTime(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-time");
  var message = opts.message || "the time must be a GeneralizedTime";
  var readOpts = opts.allowFractional ? { allowFractional: true } : undefined;
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.GENERALIZED_TIME) {
      throw ctx.E(code, message);
    }
    return asn1.read.time(n, readOpts);
  });
}

// A UTF8String-only leaf -- the PKIFreeText element shape (RFC 3161 sec. 2.4.2,
// RFC 9810 sec. 5.1.1) shared by the TSP and CMP parsers.
function utf8Text(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-freetext");
  var message = opts.message || "the element must be a UTF8String";
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.UTF8_STRING) {
      throw ctx.E(code, message);
    }
    return asn1.read.string(n);
  });
}

// A raw NON-EMPTY universal SEQUENCE leaf -- surfaces the exact TLV bytes of an
// embedded element (a Certificate, a CertificateList, a PKIPublicationInfo)
// after asserting the SEQUENCE tag and at least one child. An empty SEQUENCE
// (30 00) has the right tag but is none of those structures, so it rejects
// rather than surfacing degenerate bytes to certificate processing.
function rawNonEmptySequence(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-sequence");
  var message = opts.message || "expected a non-empty universal SEQUENCE";
  return schema.decode(function (n, ctx) {
    if (!(n.tagClass === "universal" && n.tagNumber === asn1.TAGS.SEQUENCE && n.children && n.children.length >= 1)) {
      throw ctx.E(code, message);
    }
    return n.bytes;
  });
}

// CRLReason ::= ENUMERATED (RFC 5280 sec. 5.3.1) -- value 7 is unused/reserved.
// The ONE canonical value->name table every consumer validates against: the
// CRL reasonCode decoder surfaces the numeric code, the OCSP RevokedInfo
// decoder the name; both draw the legal set from here so they cannot drift.
var CRL_REASON_NAMES = {
  "0": "unspecified", "1": "keyCompromise", "2": "cACompromise", "3": "affiliationChanged",
  "4": "superseded", "5": "cessationOfOperation", "6": "certificateHold",
  "8": "removeFromCRL", "9": "privilegeWithdrawn", "10": "aACompromise",
};

var GN_CONSTRUCTED = { 0: 1, 3: 1, 4: 1, 5: 1 };
var GN_IA5 = { 1: 1, 2: 1, 6: 1 };
function generalName(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-general-name");
  var decodeValue = opts.decodeValue === true;
  var subtreeBase = opts.subtreeBase === true;
  var NAME = name(ns);
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "context" || n.tagNumber < 0 || n.tagNumber > 8) {
      throw ctx.E(code, "value must be a GeneralName (context tag [0]..[8]) (RFC 5280 sec. 4.2.1.6)");
    }
    var t = n.tagNumber;
    var constructed = !!n.children;
    var value;
    if (GN_CONSTRUCTED[t]) {
      if (!constructed || n.children.length < 1) throw ctx.E(code, "GeneralName [" + t + "] must be a non-empty constructed value (RFC 5280 sec. 4.2.1.6)");
      if (t === 0) {
        // otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }.
        if (n.children.length !== 2) throw ctx.E(code, "GeneralName otherName [0] must be a SEQUENCE { type-id, value [0] }");
        var typeId;
        try { typeId = asn1.read.oid(n.children[0]); }
        catch (e) { throw ctx.E(code, "GeneralName otherName [0] must lead with a type-id OBJECT IDENTIFIER", e); }
        var ov = n.children[1];
        if (!(ov.tagClass === "context" && ov.tagNumber === 0 && ov.children && ov.children.length === 1)) {
          throw ctx.E(code, "GeneralName otherName [0] value must be a [0] EXPLICIT wrapper carrying exactly one value");
        }
        if (decodeValue) value = { typeId: typeId, valueBytes: ov.children[0].bytes };
      } else if (t === 4) {
        // directoryName [4] EXPLICIT Name -- validate the wrapped RDNSequence.
        if (n.children.length !== 1) throw ctx.E(code, "GeneralName directoryName [4] must wrap exactly one Name");
        var dnMatch = schema.walk(NAME, n.children[0], ctx);
        if (decodeValue) value = dnMatch.result;
      }
    } else {
      if (constructed) throw ctx.E(code, "GeneralName [" + t + "] must be primitive (X.690 sec. 10.2)");
      if (GN_IA5[t]) {
        if (n.content.length === 0) throw ctx.E(code, "GeneralName [" + t + "] must be a non-empty IA5String");
        for (var i = 0; i < n.content.length; i++) {
          // 7-bit IA5, and no C0/DEL control byte -- an embedded NUL/control in a
          // dNSName/rfc822Name/URI enables a name-truncation/confusion bypass
          // (CVE-2009-2408 class) downstream, so reject it at decode.
          if (n.content[i] < 0x20 || n.content[i] > 0x7e) throw ctx.E(code, "GeneralName [" + t + "] must be a printable IA5String (no control bytes)");
        }
        if (decodeValue) value = n.content.toString("latin1");
      } else if (t === 7) {
        if (subtreeBase) {
          if (n.content.length !== 8 && n.content.length !== 32) throw ctx.E(code, "GeneralName iPAddress [7] subtree base must be an 8- or 32-octet address+mask (RFC 5280 sec. 4.2.1.10)");
        } else if (n.content.length !== 4 && n.content.length !== 16) {
          throw ctx.E(code, "GeneralName iPAddress [7] must be a 4- or 16-octet address");
        }
        // n.content is proven non-null here (the primitive-form guard above
        // threw on a constructed node); copy the octets out.
        if (decodeValue) value = Buffer.concat([n.content]);
      } else if (t === 8) {
        var regId;
        try { regId = asn1.decodeOidContent(n.content); }
        catch (e) { throw ctx.E(code, "GeneralName registeredID [8] must be a valid OBJECT IDENTIFIER", e); }
        if (decodeValue) value = regId;
      }
    }
    var out = { bytes: n.bytes, tagClass: n.tagClass, tagNumber: n.tagNumber };
    if (decodeValue) out.value = value === undefined ? null : value;
    return out;
  });
}

// GeneralNames ::= SEQUENCE OF GeneralName (RFC 5280 sec. 4.2.1.6), SIZE (1..MAX). Every
// element is validated by generalName (its CHOICE alternative's form + content) and
// surfaced raw, so a caller carrying a GeneralNames field cannot accept a malformed
// element by treating the whole sequence as opaque bytes. Returns { names, bytes }
// where each `names[i]` is the generalName leaf's return -- { bytes, tagClass,
// tagNumber } and, when opts.decodeValue is set, the decoded `value` -- and `bytes`
// is the raw outer DER.
// `opts.implicitTag` handles a [tag] IMPLICIT GeneralNames -- the context tag REPLACES
// the universal SEQUENCE tag (RFC 5755 Holder.entityName [1]); otherwise it is a bare
// universal SEQUENCE OF. `opts.code` is the caller's error code. Shared so the x509 /
// attribute-certificate / (future) CRMF parsers validate a GeneralNames identically.
function generalNames(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-general-names");
  // decodeValue / subtreeBase thread through to each element (the path
  // validator's constraint matcher passes decodeValue:true).
  var gn = generalName(ns, { code: code, decodeValue: opts.decodeValue === true, subtreeBase: opts.subtreeBase === true });
  function build(m) { return { names: m.items.map(function (it) { return it.value; }), bytes: m.node.bytes }; }
  if (opts.implicitTag != null) {
    return schema.implicitSeqOf(opts.implicitTag, gn, { min: 1, code: code, what: opts.what || "GeneralNames", build: build });
  }
  return schema.seqOf(gn, { assert: "sequence", min: 1, code: code, what: opts.what || "GeneralNames", build: build });
}

// certExtensionDecoders(ns) -- the ns-parameterized RFC 5280 sec. 4.2.1 extension
// VALUE decoders. `x509.parse` surfaces each extension as { oid, name, critical,
// value } with `value` the raw inner OCTET-STRING content (a Buffer); the path
// validator and the future complete-extension-set surface need the STRUCTURE
// inside. Each decoder takes that raw Buffer and returns the decoded value, or
// throws a typed `<prefix>/bad-*` code, mirroring the CRL's fail-closed
// `decodeExt` pattern (asn1.decode -> read.* / schema.walk, wrapped). Returns
// { byOid } keyed by dotted OID so a consumer dispatches by ext.oid.
var _T = asn1.TAGS;

// assertPolicyQualifiers(qNode, fail) -- RFC 5280 sec. 4.2.1.4: a PolicyInformation's
// policyQualifiers is a non-empty SEQUENCE OF PolicyQualifierInfo, each a SEQUENCE
// { policyQualifierId OID, qualifier } of EXACTLY two members led by an OID. The
// structure is validated fail-closed; the qualifier body stays opaque (surfaced
// raw by the caller). `fail(msg)` throws the caller's typed code. Shared by the
// certificatePolicies extension decoder and the RFC 5035 ESS SigningCertificate
// policies field so the same PolicyInformation shape cannot drift between them.
// `fail(msg, cause?)` throws the caller's typed code, carrying the underlying
// leaf fault as the error cause when one is available.
function assertPolicyQualifiers(qNode, fail) {
  if (qNode.tagClass !== "universal" || qNode.tagNumber !== _T.SEQUENCE || !qNode.children || !qNode.children.length) {
    fail("policyQualifiers must be a non-empty SEQUENCE (RFC 5280 sec. 4.2.1.4)");
  }
  qNode.children.forEach(function (pq) {
    if (pq.tagClass !== "universal" || pq.tagNumber !== _T.SEQUENCE || !pq.children || pq.children.length !== 2) {
      fail("policyQualifiers element must be a PolicyQualifierInfo SEQUENCE { policyQualifierId, qualifier } (RFC 5280 sec. 4.2.1.4)");
    }
    try { asn1.read.oid(pq.children[0]); } catch (e) { fail("PolicyQualifierInfo must lead with a policyQualifierId OID", e); }
  });
}

function certExtensionDecoders(ns) {
  var GN_SUBTREE = generalName(ns, { decodeValue: true, subtreeBase: true, code: ns.prefix + "/bad-name-constraints" });

  function decodeTop(buf, code, what) {
    var n;
    try { n = asn1.decode(buf); }
    catch (e) { throw ns.E(code, "malformed " + what + " extension value: " + ((e && e.message) || String(e)), e); }
    return n;
  }
  function seqChildren(buf, code, what) {
    var n = decodeTop(buf, code, what);
    if (n.tagClass !== "universal" || n.tagNumber !== _T.SEQUENCE || !n.children) {
      throw ns.E(code, what + " must be a SEQUENCE (RFC 5280 sec. 4.2.1)");
    }
    return n.children;
  }
  function readInt(node, code, what) {
    try { return asn1.read.integer(node); }
    catch (e) { throw ns.E(code, what + " must be an INTEGER", e); }
  }

  // basicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER (0..MAX) OPTIONAL }
  function basicConstraints(buf) {
    var C = ns.prefix + "/bad-basic-constraints";
    var kids = seqChildren(buf, C, "BasicConstraints");
    var i = 0, cA = false, pathLen = null;
    if (kids[i] && kids[i].tagClass === "universal" && kids[i].tagNumber === _T.BOOLEAN) {
      var v;
      try { v = asn1.read.boolean(kids[i]); } catch (e) { throw ns.E(C, "BasicConstraints cA must be a BOOLEAN", e); }
      if (v !== true) throw ns.E(C, "BasicConstraints cA DEFAULT FALSE must be omitted, not an explicit FALSE (X.690 sec. 11.5)");
      cA = true; i++;
    }
    if (kids[i] && kids[i].tagClass === "universal" && kids[i].tagNumber === _T.INTEGER) {
      if (!cA) throw ns.E(C, "BasicConstraints pathLenConstraint is only permitted when cA is TRUE (RFC 5280 sec. 4.2.1.9)");
      var pl = readInt(kids[i], C, "pathLenConstraint");
      // Bounded before Number() narrowing -- a value past the safe-integer range
      // would round silently and be compared as a path-length ceiling, so it is
      // exact-or-rejected (the same rule the RSASSA-PSS/PKCS#12 counters follow).
      if (pl < 0n || pl > 2147483647n) throw ns.E(C, "BasicConstraints pathLenConstraint must be a non-negative integer within range");
      pathLen = Number(pl); i++;
    }
    if (i !== kids.length) throw ns.E(C, "BasicConstraints has unexpected trailing fields");
    return { cA: cA, pathLenConstraint: pathLen };
  }

  // keyUsage ::= BIT STRING (named bits). At least one bit MUST be set.
  var KU_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
  function keyUsage(buf) {
    var C = ns.prefix + "/bad-key-usage";
    var n = decodeTop(buf, C, "KeyUsage");
    if (n.tagClass !== "universal" || n.tagNumber !== _T.BIT_STRING) throw ns.E(C, "KeyUsage must be a BIT STRING (RFC 5280 sec. 4.2.1.3)");
    var bs;
    try { bs = asn1.read.bitString(n); } catch (e) { throw ns.E(C, "KeyUsage must be a well-formed BIT STRING", e); }
    // At least one bit MUST be set (RFC 5280 sec. 4.2.1.3) -- an all-zero value (a
    // non-empty byte run of only zero bits, e.g. 03 02 07 00) is malformed too.
    var anyBit = false;
    for (var z = 0; z < bs.bytes.length; z++) { if (bs.bytes[z] !== 0) { anyBit = true; break; } }
    if (!anyBit) throw ns.E(C, "KeyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
    // KeyUsage is a NamedBitList -- enforce the shared X.690 sec. 11.2.2 minimal-DER rule.
    schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (m) { throw ns.E(C, m); });
    var out = {};
    KU_BITS.forEach(function (nm, bit) {
      var byte = bit >> 3, mask = 0x80 >> (bit & 7);
      out[nm] = byte < bs.bytes.length && (bs.bytes[byte] & mask) !== 0;
    });
    return out;
  }

  // GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0, maximum [1] OPTIONAL }
  function subtreeList(node, C) {
    // node is the [0]/[1] IMPLICIT SEQUENCE OF GeneralSubtree (context-constructed).
    // GeneralSubtrees is SIZE(1..MAX) -- an explicitly present but empty subtree
    // list (a0 00) absorbs no constraint and is malformed, not a no-op.
    if (!node.children || node.children.length < 1) throw ns.E(C, "NameConstraints permittedSubtrees/excludedSubtrees must be a non-empty GeneralSubtrees (SIZE 1..MAX, RFC 5280 sec. 4.2.1.10)");
    return node.children.map(function (st) {
      if (st.tagClass !== "universal" || st.tagNumber !== _T.SEQUENCE || !st.children || st.children.length < 1) {
        throw ns.E(C, "GeneralSubtree must be a SEQUENCE { base, minimum?, maximum? }");
      }
      var base = schema.walk(GN_SUBTREE, st.children[0], ns);
      for (var j = 1; j < st.children.length; j++) {
        var f = st.children[j];
        if (f.tagClass !== "context" || (f.tagNumber !== 0 && f.tagNumber !== 1)) throw ns.E(C, "GeneralSubtree has an unexpected field");
        if (f.tagNumber === 0) throw ns.E(C, "GeneralSubtree minimum DEFAULT 0 must be omitted (RFC 5280 sec. 4.2.1.10 requires minimum = 0)");
        if (f.tagNumber === 1) throw ns.E(C, "GeneralSubtree maximum is not permitted in the RFC 5280 profile (sec. 4.2.1.10)");
      }
      return { base: base };
    });
  }
  function nameConstraints(buf) {
    var C = ns.prefix + "/bad-name-constraints";
    var kids = seqChildren(buf, C, "NameConstraints");
    var permitted = [], excluded = [], sawP = false, sawE = false, ncLastTag = -1;
    kids.forEach(function (k) {
      if (k.tagClass !== "context" || !k.children) throw ns.E(C, "NameConstraints fields are [0] permittedSubtrees / [1] excludedSubtrees");
      if (k.tagNumber <= ncLastTag) throw ns.E(C, "NameConstraints fields must be unique and in ascending order (DER)");
      ncLastTag = k.tagNumber;
      if (k.tagNumber === 0) { if (sawP) throw ns.E(C, "duplicate permittedSubtrees"); sawP = true; permitted = subtreeList(k, C); }
      else if (k.tagNumber === 1) { if (sawE) throw ns.E(C, "duplicate excludedSubtrees"); sawE = true; excluded = subtreeList(k, C); }
      else throw ns.E(C, "NameConstraints has an unexpected field [" + k.tagNumber + "]");
    });
    if (!sawP && !sawE) throw ns.E(C, "NameConstraints must contain permittedSubtrees or excludedSubtrees (RFC 5280 sec. 4.2.1.10)");
    return { permittedSubtrees: permitted, excludedSubtrees: excluded };
  }

  // certificatePolicies ::= SEQUENCE SIZE(1..MAX) OF PolicyInformation
  function certificatePolicies(buf) {
    var C = ns.prefix + "/bad-policy";
    var kids = seqChildren(buf, C, "CertificatePolicies");
    if (kids.length < 1) throw ns.E(C, "CertificatePolicies must contain at least one PolicyInformation (RFC 5280 sec. 4.2.1.4)");
    var seen = {};
    return kids.map(function (pi) {
      // PolicyInformation ::= SEQUENCE { policyIdentifier, policyQualifiers
      // SEQUENCE SIZE(1..MAX) OPTIONAL } -- exactly one or two fields; a second
      // field, if present, MUST be a SEQUENCE. Extra/mis-typed fields are malformed.
      if (pi.tagClass !== "universal" || pi.tagNumber !== _T.SEQUENCE || !pi.children || pi.children.length < 1 || pi.children.length > 2) {
        throw ns.E(C, "PolicyInformation must be a SEQUENCE { policyIdentifier, policyQualifiers? }");
      }
      var pid;
      try { pid = asn1.read.oid(pi.children[0]); } catch (e) { throw ns.E(C, "PolicyInformation policyIdentifier must be an OBJECT IDENTIFIER", e); }
      if (seen[pid]) throw ns.E(C, "duplicate policy OID " + pid + " (RFC 5280 sec. 4.2.1.4)");
      seen[pid] = true;
      var qualifiers = null;
      if (pi.children.length > 1) {
        var q = pi.children[1];
        // PolicyQualifierInfo structure validated by the shared assertion; the
        // qualifier body stays opaque (surfaced raw).
        assertPolicyQualifiers(q, function (msg, cause) { throw ns.E(C, msg, cause); });
        qualifiers = q.bytes;
      }
      return { policyIdentifier: pid, qualifiersBytes: qualifiers };
    });
  }

  // policyMappings ::= SEQUENCE SIZE(1..MAX) OF SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }
  function policyMappings(buf) {
    var C = ns.prefix + "/bad-policy";
    var kids = seqChildren(buf, C, "PolicyMappings");
    if (kids.length < 1) throw ns.E(C, "PolicyMappings must contain at least one mapping (RFC 5280 sec. 4.2.1.5)");
    return kids.map(function (mp) {
      if (mp.tagClass !== "universal" || mp.tagNumber !== _T.SEQUENCE || !mp.children || mp.children.length !== 2) {
        throw ns.E(C, "policy mapping must be a SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }");
      }
      var idp, sdp;
      try { idp = asn1.read.oid(mp.children[0]); sdp = asn1.read.oid(mp.children[1]); }
      catch (e) { throw ns.E(C, "policy mapping members must be OBJECT IDENTIFIERs", e); }
      return { issuerDomainPolicy: idp, subjectDomainPolicy: sdp };
    });
  }

  // policyConstraints ::= SEQUENCE { requireExplicitPolicy [0] INTEGER OPT, inhibitPolicyMapping [1] INTEGER OPT }
  function policyConstraints(buf) {
    var C = ns.prefix + "/bad-policy";
    var kids = seqChildren(buf, C, "PolicyConstraints");
    if (kids.length < 1) throw ns.E(C, "PolicyConstraints must contain at least one field (RFC 5280 sec. 4.2.1.11)");
    var rep = null, ipm = null, pcLastTag = -1;
    kids.forEach(function (k) {
      if (k.tagClass !== "context") throw ns.E(C, "PolicyConstraints fields are context-tagged [0]/[1]");
      if (k.tagNumber <= pcLastTag) throw ns.E(C, "PolicyConstraints fields must be unique and in ascending order (DER)");
      pcLastTag = k.tagNumber;
      var v;
      try { v = asn1.read.integerImplicit(k, k.tagNumber); } catch (e) { throw ns.E(C, "PolicyConstraints field must be an INTEGER", e); }
      // Bounded before Number() narrowing (a skip count past the safe-integer
      // range would round silently) -- exact-or-rejected.
      if (v < 0n || v > 2147483647n) throw ns.E(C, "PolicyConstraints skip count must be a non-negative integer within range");
      if (k.tagNumber === 0) rep = Number(v);
      else if (k.tagNumber === 1) ipm = Number(v);
      else throw ns.E(C, "PolicyConstraints has an unexpected field [" + k.tagNumber + "]");
    });
    return { requireExplicitPolicy: rep, inhibitPolicyMapping: ipm };
  }

  // inhibitAnyPolicy ::= INTEGER (0..MAX)
  function inhibitAnyPolicy(buf) {
    var C = ns.prefix + "/bad-policy";
    var n = decodeTop(buf, C, "InhibitAnyPolicy");
    if (n.tagClass !== "universal" || n.tagNumber !== _T.INTEGER) throw ns.E(C, "InhibitAnyPolicy must be an INTEGER (RFC 5280 sec. 4.2.1.14)");
    var v = readInt(n, C, "InhibitAnyPolicy");
    // Bounded before Number() narrowing (a skip count past the safe-integer
    // range would round silently) -- exact-or-rejected.
    if (v < 0n || v > 2147483647n) throw ns.E(C, "InhibitAnyPolicy skip count must be a non-negative integer within range");
    return Number(v);
  }

  // subjectAltName / issuerAltName ::= GeneralNames -- decoded values surfaced.
  function altName(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var n = decodeTop(buf, C, "GeneralNames");
    return schema.walk(generalNames(ns, { decodeValue: true, code: C }), n, ns).result;
  }

  // extKeyUsage ::= SEQUENCE SIZE(1..MAX) OF KeyPurposeId (OID)
  function extKeyUsage(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var kids = seqChildren(buf, C, "ExtKeyUsage");
    if (kids.length < 1) throw ns.E(C, "ExtKeyUsage must contain at least one KeyPurposeId (RFC 5280 sec. 4.2.1.12)");
    return kids.map(function (k) {
      try { return asn1.read.oid(k); } catch (e) { throw ns.E(C, "ExtKeyUsage KeyPurposeId must be an OBJECT IDENTIFIER", e); }
    });
  }

  // authorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPT, authorityCertIssuer [1] OPT, authorityCertSerialNumber [2] OPT }
  function authorityKeyIdentifier(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var kids = seqChildren(buf, C, "AuthorityKeyIdentifier");
    var out = { keyIdentifier: null, authorityCertIssuer: null, authorityCertSerialNumber: null };
    var lastTag = -1;
    kids.forEach(function (k) {
      if (k.tagClass !== "context") throw ns.E(C, "AuthorityKeyIdentifier fields are context-tagged");
      // DER: the OPTIONAL fields appear at most once and in ascending tag order.
      if (k.tagNumber <= lastTag) throw ns.E(C, "AuthorityKeyIdentifier fields must be unique and in ascending order (DER)");
      lastTag = k.tagNumber;
      // keyIdentifier [0] IMPLICIT OCTET STRING and authorityCertSerialNumber
      // [2] IMPLICIT INTEGER are primitive leaves; the readers enforce the
      // primitive form fail-closed (a constructed context node is rejected,
      // never dereferenced for its absent content).
      if (k.tagNumber === 0) { try { out.keyIdentifier = Buffer.from(asn1.read.octetStringImplicit(k, 0)); } catch (e) { throw ns.E(C, "AuthorityKeyIdentifier keyIdentifier [0] must be an IMPLICIT OCTET STRING", e); } }
      else if (k.tagNumber === 1) out.authorityCertIssuer = schema.walk(generalNames(ns, { implicitTag: 1, decodeValue: true, code: C }), k, ns).result;
      else if (k.tagNumber === 2) { try { out.authorityCertSerialNumber = asn1.read.integerImplicit(k, 2); } catch (e) { throw ns.E(C, "authorityCertSerialNumber must be an INTEGER", e); } }
      else throw ns.E(C, "AuthorityKeyIdentifier has an unexpected field [" + k.tagNumber + "]");
    });
    if ((out.authorityCertIssuer === null) !== (out.authorityCertSerialNumber === null)) {
      throw ns.E(C, "AuthorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber must both be present or both absent (RFC 5280 sec. 4.2.1.1)");
    }
    return out;
  }

  // subjectKeyIdentifier ::= OCTET STRING
  function subjectKeyIdentifier(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var n = decodeTop(buf, C, "SubjectKeyIdentifier");
    try { return Buffer.concat([asn1.read.octetString(n)]); }
    catch (e) { throw ns.E(C, "SubjectKeyIdentifier must be an OCTET STRING (RFC 5280 sec. 4.2.1.2)", e); }
  }

  // signedCertificateTimestampList (RFC 6962 sec. 3.3) -- the extension value is a DER
  // OCTET STRING wrapping the TLS-encoded SCT list. Delegated to the CT module,
  // which owns the inner peel + the bounded TLS decode; structure is decoded, the
  // signature stays raw and unverified. The registry contract is that a decoder
  // throws a `<prefix>/bad-*` code, so the CT module's own `ct/*` fault is wrapped
  // and carried as `.cause` rather than leaking a foreign namespace here.
  function sctList(buf) {
    var C = ns.prefix + "/bad-extension-value";
    try { return ct.parseSctList(buf); }
    catch (e) { throw ns.E(C, "malformed signedCertificateTimestampList extension value (RFC 6962 sec. 3.3)", e); }
  }

  // precertificatePoison (RFC 6962 sec. 3.1) -- a critical extension whose value is
  // exactly ASN.1 NULL (05 00), the marker distinguishing a precertificate from
  // a final certificate. Content-validated, not merely tag-checked.
  function precertPoison(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var n = decodeTop(buf, C, "PrecertificatePoison");
    try { asn1.read.nullValue(n); }
    catch (e) { throw ns.E(C, "the precertificate poison extension value must be ASN.1 NULL (RFC 6962 sec. 3.1)", e); }
    return { poison: true };
  }

  // byName returns undefined for an unregistered name; keying a decoder row
  // under "undefined" would silently drop that extension from dispatch (the
  // consumer would treat the extension as structurally unvalidated / absent),
  // so a typo'd key-list entry must fail here, at module load.
  function O(nm) {
    var d = ns.oid.byName(nm);
    if (typeof d !== "string") throw new TypeError("certExtensionDecoders: " + JSON.stringify(nm) + " is not a registered OID name");
    return d;
  }
  var byOid = {};
  byOid[O("basicConstraints")] = basicConstraints;
  byOid[O("keyUsage")] = keyUsage;
  byOid[O("nameConstraints")] = nameConstraints;
  byOid[O("certificatePolicies")] = certificatePolicies;
  byOid[O("policyMappings")] = policyMappings;
  byOid[O("policyConstraints")] = policyConstraints;
  byOid[O("inhibitAnyPolicy")] = inhibitAnyPolicy;
  byOid[O("subjectAltName")] = altName;
  byOid[O("issuerAltName")] = altName;
  byOid[O("extKeyUsage")] = extKeyUsage;
  byOid[O("authorityKeyIdentifier")] = authorityKeyIdentifier;
  byOid[O("subjectKeyIdentifier")] = subjectKeyIdentifier;
  byOid[O("signedCertificateTimestampList")] = sctList;
  byOid[O("precertificatePoison")] = precertPoison;
  return { byOid: byOid };
}

// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
// extnValue OCTET STRING }. `critical` is a universal BOOLEAN present-by-count
// (not context-tagged), so the per-extension decode handles the 2-vs-3-child
// shape directly; the seqOf centralizes the SEQUENCE / SIZE(1..MAX) assertion
// and the RFC 5280 sec. 4.2 per-OID uniqueness.
function extension(ns) {
  return schema.decode(function (ext) {
    // Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue } -- a
    // UNIVERSAL SEQUENCE of exactly 2 (critical omitted) or 3 children. A
    // context-tagged item (e.g. [5]{OID, OCTET STRING}) or a wrong child count
    // is malformed; assert the tag, don't just count children (fail closed).
    if (!ext.children || ext.tagClass !== "universal" || ext.tagNumber !== asn1.TAGS.SEQUENCE ||
        ext.children.length < 2 || ext.children.length > 3) {
      throw ns.E(ns.prefix + "/bad-extension", "Extension must be a SEQUENCE of {extnID, critical?, extnValue}");
    }
    var extnID = asn1.read.oid(ext.children[0]);
    var critical = false, valueNode;
    if (ext.children.length === 3) {
      critical = asn1.read.boolean(ext.children[1]);
      // critical is BOOLEAN DEFAULT FALSE -- DER omits the field when false, so an
      // explicitly-encoded FALSE is a non-canonical form; reject it fail-closed.
      if (critical === false) throw ns.E(ns.prefix + "/bad-extension", "an explicit critical FALSE must be omitted (BOOLEAN DEFAULT FALSE)");
      valueNode = ext.children[2];
    } else {
      valueNode = ext.children[1];
    }
    return { oid: extnID, name: ns.oid.name(extnID) || null, critical: critical, value: asn1.read.octetString(valueNode) };
  });
}
// opts.implicitTag (optional): read Extensions as a [tag] IMPLICIT SEQUENCE OF
// Extension -- the context tag REPLACES the universal SEQUENCE tag, for the CRMF
// CertTemplate extensions [9] (RFC 4211 sec. 5). With no opts the shape is a bare
// universal SEQUENCE OF, byte-identical to every existing caller.
function extensions(ns, opts) {
  opts = opts || {};
  var EXT = extension(ns);
  var extOpts = {
    min: 1, code: ns.prefix + "/bad-extensions", what: "Extensions",
    unique: function (it) { return it.value.oid; }, dupCode: ns.prefix + "/duplicate-extension",
    build: function (m) { return m.items.map(function (it) { return it.value; }); },
  };
  if (opts.implicitTag != null) return schema.implicitSeqOf(opts.implicitTag, EXT, extOpts);
  return schema.seqOf(EXT, Object.assign({ assert: "sequence" }, extOpts));
}

// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
// subjectPublicKey BIT STRING } (RFC 5280 sec. 4.1.2.7, RFC 2986 sec. 4.1). Asserted as a
// universal SEQUENCE -- a context-tagged or SET-tagged constructed node carrying
// two well-formed children is NOT a SubjectPublicKeyInfo. Shared by the
// certificate and CSR parsers.
// opts.implicitTag (optional): read the SubjectPublicKeyInfo as a [tag] IMPLICIT
// SEQUENCE (a context-class constructed node whose children are algorithm +
// subjectPublicKey), for the CRMF CertTemplate publicKey [6] (RFC 4211 sec. 5). With no
// opts the shape is a universal SEQUENCE, byte-identical to every existing caller.
function spki(ns, opts) {
  opts = opts || {};
  return schema.seq([
    schema.field("algorithm", algorithmIdentifier(ns)),
    schema.field("subjectPublicKey", schema.bitString()),
  ], {
    assert: opts.implicitTag != null ? "implicit" : "sequence", implicitTag: opts.implicitTag,
    arity: { exact: 2 }, code: ns.prefix + "/bad-spki", what: "SubjectPublicKeyInfo",
    build: function (m) {
      return {
        algorithm: m.fields.algorithm.value.result,
        publicKey: { unusedBits: m.fields.subjectPublicKey.value.unusedBits, bytes: m.fields.subjectPublicKey.value.bytes },
        // `bytes` is the importable SubjectPublicKeyInfo DER. In IMPLICIT [tag]
        // mode the wire node leads with the context tag, so recover the SEQUENCE
        // encoding a consumer imports / hashes rather than the [tag] wire form.
        bytes: opts.implicitTag != null ? asn1.sequenceTlv(m.node) : m.node.bytes,
      };
    },
  });
}

// Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF AttributeValue }.
// AttributeValue is ANY, kept as raw DER (node.bytes) -- an unrecognized attribute
// type never fails the parse. values is SET SIZE (1..MAX) by default: an empty SET
// is rejected; there is NO SET-OF uniqueness. Shared by the CSR (requested
// attributes, RFC 2986 sec. 4.1) and PKCS#8 (private-key attributes, RFC 5958 sec. 2).
// opts.minValues (default 1) lowers the floor to 0 for the EST CsrAttrs key-type
// hints, whose empty values SET means "any key of this type" (RFC 9908 sec. 3.2).
function attribute(ns, opts) {
  opts = opts || {};
  var minValues = opts.minValues === undefined ? 1 : opts.minValues;
  return schema.seq([
    schema.field("type", schema.oidLeaf()),
    schema.field("values", schema.setOf(schema.any(), { assert: "set", min: minValues, max: constants.LIMITS.ATTRIBUTE_MAX_VALUES,
      code: ns.prefix + "/bad-attribute-values", what: "attribute values" })),
  ], {
    assert: "sequence", arity: { exact: 2 }, code: ns.prefix + "/bad-attribute", what: "Attribute",
    build: function (m, ctx) {
      var t = m.fields.type.value;
      return {
        type: t,
        name: ctx.oid.name(t) || null,
        values: m.fields.values.value.items.map(function (it) { return it.node.bytes; }),
      };
    },
  });
}

// Certificate, CertificateList, and CertificationRequest share one outer shape:
// SEQUENCE { toBeSigned SEQUENCE, signatureAlgorithm, signatureValue }. This
// returns the first element (the to-be-signed info) when `root` is that
// SEQUENCE-of-exactly-3 whose first child is itself a constructed universal
// SEQUENCE, or null otherwise. Every format's `matches` detector shares this
// preamble, so the signed-envelope shape is recognized in one place and the three
// detectors cannot drift on it (the CRL detector historically omitted the
// tbs-is-universal check this recovers).
function signedEnvelopeTbs(root) {
  if (!schema.isUniversal(root, asn1.TAGS.SEQUENCE)) return null;
  if (!root.children || root.children.length !== 3) return null;
  var tbs = root.children[0];
  if (!tbs.children || !schema.isUniversal(tbs, asn1.TAGS.SEQUENCE)) return null;
  return tbs;
}

// rootSequenceChildren(root, minLen, maxLen) -- the shared root-shape guard the
// format matches() detectors re-inline: returns root.children when root is a
// NON-EMPTY universal SEQUENCE whose child count is within [minLen, maxLen]
// (maxLen optional/Infinity), else null. Sibling of signedEnvelopeTbs.
function rootSequenceChildren(root, minLen, maxLen) {
  if (!schema.isUniversal(root, asn1.TAGS.SEQUENCE) || !root.children) return null;
  var n = root.children.length;
  if (n < (minLen || 0)) return null;
  if (maxLen != null && n > maxLen) return null;
  return root.children;
}

// Every format's `parse` is the shared runParse bound to that format's identity
// (PEM label, error class, error-code prefix, top-level schema). This returns the
// bound parser so a format declares its configuration once and never re-writes the
// coerce -> decode -> walk wrapper. `opts`: { pemLabel, PemError, ErrorClass,
// prefix, what, topSchema, ns }.
// The top-level schema's reject code -- the verdict for a DER that is not this
// structure at all -- is `<prefix>/not-a-<structure>` (x509/not-a-certificate,
// cms/not-a-content-info, ...). Three codes predate that convention and stay
// frozen on the public error-code surface (ocsp/bad-ocsp-response,
// tsp/bad-response, crmf/bad-cert-req-messages); a new format follows the
// not-a-* form, never those precedents.
function makeParser(opts) {
  return function (input) { return runParse(input, opts); };
}

// The X.509 SIGNED{ToBeSigned} macro (RFC 5280 sec. 4.1.1.3): the outer
// SEQUENCE { toBeSigned, signatureAlgorithm AlgorithmIdentifier,
// signatureValue BIT STRING } shared by Certificate, CertificateList and
// CertificationRequest. `tbsSchema` parses the first element; the SEQUENCE-of-3
// shape, the arity, the signature extraction and the raw tbs / outer-signature
// bytes (for the cert/CRL outer==inner agreement check) are owned here once, and
// each format's `opts.build(envelope, ctx)` shapes its own object from the
// envelope. A CSR's build simply omits the agreement check -- its CRI has no inner
// signature AlgorithmIdentifier -- so the omission is structural, not a copy that
// forgot a guard.
// signatureValue is surfaced RAW as { unusedBits, bytes }: for the envelope
// family, octet alignment is a verify-layer rule (path-validate rejects
// unusedBits != 0 for certification paths; an external verifier must do the
// same). A format with no in-tree verify layer (OCSP, CMP protection, CRMF
// POP) instead enforces alignment at parse.
function signedEnvelope(ns, tbsSchema, opts) {
  return schema.seq([
    schema.field("toBeSigned", tbsSchema),
    schema.field("signatureAlgorithm", algorithmIdentifier(ns)),
    schema.field("signatureValue", schema.bitString()),
  ], {
    assert: "sequence", arity: { exact: 3 }, code: opts.code, what: opts.what,
    build: function (m, ctx) {
      var tbsMatch = m.fields.toBeSigned.value;
      var sigBits = m.fields.signatureValue.value;
      return opts.build({
        tbsMatch: tbsMatch,                                    // raw seq-match: .fields.* / .result / .node
        tbsBytes: tbsMatch.node.bytes,                         // the exact signed region
        outerSignatureAlgorithmBytes: m.fields.signatureAlgorithm.node.bytes,
        signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
        signatureValue: { unusedBits: sigBits.unusedBits, bytes: sigBits.bytes },
      }, ctx);
    },
  });
}

module.exports = {
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  coerceToDer: coerceToDer,
  decodeRoot: decodeRoot,
  runParse: runParse,
  makeNS: makeNS,
  versionReader: versionReader,
  DN_SHORT: DN_SHORT,
  time: time,
  algorithmIdentifier: algorithmIdentifier,
  spki: spki,
  makeParser: makeParser,
  signedEnvelopeTbs: signedEnvelopeTbs,
  rootSequenceChildren: rootSequenceChildren,
  assertPolicyQualifiers: assertPolicyQualifiers,
  signedEnvelope: signedEnvelope,
  attrValueToString: attrValueToString,
  attributeTypeAndValue: attributeTypeAndValue,
  relativeDistinguishedName: relativeDistinguishedName,
  name: name,
  generalName: generalName,
  generalNames: generalNames,
  generalizedTime: generalizedTime,
  utf8Text: utf8Text,
  rawNonEmptySequence: rawNonEmptySequence,
  CRL_REASON_NAMES: CRL_REASON_NAMES,
  certExtensionDecoders: certExtensionDecoders,
  attribute: attribute,
  extension: extension,
  extensions: extensions,
};

