// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.tsp
 * @nav        Schema
 * @title      TSP
 * @order      170
 * @slug       tsp
 *
 * @intro
 *   RFC 3161 Time-Stamp Protocol handling. A `TimeStampResp` is what a client
 *   receives from a TSA — a `PKIStatusInfo` plus, on success, a `TimeStampToken`;
 *   `parse` decodes it and enforces the status-to-token coupling (a granted
 *   response carries a token, a rejection does not). A `TimeStampToken` is itself a
 *   CMS SignedData whose encapsulated content is a `TSTInfo`, so `parseToken`
 *   composes the CMS parser, asserts the `id-ct-TSTInfo` content type and the
 *   single-signer rule, and decodes the inner `TSTInfo`. `parseTstInfo` decodes a
 *   bare `TSTInfo` payload directly.
 *
 *   The parser surfaces everything a verifier needs and interprets nothing it
 *   cannot: `messageImprint.hashAlgorithm` and the raw `hashedMessage`, the
 *   `genTime` (with sub-second precision), the `serialNumber` and `nonce` (lossless,
 *   as BigInt + hex), and the `policy`. The imprint-to-request and nonce-to-request
 *   round-trips, the ESS signing-certificate binding, the timestamping EKU, and the
 *   signature are verification-layer concerns above parse altitude. DER-only,
 *   fail-closed.
 *
 * @card
 *   Parse DER / PEM RFC 3161 timestamp responses and tokens — per-response status,
 *   the TSTInfo payload (imprint, genTime, serial, nonce, accuracy), raw verifier
 *   inputs, single-signer token composition over CMS, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var cms = require("./schema-cms");
var frameworkError = require("./framework-error");

var TspError = frameworkError.TspError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("tsp", TspError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var EXTENSION = pkix.extension(NS);

// TSTInfo.version is INTEGER { v1(1) } — the only legal value is 1.
var VERSION = pkix.versionReader(NS, { "1": 1 });

// id-ct-TSTInfo is the eContentType that identifies a timestamp token (RFC 3161
// §2.4.2); resolved from the registry, never a dotted literal.
var OID_TST_INFO = oid.byName("tSTInfo");

var TAGS = asn1.TAGS;

// PKIFailureInfo ::= BIT STRING NamedBitList (RFC 3161 §2.4.2). bit 0 is the MSB of
// the first content octet; a set bit outside the named set is surfaced by index.
var FAILURE_BITS = {
  0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable",
  15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure",
};

// ---- shared leaves ---------------------------------------------------

// GeneralizedTime-only leaf. RFC 3161 §2.4.2 requires genTime to be GeneralizedTime,
// never UTCTime; assert the tag before the (fractional-capable) codec read.
var GEN_TIME = schema.decode(function (n, ctx) {
  if (n.tagClass !== "universal" || n.tagNumber !== TAGS.GENERALIZED_TIME) {
    throw ctx.E("tsp/bad-gentime", "genTime must be a GeneralizedTime (RFC 3161 §2.4.2)");
  }
  // RFC 3161 genTime may carry sub-second precision (X.690 §11.7 fractional profile).
  return asn1.read.time(n, { allowFractional: true });
});

// tsa [0] EXPLICIT GeneralName (RFC 3161 §2.4.2) — validated + surfaced raw via the
// shared pkix.generalName primitive (RFC 5280 §4.2.1.6), which checks the chosen
// alternative's form and content so a malformed GeneralName fails closed.
var GENERAL_NAME_RAW = pkix.generalName(NS, { code: "tsp/bad-tsa" });

// A PKIFreeText element MUST be a UTF8String (RFC 3161 §2.4.2).
var UTF8_TEXT = schema.decode(function (n, ctx) {
  if (n.tagClass !== "universal" || n.tagNumber !== TAGS.UTF8_STRING) {
    throw ctx.E("tsp/bad-status-info", "PKIFreeText elements must be UTF8String");
  }
  return asn1.read.string(n);
});

// ---- MessageImprint --------------------------------------------------

// MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage
// OCTET STRING } (RFC 3161 §2.4.1). hashedMessage is a digest — surfaced RAW.
var MESSAGE_IMPRINT = schema.seq([
  schema.field("hashAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("hashedMessage", schema.octetString()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "tsp/bad-message-imprint", what: "MessageImprint",
  build: function (m) {
    return { hashAlgorithm: m.fields.hashAlgorithm.value.result, hashedMessage: m.fields.hashedMessage.value };
  },
});

// ---- Accuracy --------------------------------------------------------

// Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] IMPLICIT INTEGER
// (1..999) OPTIONAL, micros [1] IMPLICIT INTEGER (1..999) OPTIONAL } (RFC 3161
// §2.4.2). Every sub-field is optional; a missing one defaults to 0.
var ACCURACY = schema.seq([
  schema.optional("seconds", schema.integerLeaf(), { whenUniversal: [TAGS.INTEGER] }),
  schema.trailing([
    { tag: 0, name: "millis", schema: schema.implicitInteger(0) },
    { tag: 1, name: "micros", schema: schema.implicitInteger(1) },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "tsp/bad-accuracy", orderCode: "tsp/bad-accuracy" }),
], {
  assert: "sequence", code: "tsp/bad-accuracy", what: "Accuracy",
  build: function (m) {
    function sub(f) {
      if (!f.present) return 0;
      var v = f.value;
      // millis / micros are constrained to 1..999 (RFC 3161 §2.4.2); 0 is also
      // excluded (and non-canonical for a positive count).
      if (v < 1n || v > 999n) throw NS.E("tsp/bad-accuracy", "Accuracy millis/micros must be in 1..999");
      return Number(v);
    }
    return {
      // seconds is an unbounded INTEGER — keep it lossless as a BigInt (millis /
      // micros are constrained to 1..999, so Number is exact for those).
      seconds: m.fields.seconds.present ? m.fields.seconds.value : 0n,
      millis: sub(m.fields.millis),
      micros: sub(m.fields.micros),
    };
  },
});

// ---- TSTInfo ---------------------------------------------------------

// TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
// accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] EXPLICIT
// GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL } (RFC 3161
// §2.4.2). The five mandatory fields come first; the optionals are consumed by tag.
var TST_INFO = schema.seq([
  schema.field("version", VERSION),
  schema.field("policy", schema.oidLeaf()),
  schema.field("messageImprint", MESSAGE_IMPRINT),
  schema.field("serialNumber", schema.integerLeaf()),
  schema.field("genTime", GEN_TIME),
  schema.optional("accuracy", ACCURACY, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.optional("ordering", schema.boolean(), { whenUniversal: [TAGS.BOOLEAN] }),
  schema.optional("nonce", schema.integerLeaf(), { whenUniversal: [TAGS.INTEGER] }),
  schema.trailing([
    { tag: 0, name: "tsa", schema: GENERAL_NAME_RAW, explicit: true, emptyCode: "tsp/bad-tsa" },
    { tag: 1, name: "extensions", schema: schema.implicitSeqOf(1, EXTENSION, { min: 1, unique: function (it) { return it.value.oid; }, dupCode: "tsp/duplicate-extension", code: "tsp/bad-extensions", what: "extensions" }) },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "tsp/bad-tst-info", orderCode: "tsp/bad-tst-info" }),
], {
  assert: "sequence", code: "tsp/bad-tst-info", what: "TSTInfo",
  build: function (m, ctx) {
    // ordering BOOLEAN DEFAULT FALSE — an explicit FALSE must be omitted (DER).
    if (m.fields.ordering.present && m.fields.ordering.value === false) {
      throw NS.E("tsp/bad-ordering", "ordering is BOOLEAN DEFAULT FALSE — an explicit FALSE must be omitted");
    }
    var policy = m.fields.policy.value;
    var tsa = m.fields.tsa;
    return {
      version: m.fields.version.value,
      policy: policy,
      policyName: ctx.oid.name(policy) || null,
      messageImprint: m.fields.messageImprint.value.result,
      serialNumber: m.fields.serialNumber.value,
      serialNumberHex: m.fields.serialNumber.node.content.toString("hex"),
      genTime: m.fields.genTime.value,
      // genTime is surfaced as a millisecond-precision Date; genTimeFraction is the
      // exact fractional-seconds digits (lossless for sub-millisecond precision), or
      // null when genTime carries no fraction.
      genTimeFraction: (function () { var g = /\.(\d+)Z$/.exec(m.fields.genTime.node.content.toString("latin1")); return g ? g[1] : null; })(),
      accuracy: m.fields.accuracy.present ? m.fields.accuracy.value.result : null,
      ordering: m.fields.ordering.present ? m.fields.ordering.value : false,
      nonce: m.fields.nonce.present ? m.fields.nonce.value : null,
      nonceHex: m.fields.nonce.present ? m.fields.nonce.node.content.toString("hex") : null,
      tsa: tsa.present ? tsa.value : null,
      extensions: m.fields.extensions.present ? m.fields.extensions.value.items.map(function (it) { return it.value; }) : null,
    };
  },
});

// ---- PKIStatusInfo / TimeStampResp -----------------------------------

// PKIStatusInfo ::= SEQUENCE { status PKIStatus (INTEGER), statusString PKIFreeText
// OPTIONAL, failInfo PKIFailureInfo OPTIONAL } (RFC 3161 §2.4.2, from RFC 4210).
var PKI_STATUS_INFO = schema.seq([
  schema.field("status", schema.integerLeaf()),
  schema.optional("statusString", schema.seqOf(UTF8_TEXT, { assert: "sequence", min: 1, code: "tsp/bad-status-info", what: "statusString" }), { whenUniversal: [TAGS.SEQUENCE] }),
  schema.optional("failInfo", schema.bitString(), { whenUniversal: [TAGS.BIT_STRING] }),
], {
  assert: "sequence", code: "tsp/bad-status-info", what: "PKIStatusInfo",
  build: function (m) {
    var status = m.fields.status.value;
    // PKIStatus ::= INTEGER { granted(0) .. revocationNotification(5) }.
    if (status < 0n || status > 5n) throw NS.E("tsp/bad-status", "PKIStatus " + status + " is outside 0..5 (RFC 3161 §2.4.2)");
    var failInfo = null;
    if (m.fields.failInfo.present) {
      var bs = m.fields.failInfo.value;
      _assertMinimalNamedBits(bs.unusedBits, bs.bytes);
      failInfo = { unusedBits: bs.unusedBits, bytes: bs.bytes, bits: _namedBits(bs.bytes) };
    }
    return {
      status: Number(status),
      statusString: m.fields.statusString.present ? m.fields.statusString.value.items.map(function (it) { return it.value; }) : null,
      failInfo: failInfo,
    };
  },
});

// X.690 §11.2.2 — a BIT STRING typed with a NamedBitList (PKIFailureInfo) MUST have
// all trailing 0 bits removed under DER: no trailing all-zero content octet, and the
// declared unusedBits must sit exactly below the lowest set bit of the last octet (so
// the encoding is minimal). The empty value encodes as 0 content octets, 0 unusedBits.
function _assertMinimalNamedBits(unusedBits, bytes) {
  if (bytes.length === 0) {
    if (unusedBits !== 0) throw NS.E("tsp/bad-failinfo", "an empty PKIFailureInfo must encode with 0 unused bits (X.690 §11.2.2)");
    return;
  }
  var last = bytes[bytes.length - 1];
  if (last === 0) throw NS.E("tsp/bad-failinfo", "PKIFailureInfo NamedBitList must not have a trailing all-zero octet (X.690 §11.2.2)");
  if (((last >> unusedBits) & 1) !== 1) throw NS.E("tsp/bad-failinfo", "PKIFailureInfo NamedBitList must have all trailing zero bits removed (X.690 §11.2.2)");
}

// Decode the set NamedBitList bits to their RFC 3161 names (bit 0 = MSB of byte 0).
// A set bit outside the defined set is an unsupported PKIFailureInfo value — a client
// MUST error on a failInfo it does not understand (RFC 3161 §2.4.2), so reject it
// rather than surfacing an opaque "bitN".
function _namedBits(bytes) {
  var out = [];
  for (var i = 0; i < bytes.length * 8; i++) {
    if ((bytes[i >> 3] >> (7 - (i & 7))) & 1) {
      var nm = FAILURE_BITS[i];
      if (!nm) throw NS.E("tsp/bad-failinfo", "unsupported PKIFailureInfo bit " + i + " (RFC 3161 §2.4.2)");
      out.push(nm);
    }
  }
  return out;
}

// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken
// OPTIONAL } (RFC 3161 §2.4.2). There is NO version field. The token is a CMS
// ContentInfo, decoded via cms.parse; the status-to-token coupling is load-bearing.
var TIME_STAMP_RESP = schema.seq([
  schema.field("status", PKI_STATUS_INFO),
  schema.optional("timeStampToken", schema.any(), { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 1 }, code: "tsp/bad-response", what: "TimeStampResp",
  build: function (m) {
    var status = m.fields.status.value.result;
    var present = m.fields.timeStampToken.present;
    // RFC 3161 §2.4.2 — granted / grantedWithMods carry a token; any other status
    // (rejection / waiting / revocation*) MUST NOT.
    var granted = status.status === 0 || status.status === 1;
    if (granted && !present) throw NS.E("tsp/missing-token", "a granted TimeStampResp must carry a timeStampToken (RFC 3161 §2.4.2)");
    if (!granted && present) throw NS.E("tsp/unexpected-token", "a non-granted TimeStampResp must not carry a timeStampToken (RFC 3161 §2.4.2)");
    // failInfo is the reason a request was rejected, so it is present ONLY when the
    // status is rejection(2) — not on granted(0/1) nor on waiting / revocation* (3/4/5).
    if (status.status !== 2 && status.failInfo) throw NS.E("tsp/unexpected-failinfo", "failInfo is present only when the status is rejection(2) (RFC 3161 §2.4.2)");
    // A granted response's timeStampToken MUST be a well-formed TimeStampToken —
    // decode it (composing the CMS parser) rather than surfacing arbitrary SEQUENCE
    // bytes as a token; a malformed token fails the response parse.
    return {
      status: status.status,
      statusString: status.statusString,
      failInfo: status.failInfo,
      timeStampToken: present ? parseToken(m.fields.timeStampToken.value.bytes) : null,
    };
  },
});

/**
 * @primitive  pki.schema.tsp.parseTstInfo
 * @signature  pki.schema.tsp.parseTstInfo(input) -> tstInfo
 * @since      0.1.13
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.schema.tsp.parseToken, pki.schema.tsp.parse
 *
 * Parse a bare `TSTInfo` payload (a DER `Buffer`) — the structure a timestamp token
 * encapsulates — into `{ version, policy, messageImprint, serialNumber, genTime,
 * accuracy, ordering, nonce, tsa, extensions }`. `messageImprint.hashedMessage` is
 * the raw digest; `serialNumber` / `nonce` are lossless (BigInt + hex); `genTime` is
 * a `Date` with sub-second precision. A malformed structure throws a typed
 * `TspError` (`tsp/*`); a leaf-level codec fault surfaces as `asn1/*`.
 *
 * @example
 *   var tst = pki.schema.tsp.parseTstInfo(der);
 *   tst.genTime;                       // -> Date
 *   tst.messageImprint.hashedMessage;  // -> Buffer (the raw digest)
 */
var parseTstInfo = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp", what: "TSTInfo", topSchema: TST_INFO, ns: NS });

/**
 * @primitive  pki.schema.tsp.parse
 * @signature  pki.schema.tsp.parse(input) -> timeStampResp
 * @since      0.1.13
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.schema.tsp.parseToken, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM string into a `TimeStampResp`: `{ status,
 * statusString, failInfo, timeStampToken }`. The status-to-token coupling is
 * enforced — a granted response (status 0/1) carries `timeStampToken` (surfaced raw
 * for `parseToken`), any other status does not. `failInfo` decodes the
 * `PKIFailureInfo` named bits. A malformed structure throws a typed `TspError`.
 *
 * @example
 *   var res = pki.schema.tsp.parse(der);
 *   res.status;                        // -> 0 (granted)
 *   pki.schema.tsp.parseToken(res.timeStampToken);
 */
var parse = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp", what: "TimeStampResp", topSchema: TIME_STAMP_RESP, ns: NS });

/**
 * @primitive  pki.schema.tsp.parseToken
 * @signature  pki.schema.tsp.parseToken(input) -> tstInfo
 * @since      0.1.13
 * @status     experimental
 * @spec       RFC 3161, RFC 5652
 * @related    pki.schema.tsp.parse, pki.schema.cms.parse
 *
 * Parse a `TimeStampToken` (a DER `Buffer` or PEM) — a CMS SignedData whose
 * encapsulated content is a `TSTInfo`. Composes `pki.schema.cms.parse`, asserts the
 * `id-ct-TSTInfo` content type (`tsp/wrong-econtent-type`), that the content is
 * attached (`tsp/detached-token`), and the single-signer rule (`tsp/multi-signer`,
 * RFC 3161 §2.4.2), then decodes the inner `TSTInfo`. Returns `{ tstInfo, eContent,
 * signerInfo, certificates }` — the decoded payload, the raw eContent bytes a verifier
 * hashes for the CMS message-digest, and the CMS signer material.
 *
 * @example
 *   var token = pki.schema.tsp.parseToken(tokenDer);
 *   token.tstInfo.genTime;   // -> Date
 *   token.signerInfo.sid;    // -> the TSA signer identifier
 */
function parseToken(input) {
  // De-armor with TSP's label-agnostic PEM rules first (RFC 3161 has no standard
  // label), THEN hand DER to the CMS parser — otherwise cms.parse would reject any
  // PEM block not labeled "CMS" before the TSP checks run.
  var der = pkix.coerceToDer(input, { pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp" });
  // Wrap the CMS decode so tsp.parse / parseToken keep their typed-TspError contract —
  // a malformed token surfaces tsp/bad-token, not a bare cms/* error.
  var signed;
  try { signed = cms.parse(der); }
  catch (e) {
    if (e instanceof TspError) throw e;
    throw new TspError("tsp/bad-token", "the timeStampToken did not decode as a CMS SignedData: " + ((e && e.message) || String(e)), e);
  }
  var encap = signed.encapContentInfo;
  if (encap.eContentType !== OID_TST_INFO) {
    throw new TspError("tsp/wrong-econtent-type", "a TimeStampToken must encapsulate id-ct-TSTInfo, got " + encap.eContentType);
  }
  if (encap.eContent === null) throw new TspError("tsp/detached-token", "a TimeStampToken must carry attached eContent (RFC 3161 §2.4.2)");
  if (signed.signerInfos.length !== 1) {
    throw new TspError("tsp/multi-signer", "a TimeStampToken must contain exactly one (TSA) signerInfo (RFC 3161 §2.4.2)");
  }
  var tstInfo;
  try { tstInfo = schema.walk(TST_INFO, asn1.decode(encap.eContent), NS); }
  catch (e) {
    if (e instanceof TspError) throw e;
    throw new TspError("tsp/bad-der", "the encapsulated TSTInfo did not decode: " + ((e && e.message) || String(e)), e);
  }
  // Surface the RAW eContent (the exact DER a verifier hashes for the CMS
  // message-digest signed attribute) alongside the decoded TSTInfo — a re-serialized
  // tstInfo may not byte-match, so the raw bytes are the verification feed.
  return { tstInfo: tstInfo.result, eContent: encap.eContent, signerInfo: signed.signerInfos[0], certificates: signed.certificates };
}

/**
 * @primitive  pki.schema.tsp.pemDecode
 * @signature  pki.schema.tsp.pemDecode(text, label?) -> Buffer
 * @since      0.1.13
 * @status     experimental
 * @spec       RFC 7468, RFC 3161
 * @related    pki.schema.tsp.parse
 *
 * Extract the DER bytes from a PEM block (RFC 3161 defines no standard label, so the
 * first block is taken unless `label` is given). Throws `PemError` on a missing
 * envelope or a non-base64 body.
 *
 * @example
 *   var der = pki.schema.tsp.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || null, PemError); }

// A TimeStampResp root is a SEQUENCE of 1-2 whose first child is a PKIStatusInfo (a
// SEQUENCE whose own first child is an INTEGER status). Disjoint from the OID-first
// CMS ContentInfo, the INTEGER-first PKCS#8 key, and the exactly-3 signed-envelope
// trio, so it detects unambiguously regardless of registry order.
function matches(root) {
  if (!root || root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE || !root.children) return false;
  var k = root.children;
  if (k.length < 1 || k.length > 2) return false;
  var si = k[0];
  if (!(si.tagClass === "universal" && si.tagNumber === TAGS.SEQUENCE && si.children && si.children.length >= 1)) return false;
  if (!(si.children[0].tagClass === "universal" && si.children[0].tagNumber === TAGS.INTEGER)) return false;
  if (k.length === 2 && !(k[1].tagClass === "universal" && k[1].tagNumber === TAGS.SEQUENCE)) return false;
  return true;
}

module.exports = {
  parse: parse,
  parseTstInfo: parseTstInfo,
  parseToken: parseToken,
  pemDecode: pemDecode,
  matches: matches,
};
