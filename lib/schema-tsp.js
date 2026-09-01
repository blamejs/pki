// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.tsp
 * @nav        Schema
 * @title      TSP
 * @fullname   RFC 3161 timestamps (TSP): request, sign and verify
 * @order      170
 * @slug       tsp
 *
 * @intro
 *   RFC 3161 Time-Stamp Protocol handling. A `TimeStampResp` is what a client
 *   receives from a TSA -- a `PKIStatusInfo` plus, on success, a `TimeStampToken`;
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
 *   as BigInt + hex), and the `policy`. The PRESENCE of the ESS
 *   SigningCertificate(V2) attribute is asserted at parse (a structural token
 *   property); the imprint-to-request and nonce-to-request round-trips, the ESS
 *   hash-vs-certificate binding, the timestamping EKU, and the signature are
 *   verification-layer concerns above parse altitude. DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM RFC 3161 timestamp responses and tokens: per-response status,
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

var VERSION = pkix.versionReader(NS, { "1": 1 });

var OID_TST_INFO = oid.byName("tSTInfo");

var OID_SIGNING_CERT = oid.byName("signingCertificate");
var OID_SIGNING_CERT_V2 = oid.byName("signingCertificateV2");

var TAGS = asn1.TAGS;

var FAILURE_BITS = {
  0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable",
  15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure",
};


var GEN_TIME = pkix.generalizedTime(NS, { code: "tsp/bad-gentime", message: "genTime must be a GeneralizedTime (RFC 3161 sec. 2.4.2)", allowFractional: true });

var GENERAL_NAME_RAW = pkix.generalName(NS, { code: "tsp/bad-tsa" });

var UTF8_TEXT = pkix.utf8Text(NS, { code: "tsp/bad-status-info", message: "PKIFreeText elements must be UTF8String" });


var MESSAGE_IMPRINT = schema.seq([
  schema.field("hashAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("hashedMessage", schema.octetString()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "tsp/bad-message-imprint", what: "MessageImprint",
  build: function (m) {
    return { hashAlgorithm: m.fields.hashAlgorithm.value.result, hashedMessage: m.fields.hashedMessage.value };
  },
});


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
      if (v < 1n || v > 999n) throw NS.E("tsp/bad-accuracy", "Accuracy millis/micros must be in 1..999");
      return Number(v);
    }
    if (m.fields.seconds.present && m.fields.seconds.value < 0n) {
      throw NS.E("tsp/bad-accuracy", "Accuracy seconds must not be negative (RFC 3161 sec. 2.4.2)");
    }
    return {
      seconds: m.fields.seconds.present ? m.fields.seconds.value : 0n,
      millis: sub(m.fields.millis),
      micros: sub(m.fields.micros),
    };
  },
});


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
    if (m.fields.ordering.present && m.fields.ordering.value === false) {
      throw NS.E("tsp/bad-ordering", "ordering is BOOLEAN DEFAULT FALSE -- an explicit FALSE must be omitted");
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
      genTimeFraction: (function () {
        var s = m.fields.genTime.node.content.toString("latin1"), n = s.length;
        if (n < 3 || s.charAt(n - 1) !== "Z") return null;
        var dot = s.lastIndexOf(".");
        if (dot < 0 || dot > n - 3) return null;
        var frac = s.slice(dot + 1, n - 1);
        for (var fi = 0; fi < frac.length; fi++) { var cc = frac.charCodeAt(fi); if (cc < 48 || cc > 57) return null; }
        return frac;
      })(),
      accuracy: m.fields.accuracy.present ? m.fields.accuracy.value.result : null,
      ordering: m.fields.ordering.present ? m.fields.ordering.value : false,
      nonce: m.fields.nonce.present ? m.fields.nonce.value : null,
      nonceHex: m.fields.nonce.present ? m.fields.nonce.node.content.toString("hex") : null,
      tsa: tsa.present ? tsa.value : null,
      extensions: m.fields.extensions.present ? m.fields.extensions.value.items.map(function (it) { return it.value; }) : null,
    };
  },
});


var PKI_STATUS_INFO = schema.seq([
  schema.field("status", schema.integerLeaf()),
  schema.optional("statusString", schema.seqOf(UTF8_TEXT, { assert: "sequence", min: 1, code: "tsp/bad-status-info", what: "statusString" }), { whenUniversal: [TAGS.SEQUENCE] }),
  schema.optional("failInfo", schema.bitString(), { whenUniversal: [TAGS.BIT_STRING] }),
], {
  assert: "sequence", code: "tsp/bad-status-info", what: "PKIStatusInfo",
  build: function (m) {
    var status = m.fields.status.value;
    if (status < 0n || status > 5n) throw NS.E("tsp/bad-status", "PKIStatus " + status + " is outside 0..5 (RFC 3161 sec. 2.4.2)");
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

function _assertMinimalNamedBits(unusedBits, bytes) {
  schema.assertMinimalNamedBits(unusedBits, bytes, function (m) { throw NS.E("tsp/bad-failinfo", m); });
}

function _namedBits(bytes) {
  var out = [];
  for (var i = 0; i < bytes.length * 8; i++) {
    if ((bytes[i >> 3] >> (7 - (i & 7))) & 1) {
      var nm = FAILURE_BITS[i];
      if (!nm) throw NS.E("tsp/bad-failinfo", "unsupported PKIFailureInfo bit " + i + " (RFC 3161 sec. 2.4.2)");
      out.push(nm);
    }
  }
  return out;
}

var TIME_STAMP_RESP = schema.seq([
  schema.field("status", PKI_STATUS_INFO),
  schema.optional("timeStampToken", schema.any(), { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 1 }, code: "tsp/bad-response", what: "TimeStampResp",
  build: function (m) {
    var status = m.fields.status.value.result;
    var present = m.fields.timeStampToken.present;
    var granted = status.status === 0 || status.status === 1;
    if (granted && !present) throw NS.E("tsp/missing-token", "a granted TimeStampResp must carry a timeStampToken (RFC 3161 sec. 2.4.2)");
    if (!granted && present) throw NS.E("tsp/unexpected-token", "a non-granted TimeStampResp must not carry a timeStampToken (RFC 3161 sec. 2.4.2)");
    if (status.status !== 2 && status.failInfo) throw NS.E("tsp/unexpected-failinfo", "failInfo is present only when the status is rejection(2) (RFC 3161 sec. 2.4.2)");
    return {
      status: status.status,
      statusString: status.statusString,
      failInfo: status.failInfo,
      timeStampToken: present ? parseToken(m.fields.timeStampToken.value.bytes) : null,
    };
  },
});


var TIME_STAMP_REQ = schema.seq([
  schema.field("version", VERSION),
  schema.field("messageImprint", MESSAGE_IMPRINT),
  schema.optional("reqPolicy", schema.oidLeaf(), { whenUniversal: [TAGS.OBJECT_IDENTIFIER] }),
  schema.optional("nonce", schema.integerLeaf(), { whenUniversal: [TAGS.INTEGER] }),
  schema.optional("certReq", schema.boolean(), { whenUniversal: [TAGS.BOOLEAN] }),
  schema.trailing([
    { tag: 0, name: "extensions", schema: schema.implicitSeqOf(0, EXTENSION, { min: 1, unique: function (it) { return it.value.oid; }, dupCode: "tsp/duplicate-extension", code: "tsp/bad-extensions", what: "extensions" }) },
  ], { minTag: 0, maxTag: 0, unexpectedCode: "tsp/bad-request", orderCode: "tsp/bad-request" }),
], {
  assert: "sequence", code: "tsp/bad-request", what: "TimeStampReq",
  build: function (m, ctx) {
    if (m.fields.certReq.present && m.fields.certReq.value === false) {
      throw NS.E("tsp/bad-request", "certReq is BOOLEAN DEFAULT FALSE -- an explicit FALSE must be omitted (DER)");
    }
    var reqPolicy = m.fields.reqPolicy.present ? m.fields.reqPolicy.value : null;
    return {
      version: m.fields.version.value,
      messageImprint: m.fields.messageImprint.value.result,
      reqPolicy: reqPolicy,
      reqPolicyName: reqPolicy ? (ctx.oid.name(reqPolicy) || null) : null,
      nonce: m.fields.nonce.present ? m.fields.nonce.value : null,
      nonceHex: m.fields.nonce.present ? m.fields.nonce.node.content.toString("hex") : null,
      certReq: m.fields.certReq.present ? m.fields.certReq.value : false,
      extensions: m.fields.extensions.present ? m.fields.extensions.value.items.map(function (it) { return it.value; }) : null,
    };
  },
});

/**
 * @primitive  pki.schema.tsp.parseRequest
 * @signature  pki.schema.tsp.parseRequest(input) -> timeStampReq
 * @since      0.2.19
 * @status     stable
 * @spec       RFC 3161
 * @related    pki.schema.tsp.parse, pki.tsp.request
 *
 * Parse a DER `Buffer` or PEM string into a `TimeStampReq` (RFC 3161 sec. 2.4.1):
 * `{ version, messageImprint, reqPolicy, reqPolicyName, nonce, nonceHex, certReq, extensions }`.
 * `version` MUST be 1; `certReq` is BOOLEAN DEFAULT FALSE (an explicit FALSE is non-DER and
 * rejected `tsp/bad-request`); `nonce` is lossless (BigInt + hex); `messageImprint.hashedMessage`
 * is the raw digest. A malformed structure throws a typed `TspError`.
 *
 * @example
 *   var der = pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { certReq: true });
 *   var req = pki.schema.tsp.parseRequest(der);
 *   req.certReq;                        // -> boolean
 *   req.messageImprint.hashedMessage;   // -> Buffer (the raw digest)
 */
var parseRequest = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp", what: "TimeStampReq", topSchema: TIME_STAMP_REQ, ns: NS });

/**
 * @primitive  pki.schema.tsp.parseTstInfo
 * @signature  pki.schema.tsp.parseTstInfo(input) -> tstInfo
 * @since      0.1.13
 * @status     stable
 * @spec       RFC 3161
 * @related    pki.schema.tsp.parseToken, pki.schema.tsp.parse
 *
 * Parse a bare `TSTInfo` payload (a DER `Buffer`) -- the structure a timestamp token
 * encapsulates -- into `{ version, policy, messageImprint, serialNumber, genTime,
 * accuracy, ordering, nonce, tsa, extensions }`. `messageImprint.hashedMessage` is
 * the raw digest; `serialNumber` / `nonce` are lossless (BigInt + hex); `genTime` is
 * a `Date` with sub-second precision. A malformed structure throws a typed
 * `TspError` (`tsp/*`); a leaf-level codec fault surfaces as `asn1/*`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var token = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { cert: cert, key: key }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var der = pki.schema.tsp.parseToken(token).eContent;   // the raw TSTInfo the TSA signed
 *   var tst = pki.schema.tsp.parseTstInfo(der);
 *   tst.genTime;                       // -> Date
 *   tst.messageImprint.hashedMessage;  // -> Buffer (the raw digest)
 */
var parseTstInfo = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp", what: "TSTInfo", topSchema: TST_INFO, ns: NS });

/**
 * @primitive  pki.schema.tsp.parse
 * @signature  pki.schema.tsp.parse(input) -> timeStampResp
 * @since      0.1.13
 * @status     stable
 * @spec       RFC 3161
 * @related    pki.schema.tsp.parseToken, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM string into a `TimeStampResp`: `{ status,
 * statusString, failInfo, timeStampToken }`. The status-to-token coupling is
 * enforced -- a granted response (status 0/1) carries `timeStampToken` (surfaced raw
 * for `parseToken`), any other status does not. `failInfo` decodes the
 * `PKIFailureInfo` named bits. A malformed structure throws a typed `TspError`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var token = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { cert: cert, key: key }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var der = pki.tsp.response(token, {});
 *   var res = pki.schema.tsp.parse(der);
 *   res.status;                              // -> 0 (granted)
 *   res.timeStampToken.tstInfo.genTime;      // -> Date (a granted token is decoded)
 */
var parse = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp", what: "TimeStampResp", topSchema: TIME_STAMP_RESP, ns: NS });

/**
 * @primitive  pki.schema.tsp.parseToken
 * @signature  pki.schema.tsp.parseToken(input) -> tstInfo
 * @since      0.1.13
 * @status     stable
 * @spec       RFC 3161, RFC 5652
 * @related    pki.schema.tsp.parse, pki.schema.cms.parse
 *
 * Parse a `TimeStampToken` (a DER `Buffer` or PEM) -- a CMS SignedData whose
 * encapsulated content is a `TSTInfo`. Composes `pki.schema.cms.parse`, asserts the
 * `id-ct-TSTInfo` content type (`tsp/wrong-econtent-type`), that the content is
 * attached (`tsp/detached-token`), the single-signer rule (`tsp/multi-signer`,
 * RFC 3161 sec. 2.4.2), and that the signerInfo carries a SigningCertificate or
 * SigningCertificateV2 signed attribute (`tsp/missing-signing-certificate`,
 * RFC 3161 sec. 2.4.2 / RFC 5816; the hash-vs-certificate binding stays a
 * verification-layer concern), then decodes the inner `TSTInfo`. Returns
 * `{ tstInfo, eContent, signerInfo, certificates }`: the decoded payload, the raw
 * eContent bytes a verifier hashes for the CMS message-digest, and the CMS signer
 * material.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var tokenDer = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { cert: cert, key: key }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var token = pki.schema.tsp.parseToken(tokenDer);
 *   token.tstInfo.genTime;   // -> Date
 *   token.signerInfo.sid;    // -> the TSA signer identifier
 */
function parseToken(input) {
  var der = pkix.coerceToDer(input, { pemLabel: null, PemError: PemError, ErrorClass: TspError, prefix: "tsp" });
  var signed;
  try { signed = cms.parse(der); }
  catch (e) {
    if (e instanceof TspError) throw e;
    throw new TspError("tsp/bad-token", "the timeStampToken did not decode as a CMS SignedData: " + ((e && e.message) || String(e)), e);
  }
  if (signed.contentTypeName !== "signedData") {
    throw new TspError("tsp/not-signed-data", "a TimeStampToken must be a CMS SignedData, got " + (signed.contentTypeName || signed.contentType));
  }
  var encap = signed.encapContentInfo;
  if (encap.eContentType !== OID_TST_INFO) {
    throw new TspError("tsp/wrong-econtent-type", "a TimeStampToken must encapsulate id-ct-TSTInfo, got " + encap.eContentType);
  }
  if (encap.eContent === null) throw new TspError("tsp/detached-token", "a TimeStampToken must carry attached eContent (RFC 3161 sec. 2.4.2)");
  if (signed.signerInfos.length !== 1) {
    throw new TspError("tsp/multi-signer", "a TimeStampToken must contain exactly one (TSA) signerInfo (RFC 3161 sec. 2.4.2)");
  }
  var signedAttrs = signed.signerInfos[0].signedAttrs || [];
  var hasSigningCert = false;
  for (var a = 0; a < signedAttrs.length; a++) {
    if (signedAttrs[a].type === OID_SIGNING_CERT || signedAttrs[a].type === OID_SIGNING_CERT_V2) { hasSigningCert = true; break; }
  }
  if (!hasSigningCert) {
    throw new TspError("tsp/missing-signing-certificate", "a TimeStampToken signerInfo must carry a SigningCertificate or SigningCertificateV2 signed attribute (RFC 3161 sec. 2.4.2, RFC 5816)");
  }
  var tstInfo;
  try { tstInfo = schema.embeddedDer(TST_INFO, encap.eContent, NS, { code: "tsp/bad-der", what: "the encapsulated TSTInfo" }); }
  catch (e) {
    if (e instanceof TspError) throw e;
    throw new TspError("tsp/bad-der", "the encapsulated TSTInfo did not decode: " + ((e && e.message) || String(e)), e);
  }
  return { tstInfo: tstInfo.result, eContent: encap.eContent, signerInfo: signed.signerInfos[0], certificates: signed.certificates };
}

/**
 * @primitive  pki.schema.tsp.pemDecode
 * @signature  pki.schema.tsp.pemDecode(text, label?) -> Buffer
 * @since      0.1.13
 * @status     stable
 * @spec       RFC 7468, RFC 3161
 * @related    pki.schema.tsp.parse
 *
 * Extract the DER bytes from a PEM block (RFC 3161 defines no standard label, so the
 * first block is taken unless `label` is given). Throws `PemError` on a missing
 * envelope or a non-base64 body.
 *
 * @example
 *   var req = pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) }, {});
 *   var pemText = pki.schema.tsp.pemEncode(req, "TSP REQUEST");
 *   var der = pki.schema.tsp.pemDecode(pemText);
 */
// @internal
function decodeGeneralName(bytes) {
  return schema.embeddedDer(pkix.generalName(NS, { decodeValue: true, code: "tsp/bad-tsa" }), bytes, NS, { code: "tsp/bad-tsa", what: "GeneralName" });
}

function pemDecode(text, label) { return pkix.pemDecode(text, label || null, PemError); }

/**
 * @primitive  pki.schema.tsp.pemEncode
 * @signature  pki.schema.tsp.pemEncode(der, label) -> string
 * @since      0.1.23
 * @status     stable
 * @spec       RFC 7468, RFC 3161
 * @related    pki.schema.tsp.pemDecode
 *
 * Wrap DER bytes in a PEM envelope. RFC 3161 defines no standard PEM label, so
 * `label` is REQUIRED -- the operator names the envelope explicitly (mirroring
 * `pemDecode`, which accepts any label). Omitting it throws `pem/bad-label`.
 *
 * @example
 *   var der = pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) }, {});
 *   var pem = pki.schema.tsp.pemEncode(der, "TSP RESPONSE");
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label, PemError); }

function matches(root) {
  var k = pkix.rootSequenceChildren(root, 1, 2);
  if (!k) return false;
  var si = k[0];
  if (!(schema.isUniversal(si, TAGS.SEQUENCE) && si.children && si.children.length >= 1)) return false;
  if (!schema.isUniversal(si.children[0], TAGS.INTEGER)) return false;
  if (k.length === 2 && !schema.isUniversal(k[1], TAGS.SEQUENCE)) return false;
  return true;
}

module.exports = {
  parse: parse,
  parseResponse: parse,
  parseRequest: parseRequest,
  decodeGeneralName: decodeGeneralName,   // @internal
  parseTstInfo: parseTstInfo,
  parseToken: parseToken,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
};
