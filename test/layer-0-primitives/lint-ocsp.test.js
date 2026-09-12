// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.lint.ocsp: the RFC 6960 response profile and the RFC 5019 lightweight rows.
 * A BasicOCSPResponse is assembled from parts so one clause can be broken while the rest stays
 * conforming; the signature is a placeholder, since linting reads structure and never verifies it.
 * Every row is driven through the SHIPPED pki.lint.ocsp path: the finding id, its severity, the
 * per-response context, the four shapes the strict parser refuses before a rule could run, the
 * profile door shared with the other two lint verbs, and the parsed-object door.
 */

var pki = require("../../index.js");
var asn1 = require("../../lib/asn1-der");
var b = asn1.build;
var oid = require("../../lib/oid");
var helpers = require("../helpers");
var check = helpers.check;

function O(name) { return oid.byName(name); }
function ids(r) { return r.findings.map(function (f) { return f.id; }); }
function hasId(r, id) { return ids(r).indexOf(id) !== -1; }
function sevOf(r, id) { var f = r.findings.filter(function (x) { return x.id === id; })[0]; return f && f.severity; }
function ctxOf(r, id) { var f = r.findings.filter(function (x) { return x.id === id; })[0]; return f && f.context; }
function countOf(r, id) { return r.findings.filter(function (x) { return x.id === id; }).length; }
function throwsCode(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

var ALG = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
var SIG = b.bitString(Buffer.alloc(8, 1), 0);
var DN = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8("Test Responder")])])]);
var T_THIS = new Date("2027-01-01T00:00:00Z"), T_NEXT = new Date("2028-01-01T00:00:00Z"), T_PRODUCED = new Date("2027-01-01T00:00:00Z");
var EPOCH = new Date("1970-01-01T00:00:00Z");

function ext(name, critical, innerDer) {
  var kids = [typeof name === "string" && name.indexOf(".") !== -1 ? b.oid(name) : b.oid(O(name))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(innerDer));
  return b.sequence(kids);
}
function certId(serial) {
  return b.sequence([b.sequence([b.oid(O("sha256")), b.nullValue()]), b.octetString(Buffer.alloc(32, 3)), b.octetString(Buffer.alloc(32, 4)), b.integer(BigInt(serial == null ? 1 : serial))]);
}
function good() { return b.contextPrimitive(0, Buffer.alloc(0)); }
function revoked(time, reason) {
  var inner = [b.generalizedTime(time || T_THIS)];
  if (reason != null) inner.push(b.explicit(0, b.enumerated(BigInt(reason))));
  return b.contextConstructed(1, Buffer.concat(inner));
}
// s: { serial, status, thisUpdate, noNextUpdate, nextUpdate, exts (array of extension DER) }
function single(s) {
  s = s || {};
  var kids = [certId(s.serial), s.status || good(), b.generalizedTime(s.thisUpdate || T_THIS)];
  if (!s.noNextUpdate) kids.push(b.explicit(0, b.generalizedTime(s.nextUpdate || T_NEXT)));
  if (s.exts) kids.push(b.explicit(1, b.sequence(s.exts)));
  return b.sequence(kids);
}
// o: { byKey, producedAt, responses (array of SingleResponse DER), exts (array of extension DER),
//      certs (array of DER | [] for present-but-empty | undefined for absent), sig (signature DER) }
function makeResponse(o) {
  o = o || {};
  var rd = [];
  rd.push(o.byKey ? b.explicit(2, b.octetString(Buffer.alloc(20, 9))) : b.explicit(1, DN));
  rd.push(b.generalizedTime(o.producedAt || T_PRODUCED));
  rd.push(b.sequence(o.responses || [single()]));
  if (o.exts) rd.push(b.explicit(1, b.sequence(o.exts)));
  var basic = [b.sequence(rd), ALG, o.sig || SIG];
  if (o.certs !== undefined) basic.push(b.explicit(0, b.sequence(o.certs)));
  return b.sequence([b.enumerated(0n), b.explicit(0, b.sequence([b.oid(O("ocspBasic")), b.octetString(b.sequence(basic))]))]);
}
var NONCE = ext("ocspNonce", false, b.octetString(Buffer.alloc(32, 7)));
var EXT_REVOKE = ext("ocspExtendedRevoke", false, b.nullValue());
var CRL_ID = ext("ocspCrl", false, b.sequence([b.explicit(1, b.integer(5n))]));
function cutoff(t) { return ext("ocspArchiveCutoff", false, b.generalizedTime(t || new Date("2020-01-01T00:00:00Z"))); }
function reasonCode(v, critical) { return ext("reasonCode", !!critical, b.enumerated(BigInt(v))); }
function invalidityDate(critical) { return ext("invalidityDate", !!critical, b.generalizedTime(new Date("2026-06-01T00:00:00Z"))); }
function certificateIssuer(critical) { return ext("certificateIssuer", !!critical, b.sequence([b.explicit(4, DN)])); }
function fatalCode(der) {
  var r = pki.lint.ocsp(der);
  return r.worst === "fatal" && hasId(r, "lint/unparseable") && r.findings[0].context ? r.findings[0].context.code : null;
}
function lint(o, opts) { return pki.lint.ocsp(makeResponse(o), opts); }

async function run() {
  // ==== CONTROL FIRST: a conforming response draws none of these rows, or nothing below is evidence.
  var okReport = lint();
  check("CONTROL: a conforming response is clean of every rfc6960 row", ids(okReport).filter(function (i) { return i.indexOf("lint/rfc6960/") === 0; }).length === 0);
  check("CONTROL: a conforming response is not fatal and ran the profile", okReport.worst !== "fatal" && okReport.ran.length > 0);
  check("CONTROL: the rfc5019 rows count as not applicable in the default run", okReport.counts.na >= 4 && ids(okReport).filter(function (i) { return i.indexOf("lint/rfc5019/") === 0; }).length === 0);

  // ==== The data path never throws.
  check("hostile bytes return a fatal lint/unparseable rather than throwing", pki.lint.ocsp(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])).worst === "fatal");
  check("a string that is not a decodable OCSP PEM -> fatal lint/unparseable", (function () {
    var r = pki.lint.ocsp("-----BEGIN OCSP RESPONSE-----\nnot base64 at all\n-----END OCSP RESPONSE-----\n");
    return r.worst === "fatal" && hasId(r, "lint/unparseable");
  })());
  check("a response supplied as PEM lints the same as the DER", (function () {
    var der = makeResponse({ certs: [] });
    return JSON.stringify(ids(pki.lint.ocsp(pki.schema.ocsp.pemEncode(der)))) === JSON.stringify(ids(pki.lint.ocsp(der)));
  })());
  check("a parsed response (the parser's own output) lints the same as its bytes", (function () {
    var der = makeResponse({ certs: [] });
    return JSON.stringify(ids(pki.lint.ocsp(pki.schema.ocsp.parseResponse(der)))) === JSON.stringify(ids(pki.lint.ocsp(der)));
  })());
  check("a rebuilt parsed object is refused as config-time misuse, not linted", throwsCode(function () { pki.lint.ocsp(Object.assign({}, pki.schema.ocsp.parseResponse(makeResponse()))); }) === "lint/bad-input");
  check("a number is refused as config-time misuse", throwsCode(function () { pki.lint.ocsp(42); }) === "lint/bad-input");
  check("an object that is not a response is refused as config-time misuse", throwsCode(function () { pki.lint.ocsp({ hello: 1 }); }) === "lint/bad-input");
  check("a caller object with a throwing getter is contained as a typed error", throwsCode(function () {
    var o = {}; Object.defineProperty(o, "responseStatus", { get: function () { throw new Error("boom"); } }); pki.lint.ocsp(o);
  }) === "lint/bad-input");

  check("a non-successful response (tryLater, no responseBytes) draws no finding and marks every row not applicable", (function () {
    var r = pki.lint.ocsp(b.sequence([b.enumerated(3n)]));
    return r.findings.length === 0 && r.worst === null && r.ran.length === 0 && r.counts.na === pki.lint.rules("rfc6960").length + pki.lint.rules("rfc5019").length;
  })());

  // ==== The profile door, shared with the other two verbs.
  check("lint.ocsp refuses a certificate profile by name", throwsCode(function () { lint(null, { profile: "rfc5280" }); }) === "lint/unknown-profile");
  check("lint.ocsp refuses the CRL profile by name", throwsCode(function () { lint(null, { profile: "rfc5280-crl" }); }) === "lint/unknown-profile");
  check("lint.ocsp refuses an unknown profile", throwsCode(function () { lint(null, { profile: "nope" }); }) === "lint/unknown-profile");
  check("lint.certificate refuses an OCSP profile by name", throwsCode(function () { pki.lint.certificate(Buffer.alloc(4), { profile: "rfc6960" }); }) === "lint/unknown-profile");
  check("lint.crl refuses an OCSP profile by name", throwsCode(function () { pki.lint.crl(Buffer.alloc(4), { profile: "rfc5019" }); }) === "lint/unknown-profile");
  check("lint.ocsp refuses a misspelled option", throwsCode(function () { lint(null, { profil: "rfc6960" }); }) === "lint/bad-input");
  check("lint.ocsp refuses a bad severity", throwsCode(function () { lint(null, { severity: "loud" }); }) === "lint/bad-severity");
  check("profiles() lists both OCSP profiles", pki.lint.profiles().indexOf("rfc6960") !== -1 && pki.lint.profiles().indexOf("rfc5019") !== -1);
  check("rules() enumerates the OCSP rows with their citations", pki.lint.rules("rfc6960").every(function (r) { return r.id.indexOf("lint/rfc6960/") === 0 && typeof r.citation === "string" && r.citation.length > 0; }) && pki.lint.rules("rfc5019").length === 4);
  check("rules() with no profile includes the OCSP rows", pki.lint.rules().some(function (r) { return r.id === "lint/rfc6960/update-times-inverted"; }));
  check("the severity floor filters findings but not counts", (function () {
    var r = lint({ certs: [] }, { severity: "error" });
    return !hasId(r, "lint/rfc6960/certs-present-but-empty") && r.counts.warn === 1;
  })());

  // ==== rfc6960: times.
  check("thisUpdate after nextUpdate -> update-times-inverted (error) naming the response", (function () {
    var r = lint({ responses: [single(), single({ serial: 2, thisUpdate: T_NEXT, nextUpdate: T_THIS })] });
    return hasId(r, "lint/rfc6960/update-times-inverted") && sevOf(r, "lint/rfc6960/update-times-inverted") === "error" && ctxOf(r, "lint/rfc6960/update-times-inverted").response === 1;
  })());
  check("thisUpdate equal to nextUpdate is not inverted", !hasId(lint({ responses: [single({ thisUpdate: T_THIS, nextUpdate: T_THIS })] }), "lint/rfc6960/update-times-inverted"));
  check("a response with no nextUpdate is not inverted (and draws no rfc6960 row)", ids(lint({ responses: [single({ noNextUpdate: true })] })).filter(function (i) { return i.indexOf("lint/rfc6960/") === 0; }).length === 0);
  check("producedAt before a thisUpdate -> produced-before-this-update (notice)", (function () {
    var r = lint({ producedAt: new Date("2026-12-31T23:59:59Z") });
    return hasId(r, "lint/rfc6960/produced-before-this-update") && sevOf(r, "lint/rfc6960/produced-before-this-update") === "notice";
  })());
  check("producedAt equal to thisUpdate is not reported", !hasId(lint({ producedAt: T_THIS }), "lint/rfc6960/produced-before-this-update"));

  // ==== rfc6960: the signature.
  check("an empty signature BIT STRING -> signature-empty (error)", (function () {
    var r = lint({ sig: b.bitString(Buffer.alloc(0), 0) });
    return hasId(r, "lint/rfc6960/signature-empty") && sevOf(r, "lint/rfc6960/signature-empty") === "error";
  })());

  // ==== rfc6960: certs.
  check("certs present but empty -> certs-present-but-empty (warn)", (function () {
    var r = lint({ certs: [] });
    return hasId(r, "lint/rfc6960/certs-present-but-empty") && sevOf(r, "lint/rfc6960/certs-present-but-empty") === "warn";
  })());
  check("certs absent is clean", !hasId(lint(), "lint/rfc6960/certs-present-but-empty"));

  // ==== rfc6960: extended revoke (sec. 4.4.8) and the non-issued shape (sec. 2.2).
  check("CONTROL: extendedRevoke NULL, non-critical, in responseExtensions is clean", ids(lint({ exts: [EXT_REVOKE] })).filter(function (i) { return i.indexOf("lint/rfc6960/") === 0; }).length === 0);
  check("extendedRevoke critical -> response-extension-criticality (error)", (function () {
    var r = lint({ exts: [ext("ocspExtendedRevoke", true, b.nullValue())] });
    return hasId(r, "lint/rfc6960/response-extension-criticality") && sevOf(r, "lint/rfc6960/response-extension-criticality") === "error";
  })());
  check("extendedRevoke whose value is not NULL -> extended-revoke-value-not-null (error)", (function () {
    var r = lint({ exts: [ext("ocspExtendedRevoke", false, b.octetString(Buffer.alloc(1)))] });
    return hasId(r, "lint/rfc6960/extended-revoke-value-not-null") && sevOf(r, "lint/rfc6960/extended-revoke-value-not-null") === "error";
  })());
  check("extendedRevoke whose NULL carries a content octet (05 01 00) is not a NULL: both value rows fire", (function () {
    var r = lint({ exts: [ext("ocspExtendedRevoke", false, Buffer.from([0x05, 0x01, 0x00]))] });
    return hasId(r, "lint/rfc6960/extended-revoke-value-not-null") && hasId(r, "lint/rfc6960/extension-value-syntax");
  })());
  check("extendedRevoke in singleExtensions -> extended-revoke-in-single-extensions (error) naming the response", (function () {
    var r = lint({ responses: [single({ exts: [EXT_REVOKE] })] });
    return hasId(r, "lint/rfc6960/extended-revoke-in-single-extensions") && ctxOf(r, "lint/rfc6960/extended-revoke-in-single-extensions").response === 0;
  })());
  check("the non-issued shape without extendedRevoke -> non-issued-without-extended-revoke (error)", (function () {
    var r = lint({ responses: [single({ status: revoked(EPOCH, 6) })] });
    return hasId(r, "lint/rfc6960/non-issued-without-extended-revoke") && sevOf(r, "lint/rfc6960/non-issued-without-extended-revoke") === "error";
  })());
  check("CONTROL: the non-issued shape WITH extendedRevoke is clean of that row", !hasId(lint({ exts: [EXT_REVOKE], responses: [single({ status: revoked(EPOCH, 6) })] }), "lint/rfc6960/non-issued-without-extended-revoke"));
  check("certificateHold at a time other than the epoch is an ordinary hold, not the non-issued shape", !hasId(lint({ responses: [single({ status: revoked(T_THIS, 6) })] }), "lint/rfc6960/non-issued-without-extended-revoke"));
  check("the epoch with a reason other than certificateHold is not the non-issued shape", !hasId(lint({ responses: [single({ status: revoked(EPOCH, 1) })] }), "lint/rfc6960/non-issued-without-extended-revoke"));
  check("the non-issued shape carrying a CrlID -> non-issued-with-crl-extensions (error)", (function () {
    var r = lint({ exts: [EXT_REVOKE], responses: [single({ status: revoked(EPOCH, 6), exts: [CRL_ID] })] });
    return hasId(r, "lint/rfc6960/non-issued-with-crl-extensions") && sevOf(r, "lint/rfc6960/non-issued-with-crl-extensions") === "error" && ctxOf(r, "lint/rfc6960/non-issued-with-crl-extensions").extension === "ocspCrl";
  })());
  check("the non-issued shape carrying a CRL entry extension -> non-issued-with-crl-extensions", hasId(lint({ exts: [EXT_REVOKE], responses: [single({ status: revoked(EPOCH, 6), exts: [invalidityDate()] })] }), "lint/rfc6960/non-issued-with-crl-extensions"));
  check("an ordinary revoked response may carry a CrlID", !hasId(lint({ responses: [single({ status: revoked(T_THIS, 1), exts: [CRL_ID] })] }), "lint/rfc6960/non-issued-with-crl-extensions"));
  check("the non-issued shape may carry an extension that is neither a CrlID nor a CRL entry extension", !hasId(lint({ exts: [EXT_REVOKE], responses: [single({ status: revoked(EPOCH, 6), exts: [cutoff()] })] }), "lint/rfc6960/non-issued-with-crl-extensions"));

  // ==== rfc6960: placement.
  check("archiveCutoff in responseExtensions -> archive-cutoff-in-response-extensions (error)", (function () {
    var r = lint({ exts: [cutoff()] });
    return hasId(r, "lint/rfc6960/archive-cutoff-in-response-extensions") && sevOf(r, "lint/rfc6960/archive-cutoff-in-response-extensions") === "error";
  })());
  check("CONTROL: archiveCutoff in singleExtensions is clean", !hasId(lint({ responses: [single({ exts: [cutoff()] })] }), "lint/rfc6960/archive-cutoff-in-response-extensions"));
  check("CrlID in responseExtensions -> crl-references-in-response-extensions (error)", (function () {
    var r = lint({ exts: [CRL_ID] });
    return hasId(r, "lint/rfc6960/crl-references-in-response-extensions") && sevOf(r, "lint/rfc6960/crl-references-in-response-extensions") === "error";
  })());
  check("a nonce in singleExtensions -> nonce-in-single-extensions (error)", (function () {
    var r = lint({ responses: [single({ exts: [NONCE] })] });
    return hasId(r, "lint/rfc6960/nonce-in-single-extensions") && sevOf(r, "lint/rfc6960/nonce-in-single-extensions") === "error";
  })());
  check("CONTROL: a nonce in responseExtensions is clean under rfc6960", ids(lint({ exts: [NONCE] })).filter(function (i) { return i.indexOf("lint/rfc6960/") === 0; }).length === 0);
  check("a request-only extension on a response -> request-extension-in-response (error), on either list", (function () {
    var r1 = lint({ exts: [NONCE, ext("ocspResponse", false, b.sequence([b.oid(O("ocspBasic"))]))] });
    var r2 = lint({ responses: [single({ exts: [cutoff(), ext("ocspServiceLocator", false, b.sequence([DN]))] })] });
    var r3 = lint({ exts: [ext("ocspPrefSigAlgs", false, b.sequence([]))] });
    return countOf(r1, "lint/rfc6960/request-extension-in-response") === 1 && sevOf(r1, "lint/rfc6960/request-extension-in-response") === "error"
      && ctxOf(r1, "lint/rfc6960/request-extension-in-response").extension === "ocspResponse"
      && countOf(r2, "lint/rfc6960/request-extension-in-response") === 1 && ctxOf(r2, "lint/rfc6960/request-extension-in-response").response === 0
      && hasId(r3, "lint/rfc6960/request-extension-in-response");
  })());
  check("archiveCutoff later than producedAt -> archive-cutoff-after-produced-at (notice)", (function () {
    var r = lint({ responses: [single({ exts: [cutoff(new Date("2027-06-01T00:00:00Z"))] })] });
    return hasId(r, "lint/rfc6960/archive-cutoff-after-produced-at") && sevOf(r, "lint/rfc6960/archive-cutoff-after-produced-at") === "notice";
  })());
  check("archiveCutoff equal to producedAt is not reported", !hasId(lint({ responses: [single({ exts: [cutoff(T_PRODUCED)] })] }), "lint/rfc6960/archive-cutoff-after-produced-at"));

  // ==== rfc6960: single-extension criticality and value syntax (sec. 4.4.5 carries RFC 5280 sec. 5.3).
  check("CONTROL: reasonCode + invalidityDate non-critical and certificateIssuer critical are clean", ids(lint({ responses: [single({ status: revoked(T_THIS, 1), exts: [reasonCode(1), invalidityDate(), certificateIssuer(true)] })] })).filter(function (i) { return i.indexOf("lint/rfc6960/") === 0; }).length === 0);
  check("a critical reasonCode single extension -> single-extension-criticality (error) naming the extension", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, 1), exts: [reasonCode(1, true)] })] });
    var c = ctxOf(r, "lint/rfc6960/single-extension-criticality");
    return hasId(r, "lint/rfc6960/single-extension-criticality") && sevOf(r, "lint/rfc6960/single-extension-criticality") === "error" && c.extension === "reasonCode" && c.response === 0;
  })());
  check("a critical invalidityDate -> single-extension-criticality", hasId(lint({ responses: [single({ exts: [invalidityDate(true)] })] }), "lint/rfc6960/single-extension-criticality"));
  check("a non-critical certificateIssuer -> single-extension-criticality", hasId(lint({ responses: [single({ exts: [certificateIssuer(false)] })] }), "lint/rfc6960/single-extension-criticality"));
  check("a reasonCode value that is not a CRLReason -> extension-value-syntax (error)", (function () {
    var r = lint({ responses: [single({ exts: [ext("reasonCode", false, b.enumerated(7n))] })] });
    return hasId(r, "lint/rfc6960/extension-value-syntax") && sevOf(r, "lint/rfc6960/extension-value-syntax") === "error" && ctxOf(r, "lint/rfc6960/extension-value-syntax").extension === "reasonCode";
  })());
  check("an invalidityDate that is not a GeneralizedTime -> extension-value-syntax", hasId(lint({ responses: [single({ exts: [ext("invalidityDate", false, b.utcTime(new Date("2026-06-01T00:00:00Z")))] })] }), "lint/rfc6960/extension-value-syntax"));
  check("a certificateIssuer that is not GeneralNames -> extension-value-syntax", hasId(lint({ responses: [single({ exts: [ext("certificateIssuer", true, b.nullValue())] })] }), "lint/rfc6960/extension-value-syntax"));
  check("an unknown extension's value is not graded for syntax", !hasId(lint({ responses: [single({ exts: [ext("1.3.6.1.4.1.99999.7", false, b.utf8("anything"))] })] }), "lint/rfc6960/extension-value-syntax"));
  // The reasonCode single extension IS the RFC 5280 sec. 5.3.1 extension, carried over by sec. 4.4.5,
  // so its two rows grade at that clause's strength; RevokedInfo's own revocationReason is a separate
  // field of the same type, and the clause is applied to it by reading, so those rows are advisory.
  check("a reasonCode single extension of unspecified(0) -> reason-code-unspecified (warn)", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, 1), exts: [reasonCode(0)] })] });
    return hasId(r, "lint/rfc6960/reason-code-unspecified") && sevOf(r, "lint/rfc6960/reason-code-unspecified") === "warn" && !hasId(r, "lint/rfc6960/revocation-reason-unspecified");
  })());
  check("a reasonCode single extension of removeFromCRL(8) -> remove-from-crl-reason (error)", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, 1), exts: [reasonCode(8)] })] });
    return hasId(r, "lint/rfc6960/remove-from-crl-reason") && sevOf(r, "lint/rfc6960/remove-from-crl-reason") === "error" && !hasId(r, "lint/rfc6960/revocation-reason-remove-from-crl");
  })());

  // ==== rfc6960: the revocation reason inside RevokedInfo.
  check("a revocationReason of unspecified(0) -> revocation-reason-unspecified (notice)", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, 0) })] });
    return hasId(r, "lint/rfc6960/revocation-reason-unspecified") && sevOf(r, "lint/rfc6960/revocation-reason-unspecified") === "notice" && ctxOf(r, "lint/rfc6960/revocation-reason-unspecified").response === 0 && !hasId(r, "lint/rfc6960/reason-code-unspecified");
  })());
  check("a revocationReason of removeFromCRL(8) -> revocation-reason-remove-from-crl (notice)", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, 8) })] });
    return hasId(r, "lint/rfc6960/revocation-reason-remove-from-crl") && sevOf(r, "lint/rfc6960/revocation-reason-remove-from-crl") === "notice" && !hasId(r, "lint/rfc6960/remove-from-crl-reason");
  })());
  var REASON_ROWS = ["lint/rfc6960/reason-code-unspecified", "lint/rfc6960/remove-from-crl-reason", "lint/rfc6960/revocation-reason-unspecified", "lint/rfc6960/revocation-reason-remove-from-crl"];
  check("CONTROL: a revocationReason of keyCompromise(1) draws none of the four reason rows", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, 1) })] });
    return REASON_ROWS.every(function (id) { return !hasId(r, id); });
  })());
  check("a revoked status with no reason draws none of the four reason rows", (function () {
    var r = lint({ responses: [single({ status: revoked(T_THIS, null) })] });
    return REASON_ROWS.every(function (id) { return !hasId(r, id); });
  })());

  // ==== rfc6960: unknown critical extensions and duplicate CertIDs.
  check("an unknown critical responseExtension -> unknown-critical-extension (error)", (function () {
    var r = lint({ exts: [ext("1.3.6.1.4.1.99999.7", true, b.nullValue())] });
    return hasId(r, "lint/rfc6960/unknown-critical-extension") && sevOf(r, "lint/rfc6960/unknown-critical-extension") === "error";
  })());
  check("an unknown critical singleExtension -> unknown-critical-extension naming the response", ctxOf(lint({ responses: [single({ exts: [ext("1.3.6.1.4.1.99999.7", true, b.nullValue())] })] }), "lint/rfc6960/unknown-critical-extension").response === 0);
  check("an unknown NON-critical extension is not reported", !hasId(lint({ exts: [ext("1.3.6.1.4.1.99999.7", false, b.nullValue())] }), "lint/rfc6960/unknown-critical-extension"));
  check("a critical extension the profile knows (CrlID) is not unknown", !hasId(lint({ responses: [single({ exts: [ext("ocspCrl", true, b.sequence([b.explicit(1, b.integer(5n))]))] })] }), "lint/rfc6960/unknown-critical-extension"));
  check("two SingleResponses for one CertID -> duplicate-cert-id (notice), conflicting when the statuses differ", (function () {
    var same = lint({ responses: [single(), single()] });
    var conflict = lint({ responses: [single(), single({ status: revoked(T_THIS, 1) })] });
    return hasId(same, "lint/rfc6960/duplicate-cert-id") && sevOf(same, "lint/rfc6960/duplicate-cert-id") === "notice"
      && ctxOf(same, "lint/rfc6960/duplicate-cert-id").conflicting === false && ctxOf(same, "lint/rfc6960/duplicate-cert-id").response === 1
      && ctxOf(conflict, "lint/rfc6960/duplicate-cert-id").conflicting === true;
  })());
  check("two revoked answers with no reason for one CertID agree, and two with different reasons conflict", (function () {
    var agree = lint({ responses: [single({ status: revoked(T_THIS, null) }), single({ status: revoked(T_THIS, null) })] });
    var differ = lint({ responses: [single({ status: revoked(T_THIS, null) }), single({ status: revoked(T_THIS, 1) })] });
    return ctxOf(agree, "lint/rfc6960/duplicate-cert-id").conflicting === false && ctxOf(differ, "lint/rfc6960/duplicate-cert-id").conflicting === true;
  })());
  check("two SingleResponses for different serials are not duplicates", !hasId(lint({ responses: [single(), single({ serial: 2 })] }), "lint/rfc6960/duplicate-cert-id"));
  check("three SingleResponses for one CertID draw two findings, one per repeat, each naming the first", (function () {
    var r = lint({ responses: [single(), single(), single()] });
    return countOf(r, "lint/rfc6960/duplicate-cert-id") === 2 && r.findings.filter(function (f) { return f.id === "lint/rfc6960/duplicate-cert-id"; }).every(function (f) { return f.context.first === 0; });
  })());
  check("five thousand distinct CertIDs draw no duplicate, and a repeat among them is still found", (function () {
    var many = [];
    for (var i = 1; i <= 5000; i++) many.push(single({ serial: i }));
    var clean = lint({ responses: many });
    many.push(single({ serial: 2500 }));
    var one = lint({ responses: many });
    return !hasId(clean, "lint/rfc6960/duplicate-cert-id") && countOf(one, "lint/rfc6960/duplicate-cert-id") === 1 && ctxOf(one, "lint/rfc6960/duplicate-cert-id").first === 2499;
  })());

  // ==== rfc5019: the lightweight profile, selected by name.
  var lw = { profile: "rfc5019" };
  check("CONTROL: a single byKey response with nextUpdate and no responseExtensions is clean under rfc5019", ids(lint({ byKey: true }, lw)).length === 0);
  check("no nextUpdate -> rfc5019/next-update-missing (error)", (function () {
    var r = lint({ byKey: true, responses: [single({ noNextUpdate: true })] }, lw);
    return hasId(r, "lint/rfc5019/next-update-missing") && sevOf(r, "lint/rfc5019/next-update-missing") === "error";
  })());
  check("two SingleResponses -> rfc5019/multiple-single-responses (warn)", (function () {
    var r = lint({ byKey: true, responses: [single(), single({ serial: 2 })] }, lw);
    return hasId(r, "lint/rfc5019/multiple-single-responses") && sevOf(r, "lint/rfc5019/multiple-single-responses") === "warn";
  })());
  check("responseExtensions present -> rfc5019/response-extensions-present (warn)", (function () {
    var r = lint({ byKey: true, exts: [NONCE] }, lw);
    return hasId(r, "lint/rfc5019/response-extensions-present") && sevOf(r, "lint/rfc5019/response-extensions-present") === "warn";
  })());
  check("responderID byName -> rfc5019/responder-id-by-name (notice)", (function () {
    var r = lint({}, lw);
    return hasId(r, "lint/rfc5019/responder-id-by-name") && sevOf(r, "lint/rfc5019/responder-id-by-name") === "notice";
  })());
  check("selecting rfc5019 runs only its rows; the rfc6960 rows are not in ran", lint({ responses: [single({ thisUpdate: T_NEXT, nextUpdate: T_THIS })] }, lw).ran.every(function (id) { return id.indexOf("lint/rfc5019/") === 0; }));
  check("selecting rfc6960 runs only its rows", lint({ responses: [single({ noNextUpdate: true })] }, { profile: "rfc6960" }).ran.every(function (id) { return id.indexOf("lint/rfc6960/") === 0; }));

  // ==== Dead rows: the strict parser refuses these first, so the boundary is pinned as the engine's fatal.
  check("a version other than v1 is fatal at parse (sec. 4.2.2.3)", fatalCode((function () {
    var rd = [b.explicit(0, b.integer(1n)), b.explicit(1, DN), b.generalizedTime(T_PRODUCED), b.sequence([single()])];
    return b.sequence([b.enumerated(0n), b.explicit(0, b.sequence([b.oid(O("ocspBasic")), b.octetString(b.sequence([b.sequence(rd), ALG, SIG]))]))]);
  })()) === "ocsp/bad-version");
  check("an undefined CRLReason value is fatal at parse", fatalCode(makeResponse({ responses: [single({ status: revoked(T_THIS, 7) })] })) === "ocsp/bad-revocation-reason");
  check("an empty extension list is fatal at parse", fatalCode(makeResponse({ exts: [] })) === "ocsp/bad-extensions");
  check("a repeated extension is fatal at parse", fatalCode(makeResponse({ exts: [NONCE, NONCE] })) === "ocsp/duplicate-extension");
  check("an empty responses list is fatal at parse", fatalCode(makeResponse({ responses: [] })) === "ocsp/bad-responses");
  check("a nonce of 129 octets is fatal at parse (RFC 9654 sec. 2.1)", fatalCode(makeResponse({ exts: [ext("ocspNonce", false, b.octetString(Buffer.alloc(129, 1)))] })) === "ocsp/bad-nonce");
  check("an unsuccessful status carrying responseBytes is fatal at parse", (function () {
    var tryLater = Buffer.from(makeResponse());
    var at = tryLater.indexOf(Buffer.from([0x0a, 0x01, 0x00]));   // the ENUMERATED responseStatus, successful(0)
    tryLater[at + 2] = 0x03;                                         // tryLater(3), with the responseBytes still present
    return at !== -1 && fatalCode(tryLater) === "ocsp/bad-response-bytes";
  })());

  // ==== A real signed response from the producer lints clean, and a report is deterministic.
  var world = require("../helpers/ocsp-world");
  var w = await world.makeOcspWorld("ec-p256");
  // producedAt defaults to the signing time, so thisUpdate sits in the past of it here; a thisUpdate
  // after the signing time is the produced-before-this-update shape, and would be reported.
  var real = await pki.ocsp.sign({ responderID: "byKey", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: T_NEXT }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("a response pki.ocsp.sign produces is clean under both profiles", ids(pki.lint.ocsp(real)).length === 0 && ids(pki.lint.ocsp(real, lw)).length === 0);
  var future = await pki.ocsp.sign({ responderID: "byKey", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: T_NEXT, nextUpdate: new Date("2029-01-01T00:00:00Z") }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("a signed response whose thisUpdate is after its signing time draws the produced-before-this-update notice", hasId(pki.lint.ocsp(future), "lint/rfc6960/produced-before-this-update"));
  var once = JSON.stringify(pki.lint.ocsp(makeResponse({ certs: [], exts: [cutoff()] })));
  var twice = JSON.stringify(pki.lint.ocsp(makeResponse({ certs: [], exts: [cutoff()] })));
  check("a report is deterministic across two runs", once === twice);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
