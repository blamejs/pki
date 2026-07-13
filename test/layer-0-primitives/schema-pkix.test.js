// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — the shared PKIX extension-value decoders (schema-pkix.js).
 * RED disambiguation vectors for the §4.2.1 extnValue structures the path
 * validator consumes: each decoder accepts its canonical shape and rejects
 * the malformed / non-DER / profile-violating forms fail-closed with a
 * typed `path/bad-*` code. Also pins the two generalName additions: the
 * decoded-value option (raw-only without it) and the subtree-base
 * iPAddress mode (8/32 address+mask vs the 4/16 SAN form).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

var pkix = require("../../lib/schema-pkix");
var errors = require("../../lib/framework-error");
var oid = require("../../lib/oid");
var schema = require("../../lib/schema-engine");
var asn1 = require("../../lib/asn1-der");

var b = pki.asn1.build;
var NS = pkix.makeNS("path", errors.PathError, oid);

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }

var DEC = pkix.certExtensionDecoders(NS);
var OID_BC = "2.5.29.19", OID_KU = "2.5.29.15", OID_NC = "2.5.29.30", OID_CP = "2.5.29.32",
    OID_PM = "2.5.29.33", OID_PC = "2.5.29.36", OID_IAP = "2.5.29.54", OID_SAN = "2.5.29.17",
    OID_IAN = "2.5.29.18", OID_EKU = "2.5.29.37", OID_AKI = "2.5.29.35", OID_SKID = "2.5.29.14";

// ---------------------------------------------------------------------------
// basicConstraints
// ---------------------------------------------------------------------------

function testBasicConstraints() {
  var d = DEC.byOid[OID_BC];
  check("bc decoder registered", typeof d === "function");

  var ca = d(b.sequence([b.boolean(true)]));
  check("bc cA:TRUE decodes", ca.cA === true && ca.pathLenConstraint === null);
  var caLen = d(b.sequence([b.boolean(true), b.integer(3n)]));
  check("bc pathLen decodes", caLen.cA === true && caLen.pathLenConstraint === 3);
  var empty = d(b.sequence([]));
  check("bc empty SEQUENCE = end-entity default", empty.cA === false && empty.pathLenConstraint === null);

  check("bc explicit cA:FALSE rejected (DEFAULT omit-in-DER)",
    code(function () { d(b.sequence([b.boolean(false)])); }) === "path/bad-basic-constraints");
  check("bc pathLen without cA rejected (RFC 5280 4.2.1.9)",
    code(function () { d(b.sequence([b.integer(0n)])); }) === "path/bad-basic-constraints");
  check("bc negative pathLen rejected",
    code(function () { d(b.sequence([b.boolean(true), b.integer(-1n)])); }) === "path/bad-basic-constraints");
  check("bc oversized pathLen rejected (exact-or-rejected before Number narrowing)",
    code(function () { d(b.sequence([b.boolean(true), b.integer(1n << 60n)])); }) === "path/bad-basic-constraints");
  check("bc trailing garbage rejected",
    code(function () { d(Buffer.concat([b.sequence([b.boolean(true)]), Buffer.from([0x00])])); }) === "path/bad-basic-constraints");
  check("bc non-SEQUENCE rejected",
    code(function () { d(b.octetString(Buffer.from([1]))); }) === "path/bad-basic-constraints");
}

// ---------------------------------------------------------------------------
// keyUsage
// ---------------------------------------------------------------------------

function testKeyUsage() {
  var d = DEC.byOid[OID_KU];
  // keyCertSign = bit 5 -> 0b00000100 with 2 unused bits.
  var ku = d(b.bitString(Buffer.from([0x04]), 2));
  check("ku keyCertSign decodes", ku.keyCertSign === true && ku.cRLSign === false);
  var both = d(b.bitString(Buffer.from([0x06]), 1));
  check("ku keyCertSign+cRLSign decode", both.keyCertSign === true && both.cRLSign === true);
  var ds = d(b.bitString(Buffer.from([0x80]), 7));
  check("ku digitalSignature decodes", ds.digitalSignature === true && ds.keyCertSign === false);

  check("ku empty BIT STRING rejected (at least one bit MUST be set, RFC 5280 4.2.1.3)",
    code(function () { d(b.bitString(Buffer.alloc(0), 0)); }) === "path/bad-key-usage");
  check("ku all-zero BIT STRING rejected (non-empty bytes, no bit set)",
    code(function () { d(b.bitString(Buffer.from([0x00]), 7)); }) === "path/bad-key-usage");
  check("ku non-minimal trailing-zero octet rejected (NamedBitList DER, X.690 11.2.2)",
    code(function () { d(b.bitString(Buffer.from([0x80, 0x00]), 0)); }) === "path/bad-key-usage");
  check("ku non-minimal unused-bits (declared 6, minimal 7) rejected",
    code(function () { d(b.bitString(Buffer.from([0x80]), 6)); }) === "path/bad-key-usage");
  check("ku non-BIT-STRING rejected",
    code(function () { d(b.integer(1n)); }) === "path/bad-key-usage");
}

// ---------------------------------------------------------------------------
// nameConstraints (+ subtree-base iPAddress mode)
// ---------------------------------------------------------------------------

function gnDns(text) { return b.contextPrimitive(2, Buffer.from(text, "ascii")); }
function gnIp(octets) { return b.contextPrimitive(7, Buffer.from(octets)); }
function subtree(gn) { return b.sequence([gn]); }
function ncBuf(permitted, excluded) {
  var children = [];
  if (permitted) children.push(b.contextConstructed(0, Buffer.concat(permitted.map(subtree))));
  if (excluded) children.push(b.contextConstructed(1, Buffer.concat(excluded.map(subtree))));
  return b.sequence(children);
}

function testNameConstraints() {
  var d = DEC.byOid[OID_NC];
  var nc = d(ncBuf([gnDns("example.com")], null));
  check("nc permitted dNSName decodes", nc.permittedSubtrees.length === 1 && nc.excludedSubtrees.length === 0);
  check("nc base carries the decoded value", nc.permittedSubtrees[0].base.value === "example.com");
  check("nc base carries the tag", nc.permittedSubtrees[0].base.tagNumber === 2);

  var ncIp = d(ncBuf([gnIp([192, 168, 0, 0, 255, 255, 0, 0])], null));
  check("nc 8-octet iPAddress subtree base (addr+mask) accepted", ncIp.permittedSubtrees[0].base.tagNumber === 7);

  check("nc 4-octet iPAddress subtree base rejected (needs the mask, RFC 5280 4.2.1.10)",
    code(function () { d(ncBuf([gnIp([192, 168, 0, 0])], null)); }) === "path/bad-name-constraints");
  check("nc empty SEQUENCE rejected (one of permitted/excluded MUST be present)",
    code(function () { d(b.sequence([])); }) === "path/bad-name-constraints");
  check("nc explicitly-empty permittedSubtrees rejected (GeneralSubtrees SIZE 1..MAX)",
    code(function () { d(b.sequence([b.contextConstructed(0, Buffer.alloc(0))])); }) === "path/bad-name-constraints");
  check("nc out-of-order fields rejected ([1] before [0])",
    code(function () { d(b.sequence([b.contextConstructed(1, subtree(gnDns("x.example"))), b.contextConstructed(0, subtree(gnDns("y.example")))])); }) === "path/bad-name-constraints");
  check("nc present minimum rejected (MUST be zero => DEFAULT omitted)",
    code(function () { d(b.sequence([b.contextConstructed(0, b.sequence([gnDns("a.example"), b.contextPrimitive(0, Buffer.from([0x00]))]))])); }) === "path/bad-name-constraints");
  check("nc present maximum rejected (MUST be absent, RFC 5280 4.2.1.10)",
    code(function () { d(b.sequence([b.contextConstructed(0, b.sequence([gnDns("a.example"), b.contextPrimitive(1, Buffer.from([0x05]))]))])); }) === "path/bad-name-constraints");
}

// ---------------------------------------------------------------------------
// certificatePolicies / policyMappings / policyConstraints / inhibitAnyPolicy
// ---------------------------------------------------------------------------

function testPolicyDecoders() {
  var P1 = "1.3.6.1.4.1.99999.1", P2 = "1.3.6.1.4.1.99999.2";

  var cp = DEC.byOid[OID_CP];
  var v = cp(b.sequence([b.sequence([b.oid(P1)]), b.sequence([b.oid(P2), b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.nullValue()])])])]));
  check("cp two policies decode", v.length === 2 && v[0].policyIdentifier === P1 && v[1].policyIdentifier === P2);
  check("cp qualifiers surfaced raw", Buffer.isBuffer(v[1].qualifiersBytes) && v[0].qualifiersBytes === null);
  check("cp empty SEQUENCE rejected (SIZE 1..MAX)",
    code(function () { cp(b.sequence([])); }) === "path/bad-policy");
  check("cp duplicate policy OID rejected (RFC 5280 4.2.1.4)",
    code(function () { cp(b.sequence([b.sequence([b.oid(P1)]), b.sequence([b.oid(P1)])])); }) === "path/bad-policy");
  check("cp malformed OID content rejected, never dropped (CVE-2023-0465 class)",
    code(function () { cp(b.sequence([b.sequence([b.raw(Buffer.from([0x06, 0x01, 0x80]))])])); }) === "path/bad-policy");
  check("cp PolicyInformation with a third field rejected",
    code(function () { cp(b.sequence([b.sequence([b.oid(P1), b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1")])]), b.integer(1n)])])); }) === "path/bad-policy");
  check("cp policyQualifiers that is not a SEQUENCE rejected",
    code(function () { cp(b.sequence([b.sequence([b.oid(P1), b.integer(1n)])])); }) === "path/bad-policy");
  check("cp policyQualifiers element that is not a PolicyQualifierInfo SEQUENCE rejected",
    code(function () { cp(b.sequence([b.sequence([b.oid(P1), b.sequence([b.nullValue()])])])); }) === "path/bad-policy");
  // PolicyQualifierInfo is SEQUENCE { policyQualifierId, qualifier } — EXACTLY two
  // members. A missing qualifier (OID only) or a trailing extra field is malformed.
  check("cp PolicyQualifierInfo missing its qualifier rejected",
    code(function () { cp(b.sequence([b.sequence([b.oid(P1), b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1")])])])])); }) === "path/bad-policy");
  check("cp PolicyQualifierInfo with a trailing extra field rejected",
    code(function () { cp(b.sequence([b.sequence([b.oid(P1), b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.nullValue(), b.integer(1n)])])])])); }) === "path/bad-policy");

  var pm = DEC.byOid[OID_PM];
  var m = pm(b.sequence([b.sequence([b.oid(P1), b.oid(P2)])]));
  check("pm mapping decodes", m.length === 1 && m[0].issuerDomainPolicy === P1 && m[0].subjectDomainPolicy === P2);
  check("pm empty SEQUENCE rejected",
    code(function () { pm(b.sequence([])); }) === "path/bad-policy");

  var pc = DEC.byOid[OID_PC];
  var c = pc(b.sequence([b.contextPrimitive(0, Buffer.from([0x02])), b.contextPrimitive(1, Buffer.from([0x00]))]));
  check("pc both fields decode", c.requireExplicitPolicy === 2 && c.inhibitPolicyMapping === 0);
  var cOnly = pc(b.sequence([b.contextPrimitive(1, Buffer.from([0x01]))]));
  check("pc single field decodes", cOnly.requireExplicitPolicy === null && cOnly.inhibitPolicyMapping === 1);
  check("pc empty SEQUENCE rejected (one field MUST be present, RFC 5280 4.2.1.11)",
    code(function () { pc(b.sequence([])); }) === "path/bad-policy");
  check("pc negative value rejected",
    code(function () { pc(b.sequence([b.contextPrimitive(0, Buffer.from([0xff]))])); }) === "path/bad-policy");
  check("pc oversized skip count rejected (exact-or-rejected before Number narrowing)",
    code(function () { pc(b.sequence([b.contextPrimitive(0, pki.asn1.decode(b.integer(1n << 60n)).content)])); }) === "path/bad-policy");
  check("pc duplicate requireExplicitPolicy field rejected",
    code(function () { pc(b.sequence([b.contextPrimitive(0, Buffer.from([0x00])), b.contextPrimitive(0, Buffer.from([0x0a]))])); }) === "path/bad-policy");
  check("pc out-of-order fields rejected ([1] before [0])",
    code(function () { pc(b.sequence([b.contextPrimitive(1, Buffer.from([0x01])), b.contextPrimitive(0, Buffer.from([0x00]))])); }) === "path/bad-policy");

  var iap = DEC.byOid[OID_IAP];
  check("iap SkipCerts decodes", iap(b.integer(4n)) === 4);
  check("iap negative rejected", code(function () { iap(b.integer(-1n)); }) === "path/bad-policy");
  check("iap oversized skip count rejected (exact-or-rejected before Number narrowing)",
    code(function () { iap(b.integer(1n << 60n)); }) === "path/bad-policy");
  check("iap non-INTEGER rejected", code(function () { iap(b.octetString(Buffer.from([4]))); }) === "path/bad-policy");
}

// ---------------------------------------------------------------------------
// SAN / IAN / EKU / AKI / SKID
// ---------------------------------------------------------------------------

function testNameAndKeyDecoders() {
  var san = DEC.byOid[OID_SAN];
  var s = san(b.sequence([gnDns("host.example"), b.contextPrimitive(1, Buffer.from("a@b.example", "ascii"))]));
  check("san decodes both names", s.names.length === 2);
  check("san dNSName decoded value", s.names[0].value === "host.example");
  check("san rfc822Name decoded value", s.names[1].value === "a@b.example");
  check("san empty rejected (SIZE 1..MAX)", code(function () { san(b.sequence([])); }) !== "NO-THROW");
  check("san dNSName with an embedded control byte (NUL) rejected (CVE-2009-2408 class)",
    code(function () { san(b.sequence([b.contextPrimitive(2, Buffer.from([0x61, 0x00, 0x62]))])); }) === "path/bad-extension-value");
  check("ian registered", typeof DEC.byOid[OID_IAN] === "function");

  var eku = DEC.byOid[OID_EKU];
  var e = eku(b.sequence([b.oid("1.3.6.1.5.5.7.3.1"), b.oid("1.3.6.1.5.5.7.3.2")]));
  check("eku purpose OIDs decode", e.length === 2 && e[0] === "1.3.6.1.5.5.7.3.1");
  check("eku empty rejected", code(function () { eku(b.sequence([])); }) === "path/bad-extension-value");

  var aki = DEC.byOid[OID_AKI];
  var a = aki(b.sequence([b.contextPrimitive(0, Buffer.from([0xde, 0xad]))]));
  check("aki keyIdentifier decodes", a.keyIdentifier.equals(Buffer.from([0xde, 0xad])));
  var aFull = aki(b.sequence([
    b.contextPrimitive(0, Buffer.from([0x01])),
    b.contextConstructed(1, gnDns("issuer.example")),
    b.contextPrimitive(2, Buffer.from([0x07])),
  ]));
  check("aki issuer+serial decode together", aFull.authorityCertIssuer !== null && aFull.authorityCertSerialNumber === 7n);
  check("aki issuer WITHOUT serial rejected (both-or-neither, RFC 5280 4.2.1.1)",
    code(function () { aki(b.sequence([b.contextConstructed(1, gnDns("x.example"))])); }) === "path/bad-extension-value");
  // A CONSTRUCTED keyIdentifier [0] (not the IMPLICIT primitive OCTET STRING)
  // must be rejected, never dereferenced for its absent content (fuzz-found).
  check("aki constructed keyIdentifier [0] rejected fail-closed",
    code(function () { aki(b.sequence([b.contextConstructed(0, b.octetString(Buffer.from([1])))])); }) === "path/bad-extension-value");
  check("aki duplicate keyIdentifier [0] rejected",
    code(function () { aki(b.sequence([b.contextPrimitive(0, Buffer.from([0xaa])), b.contextPrimitive(0, Buffer.from([0xbb]))])); }) === "path/bad-extension-value");
  check("aki out-of-order fields rejected ([2] before [0])",
    code(function () { aki(b.sequence([b.contextConstructed(1, gnDns("i.example")), b.contextPrimitive(2, Buffer.from([0x07])), b.contextPrimitive(0, Buffer.from([0x01]))])); }) === "path/bad-extension-value");

  var skid = DEC.byOid[OID_SKID];
  check("skid decodes", skid(b.octetString(Buffer.from([0xaa]))).equals(Buffer.from([0xaa])));
  check("skid non-OCTET-STRING rejected", code(function () { skid(b.integer(1n)); }) === "path/bad-extension-value");
}

// ---------------------------------------------------------------------------
// cRLDistributionPoints / freshestCRL (RFC 5280 §4.2.1.13 / §4.2.1.15) —
// one decoder, both OIDs; the DistributionPointName is surfaced through the
// shared helper as the raw name encodings (the §5.2.5 "identical encoding"
// correspondence key).
// ---------------------------------------------------------------------------

function gnUri(text) { return b.contextPrimitive(6, Buffer.from(text, "ascii")); }
// DistributionPointName fullName [0] (IMPLICIT GeneralNames).
function dpnFull(gns) { return b.contextConstructed(0, Buffer.concat([].concat(gns))); }
// DistributionPointName nameRelativeToCRLIssuer [1] (IMPLICIT RelativeDistinguishedName).
function dpnRel(atvs) { return b.contextConstructed(1, Buffer.concat(atvs)); }
// DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT <DPN>, reasons [1]? }
function distPoint(dpn, reasonsBits) {
  var kids = [b.contextConstructed(0, dpn)];
  if (reasonsBits) kids.push(b.contextPrimitive(1, reasonsBits));
  return b.sequence(kids);
}

function testCrlDistributionPoints() {
  var OID_CDP = "2.5.29.31", OID_FRESHEST = "2.5.29.46";
  var d = DEC.byOid[OID_CDP];
  check("cdp decoder registered", typeof d === "function");
  var URL1 = "http://crl.example/a.crl";
  var gn1 = gnUri(URL1);
  var someReasons = Buffer.from([0x06, 0x40]); // 6 unused bits, keyCompromise

  // D16 — the raw-bytes contract: the INNER GeneralName encoding is surfaced,
  // not the [0] fullName wrapper and not the [0] field wrapper (an
  // off-by-one-tag surface would never match, or match too loosely).
  var v = d(b.sequence([distPoint(dpnFull([gn1]))]));
  check("D16 one DP decodes", Array.isArray(v) && v.length === 1);
  check("D16 fullName kind", !!v[0].distributionPoint && v[0].distributionPoint.kind === "fullName");
  check("D16 names[0] is the raw inner GeneralName encoding",
    v[0].distributionPoint.names.length === 1 && Buffer.isBuffer(v[0].distributionPoint.names[0]) &&
    v[0].distributionPoint.names[0].equals(gn1));
  check("D16 reasons and cRLIssuer default null", v[0].reasons === null && v[0].cRLIssuer === null);

  // nameRelativeToCRLIssuer surfaces its full [1]-tagged TLV.
  var atv1 = b.sequence([b.oid("2.5.4.3"), b.utf8("Shard1")]);
  var vr = d(b.sequence([distPoint(dpnRel([atv1]))]));
  check("rdn DPN kind + raw [1] TLV bytes", vr[0].distributionPoint.kind === "rdn" &&
    vr[0].distributionPoint.bytes.equals(dpnRel([atv1])));

  // reasons surfaced raw when present alongside a name.
  var vre = d(b.sequence([distPoint(dpnFull([gn1]), someReasons)]));
  check("reasons surfaced as the raw BIT STRING",
    !!vre[0].reasons && vre[0].reasons.unusedBits === 6 && vre[0].reasons.bytes.equals(Buffer.from([0x40])));

  // cRLIssuer-only DP is legal ("either distributionPoint or cRLIssuer MUST be present").
  var issuerGn = b.contextConstructed(4, b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]));
  var vc = d(b.sequence([b.sequence([b.contextConstructed(2, issuerGn)])]));
  check("cRLIssuer-only DP decodes", vc[0].distributionPoint === null &&
    !!vc[0].cRLIssuer && vc[0].cRLIssuer.names.length === 1);

  // D14 — empty outer SEQUENCE violates SIZE (1..MAX).
  check("D14 empty CRLDistributionPoints rejected (SIZE 1..MAX)",
    code(function () { d(b.sequence([])); }) === "path/bad-crl-distribution-points");
  // D15 — "a DistributionPoint MUST NOT consist of only the reasons field".
  check("D15 reasons-only DistributionPoint rejected",
    code(function () { d(b.sequence([b.sequence([b.contextPrimitive(1, someReasons)])])); }) === "path/bad-crl-distribution-points");
  check("empty DistributionPoint rejected (distributionPoint or cRLIssuer MUST be present)",
    code(function () { d(b.sequence([b.sequence([])])); }) === "path/bad-crl-distribution-points");
  check("DPN alternative other than [0]/[1] rejected",
    code(function () { d(b.sequence([distPoint(b.contextConstructed(2, gn1))])); }) === "path/bad-crl-distribution-points");
  check("empty fullName rejected (GeneralNames SIZE 1..MAX)",
    code(function () { d(b.sequence([distPoint(b.contextConstructed(0, Buffer.alloc(0)))])); }) === "path/bad-crl-distribution-points");
  check("out-of-order DistributionPoint fields rejected ([1] before [0])",
    code(function () { d(b.sequence([b.sequence([b.contextPrimitive(1, someReasons), b.contextConstructed(0, dpnFull([gn1]))])])); }) === "path/bad-crl-distribution-points");

  // D17 — freshestCRL reuses the same decoder body (one codec, both OIDs).
  var f = DEC.byOid[OID_FRESHEST];
  check("D17 freshestCRL decoder registered", typeof f === "function");
  var fv = f(b.sequence([distPoint(dpnFull([gn1]))]));
  check("D17 freshestCRL yields the same shape for the same bytes",
    fv.length === 1 && fv[0].distributionPoint.kind === "fullName" && fv[0].distributionPoint.names[0].equals(gn1));

  // D18 (helper unit) — the shared distributionPointName rejects a malformed
  // DPN fail-closed with the caller's code (the CRL checker routes this to
  // its malformed-IDP skip, never an assumed-unrestricted scope).
  check("D18u distributionPointName exported", typeof pkix.distributionPointName === "function");
  check("D18u empty fullName rejected with the caller's code",
    code(function () { pkix.distributionPointName(NS, asn1.decode(b.contextConstructed(0, Buffer.alloc(0))), "path/bad-idp"); }) === "path/bad-idp");
  check("D18u non-[0]/[1] alternative rejected with the caller's code",
    code(function () { pkix.distributionPointName(NS, asn1.decode(b.contextConstructed(2, gn1)), "path/bad-idp"); }) === "path/bad-idp");
  check("D18u fullName surfaces raw inner GeneralName bytes",
    pkix.distributionPointName(NS, asn1.decode(dpnFull([gn1])), "path/bad-idp").names[0].equals(gn1));
}

// ---------------------------------------------------------------------------
// generalName decoded-value option — behavior-preserving for existing callers
// ---------------------------------------------------------------------------

function testGeneralNameDecodedValue() {
  var bare = pkix.generalName(NS, {});
  var withValue = pkix.generalName(NS, { decodeValue: true });
  var node = asn1.decode(gnDns("plain.example"));

  var rawOnly = schema.walk(bare, node, NS);
  check("generalName without the flag stays raw-only", rawOnly.value === undefined && Buffer.isBuffer(rawOnly.bytes));

  var decoded = schema.walk(withValue, node, NS);
  check("generalName decodeValue surfaces the IA5 text", decoded.value === "plain.example");

  var ipNode = asn1.decode(gnIp([10, 0, 0, 1]));
  var ipDecoded = schema.walk(withValue, ipNode, NS);
  check("generalName decodeValue surfaces IP octets", Buffer.isBuffer(ipDecoded.value) && ipDecoded.value.length === 4);

  var dirNode = asn1.decode(b.contextConstructed(4, b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("Dir")])])])));
  var dirDecoded = schema.walk(withValue, dirNode, NS);
  check("generalName decodeValue surfaces directoryName rdns", dirDecoded.value && dirDecoded.value.dn === "CN=Dir");

  // Subtree-base mode: 8/32-octet iPAddress accepted, 4/16 rejected.
  var subtreeGn = pkix.generalName(NS, { subtreeBase: true });
  var ip8 = asn1.decode(gnIp([192, 168, 0, 0, 255, 255, 0, 0]));
  check("subtreeBase 8-octet iPAddress accepted", schema.walk(subtreeGn, ip8, NS).tagNumber === 7);
  check("subtreeBase 4-octet iPAddress rejected",
    code(function () { schema.walk(subtreeGn, asn1.decode(gnIp([192, 168, 0, 0])), NS); }) === "path/bad-general-name");
  check("SAN-form 8-octet iPAddress still rejected without the flag",
    code(function () { schema.walk(bare, ip8, NS); }) === "path/bad-general-name");
}

// ---------------------------------------------------------------------------
// AlgorithmIdentifier params-must-be-absent (RFC 9909 §3 / 9814 §4 / 9881 §2 /
// 8410 §3) — enforced once in the shared factory, inherited by every consumer.
// ---------------------------------------------------------------------------

function testAlgParamsMustBeAbsent() {
  var ALG = pkix.algorithmIdentifier(NS);
  function res(bytes) { return schema.walk(ALG, asn1.decode(bytes), NS).result; }
  function rej(bytes) { return code(function () { schema.walk(ALG, asn1.decode(bytes), NS); }); }
  var slh = oid.byName("id-slh-dsa-sha2-128s"), ml = oid.byName("id-ml-dsa-65"),
      ed = oid.byName("Ed25519"), x = oid.byName("X25519"), rsa = oid.byName("rsaEncryption");

  // absent parameters: parses (behavior-preserving for the whole class)
  check("slh-dsa algId without params parses", res(b.sequence([b.oid(slh)])).parameters === null);
  check("ml-dsa algId without params parses", res(b.sequence([b.oid(ml)])).parameters === null);
  check("Ed25519 algId without params parses", res(b.sequence([b.oid(ed)])).parameters === null);
  check("X25519 algId without params parses", res(b.sequence([b.oid(x)])).parameters === null);

  // present parameters — explicit NULL — rejected for every class member
  check("slh-dsa + NULL params rejected", rej(b.sequence([b.oid(slh), b.nullValue()])) === "path/bad-algorithm-parameters");
  check("ml-dsa + NULL params rejected", rej(b.sequence([b.oid(ml), b.nullValue()])) === "path/bad-algorithm-parameters");
  check("Ed25519 + NULL params rejected", rej(b.sequence([b.oid(ed), b.nullValue()])) === "path/bad-algorithm-parameters");
  check("X25519 + NULL params rejected", rej(b.sequence([b.oid(x), b.nullValue()])) === "path/bad-algorithm-parameters");
  // present parameters — arbitrary bytes (not just NULL) — rejected
  check("slh-dsa + garbage params rejected", rej(b.sequence([b.oid(slh), b.integer(1n)])) === "path/bad-algorithm-parameters");
  // the pre-hash HashSLH-DSA OIDs (RFC 9909 §3) are covered too
  var hashSlh = oid.byName("id-hash-slh-dsa-sha2-128s-with-sha256");
  check("HashSLH-DSA without params parses", res(b.sequence([b.oid(hashSlh)])).parameters === null);
  check("HashSLH-DSA + NULL params rejected", rej(b.sequence([b.oid(hashSlh), b.nullValue()])) === "path/bad-algorithm-parameters");

  // FIPS 203 ML-KEM (draft-ietf-lamps-kyber-certificates) is in the same
  // parameters-MUST-be-absent class as its ML-DSA signature sibling — a KEM
  // never reaches the signature-verification path, so parse time is the ONLY
  // layer that can reject the violation.
  var mlkem = oid.byName("id-ml-kem-512");
  check("ml-kem algId without params parses", res(b.sequence([b.oid(mlkem)])).parameters === null);
  check("ml-kem + NULL params rejected", rej(b.sequence([b.oid(mlkem), b.nullValue()])) === "path/bad-algorithm-parameters");

  // behavior-preserving: algorithms that carry parameters are untouched
  check("rsaEncryption + NULL params still parses", res(b.sequence([b.oid(rsa), b.nullValue()])).parameters !== null);
  check("rsaEncryption without params still parses", res(b.sequence([b.oid(rsa)])).parameters === null);

  // the guard covers the [tag] IMPLICIT AlgorithmIdentifier shape too (the pwri
  // keyDerivationAlgorithm [0] variant shares the same build).
  var IMPL = pkix.algorithmIdentifier(NS, { implicitTag: 0 });
  var slhImpl = b.contextConstructed(0, Buffer.concat([b.oid(slh), b.nullValue()]));
  check("slh-dsa + NULL params rejected in IMPLICIT [0] shape too",
    code(function () { schema.walk(IMPL, asn1.decode(slhImpl), NS); }) === "path/bad-algorithm-parameters");
}

// The params-must-be-absent rejection renders the OID's friendly name when it
// has one; for an OID a (custom/partial) registry marks params-absent but does
// NOT name, the message falls back to the raw dotted OID -- the reject is still
// the typed <prefix>/bad-algorithm-parameters verdict, never the literal
// "undefined" a nameless lookup would otherwise splice in.
function testAlgParamsAbsentNamelessOid() {
  var namelessOid = { paramsMustBeAbsent: function () { return true; }, name: function () { return undefined; }, byName: oid.byName };
  var FNS = pkix.makeNS("path", errors.PathError, namelessOid);
  var ALG = pkix.algorithmIdentifier(FNS);
  var withParams = b.sequence([b.oid("1.2.3.4"), b.nullValue()]);
  var err = null;
  try { schema.walk(ALG, asn1.decode(withParams), FNS); }
  catch (e) { err = e; }
  check("alg params-must-be-absent, nameless OID: rejects and renders the dotted OID (not 'undefined')",
    !!err && err.code === "path/bad-algorithm-parameters" &&
    err.message.indexOf("1.2.3.4") !== -1 && err.message.indexOf("undefined") === -1);
}

// ---------------------------------------------------------------------------
// pemDecode strictness (RFC 7468 sec. 3; RFC 4648 sec. 3.5 canonical base64)
// ---------------------------------------------------------------------------

function testPemDecodeStrictness() {
  var PemError = errors.PemError;
  function dec(body) { return pkix.pemDecode("-----BEGIN X-----\n" + body + "\n-----END X-----", null, PemError); }
  function decCode(body) { return code(function () { dec(body); }); }

  check("pemDecode: canonical body decodes", dec("AQE=").equals(Buffer.from([0x01, 0x01])));
  check("pemDecode: no armor -> pem/no-block",
    code(function () { pkix.pemDecode("just text", null, PemError); }) === "pem/no-block");
  check("pemDecode: non-string/non-Buffer input -> pem/bad-input",
    code(function () { pkix.pemDecode(42, null, PemError); }) === "pem/bad-input");
  check("pemDecode: PEM-armored Buffer decodes (readFileSync path)",
    pkix.pemDecode(Buffer.from("-----BEGIN X-----\nAQE=\n-----END X-----", "utf8"), null, PemError).equals(Buffer.from([0x01, 0x01])));
  // The size cap binds the Buffer input form too, and as a typed verdict: the
  // byte length is checked BEFORE the latin1 string copy, so an oversized file
  // never gets a full-size string allocation (nor, above Node's max string
  // length, an untyped ERR_STRING_TOO_LONG in place of pem/too-large).
  check("pemDecode: Buffer above PEM_MAX_BYTES -> pem/too-large",
    code(function () { pkix.pemDecode(Buffer.alloc(pki.C.LIMITS.PEM_MAX_BYTES + 1), null, PemError); }) === "pem/too-large");
  check("pemDecode: non-alphabet body -> pem/bad-base64", decCode("A!B=") === "pem/bad-base64");
  // Canonical-form rejects: several distinct PEM texts must not alias one DER.
  check("pemDecode: nonzero trailing bits in the final symbol (AQF=) rejected", decCode("AQF=") === "pem/bad-base64");
  check("pemDecode: stray pad on a complete group (QUJD=) rejected", decCode("QUJD=") === "pem/bad-base64");
  check("pemDecode: truncated 2-character group (AB) rejected", decCode("AB") === "pem/bad-base64");
  check("pemDecode: unpadded complete group (QUJD) decodes", dec("QUJD").equals(Buffer.from("ABC", "ascii")));
  check("pemDecode: shipped path routes the verdict (x509.pemDecode)",
    code(function () { pki.schema.x509.pemDecode("-----BEGIN CERTIFICATE-----\nAQF=\n-----END CERTIFICATE-----", "CERTIFICATE"); }) === "pem/bad-base64");
}

// ---------------------------------------------------------------------------
// pemDecodeAll — strict RFC 7468 multi-block chain (RFC 8555 sec. 9.1)
// ---------------------------------------------------------------------------

function testPemDecodeAll() {
  var PemError = errors.PemError;
  var vectors = require("../helpers/vectors");
  var certDer = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);
  var block = pkix.pemEncode(certDer, "CERTIFICATE", PemError);   // trailing \n
  // 75. a 3-block chain -> 3 DER buffers, each a parseable certificate.
  var got = pkix.pemDecodeAll(block + block + block, "CERTIFICATE", PemError);
  check("75. 3-block chain -> 3 parseable certs", got.length === 3 && got.every(function (d) { return d.equals(certDer) && !!pki.schema.x509.parse(d); }));
  // 75b. the default label is CERTIFICATE.
  check("75b. default label CERTIFICATE", pkix.pemDecodeAll(block, undefined, PemError).length === 1);
  // 76. explanatory text between blocks rejected (sec. 9.1 MUST NOT).
  check("76. prose between blocks rejected", code(function () { pkix.pemDecodeAll(block + "notes\n" + block, "CERTIFICATE", PemError); }) === "pem/explanatory-text");
  check("76b. prose before the first block rejected", code(function () { pkix.pemDecodeAll("preamble\n" + block, "CERTIFICATE", PemError); }) === "pem/explanatory-text");
  // 77. a non-CERTIFICATE block in the chain rejected.
  var pk = pkix.pemEncode(Buffer.from([1, 2, 3]), "PRIVATE KEY", PemError);
  check("77. wrong-label block rejected", code(function () { pkix.pemDecodeAll(block + pk, "CERTIFICATE", PemError); }) === "pem/label-mismatch");
  // 78. zero blocks rejected.
  check("78. zero blocks rejected", code(function () { pkix.pemDecodeAll("no pem here", "CERTIFICATE", PemError); }) === "pem/no-block");
}

// ---------------------------------------------------------------------------
// pemEncode label validation (RFC 7468 sec. 3 label grammar)
// ---------------------------------------------------------------------------

function testPemEncodeLabel() {
  var PemError = errors.PemError;
  function encCode(label) { return code(function () { pkix.pemEncode(Buffer.from([0x01]), label, PemError); }); }
  check("pemEncode: uppercase multi-word label accepted", encCode("X509 CRL") === "NO-THROW");
  check("pemEncode: lowercase label rejected (pemDecode could not re-read it)", encCode("certificate") === "pem/bad-label");
  check("pemEncode: label containing '-----' rejected (armor injection)", encCode("X-----BOOM") === "pem/bad-label");
  check("pemEncode: leading-space label rejected", encCode(" CERT") === "pem/bad-label");
  check("pemEncode: trailing-space label rejected", encCode("CERT ") === "pem/bad-label");
  check("pemEncode: empty label rejected", encCode("") === "pem/bad-label");
  check("pemEncode: newline in label rejected", encCode("A\nB") === "pem/bad-label");
  // The DER input is re-viewed through the byte guard: a string would silently
  // utf8-armor into a bogus PEM, a detached-backed Buffer into an empty body.
  check("pemEncode: string DER input rejected (no silent utf8 armor)", code(function () { pkix.pemEncode("not-der", "CERTIFICATE", PemError); }) === "pem/bad-input");
  check("pemEncode: detached-backed Buffer rejected", code(function () { var ab = new ArrayBuffer(3); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] }); pkix.pemEncode(b, "CERTIFICATE", PemError); }) === "pem/bad-input");
  var der = Buffer.from([0x01, 0x02, 0x03]);
  check("pemEncode/pemDecode round-trip",
    pkix.pemDecode(pkix.pemEncode(der, "TEST BLOCK", PemError), "TEST BLOCK", PemError).equals(der));
}

// ---------------------------------------------------------------------------
// attrValueToString encode direction (RFC 4514 sec. 2.4) — the '#hex' form is
// validated (throw, never silent truncation) and cannot collide with a literal
// '#'-leading string (the decode escapes the leading character).
// ---------------------------------------------------------------------------

function testAttrValueEncodeHexForm() {
  var ATV = pkix.attrValueToString(NS);
  function enc(v) { return schema.encode(ATV, v, NS); }
  function encCode(v) { return code(function () { enc(v); }); }

  check("atv encode: valid #hex emits the raw TLV", enc("#0500").equals(Buffer.from([0x05, 0x00])));
  check("atv encode: non-hex after # rejected (no silent empty buffer)", encCode("#zz") === "path/bad-atv");
  check("atv encode: partial hex rejected (no silent truncation)", encCode("#abzz") === "path/bad-atv");
  check("atv encode: odd-length hex rejected", encCode("#050") === "path/bad-atv");
  check("atv encode: hex that is not one whole DER TLV rejected", encCode("#00") === "path/bad-atv");
  check("atv encode: empty hex rejected", encCode("#") === "path/bad-atv");

  var literal = schema.walk(ATV, asn1.decode(b.utf8("#0500")), NS);
  check("atv decode: literal '#'-leading string surfaced escaped", literal === "\\#0500");
  check("atv encode: escaped literal re-encodes as the original UTF8String",
    enc(literal).equals(b.utf8("#0500")));
  var bs = schema.walk(ATV, asn1.decode(b.utf8("\\x")), NS);
  check("atv decode: literal '\\'-leading string surfaced escaped", bs === "\\\\x");
  check("atv encode: escaped backslash re-encodes as the original UTF8String", enc(bs).equals(b.utf8("\\x")));
  var hexForm = schema.walk(ATV, asn1.decode(b.integer(5n)), NS);
  check("atv decode: non-string value takes the # hex form", hexForm === "#020105");
  check("atv encode: hex form round-trips the raw DER", enc(hexForm).equals(b.integer(5n)));
  check("atv decode/encode: plain string unchanged",
    enc(schema.walk(ATV, asn1.decode(b.utf8("plain")), NS)).equals(b.utf8("plain")));
}

// ---------------------------------------------------------------------------
// pkix.time — the RFC 5280 Time cutover on decode (sec. 4.1.2.5): a date
// through 2049 MUST be UTCTime; GeneralizedTime is reserved for 2050 onward.
// ---------------------------------------------------------------------------

function testRfc5280TimeCutover() {
  var T = pkix.time(NS);
  function w(node) { return schema.walk(T, asn1.decode(node), NS); }
  check("time: UTCTime 2026 decodes", w(b.utcTime(new Date("2026-01-01T00:00:00Z"))) instanceof Date);
  check("time: GeneralizedTime 2050 decodes", w(b.generalizedTime(new Date("2050-01-01T00:00:00Z"))) instanceof Date);
  check("time: GeneralizedTime 1949 decodes (UTCTime cannot express it)",
    w(b.generalizedTime(new Date("1949-12-31T00:00:00Z"))) instanceof Date);
  check("time: GeneralizedTime 2020 rejected (must be UTCTime through 2049)",
    code(function () { w(b.generalizedTime(new Date("2020-01-01T00:00:00Z"))); }) === "path/bad-time");
  check("time: GeneralizedTime 2049 rejected (cutover boundary)",
    code(function () { w(b.generalizedTime(new Date("2049-12-31T23:59:59Z"))); }) === "path/bad-time");
  check("time: non-time tag rejected", code(function () { w(b.integer(1n)); }) === "path/bad-time");
}

// ---------------------------------------------------------------------------
// pemDecodeAll — explanatory text AFTER the chain is rejected (the mirror of
// the before/between rules; RFC 8555 sec. 9.1 certchain = stricttextualmsg
// *(eol stricttextualmsg), no trailing prose).
// ---------------------------------------------------------------------------

function testPemDecodeAllTrailingProse() {
  var PemError = errors.PemError;
  var vectors = require("../helpers/vectors");
  var block = pkix.pemEncode(pki.schema.x509.pemDecode(vectors.CERT_EC_PEM), "CERTIFICATE", PemError);
  check("prose after the chain rejected (RFC 8555 sec. 9.1)",
    code(function () { pkix.pemDecodeAll(block + "trailing notes\n", "CERTIFICATE", PemError); }) === "pem/explanatory-text");
}

// ---------------------------------------------------------------------------
// coerceToDer / decodeRoot — the shared parse-entry boundary.
//  * a Buffer whose "-----BEGIN" is preceded by a NON-text byte is NOT PEM
//    armor (DER is binary); it is routed as DER verbatim, never unwrapped.
//  * a DER buffer the codec rejects surfaces the caller's <prefix>/bad-der.
// ---------------------------------------------------------------------------

function testCoerceAndDecodeRoot() {
  var derOpts = { pemLabel: null, PemError: errors.PemError, ErrorClass: errors.PathError, prefix: "path" };
  // A leading NUL (0x00) before "-----BEGIN" -> _isPemArmor returns false ->
  // the bytes pass through as DER (a binary payload that merely contains the
  // armor string is not misrouted into the PEM decoder).
  var craft = Buffer.concat([Buffer.from([0x00]), Buffer.from("-----BEGIN X-----\nAQE=\n-----END X-----", "latin1")]);
  var out = pkix.coerceToDer(craft, derOpts);
  check("coerceToDer: binary-prefixed BEGIN routed as DER (not PEM-unwrapped)", Buffer.isBuffer(out) && out.equals(craft));

  // decodeRoot wraps a codec fault in the caller's <prefix>/bad-der (indefinite
  // length is rejected by the strict DER decoder).
  check("decodeRoot: undecodable DER -> <prefix>/bad-der",
    code(function () { pkix.decodeRoot(Buffer.from([0x30, 0x80, 0x00, 0x00]), { ErrorClass: errors.PathError, prefix: "path", what: "test" }); }) === "path/bad-der");
  // With `what` omitted the message falls back to the "input" label (the default
  // subject noun) while the typed <prefix>/bad-der verdict is unchanged.
  var eNoWhat = null;
  try { pkix.decodeRoot(Buffer.from([0x30, 0x80, 0x00, 0x00]), { ErrorClass: errors.PathError, prefix: "path" }); }
  catch (e) { eNoWhat = e; }
  check("decodeRoot: omitted `what` falls back to the \"input\" label, still <prefix>/bad-der",
    !!eNoWhat && eNoWhat.code === "path/bad-der" && /^input DER did not decode:/.test(eNoWhat.message));
}

// ---------------------------------------------------------------------------
// attrValueToString — a malformed KNOWN string type (invalid UTF-8) surfaces
// as the caller's <prefix>/bad-atv, never hex-encoded away (that would bypass
// the decoder's strict string validation on the DN path).
// ---------------------------------------------------------------------------

function testAttrValueMalformedString() {
  var ATV = pkix.attrValueToString(NS);
  // UTF8String (tag 0x0C) with a lone 0xFF content byte — never valid UTF-8.
  var badUtf8 = asn1.decode(Buffer.from([0x0c, 0x01, 0xff]));
  check("atv malformed UTF8String rejected fail-closed (not hex-escaped away)",
    code(function () { schema.walk(ATV, badUtf8, NS); }) === "path/bad-atv");
}

// ---------------------------------------------------------------------------
// name() label derivation — an unregistered attribute-type OID surfaces name
// null and renders as the dotted OID; a registered-but-not-DN-short name
// renders under its long name (neither collapses to a wrong short label).
// ---------------------------------------------------------------------------

function testNameLabelDerivation() {
  var NAME = pkix.name(NS);
  function nm(oidStr, val) {
    return schema.walk(NAME, asn1.decode(b.sequence([b.set([b.sequence([b.oid(oidStr), b.utf8(val)])])])), NS).result;
  }
  var unreg = "1.3.6.1.4.1.99999.7";
  var rUnreg = nm(unreg, "Val");
  check("name: unregistered ATV type surfaces name null", rUnreg.rdns[0][0].name === null && rUnreg.rdns[0][0].type === unreg);
  check("name: unregistered type renders as the dotted OID", rUnreg.dn === unreg + "=Val");
  // basicConstraints (2.5.29.19) has a registered name but no DN short label.
  var rLong = nm("2.5.29.19", "V2");
  check("name: registered non-DN-short type renders under its long name", rLong.rdns[0][0].name === "basicConstraints" && rLong.dn === "basicConstraints=V2");
}

// ---------------------------------------------------------------------------
// generalizedTime / utf8Text / rawNonEmptySequence — the ns-parameterized
// leaf factories exercised with DEFAULT opts (no explicit code/message), so
// the fault surfaces under the <prefix>/bad-* default the factory supplies.
// ---------------------------------------------------------------------------

function testGeneralizedTimeUtf8RawSeqDefaults() {
  var GT = pkix.generalizedTime(NS);
  check("generalizedTime default: a GeneralizedTime decodes",
    schema.walk(GT, asn1.decode(b.generalizedTime(new Date("2050-01-01T00:00:00Z"))), NS) instanceof Date);
  check("generalizedTime default: a UTCTime rejected with the default code",
    code(function () { schema.walk(GT, asn1.decode(b.utcTime(new Date("2026-01-01T00:00:00Z"))), NS); }) === "path/bad-time");

  var UT = pkix.utf8Text(NS);
  check("utf8Text default: a UTF8String decodes", schema.walk(UT, asn1.decode(b.utf8("hi")), NS) === "hi");
  check("utf8Text default: a non-UTF8String rejected with the default code",
    code(function () { schema.walk(UT, asn1.decode(b.integer(1n)), NS); }) === "path/bad-freetext");

  var RS = pkix.rawNonEmptySequence(NS);
  var sb = b.sequence([b.integer(1n)]);
  check("rawNonEmptySequence default: a non-empty SEQUENCE surfaces its raw TLV", schema.walk(RS, asn1.decode(sb), NS).equals(sb));
  check("rawNonEmptySequence default: an empty SEQUENCE rejected with the default code",
    code(function () { schema.walk(RS, asn1.decode(b.sequence([])), NS); }) === "path/bad-sequence");
  check("rawNonEmptySequence default: a non-SEQUENCE rejected with the default code",
    code(function () { schema.walk(RS, asn1.decode(b.integer(1n)), NS); }) === "path/bad-sequence");
}

// ---------------------------------------------------------------------------
// generalName CHOICE arms — the per-alternative form + content checks (X.690
// sec. 10.2, RFC 5280 sec. 4.2.1.6) and the raw-only default (no opts).
// ---------------------------------------------------------------------------

function testGeneralNameArms() {
  var GNv = pkix.generalName(NS, { decodeValue: true });
  function rej(node) { return code(function () { schema.walk(GNv, asn1.decode(node), NS); }); }

  // otherName [0] ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
  check("gn otherName [0] non-OID type-id rejected",
    rej(b.contextConstructed(0, Buffer.concat([b.integer(1n), b.contextConstructed(0, b.integer(2n))]))) === "path/bad-general-name");
  check("gn otherName [0] value not a [0] EXPLICIT wrapper rejected",
    rej(b.contextConstructed(0, Buffer.concat([b.oid("1.2.3"), b.integer(5n)]))) === "path/bad-general-name");
  var goodOther = schema.walk(GNv, asn1.decode(b.contextConstructed(0, Buffer.concat([
    b.oid("1.3.6.1.4.1.311.20.2.3"), b.contextConstructed(0, b.utf8("u@e"))]))), NS);
  check("gn otherName [0] decoded value surfaces typeId + raw valueBytes",
    goodOther.value && goodOther.value.typeId === "1.3.6.1.4.1.311.20.2.3" && Buffer.isBuffer(goodOther.value.valueBytes));

  // directoryName [4] EXPLICIT Name — exactly one wrapped Name.
  check("gn directoryName [4] with != 1 wrapped child rejected",
    rej(b.contextConstructed(4, Buffer.concat([b.sequence([]), b.sequence([])]))) === "path/bad-general-name");

  // rfc822Name/dNSName/URI [1]/[2]/[6] — non-empty IA5.
  check("gn IA5 name [2] empty content rejected", rej(b.contextPrimitive(2, Buffer.alloc(0))) === "path/bad-general-name");

  // registeredID [8] — a valid OBJECT IDENTIFIER content.
  check("gn registeredID [8] malformed OID content rejected", rej(b.contextPrimitive(8, Buffer.from([0x80]))) === "path/bad-general-name");
  var regOk = schema.walk(GNv, asn1.decode(b.contextPrimitive(8, asn1.decode(b.oid("1.2.3.4")).content)), NS);
  check("gn registeredID [8] valid OID decodes to the dotted string", regOk.value === "1.2.3.4");

  // Bare factory (no opts) — raw-only, no decoded value.
  var GNbare = pkix.generalName(NS);
  var bare = schema.walk(GNbare, asn1.decode(b.contextPrimitive(2, Buffer.from("x.example", "ascii"))), NS);
  check("gn bare factory (no opts) is raw-only", bare.tagNumber === 2 && bare.value === undefined && Buffer.isBuffer(bare.bytes));

  // generalNames bare factory (no opts) — default code + SIZE(1..MAX).
  var GNS = pkix.generalNames(NS);
  check("generalNames bare factory decodes a one-element list",
    schema.walk(GNS, asn1.decode(b.sequence([b.contextPrimitive(2, Buffer.from("a.example", "ascii"))])), NS).result.names.length === 1);
  check("generalNames bare factory rejects an empty SEQUENCE with the default code",
    code(function () { schema.walk(GNS, asn1.decode(b.sequence([])), NS); }) === "path/bad-general-names");
}

// ---------------------------------------------------------------------------
// certExtensionDecoders — the reader-catch and structural-shape branches every
// per-OID decoder shares. A structurally-valid-but-semantically-bad leaf
// (non-minimal INTEGER, out-of-range BOOLEAN, bad BIT STRING, malformed OID)
// passes the strict decode and is rejected fail-closed at the typed reader.
// ---------------------------------------------------------------------------

function testExtensionDecoderReaderCatches() {
  var bc = DEC.byOid[OID_BC];
  check("bc undecodable extension value -> bad-der-class reject",
    code(function () { bc(Buffer.from([0x02, 0x05, 0x01])); }) === "path/bad-basic-constraints");
  check("bc non-minimal INTEGER pathLen rejected at the reader",
    code(function () { bc(b.sequence([b.boolean(true), b.raw(Buffer.from([0x02, 0x02, 0x00, 0x01]))])); }) === "path/bad-basic-constraints");
  check("bc out-of-range BOOLEAN cA rejected at the reader",
    code(function () { bc(b.sequence([b.raw(Buffer.from([0x01, 0x01, 0x42]))])); }) === "path/bad-basic-constraints");
  check("bc trailing field after cA/pathLen rejected",
    code(function () { bc(b.sequence([b.boolean(true), b.integer(3n), b.integer(4n)])); }) === "path/bad-basic-constraints");

  var ku = DEC.byOid[OID_KU];
  check("ku BIT STRING with unused-bit count > 7 rejected at the reader",
    code(function () { ku(b.raw(Buffer.from([0x03, 0x02, 0x08, 0x00]))); }) === "path/bad-key-usage");

  var nc = DEC.byOid[OID_NC];
  check("nc GeneralSubtree that is not a SEQUENCE rejected",
    code(function () { nc(b.sequence([b.contextConstructed(0, b.integer(1n))])); }) === "path/bad-name-constraints");
  check("nc GeneralSubtree with an unexpected non-context field rejected",
    code(function () { nc(b.sequence([b.contextConstructed(0, b.sequence([gnDns("a.ex"), b.integer(1n)]))])); }) === "path/bad-name-constraints");
  check("nc a non-context top-level field rejected",
    code(function () { nc(b.sequence([b.integer(1n)])); }) === "path/bad-name-constraints");
  check("nc an unexpected context field [2] rejected",
    code(function () { nc(b.sequence([b.contextConstructed(2, b.sequence([]))])); }) === "path/bad-name-constraints");

  var cp = DEC.byOid[OID_CP];
  check("cp PolicyQualifierInfo whose leading member is not an OID rejected",
    code(function () { cp(b.sequence([b.sequence([b.oid("1.3.6.1.4.1.99999.1"), b.sequence([b.sequence([b.integer(1n), b.nullValue()])])])])); }) === "path/bad-policy");

  var pm = DEC.byOid[OID_PM];
  check("pm mapping element that is not a 2-member SEQUENCE rejected",
    code(function () { pm(b.sequence([b.integer(1n)])); }) === "path/bad-policy");
  check("pm mapping member that is not an OID rejected",
    code(function () { pm(b.sequence([b.sequence([b.raw(Buffer.from([0x06, 0x01, 0x80])), b.oid("1.2.3")])])); }) === "path/bad-policy");

  var pc = DEC.byOid[OID_PC];
  check("pc a non-context field rejected",
    code(function () { pc(b.sequence([b.integer(1n)])); }) === "path/bad-policy");
  check("pc a non-minimal IMPLICIT INTEGER field rejected at the reader",
    code(function () { pc(b.sequence([b.contextPrimitive(0, Buffer.from([0x00, 0x01]))])); }) === "path/bad-policy");
  check("pc an unexpected context field [2] rejected",
    code(function () { pc(b.sequence([b.contextPrimitive(2, Buffer.from([0x00]))])); }) === "path/bad-policy");

  var eku = DEC.byOid[OID_EKU];
  check("eku a KeyPurposeId with malformed OID content rejected at the reader",
    code(function () { eku(b.sequence([b.raw(Buffer.from([0x06, 0x01, 0x80]))])); }) === "path/bad-extension-value");

  var aki = DEC.byOid[OID_AKI];
  check("aki a non-context field rejected",
    code(function () { aki(b.sequence([b.integer(1n)])); }) === "path/bad-extension-value");
  check("aki authorityCertSerialNumber [2] with a non-minimal INTEGER rejected at the reader",
    code(function () { aki(b.sequence([b.contextPrimitive(2, Buffer.from([0x00, 0x01]))])); }) === "path/bad-extension-value");
  check("aki an unexpected context field [3] rejected",
    code(function () { aki(b.sequence([b.contextPrimitive(3, Buffer.from([0x01]))])); }) === "path/bad-extension-value");
}

// ---------------------------------------------------------------------------
// cRLDistributionPoints — the DistributionPoint structural-shape branches.
// ---------------------------------------------------------------------------

function testCrlDistributionPointShapes() {
  var d = DEC.byOid["2.5.29.31"];
  check("cdp a DistributionPoint that is not a SEQUENCE rejected",
    code(function () { d(b.sequence([b.integer(1n)])); }) === "path/bad-crl-distribution-points");
  check("cdp a non-context DistributionPoint field rejected",
    code(function () { d(b.sequence([b.sequence([b.integer(1n)])])); }) === "path/bad-crl-distribution-points");
  check("cdp distributionPoint [0] not wrapping exactly one DPN rejected",
    code(function () { d(b.sequence([b.sequence([b.contextConstructed(0, Buffer.alloc(0))])])); }) === "path/bad-crl-distribution-points");
  check("cdp reasons [1] that is not a well-formed BIT STRING rejected at the reader",
    code(function () { d(b.sequence([b.sequence([b.contextPrimitive(1, Buffer.from([0x08, 0x00]))])])); }) === "path/bad-crl-distribution-points");
  check("cdp an unexpected DistributionPoint field [3] rejected",
    code(function () { d(b.sequence([b.sequence([b.contextConstructed(3, Buffer.alloc(0))])])); }) === "path/bad-crl-distribution-points");
}

// ---------------------------------------------------------------------------
// certExtensionDecoders load guard — a registry key-list name that resolves to
// undefined (a typo, or a name absent from the OID registry) fails at module
// load, never silently dropping the extension from dispatch.
// ---------------------------------------------------------------------------

function testCertExtensionDecodersLoadGuard() {
  var fakeOid = { byName: function () { return undefined; }, name: function (x) { return oid.name(x); } };
  check("certExtensionDecoders throws when a key-list name is unregistered",
    code(function () { pkix.certExtensionDecoders(pkix.makeNS("path", errors.PathError, fakeOid)); }) === "TypeError");
}

// ---------------------------------------------------------------------------
// signedEnvelopeTbs — the shared signed-envelope shape recognizer returns the
// tbs only for a SEQUENCE-of-3 whose first child is itself a universal
// SEQUENCE; anything else is null (so a matches() detector cannot over-match).
// ---------------------------------------------------------------------------

function testSignedEnvelopeTbs() {
  check("signedEnvelopeTbs: 3-element SEQUENCE with a non-SEQUENCE tbs -> null",
    pkix.signedEnvelopeTbs(asn1.decode(b.sequence([b.integer(1n), b.integer(2n), b.integer(3n)]))) === null);
  var tbs = pkix.signedEnvelopeTbs(asn1.decode(b.sequence([b.sequence([b.integer(1n)]), b.integer(2n), b.integer(3n)])));
  check("signedEnvelopeTbs: a SEQUENCE-of-3 with a SEQUENCE tbs returns the tbs node",
    tbs && tbs.tagClass === "universal" && tbs.tagNumber === asn1.TAGS.SEQUENCE);
}

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

function run() {
  testBasicConstraints();
  testKeyUsage();
  testNameConstraints();
  testPolicyDecoders();
  testNameAndKeyDecoders();
  testCrlDistributionPoints();
  testGeneralNameDecodedValue();
  testAlgParamsMustBeAbsent();
  testAlgParamsAbsentNamelessOid();
  testPemDecodeStrictness();
  testPemDecodeAll();
  testPemEncodeLabel();
  testAttrValueEncodeHexForm();
  testRfc5280TimeCutover();
  testPemDecodeAllTrailingProse();
  testCoerceAndDecodeRoot();
  testAttrValueMalformedString();
  testNameLabelDerivation();
  testGeneralizedTimeUtf8RawSeqDefaults();
  testGeneralNameArms();
  testExtensionDecoderReaderCatches();
  testCrlDistributionPointShapes();
  testCertExtensionDecodersLoadGuard();
  testSignedEnvelopeTbs();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("CHECKS " + helpers.getChecks());
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  }
}
