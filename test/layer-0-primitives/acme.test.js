// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.acme (RFC 8555 / 8737 / 8738 / 9773 ACME message layer).
 * RED-first: pki.acme is undefined until the module lands. The object model
 * (spec validators + identify + the three state machines) is exercised here;
 * the builders, challenge computations, and ARI compose the pki.jose envelope.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = require("../helpers/vectors");
var subtle = require("../../lib/webcrypto").webcrypto.subtle;
var asn1 = pki.asn1;
var b = asn1.build;
var oid = require("../../lib/oid");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
async function acode(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

var REAL_CERT = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);
// A structurally-valid validation certificate: REAL_CERT's tbs with its [3]
// extensions replaced (x509.parse is structural, so the placeholder signature is fine).
function makeValidationCert(exts) {
  var tbs = asn1.decode(REAL_CERT).children[0];
  var cert = asn1.decode(REAL_CERT);
  var newTbs = b.sequence([
    tbs.children[0].bytes, tbs.children[1].bytes, tbs.children[2].bytes, tbs.children[3].bytes,
    tbs.children[4].bytes, tbs.children[5].bytes, tbs.children[6].bytes,
    b.explicit(3, b.sequence(exts)),
  ]);
  return b.sequence([newTbs, cert.children[1].bytes, cert.children[2].bytes]);
}
function sanExt(names, critical) {
  var children = [b.oid(oid.byName("subjectAltName"))];
  if (critical) children.push(b.boolean(true));
  children.push(b.octetString(b.sequence(names)));
  return b.sequence(children);
}
function dnsName(v) { return b.contextPrimitive(2, Buffer.from(v, "ascii")); }
function ipName(bytes) { return b.contextPrimitive(7, Buffer.from(bytes)); }
// A hand-built acmeIdentifier extension whose Authorization is `digest` (any size).
function acmeIdExt(digest, critical) {
  var children = [b.oid(oid.byName("acmeIdentifier"))];
  if (critical) children.push(b.boolean(true));
  children.push(b.octetString(b.octetString(digest)));
  return b.sequence(children);
}
// An authorityKeyIdentifier extension carrying `keyId` (a [0] IMPLICIT keyIdentifier).
function akiExt(keyId) {
  var akiValue = b.sequence([b.contextPrimitive(0, keyId)]);
  return b.sequence([b.oid(oid.byName("authorityKeyIdentifier")), b.octetString(akiValue)]);
}
// A cert derived from REAL_CERT with its serialNumber (child 1) and/or [3]
// extensions (child 7) swapped; the placeholder signature stays (x509.parse is structural).
function makeCert(opts) {
  opts = opts || {};
  var cert = asn1.decode(REAL_CERT);
  var kids = cert.children[0].children.map(function (c) { return c.bytes; });
  if (opts.serial) kids[1] = opts.serial;
  if (opts.exts) kids[7] = b.explicit(3, b.sequence(opts.exts));
  return b.sequence([b.sequence(kids), cert.children[1].bytes, cert.children[2].bytes]);
}
// A minimal DER PKCS#10 CSR: version 0, empty-or-CN subject, the given raw SPKI
// DER, and an optional extensionRequest attribute carrying a SAN of dNSNames.
var ECDSA_SHA256 = "1.2.840.10045.4.3.2";
function sanExtension(dnsNames) {
  var gns = dnsNames.map(function (n) { return b.contextPrimitive(2, Buffer.from(n, "ascii")); });
  return b.sequence([b.oid(oid.byName("subjectAltName")), b.octetString(b.sequence(gns))]);
}
function extensionRequestAttr(dnsNames) {
  var exts = b.sequence([sanExtension(dnsNames)]);          // Extensions ::= SEQUENCE OF Extension
  return b.sequence([b.oid(oid.byName("extensionRequest")), b.set([exts])]);
}
function cnSubject(cn) { return b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8(cn)])])]); }
function buildCsr(o) {
  o = o || {};
  var attrList = o.san ? extensionRequestAttr(o.san) : Buffer.alloc(0);
  var cri = b.sequence([
    b.integer(0n),
    o.subject || b.sequence([]),
    o.spki,
    b.contextConstructed(0, attrList),
  ]);
  return b.sequence([cri, b.sequence([b.oid(ECDSA_SHA256)]), b.bitString(Buffer.from([0x00]), 0)]);
}
async function ecKeyPair() {
  var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { key: kp.privateKey, jwk: await subtle.exportKey("jwk", kp.publicKey), spki: Buffer.from(await subtle.exportKey("spki", kp.publicKey)) };
}
function b64uJson(s) { return JSON.parse(Buffer.from(pki.jose.base64url.decode(s)).toString("utf8")); }

var DIRECTORY = { newNonce: "https://ca/n", newAccount: "https://ca/a", newOrder: "https://ca/o", revokeCert: "https://ca/r", keyChange: "https://ca/k", meta: { termsOfService: "https://ca/tos" }, renewalInfo: "https://ca/ri" };
var ORDER = { status: "pending", expires: "2026-01-01T00:00:00Z", identifiers: [{ type: "dns", value: "example.org" }], authorizations: ["https://ca/authz/1"], finalize: "https://ca/o/1/finalize" };
var AUTHZ = { identifier: { type: "dns", value: "example.org" }, status: "pending", challenges: [{ type: "http-01", url: "https://ca/chall/1", status: "pending", token: "DGyRejmCefe7v4NfDGDKfA" }] };
var CHALLENGE = { type: "http-01", url: "https://ca/chall/1", status: "pending", token: "DGyRejmCefe7v4NfDGDKfA" };

// ---- object validators (RFC 8555 sec. 7.1.x) -------------------------
function testObjects() {
  // 39. a full directory validates.
  check("39. directory validates", pki.acme.validate("directory", DIRECTORY).newNonce === "https://ca/n");
  // 40. a directory missing a required resource rejects.
  var noNonce = Object.assign({}, DIRECTORY); delete noNonce.newNonce;
  check("40. directory missing newNonce rejected", code(function () { pki.acme.validate("directory", noNonce); }) === "acme/missing-field");
  // 41. an unrecognized order status rejects.
  check("41. order bad status rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { status: "complete" })); }) === "acme/bad-status");
  // 42. expires is required-when pending/valid; optional otherwise.
  var pendNoExp = Object.assign({}, ORDER); delete pendNoExp.expires;
  check("42a. pending order without expires rejected", code(function () { pki.acme.validate("order", pendNoExp); }) === "acme/missing-field");
  check("42b. invalid order without expires accepted", pki.acme.validate("order", Object.assign({}, pendNoExp, { status: "invalid" })).status === "invalid");
  // 43. finalize URL + non-empty authorizations required.
  var noFin = Object.assign({}, ORDER); delete noFin.finalize;
  check("43a. order without finalize rejected", code(function () { pki.acme.validate("order", noFin); }) === "acme/missing-field");
  check("43b. empty authorizations rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { authorizations: [] })); }) === "acme/bad-order");
  // 44. an authorization identifier value beginning *. rejected (sec. 7.1.4).
  check("44. authz wildcard value rejected", code(function () { pki.acme.validate("authorization", Object.assign({}, AUTHZ, { identifier: { type: "dns", value: "*.example.org" } })); }) === "acme/bad-identifier");
  // 45. wildcard flag true / false / absent all accepted for the authz shape.
  check("45a. wildcard true accepted", pki.acme.validate("authorization", Object.assign({}, AUTHZ, { wildcard: true })).wildcard === true);
  check("45b. wildcard false accepted", pki.acme.validate("authorization", Object.assign({}, AUTHZ, { wildcard: false })).wildcard === false);
  check("45c. wildcard absent accepted", pki.acme.validate("authorization", AUTHZ).status === "pending");
  // 46. validated is required-when the challenge is valid.
  check("46a. valid challenge without validated rejected", code(function () { pki.acme.validate("challenge", Object.assign({}, CHALLENGE, { status: "valid" })); }) === "acme/missing-field");
  check("46b. valid challenge with validated accepted", pki.acme.validate("challenge", Object.assign({}, CHALLENGE, { status: "valid", validated: "2026-01-01T00:00:00Z" })).status === "valid");
  // 47. a processing challenge MAY carry an error (errata 5732).
  check("47. processing challenge with error accepted", pki.acme.validate("challenge", Object.assign({}, CHALLENGE, { status: "processing", error: { type: "urn:ietf:params:acme:error:connection" } })).status === "processing");
  // unknown fields are tolerated, never reflected.
  check("47b. unknown field ignored", pki.acme.validate("order", Object.assign({}, ORDER, { futureField: 1 })).status === "pending");
  // a wildcard dns identifier is legal in an ORDER (CA order resources carry them);
  // the order validator must not reject the *. shape the authorization validator does.
  check("47c. wildcard order identifier accepted", pki.acme.validate("order", Object.assign({}, ORDER, { identifiers: [{ type: "dns", value: "*.example.org" }] })).identifiers.length === 1);
  check("47d. double-label wildcard order identifier rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { identifiers: [{ type: "dns", value: "*.*.example.org" }] })); }) === "acme/bad-identifier");
  // an account contact is a URI, most commonly mailto: -- it must not be narrowed to http(s).
  check("47e. account mailto contact accepted", pki.acme.validate("account", { status: "valid", orders: "https://ca/acct/1/orders", contact: ["mailto:admin@example.org"] }).status === "valid");
  check("47f. account non-URI contact rejected", code(function () { pki.acme.validate("account", { status: "valid", orders: "https://ca/acct/1/orders", contact: ["not a uri"] }); }) === "acme/bad-account");
  // a syntactically well-formed but CALENDAR-impossible RFC 3339 instant is rejected.
  check("47g. impossible month rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2026-13-01T00:00:00Z" })); }) === "acme/bad-order");
  check("47h. February 30 rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2026-02-30T00:00:00Z" })); }) === "acme/bad-order");
  check("47i. hour 25 rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2026-01-01T25:00:00Z" })); }) === "acme/bad-order");
  check("47j. out-of-range zone offset rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2026-01-01T00:00:00+25:00" })); }) === "acme/bad-order");
  check("47k. leap-year February 29 accepted", pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2028-02-29T00:00:00Z" })).status === "pending");
  check("47l. non-leap February 29 rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2026-02-29T00:00:00Z" })); }) === "acme/bad-order");
  // a :60 leap second is rejected -- the toolkit only handles instants it can compare.
  check("47o. leap-second timestamp rejected", code(function () { pki.acme.validate("order", Object.assign({}, ORDER, { expires: "2026-06-30T23:59:60Z" })); }) === "acme/bad-order");
  // an authorization's challenges are each validated as a challenge, not just "an object".
  check("47m. authz with a malformed challenge rejected", code(function () { pki.acme.validate("authorization", Object.assign({}, AUTHZ, { challenges: [{ type: "http-01" }] })); }) === "acme/missing-field");
  check("47n. authz with a bad-status challenge rejected", code(function () { pki.acme.validate("authorization", Object.assign({}, AUTHZ, { challenges: [{ type: "http-01", url: "https://ca/c", status: "bogus" }] })); }) === "acme/bad-status");
}

// ---- state machines (RFC 8555 sec. 7.1.6) ----------------------------
function testTransitions() {
  // 48. every legal edge accepted; one illegal edge per machine rejected.
  check("48a. order pending->ready ok", code(function () { pki.acme.assertTransition("order", "pending", "ready"); }) === "NO-THROW");
  check("48b. order ready->processing->valid ok", code(function () { pki.acme.assertTransition("order", "ready", "processing"); pki.acme.assertTransition("order", "processing", "valid"); }) === "NO-THROW");
  check("48c. any->invalid ok", code(function () { pki.acme.assertTransition("order", "processing", "invalid"); }) === "NO-THROW");
  check("48d. order valid->pending rejected", code(function () { pki.acme.assertTransition("order", "valid", "pending"); }) === "acme/bad-transition");
  check("48e. challenge invalid->valid rejected", code(function () { pki.acme.assertTransition("challenge", "invalid", "valid"); }) === "acme/bad-transition");
  check("48f. authz deactivated->valid rejected", code(function () { pki.acme.assertTransition("authorization", "deactivated", "valid"); }) === "acme/bad-transition");
  check("48g. challenge processing retry (self) ok", code(function () { pki.acme.assertTransition("challenge", "processing", "processing"); }) === "NO-THROW");
  // a terminal valid order/challenge must NOT regress to invalid (RFC 8555 sec. 7.1.6).
  check("48h. order valid->invalid rejected (valid is terminal)", code(function () { pki.acme.assertTransition("order", "valid", "invalid"); }) === "acme/bad-transition");
  check("48i. challenge valid->invalid rejected (valid is terminal)", code(function () { pki.acme.assertTransition("challenge", "valid", "invalid"); }) === "acme/bad-transition");
  // a non-terminal state -> invalid stays legal (the table, not a blanket shortcut).
  check("48j. order ready->invalid ok", code(function () { pki.acme.assertTransition("order", "ready", "invalid"); }) === "NO-THROW");
}

// ---- problem documents (RFC 8555 sec. 6.7) ---------------------------
function testProblem() {
  // 49. a top-level identifier is forbidden.
  check("49. problem top-level identifier rejected", code(function () { pki.acme.validate("problem", { type: "urn:ietf:params:acme:error:malformed", identifier: { type: "dns", value: "x" } }); }) === "acme/bad-problem");
  // the type MUST be in the ACME error namespace -- a generic problem+json (about:blank) is not an ACME error.
  check("49b. non-namespace problem type rejected", code(function () { pki.acme.validate("problem", { type: "about:blank" }); }) === "acme/bad-problem");
  check("49c. non-namespace subproblem type rejected", code(function () { pki.acme.validateProblem({ type: "urn:ietf:params:acme:error:compound", subproblems: [{ type: "about:blank" }] }); }) === "acme/bad-problem");
  // 50. subproblems (each optionally carrying an identifier) surfaced.
  var compound = { type: "urn:ietf:params:acme:error:compound", subproblems: [{ type: "urn:ietf:params:acme:error:rejectedIdentifier", identifier: { type: "dns", value: "a.example" } }] };
  check("50. compound + subproblem identifier accepted", pki.acme.validate("problem", compound).subproblems.length === 1);
  // validateProblem is reachable directly (not only via validate("problem", ...)).
  check("50b. validateProblem accepts a bare problem document", pki.acme.validateProblem({ type: "urn:ietf:params:acme:error:malformed", detail: "x" }).detail === "x");
  // a subproblem identifier MAY be a wildcard (a rejectedIdentifier for a wildcard order).
  check("50c. wildcard subproblem identifier accepted", pki.acme.validateProblem({ type: "urn:ietf:params:acme:error:compound", subproblems: [{ type: "urn:ietf:params:acme:error:rejectedIdentifier", identifier: { type: "dns", value: "*.example.org" } }] }).subproblems.length === 1);
}

// ---- identifiers (RFC 8555 sec. 7.1.4 / RFC 8738) --------------------
function testIdentifiers() {
  function dns(v) { return pki.acme.validate("authorization", { identifier: { type: "dns", value: v }, status: "pending", challenges: [{ type: "http-01", url: "https://ca/c", status: "pending", token: "DGyRejmCefe7v4NfDGDKfA" }] }); }
  // 52. a non-ASCII (u-umlaut) dns value rejected (A-label required).
  check("52. non-ASCII dns rejected", code(function () { dns("münchen.example"); }) === "acme/bad-identifier");
  // 53. a malformed xn-- A-label rejected.
  check("53. bad xn-- ACE rejected", code(function () { dns("xn--.example"); }) === "acme/bad-identifier");
  check("53b. good xn-- ACE accepted", dns("xn--mnchen-3ya.example").status === "pending");
  // a label over 63 octets is invalid (RFC 1035 sec. 2.3.4).
  check("53c. over-long dns label rejected", code(function () { dns(new Array(65).join("a") + ".example"); }) === "acme/bad-identifier");
  check("53d. 63-octet label accepted", dns(new Array(64).join("a") + ".example").status === "pending");
  // 54. ip canonical round-trip (RFC 8738 / RFC 5952).
  function ip(v) { return pki.acme.validate("authorization", { identifier: { type: "ip", value: v }, status: "pending", challenges: [{ type: "http-01", url: "https://ca/c", status: "pending", token: "DGyRejmCefe7v4NfDGDKfA" }] }); }
  check("54a. IPv4 leading-zero rejected", code(function () { ip("192.168.001.001"); }) === "acme/bad-identifier");
  check("54b. IPv6 non-canonical rejected", code(function () { ip("2001:0db8::1"); }) === "acme/bad-identifier");
  check("54c. IPv6 canonical accepted", ip("2001:db8::1").status === "pending");
  check("54d. IPv4 canonical accepted", ip("192.168.1.1").status === "pending");
  check("54e. IPv6 uppercase rejected", code(function () { ip("2001:DB8::1"); }) === "acme/bad-identifier");
}

// ---- identify mutual exclusion (RFC 8555 dispatch) -------------------
function testIdentify() {
  // 80. every fixture identifies as exactly one kind.
  var cases = { directory: DIRECTORY, order: ORDER, authorization: AUTHZ, challenge: CHALLENGE, renewalInfo: { suggestedWindow: { start: "2026-01-01T00:00:00Z", end: "2026-01-08T00:00:00Z" } }, account: { status: "valid", orders: "https://ca/acct/1/orders" }, problem: { type: "urn:ietf:params:acme:error:malformed" }, jws: { protected: "eyJ", payload: "", signature: "abc" } };
  var ok = true;
  Object.keys(cases).forEach(function (k) { if (pki.acme.identify(cases[k]) !== k) { ok = false; console.log("  identify " + k + " -> " + pki.acme.identify(cases[k])); } });
  check("80. every ACME object identifies as its one kind", ok);
  // a DER structure (a Buffer / non-object) identifies as unknown, never routes.
  check("80b. DER buffer -> unknown", pki.acme.identify(Buffer.from([0x30, 0x03])) === "unknown");
  check("80c. plain object -> unknown", pki.acme.identify({ hello: 1 }) === "unknown");
}

// ---- challenge computations (RFC 8555 sec. 8 / 8737 / 8738) ----------
var TOKEN = "DGyRejmCefe7v4NfDGDKfA";   // 22 base64url chars
async function testChallenges() {
  var ec = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var jwk = await subtle.exportKey("jwk", ec.publicKey);
  var ec2 = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var jwk2 = await subtle.exportKey("jwk", ec2.publicKey);
  // 51. token syntax: `=`, `+`, and a 21-char token each rejected.
  check("51a. token with = rejected", (await acode(function () { return pki.acme.keyAuthorization("DGyRejmCefe7v4NfDGDKf=", jwk); })) === "acme/bad-token");
  check("51b. token with + rejected", (await acode(function () { return pki.acme.keyAuthorization("DGyRejmCefe7v4NfDGDK+A", jwk); })) === "acme/bad-token");
  check("51c. 21-char token rejected", (await acode(function () { return pki.acme.keyAuthorization("DGyRejmCefe7v4NfDGDKf", jwk); })) === "acme/bad-token");
  // 56. keyAuthorization = token.thumbprint; changing the account key changes it.
  var ka = await pki.acme.keyAuthorization(TOKEN, jwk);
  var tp = await pki.jose.thumbprint(jwk);
  check("56. keyAuthorization format", ka === TOKEN + "." + tp && ka !== (await pki.acme.keyAuthorization(TOKEN, jwk2)));
  // 57. http-01 path + body.
  var h = await pki.acme.http01(TOKEN, jwk);
  check("57. http-01 path + body", h.path === "/.well-known/acme-challenge/" + TOKEN && h.body === ka && !/\n$/.test(h.body));
  // 58. dns-01 name + value = b64u(sha256(keyAuth)).
  var d = await pki.acme.dns01(TOKEN, jwk, "example.org");
  var expectDns = pki.jose.base64url.encode(Buffer.from(await subtle.digest("SHA-256", Buffer.from(ka, "ascii"))));
  check("58. dns-01 name + digest", d.name === "_acme-challenge.example.org" && d.value === expectDns);
  // 59. wildcard order identifier validates at the base domain.
  check("59. dns-01 wildcard strip", (await pki.acme.dns01(TOKEN, jwk, "*.example.org")).name === "_acme-challenge.example.org");
  // 60. tls-alpn extnValue = OCTET STRING(32) of the digest; build/read round-trip.
  var digest32 = Buffer.from(await subtle.digest("SHA-256", Buffer.from(ka, "ascii")));
  var ext = await pki.acme.tlsAlpn01Extension(TOKEN, jwk);
  var extDec = asn1.decode(ext);
  var innerAuth = asn1.read.octetString(asn1.decode(asn1.read.octetString(extDec.children[extDec.children.length - 1])));
  check("60. tls-alpn extnValue 32-byte digest round-trip", innerAuth.length === 32 && innerAuth.equals(digest32) && extDec.children[1].tagNumber === 1 /* BOOLEAN critical */);
  // a full validation cert verifies; a 31/33-byte Authorization is rejected.
  var goodCert = makeValidationCert([acmeIdExt(digest32, true), sanExt([dnsName("pkijs.com")], false)]);
  check("60b. valid tls-alpn cert verifies", (await acode(function () { return pki.acme.verifyTlsAlpn01(goodCert, TOKEN, jwk, { type: "dns", value: "pkijs.com" }); })) === "NO-THROW");
  check("60c. 33-byte Authorization rejected", (await acode(function () { return pki.acme.verifyTlsAlpn01(makeValidationCert([acmeIdExt(Buffer.alloc(33), true), sanExt([dnsName("pkijs.com")], false)]), TOKEN, jwk, { type: "dns", value: "pkijs.com" }); })) === "acme/bad-tlsalpn");
  // 61. non-critical acmeIdentifier + a two-entry SAN each rejected.
  check("61a. non-critical acmeIdentifier rejected", (await acode(function () { return pki.acme.verifyTlsAlpn01(makeValidationCert([acmeIdExt(digest32, false), sanExt([dnsName("pkijs.com")], false)]), TOKEN, jwk, { type: "dns", value: "pkijs.com" }); })) === "acme/bad-tlsalpn");
  check("61b. two-entry SAN rejected", (await acode(function () { return pki.acme.verifyTlsAlpn01(makeValidationCert([acmeIdExt(digest32, true), sanExt([dnsName("pkijs.com"), dnsName("www.pkijs.com")], false)]), TOKEN, jwk, { type: "dns", value: "pkijs.com" }); })) === "acme/bad-tlsalpn");
  // 61c. a wrong-domain SAN rejected.
  check("61c. wrong SAN dNSName rejected", (await acode(function () { return pki.acme.verifyTlsAlpn01(goodCert, TOKEN, jwk, { type: "dns", value: "other.example" }); })) === "acme/bad-tlsalpn");
  // 62. an ip identifier requires a single iPAddress SAN.
  var ipCert = makeValidationCert([acmeIdExt(digest32, true), sanExt([ipName([192, 168, 1, 1])], false)]);
  check("62a. ip identifier iPAddress SAN accepted", (await acode(function () { return pki.acme.verifyTlsAlpn01(ipCert, TOKEN, jwk, { type: "ip", value: "192.168.1.1" }); })) === "NO-THROW");
  check("62b. ip identifier with dNSName SAN rejected", (await acode(function () { return pki.acme.verifyTlsAlpn01(goodCert, TOKEN, jwk, { type: "ip", value: "192.168.1.1" }); })) === "acme/bad-tlsalpn");
  // 62c. the iPAddress SAN VALUE must equal the requested ip -- a cert for one IP must
  // not verify for a different requested IP (only the tag was checked before).
  check("62c. mismatched iPAddress SAN rejected", (await acode(function () { return pki.acme.verifyTlsAlpn01(ipCert, TOKEN, jwk, { type: "ip", value: "203.0.113.10" }); })) === "acme/bad-tlsalpn");
  var ip6Cert = makeValidationCert([acmeIdExt(digest32, true), sanExt([ipName([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])], false)]);
  check("62d. matching IPv6 iPAddress SAN accepted", (await acode(function () { return pki.acme.verifyTlsAlpn01(ip6Cert, TOKEN, jwk, { type: "ip", value: "2001:db8::1" }); })) === "NO-THROW");
  // 63. the acmeIdentifier OID row resolves.
  check("63. acmeIdentifier OID row", oid.name("1.3.6.1.5.5.7.1.31") === "acmeIdentifier");
}

// ---- request builders (RFC 8555 sec. 7.x) ----------------------------
async function testBuilders() {
  var acct = await ecKeyPair();
  var cert = await ecKeyPair();
  var kid = "https://ca/acct/1";
  var base = { key: acct.key, alg: "ES256", nonce: "aGVsbG8", url: "https://ca/o", kid: kid };

  // 64. finalize payload csr = strict-b64u DER (not PEM); decodes back to the CSR.
  var goodCsr = buildCsr({ spki: cert.spki, san: ["example.org"] });
  var fin = await pki.acme.finalize(Object.assign({}, base, { url: "https://ca/o/1/finalize", csr: goodCsr, identifiers: [{ type: "dns", value: "example.org" }], accountJwk: acct.jwk }));
  check("64. finalize csr is b64u DER round-trip", Buffer.from(pki.jose.base64url.decode(b64uJson(fin.payload).csr)).equals(goodCsr));
  // the outer JWS verifies under the account key + acme-outer profile.
  check("64b. finalize JWS verifies", (await acode(function () { return pki.jose.verify(fin, { profile: "acme-outer", key: acct.jwk }); })) === "NO-THROW");

  // 65. identifier-set match (order-insensitive; CN counted).
  check("65a. matching SAN accepted", (await acode(function () { return pki.acme.finalize(Object.assign({}, base, { csr: goodCsr, identifiers: [{ type: "dns", value: "example.org" }], accountJwk: acct.jwk })); })) === "NO-THROW");
  check("65b. mismatched identifiers rejected", (await acode(function () { return pki.acme.finalize(Object.assign({}, base, { csr: goodCsr, identifiers: [{ type: "dns", value: "other.example" }], accountJwk: acct.jwk })); })) === "acme/csr-identifier-mismatch");
  check("65c. superset order rejected", (await acode(function () { return pki.acme.finalize(Object.assign({}, base, { csr: goodCsr, identifiers: [{ type: "dns", value: "example.org" }, { type: "dns", value: "www.example.org" }], accountJwk: acct.jwk })); })) === "acme/csr-identifier-mismatch");
  var cnCsr = buildCsr({ spki: cert.spki, subject: cnSubject("cn.example") });
  check("65d. CN counted in the identifier set", (await acode(function () { return pki.acme.finalize(Object.assign({}, base, { csr: cnCsr, identifiers: [{ type: "dns", value: "cn.example" }], accountJwk: acct.jwk })); })) === "NO-THROW");

  // 66. CSR public key == account key -> acme/key-reuse (sec. 11.1).
  var reuseCsr = buildCsr({ spki: acct.spki, san: ["example.org"] });
  check("66. finalize account-key-reuse rejected", (await acode(function () { return pki.acme.finalize(Object.assign({}, base, { csr: reuseCsr, identifiers: [{ type: "dns", value: "example.org" }], accountJwk: acct.jwk })); })) === "acme/key-reuse");

  // 67. EAB inner JWS: HS256 MAC only; payload == the account JWK; no nonce; url == outer.
  var macKey = Buffer.from("0123456789abcdef0123456789abcdef", "ascii");
  var macJwk = { kty: "oct", k: pki.jose.base64url.encode(macKey) };
  var eab = await pki.acme.externalAccountBinding({ macKey: macKey, kid: "mac-kid-1", url: base.url, accountJwk: acct.jwk });
  check("67a. EAB inner verifies under eab-inner + oct macKey", (await acode(function () { return pki.jose.verify(eab, { profile: "eab-inner", key: macJwk }); })) === "NO-THROW");
  check("67b. EAB inner payload == account JWK", JSON.stringify(b64uJson(eab.payload)) === JSON.stringify(acct.jwk));
  var eabHdr = b64uJson(eab.protected);
  check("67c. EAB header: HS256, kid, url==outer, no nonce", eabHdr.alg === "HS256" && eabHdr.kid === "mac-kid-1" && eabHdr.url === base.url && !("nonce" in eabHdr));
  check("67d. EAB rejects a signature alg", (await acode(function () { return pki.acme.externalAccountBinding({ macKey: macKey, kid: "k", url: base.url, accountJwk: acct.jwk, alg: "ES256" }); })) === "acme/bad-input");
  check("67d2. EAB rejects a non-key macKey (fail closed, no raw TypeError)", (await acode(function () { return pki.acme.externalAccountBinding({ macKey: "notakey", kid: "k", url: base.url, accountJwk: acct.jwk }); })) === "acme/bad-input");
  var acctPrivJwk = await subtle.exportKey("jwk", acct.key);   // carries the private `d`
  check("67d3. EAB rejects a private account jwk (no key leak in the payload)", (await acode(function () { return pki.acme.externalAccountBinding({ macKey: macKey, kid: "k", url: base.url, accountJwk: acctPrivJwk }); })) === "jose/private-key-material");
  check("67e. EAB inner refused by the outer profile (no HS* outside EAB)", (await acode(function () { return pki.jose.verify(eab, { profile: "acme-outer", key: macJwk }); })) !== "NO-THROW");

  // newAccount: jwk-signed (a new account has no kid), contact validated fail-closed, EAB attached.
  var na = await pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, contact: ["mailto:admin@example.org"], termsOfServiceAgreed: true, externalAccountBinding: eab });
  var naPayload = b64uJson(na.payload);
  check("67f. newAccount payload carries contact + tos + EAB", naPayload.contact[0] === "mailto:admin@example.org" && naPayload.termsOfServiceAgreed === true && naPayload.externalAccountBinding.protected === eab.protected);
  check("67g. newAccount is jwk-signed and verifies under the account key", JSON.stringify(b64uJson(na.protected).jwk) === JSON.stringify(acct.jwk) && (await acode(function () { return pki.jose.verify(na, { profile: "acme-outer", key: acct.jwk }); })) === "NO-THROW");
  check("67h. newAccount mailto with header fields rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, contact: ["mailto:a@b.com?subject=x"] }); })) === "acme/bad-contact");
  check("67i. newAccount mailto with two addresses rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, contact: ["mailto:a@b.com,c@d.com"] }); })) === "acme/bad-contact");
  check("67j. newAccount without an embedded jwk rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url }); })) === "acme/bad-input");
  check("67k. newAccount non-URI contact rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, contact: ["not a uri"] }); })) === "acme/bad-contact");
  check("67l. newAccount bare-email contact rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, contact: ["admin@example.org"] }); })) === "acme/bad-contact");
  // a kid-mode builder called without a kid must fail closed, not emit a keyless header.
  check("67m. newOrder with an undefined kid rejected", (await acode(function () { return pki.acme.newOrder({ key: acct.key, alg: "ES256", nonce: base.nonce, url: "https://ca/o", identifiers: [{ type: "dns", value: "example.org" }] }); })) === "jose/bad-header");
  // account flags must be actual booleans -- never coerce "false"/0 to true.
  check("67n. newAccount non-boolean termsOfServiceAgreed rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, termsOfServiceAgreed: "false" }); })) === "acme/bad-input");
  check("67o. newAccount non-boolean onlyReturnExisting rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, onlyReturnExisting: 1 }); })) === "acme/bad-input");
  // a mailto contact is caught regardless of scheme case (RFC 3986 schemes are case-insensitive).
  check("67q. newAccount uppercase MAILTO with header fields rejected", (await acode(function () { return pki.acme.newAccount({ key: acct.key, alg: "ES256", nonce: base.nonce, url: base.url, jwk: acct.jwk, contact: ["MAILTO:a@b.com?subject=x"] }); })) === "acme/bad-contact");

  // 68. keyChange nested JWS: inner jwk, no nonce, url == outer; payload {account, oldKey}.
  var nk = await ecKeyPair();
  var kc = await pki.acme.keyChange({ key: acct.key, alg: "ES256", kid: kid, account: kid, oldKey: acct.jwk, newKey: nk.key, newJwk: nk.jwk, newAlg: "ES256", nonce: base.nonce, url: "https://ca/k" });
  var inner = b64uJson(kc.payload);
  var innerHdr = b64uJson(inner.protected);
  var innerPay = b64uJson(inner.payload);
  check("68a. keyChange inner header jwk, url==outer, no nonce", JSON.stringify(innerHdr.jwk) === JSON.stringify(nk.jwk) && innerHdr.url === "https://ca/k" && !("nonce" in innerHdr));
  check("68b. keyChange inner payload {account, oldKey}", innerPay.account === kid && JSON.stringify(innerPay.oldKey) === JSON.stringify(acct.jwk));
  check("68c. keyChange inner verifies under keychange-inner + new key", (await acode(function () { return pki.jose.verify(inner, { profile: "keychange-inner", key: nk.jwk }); })) === "NO-THROW");
  check("68d. keyChange missing oldKey rejected", (await acode(function () { return pki.acme.keyChange({ key: acct.key, alg: "ES256", kid: kid, account: kid, newKey: nk.key, newJwk: nk.jwk, newAlg: "ES256", nonce: base.nonce, url: "https://ca/k" }); })) === "acme/bad-input");
  var acctPrivJwk2 = await subtle.exportKey("jwk", acct.key);
  check("68e. keyChange rejects a private oldKey (no key leak in the inner payload)", (await acode(function () { return pki.acme.keyChange({ key: acct.key, alg: "ES256", kid: kid, account: kid, oldKey: acctPrivJwk2, newKey: nk.key, newJwk: nk.jwk, newAlg: "ES256", nonce: base.nonce, url: "https://ca/k" }); })) === "jose/private-key-material");

  // 69. revokeCert: certificate = b64u(DER); reason 0..10; both key modes; exactly-one key ref.
  var predCert = makeCert({ exts: [akiExt(Buffer.from("aabbccddeeff00112233445566778899aabbccdd", "hex"))] });
  var rev = await pki.acme.revokeCert(Object.assign({}, base, { url: "https://ca/r", certificate: predCert, reason: 1 }));
  check("69a. revokeCert certificate is b64u DER", Buffer.from(pki.jose.base64url.decode(b64uJson(rev.payload).certificate)).equals(predCert) && b64uJson(rev.payload).reason === 1);
  check("69b. revokeCert kid-mode verifies", (await acode(function () { return pki.jose.verify(rev, { profile: "acme-outer", key: acct.jwk }); })) === "NO-THROW");
  var revJwk = await pki.acme.revokeCert({ key: cert.key, alg: "ES256", nonce: base.nonce, url: "https://ca/r", certificate: predCert, jwk: cert.jwk });
  check("69c. revokeCert jwk-mode signs with the cert key", (await acode(function () { return pki.jose.verify(revJwk, { profile: "acme-outer", key: cert.jwk }); })) === "NO-THROW");
  check("69d. revokeCert reason out of range rejected", (await acode(function () { return pki.acme.revokeCert(Object.assign({}, base, { url: "https://ca/r", certificate: predCert, reason: 11 })); })) === "acme/bad-revocation-reason");
  check("69e. revokeCert both kid and jwk rejected", (await acode(function () { return pki.acme.revokeCert(Object.assign({}, base, { url: "https://ca/r", certificate: predCert, jwk: cert.jwk })); })) === "acme/bad-input");
  check("69g. revokeCert unassigned reason 7 rejected", (await acode(function () { return pki.acme.revokeCert(Object.assign({}, base, { url: "https://ca/r", certificate: predCert, reason: 7 })); })) === "acme/bad-revocation-reason");
  check("69h. revokeCert assigned reasons 6 and 8 accepted", (await acode(function () { return pki.acme.revokeCert(Object.assign({}, base, { url: "https://ca/r", certificate: predCert, reason: 6 })); })) === "NO-THROW" && (await acode(function () { return pki.acme.revokeCert(Object.assign({}, base, { url: "https://ca/r", certificate: predCert, reason: 8 })); })) === "NO-THROW");

  // deactivate: the only client-settable status, kid-signed.
  var deact = await pki.acme.deactivate({ key: acct.key, alg: "ES256", nonce: base.nonce, url: "https://ca/authz/1", kid: kid });
  check("69f. deactivate payload is {status:deactivated} and verifies", b64uJson(deact.payload).status === "deactivated" && (await acode(function () { return pki.jose.verify(deact, { profile: "acme-outer", key: acct.jwk }); })) === "NO-THROW");

  // 70. newOrder replaces == the ARI certID of the predecessor.
  var predId = pki.acme.ariCertId(predCert);
  var ord = await pki.acme.newOrder(Object.assign({}, base, { url: "https://ca/o", identifiers: [{ type: "dns", value: "example.org" }], replaces: predId }));
  check("70. newOrder replaces == predecessor certID", b64uJson(ord.payload).replaces === predId);
  // a wildcard order identifier is accepted; a double wildcard is not.
  check("70b. wildcard order identifier accepted", (await acode(function () { return pki.acme.newOrder(Object.assign({}, base, { url: "https://ca/o", identifiers: [{ type: "dns", value: "*.example.org" }] })); })) === "NO-THROW");
  check("70c. double-label wildcard rejected", (await acode(function () { return pki.acme.newOrder(Object.assign({}, base, { url: "https://ca/o", identifiers: [{ type: "dns", value: "*.*.example.org" }] })); })) === "acme/bad-identifier");

  // POST-as-GET emits an empty payload; challengeResponse emits {} -- distinct bytes.
  var pag = await pki.acme.postAsGet(Object.assign({}, base, { url: kid }));
  var cr = await pki.acme.challengeResponse(Object.assign({}, base, { url: "https://ca/chall/1" }));
  check("33. POST-as-GET payload empty vs challenge {} distinct", pag.payload === "" && cr.payload === pki.jose.base64url.encode(Buffer.from("{}", "utf8")));
  // POST-as-GET is always kid-signed: a leftover jwk (no kid) is ignored, and the
  // missing kid fails closed rather than downgrading to an embedded-key read.
  check("33b. postAsGet ignores a leftover jwk and requires kid", (await acode(function () { return pki.acme.postAsGet({ key: acct.key, alg: "ES256", nonce: base.nonce, url: kid, jwk: acct.jwk }); })) === "jose/bad-header");
  var pag2 = await pki.acme.postAsGet(Object.assign({}, base, { url: kid, jwk: acct.jwk }));
  check("33c. postAsGet with kid+jwk still emits a kid-only header", !("jwk" in b64uJson(pag2.protected)) && b64uJson(pag2.protected).kid === kid);
}

// ---- ARI (RFC 9773) --------------------------------------------------
function testAri() {
  var keyId = Buffer.from("aabbccddeeff00112233445566778899aabbccdd", "hex");
  var cert = makeCert({ exts: [akiExt(keyId)] });
  // 71. certID = b64u(aki).b64u(serial); parse round-trips both halves strict-b64u.
  var id = pki.acme.ariCertId(cert);
  check("71a. certID two b64u halves joined by .", /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(id));
  var parsed = pki.acme.parseAriCertId(id);
  check("71b. parseAriCertId keyIdentifier round-trips", Buffer.isBuffer(parsed.keyIdentifier) && parsed.keyIdentifier.equals(keyId));
  check("71c. a certID with padding rejected", code(function () { pki.acme.parseAriCertId(id.split(".")[0] + "=." + id.split(".")[1]); }) === "acme/bad-certid");
  check("71d. a one-part certID rejected", code(function () { pki.acme.parseAriCertId("onlyonepart"); }) === "acme/bad-certid");
  check("71e. a cert with no AKI rejected", code(function () { pki.acme.ariCertId(REAL_CERT); }) === "acme/bad-certid");

  // 72. a high-bit serial keeps its leading 00 content octet (the class bug).
  var highbit = makeCert({ serial: b.integer(0xC0FFEEn), exts: [akiExt(keyId)] });
  var hbSerial = pki.acme.parseAriCertId(pki.acme.ariCertId(highbit)).serial;
  check("72. high-bit serial keeps leading 00 sign-pad octet", hbSerial.length === 4 && hbSerial[0] === 0x00 && hbSerial.equals(Buffer.from([0x00, 0xc0, 0xff, 0xee])));

  // 73. an inverted / zero-width renewal window rejected.
  check("73a. inverted window rejected", code(function () { pki.acme.validateRenewalInfo({ suggestedWindow: { start: "2026-01-08T00:00:00Z", end: "2026-01-01T00:00:00Z" } }); }) === "acme/bad-renewal-window");
  check("73b. zero-width window rejected", code(function () { pki.acme.validateRenewalInfo({ suggestedWindow: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T00:00:00Z" } }); }) === "acme/bad-renewal-window");
  check("73c. a valid window accepted", pki.acme.validateRenewalInfo({ suggestedWindow: { start: "2026-01-01T00:00:00Z", end: "2026-01-08T00:00:00Z" } }).suggestedWindow.end === "2026-01-08T00:00:00Z");
  check("73d. a leap-second window endpoint rejected", code(function () { pki.acme.validateRenewalInfo({ suggestedWindow: { start: "2026-01-01T00:00:00Z", end: "2026-06-30T23:59:60Z" } }); }) === "acme/bad-renewal-window");
  // 74. missing start or end rejected.
  check("74a. missing end rejected", code(function () { pki.acme.validateRenewalInfo({ suggestedWindow: { start: "2026-01-01T00:00:00Z" } }); }) === "acme/bad-renewal-window");
  check("74b. missing start rejected", code(function () { pki.acme.validateRenewalInfo({ suggestedWindow: { end: "2026-01-08T00:00:00Z" } }); }) === "acme/bad-renewal-window");
  // the generic validate() dispatch routes renewalInfo through the full window check,
  // not just the spec shape -- a { suggestedWindow: {} } must not slip through.
  check("74f. validate(renewalInfo) applies the window check", code(function () { pki.acme.validate("renewalInfo", { suggestedWindow: {} }); }) === "acme/bad-renewal-window");
  // A malformed renewalInfo must throw a WELL-FORMED typed fault -- the kind name
  // "renewalInfo" must not leak camelCase into the error code (a code like
  // "acme/bad-renewalInfo" violates the domain/reason shape and would make the
  // error constructor itself throw a raw TypeError instead of a PkiError).
  check("74c. non-object renewalInfo throws a typed acme fault", code(function () { pki.acme.validate("renewalInfo", "notanobject"); }).indexOf("acme/") === 0);
  check("74d. mistyped suggestedWindow throws a typed acme fault", code(function () { pki.acme.validate("renewalInfo", { suggestedWindow: 5 }); }).indexOf("acme/") === 0);
  check("74e. validateRenewalInfo on a non-object throws a typed acme fault", code(function () { pki.acme.validateRenewalInfo(42); }).indexOf("acme/") === 0);
}

// ---- FORMATS non-registration (dispatch) -----------------------------
function testRegistration() {
  // 79. ACME is a JSON layer; it never registers in the DER format orchestrator.
  var formats = pki.schema.all().map(function (f) { return f.key || f.name || f; });
  check("79a. schema.all() has no acme/jose entry", formats.indexOf("acme") === -1 && formats.indexOf("jose") === -1);
  var jsonBody = Buffer.from(JSON.stringify(DIRECTORY), "utf8");
  check("79b. an ACME JSON body into schema.parse never routes", code(function () { pki.schema.parse(jsonBody); }).indexOf("schema/") === 0);
}

function run() {
  return Promise.resolve().then(function () {
    testObjects();
    testTransitions();
    testProblem();
    testIdentifiers();
    testIdentify();
    testRegistration();
    return testChallenges();
  }).then(function () {
    return testBuilders();
  }).then(function () {
    testAri();
    console.log("CHECKS " + helpers.getChecks());
  });
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(function () {}, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
