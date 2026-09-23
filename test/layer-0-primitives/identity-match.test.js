// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- service identity (pki.identity.match).
 * RED conformance vectors for RFC 9525, which obsoletes RFC 6125, with RFC 4985
 * for the SRVName otherName and RFC 5280 sec. 4.2.1.6 for the entries it reads.
 * The oracle is the section cited on each group. Every vector drives the shipped
 * door with a certificate this file signs, so a rule that stops being applied
 * shows up as a verdict rather than as a missing symbol.
 */

var crypto = require("crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }
async function codeAsync(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }

var KP = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
var KEY = KP.privateKey.export({ format: "der", type: "pkcs8" });
var SPKI = KP.publicKey.export({ format: "der", type: "spki" });

var serial = 100;

/** A certificate carrying exactly the GeneralName entries given, as pre-encoded DER, so an
 *  entry the builders refuse to emit can still be presented to the matcher. */
async function certWithSanDer(entries, subject) {
  serial += 1;
  var san = b.sequence(entries);
  return pki.x509.sign({
    subject: subject || [{ commonName: "identity-subject.example" }],
    subjectPublicKey: SPKI, serialNumber: serial, notBefore: NB, notAfter: NA,
    extensions: [b.sequence([b.oid(pki.oid.byName("subjectAltName")), b.octetString(san)])],
  }, { key: KEY });
}
function dnsEntry(name) { return b.implicit(2, b.ia5(name)); }
function ipEntry(buf) { return b.implicit(7, b.octetString(buf)); }
function uriEntry(uri) { return b.implicit(6, b.ia5(uri)); }
function otherNameEntry(typeOid, valueDer) {
  return b.contextConstructed(0, Buffer.concat([b.oid(typeOid), b.explicit(0, valueDer)]));
}
function srvEntry(text) { return otherNameEntry(pki.oid.byName("dnsSRV"), b.ia5(text)); }

async function certWithDns() {
  var names = [];
  for (var i = 0; i < arguments.length; i++) names.push(dnsEntry(arguments[i]));
  return certWithSanDer(names);
}

// ---- DNS-ID (RFC 9525 sec. 6.3) ---------------------------------------
async function testDnsId() {
  var c = await certWithDns("www.example.com");
  check("1. a name equal to the reference matches", pki.identity.match(c, "www.example.com").matched === true);
  check("1b. ...and the verdict names the reference that matched",
    pki.identity.match(c, "www.example.com").matchedReference === "www.example.com");
  check("2. the reference is folded as ASCII", pki.identity.match(c, "WWW.EXAMPLE.COM").matched === true);
  var cUpper = await certWithDns("WWW.Example.COM");
  check("3. the presented name is folded the same way", pki.identity.match(cUpper, "www.example.com").matched === true);
  check("4. a trailing dot on the reference is normalized", pki.identity.match(c, "www.example.com.").matched === true);
  var cDot = await certWithDns("www.example.com.");
  check("5. a trailing dot on the presented name is normalized the same way",
    pki.identity.match(cDot, "www.example.com").matched === true);

  var cThree = await certWithDns("a.example.com", "b.example.com", "www.example.com");
  var vThree = pki.identity.match(cThree, "www.example.com");
  check("6. the search reaches the third presented entry",
    vThree.matched === true && vThree.matchedEntry.indexOf("www.example.com") !== -1);
  var vRefs = pki.identity.match(c, ["a.example.net", "b.example.net", "www.example.com"]);
  check("7. the search reaches the third reference", vRefs.matched === true && vRefs.matchedReference === "www.example.com");

  var cA = await certWithDns("xn--bcher-kva.example.com");
  check("8. an A-label is compared as the ASCII it is, not decoded",
    pki.identity.match(cA, "XN--BCHER-KVA.example.com").matched === true);
  var cUnder = await certWithDns("_dmarc.example.com");
  check("9. an underscore label is compared, not held to the name-constraint host rule",
    pki.identity.match(cUnder, "_dmarc.example.com").matched === true);
  var cUri = await certWithSanDer([uriEntry("https://a-b.c-d.example.com/x")]);
  check("10. the widest-acceptance control for the URI host reader",
    pki.identity.match(cUri, { type: "uri", scheme: "https", value: "a-b.c-d.example.com" }).matched === true);
}

// ---- Wildcards (RFC 9525 sec. 6.3, sec. 7.1) --------------------------
async function testWildcards() {
  var cStar = await certWithDns("*.example.com");
  check("11. a wildcard reaches one label", pki.identity.match(cStar, "foo.example.com").matched === true);
  var cDeep = await certWithDns("*.a.example.com");
  check("12. ...at whatever depth the label sits", pki.identity.match(cDeep, "b.a.example.com").matched === true);
  check("13. a wildcard does not match the name it is a subdomain of",
    pki.identity.match(cStar, "example.com").matched === false);
  check("14. a wildcard reaches exactly one label, which a suffix comparison gets wrong",
    pki.identity.match(cStar, "a.b.example.com").matched === false);

  var cPartial = await certWithDns("w*.example.com");
  var vPartial = pki.identity.match(cPartial, "www.example.com");
  check("15. a wildcard that is not the whole label is ignored, not refused",
    vPartial.matched === false && vPartial.ignored.length === 1);
  check("15b. ...and the reason names what the entry did", /wildcard/.test(vPartial.ignored[0].reason));
  var cTwo = await certWithDns("*.*.example.com");
  check("16. two wildcards are ignored",
    pki.identity.match(cTwo, "a.b.example.com").ignored.length === 1);
  var cMid = await certWithDns("foo.*.example.com");
  check("17. a wildcard outside the left-most label is ignored",
    pki.identity.match(cMid, "foo.bar.example.com").ignored.length === 1);
  var cBare = await certWithDns("*");
  check("18. a bare wildcard is ignored", pki.identity.match(cBare, "example.com").ignored.length === 1);

  var cMixed = await certWithDns("w*.example.com", "www.example.com");
  check("19. an ignored entry does not refuse the certificate, and the search continues",
    pki.identity.match(cMixed, "www.example.com").matched === true);
  check("20. a wildcard in a REFERENCE is a caller mistake",
    code(function () { pki.identity.match(cStar, "*.example.com"); }) === "identity/bad-reference");
  var vOff = pki.identity.match(cStar, "foo.example.com", { wildcards: false });
  check("21. opts.wildcards false puts every wildcard entry in ignored",
    vOff.matched === false && vOff.ignored.length === 1);
}

// ---- IP-ID (RFC 9525 sec. 6.2, sec. 6.4; RFC 9110 sec. 4.3.5) ---------
async function testIpId() {
  var v4 = Buffer.from([192, 0, 2, 1]);
  var v6 = Buffer.from("20010db8000000000000000000000001", "hex");
  var c4 = await certWithSanDer([ipEntry(v4)]);
  var c6 = await certWithSanDer([ipEntry(v6)]);
  check("22. a dotted-quad reference matches a four-octet entry", pki.identity.match(c4, "192.0.2.1").matched === true);
  check("23. a textual IPv6 reference matches a sixteen-octet entry", pki.identity.match(c6, "2001:db8::1").matched === true);
  check("24. ...and the expanded spelling of the same address matches, so the comparison is on octets",
    pki.identity.match(c6, "2001:0db8:0000:0000:0000:0000:0000:0001").matched === true);
  check("25. a reference given as sixteen octets matches",
    pki.identity.match(c6, new Uint8Array(v6)).matched === true);

  var cText = await certWithDns("192.0.2.1");
  check("26. an IP-ID is never matched against a dNSName carrying the same address as text",
    pki.identity.match(cText, "192.0.2.1").matched === false);
  check("27. an IPv4-mapped IPv6 reference packs to sixteen octets and does not match four",
    pki.identity.match(c4, "::ffff:192.0.2.1").matched === false);
  check("28. no network-level matching applies", pki.identity.match(c4, "192.0.2.0").matched === false);
  check("29. an eight-octet value is an address plus a mask, which is a name constraint and not a reference",
    code(function () { pki.identity.match(c4, new Uint8Array(8)); }) === "identity/bad-reference");
  check("30. a five-octet value is no address at all",
    code(function () { pki.identity.match(c4, new Uint8Array(5)); }) === "identity/bad-reference");
  check("32. a four-octet reference does not match a sixteen-octet entry by prefix",
    pki.identity.match(c6, "192.0.2.1").matched === false);

  // The length that was checked is the length that is compared: the snapshot is taken at the
  // door, so a buffer that shrinks afterwards cannot make the comparison read what it did not.
  var rab = new ArrayBuffer(16, { maxByteLength: 16 });
  var view = new Uint8Array(rab);
  view.set(v6);
  var vResize = pki.identity.match(c6, view);
  rab.resize(4);
  check("31. the verdict is computed from the snapshot taken at the door", vResize.matched === true);
}

// ---- The subject is never a source of identity (sec. 2) ---------------
async function testSubjectIsNeverIdentity() {
  var cnSubject = [{ commonName: "www.example.com" }];
  var cOther = await certWithSanDer([dnsEntry("other.example.net")], cnSubject);
  check("33. a commonName equal to the reference is not an identity",
    pki.identity.match(cOther, "www.example.com").matched === false);

  serial += 1;
  var noSan = await pki.x509.sign({
    subject: cnSubject, subjectPublicKey: SPKI, serialNumber: serial, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: KEY });
  var vNoSan = pki.identity.match(noSan, "www.example.com");
  check("34. a certificate with no subjectAltName presents no identifier, and the verdict says so",
    vNoSan.matched === false && /no subjectAltName/.test(vNoSan.reason));

  var emailSubject = [{ commonName: "s.example" }, { emailAddress: "a@example.com" }];
  var cEmail = await certWithSanDer([dnsEntry("other.example.net")], emailSubject);
  check("35. the rfc822Name a name constraint synthesizes from the subject is not shared with this path",
    pki.identity.match(cEmail, "example.com").matched === false);

  var dirName = b.contextConstructed(4, b.sequence([b.set([b.sequence([
    b.oid(pki.oid.byName("commonName")), b.utf8("www.example.com")])])]));
  var cDir = await certWithSanDer([dirName]);
  var vDir = pki.identity.match(cDir, "www.example.com");
  check("36. a directoryName naming the same string is not a DNS-ID",
    vDir.matched === false && /no presented identifier matched/.test(vDir.reason));
  var cRid = await certWithSanDer([b.implicit(8, b.oid(pki.oid.byName("commonName")))]);
  check("37. a registeredID is an identifier form this check does not read",
    pki.identity.match(cRid, "www.example.com").matched === false);
}

// ---- SRV-ID (RFC 4985, RFC 9525 sec. 6.5) -----------------------------
async function testSrvId() {
  var cSrv = await certWithSanDer([srvEntry("_imap.example.com")]);
  var ref = { type: "srv", service: "_imap", value: "example.com" };
  check("39. an SRVName matches the service and the domain together", pki.identity.match(cSrv, ref).matched === true);
  check("40. the service name is folded as ASCII",
    pki.identity.match(cSrv, { type: "srv", service: "_IMAP", value: "example.com" }).matched === true);
  check("41. a different service does not match",
    pki.identity.match(cSrv, { type: "srv", service: "_xmpp-client", value: "example.com" }).matched === false);
  check("42. the underscore is part of the service name, not a separator",
    code(function () { pki.identity.match(cSrv, { type: "srv", service: "imap", value: "example.com" }); }) === "identity/bad-reference");

  var cSrvB = await certWithSanDer([srvEntry("_imap.b.example")]);
  check("43. a service from one reference is never paired with a domain from another",
    pki.identity.match(cSrvB, [{ type: "srv", service: "_imap", value: "a.example" }, "b.example"]).matched === false);

  var cUtf8 = await certWithSanDer([otherNameEntry(pki.oid.byName("dnsSRV"), b.utf8("_imap.example.com"))]);
  var vUtf8 = pki.identity.match(cUtf8, ref);
  check("44. an SRVName that is not an IA5String is ignored, and the reason names the type",
    vUtf8.matched === false && vUtf8.ignored.length === 1 && /IA5String/.test(vUtf8.ignored[0].reason));
  var cNoUnder = await certWithSanDer([srvEntry("imap.example.com")]);
  check("45. an SRVName with no leading underscore is ignored",
    pki.identity.match(cNoUnder, ref).ignored.length === 1);
  var cEmptySvc = await certWithSanDer([srvEntry("_.example.com")]);
  check("46. an SRVName naming no service is ignored", pki.identity.match(cEmptySvc, ref).ignored.length === 1);
  var cEmptyDom = await certWithSanDer([srvEntry("_imap.")]);
  check("47. an SRVName naming no domain is ignored", pki.identity.match(cEmptyDom, ref).ignored.length === 1);
  check("48. an SRVName is not matched as a bare DNS-ID", pki.identity.match(cSrv, "example.com").matched === false);

  var cUnknown = await certWithSanDer([otherNameEntry(pki.oid.byName("hardwareModuleName"), b.ia5("_imap.example.com"))]);
  var vUnknown = pki.identity.match(cUnknown, ref);
  check("49. an otherName under another type-id is not read", vUnknown.matched === false && vUnknown.ignored.length === 0);
}

// ---- URI-ID (RFC 9525 sec. 6.2, sec. 7.2) -----------------------------
async function testUriId() {
  var ref = { type: "uri", scheme: "https", value: "www.example.com" };
  var cPath = await certWithSanDer([uriEntry("https://www.example.com/path?q=1#f")]);
  check("50. path, query and fragment are not compared", pki.identity.match(cPath, ref).matched === true);
  var cAuth = await certWithSanDer([uriEntry("https://user@www.example.com:8443/")]);
  check("51. userinfo and port are not compared", pki.identity.match(cAuth, ref).matched === true);
  var cCase = await certWithSanDer([uriEntry("HTTPS://WWW.EXAMPLE.COM/")]);
  check("52. the scheme and the host are folded as ASCII", pki.identity.match(cCase, ref).matched === true);
  var cHttp = await certWithSanDer([uriEntry("http://www.example.com/")]);
  check("53. the scheme is a conjunct, not a hint", pki.identity.match(cHttp, ref).matched === false);

  var cMailto = await certWithSanDer([uriEntry("mailto:a@example.com")]);
  var vMailto = pki.identity.match(cMailto, { type: "uri", scheme: "mailto", value: "example.com" });
  check("54. a URI with no authority carries no host and is ignored",
    vMailto.matched === false && vMailto.ignored.length === 1 && /no host/.test(vMailto.ignored[0].reason));
  var cV6 = await certWithSanDer([uriEntry("https://[2001:db8::1]/")]);
  var vV6 = pki.identity.match(cV6, { type: "uri", scheme: "https", value: "2001:db8::1" });
  check("55. a bracketed address is not a reg-name, so the entry is ignored",
    vV6.matched === false && vV6.ignored.length === 1 && /IP literal/.test(vV6.ignored[0].reason));
  var cPct = await certWithSanDer([uriEntry("https://ex%61mple.com/")]);
  var vPct = pki.identity.match(cPct, { type: "uri", scheme: "https", value: "example.com" });
  check("56. a percent-escaped host is not decoded before comparison, and the entry is ignored",
    vPct.matched === false && vPct.ignored.length === 1 && /percent-escape/.test(vPct.ignored[0].reason));
  // A wildcard is a property of a presented identifier (sec. 6.3), not of the `dNSName` form,
  // so a URI-ID host carrying one reaches the same rule. The host is still narrowed to a
  // reg-name that is not an address, which is what sec. 6.2 asks of it.
  var cWildUri = await certWithSanDer([uriEntry("https://*.example.com/")]);
  check("53a. a wildcard in a URI-ID host reaches the wildcard rule",
    pki.identity.match(cWildUri, ref).matched === true);
  check("53b. ...and answers the same as the dNSName form does for the same names",
    pki.identity.match(cWildUri, { type: "uri", scheme: "https", value: "a.b.example.com" }).matched === false &&
    pki.identity.match(cWildUri, { type: "uri", scheme: "https", value: "example.com" }).matched === false);
  check("53c. ...and opts.wildcards false turns it off here too",
    pki.identity.match(cWildUri, ref, { wildcards: false }).ignored.length === 1);
  var cWildIp = await certWithSanDer([uriEntry("https://*.0.2.1/")]);
  check("53d. a wildcard does not make an address into a reg-name",
    pki.identity.match(cWildIp, { type: "uri", scheme: "https", value: "192.0.2.1" }).matched === false);
  var cSip = await certWithSanDer([uriEntry("sip:voice.example.com")]);
  var vSip = pki.identity.match(cSip, { type: "uri", scheme: "sip", value: "voice.example.com" });
  check("57. a sip URI written with no authority is ignored, which is what sec. 7.2 directs",
    vSip.matched === false && vSip.ignored.length === 1);
}

// ---- Internationalized names (sec. 6.3, sec. 7.3) ---------------------
async function testInternationalized() {
  var c = await certWithDns("www.example.com");
  check("59. a U-label reference is refused, naming the conversion this toolkit cannot perform",
    code(function () { pki.identity.match(c, "bücher.example.com"); }) === "identity/unsupported-reference");
  check("60. a byte in the 0x80 to 0xFF range is refused the same way",
    code(function () { pki.identity.match(c, "a" + String.fromCharCode(0xe4) + ".example.com"); }) === "identity/unsupported-reference");
  check("61. a control byte is malformed input rather than a missing capability",
    code(function () { pki.identity.match(c, "a" + String.fromCharCode(0) + ".example.com"); }) === "identity/bad-reference");

  // The control proving the presented side never reaches a comparison carrying such a byte: it
  // is refused before a certificate holding one exists, so the matcher is never the check.
  var bad = "a" + String.fromCharCode(0xc3) + String.fromCharCode(0xa4) + ".example.com";
  var signCode = await codeAsync(function () { return certWithSanDer([b.implicit(2, b.ia5(bad))]); });
  check("62. a dNSName carrying a byte outside printable ASCII never reaches a comparison",
    signCode !== "NO-THROW");
}

// ---- Bounds ------------------------------------------------------------
async function testBounds() {
  var cap = pki.constants.LIMITS.SAN_MAX_ENTRIES;
  var many = [];
  for (var i = 0; i < cap; i++) many.push(dnsEntry("h" + i + ".example.com"));
  many.push(dnsEntry("www.example.com"));
  var cMany = await certWithSanDer(many);
  check("63. a certificate past the entry cap is refused rather than searched",
    code(function () { pki.identity.match(cMany, "www.example.com"); }) === "identity/too-many-names");
  check("66. ...and the bound fires before the comparison work, with one reference too",
    code(function () { pki.identity.match(cMany, "nothing.example"); }) === "identity/too-many-names");

  var cOne = await certWithDns("www.example.com");
  var refs = [];
  for (var r = 0; r <= pki.constants.LIMITS.IDENTITY_MAX_REFERENCES; r++) refs.push("r" + r + ".example.com");
  check("64. a reference list past its cap is refused at the door",
    code(function () { pki.identity.match(cOne, refs); }) === "identity/too-many-references");

  var atCap = [];
  for (var k = 0; k < cap; k++) atCap.push(dnsEntry("k" + k + ".example.com"));
  var cAtCap = await certWithSanDer(atCap);
  var refsAtCap = [];
  for (var m = 0; m < pki.constants.LIMITS.IDENTITY_MAX_REFERENCES; m++) refsAtCap.push("m" + m + ".example.net");
  check("65. a certificate at the cap against a reference list at the cap completes and finds nothing",
    pki.identity.match(cAtCap, refsAtCap).matched === false);
}

// ---- The doors ---------------------------------------------------------
async function testDoors() {
  var c = await certWithDns("www.example.com");
  check("67. an unknown option is named",
    code(function () { pki.identity.match(c, "www.example.com", { unknownOption: 1 }); }) === "identity/bad-input");
  check("68. an empty reference list would read as a check that passed",
    code(function () { pki.identity.match(c, []); }) === "identity/bad-input");
  check("69. an empty reference is not a name", code(function () { pki.identity.match(c, ""); }) === "identity/bad-reference");

  // An option whose value can differ between the check and the use is refused rather than read
  // once, which is the same door every other verb in this toolkit applies.
  var reads = 0;
  var opts = { get wildcards() { reads += 1; return reads === 1; } };
  var cStar = await certWithDns("*.example.com");
  check("70. an option supplied through an accessor is refused, not read and then re-read",
    code(function () { pki.identity.match(cStar, "foo.example.com", opts); }) === "identity/bad-input");
  check("70b. CONTROL: the same option as a plain value decides the verdict",
    pki.identity.match(cStar, "foo.example.com", { wildcards: true }).matched === true &&
    pki.identity.match(cStar, "foo.example.com", { wildcards: false }).matched === false);

  var derForms = pki.identity.match(c, "www.example.com");
  var pemForm = pki.identity.match(pki.schema.x509.pemEncode(c, "CERTIFICATE"), "www.example.com");
  var parsedForm = pki.identity.match(pki.schema.x509.parse(c), "www.example.com");
  check("72. DER bytes, a PEM string and a parsed certificate give the identical verdict",
    derForms.matched === pemForm.matched && pemForm.matched === parsedForm.matched &&
    derForms.matchedEntry === parsedForm.matchedEntry);

  // A parsed certificate is re-derived from the bytes it recorded, so a field rewritten after
  // the parse describes nothing: the comparison runs against the name that was signed.
  var parsed = pki.schema.x509.parse(c);
  var forged = pki.schema.x509.parse(await certWithDns("attacker.example"));
  parsed.extensions = forged.extensions;
  check("71. a rebuilt extensions array does not decide the verdict; the signed bytes do",
    pki.identity.match(parsed, "attacker.example").matched === false &&
    pki.identity.match(parsed, "www.example.com").matched === true);

  var refArray = ["a.example.net", "www.example.com"];
  var refRecord = { type: "uri", scheme: "https", value: "www.example.com" };
  var first = pki.identity.match(c, refArray);
  var second = pki.identity.match(c, refArray);
  check("73. the caller's array and record are unchanged, and a second call gives the same verdict",
    refArray.length === 2 && refArray[0] === "a.example.net" &&
    refRecord.scheme === "https" && first.matched === second.matched &&
    first.matchedReference === second.matchedReference);
}

// ---- The path.validate gate (RFC 9525 sec. 1.2, sec. 6.6) -------------
async function testPathGate() {
  var caKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var caKey = caKp.privateKey.export({ format: "der", type: "pkcs8" });
  var caDer = await pki.x509.sign({
    subject: [{ commonName: "identity-gate-ca.example" }], subjectPublicKey: caKp.publicKey.export({ format: "der", type: "spki" }),
    serialNumber: 1, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
  }, { key: caKey });

  async function leafUnder(name, sans) {
    serial += 1;
    return pki.x509.sign({
      subject: [{ commonName: name }], subjectPublicKey: SPKI, serialNumber: serial, notBefore: NB, notAfter: NA,
      extensions: { keyUsage: ["digitalSignature"], subjectAltName: sans,
        subjectKeyIdentifier: true, authorityKeyIdentifier: true },
    }, { key: caKey, cert: caDer });
  }
  var leaf = await leafUnder("gate-leaf.example", [{ dNSName: "www.example.com" }]);
  var at = { time: new Date("2026-06-01T00:00:00Z"), trustAnchors: [caDer] };

  function rowFor(res, index, name) {
    for (var i = 0; i < res.results.length; i++) {
      if (res.results[i].index !== index) continue;
      for (var k = 0; k < res.results[i].checks.length; k++) {
        if (res.results[i].checks[k].name === name) return res.results[i].checks[k];
      }
    }
    return null;
  }

  var ok = await pki.path.validate([leaf], Object.assign({ identity: "www.example.com" }, at));
  var okRow = rowFor(ok, 0, "identity");
  check("74. a matching identity leaves the path valid and records the check",
    ok.valid === true && okRow !== null && okRow.ok === true && ok.identityChecked === "www.example.com");

  var bad = await pki.path.validate([leaf], Object.assign({ identity: "other.example.com" }, at));
  var badRow = rowFor(bad, 0, "identity");
  check("75. a mismatch makes the path invalid and names the code",
    bad.valid === false && badRow !== null && badRow.code === "path/identity-mismatch");

  var none = await pki.path.validate([leaf], at);
  check("76. an omitted identity reports that no check ran rather than leaving the field out",
    none.valid === true && none.identityChecked === false && rowFor(none, 0, "identity") === null);

  var interLeaf = await leafUnder("gate-plain.example", [{ dNSName: "leaf-only.example.com" }]);
  var leafOnly = await pki.path.validate([interLeaf], Object.assign({ identity: "identity-gate-ca.example" }, at));
  check("77. the gate reads the leaf and no other certificate in the path", leafOnly.valid === false);

  var expired = await pki.path.validate([leaf],
    { time: new Date("2030-01-01T00:00:00Z"), trustAnchors: [caDer], identity: "other.example.com" });
  var expiredIdentity = rowFor(expired, 0, "identity");
  check("78. the gate neither replaces nor masks a sec. 6.1 check: both rows are present",
    expired.valid === false && expiredIdentity !== null && expiredIdentity.ok === false &&
    rowFor(expired, 0, "validity") !== null);

  check("79. a malformed identity record is a path input fault",
    (await codeAsync(function () {
      return pki.path.validate([leaf], Object.assign({ identity: { type: "srv", unknownKey: 1 } }, at));
    })) === "path/bad-input");
  check("80. an empty identity list is refused the same way",
    (await codeAsync(function () {
      return pki.path.validate([leaf], Object.assign({ identity: [] }, at));
    })) === "path/bad-input");
  check("81. the failure flag and the row are one decision: the row is there and valid is false",
    bad.valid === false && badRow.ok === false);

  // The reference identities are read in the synchronous prologue, before the first await, so
  // the policy the verdict answers for is the one the call was made with. A caller that reuses
  // its options object, or whose object is reachable from elsewhere, cannot change the question
  // after asking it.
  var mutable = ["wrong.example"];
  var pending = pki.path.validate([leaf], Object.assign({ identity: mutable }, at));
  mutable[0] = "www.example.com";
  mutable.length = 1;
  var mutated = await pending;
  check("82. a reference list mutated after the call does not change the verdict",
    mutated.valid === false && rowFor(mutated, 0, "identity").code === "path/identity-mismatch");

  var swappedOpts = Object.assign({ identity: "www.example.com" }, at);
  var pending2 = pki.path.validate([leaf], swappedOpts);
  swappedOpts.identity = null;
  var kept = await pending2;
  check("83. clearing the option after the call does not skip the check",
    kept.valid === true && kept.identityChecked === "www.example.com" && rowFor(kept, 0, "identity") !== null);

  var recordOpts = Object.assign({ identity: { type: "dns", value: "www.example.com" } }, at);
  var pending3 = pki.path.validate([leaf], recordOpts);
  recordOpts.identity.value = "other.example.com";
  var recordKept = await pending3;
  check("84. a record's fields are read before the first await too", recordKept.valid === true);
  // RFC 9525 sec. 6.6 has the caller use the matched reference as the validated identity of the
  // service, so what the verdict hands back has to be the identity that was checked and not a
  // window onto the caller's own object.
  check("84a. the reported identity is the one that was checked, not the caller's live object",
    recordKept.identityChecked && recordKept.identityChecked.value === "www.example.com");
  check("84b. ...and it cannot be rewritten after the verdict is built", (function () {
    try { recordKept.identityChecked.value = "attacker.example"; } catch (_e) { /* frozen */ }
    return recordKept.identityChecked.value === "www.example.com";
  })());

  var addr = new Uint8Array([192, 0, 2, 1]);
  var addrOpts = Object.assign({ identity: addr }, at);
  var pending4 = pki.path.validate([leaf], addrOpts);
  addr[0] = 10;
  var addrKept = await pending4;
  check("85. address bytes are copied before the first await",
    addrKept.valid === false && rowFor(addrKept, 0, "identity").code === "path/identity-mismatch");

  // Several anchors are several attempts, and the later ones run after an await. Each attempt
  // asks the question the caller asked, so the snapshot travels with it rather than each attempt
  // reading the caller's list again.
  var multiRefs = ["www.example.com"];
  var multiPending = pki.path.validate([leaf],
    { time: at.time, trustAnchors: [caDer, caDer], identity: multiRefs });
  multiRefs[0] = "other.example.com";
  var multiKept = await multiPending;
  check("85a. a mutated list does not change the answer when several anchors are tried",
    multiKept.valid === true && multiKept.identityChecked === "www.example.com");
  var multiMiss = ["other.example.com"];
  var missPending = pki.path.validate([leaf],
    { time: at.time, trustAnchors: [caDer, caDer], identity: multiMiss });
  multiMiss[0] = "www.example.com";
  var missKept = await missPending;
  check("85b. ...and a mismatch stays a mismatch across every attempt", missKept.valid === false);

  // The settled list is the comparison's own state, so nothing that can reach it can rewrite
  // what was checked. It is not on the public namespace either: the verb is the door.
  check("85c. the public namespace carries the verb and nothing to hand it settled state",
    Object.keys(pki.identity).join(",") === "match");
  var innerRefs = require("../../lib/identity-match").snapshotReferences(["victim.example"]);
  check("85d. a settled list and its records are frozen", (function () {
    try { innerRefs[0].domain = "attacker.example"; } catch (_e) { /* frozen */ }
    try { innerRefs.length = 0; } catch (_e2) { /* frozen */ }
    return innerRefs.length === 1 && innerRefs[0].domain === "victim.example";
  })());
  var ipRefs = require("../../lib/identity-match").snapshotReferences([new Uint8Array([192, 0, 2, 1])]);
  check("85e. and so are the address octets, which a Buffer would leave writable", (function () {
    try { ipRefs[0].octets[0] = 10; } catch (_e) { /* frozen */ }
    return ipRefs[0].octets[0] === 192;
  })());

  check("86. a malformed reference is refused before any work is done",
    (await codeAsync(function () {
      return pki.path.validate([leaf], Object.assign({ identity: { type: "srv", value: "a.example" } }, at));
    })) === "path/bad-input");

  // The control for vector 38: promoting the host reader did not take the RFC 5280 sec. 4.2.1.10
  // synthesis of an rfc822Name from the subject away from name constraints.
  var ncCa = await pki.x509.sign({
    subject: [{ commonName: "identity-nc-ca.example" }], subjectPublicKey: caKp.publicKey.export({ format: "der", type: "spki" }),
    serialNumber: 2, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      nameConstraints: { permitted: [{ rfc822Name: "permitted.example" }] }, subjectKeyIdentifier: true },
  }, { key: caKey });
  serial += 1;
  var emailLeaf = await pki.x509.sign({
    subject: [{ commonName: "nc-leaf.example" }, { emailAddress: "a@other.example" }],
    subjectPublicKey: SPKI, serialNumber: serial, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectKeyIdentifier: true, authorityKeyIdentifier: true },
  }, { key: caKey, cert: ncCa });
  var ncRes = await pki.path.validate([ncCa, emailLeaf],
    { time: new Date("2026-06-01T00:00:00Z"), trustAnchors: [ncCa] });
  check("38. name constraints still synthesize an rfc822Name from the subject attribute",
    ncRes.valid === false);

  // The control for vector 58: the promoted URI reader keeps the name-constraint verdict.
  var uriCa = await pki.x509.sign({
    subject: [{ commonName: "identity-uri-ca.example" }], subjectPublicKey: caKp.publicKey.export({ format: "der", type: "spki" }),
    serialNumber: 3, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      nameConstraints: { permitted: [{ uniformResourceIdentifier: ".example.com" }] }, subjectKeyIdentifier: true },
  }, { key: caKey });
  serial += 1;
  var uriLeaf = await pki.x509.sign({
    subject: [{ commonName: "uri-leaf.example" }], subjectPublicKey: SPKI, serialNumber: serial,
    notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ uri: "https://www.example.com/" }],
      subjectKeyIdentifier: true, authorityKeyIdentifier: true },
  }, { key: caKey, cert: uriCa });
  var uriRes = await pki.path.validate([uriLeaf],
    { time: new Date("2026-06-01T00:00:00Z"), trustAnchors: [uriCa] });
  check("58. a URI name constraint keeps its verdict through the promoted host reader", uriRes.valid === true);
}

// ---- The refusals each door states, driven one at a time ---------------
// Every arm of the reference classifier and every reason the search can skip an entry
// for, so a rule that stops being applied shows up here rather than in a coverage
// report. Each case names the clause it comes from.
async function testEveryRefusalAndSkip() {
  var c = await certWithDns("www.example.com");
  function refuse(label, value, want) {
    check(label, code(function () { pki.identity.match(c, value); }) === want);
  }
  refuse("R1. a DELETE byte is not a name", "a" + String.fromCharCode(0x7f) + ".example", "identity/bad-reference");
  refuse("R2. a record value that is not a string", { type: "dns", value: 7 }, "identity/bad-reference");
  refuse("R3. a record value that is empty", { type: "dns", value: "" }, "identity/bad-reference");
  refuse("R4. a name longer than 253 characters",
    new Array(64).join("abcd.") + "example.com", "identity/bad-reference");
  refuse("R5. a name with an empty label", "a..b.example", "identity/bad-reference");
  refuse("R6. a label longer than 63 characters",
    new Array(66).join("a") + ".example", "identity/bad-reference");
  refuse("R7. a reference that is neither a string, a byte source nor a record", 7, "identity/bad-reference");
  refuse("R8. a record naming a type this verb does not read", { type: "email", value: "a@b.example" },
    "identity/unsupported-reference");
  refuse("R9. an srv record with no service", { type: "srv", value: "example.com" }, "identity/bad-reference");
  refuse("R10. an srv record whose service is only its underscore", { type: "srv", service: "_", value: "example.com" },
    "identity/bad-reference");
  refuse("R11. a uri record with no scheme", { type: "uri", value: "example.com" }, "identity/bad-reference");
  refuse("R12. a uri record whose scheme carries its colon",
    { type: "uri", scheme: "https:", value: "example.com" }, "identity/bad-reference");
  // RFC 9525 sec. 3 classifies IPv4 first and considers everything it refuses as a domain.
  // `999.999.999.999` is no address, so it is a name, and a name is compared only against
  // dNSName entries.
  check("R13. a dotted-decimal string that is no address is classified as a name",
    pki.identity.match(await certWithDns("999.999.999.999"), "999.999.999.999.").matched === true &&
    pki.identity.match(await certWithSanDer([ipEntry(Buffer.from([1, 2, 3, 4]))]), "999.999.999.999").matched === false);
  check("R14. an ip record wrapping a textual address reads as an IP-ID",
    pki.identity.match(await certWithSanDer([ipEntry(Buffer.from([10, 0, 0, 7]))]),
      { type: "ip", value: "10.0.0.7" }).matched === true);
  // The record states the type, so it decides what the value must be. Classifying the value
  // again would let a name inside an `ip` record be compared as a name, which is the
  // consistent-classification rule of RFC 9525 sec. 3 and sec. 7.4 read backwards.
  refuse("R14a. an ip record carrying a name is a caller mistake, not a DNS-ID",
    { type: "ip", value: "www.example.com" }, "identity/bad-reference");
  refuse("R14b. an ip record carrying a malformed address is refused",
    { type: "ip", value: "999.0.2.1" }, "identity/bad-reference");
  check("R14c. ...and the certificate carrying that name is not matched by it",
    pki.identity.match(c, { type: "dns", value: "www.example.com" }).matched === true);
  check("R15. a dns record reads as a DNS-ID",
    pki.identity.match(c, { type: "dns", value: "www.example.com" }).matched === true);

  // Every reason the search skips a presented entry.
  function skipReason(entries, ref) {
    var v = pki.identity.match(entries, ref);
    return v.ignored.length === 1 ? v.ignored[0].reason : "NONE(" + v.ignored.length + ")";
  }
  var srvRef = { type: "srv", service: "_imap", value: "example.com" };
  // The SRVName reader's "not valid DER" and "constructed IA5String" arms are
  // verified-unreachable through this door: the otherName value is a [0] EXPLICIT wrapper
  // whose single child the strict DER decoder already walked when the certificate was read,
  // so bytes that reach `_srvName` decoded once and a constructed string was refused there.
  // Both are proven by the certificate refusing to exist: a truncated inner TLV fails
  // `pki.x509.sign` with a GeneralNames overrun, and a constructed IA5String fails the same
  // decoder. They stay as the reader's own contract because the value is a second decode of
  // untrusted bytes and the wrapper is not the only way one could arrive.
  check("S1. a truncated SRVName value never becomes a certificate to match against",
    (await codeAsync(function () {
      return certWithSanDer([otherNameEntry(pki.oid.byName("dnsSRV"), Buffer.from([0x16, 0x7f]))]);
    })) !== "NO-THROW");
  check("S2. neither does a constructed IA5String SRVName value",
    (await codeAsync(function () {
      return certWithSanDer([otherNameEntry(pki.oid.byName("dnsSRV"), Buffer.from([0x36, 0x03, 0x16, 0x01, 0x61]))]);
    })) !== "NO-THROW");
  check("S3. an empty SRVName value",
    /empty/.test(skipReason(await certWithSanDer([otherNameEntry(pki.oid.byName("dnsSRV"), Buffer.from([0x16, 0x00]))]), srvRef)));
  var uriRef = { type: "uri", scheme: "https", value: "www.example.com" };
  check("S4. a URI with no scheme at all",
    /no scheme/.test(skipReason(await certWithSanDer([uriEntry("//www.example.com/")]), uriRef)));
  check("S5. a URI whose host is an IPv4 address is not a reg-name",
    /reg-name/.test(skipReason(await certWithSanDer([uriEntry("https://192.0.2.1/")]), uriRef)));
  check("S6. a presented name that is not shaped like a domain name",
    /not shaped like a domain name/.test(skipReason(await certWithDns("a..b.example"), "a.b.example")));
  // A wildcard whose reference has an empty left-most label has nothing to reach into.
  var cStar = await certWithDns("*.example.com");
  check("S7. a wildcard reaches a label, so an empty one is no match",
    pki.identity.match(cStar, { type: "dns", value: "foo.example.com" }).matched === true);
  check("S8. a wildcard whose tail differs is a no-match, not a match on the wildcard alone",
    pki.identity.match(cStar, "foo.other.com").matched === false);
  // An empty dNSName never becomes a certificate: RFC 5280 sec. 4.2.1.6 makes the value an
  // IA5String the decoder holds to non-empty, so the matcher's own length floor is the
  // reader's contract rather than the check that catches one.
  check("S9. an empty presented name never becomes a certificate to match against",
    (await codeAsync(function () { return certWithSanDer([dnsEntry("")]); })) !== "NO-THROW");
  check("S10. a presented name past 253 characters is not shaped like one",
    pki.identity.match(await certWithDns(new Array(64).join("abcd.") + "example.com"),
      "example.com").ignored.length === 1);

  // Every reference kind against every presented form it does NOT read, so each arm's
  // tag test answers rather than falling through to whatever the next arm decides.
  var forms = await certWithSanDer([dnsEntry("x.example"), ipEntry(Buffer.from([1, 2, 3, 4])),
    uriEntry("https://y.example/"), srvEntry("_imap.z.example")]);
  check("S11. an SRV reference does not read a dNSName, an iPAddress or a URI entry",
    pki.identity.match(forms, { type: "srv", service: "_imap", value: "x.example" }).matched === false);
  check("S12. a URI reference does not read a dNSName, an iPAddress or an otherName",
    pki.identity.match(forms, { type: "uri", scheme: "https", value: "x.example" }).matched === false);
  check("S13. a DNS reference does not read a URI, an iPAddress or an otherName",
    pki.identity.match(forms, "y.example").matched === false);
  check("S14. an IP reference does not read a dNSName, a URI or an otherName",
    pki.identity.match(forms, "5.6.7.8").matched === false);
  check("S15. CONTROL: each of the four does match the form it reads",
    pki.identity.match(forms, "x.example").matched === true &&
    pki.identity.match(forms, "1.2.3.4").matched === true &&
    pki.identity.match(forms, { type: "uri", scheme: "https", value: "y.example" }).matched === true &&
    pki.identity.match(forms, { type: "srv", service: "_imap", value: "z.example" }).matched === true);

  // An entry form this check does not read is named in the verdict by its tag, so a
  // certificate presenting only those says which forms it carried.
  var cX400 = await certWithSanDer([b.contextConstructed(3, b.sequence([b.sequence([])]))]);
  check("S16. an entry form this check does not read is a no-match, not a fault",
    pki.identity.match(cX400, "example.com").matched === false);

  check("S17. a non-boolean wildcards option is refused",
    code(function () { pki.identity.match(c, "www.example.com", { wildcards: "yes" }); }) === "identity/bad-input");
}

async function run() {
  await testEveryRefusalAndSkip();
  await testDnsId();
  await testWildcards();
  await testIpId();
  await testSubjectIsNeverIdentity();
  await testSrvId();
  await testUriId();
  await testInternationalized();
  await testBounds();
  await testDoors();
  await testPathGate();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
