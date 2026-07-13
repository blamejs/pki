// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.inspect: human-readable certificate rendering (openssl x509 -text
 * in pure JS). The report is our own stable, OpenSSL-familiar format (OpenSSL's
 * exact bytes differ across versions), so the conformance vectors assert the
 * decoded VALUES are present + correct, and the interop check confirms those same
 * values against the authoritative `openssl x509 -text` decode when an openssl
 * binary is available (any version -- the comparison is value-level, not byte-exact).
 */

var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;
var cp = require("child_process");
var fs = require("fs");
var path = require("path");
var os = require("os");

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

// A real EC cert (from the shared vectors) and a real Fulcio cert (rich extensions).
var ecPem = helpers.vectors.CERT_EC_PEM;
var ecDer = pki.schema.x509.pemDecode(ecPem, "CERTIFICATE");
var fulcioDer = Buffer.from(require("../fixtures/sigstore/npm-provenance-bundle.json").verificationMaterial.certificate.rawBytes, "base64");

function run() {
  // --- Core render: the EC cert report carries every decoded field ---
  var t = pki.inspect.certificate(ecPem);
  check("inspect: header + Data block", /^Certificate:\n {4}Data:\n {8}Version: 3 \(0x2\)/.test(t));
  check("inspect: serial as colon-hex", t.indexOf("09:71:42:94:84:18:3f:f3:47:54:58:66:3b:75:36:97:27:d2:96:65") >= 0);
  check("inspect: issuer + subject DN (openssl short names)", /Issuer: C=US, ST=California, O=blamejs pki, OU=Test, CN=pkijs\.com/.test(t) && /Subject: C=US/.test(t));
  check("inspect: validity in openssl date form", /Not Before: [A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d \d{4} GMT/.test(t) && /Not After : /.test(t));
  check("inspect: EC key details (bits + curve)", /Public-Key: \(256 bit\)/.test(t) && /ASN1 OID: prime256v1/.test(t) && /NIST CURVE: P-256/.test(t));
  check("inspect: extensions decoded (BasicConstraints/KeyUsage/SAN/SKI)",
    /X509v3 Basic Constraints: critical\n\s+CA:TRUE/.test(t) &&
    /X509v3 Key Usage: critical\n\s+Certificate Sign, CRL Sign/.test(t) &&
    /X509v3 Subject Alternative Name:\n\s+DNS:pkijs\.com, DNS:www\.pkijs\.com/.test(t) &&
    /X509v3 Subject Key Identifier:\n\s+83:91:31:BE/.test(t));
  check("inspect: signature block", /Signature Value:\n\s+30:46:02:21/.test(t));

  // --- Accepts DER Buffer + an already-parsed cert too ---
  check("inspect accepts a DER Buffer", pki.inspect.certificate(ecDer).indexOf("CN=pkijs.com") >= 0);
  check("inspect accepts a parsed cert", pki.inspect.certificate(pki.schema.x509.parse(ecDer)).indexOf("CN=pkijs.com") >= 0);

  // --- The value-add over openssl: named Fulcio extensions + EKU purpose names ---
  var f = pki.inspect.certificate(fulcioDer);
  check("inspect: EKU renders the purpose name", /X509v3 Extended Key Usage:\n\s+Code Signing/.test(f));
  check("inspect: AKI keyid", /X509v3 Authority Key Identifier:\n\s+keyid:[0-9A-F:]+/.test(f));
  check("inspect: SAN URI", /X509v3 Subject Alternative Name: critical\n\s+URI:https:\/\/github\.com\/blamejs\/pki/.test(f));
  check("inspect: registry names an OID openssl shows as bytes", /buildSignerURI:\n\s+https:\/\/github\.com\/blamejs\/pki/.test(f) && /runnerEnvironment:\n\s+github-hosted/.test(f));

  // --- Rich extensions (a real openssl-generated cert): IP/dirName SANs, policies,
  // CRL distribution points, name constraints, and a high-bit serial all render
  // their true values (not mojibake / [object Object] / a hex dump / a sign byte). ---
  var richPem = fs.readFileSync(path.join(__dirname, "..", "fixtures", "inspect", "rich-cert.pem"), "utf8");
  var r = pki.inspect.certificate(richPem);
  check("inspect: IPv4 SAN as dotted-quad", /IP Address:192\.168\.1\.10/.test(r));
  check("inspect: IPv6 SAN grouped", /IP Address:2001:DB8:/.test(r));
  check("inspect: directoryName SAN as a DN (not [object Object])", /DirName:.*CN=altdir/.test(r) && r.indexOf("[object Object]") < 0);
  check("inspect: whole SAN on one line (no IP byte injects a newline)", /DNS:rich\.blamejs\.test, IP Address:192\.168\.1\.10, IP Address:2001:DB8:0:0:0:0:0:1, email:hostmaster@blamejs\.test, URI:https:\/\/blamejs\.test\/, DirName:CN=altdir/.test(r));
  check("inspect: high-bit serial has no DER 00 sign byte", /Serial Number:\n\s+f1:e2:d3/.test(r) && !/Serial Number:\n\s+00:f1/.test(r));
  check("inspect: certificatePolicies renders the policy OID", /X509v3 Certificate Policies:\n\s+Policy: 1\.3\.6\.1\.4\.1\.99999\.1\.2/.test(r));
  check("inspect: CRL distribution point renders the URI", /X509v3 CRL Distribution Points:[\s\S]*URI:http:\/\/crl\.blamejs\.test\/ca\.crl/.test(r));
  check("inspect: name constraints render permitted/excluded", /X509v3 Name Constraints: critical[\s\S]*Permitted:[\s\S]*DNS:\.blamejs\.test[\s\S]*Excluded:[\s\S]*DNS:evil\.test/.test(r));

  // A control byte in a UTF8String DN attribute (0x0a is a legal UTF8String byte, so
  // the strict parser accepts it) must NOT inject a forged line into the report -- it
  // renders escaped. Anchor on the subject CN's UTF8String TLV (0c 11 <17 bytes>); the
  // same text is also the issuer CN, so take the second occurrence. Parse is
  // structural, so mutating a TBS content byte yields a still-parseable certificate.
  var richDer = pki.schema.x509.pemDecode(richPem, "CERTIFICATE");
  var cnTag = Buffer.concat([Buffer.from([0x0c, 0x11]), Buffer.from("rich.blamejs.test", "latin1")]);
  var at = richDer.indexOf(cnTag, richDer.indexOf(cnTag) + 1) + 2;   // subject CN content
  check("inspect: rich-cert subject CN locatable for mutation", at > 2);
  var evilDer = Buffer.from(richDer); evilDer[at] = 0x0a;   // 'r' -> newline
  var e = pki.inspect.certificate(evilDer);
  check("inspect: control byte in a DN value is RFC 4514-escaped, not injected",
    /Subject: CN=\\0Aich\.blamejs\.test/.test(e) && e.indexOf("CN=\nich.blamejs.test") < 0);

  // A DN value that genuinely starts with '#' is surfaced by the parser with a leading
  // '\' sentinel; inspect reuses the parser's already-escaped dn, so it must render
  // single-escaped '\#...' -- NOT double-escaped '\\#...' by re-escaping the sentinel.
  var hashDer = Buffer.from(richDer); hashDer[at] = 0x23;   // 'r' -> '#'
  var h = pki.inspect.certificate(hashDer);
  check("inspect: a DN value starting with '#' is single-escaped, not double",
    /Subject: CN=\\#ich\.blamejs\.test/.test(h) && h.indexOf("CN=\\\\#ich") < 0);

  // Append a synthetic extension to the EC fixture's TBS and return a parseable
  // cert DER (parse is structural, so no re-signing is needed). Used to drive
  // fallback rendering and the AKI issuer/serial form through the shipped path.
  var b = pki.asn1.build, A = pki.asn1;
  var baseDer = pki.schema.x509.pemDecode(ecPem, "CERTIFICATE");
  var baseCert = A.decode(baseDer), baseTbs = baseCert.children[0];
  var extIdx = baseTbs.children.findIndex(function (c) { return c.tagClass === "context" && c.tagNumber === 3; });
  var extList = baseTbs.children[extIdx].children[0].children.map(function (c) { return c.bytes; });
  function injectExt(extDer) {
    return b.sequence([
      b.sequence(baseTbs.children.map(function (c, i) {
        return i === extIdx ? b.explicit(3, b.sequence(extList.concat([extDer]))) : c.bytes;
      })),
      baseCert.children[1].bytes, baseCert.children[2].bytes,
    ]);
  }

  // A control byte (a bare \r) in a fallback-rendered extension value must NOT reach
  // the report raw -- a bare \r moves the terminal cursor back over prior output. A
  // value with any control byte is rejected as non-printable and hex-dumped instead.
  var cr = pki.inspect.certificate(injectExt(
    b.sequence([b.oid("1.3.6.1.4.1.99999.7.7"), b.octetString(b.ia5("line-a\rline-b"))])));
  check("inspect: control byte in a fallback value is hex-dumped, never raw",
    cr.indexOf("\r") < 0 && cr.indexOf("line-a\rline-b") < 0 && /6c:69:6e:65:2d:61/.test(cr));

  // The issuer+serial AKI form (no keyIdentifier) must render its real values, not
  // "keyid:(none)". Build AKI = { [1] authorityCertIssuer dirName, [2] serial }.
  var akiName = b.sequence([b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.utf8("aki-ca")])])]);
  var akiVal = b.sequence([b.contextConstructed(1, b.contextConstructed(4, akiName)), b.contextPrimitive(2, Buffer.from([0x42]))]);
  var aki = pki.inspect.certificate(injectExt(
    b.sequence([b.oid(pki.oid.byName("authorityKeyIdentifier")), b.octetString(akiVal)])));
  check("inspect: issuer/serial-only AKI renders its values, not keyid:(none)",
    /DirName:CN=aki-ca/.test(aki) && /serial:0x42/.test(aki) && aki.indexOf("keyid:(none)") < 0);

  // An RFC 4514 separator (a comma) in a DN attribute value must be escaped so it
  // cannot masquerade as an extra RDN. Mutate the issuer CN "pkijs.com" (the first
  // occurrence) so the '.' becomes a ',' in place; parse stays structural.
  var commaDer = Buffer.from(baseDer);
  var dot = commaDer.indexOf(Buffer.from("pkijs.com", "latin1")) + 5;   // the '.' in pkijs.com
  commaDer[dot] = 0x2c;                                                 // '.' -> ','
  var comma = pki.inspect.certificate(commaDer);
  check("inspect: a comma in a DN value is RFC 4514-escaped, not a forged RDN",
    /CN=pkijs\\,com/.test(comma) && !/CN=pkijs,com/.test(comma));

  // An RSA-PSS SPKI (id-RSASSA-PSS) carries the same RSAPublicKey as rsaEncryption,
  // so it must render as modulus + exponent, not the raw-bytes fallback. Swap the EC
  // fixture's SPKI (the SEQUENCE just before the [3] extensions) for a synthetic
  // rsassaPss key; parse is structural, so the cert stays parseable.
  var rsaPub = b.sequence([b.integer(BigInt("0x" + "c3".repeat(16))), b.integer(65537n)]);
  var pssSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("rsassaPss")), b.nullValue()]), b.bitString(rsaPub)]);
  var pss = pki.inspect.certificate(b.sequence([
    b.sequence(baseTbs.children.map(function (c, i) { return i === extIdx - 1 ? pssSpki : c.bytes; })),
    baseCert.children[1].bytes, baseCert.children[2].bytes,
  ]));
  check("inspect: an RSA-PSS SPKI renders as an RSA key (modulus + exponent)",
    /Public Key Algorithm: rsassaPss/.test(pss) && /Modulus:/.test(pss) && /Exponent: 65537/.test(pss));

  // An RSA modulus whose top byte is < 0x80 has no DER sign octet: inspect must report
  // its true bit length (127, not 128) and omit the '00:' pad, matching openssl.
  var loMod = BigInt("0x7f" + "c3".repeat(15));   // 16 bytes, top bit clear
  var loSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(b.sequence([b.integer(loMod), b.integer(65537n)]))]);
  var lo = pki.inspect.certificate(b.sequence([
    b.sequence(baseTbs.children.map(function (c, i) { return i === extIdx - 1 ? loSpki : c.bytes; })),
    baseCert.children[1].bytes, baseCert.children[2].bytes,
  ]));
  check("inspect: an RSA modulus < 0x80 reports true bits and no sign padding",
    /Public-Key: \(127 bit\)/.test(lo) && /Modulus:\n\s+7f:c3/.test(lo));

  // A CRL distribution point that carries only cRLIssuer (an indirect CRL, no
  // distributionPoint) must render the issuer GeneralNames, not a bare placeholder.
  var crlIssuerDp = b.sequence([b.contextConstructed(2, b.contextPrimitive(6, Buffer.from("http://crl-issuer.test", "latin1")))]);
  var ci = pki.inspect.certificate(injectExt(
    b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")), b.octetString(b.sequence([crlIssuerDp]))])));
  check("inspect: a cRLIssuer-only distribution point renders the issuer, not a placeholder",
    /CRL Issuer:\n\s+URI:http:\/\/crl-issuer\.test/.test(ci) && ci.indexOf("(distribution point)") < 0);

  // A CRL distribution point with a reasons BIT STRING must render the reason scope,
  // not drop it (which would make a scoped revocation source look generally applicable).
  var dpName = b.contextConstructed(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://crl.test", "latin1"))));
  var rsnDp = b.sequence([dpName, b.contextPrimitive(1, Buffer.from([0x05, 0x60]))]);   // reasons: keyCompromise, cACompromise
  var rsn = pki.inspect.certificate(injectExt(
    b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")), b.octetString(b.sequence([rsnDp]))])));
  check("inspect: a CRL DP reasons BIT STRING renders the reason scope",
    /Reasons: Key Compromise, CA Compromise/.test(rsn));

  // The policy / CT extensions decode to structured values -- render them, not a hex dump.
  var inhibit = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("inhibitAnyPolicy")), b.octetString(b.integer(3n))])));
  check("inspect: inhibitAnyPolicy renders its skip count", /Inhibit Any Policy Skip Certs: 3/.test(inhibit));
  var poison = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("precertificatePoison")), b.octetString(b.nullValue())])));
  check("inspect: precertificatePoison renders a marker, not a hex dump", /Precertificate Poison/.test(poison));
  var polC = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("policyConstraints")), b.octetString(b.sequence([b.contextPrimitive(0, Buffer.from([0x01]))]))])));
  check("inspect: policyConstraints renders requireExplicitPolicy", /Require Explicit Policy: 1/.test(polC));

  // A certificate policy with a CPS qualifier must render the qualifier value, not
  // drop it (which would make a qualified policy look unqualified).
  var cps = b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.ia5("https://cps.example/policy")]);
  var polQ = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("certificatePolicies")),
    b.octetString(b.sequence([b.sequence([b.oid("1.3.6.1.4.1.99999.1.2"), b.sequence([cps])])]))])));
  check("inspect: a certificate policy CPS qualifier renders its value, not dropped",
    /https:\/\/cps\.example\/policy/.test(polQ));

  // Completeness gate (the schema-driven promise): every extension the shared decoders
  // can decode has a renderer, so a newly-decodable extension can't silently hex-dump.
  var pkixMod = require("../../lib/schema-pkix"), oidMod = require("../../lib/oid"), errMod = require("../../lib/framework-error");
  var decNS = pkixMod.makeNS("inspect-test", errMod.InspectError, oidMod);
  var decodable = Object.keys(pkixMod.certExtensionDecoders(decNS).byOid).map(function (o) { return oidMod.name(o); });
  var unrendered = decodable.filter(function (n) { return pki.inspect.renderedExtensions.indexOf(n) < 0; });
  check("inspect: every decoder-decodable extension has a renderer (no hex-dump drift): " + (unrendered.join(",") || "none"), unrendered.length === 0);

  // --- Fail-closed input; a malformed extension does NOT sink the report ---
  check("inspect(42) -> inspect/bad-input", codeOf(function () { pki.inspect.certificate(42); }) === "inspect/bad-input");
  check("inspect(garbage der) -> inspect/bad-certificate", codeOf(function () { pki.inspect.certificate(Buffer.from("not a cert")); }) === "inspect/bad-certificate");
  check("inspect(bad PEM) -> inspect/bad-input", codeOf(function () { pki.inspect.certificate("-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----"); }) === "inspect/bad-input");
  // A spoofed / partial object with only a tbsBytes property must throw the typed
  // error, not a raw TypeError from the renderer dereferencing a missing field.
  check("inspect({tbsBytes}) -> inspect/bad-input (not a raw TypeError)", codeOf(function () { pki.inspect.certificate({ tbsBytes: Buffer.alloc(0) }); }) === "inspect/bad-input");

  // --- Adversarial / edge extension, key, and input forms: each drives an
  // otherwise-untaken best-effort render branch and asserts the fail-safe result
  // (a hostile or opaque value renders labelled-hex, never a raw byte that could
  // inject a report line; a malformed sub-structure hex-dumps, never throws). ---

  // Only issuerAltName can carry a fresh GeneralNames without duplicating the EC
  // fixture's own subjectAltName (the strict parser rejects a repeated extension).
  function ianExt(gnDer) { return b.sequence([b.oid(pki.oid.byName("issuerAltName")), b.octetString(b.sequence([gnDer]))]); }
  // otherName [0] IMPLICIT SEQUENCE { type-id, [0] EXPLICIT value } -- an opaque
  // choice, rendered as hex so its bytes can never break the line structure.
  var otherNameGn = b.contextConstructed(0, Buffer.concat([b.oid("1.3.6.1.4.1.99999.3.1"), b.explicit(0, b.utf8("hi"))]));
  check("inspect: issuerAltName otherName renders as labelled hex, not raw bytes",
    /X509v3 Issuer Alternative Name:\n\s+othername:a0:12:/.test(pki.inspect.certificate(injectExt(ianExt(otherNameGn)))));
  // ediPartyName [5] -- another opaque constructed choice -> its whole TLV as hex.
  var ediGn = b.contextConstructed(5, b.sequence([b.explicit(1, b.utf8("party"))]));
  check("inspect: issuerAltName ediPartyName [5] renders labelled hex",
    /X509v3 Issuer Alternative Name:\n\s+EdiPartyName:a5:0b:/.test(pki.inspect.certificate(injectExt(ianExt(ediGn)))));
  // registeredID [8] -- a bare OID choice -> the dotted OID string.
  var regGn = b.contextPrimitive(8, b.oid("1.2.3.4").subarray(2));
  check("inspect: issuerAltName registeredID [8] renders the OID",
    /X509v3 Issuer Alternative Name:\n\s+Registered ID:1\.2\.3\.4/.test(pki.inspect.certificate(injectExt(ianExt(regGn)))));

  // A name-constraints iPAddress subtree is a 32-octet IPv6 address+mask -> the
  // "addr/mask" form; and with only permittedSubtrees present, the excluded block
  // is omitted (the per-list empty-array early return), not rendered empty.
  var ncIp = Buffer.alloc(32); ncIp[0] = 0x20; ncIp[1] = 0x01; ncIp[16] = 0xff; ncIp[17] = 0xff;
  var nc32 = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("nameConstraints")), b.boolean(true),
    b.octetString(b.sequence([b.contextConstructed(0, b.sequence([b.contextPrimitive(7, ncIp)]))]))])));
  check("inspect: nameConstraints 32-byte IPv6 subtree renders addr/mask, excluded omitted",
    /Permitted:\n\s+IP Address:2001:0:0:0:0:0:0:0\/FFFF:0:0:0:0:0:0:0/.test(nc32) && nc32.indexOf("Excluded:") < 0);

  // An extKeyUsage whose KeyPurposeId OID is unregistered renders the raw dotted
  // OID (the registry lookup misses, but the purpose is never dropped).
  check("inspect: an unregistered EKU purpose renders its raw OID",
    /X509v3 Extended Key Usage:\n\s+1\.3\.6\.1\.4\.1\.99999\.8\.8/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("extKeyUsage")), b.octetString(b.sequence([b.oid("1.3.6.1.4.1.99999.8.8")]))])))));

  // basicConstraints with a pathLenConstraint -- replace the fixture's own CA:TRUE
  // basicConstraints (parser rejects a duplicate) so the pathlen suffix renders.
  function extOidOf(raw) { return A.read.oid(A.decode(raw).children[0]); }
  function replaceExt(oidName, extDer) {
    var target = pki.oid.byName(oidName);
    var kept = extList.filter(function (raw) { return extOidOf(raw) !== target; });
    return b.sequence([
      b.sequence(baseTbs.children.map(function (c, i) { return i === extIdx ? b.explicit(3, b.sequence(kept.concat([extDer]))) : c.bytes; })),
      baseCert.children[1].bytes, baseCert.children[2].bytes,
    ]);
  }
  check("inspect: basicConstraints renders pathlen when present",
    /X509v3 Basic Constraints: critical\n\s+CA:TRUE, pathlen:3/.test(
      pki.inspect.certificate(replaceExt("basicConstraints", b.sequence([b.oid(pki.oid.byName("basicConstraints")), b.boolean(true), b.octetString(b.sequence([b.boolean(true), b.integer(3n)]))])))));

  // A CRL distribution point whose distributionPoint is nameRelativeToCRLIssuer [1]
  // (an RDN, not a fullName) renders the relative-name marker, not a hex dump.
  var relDp = b.sequence([b.contextConstructed(0, b.contextConstructed(1, b.sequence([b.oid(pki.oid.byName("commonName")), b.utf8("crl-rdn")])))]);
  check("inspect: a CRL DP relative-name renders the marker",
    /X509v3 CRL Distribution Points:\n\s+Relative Name \(to CRL issuer\)/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")), b.octetString(b.sequence([relDp]))])))));

  // A CRL DP fullName carrying an iPAddress [7] GeneralName (left raw by the
  // decoder) renders as a dotted-quad, never a raw octet that could inject a line.
  var ipFull = b.sequence([b.contextConstructed(0, b.contextConstructed(0, b.contextPrimitive(7, Buffer.from([10, 0, 0, 1]))))]);
  check("inspect: a CRL DP fullName IP renders as a dotted-quad",
    /Full Name:\n\s+IP Address:10\.0\.0\.1/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")), b.octetString(b.sequence([ipFull]))])))));

  // An AKI issuer+serial form with an odd-nibble serial pads to an even-length hex
  // string (0x9 -> serial:0x09), and an all-optional-absent AKI renders keyid:(none)
  // rather than dropping the field or dereferencing a missing one.
  var akiIssuer = b.sequence([b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.utf8("aki-ca")])])]);
  var akiOdd = b.sequence([b.contextConstructed(1, b.contextConstructed(4, akiIssuer)), b.contextPrimitive(2, Buffer.from([0x09]))]);
  check("inspect: an AKI odd-nibble serial is zero-padded to even hex",
    /serial:0x09/.test(pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("authorityKeyIdentifier")), b.octetString(akiOdd)])))));
  check("inspect: an all-absent AKI renders keyid:(none)",
    /X509v3 Authority Key Identifier:\n\s+keyid:\(none\)/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("authorityKeyIdentifier")), b.octetString(b.sequence([]))])))));

  // An SCT list with one v1 SCT (decoded fields) plus one SCT of an unrecognized
  // version (preserved opaque) renders both the decoded SCT and the unknown count.
  function u16(n) { return Buffer.from([(n >> 8) & 0xff, n & 0xff]); }
  var sctV1 = Buffer.concat([Buffer.from([0]), Buffer.alloc(32, 0xab), Buffer.from([0, 0, 0, 0, 0, 0, 0, 5]), u16(0), Buffer.from([4]), Buffer.from([3]), u16(0)]);
  var sctUnk = Buffer.from([9, 0xde, 0xad]);
  var sctInner = Buffer.concat([u16(sctV1.length), sctV1, u16(sctUnk.length), sctUnk]);
  var sctBlob = Buffer.concat([u16(sctInner.length), sctInner]);
  var sctRep = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("signedCertificateTimestampList")), b.octetString(b.octetString(sctBlob))])));
  check("inspect: an SCT list renders the v1 SCT and the unknown-version count",
    /Signed Certificate Timestamp:\n\s+Version: v1\n\s+Log ID: ABABABAB/.test(sctRep) &&
    /Timestamp: 5/.test(sctRep) && /\(1 SCT\(s\) of an unrecognized version\)/.test(sctRep));

  // A certificate policy qualifier with an unregistered qualifier OID and a
  // non-printable value renders the OID label + a hex dump of the value.
  var binQual = b.sequence([b.oid("1.3.6.1.4.1.99999.9.9"), b.octetString(Buffer.from([1, 2, 3]))]);
  var polBin = b.sequence([b.oid("1.3.6.1.4.1.99999.1.2"), b.sequence([binQual])]);
  check("inspect: an unregistered non-printable policy qualifier renders OID + hex",
    /1\.3\.6\.1\.4\.1\.99999\.9\.9: 04:03:01:02:03/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("certificatePolicies")), b.octetString(b.sequence([polBin]))])))));

  // A registered-decoder extension whose VALUE is malformed for that decoder
  // (an INTEGER where extKeyUsage wants a SEQUENCE) hex-dumps via the fallback,
  // never throwing and never sinking the surrounding report.
  check("inspect: a decoder that throws on a malformed value falls back to hex",
    /X509v3 Extended Key Usage:\n\s+02:01:05/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("extKeyUsage")), b.octetString(b.integer(5n))])))));

  // Non-EC/RSA (EdDSA) and degenerate key forms exercise the raw-key + fallback
  // key branches: an Ed25519 SPKI shows its raw public key; an ecPublicKey with an
  // unknown named curve falls back to a point-derived bit length (no ASN1 OID line);
  // an RSA key with an odd-length modulus hex pads it; a non-RSAPublicKey inner
  // value falls through to the raw bytes rather than throwing.
  function swapSpki(spkiDer) {
    return b.sequence([
      b.sequence(baseTbs.children.map(function (c, i) { return i === extIdx - 1 ? spkiDer : c.bytes; })),
      baseCert.children[1].bytes, baseCert.children[2].bytes,
    ]);
  }
  var edKey = pki.inspect.certificate(swapSpki(b.sequence([b.sequence([b.oid("1.3.101.112")]), b.bitString(Buffer.alloc(32, 0xab))])));
  check("inspect: an Ed25519 SPKI renders raw public-key bytes",
    /Public Key Algorithm: Ed25519\n\s+Public-Key: \(256 bit\)\n\s+pub:\n\s+ab:ab:ab/.test(edKey));
  var unkCurve = pki.inspect.certificate(swapSpki(b.sequence([b.sequence([b.oid(pki.oid.byName("ecPublicKey")), b.oid("1.3.6.1.4.1.99999.5.5")]), b.bitString(Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0x11)]))])));
  check("inspect: an ecPublicKey with an unknown curve derives bits from the point, no ASN1 OID",
    /Public Key Algorithm: ecPublicKey\n\s+Public-Key: \(256 bit\)/.test(unkCurve) && unkCurve.indexOf("ASN1 OID:") < 0);
  var rsaOdd = pki.inspect.certificate(swapSpki(b.sequence([b.sequence([b.oid(pki.oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(b.sequence([b.integer(0x123n), b.integer(3n)]))])));
  check("inspect: an RSA modulus with odd-length hex is zero-padded", /Modulus:\n\s+01:23\n/.test(rsaOdd) && /Public-Key: \(9 bit\)/.test(rsaOdd));
  var rsaBad = pki.inspect.certificate(swapSpki(b.sequence([b.sequence([b.oid(pki.oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(Buffer.from([0xff, 0xff, 0xff]))])));
  check("inspect: a non-RSAPublicKey inner value falls back to raw bytes",
    /Public Key Algorithm: rsaEncryption\n\s+Public-Key: \(24 bit\)\n\s+pub:\n\s+ff:ff:ff/.test(rsaBad));

  // A hex-dump fallback for an unknown extension whose value is empty (-> "(empty)")
  // and whose value is non-printable, non-DER binary (-> colon-hex, never raw).
  check("inspect: an empty unknown-extension value renders (empty)",
    /1\.3\.6\.1\.4\.1\.99999\.7\.3:\n\s+\(empty\)/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid("1.3.6.1.4.1.99999.7.3"), b.octetString(Buffer.alloc(0))])))));
  var binFall = pki.inspect.certificate(injectExt(b.sequence([b.oid("1.3.6.1.4.1.99999.7.4"), b.octetString(Buffer.from([0xff, 0xfe, 0x00, 0x99]))])));
  check("inspect: a non-printable non-DER unknown value hex-dumps, never raw",
    /1\.3\.6\.1\.4\.1\.99999\.7\.4:\n\s+ff:fe:00:99/.test(binFall));

  // The pre-parsed fast path: field forms a strict parse never produces but the
  // documented best-effort renderer must still handle -- an unparseable validity
  // (rendered as the raw string, not a crash), an algorithm carrying only an OID or
  // neither name nor OID, a small/odd/empty serial (inline decimal), a raw-Buffer or
  // null public key, no extensions, and a raw-Buffer or absent signature value.
  function mkParsed(over) {
    var base = {
      version: 3, serialNumberHex: "05",
      signatureAlgorithm: { name: "ecdsaWithSHA256", oid: "1.2.840.10045.4.3.2" },
      issuer: { dn: "CN=issuer" }, subject: { dn: "CN=subject" },
      validity: { notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z") },
      subjectPublicKeyInfo: { algorithm: { name: "Ed25519" }, publicKey: Buffer.alloc(4, 0xaa) },
      extensions: [], signatureValue: Buffer.from([0x30, 0x03]), tbsBytes: Buffer.from([0x30, 0x00]),
    };
    Object.keys(over || {}).forEach(function (k) { base[k] = over[k]; });
    return base;
  }
  var badDate = pki.inspect.certificate(mkParsed({ validity: { notBefore: "not-a-date", notAfter: "also-bad" } }));
  check("inspect: an unparseable validity renders the raw string, not a crash",
    /Not Before: not-a-date/.test(badDate) && /Not After : also-bad/.test(badDate));
  check("inspect: a signature algorithm with only an OID renders the OID",
    /Signature Algorithm: 1\.2\.3\.4\.5/.test(pki.inspect.certificate(mkParsed({ signatureAlgorithm: { oid: "1.2.3.4.5" } }))));
  check("inspect: a signature algorithm with neither name nor OID renders 'unknown'",
    /Signature Algorithm: unknown/.test(pki.inspect.certificate(mkParsed({ signatureAlgorithm: {} }))));
  check("inspect: a small serial renders inline decimal + hex",
    /Serial Number: 5 \(0x5\)/.test(pki.inspect.certificate(mkParsed({}))));
  check("inspect: an empty serial renders 0 (0x0)",
    /Serial Number: 0 \(0x0\)/.test(pki.inspect.certificate(mkParsed({ serialNumberHex: "" }))));
  check("inspect: an odd-length serial hex is zero-padded before decoding",
    /Serial Number: 2748 \(0xabc\)/.test(pki.inspect.certificate(mkParsed({ serialNumberHex: "abc" }))));
  check("inspect: a raw-Buffer public key renders its bytes",
    /Public-Key: \(48 bit\)\n\s+pub:\n\s+cd:cd:cd:cd:cd:cd/.test(pki.inspect.certificate(mkParsed({ subjectPublicKeyInfo: { algorithm: { name: "Ed25519" }, publicKey: Buffer.alloc(6, 0xcd) } }))));
  var nullKey = pki.inspect.certificate(mkParsed({ subjectPublicKeyInfo: { algorithm: { name: "Ed25519" }, publicKey: null } }));
  check("inspect: a null public key renders the algorithm line without a pub block",
    /Public Key Algorithm: Ed25519/.test(nullKey) && nullKey.indexOf("pub:") < 0);
  check("inspect: no extensions omits the X509v3 extensions block",
    pki.inspect.certificate(mkParsed({})).indexOf("X509v3 extensions") < 0);
  check("inspect: a raw-Buffer signature value renders a Signature Value block",
    /Signature Value:\n\s+30:03/.test(pki.inspect.certificate(mkParsed({}))));
  check("inspect: an absent signature value omits the Signature Value block",
    pki.inspect.certificate(mkParsed({ signatureValue: null })).indexOf("Signature Value:") < 0);

  // An ecPublicKey SPKI whose algorithm carries NO curve parameters: decoding the
  // absent parameters throws internally and is caught, so no curve name is resolved
  // and the bit length is derived from the point -- no ASN1 OID line, no crash. (The
  // unknown-curve vector above passes a valid-but-unregistered OID, which decodes
  // without throwing; this drives the catch itself via genuinely absent parameters.)
  var ecNoParams = pki.inspect.certificate(mkParsed({ subjectPublicKeyInfo: { algorithm: { name: "ecPublicKey" }, publicKey: Buffer.alloc(65, 0x04) } }));
  check("inspect: an ecPublicKey with no curve parameters derives bits from the point",
    /Public Key Algorithm: ecPublicKey\n\s+Public-Key: \(256 bit\)/.test(ecNoParams) && ecNoParams.indexOf("ASN1 OID:") < 0);

  // An ecPublicKey with no public key at all (absent parameters + null key) renders a
  // (0 bit) length and omits the pub block rather than dereferencing a missing point.
  var ecNullPub = pki.inspect.certificate(mkParsed({ subjectPublicKeyInfo: { algorithm: { name: "ecPublicKey" }, publicKey: null } }));
  check("inspect: an ecPublicKey with no public key renders (0 bit), no pub block",
    /Public Key Algorithm: ecPublicKey\n\s+Public-Key: \(0 bit\)/.test(ecNullPub) && ecNullPub.indexOf("pub:") < 0);

  // A basicConstraints with cA absent (BOOLEAN DEFAULT FALSE) renders CA:FALSE, not
  // TRUE -- the fixture's own CA:TRUE constraints only exercise the TRUE arm.
  check("inspect: basicConstraints with cA absent renders CA:FALSE",
    /X509v3 Basic Constraints[^\n]*\n\s+CA:FALSE/.test(
      pki.inspect.certificate(replaceExt("basicConstraints", b.sequence([b.oid(pki.oid.byName("basicConstraints")), b.octetString(b.sequence([]))])))));

  // A policyConstraints carrying inhibitPolicyMapping [1] renders that line (the
  // requireExplicitPolicy-only vector above exercises only the [0] field).
  check("inspect: policyConstraints renders inhibitPolicyMapping",
    /Inhibit Policy Mapping: 2/.test(
      pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("policyConstraints")), b.octetString(b.sequence([b.contextPrimitive(1, Buffer.from([0x02]))]))])))));

  // A CRL DP fullName carrying a directoryName [4] entry -- one of the choices _gnRaw
  // leaves as best-effort hex rather than one of its named DNS/URI/email/IP forms
  // (the IP-in-fullName vector above covers the [7] named case). It must render as
  // colon-hex, never leaking a raw DN byte that could inject a report line.
  var dpDirName = b.sequence([b.contextConstructed(0, b.contextConstructed(0,
    b.contextConstructed(4, b.sequence([b.set([b.sequence([b.oid(pki.oid.byName("commonName")), b.utf8("fn-dir")])])]))))]);
  var fnDir = pki.inspect.certificate(injectExt(b.sequence([b.oid(pki.oid.byName("cRLDistributionPoints")), b.octetString(b.sequence([dpDirName]))])));
  check("inspect: a CRL DP fullName directoryName renders best-effort hex, never raw",
    /Full Name:\n\s+a4:13:30:11/.test(fnDir) && fnDir.indexOf("fn-dir") < 0);

  // --- Interop KAT: the decoded VALUES match the authoritative openssl decode
  // (any openssl version; value-level, not byte-exact). Skips if no openssl. ---
  var ossl = findOpenssl();
  if (!ossl) { check("interop: openssl available (skipped -- no binary)", true); return; }
  var derFile = path.join(os.tmpdir(), "pki-inspect-" + process.pid + ".der");
  fs.writeFileSync(derFile, ecDer);
  var ref;
  // Pin -nameopt so the DN format is deterministic across OpenSSL versions (3.0
  // prints "CN = x" with spaces around '='; 3.5+ prints "CN=x") -- otherwise this
  // value-agreement check fails on runners with an older openssl though the render
  // is correct. eqNorm below is a second line of defense on the same axis.
  try { ref = cp.execFileSync(ossl, ["x509", "-in", derFile, "-inform", "DER", "-text", "-noout", "-nameopt", "RFC2253"], { encoding: "utf8" }); }
  catch (_e) { ref = ""; }
  fs.unlinkSync(derFile);
  // Every value my renderer prints for this cert must also appear in openssl's
  // decode -- so my report agrees with the reference implementation.
  var mustAgree = [
    "09:71:42:94:84:18:3f:f3:47:54:58:66:3b:75:36:97:27:d2:96:65", // serial
    "CN=pkijs.com", "prime256v1", "P-256", "CA:TRUE",
    "Certificate Sign, CRL Sign", "83:91:31:BE:33:42:B9:D8",       // SKI
    "DNS:pkijs.com",
  ];
  // openssl's `x509 -text` prints DN attributes as "CN=x" (3.5+) or "CN = x"
  // (3.0), so normalize whitespace around '=' before the value comparison -- this
  // KAT is value-level, not byte-exact to any single openssl release.
  function eqNorm(s) { return String(s).replace(/\s*=\s*/g, "="); }
  var refN = eqNorm(ref), tN = eqNorm(t);
  var agree = ref ? mustAgree.every(function (v) { var vn = eqNorm(v); return refN.indexOf(vn) >= 0 && tN.indexOf(vn) >= 0; }) : false;
  check("interop: pki.inspect values agree with openssl x509 -text (" + ossl.split(/[\\/]/).slice(-3).join("/") + ")", agree);
}

function findOpenssl() {
  // Prefer the installed OpenSSL 4.x major where present, then whatever is on PATH.
  var candidates = [
    "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe",
    "openssl",
    "/usr/bin/openssl", "/usr/local/bin/openssl",
  ];
  for (var i = 0; i < candidates.length; i++) {
    try { cp.execFileSync(candidates[i], ["version"], { stdio: "ignore" }); return candidates[i]; }
    catch (_e) { /* try next */ }
  }
  return null;
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
