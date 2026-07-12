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
  check("inspect: control byte in a DN value is escaped, not injected",
    /Subject: CN=\\x0Aich\.blamejs\.test/.test(e) && e.indexOf("CN=\nich.blamejs.test") < 0);

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

  // --- Fail-closed input; a malformed extension does NOT sink the report ---
  check("inspect(42) -> inspect/bad-input", codeOf(function () { pki.inspect.certificate(42); }) === "inspect/bad-input");
  check("inspect(garbage der) -> inspect/bad-certificate", codeOf(function () { pki.inspect.certificate(Buffer.from("not a cert")); }) === "inspect/bad-certificate");
  check("inspect(bad PEM) -> inspect/bad-input", codeOf(function () { pki.inspect.certificate("-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----"); }) === "inspect/bad-input");

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
