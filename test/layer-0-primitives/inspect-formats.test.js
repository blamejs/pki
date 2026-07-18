// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.inspect.crl / .csr / .cms / .any: the non-certificate half of the OpenSSL-style
 * report surface. Each report is a FIELD LIST over the certificate inspector's shipped renderers,
 * openssl-FAMILIAR (stable house form, not byte-identical to any one OpenSSL build). These vectors
 * drive the SHIPPED consumer path pki.inspect.<fn>(...) and assert an observable label/value line
 * (the report MUST contain) or err.code -- never a captured OpenSSL string. Best-effort: a
 * valid-but-unusual structure renders without throwing; only entry-point coercion throws.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var b = pki.asn1.build;
var oid = pki.oid;

async function codeOf(promise) {
  try { await promise; return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); }
}
function has(report, s) { return report.indexOf(s) !== -1; }

function algId() { return b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]); }
function nameDer(cn) { return b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8(cn)])])]); }
function utc(s) { return b.utcTime(new Date(s)); }
function ext(o, val, crit) { var c = [b.oid(o)]; if (crit) c.push(b.boolean(true)); c.push(b.octetString(val)); return b.sequence(c); }
function mkCrl(o) {
  o = o || {};
  var t = [b.integer(o.version === undefined ? 1n : o.version), algId(), nameDer(o.issuer || "Test CA"), utc("2026-01-01T00:00:00Z")];
  if (o.nextUpdate !== false) t.push(utc("2026-02-01T00:00:00Z"));
  if (o.revoked) t.push(b.sequence(o.revoked));
  if (o.crlExtensions) t.push(b.explicit(0, b.sequence(o.crlExtensions)));
  return b.sequence([b.sequence(t), algId(), b.bitString(Buffer.alloc(64, 0xAB), 0)]);
}

async function run() {
  var s = signing.makeSigner("ec-p256");

  // ---- CRL ----
  var revokedCrl = mkCrl({ version: 1n,
    revoked: [b.sequence([b.integer(0x8005n), utc("2026-01-15T00:00:00Z"), b.sequence([ext(oid.byName("reasonCode"), b.enumerated(1n))])])],
    crlExtensions: [ext(oid.byName("cRLNumber"), b.integer(42n))] });
  var rc = pki.inspect.crl(revokedCrl);
  check("CRL report header", has(rc, "Certificate Revocation List (CRL):"));
  check("CRL issuer + Last/Next Update", has(rc, "Issuer: CN=Test CA") && has(rc, "Last Update: Jan") && has(rc, "Next Update: Feb"));
  check("CRL revoked serial strips the DER sign byte (0x8005)", has(rc, "Serial Number: 32773 (0x8005)"));
  check("CRL entry reasonCode -> named reason (pre-decoded Number)", has(rc, "keyCompromise"));
  check("CRL cRLNumber -> decimal (pre-decoded BigInt, not hex)", has(rc, "42"));
  // Empty revoked list (valid-but-unusual) does not throw + says No Revoked Certificates.
  var emptyRc = pki.inspect.crl(mkCrl({}));
  check("empty CRL -> 'No Revoked Certificates.' (no throw)", has(emptyRc, "No Revoked Certificates."));
  // null nextUpdate -> NONE
  check("CRL null nextUpdate -> 'Next Update: NONE'", has(pki.inspect.crl(mkCrl({ nextUpdate: false })), "Next Update: NONE"));
  // an UNKNOWN CRITICAL crl extension renders (labelled hex) without throwing.
  var unkCrl = mkCrl({ version: 1n, crlExtensions: [ext("1.3.6.1.4.1.99999.1", b.nullValue(), true), ext(oid.byName("cRLNumber"), b.integer(1n))] });
  check("CRL unknown critical extension renders without throwing", pki.inspect.crl(unkCrl).length > 0 && has(pki.inspect.crl(unkCrl), "critical"));
  // A raw-value CRL extension (authorityKeyIdentifier) delegates to the shared _extension (keyid);
  // an entry invalidityDate (pre-decoded Date) renders via _date.
  var akiVal = b.sequence([b.contextPrimitive(0, Buffer.alloc(20, 0xAB))]);
  var extrasCrl = mkCrl({ version: 1n,
    revoked: [b.sequence([b.integer(7n), utc("2026-01-15T00:00:00Z"), b.sequence([ext(oid.byName("invalidityDate"), b.generalizedTime(new Date("2026-01-10T00:00:00Z")))])])],
    crlExtensions: [ext(oid.byName("authorityKeyIdentifier"), akiVal), ext(oid.byName("cRLNumber"), b.integer(9n))] });
  var extrasR = pki.inspect.crl(extrasCrl);
  check("CRL AKI crlExtension delegates to _extension (keyid) + cRLNumber decimal 9", has(extrasR, "keyid") && has(extrasR, "9"));
  check("CRL entry invalidityDate (pre-decoded Date) renders via _date", has(extrasR, "Invalidity Date") && has(extrasR, "Jan 10"));

  // ---- CSR ----
  var csrDer = await pki.csr.sign({ subject: [{ commonName: "t.example" }], subjectPublicKey: s.spki }, s.key);
  var csrR = pki.inspect.csr(csrDer);
  check("CSR report header + subject", has(csrR, "Certificate Request:") && has(csrR, "Subject: CN=t.example"));
  check("CSR renders the EC public key block (reused _keyBlock)", has(csrR, "Public Key Algorithm: ecPublicKey"));
  check("CSR with no attributes -> 'Attributes:' + '(none)' (no throw)", has(csrR, "Attributes:") && has(csrR, "(none)"));
  check("CSR trailing Signature Value block", has(csrR, "Signature Value:"));
  // extensionRequest: requested extensions render through the shared _extension (identical to a cert's).
  var csrExtR = pki.inspect.csr(await pki.csr.sign({ subject: [{ commonName: "e.example" }], subjectPublicKey: s.spki, extensionRequest: { subjectAltName: [{ dNSName: "e.example" }] } }, s.key));
  check("CSR extensionRequest -> 'Requested Extensions:' + DNS SAN", has(csrExtR, "Requested Extensions:") && has(csrExtR, "DNS:e.example"));
  // RSA CSR renders Modulus + Exponent (the reused _keyBlock RSA arm).
  var rsa = signing.makeSigner("rsa");
  var rsaCsr = pki.inspect.csr(await pki.csr.sign({ subject: [{ commonName: "rsa.example" }], subjectPublicKey: rsa.spki }, rsa.key));
  check("RSA CSR renders Modulus + Exponent", has(rsaCsr, "Modulus:") && has(rsaCsr, "Exponent:"));

  // ---- CMS ----
  var attached = await pki.cms.sign(Buffer.from("hi"), [{ cert: s.cert, key: s.key }], { detached: false });
  var cmsR = pki.inspect.cms(attached);
  check("CMS ContentInfo header + signedData content type", has(cmsR, "CMS ContentInfo:") && has(cmsR, "Content Type: signedData"));
  check("CMS renders digest algorithms + encapsulated content", has(cmsR, "sha256") && has(cmsR, "Encapsulated Content Info:"));
  check("CMS signer IAS sid: Issuer + Serial Number", has(cmsR, "Issuer: CN=Test Signer") && has(cmsR, "Serial Number:"));
  check("CMS embedded certificate delegated to certificate() (nested report)", has(cmsR, "Version: 3 (0x2)"));
  // detached SignedData (eContent null) -> <detached> marker, no throw.
  var detached = await pki.cms.sign(Buffer.from("hi"), [{ cert: s.cert, key: s.key }], { detached: true });
  check("detached CMS -> '<no content (detached)>' (no throw)", has(pki.inspect.cms(detached), "<no content (detached)>"));
  // Signed attributes render via _attrValue (the attached signer carries content-type / message-digest / signing-time).
  check("CMS signed attributes render (contentType + messageDigest via _attrValue)",
    has(cmsR, "Signed Attributes:") && has(cmsR, "contentType") && has(cmsR, "messageDigest"));
  // subjectKeyIdentifier sid (the [0] arm): a signer cert bearing an SKI, signed with sid:"ski".
  var skiSigner = signing.makeSigner("ec-p256", { ski: true });
  var skiCms = await pki.cms.sign(Buffer.from("hi"), [{ cert: skiSigner.cert, key: skiSigner.key }], { detached: false, sid: "ski" });
  check("CMS subjectKeyIdentifier sid -> 'Subject Key Identifier:' (the [0] arm, not issuer/serial)",
    has(pki.inspect.cms(skiCms), "Subject Key Identifier:"));
  // Dispatch is on the stable contentType OID, not the mutable display name: a SignedData whose
  // contentTypeName an app overrode still renders the full SignedData report.
  var renamed = pki.schema.cms.parse(attached); renamed.contentTypeName = "customSignedName";
  check("CMS dispatches on the contentType OID, not the display name", has(pki.inspect.cms(renamed), "SignerInfo:") && has(pki.inspect.cms(renamed), "Digest Algorithms:"));
  // multi-signer (valid-but-unusual): each SignerInfo block renders.
  var s2 = signing.makeSigner("ed25519");
  var multi = await pki.cms.sign(Buffer.from("hi"), [{ cert: s.cert, key: s.key }, { cert: s2.cert, key: s2.key }], { detached: false });
  check("CMS multi-signer renders both SignerInfo blocks", pki.inspect.cms(multi).split("SignerInfo:").length === 3);
  // non-SignedData never-throws: an envelopedData renders a structured summary.
  var env = await pki.cms.encrypt(Buffer.from("secret"), [{ cert: s.cert }]);
  var envR = pki.inspect.cms(env);
  check("CMS non-SignedData (envelopedData) renders a non-throwing summary with a RecipientInfo",
    envR.length > 0 && has(envR, "RecipientInfo:"));

  // ---- detectFormat (the schema-all engine primitive any dispatches on) ----
  check("pki.schema.detectFormat routes cert -> x509", pki.schema.detectFormat(s.cert) === "x509");
  check("pki.schema.detectFormat routes csr -> csr", pki.schema.detectFormat(csrDer) === "csr");
  check("pki.schema.detectFormat returns null for a decodable-but-unregistered shape",
    pki.schema.detectFormat(b.sequence([b.integer(1n), b.integer(2n), b.integer(3n)])) === null);

  // ---- any (dispatch) ----
  check("any routes a certificate", pki.inspect.any(s.cert).split("\n")[0] === "Certificate:");
  check("any routes a CRL", pki.inspect.any(revokedCrl).split("\n")[0] === "Certificate Revocation List (CRL):");
  check("any routes a CSR", pki.inspect.any(csrDer).split("\n")[0] === "Certificate Request:");
  check("any routes a CMS", pki.inspect.any(attached).split("\n")[0] === "CMS ContentInfo:");

  // ---- input coercion arms (pre-parsed object fast path + PEM) ----
  check("inspect.crl accepts a pre-parsed object", pki.inspect.crl(pki.schema.crl.parse(revokedCrl)).length > 0);
  check("inspect.csr accepts a pre-parsed object", pki.inspect.csr(pki.schema.csr.parse(csrDer)).length > 0);
  check("inspect.cms accepts a pre-parsed object", pki.inspect.cms(pki.schema.cms.parse(attached)).length > 0);
  check("inspect.crl accepts a PEM string", pki.inspect.crl(pki.schema.crl.pemEncode(revokedCrl, "X509 CRL")).length > 0);
  // CSR challengePassword -> a non-extensionRequest attribute rendered via _attrValue.
  var cpCsr = pki.inspect.csr(await pki.csr.sign({ subject: [{ commonName: "c.example" }], subjectPublicKey: s.spki, challengePassword: "secret123" }, s.key));
  check("CSR challengePassword renders as an attribute", has(cpCsr, "challengePassword"));
  // CompressedData (a non-SignedData shape) renders a summary with its compression algorithm.
  var compressed = await pki.cms.compress(Buffer.from("compress me ".repeat(20)));
  check("CMS CompressedData renders a non-throwing summary (Compression Algorithm)", has(pki.inspect.cms(compressed), "Compression Algorithm:"));
  // A deferred CMS content type (id-data) is a VALID ContentInfo the parser defers -> outer
  // summary, not inspect/bad-cms.
  var idData = b.sequence([b.oid(oid.byName("data")), b.explicit(0, b.octetString(Buffer.from("payload")))]);
  check("inspect.cms on a deferred content type (id-data) renders an outer summary (no throw)",
    has(pki.inspect.cms(idData), "Content Type: data") && has(pki.inspect.cms(idData), "outer ContentInfo only"));
  // any() routes a label-mismatched PEM (a SignedData armored PKCS7, not CMS) by the detected DER.
  var pkcs7Pem = "-----BEGIN PKCS7-----\n" + Buffer.from(attached).toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END PKCS7-----\n";
  check("any() routes a PKCS7-labeled CMS PEM (label-agnostic detect -> DER route)",
    pki.inspect.any(pkcs7Pem).split("\n")[0] === "CMS ContentInfo:");
  // A CMS ContentInfo with a private/unregistered contentType OID (cms/unknown-content-type) also
  // renders the outer summary, not inspect/bad-cms.
  var unkCms = b.sequence([b.oid("1.3.6.1.4.1.99999.7"), b.explicit(0, b.octetString(Buffer.from("x")))]);
  check("inspect.cms on an unregistered contentType renders an outer summary (no throw)",
    has(pki.inspect.cms(unkCms), "Content Type: 1.3.6.1.4.1.99999.7") && has(pki.inspect.cms(unkCms), "outer ContentInfo only"));
  // any() preserves its error contract: a non-decodable Buffer -> inspect/bad-input (not a raw SchemaError).
  check("any() on a non-decodable Buffer -> inspect/bad-input (detectFormat error wrapped)",
    await codeOf(Promise.resolve().then(function () { return pki.inspect.any(Buffer.from([0xff])); })) === "inspect/bad-input");

  // ---- fail-closed coercion ----
  check("inspect.crl(42) -> inspect/bad-input", await codeOf(Promise.resolve().then(function () { return pki.inspect.crl(42); })) === "inspect/bad-input");
  check("inspect.crl(garbage DER) -> inspect/bad-crl", await codeOf(Promise.resolve().then(function () { return pki.inspect.crl(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])); })) === "inspect/bad-crl");
  check("inspect.csr('bad PEM') -> inspect/bad-input", await codeOf(Promise.resolve().then(function () { return pki.inspect.csr("-----BEGIN CERTIFICATE REQUEST-----\nnot base64!\n-----END CERTIFICATE REQUEST-----"); })) === "inspect/bad-input");
  check("a spoofed pre-parsed CRL object (marker only) -> inspect/bad-input",
    await codeOf(Promise.resolve().then(function () { return pki.inspect.crl({ thisUpdate: new Date() }); })) === "inspect/bad-input");
  // any on an out-of-scope but detectable format (pkcs8) throws inspect/unsupported-format.
  var pkcs8 = require("node:crypto").generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" });
  check("any on an out-of-scope format -> inspect/unsupported-format",
    await codeOf(Promise.resolve().then(function () { return pki.inspect.any(pkcs8); })) === "inspect/unsupported-format");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
