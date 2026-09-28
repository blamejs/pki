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
  // an UNKNOWN CRITICAL crl extension renders (labeled hex) without throwing.
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
  // deltaCRLIndicator (raw-Buffer INTEGER BaseCRLNumber, not pre-decoded) renders in decimal so an
  // operator can relate the delta CRL to its base -- not the raw DER hex the generic fallback prints.
  var deltaCrl = mkCrl({ version: 1n, crlExtensions: [ext(oid.byName("deltaCRLIndicator"), b.integer(42n), true), ext(oid.byName("cRLNumber"), b.integer(43n))] });
  check("CRL deltaCRLIndicator renders the base CRL number in decimal (decoded INTEGER, not DER hex)",
    has(pki.inspect.crl(deltaCrl), "BaseCRLNumber: 42"));
  // A deltaCRLIndicator whose value is not a bare INTEGER is best-effort: fall through to the shared
  // _extension (hex), never throw the report.
  var badDelta = mkCrl({ version: 1n, crlExtensions: [ext(oid.byName("deltaCRLIndicator"), b.octetString(Buffer.from("x")), true), ext(oid.byName("cRLNumber"), b.integer(1n))] });
  check("CRL malformed deltaCRLIndicator falls through to hex (best-effort, no throw, no BaseCRLNumber)",
    pki.inspect.crl(badDelta).length > 0 && !has(pki.inspect.crl(badDelta), "BaseCRLNumber:"));
  // pki.oid.register() can override a built-in extension name. The decoder pre-decodes
  // cRLNumber/reasonCode/invalidityDate by STABLE OID, so ext.name diverges from the canonical
  // while ext.oid and the pre-decoded value stay canonical -- the report must dispatch on ext.oid,
  // not the mutable name, or _extension gets a BigInt/Number/Date and renders it as empty/wrong.
  var renamedCrl = pki.schema.crl.parse(revokedCrl);
  renamedCrl.crlExtensions.forEach(function (e) { if (e.oid === oid.byName("cRLNumber")) e.name = "x-crlnum"; });
  renamedCrl.revokedCertificates.forEach(function (rc2) { (rc2.crlEntryExtensions || []).forEach(function (e) { if (e.oid === oid.byName("reasonCode")) e.name = "x-reason"; }); });
  var renamedR = pki.inspect.crl(renamedCrl);
  check("CRL cRLNumber renders by stable OID even when its display name is overridden", has(renamedR, "42"));
  check("CRL entry reasonCode renders by stable OID even when its display name is overridden", has(renamedR, "keyCompromise"));
  var renamedExtras = pki.schema.crl.parse(extrasCrl);
  renamedExtras.revokedCertificates.forEach(function (rc2) { (rc2.crlEntryExtensions || []).forEach(function (e) { if (e.oid === oid.byName("invalidityDate")) e.name = "x-invdate"; }); });
  check("CRL entry invalidityDate renders by stable OID even when its display name is overridden", has(pki.inspect.crl(renamedExtras), "Jan 10"));

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
  // extensionRequest dispatch keys on the STABLE OID: a pki.oid.register() name override must not
  // drop the "Requested Extensions" rendering (attr.type + attr.extensions stay canonical).
  var extReqCsr = pki.schema.csr.parse(await pki.csr.sign({ subject: [{ commonName: "o.example" }], subjectPublicKey: s.spki, extensionRequest: { subjectAltName: [{ dNSName: "o.example" }] } }, s.key));
  extReqCsr.attributes.forEach(function (a) { if (a.type === oid.byName("extensionRequest")) a.name = "x-extreq"; });
  check("CSR extensionRequest renders by stable OID even when its display name is overridden",
    has(pki.inspect.csr(extReqCsr), "Requested Extensions:") && has(pki.inspect.csr(extReqCsr), "DNS:o.example"));
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
  // _attrValue keys on the STABLE OID: overriding the signed-attr display names must still decode
  // contentType -> a name ("data") and signingTime -> a date ("... GMT"), not fall back to hex.
  var saCms = pki.schema.cms.parse(attached);
  saCms.signerInfos.forEach(function (si) { (si.signedAttrs || []).forEach(function (a) { a.name = "x-" + a.name; }); });
  var saBlock = pki.inspect.cms(saCms).split("Signed Attributes:")[1] || "";
  check("CMS signed-attr values decode by stable OID even when the attr display names are overridden",
    saBlock.indexOf("data") !== -1 && /GMT/.test(saBlock));
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
  check("inspect.cms accepts a pre-parsed CompressedData object (non-SignedData fast path renders)",
    has(pki.inspect.cms(pki.schema.cms.parse(compressed)), "Compression Algorithm:"));
  // AuthEnvelopedData (AES-GCM, the default pki.cms.encrypt output) and EnvelopedData (AES-CBC)
  // through the parsed-object fast path: the shape predicate keys on the field the build actually
  // surfaces (encryptedContentInfo), not the internal schema field name (authEncryptedContentInfo).
  var aeadDer = await pki.cms.encrypt(Buffer.from("x"), [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-gcm" });
  var envDer = await pki.cms.encrypt(Buffer.from("x"), [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("inspect.cms accepts a pre-parsed AuthEnvelopedData object (AES-GCM encrypt fast path)",
    pki.inspect.cms(pki.schema.cms.parse(aeadDer)).split("\n")[0] === "CMS ContentInfo:");
  check("inspect.cms accepts a pre-parsed EnvelopedData object (AES-CBC encrypt fast path)",
    pki.inspect.cms(pki.schema.cms.parse(envDer)).split("\n")[0] === "CMS ContentInfo:");
  // A deferred CMS content type (id-data) is a VALID ContentInfo the parser defers -> outer
  // summary, not inspect/bad-cms.
  var idData = b.sequence([b.oid(oid.byName("data")), b.explicit(0, b.octetString(Buffer.from("payload")))]);
  check("inspect.cms on a deferred content type (id-data) renders an outer summary (no throw)",
    has(pki.inspect.cms(idData), "Content Type: data") && has(pki.inspect.cms(idData), "outer ContentInfo only"));
  // any() routes a label-mismatched PEM (a SignedData armored PKCS7, not CMS) by the detected DER.
  var pkcs7Pem = "-----BEGIN PKCS7-----\n" + Buffer.from(attached).toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END PKCS7-----\n";
  check("any() routes a PKCS7-labeled CMS PEM (label-agnostic detect -> DER route)",
    pki.inspect.any(pkcs7Pem).split("\n")[0] === "CMS ContentInfo:");
  check("inspect.cms accepts a PKCS7-labeled PEM directly (label-agnostic coercion)",
    pki.inspect.cms(pkcs7Pem).split("\n")[0] === "CMS ContentInfo:");
  // The fs.readFileSync path: a PEM-armored Buffer (not a string) under an alias label must unwrap
  // exactly like the string and like any(), not hit the format parser's canonical-label check.
  check("inspect.cms accepts a PKCS7-labeled PEM as a Buffer (label-agnostic coercion)",
    pki.inspect.cms(Buffer.from(pkcs7Pem)).split("\n")[0] === "CMS ContentInfo:");
  var aliasCrlPem = "-----BEGIN CRL-----\n" + Buffer.from(revokedCrl).toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CRL-----\n";
  check("inspect.crl accepts an aliased-label ('CRL', not 'X509 CRL') PEM Buffer (label-agnostic coercion)",
    pki.inspect.crl(Buffer.from(aliasCrlPem)).length > 0);
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
  check("a partial pre-parsed SignedData object (contentType/name only) -> inspect/bad-input (not a partial render)",
    await codeOf(Promise.resolve().then(function () { return pki.inspect.cms({ contentType: "1.2.840.113549.1.7.2", contentTypeName: "signedData" }); })) === "inspect/bad-input");
  check("a partial pre-parsed EnvelopedData object (type/name/version but no structural fields) -> inspect/bad-input",
    await codeOf(Promise.resolve().then(function () { return pki.inspect.cms({ contentType: oid.byName("envelopedData"), contentTypeName: "envelopedData", version: 0 }); })) === "inspect/bad-input");
  await runEveryDetectedFormat();

  console.log("CHECKS " + helpers.getChecks());
}

// ---------------------------------------------------------------------------------------------------
// Every format pki.schema.all() detects reaches a report, and each is reachable BY NAME as well as by
// detection, because a renderer only detection can reach is a feature an operator cannot ask for.
//
// The fixtures are built rather than captured, one per format, because a renderer written against a
// schema read by eye renders fields the parser does not return. Recipes that cost something to
// rediscover are noted where they are used.
// ---------------------------------------------------------------------------------------------------

var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2030-01-01T00:00:00Z");

async function buildEveryFormat() {
  var nodeCrypto = require("node:crypto");
  var kp = await pki.key.generate("Ed25519");
  var key = await pki.key.export(kp.privateKey), spki = await pki.key.export(kp.publicKey);
  var cert = await pki.x509.sign({ subject: "A Format CA", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
  var keyId = nodeCrypto.createHash("sha1").update(spki).digest();
  var imprint = { hashAlgorithm: "sha256", hashedMessage: nodeCrypto.createHash("sha256").update("x").digest() };
  // A TSA certificate needs a CRITICAL timeStamping extendedKeyUsage and a digitalSignature keyUsage,
  // or pki.tsp.sign refuses to issue under it.
  var tsaCert = await pki.x509.sign({ subject: "A Format TSA", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
  { cert: cert, key: key });
  var token = await pki.tsp.sign(imprint, { cert: tsaCert, key: key }, { policy: "1.2.3", serialNumber: 1 });

  return {
    key: key, spki: spki, cert: cert,
    x509: cert,
    crl: await pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, crlNumber: 1n, revoked: [] }, { cert: cert, key: key }),
    csr: await pki.csr.sign({ subject: "A Format Subject", subjectPublicKey: spki }, { key: key }),
    cms: await pki.cms.sign(Buffer.from("format probe"), [{ cert: cert, key: key }]),
    pkcs8: key,
    // A shrouded key bag so the store carries private key material the report must not print.
    pkcs12: await pki.pkcs12.build({ safeContents: [{ bags: [
      { type: "cert", cert: cert },
      { type: "shroudedKey", key: key, encrypt: { password: "1234" } }] }] },
    { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 2048 } }),
    crmf: await pki.crmf.build({ certReqId: 0, certTemplate: { subject: "A Format Subject",
      publicKey: spki, validity: { notBefore: NB, notAfter: NA } } }, { key: key }),
    csrattrs: b.sequence([b.oid("1.2.840.113549.1.9.7"),
      b.sequence([b.oid("1.2.840.113549.1.1.1"), b.set([b.integer(2048n)])])]),
    // trustanchor: matches() requires a [1] or [2] tagged member, so a list of bare certificates is
    // deliberately not claimed by it. The [2] arm is TrustAnchorInfo.
    trustanchor: b.sequence([b.explicit(2, b.sequence([b.raw(spki), b.octetString(keyId)]))]),
    "ocsp-request": await pki.ocsp.buildRequest({ cert: cert, issuer: cert }),
    // The same request with the two optional fields present, so F2g2 can tell an absent field from a
    // misnamed one.
    ocspRequestFull: await pki.ocsp.buildRequest({ cert: cert, issuer: cert },
      // RFC 9654 sec. 2.1 fixes a nonce at 32 to 128 octets.
      { requestorName: pki.x509.parseDn("CN=A Format Requestor").bytes, nonce: Buffer.alloc(32, 5) }),
    "ocsp-response": await pki.ocsp.sign({ responderID: "byName",
      responses: [{ cert: cert, issuer: cert, status: "good", thisUpdate: NB, nextUpdate: NA }] },
    { cert: cert, key: key }),
    // A revoked answer: the status is an object whose `revoked` names the time, which is the shape the
    // parser returns as certStatus.type plus revocationTime and revocationReason.
    ocspRevoked: await pki.ocsp.sign({ responderID: "byName",
      responses: [{ cert: cert, issuer: cert, thisUpdate: NB, nextUpdate: NA,
        status: { revoked: new Date("2027-03-01T00:00:00Z"), revocationReason: "keyCompromise" } }] },
    { cert: cert, key: key }),
    // The registry's "tsp" entry detects a TimeStampResp: matches() wants a PKIStatusInfo first child.
    // A bare token is a CMS ContentInfo and is detected as cms.
    tsp: pki.tsp.response(token, {}),
    tspToken: token,
    attrcert: await pki.attrcert.sign({ holder: { entityName: { directoryName: "CN=Alice" } },
      notBeforeTime: NB, notAfterTime: NA,
      attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:format" } } } },
    { name: "CN=A Format AA", publicKey: spki, key: key }),
    cmp: await pki.cmp.build({ header: { sender: { directoryName: "CN=A Format Subject" },
      recipient: { directoryName: "CN=A Format CA" }, transactionID: Buffer.alloc(16, 7) },
    body: { ir: { certTemplate: { subject: [{ commonName: "A Format Subject" }], publicKey: spki } } } },
    { cert: cert, key: key }),
  };
}

async function runEveryDetectedFormat() {
  var f = await buildEveryFormat();

  // The claim, stated once over the whole registry rather than format by format: every name
  // pki.schema.all() detects routes to a report. The expected set is the registry's own, so a format
  // added later is a failure here until it has a renderer, which is what makes this the item's guard.
  var names = pki.schema.all();
  var unreachable = [], byName = [], mismatched = [];
  names.forEach(function (n) {
    if (NO_REPORT_BY_DESIGN[n]) return;
    var der = f[n];
    if (der === undefined) { unreachable.push(n + " (no fixture)"); return; }
    var viaAny;
    try { viaAny = pki.inspect.any(der); } catch (e) { unreachable.push(n + " -> " + e.code); return; }
    if (!viaAny || viaAny.length < 10) { unreachable.push(n + " (empty report)"); return; }
    // Reachable BY NAME too: the verb for this format, found on the shipped namespace rather than
    // assumed, and rendering the same string as detection did.
    var verb = INSPECT_VERB_FOR[n];
    if (!verb || typeof pki.inspect[verb] !== "function") { byName.push(n + " (no verb " + verb + ")"); return; }
    var viaVerb;
    try { viaVerb = pki.inspect[verb](der); } catch (e) { byName.push(n + "." + verb + " -> " + e.code); return; }
    if (viaVerb !== viaAny) mismatched.push(n);
  });
  check("F1. every format pki.schema.all() detects reaches a report through any() (" +
    names.length + " formats, " + Object.keys(NO_REPORT_BY_DESIGN).length +
    " with no report by design; unreachable: " + (unreachable.join(", ") || "none") + ")",
    unreachable.length === 0 && names.length === 15);
  check("F2. and every one is reachable by name, rendering the same report (" +
    (byName.join(", ") || "all named") + (mismatched.length ? "; differs: " + mismatched.join(", ") : "") + ")",
    byName.length === 0 && mismatched.length === 0);

  // Each verb named in full, one vector apiece, asserting a field only that format has. F1 and F2 prove
  // the SET is complete; these prove each report says something true about its own structure, and they
  // fail readably when one renderer breaks rather than as a list.
  check("F2a. pki.inspect.pkcs8 names the key algorithm",
    has(pki.inspect.pkcs8(f.pkcs8), "PKCS#8 Private Key:") && has(pki.inspect.pkcs8(f.pkcs8), "Private Key Algorithm:"));
  // An AlgorithmIdentifier's PARAMETERS say which curve an EC key is on, and they are public: they describe
  // the algorithm rather than the key. Without them the report named only `ecPublicKey` and identified no
  // curve anywhere, which the verb's own documentation promises it does.
  var ecPkcs8 = require("node:crypto").generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .privateKey.export({ format: "der", type: "pkcs8" });
  var ecR = pki.inspect.pkcs8(ecPkcs8);
  check("F2a2. and it identifies the curve an EC key is on, without printing the key",
    has(ecR, "Private Key Algorithm: ecPublicKey") && has(ecR, "Algorithm Parameters: prime256v1") &&
    !leaks(ecR, pki.schema.pkcs8.parse(ecPkcs8).privateKey));
  check("F2b. pki.inspect.pkcs12 names the integrity mode and the bags",
    has(pki.inspect.pkcs12(f.pkcs12), "PKCS#12 Store:") && has(pki.inspect.pkcs12(f.pkcs12), "Integrity Mode:") &&
    has(pki.inspect.pkcs12(f.pkcs12), "Safe Bags:"));
  check("F2c. pki.inspect.crmf names the request id and the template subject",
    has(pki.inspect.crmf(f.crmf), "CRMF Certificate Request Messages:") &&
    has(pki.inspect.crmf(f.crmf), "Request ID:") && has(pki.inspect.crmf(f.crmf), "A Format Subject"));
  check("F2d. pki.inspect.cmp names the body arm and the transaction id",
    has(pki.inspect.cmp(f.cmp), "CMP Message:") && has(pki.inspect.cmp(f.cmp), "Arm: ir") &&
    has(pki.inspect.cmp(f.cmp), "Transaction ID:"));
  check("F2e. pki.inspect.csrattrs names each requested item",
    has(pki.inspect.csrattrs(f.csrattrs), "EST CSR Attributes:") && has(pki.inspect.csrattrs(f.csrattrs), "Items: 2"));
  check("F2f. pki.inspect.trustanchor names the anchor form and its key identifier",
    has(pki.inspect.trustanchor(f.trustanchor), "Trust Anchor List:") &&
    has(pki.inspect.trustanchor(f.trustanchor), "Anchors: 1") &&
    has(pki.inspect.trustanchor(f.trustanchor), "Key Identifier:"));
  check("F2g. pki.inspect.ocspRequest names the CertID hash algorithm and the serial",
    has(pki.inspect.ocspRequest(f["ocsp-request"]), "OCSP Request:") &&
    has(pki.inspect.ocspRequest(f["ocsp-request"]), "Issuer Key Hash:") &&
    has(pki.inspect.ocspRequest(f["ocsp-request"]), "Serial Number:"));
  // A field a report calls absent has to be absent, not misnamed: the bare request above prints
  // "(none)" for its requestor name and its extensions, so the populated request is rendered too and
  // both must carry values. A wrong field name reads exactly like an absent optional field, and this is
  // the difference between the two.
  var bare = pki.inspect.ocspRequest(f["ocsp-request"]);
  var full = pki.inspect.ocspRequest(f.ocspRequestFull);
  check("F2g2. and a requestor name and a nonce render as values where the bare request says (none)",
    has(bare, "Requestor Name: (none)") && has(bare, "Request Extensions: (none)") &&
    !has(full, "Requestor Name: (none)") && has(full, "A Format Requestor") &&
    !has(full, "Request Extensions: (none)") && has(full, "Nonce"));
  check("F2h. pki.inspect.ocspResponse names the response status and the certificate status",
    has(pki.inspect.ocspResponse(f["ocsp-response"]), "OCSP Response:") &&
    has(pki.inspect.ocspResponse(f["ocsp-response"]), "Response Status:") &&
    has(pki.inspect.ocspResponse(f["ocsp-response"]), "Cert Status: good"));
  // A revoked answer carries two fields a good one does not, and reading the status as "unknown" is what
  // a wrong field name looks like, so the revoked arm is its own vector rather than assumed to follow.
  var revR = pki.inspect.ocspResponse(f.ocspRevoked);
  check("F2h2. and a revoked answer carries its revocation time and reason",
    has(revR, "Cert Status: revoked") && has(revR, "Revocation Time:") &&
    has(revR, "Revocation Reason: keyCompromise") && !has(revR, "Cert Status: unknown"));
  check("F2i. pki.inspect.tsp names the status and the message imprint",
    has(pki.inspect.tsp(f.tsp), "Timestamp Response:") && has(pki.inspect.tsp(f.tsp), "Message Imprint:"));
  // The attributes are what an attribute certificate exists to assert, so the DECODED value is asserted and
  // not just the label: the parser decodes a role to the name it grants, and a report showing the bytes it
  // decoded from tells a reader nothing they can act on.
  var acReport = pki.inspect.attrcert(f.attrcert);
  check("F2j. pki.inspect.attrcert names the holder and the decoded attributes it asserts",
    has(acReport, "Attribute Certificate:") && has(acReport, "Holder:") && has(acReport, "Attributes:") &&
    has(acReport, "roleName: URI:urn:role:format") && !/role:\n\s+30:/.test(acReport));
  // The same for an extension the certificate decoders do not know: the attribute-certificate parser decoded
  // it, and without reading that the report hex-dumped the bytes it had already decoded.
  var acExt = await pki.attrcert.sign({ holder: { entityName: { directoryName: "CN=Alice" } },
    notBeforeTime: NB, notAfterTime: NA, extensions: { noRevAvail: true },
    attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:ext" } } } },
  { name: "CN=A Format AA", publicKey: f.spki, key: f.key });
  check("F2k. and an extension its own parser decoded renders decoded, not as its bytes",
    has(pki.inspect.attrcert(acExt), "noRevAvail: true") &&
    !/noRevAvail:\n\s+05:00/.test(pki.inspect.attrcert(acExt)));
  // A decoded record that is NOT a name has to render as its own fields. Asked of every value, the name
  // renderer answers a non-name with a truthy placeholder, and that answer stood in for the record: a group
  // attribute rendered as that placeholder instead of the memberships it grants.
  var acGroup = await pki.attrcert.sign({ holder: { entityName: { directoryName: "CN=Alice" } },
    notBeforeTime: NB, notAfterTime: NA, attributes: { group: { values: [{ string: "admins" }] } } },
  { name: "CN=A Format AA", publicKey: f.spki, key: f.key });
  var groupR = pki.inspect.attrcert(acGroup);
  check("F2l. and a decoded record that is not a name renders its own fields",
    has(groupR, "admins") && !has(groupR, "tagundefined"));

  // ---- the one security decision: a report never prints private key material ----
  // Asserted by searching the rendered text for a byte run of the key itself, in the encodings a
  // renderer could plausibly emit, rather than by reading the renderer and believing it.
  var privInner = pki.schema.pkcs8.parse(f.pkcs8).privateKey;
  function leaks(report, secret) {
    var hex = secret.toString("hex");
    return report.indexOf(hex) !== -1 ||
      report.indexOf(secret.toString("base64")) !== -1 ||
      report.indexOf(hex.replace(/(..)(?=.)/g, "$1:")) !== -1;
  }
  var p8 = pki.inspect.pkcs8(f.pkcs8);
  check("F3. a PKCS#8 report names the algorithm and does NOT carry the private key bytes",
    has(p8, "Ed25519") && !leaks(p8, privInner) && !leaks(p8, f.pkcs8));
  var p12 = pki.inspect.pkcs12(f.pkcs12);
  check("F4. a PKCS#12 report does NOT carry the private key bytes",
    p12.length > 40 && !leaks(p12, privInner));
  // A password-protected store cannot be opened by a verb that takes no password, so the report says
  // what opening it needs. A report that silently showed nothing would read as an empty file.
  check("F5. a PKCS#12 report shows its MAC and says what opening the contents needs",
    has(p12, "MAC") && has(p12, "pki.pkcs12.open"));
  // The report SAYS which bags hold a private key, and the statement is asserted rather than assumed: a
  // parsed bag reports itself by its ASN.1 name, so a marker keyed on the builder's shorthand never fired.
  check("F5b. and it marks the bags that hold a private key, by the name a parsed bag reports",
    /pkcs8ShroudedKeyBag {2}\(private key, not rendered\)/.test(p12) && has(p12, "certBag"));
  // A safeContentsBag holds further bags, and reporting only the container made a container of keys and
  // certificates read the same as an empty one. The no-key-material rule carries into the nested level.
  var nestedP12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "safeContents",
    nested: [{ type: "cert", cert: f.cert }, { type: "shroudedKey", key: f.key, encrypt: { password: "1234" } }] }] }] },
  { password: "1234" });
  var nestedR = pki.inspect.pkcs12(nestedP12);
  check("F5c. and a container's nested bags are inventoried, still without rendering key material",
    has(nestedR, "safeContentsBag  (2 nested)") && has(nestedR, "certBag") &&
    /pkcs8ShroudedKeyBag {2}\(private key, not rendered\)/.test(nestedR) &&
    !leaks(nestedR, pki.schema.pkcs8.parse(f.key).privateKey));

  // ---- each new verb refuses the wrong format with its own typed code, as the four do ----
  var wrong = f.cert;
  var refusals = [];
  Object.keys(INSPECT_VERB_FOR).forEach(function (n) {
    var verb = INSPECT_VERB_FOR[n];
    if (n === "x509" || typeof pki.inspect[verb] !== "function") return;
    var code = "NO-THROW";
    try { pki.inspect[verb](wrong); } catch (e) { code = (e && e.code) || "RAW"; }
    if (code === "NO-THROW" || code.indexOf("inspect/") !== 0) refusals.push(verb + " -> " + code);
  });
  check("F6. every format verb refuses a certificate with its own inspect/ code (" +
    (refusals.join(", ") || "all refuse") + ")", refusals.length === 0);

  // A timestamp TOKEN is a CMS ContentInfo, so it is detected as cms and rendered by that report. The
  // tsp report is for the RESPONSE wrapper, and the two are different artifacts.
  check("F7. a bare timestamp token renders as CMS, while the response wrapper renders as a timestamp",
    pki.inspect.any(f.tspToken).split("\n")[0] === "CMS ContentInfo:" &&
    pki.inspect.any(f.tsp).split("\n")[0] !== "CMS ContentInfo:");
  check("F8. the timestamp response report carries its status and the TSTInfo inside the token",
    has(pki.inspect.tsp(f.tsp), "Status") && has(pki.inspect.tsp(f.tsp), "1.2.3"));

  // The CMS report's non-SignedData arm reads four other content types, and no vector had ever driven it:
  // every CMS report in this suite was a SignedData, so the whole branch was unexercised and a report
  // that named the wrong field for any of them would have said nothing wrong out loud.
  // A key-encryption-key recipient, because the Ed25519 certificate above is signature-only and cannot
  // be a CMS encryption recipient; the arm under test is the report's, not the key agreement's.
  var env = await pki.cms.encrypt(Buffer.from("enveloped"),
    [{ kek: Buffer.alloc(16, 3), kekId: Buffer.from("format-kek") }],
    { contentEncryptionAlgorithm: "aes-128-cbc" });
  var envR = pki.inspect.cms(env);
  check("F11. an EnvelopedData report names its recipients and the content encryption algorithm",
    has(envR, "envelopedData") && has(envR, "RecipientInfo:") && has(envR, "Content Encryption Algorithm:"));
  var mac = await pki.cms.authenticate(Buffer.from("authenticated"), [{ password: "s3cret" }], {});
  var macR = pki.inspect.cms(mac);
  // The registry's name for RFC 5652 AuthenticatedData is `authData`, which is what the report prints.
  check("F12. an AuthenticatedData report names its MAC algorithm",
    has(macR, "authData") && has(macR, "MAC Algorithm: hmacWithSHA256"));
  var comp = await pki.cms.compress(Buffer.from("compressed compressed compressed"));
  var compR = pki.inspect.cms(comp);
  check("F13. a CompressedData report names its compression algorithm",
    has(compR, "compressedData") && has(compR, "Compression Algorithm:"));
  var dig = await pki.cms.digest(Buffer.from("digested"));
  check("F14. a DigestedData report renders its outer content type without throwing",
    has(pki.inspect.cms(dig), "digestedData"));

  await runPopulatedFormats(f);

  // renderedExtensions answers a different question and this item does not touch it.
  check("F9. renderedExtensions still lists extension renderers, not formats",
    pki.inspect.renderedExtensions.indexOf("subjectAltName") !== -1 &&
    pki.inspect.renderedExtensions.indexOf("pkcs12") === -1);

  // An X.509-1997 attribute certificate owes a refusal rather than a report, and the refusal has to say
  // WHICH form the reader is holding: "inspect does not support this format" sends an operator looking
  // for a missing feature, where the truth is that the form is obsolete and this build will not parse
  // it. The fixture matches the v1 detector: an acinfo of six children whose first is a [0]/[1] with
  // children and whose second is a SEQUENCE.
  var v1Acinfo = b.sequence([b.explicit(0, b.sequence([b.raw(nameDer("v1 holder"))])), b.sequence([b.raw(nameDer("v1 issuer"))]),
    algId(), b.integer(1n), b.sequence([utc("2026-01-01T00:00:00Z"), utc("2027-01-01T00:00:00Z")]), b.sequence([])]);
  var v1Der = b.sequence([v1Acinfo, algId(), b.bitString(Buffer.alloc(64, 0xff), 0)]);
  var v1Code = "NO-THROW", v1Msg = "";
  try { pki.inspect.any(v1Der); } catch (e) { v1Code = (e && e.code) || "RAW"; v1Msg = (e && e.message) || ""; }
  check("F10. a v1 attribute certificate is refused by what it IS, not as an unsupported format (" +
    v1Code + ")",
  v1Code !== "NO-THROW" && v1Code !== "inspect/unsupported-format" &&
    /v1|1997|obsolete/i.test(v1Msg + v1Code));
}

// ---------------------------------------------------------------------------------------------------
// The fixtures above are minimal, so they drive the "field absent" half of every optional field a report
// renders. These drive the other half: a structure carrying the fields, so the branch that prints a value
// runs and a renderer reading the wrong field name is caught by the value not appearing. An absent field
// and a misnamed one look identical in a minimal fixture, which is what makes this pass worth its length.
// ---------------------------------------------------------------------------------------------------

async function runPopulatedFormats(f) {
  var key = f.key, spki = f.spki, cert = f.cert;

  // PKCS#12 carrying an ENCRYPTED safe beside a plaintext one, so the encrypted-safes loop runs and the
  // report names the encryption algorithm without decrypting it.
  var p12Enc = await pki.pkcs12.build({ safeContents: [
    { bags: [{ type: "cert", cert: cert }] },
    { encrypt: { password: "1234" }, bags: [{ type: "cert", cert: cert }] }] },
  { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 4096 } });
  var encR = pki.inspect.pkcs12(p12Enc);
  // The ALGORITHM is the point of that line, so it is asserted by name: an encrypted safe is a CMS
  // EncryptedData and the algorithm sits on its encryptedContentInfo, so reading it off the safe reported
  // every encrypted store as "unknown" while the line itself still rendered.
  check("P1. a PKCS#12 with an encrypted safe names the algorithm and says it is not decrypted",
    has(encR, "Encrypted Safes: 1") && has(encR, "(not decrypted)") && has(encR, "Iterations: 4096") &&
    /Encrypted Safes: 1\n\s+\[0\] pbes2/.test(encR) && !has(encR, "] unknown"));

  // A CRMF template carrying every optional field the report reads.
  // A serialNumber is only a field of a REVOCATION template (crmf-sign's REVOCATION_TEMPLATE_KEYS), so a
  // certificate request cannot carry one and the report's serial line is reached by the revocation form.
  // RFC 4211 sec. 5: a supplied certTemplate version is the DER value 2, which names v3.
  var crmfFull = await pki.crmf.build({ certReqId: 7, certTemplate: { version: 2,
    issuer: [{ commonName: "A Populated Issuer" }], subject: [{ commonName: "A Populated Subject" }],
    publicKey: spki, validity: { notBefore: NB, notAfter: NA },
    extensions: { subjectAltName: [{ dNSName: "populated.example" }] } } }, { key: key });
  var crmfR = pki.inspect.crmf(crmfFull);
  // The proof of possession names its FORM: a key whose holder proved possession by signing and one an RA
  // vouched for are different assurances, and "present" said which of them had happened for neither.
  check("P2. a populated CRMF report carries the issuer, validity, extensions and the proof form",
    has(crmfR, "Request ID: 7") && has(crmfR, "A Populated Issuer") &&
    has(crmfR, "Not Before") && has(crmfR, "Requested Extensions:") && has(crmfR, "populated.example") &&
    has(crmfR, "Proof of Possession: signature"));

  // A CMP header carrying the times, nonces and key id the report reads.
  var cmpFull = await pki.cmp.build({ header: { sender: { directoryName: "CN=A Populated Subject" },
    recipient: { directoryName: "CN=A Populated CA" }, transactionID: Buffer.alloc(16, 7),
    senderNonce: Buffer.alloc(16, 9), recipNonce: Buffer.alloc(16, 11), messageTime: NB },
  body: { ir: { certTemplate: { subject: [{ commonName: "A Populated Subject" }], publicKey: spki } } } },
  { cert: cert, key: key, extraCerts: [cert] });
  var cmpR = pki.inspect.cmp(cmpFull);
  // The builder carries the signing certificate in extraCerts beside the one named here, so the count is
  // read as "more than none" rather than pinned to what the caller passed.
  check("P3. a populated CMP report carries the message time, both nonces and the extra certificates",
    has(cmpR, "Message Time:") && has(cmpR, "Sender Nonce:") && has(cmpR, "Recipient Nonce:") &&
    has(cmpR, "Protection Algorithm:") && has(cmpR, "Protection: present") &&
    /Extra Certificates: [1-9]/.test(cmpR));

  // A trust anchor carrying a title and certificate path controls, and one taking the certificate arm.
  // TrustAnchorInfo's version is DEFAULT v1, so DER omits it; including it is a malformed encoding the
  // strict parser refuses.
  var taFull = b.sequence([b.explicit(2, b.sequence([
    b.raw(spki), b.octetString(Buffer.alloc(20, 0xab)), b.utf8("A Populated Anchor"),
    b.sequence([b.raw(pki.x509.parseDn("CN=A Populated Anchor").bytes),
      b.implicit(1, b.sequence([b.sequence([b.oid("2.5.29.32.0")])])),
      b.implicit(4, b.integer(3n))])]))]);
  var taR = pki.inspect.trustanchor(taFull);
  check("P4. a populated trust anchor report carries its title and path controls",
    has(taR, "Form: taInfo") && has(taR, "Title: A Populated Anchor") &&
    has(taR, "Certificate Path Controls:") && has(taR, "Path Length: 3") && has(taR, "Policies: 1"));
  // policyFlags is a BIT STRING the parser decodes to a record of named booleans, so the report has to
  // enumerate the ones that are SET: read as an array the line never ran at all and a trust anchor's
  // active policy restrictions were simply absent from the report.
  var taFlags = pki.inspect.trustanchor(b.sequence([b.explicit(2, b.sequence([
    b.raw(spki), b.octetString(Buffer.alloc(20, 0xab)),
    b.sequence([b.raw(pki.x509.parseDn("CN=A Flagged Anchor").bytes),
      b.implicit(2, b.namedBitString([0, 2]))])]))]));
  check("P4b. and a trust anchor's set policy flags are named, not dropped",
    has(taFlags, "Policy Flags: inhibitPolicyMapping, inhibitAnyPolicy") &&
    !has(taFlags, "requireExplicitPolicy"));
  // The subtrees an anchor may certify within bound what trusting it means, so an anchor restricted to one
  // name must not read the same as an unrestricted one. Omitted, the two reports were identical.
  var ncDer = b.sequence([b.implicit(0, b.sequence([b.sequence([
    b.contextPrimitive(2, Buffer.from("constrained.example", "latin1"))])]))]);
  function anchorWith(extra) {
    return b.sequence([b.explicit(2, b.sequence([b.raw(spki), b.octetString(Buffer.alloc(20, 1)),
      b.sequence([b.raw(pki.x509.parseDn("CN=A Constrained Anchor").bytes)].concat(extra))]))]);
  }
  var taConstrained = pki.inspect.trustanchor(anchorWith([b.implicit(3, ncDer)]));
  var taOpen = pki.inspect.trustanchor(anchorWith([]));
  check("P4c. a trust anchor's name constraints are rendered, so a restricted anchor reads differently",
    has(taConstrained, "Name Constraints:") && has(taConstrained, "Permitted:") &&
    has(taConstrained, "constrained.example") && taConstrained !== taOpen &&
    !has(taOpen, "Name Constraints:"));
  // The other two forms hold a CERTIFICATE, whose subject and public key are what name the anchor. Read as
  // though every form were TrustAnchorInfo, both rendered their form and nothing else, so two different
  // anchors produced the same report and neither could be told from the other.
  var taCertArm = pki.inspect.trustanchor(b.sequence([b.raw(cert)]));
  var taTbsArm = pki.inspect.trustanchor(b.sequence([b.explicit(1, b.raw(pki.schema.x509.parse(cert).tbsBytes))]));
  check("P5. the certificate anchor form names the certificate that is the anchor",
    has(taCertArm, "Form: certificate") && has(taCertArm, "Subject: CN=A Format CA") &&
    has(taCertArm, "Subject Public Key Info:") && has(taCertArm, "Ed25519"));
  check("P5b. and the tbsCert form does too, so the two are not indistinguishable reports",
    has(taTbsArm, "Form: tbsCert") && has(taTbsArm, "Subject: CN=A Format CA") &&
    has(taTbsArm, "Subject Public Key Info:") && taTbsArm !== taCertArm);
  // A PBMAC1 store keeps the parameters that protect it inside its own structure, so a report reading the
  // outer MacData describes nothing: 2048 PBKDF2 iterations rendered as one iteration and an empty salt.
  var p12Pbmac1 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: cert }] }] },
    { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256", iterations: 2048 } });
  var pbR = pki.inspect.pkcs12(p12Pbmac1);
  check("P5c. a PBMAC1 store reports the iterations and salt that actually protect it",
    has(pbR, "Kind: pbmac1") && has(pbR, "Iterations: 2048") && has(pbR, "Key Derivation: hmacWithSHA256") &&
    /Salt: [0-9a-f]{2}:/.test(pbR) && !has(pbR, "Iterations: 1"));

  // An OCSP request carrying a per-request extension, which is a different list from the request's own.
  // singleRequestExtensions takes pre-encoded Extension DER, one per array member.
  var singleExt = b.sequence([b.oid("1.3.6.1.4.1.99999.2"), b.octetString(b.nullValue())]);
  var reqExt = await pki.ocsp.buildRequest({ cert: cert, issuer: cert, singleRequestExtensions: [singleExt] });
  check("P6. an OCSP request with a single-request extension renders that list",
    has(pki.inspect.ocspRequest(reqExt), "Single Request Extensions:"));

  // An OCSP response carrying a per-answer extension and a response extension.
  // The nonce a response echoes back is an opts field, not a responseData field: it becomes a response
  // extension, which is the list this vector needs beside the per-answer one.
  var respExt = await pki.ocsp.sign({ responderID: "byName",
    responses: [{ cert: cert, issuer: cert, status: "good", thisUpdate: NB, nextUpdate: NA,
      singleExtensions: { archiveCutoff: NB } }] },
  { cert: cert, key: key }, { nonce: Buffer.alloc(32, 5) });
  var respExtR = pki.inspect.ocspResponse(respExt);
  check("P7. an OCSP response renders both its per-answer and its response extensions",
    has(respExtR, "Single Extensions:") && has(respExtR, "Response Extensions:"));
  // An answer stating no window, so the NONE branch runs beside the dated one. The signer DEFAULTS a
  // nextUpdate when one is merely omitted, and `null` is how a caller says there is none.
  var noNext = await pki.ocsp.sign({ responderID: "byName",
    responses: [{ cert: cert, issuer: cert, status: "good", thisUpdate: NB, nextUpdate: null }] },
  { cert: cert, key: key });
  check("P8. an answer with no nextUpdate says NONE rather than omitting the line",
    has(pki.inspect.ocspResponse(noNext), "Next Update: NONE"));

  // A timestamp carrying accuracy, ordering, a nonce and a TSA name.
  var tsaCert = await pki.x509.sign({ subject: "A Populated TSA", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
  { cert: cert, key: key });
  var imprint = { hashAlgorithm: "sha256", hashedMessage: require("node:crypto").createHash("sha256").update("p").digest() };
  // The TSTInfo's tsa field is not a sign option: it is derived, so this fixture drives the accuracy,
  // ordering, nonce and serial branches and the tsa line is whatever the signer put there.
  var fullToken = await pki.tsp.sign(imprint, { cert: tsaCert, key: key },
    { policy: "1.2.3.4", serialNumber: 99, nonce: 1234n, ordering: true,
      accuracy: { seconds: 1, millis: 500 } });
  var tspR = pki.inspect.tsp(pki.tsp.response(fullToken, {}));
  check("P9. a populated timestamp report carries the accuracy, ordering, nonce and serial",
    has(tspR, "Accuracy: 1s") && has(tspR, "Ordering: true") && has(tspR, "Nonce:") &&
    has(tspR, "Serial Number: 99") && has(tspR, "1.2.3.4"));
  // A failure response carries no token at all, which is the other half of the token branch.
  var failResp = pki.tsp.response(null, { status: 2, statusString: "rejected by policy", failInfo: ["badRequest"] });
  var failR = pki.inspect.tsp(failResp);
  check("P10. a rejected timestamp response renders its status strings and reports no token",
    has(failR, "Status: 2") && has(failR, "rejected by policy") && has(failR, "Token: (none)"));
  // The failure REASON is the one thing that line is for, and PKIFailureInfo is a BIT STRING the parser
  // decodes to named bits: read as an array it rendered as object notation and the reason was lost. So the
  // assertion is the decoded reason, not the presence of a label.
  check("P10b. and it names the decoded failure reason rather than its object notation",
    has(failR, "Failure Info: badRequest") && !has(failR, "[object Object]"));
  // The same response handed to the verb as a PARSED object renders the same way. A rejection carries
  // timeStampToken: null, and requiring a token here refused a shape the parser returns.
  check("P10c. and the parsed form of that response renders identically to its bytes",
    pki.inspect.tsp(pki.schema.tsp.parseResponse(failResp)) === failR);
  // A statusString is text a RESPONDER chose, and a report is read in a terminal. Copied raw, a newline
  // forges a report line and an escape sequence rewrites the screen around it. The certificate report has
  // escaped distinguished names against exactly this since it shipped, and every field these renderers add
  // that carries chosen text is held to the same rule. The control bytes are built at runtime because the
  // source of this file stays ASCII.
  var forge = "oops" + String.fromCharCode(10) + "    Status: 0" + String.fromCharCode(27) + "[2J";
  var injected = pki.inspect.tsp(pki.tsp.response(null, { status: 2, statusString: forge }));
  check("P10d. a responder's status string cannot forge a report line or move the terminal",
    injected.indexOf(String.fromCharCode(27)) === -1 &&
    injected.split(String.fromCharCode(10)).filter(function (l) { return /^\s+Status: 0$/.test(l); }).length === 0 &&
    has(injected, "oops"));
  // A TSTInfo's tsa names the authority that stamped the time, and the parser hands it over RAW: with a
  // context tag and its bytes and no decoded value, the shape a GeneralNames member also arrives in. The
  // list path decoded one and the single path did not, so a directoryName rendered as its label with no
  // name after it and the authority was absent from the report. The shipped signer writes no tsa field, so
  // the fixture is a TSTInfo built here and spliced into a real token's eContent; the renderer parses and
  // does not verify, which is why an unsigned splice is a fair input to it.
  var tsaName = b.explicit(0, b.explicit(4, pki.x509.parseDn("CN=A Named TSA").bytes));
  var tstWithTsa = b.sequence([b.integer(1n), b.oid("1.2.3"),
    b.sequence([b.sequence([b.oid("2.16.840.1.101.3.4.2.1"), b.nullValue()]),
      b.octetString(Buffer.alloc(32, 0))]),
    b.integer(1n), b.generalizedTime(NB), tsaName]);
  var tokNode = pki.asn1.decode(f.tspToken);
  var sd = tokNode.children[1].children[0];
  var newEci = b.sequence([b.raw(sd.children[2].children[0].bytes), b.explicit(0, b.octetString(tstWithTsa))]);
  var splicedToken = b.sequence([b.raw(tokNode.children[0].bytes),
    b.explicit(0, b.sequence(sd.children.map(function (k, i) { return i === 2 ? newEci : b.raw(k.bytes); })))]);
  var tsaR = pki.inspect.tsp(b.sequence([b.sequence([b.integer(0n)]), b.raw(splicedToken)]));
  check("P10f. a timestamp's TSA name is decoded, not rendered as an empty label",
    has(tsaR, "TSA: DirName:CN=A Named TSA"));

  // The same for a trust anchor's title, which whoever wrote the anchor list chose.
  var forgedTitle = pki.inspect.trustanchor(b.sequence([b.explicit(2, b.sequence([
    b.raw(spki), b.octetString(Buffer.alloc(20, 0xab)), b.utf8(forge)]))]));
  check("P10e. and neither can a trust anchor's title",
    forgedTitle.indexOf(String.fromCharCode(27)) === -1 &&
    forgedTitle.split(String.fromCharCode(10)).filter(function (l) { return /^\s+Status: 0$/.test(l); }).length === 0);

  // RFC 6960 sec. 4.2.1 gives ResponderID two forms. The key form is a hash, not a name, so a report that
  // sent it to the name renderer identified the responder as nothing at all.
  var byKeyResp = await pki.ocsp.sign({ responderID: "byKey",
    responses: [{ cert: cert, issuer: cert, status: "good", thisUpdate: NB, nextUpdate: NA }] },
  { cert: cert, key: key });
  var byKeyR = pki.inspect.ocspResponse(byKeyResp);
  check("P11b. a byKey responder is identified by its key hash, in both forms of the field",
    /Responder ID: keyHash:[0-9a-f]{2}:/.test(byKeyR) && !has(byKeyR, "tagundefined") &&
    has(pki.inspect.ocspResponse(f["ocsp-response"]), "Responder ID: CN="));

  // The third CertStatus arm. RFC 6960 sec. 2.2's "unknown" is a real answer, distinct from a status a
  // report could not read, and the two would be indistinguishable if the renderer defaulted to the word.
  var unknownResp = await pki.ocsp.sign({ responderID: "byName",
    responses: [{ cert: cert, issuer: cert, status: "unknown", thisUpdate: NB, nextUpdate: NA }] },
  { cert: cert, key: key });
  check("P11c. the unknown certificate status is rendered as the answer it is",
    has(pki.inspect.ocspResponse(unknownResp), "Cert Status: unknown"));

  // A SIGNED OCSP request, so the signature line reads "present" rather than "(unsigned)".
  var signedReq = await pki.ocsp.buildRequest({ cert: cert, issuer: cert },
    { requestorName: pki.x509.parseDn("CN=A Signing Requestor").bytes, signer: { cert: cert, key: key } });
  check("P12. a signed OCSP request reports its signature as present",
    has(pki.inspect.ocspRequest(signedReq), "Signature: present"));

  // A MAC-protected CMP message. Its shared secret is what a senderKID names, so the header carries one
  // where a signature-protected message does not. The mac option's own field is `secret`.
  var macCmp = await pki.cmp.build({ header: { sender: { directoryName: "CN=A MAC Subject" },
    recipient: { directoryName: "CN=A MAC CA" }, transactionID: Buffer.alloc(16, 7),
    senderKID: Buffer.from("kid-1") },
  body: { ir: { certTemplate: { subject: [{ commonName: "A MAC Subject" }], publicKey: spki } } } },
  { mac: { secret: "s3cret" } });
  check("P13. a MAC-protected CMP message reports its sender key id",
    has(pki.inspect.cmp(macCmp), "Sender Key ID:"));

  // An attribute certificate whose holder takes the baseCertificateID form rather than a name, and which
  // carries an extension: two branches a holder named by entity alone never reaches.
  // A baseCertificateID's serial field is `serial` (attrcert-sign's accepted set is issuer, serial, issuerUID).
  var acBase = await pki.attrcert.sign({ holder: { baseCertificateID: { issuer: { directoryName: "CN=A Format CA" },
    serial: pki.schema.x509.parse(cert).serialNumber } }, notBeforeTime: NB, notAfterTime: NA,
  attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:populated" } } },
  extensions: { noRevAvail: true } }, { name: "CN=A Populated AA", publicKey: spki, key: key });
  var acR = pki.inspect.attrcert(acBase);
  check("P11. an attribute certificate held by base certificate id renders that form and its extensions",
    has(acR, "Base Certificate ID:") && has(acR, "Serial Number:") && has(acR, "Extensions:"));
  // The third Holder arm of RFC 5755 sec. 4.1: a digest of the object held rather than a name for it.
  var acDigest = await pki.attrcert.sign({ holder: { objectDigestInfo: { digestedObjectType: "publicKey",
    digestAlgorithm: "sha256", objectDigest: Buffer.alloc(32, 1) } }, notBeforeTime: NB, notAfterTime: NA,
  attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:digest" } } } },
  { name: "CN=A Populated AA", publicKey: spki, key: key });
  // The DIGEST is what identifies a holder named this way, so the algorithm alone left every holder
  // identified by one digest algorithm reading the same and the report carrying no identity at all.
  var digestR = pki.inspect.attrcert(acDigest);
  check("P11d. a holder named by object digest renders the type, the algorithm and the digest itself",
    has(digestR, "Object Digest Info:") && has(digestR, "Digested Object Type: publicKey") &&
    has(digestR, "Digest Algorithm: sha256") && /Digest:\n\s+01:01:01/.test(digestR));
  // The holder's own certificate serial, which is what distinguishes two holders under one issuer. RFC 5755
  // IssuerSerial names the field `serial`, not the `serialNumber` a certificate carries, and read by the
  // wrong name the line vanished while the attribute certificate's OWN serial line still matched a test
  // looking only for the label.
  var holderSerial = pki.schema.attrcert.parse(acBase).holder.baseCertificateID.serialHex;
  var holderColon = holderSerial.replace(/(..)(?=.)/g, "$1:");
  check("P11e. and a holder named by base certificate id carries that certificate's own serial",
    holderSerial.length > 0 && has(acR, holderColon) &&
    acR.split("Serial Number").length === 3);
}

/** The verb that renders each detected format, so F2 asks the namespace by name rather than assuming
 *  a naming rule. `x509` is the certificate renderer, which predates this table. */
var INSPECT_VERB_FOR = Object.assign(Object.create(null), {
  x509: "certificate", crl: "crl", csr: "csr", cms: "cms",
  pkcs8: "pkcs8", pkcs12: "pkcs12", crmf: "crmf", cmp: "cmp", csrattrs: "csrattrs",
  trustanchor: "trustanchor", "ocsp-request": "ocspRequest", "ocsp-response": "ocspResponse",
  tsp: "tsp", attrcert: "attrcert",
});

/** `attrcert-v1` is in the detect set so that an X.509-1997 attribute certificate can be REFUSED by
 *  name instead of misparsed as the v2 form: its parser always throws
 *  `attrcert/legacy-v1-not-supported` (RFC 5755 sec. 1 obsoletes it). So it owes no renderer, and what
 *  it owes instead is that a reader of one is told which form it holds, which F10 asserts. */
var NO_REPORT_BY_DESIGN = Object.assign(Object.create(null), { "attrcert-v1": true });

module.exports = { run: run };

if (require.main === module) run().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
