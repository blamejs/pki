// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for RFC 9763 related certificates -- the two ends of one exchange, which is
// how a subject holding a classical certificate and a post-quantum one lets a protocol use both.
//
// The requester asks in a CSR attribute (sec. 3.1):
//
//   RequesterCertificate ::= SEQUENCE {
//     certID        IssuerAndSerialNumber,
//     requestTime   BinaryTime,
//     locationInfo  UniformResourceIdentifiers,
//     signature     BIT STRING }
//
//   UniformResourceIdentifiers ::= SEQUENCE SIZE (1..MAX) OF URI
//   URI ::= IA5String
//
// locationInfo is a SEQUENCE OF, not one URI: a summary of this RFC reads the type name as singular,
// and the ASN.1 module in its appendix does not, so the list form is vectored.
//
// What the signature covers is narrow, and sec. 3.1 says so exactly: "the signature field contains a
// digital signature over the concatenation of DER-encoded IssuerAndSerialNumber and BinaryTime. The
// concatenated value is signed using the signature algorithm and private key associated with the
// certificate identified by the certID field." So locationInfo is NOT covered, and a vector asserts
// that rather than assuming the whole structure is signed.
//
// The issuer answers in a certificate extension (sec. 4.1):
//
//   RelatedCertificate ::= SEQUENCE {
//     hashAlgorithm DigestAlgorithmIdentifier,
//     hashValue     OCTET STRING }
//
// over "the entire related certificate", and it "SHOULD NOT be marked critical. Marking this
// extension critical would severely impact interoperability."
//
// Neither structure carries the digest as an argument the caller must supply, and sec. 4.1 says where
// it comes from: "If there is a hash algorithm explicitly indicated by the related certificate's
// signature OID (e.g., ecdsa-with-SHA512), that hash algorithm SHOULD also be used for this
// extension." That is the only derivation the document sanctions, so it is the default on both sides
// and the vectors pin it.
//
// BinaryTime is RFC 6019's INTEGER (0..MAX), "the number of seconds, excluding leap seconds, after
// midnight UTC, January 1, 1970".

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }
async function codeAsync(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }

var RELATED_OID = "1.3.6.1.5.5.7.1.36";
var REQUEST_OID = "1.2.840.113549.1.9.16.2.60";
var CERT_TIME = 1800000000;   // seconds since the epoch

// A certificate whose signatureAlgorithm is whatever is named, over whatever key is given. Hand-built,
// because pki.x509.sign derives the signature algorithm from the signing key and so cannot produce the
// pairings these vectors need: a certificate whose signature OID indicates no hash at all, and one
// whose OID indicates each of the hashes sec. 4.1's derivation has to reach.
function certSignedWith(sigAlgName, spki, serial) {
  var alg = b.sequence([b.oid(O(sigAlgName))]);
  var name = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("Signed " + sigAlgName)])])]);
  var validity = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
  var tbs = b.sequence([b.explicit(0, b.integer(2n)), b.integer(serial), alg, name, validity, name, b.raw(spki)]);
  return b.sequence([tbs, alg, b.bitString(Buffer.from([0, 0, 0, 0]), 0)]);
}

// The relatedCertificate extension of a parsed certificate, read the way an operator reads one: the
// parse surfaces the raw extnValue, and the shared extension decoder turns it into the record.
function relatedExt(parsed) {
  var e = parsed.extensions.filter(function (x) { return x.oid === RELATED_OID; })[0];
  if (e === undefined) return undefined;
  var d = pki.schema.x509.decodeExtension(e);
  return { critical: e.critical, state: d.state, code: d.code, relatedCertificate: d.decoded };
}

function testSurface() {
  ["requestSignedData", "verifyRequest", "certificateHash", "matchesCertificate"].forEach(function (n) {
    check("pki.relatedCert." + n + " is exposed", typeof pki.relatedCert[n] === "function");
  });
  check("O1: the extension OID is id-pe 36, both directions",
    O("relatedCertificate") === RELATED_OID && pki.oid.name(RELATED_OID) === "relatedCertificate");
  check("O2: the CSR attribute OID is id-aa 60, both directions",
    O("relatedCertRequest") === REQUEST_OID && pki.oid.name(REQUEST_OID) === "relatedCertRequest");
}

// ---- the signed preimage ---------------------------------------------------

function testPreimage() {
  var issuer = pki.x509.parseDn("CN=Related CA, O=Example");
  var certId = { issuer: issuer.bytes, serialNumber: 42n };

  // Built here from the two structures rather than by the library, so the vector is a known answer.
  var isn = b.sequence([b.raw(issuer.bytes), b.integer(42n)]);
  var bt = b.integer(BigInt(CERT_TIME));
  var want = Buffer.concat([isn, bt]);

  var got = pki.relatedCert.requestSignedData({ certID: certId, requestTime: CERT_TIME });
  check("P1: the preimage is the DER IssuerAndSerialNumber followed by the DER BinaryTime",
    Buffer.compare(got, want) === 0);
  check("P2: and nothing else, so locationInfo is outside the signature sec. 3.1 describes",
    got.length === isn.length + bt.length);

  check("P3: a Date is read as whole seconds since the epoch",
    Buffer.compare(pki.relatedCert.requestSignedData({ certID: certId, requestTime: new Date(CERT_TIME * 1000 + 999) }), want) === 0);
  check("P4: a negative time is refused, since BinaryTime is INTEGER (0..MAX)",
    code(function () { pki.relatedCert.requestSignedData({ certID: certId, requestTime: -1 }); }) === "relatedcert/bad-input");
  check("P5: a fractional time is refused rather than truncated in silence",
    code(function () { pki.relatedCert.requestSignedData({ certID: certId, requestTime: 1.5 }); }) === "relatedcert/bad-input");
  check("P6: a serial that is not a positive integer is refused",
    code(function () { pki.relatedCert.requestSignedData({ certID: { issuer: issuer.bytes, serialNumber: 0n }, requestTime: CERT_TIME }); }) === "relatedcert/bad-input");
  check("P7: a name that is not a Name SEQUENCE is refused",
    code(function () { pki.relatedCert.requestSignedData({ certID: { issuer: Buffer.from([5, 0]), serialNumber: 1n }, requestTime: CERT_TIME }); }) === "relatedcert/bad-input");
  check("P8: an unknown option is refused rather than dropped",
    code(function () { pki.relatedCert.requestSignedData({ certID: certId, requestTime: CERT_TIME, locationInfo: ["https://x/"] }); }) === "relatedcert/bad-input");
  check("P9: an unknown field beside the two certID reads is refused",
    code(function () { pki.relatedCert.requestSignedData({ certID: { issuer: issuer.bytes, serialNumber: 42n, serial: 43n }, requestTime: CERT_TIME }); }) === "relatedcert/bad-input");
}

// ---- the CSR attribute, and the proof inside it ----------------------------

async function testCsrAttribute() {
  var held = signing.makeSigner("ec-p256", { cn: "Held Cert", serial: 42 });
  var heldParsed = pki.schema.x509.parse(held.cert);
  var subject = signing.makeSigner("ec-p256", { cn: "New Key", serial: 43 });

  var certID = { issuer: heldParsed.issuer.bytes, serialNumber: heldParsed.serialNumber };
  var locationInfo = ["https://certs.example/held.cer"];
  var preimage = pki.relatedCert.requestSignedData({ certID: certID, requestTime: CERT_TIME });
  var proof = crypto.sign("sha256", preimage, { key: held.keyObject, dsaEncoding: "der" });

  var csrDer = await pki.csr.sign({
    subject: "New Key", subjectPublicKey: subject.spki,
    relatedCertRequest: { certID: certID, requestTime: CERT_TIME, locationInfo: locationInfo, signature: proof },
  }, { key: subject.key });
  check("C1: a CSR carrying the relatedCertRequest attribute is produced", Buffer.isBuffer(csrDer));

  var attrs = pki.schema.csr.parse(csrDer).attributes.filter(function (a) { return a.type === REQUEST_OID; });
  check("C2: exactly one relatedCertRequest attribute round-trips", attrs.length === 1);
  var rc = attrs[0].relatedCertRequest;
  check("C3: the attribute value is recognized and decoded, not left opaque", rc != null);
  check("C4: certID round-trips as an issuer and a serial",
    rc.certID.serialNumber === heldParsed.serialNumber &&
    Buffer.compare(rc.certID.issuer.bytes, heldParsed.issuer.bytes) === 0);
  check("C5: requestTime round-trips as whole seconds", rc.requestTime === BigInt(CERT_TIME));
  check("C6: locationInfo round-trips as a LIST of URIs, which is the module's type, not one URI",
    Array.isArray(rc.locationInfo) && rc.locationInfo.length === 1 && rc.locationInfo[0] === locationInfo[0]);
  check("C7: the signature round-trips byte-identically",
    Buffer.compare(rc.signature.bytes, proof) === 0 && rc.signature.unusedBits === 0);

  // The proof is the evidence the requester holds the other certificate.
  check("C8: the proof verifies under the key of the certificate certID names",
    (await pki.relatedCert.verifyRequest(rc, held.cert)) === true);

  var other = signing.makeSigner("ec-p256", { cn: "Other", serial: 44 });
  var forged = crypto.sign("sha256", preimage, { key: other.keyObject, dsaEncoding: "der" });
  check("C9: a proof made by another key does not verify",
    (await pki.relatedCert.verifyRequest({ certID: rc.certID, requestTime: rc.requestTime,
      locationInfo: rc.locationInfo, signature: { unusedBits: 0, bytes: forged } }, held.cert)) === false);

  check("C10: a certificate whose issuer and serial are not the ones certID names is refused",
    (await codeAsync(pki.relatedCert.verifyRequest(rc, other.cert))) === "relatedcert/cert-mismatch");

  // The identifier is ENCODED ONCE and those bytes are both hashed into the preimage and compared with
  // the certificate. Two encodings would read the caller's record twice, so an accessor could answer the
  // preimage with one identifier and the binding check with another, and a proof made for one certificate
  // would verify against a different one that shares its key. Measured as a read count, at the record and
  // at the fields inside it, because the encoding walks into both.
  var reads = { certID: 0, issuer: 0, serialNumber: 0 };
  var inner = rc.certID;
  var countedId = {};
  ["issuer", "serialNumber"].forEach(function (f) {
    var v = inner[f];
    Object.defineProperty(countedId, f, { enumerable: true, get: function () { reads[f] += 1; return v; } });
  });
  var countedReq = { requestTime: rc.requestTime, locationInfo: rc.locationInfo, signature: rc.signature };
  Object.defineProperty(countedReq, "certID", { enumerable: true, get: function () { reads.certID += 1; return countedId; } });
  var countedOk = await pki.relatedCert.verifyRequest(countedReq, held.cert);
  check("C10a: certID and each field inside it are read from the caller exactly once (certID " +
    reads.certID + ", issuer " + reads.issuer + ", serialNumber " + reads.serialNumber + ")",
    countedOk === true && reads.certID === 1 && reads.issuer === 1 && reads.serialNumber === 1);

  check("C11: altering requestTime breaks the proof, since the time is inside the preimage",
    (await pki.relatedCert.verifyRequest({ certID: rc.certID, requestTime: rc.requestTime + 1n,
      locationInfo: rc.locationInfo, signature: rc.signature }, held.cert)) === false);

  // Altering locationInfo does NOT break it, because sec. 3.1 leaves it out of the signature.
  // Pinning this is how the scope of the proof stays a fact rather than an assumption: a caller must
  // not read a verified proof as vouching for where the certificate can be fetched.
  check("C12: altering locationInfo does not break the proof, which is the signature's stated scope",
    (await pki.relatedCert.verifyRequest({ certID: rc.certID, requestTime: rc.requestTime,
      locationInfo: ["https://attacker.example/other.cer"], signature: rc.signature }, held.cert)) === true);

  var ok = { certID: certID, requestTime: CERT_TIME, locationInfo: locationInfo, signature: proof };
  async function badSpec(spec) {
    return (await codeAsync(pki.csr.sign({ subject: "New Key", subjectPublicKey: subject.spki,
      relatedCertRequest: spec }, { key: subject.key }))) === "csr/bad-input";
  }
  function less(k) { var c = Object.assign({}, ok); delete c[k]; return c; }
  function withKey(k, v) { var c = Object.assign({}, ok); c[k] = v; return c; }

  check("C13: an empty locationInfo is refused, since the type is SIZE (1..MAX)", await badSpec(withKey("locationInfo", [])));
  check("C14: a locationInfo that is not an array is refused", await badSpec(withKey("locationInfo", locationInfo[0])));
  check("C15: a locationInfo member that is not a string is refused", await badSpec(withKey("locationInfo", [7])));
  check("C16: a non-ASCII URI is refused, since URI is IA5String", await badSpec(withKey("locationInfo", ["https://é.example/"])));
  check("C17: a missing signature is refused", await badSpec(less("signature")));
  check("C18: a missing certID is refused", await badSpec(less("certID")));
  check("C19: a missing requestTime is refused", await badSpec(less("requestTime")));
  check("C20: an unknown field in the attribute spec is refused", await badSpec(Object.assign({ nonce: 1 }, ok)));

  return { held: held, heldParsed: heldParsed, subject: subject, rc: rc, certID: certID, preimage: preimage };
}

// ---- the parser's own refusals, on bytes no builder of ours emits ----------

async function testAttributeParsing(ctx) {
  var subject = ctx.subject;
  // A hand-built CertificationRequest, because pki.csr.sign routes this attribute through its
  // validating builder and refuses a pre-encoded one, which is what stops a producer emitting a
  // malformed attribute. Parsing is structural, so the outer signature is a placeholder: what these
  // vectors drive is the attribute-value reader, and each value is one no builder of ours emits.
  function csrWithAttributeValue(valueSet) {
    var name = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("New Key")])])]);
    var attr = b.sequence([b.oid(O("relatedCertRequest")), valueSet]);
    var cri = b.sequence([b.integer(0n), name, b.raw(subject.spki),
      b.contextConstructed(0, attr)]);
    return b.sequence([cri, b.sequence([b.oid(O("ecdsaWithSHA256"))]), b.bitString(Buffer.alloc(64, 1), 0)]);
  }
  async function parseAttr(valueDer) {
    return pki.schema.csr.parse(csrWithAttributeValue(b.set([valueDer])));
  }
  function isn() { return b.sequence([b.raw(ctx.heldParsed.issuer.bytes), b.integer(ctx.heldParsed.serialNumber)]); }
  function uris(list) { return b.sequence(list.map(function (u) { return b.ia5(u); })); }
  var sig = b.bitString(Buffer.alloc(64, 7), 0);
  var T = BigInt(CERT_TIME);

  check("A1: a well-formed hand-built value parses",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(T), uris(["https://a.example/"]), sig])))) === "NO-THROW");
  check("A2: an empty UniformResourceIdentifiers is refused (SIZE (1..MAX))",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(T), uris([]), sig])))) === "csr/bad-attribute-value");
  check("A3: a negative BinaryTime is refused (INTEGER (0..MAX))",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(-1n), uris(["https://a.example/"]), sig])))) === "csr/bad-attribute-value");
  check("A4: a signature field type confusion is refused",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(T), uris(["https://a.example/"]), b.octetString(Buffer.alloc(8))])))) === "csr/bad-attribute-value");
  check("A5: a missing field is refused rather than read as absent",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(T), uris(["https://a.example/"])])))) === "csr/bad-attribute-value");
  check("A6: a fifth field is refused rather than ignored",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(T), uris(["https://a.example/"]), sig, b.nullValue()])))) === "csr/bad-attribute-value");
  check("A7: a URI that is not an IA5String is refused",
    (await codeAsync(parseAttr(b.sequence([isn(), b.integer(T), b.sequence([b.utf8("https://a.example/")]), sig])))) === "csr/bad-attribute-value");
  check("A8: a certID that is not an IssuerAndSerialNumber is refused",
    (await codeAsync(parseAttr(b.sequence([b.sequence([b.raw(ctx.heldParsed.issuer.bytes)]), b.integer(T), uris(["https://a.example/"]), sig])))) === "csr/bad-attribute-value");
  var good = b.sequence([isn(), b.integer(T), uris(["https://a.example/"]), sig]);
  var good2 = b.sequence([isn(), b.integer(T + 1n), uris(["https://b.example/"]), sig]);
  check("A9: a two-value attribute is refused, the attribute being single-valued",
    code(function () { pki.schema.csr.parse(csrWithAttributeValue(b.set([good, good2]))); }) === "csr/bad-attribute-value");
  check("A10: and a zero-value attribute is refused",
    code(function () { pki.schema.csr.parse(csrWithAttributeValue(b.set([]))); }) !== "NO-THROW");

  // The builder refuses the pre-encoded door for this attribute, so a producer cannot route around
  // the validation the dedicated spec field applies. The same rule already covers extensionRequest
  // and challengePassword, and a third recognized attribute joining them is the whole set.
  // UniformResourceIdentifiers is a SEQUENCE OF, so two URIs in descending order are conformant and
  // keep their order. Reading them as a SET OF would refuse this, DER requiring a SET's members
  // ascending, and would also reorder them on the way out.
  var descending = ["https://zzz.example/b.cer", "https://aaa.example/a.cer"];
  var twoUris = await parseAttr(b.sequence([isn(), b.integer(T), uris(descending), sig]));
  var got = twoUris.attributes.filter(function (a) { return a.type === REQUEST_OID; })[0].relatedCertRequest.locationInfo;
  check("A12: two URIs in descending order are accepted, the type being a SEQUENCE OF",
    got.length === 2 && got[0] === descending[0] && got[1] === descending[1]);

  check("A13: a pre-encoded relatedCertRequest attribute is refused by the builder",
    (await codeAsync(pki.csr.sign({ subject: "New Key", subjectPublicKey: subject.spki,
      attributes: [b.sequence([b.oid(O("relatedCertRequest")), b.set([good])])] }, { key: subject.key }))) === "csr/bad-input");
}

// ---- the certificate extension --------------------------------------------

async function testExtension(ctx) {
  var held = ctx.held, subject = ctx.subject;
  var want256 = crypto.createHash("sha256").update(held.cert).digest();

  // sec. 4.1: the digest is over the entire related certificate, and the algorithm defaults to the
  // one the related certificate's own signature OID indicates. That certificate is signed
  // ecdsa-with-SHA256, so the derivation reaches sha256 with nothing named by the caller.
  var derived = pki.relatedCert.certificateHash(held.cert);
  check("E1: the hash is over the entire related certificate", Buffer.compare(derived.hashValue, want256) === 0);
  check("E2: and the algorithm is derived from the related certificate's signature OID", derived.hashAlgorithm === "sha256");

  var want512 = crypto.createHash("sha512").update(held.cert).digest();
  var named = pki.relatedCert.certificateHash(held.cert, "sha512");
  check("E3: a named algorithm is used instead of the derived one",
    named.hashAlgorithm === "sha512" && Buffer.compare(named.hashValue, want512) === 0);

  // A certificate whose signature OID indicates no hash leaves the derivation with no answer, so it
  // is refused rather than defaulted to a hash the document does not name.
  var noHash = certSignedWith("Ed25519", held.spki, 0x99n);
  check("E4: a certificate whose signature OID indicates no hash is refused rather than defaulted",
    code(function () { pki.relatedCert.certificateHash(noHash); }) === "relatedcert/no-digest");
  check("E5: and naming one resolves it", pki.relatedCert.certificateHash(noHash, "sha384").hashAlgorithm === "sha384");

  // The derivation is claimed for the relation, not for one algorithm, so every signature OID that
  // names a hash is measured. A single fixture signed ecdsaWithSHA256 cannot tell a working derivation
  // apart from a hardcoded sha256.
  [["ecdsaWithSHA384", "sha384"], ["ecdsaWithSHA512", "sha512"],
    ["sha384WithRSAEncryption", "sha384"], ["sha512WithRSAEncryption", "sha512"],
    ["sha256WithRSAEncryption", "sha256"]].forEach(function (row, i) {
    var c = certSignedWith(row[0], held.spki, BigInt(0xa0 + i));
    var got = pki.relatedCert.certificateHash(c);
    check("E4." + (i + 1) + ": a certificate signed " + row[0] + " derives " + row[1],
      got.hashAlgorithm === row[1] &&
      Buffer.compare(got.hashValue, crypto.createHash(row[1]).update(c).digest()) === 0);
  });

  check("E6: sha1 is refused as the digest binding a certificate identity",
    code(function () { pki.relatedCert.certificateHash(held.cert, "sha1"); }) === "relatedcert/bad-input");
  // And refused where sha1 is what the certificate's own signature OID indicates, which is the case
  // the derivation would otherwise walk straight into.
  ["sha1WithRSAEncryption", "ecdsaWithSHA1"].forEach(function (n, i) {
    check("E6." + (i + 1) + ": a certificate signed " + n + " is refused rather than hashed with sha1",
      code(function () { pki.relatedCert.certificateHash(certSignedWith(n, held.spki, BigInt(0xb0 + i))); }) === "relatedcert/bad-input");
  });
  check("E7: an algorithm this build cannot compute is refused",
    code(function () { pki.relatedCert.certificateHash(held.cert, "md5"); }) === "relatedcert/bad-input");
  check("E8: input that is not a certificate is refused",
    code(function () { pki.relatedCert.certificateHash(Buffer.from([5, 0])); }) === "relatedcert/bad-input");

  async function issue(extValue, serial) {
    return await pki.x509.sign({
      subject: "New Key", subjectPublicKey: subject.spki, serialNumber: serial,
      notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
      extensions: { relatedCertificate: extValue },
    }, { key: subject.key });
  }
  function extOf(der) { return relatedExt(pki.schema.x509.parse(der)); }

  var ext = extOf(await issue({ hashAlgorithm: "sha256", hashValue: want256 }, 7n));
  check("E9: the extension is emitted and parses back", ext !== undefined);
  check("E10: it is NOT critical, which sec. 4.1 says marking would severely impact interoperability",
    ext.critical === false);
  check("E11: its value round-trips as the algorithm and the hash",
    ext.relatedCertificate.hashAlgorithm === "sha256" &&
    Buffer.compare(ext.relatedCertificate.hashValue, want256) === 0);

  // Built from the related certificate itself, so a caller does not compute a digest and then name a
  // different algorithm than the one it used.
  var fromCert = extOf(await issue({ relatedCertificate: held.cert }, 8n));
  check("E12: built from the related certificate directly, the value is the derived one",
    fromCert.relatedCertificate.hashAlgorithm === "sha256" &&
    Buffer.compare(fromCert.relatedCertificate.hashValue, want256) === 0);
  var fromCert512 = extOf(await issue({ relatedCertificate: held.cert, hashAlgorithm: "sha512" }, 9n));
  check("E13: and an algorithm may be named alongside the certificate",
    fromCert512.relatedCertificate.hashAlgorithm === "sha512" &&
    Buffer.compare(fromCert512.relatedCertificate.hashValue, want512) === 0);

  check("E14: supplying both a hashValue and a certificate to hash is refused, the two being able to disagree",
    (await codeAsync(issue({ hashAlgorithm: "sha256", hashValue: want256, relatedCertificate: held.cert }, 10n))) === "x509/bad-input");
  check("E15: neither a hashValue nor a certificate is refused",
    (await codeAsync(issue({ hashAlgorithm: "sha256" }, 11n))) === "x509/bad-input");
  check("E16: a hashValue whose length is not its algorithm's is refused",
    (await codeAsync(issue({ hashAlgorithm: "sha256", hashValue: Buffer.alloc(31) }, 12n))) === "x509/bad-input");
  check("E17: a hashValue without an algorithm is refused rather than assumed",
    (await codeAsync(issue({ hashValue: want256 }, 13n))) === "x509/bad-input");
  check("E18: an algorithm this build does not read is refused",
    (await codeAsync(issue({ hashAlgorithm: "md5", hashValue: Buffer.alloc(16) }, 14n))) === "x509/bad-input");
  check("E19: an unknown field in the extension spec is refused",
    (await codeAsync(issue({ hashAlgorithm: "sha256", hashValue: want256, uri: "https://x/" }, 15n))) === "x509/bad-input");
  check("E20: a value that is not an object is refused",
    (await codeAsync(issue(want256, 16n))) === "x509/bad-input");

  // The pairing: an issued certificate's extension read back against the certificate it names.
  check("E21: the extension matches the certificate it was built from",
    pki.relatedCert.matchesCertificate(fromCert.relatedCertificate, held.cert) === true);
  check("E22: and does not match a different certificate",
    pki.relatedCert.matchesCertificate(fromCert.relatedCertificate, subject.cert) === false);
  check("E23: a sha512 value matches under its own algorithm, not the derived one",
    pki.relatedCert.matchesCertificate(fromCert512.relatedCertificate, held.cert) === true);
  check("E24: a value whose algorithm this build cannot compute is refused, not reported false",
    code(function () { pki.relatedCert.matchesCertificate({ hashAlgorithm: "md5", hashValue: Buffer.alloc(16) }, held.cert); }) === "relatedcert/bad-input");
  check("E25: a value whose hash length disagrees with its algorithm is refused, not reported false",
    code(function () { pki.relatedCert.matchesCertificate({ hashAlgorithm: "sha256", hashValue: Buffer.alloc(31) }, held.cert); }) === "relatedcert/bad-input");
}

// ---- extension-value parsing, on bytes no builder of ours emits ------------

async function testExtensionParsing(ctx) {
  var subject = ctx.subject;
  async function parseExt(valueDer, serial) {
    var der = await pki.x509.sign({
      subject: "New Key", subjectPublicKey: subject.spki, serialNumber: serial,
      notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
      extensions: [b.sequence([b.oid(O("relatedCertificate")), b.octetString(valueDer)])],
    }, { key: subject.key });
    return pki.schema.x509.parse(der);
  }
  var alg256 = b.sequence([b.oid(O("sha256"))]);
  check("X1: a well-formed hand-built value parses",
    (await codeAsync(parseExt(b.sequence([alg256, b.octetString(Buffer.alloc(32))]), 0x30n))) === "NO-THROW");
  check("X2: a value that is not a two-field SEQUENCE is refused",
    (await codeAsync(parseExt(b.sequence([alg256]), 0x31n))) === "x509/bad-extension-value");
  check("X3: a third field is refused rather than ignored",
    (await codeAsync(parseExt(b.sequence([alg256, b.octetString(Buffer.alloc(32)), b.nullValue()]), 0x32n))) === "x509/bad-extension-value");
  check("X4: a hashValue that is not an OCTET STRING is refused",
    (await codeAsync(parseExt(b.sequence([alg256, b.integer(5n)]), 0x33n))) === "x509/bad-extension-value");
  check("X5: a hashAlgorithm that is not an AlgorithmIdentifier is refused",
    (await codeAsync(parseExt(b.sequence([b.oid(O("sha256")), b.octetString(Buffer.alloc(32))]), 0x34n))) === "x509/bad-extension-value");
  check("X6: a hashValue whose length is not the named algorithm's is refused",
    (await codeAsync(parseExt(b.sequence([alg256, b.octetString(Buffer.alloc(31))]), 0x35n))) === "x509/bad-extension-value");
  check("X7: an empty hashValue is refused",
    (await codeAsync(parseExt(b.sequence([alg256, b.octetString(Buffer.alloc(0))]), 0x36n))) === "x509/bad-extension-value");
  // sec. 4.1 states the criticality at SHOULD NOT, so a critical one is ACCEPTED here and graded by
  // the linter. Refusing it would report a SHOULD NOT as a MUST NOT, which is the promotion this
  // codebase keeps out of the parsers: the same reason issuerAltName is absent from the CRL
  // criticality table it would otherwise belong in.
  var criticalDer = await pki.x509.sign({
    subject: "New Key", subjectPublicKey: subject.spki, serialNumber: 0x37n,
    notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
    extensions: [b.sequence([b.oid(O("relatedCertificate")), b.boolean(true),
      b.octetString(b.sequence([alg256, b.octetString(Buffer.alloc(32))]))])],
  }, { key: subject.key });
  var criticalExt = relatedExt(pki.schema.x509.parse(criticalDer));
  check("X8: a critical relatedCertificate extension parses, sec. 4.1 stating the rule at SHOULD NOT",
    criticalExt.critical === true && criticalExt.relatedCertificate.hashAlgorithm === "sha256");

  var findings = pki.lint.certificate(criticalDer, { profile: "rfc9763" }).findings;
  var row = findings.filter(function (f) { return f.id === "lint/rfc9763/related-certificate-critical"; });
  check("X9: and the linter grades it, at warn rather than error",
    row.length === 1 && row[0].severity === "warn");
  var cleanFindings = pki.lint.certificate(await pki.x509.sign({
    subject: "New Key", subjectPublicKey: subject.spki, serialNumber: 0x38n,
    notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
    extensions: { relatedCertificate: { relatedCertificate: ctx.held.cert } },
  }, { key: subject.key }), { profile: "rfc9763" }).findings;
  check("X10: a non-critical one draws no finding, so the rule is not firing on presence",
    cleanFindings.filter(function (f) { return f.id === "lint/rfc9763/related-certificate-critical"; }).length === 0);
}

// ---- the placement MUST, and the algorithm derivation on the verifying side ----

async function testPlacementAndAlgorithms(ctx) {
  var held = ctx.held, subject = ctx.subject;

  // sec. 4.1: "For certificate chains, this extension MUST only be included in the end-entity
  // certificate." A cA=TRUE certificate carrying it breaks that, and this one is graded as an error
  // where the criticality clause is graded as a warning, which is the two clauses' own strengths.
  var caDer = await pki.x509.sign({
    subject: "Related CA", subjectPublicKey: subject.spki, serialNumber: 0x50n,
    notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      relatedCertificate: { relatedCertificate: held.cert } },
  }, { key: subject.key });
  var caRows = pki.lint.certificate(caDer, { profile: "rfc9763" }).findings
    .filter(function (f) { return f.id === "lint/rfc9763/related-certificate-on-ca"; });
  check("L1: the extension on a cA=TRUE certificate is graded, at error",
    caRows.length === 1 && caRows[0].severity === "error");
  var eeRows = pki.lint.certificate(await pki.x509.sign({
    subject: "New Key", subjectPublicKey: subject.spki, serialNumber: 0x51n,
    notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
    extensions: { relatedCertificate: { relatedCertificate: held.cert } },
  }, { key: subject.key }), { profile: "rfc9763" }).findings;
  check("L2: an end-entity certificate carrying it draws neither row",
    eeRows.filter(function (f) { return f.id.indexOf("lint/rfc9763/") === 0; }).length === 0);
  var absentRows = pki.lint.certificate(held.cert, { profile: "rfc9763" }).findings
    .filter(function (f) { return f.id.indexOf("lint/rfc9763/") === 0; });
  check("L3: a certificate without the extension draws neither row, so neither fires on absence",
    absentRows.length === 0);

  // Both fields the renderer reads are measured, a digest being meaningful only beside the algorithm
  // that produced it.
  var eeDer = await pki.x509.sign({
    subject: "New Key", subjectPublicKey: subject.spki, serialNumber: 0x52n,
    notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
    extensions: { relatedCertificate: { relatedCertificate: held.cert, hashAlgorithm: "sha384" } },
  }, { key: subject.key });
  var shown = pki.inspect.certificate(eeDer);
  var want384 = crypto.createHash("sha384").update(held.cert).digest("hex").toUpperCase()
    .replace(/(..)(?=.)/g, "$1:");
  check("L4: pki.inspect names the digest algorithm the extension carries",
    shown.indexOf("Hash Algorithm: sha384") !== -1);
  check("L5: and prints the whole digest, so a rendered value is comparable to a computed one",
    shown.indexOf("Related Certificate: " + want384) !== -1);

  // The digest the proof was made with, named rather than derived. sha384 is not what the related
  // certificate's signature OID indicates, so a proof made under it verifies only if the option is
  // actually read.
  var certID = { issuer: ctx.heldParsed.issuer.bytes, serialNumber: ctx.heldParsed.serialNumber };
  var preimage = pki.relatedCert.requestSignedData({ certID: certID, requestTime: CERT_TIME });
  var rc384 = { certID: certID, requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
    signature: { unusedBits: 0, bytes: crypto.sign("sha384", preimage, { key: held.keyObject, dsaEncoding: "der" }) } };
  check("V1: a proof made under a named digest verifies when that digest is named",
    (await pki.relatedCert.verifyRequest(rc384, held.cert, { digestAlgorithm: "sha384" })) === true);
  check("V2: and does not verify under the derived one, so the option is read rather than ignored",
    (await pki.relatedCert.verifyRequest(rc384, held.cert)) === false);
  check("V3: a digest outside the accepted set is refused",
    (await codeAsync(pki.relatedCert.verifyRequest(rc384, held.cert, { digestAlgorithm: "sha1" }))) === "relatedcert/bad-input");
  check("V4: an unknown option is refused rather than dropped",
    (await codeAsync(pki.relatedCert.verifyRequest(rc384, held.cert, { digest: "sha384" }))) === "relatedcert/bad-input");

  // The keys whose algorithm admits no digest choice. The claim is about a class, so every member the
  // key table names is driven: the proof is a plain signature over the same bytes, it verifies with no
  // digest named, naming one is refused rather than ignored, and a tampered proof fails.
  var fixedKinds = ["ed25519", "ed448", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"];
  for (var fi = 0; fi < fixedKinds.length; fi++) {
    var kind = fixedKinds[fi];
    var fk = signing.makeSigner(kind, { cn: kind + " Held", serial: 0x60 + fi });
    var fkParsed = pki.schema.x509.parse(fk.cert);
    var fkId = { issuer: fkParsed.issuer.bytes, serialNumber: fkParsed.serialNumber };
    var fkPre = pki.relatedCert.requestSignedData({ certID: fkId, requestTime: CERT_TIME });
    var fkRc = { certID: fkId, requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
      signature: { unusedBits: 0, bytes: crypto.sign(null, fkPre, fk.keyObject) } };
    check("V5." + (fi + 1) + ": a " + kind + " proof verifies with no digest named",
      (await pki.relatedCert.verifyRequest(fkRc, fk.cert)) === true);
    check("V6." + (fi + 1) + ": naming a digest for " + kind + " is refused, not ignored",
      (await codeAsync(pki.relatedCert.verifyRequest(fkRc, fk.cert, { digestAlgorithm: "sha256" }))) === "relatedcert/bad-input");
    check("V7." + (fi + 1) + ": a tampered " + kind + " proof does not verify",
      (await pki.relatedCert.verifyRequest({ certID: fkId, requestTime: fkRc.requestTime + 1n,
        locationInfo: fkRc.locationInfo, signature: fkRc.signature }, fk.cert)) === false);
  }

  // The other half of the key table: a key kind that DOES take a digest, at each digest it pairs with.
  // Only ECDSA was driven above, and the table's RSA rows are a separate claim.
  var rsa = signing.makeSigner("rsa", { cn: "RSA Held", serial: 0x70 });
  var rsaParsed = pki.schema.x509.parse(rsa.cert);
  var rsaId = { issuer: rsaParsed.issuer.bytes, serialNumber: rsaParsed.serialNumber };
  var rsaPre = pki.relatedCert.requestSignedData({ certID: rsaId, requestTime: CERT_TIME });
  for (var di = 0; di < 3; di++) {
    var dg = ["sha256", "sha384", "sha512"][di];
    var rsaRc = { certID: rsaId, requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
      signature: { unusedBits: 0, bytes: crypto.sign(dg, rsaPre, rsa.keyObject) } };
    check("V8." + (di + 1) + ": an RSA proof under " + dg + " verifies when that digest is named",
      (await pki.relatedCert.verifyRequest(rsaRc, rsa.cert, { digestAlgorithm: dg })) === true);
    check("V9." + (di + 1) + ": and an RSA proof under " + dg + " fails under a different digest",
      (await pki.relatedCert.verifyRequest(rsaRc, rsa.cert,
        { digestAlgorithm: dg === "sha256" ? "sha384" : "sha256" })) === false);
  }

  // signatureAlgorithm names the algorithm outright, for a key the derivation does not reach.
  check("V8: a named DER AlgorithmIdentifier is used instead of the derivation",
    (await pki.relatedCert.verifyRequest(rc384, held.cert,
      { signatureAlgorithm: b.sequence([b.oid(O("ecdsaWithSHA384"))]) })) === true);
  check("V9: a named algorithm that does not match the key does not verify",
    (await pki.relatedCert.verifyRequest(rc384, held.cert,
      { signatureAlgorithm: b.sequence([b.oid(O("sha384WithRSAEncryption"))]) })) === false);
  check("V10: a signatureAlgorithm that is not an AlgorithmIdentifier is refused",
    (await codeAsync(pki.relatedCert.verifyRequest(rc384, held.cert, { signatureAlgorithm: Buffer.from([5, 0]) }))) === "relatedcert/bad-input");
  check("V11: an empty proof signature is refused rather than verified against nothing",
    (await codeAsync(pki.relatedCert.verifyRequest({ certID: certID, requestTime: BigInt(CERT_TIME),
      locationInfo: ["https://a.example/"], signature: { unusedBits: 0, bytes: Buffer.alloc(0) } }, held.cert))) === "relatedcert/bad-input");
  // A parsed certID carries serialNumberHex beside the serial, so the field is accepted. Both
  // directions are asserted on the same route: an agreeing value passes and a disagreeing one is
  // refused, which is what says the field is checked rather than accepted and ignored.
  function withHex(hex) {
    return { certID: { issuer: certID.issuer, serialNumber: certID.serialNumber, serialNumberHex: hex },
      requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"], signature: rc384.signature };
  }
  var agreeing = ctx.heldParsed.serialNumber.toString(16);
  check("V12: a certID whose serialNumberHex agrees with its serialNumber is accepted",
    (await pki.relatedCert.verifyRequest(withHex(agreeing), held.cert, { digestAlgorithm: "sha384" })) === true);
  check("V13: and one that disagrees is refused rather than ignored",
    (await codeAsync(pki.relatedCert.verifyRequest(withHex("ff"), held.cert, { digestAlgorithm: "sha384" }))) === "relatedcert/bad-input");

  // The signature is read as every other ASN.1 signature field is, so an ECDSA proof is the DER
  // SEQUENCE { r, s }. A WebCrypto sign returns the fixed-width r || s, and a caller reaching for it
  // gets a false rather than a throw, so both forms are pinned: the DER one verifies and the
  // fixed-width one does not.
  var asDer = crypto.sign("sha256", preimage, { key: held.keyObject, dsaEncoding: "der" });
  var raw = crypto.sign("sha256", preimage, { key: held.keyObject, dsaEncoding: "ieee-p1363" });
  function proofRc(bytes) {
    return { certID: certID, requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
      signature: { unusedBits: 0, bytes: bytes } };
  }
  check("V17: a DER SEQUENCE { r, s } proof verifies",
    (await pki.relatedCert.verifyRequest(proofRc(asDer), held.cert)) === true);
  check("V18: the same signature as fixed-width r || s does not, that not being the field's encoding",
    (await pki.relatedCert.verifyRequest(proofRc(raw), held.cert)) === false);

  // An RSASSA-PSS key, whose parameters are part of its algorithm rather than derivable from a digest
  // name. Resolving the identifier through the same resolver the signing verbs use reaches it, so the
  // proof verifies with no signatureAlgorithm named, at each digest.
  var pss = signing.makeSigner("rsa-pss", { cn: "PSS Held", serial: 0x61 });
  var pssParsed = pki.schema.x509.parse(pss.cert);
  var pssId = { issuer: pssParsed.issuer.bytes, serialNumber: pssParsed.serialNumber };
  var pssPre = pki.relatedCert.requestSignedData({ certID: pssId, requestTime: CERT_TIME });
  check("V14: the certificate's key is an RSASSA-PSS one", pssParsed.subjectPublicKeyInfo.algorithm.name === "rsassaPss");
  for (var pi = 0; pi < 3; pi++) {
    var pd = ["sha256", "sha384", "sha512"][pi];
    var pssSig = crypto.sign(pd, pssPre, { key: pss.keyObject,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
    var pssRc = { certID: pssId, requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
      signature: { unusedBits: 0, bytes: pssSig } };
    check("V14." + (pi + 1) + ": an RSASSA-PSS proof under " + pd + " verifies, parameters and all",
      (await pki.relatedCert.verifyRequest(pssRc, pss.cert, { digestAlgorithm: pd })) === true);
    check("V15." + (pi + 1) + ": and the same proof fails under a different digest",
      (await pki.relatedCert.verifyRequest(pssRc, pss.cert,
        { digestAlgorithm: pd === "sha256" ? "sha512" : "sha256" })) === false);
  }

  // An RSASSA-PSS key whose SPKI RESTRICTS its hash. The verb decides whether naming a digest would
  // change the identifier by resolving the scheme at two digests and comparing, and one of those probes
  // asked for SHA-512 — which a key pinned to SHA-256 refuses outright. So the probe threw before the
  // digest the caller actually asked for was resolved, and a valid proof under the key's own pinned hash
  // was rejected as an unsupported algorithm. A restricted key does not admit a choice of digest, which
  // is the answer the probe was trying to compute.
  var pinned = signing.makeSigner("rsa-pss", { cn: "PSS Pinned", serial: 0x62, pssHash: "sha256" });
  var pinnedParsed = pki.schema.x509.parse(pinned.cert);
  var pinnedId = { issuer: pinnedParsed.issuer.bytes, serialNumber: pinnedParsed.serialNumber };
  var pinnedPre = pki.relatedCert.requestSignedData({ certID: pinnedId, requestTime: CERT_TIME });
  var pinnedSig = crypto.sign("sha256", pinnedPre, { key: pinned.keyObject,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
  var pinnedRc = { certID: pinnedId, requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
    signature: { unusedBits: 0, bytes: pinnedSig } };
  var pinnedCode = "NO-THROW", pinnedOk = null;
  try { pinnedOk = await pki.relatedCert.verifyRequest(pinnedRc, pinned.cert, { digestAlgorithm: "sha256" }); }
  catch (e) { pinnedCode = e.code || e.message; }
  check("V19: a proof under a hash-restricted RSASSA-PSS key verifies at the digest the key pins" +
    (pinnedCode === "NO-THROW" ? "" : " (refused with " + pinnedCode + ")"), pinnedOk === true);
  check("V19a: and it verifies with no digest named at all, the key having only one",
    (await pki.relatedCert.verifyRequest(pinnedRc, pinned.cert)) === true);
  check("V19b: CONTROL the same key's SPKI does pin a hash, so this is the restricted case",
    pinnedParsed.subjectPublicKeyInfo.algorithm.name === "rsassaPss" &&
    pinnedParsed.subjectPublicKeyInfo.algorithm.parameters != null);

  // A key that cannot sign at all. An encryption-only key makes no proof, so the refusal names the way
  // out instead of an algorithm being guessed for it.
  var kems = ["x25519", "x448", "ml-kem-512", "ml-kem-768"];
  for (var ki = 0; ki < kems.length; ki++) {
    var recip = signing.makeRecipient(kems[ki]);
    var rp = pki.schema.x509.parse(recip.cert);
    check("V16." + (ki + 1) + ": a " + kems[ki] + " key, which cannot sign, is refused",
      (await codeAsync(pki.relatedCert.verifyRequest({
        certID: { issuer: rp.issuer.bytes, serialNumber: rp.serialNumber },
        requestTime: BigInt(CERT_TIME), locationInfo: ["https://a.example/"],
        signature: { unusedBits: 0, bytes: Buffer.alloc(64, 1) },
      }, recip.cert))) === "relatedcert/unsupported-algorithm");
  }
}

async function run() {
  testSurface();
  testPreimage();
  var ctx = await testCsrAttribute();
  await testAttributeParsing(ctx);
  await testExtension(ctx);
  await testExtensionParsing(ctx);
  await testPlacementAndAlgorithms(ctx);
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
