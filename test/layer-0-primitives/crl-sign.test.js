// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.crl.sign / .verify / .isRevoked -- the X.509 CRL producing side
// (RFC 5280 sec. 5). Every vector drives the shipped consumer and asserts through pki.schema.crl.parse
// round-trip, a raw asn1.decode of the emitted DER, pki.crl.verify's boolean verdict, or err.code. Keys
// come from the makeSigner helper (real runtime keypairs, every algorithm arm). schema-crl's strict
// decoder is the round-trip oracle -- it enforces the reasonCode ENUMERATED tag, the invalidityDate
// GeneralizedTime-only rule, the v2-iff-extensions rule, the non-empty revokedCertificates SEQUENCE OF,
// and the outer==inner signatureAlgorithm agreement, so a successful parse proves those on the wire.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var asn1 = pki.asn1;
var TAGS = asn1.TAGS;
function byName(n) { return pki.oid.byName(n); }

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

var TU = new Date("2026-01-01T00:00:00Z");
var NU = new Date("2026-02-01T00:00:00Z");
var RD = new Date("2026-01-15T00:00:00Z");

function issuerOf(s, name) { return { name: name || "Test CRL Issuer", publicKey: s.spki, key: s.key }; }
function crlExt(c, name) { return c.crlExtensions.filter(function (x) { return x.oid === byName(name); })[0]; }
function entryExt(entry, name) { return entry.crlEntryExtensions.filter(function (x) { return x.oid === byName(name); })[0]; }

// ---- round-trip + field decoding -------------------------------------------

async function testRoundTrip() {
  var s = makeSigner("ec-p256");
  var der = await pki.crl.sign({
    thisUpdate: TU, nextUpdate: NU, crlNumber: 7n,
    revoked: [{ serialNumber: 0x1234n, revocationDate: RD, reason: "keyCompromise" }],
    extensions: { authorityKeyIdentifier: Buffer.alloc(20, 0xab) },
  }, issuerOf(s));

  check("sign returns a Buffer", Buffer.isBuffer(der));
  var c = pki.schema.crl.parse(der);
  check("round-trip version = 2", c.version === 2);
  check("round-trip issuer CN", /Test CRL Issuer/.test(c.issuer.dn));
  check("round-trip thisUpdate Date", c.thisUpdate.getTime() === TU.getTime());
  check("round-trip nextUpdate Date", c.nextUpdate.getTime() === NU.getTime());
  check("one revoked entry", c.revokedCertificates.length === 1);
  check("round-trip serialNumberHex", c.revokedCertificates[0].serialNumberHex === "1234");
  check("round-trip revocationDate Date", c.revokedCertificates[0].revocationDate.getTime() === RD.getTime());
  check("reasonCode decoded to 1", (entryExt(c.revokedCertificates[0], "reasonCode") || {}).value === 1);
  check("cRLNumber decoded to 7n", (crlExt(c, "cRLNumber") || {}).value === 7n);

  // tbsBytes is the exact signed range -- re-parsing must recover identical bytes.
  check("tbsBytes byte-stable across re-parse", Buffer.compare(c.tbsBytes, pki.schema.crl.parse(der).tbsBytes) === 0);
}

// ---- sec. 5.1.2.6 -- an empty revocation list omits the field (not an empty SEQUENCE) ----

async function testEmptyListOmitsRevoked() {
  var s = makeSigner("ed25519");
  // schema-crl's REVOKED_LIST has min:1, so an emitted EMPTY SEQUENCE OF would throw crl/bad-revoked-certificates
  // here -- a clean parse proves the field was OMITTED entirely.
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [] }, issuerOf(s)));
  check("empty revoked list parses (field omitted, no empty SEQUENCE)", c.revokedCertificates.length === 0);
  check("no-extension CRL is v1", c.version === 1);
}

// ---- sec. 5.1.2.1 -- version derived from the extension set ----

async function testVersionDerivation() {
  var s = makeSigner("ec-p256");
  var v1 = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 5n, revocationDate: RD }] }, issuerOf(s)));
  check("no extensions -> v1 (version omitted)", v1.version === 1);
  var v2n = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(s)));
  check("a CRL extension -> v2", v2n.version === 2);
  var v2e = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 5n, revocationDate: RD, reason: "superseded" }] }, issuerOf(s)));
  check("an entry extension -> v2", v2e.version === 2);
}

// ---- sec. 5.3.2 -- invalidityDate is ALWAYS GeneralizedTime (not the UTCTime cutover) ----

async function testInvalidityDateGeneralizedTime() {
  var s = makeSigner("ec-p256");
  var when = new Date("2020-06-01T00:00:00Z");   // < year 2050: the timeDer cutover would wrongly pick UTCTime
  // schema-crl.decodeExt REQUIRES GeneralizedTime for invalidityDate, so a clean parse proves the builder
  // used b.generalizedTime directly (the trap is reusing timeDer here).
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 9n, revocationDate: RD, invalidityDate: when }] }, issuerOf(s)));
  var iv = entryExt(c.revokedCertificates[0], "invalidityDate");
  check("invalidityDate decoded (GeneralizedTime-only enforced)", iv && iv.value.getTime() === when.getTime());
}

// ---- sec. 5.3.1 -- reasonCode ENUMERATED + value rules ----

async function testReasonCodeRules() {
  var s = makeSigner("ec-p256");
  // read.enumerated in schema-crl rejects a bare INTEGER, so a clean parse proves the ENUMERATED tag (0x0A).
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: "cACompromise" }] }, issuerOf(s)));
  check("reason cACompromise -> ENUMERATED value 2", (entryExt(c.revokedCertificates[0], "reasonCode") || {}).value === 2);
  check("reason 7 (unused) -> crl/bad-reason-code",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: 7 }] }, issuerOf(s))) === "crl/bad-reason-code");
  check("removeFromCRL(8) in a complete CRL -> crl/bad-reason-code",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: "removeFromCRL" }] }, issuerOf(s))) === "crl/bad-reason-code");
  // unspecified(0) SHOULD be absent -> the builder OMITS it (no extension -> v1).
  var u = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: 0 }] }, issuerOf(s)));
  check("unspecified(0) reason omitted -> entry has no extensions", u.revokedCertificates[0].crlEntryExtensions.length === 0);
  check("an unspecified(0)-only CRL is v1", u.version === 1);
  // A CRLReason arrives as a registry name or its number; anything else is rejected rather than coerced.
  function withReason(r) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: r }] }, issuerOf(s)); }
  check("unknown CRLReason name -> crl/bad-reason-code", await codeOf(withReason("nope")) === "crl/bad-reason-code");
  check("non-name non-number reason -> crl/bad-reason-code", await codeOf(withReason({})) === "crl/bad-reason-code");
}

// ---- sec. 5.1.1.2 -- signature == signatureAlgorithm, single source ----

async function testSigAlgSingleSource() {
  var s = makeSigner("ec-p256");
  var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(s));
  var top = asn1.decode(der);
  var tbs = top.children[0], outerSig = top.children[1];
  var i = (tbs.children[0].tagClass === "universal" && tbs.children[0].tagNumber === TAGS.INTEGER) ? 1 : 0;   // skip the bare version INTEGER
  check("tbs.signature bytes == outer signatureAlgorithm bytes", Buffer.compare(tbs.children[i].bytes, outerSig.bytes) === 0);
  check("parse accepts it (no crl/bad-signature-algorithm)", pki.schema.crl.parse(der).version === 2);
}

// ---- sec. 5.2.3 -- cRLNumber INTEGER (0..MAX), <= 20 octets ----

async function testCrlNumberCap() {
  var s = makeSigner("ec-p256");
  var big21 = Buffer.alloc(21, 0xff); big21[0] = 0x7f;   // 21 content octets (top bit clear -> no sign pad)
  var big20 = Buffer.alloc(20, 0xff); big20[0] = 0x7f;   // 20 content octets
  check("21-octet cRLNumber -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: big21 }, issuerOf(s))) === "crl/bad-crl-number");
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: big20 }, issuerOf(s)));
  check("20-octet cRLNumber accepted + round-trips", (crlExt(c, "cRLNumber") || {}).value === BigInt("0x" + big20.toString("hex")));

  // Every accepted cRLNumber spelling normalizes to the same INTEGER, and every other type is rejected --
  // the same coercion deltaCRLIndicator's baseCRLNumber rides, so closing it here closes both callers.
  function crlNum(v) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: v }, issuerOf(s)); }
  async function crlNumValue(v) { return (crlExt(pki.schema.crl.parse(await crlNum(v)), "cRLNumber") || {}).value; }
  check("safe-integer number cRLNumber -> INTEGER 9", (await crlNumValue(9)) === 9n);
  check("non-safe-integer number cRLNumber -> crl/bad-crl-number", await codeOf(crlNum(Math.pow(2, 53))) === "crl/bad-crl-number");
  check("decimal string cRLNumber -> INTEGER 255", (await crlNumValue("255")) === 255n);
  check("0x-hex string cRLNumber -> INTEGER 255", (await crlNumValue("0xff")) === 255n);
  check("unparseable string cRLNumber -> crl/bad-crl-number", await codeOf(crlNum("zzz")) === "crl/bad-crl-number");
  check("empty-Buffer cRLNumber -> INTEGER 0", (await crlNumValue(Buffer.alloc(0))) === 0n);
  check("boolean cRLNumber -> crl/bad-crl-number", await codeOf(crlNum(true)) === "crl/bad-crl-number");
  check("negative cRLNumber -> crl/bad-crl-number (INTEGER 0..MAX)", await codeOf(crlNum(-1n)) === "crl/bad-crl-number");
}

// ---- sec. 5.2.1 -- authorityKeyIdentifier: keyIdentifier method only, non-critical ----

async function testAkiShape() {
  var s = makeSigner("ec-p256", { ski: true });
  var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: { authorityKeyIdentifier: true } }, { cert: s.cert, key: s.key });
  var aki = crlExt(pki.schema.crl.parse(der), "authorityKeyIdentifier");
  check("AKI present", !!aki);
  check("AKI non-critical", aki.critical === false);
  var v = asn1.decode(aki.value);
  check("AKI is SEQUENCE { [0] keyIdentifier } only", v.children.length === 1 && v.children[0].tagClass === "context" && v.children[0].tagNumber === 0);
  var ski = pki.schema.x509.parse(s.cert).extensions.filter(function (x) { return x.oid === byName("subjectKeyIdentifier"); })[0];
  check("AKI key id == the issuer cert SKI", Buffer.compare(v.children[0].content, asn1.read.octetString(asn1.decode(ski.value))) === 0);

  // sec. 5.2.1 -- the keyIdentifier source, arm by arm. All four CRLs below are signed under the SAME key,
  // so the emitted key id is the only thing that varies and it names which arm ran. The minimalCert helper
  // stores an SKI that is deliberately NOT the sec. 4.2.1.2 method-1 derivation, so "took the stored SKI"
  // and "re-derived from the SPKI" are observably different values rather than a coincidence.
  async function akiKeyId(issuer) {
    var d = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: { authorityKeyIdentifier: true } }, issuer);
    return asn1.decode(crlExt(pki.schema.crl.parse(d), "authorityKeyIdentifier").value).children[0].content;
  }
  var derived = await akiKeyId(issuerOf(s));                       // no issuer cert -> derive from the issuer SPKI
  var stored = await akiKeyId({ cert: s.cert, key: s.key });       // issuer cert with a readable SKI -> use it
  check("no issuer cert -> AKI key id derived from the issuer SPKI", Buffer.isBuffer(derived) && derived.length === 20);
  check("a readable issuer-cert SKI is used verbatim, not re-derived", Buffer.compare(stored, derived) !== 0);
  // An issuer cert whose SKI value is not a readable OCTET STRING: the decode faults and the key id is
  // re-derived from the issuer SPKI (a correct sec. 5.2.1 key id) rather than the CRL failing or the AKI
  // being dropped. Same key as above, so the fallback must land on exactly the derived value.
  var badSkiCert = signing.minimalCert(s.spki, { ski: true, badSki: true });
  check("unreadable issuer-cert SKI -> AKI re-derived from the SPKI",
    Buffer.compare(await akiKeyId({ cert: badSkiCert, key: s.key }), derived) === 0);
  // A certificate carrying NO extensions is still a usable issuer -- the parser emits an empty
  // array for one, so the SKI lookup misses and the key id is re-derived. Built as real bytes rather
  // than by emptying a parsed certificate's list: an issuer certificate is re-derived from the bytes
  // it was read from, so an edited object would be refused at the door and this would be testing the
  // door instead of the SKI fallback.
  var noExts = signing.minimalCert(s.spki);
  check("issuer cert with no extensions -> AKI re-derived from the SPKI",
    Buffer.compare(await akiKeyId({ cert: noExts, key: s.key }), derived) === 0);
  // Two different things happen to an issuer certificate a caller has interfered with, and both are
  // safe. DELETING a property from the parser's own object changes nothing: the certificate is
  // re-derived from the bytes it was read from, so the real extensions are what the AKI comes from.
  var mutated = pki.schema.x509.parse(s.cert);
  delete mutated.extensions;
  check("deleting a property from a parsed issuer cert does not change what is used",
    Buffer.compare(await akiKeyId({ cert: mutated, key: s.key }), stored) === 0);
  // REBUILDING it is refused outright -- a copy carries no record, so there are no bytes to derive
  // from and nothing to check the object against. "The list is absent" and "the list is empty" is
  // the distinction a scope guard reading `(list || [])` cannot make, and neither reading is taken.
  var rebuilt = Object.assign({}, pki.schema.x509.parse(s.cert));
  delete rebuilt.extensions;
  check("a REBUILT issuer cert is refused, whatever it is missing",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: rebuilt, key: s.key })) === "crl/bad-input");
  check("authorityKeyIdentifier that is neither true nor a Buffer -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { authorityKeyIdentifier: 5 } }, issuerOf(s))) === "crl/bad-input");
}

// ---- sec. 5.1.1.3 -- verify over the raw tbs, per algorithm, fail-closed ----

async function testVerifyPerAlgorithm() {
  var arms = ["rsa", "ec-p256", "ed25519", "ml-dsa-65"];
  for (var k = 0; k < arms.length; k++) {
    var alg = arms[k];
    var s = makeSigner(alg);
    var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, revoked: [{ serialNumber: 3n, revocationDate: RD, reason: "keyCompromise" }] }, issuerOf(s));
    check(alg + " verify true with the correct key", (await pki.crl.verify(der, { publicKey: s.spki })) === true);
    var bad = Buffer.from(der); bad[bad.length - 1] ^= 0xff;
    check(alg + " verify false on a tampered signature", (await pki.crl.verify(bad, { publicKey: s.spki })) === false);
    check(alg + " verify false with a wrong key", (await pki.crl.verify(der, { publicKey: makeSigner(alg).spki })) === false);
  }
  // RSA-PSS arm (opts.pss)
  var rp = makeSigner("rsa");
  var pssDer = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(rp), { pss: true });
  check("RSA-PSS CRL verifies", (await pki.crl.verify(pssDer, { publicKey: rp.spki })) === true);
}

// ---- RFC 9814 sec. 4 -- algorithm-confusion fails closed ----

async function testVerifyAlgorithmConfusion() {
  var ec = makeSigner("ec-p256"), ed = makeSigner("ed25519");
  var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(ec));
  check("ECDSA CRL against an Ed25519 SPKI -> verify false", (await pki.crl.verify(der, { publicKey: ed.spki })) === false);
}

// ---- verify accepts every documented crl / issuer shape, and rejects the rest ----

async function testVerifyInputShapes() {
  var s = makeSigner("ec-p256");
  var spec = { thisUpdate: TU, nextUpdate: NU, crlNumber: 1n };
  var der = await pki.crl.sign(spec, issuerOf(s));
  var pem = await pki.crl.sign(spec, issuerOf(s), { pem: true });
  // The crl argument: DER Buffer (covered above), PEM string, or an already-parsed CRL.
  check("verify accepts a PEM CRL string", (await pki.crl.verify(pem, { publicKey: s.spki })) === true);
  check("verify accepts a parsed CRL object", (await pki.crl.verify(pki.schema.crl.parse(der), { publicKey: s.spki })) === true);
  check("verify of a non-CRL value -> crl/bad-input", await codeOf(pki.crl.verify(5, { publicKey: s.spki })) === "crl/bad-input");
  // An object that merely looks like a parsed CRL but is missing a signed field is not accepted as one.
  var shallow = pki.schema.crl.parse(der);
  check("verify of a parsed CRL missing signatureValue -> crl/bad-input",
    await codeOf(pki.crl.verify({ tbsBytes: shallow.tbsBytes, signatureAlgorithm: shallow.signatureAlgorithm }, { publicKey: s.spki })) === "crl/bad-input");
  // The issuer argument: raw SPKI Buffer, { publicKey }, { cert } (DER or parsed), or a parsed certificate.
  check("verify accepts a raw SPKI Buffer issuer", (await pki.crl.verify(der, s.spki)) === true);
  check("verify with no issuer -> crl/bad-input", await codeOf(pki.crl.verify(der, null)) === "crl/bad-input");
  check("verify with an unrecognized issuer shape -> crl/bad-input", await codeOf(pki.crl.verify(der, {})) === "crl/bad-input");
  var ca = makeSigner("ec-p256");
  var caDer = await pki.x509.sign({
    subject: "CA verify shapes", subjectPublicKey: ca.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: ca.key });
  var caParsed = pki.schema.x509.parse(caDer);
  var crlByCa = await pki.crl.sign(spec, { cert: caParsed, key: ca.key });
  check("verify accepts a { cert } DER issuer", (await pki.crl.verify(crlByCa, { cert: caDer })) === true);
  check("verify accepts a { cert } parsed-certificate issuer", (await pki.crl.verify(crlByCa, { cert: caParsed })) === true);
  check("verify accepts a parsed certificate as the issuer", (await pki.crl.verify(crlByCa, caParsed)) === true);
  // Every accepted issuer shape still resolves to a real key -- the wrong CA's cert fails closed.
  check("a parsed-certificate issuer for the wrong CA -> verify false", (await pki.crl.verify(crlByCa, pki.schema.x509.parse(s.cert))) === false);

  // A CRL signature verifying says only that SOME key signed these bytes. Whether that key was
  // ALLOWED to sign a CRL, and whether it belongs to the issuer this CRL names, are separate
  // questions -- and only a certificate can answer them. The producing side of this same file
  // already refuses to SIGN without cRLSign; the verifying side asked neither, so a CRL minted
  // under an end-entity certificate of the same CA verified as that CA's CRL.
  var ee = makeSigner("ec-p256");
  var eeDer = await pki.x509.sign({
    subject: "CA verify shapes", subjectPublicKey: ee.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: false }, keyUsage: ["digitalSignature"] },
  }, { key: ee.key });
  // Signed with the end-entity KEY and claiming the CA's name -- which is how an attacker holding
  // such a certificate would mint it, and the one shape this file's producing-side cRLSign gate
  // cannot refuse, since no certificate is offered to it.
  var crlByEe = await pki.crl.sign(spec, { publicKey: ee.spki, name: "CA verify shapes", key: ee.key });
  check("a CRL signed by a certificate whose keyUsage omits cRLSign does not verify under it",
    (await pki.crl.verify(crlByEe, { cert: eeDer })) === false);
  // ...and the signature itself is still sound, so the refusal is about authority, not about maths:
  // handed only the KEY, with no certificate to carry the restriction, the same CRL verifies.
  check("the same CRL verifies under the bare key -- a key carries no authority to restrict",
    (await pki.crl.verify(crlByEe, ee.spki)) === true);
  // An absent keyUsage places no restriction (sec. 4.2.1.3), so it must not read as a refusal.
  var noKuDer = await pki.x509.sign({
    subject: "CA verify shapes", subjectPublicKey: ca.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true } },
  }, { key: ca.key });
  check("an issuer certificate with no keyUsage at all still verifies its CRL",
    (await pki.crl.verify(crlByCa, { cert: noKuDer })) === true);
  // The SAME keyUsage must read the same on every side. keyUsage is a NamedBitList, so DER drops
  // its trailing zero bits (X.690 sec. 11.2.2) and requires at least one bit set (sec. 4.2.1.3) --
  // rules the shared extension decoder enforces, and which the signing side and pki.path.validate
  // therefore apply. Reading the bits here with a plain BIT STRING read accepted encodings both of
  // those reject, so one malformed certificate was authorized to sign by the verifier and refused
  // by everything else.
  // The certificate has to come from OUTSIDE: pki.x509.sign refuses to emit either encoding, which
  // is the point -- the certificate you verify a CRL against is one you were handed, not one you
  // minted, so the verifier is where the rule has to hold.
  var b = pki.asn1.build;
  // The certificate is built as real BYTES carrying the raw keyUsage value, not by editing a parsed
  // one: an issuer certificate is re-derived from the bytes it was read from, so an edited object
  // would be refused at the door and these vectors would be testing the door rather than the
  // NamedBitList rule. Bytes are also the faithful case -- the certificate you verify a CRL against
  // is one you were handed.
  // The REAL CA certificate with only its keyUsage extension value replaced, so the key, the SPKI
  // and the issuer name are untouched and the only variable is the encoding under test.
  function caWithRawKu(kuValue) {
    var root = pki.asn1.decode(caDer);
    var tbs = root.children[0];
    var kids = tbs.children.slice();
    var wrapper = kids[kids.length - 1];
    if (!wrapper || wrapper.tagClass !== "context" || wrapper.tagNumber !== 3) {
      throw new Error("fixture: the CA certificate carries no extensions to replace");
    }
    var kuOid = pki.oid.byName("keyUsage");
    var exts = wrapper.children[0].children.map(function (e) {
      if (pki.asn1.read.oid(e.children[0]) !== kuOid) return e.bytes;
      var parts = [b.oid(kuOid)];
      if (e.children.length === 3) parts.push(e.children[1].bytes);   // the critical flag, as encoded
      parts.push(b.octetString(kuValue));
      return b.sequence(parts);
    });
    kids[kids.length - 1] = { bytes: b.contextConstructed(3, b.sequence(exts)) };
    var newTbs = b.sequence(kids.map(function (c) { return c.bytes; }));
    // The outer signature is stale: pki.crl.verify uses this certificate's KEY and keyUsage to judge
    // the CRL, and never validates the certificate itself (that is pki.path.validate's job).
    // Returned PARSED, because this argument is a certificate rather than bytes -- and a parsed one
    // carries the parser's record, so it is accepted at the door and re-derived from these bytes.
    return pki.schema.x509.parse(b.sequence([newTbs, root.children[1].bytes, root.children[2].bytes]));
  }
  // cRLSign is bit 6, so the minimal DER content is one unused bit over one octet. Padding it with a
  // redundant all-zero octet leaves cRLSign set while breaking the encoding rule.
  check("a non-minimal NamedBitList keyUsage is refused, not read for its cRLSign bit",
    await codeOf(pki.crl.verify(crlByCa, caWithRawKu(b.bitString(Buffer.from([0x02, 0x00]), 1)))) === "crl/bad-issuer");
  // An all-zero keyUsage asserts nothing, which sec. 4.2.1.3 forbids outright -- a defect in the
  // certificate, not a certificate that merely lacks cRLSign.
  check("a keyUsage asserting no bits at all is refused as malformed",
    await codeOf(pki.crl.verify(crlByCa, caWithRawKu(b.bitString(Buffer.from([0x00]), 7)))) === "crl/bad-issuer");
  // ...and the well-formed minimal encoding of the same permission still verifies, so the rule is
  // about the encoding rather than about the bit.
  check("the minimal encoding of the same cRLSign permission still verifies",
    (await pki.crl.verify(crlByCa, caWithRawKu(b.bitString(Buffer.from([0x02]), 1)))) === true);
}

// ---- the signing key must actually match the resolved scheme -- faults are typed, never a partial CRL ----

async function testSignerKeyFaults() {
  var ec = makeSigner("ec-p256"), ed = makeSigner("ed25519");
  var spec = { thisUpdate: TU, nextUpdate: NU, crlNumber: 1n };
  function withIssuer(i) { return pki.crl.sign(spec, i); }
  // The scheme resolves from the issuer SPKI, so a key that cannot sign under it fails closed rather than
  // emitting a CRL whose signature no relying party can check.
  check("issuer SPKI and signing key of different algorithms -> crl/bad-input",
    await codeOf(withIssuer({ name: "CN=X", publicKey: ec.spki, key: ed.key })) === "crl/bad-input");
  check("an unusable signing key -> crl/bad-input",
    await codeOf(withIssuer({ name: "CN=X", publicKey: ec.spki, key: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]) })) === "crl/bad-input");
  check("a signing key of an unsupported type -> crl/bad-input",
    await codeOf(withIssuer({ name: "CN=X", publicKey: ec.spki, key: 5 })) === "crl/bad-input");
  // A key whose algorithm cannot produce signatures at all is refused at scheme resolution, with the
  // registry's own verdict -- not silently downgraded to some default signature algorithm.
  var kem = require("node:crypto").generateKeyPairSync("ml-kem-768").publicKey.export({ format: "der", type: "spki" });
  check("a key-encapsulation SPKI as the issuer key -> crl/unsupported-algorithm",
    await codeOf(withIssuer({ name: "CN=X", publicKey: kem, key: ec.key })) === "crl/unsupported-algorithm");
  check("an unknown digestAlgorithm override -> crl/unsupported-algorithm",
    await codeOf(pki.crl.sign(spec, issuerOf(ec), { digestAlgorithm: "not-a-hash" })) === "crl/unsupported-algorithm");
  // An undecodable PEM signing key is reported as a key-decoding fault, not as a signing failure -- the
  // verdict names what the caller got wrong.
  check("an undecodable PEM signing key -> crl/bad-input",
    await codeOf(withIssuer({ name: "CN=X", publicKey: ec.spki, key: "-----BEGIN PRIVATE KEY-----\nnot base64 at all\n-----END PRIVATE KEY-----" })) === "crl/bad-input");
  // issuer.key may be a CryptoKey rather than PKCS#8 bytes; the CRL it produces must verify like any other.
  var ck = await pki.webcrypto.subtle.importKey("pkcs8", ec.key, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  var ckDer = await pki.crl.sign(spec, { name: "CN=X", publicKey: ec.spki, key: ck });
  check("a CryptoKey issuer.key signs a CRL that verifies", (await pki.crl.verify(ckDer, { publicKey: ec.spki })) === true);
  check("a CryptoKey of the wrong algorithm -> crl/bad-input",
    await codeOf(withIssuer({ name: "CN=X", publicKey: ec.spki, key: await pki.webcrypto.subtle.importKey("pkcs8", ed.key, { name: "Ed25519" }, false, ["sign"]) })) === "crl/bad-input");
}

// ---- sec. 5.2.5 -- IssuingDistributionPoint gates ----

async function testIdpGates() {
  var s = makeSigner("ec-p256");
  function idp(v) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: { issuingDistributionPoint: v } }, issuerOf(s)); }
  var e = crlExt(pki.schema.crl.parse(await idp({ onlyContainsUserCerts: true })), "issuingDistributionPoint");
  check("IDP present + critical", e && e.critical === true);
  var vv = asn1.decode(e.value);
  check("IDP emits only the [1] scope boolean (DEFAULT-FALSE omitted)", vv.children.length === 1 && vv.children[0].tagClass === "context" && vv.children[0].tagNumber === 1);
  check("empty IDP -> crl/bad-idp", await codeOf(idp({})) === "crl/bad-idp");
  check("two scope booleans TRUE -> crl/bad-idp", await codeOf(idp({ onlyContainsUserCerts: true, onlyContainsCACerts: true })) === "crl/bad-idp");
  check("onlyContainsAttributeCerts=TRUE -> crl/bad-idp", await codeOf(idp({ onlyContainsAttributeCerts: true })) === "crl/bad-idp");
  check("non-object IDP -> crl/bad-idp", await codeOf(idp("x")) === "crl/bad-idp");
  check("unknown IDP field -> crl/bad-idp", await codeOf(idp({ bogus: 1 })) === "crl/bad-idp");
  // distributionPoint [0] { fullName [0] IMPLICIT GeneralNames } -- accepted as a list or a single GeneralName.
  var fn = asn1.decode(crlExt(pki.schema.crl.parse(await idp({ fullName: [{ uniformResourceIdentifier: "http://x/crl" }] })), "issuingDistributionPoint").value);
  check("IDP fullName emits distributionPoint [0]", fn.children.length === 1 && fn.children[0].tagClass === "context" && fn.children[0].tagNumber === 0);
  check("IDP accepts a single-object fullName",
    !!crlExt(pki.schema.crl.parse(await idp({ fullName: { uniformResourceIdentifier: "http://x" } })), "issuingDistributionPoint"));
  check("IDP fullName [] -> crl/bad-idp (GeneralNames is SIZE(1..MAX))", await codeOf(idp({ fullName: [] })) === "crl/bad-idp");
}

// ---- sec. 5.2.6 / 5.2.7 -- freshestCRL + authorityInfoAccess on a complete (non-delta) CRL ----

async function testFreshestAndAia() {
  var s = makeSigner("ec-p256");
  function withExt(e) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: e }, issuerOf(s)); }
  // freshestCRL is a SEQUENCE OF DistributionPoint. A bare GeneralName list is one DP's fullName; an array
  // of { fullName } objects is one DP each. Both emit; neither is rejected as the other's shape.
  var f1 = crlExt(pki.schema.crl.parse(await withExt({ freshestCRL: [{ uniformResourceIdentifier: "http://x/f.crl" }] })), "freshestCRL");
  check("freshestCRL from a GeneralName list -> one distribution point", f1 && asn1.decode(f1.value).children.length === 1);
  check("freshestCRL is non-critical (sec. 5.2.6)", f1.critical === false);
  var f2 = crlExt(pki.schema.crl.parse(await withExt({ freshestCRL: [{ fullName: { uniformResourceIdentifier: "http://x" } }, { fullName: [{ uniformResourceIdentifier: "http://y" }] }] })), "freshestCRL");
  check("freshestCRL from { fullName } distribution points -> one DP each", f2 && asn1.decode(f2.value).children.length === 2);
  check("empty freshestCRL -> crl/bad-input", await codeOf(withExt({ freshestCRL: [] })) === "crl/bad-input");
  // authorityInfoAccess is a SEQUENCE OF AccessDescription, caIssuers-only (sec. 5.2.7).
  var a = crlExt(pki.schema.crl.parse(await withExt({ authorityInfoAccess: [{ uniformResourceIdentifier: "http://ca/ca.crt" }] })), "authorityInfoAccess");
  check("authorityInfoAccess present + non-critical (sec. 5.2.7)", a && a.critical === false);
  var ad = asn1.decode(a.value).children[0];
  check("authorityInfoAccess accessMethod is caIssuers", asn1.read.oid(ad.children[0]) === byName("caIssuers"));
  check("authorityInfoAccess accessLocation is the [6] URI GeneralName", ad.children[1].tagClass === "context" && ad.children[1].tagNumber === 6);
  check("empty authorityInfoAccess -> crl/bad-input", await codeOf(withExt({ authorityInfoAccess: [] })) === "crl/bad-input");
}

// ---- sec. 5.2.4 / 5.2.6 -- delta CRL indicator + freshestCRL conflict ----

async function testDeltaAndFreshest() {
  var s = makeSigner("ec-p256");
  var d = crlExt(pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s))), "deltaCRLIndicator");
  check("deltaCRLIndicator present + critical", d && d.critical === true);
  check("delta CRL + freshestCRL -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: { deltaCRLIndicator: 3n, freshestCRL: [{ uniformResourceIdentifier: "http://x/f.crl" }] } }, issuerOf(s))) === "crl/bad-input");
  var rc = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 6n, extensions: { deltaCRLIndicator: 3n }, revoked: [{ serialNumber: 2n, revocationDate: RD, reason: "removeFromCRL" }] }, issuerOf(s)));
  check("removeFromCRL(8) accepted in a delta CRL", (entryExt(rc.revokedCertificates[0], "reasonCode") || {}).value === 8);
}

// A CRL carrying a scope extension this library deliberately refuses to EMIT -- an IDP, or a
// certificateIssuer on an entry (pki.path.crlChecker cannot process an indirect CRL, so signing one
// would produce a CRL nothing here can use). A third-party CRL can still carry them, and that is the
// input the scope guards have to be safe against.
//
// The fixtures build BYTES rather than editing a parsed object. A parsed CRL is re-derived from the
// bytes it was read from before any verdict is taken, so an edit made afterwards is discarded --
// which is the point of that rule, and it means an edited object tests the door instead of the
// guard. Splicing the DER puts the extension where a third party's CRL would have it. The outer
// signature is left stale on purpose: these verbs answer scope and revocation, and neither verifies
// it (pki.crl.verify is the verb that does, and it has its own vectors).
function _spliceCrlExt(der, extDer, opts) {
  var b = pki.asn1.build;
  var root = pki.asn1.decode(der);
  var tbs = root.children[0];
  var kids = tbs.children.slice();
  var last = kids[kids.length - 1];
  var isExtWrapper = last && last.tagClass === "context" && last.tagNumber === 0;
  var existing = isExtWrapper ? last.children[0].children.map(function (c) { return c.bytes; }) : [];
  if (isExtWrapper) kids.pop();
  var extsSeq = b.sequence(existing.concat([extDer]));
  kids = kids.map(function (c) { return c.bytes; }).concat([b.contextConstructed(0, extsSeq)]);
  var newTbs = b.sequence(kids);
  return b.sequence([newTbs, root.children[1].bytes, root.children[2].bytes]);
  // opts is unused today; kept out of the signature deliberately -- a fixture with a knob nobody
  // sets is a fixture nobody can read.
}
// The same splice, one level in: an extension added to the FIRST revoked entry's
// crlEntryExtensions. revokedCertificates is located structurally rather than by index -- it is the
// universal SEQUENCE that follows the last Time in the tbsCertList, which distinguishes it from the
// issuer Name (also a SEQUENCE, but before the Times) whatever the optional fields do.
function _spliceEntryExt(der, extDer) {
  var b = pki.asn1.build;
  var TAGS = pki.asn1.TAGS;
  var root = pki.asn1.decode(der);
  var tbs = root.children[0];
  var kids = tbs.children.slice();
  var lastTime = -1;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].tagClass === "universal" && (kids[i].tagNumber === TAGS.UTC_TIME || kids[i].tagNumber === TAGS.GENERALIZED_TIME)) lastTime = i;
  }
  var ri = lastTime + 1;
  if (ri >= kids.length || kids[ri].tagClass !== "universal" || kids[ri].tagNumber !== TAGS.SEQUENCE) {
    throw new Error("fixture: this CRL has no revokedCertificates to splice an entry extension into");
  }
  var entries = kids[ri].children.slice();
  var first = entries[0].children.slice();
  var lastOfEntry = first[first.length - 1];
  var hasEntryExts = lastOfEntry && lastOfEntry.tagClass === "universal" && lastOfEntry.tagNumber === TAGS.SEQUENCE;
  var existing = hasEntryExts ? lastOfEntry.children.map(function (c) { return c.bytes; }) : [];
  if (hasEntryExts) first.pop();
  var newEntry = b.sequence(first.map(function (c) { return c.bytes; }).concat([b.sequence(existing.concat([extDer]))]));
  entries[0] = { bytes: newEntry };
  kids[ri] = { bytes: b.sequence(entries.map(function (e) { return e.bytes; })) };
  var newTbs = b.sequence(kids.map(function (c) { return c.bytes; }));
  return b.sequence([newTbs, root.children[1].bytes, root.children[2].bytes]);
}

// IssuingDistributionPoint ::= SEQUENCE { ... indirectCRL [4] BOOLEAN DEFAULT FALSE }
function _forceIndirect(der) {
  var b = pki.asn1.build;
  return _spliceCrlExt(der, b.sequence([
    b.oid(pki.oid.byName("issuingDistributionPoint")),
    b.boolean(true),
    b.octetString(b.sequence([b.contextPrimitive(4, Buffer.from([0xff]))])),
  ]));
}

// ---- PEM output + isRevoked lookup ----

async function testPemAndIsRevoked() {
  var s = makeSigner("ed25519");
  var pem = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, revoked: [{ serialNumber: 0xabcdn, revocationDate: RD }] }, issuerOf(s), { pem: true });
  check("opts.pem returns a string", typeof pem === "string");
  check("opts.pem has BEGIN X509 CRL", /-----BEGIN X509 CRL-----/.test(pem));
  var der = pki.schema.crl.pemDecode(pem);
  check("isRevoked finds a listed serial", pki.crl.isRevoked(der, 0xabcdn) !== null);
  // 0xabcd has its top bit set, so the DER INTEGER content carries a leading 00 sign octet -- isRevoked
  // normalizes the query the same way schema-crl surfaces serialNumberHex, so the padded forms match.
  check("isRevoked returns the matching entry (sign padding preserved)", pki.crl.isRevoked(der, 0xabcdn).serialNumberHex === "00abcd");
  check("isRevoked returns null for an absent serial", pki.crl.isRevoked(der, 0x9999n) === null);
  // Every documented serialNumber spelling resolves to the SAME entry -- a lookup must not depend on which
  // form the caller happens to hold, or a revoked certificate would read as unlisted.
  function found(v) { var e = pki.crl.isRevoked(der, v); return e && e.serialNumberHex === "00abcd"; }
  check("isRevoked accepts a safe-integer serial", found(43981));
  check("isRevoked accepts a 0x-hex string serial", found("0xabcd"));
  check("isRevoked accepts a decimal string serial", found("43981"));
  check("isRevoked accepts a magnitude Buffer serial", found(Buffer.from([0xab, 0xcd])));
  function serialCode(v) { try { pki.crl.isRevoked(der, v); return null; } catch (e) { return e && e.code; } }
  check("isRevoked non-safe-integer serial -> crl/bad-input", serialCode(Math.pow(2, 53)) === "crl/bad-input");

  // SCOPE. A serial number means something only inside the set of certificates a CRL speaks for,
  // and two shapes of CRL speak for a different set than a serial-only match assumes.
  // pki.path.crlChecker already refuses both -- so the toolkit knew the rule and applied it in one
  // consumer, while the standalone verb answered from any CRL it was handed.
  function scopeCode(crl, serial) { try { pki.crl.isRevoked(crl, serial); return "NO-THROW"; } catch (e) { return e && e.code; } }
  // A DELTA lists CHANGES: a serial in it may be there to say the certificate was RELEASED
  // (removeFromCRL), so read alone the entry that means "no longer revoked" reads as "revoked".
  var deltaDer = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n,
    extensions: { deltaCRLIndicator: 1n },
    revoked: [{ serialNumber: 0xabcdn, revocationDate: RD, reason: "removeFromCRL" }] }, issuerOf(s));
  check("isRevoked refuses to answer from a delta CRL alone", scopeCode(deltaDer, 0xabcdn) === "crl/delta-not-authoritative");
  // ...and the refusal is about the CRL's scope, not about that particular serial: a serial the
  // delta does not list is equally unanswerable from it.
  check("...for a serial the delta does not list either", scopeCode(deltaDer, 0x9999n) === "crl/delta-not-authoritative");
  // An INDIRECT CRL carries entries for OTHER issuers, identified per entry. Serials are unique per
  // issuer, not globally, so matching on serial alone attributes another issuer's revocation here.
  var indirectDer = _forceIndirect(der);
  check("isRevoked refuses to answer from an indirect CRL", scopeCode(indirectDer, 0xabcdn) === "crl/indirect-not-supported");
  // A direct CRL with no scope extensions still answers, which is the case every caller has.
  check("a plain direct CRL still answers", pki.crl.isRevoked(der, 0xabcdn) !== null);
  // A CRL's answer is a verdict over a signed byte range, but a parsed CRL presents that range and
  // the revocation list as separate properties. Keep a correctly signed CRL's tbsBytes and signature
  // and empty the list, and every completeness rule passes while a revoked certificate reports as
  // not-listed. The parser's record closes it: the answer is re-derived from the recorded bytes.
  var realCrl = pki.schema.crl.parse(der);
  check("the parser's own CRL object still answers", pki.crl.isRevoked(realCrl, 0xabcdn) !== null);
  check("a CRL with an emptied revocation list is refused, not answered from",
    scopeCode(Object.assign({}, realCrl, { revokedCertificates: [] }), 0xabcdn) === "crl/bad-input");
  check("...and one with its scope extensions emptied is refused too",
    scopeCode(Object.assign({}, realCrl, { crlExtensions: [] }), 0xabcdn) === "crl/bad-input");
  // certificateIssuer is meaningful only on an indirect CRL. On one that declares itself direct, the
  // entry and the CRL disagree about whose certificate this is -- and SKIPPING the entry would be
  // the worse of the two answers, since a matching entry silently not matching reports the
  // certificate as NOT revoked.
  var withCertIssuer = _spliceEntryExt(der, (function () {
    var b = pki.asn1.build;
    return b.sequence([
      b.oid(pki.oid.byName("certificateIssuer")),
      b.boolean(true),
      // GeneralNames { [4] directoryName } -- the content is any DN; only its PRESENCE matters here.
      b.octetString(b.sequence([b.contextConstructed(4, b.sequence([]))])),
    ]);
  })());
  check("an entry naming another issuer on a direct CRL is refused, never silently unmatched",
    scopeCode(withCertIssuer, 0xabcdn) === "crl/indirect-not-supported");
  // The contradiction is a property of the CRL, not of the entry that happens to match. Checking it
  // only on the matching entry left the NOT-LISTED answer -- the one that says "this certificate is
  // fine" -- coming from a CRL whose own entries dispute whose certificates it lists.
  check("...and for a serial the CRL does not list, where the answer would be not-revoked",
    scopeCode(withCertIssuer, 0x9999n) === "crl/indirect-not-supported");
  // A malformed IDP means the scope cannot be established at all, which is not a scope to answer
  // from -- the same refusal, for the same reason, rather than a guess that it is direct.
  var badIdp = _spliceCrlExt(der, (function () {
    var b = pki.asn1.build;
    // An IDP whose extnValue is an INTEGER rather than the IssuingDistributionPoint SEQUENCE.
    return b.sequence([
      b.oid(pki.oid.byName("issuingDistributionPoint")),
      b.boolean(true),
      b.octetString(b.integer(1n)),
    ]);
  })());
  check("a CRL whose scope extension cannot be read is refused, not read as unscoped",
    scopeCode(badIdp, 0xabcdn) === "crl/scope-not-authoritative");
  // The indirect flag is a DER BOOLEAN: exactly one content octet, 0x00 or 0xFF (X.690 sec. 11.1).
  // Every other encoding is a scope that cannot be established, and reading one as "absent, so
  // direct" is the one answer that must never follow -- it turns an unreadable scope into a licence
  // to answer by serial. A DEFAULT FALSE is likewise not encoded at all (X.690 sec. 11.5), so an
  // explicit FALSE is a statement the encoding rules do not permit rather than a reassuring one.
  function idpTag(tag, contentBytes) {
    var b = pki.asn1.build;
    return _spliceCrlExt(der, b.sequence([
      b.oid(pki.oid.byName("issuingDistributionPoint")),
      b.boolean(true),
      b.octetString(b.sequence([b.contextPrimitive(tag, Buffer.from(contentBytes))])),
    ]));
  }
  check("an empty indirectCRL BOOLEAN is refused, not read as absent",
    scopeCode(idpTag(4, []), 0xabcdn) === "crl/scope-not-authoritative");
  check("a multi-octet indirectCRL BOOLEAN is refused",
    scopeCode(idpTag(4, [0x00, 0xff]), 0xabcdn) === "crl/scope-not-authoritative");
  check("a non-DER indirectCRL BOOLEAN value is refused, not read by its low bit",
    scopeCode(idpTag(4, [0x01]), 0xabcdn) === "crl/scope-not-authoritative");
  // Every OTHER form of issuingDistributionPoint narrows which certificates the CRL speaks for, and
  // which part applies is decided against fields of the CERTIFICATE -- which this verb never sees.
  // So an absent serial is not an unrevoked certificate, and the whole family refuses rather than
  // answering: stopping at delta and indirect would apply the rule to two of its members.
  check("a CRL scoped to CA certificates is refused: a serial does not say what kind it names",
    scopeCode(idpTag(2, [0xff]), 0xabcdn) === "crl/scope-not-authoritative");
  check("...and for the serial it does list, where the answer would look right",
    scopeCode(idpTag(1, [0xff]), 0xabcdn) === "crl/scope-not-authoritative");
  check("a reason-sharded CRL is refused: a certificate revoked for another reason is absent from it",
    scopeCode(idpTag(3, [0x01, 0x80]), 0xabcdn) === "crl/scope-not-authoritative");
  check("a partitioned CRL is refused: the correspondence is against the certificate's own DP",
    scopeCode((function () {
      var b = pki.asn1.build;
      return _spliceCrlExt(der, b.sequence([
        b.oid(pki.oid.byName("issuingDistributionPoint")),
        b.boolean(true),
        // distributionPoint [0] { fullName [0] { uniformResourceIdentifier [6] } }
        b.octetString(b.sequence([b.contextConstructed(0, b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://crl.example/a", "ascii"))))])),
      ]));
    })(), 0xabcdn) === "crl/scope-not-authoritative");
  // Indirect keeps its own name: it is not a narrower scope, it is a list whose serials belong to
  // other issuers, and that is the sharper thing to tell an operator.
  check("indirect is named as indirect, not folded into the scope refusal",
    scopeCode(idpTag(4, [0xff]), 0xabcdn) === "crl/indirect-not-supported");
  // A CLAIMED-parsed CRL was trusted as parser output the moment it carried the three properties the
  // door tested for, and every scope guard above reads its list as `(crlExtensions || [])` -- so
  // OMITTING the property entirely made a scope-restricted CRL answer as an unrestricted one. A
  // guard cannot fire on a list that is not there, which is why the door has to establish it IS.
  var scopedParsed = pki.schema.crl.parse(await pki.crl.sign(
    { thisUpdate: TU, nextUpdate: NU, crlNumber: 3n, revoked: [{ serialNumber: 0xabcdn, revocationDate: RD }],
      extensions: { issuingDistributionPoint: { onlyContainsUserCerts: true } } }, issuerOf(s)));
  check("a scoped CRL handed as parser output is still refused",
    scopeCode(scopedParsed, 0xabcdn) === "crl/scope-not-authoritative");
  var strippedExts = Object.assign({}, scopedParsed);
  delete strippedExts.crlExtensions;
  check("...and stripping the extension list is a malformed input, not an unscoped CRL",
    scopeCode(strippedExts, 0xabcdn) === "crl/bad-input");
  var strippedEntryExts = Object.assign({}, pki.schema.crl.parse(der));
  strippedEntryExts.revokedCertificates = strippedEntryExts.revokedCertificates.map(function (e) {
    var c = Object.assign({}, e); delete c.crlEntryExtensions; return c;
  });
  check("an entry with no crlEntryExtensions property is malformed, not an entry naming no issuer",
    scopeCode(strippedEntryExts, 0xabcdn) === "crl/bad-input");
  check("a bare tbsBytes-carrying object is refused rather than dereferenced",
    scopeCode({ tbsBytes: Buffer.alloc(0), signatureValue: { bytes: Buffer.alloc(0) }, signatureAlgorithm: { oid: "1.2" } }, 0xabcdn) === "crl/bad-input");
  // The unmodified parser output still works -- the rule is completeness, not a ban on the form.
  check("an unmodified parsed CRL still answers", pki.crl.isRevoked(pki.schema.crl.parse(der), 0xabcdn) !== null);
  check("isRevoked unparseable string serial -> crl/bad-input", serialCode("zz") === "crl/bad-input");
  check("isRevoked non-numeric serial -> crl/bad-input", serialCode({}) === "crl/bad-input");
  check("isRevoked zero serial -> crl/bad-input (serials are positive)", serialCode(0n) === "crl/bad-input");
  check("isRevoked empty-Buffer serial -> crl/bad-input (serials are positive)", serialCode(Buffer.alloc(0)) === "crl/bad-input");
  // isRevoked shares the crl-shape coercion with verify, so a PEM string is a valid list to look up in.
  check("isRevoked accepts a PEM CRL string", pki.crl.isRevoked(pem, 0xabcdn) !== null);
}

// ---- config-time fail-closed ----

async function testFailClosed() {
  var s = makeSigner("ec-p256");
  check("no signing key -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU }, { publicKey: s.spki })) === "crl/bad-input");
  check("empty issuer DN -> crl/bad-issuer", await codeOf(pki.crl.sign({ issuer: [], thisUpdate: TU, nextUpdate: NU }, { publicKey: s.spki, key: s.key })) === "crl/bad-issuer");
  check("missing thisUpdate -> crl/bad-input", await codeOf(pki.crl.sign({ nextUpdate: NU }, issuerOf(s))) === "crl/bad-input");
  check("nextUpdate before thisUpdate -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: NU, nextUpdate: TU }, issuerOf(s))) === "crl/bad-input");
  check("revoked entry without a serialNumber -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ revocationDate: RD }] }, issuerOf(s))) === "crl/bad-input");
  check("unknown CRL extension key -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { bogus: 1 } }, issuerOf(s))) === "crl/bad-input");
  // RFC 5280 sec. 5.1.2.6 -- a CRL must not list the same serial number twice.
  check("duplicate revoked serial number -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 5n, revocationDate: RD }, { serialNumber: 5n, revocationDate: RD }] }, issuerOf(s))) === "crl/bad-input");
  // Structural inputs are type-checked rather than coerced -- a mis-shaped spec is a permanent verdict.
  check("non-object non-array extensions -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: 42 }, issuerOf(s))) === "crl/bad-input");
  check("non-array revoked -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: {} }, issuerOf(s))) === "crl/bad-input");
  check("null revoked entry -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [null] }, issuerOf(s))) === "crl/bad-input");
  check("non-array entry extensions -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: {} }] }, issuerOf(s))) === "crl/bad-input");
  check("issuer.cert that is not a certificate -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU }, { cert: {}, key: s.key })) === "crl/bad-input");
  check("a non-object CRL spec -> crl/bad-input", await codeOf(pki.crl.sign(null, issuerOf(s))) === "crl/bad-input");
  check("an omitted issuer -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU })) === "crl/bad-input");
  // sec. 5.1.2.3 -- with no issuer.cert to take the DN from, one must be supplied explicitly.
  check("no issuer DN and no issuer.cert -> crl/bad-issuer",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU }, { publicKey: s.spki, key: s.key })) === "crl/bad-issuer");
}

// ---- sec. 5.2.3 / 5.2.4 -- a delta CRL MUST carry a cRLNumber greater than its baseCRLNumber ----

async function testDeltaRequiresCrlNumber() {
  var s = makeSigner("ec-p256");
  check("delta CRL with no cRLNumber -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s))) === "crl/bad-input");
  check("delta CRL whose cRLNumber == baseCRLNumber -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 3n, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s))) === "crl/bad-crl-number");
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s)));
  check("delta CRL with cRLNumber > baseCRLNumber accepted", (crlExt(c, "deltaCRLIndicator") || {}).critical === true && (crlExt(c, "cRLNumber") || {}).value === 5n);
}

// ---- sec. 4.2.1.3 -- an issuer cert whose keyUsage omits cRLSign cannot sign a CRL ----

async function testIssuerCertCrlSign() {
  var s = makeSigner("ec-p256");
  var base = { subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z") };
  var caCrlSign = pki.schema.x509.parse(await pki.x509.sign(Object.assign({ subject: "CA cRLSign", extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, base), { key: s.key }));
  check("issuer cert asserting cRLSign signs a CRL", Buffer.isBuffer(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: caCrlSign, key: s.key })));
  var caNoCrlSign = pki.schema.x509.parse(await pki.x509.sign(Object.assign({ subject: "CA no cRLSign", extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "digitalSignature"] } }, base), { key: s.key }));
  check("issuer cert whose keyUsage omits cRLSign -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: caNoCrlSign, key: s.key })) === "crl/bad-input");
  // An unreadable keyUsage is NOT treated as "no keyUsage extension" (which would be unrestricted): the
  // cRLSign gate fails closed on a value it cannot decode.
  var kuBad = pki.asn1.build.sequence([pki.asn1.build.oid(byName("keyUsage")), pki.asn1.build.boolean(true), pki.asn1.build.octetString(Buffer.from([0xff, 0xff]))]);
  check("issuer cert with a malformed keyUsage -> crl/bad-key-usage",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: signing.minimalCert(s.spki, { exts: [kuBad] }), key: s.key })) === "crl/bad-key-usage");
  // A hostile object cannot make this verb raise an untyped fault. Two routes, both closed, and the
  // contract -- every failure is a CrlError carrying a stable code -- holds for each.
  function trapExt() {
    var trap = { oid: byName("keyUsage"), critical: true };
    Object.defineProperty(trap, "value", { get: function () { throw new RangeError("unreadable extension value"); } });
    return trap;
  }
  // Installed on the parser's OWN object, the trap is never read: the certificate is re-derived from
  // the bytes it was parsed from, so the CRL signs from the real extensions.
  var trapped = pki.schema.x509.parse(s.cert);
  trapped.extensions = [trapExt()];
  check("a throwing accessor on a parsed issuer cert is discarded with the rest of the edit",
    Buffer.isBuffer(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: trapped, key: s.key })));
  // Installed on a REBUILT object, it is refused at the door -- and the refusal is typed, so the
  // RangeError does not escape as itself even though reading the claim fields touches the object.
  var hostile = Object.assign({}, pki.schema.x509.parse(s.cert), { extensions: [trapExt()] });
  check("a throwing accessor on a rebuilt issuer cert is a typed fault, not a raw one",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: hostile, key: s.key })) === "crl/bad-input");
}

// ---- sec. 5.2 -- the pre-encoded Extension escape hatch is held to the profile (criticality + delta rules) ----

async function testPreEncodedExtProfile() {
  var s = makeSigner("ec-p256");
  var B = pki.asn1.build;
  function extDer(name, critical, valueDer) {
    var kids = [B.oid(byName(name))];
    if (critical) kids.push(B.boolean(true));
    kids.push(B.octetString(valueDer));
    return B.sequence(kids);
  }
  // cRLNumber MUST be non-critical (sec. 5.2.3) -- a critical pre-encoded one is rejected.
  check("pre-encoded critical cRLNumber -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("cRLNumber", true, B.integer(1n))] }, issuerOf(s))) === "crl/bad-input");
  // deltaCRLIndicator MUST be critical (sec. 5.2.4) -- a non-critical pre-encoded one is rejected.
  check("pre-encoded non-critical deltaCRLIndicator -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", false, B.integer(2n))] }, issuerOf(s))) === "crl/bad-input");
  // A pre-encoded (critical) delta with NO cRLNumber anywhere -> rejected (sec. 5.2.3/5.2.4).
  check("pre-encoded delta without a cRLNumber -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("deltaCRLIndicator", true, B.integer(2n))] }, issuerOf(s))) === "crl/bad-input");
  // A pre-encoded (critical) delta whose base (5) is >= spec.crlNumber (5) -> rejected.
  check("pre-encoded delta with cRLNumber <= baseCRLNumber -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", true, B.integer(5n))] }, issuerOf(s))) === "crl/bad-crl-number");
  // A conforming pre-encoded delta (critical, base 2) + spec.crlNumber 5 is accepted.
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", true, B.integer(2n))] }, issuerOf(s)));
  check("conforming pre-encoded delta + spec.crlNumber accepted", (crlExt(c, "deltaCRLIndicator") || {}).critical === true);
  // The entry-extension escape hatch is held to the same profile: reasonCode MUST be non-critical (sec. 5.3.1).
  check("pre-encoded critical entry reasonCode -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("reasonCode", true, B.enumerated(1n))] }] }, issuerOf(s))) === "crl/bad-input");
  // freshestCRL: a distribution point with an empty fullName is rejected (GeneralNames is SIZE(1..MAX)).
  check("freshestCRL DP with an empty fullName -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { freshestCRL: [{ fullName: [] }] } }, issuerOf(s))) === "crl/bad-input");
  // A pre-encoded freshestCRL co-present with a pre-encoded delta indicator is rejected (sec. 5.2.6).
  check("pre-encoded freshestCRL in a pre-encoded delta CRL -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", true, B.integer(2n)), extDer("freshestCRL", false, B.sequence([]))] }, issuerOf(s))) === "crl/bad-input");
  // Value validation on the escape hatch: a pre-encoded cRLNumber whose value is not an INTEGER is rejected.
  check("pre-encoded cRLNumber with a non-INTEGER value -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("cRLNumber", false, B.boolean(true))] }, issuerOf(s))) === "crl/bad-crl-number");
  // A pre-encoded entry reasonCode with a reserved value (7) is rejected.
  check("pre-encoded entry reasonCode value 7 -> crl/bad-reason-code",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("reasonCode", false, B.enumerated(7n))] }] }, issuerOf(s))) === "crl/bad-reason-code");
  // A pre-encoded entry invalidityDate encoded as UTCTime (not GeneralizedTime) is rejected.
  check("pre-encoded entry invalidityDate as UTCTime -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("invalidityDate", false, B.utcTime(new Date("2026-01-01T00:00:00Z")))] }] }, issuerOf(s))) === "crl/bad-input");
  // The removeFromCRL(8)-delta-only rule applies to the entry escape hatch too.
  check("pre-encoded entry removeFromCRL(8) in a full CRL -> crl/bad-reason-code",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("reasonCode", false, B.enumerated(8n))] }] }, issuerOf(s))) === "crl/bad-reason-code");
  // A pre-encoded invalidityDate with a GeneralizedTime tag but malformed content is rejected (parsed, not tag-only).
  check("pre-encoded entry invalidityDate with malformed content -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("invalidityDate", false, Buffer.from([0x18, 0x04, 0x41, 0x41, 0x41, 0x41]))] }] }, issuerOf(s))) === "crl/bad-input");
  // certificateIssuer (indirect CRLs) is deferred until crlChecker handles indirect CRLs -- rejected on both forms.
  check("object-form certificateIssuer entry -> crl/bad-input (deferred)",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, certificateIssuer: [{ directoryName: "CN=Other CA" }] }] }, issuerOf(s))) === "crl/bad-input");
  check("pre-encoded certificateIssuer entry -> crl/bad-input (deferred)",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("certificateIssuer", true, B.sequence([]))] }] }, issuerOf(s))) === "crl/bad-input");
  // An indirect-CRL IDP (indirectCRL) is deferred until crlChecker handles indirect CRLs -- rejected on both forms.
  check("issuingDistributionPoint indirectCRL:true -> crl/bad-idp (deferred)",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: { issuingDistributionPoint: { onlyContainsUserCerts: true, indirectCRL: true } } }, issuerOf(s))) === "crl/bad-idp");
  check("pre-encoded indirect-CRL IDP -> crl/bad-idp (deferred)",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("issuingDistributionPoint", true, B.sequence([B.contextPrimitive(4, Buffer.from([0xff]))]))] }, issuerOf(s))) === "crl/bad-idp");
  // The pre-encoded IDP is held to the same sec. 5.2.5 profile as the object form.
  check("pre-encoded empty IDP -> crl/bad-idp",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("issuingDistributionPoint", true, B.sequence([]))] }, issuerOf(s))) === "crl/bad-idp");
  check("pre-encoded IDP with two scope booleans -> crl/bad-idp",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("issuingDistributionPoint", true, B.sequence([B.contextPrimitive(1, Buffer.from([0xff])), B.contextPrimitive(2, Buffer.from([0xff]))]))] }, issuerOf(s))) === "crl/bad-idp");
  check("pre-encoded IDP with onlyContainsAttributeCerts -> crl/bad-idp",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("issuingDistributionPoint", true, B.sequence([B.contextPrimitive(5, Buffer.from([0xff]))]))] }, issuerOf(s))) === "crl/bad-idp");

  function withExts(list) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: list }, issuerOf(s)); }
  function withEntryExts(list) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: list }] }, issuerOf(s)); }
  // A recognized extension's value is DECODED on the escape hatch, never emitted opaque: content that is not
  // well-formed DER is rejected rather than copied through to the wire.
  check("pre-encoded ext whose value is not valid DER -> crl/bad-input",
    await codeOf(withExts([extDer("issuingDistributionPoint", true, Buffer.from([0xff, 0xff]))])) === "crl/bad-input");
  // The sec. 5.2.3 cRLNumber bounds bind the hatch exactly as they bind spec.crlNumber.
  check("pre-encoded negative cRLNumber -> crl/bad-crl-number",
    await codeOf(withExts([extDer("cRLNumber", false, B.integer(-1n))])) === "crl/bad-crl-number");
  check("pre-encoded 21-octet cRLNumber -> crl/bad-crl-number",
    await codeOf(withExts([extDer("cRLNumber", false, B.integer(BigInt("0x7f" + "ff".repeat(20))))])) === "crl/bad-crl-number");
  // A pre-encoded IDP member must be context-tagged (sec. 5.2.5 -- every field is a context tag).
  check("pre-encoded IDP with a universal-tagged member -> crl/bad-idp",
    await codeOf(withExts([extDer("issuingDistributionPoint", true, B.sequence([B.integer(1n)]))])) === "crl/bad-idp");
  // sec. 5.2 -- at most one instance of an extension, counting the object form and the hatch together.
  check("spec.crlNumber plus a pre-encoded cRLNumber -> crl/bad-input (duplicate)",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: [extDer("cRLNumber", false, B.integer(2n))] }, issuerOf(s))) === "crl/bad-input");
  // A recognized non-INTEGER extension's value must be a SEQUENCE.
  check("pre-encoded authorityKeyIdentifier with a non-SEQUENCE value -> crl/bad-input",
    await codeOf(withExts([extDer("authorityKeyIdentifier", false, B.integer(1n))])) === "crl/bad-input");
  // The same one-instance rule on entry extensions: spec.reason emits reasonCode, so a pre-encoded one collides.
  check("entry reason plus a pre-encoded reasonCode -> crl/bad-input (duplicate)",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: "keyCompromise", extensions: [extDer("reasonCode", false, B.enumerated(1n))] }] }, issuerOf(s))) === "crl/bad-input");
  check("pre-encoded reasonCode encoded as INTEGER not ENUMERATED -> crl/bad-reason-code",
    await codeOf(withEntryExts([extDer("reasonCode", false, B.integer(1n))])) === "crl/bad-reason-code");
  // The conforming pre-encoded entry extension is accepted and reaches the wire intact (v2 by sec. 5.1.2.1).
  var pe = pki.schema.crl.parse(await withEntryExts([extDer("reasonCode", false, B.enumerated(1n))]));
  check("conforming pre-encoded entry reasonCode accepted", (entryExt(pe.revokedCertificates[0], "reasonCode") || {}).value === 1);
  check("a pre-encoded entry extension forces v2", pe.version === 2);
}

async function main() {
  await testRoundTrip();
  await testEmptyListOmitsRevoked();
  await testVersionDerivation();
  await testInvalidityDateGeneralizedTime();
  await testReasonCodeRules();
  await testSigAlgSingleSource();
  await testCrlNumberCap();
  await testAkiShape();
  await testVerifyPerAlgorithm();
  await testVerifyAlgorithmConfusion();
  await testVerifyInputShapes();
  await testSignerKeyFaults();
  await testIdpGates();
  await testFreshestAndAia();
  await testDeltaAndFreshest();
  await testDeltaRequiresCrlNumber();
  await testIssuerCertCrlSign();
  await testPreEncodedExtProfile();
  await testPemAndIsRevoked();
  await testFailClosed();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
