// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- RFC 5914 TrustAnchorList / TrustAnchorInfo.
 *
 * A trust anchor as a structure rather than as a certificate, carrying the constraints a root
 * program otherwise states out of band. RFC 5937 sec. 3.2 says how those constraints reach RFC 5280
 * sec. 6.1 path validation, and the rule is uniform: the stricter of the anchor's value and the
 * caller's always wins.
 *
 * The fragile part is the tag numbering, which has gaps in both tagged structures: TrustAnchorInfo
 * has no [0], its `exts` is [1] EXPLICIT and its `taTitleLangTag` [2]; TrustAnchorChoice has no [0]
 * either, its `tbsCert` is [1] EXPLICIT and its `taInfo` [2] EXPLICIT, with `certificate` untagged.
 * A parser that numbered either from zero reads every field as its neighbor.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var nodeCrypto = require("node:crypto");

var b = pki.asn1.build;
var O = pki.oid.byName;
var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2036-01-01T00:00:00Z");
var T = new Date("2027-01-01T00:00:00Z");

var KP = nodeCrypto.generateKeyPairSync("ed25519");
var SPKI = KP.publicKey.export({ format: "der", type: "spki" });
var KEYID = nodeCrypto.createHash("sha1").update(SPKI).digest();

function algId() { return b.sequence([b.oid("1.3.101.112")]); }
function nameDer(cn) { return b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8(cn)])])]); }

/** A TrustAnchorInfo built field by field, so a vector can omit or mis-tag exactly one thing. */
function taInfo(spec) {
  var s = spec || {};
  var kids = [];
  if (s.version !== undefined) kids.push(b.integer(s.version));
  kids.push(b.raw(s.pubKey === undefined ? SPKI : s.pubKey));
  kids.push(b.octetString(s.keyId === undefined ? KEYID : s.keyId));
  if (s.taTitle !== undefined) kids.push(b.utf8(s.taTitle));
  if (s.certPath !== undefined) kids.push(s.certPath);
  // `exts [1] EXPLICIT` is one of the three members the module writes EXPLICIT beside; the
  // language tag is not, so it takes the tag in place of its own.
  if (s.exts !== undefined) kids.push(b.explicit(s.extsTag === undefined ? 1 : s.extsTag, s.exts));
  if (s.langTag !== undefined) {
    kids.push(s.langTagExplicit
      ? b.explicit(s.langTagTag === undefined ? 2 : s.langTagTag, b.utf8(s.langTag))
      : b.implicit(s.langTagTag === undefined ? 2 : s.langTagTag, b.utf8(s.langTag)));
  }
  return b.sequence(kids);
}

/** CertPathControls, whose own tags run [0]..[4] with no gap and are ALL implicit: the RFC 5914
 *  module is `DEFINITIONS IMPLICIT TAGS`, so each context tag replaces its member's own. */
function certPathControls(spec) {
  var s = spec || {};
  var kids = [b.raw(s.taName === undefined ? nameDer("Example Root") : s.taName)];
  if (s.certificate !== undefined) kids.push(b.implicit(0, s.certificate));
  if (s.policySet !== undefined) kids.push(b.implicit(1, s.policySet));
  if (s.policyFlags !== undefined) kids.push(b.implicit(2, b.namedBitString(s.policyFlags)));
  if (s.nameConstr !== undefined) kids.push(b.implicit(3, s.nameConstr));
  if (s.pathLen !== undefined) kids.push(b.implicit(4, b.integer(s.pathLen)));
  return b.sequence(kids);
}

function policies(oids) {
  return b.sequence(oids.map(function (o) { return b.sequence([b.oid(o)]); }));
}
/** GeneralSubtrees rides an IMPLICIT [0] / [1], which REPLACES the SEQUENCE OF tag rather than
 *  wrapping it: the tag's content is the GeneralSubtree elements themselves. */
function subtreesOf(tag, dnsNames) {
  var elements = dnsNames.map(function (d) {
    return b.sequence([b.contextPrimitive(2, Buffer.from(d, "latin1"))]);
  });
  return b.contextConstructed(tag, Buffer.concat(elements));
}
function nameConstraints(permittedDns, excludedDns) {
  var kids = [];
  if (permittedDns) kids.push(subtreesOf(0, permittedDns));
  if (excludedDns) kids.push(subtreesOf(1, excludedDns));
  return b.sequence(kids);
}

function list(choices) { return b.sequence(choices); }
function asTaInfo(info) { return b.explicit(2, info); }
function asTbsCert(tbs) { return b.explicit(1, tbs); }

function codeOf(fn) {
  try { fn(); return "NO-THROW"; }
  catch (e) { return e.code || e.name; }
}

// ---- the three CHOICE arms, and the tag gaps that decide them ---------------------------------

function testTheThreeArmsAreToldApartByTheirTags() {
  var info = taInfo({ certPath: certPathControls({}) });
  var parsed = pki.schema.trustanchor.parse(list([asTaInfo(info)]));
  check("1. a TrustAnchorList is a list of anchors, each naming which arm it came from",
    Array.isArray(parsed.anchors) && parsed.anchors.length === 1 && parsed.anchors[0].kind === "taInfo");
  check("2. the taInfo arm surfaces its public key and key identifier",
    parsed.anchors[0].taInfo.pubKey.bytes.equals(SPKI) &&
    parsed.anchors[0].taInfo.keyId.equals(KEYID));

  // A bare Certificate is the untagged arm, told apart by being a universal SEQUENCE.
  var certDer = b.sequence([
    b.sequence([b.explicit(0, b.integer(2n)), b.integer(7n), algId(), nameDer("Root"),
      b.sequence([b.utcTime(NB), b.utcTime(NA)]), nameDer("Root"), b.raw(SPKI)]),
    algId(), b.bitString(Buffer.alloc(64), 0)]);
  var withCert = pki.schema.trustanchor.parse(list([b.raw(certDer)]));
  check("3. an untagged element is the certificate arm",
    withCert.anchors[0].kind === "certificate" && Buffer.isBuffer(withCert.anchors[0].certificate.tbsBytes));

  // The tbsCert arm is [1] EXPLICIT over a TBSCertificate, an anchor with no signature to check.
  var tbs = b.sequence([b.explicit(0, b.integer(2n)), b.integer(7n), algId(), nameDer("Root"),
    b.sequence([b.utcTime(NB), b.utcTime(NA)]), nameDer("Root"), b.raw(SPKI)]);
  var withTbs = pki.schema.trustanchor.parse(list([asTbsCert(tbs)]));
  check("4. the [1] EXPLICIT arm is a TBSCertificate, carrying a subject and a key and no signature",
    withTbs.anchors[0].kind === "tbsCert" && withTbs.anchors[0].tbsCert.subject.dn.indexOf("Root") !== -1 &&
    withTbs.anchors[0].tbsCert.signatureValue === undefined);

  // The gap matters: [0] is not an arm of this CHOICE.
  check("5. a [0] element names no arm of the CHOICE and is refused",
    codeOf(function () { return pki.schema.trustanchor.parse(list([b.explicit(0, tbs)])); }) === "trustanchor/bad-anchor");
  check("6. and so is a [3]",
    codeOf(function () { return pki.schema.trustanchor.parse(list([b.explicit(3, info)])); }) === "trustanchor/bad-anchor");

  // SIZE (1..MAX)
  check("7. an empty TrustAnchorList is refused, the type being SIZE (1..MAX)",
    codeOf(function () { return pki.schema.trustanchor.parse(list([])); }) === "trustanchor/bad-list");
}

function testTheTrustAnchorInfoFieldsAndTheirTags() {
  var full = taInfo({
    taTitle: "Example Root CA",
    certPath: certPathControls({ policySet: policies(["2.23.140.1.2.1"]), pathLen: 3n }),
    exts: b.sequence([b.sequence([b.oid(O("subjectKeyIdentifier")), b.octetString(b.octetString(KEYID))])]),
    langTag: "en-US",
  });
  var a = pki.schema.trustanchor.parseInfo(full);
  check("8. version defaults to v1 when the DEFAULT is omitted, as DER requires", a.version === 1);
  check("9. the title and its language tag are read from [2], not from each other",
    a.taTitle === "Example Root CA" && a.taTitleLangTag === "en-US");
  check("10. the extensions come from [1] EXPLICIT",
    Array.isArray(a.exts) && a.exts.length === 1 && a.exts[0].name === "subjectKeyIdentifier");
  check("11. certPath carries the name, the policy set and the path length",
    a.certPath.taName.dn.indexOf("Example Root") !== -1 &&
    a.certPath.policySet.length === 1 && a.certPath.policySet[0].policyIdentifier === "2.23.140.1.2.1" &&
    a.certPath.pathLenConstraint === 3);

  // A parser that numbered the tags from zero would read the language tag as the extensions.
  check("12. the extensions and the language tag are not interchangeable",
    codeOf(function () { return pki.schema.trustanchor.parseInfo(taInfo({ langTag: "en", langTagTag: 1 })); }) !== "NO-THROW");

  // RFC 5914's module is `DEFINITIONS IMPLICIT TAGS`, and only three members in it are written
  // EXPLICIT: TrustAnchorInfo.exts [1] and both tagged arms of TrustAnchorChoice. Every other
  // tagged member takes the context tag IN PLACE OF its own. A reader that wrapped instead would
  // reject every conforming list, and a writer that wrapped would emit one nothing else reads --
  // neither of which the round trip through this toolkit's own reader would show.
  check("12b. taTitleLangTag [2] is implicit, so a wrapped one is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({ langTag: "en-US", langTagExplicit: true }));
    }) !== "NO-THROW");
  check("12c. CONTROL: the implicit form reads",
    pki.schema.trustanchor.parseInfo(taInfo({ langTag: "en-US" })).taTitleLangTag === "en-US");
  // The three implicitly-tagged CertPathControls members whose values are constructed: each one's
  // universal SEQUENCE tag is replaced, so an extra wrapper is a different encoding.
  var wrappedPolicySet = b.sequence([b.raw(nameDer("Example Root")),
    b.contextConstructed(1, policies(["2.23.140.1.2.1"]))]);
  check("12d. a policySet [1] wrapped rather than re-tagged is refused",
    codeOf(function () { return pki.schema.trustanchor.parseInfo(taInfo({ certPath: wrappedPolicySet })); }) !== "NO-THROW");
  var wrappedNc = b.sequence([b.raw(nameDer("Example Root")),
    b.contextConstructed(3, nameConstraints(["example.test"], null))]);
  check("12e. a nameConstr [3] wrapped rather than re-tagged is refused",
    codeOf(function () { return pki.schema.trustanchor.parseInfo(taInfo({ certPath: wrappedNc })); }) !== "NO-THROW");
  check("12f. CONTROL: both read when the tag replaces the value's own",
    pki.schema.trustanchor.parseInfo(taInfo({ certPath: certPathControls({
      policySet: policies(["2.23.140.1.2.1"]), nameConstr: nameConstraints(["example.test"], null),
    }) })).certPath.policySet.length === 1);

  // DER forbids encoding a DEFAULT at its default value.
  check("13. an explicitly encoded version v1 is refused, DER omitting a DEFAULT at its default",
    codeOf(function () { return pki.schema.trustanchor.parseInfo(taInfo({ version: 1n })); }) === "trustanchor/bad-version");
  check("14. a version other than v1 is refused",
    codeOf(function () { return pki.schema.trustanchor.parseInfo(taInfo({ version: 2n })); }) === "trustanchor/bad-version");

  // `TrustAnchorTitle ::= UTF8String (SIZE (1..64))` bounds CHARACTERS. A count in UTF-16 code
  // units doubles every character outside the basic plane, so a conforming title would be refused.
  var astral = "";
  for (var ai = 0; ai < 33; ai++) astral += String.fromCodePoint(0x1f512);
  check("14b. a 33-character title outside the basic plane is 33 characters, not 66",
    pki.schema.trustanchor.parseInfo(taInfo({ taTitle: astral })).taTitle === astral);
  var over = "";
  for (var oi = 0; oi < 65; oi++) over += String.fromCodePoint(0x1f512);
  check("14c. ...and 65 of them is over the bound",
    codeOf(function () { return pki.schema.trustanchor.parseInfo(taInfo({ taTitle: over })); }) === "trustanchor/bad-title");
  check("14d. the builder bounds a title exactly as the reader does",
    Buffer.isBuffer(pki.trustanchor.build({ anchors: [{ taInfo: {
      pubKey: SPKI, keyId: KEYID, taTitle: astral } }] })) &&
    codeOf(function () {
      return pki.trustanchor.build({ anchors: [{ taInfo: { pubKey: SPKI, keyId: KEYID, taTitle: over } }] });
    }) === "trustanchor/bad-input");
}

// ---- every MUST RFC 5914 states ----------------------------------------------------------------

function testTheNormativeRules() {
  check("15. an empty taName is refused: RFC 5914 sec. 2 says it MUST NOT be an empty sequence",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({ certPath: certPathControls({ taName: b.sequence([]) }) }));
    }) === "trustanchor/bad-name");

  // RFC 5914 sec. 3: "the OPTIONAL policyQualifiers structure MUST NOT be included".
  var qualified = b.sequence([b.sequence([b.oid("2.23.140.1.2.1"),
    b.sequence([b.sequence([b.oid("1.3.6.1.5.5.7.2.1"), b.ia5("https://cps.example")])])])]);
  check("16. a policySet carrying policy qualifiers is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({ certPath: certPathControls({ policySet: qualified }) }));
    }) === "trustanchor/bad-policy-set");

  // "Where it appears, the pathLenConstraint field MUST be greater than or equal to zero", which
  // the type already says as INTEGER (0..MAX).
  check("17. a negative pathLenConstraint is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({ certPath: certPathControls({ pathLen: -1n }) }));
    }) === "trustanchor/bad-path-len");

  // "This bit MUST be set to FALSE if policySet is absent."
  check("18. requireExplicitPolicy set with no policySet is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({ certPath: certPathControls({ policyFlags: [1] }) }));
    }) === "trustanchor/bad-policy-flags");
  check("19. CONTROL: the same flag with a policySet present is accepted",
    pki.schema.trustanchor.parseInfo(taInfo({
      certPath: certPathControls({ policySet: policies(["2.23.140.1.2.1"]), policyFlags: [1] }),
    })).certPath.policyFlags.requireExplicitPolicy === true);
  check("20. ...and the other two flags carry no such condition",
    pki.schema.trustanchor.parseInfo(taInfo({ certPath: certPathControls({ policyFlags: [0, 2] }) }))
      .certPath.policyFlags.inhibitPolicyMapping === true);

  // The four extension types RFC 5914 sec. 3 says MUST NOT appear in `exts`, and says are IGNORED
  // if they do. Ignored, not refused: this is a profile violation, reported.
  var banned = b.sequence([b.sequence([b.oid(O("nameConstraints")), b.octetString(nameConstraints(["example.test"], null))])]);
  var withBanned = pki.schema.trustanchor.parseInfo(taInfo({ exts: banned }));
  check("21. an extension RFC 5914 excludes from exts is reported rather than refused",
    Array.isArray(withBanned.excludedExtensions) && withBanned.excludedExtensions.length === 1 &&
    withBanned.excludedExtensions[0] === O("nameConstraints"));
  check("22. ...and it is left out of the extensions a caller reads, since the RFC ignores it",
    withBanned.exts.length === 0);
}

function testTheCertificateMatchRule() {
  // RFC 5914 sec. 2: where certPath.certificate is present, its subject MUST match taName, its
  // public key MUST match pubKey, and its subjectKeyIdentifier, if present, MUST match keyId.
  function certFor(subjectCn, spki, ski) {
    var exts = ski ? [b.explicit(3, b.sequence([b.sequence([b.oid(O("subjectKeyIdentifier")), b.octetString(b.octetString(ski))])]))] : [];
    var tbs = b.sequence([b.explicit(0, b.integer(2n)), b.integer(7n), algId(), nameDer("Issuer"),
      b.sequence([b.utcTime(NB), b.utcTime(NA)]), nameDer(subjectCn), b.raw(spki)].concat(exts));
    return b.sequence([tbs, algId(), b.bitString(Buffer.alloc(64), 0)]);
  }
  var good = taInfo({ certPath: certPathControls({ taName: nameDer("Example Root"), certificate: certFor("Example Root", SPKI, KEYID) }) });
  check("23. a certificate matching the name, the key and the key identifier is accepted",
    pki.schema.trustanchor.parseInfo(good).certPath.certificate.subject.dn.indexOf("Example Root") !== -1);

  check("24. a certificate whose subject does not match taName is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({
        certPath: certPathControls({ taName: nameDer("Example Root"), certificate: certFor("Other Root", SPKI, KEYID) }) }));
    }) === "trustanchor/certificate-mismatch");

  var otherKp = nodeCrypto.generateKeyPairSync("ed25519");
  var otherSpki = otherKp.publicKey.export({ format: "der", type: "spki" });
  check("25. a certificate whose public key does not match pubKey is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({
        certPath: certPathControls({ taName: nameDer("Example Root"), certificate: certFor("Example Root", otherSpki, KEYID) }) }));
    }) === "trustanchor/certificate-mismatch");

  check("26. a certificate whose subjectKeyIdentifier does not match keyId is refused",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({
        certPath: certPathControls({ taName: nameDer("Example Root"), certificate: certFor("Example Root", SPKI, Buffer.alloc(20, 9)) }) }));
    }) === "trustanchor/certificate-mismatch");

  // The name comparison is the RFC 5280 sec. 7.1 canonical one, which refuses a name carrying an
  // embedded control byte rather than comparing it (CVE-2009-2408). It reports that refusal
  // through the caller's error factory, so a comparison that forgot to pass one would surface a
  // bare TypeError here instead of a typed verdict, and a caller catching PkiError would not
  // catch it. Found by the fuzz target in nine seconds.
  var nul = String.fromCharCode(0);
  var ctrlName = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.utf8("Root" + nul + "evil")])])]);
  check("26b. a taName carrying an embedded control byte is refused with a typed error",
    codeOf(function () {
      return pki.schema.trustanchor.parseInfo(taInfo({
        certPath: certPathControls({ taName: ctrlName, certificate: certFor("Example Root", SPKI, KEYID) }) }));
    }).indexOf("trustanchor/") === 0);

  check("27. CONTROL: a certificate carrying no subjectKeyIdentifier is accepted, the rule being conditional",
    pki.schema.trustanchor.parseInfo(taInfo({
      certPath: certPathControls({ taName: nameDer("Example Root"), certificate: certFor("Example Root", SPKI, null) }) }))
      .certPath.certificate !== null);
}

// ---- the round trip ----------------------------------------------------------------------------

function testTheBuilderIsTheParsersInverse() {
  var der = pki.trustanchor.build({
    anchors: [{
      taInfo: {
        pubKey: SPKI, keyId: KEYID, taTitle: "Example Root CA", taTitleLangTag: "en-US",
        certPath: {
          taName: "CN=Example Root",
          policySet: ["2.23.140.1.2.1"],
          policyFlags: { requireExplicitPolicy: true },
          pathLenConstraint: 3,
        },
      },
    }],
  });
  var back = pki.schema.trustanchor.parse(der);
  check("28. a built list round-trips through the parser",
    back.anchors.length === 1 && back.anchors[0].kind === "taInfo" &&
    back.anchors[0].taInfo.taTitle === "Example Root CA" &&
    back.anchors[0].taInfo.certPath.pathLenConstraint === 3);
  // The round trip is parse THEN build, driven off what the parser returned. Rebuilding from the
  // same literal spec would only show the builder is deterministic, which a builder that drops a
  // field does just as well.
  var readBack = back.anchors[0].taInfo;
  check("29. ...and the parsed record re-encodes to the identical bytes",
    pki.trustanchor.build({ anchors: [{ taInfo: {
      pubKey: readBack.pubKey.bytes,
      keyId: readBack.keyId,
      taTitle: readBack.taTitle,
      taTitleLangTag: readBack.taTitleLangTag,
      certPath: {
        taName: readBack.certPath.taName.bytes,
        policySet: readBack.certPath.policySet.map(function (p) { return p.policyIdentifier; }),
        policyFlags: readBack.certPath.policyFlags,
        pathLenConstraint: readBack.certPath.pathLenConstraint,
      } } }] }).equals(der));
  check("30. the builder refuses what the parser refuses: requireExplicitPolicy with no policySet",
    codeOf(function () {
      return pki.trustanchor.build({ anchors: [{ taInfo: { pubKey: SPKI, keyId: KEYID,
        certPath: { taName: "CN=Example Root", policyFlags: { requireExplicitPolicy: true } } } }] });
    }) === "trustanchor/bad-input");
  check("31. ...and an empty anchor list",
    codeOf(function () { return pki.trustanchor.build({ anchors: [] }); }) === "trustanchor/bad-input");

  var pem = pki.schema.trustanchor.pemEncode(der);
  check("32. the PEM envelope round-trips under the RFC 5914 label",
    pem.indexOf("-----BEGIN TRUST ANCHOR LIST-----") === 0 &&
    pki.schema.trustanchor.pemDecode(pem).equals(der));
}

// ---- the anchors reach pki.path.validate --------------------------------------------------------

async function testTheAnchorsDriveValidation() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var pub = await pki.key.export(pair.publicKey);
  var rootCert = await pki.x509.sign({
    subject: "CN=TA Root", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: key });
  var leaf = await pki.x509.sign({
    subject: "CN=leaf.example", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: false }, subjectAltName: [{ dNSName: "leaf.example" }],
      certificatePolicies: [{ oid: "2.23.140.1.2.1" }] },
  }, { cert: rootCert, key: key });

  var rootSpki = pki.schema.x509.parse(rootCert).subjectPublicKeyInfo.bytes;
  var rootKeyId = nodeCrypto.createHash("sha1").update(rootSpki).digest();

  function listWith(certPath) {
    return pki.trustanchor.build({ anchors: [{ taInfo: {
      pubKey: rootSpki, keyId: rootKeyId, certPath: certPath } }] });
  }

  var plain = pki.trust.parseTrustAnchorList(listWith({ taName: "CN=TA Root" }));
  check("33. a parsed list becomes trust-store entries pki.trust.anchor accepts",
    plain.anchors.length === 1 && typeof plain.anchors[0].algorithm === "string");
  var res = await pki.path.validate([leaf], { trustAnchors: [pki.trust.anchor(plain.anchors[0])], time: T });
  check("34. ...and those anchors validate a path", res.valid === true);

  // The entry carries a name, a public key and an algorithm, which IS the anchor tuple
  // pki.path.validate accepts, so the obvious call passes it straight through. Its constraints
  // have to survive that call and a copy of it, or an operator doing the obvious thing gets an
  // unconstrained anchor and every restriction the list stated is silently dropped.
  var restricted = pki.trust.parseTrustAnchorList(listWith({
    taName: "CN=TA Root", policySet: ["1.3.6.1.4.1.99999.44"] }));
  var viaAnchor = await pki.path.validate([leaf], {
    trustAnchors: [pki.trust.anchor(restricted.anchors[0])], time: T,
    userInitialPolicySet: ["2.23.140.1.2.1"], initialExplicitPolicy: true });
  var viaEntry = await pki.path.validate([leaf], {
    trustAnchors: [restricted.anchors[0]], time: T,
    userInitialPolicySet: ["2.23.140.1.2.1"], initialExplicitPolicy: true });
  var viaCopy = await pki.path.validate([leaf], {
    trustAnchors: [Object.assign({}, restricted.anchors[0])], time: T,
    userInitialPolicySet: ["2.23.140.1.2.1"], initialExplicitPolicy: true });
  check("34b. a restricted anchor refuses the same path through the entry and a copy of it, not only through anchor()",
    viaAnchor.valid === false && viaEntry.valid === false && viaCopy.valid === false);

  // The entry is reachable, so the restrictions it carries must not be the ones anchor() enforces.
  // Editing them on the entry is the cheapest way to weaken a published anchor, and the private
  // record anchor() reads from keeps its own copy for the same reason it copies the name and key.
  var editable = pki.trust.parseTrustAnchorList(listWith({ taName: "CN=TA Root", pathLenConstraint: 0 }));
  editable.anchors[0].constraints.pathLenConstraint = 100;
  check("34c. editing the entry's constraints does not change what anchor() enforces",
    pki.trust.anchor(editable.anchors[0]).constraints.pathLenConstraint === 0);

  // RFC 5937 sec. 3.2: the anchor's name constraints intersect (permitted) and union (excluded)
  // with the caller's, so an anchor that excludes the leaf's name refuses it.
  var excluded = pki.trust.parseTrustAnchorList(listWith({
    taName: "CN=TA Root", nameConstr: nameConstraints(null, ["leaf.example"]) }));
  var resExcluded = await pki.path.validate([leaf],
    { trustAnchors: [pki.trust.anchor(excluded.anchors[0])], time: T });
  check("35. an anchor's excluded subtree refuses a name inside it",
    resExcluded.valid === false);
  var permitted = pki.trust.parseTrustAnchorList(listWith({
    taName: "CN=TA Root", nameConstr: nameConstraints(["other.test"], null) }));
  var resPermitted = await pki.path.validate([leaf],
    { trustAnchors: [pki.trust.anchor(permitted.anchors[0])], time: T });
  check("36. an anchor's permitted subtree refuses a name outside it", resPermitted.valid === false);

  // policyFlags: "If a require explicit policy value of true is associated with the trust anchor
  // ... and the initial-explicit-policy value is false, set the initial-explicit-policy value to
  // true." So the anchor can turn it on where the caller did not.
  var noPolicyLeaf = await pki.x509.sign({
    subject: "CN=nopolicy.example", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: false } },
  }, { cert: rootCert, key: key });
  var strict = pki.trust.parseTrustAnchorList(listWith({
    taName: "CN=TA Root", policySet: ["2.23.140.1.2.1"], policyFlags: { requireExplicitPolicy: true } }));
  var resStrict = await pki.path.validate([noPolicyLeaf],
    { trustAnchors: [pki.trust.anchor(strict.anchors[0])], time: T });
  check("37. an anchor requiring an explicit policy refuses a certificate carrying none",
    resStrict.valid === false);
  var resLoose = await pki.path.validate([noPolicyLeaf],
    { trustAnchors: [pki.trust.anchor(plain.anchors[0])], time: T });
  check("38. CONTROL: the same certificate under an anchor with no such flag validates",
    resLoose.valid === true);

  // policySet intersects with the caller's user-initial-policy-set.
  var otherPolicy = pki.trust.parseTrustAnchorList(listWith({
    taName: "CN=TA Root", policySet: ["1.3.6.1.4.1.99999.44"] }));
  var resIntersect = await pki.path.validate([leaf], {
    trustAnchors: [pki.trust.anchor(otherPolicy.anchors[0])], time: T,
    userInitialPolicySet: ["2.23.140.1.2.1"], initialExplicitPolicy: true,
  });
  check("39. an anchor's policy set intersects with the caller's, so a disjoint pair permits nothing",
    resIntersect.valid === false);
  // anyPolicy on either side of that intersection means "any policy satisfies me", so it leaves
  // the other side's set alone. Filtering it literally would compare a concrete identifier against
  // the wildcard identifier, find no match, and refuse a path both sides accept.
  var anchorAny = pki.trust.parseTrustAnchorList(listWith({
    taName: "CN=TA Root", policySet: [pki.oid.byName("anyPolicy")] }));
  var resAnchorAny = await pki.path.validate([leaf], {
    trustAnchors: [pki.trust.anchor(anchorAny.anchors[0])], time: T,
    userInitialPolicySet: ["2.23.140.1.2.1"], initialExplicitPolicy: true,
  });
  check("39b. an anchor naming anyPolicy leaves the caller's policy set alone",
    resAnchorAny.valid === true &&
    resAnchorAny.userConstrainedPolicySet.join(",") === "2.23.140.1.2.1");
  var resCallerAny = await pki.path.validate([leaf], {
    trustAnchors: [pki.trust.anchor(pki.trust.parseTrustAnchorList(listWith({
      taName: "CN=TA Root", policySet: ["2.23.140.1.2.1"] })).anchors[0])], time: T,
    initialExplicitPolicy: true,
  });
  check("39c. ...and a caller naming none leaves the anchor's alone",
    resCallerAny.valid === true &&
    resCallerAny.userConstrainedPolicySet.join(",") === "2.23.140.1.2.1");

  // pathLenConstraint: "set the max_path_length state variable equal to the pathLenConstraint".
  var interm = await pki.x509.sign({
    subject: "CN=Intermediate", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { cert: rootCert, key: key });
  var deepLeaf = await pki.x509.sign({
    subject: "CN=deep.example", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: false } },
  }, { cert: interm, key: key });
  var capped = pki.trust.parseTrustAnchorList(listWith({ taName: "CN=TA Root", pathLenConstraint: 0 }));
  var resCapped = await pki.path.validate([interm, deepLeaf],
    { trustAnchors: [pki.trust.anchor(capped.anchors[0])], time: T });
  check("40. an anchor's pathLenConstraint bounds the intermediates below it",
    resCapped.valid === false);
  var resUncapped = await pki.path.validate([interm, deepLeaf],
    { trustAnchors: [pki.trust.anchor(plain.anchors[0])], time: T });
  check("41. CONTROL: the same path under an anchor with no constraint validates",
    resUncapped.valid === true);

  // RFC 5937 sec. 3.2 binds a basic constraints extension "associated with the trust anchor", and
  // RFC 5914 sec. 2.6 says `exts` is where an anchor associates any extension the four certPath
  // fields do not carry. basicConstraints is not one of the four it excludes, so a path length
  // stated there binds as much as one stated in certPath, and so does one in the certificate an
  // anchor is supplied as.
  var bcPathLenZero = pki.asn1.build.sequence([
    pki.asn1.build.oid(pki.oid.byName("basicConstraints")),
    pki.asn1.build.boolean(true),
    pki.asn1.build.octetString(pki.asn1.build.sequence([
      pki.asn1.build.boolean(true), pki.asn1.build.integer(0n)])),
  ]);
  var viaExts = pki.trust.parseTrustAnchorList(pki.trustanchor.build({ anchors: [{ taInfo: {
    pubKey: rootSpki, keyId: rootKeyId, certPath: { taName: "CN=TA Root" }, exts: [bcPathLenZero] } }] }));
  var resExts = await pki.path.validate([interm, deepLeaf],
    { trustAnchors: [pki.trust.anchor(viaExts.anchors[0])], time: T });
  check("41d. a basicConstraints pathLenConstraint in exts bounds the path", resExts.valid === false);

  // The same limit carried by the certificate an anchor is supplied as. The chain is issued under
  // an unconstrained root, because the signer refuses to issue a CA below a pathLen-0 issuer.
  var rootCapped = await pki.x509.sign({
    subject: "CN=TA Root", subjectPublicKey: pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign"] },
  }, { key: key });
  var viaCertArm = pki.trust.parseTrustAnchorList(
    pki.trustanchor.build({ anchors: [{ certificate: rootCapped }] }));
  var resCertArm = await pki.path.validate([interm, deepLeaf],
    { trustAnchors: [pki.trust.anchor(viaCertArm.anchors[0])], time: T });
  check("41e. a certificate anchor's own pathLenConstraint bounds the path", resCertArm.valid === false);
  var resRawCert = await pki.path.validate([interm, deepLeaf],
    { trustAnchors: [rootCapped], time: T });
  check("41f. ...and so does one passed straight to validate as a certificate",
    resRawCert.valid === false);
  var resRawPlain = await pki.path.validate([interm, deepLeaf], { trustAnchors: [rootCert], time: T });
  check("41g. CONTROL: the same certificate without a pathLenConstraint validates the path",
    resRawPlain.valid === true);

  // Every nested record the builder reads is refused by its own typed error, not by a native
  // TypeError from the first property read below it.
  var nested = [
    ["taInfo", { taInfo: null }],
    ["certPath", { taInfo: { pubKey: rootSpki, keyId: rootKeyId, certPath: null } }],
    ["certPath.policyFlags", { taInfo: { pubKey: rootSpki, keyId: rootKeyId,
      certPath: { taName: "CN=TA Root", policyFlags: null } } }],
  ];
  var untyped = [];
  for (var ni = 0; ni < nested.length; ni++) {
    try { pki.trustanchor.build({ anchors: [nested[ni][1]] }); untyped.push(nested[ni][0] + ":no-throw"); }
    catch (e) { if (e.code !== "trustanchor/bad-input") untyped.push(nested[ni][0] + ":" + (e.code || e.name)); }
  }
  check("41h. a malformed nested record is refused with the builder's typed error" +
    (untyped.length ? " (" + untyped.join(", ") + ")" : ""), untyped.length === 0);

  // An anchor may only narrow, so every constraint it carries has to leave the caller's own options
  // in force. An option defined non-enumerably is still the caller's option: reading them through a
  // copy would answer only for the ones the copy loop enumerated, and dropping
  // initialExplicitPolicy that way turns a refusal into an acceptance the moment an anchor states
  // anything at all.
  function optsWithHiddenExplicitPolicy(anchorEntry) {
    var o = { trustAnchors: [pki.trust.anchor(anchorEntry)], time: T };
    Object.defineProperty(o, "initialExplicitPolicy", { value: true, enumerable: false });
    return o;
  }
  var hiddenNone = await pki.path.validate([noPolicyLeaf], optsWithHiddenExplicitPolicy(plain.anchors[0]));
  check("41b. CONTROL: a non-enumerable initialExplicitPolicy refuses a certificate carrying no policy",
    hiddenNone.valid === false);
  var constrainers = [
    ["pathLenConstraint", listWith({ taName: "CN=TA Root", pathLenConstraint: 100 })],
    ["policySet", listWith({ taName: "CN=TA Root", policySet: ["2.23.140.1.2.1"] })],
    ["all-false policyFlags", listWith({ taName: "CN=TA Root",
      policyFlags: { inhibitPolicyMapping: false, requireExplicitPolicy: false, inhibitAnyPolicy: false } })],
  ];
  var widened = [];
  for (var ci = 0; ci < constrainers.length; ci++) {
    var entry = pki.trust.parseTrustAnchorList(constrainers[ci][1]).anchors[0];
    var resHidden = await pki.path.validate([noPolicyLeaf], optsWithHiddenExplicitPolicy(entry));
    if (resHidden.valid !== false) widened.push(constrainers[ci][0]);
  }
  // The same constraints reach validate() from a hand-built tuple, which is the route that can
  // state an empty policy set the RFC 5914 encoding has no room for.
  var tupleEntries = [
    ["tuple empty policySet", { policySet: [] }],
    ["tuple all-false policyFlags",
      { policyFlags: { inhibitPolicyMapping: false, requireExplicitPolicy: false, inhibitAnyPolicy: false } }],
  ];
  for (var ti = 0; ti < tupleEntries.length; ti++) {
    var tuple = Object.assign({}, plain.anchors[0], { constraints: tupleEntries[ti][1] });
    var resTuple = await pki.path.validate([noPolicyLeaf], optsWithHiddenExplicitPolicy(tuple));
    if (resTuple.valid !== false) widened.push(tupleEntries[ti][0]);
  }
  check("41c. adding an anchor constraint never widens what the caller asked for" +
    (widened.length ? " (widened by: " + widened.join(", ") + ")" : ""),
    widened.length === 0);
}

// ---- the orchestrator routes it -----------------------------------------------------------------

function testTheFormatIsDetected() {
  var der = pki.trustanchor.build({ anchors: [{ taInfo: {
    pubKey: SPKI, keyId: KEYID, certPath: { taName: "CN=Example Root" } } }] });
  check("42. pki.schema.parse detects a TrustAnchorList and routes it to this parser",
    pki.schema.detectFormat(der) === "trustanchor" && pki.schema.parse(der).anchors.length === 1);
  check("43. the format is enumerated among the others",
    pki.schema.all().indexOf("trustanchor") !== -1);
}

async function run() {
  testTheThreeArmsAreToldApartByTheirTags();
  testTheTrustAnchorInfoFieldsAndTheirTags();
  testTheNormativeRules();
  testTheCertificateMatchRule();
  testTheBuilderIsTheParsersInverse();
  await testTheAnchorsDriveValidation();
  testTheFormatIsDetected();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
