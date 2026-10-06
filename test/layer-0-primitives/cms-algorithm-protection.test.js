// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * RFC 6211 CMSAlgorithmProtection: the attribute that puts a copy of the algorithm identifiers a
 * SignerInfo or an AuthenticatedData already names where the signature or the MAC covers them.
 *
 * `CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm DigestAlgorithmIdentifier,
 * signatureAlgorithm [1] SignatureAlgorithmIdentifier OPTIONAL, macAlgorithm [2]
 * MessageAuthenticationCodeAlgorithm OPTIONAL }` with "Exactly one of signatureAlgorithm or
 * macAlgorithm SHALL be present" (RFC 6211 sec. 2).
 *
 * The attack the AuthenticatedData arm stops needs no key: RFC 5652 sec. 9.2 makes the MAC input the
 * DER encoding of `authAttrs` alone, so `AuthenticatedData.digestAlgorithm` and `macAlgorithm` sit
 * outside it and the MAC covers neither. Rewriting the digest algorithm leaves the MAC verifying,
 * and the recipient then recomputes the content digest under the algorithm the attacker chose.
 *
 * The document contradicts itself on the OID. RFC 6211 sec. 2 and Appendix A both state
 * `1.2.840.113549.1.9.52`, which OpenSSL and Bouncy Castle use; the IANA registry, errata 9144 and
 * 9145, and `draft-ietf-lamps-rfc6211-update-03` state `1.2.840.113549.1.9.16.2.52`. Both are
 * accepted here and the RFC body value is emitted, because a mismatched OID is equivalent to no
 * protection at all (update draft sec. 5).
 *
 * Every hostile case is built as an ENCODING and every refusal drives a shipped `pki.*` verb.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var signing = require("../helpers/signing");
var crypto = require("node:crypto");
var b = pki.asn1.build;

var CONTENT = Buffer.from("RFC 6211 algorithm protection content", "utf8");
var OID_PKCS9 = "1.2.840.113549.1.9.52";
var OID_REGISTRY = "1.2.840.113549.1.9.16.2.52";

async function codeOf(p) {
  try { await p; return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; }
}
function codeOfSync(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; }
}
// Two refusals carrying one code are told apart by what each says, which is how a vector asserts
// WHICH of them a verb reached first.
async function messageOf(p) {
  try { await p; return "NO-THROW"; } catch (e) { return String(e.message || ""); }
}
function algId(name, params) {
  return params === undefined ? b.sequence([b.oid(pki.oid.byName(name))])
    : b.sequence([b.oid(pki.oid.byName(name)), params]);
}
// A CMSAlgorithmProtection value: the digest identifier, then exactly one arm.
function protection(digest, arm, armTag) {
  var parts = [digest];
  if (arm !== null) parts.push(b.contextConstructed(armTag, arm.slice(2)));
  return b.sequence(parts);
}
// The attribute as a whole, with the attrType and the value count both chosen by the caller.
function attr(oidDotted, values) {
  return b.sequence([b.oid(oidDotted), b.set(values)]);
}

// A SignedData another implementation could produce: the signed attributes are whatever the caller
// asks for and the signature is computed over exactly those bytes, so it VERIFIES. This is the only
// way to reach the comparison with a sound signature, because an attacker who rewrites an attribute
// breaks the signature that covers it and our own emitter refuses to write a contradictory copy. The
// fixture is an encoding, not a mutated parse result.
function foreignSignedData(signer, pairs, sigAlgId) {
  var md = crypto.createHash("sha256").update(CONTENT).digest();
  var all = [
    b.sequence([b.oid(pki.oid.byName("contentType")), b.set([b.oid(pki.oid.byName("data"))])]),
    b.sequence([b.oid(pki.oid.byName("messageDigest")), b.set([b.octetString(md)])]),
  ].concat(pairs);
  var setOf = b.set(all);                       // 0x31, the form the signature covers (RFC 5652 sec. 5.4)
  var sig = crypto.sign("sha256", setOf, { key: signer.keyObject, dsaEncoding: "der" });
  var wire = Buffer.from(setOf); wire[0] = 0xA0;
  var cert = pki.schema.x509.parse(signer.cert);
  var sid = b.sequence([cert.issuer.bytes, b.integer(cert.serialNumber)]);
  var si = b.sequence([b.integer(1n), sid,
    b.sequence([b.oid(pki.oid.byName("sha256"))]), wire,
    sigAlgId || b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA256"))]), b.octetString(sig)]);
  var sd = b.sequence([b.integer(1n),
    b.set([b.sequence([b.oid(pki.oid.byName("sha256"))])]),
    b.sequence([b.oid(pki.oid.byName("data")), b.explicit(0, b.octetString(CONTENT))]),
    b.contextConstructed(0, pki.asn1.decode(signer.cert).bytes),
    b.set([si])]);
  return b.sequence([b.oid(pki.oid.byName("signedData")), b.explicit(0, sd)]);
}

// The signed attributes of one SignerInfo, rebuilt with `extra` added. The signature covers them, so
// a fixture built this way is expected to fail its signature: these vectors drive the PARSER and the
// comparison, and the signer verdict is asserted alongside.
function withSignedAttr(cmsDer, extra, replaceType) {
  var root = pki.asn1.decode(cmsDer);
  var sd = root.children[1].children[0];
  var siSet = sd.children[sd.children.length - 1];
  var si = siSet.children[0];
  var want = replaceType ? pki.oid.byName(replaceType) : null;
  var kids = si.children.map(function (k) {
    if (k.tagClass !== "context" || k.tagNumber !== 0) return k.bytes;
    var members = k.children.filter(function (m) {
      return want === null || pki.asn1.read.oid(m.children[0]) !== want;
    }).map(function (m) { return m.bytes; });
    if (extra) members.push(extra);
    var set = Buffer.from(b.set(members));
    set[0] = 0xA0;
    return set;
  });
  var sdKids = sd.children.map(function (k, i) {
    return i === sd.children.length - 1 ? b.set([b.sequence(kids)]) : k.bytes;
  });
  return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
}

// The unsigned attributes of one SignerInfo, with `extra` spliced in.
function withUnsignedAttr(cmsDer, extra) {
  var root = pki.asn1.decode(cmsDer);
  var sd = root.children[1].children[0];
  var siSet = sd.children[sd.children.length - 1];
  var kids = siSet.children[0].children.map(function (k) { return k.bytes; });
  var set = Buffer.from(b.set([extra]));
  set[0] = 0xA1;
  kids.push(set);
  var sdKids = sd.children.map(function (k, i) {
    return i === sd.children.length - 1 ? b.set([b.sequence(kids)]) : k.bytes;
  });
  return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
}

async function run() {
  var signer = signing.makeSigner("ec-p256");
  var SIGNER = { cert: signer.cert, key: signer.key };

  // ---- accept arms --------------------------------------------------------------------------
  // AP-2: the emitted copy is the field it claims to copy, byte for byte. RFC 6211 sec. 2 says the
  // attribute "contains a copy of the SignerInfo.digestAlgorithm field ... including any parameters
  // associated with it", so an emitter re-deriving the identifier from a registry row is the defect
  // this vector catches.
  var signed = await pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: true });
  var parsed = pki.schema.cms.parse(signed);
  var si0 = parsed.signerInfos[0];
  var apAttr = (si0.signedAttrs || []).filter(function (a) { return a.type === OID_PKCS9; })[0];
  check("AP-2 the attribute is emitted into signedAttrs under the RFC 6211 sec. 2 OID",
    apAttr !== undefined && apAttr.values.length === 1);
  var apValue = pki.schema.cms.parseAlgorithmProtection(apAttr.values[0]);
  check("AP-2 its digestAlgorithm is a copy of the SignerInfo field, parameters included",
    apValue.digestAlgorithm.oid === si0.digestAlgorithm.oid &&
    String(apValue.digestAlgorithm.parameters) === String(si0.digestAlgorithm.parameters));
  check("AP-2 its [1] arm is a copy of the SignerInfo signatureAlgorithm",
    apValue.signatureAlgorithm !== null && apValue.macAlgorithm === null &&
    apValue.signatureAlgorithm.oid === si0.signatureAlgorithm.oid &&
    String(apValue.signatureAlgorithm.parameters) === String(si0.signatureAlgorithm.parameters));

  // AP-1: the comparison runs and the signature still verifies.
  var v1 = await pki.cms.verify(signed, { certs: [signer.cert] });
  check("AP-1 a signature carrying the attribute verifies",
    v1.valid === true && v1.signers[0].ok === true);
  check("AP-1 and the verdict says which comparisons ran",
    v1.signers[0].algorithmProtection.present === true &&
    v1.signers[0].algorithmProtection.oid === OID_PKCS9 &&
    v1.signers[0].algorithmProtection.compared.indexOf("digestAlgorithm") !== -1 &&
    v1.signers[0].algorithmProtection.compared.indexOf("signatureAlgorithm") !== -1);

  // AP-6: both OIDs are accepted on parse and both run the comparison. A reader that recognized only
  // one would silently check nothing on the other, which is the interop failure the update draft
  // sec. 1 records between two implementations of this very attribute.
  var registrySigned = await pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: "registry" });
  var vReg = await pki.cms.verify(registrySigned, { certs: [signer.cert] });
  check("AP-6 the registry OID is emitted on request and verifies",
    vReg.signers[0].ok === true &&
    vReg.signers[0].algorithmProtection.present === true &&
    vReg.signers[0].algorithmProtection.oid === OID_REGISTRY);
  check("AP-6 and the comparison ran under it, not merely the recognition",
    vReg.signers[0].algorithmProtection.compared.length === 2);

  // AP-3: RSASSA-PSS, where the parameters ARE the substitution surface (RFC 4056 sec. 2.2 makes
  // them mandatory and the signature covers none of them).
  var pssSigner = signing.makeSigner("rsa-pss");
  var pssSigned = await pki.cms.sign(CONTENT, { cert: pssSigner.cert, key: pssSigner.key, pss: {} },
    { algorithmProtection: true });
  var vPss = await pki.cms.verify(pssSigned, { certs: [pssSigner.cert] });
  check("AP-3 an RSASSA-PSS signature carrying the attribute verifies",
    vPss.signers[0].ok === true && vPss.signers[0].algorithmProtection.compared.length === 2);

  // AP-3b: RFC 6211 sec. 3 on how the two identifiers are compared: "A field with a default value
  // MUST compare as identical, independently of whether the value is defaulted or is explicitly
  // provided.  This implies that a binary compare of the encoded bytes is insufficient." RSASSA-PSS
  // is where that bites, since RFC 4055 sec. 3.1 gives each of its four parameter fields a default.
  // The SignerInfo's own signatureAlgorithm is spliced, not the attribute: the signature covers the
  // signed attributes and not that field, which is the exposure the attribute exists to close, so
  // the fixture stays cryptographically valid and the only difference is the encoding of a
  // defaulted field.
  function withExplicitTrailerField(cmsDer) {
    var root = pki.asn1.decode(cmsDer);
    var sd = root.children[1].children[0];
    var siSet = sd.children[sd.children.length - 1];
    var si = siSet.children[0];
    var algIdx = si.children.length - 2;                     // ..., signatureAlgorithm, signature
    var sigAlg = si.children[algIdx];
    var params = pki.asn1.decode(sigAlg.children[1].bytes);
    var fields = params.children.map(function (f) { return f.bytes; });
    fields.push(b.contextConstructed(3, b.integer(1)));      // trailerField, explicitly its DEFAULT
    var spliced = b.sequence([sigAlg.children[0].bytes, b.sequence(fields)]);
    var siKids = si.children.map(function (k, i) { return i === algIdx ? spliced : k.bytes; });
    var sdKids = sd.children.map(function (k, i) {
      return i === sd.children.length - 1 ? b.set([b.sequence(siKids)]) : k.bytes;
    });
    return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
  }
  var pssDefaulted = withExplicitTrailerField(pssSigned);
  var vPssDefaulted = await pki.cms.verify(pssDefaulted, { certs: [pssSigner.cert] });
  check("AP-3b a defaulted field compares the same written out as omitted",
    vPssDefaulted.signers[0].ok === true &&
    vPssDefaulted.signers[0].algorithmProtection.mismatch === null &&
    vPssDefaulted.signers[0].algorithmProtection.compared.indexOf("signatureAlgorithm") !== -1);
  check("AP-3b CONTROL the splice really changed the bytes the comparison reads",
    !pssDefaulted.equals(pssSigned));
  // The leniency is for the defaulted VALUE alone: a field carrying anything else is the
  // substitution this attribute exists to catch.
  function withSaltLength(cmsDer, len) {
    var root = pki.asn1.decode(cmsDer);
    var sd = root.children[1].children[0];
    var si = sd.children[sd.children.length - 1].children[0];
    var algIdx = si.children.length - 2;
    var sigAlg = si.children[algIdx];
    var params = pki.asn1.decode(sigAlg.children[1].bytes);
    var fields = params.children.map(function (f) {
      return (f.tagClass === "context" && f.tagNumber === 2) ? b.contextConstructed(2, b.integer(len)) : f.bytes;
    });
    var spliced = b.sequence([sigAlg.children[0].bytes, b.sequence(fields)]);
    var siKids = si.children.map(function (k, i) { return i === algIdx ? spliced : k.bytes; });
    var sdKids = sd.children.map(function (k, i) {
      return i === sd.children.length - 1 ? b.set([b.sequence(siKids)]) : k.bytes;
    });
    return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(sdKids))]);
  }
  var vPssSalt = await pki.cms.verify(withSaltLength(pssSigned, 48), { certs: [pssSigner.cert] });
  check("AP-3b and a non-default value in the same field is still a mismatch",
    vPssSalt.signers[0].ok === false &&
    vPssSalt.signers[0].algorithmProtection.mismatch !== null &&
    vPssSalt.signers[0].algorithmProtection.mismatch.code === "cms/algorithm-protection-mismatch" &&
    vPssSalt.signers[0].algorithmProtection.compared.indexOf("signatureAlgorithm") === -1);

  // AP-4: a countersignature is its own SignerInfo and inherits the check.
  var countersigned = await pki.cms.countersign(signed, SIGNER, { algorithmProtection: true });
  var vCs = await pki.cms.verify(countersigned, { certs: [signer.cert] });
  check("AP-4 a countersignature carrying the attribute verifies with its own comparison",
    vCs.signers[0].ok === true && vCs.signers[0].countersignatures[0].ok === true &&
    vCs.signers[0].countersignatures[0].algorithmProtection.compared.length === 2);

  // ---- absent arms --------------------------------------------------------------------------
  // AP-7: absence is not failure by default (RFC 8933 sec. 4.1 makes inclusion a SHOULD), and the
  // verdict distinguishes "not present" from "compared".
  var plain = await pki.cms.sign(CONTENT, SIGNER);
  var vPlain = await pki.cms.verify(plain, { certs: [signer.cert] });
  check("AP-7 a signature without the attribute verifies, and says so",
    vPlain.signers[0].ok === true &&
    vPlain.signers[0].algorithmProtection.present === false &&
    vPlain.signers[0].algorithmProtection.compared.length === 0);

  // AP-8: the opt-in makes absence a failure.
  var vStrict = await pki.cms.verify(plain, { certs: [signer.cert], requireAlgorithmProtection: true });
  check("AP-8 under requireAlgorithmProtection an absent attribute fails",
    vStrict.signers[0].ok === false &&
    vStrict.signers[0].code === "cms/missing-algorithm-protection");
  var vStrictOk = await pki.cms.verify(signed, { certs: [signer.cert], requireAlgorithmProtection: true });
  check("AP-8 CONTROL the same option on a signature that carries it reports ok",
    vStrictOk.signers[0].ok === true);

  // AP-9: a SignerInfo with no signedAttrs has nowhere to carry it, and D1's SHOULD is conditioned on
  // signed attributes being present. The option still refuses, because an operator who requires the
  // protection is asking for a signature that carries it.
  var attrless = await pki.cms.sign(CONTENT, SIGNER, { signedAttributes: false });
  var vAttrless = await pki.cms.verify(attrless, { certs: [signer.cert], requireAlgorithmProtection: true });
  check("AP-9 a signature with no signed attributes cannot satisfy the option",
    vAttrless.signers[0].ok === false &&
    vAttrless.signers[0].code === "cms/missing-algorithm-protection");
  var vAttrlessDefault = await pki.cms.verify(attrless, { certs: [signer.cert] });
  check("AP-9 CONTROL and verifies without the option",
    vAttrlessDefault.signers[0].ok === true &&
    vAttrlessDefault.signers[0].algorithmProtection.present === false);

  // AP-10: RFC 8933 sec. 4.1's SHOULD, and the same SHOULD in RFC 9882 sec. 4 and RFC 9814 sec. 5
  // for the post-quantum signature families, reported as a lint notice rather than a refusal.
  var apIds = function (rep) {
    return rep.findings.filter(function (f) { return f.id === "lint/rfc8933/algorithm-protection-absent"; });
  };
  check("AP-10 the absent attribute draws a lint notice on a signer that has signed attributes",
    apIds(pki.lint.cms(plain)).length === 1 && apIds(pki.lint.cms(plain))[0].severity === "notice");
  check("AP-10 CONTROL a signature carrying it draws none",
    apIds(pki.lint.cms(signed)).length === 0);
  // The registry reads a row's source as a selectable profile name, so RFC 8933 updating RFC 5652
  // means its own profile: asking for "rfc8933" runs this row, and asking for "rfc5652" does not
  // claim a requirement that document does not state.
  // RFC 8933 sec. 4.1 states the requirement twice, and the second sentence is the authenticated
  // data one: "Likewise, the originator of an authenticated-data content type that includes
  // authenticated attributes SHOULD include the CMSAlgorithmProtection attribute [RFC6211] as one
  // of the authenticated attributes." That is the content type whose algorithm fields nothing else
  // covers, so a row reading only signed-data would miss the widest exposure.
  var apKek = Buffer.alloc(32, 0x5a);
  var apAuthRecipient = [{ kek: apKek, kekId: Buffer.from("k") }];
  var authNoAp = await pki.cms.authenticate(CONTENT, apAuthRecipient);
  var authWithAp = await pki.cms.authenticate(CONTENT, apAuthRecipient, { algorithmProtection: true });
  var authNoAttrs = await pki.cms.authenticate(CONTENT, apAuthRecipient, { authenticatedAttributes: false });
  check("AP-10 an AuthenticatedData with authenticated attributes and no such attribute draws the notice",
    apIds(pki.lint.cms(authNoAp)).length === 1 &&
    apIds(pki.lint.cms(authNoAp))[0].severity === "notice" &&
    apIds(pki.lint.cms(authNoAp, { profile: "rfc8933" })).length === 1);
  check("AP-10 CONTROL one carrying it draws none, and one with no authenticated attributes draws none",
    apIds(pki.lint.cms(authWithAp)).length === 0 &&
    apIds(pki.lint.cms(authNoAttrs)).length === 0);
  check("AP-10 the row is registered against the document that states the requirement",
    pki.lint.rules().filter(function (r) {
      return r.id === "lint/rfc8933/algorithm-protection-absent";
    })[0].source === "rfc8933" &&
    pki.lint.profiles().indexOf("rfc8933") !== -1 &&
    pki.lint.rules("rfc8933", "cms").map(function (r) { return r.id; }).join() ===
      "lint/rfc8933/algorithm-protection-absent" &&
    apIds(pki.lint.cms(plain, { profile: "rfc8933" })).length === 1 &&
    apIds(pki.lint.cms(plain, { profile: "rfc5652" })).length === 0);

  // AP-6b: only the two documented identifiers are selectable. A truthy value read as the default
  // would emit the RFC 6211 identifier to a caller who asked for the registry one, and a mismatched
  // identifier is equivalent to no protection at all, so a misspelling has to be a refusal.
  var badChoices = ["regsitry", "REGISTRY", 1, {}, "true"];
  var signRefused = true;
  var authRefused = true;
  for (var bc = 0; bc < badChoices.length; bc++) {
    if ((await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: badChoices[bc] }))) !== "cms/bad-input") signRefused = false;
    if ((await codeOf(pki.cms.authenticate(CONTENT, [{ kek: Buffer.alloc(32, 0x33), kekId: Buffer.from("k") }],
      { algorithmProtection: badChoices[bc] }))) !== "cms/bad-input") authRefused = false;
  }
  check("AP-6b an algorithmProtection value other than true or \"registry\" is refused by sign",
    signRefused);
  check("AP-6b and by authenticate", authRefused);
  check("AP-6b and by countersign",
    (await codeOf(pki.cms.countersign(signed, SIGNER, { algorithmProtection: "regsitry" }))) === "cms/bad-input");
  check("AP-6b CONTROL the documented off forms are absence rather than a bad value",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: false }))) === "NO-THROW" &&
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: null }))) === "NO-THROW" &&
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: undefined }))) === "NO-THROW");
  // Any other falsy value is a configuration fault, not an off form: a caller who wrote one asked
  // for the attribute and would otherwise get a message carrying none, with nothing said. The
  // resolver owns the whole value domain, so the refusal holds on the route that cannot place the
  // attribute at all, where the emission branch is never reached.
  var offJunk = ["", 0, NaN];
  var offRefused = true;
  var offRefusedBare = true;
  for (var oj = 0; oj < offJunk.length; oj++) {
    if ((await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: offJunk[oj] }))) !== "cms/bad-input") offRefused = false;
    if ((await codeOf(pki.cms.sign(CONTENT, SIGNER,
      { signedAttributes: false, algorithmProtection: offJunk[oj] }))) !== "cms/bad-input") offRefusedBare = false;
  }
  check("AP-6b a falsy value other than false is refused rather than read as absence", offRefused);
  // The value is read at the door, before the content is. A streamed content is consumed and hashed
  // to build the attributes, so an option read only where the attributes are built is a refusal
  // that arrives after the stream has been drained: for one that cannot be replayed the caller
  // cannot act on it, and for one that never ends it never arrives at all.
  var drawn = 0;
  var countingStream = (async function* () { drawn += 1; yield CONTENT; })();
  var streamRefusal = await codeOf(pki.cms.sign(countingStream, SIGNER,
    { detached: true, algorithmProtection: "typo" }));
  check("AP-6b and a streamed content is not read before the option is (" +
    streamRefusal + ", chunks drawn " + drawn + ")",
    streamRefusal === "cms/bad-input" && drawn === 0);
  check("AP-6b CONTROL the same stream signs when the option is one of the two documented values",
    (await codeOf(pki.cms.sign((async function* () { yield CONTENT; })(), SIGNER,
      { detached: true, algorithmProtection: "registry" }))) === "NO-THROW");
  // The authenticate verb reads it at its own door too, ahead of hashing the content and wrapping
  // each recipient's key. Observed through two refusals that cannot both be reported: a key-encryption
  // key of an unusable length is refused where the recipients are built, so an option read after
  // that point would answer with the key's message instead of its own.
  var unusableKek = [{ kek: Buffer.alloc(7, 0x01), kekId: Buffer.from("k") }];
  var kekFirst = await messageOf(pki.cms.authenticate(CONTENT, unusableKek));
  var optionFirst = await messageOf(pki.cms.authenticate(CONTENT, unusableKek, { algorithmProtection: "typo" }));
  check("AP-6b and the authenticate verb reads the option before it reaches the recipients",
    kekFirst.indexOf("key-encryption key") !== -1 &&
    optionFirst.indexOf("algorithmProtection is true for the identifier") === 0);
  // The door resolves the option and the emitter reads it again, which is only sound because an
  // option supplied through an accessor never arrives: the options door refuses one, own or
  // inherited, before any value is read. Two reads of a plain field answer the same.
  var accessorReads = 0;
  var accessorOpts = {};
  Object.defineProperty(accessorOpts, "algorithmProtection", {
    enumerable: true, configurable: true,
    get: function () { accessorReads += 1; return accessorReads === 1 ? true : "registry"; },
  });
  var inheritedOpts = Object.create(accessorOpts);
  check("AP-6b an option supplied through an accessor is refused before it is read at all",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, accessorOpts))) === "cms/bad-input" &&
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, inheritedOpts))) === "cms/bad-input" &&
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: Buffer.alloc(32, 0x11), kekId: Buffer.from("k") }],
      accessorOpts))) === "cms/bad-input" &&
    accessorReads === 0);
  check("AP-6b and on the route that signs the content directly", offRefusedBare);
  check("AP-6b CONTROL signedAttributes: false with the attribute asked for names the conflict",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { signedAttributes: false, algorithmProtection: true }))) === "cms/bad-input");

  // AP-6c: the verifier's and the decrypter's requirement switch is read the same way. This is the
  // direction that costs the caller the control they asked for: "true" out of a config file is
  // truthy to JavaScript and unequal to true, so a boundary comparing against true verifies with
  // the requirement off and reports a signer as ok.
  var reqJunk = ["true", "false", 1, 0, {}];
  var verifyRefused = true;
  for (var rj = 0; rj < reqJunk.length; rj++) {
    if ((await codeOf(pki.cms.verify(plain, { certs: [signer.cert], requireAlgorithmProtection: reqJunk[rj] }))) !== "cms/bad-input") verifyRefused = false;
  }
  check("AP-6c a non-boolean requireAlgorithmProtection is refused by verify", verifyRefused);
  check("AP-6c CONTROL the documented values still decide the verdict",
    (await pki.cms.verify(plain, { certs: [signer.cert], requireAlgorithmProtection: true })).signers[0].ok === false &&
    (await pki.cms.verify(plain, { certs: [signer.cert], requireAlgorithmProtection: false })).signers[0].ok === true &&
    (await pki.cms.verify(plain, { certs: [signer.cert], requireAlgorithmProtection: null })).signers[0].ok === true);
  check("AP-10 CONTROL and a signer that signs the content directly draws none, the SHOULD being " +
    "conditioned on signed attributes being present",
  apIds(pki.lint.cms(attrless)).length === 0);

  // AP-8e: copying the trust material reads each anchor, and that read runs the caller's code when
  // an anchor carries accessors. The requirement is read before any of that, so an accessor that
  // clears it cannot answer for the call: the same message without the attribute still fails.
  var trustTuple = pki.path.anchorFromCert(signer.cert);
  var trustFlipReads = 0;
  var trustAnchorFlip = { name: trustTuple.name, algorithm: trustTuple.algorithm };
  var trustFlipOpts = { certs: [signer.cert], requireAlgorithmProtection: true };
  Object.defineProperty(trustAnchorFlip, "publicKey", {
    get: function () { trustFlipReads += 1; trustFlipOpts.requireAlgorithmProtection = false; return trustTuple.publicKey; },
    enumerable: true, configurable: true,
  });
  trustFlipOpts.trustAnchors = [trustAnchorFlip];
  var vTrustFlip = await pki.cms.verify(plain, trustFlipOpts);
  check("AP-8e the requirement is read before the trust material is copied, so an anchor accessor " +
    "cannot clear it",
    trustFlipReads > 0 && vTrustFlip.signers[0].ok === false &&
    vTrustFlip.signers[0].code === "cms/missing-algorithm-protection");
  check("AP-8e CONTROL the same anchor without the option verifies the signer",
    (await pki.cms.verify(plain, { certs: [signer.cert],
      trustAnchors: [{ name: trustTuple.name, publicKey: trustTuple.publicKey, algorithm: trustTuple.algorithm }] })).signers[0].ok === true);

  // AP-8c: the policy is the one the call was made with. A streamed detached content is the one
  // place a caller's own code runs while verification is pending, so an option read inside the
  // per-signer loop is an option the caller can still change; the generator below flips it the way
  // a hostile or merely careless caller would.
  var detached = await pki.cms.sign(CONTENT, SIGNER, { detached: true });
  var flipOpts = { certs: [signer.cert], requireAlgorithmProtection: true };
  flipOpts.content = (async function* () {
    flipOpts.requireAlgorithmProtection = false;
    yield CONTENT;
  })();
  var vFlipped = await pki.cms.verify(detached, flipOpts);
  check("AP-8c the requirement is the one the call was made with, not the one a stream left behind",
    vFlipped.signers[0].ok === false &&
    vFlipped.signers[0].code === "cms/missing-algorithm-protection");
  check("AP-8c CONTROL the same message under the option set to false from the start verifies",
    (await pki.cms.verify(detached, { certs: [signer.cert], content: CONTENT,
      requireAlgorithmProtection: false })).signers[0].ok === true);

  // AP-9b: an explicitly requested protection that cannot be emitted is a refusal, not a silently
  // unprotected message. With no signed attributes there is nowhere to put it, which is why
  // RFC 8933 sec. 4.1's SHOULD is conditioned on their presence.
  check("AP-9b signedAttributes: false with algorithmProtection: true is refused by sign",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER,
      { signedAttributes: false, algorithmProtection: true }))) === "cms/bad-input");
  check("AP-9b and by countersign",
    (await codeOf(pki.cms.countersign(signed, SIGNER,
      { signedAttributes: false, algorithmProtection: true }))) === "cms/bad-input");
  check("AP-9b CONTROL each option on its own is accepted",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { signedAttributes: false }))) === "NO-THROW" &&
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: true }))) === "NO-THROW");

  // AP-8b: a countersignature is a signer with its own algorithm identifiers, so a policy that
  // requires the attribute applies to it as well. Checking only the primary signature would let a
  // countersignature carrying none pass under the option that asked for one.
  var csPlain = await pki.cms.countersign(signed, SIGNER);
  var vCsStrict = await pki.cms.verify(csPlain,
    { certs: [signer.cert], content: CONTENT, requireAlgorithmProtection: true });
  check("AP-8b requireAlgorithmProtection reaches a countersignature row",
    vCsStrict.signers[0].ok === true &&
    vCsStrict.signers[0].countersignatures[0].ok === false &&
    vCsStrict.signers[0].countersignatures[0].code === "cms/missing-algorithm-protection");
  var csBoth = await pki.cms.countersign(signed, SIGNER, { algorithmProtection: true });
  var vCsBoth = await pki.cms.verify(csBoth,
    { certs: [signer.cert], content: CONTENT, requireAlgorithmProtection: true });
  check("AP-8b CONTROL a countersignature that carries it satisfies the option",
    vCsBoth.signers[0].ok === true && vCsBoth.signers[0].countersignatures[0].ok === true);

  // ---- disagreement arms, one per protected field --------------------------------------------
  // AP-11 CONTROL first: a foreign message whose attribute agrees verifies, which is what makes the
  // refusals below attributable to the comparison and to nothing else about the fixture.
  var foreignOk = foreignSignedData(signer, [attr(OID_PKCS9,
    [protection(algId("sha256"), algId("ecdsaWithSHA256"), 1)])]);
  var vForeignOk = await pki.cms.verify(foreignOk, { certs: [signer.cert] });
  check("AP-11 CONTROL a hand-built message whose attribute agrees verifies, comparisons run",
    vForeignOk.signers[0].ok === true &&
    vForeignOk.signers[0].algorithmProtection.compared.length === 2);

  // AP-11: the digest OID disagrees. RFC 6211 sec. 3.1: "If the fields are not the same (modulo
  // encoding), then signature validation MUST fail." The signature here is sound, so the comparison
  // is the only thing that can refuse the message.
  var vWrongDigest = await pki.cms.verify(foreignSignedData(signer,
    [attr(OID_PKCS9, [protection(algId("sha512"), algId("ecdsaWithSHA256"), 1)])]),
  { certs: [signer.cert] });
  check("AP-11 a digestAlgorithm naming another algorithm fails a sound signature",
    vWrongDigest.signers[0].ok === false &&
    vWrongDigest.signers[0].code === "cms/algorithm-protection-mismatch");

  // AP-13: the signature arm disagrees.
  var vWrongSig = await pki.cms.verify(foreignSignedData(signer,
    [attr(OID_PKCS9, [protection(algId("sha256"), algId("ecdsaWithSHA512"), 1)])]),
  { certs: [signer.cert] });
  check("AP-13 a signatureAlgorithm naming another algorithm fails a sound signature",
    vWrongSig.signers[0].ok === false &&
    vWrongSig.signers[0].code === "cms/algorithm-protection-mismatch");

  // AP-11b: the mismatch message names an identifier the registry has no name for by its OID, since
  // an attribute can name any algorithm and a verdict an operator reads has to say which.
  var vUnnamed = await pki.cms.verify(foreignSignedData(signer,
    [attr(OID_PKCS9, [b.sequence([b.sequence([b.oid("1.2.3.4.5.6.7")]),
      b.contextConstructed(1, algId("ecdsaWithSHA256").slice(2))])])]),
  { certs: [signer.cert] });
  check("AP-11b an unregistered digest OID is named by its OID in the mismatch",
    vUnnamed.signers[0].ok === false &&
    vUnnamed.signers[0].code === "cms/algorithm-protection-mismatch" &&
    vUnnamed.signers[0].message.indexOf("1.2.3.4.5.6.7") !== -1);
  var vUnnamedArm = await pki.cms.verify(foreignSignedData(signer,
    [attr(OID_PKCS9, [b.sequence([algId("sha256"),
      b.contextConstructed(1, b.sequence([b.oid("1.2.3.4.5.6.8")]).slice(2))])])]),
  { certs: [signer.cert] });
  check("AP-11b and so is an unregistered signature OID on the arm",
    vUnnamedArm.signers[0].code === "cms/algorithm-protection-mismatch" &&
    vUnnamedArm.signers[0].message.indexOf("1.2.3.4.5.6.8") !== -1);

  // AP-16: the signature arm compares EXACTLY and does not inherit the digest arm's RFC 5754 grant.
  // An `ecdsaWith*` identifier is refused outright for carrying parameters (RFC 5758, enforced by
  // the shared decoder), so the pair that reaches a comparison is an RSA one: RFC 4055 requires
  // `sha256WithRSAEncryption` to carry a NULL, and an arm that omits it is a different identifier
  // rather than the same one spelled differently.
  var rsaSigner = signing.makeSigner("rsa");
  var rsaSigAlg = algId("sha256WithRSAEncryption", b.nullValue());
  var vNullParamSig = await pki.cms.verify(foreignSignedData(rsaSigner,
    [attr(OID_PKCS9, [protection(algId("sha256"), algId("sha256WithRSAEncryption"), 1)])], rsaSigAlg),
  { certs: [rsaSigner.cert] });
  check("AP-16 the signature arm compares parameters exactly, so an omitted NULL is a mismatch",
    vNullParamSig.signers[0].ok === false &&
    vNullParamSig.signers[0].code === "cms/algorithm-protection-mismatch");
  var vRsaOk = await pki.cms.verify(foreignSignedData(rsaSigner,
    [attr(OID_PKCS9, [protection(algId("sha256"), rsaSigAlg, 1)])], rsaSigAlg),
  { certs: [rsaSigner.cert] });
  check("AP-16 CONTROL the same identifier spelled the same way on both sides verifies",
    vRsaOk.signers[0].ok === true && vRsaOk.signers[0].algorithmProtection.compared.length === 2);

  // AP-12: the digest arm follows RFC 3370 sec. 2.1 and RFC 5754 sec. 2, which require both
  // spellings to be accepted, so absent and DER NULL compare equal there. This is the one judgment
  // RFC 6211 sec. 3 leaves to the implementer, pinned in both directions with AP-16.
  var vNullParamDigest = await pki.cms.verify(foreignSignedData(signer,
    [attr(OID_PKCS9, [protection(algId("sha256", b.nullValue()), algId("ecdsaWithSHA256"), 1)])]),
  { certs: [signer.cert] });
  check("AP-12 the digest arm reads absent and DER NULL as one algorithm",
    vNullParamDigest.signers[0].ok === true &&
    vNullParamDigest.signers[0].algorithmProtection.compared.length === 2);

  // ---- cardinality arms ---------------------------------------------------------------------
  // AP-20 / AP-21: "There MUST NOT be zero or multiple instances of AttributeValue present"
  // (RFC 6211 sec. 2). A second value is a smuggling slot, and DER SET-OF ordering puts its position
  // under the producer's control, so both orders are driven.
  var good = protection(algId("sha256"), algId("ecdsaWithSHA256"), 1);
  var evil = protection(algId("sha512"), algId("ecdsaWithSHA512"), 1);
  // Zero values is already the generic `Attribute` rule, `attrValues SET SIZE (1..MAX)`, so it is
  // refused before the per-type arm reads anything. The vector pins that the two rules do not leave
  // a gap between them rather than asserting a code this attribute owns.
  check("AP-20 an attribute with zero values is refused at parse by the SET SIZE (1..MAX) rule",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, []), "cmsAlgorithmProtection"));
    }) === "cms/bad-attribute-values");
  check("AP-21 two values are refused, in either DER order",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [good, evil]), "cmsAlgorithmProtection"));
    }) === "cms/bad-algorithm-protection-attr" &&
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [evil, good]), "cmsAlgorithmProtection"));
    }) === "cms/bad-algorithm-protection-attr");
  check("AP-21 CONTROL one value parses",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [good]), "cmsAlgorithmProtection"));
    }) === "NO-THROW");

  // AP-22: "The SignedAttributes in a signerInfo MUST include only one instance of the algorithm
  // protection attribute" (RFC 6211 sec. 2). Two Attribute members of one type are legal DER, so a
  // reader stopping at the first match can be steered.
  var twoInstances = withSignedAttr(withSignedAttr(signed, attr(OID_PKCS9, [good]), "cmsAlgorithmProtection"),
    attr(OID_REGISTRY, [evil]), null);
  check("AP-22 two instances in one signedAttrs are refused, across the two OID spellings",
    codeOfSync(function () { pki.schema.cms.parse(twoInstances); }) === "cms/duplicate-signed-attr");

  // ---- placement arms -----------------------------------------------------------------------
  // AP-27: "it MUST NOT be an unsigned attribute" (RFC 6211 sec. 2), and sec. 5 says such an
  // instance provides no additional security.
  check("AP-27 the attribute in unsignedAttrs is refused at parse",
    codeOfSync(function () {
      pki.schema.cms.parse(withUnsignedAttr(signed, attr(OID_PKCS9, [good])));
    }) === "cms/misplaced-attr");

  // AP-27b: the producer refuses the placement its own parser refuses. RFC 6211 sec. 2: the
  // attribute "MUST NOT be an unsigned attribute". Without this door `unsignedAttributes` would
  // emit a message this package's own verifier then rejects with cms/misplaced-attr, which is a
  // message no caller can use and one only the producer can prevent.
  check("AP-27b the unsignedAttributes door refuses the attribute, under both identifiers",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER,
      { unsignedAttributes: [{ type: "cmsAlgorithmProtection", values: [good] }] }))) === "cms/bad-input" &&
    (await codeOf(pki.cms.sign(CONTENT, SIGNER,
      { unsignedAttributes: [{ type: "cmsAlgorithmProtect", values: [good] }] }))) === "cms/bad-input");
  check("AP-27b CONTROL an unsigned attribute the RFC does allow there is still accepted",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER,
      { unsignedAttributes: [{ type: "timeStampToken", values: [b.octetString(Buffer.from("t"))] }] }))) === "NO-THROW");

  // AP-30: an instance where nothing covers it satisfies no policy that requires the attribute.
  // Reaching the policy means the parse admitted it, which it does not, so the refusal IS the answer
  // and this vector pins that the two rules do not contradict each other.
  check("AP-30 a message cannot carry it unsigned at all, so no policy is satisfied that way",
    codeOfSync(function () {
      pki.schema.cms.parse(withUnsignedAttr(plain, attr(OID_PKCS9, [good])));
    }) === "cms/misplaced-attr");

  // ---- cross-arm arms -----------------------------------------------------------------------
  // AP-33: "This field is populated only if the attribute is placed in an AuthenticatedData.authAttrs
  // sequence" (RFC 6211 sec. 2, macAlgorithm). A [2] arm inside signedAttrs protects nothing the
  // SignerInfo has, so it fails closed rather than being read as an absent signature arm.
  var vMacArm = await pki.cms.verify(foreignSignedData(signer,
    [attr(OID_PKCS9, [protection(algId("sha256"), algId("hmacWithSHA256"), 2)])]),
  { certs: [signer.cert] });
  check("AP-33 a [2] MAC arm inside signedAttrs is a mismatch, not an ignored field",
    vMacArm.signers[0].ok === false &&
    vMacArm.signers[0].code === "cms/algorithm-protection-mismatch");

  // ---- strict-DER and shape arms ------------------------------------------------------------
  // AP-34 / AP-35: "Exactly one of signatureAlgorithm or macAlgorithm SHALL be present."
  var bothArms = b.sequence([algId("sha256"),
    b.contextConstructed(1, algId("ecdsaWithSHA256").slice(2)),
    b.contextConstructed(2, algId("hmacWithSHA256").slice(2))]);
  var neitherArm = b.sequence([algId("sha256")]);
  check("AP-34 both arms present is refused",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [bothArms]), "cmsAlgorithmProtection"));
    }) === "cms/bad-algorithm-protection-attr");
  check("AP-35 neither arm present is refused",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [neitherArm]), "cmsAlgorithmProtection"));
    }) === "cms/bad-algorithm-protection-attr");

  // AP-36: a trailing third element. The SEQUENCE is exactly two elements, which is the size check
  // Bouncy Castle enforces.
  var threeElements = b.sequence([algId("sha256"),
    b.contextConstructed(1, algId("ecdsaWithSHA256").slice(2)), algId("sha512")]);
  check("AP-36 a third element is refused",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [threeElements]), "cmsAlgorithmProtection"));
    }) !== "NO-THROW");

  // AP-37 / AP-38: the Appendix A module is DEFINITIONS IMPLICIT TAGS, so the arm is the implicit
  // 0xA1 holding the identifier's own content, not an explicit wrapper and not an untagged SEQUENCE.
  var explicitArm = b.sequence([algId("sha256"), b.explicit(1, algId("ecdsaWithSHA256"))]);
  var untaggedArm = b.sequence([algId("sha256"), algId("ecdsaWithSHA256")]);
  check("AP-37 an EXPLICIT [1] arm is refused",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [explicitArm]), "cmsAlgorithmProtection"));
    }) !== "NO-THROW");
  check("AP-38 an untagged second element is refused",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [untaggedArm]), "cmsAlgorithmProtection"));
    }) !== "NO-THROW");

  // AP-39: the inner identifier is held to the shared decoder's own rules.
  var junkInner = b.sequence([algId("sha256"), b.contextConstructed(1, Buffer.from([0x02, 0x01, 0x05]))]);
  check("AP-39 a malformed inner AlgorithmIdentifier is refused by the shared decoder",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, attr(OID_PKCS9, [junkInner]), "cmsAlgorithmProtection"));
    }) !== "NO-THROW");

  // ---- the producer door --------------------------------------------------------------------
  // AP-24 / AP-25: a caller-supplied copy cannot contradict the fields the verb emits, and cannot be
  // a second instance beside the verb's own. `additionalSignedAttributes` reaches the wire unparsed,
  // so this is the producer hole the attribute would otherwise leave open.
  check("AP-24 a caller-supplied copy beside the verb's own emission is refused",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER, { algorithmProtection: true,
      additionalSignedAttributes: [{ type: "cmsAlgorithmProtection", values: [good] }] }))) === "cms/bad-input");
  check("AP-25 a caller-supplied copy naming other algorithms is refused",
    (await codeOf(pki.cms.sign(CONTENT, SIGNER,
      { additionalSignedAttributes: [{ type: "cmsAlgorithmProtection", values: [evil] }] }))) === "cms/bad-input");
  var agreeing = await pki.cms.sign(CONTENT, SIGNER,
    { additionalSignedAttributes: [{ type: "cmsAlgorithmProtection", values: [good] }] });
  check("AP-25 CONTROL a caller-supplied copy that agrees with the emitted fields is admitted",
    (await pki.cms.verify(agreeing, { certs: [signer.cert] })).signers[0].ok === true);

  // ---- the AuthenticatedData arm, where the attack needs no key -----------------------------
  var kek = Buffer.alloc(32, 0x33);
  var authed = await pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
    { algorithmProtection: true });
  var authParsed = pki.schema.cms.parse(authed);
  var authAttr = (authParsed.authAttrs || []).filter(function (a) { return a.type === OID_PKCS9; })[0];
  check("AP-5 the authenticate verb emits the [2] MAC arm and no [1] arm",
    authAttr !== undefined &&
    pki.schema.cms.parseAlgorithmProtection(authAttr.values[0]).macAlgorithm !== null &&
    pki.schema.cms.parseAlgorithmProtection(authAttr.values[0]).signatureAlgorithm === null);
  var opened = await pki.cms.decrypt(authed, { kek: kek });
  check("AP-5 and the message authenticates with both comparisons run",
    opened.authenticated === true &&
    opened.algorithmProtection.compared.indexOf("digestAlgorithm") !== -1 &&
    opened.algorithmProtection.compared.indexOf("macAlgorithm") !== -1);

  // AP-19: the attack of RFC 8933 sec. 6, which needs no key. RFC 5652 sec. 9.2 makes the MAC input
  // the DER encoding of `authAttrs` alone, so the outer digestAlgorithm is covered by nothing:
  // rewriting it leaves the MAC verifying and has the recipient recompute the content digest under
  // the algorithm the attacker chose. The copy inside authAttrs is what refuses it.
  var substituted = withOuterDigest(authed, "sha512");
  check("AP-19 a rewritten outer digestAlgorithm is refused by the comparison",
    (await codeOf(pki.cms.decrypt(substituted, { kek: kek }))) === "cms/algorithm-protection-mismatch");
  var plainAuthed = await pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }], {});
  check("AP-19 PREMISE the same rewrite on a message without the attribute is NOT caught by the " +
    "MAC, which is what makes the attribute the only thing that stops it",
  (await codeOf(pki.cms.decrypt(withOuterDigest(plainAuthed, "sha512"), { kek: kek }))) !== "cms/algorithm-protection-mismatch");
  check("AP-19 CONTROL the message before the rewrite authenticates",
    (await pki.cms.decrypt(authed, { kek: kek })).authenticated === true);

  // AP-18: the [2] arm against the outer macAlgorithm, which sits outside the MAC input too, so
  // without the attribute the attacker chooses which MAC algorithm the recipient runs.
  check("AP-18 a rewritten outer macAlgorithm is refused by the comparison",
    (await codeOf(pki.cms.decrypt(withOuterMac(authed, "hmacWithSHA384"), { kek: kek }))) === "cms/algorithm-protection-mismatch");

  // AP-8 on this content type: the opt-in refuses an absent attribute here too.
  check("AP-8 requireAlgorithmProtection refuses an AuthenticatedData without the attribute",
    (await codeOf(pki.cms.decrypt(plainAuthed, { kek: kek }, { requireAlgorithmProtection: true })))
      === "cms/missing-algorithm-protection");
  check("AP-8 CONTROL and admits one that carries it",
    (await pki.cms.decrypt(authed, { kek: kek }, { requireAlgorithmProtection: true })).authenticated === true);
  // AP-9 on this content type: an AuthenticatedData with no authenticated attributes has nowhere to
  // carry the attribute, and the option refuses it rather than passing over the structure that
  // cannot satisfy it. The MAC then covers the content octets directly and the two outer algorithm
  // fields are covered by nothing at all, which is the case the option exists for.
  var bareAuthed = await pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
    { authenticatedAttributes: false });
  check("AP-9 an AuthenticatedData with no authenticated attributes cannot satisfy the option",
    (await codeOf(pki.cms.decrypt(bareAuthed, { kek: kek }, { requireAlgorithmProtection: true })))
      === "cms/missing-algorithm-protection");
  check("AP-9 CONTROL and it authenticates without the option",
    (await pki.cms.decrypt(bareAuthed, { kek: kek })).authenticated === true);
  // AP-26b: the parser refuses in an AuthEnvelopedData what the emitting verbs refuse to put there.
  // RFC 6211 sec. 2 populates the macAlgorithm arm "only if the attribute is placed in an
  // AuthenticatedData.authAttrs sequence", and RFC 8933 sec. 6 says the attribute protects nothing
  // in an AuthEnvelopedData, which has no digest or MAC algorithm field for a copy to name. Our own
  // verb will not emit one there, so the fixture is spliced: a message from another producer is the
  // only way this set carries the attribute, and the cardinality and value rules below it would
  // otherwise never be asked.
  var aeadBase = await pki.cms.encrypt(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
    { contentEncryptionAlgorithm: "aes-256-gcm" });
  function withAuthEnvelopedAttr(cmsDer, attrTlv) {
    var root = pki.asn1.decode(cmsDer);
    var aed = root.children[1].children[0];
    var kids = [];
    aed.children.forEach(function (c, i) {
      kids.push(c.bytes);
      var next = aed.children[i + 1];
      if (c.tagClass === "universal" && c.tagNumber === 16 && next && next.tagNumber === 4) {
        kids.push(b.contextConstructed(1, attrTlv));   // [1] authAttrs, ahead of the mac
      }
    });
    return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(kids))]);
  }
  var aeadDigestOnly = b.sequence([algId("sha256")]);       // a value with neither arm, which sec. 2 forbids
  var aeadSpliced = withAuthEnvelopedAttr(aeadBase, attr(OID_PKCS9, [aeadDigestOnly]));
  check("AP-26b the attribute is refused in an AuthEnvelopedData's authenticated attributes",
    codeOfSync(function () { pki.schema.cms.parse(aeadSpliced); }) === "cms/misplaced-attr");
  check("AP-26b and under the registry identifier as well",
    codeOfSync(function () {
      pki.schema.cms.parse(withAuthEnvelopedAttr(aeadBase, attr(OID_REGISTRY, [aeadDigestOnly])));
    }) === "cms/misplaced-attr");
  check("AP-26b CONTROL the same message parses with that attribute set absent",
    pki.schema.cms.parse(aeadBase).contentTypeName === "authEnvelopedData");
  // That set answers to two names, and naming only the narrower one would drop every restriction
  // the wider one carries. A countersignature is an unsigned attribute and nothing else (RFC 5652
  // sec. 11.4), which the authenticated-attribute rule already refused.
  check("AP-26b and the restrictions an authenticated-attribute set already carried still hold there",
    codeOfSync(function () {
      pki.schema.cms.parse(withAuthEnvelopedAttr(aeadBase,
        attr(pki.oid.byName("countersignature"), [b.nullValue()])));
    }) === "cms/misplaced-attr");

  // AP-26d: which arm the value carries is the validator's question, not the parser's. RFC 6211
  // sec. 2 says which arm a producer fills; sec. 3.1 and 3.2 give the consequence to whoever
  // validates, and an attribute holding the other arm is a claim about a structure this is not. The
  // message parses so an operator can see that, and the verb refuses it. Driven on BOTH content
  // types, since each has its own arm and its own verb.
  var sigArmInAuthAttrs = withAuthAttr(authWithAp,
    attr(OID_PKCS9, [protection(algId("sha256"), algId("ecdsaWithSHA256"), 1)]), "cmsAlgorithmProtection");
  check("AP-26d a signatureAlgorithm arm in authAttrs parses, so the message can be read",
    pki.schema.cms.parse(sigArmInAuthAttrs).contentTypeName === "authData");
  check("AP-26d and pki.cms.decrypt refuses it as the mismatch it is",
    (await codeOf(pki.cms.decrypt(sigArmInAuthAttrs, { kek: apKek }))) === "cms/algorithm-protection-mismatch");

  // AP-26c: the off forms mean the same thing in bare authentication mode. The attribute cannot ride
  // in a message with no attribute set, so asking for it there is refused by placement, but saying
  // "no attribute" is not an unknown option: a caller passing one options object to several messages
  // should not have to strip a switch it had already turned off.
  var bareRecipient = [{ kek: kek, kekId: Buffer.from("k") }];
  check("AP-26c the documented off forms are accepted with authenticatedAttributes: false",
    (await codeOf(pki.cms.authenticate(CONTENT, bareRecipient,
      { authenticatedAttributes: false, algorithmProtection: false }))) === "NO-THROW" &&
    (await codeOf(pki.cms.authenticate(CONTENT, bareRecipient,
      { authenticatedAttributes: false, algorithmProtection: null }))) === "NO-THROW");
  check("AP-26c and asking for the attribute there is refused for the placement, not as an unknown option",
    (await messageOf(pki.cms.authenticate(CONTENT, bareRecipient,
      { authenticatedAttributes: false, algorithmProtection: true })))
      .indexOf("algorithmProtection needs authenticated attributes to ride in") === 0);
  check("AP-26c and a misspelling there is still the value refusal",
    (await messageOf(pki.cms.authenticate(CONTENT, bareRecipient,
      { authenticatedAttributes: false, algorithmProtection: "typo" })))
      .indexOf("algorithmProtection is true for the identifier") === 0);

  // AP-6c on this content type: the same switch, read the same way. The MAC over authAttrs alone
  // is what the attribute exists to extend, so a requirement the caller believes is on and is not
  // is the whole exposure this option closes.
  check("AP-6c a non-boolean requireAlgorithmProtection is refused by decrypt",
    (await codeOf(pki.cms.decrypt(plainAuthed, { kek: kek }, { requireAlgorithmProtection: "true" })))
      === "cms/bad-input" &&
    (await codeOf(pki.cms.decrypt(plainAuthed, { kek: kek }, { requireAlgorithmProtection: 1 })))
      === "cms/bad-input");
  check("AP-6c CONTROL the documented off forms admit the same message",
    (await pki.cms.decrypt(plainAuthed, { kek: kek }, { requireAlgorithmProtection: false })).authenticated === true &&
    (await pki.cms.decrypt(plainAuthed, { kek: kek }, { requireAlgorithmProtection: null })).authenticated === true);
  // AP-6d: the option is read on every content type `decrypt` takes, not only the one that can
  // satisfy it. RFC 8933 sec. 6 gives the attribute a place in an AuthenticatedData alone, so a
  // caller asking for it while decrypting an EnvelopedData or an EncryptedData is asking for a
  // requirement that message cannot meet, and handing back plaintext answers neither question.
  var envRecipient = { kek: kek, kekId: Buffer.from("k") };
  var enveloped = await pki.cms.encrypt(CONTENT, [envRecipient], { contentEncryptionAlgorithm: "aes-256-gcm" });
  check("AP-6d the requirement is refused on a content type that cannot carry the attribute",
    (await codeOf(pki.cms.decrypt(enveloped, { kek: kek }, { requireAlgorithmProtection: true })))
      === "cms/bad-input");
  check("AP-6d and a non-boolean is refused there too, not read as off",
    (await codeOf(pki.cms.decrypt(enveloped, { kek: kek }, { requireAlgorithmProtection: "true" })))
      === "cms/bad-input");
  check("AP-6d CONTROL the same message decrypts with the option off or absent",
    (await pki.cms.decrypt(enveloped, { kek: kek }, { requireAlgorithmProtection: false })).content.equals(CONTENT) &&
    (await pki.cms.decrypt(enveloped, { kek: kek })).content.equals(CONTENT));

  // AP-26: the producer door on the authenticate verb, the same rule the signing verbs hold. A
  // caller-supplied copy that contradicts the identifiers being emitted would produce a message this
  // package's own verifier refuses.
  var wantDigest = algId("sha256");
  var evilAuthAttr = b.sequence([b.oid(OID_PKCS9),
    b.set([protection(algId("sha512"), algId("hmacWithSHA256"), 2)])]);
  check("AP-26 a caller-supplied copy naming another digest is refused by the authenticate verb",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { authAttrs: [evilAuthAttr] }))) === "cms/bad-input");
  check("AP-26 a caller-supplied copy beside the verb's own emission is refused",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { algorithmProtection: true, authAttrs: [b.sequence([b.oid(OID_PKCS9),
        b.set([protection(wantDigest, algId("hmacWithSHA256"), 2)])])] }))) === "cms/bad-input");
  var agreeingAuth = await pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
    { authAttrs: [b.sequence([b.oid(OID_PKCS9), b.set([protection(wantDigest, algId("hmacWithSHA256"), 2)])])] });
  check("AP-26 CONTROL a caller-supplied copy that agrees is admitted and authenticates",
    (await pki.cms.decrypt(agreeingAuth, { kek: kek })).algorithmProtection.compared.length === 2);
  check("AP-26 a caller-supplied copy carrying two values is refused by the count rule",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { authAttrs: [b.sequence([b.oid(OID_PKCS9), b.set([
        protection(wantDigest, algId("hmacWithSHA256"), 2),
        protection(algId("sha512"), algId("hmacWithSHA512"), 2)])])] }))) === "cms/bad-input");
  // The adapter that reads a caller's TLV must not decide anything about a TLV it cannot read: a
  // junk attribute is still the existing door's refusal, with its own code, rather than this one's.
  check("AP-26 a caller attribute that is not a readable Attribute keeps its own refusal",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { authAttrs: [Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])] }))) !== "NO-THROW");
  check("AP-26 and so does one whose value set is missing entirely",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { authAttrs: [b.sequence([b.oid(OID_PKCS9)])] }))) !== "NO-THROW");
  check("AP-26 bytes that are not DER at all are refused by the decoder that owns that fault",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { authAttrs: [Buffer.from([0x30, 0x80])] }))) !== "NO-THROW");
  check("AP-26 and an attribute whose type is not an OBJECT IDENTIFIER likewise",
    (await codeOf(pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
      { authAttrs: [b.sequence([b.integer(1n), b.set([b.nullValue()])])] }))) !== "NO-THROW");

  // AP-31: RFC 8933 sec. 6 says the attribute "provides no protection for the algorithm identifiers
  // used in the authenticated-enveloped-data content type", which has no digest or MAC algorithm
  // field for a copy to name. Refused on the way out, since emitting one claims a protection the
  // structure cannot carry; a message from elsewhere carrying one is pointless rather than malformed
  // and still parses.
  var recipient = signing.makeRecipient("rsa");
  var macArmAttr = b.sequence([b.oid(OID_PKCS9), b.set([protection(algId("sha256"), algId("hmacWithSHA256"), 2)])]);
  check("AP-31 the AuthEnvelopedData authAttrs door refuses the attribute",
    (await codeOf(pki.cms.encrypt(CONTENT, [{ cert: recipient.cert }],
      { contentEncryptionAlgorithm: "aes-256-gcm", authAttrs: [macArmAttr] }))) === "cms/bad-input");
  check("AP-31 CONTROL another authenticated attribute is still accepted there",
    (await codeOf(pki.cms.encrypt(CONTENT, [{ cert: recipient.cert }],
      { contentEncryptionAlgorithm: "aes-256-gcm",
        authAttrs: [b.sequence([b.oid(pki.oid.byName("contentType")), b.set([b.oid(pki.oid.byName("data"))])])] })))
      === "NO-THROW");

  // AP-6 on this content type: the registry identifier is reachable here too, and read back.
  var authReg = await pki.cms.authenticate(CONTENT, [{ kek: kek, kekId: Buffer.from("k") }],
    { algorithmProtection: "registry" });
  var openedReg = await pki.cms.decrypt(authReg, { kek: kek });
  check("AP-6 the authenticate verb emits the registry identifier on request, and decrypt reads it",
    openedReg.algorithmProtection.oid === OID_REGISTRY &&
    openedReg.algorithmProtection.compared.length === 2);

  // AP-39b: a value this build cannot decode at all is a mismatch rather than a pass. The parser
  // refuses such a message, so the arm is reached only where a structure was read by something
  // looser; the report says the attribute could not be read instead of reporting it compared.
  var brokenValue = b.sequence([b.oid(OID_PKCS9), b.set([b.sequence([algId("sha256")])])]);
  check("AP-39b an attribute value that does not decode is refused at parse rather than compared",
    codeOfSync(function () {
      pki.schema.cms.parse(withSignedAttr(signed, brokenValue, "cmsAlgorithmProtection"));
    }) === "cms/bad-algorithm-protection-attr");

  console.log("CHECKS " + helpers.getChecks());
}

// Rewrite the AuthenticatedData's outer `digestAlgorithm [1]`, leaving every byte of authAttrs
// alone. RFC 5652 sec. 9.2 makes the MAC input the attribute set alone, so the MAC still verifies.
function withOuterDigest(authDer, digestName) {
  return _withOuterField(authDer, function (k) {
    return k.tagClass === "context" && k.tagNumber === 1;
  }, b.contextConstructed(1, b.oid(pki.oid.byName(digestName))));
}
// The same for the outer `macAlgorithm`, which is the untagged AlgorithmIdentifier at index 3.
function withOuterMac(authDer, macName) {
  var seen = 0;
  return _withOuterField(authDer, function (k) {
    if (k.tagClass !== "universal" || k.tagNumber !== pki.asn1.TAGS.SEQUENCE) return false;
    seen += 1;
    return seen === 1;
  }, b.sequence([b.oid(pki.oid.byName(macName))]));
}
// The authenticated attributes of an AuthenticatedData, rebuilt with `extra` added and any
// attribute of `replaceType` dropped. The MAC covers this set, so a fixture built this way is
// expected to fail its MAC: these vectors drive the PARSER.
function withAuthAttr(authDer, extra, replaceType) {
  var root = pki.asn1.decode(authDer);
  var ad = root.children[1].children[0];
  var want = replaceType ? pki.oid.byName(replaceType) : null;
  var kids = ad.children.map(function (k) {
    if (!(k.tagClass === "context" && k.tagNumber === 2)) return k.bytes;
    var kept = [];
    k.children.forEach(function (a) {
      if (want && pki.asn1.read.oid(a.children[0]) === want) return;
      kept.push(a.bytes);
    });
    kept.push(extra);
    var setOf = b.set(kept);
    var wire = Buffer.from(setOf); wire[0] = 0xA2;      // [2] IMPLICIT, the form authAttrs rides in
    return wire;
  });
  return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(kids))]);
}

function _withOuterField(authDer, pick, replacement) {
  var root = pki.asn1.decode(authDer);
  var ad = root.children[1].children[0];
  var kids = ad.children.map(function (k) { return pick(k) ? replacement : k.bytes; });
  return b.sequence([root.children[0].bytes, b.explicit(0, b.sequence(kids))]);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    null,
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
