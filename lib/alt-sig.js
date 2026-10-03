// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.altSig
 * @nav        Signing
 * @title      Alternative signatures
 * @order      237
 * @slug       alt-sig
 * @fullname   Alternative signatures: one certificate carrying two, for an algorithm migration
 *
 * @intro
 *   One certificate, two signatures. A PKI moving from one set of algorithms to
 *   another cannot reissue to every relying party at once, so ITU-T X.509 (2019)
 *   clause 9.8 lets a certificate carry a second public key, a second signature
 *   algorithm and a second signature in extensions. A relying party that has not
 *   migrated reads the native signature and ignores the rest; one that has reads
 *   the alternative signature instead. The shape is widely called Catalyst.
 *
 *   `signedData` builds the bytes that alternative signature covers. They are the
 *   `PreTBSCertificate`: the `tbsCertificate` without its `signature`
 *   AlgorithmIdentifier and without the `altSignatureValue` extension. A CRL has
 *   the same shape in `PreTBSCertList`, where `signature` is the second element
 *   rather than the third. Those bytes never appear on the wire, so a verifier
 *   rebuilds them. This is the one place the toolkit re-encodes what it parsed, so
 *   it does it by keeping the original bytes of every component it retains and
 *   recomputing only the two SEQUENCE headers whose lengths change. Nothing is
 *   re-serialized from a decoded model, because a model that normalized any byte
 *   would either fail every verification or accept an encoding the issuer never
 *   signed.
 *
 *   `verify` checks that signature under the alternative public key of the ISSUER,
 *   which clause 9.8.4 requires, through the same engine certification-path
 *   validation uses. The algorithm is not derived here: the structure states it in
 *   `altSignatureAlgorithm`, and the engine binds that stated algorithm to the key
 *   it was handed, so an algorithm that does not match the key is refused rather
 *   than reported as a bad signature.
 *
 *   `subjectAltPublicKey` reads a certificate's own alternative public key, which is
 *   what a verifier needs to check the certificate BELOW it. `SubjectAltPublicKeyInfo`
 *   carries the same two components in the same order as `SubjectPublicKeyInfo`, and a
 *   field name is not encoded, so the extension value is an SPKI on the wire and an
 *   importer takes it unchanged.
 *
 *   Clause 7.10.3 gives a CRL the same procedure with the same two extensions, and
 *   both verbs read a CRL as readily as a certificate. `subjectAltPublicKeyInfo` is
 *   certificate-only, which clause 7.2.2 states in a NOTE.
 *
 *   `pki.x509.sign` and `pki.crl.sign` produce all of this: an `altKey` beside the
 *   issuing key makes the two-pass signature the clause describes, so the ordering
 *   it requires is not the caller's to get right.
 *
 * @card Build and verify the second signature an X.509 (2019) clause 9.8 certificate
 *   or CRL carries, for a PKI migrating between algorithm sets.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var schemaX509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var seam = require("./verify-seam");

var AltSigError = frameworkError.AltSigError;
var b = asn1.build;
var _create = intrinsic.create;
var _assign = intrinsic.assign;
var _forEach = intrinsic.forEach;
var _map = intrinsic.map;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferConcat = intrinsic.bufferConcat;
var _push = intrinsic.push;

function _err(code, message, cause) { return new AltSigError(code, message, cause); }

var _seam = seam.makeSeam("alt-sig", AltSigError, "altsig/bad-input");

var OID_SAPKI = oid.byName("subjectAltPublicKeyInfo");
var OID_ALT_ALG = oid.byName("altSignatureAlgorithm");
var OID_ALT_VAL = oid.byName("altSignatureValue");
_forEach([OID_SAPKI, OID_ALT_ALG, OID_ALT_VAL], function (o) {
  if (!o) throw new Error("alt-sig: the clause 9.8 extension OIDs are not in the registry");
});

var KNOWN_VERIFY_OPTS = _create(null);

/** @internal Which structure this is, and where its extensions sit. A certificate carries them in
 *  `[3] EXPLICIT` at the end of the tbsCertificate; a CRL in `[0] EXPLICIT` at the end of the
 *  tbsCertList. The two shapes are told apart by the format detectors the parsers already publish,
 *  which are proven mutually exclusive, rather than by a tag probe written here. */
/** @internal `preName` is the type the preimage is an instance of, and `signatureIndex` finds the
 *  `signature` AlgorithmIdentifier the preimage drops. The field sits at a different element in the two
 *  structures because the optional `version` before it is encoded differently: a certificate's is
 *  `[0] EXPLICIT`, so `signature` is the third element, while a CRL's is a bare INTEGER, so it is the
 *  second. Each is located by the tag of the element before it rather than by a fixed offset. */
/** @internal `carriesSubjectAltKey` is which kinds may hold a `subjectAltPublicKeyInfo` extension:
 *  certificates only (ITU-T X.509 (2019) clause 7.2.2, NOTE). It is a row on the kind rather than a
 *  position in this array, so adding a third kind states its own answer and reordering the array cannot
 *  silently invert the rule. */
var KINDS = [
  { name: "certificate", carriesSubjectAltKey: true, preName: "PreTBSCertificate", matches: schemaX509.matches, parse: schemaX509.parse, extTag: 3,
    signatureIndex: function (tbs) {
      var first = tbs.children[0];
      return (first.tagClass === "context" && first.tagNumber === 0) ? 2 : 1;
    } },
  { name: "CRL", carriesSubjectAltKey: false, preName: "PreTBSCertList", matches: schemaCrl.matches, parse: schemaCrl.parse, extTag: 0,
    signatureIndex: function (tbs) {
      var first = tbs.children[0];
      return (first.tagClass === "universal" && first.tagNumber === asn1.TAGS.INTEGER) ? 1 : 0;
    } },
];

function _classify(root) {
  for (var i = 0; i < KINDS.length; i++) {
    if (KINDS[i].matches(root) === true) return KINDS[i];
  }
  return null;
}

/** @internal The decoded root of a signed structure this module reads, with the kind it is. */
function _open(input, what) {
  var der = guard.bytes.snapshot(input, _err, "altsig/bad-input", what);
  var root;
  try { root = asn1.decode(der); }
  catch (e) { throw _err("altsig/bad-input", what + " must be DER", e); }
  var kind = _classify(root);
  if (kind === null) {
    throw _err("altsig/bad-input", what + " must be an X.509 certificate or a CRL");
  }
  if (root.children.length < 3) {
    throw _err("altsig/bad-input", "a signed " + kind.name + " carries a toBeSigned, an algorithm and a signature");
  }
  /** @internal The structure is PARSED, not merely detected. `matches` answers which format the bytes are,
   *  which is not the same as their being a well-formed one of it: a certificate carrying the
   *  altSignatureValue extension TWICE passed the detector, `_findExt` took the first signature and
   *  `_preimage` removed both, so an ambiguous certificate the shared parser refuses with
   *  `x509/duplicate-extension` received a successful verdict here. Running the parser is what holds every
   *  structural rule this module then relies on, rather than the handful its own walk happens to check. */
  try { kind.parse(der); }
  catch (e) {
    throw _err("altsig/bad-input", what + " is not a well-formed " + kind.name +
      ", so the extensions this verb reads from it cannot be trusted to be the ones it carries", e);
  }
  return { der: der, root: root, kind: kind };
}

/** @internal The extensions SEQUENCE node of a certificate or CRL, or null when the field is absent.
 *  The tagged field is the last child of the toBeSigned in both structures, and it is located by its
 *  tag rather than by position, since the optional fields before it may or may not be present. */
function _extensionsNode(tbs, extTag) {
  var kids = tbs.children || [];
  for (var i = kids.length - 1; i >= 0; i--) {
    var k = kids[i];
    if (k.tagClass === "context" && k.tagNumber === extTag && k.children && k.children.length === 1 &&
        k.children[0].tagClass === "universal" && k.children[0].tagNumber === asn1.TAGS.SEQUENCE) {
      return { index: i, wrapper: k, list: k.children[0] };
    }
  }
  return null;
}

function _extOid(node) {
  if (!node.children || node.children.length < 2) return null;
  try { return asn1.read.oid(node.children[0]); }
  catch (_e) { return null; }
}

/** @internal Every extension of the structure, as `{ oid, node }`, in the order encoded. */
function _extensionList(opened) {
  var found = _extensionsNode(opened.root.children[0], opened.kind.extTag);
  if (found === null) return { block: null, items: [] };
  return {
    block: found,
    items: _map(found.list.children || [], function (n) { return { oid: _extOid(n), node: n }; }),
  };
}

function _findExt(items, wanted) {
  for (var i = 0; i < items.length; i++) { if (items[i].oid === wanted) return items[i]; }
  return null;
}

/**
 * @primitive pki.altSig.signedData
 * @signature pki.altSig.signedData(structure) -> Buffer
 * @since 0.8.43
 * @status stable
 * @spec ITU-T X.509 (2019) clause 7.2.2 / 7.10.3 / 9.8
 * @defends alternative-signature-scope-confusion (CWE-347)
 * @related pki.altSig.verify, pki.x509.sign, pki.crl.sign
 *
 * The bytes an alternative signature covers, for a certificate or a CRL. ITU-T X.509 (2019) clause
 * 7.2.2 says to "exclude the signature component and the altSignatureValue extension from the public-key
 * certificate, and generate the digital signature over the remaining DER encoded public-key
 * certificate", and clause 7.10.3 says the same of a CRL. Two members are named `signature`, so
 * `draft-truskovsky-lamps-pq-hybrid-x509` gives the excluded one a type of its own: the
 * `PreTBSCertificate` of section 4 is the `tbsCertificate` without "the signature field (the third
 * element in the TBSCertificate sequence)", and the `PreTBSCertList` of section 5 is the `tbsCertList`
 * without its second element. The `altSignatureValue` extension is removed from the extension list of
 * each, and the relative order of the extensions that remain is unchanged. What comes back is that
 * structure: the toBeSigned alone, carrying one member fewer.
 *
 * These are the bytes Bouncy Castle emits and checks, so an alternative signature this toolkit makes
 * verifies there, and one made there verifies here.
 *
 * A verifier has to rebuild the encoding, since it never appears on the wire. Every component retained
 * keeps the bytes it had, and only the SEQUENCE headers whose lengths change are recomputed; nothing is
 * re-serialized from a decoded model.
 *
 * A structure carrying no `altSignatureAlgorithm` extension throws `altsig/absent`: there is no stated
 * algorithm, so there is no alternative signature to be checked and no question these bytes answer.
 *
 * @example
 *   var native = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var alt = await pki.key.generate({ name: "ML-DSA-65" });
 *   var nativeSpki = await pki.key.export(native.publicKey, { format: "der" });
 *   var altSpki = await pki.key.export(alt.publicKey, { format: "der" });
 *   var certDer = await pki.x509.sign({
 *     subject: "CN=Catalyst", subjectPublicKey: nativeSpki, serialNumber: 1n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *     extensions: { subjectAltPublicKeyInfo: altSpki },
 *   }, { key: native.privateKey, altKey: alt.privateKey, altPublicKey: altSpki });
 *   pki.altSig.signedData(certDer).length > 0;   // -> true
 */
function signedData(structure) {
  var opened = _open(structure, "the signed structure");
  return _preimage(opened);
}

function _preimage(opened) {
  var exts = _extensionList(opened);
  if (_findExt(exts.items, OID_ALT_ALG) === null) {
    throw _err("altsig/absent",
      "the " + opened.kind.name + " carries no altSignatureAlgorithm extension, so it states no alternative signature (ITU-T X.509 (2019) clause 9.8.3)");
  }
  var tbs = opened.root.children[0];
  var sigIndex = opened.kind.signatureIndex(tbs);
  var sigField = tbs.children[sigIndex];
  /** @internal The element dropped is held to being an AlgorithmIdentifier before it is dropped, so a
   *  structure whose fields do not sit where the type places them is refused rather than silently
   *  signed over with a different element missing. The parser `_open` ran already holds the layout;
   *  this keeps a future structure whose layout differs from failing quietly. */
  if (!sigField || sigField.tagClass !== "universal" || sigField.tagNumber !== asn1.TAGS.SEQUENCE) {
    throw _err("altsig/bad-input",
      "the " + opened.kind.name + " does not carry its signature AlgorithmIdentifier where the type places it, so the " +
      opened.kind.preName + " cannot be built from it");
  }
  var kept = [];
  _forEach(tbs.children || [], function (k, i) {
    if (i === sigIndex) return;
    if (exts.block !== null && i === exts.block.index) return;
    _push(kept, k.bytes);
  });
  if (exts.block !== null) {
    var keptExts = [];
    _forEach(exts.items, function (it) { if (it.oid !== OID_ALT_VAL) _push(keptExts, it.node.bytes); });
    if (keptExts.length === 0) {
      throw _err("altsig/bad-input",
        "removing the altSignatureValue extension would leave an empty Extensions SEQUENCE, which the type does not allow");
    }
    _push(kept, b.explicit(opened.kind.extTag, b.sequence([b.raw(_bufferConcat(keptExts))])));
  }
  /** @internal Two headers are recomputed and no leaf is: the Extensions SEQUENCE and its tagged
   *  wrapper above, and the toBeSigned SEQUENCE here.
   *  WHAT IS EXCLUDED. ITU-T X.509 (2019) clause 7.2.2 says to "exclude the signature
   *  component and the altSignatureValue extension from the public-key certificate, and generate the
   *  digital signature over the remaining DER encoded public-key certificate". Two structures have a member
   *  named `signature`: the outer SEQUENCE, through `COMPONENTS OF SIGNATURE`, whose `signature` is the BIT
   *  STRING and whose `algorithmIdentifier` is a separately named component; and `TBSCertificate`, whose
   *  `signature` is an AlgorithmIdentifier. The clause names neither, and both can be built.
   *  draft-truskovsky-lamps-pq-hybrid-x509 settles it by defining the preimage as a type of its own.
   *  Section 4's `PreTBSCertificate` is the TBSCertificate without "the signature field (the third
   *  element in the TBSCertificate sequence)", and section 5's `PreTBSCertList` is the TBSCertList
   *  without its second element; the extension list in each drops altSignatureValue. The draft gives the
   *  reason the toBeSigned's own field is the one excluded: the signature AlgorithmIdentifier "might not
   *  be known at the time that the alternative signature is calculated", and being "associated with the
   *  final signatureValue field" it "does not need to be protected by the alternative signature". Both
   *  creation procedures bear that out, adding the field in a step after the alternative signature is
   *  computed. These are the bytes Bouncy Castle emits and checks, so an alternative signature this
   *  toolkit makes is one another implementation verifies, and the reverse. */
  return b.sequence([b.raw(_bufferConcat(kept))]);
}

/** @internal One decoded extension value of this structure, through the shared certificate-extension
 *  decoders so the value is held to its type before anything acts on it. */
var NS = pkix.makeNS("altsig", AltSigError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
function _decodeExt(item, label) {
  var dec = EXT_DECODERS[item.oid];
  var value;
  try { value = asn1.read.octetString(item.node.children[item.node.children.length - 1]); }
  catch (e) { throw _err("altsig/bad-input", "the " + label + " extension value must be an OCTET STRING", e); }
  try { return dec(value); }
  catch (e) {
    if (e instanceof AltSigError) throw e;
    throw _err("altsig/bad-input", "the " + label + " extension value is malformed", e);
  }
}

/**
 * @primitive pki.altSig.subjectAltPublicKey
 * @signature pki.altSig.subjectAltPublicKey(certificate) -> Buffer
 * @since 0.8.43
 * @status stable
 * @spec ITU-T X.509 (2019) clause 9.8.2
 * @defends alternative-key-substitution (CWE-347)
 * @related pki.altSig.verify, pki.x509.sign
 *
 * A certificate's own alternative public key, as the SPKI DER an importer takes. This is the key that
 * verifies the alternative signature on a certificate this one ISSUED, which is how the alternative
 * chain is followed: clause 9.8.4 requires the alternative signature to be "verified using the
 * alternative public key of the issuer".
 *
 * `SubjectAltPublicKeyInfo` carries the same two components in the same order as
 * `SubjectPublicKeyInfo`, and a field name is not encoded, so the extension value is already an SPKI
 * and is returned unchanged rather than rebuilt from its parts.
 *
 * A certificate with no such extension throws `altsig/absent`, as does a CRL, the extension being
 * certificate-only (clause 7.2.2, NOTE).
 *
 * @example
 *   var native = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var alt = await pki.key.generate({ name: "ML-DSA-65" });
 *   var nativeSpki = await pki.key.export(native.publicKey, { format: "der" });
 *   var altSpki = await pki.key.export(alt.publicKey, { format: "der" });
 *   var caDer = await pki.x509.sign({
 *     subject: "CN=Catalyst CA", subjectPublicKey: nativeSpki, serialNumber: 1n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectAltPublicKeyInfo: altSpki },
 *   }, { key: native.privateKey, altKey: alt.privateKey, altPublicKey: altSpki });
 *   // The same bytes the CA certified, ready to verify a certificate this CA issued.
 *   pki.altSig.subjectAltPublicKey(caDer).length === altSpki.length;   // -> true
 */
function subjectAltPublicKey(certificate) {
  var opened = _open(certificate, "the certificate");
  /** @internal The KIND decides before any extension is read. `subjectAltPublicKeyInfo` is
   *  certificate-only (clause 7.2.2, NOTE) and this verb documents that a CRL is refused, but the refusal
   *  came from the extension being absent rather than from the structure being the wrong one: a CRL
   *  carrying the extension, which the pre-encoded extensions array admits under `profile: "none"`, had it
   *  decoded with the certificate decoder and its key handed back. A key is an identity, so where it was
   *  read from is the question. */
  if (opened.kind.carriesSubjectAltKey !== true) {
    throw _err("altsig/absent",
      "a " + opened.kind.name + " carries no subjectAltPublicKeyInfo: the extension is certificate-only " +
      "(ITU-T X.509 (2019) clause 7.2.2, NOTE)");
  }
  var exts = _extensionList(opened);
  var item = _findExt(exts.items, OID_SAPKI);
  if (item === null) {
    throw _err("altsig/absent",
      "the " + opened.kind.name + " carries no subjectAltPublicKeyInfo extension (ITU-T X.509 (2019) clause 9.8.2)");
  }
  return _decodeExt(item, "subjectAltPublicKeyInfo").bytes;
}

/**
 * @primitive pki.altSig.verify
 * @signature pki.altSig.verify(structure, issuerAltPublicKey, opts?) -> Promise<boolean>
 * @since 0.8.43
 * @status stable
 * @spec ITU-T X.509 (2019) clause 7.2.2 / 7.10.3 / 9.8.4
 * @defends alternative-signature-forgery (CWE-347)
 * @related pki.altSig.signedData, pki.altSig.subjectAltPublicKey, pki.path.validate
 *
 * Verify the alternative signature on a certificate or a CRL. `issuerAltPublicKey` is the issuer's
 * alternative public key as SPKI DER, which clause 9.8.4 requires: "it shall be verified using the
 * alternative public key of the issuer". `pki.altSig.subjectAltPublicKey` reads that key out of the
 * issuer's own certificate. Resolves `true` when the signature over the bytes
 * `pki.altSig.signedData` describes verifies, and `false` when a signature was checked and did not.
 *
 * The algorithm is not derived. The structure states it in its `altSignatureAlgorithm` extension, and
 * that stated algorithm is bound to the key through the same engine certification-path validation
 * uses, so a key that does not match the stated algorithm resolves `false` rather than being read under
 * some other algorithm. Clause 9.8.3's NOTE 1 is why the algorithm is a separate extension: it sits
 * inside the bytes the alternative signature covers, so it cannot be changed without breaking it.
 *
 * A structure that states no alternative signature throws, since there is nothing to check and `false`
 * would read as a signature that failed.
 *
 * This verb answers one question: whether the issuer's alternative key signed this structure. It does
 * not validate a path, check revocation, or read the native signature. `pki.path.validate` answers
 * those, over the native signature.
 *
 * @example
 *   var native = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var alt = await pki.key.generate({ name: "ML-DSA-65" });
 *   var nativeSpki = await pki.key.export(native.publicKey, { format: "der" });
 *   var altSpki = await pki.key.export(alt.publicKey, { format: "der" });
 *   var caDer = await pki.x509.sign({
 *     subject: "CN=Catalyst CA", subjectPublicKey: nativeSpki, serialNumber: 1n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectAltPublicKeyInfo: altSpki },
 *   }, { key: native.privateKey, altKey: alt.privateKey, altPublicKey: altSpki });
 *   // The CA's own alternative key verifies the alternative signature it made.
 *   await pki.altSig.verify(caDer, pki.altSig.subjectAltPublicKey(caDer));   // -> true
 */
function verify(structure, issuerAltPublicKey, opts) {
  return guard.async.deferred(function () { return _verify(structure, issuerAltPublicKey, opts); });
}

function _verify(structure, issuerAltPublicKey, opts) {
  guard.identifier.assertKnownKeys(opts, KNOWN_VERIFY_OPTS, _err, "altsig/bad-input",
    "pki.altSig.verify has an unknown option: ");
  var opened = _open(structure, "the signed structure");
  var exts = _extensionList(opened);
  var algItem = _findExt(exts.items, OID_ALT_ALG);
  var valItem = _findExt(exts.items, OID_ALT_VAL);
  if (algItem === null || valItem === null) {
    throw _err("altsig/absent",
      "the " + opened.kind.name + " carries no alternative signature: clause 9.8.3 requires the altSignatureAlgorithm and altSignatureValue extensions together");
  }
  var sigAlg = _decodeExt(algItem, "altSignatureAlgorithm");
  var sigValue = _decodeExt(valItem, "altSignatureValue");
  var spki = guard.bytes.snapshot(issuerAltPublicKey, _err, "altsig/bad-input", "the issuer's alternative public key");
  _assertSpki(spki);
  return _seam.verify(sigAlg, sigValue, spki, _preimage(opened));
}

/** @internal The alternative key is handed to an importer, so it is held to being a
 *  SubjectPublicKeyInfo first: bytes that are not one would reach the engine as a key it reports no
 *  verdict for, and a caller cannot tell that from a signature that failed. */
var SPKI_SCHEMA = pkix.spki(NS);
function _assertSpki(der) {
  try { schema.walk(SPKI_SCHEMA, asn1.decode(der), NS); }
  catch (e) {
    throw _err("altsig/bad-input", "the issuer's alternative public key must be a SubjectPublicKeyInfo in DER", e);
  }
}

module.exports = {
  signedData: signedData,
  verify: verify,
  subjectAltPublicKey: subjectAltPublicKey,
  /** @internal The extension OIDs and the preimage, for the builders that emit them. */
  OID_SAPKI: OID_SAPKI, OID_ALT_ALG: OID_ALT_ALG, OID_ALT_VAL: OID_ALT_VAL,
  setEngine: _seam.setEngine,
};
