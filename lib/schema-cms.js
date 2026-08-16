// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.cms
 * @nav        Schema
 * @title      CMS
 * @order      160
 * @slug       cms
 *
 * @intro
 *   CMS handling per RFC 5652 (sec. 3 ContentInfo envelope). `parse` turns a DER or PEM
 *   (`CMS`) message into a structured object and is an OID-dispatch envelope --
 *   ContentInfo reads its `contentType` and structurally decodes SignedData (sec. 5),
 *   EnvelopedData (sec. 6, with all five RecipientInfo kinds -- key-transport,
 *   key-agreement per RFC 5753, KEK, password, and other, including the RFC 9629
 *   KEMRecipientInfo carried under `id-ori-kem` with ML-KEM per RFC 9936),
 *   EncryptedData (sec. 8), AuthenticatedData (sec. 9), and AuthEnvelopedData (RFC 5083,
 *   with RFC 5084 AES-GCM/CCM parameter validation); the remaining PKCS#7 content
 *   types are recognized and rejected with a precise `cms/unsupported-content-type`
 *   rather than a generic unknown-format error. A SignedData surfaces its version,
 *   digest algorithms, encapsulated content, certificate / CRL sets, and signer
 *   infos; an EnvelopedData its recipient infos and encrypted content info; an
 *   EncryptedData its encrypted content info; an AuthenticatedData its MAC
 *   algorithm, optional digest algorithm, authenticated / unauthenticated
 *   attributes, and raw `mac`; an AuthEnvelopedData its recipient infos, encrypted
 *   content, validated AEAD parameters, and raw `mac`.
 *
 *   CMS is a signed container: the bytes an external verifier must hash are
 *   surfaced RAW and never re-serialized. `encapContentInfo.eContent` is the raw
 *   content (or `null` for a detached signature); each SignerInfo's `signature` is
 *   raw, and `signedAttrsBytes` is the on-wire `[0]` SignedAttributes TLV so a
 *   verifier can re-tag it to the universal SET the signature is computed over
 *   (sec. 5.4) -- `authAttrsBytes` plays the same role for the sec. 9.2 MAC input and the
 *   RFC 5083 sec. 2.2 AAD. Embedded certificates and CRLs are surfaced as raw DER +
 *   their outer tag, validated against the closed CertificateChoices /
 *   RevocationInfoChoice tag sets, so an obsolete alternative never fails the
 *   parse but an out-of-set element does. DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM CMS (RFC 5652 / 5083 / 9629) into structured, validated fields
 *   -- signed, enveloped, encrypted, authenticated, and auth-enveloped content;
 *   raw attribute bytes for external verification; certificates/CRLs kept raw,
 *   fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var guard = require("./guard-all");
var C = require("./constants");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var schemaX509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");

var CmsError = frameworkError.CmsError;
var PemError = frameworkError.PemError;

// The cms error namespace the schema engine walks under.
var NS = pkix.makeNS("cms", CmsError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var ATTRIBUTE = pkix.attribute(NS);
var NAME = pkix.name(NS);

// CMSVersion ::= INTEGER -- the SignedData version is {1,3,4,5} and the SignerInfo
// version is {1,3} (RFC 5652 sec. 5.1, sec. 5.3). Wider accept maps than any other format.
var SIGNED_DATA_VERSION = pkix.versionReader(NS, { "1": 1, "3": 3, "4": 4, "5": 5 });
var SIGNER_VERSION = pkix.versionReader(NS, { "1": 1, "3": 3 });
// EnvelopedData sec. 6.1 (0/2/3/4), EncryptedData sec. 8 (0/2), and the per-RecipientInfo
// versions (RFC 5652 sec. 6.2.1-sec. 6.2.4): ktri {0,2}, kari {3}, kekri {4}, pwri {0}.
var ENVELOPED_DATA_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2, "3": 3, "4": 4 });
var ENCRYPTED_DATA_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2 });
var KTRI_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2 });
var KARI_VERSION = pkix.versionReader(NS, { "3": 3 });
var KEKRI_VERSION = pkix.versionReader(NS, { "4": 4 });
var PWRI_VERSION = pkix.versionReader(NS, { "0": 0 });
// AuthenticatedData sec. 9.1: computed {0,1,3} (see _expectedAuthDataVersion). The
// AuthEnvelopedData version (RFC 5083 sec. 2.1) and the KEMRecipientInfo version
// (RFC 9629 sec. 3) are both a fixed 0.
var AUTHDATA_VERSION = pkix.versionReader(NS, { "0": 0, "1": 1, "3": 3 });
var COMPRESSED_DATA_VERSION = pkix.versionReader(NS, { "0": 0 });   // RFC 3274 sec. 1.1 -- version MUST be 0
var AUTHENV_VERSION = pkix.versionReader(NS, { "0": 0 });
var KEMRI_VERSION = pkix.versionReader(NS, { "0": 0 });

// id-signedData / id-envelopedData / id-encryptedData are the content types this
// build structurally decodes; the rest are recognized-and-deferred (a precise
// diagnostic, not a silent unknown-format). OIDs resolve from the registry (pkcs7 /
// smimeCt families), never dotted literals.
var OID_SIGNED_DATA = oid.byName("signedData");
var OID_ENVELOPED_DATA = oid.byName("envelopedData");
var OID_ENCRYPTED_DATA = oid.byName("encryptedData");
var OID_AUTH_DATA = oid.byName("authData");                         // RFC 5652 sec. 9
var OID_AUTH_ENVELOPED_DATA = oid.byName("authEnvelopedData");      // RFC 5083
var OID_COMPRESSED_DATA = oid.byName("compressedData");             // RFC 3274
var OID_DATA = oid.byName("data");
var OID_ORI_KEM = oid.byName("kem");                                // id-ori-kem (RFC 9629)

// AES key-wrap OID -> the KEK length in octets it wraps (RFC 3565). RFC 9629 sec. 3:
// a KEMRecipientInfo kekLength MUST be consistent with the wrap algorithm, so a
// recognized wrap pins the exact length; an unrecognized wrap carries no rule.
var WRAP_KEK_LENGTHS = {};
WRAP_KEK_LENGTHS[oid.byName("aes128-wrap")] = 16;
WRAP_KEK_LENGTHS[oid.byName("aes192-wrap")] = 24;
WRAP_KEK_LENGTHS[oid.byName("aes256-wrap")] = 32;

// ML-KEM OID -> the exact ciphertext (kemct) length in octets (FIPS 203). A
// recognized ML-KEM kem carries a fixed-size ciphertext; any other length can
// never decapsulate. (The params-absent rule rides the shared oid registry.)
// Ciphertext lengths come from the shared ML-KEM parameter registry (FIPS 203 Table 3) rather
// than a local copy, so this codec and the crypto engine cannot disagree about a parameter set.
var KEM_CT_LENGTHS = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) { KEM_CT_LENGTHS[oid.byName(n)] = oid.kemParams(n).ct; });

// Recognized AEAD content-encryption OIDs -> the AES-GCM/CCM parameter shape + the
// legal ICVlen set (RFC 5084). An unrecognized content-encryption OID surfaces its
// parameters raw with no AEAD validation (registry, not switch).
var AEAD_GCM_ICVLENS = new Set([12, 13, 14, 15, 16]);
var AEAD_CCM_ICVLENS = new Set([4, 6, 8, 10, 12, 14, 16]);
var AEAD_ALGS = {};
["aes128-GCM", "aes192-GCM", "aes256-GCM"].forEach(function (n) { AEAD_ALGS[oid.byName(n)] = "gcm"; });
["aes128-CCM", "aes192-CCM", "aes256-CCM"].forEach(function (n) { AEAD_ALGS[oid.byName(n)] = "ccm"; });

var DEFERRED = new Set([
  oid.byName("data"), oid.byName("signedAndEnvelopedData"),
  oid.byName("digestedData"),
]);
// The RFC 5652 sec. 11 attribute types with per-context placement + value rules.
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_SIGNING_TIME = oid.byName("signingTime");
var OID_COUNTERSIGNATURE = oid.byName("countersignature");

// RFC 5652 sec. 11.1-sec. 11.4 -- where each sec. 11 attribute type may appear. Keyed by
// attribute OID; each row names the attribute-set contexts the type MUST NOT
// appear in: content-type / message-digest / signing-time are signed-or-
// authenticated only; countersignature is unsigned only.
var ATTR_FORBIDDEN_IN = {};
ATTR_FORBIDDEN_IN[OID_CONTENT_TYPE] = { unsigned: true, unauth: true, unprotected: true };
ATTR_FORBIDDEN_IN[OID_MESSAGE_DIGEST] = { unsigned: true, unauth: true, unprotected: true };
ATTR_FORBIDDEN_IN[OID_SIGNING_TIME] = { unsigned: true, unauth: true, unprotected: true };
ATTR_FORBIDDEN_IN[OID_COUNTERSIGNATURE] = { signed: true, auth: true, unauth: true, unprotected: true };
var ATTR_PLACE_LABELS = {
  signed: "a signed attribute", unsigned: "an unsigned attribute", auth: "an authenticated attribute",
  unauth: "an unauthenticated attribute", unprotected: "an unprotected attribute",
};

// Enforce the sec. 11 placement rows on one parsed attribute set. `place` names the
// context the set occupies (signed / unsigned / auth / unauth / unprotected).
function _checkAttrPlacement(attrs, place) {
  for (var i = 0; i < attrs.length; i++) {
    var row = ATTR_FORBIDDEN_IN[attrs[i].type];
    if (row && row[place]) {
      // Coverage residual -- reached only when the OID is a registry entry (the guard above
      // guarantees it), so oid.name() never returns undefined and this fallback is a
      // defensive belt, not selectable through the public parse path.
      throw NS.E("cms/misplaced-attr", "the " + (oid.name(attrs[i].type) || attrs[i].type) +
        " attribute must not be " + ATTR_PLACE_LABELS[place] + " (RFC 5652 sec. 11)");
    }
  }
}

// Enforce the content-binding-attribute value constraints (RFC 5652 sec. 11.1-sec. 11.3)
// shared by SignedData signedAttrs (sec. 5.3), AuthenticatedData authAttrs (sec. 9.1),
// and a countersignature value's signedAttrs (sec. 11.4): the set MUST contain
// exactly one message-digest attribute, each sec. 11 attribute is single-valued with
// valid syntax, and no attribute type repeats. `mode` selects the content-type
// presence rule -- "content" (sec. 5.3/sec. 9.1) REQUIRES one; "countersig" (sec. 11.4)
// FORBIDS it (there is no content type for what a countersignature signs). The
// content-type value == eContentType cross-check is a separate per-build step
// (it needs the eContentType in scope); messageDigest == the actual content
// hash is a sec. 5.6 VERIFICATION concern surfaced, not a structural-parse concern.
function _checkContentBindingAttrs(attrs, mode) {
  var ct = 0, md = 0, seen = Object.create(null);
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    // RFC 5652 sec. 5.3 -- a signerInfo MUST NOT include multiple instances of the
    // same signed-attribute type (specific codes for the two mandatory types).
    if (seen[a.type]) {
      if (a.type === OID_CONTENT_TYPE) throw NS.E("cms/duplicate-content-type", "the attribute set must not repeat the content-type attribute");
      if (a.type === OID_MESSAGE_DIGEST) throw NS.E("cms/duplicate-message-digest", "the attribute set must not repeat the message-digest attribute");
      throw NS.E("cms/duplicate-signed-attr", "the attribute set must not include multiple instances of the same attribute type (" + a.type + ")");
    }
    seen[a.type] = true;
    if (a.type === OID_CONTENT_TYPE) {
      ct += 1;
      // RFC 5652 sec. 11.4 -- a countersignature's signedAttrs MUST NOT carry a
      // content-type attribute (what it signs has no content type).
      if (mode === "countersig") throw NS.E("cms/misplaced-attr", "a countersignature's signedAttrs must not carry a content-type attribute (RFC 5652 sec. 11.4)");
      if (a.values.length !== 1) throw NS.E("cms/bad-content-type-attr", "the content-type attribute must be single-valued");
      // ContentType ::= OBJECT IDENTIFIER (RFC 5652 sec. 11.1) -- validate the value's
      // full syntax (tag AND minimal base-128 OID content), not just the tag, so a
      // truncated / non-minimal subidentifier is rejected here, not at verify time.
      try { asn1.read.oid(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-content-type-attr", "the content-type attribute value must be a valid OBJECT IDENTIFIER", e); }
    } else if (a.type === OID_MESSAGE_DIGEST) {
      md += 1;
      if (a.values.length !== 1) throw NS.E("cms/bad-message-digest-attr", "the message-digest attribute must be single-valued");
      // MessageDigest ::= OCTET STRING (RFC 5652 sec. 11.2) -- validate the full syntax.
      try { asn1.read.octetString(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-message-digest-attr", "the message-digest attribute value must be an OCTET STRING", e); }
    } else if (a.type === OID_SIGNING_TIME) {
      // RFC 5652 sec. 11.3 -- signing-time MUST be single-valued and its value is
      // SigningTime ::= Time (UTCTime | GeneralizedTime, full syntax validated).
      if (a.values.length !== 1) throw NS.E("cms/bad-signing-time-attr", "the signing-time attribute must be single-valued (RFC 5652 sec. 11.3)");
      try { asn1.read.time(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-signing-time-attr", "the signing-time attribute value must be a Time (RFC 5652 sec. 11.3)", e); }
    }
  }
  // Duplicates are rejected in the loop (the seen-set); here only presence.
  if (mode !== "countersig" && ct === 0) throw NS.E("cms/missing-content-type", "the attribute set must contain a content-type attribute (RFC 5652 sec. 11.1)");
  if (md === 0) throw NS.E("cms/missing-message-digest", "the attribute set must contain a message-digest attribute (RFC 5652 sec. 11.2)");
}

// looksLikeSignedAttributes(bytes) -> boolean.
//
// Does `bytes` parse as a DER SignedAttributes block -- a SET OF Attribute carrying BOTH the
// content-type and message-digest attributes RFC 5652 sec. 5.3 makes mandatory whenever signed
// attributes are present?
//
// This is the detector for the signed-attribute stripping forgery
// (draft-vangeest-lamps-cms-euf-cma-signeddata, Attack Type 1). A CMS signature does not commit to
// WHETHER signed attributes were present, so a signature made over a SignedAttributes block can be
// re-presented as one made over content: drop the signedAttrs field and set the encapsulated
// content to the DER of those same attributes. Sec. 5.4 then says the signature is over the content
// itself, which is exactly what it covers, and with no attributes there is no message-digest or
// content-type attribute left to disagree. The proposed standards fixes are protocol changes -- a
// context string naming which mode was signed -- that no verifier can apply on its own.
//
// What a verifier CAN do is refuse the shape. Every message produced by the attack has, as its
// content, the encoded SignedAttributes of a real message, and sec. 5.3 requires those to carry
// both attributes named above. That makes their presence a NECESSARY condition of the attack rather
// than a guess, and the shape is one ordinary content does not have: a certificate, a JSON payload,
// arbitrary bytes, and even a SET OF other attributes all fail it. The cost is a message whose
// legitimate content really is an encoded SignedAttributes block signed WITHOUT attributes, which
// is refused as genuinely ambiguous -- sign it with attributes and it is unambiguous again.
//
// One mandatory attribute value, held to all three conditions a real SignedAttributes meets:
// exactly one value (RFC 5652 sec. 11.1 / sec. 11.2 make both single-valued), the right tag, and a
// body that actually READS as that type. All three together, for each attribute -- checking the
// cardinality and the tag while letting an undecodable body through would refuse content the real
// SignedAttributes parser could never have produced, which is the false positive this whole
// detector is shaped to avoid.
function _readsAs(vals, tagNumber, reader) {
  if (vals.length !== 1 || !schema.isUniversal(vals[0], tagNumber)) return false;
  var reads = true;
  try { reader(vals[0]); }
  catch (_e) {
    reads = false;   // right tag, unreadable body -- not a preimage anything signed
  }
  return reads;
}
// SigningTime ::= Time is a CHOICE of UTCTime and GeneralizedTime, so the tag is one of two and the
// reader settles which -- _readsAs pins a single tag and cannot express it.
function _readsAsTime(vals) {
  if (vals.length !== 1) return false;
  var reads = true;
  try { asn1.read.time(vals[0]); }
  catch (_e) {
    reads = false;
  }
  return reads;
}

// Deliberately a total function: it answers about arbitrary attacker bytes and must never throw.
function looksLikeSignedAttributes(bytes) {
  if (!bytes || !bytes.length) return false;
  var node;
  try { node = asn1.decode(bytes); }
  catch (_e) { return false; }   // not DER at all -- not this shape
  if (!schema.isUniversal(node, asn1.TAGS.SET) || !node.constructed) return false;
  var kids = node.children || [];
  if (!kids.length) return false;
  // Every rule _checkContentBindingAttrs applies to a REAL SignedAttributes is applied here, and
  // for one reason: the detector must match only what a conforming block can be. A set the real
  // parser would have rejected cannot be the preimage of any signature, so matching it would refuse
  // content no attack could have produced. Enumerated against that function rather than discovered
  // one rule at a time -- no duplicate attribute types (sec. 5.3), content-type single-valued and a
  // readable OID (sec. 11.1), message-digest single-valued and a readable OCTET STRING (sec. 11.2),
  // signing-time when present single-valued and a readable Time (sec. 11.3).
  var sawContentType = false, sawMessageDigest = false, seenTypes = Object.create(null);
  for (var i = 0; i < kids.length; i++) {
    var a = kids[i];
    // Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF ANY }
    if (!schema.isUniversal(a, asn1.TAGS.SEQUENCE)) return false;
    if (!a.children || a.children.length !== 2) return false;
    var t = a.children[0], vs = a.children[1];
    if (!schema.isUniversal(t, asn1.TAGS.OBJECT_IDENTIFIER)) return false;
    if (!schema.isUniversal(vs, asn1.TAGS.SET)) return false;
    var attrOid;
    try { attrOid = asn1.read.oid(t); }
    catch (_e2) { return false; }
    if (seenTypes[attrOid]) return false;   // a repeated attribute type -- sec. 5.3 forbids it
    seenTypes[attrOid] = true;
    // EVERY attribute, not only the two mandatory ones, is bounded 1..ATTRIBUTE_MAX_VALUES by the
    // shared Attribute schema this format composes. An attribute with an empty value set, or more
    // values than the cap, is one that schema would have refused -- so a set containing one cannot
    // be a preimage either, whichever attribute it is.
    var n = (vs.children || []).length;
    if (n < 1 || n > C.LIMITS.ATTRIBUTE_MAX_VALUES) return false;
    // The two mandatory attributes are checked down to their VALUES, not just their type OIDs.
    // RFC 5652 sec. 11.1 makes content-type a single OBJECT IDENTIFIER and sec. 11.2 makes
    // message-digest a single OCTET STRING, so a set carrying those OIDs over an empty or
    // wrongly-typed value CANNOT be the preimage of a real signature -- and refusing it would be a
    // false positive on content that merely resembles the shape. The detector has to stay a
    // necessary condition of the attack; anything broader costs a legitimate caller.
    var vals = vs.children || [];
    if (attrOid === OID_CONTENT_TYPE) {
      if (!_readsAs(vals, asn1.TAGS.OBJECT_IDENTIFIER, asn1.read.oid)) return false;
      sawContentType = true;
    } else if (attrOid === OID_MESSAGE_DIGEST) {
      if (!_readsAs(vals, asn1.TAGS.OCTET_STRING, asn1.read.octetString)) return false;
      sawMessageDigest = true;
    } else if (attrOid === OID_SIGNING_TIME) {
      // Not mandatory, but when present sec. 11.3 constrains it the same way, so a set carrying an
      // unreadable signing-time is one the real parser would have refused.
      if (!_readsAsTime(vals)) return false;
    }
  }
  return sawContentType && sawMessageDigest;
}

// RFC 5652 sec. 5.3 / sec. 9.3 -- when a content-type attribute is present, it MUST
// be single-valued (sec. 11.1) and its value MUST equal the eContentType (a
// cross-field consistency both parsed here). Shared by SignedData signedAttrs,
// AuthenticatedData authAttrs, and AuthEnvelopedData authAttrs -- the single-value
// rule holds even where content-type is not REQUIRED (RFC 5083), so an
// expected-first-value-plus-extra set can never surface as ambiguous.
function _assertContentTypeMatchesAttrs(attrs, eContentType) {
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type !== OID_CONTENT_TYPE) continue;
    if (attrs[i].values.length !== 1) throw NS.E("cms/bad-content-type-attr", "the content-type attribute must be single-valued (RFC 5652 sec. 11.1)");
    // ContentType ::= OBJECT IDENTIFIER -- validate the value's full syntax (tag AND
    // minimal base-128 OID content) with the CMS typed verdict, so a malformed value
    // on a path that does not run _checkContentBindingAttrs (AuthEnvelopedData,
    // RFC 5083 sec. 2.1) surfaces cms/bad-content-type-attr, not the raw asn1/* error.
    var ctv;
    try { ctv = asn1.read.oid(asn1.decode(attrs[i].values[0])); }
    catch (e) { throw NS.E("cms/bad-content-type-attr", "the content-type attribute value must be a valid OBJECT IDENTIFIER", e); }
    if (ctv !== eContentType) throw NS.E("cms/content-type-mismatch", "the content-type attribute (" + ctv + ") must equal the eContentType (" + eContentType + ") (RFC 5652 sec. 5.3)");
  }
}

// RFC 5652 sec. 5.3 -- an attribute set MUST NOT include multiple instances of the
// same attribute type. AuthEnvelopedData authAttrs (RFC 5083 sec. 2.1) gets ONLY this
// duplicate check -- NOT the content-type/message-digest presence rules (RFC 5652
// sec. 11.1/sec. 11.2 bind only signed-data and authenticated-data), so it must not reuse
// _checkContentBindingAttrs, which would over-enforce.
function _checkNoDuplicateAttrs(attrs) {
  var seen = Object.create(null);
  for (var i = 0; i < attrs.length; i++) {
    if (seen[attrs[i].type]) throw NS.E("cms/duplicate-attr", "an attribute set must not include multiple instances of the same attribute type (" + attrs[i].type + ", RFC 5652 sec. 5.3)");
    seen[attrs[i].type] = true;
  }
}

// RFC 5084 -- validate the AES-GCM/CCM content-encryption parameters when the OID
// is a recognized AEAD (an unknown OID surfaces its parameters raw with no AEAD
// check). Returns { kind, nonce, icvLen } or null. `macLen` (the AuthEnvelopedData
// mac length) is cross-checked against the effective ICVlen. The bounded nonce read
// is the pre-auth surface the oversized-IV class (CVE-2025-15467) targets.
function _validateAeadParams(alg, macLen) {
  var kind = AEAD_ALGS[alg.oid];
  if (!kind) return null;
  var K = kind.toUpperCase();
  // sec. 3.1/sec. 3.2: the parameters field MUST be present and carry the Parameters SEQUENCE.
  if (alg.parameters === null) throw NS.E("cms/bad-aead-params", "an AES-" + K + " content-encryption algorithm MUST carry its parameters (RFC 5084 sec. 3." + (kind === "gcm" ? "2" : "1") + ")");
  var node;
  // Coverage residual -- alg.parameters is an AlgorithmIdentifier child already fully
  // validated by the eager-recursive asn1.decode during the enclosing SEQUENCE parse;
  // re-decoding the same TLV cannot fault, so this catch is an unreachable fail-closed
  // belt (malformed parameters are rejected as asn1/* before _validateAeadParams runs).
  try { node = asn1.decode(alg.parameters); }
  catch (e) { throw NS.E("cms/bad-aead-params", "malformed AES-" + K + " parameters", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== T.SEQUENCE || !node.children || node.children.length < 1 || node.children.length > 2) {
    throw NS.E("cms/bad-aead-params", "AES-" + K + " parameters must be a SEQUENCE { aes-nonce, aes-ICVlen DEFAULT 12 } (RFC 5084)");
  }
  var nonce;
  try { nonce = asn1.read.octetString(node.children[0]); }
  catch (e) { throw NS.E("cms/bad-aead-params", "the AEAD aes-nonce must be an OCTET STRING", e); }
  // CCM: aes-nonce is SIZE(7..13) (RFC 5084 sec. 3.1). GCM has no ASN.1 bound; the raw
  // nonce is surfaced (a subarray, never copied into a fixed buffer), bounded by the
  // DER size cap -- a nonzero length is the only structural floor.
  if (kind === "ccm" && (nonce.length < 7 || nonce.length > 13)) throw NS.E("cms/bad-aead-params", "the AES-CCM aes-nonce must be 7..13 octets (RFC 5084 sec. 3.1)");
  if (nonce.length < 1) throw NS.E("cms/bad-aead-params", "the AEAD aes-nonce must be non-empty");
  // aes-ICVlen INTEGER DEFAULT 12.
  var icvLen = 12, icvEncoded = false;
  if (node.children.length === 2) {
    var iv;
    try { iv = asn1.read.integer(node.children[1]); }
    catch (e) { throw NS.E("cms/bad-aead-params", "the AEAD aes-ICVlen must be an INTEGER", e); }
    if (iv < 0n || iv > 16n) throw NS.E("cms/bad-aead-params", "the AEAD aes-ICVlen is out of range");
    icvLen = Number(iv); icvEncoded = true;
  }
  var legal = kind === "gcm" ? AEAD_GCM_ICVLENS : AEAD_CCM_ICVLENS;
  if (!legal.has(icvLen)) throw NS.E("cms/bad-aead-params", "the AES-" + K + " aes-ICVlen " + icvLen + " is not an allowed value (RFC 5084)");
  // X.690 sec. 11.5: a DEFAULT value MUST be omitted in DER -- an encoded ICVlen equal
  // to the default 12 is non-canonical.
  if (icvEncoded && icvLen === 12) throw NS.E("cms/non-canonical-default", "the AEAD aes-ICVlen equal to the DEFAULT 12 MUST be omitted (X.690 sec. 11.5)");
  // RFC 5084 sec. 3.1/sec. 3.2: aes-ICVlen MUST match the AuthEnvelopedData mac length.
  if (macLen != null && icvLen !== macLen) throw NS.E("cms/mac-length-mismatch", "the AEAD aes-ICVlen " + icvLen + " must equal the mac length " + macLen + " (RFC 5084)");
  return { kind: kind, nonce: nonce, icvLen: icvLen };
}

// RFC 5652 sec. 5.3 / sec. 9.1 + RFC 5083 sec. 2.1 -- a signed / authenticated attribute SET
// MUST be DER encoded even when the enclosing structure was decoded as BER (its
// bytes feed the sec. 5.4 / sec. 9.2 re-tagged hash / MAC input, so a non-DER TLV makes
// the surfaced raw bytes unusable for verification). Strictly re-decoding the
// on-wire TLV rejects any indefinite-length or non-minimal encoding in the
// subtree; on the strict parse path this always passes.
function _assertDerEncodedAttrs(node, code) {
  try { asn1.decode(node.bytes); }
  catch (e) { throw NS.E(code, "the attribute set must be DER encoded even inside a BER envelope (RFC 5652 sec. 5.3)", e); }
}

// A CertificateChoices / RevocationInfoChoice element, surfaced RAW (its DER +
// outer tag) rather than recursively parsed -- the obsolete CHOICE alternatives
// (extendedCertificate, attribute certs, otherRevocationInfo) never fail the
// parse, and a caller re-parses a `certificate`/`CertificateList` element itself.
function rawElement(item) {
  return { bytes: item.node.bytes, tagClass: item.node.tagClass, tagNumber: item.node.tagNumber };
}

// CertificateChoices (RFC 5652 sec. 10.2.2) and RevocationInfoChoice (sec. 10.2.1) are
// CLOSED CHOICE sets -- Certificate / CertificateList (a universal SEQUENCE) or
// the listed context tags, every alternative constructed. An element outside
// the set is structurally malformed even though members are surfaced raw: the
// [3] / [1] `other` arms ARE the RFC's extension points for unknown formats,
// so an open tag set is never needed. The tag sets also feed the sec. 5.1 / sec. 6.1
// version rules, which must never be computed over undefined-type elements.
var CERT_CHOICE_TAGS = { universal: {}, context: { 0: true, 1: true, 2: true, 3: true } };
var CRL_CHOICE_TAGS = { universal: {}, context: { 1: true } };
CERT_CHOICE_TAGS.universal[asn1.TAGS.SEQUENCE] = true;
CRL_CHOICE_TAGS.universal[asn1.TAGS.SEQUENCE] = true;
function rawChoiceElement(allowed, code, what) {
  return function (item) {
    var n = item.node;
    var byClass = allowed[n.tagClass];
    if (!n.constructed || !byClass || byClass[n.tagNumber] !== true) {
      throw NS.E(code, what + " element tag is outside the closed CHOICE set (RFC 5652 sec. 10.2.1-sec. 10.2.2)");
    }
    return rawElement(item);
  };
}

// RFC 5652 sec. 5.1 -- the exact SignedData CMSVersion, computed from the raw
// CertificateChoices / RevocationInfoChoice outer tags (a certificate `other` is
// [3], a v2AttrCert [2], a v1AttrCert [1]; a RevocationInfoChoice `other` is [1]),
// the SignerInfo versions, and whether the content type is id-data.
function _expectedSignedDataVersion(certificates, crls, signerInfos, eContentType) {
  var otherCert = certificates.some(function (c) { return schema.isContext(c, 3); });
  var otherCrl = crls.some(function (c) { return schema.isContext(c, 1); });
  if (otherCert || otherCrl) return 5;
  if (certificates.some(function (c) { return schema.isContext(c, 2); })) return 4;   // v2AttrCert [2]
  if (certificates.some(function (c) { return schema.isContext(c, 1); }) ||           // v1AttrCert [1]
      signerInfos.some(function (si) { return si.version === 3; }) ||
      eContentType !== OID_DATA) return 3;
  return 1;
}

// EncapsulatedContentInfo ::= SEQUENCE { eContentType OID,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL } (RFC 5652 sec. 5.2). Absent eContent
// is a detached signature (surfaced as null); present is the raw content bytes.
var ENCAP_CONTENT_INFO = schema.seq([
  schema.field("eContentType", schema.oidLeaf()),
  schema.optional("eContent", schema.octetString(), { tag: 0, explicit: true, emptyCode: "cms/bad-econtent" }),
], {
  assert: "sequence", arity: { min: 1, max: 2 }, code: "cms/bad-encap-content-info", what: "EncapsulatedContentInfo",
  build: function (m) {
    return {
      eContentType: m.fields.eContentType.value,
      eContent: m.fields.eContent.present ? m.fields.eContent.value : null,
    };
  },
});

// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
// (RFC 5652 sec. 10.2.4). serialNumberHex preserves the DER sign padding.
var ISSUER_AND_SERIAL = schema.seq([
  schema.field("issuer", NAME),
  schema.field("serialNumber", schema.integerLeaf()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cms/bad-issuer-and-serial", what: "IssuerAndSerialNumber",
  build: function (m) {
    return {
      issuer: m.fields.issuer.value.result,
      serialNumber: m.fields.serialNumber.value,
      serialNumberHex: m.fields.serialNumber.node.content.toString("hex"),
    };
  },
});

// SignerIdentifier ::= CHOICE { issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] IMPLICIT OCTET STRING } (RFC 5652 sec. 5.3) -- the arm is
// disambiguated by tag (universal SEQUENCE vs context [0]).
var SIGNER_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: asn1.TAGS.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
], { code: "cms/bad-signer-identifier", what: "SignerIdentifier" });

// SignerInfo ::= SEQUENCE { version, sid SignerIdentifier, digestAlgorithm,
//   signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm, signature OCTET STRING,
//   unsignedAttrs [1] IMPLICIT OPTIONAL } (RFC 5652 sec. 5.3). signedAttrs/unsignedAttrs
// are positional optionals (a required signatureAlgorithm sits between them, so
// they cannot be a trailing block). ONE definition drives both consumers -- the
// signerInfos of a SignedData (mode "content") and a countersignature attribute
// value (mode "countersig", RFC 5652 sec. 11.4: syntactically a SignerInfo whose
// signedAttrs MUST carry message-digest and MUST NOT carry content-type) -- so
// the two can never diverge structurally.
function makeSignerInfo(mode) {
  return schema.seq([
    schema.field("version", SIGNER_VERSION),
    schema.field("sid", SIGNER_IDENTIFIER),
    schema.field("digestAlgorithm", ALGORITHM_IDENTIFIER),
    schema.optional("signedAttrs", schema.implicitSetOf(0, ATTRIBUTE, { min: 1, code: "cms/bad-signed-attrs", what: "signedAttrs" }), { tag: 0 }),
    schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
    schema.field("signature", schema.octetString()),
    schema.optional("unsignedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unsigned-attrs", what: "unsignedAttrs" }), { tag: 1 }),
  ], {
    assert: "sequence", code: "cms/bad-signer-info", what: "SignerInfo",
    build: function (m, ctx) {
      var version = m.fields.version.value;
      var sidNode = m.fields.sid.node;
      var isSkid = sidNode.tagClass === "context" && sidNode.tagNumber === 0;
      var sid;
      if (isSkid) {
        // RFC 5652 sec. 5.3 -- a subjectKeyIdentifier sid forces SignerInfo version 3.
        if (version !== 3) throw NS.E("cms/bad-signer-version", "a subjectKeyIdentifier signer identifier requires SignerInfo version 3");
        sid = { subjectKeyIdentifier: m.fields.sid.value };
      } else {
        // RFC 5652 sec. 5.3 -- an issuerAndSerialNumber sid forces SignerInfo version 1.
        if (version !== 1) throw NS.E("cms/bad-signer-version", "an issuerAndSerialNumber signer identifier requires SignerInfo version 1");
        sid = m.fields.sid.value.result;
      }
      var signedAttrs = null, signedAttrsBytes = null;
      if (m.fields.signedAttrs.present) {
        // sec. 5.3 -- signedAttrs MUST be DER even in a BER envelope (feeds the sec. 5.4 hash).
        _assertDerEncodedAttrs(m.fields.signedAttrs.node, "cms/bad-signed-attrs");
        signedAttrs = m.fields.signedAttrs.value.items.map(function (it) { return it.value.result; });
        _checkAttrPlacement(signedAttrs, "signed");
        _checkContentBindingAttrs(signedAttrs, mode);
        // The raw on-wire signedAttrs bytes (leading 0xA0) so a verifier can re-tag to
        // a universal SET and reproduce the signed hash (RFC 5652 sec. 5.4).
        signedAttrsBytes = m.fields.signedAttrs.node.bytes;
      }
      var unsignedAttrs = null;
      if (m.fields.unsignedAttrs.present) {
        unsignedAttrs = m.fields.unsignedAttrs.value.items.map(function (it) { return it.value.result; });
        _checkAttrPlacement(unsignedAttrs, "unsigned");
        // sec. 11.4 -- every countersignature value IS a SignerInfo (validated by
        // content, never accepted on the attribute type alone). Multiple
        // countersignature instances are explicitly permitted here, and a
        // countersignature's own unsignedAttrs may nest further ones -- the
        // recursion is bounded by the decoder's depth cap.
        for (var u = 0; u < unsignedAttrs.length; u++) {
          if (unsignedAttrs[u].type !== OID_COUNTERSIGNATURE) continue;
          for (var v = 0; v < unsignedAttrs[u].values.length; v++) {
            var csNode;
            try { csNode = asn1.decode(unsignedAttrs[u].values[v]); }
            catch (e) { throw NS.E("cms/bad-countersignature", "a countersignature attribute value must be DER (RFC 5652 sec. 11.4)", e); }
            schema.walk(COUNTERSIGNATURE_SIGNER_INFO, csNode, ctx);
          }
        }
      }
      return {
        version: version,
        sid: sid,
        digestAlgorithm: m.fields.digestAlgorithm.value.result,
        signedAttrs: signedAttrs,
        signedAttrsBytes: signedAttrsBytes,
        signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
        signature: m.fields.signature.value,
        unsignedAttrs: unsignedAttrs,
      };
    },
  });
}
var SIGNER_INFO = makeSignerInfo("content");
var COUNTERSIGNATURE_SIGNER_INFO = makeSignerInfo("countersig");

// SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms SET OF,
//   encapContentInfo, certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT
//   OPTIONAL, signerInfos SET OF } (RFC 5652 sec. 5.1). digestAlgorithms and
//   signerInfos are min:0 -- a degenerate certs-only SignedData carries neither.
var SIGNED_DATA = schema.seq([
  schema.field("version", SIGNED_DATA_VERSION),
  schema.field("digestAlgorithms", schema.setOf(ALGORITHM_IDENTIFIER, { min: 0, code: "cms/bad-digest-algorithms", what: "digestAlgorithms" })),
  schema.field("encapContentInfo", ENCAP_CONTENT_INFO),
  schema.optional("certificates", schema.implicitSetOf(0, schema.any(), { min: 1, code: "cms/bad-certificates", what: "certificates" }), { tag: 0 }),
  schema.optional("crls", schema.implicitSetOf(1, schema.any(), { min: 1, code: "cms/bad-crls", what: "crls" }), { tag: 1 }),
  schema.field("signerInfos", schema.setOf(SIGNER_INFO, { min: 0, code: "cms/bad-signer-infos", what: "signerInfos" })),
], {
  assert: "sequence", code: "cms/bad-signed-data", what: "SignedData",
  build: function (m) {
    var version = m.fields.version.value;
    var encapContentInfo = m.fields.encapContentInfo.value.result;
    var certificates = m.fields.certificates.present ? m.fields.certificates.value.items.map(rawChoiceElement(CERT_CHOICE_TAGS, "cms/bad-certificates", "certificates")) : [];
    var crls = m.fields.crls.present ? m.fields.crls.value.items.map(rawChoiceElement(CRL_CHOICE_TAGS, "cms/bad-crls", "crls")) : [];
    var signerInfos = m.fields.signerInfos.value.items.map(function (it) { return it.value.result; });

    // RFC 5652 sec. 5.3 -- signedAttrs MAY be omitted only when the content type is
    // id-data; any other eContentType requires each SignerInfo to carry signedAttrs
    // (so the content-type + message-digest attributes bind the signature).
    if (encapContentInfo.eContentType !== OID_DATA) {
      for (var s = 0; s < signerInfos.length; s++) {
        if (signerInfos[s].signedAttrs === null) throw NS.E("cms/missing-signed-attrs", "a SignerInfo must carry signedAttrs when the content type is not id-data (RFC 5652 sec. 5.3)");
      }
    }

    // RFC 5652 sec. 5.3 -- when signedAttrs are present, the content-type attribute's
    // value MUST equal the eContentType (a cross-field consistency both parsed
    // here; a mismatch is an internally-inconsistent SignedData).
    for (var si = 0; si < signerInfos.length; si++) {
      if (signerInfos[si].signedAttrs) _assertContentTypeMatchesAttrs(signerInfos[si].signedAttrs, encapContentInfo.eContentType);
    }

    // RFC 5652 sec. 5.1 -- the SignedData CMSVersion is determined by its contents.
    var expected = _expectedSignedDataVersion(certificates, crls, signerInfos, encapContentInfo.eContentType);
    if (version !== expected) throw NS.E("cms/bad-version", "SignedData version " + version + " does not match its contents (RFC 5652 sec. 5.1 requires v" + expected + ")");

    return {
      version: version,
      digestAlgorithms: m.fields.digestAlgorithms.value.items.map(function (it) { return it.value.result; }),
      encapContentInfo: encapContentInfo,
      certificates: certificates,
      crls: crls,
      signerInfos: signerInfos,
    };
  },
});

// ==== EnvelopedData / EncryptedData (RFC 5652 sec. 6/sec. 8, RFC 5753) ========
var T = asn1.TAGS;

// EncryptedContentInfo ::= SEQUENCE { contentType OID, contentEncryptionAlgorithm
//   AlgorithmIdentifier, encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL } (RFC
//   5652 sec. 6.1). encryptedContent is [0] IMPLICIT (context PRIMITIVE) -- its content
//   octets ARE the ciphertext directly, so it reads through implicitOctetString(0),
//   NOT the [0] EXPLICIT shape ENCAP_CONTENT_INFO uses (which would double-strip a
//   length header). The ciphertext + algorithm parameters are surfaced RAW.
var ENCRYPTED_CONTENT_INFO = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("contentEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.optional("encryptedContent", schema.implicitOctetString(0), { tag: 0 }),
], {
  assert: "sequence", arity: { min: 2, max: 3 }, code: "cms/bad-encrypted-content-info", what: "EncryptedContentInfo",
  build: function (m) {
    return {
      contentType: m.fields.contentType.value,
      contentEncryptionAlgorithm: m.fields.contentEncryptionAlgorithm.value.result,
      encryptedContent: m.fields.encryptedContent.present ? m.fields.encryptedContent.value : null,
    };
  },
});

// RecipientIdentifier ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier [0]
//   IMPLICIT OCTET STRING } (RFC 5652 sec. 6.2.1) -- structurally identical to
//   SignerIdentifier; reuse ISSUER_AND_SERIAL + the implicitOctetString(0) leaf.
var RECIPIENT_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
], { code: "cms/bad-recipient-identifier", what: "RecipientIdentifier" });

// KeyTransRecipientInfo ::= SEQUENCE { version(0|2), rid RecipientIdentifier,
//   keyEncryptionAlgorithm, encryptedKey OCTET STRING } (RFC 5652 sec. 6.2.1).
var KEY_TRANS_RECIPIENT_INFO = schema.seq([
  schema.field("version", KTRI_VERSION),
  schema.field("rid", RECIPIENT_IDENTIFIER),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-ktri", what: "KeyTransRecipientInfo",
  build: function (m) {
    var version = m.fields.version.value;
    var ridNode = m.fields.rid.node;
    var isSkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    // RFC 5652 sec. 6.2.1 -- rid <=> version: issuerAndSerialNumber => 0, subjectKeyIdentifier => 2.
    if (isSkid && version !== 2) throw NS.E("cms/bad-recipient-version", "a subjectKeyIdentifier recipient identifier requires KeyTransRecipientInfo version 2 (RFC 5652 sec. 6.2.1)");
    if (!isSkid && version !== 0) throw NS.E("cms/bad-recipient-version", "an issuerAndSerialNumber recipient identifier requires KeyTransRecipientInfo version 0 (RFC 5652 sec. 6.2.1)");
    return {
      type: "ktri", version: version,
      rid: isSkid ? { subjectKeyIdentifier: m.fields.rid.value } : m.fields.rid.value.result,
      ridType: isSkid ? "subjectKeyIdentifier" : "issuerAndSerialNumber",
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// OriginatorPublicKey ::= SEQUENCE { algorithm, publicKey BIT STRING } (RFC 5753
//   sec. 3.1.1), reached as originatorKey [1] IMPLICIT -- SPKI-shaped but cannot reuse
//   pkix.spki (which asserts a universal SEQUENCE), so assert:"constructed".
var ORIGINATOR_PUBLIC_KEY = schema.seq([
  schema.field("algorithm", ALGORITHM_IDENTIFIER),
  schema.field("publicKey", schema.bitString()),
], {
  assert: "constructed", code: "cms/bad-originator-public-key", what: "OriginatorPublicKey",
  build: function (m) { return { algorithm: m.fields.algorithm.value.result, publicKey: m.fields.publicKey.value }; },
});

// OriginatorIdentifierOrKey ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier
//   [0] IMPLICIT OCTET STRING, originatorKey [1] IMPLICIT OriginatorPublicKey }.
var ORIGINATOR_IDENTIFIER_OR_KEY = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
  { when: { tagClass: "context", tagNumber: 1 }, schema: ORIGINATOR_PUBLIC_KEY },
], { code: "cms/bad-originator-identifier", what: "OriginatorIdentifierOrKey" });

// RecipientKeyIdentifier (RFC 5652 sec. 6.2.2) and KEKIdentifier (sec. 6.2.3) are one
//   shape -- { <keyId> OCTET STRING, date GeneralizedTime OPTIONAL, other
//   OtherKeyAttribute OPTIONAL } -- differing only in the key-id field's name and
//   the enclosing tag form. One factory defines both so the OPTIONAL handling
//   (date and the raw-surfaced OtherKeyAttribute) cannot diverge between them.
function keyIdentifierSchema(keyIdName, assert, code, what) {
  return schema.seq([
    schema.field(keyIdName, schema.octetString()),
    schema.optional("date", schema.time(NS), { whenUniversal: [T.GENERALIZED_TIME] }),
    schema.optional("other", schema.any(), { whenUniversal: [T.SEQUENCE] }),
  ], {
    assert: assert, code: code, what: what,
    build: function (m) {
      var out = {};
      out[keyIdName] = m.fields[keyIdName].value;
      out.date = m.fields.date.present ? m.fields.date.value : null;
      out.other = m.fields.other.present ? m.fields.other.node.bytes : null;
      return out;
    },
  });
}

// Reached as rKeyId [0] IMPLICIT (a SEQUENCE -- constructed, unlike ktri's [0] leaf).
var RECIPIENT_KEY_IDENTIFIER = keyIdentifierSchema("subjectKeyIdentifier",
  "constructed", "cms/bad-recipient-key-identifier", "RecipientKeyIdentifier");

// KeyAgreeRecipientIdentifier ::= CHOICE { issuerAndSerialNumber, rKeyId [0] IMPLICIT
//   RecipientKeyIdentifier } (RFC 5652 sec. 6.2.2).
var KEY_AGREE_RECIPIENT_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: RECIPIENT_KEY_IDENTIFIER },
], { code: "cms/bad-kari-identifier", what: "KeyAgreeRecipientIdentifier" });

// RecipientEncryptedKey ::= SEQUENCE { rid KeyAgreeRecipientIdentifier, encryptedKey
//   OCTET STRING } (RFC 5652 sec. 6.2.2).
var RECIPIENT_ENCRYPTED_KEY = schema.seq([
  schema.field("rid", KEY_AGREE_RECIPIENT_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-recipient-encrypted-key", what: "RecipientEncryptedKey",
  build: function (m) {
    var ridNode = m.fields.rid.node;
    var isRkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    return {
      rid: m.fields.rid.value.result,
      // Which KeyAgreeRecipientIdentifier arm was taken -- the recipient-matching
      // form differs (mirrors ktri.ridType / kari.originator.form).
      ridType: isRkid ? "rKeyId" : "issuerAndSerialNumber",
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// KeyAgreeRecipientInfo ::= [1] IMPLICIT SEQUENCE { version(3), originator [0]
//   EXPLICIT OriginatorIdentifierOrKey, ukm [1] EXPLICIT OPTIONAL,
//   keyEncryptionAlgorithm, recipientEncryptedKeys SEQUENCE OF } (RFC 5652 sec. 6.2.2 +
//   RFC 5753 sec. 3.1.1). originator [0] is EXPLICIT (wraps a CHOICE).
var KEY_AGREE_RECIPIENT_INFO = schema.seq([
  schema.field("version", KARI_VERSION),
  schema.field("originator", schema.explicit(0, ORIGINATOR_IDENTIFIER_OR_KEY, { code: "cms/bad-kari" })),
  schema.optional("ukm", schema.octetString(), { tag: 1, explicit: true, emptyCode: "cms/bad-kari" }),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("recipientEncryptedKeys", schema.seqOf(RECIPIENT_ENCRYPTED_KEY, { code: "cms/bad-recipient-encrypted-keys", what: "recipientEncryptedKeys" })),
], {
  assert: "constructed", code: "cms/bad-kari", what: "KeyAgreeRecipientInfo",
  build: function (m) {
    var origNode = m.fields.originator.node.children[0];
    var origForm = origNode.tagClass === "context" ? (origNode.tagNumber === 0 ? "subjectKeyIdentifier" : "originatorKey") : "issuerAndSerialNumber";
    var origVal = m.fields.originator.value;
    return {
      type: "kari", version: m.fields.version.value,
      originator: { form: origForm, value: origForm === "subjectKeyIdentifier" ? origVal : origVal.result },
      ukm: m.fields.ukm.present ? m.fields.ukm.value : null,
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      recipientEncryptedKeys: m.fields.recipientEncryptedKeys.value.items.map(function (it) { return it.value.result; }),
    };
  },
});

// KEKRecipientInfo ::= [2] IMPLICIT SEQUENCE { version(4), kekid KEKIdentifier,
//   keyEncryptionAlgorithm, encryptedKey } (RFC 5652 sec. 6.2.3).
var KEK_IDENTIFIER = keyIdentifierSchema("keyIdentifier",
  "sequence", "cms/bad-kek-identifier", "KEKIdentifier");
var KEK_RECIPIENT_INFO = schema.seq([
  schema.field("version", KEKRI_VERSION),
  schema.field("kekid", KEK_IDENTIFIER),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "constructed", code: "cms/bad-kekri", what: "KEKRecipientInfo",
  build: function (m) {
    return {
      type: "kekri", version: m.fields.version.value,
      kekid: m.fields.kekid.value.result,
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// PasswordRecipientInfo ::= [3] IMPLICIT SEQUENCE { version(0), keyDerivationAlgorithm
//   [0] IMPLICIT AlgorithmIdentifier OPTIONAL, keyEncryptionAlgorithm, encryptedKey }
//   (RFC 5652 sec. 6.2.4). keyDerivationAlgorithm [0] IMPLICIT is the one field needing
//   the implicitTag AlgorithmIdentifier; present iff the first post-version node is [0].
var PASSWORD_RECIPIENT_INFO = schema.seq([
  schema.field("version", PWRI_VERSION),
  schema.optional("keyDerivationAlgorithm", pkix.algorithmIdentifier(NS, { implicitTag: 0 }), { tag: 0 }),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "constructed", code: "cms/bad-pwri", what: "PasswordRecipientInfo",
  build: function (m) {
    return {
      type: "pwri", version: m.fields.version.value,
      keyDerivationAlgorithm: m.fields.keyDerivationAlgorithm.present ? m.fields.keyDerivationAlgorithm.value.result : null,
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// KEMRecipientInfo ::= SEQUENCE { version CMSVersion (0), rid RecipientIdentifier,
//   kem KEMAlgorithmIdentifier, kemct OCTET STRING, kdf KeyDerivationAlgorithm-
//   Identifier, kekLength INTEGER (1..65535), ukm [0] EXPLICIT OPTIONAL, wrap
//   KeyEncryptionAlgorithmIdentifier, encryptedKey OCTET STRING } (RFC 9629 sec. 3).
//   Reached through the ori [4] arm under id-ori-kem. The kem / kdf params-absent
//   rules (ML-KEM, HKDF) ride the shared AlgorithmIdentifier registry guard.
var KEM_RECIPIENT_INFO = schema.seq([
  schema.field("version", KEMRI_VERSION),
  schema.field("rid", RECIPIENT_IDENTIFIER),
  schema.field("kem", ALGORITHM_IDENTIFIER),
  schema.field("kemct", schema.octetString()),
  schema.field("kdf", ALGORITHM_IDENTIFIER),
  schema.field("kekLength", schema.integerLeaf()),
  schema.optional("ukm", schema.octetString(), { tag: 0, explicit: true, emptyCode: "cms/bad-kem-recipient-info" }),
  schema.field("wrap", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-kem-recipient-info", what: "KEMRecipientInfo",
  build: function (m) {
    var ridNode = m.fields.rid.node;
    var isSkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    var kem = m.fields.kem.value.result;
    var kemct = m.fields.kemct.value;
    var wrap = m.fields.wrap.value.result;
    // kekLength INTEGER (1..65535) -- bound the unbounded INTEGER before narrowing.
    var kl = m.fields.kekLength.value;
    if (kl < 1n || kl > 65535n) throw NS.E("cms/bad-kek-length", "KEMRecipientInfo kekLength must be 1..65535 (RFC 9629 sec. 3)");
    var kekLength = Number(kl);
    // RFC 9629 sec. 3 -- kekLength MUST be consistent with the wrap algorithm; a
    // recognized AES key-wrap pins the exact KEK size (registry, not switch).
    var wrapLen = WRAP_KEK_LENGTHS[wrap.oid];
    if (wrapLen !== undefined && kekLength !== wrapLen) {
      // Coverage residual -- reached only when the OID is a registry entry (the guard above
      // guarantees it), so oid.name() never returns undefined and this fallback is a
      // defensive belt, not selectable through the public parse path.
      throw NS.E("cms/kek-length-mismatch", "kekLength " + kekLength + " does not match the " + (oid.name(wrap.oid) || wrap.oid) + " KEK size " + wrapLen + " (RFC 9629 sec. 3)");
    }
    // FIPS 203 -- a recognized ML-KEM kem produces a fixed-size ciphertext; any
    // other kemct length can never decapsulate.
    var ctLen = KEM_CT_LENGTHS[kem.oid];
    if (ctLen !== undefined && kemct.length !== ctLen) {
      // Coverage residual -- reached only when the OID is a registry entry (the guard above
      // guarantees it), so oid.name() never returns undefined and this fallback is a
      // defensive belt, not selectable through the public parse path.
      throw NS.E("cms/bad-kem-ciphertext", "the " + (oid.name(kem.oid) || kem.oid) + " kemct must be exactly " + ctLen + " octets (FIPS 203)");
    }
    return {
      version: m.fields.version.value,
      rid: isSkid ? { subjectKeyIdentifier: m.fields.rid.value } : m.fields.rid.value.result,
      ridType: isSkid ? "subjectKeyIdentifier" : "issuerAndSerialNumber",
      kem: kem,
      kemct: kemct,
      kdf: m.fields.kdf.value.result,
      kekLength: kekLength,
      ukm: m.fields.ukm.present ? m.fields.ukm.value : null,
      wrap: wrap,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// OtherRecipientInfo ::= [4] IMPLICIT SEQUENCE { oriType OID, oriValue ANY } (RFC
//   5652 sec. 6.2.5). A RECOGNIZED oriType is validated by content, never accepted on
//   the type OID alone: id-ori-kem walks KEMRecipientInfo (RFC 9629) and surfaces
//   the parsed structure as `kemri` alongside the raw oriValue. An unrecognized
//   oriType stays raw-opaque (the ORI extension point), kemri null.
var OTHER_RECIPIENT_INFO = schema.seq([
  schema.field("oriType", schema.oidLeaf()),
  schema.field("oriValue", schema.any()),
], {
  assert: "constructed", code: "cms/bad-ori", what: "OtherRecipientInfo",
  build: function (m, ctx) {
    var oriType = m.fields.oriType.value;
    var raw = m.fields.oriValue.node.bytes;
    if (oriType === OID_ORI_KEM) {
      var kemri = schema.walk(KEM_RECIPIENT_INFO, m.fields.oriValue.node, ctx).result;
      return { type: "ori", oriType: oriType, oriValue: raw, kemri: kemri };
    }
    return { type: "ori", oriType: oriType, oriValue: raw, kemri: null };
  },
});

// RecipientInfo ::= CHOICE { ktri KeyTransRecipientInfo, kari [1], kekri [2], pwri
//   [3], ori [4] } (RFC 5652 sec. 6.2). A bare universal SEQUENCE is ktri (the untagged
//   alternative). An unknown context tag -> no arm -> cms/bad-recipient-info.
var RECIPIENT_INFO = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: KEY_TRANS_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 1 }, schema: KEY_AGREE_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 2 }, schema: KEK_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 3 }, schema: PASSWORD_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 4 }, schema: OTHER_RECIPIENT_INFO },
], { code: "cms/bad-recipient-info", what: "RecipientInfo" });

// OriginatorInfo ::= [0] IMPLICIT SEQUENCE { certs [0] IMPLICIT OPTIONAL, crls [1]
//   IMPLICIT OPTIONAL } (RFC 5652 sec. 6.1). Members surfaced RAW (their outer tag feeds
//   the version rule).
var ORIGINATOR_INFO = schema.seq([
  schema.optional("certs", schema.implicitSetOf(0, schema.any(), { min: 1, code: "cms/bad-originator-certs", what: "certs" }), { tag: 0 }),
  schema.optional("crls", schema.implicitSetOf(1, schema.any(), { min: 1, code: "cms/bad-originator-crls", what: "crls" }), { tag: 1 }),
], {
  assert: "constructed", code: "cms/bad-originator-info", what: "OriginatorInfo",
  build: function (m) {
    return {
      certs: m.fields.certs.present ? m.fields.certs.value.items.map(rawChoiceElement(CERT_CHOICE_TAGS, "cms/bad-originator-certs", "OriginatorInfo certs")) : [],
      crls: m.fields.crls.present ? m.fields.crls.value.items.map(rawChoiceElement(CRL_CHOICE_TAGS, "cms/bad-originator-crls", "OriginatorInfo crls")) : [],
    };
  },
});

// RFC 5652 sec. 6.1 -- the exact EnvelopedData CMSVersion, from originatorInfo's raw
// cert/crl outer tags and the recipient arms (a cert `other` is [3], a v2AttrCert
// [2]; a crl `other` is [1]; a pwri or ori forces v3; all-ktri-IAS with no
// originatorInfo/unprotectedAttrs is v0; everything else v2).
function _expectedEnvelopedDataVersion(originatorInfo, recipientInfos, hasUnprotectedAttrs) {
  var hasOrig = !!originatorInfo;
  var certs = hasOrig ? originatorInfo.certs : [];
  var crls = hasOrig ? originatorInfo.crls : [];
  if (hasOrig && (certs.some(function (c) { return schema.isContext(c, 3); }) || crls.some(function (c) { return schema.isContext(c, 1); }))) return 4;
  if ((hasOrig && certs.some(function (c) { return schema.isContext(c, 2); })) ||
      recipientInfos.some(function (r) { return r.type === "pwri" || r.type === "ori"; })) return 3;
  if (!hasOrig && !hasUnprotectedAttrs &&
      recipientInfos.every(function (r) { return r.type === "ktri" && r.ridType === "issuerAndSerialNumber"; })) return 0;
  return 2;
}

// RFC 5652 sec. 9.1 -- the exact AuthenticatedData CMSVersion, from originatorInfo's raw
// cert/crl outer tags ONLY. Unlike EnvelopedData sec. 6.1, the recipient-info kinds do
// NOT influence the version. IF originatorInfo present AND (other-cert [3] OR
// other-crl [1]) -> 3; ELSE IF originatorInfo present AND v2AttrCert [2] -> 1; ELSE 0.
function _expectedAuthDataVersion(originatorInfo) {
  if (!originatorInfo) return 0;
  var certs = originatorInfo.certs, crls = originatorInfo.crls;
  if (certs.some(function (c) { return schema.isContext(c, 3); }) || crls.some(function (c) { return schema.isContext(c, 1); })) return 3;
  if (certs.some(function (c) { return schema.isContext(c, 2); })) return 1;
  return 0;
}

// EnvelopedData ::= SEQUENCE { version, originatorInfo [0] IMPLICIT OPTIONAL,
//   recipientInfos RecipientInfos (SET SIZE 1..MAX), encryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT OPTIONAL } (RFC 5652 sec. 6.1). recipientInfos is
//   min:1 (an empty SET is non-conformant -- the INVERSE of SignedData's degenerate
//   signerInfos).
var ENVELOPED_DATA = schema.seq([
  schema.field("version", ENVELOPED_DATA_VERSION),
  schema.optional("originatorInfo", ORIGINATOR_INFO, { tag: 0 }),
  schema.field("recipientInfos", schema.setOf(RECIPIENT_INFO, { min: 1, code: "cms/bad-recipient-infos", what: "recipientInfos" })),
  schema.field("encryptedContentInfo", ENCRYPTED_CONTENT_INFO),
  schema.optional("unprotectedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unprotected-attrs", what: "unprotectedAttrs" }), { tag: 1 }),
], {
  assert: "sequence", code: "cms/bad-enveloped-data", what: "EnvelopedData",
  build: function (m) {
    var version = m.fields.version.value;
    var originatorInfo = m.fields.originatorInfo.present ? m.fields.originatorInfo.value.result : null;
    var recipientInfos = m.fields.recipientInfos.value.items.map(function (it) { return it.value.result; });
    var hasUnprotectedAttrs = m.fields.unprotectedAttrs.present;
    var expected = _expectedEnvelopedDataVersion(originatorInfo, recipientInfos, hasUnprotectedAttrs);
    if (version !== expected) throw NS.E("cms/bad-version", "EnvelopedData version " + version + " does not match its contents (RFC 5652 sec. 6.1 requires v" + expected + ")");
    var unprotectedAttrs = hasUnprotectedAttrs ? m.fields.unprotectedAttrs.value.items.map(function (it) { return it.value.result; }) : null;
    if (unprotectedAttrs) _checkAttrPlacement(unprotectedAttrs, "unprotected");
    return {
      version: version,
      originatorInfo: originatorInfo,
      recipientInfos: recipientInfos,
      encryptedContentInfo: m.fields.encryptedContentInfo.value.result,
      unprotectedAttrs: unprotectedAttrs,
    };
  },
});

// EncryptedData ::= SEQUENCE { version, encryptedContentInfo, unprotectedAttrs [1]
//   IMPLICIT OPTIONAL } (RFC 5652 sec. 8) -- no recipients, no originatorInfo; the CEK is
//   distributed out of band. version is 0, or 2 iff unprotectedAttrs are present.
var ENCRYPTED_DATA = schema.seq([
  schema.field("version", ENCRYPTED_DATA_VERSION),
  schema.field("encryptedContentInfo", ENCRYPTED_CONTENT_INFO),
  schema.optional("unprotectedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unprotected-attrs", what: "unprotectedAttrs" }), { tag: 1 }),
], {
  assert: "sequence", code: "cms/bad-encrypted-data", what: "EncryptedData",
  build: function (m) {
    var version = m.fields.version.value;
    var hasUnprotectedAttrs = m.fields.unprotectedAttrs.present;
    var expected = hasUnprotectedAttrs ? 2 : 0;
    if (version !== expected) throw NS.E("cms/bad-version", "EncryptedData version " + version + " does not match its contents (RFC 5652 sec. 8 requires v" + expected + ")");
    var unprotectedAttrs = hasUnprotectedAttrs ? m.fields.unprotectedAttrs.value.items.map(function (it) { return it.value.result; }) : null;
    if (unprotectedAttrs) _checkAttrPlacement(unprotectedAttrs, "unprotected");
    return {
      version: version,
      encryptedContentInfo: m.fields.encryptedContentInfo.value.result,
      unprotectedAttrs: unprotectedAttrs,
    };
  },
});

// AuthenticatedData ::= SEQUENCE { version, originatorInfo [0] IMPLICIT OPTIONAL,
//   recipientInfos RecipientInfos, macAlgorithm, digestAlgorithm [1] OPTIONAL,
//   encapContentInfo, authAttrs [2] IMPLICIT OPTIONAL, mac OCTET STRING,
//   unauthAttrs [3] IMPLICIT OPTIONAL } (RFC 5652 sec. 9.1). digestAlgorithm [1] is
//   IMPLICIT (module default) -- the same shape as pwri's keyDerivationAlgorithm.
var AUTHENTICATED_DATA = schema.seq([
  schema.field("version", AUTHDATA_VERSION),
  schema.optional("originatorInfo", ORIGINATOR_INFO, { tag: 0 }),
  schema.field("recipientInfos", schema.setOf(RECIPIENT_INFO, { min: 1, code: "cms/bad-recipient-infos", what: "recipientInfos" })),
  schema.field("macAlgorithm", ALGORITHM_IDENTIFIER),
  schema.optional("digestAlgorithm", pkix.algorithmIdentifier(NS, { implicitTag: 1 }), { tag: 1 }),
  schema.field("encapContentInfo", ENCAP_CONTENT_INFO),
  schema.optional("authAttrs", schema.implicitSetOf(2, ATTRIBUTE, { min: 1, code: "cms/bad-auth-attrs", what: "authAttrs" }), { tag: 2 }),
  schema.field("mac", schema.octetString()),
  schema.optional("unauthAttrs", schema.implicitSetOf(3, ATTRIBUTE, { min: 1, code: "cms/bad-unauth-attrs", what: "unauthAttrs" }), { tag: 3 }),
], {
  assert: "sequence", code: "cms/bad-auth-data", what: "AuthenticatedData",
  build: function (m) {
    var version = m.fields.version.value;
    var originatorInfo = m.fields.originatorInfo.present ? m.fields.originatorInfo.value.result : null;
    var encapContentInfo = m.fields.encapContentInfo.value.result;
    var hasDigestAlg = m.fields.digestAlgorithm.present;
    var hasAuthAttrs = m.fields.authAttrs.present;

    // RFC 5652 sec. 9.1 -- the version is computed from originatorInfo's raw cert/crl
    // tags only (recipient kinds never influence it, unlike EnvelopedData sec. 6.1).
    var expected = _expectedAuthDataVersion(originatorInfo);
    if (version !== expected) throw NS.E("cms/bad-version", "AuthenticatedData version " + version + " does not match its contents (RFC 5652 sec. 9.1 requires v" + expected + ")");

    // RFC 5652 sec. 9.1 -- authAttrs MUST be present when the content type is not
    // id-data, and digestAlgorithm <=> authAttrs is a strict biconditional.
    if (!hasAuthAttrs && encapContentInfo.eContentType !== OID_DATA) {
      throw NS.E("cms/missing-auth-attrs", "AuthenticatedData must carry authAttrs when the content type is not id-data (RFC 5652 sec. 9.1)");
    }
    if (hasDigestAlg && !hasAuthAttrs) throw NS.E("cms/missing-auth-attrs", "a digestAlgorithm requires authAttrs (RFC 5652 sec. 9.1)");
    if (hasAuthAttrs && !hasDigestAlg) throw NS.E("cms/missing-digest-algorithm", "authAttrs require a digestAlgorithm (RFC 5652 sec. 9.1)");

    var authAttrs = null, authAttrsBytes = null;
    if (hasAuthAttrs) {
      // sec. 9.1 -- AuthAttributes MUST be DER even in a BER envelope (feeds the sec. 9.2 MAC).
      _assertDerEncodedAttrs(m.fields.authAttrs.node, "cms/bad-auth-attrs");
      authAttrs = m.fields.authAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(authAttrs, "auth");
      // sec. 9.1 -- authAttrs MUST contain content-type + message-digest (sec. 11.1/sec. 11.2),
      // and the content-type value MUST equal the eContentType.
      _checkContentBindingAttrs(authAttrs, "content");
      _assertContentTypeMatchesAttrs(authAttrs, encapContentInfo.eContentType);
      // The raw on-wire authAttrs bytes (leading 0xA2) so a verifier can re-tag to
      // a universal SET and reproduce the MAC input (RFC 5652 sec. 9.2).
      authAttrsBytes = m.fields.authAttrs.node.bytes;
    }
    var unauthAttrs = null;
    if (m.fields.unauthAttrs.present) {
      unauthAttrs = m.fields.unauthAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(unauthAttrs, "unauth");
    }
    return {
      version: version,
      originatorInfo: originatorInfo,
      recipientInfos: m.fields.recipientInfos.value.items.map(function (it) { return it.value.result; }),
      macAlgorithm: m.fields.macAlgorithm.value.result,
      digestAlgorithm: hasDigestAlg ? m.fields.digestAlgorithm.value.result : null,
      encapContentInfo: encapContentInfo,
      authAttrs: authAttrs,
      authAttrsBytes: authAttrsBytes,
      mac: m.fields.mac.value,
      unauthAttrs: unauthAttrs,
    };
  },
});

// AuthEnvelopedData ::= SEQUENCE { version CMSVersion (0), originatorInfo [0]
//   IMPLICIT OPTIONAL, recipientInfos RecipientInfos, authEncryptedContentInfo
//   EncryptedContentInfo, authAttrs [1] IMPLICIT OPTIONAL, mac OCTET STRING,
//   unauthAttrs [2] IMPLICIT OPTIONAL } (RFC 5083 sec. 2.1). The version is a fixed 0
//   -- originatorInfo contents never change it. The authAttrs tags are SHIFTED
//   ([1]/[2]) relative to AuthenticatedData's ([2]/[3]).
var AUTH_ENVELOPED_DATA = schema.seq([
  schema.field("version", AUTHENV_VERSION),
  schema.optional("originatorInfo", ORIGINATOR_INFO, { tag: 0 }),
  schema.field("recipientInfos", schema.setOf(RECIPIENT_INFO, { min: 1, code: "cms/bad-recipient-infos", what: "recipientInfos" })),
  schema.field("authEncryptedContentInfo", ENCRYPTED_CONTENT_INFO),
  schema.optional("authAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-auth-attrs", what: "authAttrs" }), { tag: 1 }),
  schema.field("mac", schema.octetString()),
  schema.optional("unauthAttrs", schema.implicitSetOf(2, ATTRIBUTE, { min: 1, code: "cms/bad-unauth-attrs", what: "unauthAttrs" }), { tag: 2 }),
], {
  assert: "sequence", code: "cms/bad-auth-enveloped-data", what: "AuthEnvelopedData",
  build: function (m) {
    var encryptedContentInfo = m.fields.authEncryptedContentInfo.value.result;
    var mac = m.fields.mac.value;
    // RFC 5084 -- a recognized AES-GCM/CCM content-encryption algorithm carries
    // validated parameters, and its aes-ICVlen MUST equal the mac length.
    var aead = _validateAeadParams(encryptedContentInfo.contentEncryptionAlgorithm, mac.length);

    // RFC 5083 sec. 2.1 -- authAttrs MUST be present when the content type carried in
    // EncryptedContentInfo is not id-data.
    var hasAuthAttrs = m.fields.authAttrs.present;
    if (!hasAuthAttrs && encryptedContentInfo.contentType !== OID_DATA) {
      throw NS.E("cms/missing-auth-attrs", "AuthEnvelopedData must carry authAttrs when the content type is not id-data (RFC 5083 sec. 2.1)");
    }
    var authAttrs = null, authAttrsBytes = null;
    if (hasAuthAttrs) {
      // RFC 5083 sec. 2.1 -- AuthAttributes MUST be DER even in a BER envelope (the
      // sec. 2.2 AAD is the re-tagged DER SET). No content-type/message-digest
      // presence rules bind here (sec. 11.1/sec. 11.2 name signed-data and
      // authenticated-data; sec. 2.1 says message-digest SHOULD NOT appear), so only
      // the duplicate rule, the sec. 11 placement rows, and -- when a content-type
      // attribute IS present -- the value == contentType coherence apply.
      _assertDerEncodedAttrs(m.fields.authAttrs.node, "cms/bad-auth-attrs");
      authAttrs = m.fields.authAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(authAttrs, "auth");
      _checkNoDuplicateAttrs(authAttrs);
      _assertContentTypeMatchesAttrs(authAttrs, encryptedContentInfo.contentType);
      authAttrsBytes = m.fields.authAttrs.node.bytes;
    }
    var unauthAttrs = null;
    if (m.fields.unauthAttrs.present) {
      unauthAttrs = m.fields.unauthAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(unauthAttrs, "unauth");
    }
    return {
      version: m.fields.version.value,
      originatorInfo: m.fields.originatorInfo.present ? m.fields.originatorInfo.value.result : null,
      recipientInfos: m.fields.recipientInfos.value.items.map(function (it) { return it.value.result; }),
      encryptedContentInfo: encryptedContentInfo,
      aead: aead,
      authAttrs: authAttrs,
      authAttrsBytes: authAttrsBytes,
      mac: mac,
      unauthAttrs: unauthAttrs,
    };
  },
});

// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY DEFINED BY
//   contentType } (RFC 5652 sec. 3). The content is captured raw (explicit(0, any()))
//   and re-dispatched by contentType inside the build: id-signedData walks
//   SIGNED_DATA; id-envelopedData / id-encryptedData / id-ct-authData /
//   id-ct-authEnvelopedData walk their schemas; the other PKCS#7 types are
//   recognized-and-deferred; unknown OIDs are rejected.
// CompressedData ::= SEQUENCE { version CMSVersion (0), compressionAlgorithm
//   CompressionAlgorithmIdentifier, encapContentInfo EncapsulatedContentInfo }
//   (RFC 3274 sec. 1.1). The eContent is an RFC 1950 ZLIB stream of the inner
//   content. Parse decodes the structure and surfaces the raw compressionAlgorithm
//   + eContent; the zlib-only algorithm check + the bounded inflate live in the
//   pki.cms.decompress consuming operation, not the parser (mirroring how the
//   content-encryption algorithm is validated by decrypt, not the envelope parse).
var COMPRESSED_DATA = schema.seq([
  schema.field("version", COMPRESSED_DATA_VERSION),
  schema.field("compressionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encapContentInfo", ENCAP_CONTENT_INFO),
], {
  assert: "sequence", code: "cms/bad-compressed-data", what: "CompressedData",
  build: function (m) {
    return {
      version: m.fields.version.value,
      compressionAlgorithm: m.fields.compressionAlgorithm.value.result,
      encapContentInfo: m.fields.encapContentInfo.value.result,
    };
  },
});

var CONTENT_INFO = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("content", schema.explicit(0, schema.any(), { code: "cms/not-a-content-info" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cms/not-a-content-info", what: "ContentInfo",
  build: function (m, ctx) {
    var ct = m.fields.contentType.value;
    var inner = null;
    if (ct === OID_SIGNED_DATA) inner = SIGNED_DATA;
    else if (ct === OID_ENVELOPED_DATA) inner = ENVELOPED_DATA;
    else if (ct === OID_ENCRYPTED_DATA) inner = ENCRYPTED_DATA;
    else if (ct === OID_AUTH_DATA) inner = AUTHENTICATED_DATA;
    else if (ct === OID_AUTH_ENVELOPED_DATA) inner = AUTH_ENVELOPED_DATA;
    else if (ct === OID_COMPRESSED_DATA) inner = COMPRESSED_DATA;
    if (inner === null) {
      if (DEFERRED.has(ct)) {
        // Coverage residual -- reached only when the OID is a registry entry (the guard above
        // guarantees it), so oid.name() never returns undefined and this fallback is a
        // defensive belt, not selectable through the public parse path.
        throw NS.E("cms/unsupported-content-type", (ctx.oid.name(ct) || ct) + " is recognized but not parsed by this build");
      }
      throw NS.E("cms/unknown-content-type", "unrecognized ContentInfo content type " + ct);
    }
    // The dispatched ContentInfo type rides the result (mirroring the ocsp
    // responseType/responseTypeName pair and the RecipientInfo `type` tags), so
    // a consumer branches on contentTypeName instead of duck-typing the shape.
    var result = schema.walk(inner, m.fields.content.value, ctx).result;
    result.contentType = ct;
    // Coverage residual -- reached only when the OID is a registry entry (the guard above
    // guarantees it), so oid.name() never returns undefined and this fallback is a
    // defensive belt, not selectable through the public parse path.
    result.contentTypeName = ctx.oid.name(ct) || null;
    return result;
  },
});

/**
 * @primitive  pki.schema.cms.parse
 * @signature  pki.schema.cms.parse(input) -> content
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 5652, RFC 5083, RFC 9629
 * @related    pki.schema.parse, pki.schema.x509.parse
 *
 * Parse a DER `Buffer` or a PEM (`CMS`) string into the structured content the
 * ContentInfo carries, dispatched by its content type. `id-signedData` returns
 * `{ version, digestAlgorithms, encapContentInfo, certificates, crls,
 * signerInfos }`; `id-envelopedData` returns `{ version, originatorInfo,
 * recipientInfos, encryptedContentInfo, unprotectedAttrs }`; `id-encryptedData`
 * returns `{ version, encryptedContentInfo, unprotectedAttrs }`; `id-ct-authData`
 * returns `{ version, originatorInfo, recipientInfos, macAlgorithm,
 * digestAlgorithm, encapContentInfo, authAttrs, authAttrsBytes, mac,
 * unauthAttrs }`; `id-ct-authEnvelopedData` returns `{ version, originatorInfo,
 * recipientInfos, encryptedContentInfo, aead, authAttrs, authAttrsBytes, mac,
 * unauthAttrs }` (`aead` holds the validated AES-GCM/CCM nonce + ICV length, or
 * `null` for an unrecognized algorithm). A KEM recipient (RFC 9629) surfaces as
 * `{ type: "ori", oriType, oriValue, kemri }` with the parsed KEMRecipientInfo in
 * `kemri`. Every result additionally carries `contentType` (the dotted OID) and
 * `contentTypeName` (its registry name) naming which of the five shapes was
 * dispatched. Raw byte ranges an external verifier hashes -- `eContent`,
 * `signature`, `signedAttrsBytes`, `authAttrsBytes`, `mac` -- are surfaced
 * exactly as on the wire. The remaining PKCS#7 types throw `cms/unsupported-content-type`; an
 * unrecognized OID throws `cms/unknown-content-type`; a malformed structure
 * throws a typed `CmsError` (`cms/*`) and a leaf-level codec fault surfaces as
 * `asn1/*`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     serialNumber: 0x0a1bn, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: key });
 *   var der = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   var cms = pki.schema.cms.parse(der);
 *   cms.signerInfos[0].sid.serialNumberHex;   // -> "0a1b"
 *   cms.encapContentInfo.eContent;            // -> Buffer | null (detached)
 */
// Recording, for the reason the certificate and CRL parsers are: a SignedData is one or more
// signatures over byte ranges, and a parsed one presents those ranges (`signedAttrsBytes`, the
// encapsulated `eContent`), the signatures, and the certificates that verify them as separate
// properties of one object. Keep a genuine signer's `signature` and `signedAttrsBytes` and replace
// the `eContent` beside them, and every part of the check still passes for content that signer never
// signed -- which is exactly the forgery pki.cms.verify's own block claims to defend. The verdict
// verbs re-derive from what is recorded here, so the object a caller passes names bytes rather than
// asserting facts.
var parse = pkix.makeRecordingParser({ pemLabel: "CMS", PemError: PemError, ErrorClass: CmsError, prefix: "cms", what: "CMS ContentInfo", topSchema: CONTENT_INFO, ns: NS }, "cms");

/**
 * @primitive  pki.schema.cms.pemDecode
 * @signature  pki.schema.cms.pemDecode(text, label?) -> Buffer
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 7468, RFC 5652
 * @related    pki.schema.cms.parse
 *
 * Extract the DER bytes from a PEM CMS block (default label `CMS`). Throws
 * `PemError` on a missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var pemText = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key }, { pem: true });
 *   var der = pki.schema.cms.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "CMS", PemError); }

/**
 * @primitive  pki.schema.cms.pemEncode
 * @signature  pki.schema.cms.pemEncode(der, label?) -> string
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.cms.pemDecode
 *
 * Wrap DER bytes in a PEM CMS envelope (default label `CMS`).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var der = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   var pem = pki.schema.cms.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "CMS", PemError); }

// A CMS ContentInfo root is the only registered structure whose root leads with an
// OBJECT IDENTIFIER child: a SEQUENCE of exactly 2 whose first child is an OID and
// second a context [0] constructed wrapper. x509/crl/csr lead with a tbs SEQUENCE
// and pkcs8 with an INTEGER, so the detectors are mutually exclusive regardless of
// registry order.
function matches(root) {
  var TAGS = asn1.TAGS;
  var k = pkix.rootSequenceChildren(root, 2, 2);
  if (!k) return false;
  if (!schema.isUniversal(k[0], TAGS.OBJECT_IDENTIFIER)) return false;
  if (!(schema.isContext(k[1], 0) && k[1].children)) return false;
  return true;
}

// Validate a bare EnvelopedData (RFC 5652 sec. 6.1) -- a universal SEQUENCE node --
// returning its structured value; throws a typed cms/* error on a malformed
// structure. Exposed for a composer that carries a bare EnvelopedData OUTSIDE a
// ContentInfo (an RFC 4211 CRMF encryptedKey [4] POPOPrivKey arm), which the
// content-type dispatch in `parse` cannot reach. The node MUST already be a
// universal SEQUENCE (an IMPLICIT [n] EnvelopedData is retagged by the caller).
function walkEnvelopedData(node) { return schema.walk(ENVELOPED_DATA, node, NS).result; }

// Validate a bare SignedData / EncryptedData node the same way -- for a composer
// that holds an already-decoded content node and must not re-decode its bytes
// (an RFC 7292 PFX authSafe or encrypted safe, whose wire encoding may be BER
// that the strict `parse` entry would refuse). Same contract as
// walkEnvelopedData: the node is the bare structure, typed cms/* on rejection.
// Records provenance, like parse: the structure a consumer hands to pki.cms.verify must be
// re-derivable from the bytes it was walked from, and a PFX authSafe reaches verify this way. The
// walker's own BER-tolerant decode is what replays it -- the strict `parse` entry would refuse the
// indefinite-length encoding real stores carry.
var walkSignedData = guard.parsed.recordingWalker("cms", function (node) {
  return schema.walk(SIGNED_DATA, node, NS).result;
}, function (der) { return asn1.decode(der, { ber: true }); });
function walkEncryptedData(node) { return schema.walk(ENCRYPTED_DATA, node, NS).result; }
// Validate + surface one countersignature value (RFC 5652 sec. 11.4, Countersignature ::=
// SignerInfo) into the same parsed shape parse() gives a top-level SignerInfo -- so pki.cms.verify
// can verify a countersignature through the ONE SignerInfo definition (its sec. 11.4 rules
// enforced: message-digest present, content-type FORBIDDEN via mode "countersig"). The node is the
// bare id-countersignature value; a malformed / content-type-carrying value throws a typed cms/*.
function walkCountersignature(node) { return schema.walk(COUNTERSIGNATURE_SIGNER_INFO, node, NS).result; }

// assertAttachedCiphertext(eci, E, code, label): reject an EnvelopedData /
// EncryptedData encryptedContentInfo whose encryptedContent (the payload itself)
// is absent OR zero-length. RFC 5652 sec. 6.1 / RFC 5083 permit DETACHED content,
// so this is NOT enforced in the base walker -- it is a per-PROFILE opt-in for a
// consumer that requires the ciphertext to be present (an EST server-generated
// key, a PKCS#12 shrouded bag): a valid envelope that delivers NOTHING is
// verification-of-nothing (CWE-20). E is the caller's (code, message) factory.
function assertAttachedCiphertext(eci, E, code, label) {
  if (!eci || eci.encryptedContent === null || eci.encryptedContent.length === 0) {
    throw E(code, (label || "encrypted content") + " must carry a non-empty attached ciphertext (RFC 5652 sec. 6.1), not be detached or empty");
  }
  return eci;
}

// The "certs-only" Simple PKI Response (RFC 5272 sec. 4.1): a degenerate SignedData carrying certificates (and
// optionally CRLs) but NO signed content -- id-data with no eContent and EMPTY signerInfos. It is how RFC 7030
// EST returns a CA chain (/cacerts) and how an RFC 5280 sec. 4.2.2.1 AIA caIssuers URL may serve issuers
// (application/pkcs7-mime). Returns { certificates: [raw DER], crls: [raw DER] } -- the RAW bytes only; the
// caller validates each cert/CRL for its own purpose (EST re-parses; path building runs each through validate).
// Shared so the EST client and the path builder decode an identical shape; the caller passes its typed-error
// factory `E(code, msg, cause)` and domain `prefix` so a fault surfaces the caller's own `prefix/*` code.
// `maxCerts` (optional) caps how many certificates / CRLs are validated + returned, BEFORE the per-element
// X.509 / CRL parse -- so an untrusted source (an AIA caIssuers URL) cannot force tens of thousands of parses
// with one in-cap-bytes bundle; the EST client passes no cap (a /cacerts chain is small and fully returned).
function parseCertsOnly(der, E, prefix, maxCerts) {
  var r;
  try { r = parse(der); }
  catch (e) { throw E(prefix + "/bad-response", "a certs-only response did not decode as CMS: " + ((e && e.message) || String(e)), e); }
  if (r.contentTypeName !== "signedData") throw E(prefix + "/not-certs-only", "a certs-only response must be a CMS SignedData (RFC 5272 sec. 4.1)");
  if (r.encapContentInfo.eContentType !== OID_DATA || r.encapContentInfo.eContent !== null) {
    throw E(prefix + "/not-certs-only", "a certs-only Simple PKI Response must carry id-data with no eContent (RFC 5272 sec. 4.1)");
  }
  if (r.signerInfos.length !== 0) throw E(prefix + "/not-certs-only", "a certs-only Simple PKI Response must have empty signerInfos (RFC 5272 sec. 4.1)");
  if (!r.certificates || r.certificates.length === 0) throw E(prefix + "/no-certificates", "a certs-only response must contain at least one certificate (RFC 5272 sec. 4.1)");
  // Cap BEFORE the per-certificate X.509 parse: bound parse work by count, not only by the decoded byte size.
  var certs = (maxCerts != null && r.certificates.length > maxCerts) ? r.certificates.slice(0, maxCerts) : r.certificates;
  for (var i = 0; i < certs.length; i++) {
    // A universal-SEQUENCE CertificateChoice must be a well-formed X.509 Certificate, not merely any SEQUENCE;
    // a tagged CertificateChoices alternative (attribute cert / other) is not a plain certificate.
    if (certs[i].tagClass !== "universal") throw E(prefix + "/bad-certificate-choice", "a certs-only response exchanges plain X.509 certificates; a tagged CertificateChoices alternative is not permitted (RFC 5272)");
    try { schemaX509.parse(certs[i].bytes); }
    catch (e) { throw E(prefix + "/bad-certificate", "a certs-only response carried a non-certificate in its certificates field (RFC 5272 sec. 4.1)", e); }
  }
  var allCrls = r.crls || [];
  var crls = (maxCerts != null && allCrls.length > maxCerts) ? allCrls.slice(0, maxCerts) : allCrls;
  for (var j = 0; j < crls.length; j++) {
    if (crls[j].tagClass !== "universal") throw E(prefix + "/bad-crl", "a certs-only response CRL must be a plain X.509 CertificateList, not a tagged otherRevInfo alternative (RFC 5652 sec. 10.2.1)");
    try { schemaCrl.parse(crls[j].bytes); }
    catch (e) { throw E(prefix + "/bad-crl", "a certs-only response carried a non-CRL in its crls field", e); }
  }
  return {
    certificates: certs.map(function (c) { return c.bytes; }),
    crls: crls.map(function (c) { return c.bytes; }),
  };
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  parseCertsOnly: parseCertsOnly,
  walkEnvelopedData: walkEnvelopedData,
  walkSignedData: walkSignedData,
  walkEncryptedData: walkEncryptedData,
  walkCountersignature: walkCountersignature,
  looksLikeSignedAttributes: looksLikeSignedAttributes,
  assertAttachedCiphertext: assertAttachedCiphertext,
  // The structure's own algorithm tables, exported (like the walk* helpers) as the single source
  // of truth the crypto layer (cms-encrypt / cms-decrypt) shares -- so the wrap<->KEK-length, the
  // ML-KEM ciphertext-length, and the AEAD-mode/ICV-length rules the parser enforces cannot drift
  // from what the producer/consumer emit and accept.
  WRAP_KEK_LENGTHS: WRAP_KEK_LENGTHS,
  KEM_CT_LENGTHS: KEM_CT_LENGTHS,
  AEAD_ALGS: AEAD_ALGS,
  AEAD_GCM_ICVLENS: AEAD_GCM_ICVLENS,
  AEAD_CCM_ICVLENS: AEAD_CCM_ICVLENS,
};
