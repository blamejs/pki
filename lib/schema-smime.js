// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.smime
 * @nav        Schema
 * @title      S/MIME (ESS)
 * @fullname   S/MIME signed and encrypted mail, with ESS security labels
 * @order      180
 * @slug       smime
 *
 * @intro
 *   S/MIME Enhanced Security Services signed-attribute values per RFC 5035 (ESS)
 *   and RFC 8551 (S/MIME 4.0). These are the DER-decoded VALUES of CMS signed
 *   attributes: they ride inside a `SignerInfo.signedAttrs`, so this is a
 *   companion decoder a CMS consumer invokes by attribute OID, not a top-level
 *   format the schema orchestrator auto-routes.
 *
 *   `parseSigningCertificate` / `parseSigningCertificateV2` decode the ESS
 *   signing-certificate attributes that bind a signature to the exact certificate
 *   that made it: each surfaces its list of `ESSCertID`(v2) (the certificate hash
 *   (raw), the hash algorithm (decoded for v2, or the implied SHA-1 for v1), and
 *   the optional `issuerSerial` (issuer `GeneralNames` validated + surfaced raw,
 *   serial as a BigInt + hex)) plus the optional certificate policies.
 *   `buildSigningCertificateV2` encodes the v2 attribute value a signer attaches:
 *   one `ESSCertIDv2` per certificate, the SHA-256 form with the DEFAULT algorithm
 *   omitted and SHA-384 / SHA-512 with an absent parameters field.
 *   `parseSmimeCapabilities` decodes the ordered `SMIMECapabilities` list (each a
 *   capability OID + raw parameters). `decodeAttribute` takes a CMS-shaped
 *   `{ type, values }` attribute, enforces the single-`AttributeValue` rule
 *   (RFC 8551 sec. 2.5.2), routes on the attribute OID, and recognize-and-defers an
 *   unknown attribute type with its raw values intact.
 *
 *   Structure is decoded; verification is the consumer's. The parser surfaces
 *   `certHash` + `hashAlgorithm` + `issuerSerial` so a verifier recomputes the
 *   certificate hash (compose `webcrypto`) and matches the issuer/serial against
 *   the actual signing certificate; it never recomputes a hash or trusts a cert.
 *   Whether an attribute is correctly placed in `signedAttrs` (vs `unsignedAttrs`)
 *   is the CMS consumer's knowledge. DER-only, fail-closed.
 *
 * @card
 *   Decode RFC 5035 ESS SigningCertificate / SigningCertificateV2 and RFC 8551
 *   SMIMECapabilities signed-attribute values: cert-hash binding, validated
 *   issuer GeneralNames, ordered capability list, OID-dispatched, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var constants = require("./constants");
var x509 = require("./schema-x509");

var SmimeError = frameworkError.SmimeError;
var PemError = frameworkError.PemError;
var b = asn1.build;

var NS = pkix.makeNS("smime", SmimeError, oid);
var TAGS = asn1.TAGS;

var ALGID = pkix.algorithmIdentifier(NS);

var OID_SHA1 = oid.byName("sha1");
var OID_SHA256 = oid.byName("sha256");
var OID_SIGNING_CERTIFICATE = oid.byName("signingCertificate");
var OID_SIGNING_CERTIFICATE_V2 = oid.byName("signingCertificateV2");
var OID_SMIME_CAPABILITIES = oid.byName("smimeCapabilities");

/** @internal The digests this module will BIND a certificate with. RFC 5035 sec. 4 leaves
 *  `hashAlgorithm` open, and the two readers that consume the field disagree on the set they admit,
 *  so the builder emits only what the strictest consumer accepts: SHA-1 is excluded because a
 *  binding is an identity claim, and an identifier a verifier refuses is a token nobody can use. */
var BIND_DIGESTS = intrinsic.assign(intrinsic.create(null), { sha256: 1, sha384: 1, sha512: 1 });

var GENERAL_NAME_DIRECTORY = 4;
var ISSUER_SERIAL = schema.seq([
  schema.field("issuer", pkix.generalNames(NS, { code: "smime/bad-general-names" })),
  schema.field("serialNumber", schema.integerLeaf()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "smime/bad-issuer-serial", what: "IssuerSerial",
  build: function (m) {
    return {
      issuer: m.fields.issuer.value.result,
      serialNumber: m.fields.serialNumber.value,
      serialNumberHex: intrinsic.bufToString(m.fields.serialNumber.node.content, "hex"),
    };
  },
});

function assertSignerIssuerIsDirectoryName(certs, fail) {
  if (!certs.length || !certs[0].issuerSerial) return;
  var names = certs[0].issuerSerial.issuer.names;
  if (names.length !== 1 || names[0].tagClass !== "context" || names[0].tagNumber !== GENERAL_NAME_DIRECTORY) {
    fail("the signing certificate's IssuerSerial issuer MUST be exactly one directoryName [4] GeneralName (RFC 5035 sec. 5)");
  }
}

var POLICY_INFORMATION = schema.seq([
  schema.field("policyIdentifier", schema.oidLeaf()),
  schema.optional("policyQualifiers", schema.any(), { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "smime/bad-policy-information", what: "PolicyInformation",
  build: function (m, ctx) {
    var qualifiers = null;
    if (m.fields.policyQualifiers.present) {
      var q = m.fields.policyQualifiers.node;
      pkix.assertPolicyQualifiers(q, function (msg, cause) { throw ctx.E("smime/bad-policy-information", msg, cause); });
      qualifiers = q.bytes;
    }
    return {
      policyIdentifier: m.fields.policyIdentifier.value,
      name: ctx.oid.name(m.fields.policyIdentifier.value) || null,
      policyQualifiers: qualifiers,
    };
  },
});
var POLICIES = schema.seqOf(POLICY_INFORMATION, {
  assert: "sequence", min: 0, code: "smime/bad-policies", what: "policies",
  build: function (m) { return intrinsic.map(m.items, function (it) { return it.value.result; }); },
});

var ESS_CERT_ID = schema.seq([
  schema.field("certHash", schema.octetString()),
  schema.optional("issuerSerial", ISSUER_SERIAL, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "smime/bad-ess-cert-id", what: "ESSCertID",
  build: function (m) {
    return {
      certHash: m.fields.certHash.value,
      hashAlgorithm: { oid: OID_SHA1, name: "sha1", parameters: null, implied: true },
      issuerSerial: m.fields.issuerSerial.present ? m.fields.issuerSerial.value.result : null,
    };
  },
});

var ESS_CERT_ID_V2 = schema.seq([
  schema.optional("hashAlgorithm", ALGID, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.field("certHash", schema.octetString()),
  schema.optional("issuerSerial", ISSUER_SERIAL, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "smime/bad-ess-cert-id-v2", what: "ESSCertIDv2",
  build: function (m, ctx) {
    var hashAlgorithm;
    if (m.fields.hashAlgorithm.present) {
      var alg = m.fields.hashAlgorithm.value.result;
      if (alg.oid === OID_SHA256 && alg.parameters === null) {
        throw ctx.E("smime/non-canonical-default",
          "ESSCertIDv2 hashAlgorithm equal to the DEFAULT {algorithm id-sha256} MUST be omitted (X.690 sec. 11.5)");
      }
      hashAlgorithm = { oid: alg.oid, name: alg.name, parameters: alg.parameters, defaulted: false };
    } else {
      hashAlgorithm = { oid: OID_SHA256, name: "sha256", parameters: null, defaulted: true };
    }
    return {
      certHash: m.fields.certHash.value,
      hashAlgorithm: hashAlgorithm,
      issuerSerial: m.fields.issuerSerial.present ? m.fields.issuerSerial.value.result : null,
    };
  },
});

function signingCertificateSchema(essCertId, code, what) {
  return schema.seq([
    schema.field("certs", schema.seqOf(essCertId, { assert: "sequence", min: 1, code: "smime/bad-certs", what: "certs" })),
    schema.optional("policies", POLICIES, { whenUniversal: [TAGS.SEQUENCE] }),
  ], {
    assert: "sequence", code: code, what: what,
    build: function (m, ctx) {
      var certs = intrinsic.map(m.fields.certs.value.items, function (it) { return it.value.result; });
      assertSignerIssuerIsDirectoryName(certs, function (msg) { throw ctx.E("smime/bad-issuer-serial", msg); });
      return {
        certs: certs,
        policies: m.fields.policies.present ? m.fields.policies.value.result : null,
      };
    },
  });
}
var SIGNING_CERTIFICATE = signingCertificateSchema(ESS_CERT_ID, "smime/bad-signing-certificate", "SigningCertificate");
var SIGNING_CERTIFICATE_V2 = signingCertificateSchema(ESS_CERT_ID_V2, "smime/bad-signing-certificate-v2", "SigningCertificateV2");

var SMIME_CAPABILITY = schema.seq([
  schema.field("capabilityID", schema.oidLeaf()),
  schema.optional("parameters", schema.any(), { whenAny: true }),
], {
  assert: "sequence", code: "smime/bad-capability", what: "SMIMECapability",
  build: function (m, ctx) {
    return {
      capabilityID: m.fields.capabilityID.value,
      name: ctx.oid.name(m.fields.capabilityID.value) || null,
      parameters: m.fields.parameters.present ? m.fields.parameters.node.bytes : null,
    };
  },
});
var SMIME_CAPABILITIES = schema.seqOf(SMIME_CAPABILITY, {
  assert: "sequence", min: 0, code: "smime/bad-capabilities", what: "SMIMECapabilities",
  build: function (m) { return { capabilities: intrinsic.map(m.items, function (it) { return it.value.result; }) }; },
});

/**
 * @primitive  pki.schema.smime.parseSigningCertificate
 * @signature  pki.schema.smime.parseSigningCertificate(der, caps?) -> { certs, policies }
 * @since      0.1.22
 * @status     stable
 * @spec       RFC 5035, RFC 2634
 * @related    pki.schema.smime.parseSigningCertificateV2, pki.schema.smime.decodeAttribute
 *
 * Decode an ESS v1 `SigningCertificate` attribute value (RFC 5035 sec. 5.4.2): the
 * raw `AttributeValue` a CMS consumer plucks off `SignerInfo.signedAttrs`. Returns
 * `{ certs, policies }`: each `certs` entry is `{ certHash, hashAlgorithm,
 * issuerSerial }` in wire order (the first is the signing certificate), where
 * `hashAlgorithm` is the implied SHA-1 (v1 carries no algorithm field) and
 * `issuerSerial` (or `null`) surfaces the issuer `GeneralNames` + serial. Throws a
 * typed `smime/*` (or leaf `asn1/*`) error on malformed input.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var essCertId = b.sequence([b.octetString(Buffer.alloc(20, 1))]);   // SHA-1 hash, no issuerSerial
 *   var av = b.sequence([b.sequence([essCertId])]);                     // SigningCertificate { certs }
 *   var sc = pki.schema.smime.parseSigningCertificate(av);
 *   sc.certs[0].hashAlgorithm.name;    // "sha1" (implied)
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. A parse that exceeds one is
 *     refused with the `/too-large` code of this format.
 */
var parseSigningCertificate = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: SmimeError, prefix: "smime", what: "SigningCertificate", topSchema: SIGNING_CERTIFICATE, ns: NS });

/**
 * @primitive  pki.schema.smime.parseSigningCertificateV2
 * @signature  pki.schema.smime.parseSigningCertificateV2(der) -> { certs, policies }
 * @since      0.1.22
 * @status     stable
 * @spec       RFC 5035, RFC 5816
 * @related    pki.schema.smime.parseSigningCertificate, pki.schema.smime.decodeAttribute
 *
 * Decode an ESS v2 `SigningCertificateV2` attribute value (RFC 5035 sec. 5.4.1).
 * Identical shape to v1 but each `certs` entry carries a real `hashAlgorithm`:
 * decoded when present, or the RFC 5035 sec. 4 default `id-sha256` (with
 * `defaulted: true`) when omitted. An explicit `hashAlgorithm` byte-equal to that
 * default is a non-canonical DER encoding and is rejected `smime/non-canonical-default`
 * (X.690 sec. 11.5). Throws a typed `smime/*` error on malformed input.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var essCertId = b.sequence([b.octetString(Buffer.alloc(32, 2))]);   // hashAlgorithm defaulted
 *   var av = b.sequence([b.sequence([essCertId])]);
 *   var sc = pki.schema.smime.parseSigningCertificateV2(av);
 *   sc.certs[0].hashAlgorithm.defaulted;   // true (SHA-256 default)
 */
var parseSigningCertificateV2 = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: SmimeError, prefix: "smime", what: "SigningCertificateV2", topSchema: SIGNING_CERTIFICATE_V2, ns: NS });

/**
 * @primitive  pki.schema.smime.parseSmimeCapabilities
 * @signature  pki.schema.smime.parseSmimeCapabilities(der, caps?) -> { capabilities }
 * @since      0.1.22
 * @status     stable
 * @spec       RFC 8551
 * @related    pki.schema.smime.decodeAttribute
 *
 * Decode an `SMIMECapabilities` attribute value (RFC 8551 sec. 2.5.2) into
 * `{ capabilities }`, an ordered list (preference order, never sorted), each
 * `{ capabilityID, name, parameters }` with `parameters` the raw
 * `ANY DEFINED BY capabilityID` bytes (or `null`). Throws a typed `smime/*` error
 * on malformed input.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var cap = b.sequence([b.oid(pki.oid.byName("aes256-CBC"))]);
 *   var caps = pki.schema.smime.parseSmimeCapabilities(b.sequence([cap]));
 *   caps.capabilities[0].name;    // "aes256-CBC"
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. A parse that exceeds one is
 *     refused with the `/too-large` code of this format.
 */
var parseSmimeCapabilities = pkix.makeParser({ pemLabel: null, PemError: PemError, ErrorClass: SmimeError, prefix: "smime", what: "SMIMECapabilities", topSchema: SMIME_CAPABILITIES, ns: NS });

function _err(code, message) { return new SmimeError(code, message); }

/** @internal The digests a signing-certificate identifier may BIND a certificate with, on the
 *  reading side. It is the set the builder emits, and it is narrower than the set the ESS decoder
 *  will decode: an identifier is an identity claim, so admitting a digest nobody should bind with
 *  would let the claim be satisfied by a certificate other than the one that signed. SHA-1 is not
 *  here and is reported as weak by its own flag, because the v1 attribute has no algorithm field
 *  and is SHA-1 by definition (RFC 2634), so a reader must be able to tell "weak" from "unknown". */
var BIND_VERIFY_DIGESTS = intrinsic.assign(intrinsic.create(null), { sha256: 1, sha384: 1, sha512: 1 });
var GENERAL_NAME = pkix.generalName(NS, { decodeValue: true, code: "smime/bad-general-names" });

/** @internal What ONE signing-certificate attribute claims about `certDer`, as facts rather than a
 *  verdict. Each claim is read and compared here so there is one implementation of "does this
 *  identifier name that certificate", and the two consumers apply their own policy to the result:
 *  `pki.tsp.verify` refuses a token, and `pki.cms.verify` reports a CAdES conformance finding.
 *
 *  An ESSCertID states the signer in two independent ways, and both are compared: the hash under
 *  the identifier's own digest, and the issuer and serial where it carries them (RFC 5035 clause 5,
 *  RFC 2634 clause 5.4). A hash that agrees beside an issuer and serial naming another certificate
 *  is a contradiction, not a match. Identifiers after the first are not read: RFC 2634 clause 5.4
 *  makes the first the signing certificate and leaves the rest as the chain. */
function _bindingEntry(attr, certDer) {
  var out = { form: attr.type === OID_SIGNING_CERTIFICATE_V2 ? "v2" : "v1", readable: false,
    digestName: null, supported: false, weak: false, matches: null, certUnreadable: false,
    issuerSerialPresent: false, issuerSerialMatches: null };
  var decoded;
  try { decoded = decodeAttribute(attr); }
  catch (_e) { return out; }
  var ess = decoded.certs && decoded.certs[0];
  if (!ess) return out;
  out.readable = true;
  out.digestName = ess.hashAlgorithm == null ? "sha1" : ess.hashAlgorithm.name;
  out.weak = intrinsic.hasOwn(constants.NAMES.WEAK_DIGESTS, out.digestName);
  out.supported = out.weak || intrinsic.hasOwn(BIND_VERIFY_DIGESTS, out.digestName);
  if (!out.supported) return out;
  /** @internal Through the captured digest and the constant-time comparison: this IS the binding
   *  between a signature and the certificate its attribute names, so neither what the digest covers
   *  nor how the result is compared is the caller's to choose. */
  out.matches = guard.crypto.constantTimeEqual(guard.crypto.digest(out.digestName, certDer), ess.certHash);
  if (!ess.issuerSerial) return out;
  out.issuerSerialPresent = true;
  /** @internal A certificate that does not parse is its own fact, kept apart from an attribute that
   *  does not decode: one says the identifier is malformed and the other says the thing it would be
   *  compared against is, and a consumer orders the two itself. Folding them into one flag moved a
   *  refusal from "this identifier names another certificate" to "this attribute is unreadable". */
  var cert;
  try { cert = x509.parse(certDer); }
  catch (_e2) { out.certUnreadable = true; return out; }
  if (ess.issuerSerial.serialNumber !== cert.serialNumber) { out.issuerSerialMatches = false; return out; }
  var names = ess.issuerSerial.issuer.names || [];
  var gn = null;
  try {
    if (names.length === 1) {
      gn = schema.embeddedDer(GENERAL_NAME, names[0].bytes, NS,
        { code: "smime/bad-general-names", what: "GeneralName" });
    }
  } catch (_e3) { gn = null; }
  out.issuerSerialMatches = !!gn && gn.tagNumber === GENERAL_NAME_DIRECTORY && !!gn.value &&
    guard.name.dnEqual(gn.value.rdns, cert.issuer.rdns, _err, "smime/bad-issuer-serial",
      "the ESSCertID issuer");
  return out;
}

/** @internal Every signing-certificate attribute in `signedAttrs`, read against `certDer`.
 *  `chosen` is the v2 attribute where there is one, which supersedes v1 (RFC 5035); `superseded`
 *  holds the rest, which a consumer still holds to the same claim, because one structure making two
 *  incompatible statements about one fact is a contradiction rather than something to resolve in
 *  favor of whichever attribute a reader prefers. EVERY attribute is collected rather than the first
 *  of each type: `signedAttrs` is a DER SET OF, so which of two comes first is a function of their
 *  encodings and a hostile producer picks it.
 *
 * @internal
 */
function certBindingFacts(signedAttrs, certDer) {
  var found = [];
  intrinsic.forEach(signedAttrs || [], function (a) {
    if (a && (a.type === OID_SIGNING_CERTIFICATE || a.type === OID_SIGNING_CERTIFICATE_V2)) {
      guard.list.append(found, a);
    }
  });
  if (!found.length) return { present: false, chosen: null, superseded: [] };
  var chosenAt = 0;
  for (var i = 0; i < found.length; i++) {
    if (found[i].type === OID_SIGNING_CERTIFICATE_V2) { chosenAt = i; break; }
  }
  var superseded = [];
  for (var j = 0; j < found.length; j++) {
    if (j !== chosenAt) guard.list.append(superseded, _bindingEntry(found[j], certDer));
  }
  return { present: true, chosen: _bindingEntry(found[chosenAt], certDer), superseded: superseded };
}

var _BUILD_V2_OPTS = intrinsic.assign(intrinsic.create(null), { hashAlgorithm: 1 });

/**
 * @primitive  pki.schema.smime.buildSigningCertificateV2
 * @signature  pki.schema.smime.buildSigningCertificateV2(certs, opts?) -> Buffer
 * @since      0.8.52
 * @status     stable
 * @spec       RFC 5035, RFC 5754
 * @related    pki.schema.smime.parseSigningCertificateV2, pki.cms.sign, pki.tsp.sign
 *
 * Encode an ESS `SigningCertificateV2` attribute value (RFC 5035 sec. 5.4.1), the signed attribute
 * that binds a signature to the certificate that made it. `certs` is the signer's certificate DER,
 * or a list of certificate DERs whose first entry is the signer's (RFC 5035 sec. 5.4); each entry
 * becomes an `ESSCertIDv2` carrying that certificate's hash. The result is the single
 * `AttributeValue` of a `signingCertificateV2` signed attribute, which is what CAdES requires a
 * signature to carry (ETSI EN 319 122-1 clauses 5.2.2.2 and 5.2.2.3).
 *
 * `opts.hashAlgorithm` names the binding digest: `sha256` (the default), `sha384` or `sha512`. The
 * SHA-256 form omits the `hashAlgorithm` field, which is the RFC 5035 sec. 4 DEFAULT and so must be
 * absent (X.690 sec. 11.5); the other two emit an `AlgorithmIdentifier` with the parameters field
 * absent, which RFC 5754 sec. 2 requires an implementation to generate. SHA-1 is refused
 * `smime/unsupported-algorithm`: a binding is an identity claim, and `pki.tsp.verify` refuses a
 * SHA-1 one as a weak binding.
 *
 * The OPTIONAL `issuerSerial` and `policies` fields are not emitted; CAdES has the issuer serial
 * omitted (ETSI EN 319 122-1 clause 6.3 requirement g). A caller that needs either field builds the
 * value with `pki.asn1.build`, and `parseSigningCertificateV2` reads both back.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var av = pki.schema.smime.buildSigningCertificateV2(signerCertDer);
 *   var msg = await pki.cms.sign(Buffer.from("hello"), { cert: signerCertDer, key: key },
 *     { additionalSignedAttributes: [{ type: "signingCertificateV2", values: [av] }] });
 *   (await pki.cms.verify(msg, { certs: [signerCertDer] })).signers[0].cadesBaseline.conformant;   // true
 */
function buildSigningCertificateV2(certs, opts) {
  guard.identifier.assertKnownKeys(opts, _BUILD_V2_OPTS, _err, "smime/bad-input",
    "pki.schema.smime.buildSigningCertificateV2 has an unknown option ");
  var settings = guard.identifier.pickSettings(opts, ["hashAlgorithm"]);
  var hashName = settings.hashAlgorithm === undefined || settings.hashAlgorithm === null ? "sha256" : settings.hashAlgorithm;
  if (typeof hashName !== "string" || !BIND_DIGESTS[guard.text.keyOf(hashName)]) {
    throw _err("smime/unsupported-algorithm", "the ESSCertIDv2 binding digest must be sha256, sha384 or sha512, got " +
      guard.text.showValue(hashName));
  }
  var list = guard.list.snapshot(intrinsic.isArray(certs) ? certs : [certs]);
  if (!list.length) {
    throw _err("smime/bad-input", "a SigningCertificateV2 needs at least one certificate, the signer's first (RFC 5035 sec. 5.4)");
  }
  var ids = [];
  for (var i = 0; i < list.length; i++) {
    var der = guard.bytes.view(list[i], SmimeError, "smime/bad-input", "the certificate at certs[" + i + "]");
    var certHash = b.octetString(guard.crypto.digest(hashName, der));
    guard.list.append(ids, hashName === "sha256"
      ? b.sequence([certHash])
      : b.sequence([b.sequence([b.oid(oid.byName(hashName))]), certHash]));
  }
  return b.sequence([b.sequence(ids)]);
}

/**
 * @primitive  pki.schema.smime.decodeAttribute
 * @signature  pki.schema.smime.decodeAttribute(attr) -> { kind, ... }
 * @since      0.1.22
 * @status     stable
 * @spec       RFC 8551, RFC 5035
 * @related    pki.schema.smime.parseSigningCertificate, pki.schema.cms.parse
 *
 * OID-dispatch convenience over the three value decoders for a CMS-shaped
 * `{ type, values }` attribute (the shape `cms.parse` surfaces on
 * `signerInfos[i].signedAttrs`). Enforces the single-`AttributeValue` rule
 * (RFC 8551 sec. 2.5.2 / sec. 2.5), so a `values` length other than 1 is rejected
 * `smime/multi-valued-attribute`, then routes on `attr.type`:
 * `signingCertificate` / `signingCertificateV2` / `smimeCapabilities` decode to
 * `{ kind, ...result }`; any other type is recognize-and-deferred
 * `smime/unsupported-attribute` (its `type`, registry `name`, and raw `values`
 * carried on the error so a caller keeps the bytes).
 *
 * @example
 *   var b = pki.asn1.build;
 *   var essCertId = b.sequence([b.octetString(Buffer.alloc(32, 2))]);   // ESSCertIDv2, hashAlgorithm defaulted
 *   var av = b.sequence([b.sequence([essCertId])]);                     // SigningCertificateV2 { certs: [ ESSCertIDv2 ] }
 *   var got = pki.schema.smime.decodeAttribute({ type: pki.oid.byName("signingCertificateV2"), values: [av] });
 *   got.kind;    // "signingCertificateV2"
 */
function decodeAttribute(attr) {
  if (!attr || typeof attr !== "object" || typeof attr.type !== "string" || !intrinsic.isArray(attr.values)) {
    throw new SmimeError("smime/bad-input", "decodeAttribute expects a CMS attribute { type, values }");
  }
  if (attr.type === OID_SIGNING_CERTIFICATE || attr.type === OID_SIGNING_CERTIFICATE_V2 || attr.type === OID_SMIME_CAPABILITIES) {
    if (attr.values.length !== 1) {
      throw new SmimeError("smime/multi-valued-attribute",
        "an ESS / SMIMECapabilities attribute MUST carry exactly one AttributeValue, got " + attr.values.length + " (RFC 8551 sec. 2.5.2)");
    }
    var value = attr.values[0];
    if (attr.type === OID_SIGNING_CERTIFICATE) { var v1 = parseSigningCertificate(value); return { kind: "signingCertificate", certs: v1.certs, policies: v1.policies }; }
    if (attr.type === OID_SIGNING_CERTIFICATE_V2) { var v2 = parseSigningCertificateV2(value); return { kind: "signingCertificateV2", certs: v2.certs, policies: v2.policies }; }
    return { kind: "smimeCapabilities", capabilities: parseSmimeCapabilities(value).capabilities };
  }
  var e = new SmimeError("smime/unsupported-attribute", "unsupported S/MIME attribute type " + attr.type + (oid.name(attr.type) ? " (" + oid.name(attr.type) + ")" : ""));
  e.type = attr.type;
  e.name = oid.name(attr.type) || null;
  e.values = attr.values;
  throw e;
}

module.exports = {
  buildSigningCertificateV2: buildSigningCertificateV2,
  certBindingFacts: certBindingFacts,   // @internal

  parseSigningCertificate: parseSigningCertificate,
  parseSigningCertificateV2: parseSigningCertificateV2,
  parseSmimeCapabilities: parseSmimeCapabilities,
  decodeAttribute: decodeAttribute,
};
