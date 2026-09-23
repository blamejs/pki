// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.crl
 * @nav        Schema
 * @title      CRL
 * @order      120
 * @slug       crl
 *
 * @intro
 *   X.509 Certificate Revocation List handling per RFC 5280 sec. 5. `parse` turns a
 *   DER or PEM CRL into a structured, fully-decoded object: version, issuer
 *   distinguished name, this/next update as real `Date`s, the ordered list of
 *   revoked certificates (serial + revocation date + entry extensions), and the
 *   CRL extensions. It composes the same schema engine and shared PKIX
 *   sub-schemas (AlgorithmIdentifier, Name, Extension) the certificate parser
 *   uses, so the CertificateList inherits the identical fail-closed structural
 *   rules, and the raw `tbsCertList` bytes are returned for signature checking.
 *
 * @card
 *   Parse DER / PEM X.509 CRLs into structured, validated fields: revoked
 *   serials with real-`Date` revocation times, named extensions, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;

var CrlError = frameworkError.CrlError;
var PemError = frameworkError.PemError;
var TAGS = asn1.TAGS;



var NS = pkix.makeNS("crl", CrlError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);
var EXTENSIONS = pkix.extensions(NS);
var TIME = pkix.time(NS);

var CRL_VERSION = pkix.versionReader(NS, { "1": 2 });

/** @internal The decoders are the shared scope registry's, so which extensions a CRL profiles at
 * which scope is stated once rather than in an if/else chain here. What stays here is this
 * module's own wrapping: every fault becomes `crl/bad-extension-value` naming the extension, and
 * an OID no scope profiles keeps its raw value. The signature and the `undefined`-means-both
 * reading are unchanged, because `lib/lint.js` calls this with one argument. */
var CRL_EXT_DECODERS = pkix.crlExtensionDecoders(NS);

function decodeExt(ext, scope, ctx) {
  var value = ext.value;
  var decoder = CRL_EXT_DECODERS.at(ext.oid, scope);
  if (decoder !== null) {
    try { value = decoder(ext.value, ctx); }
    catch (e) {
      throw NS.E("crl/bad-extension-value", "malformed " + (ext.name || ext.oid) + " extension value: " + ((e && e.message) || String(e)), e);
    }
  }
  return { oid: ext.oid, name: ext.name, critical: ext.critical, value: value, valueBytes: ext.value };
}

var REVOKED_ENTRY = schema.seq([
  schema.field("userCertificate", schema.integerLeaf()),
  schema.field("revocationDate", TIME),
  schema.optional("crlEntryExtensions", EXTENSIONS, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", arity: { min: 2 }, code: "crl/bad-revoked-entry", what: "RevokedCertificate",
  build: function (m, ctx) {
    return {
      serialNumber: m.fields.userCertificate.value,
      serialNumberHex: m.fields.userCertificate.node.content.toString("hex"),
      revocationDate: m.fields.revocationDate.value,
      crlEntryExtensions: m.fields.crlEntryExtensions.present
        ? m.fields.crlEntryExtensions.value.result.map(function (e) { return decodeExt(e, "entry", ctx); })
        : [],
    };
  },
});

var REVOKED_LIST = schema.seqOf(REVOKED_ENTRY, {
  assert: "sequence", min: 1, code: "crl/bad-revoked-certificates", what: "revokedCertificates",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// allow:schema-build-drops-parsed-field
var TBS_CERTLIST = schema.seq([
  schema.optional("version", CRL_VERSION, { whenUniversal: [TAGS.INTEGER] }),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("issuer", NAME),
  schema.field("thisUpdate", TIME),
  schema.optional("nextUpdate", TIME, { whenUniversal: [TAGS.UTC_TIME, TAGS.GENERALIZED_TIME] }),
  schema.optional("revokedCertificates", REVOKED_LIST, { whenUniversal: [TAGS.SEQUENCE] }),
  schema.trailing([{ tag: 0, name: "crlExtensions", schema: EXTENSIONS, explicit: true, emptyCode: "crl/bad-extensions" }],
    { minTag: 0, maxTag: 0, unexpectedCode: "crl/bad-tbs", orderCode: "crl/bad-tbs" }),
], {
  assert: "sequence", code: "crl/bad-tbs", what: "tbsCertList",
  build: function (m, ctx) {
    return {
      version: m.fields.version.present ? m.fields.version.value : 1,
      issuer: m.fields.issuer.value.result,
      thisUpdate: m.fields.thisUpdate.value,
      nextUpdate: m.fields.nextUpdate.present ? m.fields.nextUpdate.value : null,
      revokedCertificates: m.fields.revokedCertificates.present ? m.fields.revokedCertificates.value.result : [],
      crlExtensions: m.fields.crlExtensions.present
        ? m.fields.crlExtensions.value.result.map(function (e) { return decodeExt(e, "crl", ctx); })
        : [],
      crlExtensionsPresent: m.fields.crlExtensions.present,
    };
  },
});

var CERTIFICATE_LIST = pkix.signedEnvelope(NS, TBS_CERTLIST, {
  code: "crl/not-a-crl", what: "CertificateList",
  build: function (e) {
    var tbs = e.tbsMatch.result;
    if (!e.outerSignatureAlgorithmBytes.equals(e.tbsMatch.fields.signature.node.bytes)) {
      throw NS.E("crl/bad-signature-algorithm", "signatureAlgorithm must match tbsCertList.signature (RFC 5280 sec. 5.1.1.2)");
    }
    if (!tbs.issuer.rdns.length) {
      throw NS.E("crl/bad-issuer", "issuer must be a non-empty distinguished name");
    }
    var hasExtensions = tbs.crlExtensionsPresent ||
      tbs.revokedCertificates.some(function (r) { return r.crlEntryExtensions.length > 0; });
    if (hasExtensions && tbs.version !== 2) {
      throw NS.E("crl/bad-version", "crlExtensions / crlEntryExtensions are only permitted in a v2 CRL");
    }
    return {
      version: tbs.version,
      issuer: tbs.issuer,
      thisUpdate: tbs.thisUpdate,
      nextUpdate: tbs.nextUpdate,
      revokedCertificates: tbs.revokedCertificates,
      crlExtensions: tbs.crlExtensions,
      tbsBytes: e.tbsBytes,
      signatureAlgorithm: e.signatureAlgorithm,
      signatureValue: e.signatureValue,
    };
  },
});

/**
 * @primitive  pki.schema.crl.parse
 * @signature  pki.schema.crl.parse(input, caps?) -> crl
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 5280
 * @related    pki.schema.x509.parse, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM (`X509 CRL`) string into a structured CRL:
 * `{ version, issuer, thisUpdate, nextUpdate, revokedCertificates,
 * crlExtensions, tbsBytes, signatureAlgorithm, signatureValue }`. Every field is
 * validated on the way in; a malformed CertificateList / TBSCertList throws a
 * typed `CrlError` (`crl/*`) and a leaf-level codec fault surfaces as `asn1/*`.
 *
 * Each extension record is `{ oid, name, critical, value, valueBytes }`. `valueBytes` is the raw
 * `extnValue` octets and `value` is the decoded form for the three extensions this parse decodes in
 * place, `cRLNumber`, `reasonCode` and `invalidityDate`, and the same octets for every other.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
 *   var der = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n,
 *     revoked: [{ serialNumber: 0x0a3fn, revocationDate: new Date("2026-01-15T00:00:00Z") }] },
 *     { cert: caCert, key: key });
 *   var crl = pki.schema.crl.parse(der);
 *   crl.revokedCertificates[0].serialNumberHex;  // -> "0a3f"
 * @opts
 *   - `maxBytes` / `maxDepth` / `maxItems` (number) -- decode caps for this parse. Each
 *     defaults to the matching `pki.C.LIMITS` figure and may only be set lower; a value
 *     above it, or an option outside this set, is refused. A parse that exceeds one is
 *     refused with the `/too-large` code of this format.
 */
var parse = pkix.makeRecordingParser({ pemLabel: "X509 CRL", PemError: PemError, ErrorClass: CrlError, prefix: "crl", what: "CRL", topSchema: CERTIFICATE_LIST, ns: NS }, "crl");

/**
 * @primitive  pki.schema.crl.pemDecode
 * @signature  pki.schema.crl.pemDecode(text, label?) -> Buffer
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.crl.parse
 *
 * Extract the DER bytes from a PEM CRL block (default label `X509 CRL`). Throws
 * `PemError` on a missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: key });
 *   var pemText = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
 *     { cert: caCert, key: key }, { pem: true });
 *   var der = pki.schema.crl.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "X509 CRL", PemError); }

/**
 * @primitive  pki.schema.crl.pemEncode
 * @signature  pki.schema.crl.pemEncode(der, label?) -> string
 * @since      0.1.23
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.crl.pemDecode
 *
 * Wrap CRL DER bytes in a PEM envelope with 64-column base64 lines (default
 * label `X509 CRL`, the RFC 7468 sec. 6 armor `pemDecode` expects back).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: key });
 *   var der = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
 *     { cert: caCert, key: key });
 *   var pem = pki.schema.crl.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "X509 CRL", PemError); }

function matches(root) {
  var tbs = pkix.signedEnvelopeTbs(root);
  if (!tbs) return false;
  if (tbs.children[0] && tbs.children[0].tagClass === "context") return false;
  var i = 0;
  if (schema.isUniversal(tbs.children[i], TAGS.INTEGER)) i++;
  i += 2;
  var pos = tbs.children[i];
  return schema.isUniversalOneOf(pos, [TAGS.UTC_TIME, TAGS.GENERALIZED_TIME]);
}

/** @internal The criticality RFC 5280 sec. 5.3 fixes for each CRL entry extension, from the shared
 *  scope registry: the CRL signer, the OCSP signer (sec. 4.4.5 carries the same extensions into a
 *  SingleResponse) and the linter all read this one table. */
function entryExtensionCriticality(oidRegistry) {
  return pkix.crlEntryFixedCriticality(oidRegistry);
}
/** @internal Reads a CRL entry extension's value the way this parser reads it, for a consumer that
 *  meets one outside a CRL (an OCSP SingleResponse, RFC 6960 sec. 4.4.5): reasonCode and
 *  invalidityDate through `decodeExt`, certificateIssuer as the GeneralNames the CRL profile leaves
 *  raw. Returns the record with its decoded `value`; throws `crl/bad-extension-value`. */
var OID_CERTIFICATE_ISSUER = oid.byName("certificateIssuer");
var CERTIFICATE_ISSUER_NAMES = pkix.generalNames(NS, { code: "crl/bad-extension-value" });
function readEntryExtension(ext, ctx) {
  if (ext.oid !== OID_CERTIFICATE_ISSUER) return decodeExt(ext, undefined, ctx);
  var names;
  try { names = schema.walk(CERTIFICATE_ISSUER_NAMES, pkix.decodeNested(ext.value, ctx, "a certificateIssuer extension value"), ctx || NS).result; }
  catch (e) {
    throw NS.E("crl/bad-extension-value", "malformed certificateIssuer extension value: " + ((e && e.message) || intrinsic.String(e)), e);
  }
  return { oid: ext.oid, name: ext.name, critical: ext.critical, value: names, valueBytes: ext.value };
}

/** @internal The three scopes a CRL reader meets, as the shared door reads them. `ocsp-single`
 *  carries the entry tables under its own key because RFC 6960 sec. 4.4.5 puts a CRL entry
 *  extension in an OCSP SingleResponse, where the row should say where it was read rather than
 *  claim it came off a CRL entry. */
function crlDoorTable(arm) {
  return function (ctx) { return pkix.crlExtensionDecoders(ctx).doorScope[arm]; };
}
var CRL_SCOPES = intrinsic.assign(intrinsic.create(null), {
  "crl": { decoders: crlDoorTable("crl"), criticality: pkix.crlFixedCriticality(oid) },
  "crl-entry": { decoders: crlDoorTable("entry"), criticality: pkix.crlEntryFixedCriticality(oid) },
  "ocsp-single": { decoders: crlDoorTable("entry"), criticality: pkix.crlEntryFixedCriticality(oid) },
});

/** @internal The parse decodes cRLNumber, reasonCode and invalidityDate in place, so its records
 *  carry the decoded value. The door reads the raw octets the record kept beside it, and decodes
 *  them itself under this call's caps and this call's scope. */
function rawRecords(list) {
  return intrinsic.map(list || [], function (e) {
    return { oid: e.oid, name: e.name, critical: e.critical, value: e.valueBytes };
  });
}

var DOOR = pkix.extensionDoor({
  ns: NS, ErrorClass: CrlError, key: "crl", kind: "crl", what: "the CRL",
  parse: parse, scopes: CRL_SCOPES,
  segments: function (crl) {
    var out = [{ list: rawRecords(crl.crlExtensions), scope: "crl" }];
    var revoked = crl.revokedCertificates || [];
    for (var i = 0; i < revoked.length; i++) {
      intrinsic.push(out, { list: rawRecords(revoked[i].crlEntryExtensions), scope: "crl-entry", containerIndex: i });
    }
    return out;
  },
});

/**
 * @primitive  pki.schema.crl.decodeExtensions
 * @signature  pki.schema.crl.decodeExtensions(crlOrBytes, opts?) -> rows
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 5280 sec. 5.2, RFC 5280 sec. 5.3
 * @related    pki.schema.crl.parse, pki.schema.x509.decodeExtensions, pki.lint.crl
 *
 * Read a CRL's extensions as decoded records: the CRL's own extensions first, then each revoked
 * entry's. The argument is the object `parse` returned or the bytes `parse` takes.
 *
 * One array spans both scopes rather than two, because RFC 5280 sec. 5.3 makes an unreadable
 * critical ENTRY extension a verdict about the whole CRL, and a caller handed two lists can read
 * one and not the other. Each row names where it was read: `scope` is `"crl"` or `"crl-entry"`, and
 * `containerIndex` is the position of the revoked entry an entry row came from, or `null` for the
 * CRL's own.
 *
 * Each row is `{ oid, name, critical, value, scope, index, containerIndex, state, decoded, code,
 * profile }`. `state` is the discriminator: `"decoded"`, `"unrecognized"` for an OID no decoder is
 * registered for AT THAT SCOPE, and `"undecodable"`. A `cRLNumber` on a revoked entry and a
 * `reasonCode` on the CRL are each unrecognized rather than undecodable, because neither scope
 * profiles the other's extension.
 *
 * @opts
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value. It does not turn an unrecognized OID into a throw.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call. Each may only
 *     tighten the built-in ceiling, and each bounds the decoding this call performs.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 7n,
 *     revoked: [{ serialNumber: 0x0a3fn, revocationDate: new Date("2026-01-15T00:00:00Z"), reason: "keyCompromise" }] },
 *     { cert: caCert, key: key });
 *   var rows = pki.schema.crl.decodeExtensions(crlDer);
 *   rows.filter(function (r) { return r.scope === "crl-entry" && r.name === "reasonCode"; })[0].decoded;  // -> 1
 */
var decodeExtensions = DOOR.decodeExtensions;

/**
 * @primitive  pki.schema.crl.decodeExtension
 * @signature  pki.schema.crl.decodeExtension(ext, opts) -> row
 * @since      0.8.11
 * @status     stable
 * @spec       RFC 5280 sec. 5.2, RFC 5280 sec. 5.3, RFC 6960 sec. 4.4.5
 * @related    pki.schema.crl.decodeExtensions
 *
 * Read one CRL extension record as a decoded row. `opts.scope` is required and says which table to
 * read it against, because the same identifier means different things at the three scopes a CRL
 * reader meets. The argument is `{ oid, name, critical, value }`, with `value` the raw `extnValue`
 * octets, which a `parse` result carries as `valueBytes`.
 *
 * @opts
 *   - `scope` (string, required) -- `"crl"` for a CRL's own extension, `"crl-entry"` for a revoked
 *     entry's, `"ocsp-single"` for one carried in an OCSP `SingleResponse` (RFC 6960 sec. 4.4.5).
 *   - `strict` (boolean) -- throw the decoder's own typed error instead of reporting an
 *     undecodable value.
 *   - `maxBytes` / `maxDepth` / `maxItems` (integer) -- decode caps for this call.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 7n,
 *     revoked: [{ serialNumber: 0x0a3fn, revocationDate: new Date("2026-01-15T00:00:00Z"), reason: "keyCompromise" }] },
 *     { cert: caCert, key: key });
 *   var e = pki.schema.crl.parse(crlDer).revokedCertificates[0].crlEntryExtensions[0];
 *   pki.schema.crl.decodeExtension({ oid: e.oid, name: e.name, critical: e.critical, value: e.valueBytes },
 *     { scope: "crl-entry" }).decoded;  // -> 1
 */
var decodeExtension = DOOR.decodeExtension;

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  decodeExtensions: decodeExtensions,
  decodeExtension: decodeExtension,
  /** @internal The reader this parser applies to a CRL entry extension (reasonCode, invalidityDate),
   *  for a consumer that meets the same extension elsewhere: RFC 6960 sec. 4.4.5 carries every CRL
   *  entry extension into an OCSP SingleResponse, and the linter reads it with this rather than a
   *  second one. Not on the curated `pki.schema.crl` surface. */
  decodeExt: decodeExt,
  entryExtensionCriticality: entryExtensionCriticality,
  readEntryExtension: readEntryExtension,
};
