// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.csrattrs
 * @nav        Schema
 * @title      CSR Attributes
 * @order      185
 * @slug       csrattrs
 *
 * @intro
 *   The EST CSR Attributes wire format per RFC 8951 sec. 3.5 (the RFC 7030
 *   sec. 4.5.2 ASN.1 was syntactically broken, erratum 4384) with the RFC 9908
 *   template structures. `parse` turns a DER `Buffer` into
 *   `{ items }` -- `CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID`, where
 *   `AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }`
 *   disambiguates on the universal tag. An empty SEQUENCE is a COMPLETE valid
 *   document ("no additional information desired"). Each item surfaces its
 *   `kind` (`"oid"` / `"attribute"`), the `oid` (dotted) and registry `name`;
 *   an attribute keeps its raw `values` and, for the three types RFC 9908
 *   gives meaning, a decoded view: `id-ExtensionReq` -> `extensions`, the
 *   `ecPublicKey` / `rsaEncryption` key-type conventions -> `curve` / `keySize`,
 *   and `id-aa-certificationRequestInfoTemplate` -> a fully-decoded `template`.
 *
 *   Structure is strict-DER throughout, but UNKNOWN OIDs and attribute types
 *   are TOLERATED -- surfaced raw, never a parse fault ("the client MUST ignore
 *   any OID or attribute it does not recognize", RFC 8951 sec. 4.5.2). The
 *   RFC 9908 semantic MUSTs that ARE enforced fail closed with a typed
 *   `csrattrs/*` code: at most one `id-ExtensionReq` attribute, its values a SET
 *   of exactly one `Extensions`, template version v1(0), and a template's inner
 *   attributes carrying at most one `id-aa-extensionReqTemplate` and never both
 *   extension-request kinds. Template PRIORITY (a client that understands the
 *   template ignores the legacy elements, RFC 9908 sec. 4) is a `pki.est` builder
 *   rule, not a parse rejection -- parse surfaces everything.
 *
 *   There is NO `pemDecode` / `pemEncode`: no RFC 7468 label exists for
 *   CsrAttrs; the wire encoding is bare RFC 4648 base64 handled by the EST
 *   transfer codec (`pki.est.transferDecode`), not a PEM envelope.
 *
 * @card
 *   Parse DER EST CSR Attributes (RFC 8951 / RFC 9908) into ordered items --
 *   bare OIDs, attributes with raw values, decoded extension requests / key-type
 *   conventions / request-info templates; unknown types tolerated, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CsrattrsError = frameworkError.CsrattrsError;

var NS = pkix.makeNS("csrattrs", CsrattrsError, oid);
var T = asn1.TAGS;

// minValues 0: a key-type hint's values SET MAY be empty ("any key of this
// type", RFC 9908 sec. 3.2). Per-type arity is enforced in _enrichAttribute.
var ATTRIBUTE = pkix.attribute(NS, { minValues: 0 });
var EXTENSIONS = pkix.extensions(NS);
var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);

// The RFC 9908 semantically-meaningful attribute OIDs (registry, never literals).
var OID_EXTENSION_REQUEST = oid.byName("extensionRequest");                  // id-ExtensionReq
var OID_EC_PUBLIC_KEY = oid.byName("ecPublicKey");
var OID_RSA_ENCRYPTION = oid.byName("rsaEncryption");
var OID_TEMPLATE = oid.byName("certificationRequestInfoTemplate");
var OID_EXT_REQ_TEMPLATE = oid.byName("extensionReqTemplate");

// ---- RFC 9908 sec. 3.4 CertificationRequestInfoTemplate ------------------

// version MUST be v1(0). A dedicated leaf (not pkix.versionReader) so the reject
// carries the template-specific code the RFC 9908 sec. 3.4 MUST names.
var TEMPLATE_VERSION = schema.decode(function (n, ctx) {
  var v = asn1.read.integer(n);
  if (v !== 0n) throw ctx.E("csrattrs/bad-template-version", "CertificationRequestInfoTemplate version must be v1(0) (RFC 9908 sec. 3.4)");
  return 0;
}, function () { return asn1.build.integer(0n); });

// SingleAttributeTemplate ::= SEQUENCE { type OID, value ANY OPTIONAL } -- a
// value-absent element means "the client fills this in" (RFC 9908 sec. 3.4). The
// trailing OPTIONAL ANY is the algorithmIdentifier-parameters shape.
var SINGLE_ATTR_TEMPLATE = schema.seq([
  schema.field("type", schema.oidLeaf()),
  schema.optional("value", schema.any(), { whenAny: true }),
], {
  assert: "sequence", arity: { min: 1, max: 2 }, code: "csrattrs/bad-name-template", what: "SingleAttributeTemplate",
  build: function (m, ctx) {
    return { type: m.fields.type.value, name: ctx.oid.name(m.fields.type.value) || null,
             value: m.fields.value.present ? m.fields.value.node.bytes : null };
  },
});

// RelativeDistinguishedNameTemplate ::= SET SIZE (1..MAX) OF SingleAttributeTemplate.
var RDN_TEMPLATE = schema.setOf(SINGLE_ATTR_TEMPLATE, {
  assert: "set", min: 1, code: "csrattrs/bad-name-template", what: "RelativeDistinguishedNameTemplate",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});
// NameTemplate ::= RDNSequence (a SEQUENCE OF RDN-template SETs) -> array of RDNs,
// each an array of { type, name, value } (value null = "the client fills it in").
var NAME_TEMPLATE = schema.seqOf(RDN_TEMPLATE, {
  assert: "sequence", code: "csrattrs/bad-name-template", what: "NameTemplate",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// SubjectPublicKeyInfoTemplate ::= SEQUENCE { algorithm AlgorithmIdentifier,
//   subjectPublicKey BIT STRING OPTIONAL } -- the key is OPTIONAL (present ONLY
//   as an RSA modulus-size placeholder), so pkix.spki (key required, arity 2)
//   cannot be reused.
var SPKI_TEMPLATE = schema.seq([
  schema.field("algorithm", ALGORITHM_IDENTIFIER),
  schema.optional("placeholderKey", schema.bitString(), { whenUniversal: [T.BIT_STRING] }),
], {
  // subjectPKInfo is [0] IMPLICIT (RFC 9908 sec. 3.4) -- the context tag replaces
  // the universal SEQUENCE tag, so the node is context-[0] constructed and its
  // children are read directly (the pwri keyDerivationAlgorithm [0] precedent).
  assert: "implicit", implicitTag: 0, arity: { min: 1, max: 2 }, code: "csrattrs/bad-spki-template", what: "SubjectPublicKeyInfoTemplate",
  build: function (m) {
    return { algorithm: m.fields.algorithm.value.result,
             placeholderKey: m.fields.placeholderKey.present ? m.fields.placeholderKey.value.bytes : null };
  },
});

// ExtensionTemplate ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
//   extnValue OCTET STRING OPTIONAL } -- extnValue absent means "client supplies";
//   an explicit critical FALSE is non-DER (BOOLEAN DEFAULT FALSE). Not reusable
//   from pkix.extension (whose extnValue is required), so the DER-critical rule
//   is applied here directly.
var EXTENSION_TEMPLATE = schema.decode(function (n, ctx) {
  if (!schema.isUniversal(n, T.SEQUENCE) || !n.children || n.children.length < 1 || n.children.length > 3) {
    throw ctx.E("csrattrs/bad-extension-template", "ExtensionTemplate must be a SEQUENCE of {extnID, critical?, extnValue?}");
  }
  var k = n.children, i = 1;
  var extnID = asn1.read.oid(k[0]);
  var critical = false, value = null;
  if (i < k.length && schema.isUniversal(k[i], T.BOOLEAN)) {
    critical = asn1.read.boolean(k[i]);
    if (critical === false) throw ctx.E("csrattrs/bad-extension-template", "an explicit critical FALSE must be omitted (BOOLEAN DEFAULT FALSE)");
    i += 1;
  }
  if (i < k.length) { value = asn1.read.octetString(k[i]); i += 1; }
  if (i !== k.length) throw ctx.E("csrattrs/bad-extension-template", "ExtensionTemplate has an unexpected trailing element");
  return { oid: extnID, name: ctx.oid.name(extnID) || null, critical: critical, value: value };
});

// ExtensionReqTemplate ::= ExtensionTemplates ::= SEQUENCE SIZE (1..MAX) OF
// ExtensionTemplate (RFC 9908 sec. 3.4) -- the id-aa-extensionReqTemplate value
// is a SEQUENCE OF ExtensionTemplate, not a single one.
var EXTENSION_REQ_TEMPLATE = schema.seqOf(EXTENSION_TEMPLATE, {
  assert: "sequence", min: 1, code: "csrattrs/bad-extension-template", what: "ExtensionReqTemplate",
  build: function (m) { return m.items.map(function (it) { return it.value; }); },
});

// CertificationRequestInfoTemplate ::= SEQUENCE { version, subject NameTemplate
//   OPTIONAL, subjectPKInfo [0] IMPLICIT OPTIONAL, attributes [1] IMPLICIT
//   Attributes }. attributes is present (may be an empty SET). The RFC 9908
//   sec. 3.4 inner-attribute MUSTs (<=1 extensionReqTemplate; not both
//   extension-request kinds; a values SET of exactly one ExtensionTemplate) are
//   enforced in the build.
var CERT_REQ_INFO_TEMPLATE = schema.seq([
  schema.field("version", TEMPLATE_VERSION),
  schema.optional("subject", NAME_TEMPLATE, { whenUniversal: [T.SEQUENCE] }),
  schema.optional("subjectPKInfo", SPKI_TEMPLATE, { tag: 0 }),
  schema.field("attributes", schema.implicitSetOf(1, ATTRIBUTE, { min: 0, code: "csrattrs/bad-template-attrs", what: "template attributes" })),
], {
  assert: "sequence", code: "csrattrs/bad-template", what: "CertificationRequestInfoTemplate",
  build: function (m, ctx) {
    var attributes = m.fields.attributes.value.items.map(function (it) { return it.value.result; });
    var extReqTemplates = 0, hasExtReq = false, extensionTemplates = [];
    for (var i = 0; i < attributes.length; i++) {
      var a = attributes[i];
      if (a.type === OID_EXTENSION_REQUEST) hasExtReq = true;
      if (a.type === OID_EXT_REQ_TEMPLATE) {
        extReqTemplates += 1;
        // The attribute's values SET holds exactly one ExtensionReqTemplate
        // (RFC 9908 sec. 3.4); that value is itself a SEQUENCE OF ExtensionTemplate.
        if (a.values.length !== 1) throw NS.E("csrattrs/bad-template-attrs", "an id-aa-extensionReqTemplate values must be a SET of exactly one ExtensionReqTemplate (RFC 9908 sec. 3.4)");
        extensionTemplates = extensionTemplates.concat(schema.walk(EXTENSION_REQ_TEMPLATE, asn1.decode(a.values[0]), ctx).result);
      }
    }
    if (extReqTemplates > 1) throw NS.E("csrattrs/bad-template-attrs", "a template must not carry more than one id-aa-extensionReqTemplate (RFC 9908 sec. 3.4)");
    if (extReqTemplates >= 1 && hasExtReq) throw NS.E("csrattrs/bad-template-attrs", "a template must not carry both id-ExtensionReq and id-aa-extensionReqTemplate (RFC 9908 sec. 3.4)");
    return {
      version: m.fields.version.value,
      subject: m.fields.subject.present ? m.fields.subject.value.result : null,
      subjectPKInfo: m.fields.subjectPKInfo.present ? m.fields.subjectPKInfo.value.result : null,
      attributes: attributes,
      extensionTemplates: extensionTemplates,
    };
  },
});

// ---- AttrOrOID + the semantic enrichment ---------------------------------

// Decode the three RFC 9908-meaningful attribute types onto an already-walked
// Attribute { type, name, values }. Unknown types keep only their raw values.
function _enrichAttribute(item, ctx) {
  if (item.oid === OID_EXTENSION_REQUEST) {
    if (item.values.length !== 1) throw ctx.E("csrattrs/bad-extension-req", "an id-ExtensionReq attribute values must be a SET of exactly one Extensions (RFC 9908 sec. 3.2)");
    item.extensions = schema.walk(EXTENSIONS, asn1.decode(item.values[0]), ctx).result;
  } else if (item.oid === OID_EC_PUBLIC_KEY) {
    // A key-type hint's values SET is empty ("any curve") or a singleton naming
    // ONE curve (RFC 9908 sec. 3.2); a multi-valued SET is ambiguous -- fail
    // closed rather than letting DER ordering pick the advertised constraint.
    if (item.values.length > 1) throw ctx.E("csrattrs/bad-key-type-attr", "an ecPublicKey attribute values must be empty or a SET of exactly one named-curve OBJECT IDENTIFIER (RFC 9908 sec. 3.2)");
    if (item.values.length === 1) {
      try { item.curve = asn1.read.oid(asn1.decode(item.values[0])); }
      catch (e) { throw ctx.E("csrattrs/bad-key-type-attr", "an ecPublicKey attribute value must be a named-curve OBJECT IDENTIFIER (RFC 9908 sec. 3.2)", e); }
    }
  } else if (item.oid === OID_RSA_ENCRYPTION) {
    // Empty ("any size") or a singleton naming ONE key size; reject a multi-valued SET.
    if (item.values.length > 1) throw ctx.E("csrattrs/bad-key-type-attr", "an rsaEncryption attribute values must be empty or a SET of exactly one INTEGER key size (RFC 9908 sec. 3.2)");
    if (item.values.length === 1) {
      var sz;
      try { sz = asn1.read.integer(asn1.decode(item.values[0])); }
      catch (e) { throw ctx.E("csrattrs/bad-key-type-attr", "an rsaEncryption attribute value must be an INTEGER key size (RFC 9908 sec. 3.2)", e); }
      // Bound before narrowing to a Number: an RSA modulus-size hint of 1..65536
      // bits covers every real key; a value past 2^53 would round silently.
      if (sz < 1n || sz > 65536n) throw ctx.E("csrattrs/bad-key-type-attr", "the rsaEncryption key size " + sz + " is out of range (1..65536 bits)");
      item.keySize = Number(sz);
    }
  } else if (item.oid === OID_TEMPLATE) {
    if (item.values.length !== 1) throw ctx.E("csrattrs/bad-template", "a certificationRequestInfoTemplate attribute values must be a SET of exactly one template (RFC 9908 sec. 3.4)");
    item.template = schema.walk(CERT_REQ_INFO_TEMPLATE, asn1.decode(item.values[0]), ctx).result;
  }
}

// AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }. The two
// arms are the two universal tags; anything else is not an AttrOrOID. A decode
// leaf (not schema.choice) so the enrichment + the paired write live together.
var ATTR_OR_OID = schema.decode(function (n, ctx) {
  if (schema.isUniversal(n, T.OBJECT_IDENTIFIER) && !n.constructed) {
    var o = asn1.read.oid(n);
    return { kind: "oid", oid: o, name: ctx.oid.name(o) || null };
  }
  if (schema.isUniversal(n, T.SEQUENCE) && n.children) {
    var a = schema.walk(ATTRIBUTE, n, ctx).result;          // { type, name, values:[bytes] }
    var item = { kind: "attribute", oid: a.type, name: a.name, values: a.values };
    _enrichAttribute(item, ctx);
    return item;
  }
  throw ctx.E("csrattrs/bad-attr-or-oid", "each CsrAttrs element must be an OBJECT IDENTIFIER or an Attribute SEQUENCE (RFC 8951 sec. 3.5)");
}, function (item) {
  // Paired encoder (one structure, both directions): reconstruct from the arm's
  // identifying fields + raw values -- the typed enrichment is decode-only.
  if (item.kind === "oid") return asn1.build.oid(item.oid);
  return asn1.build.sequence([asn1.build.oid(item.oid), asn1.build.set(item.values)]);
});

// CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID. min:0 -- an empty SEQUENCE is
// a complete valid document. The cross-element MUSTs (RFC 9908 sec. 3.2 single
// id-ExtensionReq; sec. 3.4 single template) are enforced in the build.
var CSR_ATTRS = schema.seqOf(ATTR_OR_OID, {
  assert: "sequence", code: "csrattrs/not-csrattrs", what: "CsrAttrs",
  build: function (m) {
    var items = m.items.map(function (it) { return it.value; });
    var extReq = 0, tpl = 0;
    for (var i = 0; i < items.length; i++) {
      if (items[i].kind !== "attribute") continue;
      if (items[i].oid === OID_EXTENSION_REQUEST) extReq += 1;
      if (items[i].oid === OID_TEMPLATE) tpl += 1;
    }
    if (extReq > 1) throw NS.E("csrattrs/duplicate-extension-req", "at most one id-ExtensionReq attribute is permitted in CsrAttrs (RFC 9908 sec. 3.2)");
    if (tpl > 1) throw NS.E("csrattrs/duplicate-template", "at most one certificationRequestInfoTemplate attribute is permitted in CsrAttrs (RFC 9908 sec. 3.4)");
    return { items: items };
  },
});

/**
 * @primitive  pki.schema.csrattrs.parse
 * @signature  pki.schema.csrattrs.parse(der) -> { items }
 * @since      0.1.24
 * @status     experimental
 * @spec       RFC 8951, RFC 9908, RFC 7030
 * @related    pki.schema.parse, pki.est.buildEnrollAttributes
 *
 * Parse a DER `Buffer` of EST CSR Attributes (`CsrAttrs`, RFC 8951 sec. 3.5) into
 * `{ items }`. Each item is `{ kind, oid, name }` -- `kind` `"oid"` for a bare
 * OID, `"attribute"` for an `Attribute`, which adds raw `values` plus, for the
 * RFC 9908 meaningful types, `extensions` (id-ExtensionReq), `curve` / `keySize`
 * (EC / RSA key-type conventions), or `template` (the request-info template). An
 * empty `SEQUENCE` yields `{ items: [] }` ("no additional information desired").
 * Unknown OIDs / attribute types are tolerated (surfaced raw); a malformed
 * structure or an RFC 9908 semantic violation throws a typed `CsrattrsError`
 * (`csrattrs/*`) and a leaf-level codec fault surfaces as `asn1/*`.
 *
 * @example
 *   var a = pki.schema.csrattrs.parse(der);
 *   a.items[0].kind;   // -> "oid" | "attribute"
 */
var parse = pkix.makeParser({ pemLabel: null, PemError: frameworkError.PemError, ErrorClass: CsrattrsError, prefix: "csrattrs", what: "CsrAttrs", topSchema: CSR_ATTRS, ns: NS });

// matches(root): a CsrAttrs is a universal SEQUENCE whose children are each a
// bare universal OID or an Attribute (a universal SEQUENCE of exactly 2 whose
// first child is an OID and second a SET). An empty SEQUENCE (30 00) is a valid
// CsrAttrs and no other registered document root accepts it. Registered BEFORE
// ocsp-request (a permissive superset probe) as the strict refinement, the same
// resolution tsp / crmf already use.
function matches(root) {
  var k = pkix.rootSequenceChildren(root, 0);
  if (!k) return false;
  if (k.length === 0) return true;
  for (var i = 0; i < k.length; i++) {
    var c = k[i];
    // bare-OID arm: a primitive universal OBJECT IDENTIFIER.
    if (schema.isUniversal(c, T.OBJECT_IDENTIFIER) && !c.constructed) continue;
    // Attribute arm: a universal SEQUENCE of exactly { OID, SET }.
    if (!schema.isUniversal(c, T.SEQUENCE) || !c.children || c.children.length !== 2) return false;
    if (!schema.isUniversal(c.children[0], T.OBJECT_IDENTIFIER)) return false;
    if (!(schema.isUniversal(c.children[1], T.SET) && c.children[1].children)) return false;
  }
  return true;
}

module.exports = {
  parse: parse,
  matches: matches,
  // The top schema, exposed (not on the curated pki.schema.csrattrs surface) so a
  // composer can drive the encode direction and prove the round-trip.
  csrAttrsSchema: CSR_ATTRS,
};
