// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.pkcs12
 * @nav        Schema
 * @title      PKCS#12
 * @order      190
 * @slug       pkcs12
 *
 * @intro
 *   PKCS#12 (PFX) key-and-certificate store handling per RFC 7292. `parse`
 *   decodes a `.p12` / `.pfx` container — the personal-information-exchange
 *   format OpenSSL, Windows CAPI, macOS Keychain, and NSS emit — into its
 *   bags: private keys (delegated to the PKCS#8 parser), shrouded keys
 *   (algorithm surfaced, ciphertext kept opaque), certificates, CRLs,
 *   secrets, and nested safe contents, each with its `friendlyName` /
 *   `localKeyId` attributes decoded.
 *
 *   A PFX is a nested container: the authenticated safe is a CMS ContentInfo
 *   whose OCTET STRING content re-decodes to a list of ContentInfos, each
 *   carrying plaintext safe contents or a CMS EncryptedData / EnvelopedData
 *   privacy wrapper (surfaced structurally via the CMS module; ciphertext is
 *   never parsed). Integrity is surfaced, not verified: password mode yields
 *   the MAC parameters plus the exact byte range the HMAC covers
 *   (`macedBytes`), public-key mode the SignedData with its signers, and a
 *   MAC-less store surfaces `integrityMode: "none"` for the caller's policy
 *   to judge. RFC 7292
 *   §4.1 encodes content in BER, so parsing this one format accepts exactly
 *   two BER shapes — indefinite lengths and constructed OCTET STRINGs —
 *   anywhere in the store; every other strictness verdict, and every other
 *   format, stays strict DER, fail-closed.
 *
 * @card
 *   Parse DER / BER / PEM RFC 7292 PKCS#12 (PFX) stores into key / cert /
 *   CRL / secret bags with their attributes — keys via the PKCS#8 parser,
 *   encrypted safes via CMS, MAC inputs surfaced raw for external
 *   verification, fail-closed.
 */

var C = require("./constants.js");
var asn1 = require("./asn1-der.js");
var oid = require("./oid.js");
var schema = require("./schema-engine.js");
var pkix = require("./schema-pkix.js");
var cms = require("./schema-cms.js");
var pkcs8 = require("./schema-pkcs8.js");
var frameworkError = require("./framework-error.js");

var Pkcs12Error = frameworkError.Pkcs12Error;
var PemError = frameworkError.PemError;
var NS = pkix.makeNS("pkcs12", Pkcs12Error, oid);
var TAGS = asn1.TAGS;

// Content types (RFC 5652 §4 / RFC 7292 §4.1).
var OID_DATA = oid.byName("data");
var OID_SIGNED_DATA = oid.byName("signedData");
var OID_ENVELOPED_DATA = oid.byName("envelopedData");
var OID_ENCRYPTED_DATA = oid.byName("encryptedData");
// Bag types (RFC 7292 §4.2).
var OID_KEY_BAG = oid.byName("keyBag");
var OID_SHROUDED_KEY_BAG = oid.byName("pkcs8ShroudedKeyBag");
var OID_CERT_BAG = oid.byName("certBag");
var OID_CRL_BAG = oid.byName("crlBag");
var OID_SECRET_BAG = oid.byName("secretBag");
var OID_SAFE_CONTENTS_BAG = oid.byName("safeContentsBag");
// CertBag / CRLBag discriminators (§4.2.3-§4.2.4).
var OID_X509_CERTIFICATE = oid.byName("x509Certificate");
var OID_SDSI_CERTIFICATE = oid.byName("sdsiCertificate");
var OID_X509_CRL = oid.byName("x509CRL");
// Bag attributes (§4.2) + the RFC 9579 MacData arm.
var OID_FRIENDLY_NAME = oid.byName("friendlyName");
var OID_LOCAL_KEY_ID = oid.byName("localKeyId");
var OID_PBMAC1 = oid.byName("pbmac1");

// DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }.
var DIGEST_INFO = schema.seq([
  schema.field("digestAlgorithm", pkix.algorithmIdentifier(NS)),
  schema.field("digest", schema.octetString()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-mac-data", what: "DigestInfo",
  build: function (m) {
    return { digestAlgorithm: m.fields.digestAlgorithm.value.result, digest: m.fields.digest.value };
  },
});

// PBKDF2-params (RFC 8018 §5.2), constrained to the RFC 9579 PBMAC1 profile:
// the salt MUST use the specified (OCTET STRING) choice and keyLength MUST be
// present (§4.b / §5 — a MacData consumer cannot infer the MAC key size).
var PBKDF2_PARAMS = schema.seq([
  schema.field("salt", schema.octetString()),
  schema.field("iterationCount", schema.integerLeaf()),
  schema.optional("keyLength", schema.integerLeaf(), { whenUniversal: [TAGS.INTEGER] }),
  schema.optional("prf", pkix.algorithmIdentifier(NS), { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "pkcs12/bad-mac-data", what: "PBKDF2-params",
  build: function (m, ctx) {
    if (!m.fields.keyLength.present) {
      throw ctx.E("pkcs12/bad-mac-data", "PBMAC1 PBKDF2-params must carry keyLength (RFC 9579 §5)");
    }
    // Both counters surface as exact JS numbers — a value past the bound
    // would round silently on conversion and hand a verifier wrong inputs.
    var iterations = m.fields.iterationCount.value;
    if (iterations < 1n || iterations > 2147483647n) {
      throw ctx.E("pkcs12/bad-mac-data", "PBKDF2 iterationCount must be a positive integer within the iteration-count range");
    }
    var keyLength = m.fields.keyLength.value;
    if (keyLength < 1n || keyLength > 2147483647n) {
      throw ctx.E("pkcs12/bad-mac-data", "PBKDF2 keyLength must be a positive integer within the key-length range");
    }
    var prf = m.fields.prf.present ? m.fields.prf.value.result : null;
    return {
      salt: m.fields.salt.value,
      iterationCount: Number(iterations),
      keyLength: Number(keyLength),
      prfOid: prf ? prf.oid : oid.byName("hmacWithSHA1"),
      prfName: prf ? prf.name : "hmacWithSHA1",
    };
  },
});

// PBMAC1-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier{PBKDF2},
// messageAuthScheme AlgorithmIdentifier } (RFC 8018 §A.5 / RFC 9579 §4).
var PBMAC1_PARAMS = schema.seq([
  schema.field("keyDerivationFunc", schema.seq([
    schema.field("algorithm", schema.oidLeaf()),
    schema.field("parameters", PBKDF2_PARAMS),
  ], { assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-mac-data", what: "PBMAC1 keyDerivationFunc" })),
  schema.field("messageAuthScheme", pkix.algorithmIdentifier(NS)),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-mac-data", what: "PBMAC1-params",
  build: function (m, ctx) {
    var kdf = m.fields.keyDerivationFunc.value;
    if (kdf.fields.algorithm.value !== oid.byName("pbkdf2")) {
      throw ctx.E("pkcs12/bad-mac-data", "PBMAC1 keyDerivationFunc must be PBKDF2 (RFC 9579 §4)");
    }
    var scheme = m.fields.messageAuthScheme.value.result;
    return {
      kdf: kdf.fields.parameters.value.result,
      schemeOid: scheme.oid,
      schemeName: scheme.name,
    };
  },
});

// MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING,
//                        iterations INTEGER DEFAULT 1 }.
var MAC_DATA = schema.seq([
  schema.field("mac", DIGEST_INFO),
  schema.field("macSalt", schema.octetString()),
  schema.optional("iterations", schema.integerLeaf(), { whenUniversal: [TAGS.INTEGER], default: 1 }),
], {
  assert: "sequence", code: "pkcs12/bad-mac-data", what: "MacData",
  build: function (m, ctx) {
    // X.690 §11.5 — a DEFAULT-valued component must be omitted from a DER
    // encoding, so an explicitly-encoded iterations = 1 is non-canonical.
    var it = m.fields.iterations;
    var iterations = 1;
    if (it.present) {
      var v = it.value;
      if (v === 1n) throw ctx.E("pkcs12/bad-mac-iterations", "iterations equal to its DEFAULT 1 must be omitted (X.690 §11.5)");
      if (v < 1n || v > 2147483647n) throw ctx.E("pkcs12/bad-mac-iterations", "iterations must be a positive integer within the iteration-count range");
      iterations = Number(v);
    }
    var di = m.fields.mac.value.result;
    var pbmac1 = null;
    if (di.digestAlgorithm.oid === OID_PBMAC1) {
      // RFC 9579 §4 — the PBMAC1 algorithm identifier MUST carry PBMAC1-params
      // (the KDF and MAC scheme a verifier needs live there, not in MacData).
      if (di.digestAlgorithm.parameters === null) {
        throw ctx.E("pkcs12/bad-mac-data", "a PBMAC1 MacData must carry PBMAC1-params (RFC 9579 §4)");
      }
      pbmac1 = schema.embeddedDer(PBMAC1_PARAMS, di.digestAlgorithm.parameters, ctx,
        { code: "pkcs12/bad-mac-data", what: "PBMAC1-params", ber: true }).result;
    }
    return {
      kind: pbmac1 ? "pbmac1" : "hmac",
      hashOid: di.digestAlgorithm.oid,
      hashName: di.digestAlgorithm.name,
      hashParameters: di.digestAlgorithm.parameters,
      pbmac1: pbmac1,
      macValue: di.digest,
      macSalt: m.fields.macSalt.value,
      iterations: iterations,
    };
  },
});

// CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT ANY } (§4.2.3):
// x509Certificate wraps the DER certificate in an OCTET STRING; sdsiCertificate
// is an IA5String. Both arms of the closed set are accepted; the value is
// surfaced raw (byte-exact), never re-encoded or recursively parsed.
var CERT_BAG = schema.seq([
  schema.field("certId", schema.oidLeaf()),
  schema.field("certValue", schema.explicit(0, schema.any(), { code: "pkcs12/bad-bag-value", what: "certValue" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-bag-value", what: "CertBag",
  build: function (m, ctx) {
    var certId = m.fields.certId.value;
    var node = m.fields.certValue.value;
    if (certId === OID_X509_CERTIFICATE) {
      return { certType: "x509Certificate", certId: certId, certValue: _octetContent(node, ctx, "an x509Certificate certValue") };
    }
    if (certId === OID_SDSI_CERTIFICATE) {
      if (!(node.tagClass === "universal" && node.tagNumber === TAGS.IA5_STRING && node.content)) {
        throw ctx.E("pkcs12/bad-bag-value", "an sdsiCertificate certValue must be an IA5String (RFC 7292 §4.2.3)");
      }
      return { certType: "sdsiCertificate", certId: certId, certValue: node.content };
    }
    throw ctx.E("pkcs12/bad-cert-type", (ctx.oid.name(certId) || certId) + " is not a recognized CertBag certId (RFC 7292 §4.2.3)");
  },
});

// CRLBag ::= SEQUENCE { crlId OID, crlValue [0] EXPLICIT ANY } (§4.2.4).
var CRL_BAG = schema.seq([
  schema.field("crlId", schema.oidLeaf()),
  schema.field("crlValue", schema.explicit(0, schema.any(), { code: "pkcs12/bad-bag-value", what: "crlValue" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-bag-value", what: "CRLBag",
  build: function (m, ctx) {
    var crlId = m.fields.crlId.value;
    if (crlId !== OID_X509_CRL) {
      throw ctx.E("pkcs12/bad-crl-type", (ctx.oid.name(crlId) || crlId) + " is not a recognized CRLBag crlId (RFC 7292 §4.2.4)");
    }
    return { crlType: "x509CRL", crlId: crlId, crlValue: _octetContent(m.fields.crlValue.value, ctx, "an x509CRL crlValue") };
  },
});

// SecretBag ::= SEQUENCE { secretTypeId OID, secretValue [0] EXPLICIT ANY }
// (§4.2.5). SecretTypes is an open set, so the type is surfaced by OID with
// the value raw — an unrecognized secret is representable, not a fault.
var SECRET_BAG = schema.seq([
  schema.field("secretTypeId", schema.oidLeaf()),
  schema.field("secretValue", schema.explicit(0, schema.any(), { code: "pkcs12/bad-bag-value", what: "secretValue" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-bag-value", what: "SecretBag",
  build: function (m, ctx) {
    var t = m.fields.secretTypeId.value;
    return { secretTypeId: t, secretTypeName: ctx.oid.name(t) || null, secretValue: m.fields.secretValue.value.bytes };
  },
});

// SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY DEFINED BY bagId,
//                        bagAttributes SET OF PKCS12Attribute OPTIONAL } (§4.2).
// The build surfaces the structural record (bagId + the inner value node +
// decoded attributes); the bagId dispatch happens in _buildBag, where the
// per-parse recursion state lives.
var SAFE_BAG = schema.seq([
  schema.field("bagId", schema.oidLeaf()),
  schema.field("bagValue", schema.explicit(0, schema.any(), { code: "pkcs12/bad-bag-value", what: "bagValue" })),
  schema.optional("bagAttributes", schema.setOf(pkix.attribute(NS), {
    code: "pkcs12/bad-attributes", what: "bagAttributes",
    max: C.LIMITS.PKCS12_MAX_ELEMENTS, maxCode: "pkcs12/too-many-elements",
  }), { whenUniversal: [TAGS.SET] }),
], {
  assert: "sequence", code: "pkcs12/bad-safe-contents", what: "SafeBag",
  build: function (m, ctx) {
    var attributes = [];
    var friendlyName = null;
    var localKeyId = null;
    var seen = {};
    if (m.fields.bagAttributes.present) {
      var items = m.fields.bagAttributes.value.items;
      for (var i = 0; i < items.length; i++) {
        var a = items[i].value.result;
        attributes.push(a);
        // friendlyName / localKeyId are SINGLE VALUE TRUE (PKCS#9 / RFC 2985):
        // exactly one value, at most one instance of each attribute.
        if (a.type === OID_FRIENDLY_NAME) {
          if (seen[a.type] || a.values.length !== 1) throw ctx.E("pkcs12/bad-friendly-name", "friendlyName carries exactly one BMPString value (PKCS#9 SINGLE VALUE)");
          friendlyName = _bmpValue(a.values[0], ctx);
        }
        if (a.type === OID_LOCAL_KEY_ID) {
          if (seen[a.type] || a.values.length !== 1) throw ctx.E("pkcs12/bad-local-key-id", "localKeyId carries exactly one OCTET STRING value (PKCS#9 SINGLE VALUE)");
          // The value bytes are a raw wire slice out of a store whose content
          // is normatively BER, so the re-decode follows the same BER rules.
          localKeyId = _octetContent(asn1.decode(a.values[0], { ber: true }), ctx, "a localKeyId value", "pkcs12/bad-local-key-id");
        }
        seen[a.type] = true;
      }
    }
    return {
      bagId: m.fields.bagId.value,
      valueNode: m.fields.bagValue.value,
      attributes: attributes,
      friendlyName: friendlyName,
      localKeyId: localKeyId,
    };
  },
});

// SafeContents ::= SEQUENCE OF SafeBag (§4.2). Strictly a SEQUENCE — a SET OF
// here is a known producer divergence and rejects.
var SAFE_CONTENTS = schema.seqOf(SAFE_BAG, {
  code: "pkcs12/bad-safe-contents", what: "SafeContents",
  max: C.LIMITS.PKCS12_MAX_ELEMENTS, maxCode: "pkcs12/too-many-elements",
});

// AuthenticatedSafe ::= SEQUENCE OF ContentInfo (§4.1) — each element parsed
// structurally here and dispatched by contentType in _dispatchSafes.
var AS_ELEMENT = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("content", schema.explicit(0, schema.any(), { code: "pkcs12/bad-safe-contentinfo", what: "safe ContentInfo content" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-safe-contentinfo", what: "safe ContentInfo",
  build: function (m) {
    return { contentType: m.fields.contentType.value, innerNode: m.fields.content.value };
  },
});
var AUTHENTICATED_SAFE = schema.seqOf(AS_ELEMENT, {
  code: "pkcs12/bad-authenticated-safe", what: "AuthenticatedSafe",
  max: C.LIMITS.PKCS12_MAX_ELEMENTS, maxCode: "pkcs12/too-many-elements",
});

// The authSafe ContentInfo (§4): contentType is data (password integrity) or
// signedData (public-key integrity) and nothing else.
var AUTH_SAFE = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("content", schema.explicit(0, schema.any(), { code: "pkcs12/bad-authsafe", what: "authSafe content" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "pkcs12/bad-authsafe", what: "authSafe ContentInfo",
  build: function (m) {
    return { contentType: m.fields.contentType.value, innerNode: m.fields.content.value };
  },
});

// PFX ::= SEQUENCE { version INTEGER {v3(3)}, authSafe ContentInfo,
//                    macData MacData OPTIONAL } (§4).
var PFX = schema.seq([
  schema.field("version", pkix.versionReader(NS, { "3": 3 })),
  schema.field("authSafe", AUTH_SAFE),
  schema.optional("macData", MAC_DATA, { whenUniversal: [TAGS.SEQUENCE] }),
], {
  assert: "sequence", code: "pkcs12/not-a-pfx", what: "PFX",
  build: function (m, ctx) {
    var version = m.fields.version.value;
    var authSafe = m.fields.authSafe.value.result;
    var macPresent = m.fields.macData.present;
    var mac = macPresent ? m.fields.macData.value.result : null;
    // Every re-decode below shares one budget, so nesting chained across
    // OCTET-STRING (and delegation) boundaries cannot restart the caps.
    var state = { budget: { remaining: C.LIMITS.PKCS12_MAX_REDECODES }, bagDepth: 0 };

    if (authSafe.contentType === OID_DATA) {
      // §5.1 step 5B — the MAC covers the value octets of the id-data OCTET
      // STRING (the AuthenticatedSafe encoding), excluding the TLV header.
      // MacData itself is OPTIONAL in the PFX syntax: a store without it
      // (OpenSSL `pkcs12 -export -nomac`) carries no integrity protection at
      // all, which is a policy concern for the caller — surfaced as
      // integrityMode "none", never rejected by a parser that surfaces
      // integrity inputs rather than verifying them.
      var macedBytes = _octetContent(authSafe.innerNode, ctx, "an id-data authSafe content");
      var dispatched = _dispatchSafes(_walkAuthenticatedSafe(macedBytes, state, ctx), state, ctx);
      return {
        version: version, integrityMode: macPresent ? "password" : "none", mac: mac, macedBytes: macedBytes,
        authSafeSigned: null, safeBags: dispatched.safeBags, encryptedSafes: dispatched.encryptedSafes,
      };
    }
    if (authSafe.contentType === OID_SIGNED_DATA) {
      // §4 integrity coherence: public-key integrity has no MacData.
      if (macPresent) throw ctx.E("pkcs12/bad-integrity-mode", "an id-signedData authSafe (public-key integrity) must omit macData (RFC 7292 §4)");
      var signed = cms.walkSignedData(authSafe.innerNode);
      if (signed.encapContentInfo.eContentType !== OID_DATA) {
        throw ctx.E("pkcs12/bad-authsafe", "a public-key-integrity authSafe must encapsulate id-data carrying the AuthenticatedSafe (RFC 7292 §4.1)");
      }
      if (signed.encapContentInfo.eContent === null) {
        throw ctx.E("pkcs12/bad-authsafe", "a public-key-integrity authSafe must carry attached eContent (RFC 7292 §4.1)");
      }
      // A signer-less SignedData carries no integrity at all — the one thing
      // public-key-integrity mode exists to provide.
      if (signed.signerInfos.length < 1) {
        throw ctx.E("pkcs12/bad-authsafe", "a public-key-integrity authSafe must carry at least one SignerInfo (RFC 7292 §4)");
      }
      var dispatchedSigned = _dispatchSafes(_walkAuthenticatedSafe(signed.encapContentInfo.eContent, state, ctx), state, ctx);
      return {
        version: version, integrityMode: "public-key", mac: null, macedBytes: null,
        authSafeSigned: signed, safeBags: dispatchedSigned.safeBags, encryptedSafes: dispatchedSigned.encryptedSafes,
      };
    }
    throw ctx.E("pkcs12/bad-authsafe-type", "authSafe contentType must be id-data or id-signedData (RFC 7292 §4), got " +
      (ctx.oid.name(authSafe.contentType) || authSafe.contentType));
  },
});

// The value octets of a universal OCTET STRING node (a BER constructed string
// arrives already reassembled to primitive content by the codec's ber mode).
function _octetContent(node, ctx, what, code) {
  if (!(node && node.tagClass === "universal" && node.tagNumber === TAGS.OCTET_STRING && node.content)) {
    throw ctx.E(code || "pkcs12/bad-bag-value", what + " must be an OCTET STRING");
  }
  return node.content;
}

// RFC 7292 §4.1 — a privacy-mode safe wraps a SafeContents, so the encrypted
// content's declared type must be id-data whichever CMS privacy structure
// carries it, and the ciphertext must be attached: CMS permits a detached
// EncryptedContentInfo, but here the ciphertext IS the safe's contents — a
// safe without it holds nothing a passphrase could ever recover.
function _privacySafe(content, ctx) {
  if (content.encryptedContentInfo.contentType !== OID_DATA) {
    throw ctx.E("pkcs12/bad-safe-contentinfo-type",
      "an encrypted safe must declare id-data (SafeContents) as its encrypted content type (RFC 7292 §4.1)");
  }
  if (content.encryptedContentInfo.encryptedContent === null) {
    throw ctx.E("pkcs12/bad-safe-contentinfo",
      "an encrypted safe must carry attached ciphertext — its encryptedContent is the SafeContents (RFC 7292 §4.1)");
  }
  return content;
}

// A PKCS#9 SINGLE-VALUE BMPString attribute value (friendlyName), decoded
// UTF-16BE by the codec's string reader (even length + surrogate rules there).
function _bmpValue(bytes, ctx) {
  var node = asn1.decode(bytes, { ber: true });
  if (!(node.tagClass === "universal" && node.tagNumber === TAGS.BMP_STRING)) {
    throw ctx.E("pkcs12/bad-friendly-name", "a friendlyName value must be a BMPString (RFC 7292 §4.2)");
  }
  return asn1.read.string(node);
}

// Re-decode the AuthenticatedSafe blob (BER content region, budgeted).
function _walkAuthenticatedSafe(bytes, state, ctx) {
  return schema.embeddedDer(AUTHENTICATED_SAFE, bytes, ctx, {
    code: "pkcs12/bad-der", what: "the AuthenticatedSafe", ber: true,
    budget: state.budget, budgetCode: "pkcs12/too-deep",
  });
}

// Dispatch each AuthenticatedSafe element by contentType (§4.1): id-data
// carries plaintext SafeContents (re-decoded here); the two privacy modes are
// full CMS structures validated by the CMS module on the already-decoded node
// — ciphertext stays opaque inside the CMS surface.
function _dispatchSafes(asMatch, state, ctx) {
  var safeBags = [];
  var encryptedSafes = [];
  for (var i = 0; i < asMatch.items.length; i++) {
    var el = asMatch.items[i].value.result;
    if (el.contentType === OID_DATA) {
      var contents = schema.embeddedDer(SAFE_CONTENTS, _octetContent(el.innerNode, ctx, "an id-data safe content"), ctx, {
        code: "pkcs12/bad-der", what: "a SafeContents", ber: true,
        budget: state.budget, budgetCode: "pkcs12/too-deep",
      });
      for (var j = 0; j < contents.items.length; j++) {
        safeBags.push(_buildBag(contents.items[j].value.result, state, ctx));
      }
    } else if (el.contentType === OID_ENCRYPTED_DATA) {
      encryptedSafes.push({ type: "encryptedData", content: _privacySafe(cms.walkEncryptedData(el.innerNode), ctx) });
    } else if (el.contentType === OID_ENVELOPED_DATA) {
      encryptedSafes.push({ type: "envelopedData", content: _privacySafe(cms.walkEnvelopedData(el.innerNode), ctx) });
    } else {
      throw ctx.E("pkcs12/bad-safe-contentinfo-type", "an AuthenticatedSafe element must be id-data, id-encryptedData, or id-envelopedData (RFC 7292 §4.1), got " +
        (ctx.oid.name(el.contentType) || el.contentType));
    }
  }
  return { safeBags: safeBags, encryptedSafes: encryptedSafes };
}

// bagId dispatch (§4.2, Appendix D). The bag-type set is closed: an
// unrecognized bagId rejects. Key material delegates to the exported PKCS#8
// parsers; cert / CRL / secret values are surfaced raw.
function _buildBag(rec, state, ctx) {
  var bag = {
    type: null, bagId: rec.bagId,
    friendlyName: rec.friendlyName, localKeyId: rec.localKeyId, attributes: rec.attributes,
  };
  // Key bags are walked from the DECODED node — their wire bytes may carry
  // BER shapes the strict pkcs8 parse entry refuses, and the node already
  // exists (no re-decode).
  if (rec.bagId === OID_KEY_BAG) {
    bag.type = "keyBag";
    bag.key = pkcs8.walkPrivateKeyInfo(rec.valueNode);
    return bag;
  }
  if (rec.bagId === OID_SHROUDED_KEY_BAG) {
    bag.type = "pkcs8ShroudedKeyBag";
    bag.encrypted = pkcs8.walkEncryptedPrivateKeyInfo(rec.valueNode);
    return bag;
  }
  if (rec.bagId === OID_CERT_BAG) {
    bag.type = "certBag";
    var cert = schema.walk(CERT_BAG, rec.valueNode, ctx).result;
    bag.certType = cert.certType; bag.certId = cert.certId; bag.certValue = cert.certValue;
    return bag;
  }
  if (rec.bagId === OID_CRL_BAG) {
    bag.type = "crlBag";
    var crl = schema.walk(CRL_BAG, rec.valueNode, ctx).result;
    bag.crlType = crl.crlType; bag.crlId = crl.crlId; bag.crlValue = crl.crlValue;
    return bag;
  }
  if (rec.bagId === OID_SECRET_BAG) {
    bag.type = "secretBag";
    var secret = schema.walk(SECRET_BAG, rec.valueNode, ctx).result;
    bag.secretTypeId = secret.secretTypeId; bag.secretTypeName = secret.secretTypeName; bag.secretValue = secret.secretValue;
    return bag;
  }
  if (rec.bagId === OID_SAFE_CONTENTS_BAG) {
    // §4.2.6 recursion — bounded independently of the codec depth cap so a
    // chain across re-decode boundaries cannot restart it.
    if (state.bagDepth + 1 > C.LIMITS.PKCS12_MAX_BAG_DEPTH) {
      throw ctx.E("pkcs12/too-deep", "safeContentsBag nesting exceeds the depth cap " + C.LIMITS.PKCS12_MAX_BAG_DEPTH);
    }
    var nestedState = { budget: state.budget, bagDepth: state.bagDepth + 1 };
    bag.type = "safeContentsBag";
    bag.nested = [];
    var nestedMatch = schema.walk(SAFE_CONTENTS, rec.valueNode, ctx);
    for (var i = 0; i < nestedMatch.items.length; i++) {
      bag.nested.push(_buildBag(nestedMatch.items[i].value.result, nestedState, ctx));
    }
    return bag;
  }
  throw ctx.E("pkcs12/bad-bag-type", (ctx.oid.name(rec.bagId) || rec.bagId) + " is not a recognized SafeBag bagId (RFC 7292 §4.2)");
}

/**
 * @primitive  pki.schema.pkcs12.parse
 * @signature  pki.schema.pkcs12.parse(input) -> pfx
 * @since      0.1.18
 * @status     experimental
 * @spec       RFC 7292, RFC 9579
 * @defends    ASN.1-parser-DoS (CWE-400)
 * @related    pki.schema.parse, pki.schema.pkcs8.parse, pki.schema.cms.parse
 *
 * Parse a DER / BER `Buffer` or a PEM string into a structured PFX:
 * `{ version, integrityMode, mac, macedBytes, authSafeSigned, safeBags,
 * encryptedSafes }`. `integrityMode` is `"password"` (id-data authSafe with
 * MacData — `mac` carries `{ kind, hashOid, hashName, hashParameters,
 * pbmac1, macValue, macSalt, iterations }`, where `kind` distinguishes the
 * RFC 9579 PBMAC1 arm; for PBMAC1 the required parameters are validated and
 * decoded onto `pbmac1` (`{ kdf: { salt, iterationCount, keyLength, prfOid,
 * prfName }, schemeOid, schemeName }`) with `hashParameters` keeping the raw
 * bytes, and `macedBytes` is the exact byte range the HMAC covers),
 * `"none"` (id-data authSafe without MacData — the shape
 * `openssl pkcs12 -export -nomac` emits; `mac` is `null` and the store
 * carries no integrity protection, a policy decision left to the caller),
 * or `"public-key"` (id-signedData authSafe — the CMS SignedData surfaced
 * on `authSafeSigned`, signature not verified here). Each of `safeBags` is
 * `{ type, bagId, friendlyName, localKeyId, attributes }` plus its arm:
 * a `keyBag` carries `key` (the PKCS#8 parse), a `pkcs8ShroudedKeyBag`
 * carries `encrypted` (algorithm surfaced, ciphertext opaque), `certBag` /
 * `crlBag` / `secretBag` carry their values raw and byte-exact, and a
 * `safeContentsBag` carries `nested` bags. Encrypted / enveloped safes are
 * surfaced structurally on `encryptedSafes` via the CMS module — recipient
 * infos and algorithms decoded, ciphertext never parsed. MAC verification
 * and bag decryption are passphrase operations for an external layer; the
 * inputs are surfaced exactly.
 *
 * Throws `Pkcs12Error` when the bytes are not a well-formed PFX, and
 * `Asn1Error` when the underlying encoding is malformed.
 *
 * @example
 *   var store = pki.schema.pkcs12.parse(der);
 *   store.safeBags.map(function (b) { return b.type; });
 */
var parse = pkix.makeParser({
  pemLabel: "PKCS12", PemError: PemError, ErrorClass: Pkcs12Error,
  prefix: "pkcs12", what: "PFX", topSchema: PFX, ns: NS, ber: true,
});

/**
 * @primitive  pki.schema.pkcs12.pemDecode
 * @signature  pki.schema.pkcs12.pemDecode(text, label?) -> Buffer
 * @since      0.1.18
 * @status     experimental
 * @spec       RFC 7468, RFC 7292
 * @related    pki.schema.pkcs12.parse
 *
 * Extract the DER bytes from a PEM block (default label `PKCS12`). A
 * `.p12` / `.pfx` file is almost always binary — the PEM path is a
 * convenience for stores that transit text channels.
 *
 * @example
 *   var der = pki.schema.pkcs12.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "PKCS12", PemError); }

/**
 * @primitive  pki.schema.pkcs12.pemEncode
 * @signature  pki.schema.pkcs12.pemEncode(der, label?) -> string
 * @since      0.1.18
 * @status     experimental
 * @spec       RFC 7468
 * @related    pki.schema.pkcs12.pemDecode
 *
 * Wrap DER bytes in a PEM envelope (default label `PKCS12`).
 *
 * @example
 *   var pem = pki.schema.pkcs12.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "PKCS12", PemError); }

// A PFX root leads with a universal INTEGER (version), colliding with the
// PKCS#8 detector on the first child — so the discriminators are children[1]
// (a ContentInfo: SEQUENCE of exactly 2, OID first, [0] constructed second —
// a shape a PrivateKeyInfo's AlgorithmIdentifier never presents) and
// children[2] (a SEQUENCE MacData or absent, never PKCS#8's OCTET STRING).
function matches(root) {
  if (!root || root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE) return false;
  var k = root.children;
  if (!k || k.length < 2 || k.length > 3) return false;
  if (!(k[0].tagClass === "universal" && k[0].tagNumber === TAGS.INTEGER)) return false;
  var ci = k[1];
  if (!ci.children || ci.tagClass !== "universal" || ci.tagNumber !== TAGS.SEQUENCE || ci.children.length !== 2) return false;
  if (!(ci.children[0].tagClass === "universal" && ci.children[0].tagNumber === TAGS.OBJECT_IDENTIFIER)) return false;
  if (!(ci.children[1].tagClass === "context" && ci.children[1].tagNumber === 0 && ci.children[1].children)) return false;
  if (k.length === 3 && !(k[2].tagClass === "universal" && k[2].tagNumber === TAGS.SEQUENCE && k[2].children)) return false;
  return true;
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
};
