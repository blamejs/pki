// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.pkcs12 (RFC 7292 PFX personal-information-exchange
 * container). Spec-first conformance vectors: a valid PFX parses to the
 * documented shape; every malformed PFX / AuthenticatedSafe / SafeBag is
 * rejected fail-closed with a typed pkcs12/* (or leaf asn1/*, or delegated
 * cms/* / pkcs8/*) code. A PFX is a nested OID-dispatch envelope — the
 * authSafe ContentInfo's OCTET STRING content re-decodes to AuthenticatedSafe
 * (SEQUENCE OF ContentInfo), each element re-decodes to SafeContents
 * (SEQUENCE OF SafeBag), each bag dispatched by bagId. Leaf containers are
 * delegated to the exported parsers (pkcs8.parse / pkcs8.parseEncrypted /
 * cms.parse), never re-implemented. RFC 7292 §4.1 says the OCTET STRING
 * content is BER-encoded, so the content-carrying re-decodes accept BER
 * (indefinite length + constructed strings); the outer coercion stays
 * strict-DER-first with a BER fallback confined to this format.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
// The matches detector is internal dispatch infrastructure (not on the curated
// pki.schema.pkcs12 surface), so reach it via the module directly.
var pkcs12Mod = require("../../lib/schema-pkcs12");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.pkcs12.parse(der); }); }
function parse(der) { return pki.schema.pkcs12.parse(der); }

// ---- OIDs used in fixtures -------------------------------------------
var ID_DATA = "1.2.840.113549.1.7.1";
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_ENVELOPED_DATA = "1.2.840.113549.1.7.3";
var ID_DIGESTED_DATA = "1.2.840.113549.1.7.5";
var ID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";
var KEY_BAG = "1.2.840.113549.1.12.10.1.1";
var SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
var CERT_BAG = "1.2.840.113549.1.12.10.1.3";
var CRL_BAG = "1.2.840.113549.1.12.10.1.4";
var SECRET_BAG = "1.2.840.113549.1.12.10.1.5";
var SAFE_CONTENTS_BAG = "1.2.840.113549.1.12.10.1.6";
var X509_CERT_TYPE = "1.2.840.113549.1.9.22.1";
var SDSI_CERT_TYPE = "1.2.840.113549.1.9.22.2";
var X509_CRL_TYPE = "1.2.840.113549.1.9.23.1";
var FRIENDLY_NAME = "1.2.840.113549.1.9.20";
var LOCAL_KEY_ID = "1.2.840.113549.1.9.21";
var SHA256 = "2.16.840.1.101.3.4.2.1";
var PBMAC1 = "1.2.840.113549.1.5.14";
var PBE_SHA_3DES = "1.2.840.113549.1.12.1.3";
var ED25519 = "1.3.101.112";
var AES256_CBC = "2.16.840.1.101.3.4.1.42";

// ---- primitive fixture builders --------------------------------------
function algId(o) { return b.sequence([b.oid(o)]); }
// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }.
function contentInfo(typeOid, node) { return b.sequence([b.oid(typeOid), b.explicit(0, node)]); }
// bmp(str): a universal BMPString TLV (UTF-16BE) — build.* has no BMP helper.
function bmp(str) {
  var utf16 = Buffer.from(str, "utf16le");
  var be = Buffer.alloc(utf16.length);
  for (var i = 0; i < utf16.length; i += 2) { be[i] = utf16[i + 1]; be[i + 1] = utf16[i]; }
  return pki.asn1.encode(0x00, false, pki.asn1.TAGS.BMP_STRING, be);
}
function attribute(o, values) { return b.sequence([b.oid(o), b.set(values)]); }
function friendlyNameAttr(str) { return attribute(FRIENDLY_NAME, [bmp(str)]); }
function localKeyIdAttr(bytes) { return attribute(LOCAL_KEY_ID, [b.octetString(bytes)]); }

// SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, attrs SET OPTIONAL }.
function safeBag(bagId, valueNode, attrs) {
  var kids = [b.oid(bagId), b.explicit(0, valueNode)];
  if (attrs) kids.push(b.set(attrs));
  return b.sequence(kids);
}
// CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT ANY }.
var CERT_DER = b.sequence([b.oid("2.5.4.3"), b.utf8("not-a-real-cert")]);
function certBagInner(certId, valueNode) { return b.sequence([b.oid(certId), b.explicit(0, valueNode)]); }
function certBag(attrs) { return safeBag(CERT_BAG, certBagInner(X509_CERT_TYPE, b.octetString(CERT_DER)), attrs); }
var CRL_DER = b.sequence([b.oid("2.5.4.3"), b.utf8("not-a-real-crl")]);
function crlBag() { return safeBag(CRL_BAG, certBagInner(X509_CRL_TYPE, b.octetString(CRL_DER))); }
function secretBag(typeOid, valueNode) { return safeBag(SECRET_BAG, b.sequence([b.oid(typeOid), b.explicit(0, valueNode)])); }

// A valid PrivateKeyInfo (Ed25519 v1) for keyBag delegation to pkcs8.parse.
var PRIVATE_KEY_INFO = b.sequence([
  b.integer(0),
  b.sequence([b.oid(ED25519)]),
  b.octetString(b.octetString(Buffer.alloc(32, 7))),
]);
function keyBag(attrs) { return safeBag(KEY_BAG, PRIVATE_KEY_INFO, attrs); }
// A valid EncryptedPrivateKeyInfo for pkcs8ShroudedKeyBag → pkcs8.parseEncrypted.
var ENC_PRIVATE_KEY_INFO = b.sequence([
  b.sequence([b.oid(PBE_SHA_3DES), b.sequence([b.octetString(Buffer.alloc(8, 1)), b.integer(2048)])]),
  b.octetString(Buffer.alloc(40, 9)),
]);
function shroudedKeyBag() { return safeBag(SHROUDED_KEY_BAG, ENC_PRIVATE_KEY_INFO); }

// SafeContents ::= SEQUENCE OF SafeBag; AuthenticatedSafe ::= SEQUENCE OF ContentInfo.
function safeContents(bags) { return b.sequence(bags); }
function innerData(safeContentsDer) { return contentInfo(ID_DATA, b.octetString(safeContentsDer)); }
function authenticatedSafe(elements) { return b.sequence(elements); }

// MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }.
function macData(o) {
  o = o || {};
  var kids = [
    b.sequence([algId(o.hashOid || SHA256), b.octetString(o.digest || Buffer.alloc(32, 2))]),
    b.octetString(o.salt || Buffer.alloc(8, 3)),
  ];
  if (o.iterations !== undefined) kids.push(b.integer(o.iterations));
  return b.sequence(kids);
}

// pfx({version, authSafe, macData, rawKids}) — the top PFX SEQUENCE.
function pfx(o) {
  o = o || {};
  if (o.rawKids) return b.sequence(o.rawKids);
  var kids = [b.integer(o.version !== undefined ? o.version : 3), o.authSafe];
  if (o.macData) kids.push(o.macData);
  return b.sequence(kids);
}

// The standard minimal password-integrity PFX: one id-data safe, one certBag.
function minimalPfx(o) {
  o = o || {};
  var bags = o.bags || [certBag()];
  var as = authenticatedSafe(o.elements || [innerData(safeContents(bags))]);
  return pfx({
    version: o.version,
    authSafe: contentInfo(ID_DATA, b.octetString(as)),
    macData: o.omitMac ? null : (o.macData || macData({ iterations: 2048 })),
  });
}

// A minimal valid SignedData whose eContent is the id-data-wrapped
// AuthenticatedSafe DER (public-key integrity mode). Public-key integrity
// requires a signer, so the default carries one; opts.noSigners builds the
// signer-less shape the parser must reject.
function rdn(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function signedDataAuthSafe(authenticatedSafeDer, opts) {
  opts = opts || {};
  var signer = b.sequence([
    b.integer(1),
    b.sequence([rdn("Signer"), b.integer(7)]),
    algId(SHA256),
    algId("1.2.840.113549.1.1.11"),
    b.octetString(Buffer.from([1, 2, 3])),
  ]);
  var signedData = b.sequence([
    b.integer(1),                               // version 1 (eContentType id-data)
    b.set([algId(SHA256)]),                     // digestAlgorithms
    b.sequence([b.oid(ID_DATA), b.explicit(0, b.octetString(authenticatedSafeDer))]),
    b.set(opts.noSigners ? [] : [signer]),      // signerInfos
  ]);
  return contentInfo(ID_SIGNED_DATA, signedData);
}

// A PBMAC1 MacData (RFC 9579): id-PBMAC1 with PBMAC1-params { keyDerivationFunc
// PBKDF2 { salt, iterationCount, keyLength }, messageAuthScheme hmacWithSHA256 }.
function pbmac1MacData(o) {
  o = o || {};
  var kdfParams = [b.octetString(Buffer.alloc(16, 8)), b.integer(o.kdfIterations !== undefined ? o.kdfIterations : 2048)];
  if (o.omitKeyLength !== true) kdfParams.push(b.integer(o.keyLength !== undefined ? o.keyLength : 32));
  var params = b.sequence([
    b.sequence([b.oid("1.2.840.113549.1.5.12"), b.sequence(kdfParams)]),
    b.sequence([b.oid("1.2.840.113549.2.9")]),
  ]);
  var alg = o.omitParams ? b.sequence([b.oid(PBMAC1)]) : b.sequence([b.oid(PBMAC1), params]);
  return b.sequence([
    b.sequence([alg, b.octetString(Buffer.alloc(32, 2))]),
    b.octetString(Buffer.alloc(8, 3)),
    b.integer(2048),
  ]);
}

// A minimal EncryptedData ContentInfo (password-privacy safe).
function encryptedDataSafe() {
  return contentInfo(ID_ENCRYPTED_DATA, b.sequence([
    b.integer(0),
    b.sequence([b.oid(ID_DATA), b.sequence([b.oid(AES256_CBC), b.octetString(Buffer.alloc(16, 4))]),
                b.contextPrimitive(0, Buffer.alloc(48, 5))]),
  ]));
}

// A minimal EnvelopedData ContentInfo with one ktri recipient (public-key privacy).
function envelopedDataSafe() {
  var ktri = b.sequence([
    b.integer(0),
    b.sequence([b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]), b.integer(9)]),
    algId("1.2.840.113549.1.1.1"),
    b.octetString(Buffer.alloc(32, 6)),
  ]);
  return contentInfo(ID_ENVELOPED_DATA, b.sequence([
    b.integer(0),
    b.set([ktri]),
    b.sequence([b.oid(ID_DATA), b.sequence([b.oid(AES256_CBC), b.octetString(Buffer.alloc(16, 4))]),
                b.contextPrimitive(0, Buffer.alloc(48, 5))]),
  ]));
}

// ---- ACCEPT: minimal password-integrity PFX ----------------
function testAcceptMinimal() {
  var der = minimalPfx();
  check("accept: minimal password-integrity PFX parses", parseCode(der) === "NO-THROW");
  var m = parse(der);
  check("accept: version surfaced as 3", m.version === 3);
  check("accept: integrityMode password", m.integrityMode === "password");
  check("accept: one safeBag", m.safeBags.length === 1);
  check("accept: bag type certBag", m.safeBags[0].type === "certBag");
  check("accept: certType x509Certificate", m.safeBags[0].certType === "x509Certificate");
  check("accept: certValue raw Buffer", Buffer.isBuffer(m.safeBags[0].certValue));
  check("accept: mac.iterations 2048", m.mac.iterations === 2048);
  check("accept: mac.hashName sha256", m.mac.hashName === "sha256");
  check("accept: mac.kind hmac", m.mac.kind === "hmac");
  check("accept: macValue + macSalt raw Buffers", Buffer.isBuffer(m.mac.macValue) && Buffer.isBuffer(m.mac.macSalt));
  check("accept: macedBytes is a Buffer", Buffer.isBuffer(m.macedBytes));
}

// ---- ACCEPT: keyBag / shroudedKeyBag delegation --------
function testAcceptKeyBags() {
  var m = parse(minimalPfx({ bags: [keyBag()] }));
  check("keyBag: type", m.safeBags[0].type === "keyBag");
  check("keyBag: delegated to pkcs8.parse (algorithm oid)", m.safeBags[0].key.privateKeyAlgorithm.oid === ED25519);

  m = parse(minimalPfx({ bags: [shroudedKeyBag()] }));
  check("shroudedKeyBag: type", m.safeBags[0].type === "pkcs8ShroudedKeyBag");
  check("shroudedKeyBag: PBE algorithm surfaced", m.safeBags[0].encrypted.encryptionAlgorithm.oid === PBE_SHA_3DES);
  check("shroudedKeyBag: ciphertext raw, never decrypted", Buffer.isBuffer(m.safeBags[0].encrypted.encryptedData));
}

// ---- ACCEPT: public-key integrity via cms.parse ------------
function testAcceptPublicKeyIntegrity() {
  var as = authenticatedSafe([innerData(safeContents([certBag()]))]);
  var der = pfx({ authSafe: signedDataAuthSafe(as) });
  check("signedData authSafe: parses", parseCode(der) === "NO-THROW");
  var m = parse(der);
  check("signedData authSafe: integrityMode public-key", m.integrityMode === "public-key");
  check("signedData authSafe: mac is null", m.mac === null);
  check("signedData authSafe: signers surfaced", m.authSafeSigned && m.authSafeSigned.signerInfos.length === 1);
  check("signedData authSafe: bags descend through eContent", m.safeBags.length === 1 && m.safeBags[0].type === "certBag");

  // A signer-less SignedData carries no integrity — the one property this
  // mode exists to provide.
  var noSigner = pfx({ authSafe: signedDataAuthSafe(as, { noSigners: true }) });
  check("signedData authSafe: zero signers rejected", parseCode(noSigner) === "pkcs12/bad-authsafe");
}

// ---- ACCEPT: safeContentsBag recursion ---------------------
function testAcceptNestedSafeContents() {
  var nested = safeBag(SAFE_CONTENTS_BAG, safeContents([certBag()]));
  var m = parse(minimalPfx({ bags: [nested] }));
  check("safeContentsBag: type", m.safeBags[0].type === "safeContentsBag");
  check("safeContentsBag: nested bags surfaced", m.safeBags[0].nested.length === 1 && m.safeBags[0].nested[0].type === "certBag");
}

// ---- ACCEPT: friendlyName + localKeyId attributes ----------
function testAcceptBagAttributes() {
  var lk = Buffer.alloc(20, 0xab);
  var m = parse(minimalPfx({ bags: [certBag([friendlyNameAttr("My Cert"), localKeyIdAttr(lk)])] }));
  check("attrs: friendlyName decoded UTF-16BE", m.safeBags[0].friendlyName === "My Cert");
  check("attrs: localKeyId raw bytes", m.safeBags[0].localKeyId.equals(lk));
  check("attrs: all attributes surfaced", m.safeBags[0].attributes.length === 2);

  // A BER store may segment a localKeyId value as a constructed OCTET STRING;
  // the attribute-value re-decode follows the same BER rules as the container.
  var lk1 = Buffer.alloc(10, 0xaa);
  var lk2 = Buffer.alloc(10, 0xbb);
  var berLk = Buffer.concat([Buffer.from([0x24, 0x80]), b.octetString(lk1), b.octetString(lk2), Buffer.from([0x00, 0x00])]);
  m = parse(minimalPfx({ bags: [certBag([attribute(LOCAL_KEY_ID, [berLk])])] }));
  check("attrs: BER segmented localKeyId reassembles", m.safeBags[0].localKeyId.equals(Buffer.concat([lk1, lk2])));
}

// ---- ACCEPT: encrypted / enveloped safes via cms.parse -
function testAcceptEncryptedSafes() {
  var m = parse(minimalPfx({ elements: [innerData(safeContents([certBag()])), encryptedDataSafe()] }));
  check("encryptedData safe: parses", m.encryptedSafes.length === 1);
  check("encryptedData safe: cms result shape", m.encryptedSafes[0].type === "encryptedData" &&
        m.encryptedSafes[0].content.encryptedContentInfo.contentEncryptionAlgorithm.oid === AES256_CBC);
  check("encryptedData safe: ciphertext raw", Buffer.isBuffer(m.encryptedSafes[0].content.encryptedContentInfo.encryptedContent));

  m = parse(minimalPfx({ elements: [envelopedDataSafe()] }));
  check("envelopedData safe: parses with recipientInfos", m.encryptedSafes[0].type === "envelopedData" &&
        m.encryptedSafes[0].content.recipientInfos.length === 1);
  check("envelopedData safe: recipient keyEncryptionAlgorithm surfaced",
        m.encryptedSafes[0].content.recipientInfos[0].keyEncryptionAlgorithm.oid === "1.2.840.113549.1.1.1");

  // BER streamed ciphertext: encryptedContent as a constructed
  // [0] IMPLICIT OCTET STRING (indefinite, segmented) reassembles.
  var ct1 = Buffer.alloc(24, 5);
  var ct2 = Buffer.alloc(24, 6);
  var berCt = Buffer.concat([Buffer.from([0xa0, 0x80]), b.octetString(ct1), b.octetString(ct2), Buffer.from([0x00, 0x00])]);
  var berEci = b.sequence([b.oid(ID_DATA), b.sequence([b.oid(AES256_CBC), b.octetString(Buffer.alloc(16, 4))]), berCt]);
  var berEncSafe = contentInfo(ID_ENCRYPTED_DATA, b.sequence([b.integer(0), berEci]));
  m = parse(minimalPfx({ elements: [berEncSafe] }));
  check("BER streamed encryptedContent reassembles byte-exact",
        m.encryptedSafes[0].content.encryptedContentInfo.encryptedContent.equals(Buffer.concat([ct1, ct2])));

  // §4.1 — a privacy safe wraps SafeContents, so the encrypted content's
  // declared type must be id-data.
  var wrongType = contentInfo(ID_ENCRYPTED_DATA, b.sequence([
    b.integer(0),
    b.sequence([b.oid(ID_SIGNED_DATA), b.sequence([b.oid(AES256_CBC), b.octetString(Buffer.alloc(16, 4))]),
                b.contextPrimitive(0, Buffer.alloc(48, 5))]),
  ]));
  check("encrypted safe declaring a non-id-data content type rejected",
        parseCode(minimalPfx({ elements: [wrongType] })) === "pkcs12/bad-safe-contentinfo-type");
}

// ---- ACCEPT: iterations default / PBMAC1 --------------
function testAcceptMacVariants() {
  var m = parse(minimalPfx({ macData: macData({}) }));
  check("mac: absent iterations defaults to 1", m.mac.iterations === 1);

  // Legacy SHA-1 HMAC — the most common deployed store shape.
  m = parse(minimalPfx({ macData: macData({ hashOid: "1.3.14.3.2.26", digest: Buffer.alloc(20, 2), iterations: 2048 }) }));
  check("mac: legacy SHA-1 HMAC resolves by name", m.mac.kind === "hmac" && m.mac.hashName === "sha1");
  check("mac: legacy HMAC has no pbmac1 surface", m.mac.pbmac1 === null);

  // RFC 9579 PBMAC1: params decoded and validated, raw bytes kept alongside.
  m = parse(minimalPfx({ macData: pbmac1MacData() }));
  check("mac: PBMAC1 surfaced distinctly", m.mac.kind === "pbmac1");
  check("mac: PBMAC1 parameters surfaced raw", Buffer.isBuffer(m.mac.hashParameters));
  check("mac: PBMAC1 KDF decoded (keyLength, salt, iterations)",
        m.mac.pbmac1.kdf.keyLength === 32 && Buffer.isBuffer(m.mac.pbmac1.kdf.salt) && m.mac.pbmac1.kdf.iterationCount === 2048);
  check("mac: PBMAC1 scheme resolved by name", m.mac.pbmac1.schemeName === "hmacWithSHA256");

  // RFC 9579 §4 — PBMAC1 without parameters is malformed.
  check("mac: PBMAC1 missing params rejected",
        parseCode(minimalPfx({ macData: pbmac1MacData({ omitParams: true }) })) === "pkcs12/bad-mac-data");
  // RFC 9579 §5 — PBKDF2-params must carry keyLength.
  check("mac: PBMAC1 missing keyLength rejected",
        parseCode(minimalPfx({ macData: pbmac1MacData({ omitKeyLength: true }) })) === "pkcs12/bad-mac-data");
  // Numeric fields surface as exact numbers or not at all — a value past the
  // safe-integer range would round silently on conversion.
  check("mac: PBMAC1 oversized iterationCount rejected",
        parseCode(minimalPfx({ macData: pbmac1MacData({ kdfIterations: (1n << 60n) }) })) === "pkcs12/bad-mac-data");
  check("mac: PBMAC1 zero keyLength rejected",
        parseCode(minimalPfx({ macData: pbmac1MacData({ keyLength: 0n }) })) === "pkcs12/bad-mac-data");
  check("mac: PBMAC1 oversized keyLength rejected",
        parseCode(minimalPfx({ macData: pbmac1MacData({ keyLength: (1n << 60n) }) })) === "pkcs12/bad-mac-data");
}

// ---- REJECT: version ---------------------------------------
function testRejectVersion() {
  check("version=1 rejected", parseCode(minimalPfx({ version: 1 })) === "pkcs12/bad-version");
  check("version=0 rejected", parseCode(minimalPfx({ version: 0 })) === "pkcs12/bad-version");
  // A version-less PFX leads with the ContentInfo where the INTEGER belongs —
  // the leaf reader rejects the tag (asn1/*), the same fail-closed tier.
  var noVersion = pfx({ rawKids: [contentInfo(ID_DATA, b.octetString(authenticatedSafe([]))), macData({ iterations: 2048 })] });
  check("version absent rejected", /^(pkcs12|asn1)\//.test(parseCode(noVersion)));
}

// ---- REJECT: arity -----------------------------------------
function testRejectArity() {
  check("PFX of 1 child rejected", /^pkcs12\//.test(parseCode(pfx({ rawKids: [b.integer(3)] }))));
  var four = pfx({ rawKids: [b.integer(3), contentInfo(ID_DATA, b.octetString(authenticatedSafe([]))), macData({ iterations: 2048 }), b.integer(1)] });
  check("PFX of 4 children rejected", /^pkcs12\//.test(parseCode(four)));
  check("non-SEQUENCE root rejected", /^pkcs12\//.test(parseCode(b.octetString(Buffer.from([1])))));
}

// ---- REJECT: authSafe type + integrity mode -----------
function testRejectAuthSafeAndIntegrity() {
  var as = authenticatedSafe([innerData(safeContents([certBag()]))]);
  var enveloped = pfx({ authSafe: contentInfo(ID_ENVELOPED_DATA, b.octetString(as)), macData: macData({ iterations: 2048 }) });
  check("authSafe id-envelopedData rejected", parseCode(enveloped) === "pkcs12/bad-authsafe-type");
  var unknown = pfx({ authSafe: contentInfo("1.2.3.4.5", b.octetString(as)), macData: macData({ iterations: 2048 }) });
  check("authSafe unknown OID rejected", parseCode(unknown) === "pkcs12/bad-authsafe-type");

  var signedWithMac = pfx({ authSafe: signedDataAuthSafe(as), macData: macData({ iterations: 2048 }) });
  check("id-signedData + macData present rejected", parseCode(signedWithMac) === "pkcs12/bad-integrity-mode");

  // MacData is OPTIONAL in the PFX syntax: a MAC-less id-data store (the
  // OpenSSL -nomac shape) parses with integrityMode "none" — no integrity is
  // a caller policy concern, not a structural fault.
  var dataNoMac = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(as)) });
  check("id-data without macData parses", parseCode(dataNoMac) === "NO-THROW");
  var nm = parse(dataNoMac);
  check("MAC-less store surfaces integrityMode none", nm.integrityMode === "none" && nm.mac === null);
  check("MAC-less store still decodes its bags", nm.safeBags.length === 1 && nm.safeBags[0].type === "certBag");
  check("MAC-less store still surfaces macedBytes", Buffer.isBuffer(nm.macedBytes));
}

// ---- REJECT: iterations DEFAULT canonicalization -----------
function testRejectIterationsDefault() {
  check("explicit iterations=1 rejected (non-canonical DER DEFAULT)",
        parseCode(minimalPfx({ macData: macData({ iterations: 1 }) })) === "pkcs12/bad-mac-iterations");
  var neg = parseCode(minimalPfx({ macData: macData({ iterations: -5 }) }));
  check("negative iterations rejected", neg === "pkcs12/bad-mac-iterations" || /^asn1\//.test(neg));
}

// ---- REJECT: bagValue / certValue tag shape ----------------
function testRejectPrimitiveContextTags() {
  var primBag = b.sequence([b.oid(CERT_BAG), b.contextPrimitive(0, CERT_DER)]);
  check("primitive [0] bagValue rejected", /^pkcs12\//.test(parseCode(minimalPfx({ bags: [primBag] }))));
  var primCertValue = safeBag(CERT_BAG, b.sequence([b.oid(X509_CERT_TYPE), b.contextPrimitive(0, CERT_DER)]));
  check("primitive [0] certValue rejected", /^pkcs12\//.test(parseCode(minimalPfx({ bags: [primCertValue] }))));
}

// ---- REJECT: SafeContents SET-OF wart -----------------------
function testRejectSetOfSafeContents() {
  var setContents = b.set([certBag()]);
  var el = contentInfo(ID_DATA, b.octetString(setContents));
  var der = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(authenticatedSafe([el]))), macData: macData({ iterations: 2048 }) });
  check("SafeContents as SET OF rejected (OpenSSL #6665 divergence)", /^pkcs12\//.test(parseCode(der)));
}

// ---- REJECT: unknown bagId / certId --------------------
function testRejectUnknownIds() {
  var unknownBag = safeBag("1.2.840.113549.1.12.10.1.99", b.octetString(Buffer.from([1])));
  check("unknown bagId rejected", parseCode(minimalPfx({ bags: [unknownBag] })) === "pkcs12/bad-bag-type");
  var unknownCert = safeBag(CERT_BAG, b.sequence([b.oid("1.2.3.4"), b.explicit(0, b.octetString(CERT_DER))]));
  check("unknown certId rejected", parseCode(minimalPfx({ bags: [unknownCert] })) === "pkcs12/bad-cert-type");
  var unknownCrl = safeBag(CRL_BAG, b.sequence([b.oid("1.2.3.4.5"), b.explicit(0, b.octetString(CRL_DER))]));
  check("unknown crlId rejected", parseCode(minimalPfx({ bags: [unknownCrl] })) === "pkcs12/bad-crl-type");
  // sdsiCertificate arm MUST still be accepted (closed set, both members).
  var sdsi = safeBag(CERT_BAG, b.sequence([b.oid(SDSI_CERT_TYPE), b.explicit(0, b.ia5("c2RzaQ=="))]));
  check("sdsiCertificate arm accepted", parseCode(minimalPfx({ bags: [sdsi] })) === "NO-THROW");
  // secretBag typeId is an open set — opaque-surface, not reject.
  var m = parse(minimalPfx({ bags: [secretBag("1.2.3.4.5.6", b.octetString(Buffer.from([7])))] }));
  check("secretBag unknown typeId opaque-surfaced", m.safeBags[0].secretTypeId === "1.2.3.4.5.6" && Buffer.isBuffer(m.safeBags[0].secretValue));
}

// ---- REJECT: single-value attrs -----------------------------
function testRejectMultiValueAttrs() {
  var twoNames = attribute(FRIENDLY_NAME, [bmp("A"), bmp("B")]);
  check("friendlyName with two values rejected", parseCode(minimalPfx({ bags: [certBag([twoNames])] })) === "pkcs12/bad-friendly-name");
  // An empty attrValues SET fails the shared Attribute schema's SIZE floor
  // (pkcs12/bad-attribute-values) before the single-value check can name the
  // attribute — either code is the same fail-closed verdict.
  var emptyKeyId = attribute(LOCAL_KEY_ID, []);
  check("localKeyId with zero values rejected", /^pkcs12\/bad-(local-key-id|attribute-values)$/.test(parseCode(minimalPfx({ bags: [certBag([emptyKeyId])] }))));
  // Unknown attrIds MUST be tolerated ("Other attributes are allowed", §4.2).
  var unknownAttr = attribute("1.2.3.4.9", [b.utf8("x")]);
  check("unknown attrId tolerated", parseCode(minimalPfx({ bags: [certBag([unknownAttr])] })) === "NO-THROW");

  // At most one INSTANCE of each single-value attribute (PKCS#9).
  var dupNames = [friendlyNameAttr("A"), friendlyNameAttr("B")];
  check("duplicate friendlyName instances rejected", parseCode(minimalPfx({ bags: [certBag(dupNames)] })) === "pkcs12/bad-friendly-name");

  // Value-type rules: friendlyName is a BMPString, localKeyId an OCTET STRING.
  var utf8Name = attribute(FRIENDLY_NAME, [b.utf8("plain")]);
  check("non-BMPString friendlyName rejected", parseCode(minimalPfx({ bags: [certBag([utf8Name])] })) === "pkcs12/bad-friendly-name");
  var intKeyId = attribute(LOCAL_KEY_ID, [b.integer(5)]);
  check("non-OCTET-STRING localKeyId rejected", parseCode(minimalPfx({ bags: [certBag([intKeyId])] })) === "pkcs12/bad-local-key-id");

  // A single attribute's value list is capped.
  var many = [];
  for (var v = 0; v < 300; v++) many.push(b.octetString(Buffer.from([v & 0xff, v >> 8])));
  var fatAttr = attribute("1.2.3.4.10", many);
  check("oversized attrValues SET rejected", parseCode(minimalPfx({ bags: [certBag([fatAttr])] })) === "pkcs12/bad-attribute-values");
}

// ---- REJECT: BMPString oddness ------------------------------
function testRejectBadBmpString() {
  var oddBmp = pki.asn1.encode(0x00, false, pki.asn1.TAGS.BMP_STRING, Buffer.from([0x00, 0x41, 0x42]));
  var attr = attribute(FRIENDLY_NAME, [oddBmp]);
  check("odd-length BMPString rejected", /^(asn1|pkcs12)\//.test(parseCode(minimalPfx({ bags: [certBag([attr])] }))));
}

// ---- REJECT: SET-OF order -----------------------------------
function testRejectSetOrder() {
  // Two attributes deliberately in DESCENDING DER order (b.set would sort —
  // use raw encode of the SET with unsorted members).
  var a1 = friendlyNameAttr("Z");
  var a2 = localKeyIdAttr(Buffer.alloc(4, 1));
  var members = Buffer.compare(a1, a2) > 0 ? [a1, a2] : [a2, a1];
  var rawSet = pki.asn1.encode(0x00, true, pki.asn1.TAGS.SET, Buffer.concat(members));
  var kids = [b.oid(CERT_BAG), b.explicit(0, certBagInner(X509_CERT_TYPE, b.octetString(CERT_DER))), rawSet];
  var bag = b.sequence(kids);
  var c = parseCode(minimalPfx({ bags: [bag] }));
  check("bagAttributes in descending order rejected", /^pkcs12\//.test(c));
}

// ---- REJECT: strict outer DER --------------------------------
function testRejectOuterNonDer() {
  var valid = minimalPfx();
  var trailing = Buffer.concat([valid, Buffer.from([0x00])]);
  check("trailing byte rejected", parseCode(trailing) === "pkcs12/bad-der");
}

// ---- BER interop --
function testBerContentAccepted() {
  // Rebuild the minimal PFX with a BER indefinite-length authSafe [0] wrapper
  // and a constructed OCTET STRING content — the OpenSSL-default shape.
  var as = authenticatedSafe([innerData(safeContents([certBag()]))]);
  // constructed OCTET STRING: 0x24 <indef> [ 04 chunk1 ] [ 04 chunk2 ] 00 00
  var half = Math.floor(as.length / 2);
  var chunk1 = b.octetString(as.subarray(0, half));
  var chunk2 = b.octetString(as.subarray(half));
  var constructedOctet = Buffer.concat([Buffer.from([0x24, 0x80]), chunk1, chunk2, Buffer.from([0x00, 0x00])]);
  // [0] EXPLICIT with indefinite length
  var explicit0 = Buffer.concat([Buffer.from([0xa0, 0x80]), constructedOctet, Buffer.from([0x00, 0x00])]);
  var authSafeCi = Buffer.concat([Buffer.from([0x30, 0x80]), b.oid(ID_DATA), explicit0, Buffer.from([0x00, 0x00])]);
  var mac = macData({ iterations: 2048 });
  var version = b.integer(3);
  var berPfx = Buffer.concat([Buffer.from([0x30, 0x80]), version, authSafeCi, mac, Buffer.from([0x00, 0x00])]);

  check("BER PFX (indefinite + constructed OCTET STRING) parses", parseCode(berPfx) === "NO-THROW");
  var m = parse(berPfx);
  check("BER PFX: bag surfaced", m.safeBags.length === 1 && m.safeBags[0].type === "certBag");
  check("BER PFX: certValue byte-exact", m.safeBags[0].certValue.equals(CERT_DER));
  // §5.1 step 5B on the BER shape: the reassembled value octets are the MAC
  // region — the exact boundary a segmented encoding could silently shift.
  check("BER PFX: macedBytes is the reassembled AuthenticatedSafe", m.macedBytes.equals(as));
  // The orchestrator detects and routes a BER PFX too (real .p12 files are BER).
  var routed = pki.schema.parse(berPfx);
  check("BER PFX routes through pki.schema.parse", routed.version === 3 && routed.safeBags.length === 1);
  // The DER equivalent of the same content also parses.
  check("DER equivalent parses", parseCode(minimalPfx()) === "NO-THROW");

  // Inner-region BER: a strict-DER outer PFX whose OCTET STRING content holds a
  // BER (indefinite-length) AuthenticatedSafe — the re-decode path's own BER
  // acceptance, independent of the outer fallback.
  var innerEl = innerData(safeContents([certBag()]));
  var asBer = Buffer.concat([Buffer.from([0x30, 0x80]), innerEl, Buffer.from([0x00, 0x00])]);
  var derOuterBerInner = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(asBer)), macData: macData({ iterations: 2048 }) });
  var mi = parse(derOuterBerInner);
  check("BER inner AuthenticatedSafe parses inside a DER outer PFX", mi.safeBags.length === 1 && mi.safeBags[0].type === "certBag");
}

// ---- depth / count bombs -----------------------------
function testDepthAndCountBombs() {
  // A safeContentsBag chain deeper than the bag-recursion budget but inside
  // the codec depth cap — proves the pkcs12-level ceiling fires on its own,
  // not the underlying decoder's.
  var inner = safeContents([certBag()]);
  for (var i = 0; i < 17; i++) inner = safeContents([safeBag(SAFE_CONTENTS_BAG, inner)]);
  check("safeContentsBag nesting bomb rejected typed",
        parseCode(minimalPfx({ bags: [safeBag(SAFE_CONTENTS_BAG, inner)] })) === "pkcs12/too-deep");

  // A chain deep enough to blow the codec cap inside the re-decoded region
  // still fails typed (wrapped by the re-decode), never a native RangeError.
  var abyss = safeContents([certBag()]);
  for (var d = 0; d < 40; d++) abyss = safeContents([safeBag(SAFE_CONTENTS_BAG, abyss)]);
  check("codec-depth bomb inside a re-decoded region rejected typed",
        /^(pkcs12|asn1)\//.test(parseCode(minimalPfx({ bags: [safeBag(SAFE_CONTENTS_BAG, abyss)] }))));

  // Element-count bomb: thousands of empty inner id-data safes.
  var empties = [];
  for (var j = 0; j < 5000; j++) empties.push(innerData(safeContents([])));
  var bomb = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(authenticatedSafe(empties))), macData: macData({ iterations: 2048 }) });
  check("element-count bomb rejected", parseCode(bomb) === "pkcs12/too-many-elements");

  // The recursion budget spans the id-signedData delegation boundary too.
  var deep = safeContents([certBag()]);
  for (var k = 0; k < 17; k++) deep = safeContents([safeBag(SAFE_CONTENTS_BAG, deep)]);
  var as = authenticatedSafe([innerData(deep)]);
  var viaSigned = pfx({ authSafe: signedDataAuthSafe(as) });
  check("nesting bomb via signedData delegation rejected typed", parseCode(viaSigned) === "pkcs12/too-deep");

  // The cross-decode budget itself: many small id-data elements each cost one
  // re-decode, so a store under the element cap but over the re-decode budget
  // fails with the budget verdict, not resource exhaustion.
  var wide = [];
  for (var w = 0; w < 100; w++) wide.push(innerData(safeContents([certBag()])));
  var wideBomb = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(authenticatedSafe(wide))), macData: macData({ iterations: 2048 }) });
  check("re-decode budget exhaustion rejected typed", parseCode(wideBomb) === "pkcs12/too-deep");
}

// ---- macedBytes exactness --------------------------------------
function testMacedBytesExactness() {
  var as = authenticatedSafe([innerData(safeContents([certBag()]))]);
  var der = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(as)), macData: macData({ iterations: 2048 }) });
  var m = parse(der);
  check("macedBytes equals the AuthenticatedSafe value octets (no TLV header)", m.macedBytes.equals(as));
  var octetTlv = b.octetString(as);
  check("macedBytes is NOT the OCTET STRING TLV (header excluded)", !m.macedBytes.equals(octetTlv));
}

// ---- raw exactness ----------------------------------------------
function testRawExactness() {
  var m = parse(minimalPfx());
  check("certValue byte-for-byte", m.safeBags[0].certValue.equals(CERT_DER));
  m = parse(minimalPfx({ bags: [crlBag()] }));
  check("crlValue byte-for-byte", m.safeBags[0].crlValue.equals(CRL_DER));
  m = parse(minimalPfx({ bags: [shroudedKeyBag()] }));
  check("shrouded encryptedData raw", m.safeBags[0].encrypted.encryptedData.equals(Buffer.alloc(40, 9)));
}

// ---- dispatch + exclusivity ---------------------------------
function testDispatch() {
  var der = minimalPfx();
  var routed = pki.schema.parse(der);
  check("schema.parse routes a PFX to pkcs12", routed.version === 3 && Array.isArray(routed.safeBags));
  check("all() lists pkcs12", pki.schema.all().indexOf("pkcs12") !== -1);
  check("all() order (pkcs12 ahead of pkcs8)", JSON.stringify(pki.schema.all()) ===
        JSON.stringify(["cms", "tsp", "crmf", "ocsp-request", "ocsp-response", "pkcs12", "pkcs8", "csr", "attrcert", "attrcert-v1", "crl", "x509"]));

  // pkcs8 differential: a PrivateKeyInfo routes to pkcs8, never pkcs12.
  var p8 = pki.schema.parse(PRIVATE_KEY_INFO);
  check("PrivateKeyInfo routes to pkcs8", p8.privateKeyAlgorithm && p8.privateKeyAlgorithm.oid === ED25519);
  check("pkcs12.matches rejects a PrivateKeyInfo", pkcs12Mod.matches(pki.asn1.decode(PRIVATE_KEY_INFO)) === false);
  // Two-child PFX (public-key integrity, no mac) still routes to pkcs12.
  var as = authenticatedSafe([innerData(safeContents([certBag()]))]);
  var twoChild = pfx({ authSafe: signedDataAuthSafe(as) });
  check("2-child PFX matches pkcs12", pkcs12Mod.matches(pki.asn1.decode(twoChild)) === true);
  check("3-child PFX matches pkcs12", pkcs12Mod.matches(pki.asn1.decode(der)) === true);
}

// ---- input coercion ------------------------------------------------
function testInputCoercion() {
  var der = minimalPfx();
  check("Buffer input parses", parseCode(der) === "NO-THROW");
  check("Uint8Array input parses", parseCode(new Uint8Array(der)) === "NO-THROW");
  var pem = pki.schema.pkcs12.pemEncode(der);
  check("pemEncode emits the PKCS12 label", pem.indexOf("-----BEGIN PKCS12-----") === 0);
  check("PEM input parses", parseCode(pem) === "NO-THROW");
  check("pemDecode round-trips", pki.schema.pkcs12.pemDecode(pem).equals(der));
  check("number input rejected", parseCode(42) === "pkcs12/bad-input");
}

// ---- multi-defect fail-closed ---------------------------------------
function testMultiDefectFailClosed() {
  var as = authenticatedSafe([innerData(safeContents([certBag()]))]);
  var evil = pfx({ rawKids: [b.integer(1), signedDataAuthSafe(as), macData({ iterations: 1 })] });
  var c = parseCode(evil);
  check("multi-defect PFX rejected typed", /^(pkcs12|asn1|cms|pkcs8)\//.test(c));
}

// ---- inner content-type reject ----------------------------------------
function testRejectInnerContentType() {
  var digested = contentInfo(ID_DIGESTED_DATA, b.octetString(Buffer.from([0x05, 0x00])));
  var der = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(authenticatedSafe([digested]))), macData: macData({ iterations: 2048 }) });
  check("inner id-digestedData rejected", parseCode(der) === "pkcs12/bad-safe-contentinfo-type");
}

// ---- empty AuthenticatedSafe is legal (RFC 7292 section 4.1) --------------------------------------
function testEmptyAuthenticatedSafe() {
  var der = pfx({ authSafe: contentInfo(ID_DATA, b.octetString(authenticatedSafe([]))), macData: macData({ iterations: 2048 }) });
  check("empty AuthenticatedSafe parses to zero bags", parseCode(der) === "NO-THROW" && parse(der).safeBags.length === 0);
}

// ---- runner ----------------------------------------------------------
testAcceptMinimal();
testAcceptKeyBags();
testAcceptPublicKeyIntegrity();
testAcceptNestedSafeContents();
testAcceptBagAttributes();
testAcceptEncryptedSafes();
testAcceptMacVariants();
testRejectVersion();
testRejectArity();
testRejectAuthSafeAndIntegrity();
testRejectIterationsDefault();
testRejectPrimitiveContextTags();
testRejectSetOfSafeContents();
testRejectUnknownIds();
testRejectMultiValueAttrs();
testRejectBadBmpString();
testRejectSetOrder();
testRejectOuterNonDer();
testBerContentAccepted();
testDepthAndCountBombs();
testMacedBytesExactness();
testRawExactness();
testDispatch();
testInputCoercion();
testMultiDefectFailClosed();
testRejectInnerContentType();
testEmptyAuthenticatedSafe();

if (require.main === module) console.log("CHECKS " + helpers.getChecks());
module.exports = {};
