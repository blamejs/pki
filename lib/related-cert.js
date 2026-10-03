// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.relatedCert
 * @nav        Signing
 * @title      Related certificates
 * @fullname   Related certificates: binding a second certificate of the same subject
 * @order      236
 * @slug       related-cert
 *
 * @intro
 *   One subject, two certificates. A migration to post-quantum signatures leaves a
 *   subject holding a classical certificate and a PQC one at the same time, and a
 *   protocol that can use both needs each certificate to say the other exists.
 *   RFC 9763 does that in two structures: a CSR attribute where the requester
 *   proves it holds the certificate it is naming, and a certificate extension where
 *   the issuer records which certificate the new one relates to.
 *
 *   `requestSignedData` builds the bytes the requester signs. Section 3.1 fixes
 *   them as the DER `IssuerAndSerialNumber` followed by the DER `BinaryTime`, and
 *   nothing else. `locationInfo` travels in the attribute and is outside those
 *   bytes, so a verified proof says the requester holds the certificate and says
 *   nothing about where that certificate can be fetched. `pki.csr.sign` takes the
 *   whole attribute as `relatedCertRequest` and encodes the first two fields from
 *   this same function, so the bytes signed and the bytes emitted cannot drift
 *   apart.
 *
 *   `verifyRequest` checks that proof against the certificate `certID` names,
 *   through the engine the certificate path uses, so the advertised algorithm is
 *   bound to the key the same way. Handing it any other certificate throws: a proof
 *   checked against a certificate the request did not name answers a different
 *   question than the one asked. The structure names no algorithm, so the identifier
 *   comes from the same resolver the signing verbs use, which is what reaches every
 *   algorithm they sign with including an RSASSA-PSS key whose parameters belong to
 *   its identifier.
 *
 *   `certificateHash` and `matchesCertificate` are the extension side.
 *   `pki.x509.sign` takes `extensions.relatedCertificate`, and the form handed the
 *   related certificate computes the digest here, so no caller can name one
 *   algorithm while carrying the output of another. The algorithm defaults the way
 *   section 4.1 directs, to the hash the related certificate's own signature OID
 *   indicates; a certificate signed with Ed25519 or ML-DSA indicates none, and that
 *   throws instead of falling back to a hash the document does not name. `sha1` is
 *   refused: a chosen-prefix collision on a certificate is a demonstrated attack.
 *
 *   The extension is emitted non-critical, which section 4.1 asks for at SHOULD NOT,
 *   and a critical one still parses: `pki.lint.certificate` with the `rfc9763`
 *   profile grades it, alongside the section's MUST that the extension appear only
 *   in the end-entity certificate of a chain.
 *
 * @card Build the bytes a requester signs, verify the proof it made, and compute or
 *   check the digest that names a related certificate (RFC 9763).
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var schemaX509 = require("./schema-x509");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var seam = require("./verify-seam");
var signScheme = require("./sign-scheme");
var C = require("./constants");

var RelatedCertError = frameworkError.RelatedCertError;
var b = asn1.build;
var _create = intrinsic.create;
var _assign = intrinsic.assign;
var _forEach = intrinsic.forEach;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferConcat = intrinsic.bufferConcat;
var _BigInt = intrinsic.BigInt;
var _floor = intrinsic.floor;
var _String = intrinsic.String;
var _keys = intrinsic.keys;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _fromCharCode = String.fromCharCode;

function _err(code, message, cause) { return new RelatedCertError(code, message, cause); }

var _seam = seam.makeSeam("related-cert", RelatedCertError, "relatedcert/bad-input");

var NS = pkix.makeNS("relatedcert", RelatedCertError, oid);
var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
/** @internal The shared `IssuerAndSerialNumber`, used to read back the identifier this module just
 *  encoded so the identity comparison has the decoded `Name` the RFC 5280 sec. 7.1 rules need. It reads
 *  our OWN bytes, not a caller's, which is what makes a second decode safe here: the caller's record was
 *  read once on the way in and these bytes are the result. */
var ISSUER_AND_SERIAL = pkix.issuerAndSerialNumber(NS, { code: "relatedcert/bad-input", what: "certID" });
function _certIdParts(der) {
  return schema.walk(ISSUER_AND_SERIAL, asn1.decode(der), NS).result;
}

var DIGEST_LENGTHS = pkix.digestLengths();
var SIG_OID_DIGEST = pkix.signatureDigestNames(oid);

/** @internal The digests this module will bind a certificate identity to. sha1 is registered and
 *  decodable, and is absent here: a chosen-prefix collision on a certificate is a demonstrated
 *  attack, so a value naming it is refused before anything is computed. A caller reading a hashValue a
 *  producer wrote under sha1 still gets the algorithm name off the parsed extension. */
var ALLOWED_DIGESTS = _assign(_create(null), {
  sha256: 1, sha384: 1, sha512: 1, "sha3-256": 1, "sha3-512": 1,
});

/** @internal The two digests the substitution below resolves against. They only have to differ. */
var PROBE_DIGESTS = ["sha256", "sha512"];
/** @internal Whether naming a digest would change the algorithm identifier this key signs with, asked
 *  by running the substitution instead of listing which key kinds admit a choice. An EdDSA or ML-DSA
 *  key resolves to one identifier whatever digest is asked for, so naming one is a request that would
 *  be dropped; an RSA or ECDSA key resolves to a different identifier per digest. A key kind added to
 *  the signing side is covered here without a second table naming it. */
/** @internal The digest an id-RSASSA-PSS SPKI pins, or null when the key pins none or is not that
 *  algorithm. `signScheme.pssSpkiPinnedHash` assumes its argument IS an id-RSASSA-PSS key and complains
 *  about the parameters of anything else, so the algorithm is checked before it is asked. */
function _pinnedDigestName(certLike) {
  var spki = certLike && certLike.subjectPublicKeyInfo;
  var keyOid = spki && spki.algorithm ? spki.algorithm.oid : null;
  if (keyOid === null || keyOid !== oid.byName("rsassaPss")) return null;
  var pinned = signScheme.pssSpkiPinnedHash(certLike, _schemeErr);
  if (pinned === null || pinned === undefined) return null;
  /** @internal Returned in THIS module's vocabulary. The scheme layer answers in the WebCrypto spelling
   *  ("SHA-256") while a digestAlgorithm here is the lowercase registry name ("sha256"), so comparing the
   *  two directly reports a disagreement between two spellings of one hash. The match is made by
   *  normalizing both rather than by a second table that could drift from the first. */
  var want = _normalizeDigestSpelling(pinned);
  var names = _keys(ALLOWED_DIGESTS);
  for (var i = 0; i < names.length; i++) {
    if (_normalizeDigestSpelling(names[i]) === want) return names[i];
  }
  return null;
}
function _normalizeDigestSpelling(name) {
  var out = "";
  var s = _String(name);
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c === 0x2d) continue;
    out += c >= 0x41 && c <= 0x5a ? _fromCharCode(c + 32) : _charAt(s, i);
  }
  return out;
}

function _digestChangesTheAlgorithm(certLike) {
  /** @internal A key that RESTRICTS its hash is asked before it is probed. An id-RSASSA-PSS SPKI may pin
   *  one, and that key refuses every other digest outright, so the second probe threw before the digest the
   *  caller asked for was ever resolved and a valid proof under the key's own hash was reported as an
   *  unsupported algorithm. A pinned key admits no choice, which is the answer the probe computes for
   *  everything else, so it is returned directly rather than reached through a request the key forbids. */
  if (_pinnedDigestName(certLike) !== null) return false;
  var first = _resolveScheme(certLike, PROBE_DIGESTS[0]).sigAlgId;
  var second = _resolveScheme(certLike, PROBE_DIGESTS[1]).sigAlgId;
  return !guard.crypto.constantTimeEqual(first, second);
}

/** @internal `combinedRsaSig` selects the combined `sha256WithRSAEncryption` form an ASN.1 signature
 *  field carries, which is what `pki.csr.sign` and `pki.x509.sign` emit; without it an RSA key resolves
 *  to the bare `rsaEncryption` a CMS signerInfo uses beside a separate digest field. */
function _resolveScheme(certLike, digest) {
  return signScheme.resolveSignScheme(certLike, { combinedRsaSig: true, digestAlgorithm: digest }, true, _schemeErr);
}

/** @internal `serialNumberHex` is here because a certID read back by a parser carries it beside the
 *  serial, and this encoder takes both a caller's description and a parsed record. It is redundant
 *  with `serialNumber`, which is the authority the encoder reads, so it is checked against that rather
 *  than accepted and ignored: a value disagreeing with the serial beside it describes two different
 *  certificates, and only one of them would be signed. */
var KNOWN_CERT_ID_KEYS = _assign(_create(null), { issuer: 1, serialNumber: 1, serialNumberHex: 1 });
var KNOWN_PREIMAGE_KEYS = _assign(_create(null), { certID: 1, requestTime: 1 });
var KNOWN_VERIFY_OPTS = _assign(_create(null), { digestAlgorithm: 1, signatureAlgorithm: 1, maxAge: 1, at: 1 });

/** @internal The freshness check RFC 9763 sec. 3.2 requires of the certification authority: "MUST check
 *  that the BinaryTime indicated in the requestTime field is sufficiently fresh." The WINDOW is not the
 *  toolkit's to choose, the same clause saying "sufficient freshness is defined by local policy and is out
 *  of the scope of this document", so `maxAge` carries it and there is no default: the proof covers the
 *  certID and the requestTime alone (sec. 3.1), so a captured attribute replayed into a fresh request for
 *  an attacker's key verifies forever without it, and a verifier that cannot perform a MUST check must not
 *  answer true. `at` is the instant judged against, for a caller reading a request recorded earlier. */
function _assertFresh(requestTime, o) {
  if (o.maxAge === undefined) {
    throw _err("relatedcert/no-freshness-policy",
      "pki.relatedCert.verifyRequest needs opts.maxAge, the seconds a requestTime may be old: RFC 9763 " +
      "sec. 3.2 requires the certification authority to check that it is sufficiently fresh and leaves " +
      "the window to local policy, and the proof covers the certID and the requestTime alone, so a " +
      "captured attribute replayed into a new request verifies forever without one");
  }
  var maxAge = guard.range.authoredInteger(o.maxAge, _err, "relatedcert/bad-input", "opts.maxAge");
  if (maxAge < 0n) throw _err("relatedcert/bad-input", "opts.maxAge must not be negative");
  var at = o.at === undefined ? new intrinsic.Date() : o.at;
  if (!guard.time.isDate(at)) throw _err("relatedcert/bad-input", "opts.at must be a Date");
  guard.time.assertValid(at, _err, "relatedcert/bad-input", "opts.at");
  var atMs = guard.time.instantOf(at);
  var atSecs = _BigInt(_floor(atMs / C.TIME.seconds(1)));
  /** @internal Both ends are refused. A requestTime older than the window is the replay the clause is
   *  about; one in the FUTURE is a request whose own clock disagrees with the verifier's, and admitting it
   *  would let a producer set a time that stays fresh for as long as they chose. */
  if (requestTime + maxAge < atSecs) {
    throw _err("relatedcert/stale-request",
      "the requestTime is older than the " + maxAge + " seconds opts.maxAge allows (RFC 9763 sec. 3.2)");
  }
  if (requestTime > atSecs) {
    throw _err("relatedcert/stale-request",
      "the requestTime is in the future, so it names no instant this verifier can judge as fresh");
  }
}

var _NAME_SCHEMA = pkix.name(NS);

/** @internal A Name the caller supplied as DER, held to being one before it reaches a preimage the
 *  caller will sign. Bytes that are not a Name would be signed as whatever they are, and the proof
 *  would then attest to a structure no verifier can read back as an issuer. */
function _nameDer(value, what) {
  var der = guard.bytes.snapshot(value, _err, "relatedcert/bad-input", what);
  if (der.length === 0) throw _err("relatedcert/bad-input", what + " must not be empty");
  var node;
  try { node = asn1.decode(der); }
  catch (e) { throw _err("relatedcert/bad-input", what + " must be a DER-encoded Name", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children) {
    throw _err("relatedcert/bad-input", what + " must be a Name, which is a SEQUENCE of RelativeDistinguishedName");
  }
  /** @internal An EMPTY Name is a readable Name and names no issuer, so it is refused here where the
   *  schema below is content with it: `30 00` is a SEQUENCE OF nothing. A certID identifies a
   *  certificate, and this toolkit's own signer refuses an empty issuer, so accepting it would sign an
   *  identifier for a certificate `pki.x509.sign` would not emit. An empty SUBJECT is a different
   *  question and stays legal, a certificate being allowed to carry its identity in a
   *  subjectAltName. */
  if (node.children.length === 0) {
    throw _err("relatedcert/bad-input", what + " is an empty Name, which identifies no issuer");
  }
  /** @internal The outer tag is not the type. A SEQUENCE holding anything at all passed this check, so
   *  bytes no verifier can read back as an issuer were signed as whatever they are: `30 02 05 00` is a
   *  SEQUENCE carrying a NULL, and `pki.csr.sign` under `profile: "none"` emitted a request this
   *  toolkit's own parser then refuses with `csr/bad-rdn`. The node is read with the SHARED X.509 Name
   *  schema, which is the reader on the other side, so what is signed here is what a verifier can
   *  read back. */
  try { schema.walk(_NAME_SCHEMA, node, NS); }
  catch (e) {
    if (e instanceof RelatedCertError) throw e;
    throw _err("relatedcert/bad-input", what + " is not a readable Name: a SEQUENCE of " +
      "RelativeDistinguishedName, each a SET of AttributeTypeAndValue", e);
  }
  return der;
}

/** @internal BinaryTime ::= INTEGER (0..MAX), "the number of seconds, excluding leap seconds, after
 *  midnight UTC, January 1, 1970" (RFC 6019 sec. 2). A Date is read to whole seconds, which is the
 *  unit the type counts. A fractional number is refused: a truncation the caller did not ask for
 *  produces a signature over a time it did not name. */
function _binaryTime(value, what) {
  if (intrinsic.types.isDate(value)) {
    guard.time.assertValid(value, _err, "relatedcert/bad-input", what);
    var secs = _floor(guard.time.instantOf(value) / C.TIME.seconds(1));
    if (secs < 0) throw _err("relatedcert/bad-input", what + " must not precede the epoch (BinaryTime is INTEGER (0..MAX))");
    return _BigInt(secs);
  }
  /** @internal A fractional number reaches the shared authored-integer guard and is refused there, so
   *  a truncation the caller did not ask for cannot become a signature over a time it did not name. */
  var n = guard.range.authoredInteger(value, _err, "relatedcert/bad-input", what);
  if (n < 0n) throw _err("relatedcert/bad-input", what + " must not be negative (BinaryTime is INTEGER (0..MAX))");
  return n;
}

function _serialNumber(value, what) {
  var n = guard.range.authoredInteger(value, _err, "relatedcert/bad-input", what);
  if (n < 1n) throw _err("relatedcert/bad-input", what + " must be a positive integer (RFC 5280 sec. 4.1.2.2)");
  return n;
}

/** @internal The IssuerAndSerialNumber DER of a certID the caller described, or of one a parser
 *  returned. A parsed record carries its issuer as a Name record whose `bytes` are the raw DER, so
 *  both shapes reach the same two reads and the encoder has one input form. */
function _certIdDer(certID) {
  if (certID === null || typeof certID !== "object") {
    throw _err("relatedcert/bad-input", "certID must be an object { issuer, serialNumber }");
  }
  var snap = guard.identifier.snapshotOptions(certID, KNOWN_CERT_ID_KEYS);
  guard.identifier.assertKnownKeys(certID, KNOWN_CERT_ID_KEYS, _err, "relatedcert/bad-input",
    "certID has an unknown field: ");
  var issuer = snap.issuer;
  if (issuer !== null && typeof issuer === "object" && !_isBuffer(issuer)) {
    /** @internal A Name record from a parser. `bytes` is read ONCE: a presence test followed by a second
     *  read is two reads of one member, and an accessor could satisfy the test and then supply other
     *  bytes to encode. */
    var issuerBytes = issuer.bytes;
    if (issuerBytes !== undefined) issuer = issuerBytes;
  }
  var serial = _serialNumber(snap.serialNumber, "certID.serialNumber");
  if (snap.serialNumberHex !== undefined && snap.serialNumberHex !== null) {
    if (typeof snap.serialNumberHex !== "string") throw _err("relatedcert/bad-input", "certID.serialNumberHex must be a hex string");
    var fromHex;
    try { fromHex = _BigInt("0x" + snap.serialNumberHex); }
    catch (e) { throw _err("relatedcert/bad-input", "certID.serialNumberHex must be a hex string", e); }
    if (fromHex !== serial) {
      throw _err("relatedcert/bad-input", "certID.serialNumberHex does not name the same serial as certID.serialNumber");
    }
  }
  return b.sequence([b.raw(_nameDer(issuer, "certID.issuer")), b.integer(serial)]);
}

/**
 * @primitive pki.relatedCert.requestSignedData
 * @signature pki.relatedCert.requestSignedData(spec) -> Buffer
 * @since 0.8.42
 * @status stable
 * @spec RFC 9763 sec. 3.1, RFC 6019 sec. 2
 * @defends related-certificate-proof-replay (CWE-347)
 * @related pki.relatedCert.verifyRequest, pki.csr.sign
 *
 * The bytes a `relatedCertRequest` proof is made over. RFC 9763 sec. 3.1 states them exactly: "the
 * signature field contains a digital signature over the concatenation of DER-encoded
 * IssuerAndSerialNumber and BinaryTime", signed with the key of the certificate `certID` names. `spec`
 * takes `certID` (`{ issuer, serialNumber }`, where `issuer` is a `Name` as DER or a parsed `Name`
 * record and `serialNumber` is a positive integer) and `requestTime` (a `Date`, or whole seconds since
 * the epoch as a number or a bigint).
 *
 * `locationInfo` is outside these bytes, which is the scope the clause draws: a verified proof says
 * the requester holds the certificate, and says nothing about where that certificate can be fetched.
 * A caller that acts on `locationInfo` is acting on an unauthenticated field.
 *
 * @example
 *   var issuer = pki.x509.parseDn("CN=Example CA, O=Example");
 *   var signMe = pki.relatedCert.requestSignedData({
 *     certID: { issuer: issuer.bytes, serialNumber: 42n },
 *     requestTime: new Date("2027-01-15T00:00:00Z"),
 *   });
 *   signMe.length > 0;   // -> true; sign these bytes with the key of certificate 42
 */
function requestSignedData(spec) {
  if (spec === null || typeof spec !== "object") {
    throw _err("relatedcert/bad-input", "pki.relatedCert.requestSignedData takes a { certID, requestTime } object");
  }
  var snap = guard.identifier.snapshotOptions(spec, KNOWN_PREIMAGE_KEYS);
  guard.identifier.assertKnownKeys(spec, KNOWN_PREIMAGE_KEYS, _err, "relatedcert/bad-input",
    "pki.relatedCert.requestSignedData has an unknown option: ");
  return _preimageFrom(_certIdDer(snap.certID), snap.requestTime);
}

/** @internal The preimage built from an ALREADY-ENCODED certID. The verifier encodes the identifier once
 *  and passes the same bytes here and to the binding comparison, so a caller whose `certID` or whose
 *  `issuer` / `serialNumber` inside it answers per read cannot have one identifier hashed and another
 *  compared. That difference is what would let a proof made for one certificate verify against a second
 *  one sharing its public key. */
function _preimageFrom(certIdDer, requestTime) {
  return _bufferConcat([certIdDer, b.integer(_binaryTime(requestTime, "requestTime"))]);
}

/** @internal The digest name a caller supplied, held to the set this module will bind an identity to.
 *  A name outside it is refused whether the reason is that the algorithm is unregistered, that this
 *  build cannot compute it, or that it is sha1. */
function _digestName(value, what) {
  if (typeof value !== "string") throw _err("relatedcert/bad-input", what + " must be a digest algorithm name");
  if (!ALLOWED_DIGESTS[value]) {
    throw _err("relatedcert/bad-input", what + " must name one of sha256 / sha384 / sha512 / sha3-256 / sha3-512; got " + guard.text.showValue(value));
  }
  return value;
}

/** @internal A certificate the caller handed in, parsed once. The full parse is what holds the bytes
 *  to being a certificate at all, so a hash is never taken over something that merely starts like one. */
function _parseCert(certDer, what) {
  var der = guard.bytes.snapshot(certDer, _err, "relatedcert/bad-input", what);
  try { return { der: der, parsed: schemaX509.parse(der) }; }
  catch (e) { throw _err("relatedcert/bad-input", what + " must be a DER-encoded X.509 certificate", e); }
}

/**
 * @primitive pki.relatedCert.certificateHash
 * @signature pki.relatedCert.certificateHash(certificate, digestAlgorithm?) -> { hashAlgorithm, hashValue }
 * @since 0.8.42
 * @status stable
 * @spec RFC 9763 sec. 4.1
 * @defends related-certificate-substitution (CWE-347)
 * @related pki.relatedCert.matchesCertificate, pki.x509.sign
 *
 * The `RelatedCertificate` value naming a certificate: the digest of the whole certificate, with the
 * algorithm that produced it. RFC 9763 sec. 4.1 hashes "the entire related certificate", so the input
 * is the certificate's full DER rather than its `tbsCertificate`.
 *
 * With no `digestAlgorithm`, the algorithm is derived the way sec. 4.1 directs: "If there is a hash
 * algorithm explicitly indicated by the related certificate's signature OID (e.g.,
 * ecdsa-with-SHA512), that hash algorithm SHOULD also be used for this extension." A certificate
 * whose signature OID indicates no hash, such as one signed with Ed25519 or ML-DSA, leaves that
 * derivation without an answer and throws `relatedcert/no-digest`; name the algorithm to resolve it.
 *
 * `sha256`, `sha384`, `sha512`, `sha3-256` and `sha3-512` are accepted. `sha1` is refused, including
 * when it is what the certificate's own signature OID indicates.
 *
 * @example
 *   var kp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var spki = await pki.key.export(kp.publicKey, { format: "der" });
 *   var related = await pki.x509.sign({ subject: "CN=Held", subjectPublicKey: spki, serialNumber: 42n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z") }, { key: kp.privateKey });
 *   pki.relatedCert.certificateHash(related).hashAlgorithm;          // -> "sha256", from this certificate's signature OID
 *   pki.relatedCert.certificateHash(related, "sha512").hashValue.length;   // -> 64
 */
function certificateHash(certificate, digestAlgorithm) {
  var c = _parseCert(certificate, "the related certificate");
  var name;
  if (digestAlgorithm === undefined || digestAlgorithm === null) {
    var indicated = SIG_OID_DIGEST[c.parsed.signatureAlgorithm.oid];
    if (indicated === undefined) {
      throw _err("relatedcert/no-digest",
        "the related certificate's signature algorithm (" + (c.parsed.signatureAlgorithm.name || c.parsed.signatureAlgorithm.oid) +
        ") indicates no hash algorithm, so name one (RFC 9763 sec. 4.1)");
    }
    if (!ALLOWED_DIGESTS[indicated]) {
      throw _err("relatedcert/bad-input",
        "the related certificate's signature algorithm indicates " + indicated +
        ", which is not used to bind a certificate identity here, so name a digest algorithm");
    }
    name = indicated;
  } else {
    name = _digestName(digestAlgorithm, "digestAlgorithm");
  }
  return { hashAlgorithm: name, hashValue: guard.crypto.digest(name, c.der) };
}

/** @internal A digest value with the algorithm that produced it, held to the set this module acts on
 *  and to that algorithm's output length. Three callers read a value this way: the extension builder
 *  before emitting one, the comparison below before trusting one, and the parser through the length
 *  table they share, so a length rule cannot hold on one side of the round trip and not the other. */
function digestValue(hashAlgorithm, hashValue) {
  var name = _digestName(hashAlgorithm, "the hashAlgorithm");
  var value = guard.bytes.snapshot(hashValue, _err, "relatedcert/bad-input", "the hashValue");
  var want = DIGEST_LENGTHS[name];
  if (want !== undefined && value.length !== want) {
    throw _err("relatedcert/bad-input", "the hashValue is " + value.length + " octets, and " + name + " produces " + want);
  }
  if (value.length === 0) throw _err("relatedcert/bad-input", "the hashValue must not be empty");
  return { hashAlgorithm: name, hashValue: value };
}

/**
 * @primitive pki.relatedCert.matchesCertificate
 * @signature pki.relatedCert.matchesCertificate(relatedCertificate, certificate) -> boolean
 * @since 0.8.42
 * @status stable
 * @spec RFC 9763 sec. 4.1
 * @defends related-certificate-substitution (CWE-347)
 * @related pki.relatedCert.certificateHash, pki.schema.x509.parse
 *
 * Whether a parsed `relatedCertificate` extension value names the given certificate. Takes the value
 * a `pki.schema.x509.parse` extension carries, `{ hashAlgorithm, hashValue }`, and the candidate
 * certificate's DER, recomputes the digest under the algorithm the value names, and compares in
 * constant time.
 *
 * A value this build cannot act on throws. A `false` from an algorithm nobody computed says the
 * certificate does not match, when what happened is that no comparison was made. Only a digest that
 * was computed and disagreed returns `false`.
 *
 * @example
 *   var kp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var spki = await pki.key.export(kp.publicKey, { format: "der" });
 *   var related = await pki.x509.sign({ subject: "CN=Held", subjectPublicKey: spki, serialNumber: 42n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z") }, { key: kp.privateKey });
 *   var leaf = await pki.x509.sign({ subject: "CN=New Key", subjectPublicKey: spki, serialNumber: 43n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"),
 *     extensions: { relatedCertificate: { relatedCertificate: related } } }, { key: kp.privateKey });
 *   var ext = pki.schema.x509.parse(leaf).extensions
 *     .filter(function (e) { return e.oid === pki.oid.byName("relatedCertificate"); })[0];
 *   pki.relatedCert.matchesCertificate(pki.schema.x509.decodeExtension(ext).decoded, related);   // -> true
 */
function matchesCertificate(relatedCertificate, certificate) {
  if (relatedCertificate === null || typeof relatedCertificate !== "object") {
    throw _err("relatedcert/bad-input", "the relatedCertificate value must be an object { hashAlgorithm, hashValue }");
  }
  var v = digestValue(relatedCertificate.hashAlgorithm, relatedCertificate.hashValue);
  var c = _parseCert(certificate, "the candidate certificate");
  /** @internal Through the captured digest. Capturing `createHash` alone leaves `update` and `digest`
   *  on the live hash prototype, so a replacement decided what the comparison was OVER: measured with
   *  two certificates differing only in serial number, an `update` that hashed the first turned the
   *  second's verdict from false to true, which is the binding this extension exists to make. */
  return guard.crypto.constantTimeEqual(guard.crypto.digest(v.hashAlgorithm, c.der), v.hashValue);
}

/** @internal The AlgorithmIdentifier the proof's key signs with, resolved through the same scheme
 *  resolver every signing verb here uses, so the identifier a proof is verified under is the one this
 *  toolkit would have emitted for that key. Assembling it by hand from a key OID and a digest name is
 *  what produced an identifier with the parameters field ABSENT, which RFC 4055 sec. 5 requires to be
 *  an explicit NULL for the RSA algorithms; every RSA proof then failed to verify.
 *
 *  The KEY decides the algorithm, not the certificate's signatureAlgorithm: that field names what the
 *  ISSUER signed the certificate with, whose key may be of another kind entirely, while the proof is
 *  made by the SUBJECT's key. The DIGEST still comes from that field, which is the relation sec. 4.1
 *  names. */
function _proofAlgorithm(parsed, digestAlgorithm) {
  var keyName = parsed.subjectPublicKeyInfo.algorithm.name || parsed.subjectPublicKeyInfo.algorithm.oid;
  var digest = null;
  if (digestAlgorithm === undefined || digestAlgorithm === null) {
    var indicated = SIG_OID_DIGEST[parsed.signatureAlgorithm.oid];
    if (indicated !== undefined) {
      digest = _digestName(indicated, "the digest the related certificate's signature algorithm indicates");
    }
  } else {
    digest = _digestName(digestAlgorithm, "digestAlgorithm");
  }

  var certLike = { subjectPublicKeyInfo: parsed.subjectPublicKeyInfo };
  var takesADigest;
  try { takesADigest = _digestChangesTheAlgorithm(certLike); }
  catch (e) {
    throw _err("relatedcert/unsupported-algorithm",
      "a proof made by a " + keyName + " key is not resolved here, so name signatureAlgorithm as a DER AlgorithmIdentifier",
      e);
  }
  if (!takesADigest) {
    /** @internal A key that admits no choice comes in two kinds, and they answer a named digest
     *  differently. A key whose algorithm carries its own digest (EdDSA, ML-DSA) can be handed no digest at
     *  all, so naming one is a request that would be dropped. A key whose SPKI PINS a digest has exactly
     *  one, and naming THAT one agrees with the key: refusing it would reject the only digest the key can
     *  be used with, while naming a different one is the real disagreement and is named as such. */
    var pinnedDigest = _pinnedDigestName(certLike);
    if (digestAlgorithm !== undefined && digestAlgorithm !== null) {
      if (pinnedDigest === null) {
        throw _err("relatedcert/bad-input",
          "a " + keyName + " key admits no digest choice, so digestAlgorithm must be omitted");
      }
      if (digest !== pinnedDigest) {
        throw _err("relatedcert/bad-input", "the " + keyName + " key is restricted to " + pinnedDigest +
          ", so digestAlgorithm must be that or omitted, not " + digest);
      }
    }
    return _readAlgorithmIdentifier(
      _resolveScheme(certLike, pinnedDigest === null ? PROBE_DIGESTS[0] : pinnedDigest).sigAlgId, keyName);
  }
  if (digest === null) {
    throw _err("relatedcert/no-digest",
      "the related certificate's signature algorithm indicates no hash algorithm, so name digestAlgorithm (RFC 9763 sec. 4.1)");
  }
  var scheme;
  try { scheme = _resolveScheme(certLike, digest); }
  catch (e) {
    throw _err("relatedcert/unsupported-algorithm",
      "no signature algorithm pairs a " + keyName + " key with " + digest, e);
  }
  return _readAlgorithmIdentifier(scheme.sigAlgId, keyName);
}

function _schemeErr(kind, message, cause) { return new RelatedCertError("relatedcert/" + kind, message, cause); }

/** @internal The resolver hands back the AlgorithmIdentifier as DER, and the seam reads a decoded
 *  record, so it is read through the shared sub-schema: the parameters field then reaches the engine as
 *  the resolver wrote it. */
function _readAlgorithmIdentifier(der, keyName) {
  try { return schema.walk(ALGORITHM_IDENTIFIER, asn1.decode(der), NS).result; }
  catch (e) {
    throw _err("relatedcert/unsupported-algorithm",
      "the signature algorithm resolved for a " + keyName + " key is not a readable AlgorithmIdentifier", e);
  }
}

/** @internal An AlgorithmIdentifier the caller named as DER, read through the shared sub-schema so it
 *  is held to the same shape a parsed one is. */
function _namedAlgorithm(value) {
  var der = guard.bytes.snapshot(value, _err, "relatedcert/bad-input", "signatureAlgorithm");
  try { return schema.walk(ALGORITHM_IDENTIFIER, asn1.decode(der), NS).result; }
  catch (e) { throw _err("relatedcert/bad-input", "signatureAlgorithm must be a DER-encoded AlgorithmIdentifier", e); }
}

/**
 * @primitive pki.relatedCert.verifyRequest
 * @signature pki.relatedCert.verifyRequest(requesterCertificate, certificate, opts?) -> Promise<boolean>
 * @since 0.8.42
 * @status stable
 * @spec RFC 9763 sec. 3.1
 * @defends related-certificate-proof-forgery (CWE-347)
 * @related pki.relatedCert.requestSignedData, pki.schema.csr.parse, pki.path.validate
 *
 * Verify the proof of possession in a `relatedCertRequest` CSR attribute. `requesterCertificate` is
 * the value `pki.schema.csr.parse` carries on that attribute, and `certificate` is the DER of the
 * certificate its `certID` names. Returns `true` when the signature over the bytes
 * `pki.relatedCert.requestSignedData` describes verifies under that certificate's subject key, and
 * `false` when a signature was checked and did not verify.
 *
 * The certificate handed in must be the one `certID` names: an issuer and serial that do not match
 * throw `relatedcert/cert-mismatch`, since verifying a proof against a certificate the request did
 * not name answers a different question than the one asked.
 *
 * The structure carries no algorithm identifier, so one is derived: the key decides the algorithm,
 * resolved through the same resolver `pki.x509.sign` and `pki.csr.sign` use, and the digest comes from
 * the hash the certificate's signature OID indicates, which is the relation sec. 4.1 names for the
 * sibling extension. Every algorithm those verbs sign with is therefore reached, including an
 * RSASSA-PSS key whose parameters are part of its algorithm identifier. `opts.digestAlgorithm` names
 * the digest instead, and a key whose algorithm fixes its own digest, such as an EdDSA or ML-DSA key,
 * refuses that option instead of ignoring it. `opts.signatureAlgorithm` takes a DER
 * `AlgorithmIdentifier` outright. A key that cannot sign, such as an ML-KEM or X25519 key, throws
 * `relatedcert/unsupported-algorithm`.
 *
 * What the proof covers is `certID` and `requestTime` only. `locationInfo` is outside it, so a
 * `true` here does not authenticate where the certificate may be fetched.
 *
 * The signature is read the way every other ASN.1 signature field is, so an ECDSA proof is the DER
 * `SEQUENCE { r, s }` of RFC 5480 sec. 2, not the fixed-width `r || s` a WebCrypto `sign` returns.
 * Handing over the fixed-width form resolves `false` rather than throwing, because a signature that
 * does not decode is a signature that does not verify; the example re-encodes it.
 *
 * `opts.maxAge` is REQUIRED, in seconds. RFC 9763 sec. 3.2 makes the freshness check the certification
 * authority's: it "MUST check that the BinaryTime indicated in the requestTime field is sufficiently
 * fresh", and the same clause leaves the window to local policy, so there is no window this verb could
 * choose for you. Without one a captured attribute copied into a new request for another key verifies
 * forever, the proof covering the certID and the requestTime alone, so a missing policy is
 * `relatedcert/no-freshness-policy` rather than a default. A `requestTime` older than the window, or in the
 * future, is `relatedcert/stale-request`.
 *
 * @opts maxAge  REQUIRED. The seconds a `requestTime` may be old, which RFC 9763 sec. 3.2 leaves to local policy. A whole non-negative integer.
 * @opts at  The instant to judge freshness against, as a `Date`. The current time when omitted; pass one to read a request recorded earlier.
 * @opts digestAlgorithm  The digest for the proof: `"sha256"` / `"sha384"` / `"sha512"` / `"sha3-256"` / `"sha3-512"`. Derived from the certificate's signature OID when omitted, and refused for a key whose algorithm fixes its own digest.
 * @opts signatureAlgorithm  A DER `AlgorithmIdentifier` naming the proof's signature algorithm outright, in place of the derivation.
 *
 * @example
 *   var kp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var spki = await pki.key.export(kp.publicKey, { format: "der" });
 *   var held = await pki.x509.sign({ subject: "CN=Held", subjectPublicKey: spki, serialNumber: 42n,
 *     notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z") }, { key: kp.privateKey });
 *   var parsed = pki.schema.x509.parse(held);
 *   var certID = { issuer: parsed.issuer.bytes, serialNumber: parsed.serialNumber };
 *   var signMe = pki.relatedCert.requestSignedData({ certID: certID, requestTime: 1800000000 });
 *   // An ECDSA proof goes into the BIT STRING as DER SEQUENCE { r, s }. WebCrypto returns the
 *   // fixed-width r || s instead, so it is re-encoded here.
 *   var raw = Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, signMe));
 *   var half = raw.length / 2;
 *   var proof = pki.asn1.build.sequence([
 *     pki.asn1.build.integer(BigInt("0x" + raw.subarray(0, half).toString("hex"))),
 *     pki.asn1.build.integer(BigInt("0x" + raw.subarray(half).toString("hex"))),
 *   ]);
 *   var csr = await pki.csr.sign({ subject: "CN=New Key", subjectPublicKey: spki,
 *     relatedCertRequest: { certID: certID, requestTime: 1800000000,
 *       locationInfo: ["https://certs.example/held.cer"], signature: proof } }, { key: kp.privateKey });
 *   var attr = pki.schema.csr.parse(csr).attributes
 *     .filter(function (a) { return a.type === pki.oid.byName("relatedCertRequest"); })[0];
 *   // The window is the certification authority's policy, so it is named: five minutes here, judged
 *   // against the instant the request was made, which is what a CA reading a recorded request does.
 *   await pki.relatedCert.verifyRequest(attr.relatedCertRequest, held,
 *     { maxAge: 300, at: new Date(1800000060 * 1000) });   // -> true
 */
function verifyRequest(requesterCertificate, certificate, opts) {
  /** @internal Every refusal reaches the caller as a rejection, so a verb that returns a promise never
   *  also throws past it: a caller handling one path and not the other would miss the refusals. */
  return guard.async.deferred(function () { return _verifyRequest(requesterCertificate, certificate, opts); });
}

function _verifyRequest(requesterCertificate, certificate, opts) {
  if (requesterCertificate === null || typeof requesterCertificate !== "object") {
    throw _err("relatedcert/bad-input", "pki.relatedCert.verifyRequest takes the parsed relatedCertRequest attribute value");
  }
  var o = guard.identifier.snapshotOptions(opts, KNOWN_VERIFY_OPTS);
  guard.identifier.assertKnownKeys(opts, KNOWN_VERIFY_OPTS, _err, "relatedcert/bad-input",
    "pki.relatedCert.verifyRequest has an unknown option: ");

  var c = _parseCert(certificate, "the related certificate");
  /** @internal The preimage is rebuilt from the request's own fields, so what is verified is what the
   *  request says, not what the certificate says: a mismatch between the two is reported below, and
   *  hashing the certificate's values would cover it over. */
  var named = _certIdDer(requesterCertificate.certID);
  /** @internal Read ONCE into the value both the freshness check and the preimage use, so a request whose
   *  `requestTime` is an accessor cannot present a fresh instant to the check and a different one to the
   *  bytes the proof is verified over. */
  var requestSecs = _binaryTime(requesterCertificate.requestTime, "requestTime");
  _assertFresh(requestSecs, o);
  var preimage = _bufferConcat([named, b.integer(requestSecs)]);
  /** @internal The IDENTITY check is by name, not by bytes. RFC 9763 sec. 3.2 says the CA "extracts the
   *  IssuerAndSerialNumber from the indicated certificate and compares this value against the
   *  IssuerAndSerialNumber provided in the certID field", and `issuer` is a `Name`, so RFC 5280 sec. 7.1
   *  governs: two encodings of one name are one name. Comparing the DER refused a conforming request, a
   *  certificate holding its issuer CN as a PrintableString against a request naming the same CN as a
   *  UTF8String. The PREIMAGE above is still the request's own bytes, which is what sec. 3.1 says the
   *  signature covers, so only the comparison folds encodings and the signed bytes are untouched.
   *  The comparison is no longer constant-time and does not need to be: an issuer name and a serial
   *  number are both carried in the certificate and in the request, so there is no secret for an early
   *  exit to leak. The constant-time compare remains where it answers about a digest. */
  var namedParts = _certIdParts(named);
  if (namedParts.serialNumber !== c.parsed.serialNumber ||
      !guard.name.dnEqual(namedParts.issuer.rdns, c.parsed.issuer.rdns, _err,
        "relatedcert/cert-mismatch", "the certID issuer")) {
    throw _err("relatedcert/cert-mismatch",
      "the certificate given is not the one certID names (RFC 9763 sec. 3.2)");
  }

  var sigAlg = o.signatureAlgorithm !== undefined && o.signatureAlgorithm !== null
    ? _namedAlgorithm(o.signatureAlgorithm)
    : _proofAlgorithm(c.parsed, o.digestAlgorithm);

  var sig = requesterCertificate.signature;
  /** @internal `bytes` and `unusedBits` are read ONCE each, for the reason given at `certID.issuer`. */
  var sigBytes = sig !== null && typeof sig === "object" && !_isBuffer(sig) ? sig.bytes : undefined;
  if (sigBytes !== undefined) {
    sig = { unusedBits: sig.unusedBits, bytes: guard.bytes.snapshot(sigBytes, _err, "relatedcert/bad-input", "the proof signature") };
  } else {
    sig = { unusedBits: 0, bytes: guard.bytes.snapshot(sig, _err, "relatedcert/bad-input", "the proof signature") };
  }
  if (sig.bytes.length === 0) throw _err("relatedcert/bad-input", "the proof signature must not be empty");

  return _seam.verify(sigAlg, sig, c.parsed.subjectPublicKeyInfo.bytes, preimage);
}

module.exports = {
  requestSignedData: requestSignedData,
  verifyRequest: verifyRequest,
  certificateHash: certificateHash,
  matchesCertificate: matchesCertificate,
  /** @internal Read a digest value the way the comparison reads one; not on the curated surface. */
  digestValue: digestValue,
  setEngine: _seam.setEngine,
};
