// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.webauthn metadata implementation. The operator-facing @module pki.webauthn
// and the @primitive blocks for verifyMetadataBlob / metadataFor / metadataAnchors live in
// lib/webauthn.js, which re-exports these, so the namespace has one documented home.
//
// webauthn-mds -- the FIDO Metadata Service (MDS v3) reader. The BLOB is a JWS whose payload
// lists every registered authenticator model, keyed by AAGUID, with the certificates its
// attestations chain to and the status reports that say whether it is still trusted.
//
// The ordering is the load-bearing part: the signature and its certificate chain are established
// against a CALLER-supplied FIDO root before a single byte of the payload is read, so a hostile
// BLOB never reaches the JSON reader, the entry walk, or any per-entry certificate decode. No
// root is bundled and there is no trust-on-first-use -- an operator supplies the anchor, exactly
// as pki.trust does for a root store. Retrieval is out of scope: the BLOB is caller-supplied
// bytes, so this module never touches a socket.
//
// FIDO Metadata Service v3.0 sec. 3.1 / sec. 3.2, RFC 7515 (JWS).

var frameworkError = require("./framework-error");
var x509 = require("./schema-x509");
var guard = require("./guard-all");
var jose = require("./jose");
var rfc3339 = require("./rfc3339");
var constants = require("./constants");
var pathValidate = require("./path-validate");
var signScheme = require("./sign-scheme");
var edwardsPoint = require("./edwards-point");
var webcrypto = require("./webcrypto");
var nodeCrypto = require("crypto");

var oid = require("./oid");
var pkix = require("./schema-pkix");
var WebauthnError = frameworkError.WebauthnError;
var _KU_NS = pkix.makeNS("webauthn", WebauthnError, oid);
function _err(code, message, cause) { return new WebauthnError(code, message, cause); }
var C = constants.LIMITS;

// Which signature schemes each certificate key type may perform, keyed by the SPKI algorithm the
// x5c leaf carries. Taking the scheme from the token and the key from the chain without checking
// they agree is the JWS algorithm-confusion class, and the relation is not one-to-one: a
// PKCS#1-encoded RSA key can do either RSA scheme, while an id-RSASSA-PSS key is restricted BY ITS
// CERTIFICATE to RSASSA-PSS and must not verify an RS* signature (RFC 4055 sec. 1.2 / 3.1).
//
// The Edwards and ML-DSA rows exist because an X.509 SubjectPublicKeyInfo carries those keys
// perfectly well -- RFC 8410 for Ed25519 / Ed448, RFC 9881 for ML-DSA -- so a JWS algorithm over
// one is a conformant BLOB signature, not a theoretical one. `EdDSA` names a scheme without fixing
// a curve (RFC 8037), so for that scheme the certificate decides which of the two it is; every
// other row's algorithm fixes its own.
var LEAF_SCHEMES_BY_SPKI_ALG = Object.assign(Object.create(null), {
  ecPublicKey: { ECDSA: 1 },
  rsaEncryption: { "RSASSA-PKCS1-v1_5": 1, "RSA-PSS": 1 },
  rsassaPss: { "RSA-PSS": 1 },
  Ed25519: { EdDSA: 1 },
  Ed448: { EdDSA: 1 },
  "id-ml-dsa-44": { "ML-DSA-44": 1 },
  "id-ml-dsa-65": { "ML-DSA-65": 1 },
  "id-ml-dsa-87": { "ML-DSA-87": 1 },
});

// The sign-scheme resolver's faults arrive as a bare kind; they keep webauthn/* codes here so a
// BLOB whose leaf pins a hash this toolkit cannot read fails as a webauthn verdict, not a foreign one.
function _schemeE(kind, message, cause) { return new WebauthnError("webauthn/" + kind, message, cause); }

// The JWS algorithms a metadata BLOB may be signed with, each with the key family it requires and
// the WebCrypto parameters that import an x5c leaf under it and verify with it.
//
// DERIVED, not declared. A second algorithm table maintained beside pki.jose's is how PS256 came
// to verify as an ACME signature and be refused as a metadata BLOB signature: both tables were
// correct on the day they were written and only one of them was extended. Deriving means the
// question "which algorithms does this toolkit accept for a JWS?" has exactly one answer, and a
// row added there reaches here without anybody remembering to copy it.
//
// The derivation is TOTAL over the registry -- every algorithm pki.jose verifies gets a row, and an
// X.509 SubjectPublicKeyInfo can carry a key of every type in it. EC becomes ECDSA over the curve
// the alg fixes; RSA with a salt length becomes RSASSA-PSS (RFC 7518 sec. 3.5) and without one
// RSASSA-PKCS1-v1_5; OKP becomes EdDSA, whose curve the certificate supplies because the algorithm
// does not name one; AKP becomes the ML-DSA parameter set the algorithm itself fixes.
//
// A row's import and verify parameters may therefore depend on the LEAF as well as the alg, which
// is why they are resolved per-verification rather than frozen into the row: EdDSA over an Ed25519
// certificate and EdDSA over an Ed448 certificate are the same JWS algorithm and two different
// WebCrypto algorithms.
//
// Null-prototype: `alg` is attacker-supplied, and an inherited Object member would otherwise
// resolve to a truthy non-row and read as a recognised algorithm.
function _deriveBlobAlgs() {
  var out = Object.create(null);
  jose.sigAlgs().forEach(function (row) {
    if (row.kty === "EC") {
      out[row.alg] = { scheme: "ECDSA", hash: row.hash,
        imp: { name: "ECDSA", namedCurve: row.crv }, ver: { name: "ECDSA", hash: row.hash } };
    } else if (row.kty === "RSA" && row.saltLength) {
      out[row.alg] = { scheme: "RSA-PSS", hash: row.hash,
        imp: { name: "RSA-PSS", hash: row.hash }, ver: { name: "RSA-PSS", saltLength: row.saltLength } };
    } else if (row.kty === "RSA") {
      out[row.alg] = { scheme: "RSASSA-PKCS1-v1_5", hash: row.hash,
        imp: { name: "RSASSA-PKCS1-v1_5", hash: row.hash }, ver: { name: "RSASSA-PKCS1-v1_5" } };
    } else if (row.kty === "OKP") {
      // `fromLeaf` marks a row whose WebCrypto algorithm is the certificate's own key algorithm.
      out[row.alg] = { scheme: "EdDSA", hash: null, fromLeaf: true };
    } else if (row.kty === "AKP") {
      out[row.alg] = { scheme: row.alg, hash: null, imp: { name: row.alg }, ver: { name: row.alg } };
    }
  });
  return out;
}
var BLOB_ALGS = _deriveBlobAlgs();

// The WebCrypto import and verify parameters for one verification. Fixed by the algorithm for every
// scheme that names its own curve or parameter set; taken from the certificate for EdDSA, which
// does not. The leaf has already been checked to permit this row's scheme, so its algorithm name is
// one of the two the scheme covers.
function _blobAlgParams(algRow, leafAlgName) {
  if (!algRow.fromLeaf) return algRow;
  return { scheme: algRow.scheme, hash: null, imp: { name: leafAlgName }, ver: { name: leafAlgName } };
}

// The status values that deny trust (MDS v3.0 sec. 3.1.4). An unknown status is IGNORED for the
// gate and surfaced raw -- the specification requires that a verifier not fail on a status it does
// not recognise -- unless the caller opts into refusing them.
var DISQUALIFYING = Object.assign(Object.create(null), {
  REVOKED: 1, ATTESTATION_KEY_COMPROMISE: 1, USER_KEY_REMOTE_COMPROMISE: 1,
  USER_KEY_PHYSICAL_COMPROMISE: 1, USER_VERIFICATION_BYPASS: 1,
});

// The statuses whose optional `certificate` field NARROWS the report to the certificate it names
// (MDS v3.0 sec. 3.1.3). Only a compromised attestation key is about one certificate; every other
// disqualifying status is about the model, and a certificate attached to one of those is a
// nonconforming field rather than a narrower scope.
var CERT_SCOPED_STATUS = Object.assign(Object.create(null), { ATTESTATION_KEY_COMPROMISE: 1 });

var _BLOB_OPTS = Object.assign(Object.create(null), {
  rootCertificates: 1, time: 1, previousNo: 1, requireRollbackCheck: 1, allowStale: 1,
  statusPolicy: 1, rejectUnknownStatus: 1,
});

function _isPlainObject(v) { return !!v && typeof v === "object" && !Array.isArray(v); }

// The results this module actually produced. Membership is the PROVENANCE check: a metadata object
// is only allowed to decide trust if verifyMetadataBlob made it. Recognising it by shape instead
// would accept anything carrying the right property names -- including a catalogue deserialized
// from a cache, where nothing establishes that the signature and chain were ever checked, and an
// attacker who can write that cache chooses which roots an authenticator is allowed to chain to.
// A WeakSet keys on object IDENTITY, which no serialization survives, so a round-tripped catalogue
// is refused and the caller re-verifies -- which the freshness rule wants of them anyway. It also
// holds no strong reference, so a discarded result is still collectable.
var _verifiedResults = new WeakSet();
function isVerifiedResult(v) { return _isPlainObject(v) && _verifiedResults.has(v); }

// Which catalogue each entry came OUT of. Knowing that a supplied catalogue is verified says
// nothing about whether the entry being judged belongs to it, and a process may hold several: pair
// an entry from catalogue A with catalogue B and B's statusPolicy and freshness decide about A's
// status reports. B reading `latest-by-date` can then hand back anchors that A, reading `any`,
// records as revoked -- and a stale A can be judged current because B is. Keyed on object identity,
// for the same reason the provenance set is, and holding no strong reference to either side.
var _entryOrigin = new WeakMap();
function _isEntryOf(entry, metadata) { return _entryOrigin.get(entry) === metadata; }

// Provenance alone is not enough: the verified catalogue is handed to the caller, and anything
// holding a reference could rewrite `allowStale`, a status report, or an entry's registered roots
// and the object would still pass the identity check. Freezing it means the catalogue that decides
// a later verification is the one the signature covered, field for field. Depth-bounded and
// cycle-safe via the frozen check; typed arrays are skipped because Object.freeze rejects a view
// with elements, and the payload is JSON-derived so it holds none anyway.
function _deepFreeze(v, depth) {
  if (!v || typeof v !== "object" || Object.isFrozen(v) || ArrayBuffer.isView(v)) return v;
  if (depth > C.JSON_MAX_DEPTH) return v;
  Object.freeze(v);
  Object.keys(v).forEach(function (k) { _deepFreeze(v[k], depth + 1); });
  return v;
}
var AAGUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// "This authenticator declares no model identity" -- the AAGUID a U2F authenticator carries, since
// U2F has no such concept. It is a sentinel, never a lookup key, and lives in one place so the
// lookup and the dispatch that decides WHICH key space applies cannot disagree about it.
var ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";
// The JWS header parameters this reader understands (RFC 7515 sec. 4.1). Used only to tell a
// standard name from an extension name when checking `crit`.
var UNDERSTOOD_HEADER = Object.assign(Object.create(null), {
  alg: 1, typ: 1, cty: 1, crit: 1, jku: 1, jwk: 1, kid: 1, x5u: 1, x5c: 1, x5t: 1, "x5t#S256": 1,
});

// The BLOB's signing certificate must be allowed to sign. RFC 5280 sec. 4.2.1.3 numbers
// digitalSignature bit 0 of the keyUsage BIT STRING; an absent extension places no restriction.
// Through the shared reader, which applies the NamedBitList rules a local bit test does not: DER
// drops trailing zero bits (X.690 sec. 11.2.2) and sec. 4.2.1.3 requires at least one bit set, so
// reading the bits here would let a certificate the rest of the toolkit calls malformed sign a BLOB.
function _assertLeafSigns(leaf) {
  var ku = pkix.keyUsageOf(_KU_NS, leaf, _err, "webauthn/bad-att-cert", "metadata BLOB x5c leaf");
  if (ku && ku.digitalSignature !== true) {
    throw _err("webauthn/bad-att-cert", "the metadata BLOB x5c leaf keyUsage does not assert digitalSignature, so it may not sign the BLOB (RFC 5280 sec. 4.2.1.3)");
  }
}

// Is this certificate the anchor itself? RFC 5280 sec. 6.1.1 defines a trust anchor as a name and a
// public key, so that pair -- not the issuer field, and not the certificate's bytes -- is what
// decides. The DN comparison is the canonical one, so two spellings of one name still match.
function _isAnchorItself(cert, anchor) {
  return guard.name.dnEqual(cert.subject.rdns, anchor.subject.rdns, _err, "webauthn/bad-att-cert", "the anchor subject") &&
    cert.subjectPublicKeyInfo.bytes.equals(anchor.subjectPublicKeyInfo.bytes);
}

// A parsed anchor certificate, whichever shape the caller supplied it in.
//
// An already-parsed certificate is taken as-is rather than re-encoded and re-parsed, but the
// recognition test names every field the anchor is later READ for -- the subject name, the public
// key bytes, and the signature algorithm OID. Recognising an object on a looser test lets something
// that is merely certificate-SHAPED through: a parsed CSR satisfies "has a subject and an SPKI", and
// a hand-built object literal satisfies it too and then raises a raw TypeError from deep inside the
// path validator, which is an untyped throw escaping a public verb.
function _asCert(v, label) {
  // Through the shared certificate door: these become the anchors a metadata BLOB's signer chain is
  // judged against, and an anchor's identity is its subject and its key. A caller-assembled object
  // could carry a real root's subject beside a substituted key -- every field well-formed, nothing
  // for a shape test to catch -- so the object is re-derived from the bytes its parser read instead.
  // Bytes in any form (a Buffer, a typed-array view, a DataView, an ArrayBuffer) are parsed here;
  // refusing one of those would make the accepted set depend on how the caller received the file.
  return guard.parsed.acceptDerived(v, "certificate", function (bytes) {
    try { return x509.parse(bytes); }
    catch (e) { throw _err("webauthn/bad-input", label + " is not a decodable certificate", e); }
  }, _err, "webauthn/bad-input", label);
}

// Verify a FIDO Metadata Service BLOB and return its entries indexed for lookup. `blob` is the
// BLOB as caller-supplied bytes or a string -- this module never fetches it. The signature is
// checked under the certificate in the BLOB's own header, that chain is validated to one of
// `opts.rootCertificates`, and only then is the payload parsed: a BLOB that does not verify never
// reaches the JSON reader. `no` must exceed a supplied `previousNo` (the rollback check) and
// `nextUpdate` must not have passed (the freshness check), both fail-closed. No FIDO root ships
// with this toolkit: which metadata authority to trust is the operator's choice, and a verifier
// that bundled its own would be deciding trust on the caller's behalf.
function verifyMetadataBlob(blob, opts) {
  return guard.async.deferred(function () { return _verifyMetadataBlob(blob, opts); });
}

function _verifyMetadataBlob(blob, opts) {
  opts = opts || {};
  if (!_isPlainObject(opts)) throw _err("webauthn/bad-input", "opts must be an object");
  guard.identifier.assertKnownKeys(opts, _BLOB_OPTS, _err, "webauthn/bad-input", "opts has an unknown key ");
  var roots = opts.rootCertificates;
  if (!Array.isArray(roots) || roots.length === 0) {
    throw _err("webauthn/metadata-no-root", "verifying a metadata BLOB requires opts.rootCertificates -- the FIDO root(s) to anchor it to; this library bundles none");
  }
  if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");
  var at = opts.time === undefined ? new Date() : opts.time;
  if (opts.previousNo !== undefined && (!Number.isSafeInteger(opts.previousNo) || opts.previousNo < 0)) {
    throw _err("webauthn/bad-input", "opts.previousNo must be a non-negative safe integer");
  }
  // The boolean options are checked for TYPE, not merely compared against true. A caller who wrote
  // `rejectUnknownStatus: "true"` from a config file is asking for the stricter behaviour; comparing
  // against `true` silently records the policy as off and the authenticator carrying an unrecognised
  // status is then accepted -- the fail-open the option exists to prevent.
  ["requireRollbackCheck", "allowStale", "rejectUnknownStatus"].forEach(function (k) {
    if (opts[k] !== undefined && typeof opts[k] !== "boolean") {
      throw _err("webauthn/bad-input", "opts." + k + " must be a boolean");
    }
  });
  if (opts.statusPolicy !== undefined && typeof opts.statusPolicy !== "function" &&
      opts.statusPolicy !== "any" && opts.statusPolicy !== "latest-by-date") {
    throw _err("webauthn/bad-input", "opts.statusPolicy must be \"any\", \"latest-by-date\", or a function");
  }
  if (opts.requireRollbackCheck === true && opts.previousNo === undefined) {
    throw _err("webauthn/metadata-no-baseline", "opts.requireRollbackCheck was set without opts.previousNo, so there is no baseline to compare against");
  }
  var anchors = roots.map(function (r, i) { return _asCert(r, "opts.rootCertificates[" + i + "]"); });

  // Cap BEFORE the copy, not after it. Measuring the CONVERTED buffer would mean an oversized input
  // is fully materialized in order to discover it should have been refused -- the allocation the
  // ceiling exists to prevent, performed on the way to reporting that it was too large. A string's
  // length is its character count and a BLOB is ASCII base64url + dots, so it bounds the byte count.
  // A byte input is re-viewed through the shared guard, which is where the detached-backing-buffer
  // case is handled once, rather than re-derived here.
  // Every byte form, not only the two a Buffer-shaped API thinks of. A BLOB is retrieved over the
  // network, and the ordinary way to hold a fetched body is an ArrayBuffer -- so the form an
  // operator most naturally arrives with was the one form this refused. `byteLength` is declared by
  // an ArrayBuffer and by every view over one, so the ceiling below still bites before any copy.
  var raw = (ArrayBuffer.isView(blob) || blob instanceof ArrayBuffer)
    ? guard.bytes.source(blob, WebauthnError, "webauthn/bad-input", "the metadata BLOB") : null;
  // A string's `.length` counts UTF-16 code units, not the UTF-8 bytes the conversion produces, so
  // measuring it would let a string of multi-byte characters sit under the ceiling and then expand
  // several-fold past it during the copy -- the allocation the ceiling exists to prevent.
  // Buffer.byteLength computes the encoded size WITHOUT producing the buffer, so the bound still
  // bites before anything is materialized. (A conforming BLOB is base64url and dots, hence ASCII,
  // where the two counts agree; a non-ASCII one is not a JWS at all and is refused on size or on
  // shape immediately after.)
  var declaredLength = raw ? raw.length : (typeof blob === "string" ? Buffer.byteLength(blob, "utf8") : null);
  if (declaredLength !== null && declaredLength > C.MDS_BLOB_MAX_BYTES) {
    throw _err("webauthn/too-large", "the metadata BLOB is " + declaredLength + " bytes, above the " + C.MDS_BLOB_MAX_BYTES + "-byte ceiling");
  }
  if (!raw && typeof blob !== "string") {
    throw _err("webauthn/bad-input", "the metadata BLOB must be bytes or a string");
  }
  var bytes = raw || Buffer.from(blob, "utf8");
  if (bytes.length > C.MDS_BLOB_MAX_BYTES) {
    throw _err("webauthn/too-large", "the metadata BLOB is " + bytes.length + " bytes, above the " + C.MDS_BLOB_MAX_BYTES + "-byte ceiling");
  }
  var segs = bytes.toString("utf8").split(".");
  if (segs.length !== 3) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB is not a three-part JWS compact serialization (RFC 7515 sec. 3.1)");
  // The header's ceiling has to bite on the ENCODED segment, before it is decoded. Checking it
  // afterwards means the decode has already allocated the very buffer the ceiling exists to bound,
  // and does so for input nothing has authenticated yet. base64url expands 4 characters to 3 bytes,
  // so the encoded length bounds the decoded one.
  if (segs[0].length > Math.ceil(C.MDS_BLOB_HEADER_MAX_BYTES / 3) * 4) {
    throw _err("webauthn/too-large", "the metadata BLOB protected header is above the " + C.MDS_BLOB_HEADER_MAX_BYTES + "-byte ceiling");
  }
  // The signature is bounded on the same principle and for the same reason: it is read before
  // anything is authenticated, and every algorithm here has a tightly bounded signature size, so a
  // segment consuming the whole envelope allowance is not a signature -- it is a request to
  // allocate megabytes and hand them to the verifier without possessing any key.
  if (segs[2].length > Math.ceil(C.MDS_BLOB_SIG_MAX_BYTES / 3) * 4) {
    throw _err("webauthn/too-large", "the metadata BLOB signature is above the " + C.MDS_BLOB_SIG_MAX_BYTES + "-byte ceiling");
  }
  var header, sig;
  try {
    // The header goes through the SAME bounded reader as the payload -- a duplicate `alg` or `x5c`
    // must not be resolvable to whichever copy a permissive parser happens to keep.
    header = guard.json.parse(Buffer.from(jose.base64url.decode(segs[0])), _err, {
      // The header is read BEFORE anything is authenticated, so its ceiling is the header's own,
      // not the whole BLOB's: a JWS protected header is a few hundred bytes, and giving this reader
      // the 32 MiB envelope cap would let unauthenticated bytes buy an unbounded multiple of that
      // in heap ahead of the signature check. The payload's reader keeps the envelope cap, which is
      // sound because nothing reaches it until the signature and chain hold.
      maxBytes: C.MDS_BLOB_HEADER_MAX_BYTES, maxDepth: C.JSON_MAX_DEPTH,
      tooLarge: "webauthn/too-large", badJson: "webauthn/bad-metadata-blob",
      // Every code the guard can raise is named. An omitted one falls back to the framework default
      // and the module's own defences -- duplicate-member smuggling, the depth cap -- surface under
      // a generic code no webauthn/* consumer can switch on.
      tooDeep: "webauthn/bad-metadata-blob", duplicateMember: "webauthn/bad-metadata-blob",
      badInput: "webauthn/bad-metadata-blob", label: "the metadata BLOB header",
    });
    sig = Buffer.from(jose.base64url.decode(segs[2]));
  } catch (e) {
    if (e instanceof WebauthnError) throw e;
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header or signature is not decodable", e);
  }
  if (!_isPlainObject(header)) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header must be a JSON object");
  // An x5u names a certificate chain to be FETCHED. This verifier performs no network retrieval, so
  // it cannot establish that chain and must not pretend the BLOB is anchored.
  if (header.x5u !== undefined) {
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header carries x5u, which names a chain to fetch; supply a BLOB with an inline x5c instead");
  }
  // RFC 7515 sec. 4.1.11: `crit` lists header parameters the recipient MUST understand and process,
  // and a JWS naming one this implementation does not is invalid. Ignoring it is the same fault as
  // ignoring x5u, one parameter over: the producer said "refuse this unless you handle it" and a
  // reader that skips the list accepts a token on terms it never met. Nothing here processes an
  // extension parameter, so any name is unprocessed -- including a standard name, which sec. 4.1.11
  // forbids listing at all.
  if (Object.prototype.hasOwnProperty.call(header, "crit")) {
    var crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0) {
      throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit must be a non-empty array (RFC 7515 sec. 4.1.11)");
    }
    var critSeen = Object.create(null);
    for (var ci = 0; ci < crit.length; ci++) {
      var critName = crit[ci];
      if (typeof critName !== "string") throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit entries must be strings");
      if (critSeen[critName]) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit repeats " + JSON.stringify(critName));
      critSeen[critName] = 1;
      if (UNDERSTOOD_HEADER[critName]) {
        throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit must not name the standard header parameter " + JSON.stringify(critName) + " (RFC 7515 sec. 4.1.11)");
      }
      throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header names critical header parameter " + JSON.stringify(critName) + ", which this reader does not process");
    }
  }
  var algRow = typeof header.alg === "string" ? BLOB_ALGS[header.alg] : undefined;
  if (!algRow) throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + JSON.stringify(header.alg) + " is not a supported JWS signature algorithm");
  if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header carries no x5c certificate chain (RFC 7515 sec. 4.1.6)");
  }
  if (header.x5c.length > C.WEBAUTHN_X5C_MAX_CERTS) {
    throw _err("webauthn/too-large", "the metadata BLOB x5c carries " + header.x5c.length + " certificates, above the " + C.WEBAUTHN_X5C_MAX_CERTS + " this library will parse");
  }
  var chain = header.x5c.map(function (entry, i) {
    if (typeof entry !== "string") throw _err("webauthn/bad-metadata-blob", "the metadata BLOB x5c entry " + i + " is not a string");
    var der;
    try { der = guard.encoding.base64(entry, C.MDS_BLOB_MAX_BYTES, _err, "webauthn/bad-metadata-blob", "a metadata BLOB x5c entry"); }
    catch (e) { throw _err("webauthn/bad-metadata-blob", "the metadata BLOB x5c entry " + i + " is not canonical base64", e); }
    try { return x509.parse(der); }
    catch (e) { throw _err("webauthn/bad-att-cert", "the metadata BLOB x5c entry " + i + " is not a decodable certificate", e); }
  });
  var leaf = chain[0];
  // RFC 5280 sec. 4.2.1.3: a certificate that carries a keyUsage extension may only be used for the
  // purposes it asserts. Verifying the BLOB signature with a leaf whose keyUsage omits
  // digitalSignature grants metadata-signing authority to a certificate that explicitly excludes it
  // -- and the path validation that follows checks the CHAIN, not the target's application-level
  // usage, so nothing else catches it. An absent keyUsage places no restriction, per that section.
  _assertLeafSigns(leaf);
  // The alg names a signature scheme; the leaf key must be permitted to perform it.
  var leafAlg = (leaf.subjectPublicKeyInfo.algorithm || {}).name;
  var leafSchemes = typeof leafAlg === "string" ? LEAF_SCHEMES_BY_SPKI_ALG[leafAlg] : undefined;
  if (!leafSchemes || !leafSchemes[algRow.scheme]) {
    throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + header.alg + " does not match the x5c leaf key type " + JSON.stringify(leafAlg));
  }
  // An id-RSASSA-PSS certificate MAY narrow the key further, to one hash (RFC 4055 sec. 1.2). The
  // restriction is the certificate's, so it outranks the alg: a key issued for SHA-256 must not
  // verify a PS512 signature just because the header asked for one.
  if (leafAlg === "rsassaPss") {
    var pinnedHash = signScheme.pssSpkiPinnedHash(leaf, _schemeE);
    if (pinnedHash && pinnedHash !== algRow.hash) {
      throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + header.alg + " uses " + algRow.hash + ", but the x5c leaf key is restricted to " + pinnedHash);
    }
  }

  // An Edwards leaf key is validated on-curve and full-order BEFORE it is imported. The identity
  // point and the other low-order points are accepted by the platform and verify a trivial
  // signature over ANY message, so a leaf carrying one authenticates whatever payload it is shown.
  // Chaining to the caller's FIDO root is not protection here: the point is malformed, not
  // unissued, and the certificate that carries it can be perfectly well signed. This is the same
  // gate every other Edwards key in the toolkit passes -- the attestation path, CMS, the path
  // validator, sigstore, JOSE -- and a new verification route skipping it is how one key type comes
  // to be checked everywhere except the newest door.
  if (leafAlg === "Ed25519" || leafAlg === "Ed448") {
    edwardsPoint.validateSpki(leaf.subjectPublicKeyInfo.bytes, leafAlg === "Ed25519" ? 6 : 7,
      WebauthnError, "webauthn/bad-att-cert");
  }
  var params = _blobAlgParams(algRow, leafAlg);
  var signingInput = Buffer.from(segs[0] + "." + segs[1], "ascii");
  return webcrypto.webcrypto.subtle.importKey("spki", leaf.subjectPublicKeyInfo.bytes, params.imp, false, ["verify"])
    .then(function (key) {
      // The VERIFY is wrapped as well as the import. A rejection handler attached to the import
      // alone leaves anything the verify itself rejects with -- a certificate whose RSASSA-PSS
      // parameters demand a longer salt than the algorithm supplies imports cleanly and then fails
      // inside OpenSSL -- to escape as a raw platform Error, out of a verb whose whole contract is
      // that every failure is a typed webauthn/* verdict.
      return webcrypto.webcrypto.subtle.verify(params.ver, key, sig, signingInput)
        .catch(function (e) { throw _err("webauthn/verify-error", "the metadata BLOB signature could not be evaluated under its x5c leaf key", e); });
    }, function (e) { throw _err("webauthn/unsupported-algorithm", "the metadata BLOB x5c leaf key could not be imported for " + header.alg, e); })
    .then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the metadata BLOB signature does not verify under its x5c leaf key");
      return _chainToAnchor(chain, anchors, at);
    })
    .then(function () {
      // ONLY NOW is the payload read. Everything above establishes that these bytes came from the
      // holder of a key the caller anchored; parsing before that would expose the JSON reader, the
      // entry walk and every per-entry decode to bytes nobody vouched for.
      return _parsePayload(segs[1], at, opts);
    });
}

// The x5c chain must validate to one of the caller's anchors. Every anchor is tried because an
// operator may hold several across a rotation; the last path verdict is threaded as the cause so a
// caller can see WHY it did not chain rather than only that it did not.
//
// `what` and `code` name the caller's subject and its own refusal code, so every chain in the
// namespace -- the BLOB's, an attestation's, an android-safetynet service chain -- reaches its
// anchors through THIS walk while keeping the verdict its own callers already handle. A second copy
// of the walk is not merely duplication: the anchor-stripping rule is subtle (a terminal
// certificate that IS the anchor is identified by subject name AND public key, which is what
// recognises a cross-signed root), and a copy that got it slightly differently would refuse a valid
// chain in one place and accept a self-validated one in another.
function _chainToAnchor(chain, anchors, at, what, code) {
  var subject = what || "metadata BLOB certificate chain";
  var faultCode = code || "webauthn/metadata-untrusted";
  var ordered = chain.slice().reverse();   // path.validate takes anchor-adjacent first
  var lastFault = null;
  return anchors.reduce(function (p, anchor) {
    return p.then(function (done) {
      if (done) return true;
      // A terminal certificate that IS the anchor is the anchor, not a path element -- validating it
      // against itself would be a different assertion from the one being made. What identifies it is
      // the trust-anchor identity the validator itself uses: the SUBJECT NAME and the PUBLIC KEY. A
      // self-issued test instead of a key comparison misses the cross-signed form of the same root,
      // which carries that identity but was signed by a cross-signing CA -- so it would be left in
      // the path and then fail to verify under the anchor that never issued it, refusing an
      // otherwise valid chain. Matching on name AND key cannot be looser: two certificates naming
      // one subject with one key ARE the same entity for anchoring, whoever signed them.
      var path = ordered.slice();
      var strippedAnchor = false;
      if (path.length && _isAnchorItself(path[0], anchor)) { path = path.slice(1); strippedAnchor = true; }
      // Nothing left to validate. The two ways of getting here are NOT the same, and the difference
      // is the whole verdict. If the anchor itself was the entire chain, then the signature was
      // verified under the anchor's own key -- the identity was established by name AND key, so
      // there is nothing further to chain and it is trusted. If the path was empty for any other
      // reason, a validator has been handed nothing and nothing has been proved, so it refuses and
      // the walk moves on to the next anchor.
      if (path.length === 0) return strippedAnchor;
      return pathValidate.validate(path, {
        time: at,
        // The anchor tuple names the anchor's own KEY -- its SubjectPublicKeyInfo algorithm and that
        // algorithm's parameters -- not the algorithm its issuer used to sign it. The validator
        // carries these forward as the working public key, and a certificate below the anchor may
        // inherit its key parameters from them (the DSA-style parameter-inheritance case), so
        // supplying the signature OID leaves such a key unreconstructable and refuses a valid chain.
        trustAnchor: { name: anchor.subject, publicKey: anchor.subjectPublicKeyInfo.bytes,
          algorithm: anchor.subjectPublicKeyInfo.algorithm.oid,
          parameters: anchor.subjectPublicKeyInfo.algorithm.parameters },
      }).then(function (r) { return !!(r && r.valid); }, function (e) { lastFault = e; return false; });
    });
  }, Promise.resolve(false)).then(function (trusted) {
    if (!trusted) {
      throw _err(faultCode, "the " + subject + " does not validate to any of the roots it must reach", lastFault);
    }
  });
}

// The instant a catalogue stops being current. `nextUpdate` is a DATE, so the BLOB is current
// through the END of that UTC day. One home, because the rule is applied twice -- once when the
// BLOB is verified, and again whenever a verified result is USED -- and two copies would drift.
function _staleAfter(nextUpdate) {
  var d = rfc3339.parseDate(nextUpdate, function (c, m) { return _err("webauthn/bad-metadata-blob", m); },
    "webauthn/bad-metadata-blob", "the metadata BLOB nextUpdate");
  return d.getTime() + constants.TIME.days(1);
}

// A verified result is a plain object the caller may hold for as long as it likes, so its freshness
// has to be re-established every time it DECIDES something -- not only when it was parsed. A
// catalogue fetched before its nextUpdate and reused a month later would otherwise keep authorizing
// an authenticator whose status reports have since revoked it, which is precisely what nextUpdate
// exists to prevent. The caller's original allowStale decision is carried on the result and honoured
// here, so opting out stays opted out rather than silently reappearing at the point of use.
function assertFresh(metadata, at, label) {
  if (!metadata || metadata.allowStale === true || typeof metadata.nextUpdate !== "string") return;
  var atMs = at instanceof Date ? at.getTime() : NaN;
  var limit = _staleAfter(metadata.nextUpdate);
  if (!isFinite(atMs) || !isFinite(limit)) return;
  if (atMs >= limit) {
    throw _err("webauthn/metadata-stale", (label || "the metadata") + " expired after " + metadata.nextUpdate +
      "; re-verify a current BLOB, or pass opts.allowStale when verifying it");
  }
}

function _parsePayload(seg, at, opts) {
  var payload;
  try {
    // The shared bounded JSON reader: byte cap before the UTF-8 decode, depth cap, and a duplicate
    // member rejected at any depth -- so a payload cannot smuggle a second `no` or `entries` past
    // whichever one JSON.parse would have kept.
    payload = guard.json.parse(Buffer.from(jose.base64url.decode(seg)), _err, {
      maxBytes: C.MDS_BLOB_MAX_BYTES, maxDepth: C.JSON_MAX_DEPTH,
      tooLarge: "webauthn/too-large", badJson: "webauthn/bad-metadata-blob",
      tooDeep: "webauthn/bad-metadata-blob", duplicateMember: "webauthn/bad-metadata-blob",
      badInput: "webauthn/bad-metadata-blob", label: "the metadata BLOB payload",
    });
  } catch (e) {
    if (e instanceof WebauthnError) throw e;
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload is not decodable JSON", e);
  }
  if (!_isPlainObject(payload)) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload must be a JSON object");
  if (typeof payload.legalHeader !== "string") throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload must carry a string legalHeader");
  if (!Number.isSafeInteger(payload.no) || payload.no < 0) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload must carry a non-negative integer no");
  // Rollback: a BLOB older than the one already held would reinstate authenticators whose trust was
  // withdrawn since, so it is refused rather than merely reported.
  if (opts.previousNo !== undefined && payload.no <= opts.previousNo) {
    throw _err("webauthn/metadata-rollback", "the metadata BLOB no " + payload.no + " does not exceed the previously held " + opts.previousNo);
  }
  var staleAfter = _staleAfter(payload.nextUpdate);
  var atMs = at.getTime();
  // An unusable comparison instant must not read as "fresh": without this, a NaN date makes every
  // comparison false and the staleness check silently passes.
  //
  // Unreachable as the code stands, and kept deliberately. Both operands are already gated by
  // throwing guards -- `at` by guard.time.assertValid at the entry, `staleAfter` by
  // rfc3339.parseDate above, which refuses a date that does not exist rather than rolling it over --
  // so no caller input reaches here non-finite. It stays because the cost is one comparison and the
  // failure it catches is silent: if either gate is ever relaxed or moved, this is what keeps a NaN
  // from being read as fresh instead of stale.
  if (!isFinite(atMs) || !isFinite(staleAfter)) {
    throw _err("webauthn/bad-input", "the metadata freshness comparison has no usable instant");
  }
  var stale = atMs >= staleAfter;
  if (stale && opts.allowStale !== true) {
    throw _err("webauthn/metadata-stale", "the metadata BLOB expired after " + payload.nextUpdate + "; pass opts.allowStale to accept it anyway");
  }
  if (!Array.isArray(payload.entries)) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload must carry an entries array");
  if (payload.entries.length > C.MDS_MAX_ENTRIES) {
    throw _err("webauthn/too-large", "the metadata BLOB declares " + payload.entries.length + " entries, above the " + C.MDS_MAX_ENTRIES + " ceiling");
  }

  var byAaguid = Object.create(null);
  var byKeyIdentifier = Object.create(null);
  var entries = payload.entries.map(function (e, i) {
    if (!_isPlainObject(e)) throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " is not an object");
    if (!Array.isArray(e.statusReports) || e.statusReports.length === 0) {
      throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " must carry a non-empty statusReports array");
    }
    // Bounded like every other repeated per-entry structure. The status gate walks this array on
    // each verify, so an unbounded one turns a single entry into per-verification work with no
    // ceiling -- the entry count and anchor count are capped for exactly that reason, and leaving
    // one of the three uncapped is the same rule applied to part of the structure.
    if (e.statusReports.length > C.MDS_MAX_STATUS_REPORTS_PER_ENTRY) {
      throw _err("webauthn/too-large", "metadata entry " + i + " declares " + e.statusReports.length +
        " status reports, above the " + C.MDS_MAX_STATUS_REPORTS_PER_ENTRY + " ceiling");
    }
    // sec. 3.1.3 makes `status` REQUIRED on every report. A report that is not an object, or that
    // omits it, is refused HERE rather than skipped by the status gate: the gate reads a missing
    // status as "nothing disqualifying", so a malformed report would be silently read as a clean
    // bill of health for the authenticator whose status it was supposed to carry.
    e.statusReports.forEach(function (r, ri) {
      if (!_isPlainObject(r)) throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " status report " + ri + " is not an object");
      if (typeof r.status !== "string" || !r.status) {
        throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " status report " + ri + " has no status (MDS v3.0 sec. 3.1.3 requires one)");
      }
    });
    var aaguid = null;
    if (e.aaguid !== undefined) {
      if (typeof e.aaguid !== "string" || !AAGUID_RE.test(e.aaguid.toLowerCase())) {
        throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " has a malformed aaguid");
      }
      aaguid = e.aaguid.toLowerCase();
    }
    // A U2F authenticator carries no AAGUID, so the catalogue keys it by the key identifiers of its
    // attestation certificates instead. Without this index such an authenticator matches nothing,
    // and a caller who enabled metadata enforcement would have every U2F registration refused as
    // unlisted -- fail-closed, but on an authenticator the catalogue does in fact describe.
    // sec. 3.1.1 puts attestationCertificateKeyIdentifiers on the ENTRY, as a sibling of
    // metadataStatement -- that is the field the lookup is keyed by, and reading it only from the
    // statement means real U2F entries never populate the index and every catalogued U2F
    // authenticator is refused as unlisted. sec. 3.2 defines the same field on the statement as
    // well, and live entries populate both, so both are read and the union is indexed.
    var st = e.metadataStatement;
    var keyIds = [];
    var seenKeyId = Object.create(null);
    [[e.attestationCertificateKeyIdentifiers, "entry"], [st && st.attestationCertificateKeyIdentifiers, "metadataStatement"]]
      .forEach(function (pair) {
        var list = pair[0];
        if (list === undefined) return;
        if (!Array.isArray(list)) {
          throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " " + pair[1] + " attestationCertificateKeyIdentifiers is not an array");
        }
        if (list.length > C.MDS_MAX_KEY_IDS_PER_ENTRY) {
          throw _err("webauthn/too-large", "metadata entry " + i + " declares " + list.length +
            " attestation certificate key identifiers, above the " + C.MDS_MAX_KEY_IDS_PER_ENTRY + " ceiling");
        }
        list.forEach(function (k) {
          // A SHA-1 key identifier is 40 hex digits (RFC 5280 sec. 4.2.1.2 method 1). Anything else
          // cannot be what a certificate hashes to, so accepting it would add a key that never
          // matches -- an entry that silently cannot be found. sec. 3.1.1 requires lower case; the
          // value is canonicalized rather than refused, so a catalogue that differs only in letter
          // case still resolves instead of denying service for every authenticator it lists.
          if (typeof k !== "string" || !/^[0-9a-fA-F]{40}$/.test(k)) {
            throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " has a malformed attestation certificate key identifier");
          }
          var lower = k.toLowerCase();
          // The entry and its statement legitimately repeat an identifier; that is one entry naming
          // itself twice, not two entries claiming one authenticator, so it is deduplicated here
          // rather than reaching the cross-entry duplicate check below.
          if (!seenKeyId[lower]) { seenKeyId[lower] = 1; keyIds.push(lower); }
        });
      });
    var out = { index: i, aaguid: aaguid, keyIdentifiers: keyIds, statusReports: e.statusReports,
      metadataStatement: st || null, timeOfLastStatusChange: e.timeOfLastStatusChange || null };
    if (aaguid) {
      // A duplicate identifier is refused rather than resolved by position: two entries claiming
      // one authenticator give the lookup a choice the specification does not define.
      if (byAaguid[aaguid]) throw _err("webauthn/duplicate-metadata-entry", "two metadata entries claim aaguid " + aaguid);
      byAaguid[aaguid] = out;
    }
    keyIds.forEach(function (k) {
      if (byKeyIdentifier[k]) throw _err("webauthn/duplicate-metadata-entry", "two metadata entries claim attestation certificate key identifier " + k);
      byKeyIdentifier[k] = out;
    });
    return out;
  });
  // The rollback rule leaves a trace, exactly as the freshness rule does either side of it. It runs
  // only when a caller supplies the sequence number it already holds, so a result that does not say
  // whether it ran cannot be told apart from one where the check was skipped -- and the whole point
  // of the rule is that a caller can show its catalogue never went backwards. `previousNo` is the
  // baseline it was compared against, so the claim is auditable rather than merely asserted.
  var result = { no: payload.no, legalHeader: payload.legalHeader, nextUpdate: payload.nextUpdate,
    stale: stale, allowStale: opts.allowStale === true,
    rollbackChecked: opts.previousNo !== undefined,
    previousNo: opts.previousNo === undefined ? null : opts.previousNo,
    entries: entries, byAaguid: byAaguid, byKeyIdentifier: byKeyIdentifier,
    statusPolicy: opts.statusPolicy || "any", rejectUnknownStatus: opts.rejectUnknownStatus === true };
  // Frozen FIRST, then recorded as verified: the mark means "this exact catalogue passed the
  // signature, chain, rollback and freshness gates", and that claim only holds if the object cannot
  // be edited afterwards. This is the only place a catalogue can have been through those gates.
  _deepFreeze(result, 0);
  _verifiedResults.add(result);
  // Recorded AFTER the freeze, alongside the provenance mark and for the same reason: an entry may
  // only be judged against the catalogue it was read out of.
  entries.forEach(function (e) { _entryOrigin.set(e, result); });
  return result;
}

// The verified metadata entry for an AAGUID, or `null` when the BLOB lists none. `metadata` is a
// `verifyMetadataBlob` result -- never raw bytes, so a lookup cannot be answered from an
// unverified BLOB. The all-zero AAGUID means "no model identity" and never matches.
// It also accepts the identifier a U2F authenticator is keyed by instead -- the key identifier of
// its attestation certificate -- so one verb covers both of the catalogue's key spaces. The two are
// disjoint by shape (a dashed 36-character UUID against 40 hex digits), so the form is DISPATCHED
// ON, never guessed at: anything matching neither is a miss rather than a lookup in whichever table
// happens to answer.
function metadataFor(metadata, identifier) {
  if (!isVerifiedResult(metadata)) throw _err("webauthn/bad-input", "metadataFor expects a verifyMetadataBlob result -- an object that merely resembles one, such as a catalogue restored from a cache, has not been through the signature and chain checks");
  if (typeof identifier !== "string") return null;
  var key = identifier.toLowerCase();
  if (AAGUID_RE.test(key)) {
    if (key === ZERO_AAGUID) return null;
    return metadata.byAaguid[key] || null;
  }
  if (/^[0-9a-f]{40}$/.test(key)) return metadataForKeyIdentifier(metadata, key);
  return null;
}

// The options metadataAnchors recognises. Null-prototype for the same reason every other
// caller-keyed table in this namespace is: a supplied key must not resolve to an inherited member.
var _ANCHOR_OPTS = Object.assign(Object.create(null), { metadata: 1, time: 1, certificate: 1 });

// The attestation root certificates an entry's authenticator chains to, decoded on demand. Decoding
// is deliberately per entry rather than for the whole BLOB: a handful of the certificates in the
// live metadata do not parse under a strict decoder, and decoding everything up front would let one
// vendor's malformed root refuse the entire BLOB for every authenticator in it.
function metadataAnchors(entry, opts) {
  if (!entry || typeof entry !== "object") throw _err("webauthn/bad-input", "metadataAnchors expects a metadata entry");
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) throw _err("webauthn/bad-input", "metadataAnchors opts must be an object");
  guard.identifier.assertKnownKeys(opts, _ANCHOR_OPTS, _err, "webauthn/bad-input", "metadataAnchors opts has an unknown key ");
  // ONE read of the caller's object: the status gate below decides on these values, and a value
  // read twice is a value that can differ between the check and the use.
  opts = Object.assign({}, opts);
  if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");
  // Provenance, the same rule metadataFor applies: only a catalogue this module actually verified
  // may govern which anchors are handed out. Accepting any object carrying a `statusPolicy` would
  // let a caller supply a predicate that denies nothing and defeat the gate on the next line --
  // and the gate's whole purpose is that a disqualified model registers no anchors.
  if (opts.metadata !== undefined) {
    if (!isVerifiedResult(opts.metadata)) {
      throw _err("webauthn/bad-input", "metadataAnchors opts.metadata expects a verifyMetadataBlob result -- an object that merely resembles one has not been through the signature and chain checks");
    }
    // ...and the entry must be one of THAT catalogue's. Verified provenance says the supplied
    // catalogue is real; it does not say this entry came from it, and a process holding two would
    // otherwise judge one catalogue's status reports under the other's policy and freshness.
    if (!_isEntryOf(entry, opts.metadata)) {
      throw _err("webauthn/bad-input", "metadataAnchors was given an entry from a different catalogue than opts.metadata, so the status reports would be judged under a policy and freshness that are not theirs");
    }
  }
  // A model whose status reports deny trust has no anchors to offer. This is the ROUTE an operator
  // follows to anchor an attestation themselves -- metadataFor, then these anchors, then
  // pki.path.validate -- and nothing along it consulted the status reports, so a REVOKED
  // authenticator's registered roots were handed over and the path validated against them. The
  // catalogue's whole purpose is to say which models are still trusted; handing out the roots of
  // one it has disqualified is answering a different question than the caller asked.
  //
  // Judged with the same inputs the attestation path uses, so the two readings cannot diverge: the
  // caller's own statusPolicy when the verified result is supplied, the instant being judged, and
  // the attestation certificate actually presented (so a report naming a single certificate is
  // judged against that one rather than denying every device the entry covers). With none of them,
  // the strictest reading applies -- any disqualifying report, judged now.
  var at = opts.time === undefined ? new Date() : opts.time;
  if (opts.metadata !== undefined) assertFresh(opts.metadata, at, "metadataAnchors");
  if (statusDenied(entry, opts.metadata, opts.certificate, at)) {
    throw _err("webauthn/metadata-status", "the metadata entry for this authenticator carries a disqualifying status report, so it registers no anchors to trust");
  }
  var st = entry.metadataStatement;
  var list = st && Array.isArray(st.attestationRootCertificates) ? st.attestationRootCertificates : [];
  if (list.length > C.MDS_MAX_ANCHORS_PER_ENTRY) {
    throw _err("webauthn/too-large", "metadata entry " + entry.index + " declares " + list.length + " attestation roots, above the " + C.MDS_MAX_ANCHORS_PER_ENTRY + " ceiling");
  }
  return list.map(function (b64, i) {
    var der;
    try { der = guard.encoding.base64(b64, C.MDS_BLOB_MAX_BYTES, _err, "webauthn/bad-metadata-entry", "an attestation root certificate"); }
    catch (e) { throw _err("webauthn/bad-metadata-entry", "metadata entry " + entry.index + " attestation root " + i + " is not canonical base64", e); }
    try { return x509.parse(der); }
    catch (e) { throw _err("webauthn/bad-metadata-entry", "metadata entry " + entry.index + " attestation root " + i + " is not a decodable certificate", e); }
  });
}

// Does this entry's status deny trust? Default: ANY disqualifying report denies, wherever it sits
// in the array. The array is not stated to be chronological, `effectiveDate` is optional, and in
// the live metadata a number of entries are not in date order -- one of them flipping its verdict
// between "last element" and "newest by date", in the direction that matters. A caller who wants
// the by-date reading asks for it.
// A status report may name the single certificate it concerns (MDS v3.0 sec. 3.1.3 `certificate`),
// and a key-compromise report that does so is about THAT attestation key -- not about every
// authenticator the entry covers. A whole batch is often listed under one entry, so ignoring the
// scoping would refuse registrations from devices whose key was never compromised. A report that
// names nothing applies to the entry as a whole, and a report whose named certificate cannot be
// read applies too: an unreadable scope is not a narrower scope.
// Phrased as "does this report demonstrably name a DIFFERENT certificate", so the only way to
// escape a disqualifying report is to PROVE it is about someone else. Every uncertain path returns
// false and the report keeps applying: a scope that cannot be read is not a narrower scope.
function _reportNamesOtherCert(report, leaf) {
  if (typeof report.certificate !== "string" || !report.certificate) return false;
  if (!leaf) return false;
  var named;
  try { named = x509.parse(guard.encoding.base64(report.certificate, C.MDS_BLOB_MAX_BYTES, _err, "webauthn/bad-metadata-entry", "a status report certificate")); }
  catch (_e) { return false; }
  try { return certKeyIdentifier(named) !== certKeyIdentifier(leaf); }
  catch (_e) { return false; }
}

// Has this report taken effect by `atMs`?
function _reportInForceAt(report, atMs) {
  var d = rfc3339.parseDate(report.effectiveDate, function (c, m) { return _err("webauthn/bad-metadata-blob", m); },
    "webauthn/bad-metadata-blob", "a status report effectiveDate");
  // Only ever called with a report whose effectiveDate rfc3339.isValidDate already accepted, and
  // parseDate throws rather than returning an Invalid Date, so d is finite; atMs was isFinite-
  // checked by the caller before this runs.
  // allow:nan-date-comparison-unguarded -- both operands are source-validated, as described above.
  return d.getTime() <= atMs;
}

function statusDenied(entry, metadata, leaf, at) {
  var policy = (metadata && metadata.statusPolicy) || "any";
  var reports = entry.statusReports || [];
  // A caller's own predicate receives the entry's reports AS GIVEN, which is what the documented
  // contract promises. Handing it a pre-filtered array would silently defeat the very policies it
  // exists for -- an entry-wide rule such as "deny whenever any attestation key is compromised"
  // would be evaluated against an array with exactly those reports removed.
  if (typeof policy === "function") return policy(reports) === true;
  // For the built-in policies, reports that demonstrably concern a DIFFERENT certificate are removed
  // first, before recency is considered. Scope has to be settled before recency, or under
  // latest-by-date such a report could be selected as the newest, displace an older model-wide
  // revocation, and then be discarded as inapplicable -- clearing the entry using a report that was
  // never about this authenticator at all.
  reports = reports.filter(function (r) {
    return !(r && typeof r.status === "string" && CERT_SCOPED_STATUS[r.status] && _reportNamesOtherCert(r, leaf));
  });
  // A report dated AFTER the instant being judged has not taken effect, whatever the policy. This
  // belongs here rather than inside one policy's branch: under the default reading, a scheduled
  // revocation would otherwise deny every registration from the moment it is published rather than
  // from the date it names, and a deliberately historical verification would see reports filed
  // after the time it asks about. When every dated report is still in the future, the answer is
  // that none of them is in force -- not that all of them are.
  var isDated = function (r) { return r && typeof r.effectiveDate === "string" && rfc3339.isValidDate(r.effectiveDate); };
  var atMs = (at instanceof Date && isFinite(at.getTime())) ? at.getTime() : null;
  if (atMs !== null) {
    reports = reports.filter(function (r) { return !isDated(r) || _reportInForceAt(r, atMs); });
  }
  var considered = reports;
  if (policy === "latest-by-date") {
    var dated = reports.filter(isDated);
    if (dated.length) {
      // EVERY report on the newest date, not the first one found there. Reducing to a single report
      // makes a tie resolve by array position: a same-day clean report and a same-day REVOKED would
      // deny or not depending purely on which the catalogue happened to list first, and reversing
      // the array would flip the verdict. Reports that are equally recent are equally current, so a
      // disqualifying one among them cannot be discarded.
      var newest = dated.reduce(function (a, b) { return a.effectiveDate >= b.effectiveDate ? a : b; }).effectiveDate;
      // effectiveDate is OPTIONAL (sec. 3.1.3), and a report without one cannot be shown to be
      // older than anything -- so it is KEPT rather than dropped. Discarding it would let an entry
      // clear an undated REVOKED simply by adding a dated clean report, which is the fail-open this
      // policy is most likely to be reached for. Where the ordering cannot be established, the
      // report still counts.
      considered = dated.filter(function (r) { return r.effectiveDate === newest; })
        .concat(reports.filter(function (r) { return !isDated(r); }));
    }
  }
  var rejectUnknown = !!(metadata && metadata.rejectUnknownStatus);
  return considered.some(function (r) {
    var s = r && typeof r.status === "string" ? r.status : null;
    if (s === null) return false;
    // Scope was settled above, so anything still here applies to this authenticator.
    if (DISQUALIFYING[s]) return true;
    // An unrecognised status is IGNORED for the gate unless the caller opted in: the specification
    // requires a verifier not to fail on a status value it does not know.
    return rejectUnknown && !_KNOWN_STATUS[s];
  });
}

// Status values this library recognises as non-disqualifying, so `rejectUnknownStatus` can tell an
// unknown value from a known-good one.
var _KNOWN_STATUS = Object.assign(Object.create(null), {
  NOT_FIDO_CERTIFIED: 1, SELF_ASSERTION_SUBMITTED: 1, FIDO_CERTIFIED: 1, FIDO_CERTIFIED_L1: 1,
  FIDO_CERTIFIED_L1plus: 1, FIDO_CERTIFIED_L2: 1, FIDO_CERTIFIED_L2plus: 1, FIDO_CERTIFIED_L3: 1,
  FIDO_CERTIFIED_L3plus: 1, UPDATE_AVAILABLE: 1,
});

// A 16-byte AAGUID from authenticatorData -> the dashed lower-case form the metadata is keyed by.
function aaguidToString(buf) {
  if (!Buffer.isBuffer(buf) || buf.length !== 16) return null;
  var h = buf.toString("hex");
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
}

// The key identifier of a certificate's subject public key, which is how the metadata keys a U2F
// authenticator that carries no AAGUID (`attestationCertificateKeyIdentifiers`).
//
// RFC 5280 sec. 4.2.1.2 method 1 exactly: the SHA-1 of the BIT STRING **contents** of the
// subjectPublicKey -- not of the whole SubjectPublicKeyInfo, which is a different digest that would
// match nothing in the catalogue and silently turn every U2F lookup into a miss.
//
// This is the same value pki-build's spkiKeyId derives for the subjectKeyIdentifier extension, from
// the DER rather than from a parsed certificate. Two derivations of one definition can drift, and a
// drift here is silent -- every U2F lookup simply stops matching -- so a vector pins the value
// against a real certificate's OWN subjectKeyIdentifier extension, which is the independent oracle
// for method 1 and fails the moment either derivation changes.
//
// The algorithm is not a choice: SHA-1 is what the standard names, this is an IDENTIFIER rather than
// a signature or an integrity check, and the identity it labels is re-established by the certificate
// chain validation that follows. Choosing a stronger hash would produce a value the catalogue does
// not contain.
function certKeyIdentifier(cert) {
  var pk = cert && cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.publicKey;
  if (!pk || !Buffer.isBuffer(pk.bytes)) {
    throw _err("webauthn/bad-input", "certKeyIdentifier expects a parsed certificate carrying a subject public key");
  }
  // Collision resistance is not the property relied on here: a second key hashing to the same
  // identifier would resolve to the same catalogue entry, and its certificate would then still have
  // to validate to the roots THAT entry registers -- which is the check that actually grants trust.
  // nosemgrep: pki-weak-hash-md5-sha1
  return nodeCrypto.createHash("sha1").update(pk.bytes).digest("hex");
}

// The verified metadata entry registering an attestation-certificate key identifier, or null. This
// is the lookup for an authenticator with no AAGUID -- the U2F case -- and it takes a
// verifyMetadataBlob result for the same reason metadataFor does: an unverified catalogue must not
// be able to answer which roots an authenticator is allowed to chain to.
function metadataForKeyIdentifier(metadata, keyId) {
  if (!isVerifiedResult(metadata)) throw _err("webauthn/bad-input", "metadataForKeyIdentifier expects a verifyMetadataBlob result -- an object that merely resembles one has not been through the signature and chain checks");
  if (typeof keyId !== "string") return null;
  return metadata.byKeyIdentifier[keyId.toLowerCase()] || null;
}

module.exports = {
  verifyMetadataBlob: verifyMetadataBlob,
  metadataFor: metadataFor,
  metadataForKeyIdentifier: metadataForKeyIdentifier,
  metadataAnchors: metadataAnchors,
  chainToAnchor: _chainToAnchor,
  assertFresh: assertFresh,
  isVerifiedResult: isVerifiedResult,
  statusDenied: statusDenied,
  aaguidToString: aaguidToString,
  ZERO_AAGUID: ZERO_AAGUID,
  certKeyIdentifier: certKeyIdentifier,
  DISQUALIFYING: DISQUALIFYING,
  // @internal -- the derived JWS algorithm table, exposed so a conformance vector can assert the
  // derivation is TOTAL over pki.jose's registry: every algorithm the toolkit verifies has a row
  // here, carrying the WebCrypto parameters its key type needs, or saying that the certificate
  // supplies them where the algorithm alone does not fix a curve.
  BLOB_ALGS: BLOB_ALGS,
};
