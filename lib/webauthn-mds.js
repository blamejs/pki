// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// and the @primitive blocks for verifyMetadataBlob / metadataFor / metadataAnchors live in

var frameworkError = require("./framework-error");
var x509 = require("./schema-x509");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _nodeCrypto = require("crypto");
/** @internal The seed of the fold below is a RESOLVED promise carrying `false`, the verdict for a chain
 *  that matched no anchor, and `Promise.resolve` builds from its RECEIVER. Read from the global binding,
 *  that seed is constructed by whatever the binding holds, so a replacement settling truthy starts the
 *  fold from "trusted" and every chain is trusted by default. */
var _Promise = intrinsic.Promise;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);
var _hasOwn = intrinsic.hasOwn;
var _reverse = intrinsic.reverse;
var _arrSlice = intrinsic.arraySlice;
var _charAt = intrinsic.uncurry(String.prototype.charAt);
/** @internal The string operations an identifier is normalized and sliced with. A metadata lookup key
 *  is built out of these, and the entry the key finds supplies both the status reports that refuse a
 *  revoked authenticator and the attestation roots a chain is anchored to, so an operation answering
 *  with another identifier selects another entry's status and another entry's roots. */
var _strToLowerCase = intrinsic.toLowerCase;
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _strSplit = intrinsic.uncurry(String.prototype.split);
/** @internal The hash constructor and the methods of the object it returns. What a digest here
 *  produces is a metadata lookup key and the identity two certificates are told apart by, so a
 *  replaced constructor, update or digest decides which entry governs an attestation. */
var _createHash = _nodeCrypto.createHash;
var _hashUpdate = intrinsic.uncurry(_nodeCrypto.createHash("sha256").update);
var _hashDigest = intrinsic.uncurry(_nodeCrypto.createHash("sha256").digest);
var jose = require("./jose");
var rfc3339 = require("./rfc3339");
var constants = require("./constants");
var pathValidate = require("./path-validate");
var signScheme = require("./sign-scheme");
var edwardsPoint = require("./edwards-point");
var webcrypto = require("./webcrypto");

var oid = require("./oid");
var pkix = require("./schema-pkix");
/** @internal The import and the verify a metadata BLOB's signature check runs, captured at load. One
 * `verify` answering true accepts a BLOB no authority signed, and the whole authenticator trust list
 * comes out of that BLOB. */
var _subtleImportKey = intrinsic.uncurry(webcrypto.webcrypto.subtle.importKey);
var _subtleVerify = intrinsic.uncurry(webcrypto.webcrypto.subtle.verify);
var WebauthnError = frameworkError.WebauthnError;
var _KU_NS = pkix.makeNS("webauthn", WebauthnError, oid);
function _err(code, message, cause) { return new WebauthnError(code, message, cause); }
var _KEYID_HEX_CI = pkix.charTable("0123456789abcdefABCDEF");
var _KEYID_HEX_LOWER = pkix.charTable("0123456789abcdef");
var C = constants.LIMITS;

/** @internal The BLOB members this module reads as integers, and so the members whose number tokens must
 *  denote exactly the integer they are read as. `no` is the one that decides something: `_assertFresh`
 *  admits a BLOB only when its `no` exceeds the one a relying party holds, so a rounded spelling compares
 *  as an integer it is not and a stale catalogue is accepted as a newer one.
 *
 *  Named individually rather than applied to the document, because a metadata statement is ordinary JSON
 *  and carries genuine doubles: the published BLOB has members whose values are not integers, among them
 *  the biometric `selfAttestedFRR` and `selfAttestedFAR` rates and `iAPARThreshold`. A document-wide rule
 *  refuses the real catalogue. */
var EXACT_INTEGER_BLOB_MEMBERS = intrinsic.freeze(intrinsic.assign(intrinsic.create(null), { no: 1 }));

/** @internal Sealed all the way down. Each row says which signature schemes a leaf key of that type
 *  may be used with, and the refusal reads the scheme straight out of the row, so a row that still
 *  inherits admits a scheme the key type does not support: `RSASSA-PKCS1-v1_5` installed on
 *  `Object.prototype` is read as present on the Ed25519 row. */
var LEAF_SCHEMES_BY_SPKI_ALG = _sealTable(intrinsic.assign(intrinsic.create(null), {
  ecPublicKey: { ECDSA: 1 },
  rsaEncryption: { "RSASSA-PKCS1-v1_5": 1, "RSA-PSS": 1 },
  rsassaPss: { "RSA-PSS": 1 },
  Ed25519: { EdDSA: 1 },
  Ed448: { EdDSA: 1 },
  "id-ml-dsa-44": { "ML-DSA-44": 1 },
  "id-ml-dsa-65": { "ML-DSA-65": 1 },
  "id-ml-dsa-87": { "ML-DSA-87": 1 },
}));

function _schemeE(kind, message, cause) { return new WebauthnError("webauthn/" + kind, message, cause); }

function _deriveBlobAlgs() {
  var out = intrinsic.create(null);
  intrinsic.forEach(jose.sigAlgs(), function (row) {
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
      out[row.alg] = { scheme: "EdDSA", hash: null, fromLeaf: true };
    } else if (row.kty === "AKP") {
      out[row.alg] = { scheme: row.alg, hash: null, imp: { name: row.alg }, ver: { name: row.alg } };
    }
  });
  return out;
}
/** @internal Sealed all the way down, because this table is EXPORTED and its NESTED rows carry the
 *  import and verify parameters a BLOB signature is checked under. A caller holding the object could
 *  redefine `RS256`'s hash, and the leaf key would then be imported for a weaker digest than the
 *  header declares. Freezing alone is not enough: a row written as an object literal still INHERITS,
 *  so `fromLeaf` installed on `Object.prototype` is read off every frozen row and sends the strongest
 *  algorithm down the take-it-from-the-leaf branch, which is why the prototype goes too. */
var BLOB_ALGS = _sealTable(_deriveBlobAlgs());

function _blobAlgParams(algRow, leafAlgName) {
  if (!algRow.fromLeaf) return algRow;
  return _sealTable({ scheme: algRow.scheme, hash: null, imp: { name: leafAlgName }, ver: { name: leafAlgName } });
}

/** @internal Frozen, because this table is EXPORTED and membership in it is what makes a status report
 *  disqualifying. A caller holding the object could redefine `REVOKED` so the lookup stops recognizing
 *  revocation, and `statusDenied` then permits a revoked authenticator with every operation around the
 *  lookup still captured. */
var DISQUALIFYING = intrinsic.freeze(intrinsic.assign(intrinsic.create(null), {
  REVOKED: 1, ATTESTATION_KEY_COMPROMISE: 1, USER_KEY_REMOTE_COMPROMISE: 1,
  USER_KEY_PHYSICAL_COMPROMISE: 1, USER_VERIFICATION_BYPASS: 1,
}));

var CERT_SCOPED_STATUS = intrinsic.freeze(intrinsic.assign(intrinsic.create(null), { ATTESTATION_KEY_COMPROMISE: 1 }));

var _BLOB_OPTS = intrinsic.assign(intrinsic.create(null), {
  rootCertificates: 1, time: 1, previousNo: 1, requireRollbackCheck: 1, allowStale: 1,
  statusPolicy: 1, rejectUnknownStatus: 1,
});

function _isPlainObject(v) { return !!v && typeof v === "object" && !intrinsic.isArray(v); }

/** @internal Both markers are read through captures. Membership here is what says an object is a
 *  verified BLOB result rather than a raw one a caller assembled, so a replacement answering `true`
 *  admits unverified metadata wherever `opts.metadata` is accepted; the second binds an entry to the
 *  result it was read out of, and one answering with the caller's own object passes an entry off as
 *  belonging to metadata that never carried it. */
var _verifiedResults = new WeakSet();
function isVerifiedResult(v) { return _isPlainObject(v) && intrinsic.weakSetHas(_verifiedResults, v); }

var _entryOrigin = new WeakMap();
function _isEntryOf(entry, metadata) { return intrinsic.weakGet(_entryOrigin, entry) === metadata; }

/** @internal A decision table and every row in it, with no prototype and nothing writable. Each row is
 *  looked up by a name taken from the input, so an inherited property answers for a row the table does
 *  not hold and a writable one answers differently than the table says. Detaching the prototype has to
 *  come first, since a frozen object's prototype can no longer be set. Arrays keep theirs: a row list
 *  is still indexed and walked. */
function _sealTable(v) {
  if (!v || typeof v !== "object" || intrinsic.isView(v)) return v;
  if (!intrinsic.isArray(v)) intrinsic.setPrototypeOf(v, null);
  intrinsic.forEach(intrinsic.getOwnPropertyNames(v), function (k) { _sealTable(v[k]); });
  return intrinsic.freeze(v);
}

function _deepFreeze(v, depth) {
  if (!v || typeof v !== "object" || intrinsic.isFrozen(v) || intrinsic.isView(v)) return v;
  if (depth > C.JSON_MAX_DEPTH) return v;
  intrinsic.freeze(v);
  intrinsic.forEach(intrinsic.keys(v), function (k) { _deepFreeze(v[k], depth + 1); });
  return v;
}
function _isAaguid(s) {
  if (s.length !== 36) return false;
  for (var i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) {
      if (_charAt(s, i) !== "-") return false;
    } else {
      var c = _charAt(s, i);
      if (!((c >= "0" && c <= "9") || (c >= "a" && c <= "f"))) return false;
    }
  }
  return true;
}
var ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";
var UNDERSTOOD_HEADER = intrinsic.freeze(intrinsic.assign(intrinsic.create(null), {
  alg: 1, typ: 1, cty: 1, crit: 1, jku: 1, jwk: 1, kid: 1, x5u: 1, x5c: 1, x5t: 1, "x5t#S256": 1,
}));

function _assertLeafSigns(leaf) {
  var ku = pkix.keyUsageOf(_KU_NS, leaf, _err, "webauthn/bad-att-cert", "metadata BLOB x5c leaf");
  if (ku && ku.digitalSignature !== true) {
    throw _err("webauthn/bad-att-cert", "the metadata BLOB x5c leaf keyUsage does not assert digitalSignature, so it may not sign the BLOB (RFC 5280 sec. 4.2.1.3)");
  }
}

/** @internal The key comparison comes from the capture. Answering `true` makes a certificate that
 *  merely carries the anchor's subject count as the anchor itself, and a single-certificate chain is
 *  then reported trusted with no path validation run over it. */
function _isAnchorItself(cert, anchor) {
  return guard.name.dnEqual(cert.subject.rdns, anchor.subject.rdns, _err, "webauthn/bad-att-cert", "the anchor subject") &&
    intrinsic.bufferEquals(cert.subjectPublicKeyInfo.bytes, anchor.subjectPublicKeyInfo.bytes);
}

function _asCert(v, label) {
  return guard.parsed.acceptDerived(v, "certificate", function (bytes) {
    try { return x509.parse(bytes); }
    catch (e) { throw _err("webauthn/bad-input", label + " is not a decodable certificate", e); }
  }, _err, "webauthn/bad-input", label);
}

function verifyMetadataBlob(blob, opts) {
  return guard.async.deferred(function () { return _verifyMetadataBlob(blob, opts); });
}

function _verifyMetadataBlob(blob, opts) {
  /** @internal A caller who passes no options gets a record with NO prototype. Defaulted to `{}` it
   *  inherits, and the snapshot below materializes every declared option name, so `allowStale`
   *  installed on `Object.prototype` reached the freshness check as an opt-in the caller never made. */
  opts = opts || intrinsic.create(null);
  if (!_isPlainObject(opts)) throw _err("webauthn/bad-input", "opts must be an object");
  guard.identifier.assertKnownKeys(opts, _BLOB_OPTS, _err, "webauthn/bad-input", "opts has an unknown key ");
  /** @internal Every option is read here, once, into a plain snapshot, and validation, the checks and
   * the result all read that snapshot. An option reached through an accessor answers each read
   * separately, so a baseline that answered absent where the rollback comparison runs and present
   * where the result is built skipped the comparison and still reported a baseline as checked.
   * Read as the rest of the file reads an option, `opts.<name>`, so an inherited one still counts. */
  var o = guard.identifier.snapshotOptions(opts, _BLOB_OPTS);

  var roots = o.rootCertificates;
  if (!intrinsic.isArray(roots) || roots.length === 0) {
    throw _err("webauthn/metadata-no-root", "verifying a metadata BLOB requires opts.rootCertificates -- the FIDO root(s) to anchor it to; this library bundles none");
  }
  if (o.time !== undefined) guard.time.assertValid(o.time, _err, "webauthn/bad-input", "opts.time");
  var at = o.time === undefined ? new intrinsic.Date() : o.time;
  if (o.previousNo !== undefined && (!intrinsic.isSafeInteger(o.previousNo) || o.previousNo < 0)) {
    throw _err("webauthn/bad-input", "opts.previousNo must be a non-negative safe integer");
  }
  intrinsic.forEach(["requireRollbackCheck", "allowStale", "rejectUnknownStatus"], function (k) {
    if (o[k] !== undefined && typeof o[k] !== "boolean") {
      throw _err("webauthn/bad-input", "opts." + k + " must be a boolean");
    }
  });
  if (o.statusPolicy !== undefined && typeof o.statusPolicy !== "function" &&
      o.statusPolicy !== "any" && o.statusPolicy !== "latest-by-date") {
    throw _err("webauthn/bad-input", "opts.statusPolicy must be \"any\", \"latest-by-date\", or a function");
  }
  if (o.requireRollbackCheck === true && o.previousNo === undefined) {
    throw _err("webauthn/metadata-no-baseline", "opts.requireRollbackCheck was set without opts.previousNo, so there is no baseline to compare against");
  }
  opts = o;
  var anchors = intrinsic.mapList(roots, function (r, i) { return _asCert(r, "opts.rootCertificates[" + i + "]"); });

  var raw = guard.bytes.isByteSource(blob)
    ? guard.bytes.source(blob, WebauthnError, "webauthn/bad-input", "the metadata BLOB") : null;
  var declaredLength = raw ? raw.length : (typeof blob === "string" ? intrinsic.byteLength(blob, "utf8") : null);
  if (declaredLength !== null && declaredLength > C.MDS_BLOB_MAX_BYTES) {
    throw _err("webauthn/too-large", "the metadata BLOB is " + declaredLength + " bytes, above the " + C.MDS_BLOB_MAX_BYTES + "-byte ceiling");
  }
  if (!raw && typeof blob !== "string") {
    throw _err("webauthn/bad-input", "the metadata BLOB must be bytes or a string");
  }
  var bytes = raw || intrinsic.bufferFrom(blob, "utf8");
  if (bytes.length > C.MDS_BLOB_MAX_BYTES) {
    throw _err("webauthn/too-large", "the metadata BLOB is " + bytes.length + " bytes, above the " + C.MDS_BLOB_MAX_BYTES + "-byte ceiling");
  }
  /** @internal The decode and the split that divides the JWS are captured. They decide which bytes are
   *  the signed input and which are the signature, so a replacement chooses what the verification
   *  below covers. */
  var segs = intrinsic.splitChar(intrinsic.bufToString(bytes, "utf8"), 46);
  if (segs.length !== 3) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB is not a three-part JWS compact serialization (RFC 7515 sec. 3.1)");
  if (segs[0].length > intrinsic.ceil(C.MDS_BLOB_HEADER_MAX_BYTES / 3) * 4) {
    throw _err("webauthn/too-large", "the metadata BLOB protected header is above the " + C.MDS_BLOB_HEADER_MAX_BYTES + "-byte ceiling");
  }
  if (segs[2].length > intrinsic.ceil(C.MDS_BLOB_SIG_MAX_BYTES / 3) * 4) {
    throw _err("webauthn/too-large", "the metadata BLOB signature is above the " + C.MDS_BLOB_SIG_MAX_BYTES + "-byte ceiling");
  }
  var header, sig;
  try {
    /** @internal The header carries `alg`, `typ` and the `x5c` chain, all strings, and no number this
     *  module reads as an integer, so there is nothing here for the rule to apply to. */
    header = guard.json.parse(intrinsic.bufferFrom(jose.base64url.decode(segs[0])), _err, {
      maxBytes: C.MDS_BLOB_HEADER_MAX_BYTES, maxDepth: C.JSON_MAX_DEPTH,
      tooLarge: "webauthn/too-large", badJson: "webauthn/bad-metadata-blob",
      tooDeep: "webauthn/bad-metadata-blob", duplicateMember: "webauthn/bad-metadata-blob",
      badInput: "webauthn/bad-metadata-blob", label: "the metadata BLOB header",
    });
    sig = intrinsic.bufferFrom(jose.base64url.decode(segs[2]));
  } catch (e) {
    if (e instanceof WebauthnError) throw e;
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header or signature is not decodable", e);
  }
  if (!_isPlainObject(header)) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header must be a JSON object");
  if (header.x5u !== undefined) {
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header carries x5u, which names a chain to fetch; supply a BLOB with an inline x5c instead");
  }
  if (_hasOwn(header, "crit")) {
    var crit = header.crit;
    if (!intrinsic.isArray(crit) || crit.length === 0) {
      throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit must be a non-empty array (RFC 7515 sec. 4.1.11)");
    }
    var critSeen = intrinsic.create(null);
    for (var ci = 0; ci < crit.length; ci++) {
      var critName = crit[ci];
      if (typeof critName !== "string") throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit entries must be strings");
      if (critSeen[critName]) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit repeats " + intrinsic.stringify(critName));
      critSeen[critName] = 1;
      if (UNDERSTOOD_HEADER[critName]) {
        throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header crit must not name the standard header parameter " + intrinsic.stringify(critName) + " (RFC 7515 sec. 4.1.11)");
      }
      throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header names critical header parameter " + intrinsic.stringify(critName) + ", which this reader does not process");
    }
  }
  var algRow = typeof header.alg === "string" ? BLOB_ALGS[header.alg] : undefined;
  if (!algRow) throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + intrinsic.stringify(header.alg) + " is not a supported JWS signature algorithm");
  if (!intrinsic.isArray(header.x5c) || header.x5c.length === 0) {
    throw _err("webauthn/bad-metadata-blob", "the metadata BLOB header carries no x5c certificate chain (RFC 7515 sec. 4.1.6)");
  }
  if (header.x5c.length > C.WEBAUTHN_X5C_MAX_CERTS) {
    throw _err("webauthn/too-large", "the metadata BLOB x5c carries " + header.x5c.length + " certificates, above the " + C.WEBAUTHN_X5C_MAX_CERTS + " this library will parse");
  }
  /** @internal The walk over the x5c entries is captured. It produces the chain the BLOB signature is
   *  verified under and anchored with, so a walk answering with certificates of its own replaces both. */
  var chain = intrinsic.mapList(header.x5c, function (entry, i) {
    if (typeof entry !== "string") throw _err("webauthn/bad-metadata-blob", "the metadata BLOB x5c entry " + i + " is not a string");
    var der;
    try { der = guard.encoding.base64(entry, C.MDS_BLOB_MAX_BYTES, _err, "webauthn/bad-metadata-blob", "a metadata BLOB x5c entry"); }
    catch (e) { throw _err("webauthn/bad-metadata-blob", "the metadata BLOB x5c entry " + i + " is not canonical base64", e); }
    try { return x509.parse(der); }
    catch (e) { throw _err("webauthn/bad-att-cert", "the metadata BLOB x5c entry " + i + " is not a decodable certificate", e); }
  });
  var leaf = chain[0];
  _assertLeafSigns(leaf);
  var leafAlg = (leaf.subjectPublicKeyInfo.algorithm || {}).name;
  var leafSchemes = typeof leafAlg === "string" ? LEAF_SCHEMES_BY_SPKI_ALG[leafAlg] : undefined;
  if (!leafSchemes || !leafSchemes[algRow.scheme]) {
    throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + header.alg + " does not match the x5c leaf key type " + intrinsic.stringify(leafAlg));
  }
  if (leafAlg === "rsassaPss") {
    var pinnedHash = signScheme.pssSpkiPinnedHash(leaf, _schemeE);
    if (pinnedHash && pinnedHash !== algRow.hash) {
      throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + header.alg + " uses " + algRow.hash + ", but the x5c leaf key is restricted to " + pinnedHash);
    }
  }

  if (leafAlg === "Ed25519" || leafAlg === "Ed448") {
    edwardsPoint.validateSpki(leaf.subjectPublicKeyInfo.bytes, leafAlg === "Ed25519" ? 6 : 7,
      WebauthnError, "webauthn/bad-att-cert");
  }
  var params = _blobAlgParams(algRow, leafAlg);
  var signingInput = intrinsic.bufferFrom(segs[0] + "." + segs[1], "ascii");
  return _subtleImportKey(webcrypto.webcrypto.subtle, "spki", leaf.subjectPublicKeyInfo.bytes, params.imp, false, ["verify"])
    .then(function (key) {
      return _subtleVerify(webcrypto.webcrypto.subtle, params.ver, key, sig, signingInput)
        .catch(function (e) { throw _err("webauthn/verify-error", "the metadata BLOB signature could not be evaluated under its x5c leaf key", e); });
    }, function (e) { throw _err("webauthn/unsupported-algorithm", "the metadata BLOB x5c leaf key could not be imported for " + header.alg, e); })
    .then(function (ok) {
      if (!ok) throw _err("webauthn/verify-failed", "the metadata BLOB signature does not verify under its x5c leaf key");
      return _chainToAnchor(chain, anchors, at);
    })
    .then(function () {
      return _parsePayload(segs[1], at, opts);
    });
}

function _chainToAnchor(chain, anchors, at, what, code) {
  var subject = what || "metadata BLOB certificate chain";
  var faultCode = code || "webauthn/metadata-untrusted";
  var ordered = _reverse(intrinsic.copyList(chain));
  var lastFault = null;
  /** @internal The fold over the anchors is captured. It is what walks each candidate anchor until
   *  one validates, so a replacement handing back a settled `true` without visiting an anchor reports
   *  the chain trusted against a root nothing compared it with. */
  return intrinsic.reduce(anchors, function (p, anchor) {
    return p.then(function (done) {
      if (done) return true;
      /** @internal Both copies are built without a construction protocol. The first is the chain this
       *  anchor is tried against, and the second is what is left once a self-presented anchor is
       *  stripped, so a copy answering with fewer elements leaves nothing to validate and the empty
       *  path reports trusted on the strength of the strip alone. A captured `slice` is not enough,
       *  since it runs ArraySpeciesCreate and hands its elements to whatever the species built. */
      var path = intrinsic.copyList(ordered);
      var strippedAnchor = false;
      if (path.length && _isAnchorItself(path[0], anchor)) { path = intrinsic.copyList(path, 1); strippedAnchor = true; }
      if (path.length === 0) return strippedAnchor;
      return pathValidate.validate(path, {
        time: at,
        trustAnchors: { name: anchor.subject, publicKey: anchor.subjectPublicKeyInfo.bytes,
          algorithm: anchor.subjectPublicKeyInfo.algorithm.oid,
          parameters: anchor.subjectPublicKeyInfo.algorithm.parameters },
      }).then(function (r) { return !!(r && r.valid); }, function (e) { lastFault = e; return false; });
    });
  }, _promiseResolve(_Promise, false)).then(function (trusted) {
    if (!trusted) {
      throw _err(faultCode, "the " + subject + " does not validate to any of the roots it must reach", lastFault);
    }
  });
}

function _staleAfter(nextUpdate) {
  var d = rfc3339.parseDate(nextUpdate, function (c, m) { return _err("webauthn/bad-metadata-blob", m); },
    "webauthn/bad-metadata-blob", "the metadata BLOB nextUpdate");
  return guard.time.instantOf(d) + constants.TIME.days(1);
}

function assertFresh(metadata, at, label) {
  if (!metadata || metadata.allowStale === true || typeof metadata.nextUpdate !== "string") return;
  var atMs = guard.time.isDate(at) ? guard.time.instantOf(at) : NaN;
  var limit = _staleAfter(metadata.nextUpdate);
  if (!intrinsic.numberIsFinite(atMs) || !intrinsic.numberIsFinite(limit)) return;
  if (atMs >= limit) {
    throw _err("webauthn/metadata-stale", (label || "the metadata") + " expired after " + metadata.nextUpdate +
      "; re-verify a current BLOB, or pass opts.allowStale when verifying it");
  }
}

function _parsePayload(seg, at, opts) {
  var payload;
  try {
    /** @internal The exact-integer rule applies to `no` ALONE, not to the document. `no` is the rollback
     *  counter: `_assertFresh` admits a BLOB only when its `no` exceeds the one a relying party already
     *  holds, and `1.0000000000000001` converts to the Number 1, so a stale BLOB spelled that way passed
     *  the `Number.isSafeInteger` check as the integer it is not and compared as that integer.
     *
     *  Document-wide would refuse the real catalogue. A metadata statement is ordinary JSON and carries
     *  genuine doubles: the published BLOB has ten members whose values are not integers, among them
     *  `selfAttestedFRR` and `selfAttestedFAR`, the biometric false-reject and false-accept rates, and
     *  `iAPARThreshold`. Measured on the live BLOB from mds3.fidoalliance.org rather than read off the
     *  specification, because the catalogue is what has to be ingestible. */
    payload = guard.json.parse(intrinsic.bufferFrom(jose.base64url.decode(seg)), _err, {
      maxBytes: C.MDS_BLOB_MAX_BYTES, maxDepth: C.JSON_MAX_DEPTH,
      exactIntegerMembers: EXACT_INTEGER_BLOB_MEMBERS,
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
  if (!intrinsic.isSafeInteger(payload.no) || payload.no < 0) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload must carry a non-negative integer no");
  if (opts.previousNo !== undefined && payload.no <= opts.previousNo) {
    throw _err("webauthn/metadata-rollback", "the metadata BLOB no " + payload.no + " does not exceed the previously held " + opts.previousNo);
  }
  var staleAfter = _staleAfter(payload.nextUpdate);
  var atMs = guard.time.instantOf(at);
  if (!intrinsic.numberIsFinite(atMs) || !intrinsic.numberIsFinite(staleAfter)) {
    throw _err("webauthn/bad-input", "the metadata freshness comparison has no usable instant");
  }
  var stale = atMs >= staleAfter;
  if (stale && opts.allowStale !== true) {
    throw _err("webauthn/metadata-stale", "the metadata BLOB expired after " + payload.nextUpdate + "; pass opts.allowStale to accept it anyway");
  }
  if (!intrinsic.isArray(payload.entries)) throw _err("webauthn/bad-metadata-blob", "the metadata BLOB payload must carry an entries array");
  if (payload.entries.length > C.MDS_MAX_ENTRIES) {
    throw _err("webauthn/too-large", "the metadata BLOB declares " + payload.entries.length + " entries, above the " + C.MDS_MAX_ENTRIES + " ceiling");
  }

  /** @internal The two lookup indexes and the walk that fills them are captured. An entry is found
   *  through these, and the entry supplies both the status reports that refuse a revoked authenticator
   *  and the attestation roots a chain is anchored to, so an index handed back already holding a key,
   *  or a walk that drops an entry, decides which entry an attestation is governed by. */
  var byAaguid = intrinsic.create(null);
  var byKeyIdentifier = intrinsic.create(null);
  var entries = intrinsic.mapList(payload.entries, function (e, i) {
    if (!_isPlainObject(e)) throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " is not an object");
    if (!intrinsic.isArray(e.statusReports) || e.statusReports.length === 0) {
      throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " must carry a non-empty statusReports array");
    }
    if (e.statusReports.length > C.MDS_MAX_STATUS_REPORTS_PER_ENTRY) {
      throw _err("webauthn/too-large", "metadata entry " + i + " declares " + e.statusReports.length +
        " status reports, above the " + C.MDS_MAX_STATUS_REPORTS_PER_ENTRY + " ceiling");
    }
    intrinsic.forEach(e.statusReports, function (r, ri) {
      if (!_isPlainObject(r)) throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " status report " + ri + " is not an object");
      if (typeof r.status !== "string" || !r.status) {
        throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " status report " + ri + " has no status (MDS v3.0 sec. 3.1.3 requires one)");
      }
    });
    var aaguid = null;
    if (e.aaguid !== undefined) {
      if (typeof e.aaguid !== "string" || !_isAaguid(_strToLowerCase(e.aaguid))) {
        throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " has a malformed aaguid");
      }
      aaguid = _strToLowerCase(e.aaguid);
    }
    var st = e.metadataStatement;
    var keyIds = [];
    var seenKeyId = intrinsic.create(null);
    intrinsic.forEach(
      [[e.attestationCertificateKeyIdentifiers, "entry"], [st && st.attestationCertificateKeyIdentifiers, "metadataStatement"]],
      function (pair) {
        var list = pair[0];
        if (list === undefined) return;
        if (!intrinsic.isArray(list)) {
          throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " " + pair[1] + " attestationCertificateKeyIdentifiers is not an array");
        }
        if (list.length > C.MDS_MAX_KEY_IDS_PER_ENTRY) {
          throw _err("webauthn/too-large", "metadata entry " + i + " declares " + list.length +
            " attestation certificate key identifiers, above the " + C.MDS_MAX_KEY_IDS_PER_ENTRY + " ceiling");
        }
        intrinsic.forEach(list, function (k) {
          if (typeof k !== "string" || k.length !== 40 || !pkix.allCharsIn(k, _KEYID_HEX_CI)) {
            throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " has a malformed attestation certificate key identifier");
          }
          var lower = _strToLowerCase(k);
          if (!seenKeyId[lower]) { seenKeyId[lower] = 1; guard.list.append(keyIds, lower); }
        });
      });
    var out = { index: i, aaguid: aaguid, keyIdentifiers: keyIds, statusReports: e.statusReports,
      metadataStatement: st || null, timeOfLastStatusChange: e.timeOfLastStatusChange || null };
    if (aaguid) {
      if (byAaguid[aaguid]) throw _err("webauthn/duplicate-metadata-entry", "two metadata entries claim aaguid " + aaguid);
      byAaguid[aaguid] = out;
    }
    intrinsic.forEach(keyIds, function (k) {
      if (byKeyIdentifier[k]) throw _err("webauthn/duplicate-metadata-entry", "two metadata entries claim attestation certificate key identifier " + k);
      byKeyIdentifier[k] = out;
    });
    return out;
  });
  var result = { no: payload.no, legalHeader: payload.legalHeader, nextUpdate: payload.nextUpdate,
    stale: stale, allowStale: opts.allowStale === true,
    rollbackChecked: opts.previousNo !== undefined,
    previousNo: opts.previousNo === undefined ? null : opts.previousNo,
    entries: entries, byAaguid: byAaguid, byKeyIdentifier: byKeyIdentifier,
    statusPolicy: opts.statusPolicy || "any", rejectUnknownStatus: opts.rejectUnknownStatus === true };
  _deepFreeze(result, 0);
  intrinsic.weakSetAdd(_verifiedResults, result);
  intrinsic.forEach(entries, function (e) { intrinsic.weakSet(_entryOrigin, e, result); });
  return result;
}

function metadataFor(metadata, identifier) {
  if (!isVerifiedResult(metadata)) throw _err("webauthn/bad-input", "metadataFor expects a verifyMetadataBlob result -- an object that merely resembles one, such as a catalogue restored from a cache, has not been through the signature and chain checks");
  if (typeof identifier !== "string") return null;
  /** @internal The fold that builds the lookup key is captured. The entry this key finds governs the
   *  attestation, supplying its status reports and its attestation roots, so a fold answering with
   *  another identifier hands the attestation another authenticator's entry. */
  var key = _strToLowerCase(identifier);
  if (_isAaguid(key)) {
    if (key === ZERO_AAGUID) return null;
    return metadata.byAaguid[key] || null;
  }
  if (key.length === 40 && pkix.allCharsIn(key, _KEYID_HEX_LOWER)) return metadataForKeyIdentifier(metadata, key);
  return null;
}

var _ANCHOR_OPTS = intrinsic.assign(intrinsic.create(null), { metadata: 1, time: 1, certificate: 1 });

function metadataAnchors(entry, opts) {
  if (!entry || typeof entry !== "object") throw _err("webauthn/bad-input", "metadataAnchors expects a metadata entry");
  opts = opts || intrinsic.create(null);
  if (typeof opts !== "object" || intrinsic.isArray(opts)) throw _err("webauthn/bad-input", "metadataAnchors opts must be an object");
  guard.identifier.assertKnownKeys(opts, _ANCHOR_OPTS, _err, "webauthn/bad-input", "metadataAnchors opts has an unknown key ");
  opts = guard.identifier.ownOptions(opts);
  if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");
  if (opts.metadata !== undefined) {
    if (!isVerifiedResult(opts.metadata)) {
      throw _err("webauthn/bad-input", "metadataAnchors opts.metadata expects a verifyMetadataBlob result -- an object that merely resembles one has not been through the signature and chain checks");
    }
    if (!_isEntryOf(entry, opts.metadata)) {
      throw _err("webauthn/bad-input", "metadataAnchors was given an entry from a different catalogue than opts.metadata, so the status reports would be judged under a policy and freshness that are not theirs");
    }
  }
  /** @internal The default instant is built with the captured constructor. It is the instant metadata
   *  freshness and every status report's effective date are compared against, so a replacement
   *  answering with an earlier one accepts expired metadata and suppresses a report already in
   *  effect. */
  var at = opts.time === undefined ? new intrinsic.Date() : opts.time;
  if (opts.metadata !== undefined) assertFresh(opts.metadata, at, "metadataAnchors");
  if (statusDenied(entry, opts.metadata, opts.certificate, at)) {
    throw _err("webauthn/metadata-status", "the metadata entry for this authenticator carries a disqualifying status report, so it registers no anchors to trust");
  }
  var st = entry.metadataStatement;
  var list = st && intrinsic.isArray(st.attestationRootCertificates) ? st.attestationRootCertificates : [];
  if (list.length > C.MDS_MAX_ANCHORS_PER_ENTRY) {
    throw _err("webauthn/too-large", "metadata entry " + entry.index + " declares " + list.length + " attestation roots, above the " + C.MDS_MAX_ANCHORS_PER_ENTRY + " ceiling");
  }
  /** @internal The walk that parses the registered roots is captured. These are the anchors an
   *  attestation path is validated to, so a walk answering with a certificate of its own supplies the
   *  anchor rather than reading it out of the entry. */
  return intrinsic.mapList(list, function (b64, i) {
    var der;
    try { der = guard.encoding.base64(b64, C.MDS_BLOB_MAX_BYTES, _err, "webauthn/bad-metadata-entry", "an attestation root certificate"); }
    catch (e) { throw _err("webauthn/bad-metadata-entry", "metadata entry " + entry.index + " attestation root " + i + " is not canonical base64", e); }
    try { return x509.parse(der); }
    catch (e) { throw _err("webauthn/bad-metadata-entry", "metadata entry " + entry.index + " attestation root " + i + " is not a decodable certificate", e); }
  });
}

function _reportNamesOtherCert(report, leaf) {
  if (typeof report.certificate !== "string" || !report.certificate) return false;
  if (!leaf) return false;
  var named;
  try { named = x509.parse(guard.encoding.base64(report.certificate, C.MDS_BLOB_MAX_BYTES, _err, "webauthn/bad-metadata-entry", "a status report certificate")); }
  catch (_e) { return false; }
  try { return certKeyIdentifier(named) !== certKeyIdentifier(leaf); }
  catch (_e) { return false; }
}

function _reportInForceAt(report, atMs) {
  var d = rfc3339.parseDate(report.effectiveDate, function (c, m) { return _err("webauthn/bad-metadata-blob", m); },
    "webauthn/bad-metadata-blob", "a status report effectiveDate");
  // allow:nan-date-comparison-unguarded -- both operands are source-validated, as described above.
  return guard.time.instantOf(d) <= atMs;
}

/** @internal The one refusal that stops a revoked or compromised authenticator being trusted, written
 *  without any array operation that consults a replaceable protocol. A captured `filter` and `map`
 *  still build their result through ArraySpeciesCreate, which reads a constructor off the receiver, so
 *  a species replacement returning an ordinary object collects the matches as indexed properties while
 *  its `length` stays 0 and the membership test at the end visits nothing. `concat` reads
 *  `Symbol.isConcatSpreadable` the same way, and a `false` there leaves the two selections nested
 *  inside the result where no report has a `status` to recognize. Both end in a permit. Every
 *  selection here is therefore an index loop appending into an array literal, which creates through
 *  no protocol, and each report field is read as an OWN property so a caller-supplied record cannot
 *  inherit `effectiveDate` and have an undated revocation read as one that is not yet in force. */
function statusDenied(entry, metadata, leaf, at) {
  var policy = (metadata && metadata.statusPolicy) || "any";
  var reports = entry.statusReports || [];
  if (typeof policy === "function") return policy(reports) === true;
  function dateOf(r) {
    if (!r || !_hasOwn(r, "effectiveDate")) return null;
    var d = r.effectiveDate;
    return (typeof d === "string" && rfc3339.isValidDate(d)) ? d : null;
  }
  function statusOf(r) {
    if (!r || !_hasOwn(r, "status")) return null;
    return typeof r.status === "string" ? r.status : null;
  }
  var atMs = (guard.time.isDate(at) && intrinsic.numberIsFinite(guard.time.instantOf(at))) ? guard.time.instantOf(at) : null;
  var i;
  var inForce = [];
  for (i = 0; i < reports.length; i++) {
    var r0 = reports[i];
    var s0 = statusOf(r0);
    if (s0 !== null && CERT_SCOPED_STATUS[s0] && _reportNamesOtherCert(r0, leaf)) continue;
    var d0 = dateOf(r0);
    if (atMs !== null && d0 !== null && !_reportInForceAt(r0, atMs)) continue;
    guard.list.append(inForce, r0);
  }
  var considered = inForce;
  if (policy === "latest-by-date") {
    var newest = null;
    for (i = 0; i < inForce.length; i++) {
      var dN = dateOf(inForce[i]);
      if (dN !== null && (newest === null || dN >= newest)) newest = dN;
    }
    if (newest !== null) {
      considered = [];
      for (i = 0; i < inForce.length; i++) {
        var dK = dateOf(inForce[i]);
        if (dK === null || dK === newest) guard.list.append(considered, inForce[i]);
      }
    }
  }
  var rejectUnknown = !!(metadata && metadata.rejectUnknownStatus);
  for (i = 0; i < considered.length; i++) {
    var s = statusOf(considered[i]);
    if (s === null) continue;
    if (DISQUALIFYING[s]) return true;
    if (rejectUnknown && !_KNOWN_STATUS[s]) return true;
  }
  return false;
}

/** @internal Frozen. Under `rejectUnknownStatus` a status NOT in this table is disqualifying, so a
 *  caller able to add an entry makes an unrecognized status read as a known-good one. */
var _KNOWN_STATUS = intrinsic.freeze(intrinsic.assign(intrinsic.create(null), {
  NOT_FIDO_CERTIFIED: 1, SELF_ASSERTION_SUBMITTED: 1, FIDO_CERTIFIED: 1, FIDO_CERTIFIED_L1: 1,
  FIDO_CERTIFIED_L1plus: 1, FIDO_CERTIFIED_L2: 1, FIDO_CERTIFIED_L2plus: 1, FIDO_CERTIFIED_L3: 1,
  FIDO_CERTIFIED_L3plus: 1, UPDATE_AVAILABLE: 1,
}));

/** @internal The rendering of an AAGUID is captured end to end. The string it returns is the metadata
 *  lookup key, so an encoding or a slice answering with another authenticator's AAGUID selects that
 *  authenticator's entry, with its status reports and its attestation roots. */
function aaguidToString(buf) {
  if (!intrinsic.isBuffer(buf) || buf.length !== 16) return null;
  var h = intrinsic.bufToString(buf, "hex");
  return _strSlice(h, 0, 8) + "-" + _strSlice(h, 8, 12) + "-" + _strSlice(h, 12, 16) + "-" +
    _strSlice(h, 16, 20) + "-" + _strSlice(h, 20);
}

/** @internal The digest, its update and its encoding all come from captures. What this returns is both
 *  a metadata lookup key and the identity two certificates are told apart by where a status report
 *  names one, so an operation answering with another certificate's identifier selects another entry
 *  and makes a certificate-scoped compromise report apply to the wrong leaf. */
function certKeyIdentifier(cert) {
  var pk = cert && cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.publicKey;
  if (!pk || !intrinsic.isBuffer(pk.bytes)) {
    throw _err("webauthn/bad-input", "certKeyIdentifier expects a parsed certificate carrying a subject public key");
  }
  return _hashDigest(_hashUpdate(_createHash("sha1"), pk.bytes), "hex");
}

function metadataForKeyIdentifier(metadata, keyId) {
  if (!isVerifiedResult(metadata)) throw _err("webauthn/bad-input", "metadataForKeyIdentifier expects a verifyMetadataBlob result -- an object that merely resembles one has not been through the signature and chain checks");
  if (typeof keyId !== "string") return null;
  return metadata.byKeyIdentifier[_strToLowerCase(keyId)] || null;
}

/** @internal Frozen, because a consumer reads these off this object at the call. `metadataFor` is what
 *  finds the entry a status refusal is read out of, and `chainToAnchor` IS the chain validation, so a
 *  writable export lets a replacement answer `null` for a disqualified entry or settle without walking
 *  a path, and the consumer's own captures decide nothing after that. */
module.exports = intrinsic.freeze({
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
  // @internal
  BLOB_ALGS: BLOB_ALGS,
});
