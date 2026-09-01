// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// and the @primitive blocks for verifyMetadataBlob / metadataFor / metadataAnchors live in

var frameworkError = require("./framework-error");
var x509 = require("./schema-x509");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _charAt = intrinsic.uncurry(String.prototype.charAt);
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
var _KEYID_HEX_CI = pkix.charTable("0123456789abcdefABCDEF");
var _KEYID_HEX_LOWER = pkix.charTable("0123456789abcdef");
var C = constants.LIMITS;

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

function _schemeE(kind, message, cause) { return new WebauthnError("webauthn/" + kind, message, cause); }

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
      out[row.alg] = { scheme: "EdDSA", hash: null, fromLeaf: true };
    } else if (row.kty === "AKP") {
      out[row.alg] = { scheme: row.alg, hash: null, imp: { name: row.alg }, ver: { name: row.alg } };
    }
  });
  return out;
}
var BLOB_ALGS = _deriveBlobAlgs();

function _blobAlgParams(algRow, leafAlgName) {
  if (!algRow.fromLeaf) return algRow;
  return { scheme: algRow.scheme, hash: null, imp: { name: leafAlgName }, ver: { name: leafAlgName } };
}

var DISQUALIFYING = Object.assign(Object.create(null), {
  REVOKED: 1, ATTESTATION_KEY_COMPROMISE: 1, USER_KEY_REMOTE_COMPROMISE: 1,
  USER_KEY_PHYSICAL_COMPROMISE: 1, USER_VERIFICATION_BYPASS: 1,
});

var CERT_SCOPED_STATUS = Object.assign(Object.create(null), { ATTESTATION_KEY_COMPROMISE: 1 });

var _BLOB_OPTS = Object.assign(Object.create(null), {
  rootCertificates: 1, time: 1, previousNo: 1, requireRollbackCheck: 1, allowStale: 1,
  statusPolicy: 1, rejectUnknownStatus: 1,
});

function _isPlainObject(v) { return !!v && typeof v === "object" && !Array.isArray(v); }

var _verifiedResults = new WeakSet();
function isVerifiedResult(v) { return _isPlainObject(v) && _verifiedResults.has(v); }

var _entryOrigin = new WeakMap();
function _isEntryOf(entry, metadata) { return _entryOrigin.get(entry) === metadata; }

function _deepFreeze(v, depth) {
  if (!v || typeof v !== "object" || Object.isFrozen(v) || ArrayBuffer.isView(v)) return v;
  if (depth > C.JSON_MAX_DEPTH) return v;
  Object.freeze(v);
  Object.keys(v).forEach(function (k) { _deepFreeze(v[k], depth + 1); });
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
var UNDERSTOOD_HEADER = Object.assign(Object.create(null), {
  alg: 1, typ: 1, cty: 1, crit: 1, jku: 1, jwk: 1, kid: 1, x5u: 1, x5c: 1, x5t: 1, "x5t#S256": 1,
});

function _assertLeafSigns(leaf) {
  var ku = pkix.keyUsageOf(_KU_NS, leaf, _err, "webauthn/bad-att-cert", "metadata BLOB x5c leaf");
  if (ku && ku.digitalSignature !== true) {
    throw _err("webauthn/bad-att-cert", "the metadata BLOB x5c leaf keyUsage does not assert digitalSignature, so it may not sign the BLOB (RFC 5280 sec. 4.2.1.3)");
  }
}

function _isAnchorItself(cert, anchor) {
  return guard.name.dnEqual(cert.subject.rdns, anchor.subject.rdns, _err, "webauthn/bad-att-cert", "the anchor subject") &&
    cert.subjectPublicKeyInfo.bytes.equals(anchor.subjectPublicKeyInfo.bytes);
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

  var raw = guard.bytes.isByteSource(blob)
    ? guard.bytes.source(blob, WebauthnError, "webauthn/bad-input", "the metadata BLOB") : null;
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
  if (segs[0].length > Math.ceil(C.MDS_BLOB_HEADER_MAX_BYTES / 3) * 4) {
    throw _err("webauthn/too-large", "the metadata BLOB protected header is above the " + C.MDS_BLOB_HEADER_MAX_BYTES + "-byte ceiling");
  }
  if (segs[2].length > Math.ceil(C.MDS_BLOB_SIG_MAX_BYTES / 3) * 4) {
    throw _err("webauthn/too-large", "the metadata BLOB signature is above the " + C.MDS_BLOB_SIG_MAX_BYTES + "-byte ceiling");
  }
  var header, sig;
  try {
    header = guard.json.parse(Buffer.from(jose.base64url.decode(segs[0])), _err, {
      maxBytes: C.MDS_BLOB_HEADER_MAX_BYTES, maxDepth: C.JSON_MAX_DEPTH,
      tooLarge: "webauthn/too-large", badJson: "webauthn/bad-metadata-blob",
      tooDeep: "webauthn/bad-metadata-blob", duplicateMember: "webauthn/bad-metadata-blob",
      badInput: "webauthn/bad-metadata-blob", label: "the metadata BLOB header",
    });
    sig = Buffer.from(jose.base64url.decode(segs[2]));
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
  _assertLeafSigns(leaf);
  var leafAlg = (leaf.subjectPublicKeyInfo.algorithm || {}).name;
  var leafSchemes = typeof leafAlg === "string" ? LEAF_SCHEMES_BY_SPKI_ALG[leafAlg] : undefined;
  if (!leafSchemes || !leafSchemes[algRow.scheme]) {
    throw _err("webauthn/unsupported-algorithm", "the metadata BLOB alg " + header.alg + " does not match the x5c leaf key type " + JSON.stringify(leafAlg));
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
  var signingInput = Buffer.from(segs[0] + "." + segs[1], "ascii");
  return webcrypto.webcrypto.subtle.importKey("spki", leaf.subjectPublicKeyInfo.bytes, params.imp, false, ["verify"])
    .then(function (key) {
      return webcrypto.webcrypto.subtle.verify(params.ver, key, sig, signingInput)
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
  var ordered = chain.slice().reverse();
  var lastFault = null;
  return anchors.reduce(function (p, anchor) {
    return p.then(function (done) {
      if (done) return true;
      var path = ordered.slice();
      var strippedAnchor = false;
      if (path.length && _isAnchorItself(path[0], anchor)) { path = path.slice(1); strippedAnchor = true; }
      if (path.length === 0) return strippedAnchor;
      return pathValidate.validate(path, {
        time: at,
        trustAnchors: { name: anchor.subject, publicKey: anchor.subjectPublicKeyInfo.bytes,
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

function _staleAfter(nextUpdate) {
  var d = rfc3339.parseDate(nextUpdate, function (c, m) { return _err("webauthn/bad-metadata-blob", m); },
    "webauthn/bad-metadata-blob", "the metadata BLOB nextUpdate");
  return guard.time.instantOf(d) + constants.TIME.days(1);
}

function assertFresh(metadata, at, label) {
  if (!metadata || metadata.allowStale === true || typeof metadata.nextUpdate !== "string") return;
  var atMs = guard.time.isDate(at) ? guard.time.instantOf(at) : NaN;
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
  if (opts.previousNo !== undefined && payload.no <= opts.previousNo) {
    throw _err("webauthn/metadata-rollback", "the metadata BLOB no " + payload.no + " does not exceed the previously held " + opts.previousNo);
  }
  var staleAfter = _staleAfter(payload.nextUpdate);
  var atMs = guard.time.instantOf(at);
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
    if (e.statusReports.length > C.MDS_MAX_STATUS_REPORTS_PER_ENTRY) {
      throw _err("webauthn/too-large", "metadata entry " + i + " declares " + e.statusReports.length +
        " status reports, above the " + C.MDS_MAX_STATUS_REPORTS_PER_ENTRY + " ceiling");
    }
    e.statusReports.forEach(function (r, ri) {
      if (!_isPlainObject(r)) throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " status report " + ri + " is not an object");
      if (typeof r.status !== "string" || !r.status) {
        throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " status report " + ri + " has no status (MDS v3.0 sec. 3.1.3 requires one)");
      }
    });
    var aaguid = null;
    if (e.aaguid !== undefined) {
      if (typeof e.aaguid !== "string" || !_isAaguid(e.aaguid.toLowerCase())) {
        throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " has a malformed aaguid");
      }
      aaguid = e.aaguid.toLowerCase();
    }
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
          if (typeof k !== "string" || k.length !== 40 || !pkix.allCharsIn(k, _KEYID_HEX_CI)) {
            throw _err("webauthn/bad-metadata-blob", "metadata entry " + i + " has a malformed attestation certificate key identifier");
          }
          var lower = k.toLowerCase();
          if (!seenKeyId[lower]) { seenKeyId[lower] = 1; keyIds.push(lower); }
        });
      });
    var out = { index: i, aaguid: aaguid, keyIdentifiers: keyIds, statusReports: e.statusReports,
      metadataStatement: st || null, timeOfLastStatusChange: e.timeOfLastStatusChange || null };
    if (aaguid) {
      if (byAaguid[aaguid]) throw _err("webauthn/duplicate-metadata-entry", "two metadata entries claim aaguid " + aaguid);
      byAaguid[aaguid] = out;
    }
    keyIds.forEach(function (k) {
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
  _verifiedResults.add(result);
  entries.forEach(function (e) { _entryOrigin.set(e, result); });
  return result;
}

function metadataFor(metadata, identifier) {
  if (!isVerifiedResult(metadata)) throw _err("webauthn/bad-input", "metadataFor expects a verifyMetadataBlob result -- an object that merely resembles one, such as a catalogue restored from a cache, has not been through the signature and chain checks");
  if (typeof identifier !== "string") return null;
  var key = identifier.toLowerCase();
  if (_isAaguid(key)) {
    if (key === ZERO_AAGUID) return null;
    return metadata.byAaguid[key] || null;
  }
  if (key.length === 40 && pkix.allCharsIn(key, _KEYID_HEX_LOWER)) return metadataForKeyIdentifier(metadata, key);
  return null;
}

var _ANCHOR_OPTS = Object.assign(Object.create(null), { metadata: 1, time: 1, certificate: 1 });

function metadataAnchors(entry, opts) {
  if (!entry || typeof entry !== "object") throw _err("webauthn/bad-input", "metadataAnchors expects a metadata entry");
  opts = opts || {};
  if (typeof opts !== "object" || Array.isArray(opts)) throw _err("webauthn/bad-input", "metadataAnchors opts must be an object");
  guard.identifier.assertKnownKeys(opts, _ANCHOR_OPTS, _err, "webauthn/bad-input", "metadataAnchors opts has an unknown key ");
  opts = Object.assign({}, opts);
  if (opts.time !== undefined) guard.time.assertValid(opts.time, _err, "webauthn/bad-input", "opts.time");
  if (opts.metadata !== undefined) {
    if (!isVerifiedResult(opts.metadata)) {
      throw _err("webauthn/bad-input", "metadataAnchors opts.metadata expects a verifyMetadataBlob result -- an object that merely resembles one has not been through the signature and chain checks");
    }
    if (!_isEntryOf(entry, opts.metadata)) {
      throw _err("webauthn/bad-input", "metadataAnchors was given an entry from a different catalogue than opts.metadata, so the status reports would be judged under a policy and freshness that are not theirs");
    }
  }
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

function statusDenied(entry, metadata, leaf, at) {
  var policy = (metadata && metadata.statusPolicy) || "any";
  var reports = entry.statusReports || [];
  if (typeof policy === "function") return policy(reports) === true;
  reports = reports.filter(function (r) {
    return !(r && typeof r.status === "string" && CERT_SCOPED_STATUS[r.status] && _reportNamesOtherCert(r, leaf));
  });
  var isDated = function (r) { return r && typeof r.effectiveDate === "string" && rfc3339.isValidDate(r.effectiveDate); };
  var atMs = (guard.time.isDate(at) && isFinite(guard.time.instantOf(at))) ? guard.time.instantOf(at) : null;
  if (atMs !== null) {
    reports = reports.filter(function (r) { return !isDated(r) || _reportInForceAt(r, atMs); });
  }
  var considered = reports;
  if (policy === "latest-by-date") {
    var dated = reports.filter(isDated);
    if (dated.length) {
      var newest = dated.reduce(function (a, b) { return a.effectiveDate >= b.effectiveDate ? a : b; }).effectiveDate;
      considered = dated.filter(function (r) { return r.effectiveDate === newest; })
        .concat(reports.filter(function (r) { return !isDated(r); }));
    }
  }
  var rejectUnknown = !!(metadata && metadata.rejectUnknownStatus);
  return considered.some(function (r) {
    var s = r && typeof r.status === "string" ? r.status : null;
    if (s === null) return false;
    if (DISQUALIFYING[s]) return true;
    return rejectUnknown && !_KNOWN_STATUS[s];
  });
}

var _KNOWN_STATUS = Object.assign(Object.create(null), {
  NOT_FIDO_CERTIFIED: 1, SELF_ASSERTION_SUBMITTED: 1, FIDO_CERTIFIED: 1, FIDO_CERTIFIED_L1: 1,
  FIDO_CERTIFIED_L1plus: 1, FIDO_CERTIFIED_L2: 1, FIDO_CERTIFIED_L2plus: 1, FIDO_CERTIFIED_L3: 1,
  FIDO_CERTIFIED_L3plus: 1, UPDATE_AVAILABLE: 1,
});

function aaguidToString(buf) {
  if (!Buffer.isBuffer(buf) || buf.length !== 16) return null;
  var h = buf.toString("hex");
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
}

function certKeyIdentifier(cert) {
  var pk = cert && cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.publicKey;
  if (!pk || !Buffer.isBuffer(pk.bytes)) {
    throw _err("webauthn/bad-input", "certKeyIdentifier expects a parsed certificate carrying a subject public key");
  }
  return nodeCrypto.createHash("sha1").update(pk.bytes).digest("hex");
}

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
  // @internal
  BLOB_ALGS: BLOB_ALGS,
};
