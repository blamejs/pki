// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.sigstore
 * @nav        Supply chain
 * @title      Sigstore
 * @fullname   Sigstore bundles: keyless signing and provenance
 * @intro Zero-dependency verifier for a Sigstore bundle, the exact artifact
 *   `npm publish --provenance` produces and the npm registry serves at its
 *   attestations API. A bundle is a keyless (Fulcio) signature over a DSSE-wrapped
 *   in-toto SLSA provenance attestation, with a Rekor transparency-log inclusion
 *   proof. `verifyBundle` composes five fail-closed legs against caller-supplied
 *   trust material (the Fulcio CA roots + Rekor log keys, never trusted from the
 *   bundle): the DSSE signature over its PAE preimage under the Fulcio leaf key;
 *   the Fulcio certificate chain, validated as of the Rekor log time (the cert is
 *   ephemeral, ~10 minutes); the Rekor inclusion proof folded to a Rekor-signed
 *   tree root; the log entry binding to this exact signature; and the in-toto
 *   subject digest the caller confirms against the published artifact. Verify-only
 *   and offline: every input is in the bundle or a caller argument. Reuses the
 *   shipped X.509 parser, RFC 5280 path validator, RFC 9162 Merkle verifier, and
 *   native crypto engine; the net-new codecs are the DSSE PAE byte-builder and a
 *   fail-closed JSON bundle reader.
 * @spec DSSE, Sigstore bundle v0.3, RFC 9162, SLSA provenance v1
 * @card Verify an npm --provenance Sigstore bundle offline (DSSE + Fulcio + Rekor + SLSA).
 */

var nodeCrypto = require("crypto");
var frameworkError = require("./framework-error");
var constants = require("./constants");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var pathValidate = require("./path-validate");
var merkle = require("./merkle");
var oid = require("./oid");
var edwardsPoint = require("./edwards-point");

var C = constants;
var SigstoreError = frameworkError.SigstoreError;
function _err(code, message, cause) { return new SigstoreError(code, message, cause); }

var JSON_MAX = C.LIMITS.JSON_MAX_BYTES;
var SP = Buffer.from(" ", "ascii");
var DSSEV1 = Buffer.from("DSSEv1", "ascii");
var _EM_DASH = String.fromCharCode(0x2014);

function _parseNoteSig(line) {
  var prefix = _EM_DASH + " ";
  if (line.slice(0, prefix.length) !== prefix) return null;
  var p = prefix.length, n = line.length;
  var t1s = p;
  while (p < n && !pkix.isJsWhitespace(line.charCodeAt(p))) p += 1;
  if (p === t1s) return null;
  var keyId = line.slice(t1s, p);
  if (line.charAt(p) !== " ") return null;
  p += 1;
  var t2s = p;
  while (p < n && !pkix.isJsWhitespace(line.charCodeAt(p))) p += 1;
  if (p === t2s) return null;
  var sig = line.slice(t2s, p);
  if (p !== n) return null;
  return { keyId: keyId, sig: sig };
}

function _stripTrailingEquals(s) {
  var i = s.length;
  while (i > 0 && s.charAt(i - 1) === "=") i -= 1;
  return s.slice(0, i);
}

var _BUNDLE_MEDIA_TYPES = {
  "application/vnd.dev.sigstore.bundle.v0.1+json": 1,
  "application/vnd.dev.sigstore.bundle.v0.2+json": 1,
  "application/vnd.dev.sigstore.bundle.v0.3+json": 1,
  "application/vnd.dev.sigstore.bundle+json;version=0.1": 1,
  "application/vnd.dev.sigstore.bundle+json;version=0.2": 1,
  "application/vnd.dev.sigstore.bundle+json;version=0.3": 1
};
function _isBundleMediaType(mt) {
  return typeof mt === "string" && Object.prototype.hasOwnProperty.call(_BUNDLE_MEDIA_TYPES, mt);
}

function _jsonParse(input, code, label) {
  return guard.json.parse(input, _err, {
    maxBytes: JSON_MAX, maxDepth: 64,
    badJson: code, tooDeep: code, duplicateMember: code, tooLarge: code, badInput: code, label: label,
  });
}


/**
 * @primitive pki.sigstore.pae
 * @signature pki.sigstore.pae(payloadType, payloadBytes) -> Buffer
 * @since 0.2.3
 * @status stable
 * @spec DSSE
 * @related pki.sigstore.verifyBundle
 *
 * The DSSE Pre-Authentication Encoding: `"DSSEv1" SP LEN(type) SP type SP
 * LEN(body) SP body`, where `LEN` is the ASCII-decimal byte length (no leading
 * zeros) and `type` is the UTF-8 `payloadType`. This is the exact preimage a DSSE
 * signature covers; `LEN` is over the decoded body byte length, never the base64
 * length. Any deviation is a signature-verify bypass.
 *
 * @example
 *   var b = pki.sigstore.pae("application/vnd.in-toto+json", Buffer.from("{}"));
 *   b.slice(0, 6).toString(); // "DSSEv1"
 */
function pae(payloadType, payloadBytes) {
  if (typeof payloadType !== "string") throw new TypeError("pae: payloadType must be a string");
  var type = Buffer.from(payloadType, "utf8");
  var body = Buffer.isBuffer(payloadBytes) ? payloadBytes : Buffer.from(payloadBytes || []);
  return Buffer.concat([
    DSSEV1, SP,
    Buffer.from(String(type.length), "ascii"), SP, type, SP,
    Buffer.from(String(body.length), "ascii"), SP, body,
  ]);
}


function _b64(s, label) {
  if (typeof s !== "string") throw _err("sigstore/bad-bundle", label + " must be a base64 string");
  var urlSafe = s.indexOf("-") !== -1 || s.indexOf("_") !== -1;
  var enc = urlSafe ? "base64url" : "base64";
  var buf = Buffer.from(s, enc);
  if (_stripTrailingEquals(buf.toString(enc)) !== _stripTrailingEquals(s)) {
    throw _err("sigstore/bad-bundle", label + " is not canonical base64");
  }
  return buf;
}


/**
 * @primitive pki.sigstore.parseBundle
 * @signature pki.sigstore.parseBundle(input) -> bundle
 * @since 0.2.3
 * @status stable
 * @spec Sigstore bundle v0.3
 * @related pki.sigstore.verifyBundle
 *
 * Decode + structurally validate a Sigstore bundle (a JSON object, string, or
 * Buffer) fail-closed: a non-object, malformed JSON, an oversize input, an
 * unknown `mediaType`, or a missing required member throws a typed
 * `sigstore/bad-bundle` / `sigstore/bad-bundle-version`. Returns the validated
 * bundle object (structure only, no cryptographic verification).
 *
 * @example
 *   // requires: `bundle` -- a Sigstore bundle as cosign or npm provenance emits it
 *   // (the JSON object, a JSON string, or its raw bytes)
 *   var b = pki.sigstore.parseBundle(bundle);
 *   b.mediaType; // "application/vnd.dev.sigstore.bundle.v0.3+json"
 */
function parseBundle(input) {
  var obj;
  if (Buffer.isBuffer(input) || typeof input === "string") {
    obj = _jsonParse(input, "sigstore/bad-bundle", "bundle");
  } else if (input && typeof input === "object") {
    obj = input;
  } else {
    throw _err("sigstore/bad-bundle", "bundle must be a JSON object, string, or Buffer");
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw _err("sigstore/bad-bundle", "bundle must be a JSON object");
  var mt = obj.mediaType;
  if (!_isBundleMediaType(mt)) {
    throw _err("sigstore/bad-bundle-version", "unsupported or unknown bundle media type: " + (mt === undefined ? "(none)" : guard.text.showValue(mt)));
  }
  if (!obj.verificationMaterial || typeof obj.verificationMaterial !== "object") {
    throw _err("sigstore/bad-bundle", "bundle is missing verificationMaterial");
  }
  if (obj.messageSignature && !obj.dsseEnvelope) {
    throw _err("sigstore/unsupported-content", "a message_signature bundle is not supported (only dsse_envelope)");
  }
  if (!obj.dsseEnvelope || typeof obj.dsseEnvelope !== "object") {
    throw _err("sigstore/bad-bundle", "bundle is missing a dsseEnvelope");
  }
  var d = obj.dsseEnvelope;
  if (typeof d.payload !== "string" || typeof d.payloadType !== "string" || !Array.isArray(d.signatures) || !d.signatures.length ||
      !d.signatures[0] || typeof d.signatures[0] !== "object" || typeof d.signatures[0].sig !== "string") {
    throw _err("sigstore/bad-dsse", "the DSSE envelope is missing a required field (payload / payloadType / signatures[].sig)");
  }
  return obj;
}


function _certBytes(c, label) {
  if (!c || typeof c !== "object" || typeof c.rawBytes !== "string") throw _err("sigstore/bad-bundle", label + " is not a { rawBytes } certificate");
  return _b64(c.rawBytes, label);
}
function _leafCertDer(vm) {
  if (vm.certificate) return _certBytes(vm.certificate, "verificationMaterial.certificate");
  if (vm.x509CertificateChain && Array.isArray(vm.x509CertificateChain.certificates) && vm.x509CertificateChain.certificates.length) {
    return _certBytes(vm.x509CertificateChain.certificates[0], "verificationMaterial.x509CertificateChain[0]");
  }
  throw _err("sigstore/bad-bundle", "bundle has no Fulcio certificate (public_key bundles are not supported)");
}
function _chainDers(vm) {
  if (vm.x509CertificateChain && Array.isArray(vm.x509CertificateChain.certificates)) {
    return vm.x509CertificateChain.certificates.map(function (c, i) { return _certBytes(c, "x509CertificateChain[" + i + "]"); });
  }
  return [_leafCertDer(vm)];
}

function _rawVerify(keyObj, data, derSig) {
  var t = keyObj.asymmetricKeyType;
  if (t === "ed25519" || t === "ed448") {
    edwardsPoint.validateSpki(keyObj.export({ type: "spki", format: "der" }), t === "ed25519" ? 6 : 7, SigstoreError, "sigstore/bad-key");
    return nodeCrypto.verify(null, data, keyObj, derSig);
  }
  var crv = keyObj.asymmetricKeyDetails && keyObj.asymmetricKeyDetails.namedCurve;
  var hash = crv === "secp384r1" ? "sha384" : (crv === "secp521r1" ? "sha512" : "sha256");
  return nodeCrypto.verify(hash, data, { key: keyObj, dsaEncoding: "der" }, derSig);
}
function _pubFromSpki(spkiDer, label) {
  var key;
  try { key = nodeCrypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" }); }
  catch (e) { throw _err("sigstore/bad-key", "invalid " + label + " public key", e); }
  var t = key.asymmetricKeyType;
  if (t === "ed25519" || t === "ed448") {
    edwardsPoint.validateSpki(spkiDer, t === "ed25519" ? 6 : 7, SigstoreError, "sigstore/bad-key");
  }
  return key;
}
function _parseCert(der, label) {
  try { return x509.parse(der); }
  catch (e) { throw _err("sigstore/bad-certificate", "invalid " + label, e); }
}


function _sha256(buf) { return nodeCrypto.createHash("sha256").update(buf).digest(); }

function _toMs(x) {
  if (x == null) return null;
  if (typeof x === "number") return Number.isFinite(x) ? x : null;
  if (guard.time.isDate(x)) { var d = guard.time.instantOf(x); return isNaN(d) ? null : d; }
  if (typeof x === "string") { var t = Date.parse(x); return isNaN(t) ? null : t; }
  return null;
}
function _inWindow(timeMs, vf) {
  if (!vf) return true;
  if (vf.start != null) { var s = _toMs(vf.start); if (s === null || !(timeMs >= s)) return false; }
  if (vf.end != null) { var e = _toMs(vf.end); if (e === null || !(timeMs <= e)) return false; }
  return true;
}
function _rekorKey(rekorKeys, keyIdBuf, hint, timeMs) {
  for (var i = 0; i < rekorKeys.length; i++) {
    var k = rekorKeys[i];
    var match = (keyIdBuf && k.keyId && k.keyId.equals(keyIdBuf)) ||
      (hint && k.keyId && k.keyId.length >= 4 && k.keyId.subarray(0, 4).equals(hint));
    if (match && _inWindow(timeMs, k.validFor)) return k;
  }
  return null;
}

function _verifyCheckpoint(envelope, ip, rekorKeys, timeMs) {
  var buf = Buffer.from(envelope, "utf8");
  var sep = buf.indexOf("\n\n");
  if (sep < 0) throw _err("sigstore/bad-checkpoint", "the checkpoint has no note/signature separator");
  var body = buf.subarray(0, sep + 1);
  var lines = body.toString("utf8").split("\n");
  if (_b64(lines[2], "checkpoint root").toString("hex") !== _b64(ip.rootHash, "inclusionProof.rootHash").toString("hex")) {
    throw _err("sigstore/inclusion-proof-mismatch", "the checkpoint root does not match the inclusion-proof root");
  }
  var sigBlock = buf.subarray(sep + 2).toString("utf8").split("\n");
  for (var i = 0; i < sigBlock.length; i++) {
    var note = _parseNoteSig(sigBlock[i]);
    if (!note) continue;
    var blob = _b64(note.sig, "checkpoint signature");
    if (blob.length < 5) continue;
    var hint = blob.subarray(0, 4), derSig = blob.subarray(4);
    var k = _rekorKey(rekorKeys, null, hint, timeMs);
    if (!k) continue;
    if (_rawVerify(_pubFromSpki(k.spki, "Rekor log"), body, derSig)) return true;
  }
  return false;
}

function _verifySet(te, rekorKeys, timeMs) {
  var promise = te.inclusionPromise;
  if (!promise || typeof promise.signedEntryTimestamp !== "string") return false;
  var keyId = te.logId && te.logId.keyId ? _b64(te.logId.keyId, "logId.keyId") : null;
  var k = _rekorKey(rekorKeys, keyId, null, timeMs);
  if (!k) return false;
  var canonical = JSON.stringify({
    body: te.canonicalizedBody,
    integratedTime: Number(te.integratedTime),
    logID: keyId.toString("hex"),
    logIndex: Number(te.logIndex),
  });
  var sig = _b64(promise.signedEntryTimestamp, "signedEntryTimestamp");
  return _rawVerify(_pubFromSpki(k.spki, "Rekor log"), Buffer.from(canonical, "utf8"), sig);
}

function _bindEntry(te, envelope, leafDer) {
  var body = _jsonParse(_b64(te.canonicalizedBody, "canonicalizedBody"), "sigstore/bad-tlog-entry", "Rekor entry body");
  if (!body || typeof body !== "object" || Array.isArray(body)) throw _err("sigstore/bad-tlog-entry", "the Rekor entry body is not a JSON object");
  var spec = body.spec;
  if (body.kind !== "dsse" || !spec || typeof spec !== "object" || !Array.isArray(spec.signatures) || !spec.signatures.length ||
      !spec.signatures[0] || typeof spec.signatures[0] !== "object" || typeof spec.signatures[0].signature !== "string") {
    throw _err("sigstore/unsupported-content", "unsupported or malformed Rekor entry: " + body.kind);
  }
  var envSig = _b64(envelope.signatures[0].sig, "dsseEnvelope.signatures[0].sig");
  var bodySig = _b64(spec.signatures[0].signature, "Rekor entry signature");
  if (!envSig.equals(bodySig)) throw _err("sigstore/entry-mismatch", "the Rekor entry signature does not match the bundle signature");
  var payload = _b64(envelope.payload, "dsseEnvelope.payload");
  if (!spec.payloadHash || typeof spec.payloadHash.value !== "string") throw _err("sigstore/bad-tlog-entry", "the Rekor dsse entry is missing its payloadHash");
  if (spec.payloadHash.value !== _sha256(payload).toString("hex")) {
    throw _err("sigstore/entry-mismatch", "the Rekor entry payloadHash does not match the bundle payload");
  }
  var vf = spec.signatures[0].verifier;
  if (typeof vf !== "string") throw _err("sigstore/bad-tlog-entry", "the Rekor dsse entry is missing its verifier certificate");
  var vDer;
  try { vDer = x509.pemDecode(_b64(vf, "Rekor entry verifier").toString("utf8"), "CERTIFICATE"); }
  catch (e) { throw _err("sigstore/bad-tlog-entry", "the Rekor entry verifier is not a valid certificate", e); }
  if (!vDer.equals(leafDer)) throw _err("sigstore/entry-mismatch", "the Rekor entry verifier certificate does not match the bundle leaf certificate");
}

function _verifyRekor(te, envelope, rekorKeys, leafDer) {
  var ip = te.inclusionProof;
  if (!ip || typeof ip.rootHash !== "string" || !Array.isArray(ip.hashes)) {
    throw _err("sigstore/bad-inclusion-proof", "the transparency-log entry has no inclusion proof");
  }
  var claimedSec = Number(te.integratedTime);
  var claimedMs = Number.isFinite(claimedSec) ? C.TIME.seconds(claimedSec) : NaN;
  _bindEntry(te, envelope, leafDer);
  var included;
  try {
    included = merkle.verifyInclusion({
      leafIndex: BigInt(ip.logIndex),
      treeSize: BigInt(ip.treeSize),
      leafHash: merkle.leafHash(_b64(te.canonicalizedBody, "canonicalizedBody")),
      proof: ip.hashes.map(function (h, i) { return _b64(h, "inclusionProof.hashes[" + i + "]"); }),
      rootHash: _b64(ip.rootHash, "inclusionProof.rootHash"),
    });
  } catch (e) {
    throw _err("sigstore/bad-inclusion-proof", "the inclusion proof is malformed: " + e.message, e);
  }
  if (!included) throw _err("sigstore/inclusion-proof-mismatch", "the inclusion proof does not reconstruct the tree root");
  var checkpointOk = ip.checkpoint && typeof ip.checkpoint.envelope === "string" && _verifyCheckpoint(ip.checkpoint.envelope, ip, rekorKeys, claimedMs);
  if (!checkpointOk) throw _err("sigstore/unsigned-root", "the Rekor checkpoint (the signed tree root) did not verify under the caller Rekor key -- the inclusion-proof root is not attested");
  var setOk = _verifySet(te, rekorKeys, claimedMs);
  if (!setOk) throw _err("sigstore/unattested-time", "the Rekor SET (the signed source of integratedTime) did not verify -- the log time is not attested and cannot date the Fulcio certificate");
  var t = Number(te.integratedTime);
  if (!Number.isFinite(t) || t < 0) throw _err("sigstore/bad-tlog-entry", "the transparency-log entry has a malformed integratedTime");
  var li = Number(te.logIndex);
  return { integratedTime: t, logIndex: Number.isFinite(li) ? li : null, logId: te.logId && te.logId.keyId ? _b64(te.logId.keyId, "logId.keyId").toString("hex") : null };
}


function _dn(cert, which) { return cert[which] && cert[which].dn; }

function _normRoots(fulcioRoots) {
  return fulcioRoots.map(function (r, i) {
    var der = Buffer.isBuffer(r) ? r : (r && (r.der || r.rawBytes));
    if (!Buffer.isBuffer(der)) throw _err("sigstore/bad-input", "fulcioRoots[" + i + "] must be a DER Buffer or { der, validFor }");
    return { cert: _parseCert(der, "Fulcio CA root [" + i + "]"), validFor: (r && r.validFor) || null };
  });
}

function _pathToAnchor(leaf, anchor, intBySubject) {
  var anchorSubj = _dn(anchor, "subject");
  /** @internal Issuers are collected leaf-first and the path is assembled once, so no element is
   * ever moved to a new index: an indexed setter has nothing to intercept and cannot replace the
   * leaf the preceding signature checks authenticated. */
  var above = [], cur = leaf, seen = {}, guardN = 0;
  function assemble() {
    var path = [];
    for (var k = above.length - 1; k >= 0; k--) guard.list.append(path, above[k]);
    guard.list.append(path, leaf);
    return path;
  }
  while (guardN++ < 16) {
    var issuerDn = _dn(cur, "issuer");
    if (issuerDn === anchorSubj) return assemble();
    var cands = intBySubject[issuerDn] || [];
    var next = null;
    for (var j = 0; j < cands.length; j++) {
      if (cands[j] === anchor || seen[_dn(cands[j], "subject")]) continue;
      next = cands[j]; break;
    }
    if (!next) return null;
    seen[_dn(next, "subject")] = 1;
    guard.list.append(above, next);
    cur = next;
  }
  return null;
}

async function _verifyChain(leaf, chainDers, fulcioRoots, timeMs) {
  var roots = _normRoots(fulcioRoots);
  var bundleLinks = chainDers.slice(1).map(function (d, i) { return _parseCert(d, "bundle intermediate [" + i + "]"); });
  var intBySubject = {};
  function addInt(c) { guard.list.append(intBySubject[_dn(c, "subject")] = intBySubject[_dn(c, "subject")] || [], c); }
  roots.forEach(function (r) { addInt(r.cert); });
  bundleLinks.forEach(addInt);
  var candidates = roots.filter(function (r) { return _inWindow(timeMs, r.validFor); });
  var lastErr = _err("sigstore/chain-incomplete", "no caller-supplied Fulcio anchor (within its validity window) issues the chain");
  for (var i = 0; i < candidates.length; i++) {
    var anchor = candidates[i].cert;
    var path = _pathToAnchor(leaf, anchor, intBySubject);
    if (!path) continue;
    var spki = anchor.subjectPublicKeyInfo;
    try {
      var res = await pathValidate.validate(path, {
        time: new Date(timeMs),
        historicalMode: true,
        trustAnchors: { name: anchor.subject, publicKey: spki.bytes, algorithm: spki.algorithm.oid, parameters: spki.algorithm.parameters },
        requiredEku: ["codeSigning"],
      });
      if (res.valid) return;
      lastErr = _err("sigstore/chain-invalid", "the Fulcio certificate chain is not valid as of the log time");
    } catch (e) {
      lastErr = _err("sigstore/chain-invalid", "the Fulcio certificate chain failed validation: " + e.message, e);
    }
  }
  throw lastErr;
}


var SAN_OID = oid.byName("subjectAltName");
var FULCIO_PREFIX = oid.byName("otherName").split(".").slice(0, -1).join(".") + ".";
function _identity(leaf) {
  var out = { san: null, extensions: {} };
  try {
    (leaf.extensions || []).forEach(function (ext) {
      if (ext.oid === SAN_OID) { out.san = _sanValue(ext); return; }
      if (ext.oid.indexOf(FULCIO_PREFIX) === 0) {
        out.extensions[ext.name || ext.oid] = _fulcioExtValue(ext, Number(ext.oid.slice(FULCIO_PREFIX.length)));
      }
    });
  } catch (e) {
    if (e instanceof SigstoreError) throw e;
    throw _err("sigstore/bad-certificate", "the Fulcio certificate identity could not be decoded", e);
  }
  return out;
}
var GN_TYPE = { 1: "rfc822Name", 2: "dNSName", 6: "uri" };
function _sanValue(ext) {
  var seq = asn1.decode(ext.value);
  var names = [];
  for (var i = 0; i < (seq.children || []).length; i++) {
    var n = seq.children[i];
    if (n.tagClass !== "context") continue;
    var val = null;
    if (!n.constructed && GN_TYPE[n.tagNumber]) {
      val = { type: GN_TYPE[n.tagNumber], value: asn1.read.octetStringImplicit(n, n.tagNumber).toString("utf8") };
    } else if (n.constructed && n.tagNumber === 0 && (n.children || []).length >= 2) {
      var inner = (n.children[1].children || [])[0] || n.children[1];
      var v;
      try {
        v = asn1.read.string(inner);
      } catch (_e) {
        v = null;
      }
      val = { type: "otherName", oid: asn1.read.oid(n.children[0]), value: v };
    }
    if (val) guard.list.append(names, val);
  }
  if (names.length > 1) throw _err("sigstore/bad-certificate", "the Fulcio certificate carries multiple SAN identities");
  return names[0] || null;
}
function _fulcioExtValue(ext, leafArc) {
  if (!Buffer.isBuffer(ext.value)) throw _err("sigstore/bad-certificate", "Fulcio extension " + ext.oid + " has no value");
  if (leafArc >= 1 && leafArc <= 6) return ext.value.toString("utf8");
  return asn1.read.string(asn1.decode(ext.value));
}

var IDENTITY_FIELDS = ["san", "issuer", "sourceRepositoryURI"];
var IDENTITY_KEYS = { san: 1, issuer: 1, sourceRepositoryURI: 1 };
var _VERIFY_BUNDLE_OPTS = { fulcioRoots: 1, rekorKeys: 1, identity: 1, predicateType: 1, time: 1 };

function _checkIdentity(id, policy) {
  var ran = { san: false, issuer: false, sourceRepositoryURI: false };
  if (policy === undefined || policy === null) return ran;
  if (typeof policy !== "object" || Array.isArray(policy)) {
    throw _err("sigstore/bad-input", "opts.identity must be an object naming the identity fields to pin (" + IDENTITY_FIELDS.join(", ") + ")");
  }
  guard.identifier.assertKnownKeys(policy, IDENTITY_KEYS, _err, "sigstore/bad-input", "opts.identity has an unknown key ");
  var asked = IDENTITY_FIELDS.filter(function (f) { return policy[f] !== undefined; });
  if (!asked.length) {
    throw _err("sigstore/bad-input", "opts.identity constrains nothing -- name at least one of " + IDENTITY_FIELDS.join(", ") + ", or omit it to state that the signer is not being checked");
  }
  asked.forEach(function (f) {
    if (typeof policy[f] !== "string" || policy[f] === "") {
      throw _err("sigstore/bad-input", "opts.identity." + f + " must be a non-empty string -- a value that cannot be compared would leave the signer unchecked under a policy that names it");
    }
    ran[f] = true;
  });
  var sanValue = id.san && id.san.value;
  if (policy.san && sanValue !== policy.san) throw _err("sigstore/identity-mismatch", "the certificate SAN " + JSON.stringify(sanValue) + " does not match the expected identity");
  if (policy.issuer && policy.issuer !== id.extensions.issuer && policy.issuer !== id.extensions.issuerLegacy) throw _err("sigstore/identity-mismatch", "the certificate OIDC issuer does not match the expected issuer");
  if (policy.sourceRepositoryURI && id.extensions.sourceRepositoryURI !== policy.sourceRepositoryURI) throw _err("sigstore/identity-mismatch", "the certificate source-repository URI does not match");
  return ran;
}


function _statement(payload, payloadType, expectedPredicate) {
  if (payloadType !== "application/vnd.in-toto+json") {
    throw _err("sigstore/bad-statement", "unsupported DSSE payloadType: " + payloadType);
  }
  var st = _jsonParse(payload, "sigstore/bad-statement", "in-toto statement");
  if (!st || typeof st !== "object" || st._type !== "https://in-toto.io/Statement/v1") throw _err("sigstore/bad-statement", "the payload is not an in-toto Statement v1");
  if (!Array.isArray(st.subject) || !st.subject.length) throw _err("sigstore/bad-statement", "the in-toto statement has no subject");
  if (expectedPredicate && st.predicateType !== expectedPredicate) {
    throw _err("sigstore/predicate-mismatch", "the statement predicateType " + JSON.stringify(st.predicateType) + " does not match the expected " + JSON.stringify(expectedPredicate));
  }
  return st;
}


/**
 * @primitive pki.sigstore.verifyBundle
 * @signature pki.sigstore.verifyBundle(bundle, opts) -> Promise<result>
 * @since 0.2.3
 * @status stable
 * @spec DSSE, Sigstore bundle v0.3, RFC 9162, SLSA provenance v1
 * @related pki.sigstore.parseBundle, pki.sigstore.pae
 *
 * Verify a Sigstore bundle (an npm `--provenance` artifact) offline against
 * caller-supplied trust material, composing five fail-closed legs: the DSSE
 * signature over its PAE under the Fulcio leaf key; the Fulcio chain validated as
 * of the Rekor log time; the Rekor inclusion proof folded to a Rekor-signed root;
 * the log entry bound to this exact signature; and the in-toto SLSA statement.
 * Any leg failing throws a typed `sigstore/*` error. On success returns
 * `{ valid: true, verified: true, payload, statement, subjects, predicateType, predicate,
 * identity, identityChecked, predicateTypeChecked, integratedTime, logIndex, logId }` (`valid` is the
 * canonical toolkit-wide verdict alias of `verified`, `predicateTypeChecked` says whether a pinned
 * `opts.predicateType` was checked, and `logIndex` / `logId` identify the attested Rekor log entry).
 * `payload` is the raw verified
 * envelope bytes (never a re-serialization), and the caller confirms a
 * `subjects[].digest` matches the published artifact.
 *
 * `verified: true` says the artifact was signed and logged; it says nothing about
 * who. Fulcio issues a certificate to anyone who completes an OIDC flow, so who
 * signed is decided only by `opts.identity`, and `identityChecked` reports which of
 * its fields were compared (`{ san, issuer, sourceRepositoryURI }`, each a boolean).
 * An `identity` naming none of them is refused, since it would accept every signer
 * while reading as a policy; so is an unrecognized field name, which would otherwise
 * pin nothing under a spelling the operator believes constrains the signer.
 *
 * @opts
 *   fulcioRoots:   Array,      // the Fulcio CA anchors: a DER Buffer or { der, validFor } each
 *   rekorKeys:     Array,      // [{ keyId, spki, validFor? }] the Rekor log public keys
 *   identity:      object,     // optional policy: { san, issuer, sourceRepositoryURI }; at least one required when present
 *   predicateType: string,     // optional: require this in-toto predicateType (e.g. the SLSA URI)
 *   time:          Date,       // optional check-date override (default: the Rekor integratedTime)
 *
 * @example
 *   // requires: `bundle` from cosign / npm provenance, and `sigstoreTrust` built from
 *   // the public-good trusted_root.json (the Fulcio + Rekor material it pins)
 *   var out = await pki.sigstore.verifyBundle(bundle, sigstoreTrust);
 *   out.verified;            // true
 *   out.subjects[0].digest;  // { sha512: "..." } -- confirm against your tarball
 */
async function verifyBundle(bundle, opts) {
  if (bundle === null || typeof bundle !== "object" && typeof bundle !== "string" && !Buffer.isBuffer(bundle)) {
    throw new TypeError("verifyBundle: bundle must be an object, JSON string, or Buffer");
  }
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _VERIFY_BUNDLE_OPTS, _err, "sigstore/bad-input", "pki.sigstore.verifyBundle has an unknown option ");
  var b = parseBundle(bundle);
  var vm = b.verificationMaterial;
  var env = b.dsseEnvelope;
  var rekorKeys = opts.rekorKeys || [];
  var fulcioRoots = opts.fulcioRoots || [];

  var leafDer = _leafCertDer(vm);
  var leaf = _parseCert(leafDer, "Fulcio leaf certificate");
  var payload = _b64(env.payload, "dsseEnvelope.payload");
  var preimage = pae(env.payloadType, payload);
  var derSig = _b64(env.signatures[0].sig, "dsseEnvelope.signatures[0].sig");
  var leafKey = _pubFromSpki(leaf.subjectPublicKeyInfo.bytes, "Fulcio leaf");
  if (!_rawVerify(leafKey, preimage, derSig)) throw _err("sigstore/dsse-verify-failed", "the DSSE signature does not verify under the Fulcio leaf key");

  var tlogs = Array.isArray(vm.tlogEntries) ? vm.tlogEntries : [];
  if (!tlogs.length) throw _err("sigstore/bad-bundle", "a keyless bundle requires at least one transparency-log entry");
  var rekor = null, lastErr = null;
  for (var ti = 0; ti < tlogs.length; ti++) {
    if (!tlogs[ti] || typeof tlogs[ti] !== "object") { lastErr = _err("sigstore/bad-bundle", "a transparency-log entry is not an object"); continue; }
    try { rekor = _verifyRekor(tlogs[ti], env, rekorKeys, leafDer); break; }
    catch (e) { lastErr = e; }
  }
  if (rekor === null) throw lastErr;
  var integratedTime = rekor.integratedTime;

  var checkTime = guard.time.isDate(opts.time) ? guard.time.instantOf(opts.time) : C.TIME.seconds(integratedTime);
  await _verifyChain(leaf, _chainDers(vm), fulcioRoots, checkTime);
  var identity = _identity(leaf);
  var identityChecked = _checkIdentity(identity, opts.identity);

  var st = _statement(payload, env.payloadType, opts.predicateType);

  return guard.verdict.of({
    valid: true,
    verified: true,
    payload: payload,
    statement: st,
    subjects: st.subject,
    predicateType: st.predicateType,
    predicate: st.predicate,
    identity: identity,
    identityChecked: identityChecked,
    predicateTypeChecked: opts.predicateType != null,
    integratedTime: integratedTime,
    logIndex: rekor.logIndex,
    logId: rekor.logId,
  });
}

module.exports = {
  pae: pae,
  parseBundle: parseBundle,
  verifyBundle: verifyBundle,
};
