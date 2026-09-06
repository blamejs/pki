// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// the operator-facing @module pki.cmc + the @primitive pki.cmc.build documentation block live in


var nodeCrypto = require("node:crypto");
var asn1 = require("./asn1-der");
var pkiBuild = require("./pki-build");
var csr = require("./schema-csr");
require("./path-validate");
var csrVerify = require("./csr-verify");
var crmf = require("./schema-crmf");
var cmcFmt = require("./schema-cmc");
var oid = require("./oid");
var cmsSign = require("./cms-sign");
var cmsEncrypt = require("./cms-encrypt");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _isArray = intrinsic.isArray;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferConcat = intrinsic.bufferConcat;
var frameworkError = require("./framework-error");

var CmcError = frameworkError.CmcError;
var b = asn1.build;
function E(code, message, cause) { return new CmcError(code, message, cause); }
function O(name) { return oid.byName(name); }

var OID_IDENTITY_PROOF_V2 = O("id-cmc-identityProofV2");
var OID_POP_LINK_RANDOM = O("id-cmc-popLinkRandom");
var OID_IDENTIFICATION = O("id-cmc-identification");
var OID_SHA256 = O("sha256");
var OID_HMAC_SHA256 = O("hmacWithSHA256");

var RENEWAL_FORBIDDEN = intrinsic.create(null);
RENEWAL_FORBIDDEN[OID_IDENTIFICATION] = "Identification";
RENEWAL_FORBIDDEN[O("id-cmc-identityProof")] = "Identity Proof";
RENEWAL_FORBIDDEN[OID_IDENTITY_PROOF_V2] = "Identity Proof V2";

var OID_RESPONSE_BODY = O("id-cmc-responseBody");

var POP_LINK_RANDOM_BYTES = 64;

var KNOWN_SPEC_KEYS = intrinsic.assign(intrinsic.create(null), {
  requests: 1, controls: 1, cmsSequence: 1, otherMsgSequence: 1,
  identityProof: 1, popLink: 1, renewal: 1,
  transactionId: 1, senderNonce: 1, dataReturn: 1,
});

var OID_TRANSACTION_ID = O("id-cmc-transactionId");
var OID_SENDER_NONCE = O("id-cmc-senderNonce");
var OID_DATA_RETURN = O("id-cmc-dataReturn");

function algId(o) { return b.sequence([b.oid(o)]); }


function makeIdAllocator() {
  var used = Object.create(null);
  var pending = Object.create(null);
  var next = 1;
  function assertValid(requested, what) {
    if (typeof requested !== "number" || !Number.isInteger(requested) || requested < 0 || requested > 4294967295) {
      throw E("cmc/bad-input", "a bodyPartID must be an integer in 0..4294967295, got " + guard.text.showValue(requested) + " (" + what + ")");
    }
    if (requested === 0) {
      throw E("cmc/bad-input",
        "bodyPartID 0 is reserved as the reference to the current PKIData and cannot identify " + what + " (RFC 5272 sec. 3.2.2)");
    }
  }
  return {
    reserve: function (requested, what) {
      assertValid(requested, what);
      if (used[requested]) {
        throw E("cmc/bad-input",
          "bodyPartID " + requested + " is used more than once; identifiers MUST be unique within a single PKIData (RFC 5272 sec. 3.2.2)");
      }
      used[requested] = true;
      pending[requested] = true;
      return requested;
    },
    claim: function (requested, what) {
      if (requested == null) {
        while (used[next]) next += 1;
        used[next] = true;
        return next;
      }
      assertValid(requested, what);
      if (pending[requested]) { delete pending[requested]; return requested; }
      if (used[requested]) {
        throw E("cmc/bad-input",
          "bodyPartID " + requested + " is used more than once; identifiers MUST be unique within a single PKIData (RFC 5272 sec. 3.2.2)");
      }
      used[requested] = true;
      return requested;
    },
  };
}


var KNOWN_REQUEST_KEYS = intrinsic.assign(intrinsic.create(null), { tcr: 1, crm: 1, orm: 1, bodyPartID: 1 });
var KNOWN_CONTROL_KEYS = intrinsic.assign(intrinsic.create(null), { type: 1, value: 1 });
var KNOWN_IDENTITY_PROOF_KEYS = intrinsic.assign(intrinsic.create(null), { identity: 1, secret: 1 });
var KNOWN_POP_LINK_KEYS = intrinsic.assign(intrinsic.create(null), { secret: 1 });
var KNOWN_MAC_KEYS = intrinsic.assign(intrinsic.create(null), { identifier: 1, secret: 1 });
var KNOWN_MAC_CARRIER_KEYS = intrinsic.assign(intrinsic.create(null), { mac: 1 });
var UTF8_STRING_TAG = 12;

/** @internal Whether two caller-supplied secrets are the same secret, comparing the bytes each spells
 * out so a string and the same bytes are not read as two different credentials. Compared in constant
 * time: the two values come from one caller here, but the primitive is the one this toolkit compares
 * secret-derived bytes with everywhere. */
function _sameSecret(a, byIdentity) {
  var ab = null, bb = null;
  try {
    ab = _secretCopy(a, "the shared secret");
    bb = _secretCopy(byIdentity, "the identityProof secret");
    return ab !== null && bb !== null && ab.length === bb.length && guard.crypto.constantTimeEqual(ab, bb);
  } finally {
    /** @internal Both copies, on every exit: one input being unusable is the path that leaves the other
     * one allocated, and a comparison that refuses is still a comparison that copied. */
    var made = [];
    if (ab) guard.list.append(made, ab);
    if (bb) guard.list.append(made, bb);
    if (made.length) guard.secret.zeroizeAll(made, CmcError, "cmc/bad-input", "the compared shared-secret copies");
  }
}
function _secretCopy(v, what) {
  if (typeof v === "string") return _bufferFrom(v, "utf8");
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmcError, "cmc/bad-input", what);
  return null;
}

/** @internal The key a shared-secret carrier derives its MAC key from: the identifier encoded as UTF-8
 * followed by the shared secret (RFC 5272 sec. 3.2(c)). Both halves of the toolkit read this one
 * function, so a request it builds and a message it authenticates derive the same bytes. The caller
 * owns the returned buffer and wipes it. */
function macPassword(mac) {
  if (!mac || typeof mac !== "object" || _isArray(mac) || _isBuffer(mac)) {
    throw E("cmc/bad-input", "a shared-secret carrier is { identifier, secret } (RFC 5272 sec. 3.2)");
  }
  guard.identifier.assertKnownKeys(mac, KNOWN_MAC_KEYS, E, "cmc/bad-input", "unknown shared-secret field ");
  if (typeof mac.identifier !== "string" || mac.identifier.length === 0) {
    throw E("cmc/bad-input", "a shared-secret carrier needs the identifier the authority knows the client by, as a non-empty string (RFC 5272 sec. 3.2)");
  }
  if (typeof mac.secret !== "string" && !guard.bytes.isByteSource(mac.secret)) {
    throw E("cmc/bad-input", "a shared-secret carrier needs the secret as a string or bytes (RFC 5272 sec. 3.2)");
  }
  var secretBytes = typeof mac.secret === "string" ? _bufferFrom(mac.secret, "utf8")
    : guard.bytes.snapshotSource(mac.secret, CmcError, "cmc/bad-input", "the shared secret");
  if (secretBytes.length === 0) {
    guard.secret.zeroize(secretBytes, CmcError, "cmc/bad-input", "the shared secret");
    throw E("cmc/bad-input", "a shared-secret carrier needs a non-empty secret (RFC 5272 sec. 3.2)");
  }
  var idBytes = _bufferFrom(mac.identifier, "utf8");
  var joined = _bufferConcat([idBytes, secretBytes]);
  guard.secret.zeroizeAll([idBytes, secretBytes], CmcError, "cmc/bad-input", "the shared-secret encoding");
  return joined;
}

function fixedRequestId(req, index) {
  if (!req || typeof req !== "object") throw E("cmc/bad-input", "each request must be an object");
  guard.identifier.assertKnownKeys(req, KNOWN_REQUEST_KEYS, E, "cmc/bad-input", function (k) {
    return "unknown field " + JSON.stringify(k) + " on request " + index +
      " -- a request names one of tcr / crm / orm, and optionally bodyPartID";
  });
  var arms = ["tcr", "crm", "orm"].filter(function (k) { return req[k] != null; });
  if (arms.length !== 1) {
    throw E("cmc/bad-input",
      "each request names exactly one of tcr / crm / orm, got " + (arms.length ? arms.join(" + ") : "none") +
      " (request " + index + ")");
  }
  if (req.crm != null) {
    var crmId = _certReqIdOf(_asCertReqMsg(_der(req.crm, "a crm CertReqMsg")));
    if (req.bodyPartID != null && _asBigInt(req.bodyPartID, "a crm request bodyPartID") !== BigInt(crmId)) {
      throw E("cmc/bad-input",
        "a crm request's bodyPartID is its CertReqMsg's own certReqId (" + crmId + "), which cannot be " +
        "overridden; request " + index + " supplies " + req.bodyPartID);
    }
    return crmId;
  }
  return req.bodyPartID == null ? null : req.bodyPartID;
}

async function _assertTcrPops(requests) {
  for (var i = 0; i < requests.length; i++) {
    if (requests[i] && requests[i].tcr != null) await _assertOneTcrPop(requests[i].tcr, i);
  }
}
async function _assertOneTcrPop(tcr, i) {
  var parsed = csr.parse(_der(tcr, "a tcr certificationRequest"));
  if (!(await csrVerify.verifyCsrSignature(parsed))) {
    throw E("cmc/bad-popo", "a tcr request [" + i + "] failed its proof-of-possession: the PKCS#10 signature does not verify under the request's own subject public key (RFC 5272 sec. 6.3), so a CA would reject it -- refusing it here rather than signing it");
  }
}

function encodeRequest(req, ids, index) {
  if (req.tcr != null) {
    try { csr.parse(_der(req.tcr, "a tcr certificationRequest")); }
    catch (e) {
      throw E("cmc/bad-input", "a tcr request must be a PKCS#10 CertificationRequest: " +
        (e && e.message ? e.message : "it did not parse as one"), e);
    }
    var id = ids.claim(req.bodyPartID, "a tcr request");
    return { bodyPartID: id, der: b.contextConstructed(0, Buffer.concat([b.integer(BigInt(id)), _der(req.tcr, "a tcr certificationRequest")])) };
  }
  if (req.crm != null) {
    var msg = _asCertReqMsg(_der(req.crm, "a crm CertReqMsg"));
    try { crmf.parse(b.sequence([msg])); }
    catch (e) {
      throw E("cmc/bad-input", "a crm request must be an RFC 4211 CertReqMsg: " +
        (e && e.message ? e.message : "it did not parse as one"), e);
    }
    var certReqId = ids.claim(_certReqIdOf(msg), "a crm request");
    var node = asn1.decode(msg);
    var headerLen = node.header.end - node.header.start;
    return { bodyPartID: certReqId, der: b.contextConstructed(1, node.bytes.subarray(headerLen)) };
  }
  var orm = req.orm;
  if (!orm || typeof orm !== "object" || orm.type == null || orm.value == null) {
    throw E("cmc/bad-input", "an orm request is { type, value } (request " + index + ")");
  }
  var ormId = ids.claim(req.bodyPartID, "an orm request");
  return {
    bodyPartID: ormId,
    der: b.contextConstructed(2, Buffer.concat([
      b.integer(BigInt(ormId)), b.oid(_oidOf(orm.type)), _der(orm.value, "an orm requestMessageValue")])),
  };
}

function _asCertReqMsg(der) {
  var node = asn1.decode(der);
  var first = node.children && node.children[0];
  if (!first || !first.children || !first.children.length) {
    throw E("cmc/bad-input", "a crm arm must be a CertReqMsg or a CertReqMessages carrying one");
  }
  var grand = first.children[0];
  if (grand.tagClass === "universal" && grand.tagNumber === asn1.TAGS.INTEGER) return der;
  if (node.children.length !== 1) {
    throw E("cmc/bad-input",
      "a crm arm carries exactly one CertReqMsg; this CertReqMessages holds " + node.children.length +
      " -- pass each as its own request so each keeps its own certReqId");
  }
  return first.bytes;
}

function _certReqIdOf(msg) {
  var node = asn1.decode(msg);
  var certReq = node.children && node.children[0];
  if (!certReq || !certReq.children || !certReq.children.length) {
    throw E("cmc/bad-input", "a crm CertReqMsg must lead with a CertRequest whose first element is certReqId");
  }
  var v = asn1.read.integer(certReq.children[0]);
  return guard.range.int(v, 0n, 4294967295n, E, "cmc/bad-input", "a crm certReqId");
}

function _claimRawElement(el, ids, what) {
  var der = _der(el, what);
  var node = asn1.decode(der);
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || !node.children.length) {
    throw E("cmc/bad-input", what + " must be a SEQUENCE leading with its bodyPartID");
  }
  var v = asn1.read.integer(node.children[0]);
  var id = guard.range.int(v, 0n, 4294967295n, E, "cmc/bad-input", what + " bodyPartID");
  ids.claim(id, what);
  return der;
}

var BINDING_BY_OID = intrinsic.create(null);
BINDING_BY_OID[O("id-cmc-transactionId")] = "transactionId";
BINDING_BY_OID[O("id-cmc-senderNonce")] = "senderNonce";
BINDING_BY_OID[O("id-cmc-dataReturn")] = "dataReturn";

var BINDING_READER = intrinsic.assign(intrinsic.create(null), {
  transactionId: function (node) { return asn1.read.integer(node); },
  senderNonce: function (node) { return asn1.read.octetString(node); },
  dataReturn: function (node) { return asn1.read.octetString(node); },
});
var BINDING_TYPE_NAME = intrinsic.assign(intrinsic.create(null), {
  transactionId: "an INTEGER (RFC 5272 sec. 6.6)",
  senderNonce: "an OCTET STRING (RFC 5272 sec. 6.6)",
  dataReturn: "an OCTET STRING (RFC 5272 sec. 6.4)",
});

function _assertNoDuplicateBinding(callerControls, spec) {
  var seen = intrinsic.create(null);
  callerControls.forEach(function (c) {
    var field = BINDING_BY_OID[_oidOf(c.type)];
    if (!field) return;
    try { BINDING_READER[field](asn1.decode(_der(c.value, "a control value"))); }
    catch (e) {
      throw E("cmc/bad-input",
        "a hand-encoded " + field + " control must carry " + BINDING_TYPE_NAME[field] +
        "; this one cannot be read as that, so the request would be signed with a binding value " +
        "nothing can compare a response against", e);
    }
    if (seen[field] || spec[field] != null) {
      throw E("cmc/bad-input",
        "the " + field + " control would be emitted twice (spec." + field + " and a control in " +
        "spec.controls, or two in spec.controls); a message carrying two leaves no single value the " +
        "response can be bound to (RFC 5272 sec. 6.6 / 6.4)");
    }
    seen[field] = true;
  });
}

function _asBigInt(v, what) { return guard.range.authoredInteger(v, E, "cmc/bad-input", what); }

function _der(v, what) {
  if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmcError, "cmc/bad-input", what);
  throw E("cmc/bad-input", what + " must be DER bytes");
}
function _oidOf(v) {
  if (typeof v !== "string") throw E("cmc/bad-input", "an OID must be a name or a dotted string");
  return oid.isDottedDecimal(v) ? v : O(v);
}


var REQUEST_FORBIDDEN_CONTROL = intrinsic.create(null);
REQUEST_FORBIDDEN_CONTROL[OID_RESPONSE_BODY] =
  "id-cmc-responseBody may appear only in the control sequence of a PKIResponse (RFC 6402 sec. 2.6)";
REQUEST_FORBIDDEN_CONTROL[O("id-cmc-statusInfo")] =
  "a CMC Status Info control reports a server's verdict on a request, so it belongs in a PKI Response, " +
  "not in the request itself (RFC 5272 sec. 6.1)";
REQUEST_FORBIDDEN_CONTROL[O("id-cmc-statusInfoV2")] =
  "an Extended CMC Status Info control reports a server's verdict on a request, so it belongs in a PKI " +
  "Response, not in the request itself (RFC 5272 sec. 6.1)";

function encodeControl(attrType, values, ids) {
  if (REQUEST_FORBIDDEN_CONTROL[attrType]) {
    throw E("cmc/control-misplaced", REQUEST_FORBIDDEN_CONTROL[attrType]);
  }
  var id = ids.claim(null, "a control");
  return b.sequence([b.integer(BigInt(id)), b.oid(attrType), b.set(values)]);
}


function _assertSecret(secret, what) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw E("cmc/bad-input",
      what + " requires the shared secret as a non-empty string; got " +
      (typeof secret === "string" ? "an empty string" : typeof secret));
  }
}

function _ownSecret(buf, owned) {
  owned.push(buf);
  return buf;
}

function identityProofV2(secret, reqSequenceBytes, identity) {
  _assertSecret(secret, "an Identity Proof V2 control");
  var owned = [];
  var key = null;
  try {
    var material;
    if (identity == null) {
      material = _ownSecret(Buffer.from(secret, "utf8"), owned);
    } else {
      material = _ownSecret(Buffer.concat([
        _ownSecret(Buffer.from(secret, "utf8"), owned),
        _ownSecret(Buffer.from(identity, "utf8"), owned),
      ]), owned);
    }
    key = nodeCrypto.createHash("sha256").update(material).digest();
    var witness = nodeCrypto.createHmac("sha256", key).update(reqSequenceBytes).digest();
    return b.sequence([algId(OID_SHA256), algId(OID_HMAC_SHA256), b.octetString(witness)]);
  } finally {
    if (key) guard.secret.zeroize(key, CmcError, "cmc/bad-input", "the Identity Proof MAC key");
    guard.secret.zeroizeAll(owned, CmcError, "cmc/bad-input", "the Identity Proof derivation input");
  }
}

function popLinkWitnessV2(secret, R) {
  _assertSecret(secret, "a POP Link Witness V2 control");
  var key = nodeCrypto.createHash("sha256").update(secret, "utf8").digest();
  var witness = nodeCrypto.createHmac("sha256", key).update(R).digest();
  try {
    return b.sequence([algId(OID_SHA256), algId(OID_HMAC_SHA256), b.octetString(witness)]);
  } finally {
    guard.secret.zeroize(key, CmcError, "cmc/bad-input", "the POP Link MAC key");
  }
}

// The operator-facing @primitive block for this function lives beside its
// re-export in cmc-verify.js, the pki.cmc @module home.
function build(spec, signer, opts) {
  return guard.bytes.fixedCall(CmcError, "cmc/bad-input", [
    [spec, "the CMC request spec"], [signer, "the signer"], [opts, "pki.cmc.build options"],
  ], _build);
}

async function _build(spec, signer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Array.isArray(spec) || Buffer.isBuffer(spec)) {
    throw E("cmc/bad-input", "the CMC request spec must be an object");
  }
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw E("cmc/bad-input", "pki.cmc.build options must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, E, "cmc/bad-input", "unknown spec field ");
  var requests = spec.requests != null ? pkiBuild.reqDenseArray(spec.requests, "requests", E, "cmc/bad-input") : [];
  if (!Array.isArray(requests)) throw E("cmc/bad-input", "spec.requests must be an array");
  var callerControls = spec.controls || [];
  if (!Array.isArray(callerControls)) throw E("cmc/bad-input", "spec.controls must be an array");

  var ids = makeIdAllocator();

  requests.forEach(function (r, i) {
    var fixed = fixedRequestId(r, i);
    if (fixed != null) ids.reserve(fixed, "request " + i);
  });
  var cmsSequence = (spec.cmsSequence != null ? pkiBuild.reqDenseArray(spec.cmsSequence, "cmsSequence", E, "cmc/bad-input") : []).map(function (el, i) {
    return _claimRawElement(el, ids, "a cmsSequence element (index " + i + ")");
  });
  var otherMsgSequence = (spec.otherMsgSequence != null ? pkiBuild.reqDenseArray(spec.otherMsgSequence, "otherMsgSequence", E, "cmc/bad-input") : []).map(function (el, i) {
    return _claimRawElement(el, ids, "an otherMsgSequence element (index " + i + ")");
  });

  var encodedRequests = requests.map(function (r, i) { return encodeRequest(r, ids, i); });
  var reqSequenceBytes = b.sequence(encodedRequests.map(function (r) { return r.der; }));

  if (spec.renewal) {
    if (spec.identityProof) {
      throw E("cmc/bad-input",
        "a renewal request carries no Identity Proof control -- the Identification and Identity Proof controls are absent (RFC 5272 sec. 3.2 (a))");
    }
    for (var ci = 0; ci < callerControls.length; ci++) {
      var forbidden = RENEWAL_FORBIDDEN[_oidOf(callerControls[ci].type)];
      if (forbidden) {
        throw E("cmc/bad-input",
          "a renewal request carries no " + forbidden + " control (RFC 5272 sec. 3.2 (a))");
      }
    }
    /** @internal A renewal carries no Identification or Identity Proof control because, in sec. 3.2(a)'s
     * words, "the same information is provided by the use of an existing certificate from a CA when
     * signing the PKI Request". A shared secret authenticates the message without naming any
     * certificate, so a renewal carried that way would assert an identity by nothing at all. */
    if (signer && typeof signer === "object" && !_isArray(signer) && signer.mac != null) {
      throw E("cmc/bad-signer",
        "a renewal request is signed with the certificate being renewed, which is what carries the " +
        "original identity in place of the Identification and Identity Proof controls (RFC 5272 sec. 3.2 (a)); " +
        "a shared secret names no certificate, so it cannot renew");
    }
    var renewalSigners = _isArray(signer) ? signer : [signer];
    for (var si = 0; si < renewalSigners.length; si++) {
      var rs = renewalSigners[si];
      if (rs && rs.cert == null && rs.spki != null) {
        throw E("cmc/bad-signer",
          "a renewal request is signed with the certificate being renewed, which is what associates the " +
          "original identity with it (RFC 5272 sec. 6.3.3); a key-only signer carries no such identity");
      }
    }
  }

  var controls = [];
  /** @internal The names a caller-written Identification control gives this client, collected as those
   * controls are encoded so the name checked is the name carried (RFC 5272 sec. 6.2.3). */
  var controlIdentifiers = [], controlIdentificationCount = 0, controlIdentifierUnreadable = false;
  callerControls.forEach(function (c) {
    if (!c || typeof c !== "object" || c.type == null || c.value == null) {
      throw E("cmc/bad-input", "each control is { type, value }");
    }
    guard.identifier.assertKnownKeys(c, KNOWN_CONTROL_KEYS, E, "cmc/bad-input", function (k) {
      return "unknown field " + JSON.stringify(k) + " on a control -- a control is { type, value }, " +
        "and its bodyPartID is allocated by the builder";
    });
    /** @internal Taken once. A control is a caller object, so reading `type` or `value` a second time
     * can answer differently than it did here, and what this request is checked against has to be what
     * it carries. The Identification name below is read off THESE bytes for the same reason. */
    var controlType = _oidOf(c.type);
    var controlValue = _der(c.value, "a control value");
    if (controlType === OID_IDENTIFICATION) {
      controlIdentificationCount += 1;
      var idNode;
      try { idNode = asn1.decode(controlValue); }
      catch (_e) { controlIdentifierUnreadable = true; }
      /** @internal The control is a UTF8String (RFC 5272 sec. 6.2.3). Another string type carrying the
       * same characters is a different value on the wire, so it cannot stand in for the control this
       * request needs while a strict authority refuses the message. */
      if (idNode && idNode.tagClass === "universal" && idNode.tagNumber === UTF8_STRING_TAG) {
        guard.list.append(controlIdentifiers, asn1.read.string(idNode));
      } else {
        controlIdentifierUnreadable = true;
      }
    }
    controls.push(encodeControl(controlType, [controlValue], ids));
  });

  _assertNoDuplicateBinding(callerControls, spec);
  if (spec.transactionId != null) {
    controls.push(encodeControl(OID_TRANSACTION_ID,
      [b.integer(_asBigInt(spec.transactionId, "spec.transactionId"))], ids));
  }
  if (spec.senderNonce != null) {
    controls.push(encodeControl(OID_SENDER_NONCE,
      [b.octetString(_der(spec.senderNonce, "spec.senderNonce"))], ids));
  }
  if (spec.dataReturn != null) {
    controls.push(encodeControl(OID_DATA_RETURN,
      [b.octetString(_der(spec.dataReturn, "spec.dataReturn"))], ids));
  }

  /** @internal The name the request gives the authority for this client, from whichever of the two
   * places names it. Read before either control is emitted, so the pair can be compared. */
  var macIdentifier = signer && typeof signer === "object" && !_isArray(signer) && signer.mac != null &&
    typeof signer.mac === "object" && typeof signer.mac.identifier === "string" ? signer.mac.identifier : null;
  var identityIdentifier = spec.identityProof && typeof spec.identityProof.identity === "string"
    ? spec.identityProof.identity : null;

  /** @internal Settled BEFORE the Identity Proof witness is computed, because the presence of an
   * Identification control changes how that witness is derived: with one, the hash is over the secret
   * and the identity together rather than the secret alone (RFC 5272 sec. 6.2.3). A name reaching the
   * request from anywhere therefore has to be known here, or the witness is derived one way and the
   * request carries the control that demands the other. */
  var carriedIdentity = identityIdentifier;
  if (carriedIdentity == null && controlIdentifiers.length > 0) carriedIdentity = controlIdentifiers[0];
  if (carriedIdentity == null) carriedIdentity = macIdentifier;

  if (spec.identityProof) {
    guard.identifier.assertKnownKeys(spec.identityProof, KNOWN_IDENTITY_PROOF_KEYS, E, "cmc/bad-input",
      function (k) { return "unknown field " + JSON.stringify(k) + " on identityProof -- it is { secret, identity? }"; });
    var identity = spec.identityProof.identity;
    if (identity != null && typeof identity !== "string") {
      throw E("cmc/bad-input", "identityProof.identity is the UTF8String the Identification control carries");
    }
    if (identity != null) controls.push(encodeControl(OID_IDENTIFICATION, [b.utf8(identity)], ids));
    controls.push(encodeControl(OID_IDENTITY_PROOF_V2,
      [identityProofV2(spec.identityProof.secret, reqSequenceBytes, carriedIdentity)], ids));
  }

  /** @internal A PasswordRecipientInfo names no recipient, so an authority holding secrets for many
   * clients has nothing in the carrier to select one by. The Identification control is what carries
   * that name: it "assists the server in locating the shared-secret" (RFC 5272 sec. 6.2.3), so a
   * request authenticated by a secret says whose secret it is. Two names for one client is refused
   * rather than picked between. */
  if (macIdentifier != null) {
    var named = [];
    for (var nc = 0; nc < controlIdentifiers.length; nc++) guard.list.append(named, controlIdentifiers[nc]);
    if (identityIdentifier != null) guard.list.append(named, identityIdentifier);
    for (var ni = 0; ni < named.length; ni++) {
      if (named[ni] !== macIdentifier) {
        throw E("cmc/bad-input",
          "the shared-secret identifier and the Identification the request already carries name the same " +
          "client to the authority, so a request cannot carry two different ones (RFC 5272 sec. 6.2.3)");
      }
    }
    if (controlIdentifierUnreadable) {
      throw E("cmc/bad-input",
        "the Identification control this request carries does not read as the UTF8String the client is " +
        "named by, so it cannot be confirmed to name the client whose secret authenticates the request (RFC 5272 sec. 6.2.3)");
    }
    /** @internal One client, one shared secret. The carrier's MAC and an Identity Proof witness are both
     * keyed from "the shared-secret" (RFC 5272 sec. 3.2 and 6.2.1), so two different ones would leave an
     * authority able to check one and not the other, and unable to tell which credential is the client's. */
    if (spec.identityProof && !_sameSecret(signer.mac.secret, spec.identityProof.secret)) {
      throw E("cmc/bad-input",
        "the shared secret that authenticates this request and the one its Identity Proof is computed " +
        "from are the same secret, so a request cannot carry two different ones (RFC 5272 sec. 3.2 / 6.2.1)");
    }
    /** @internal One request names one client once. Two controls saying the same thing still leave an
     * authority choosing between them, so the request carries exactly one however it was assembled. */
    var alreadyNamed = controlIdentificationCount + (identityIdentifier == null ? 0 : 1);
    if (alreadyNamed > 1) {
      throw E("cmc/bad-input",
        "a request names its client once, and this one carries " + alreadyNamed + " Identification controls " +
        "(RFC 5272 sec. 6.2.3)");
    }
    if (alreadyNamed === 0) {
      guard.list.append(controls, encodeControl(OID_IDENTIFICATION, [b.utf8(macIdentifier)], ids));
    }
  }

  if (spec.popLink) {
    guard.identifier.assertKnownKeys(spec.popLink, KNOWN_POP_LINK_KEYS, E, "cmc/bad-input",
      function (k) { return "unknown field " + JSON.stringify(k) + " on popLink -- it is { secret }"; });
    var rBytes = opts.popLinkRandomBytes == null ? POP_LINK_RANDOM_BYTES : opts.popLinkRandomBytes;
    if (typeof rBytes !== "number" || !Number.isInteger(rBytes) || rBytes < 1) {
      throw E("cmc/bad-input", "popLinkRandomBytes must be a positive integer");
    }
    var R = nodeCrypto.randomBytes(rBytes);
    controls.push(encodeControl(OID_POP_LINK_RANDOM, [b.octetString(R)], ids));
    controls.push(encodeControl(O("id-cmc-popLinkWitnessV2"),
      [popLinkWitnessV2(spec.popLink.secret, R)], ids));
  }

  var pkiData = b.sequence([
    b.sequence(controls),
    b.raw(reqSequenceBytes),
    b.sequence(cmsSequence),
    b.sequence(otherMsgSequence),
  ]);

  try {
    cmcFmt.parsePkiData(pkiData);
  } catch (e) {
    throw E("cmc/bad-input",
      "the assembled PKIData does not parse as one, so it would be refused by its recipient: " +
      (e && e.message ? e.message : "malformed"), e);
  }

  /** @internal RFC 5272 sec. 3.2 gives a Full PKI Request two carriers, and a request uses one: a
   * SignedData signed by a key, or an AuthenticatedData whose MAC a shared secret keys. A client
   * enrolling under a secret has no key to sign with, so naming both is a contradiction rather than a
   * preference. */
  if (signer && typeof signer === "object" && !_isArray(signer) && signer.mac != null) {
    if (signer.key != null || signer.cert != null || signer.spki != null || signer.keyIdentifier != null) {
      throw E("cmc/bad-input", "a request is carried by a signature or by a shared secret, not both (RFC 5272 sec. 3.2)");
    }
    guard.identifier.assertKnownKeys(signer, KNOWN_MAC_CARRIER_KEYS, E, "cmc/bad-input", "unknown shared-secret carrier field ");
    var macBytes = macPassword(signer.mac);
    try {
      await _assertTcrPops(requests);
      /** @internal The Password Recipient Info option, which sec. 3.2(a) requires, is what the CMS
       * producer selects for a password recipient, and it generates the MAC key sec. 3.2(b) calls for. */
      return await cmsEncrypt.authenticate(pkiData, [{ password: macBytes }],
        { contentType: "id-cct-PKIData", pem: opts.pem });
    } finally {
      guard.secret.zeroize(macBytes, CmcError, "cmc/bad-input", "the derived shared-secret key");
    }
  }

  _assertKeyOnlySigner(signer, requests);

  var ownedKeyBytes = [];
  var copiedSigner = _copySigners(signer, ownedKeyBytes);
  function _wipeOwnedKeys() {
    if (ownedKeyBytes.length) guard.secret.zeroizeAll(ownedKeyBytes, CmcError, "cmc/bad-input", "the signer key copy");
    ownedKeyBytes.length = 0;
  }
  try {
    await _assertTcrPops(requests);
    return await cmsSign.sign(pkiData, copiedSigner, { eContentType: "id-cct-PKIData", pem: opts.pem });
  } finally {
    _wipeOwnedKeys();
  }
}

function _copySigners(signer, owned) {
  function one(s) {
    if (!s || typeof s !== "object") return s;
    var out = intrinsic.create(null), k;
    for (k in s) {
      if (!_hasOwn(s, k)) continue;
      out[k] = copyValue(s[k], k === "key");
    }
    return out;
  }
  function copyValue(v, isSecret) {
    if (!isSecret) {
      if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, CmcError, "cmc/bad-input", "a signer field");
      return v;
    }
    if (Buffer.isBuffer(v) || v instanceof Uint8Array) return _own(Buffer.from(v), true);   // allow:byte-source-narrow -- private key bytes (Buffer borrowed / Uint8Array copied+wiped)
    if (!v || typeof v !== "object" || typeof v.type === "string") return v;
    var c = intrinsic.create(null), ck;
    for (ck in v) {
      if (!_hasOwn(v, ck)) continue;
      var cv = v[ck];
      c[ck] = (Buffer.isBuffer(cv) || cv instanceof Uint8Array) ? _own(Buffer.from(cv), true) : cv;   // allow:byte-source-narrow -- composite key component
    }
    return c;
  }
  function _own(buf, isSecret) {
    if (isSecret && owned) owned.push(buf);
    return buf;
  }
  return Array.isArray(signer) ? signer.map(one) : one(signer);
}


function _assertKeyOnlySigner(signer, requests) {
  var all = Array.isArray(signer) ? signer : [signer];
  var keyOnly = all.filter(function (x) { return x && x.cert == null && x.spki != null; });
  if (!keyOnly.length) return;
  if (all.length !== 1) {
    throw E("cmc/bad-signer",
      "a Full PKI Request signed with a certification request's own key MUST carry exactly one SignerInfo, " +
      "got " + all.length + " (RFC 5272 sec. 3.2)");
  }
  keyOnly.forEach(function (so) { _assertKeyOnlySignerBinding(so, requests); });
}

function _assertKeyOnlySignerBinding(so, requests) {
  var id = so.keyIdentifier;
  if (!guard.bytes.isByteSource(id)) {
    throw E("cmc/bad-signer",
      "a key-only signer must name the Subject Key Identifier its certification request declares (RFC 5272 sec. 3.2)");
  }
  var idBytes = guard.bytes.snapshotSource(id, CmcError, "cmc/bad-input", "the signer's keyIdentifier");
  if (!guard.bytes.isByteSource(so.spki)) {
    throw E("cmc/bad-signer", "a key-only signer must carry its spki as DER bytes (RFC 5272 sec. 3.2)");
  }
  var signerSpki = guard.bytes.snapshotSource(so.spki, CmcError, "cmc/bad-input", "the signer's spki");
  var declaredSki = false, sawRequest = false;
  for (var i = 0; i < requests.length; i++) {
    var req = requests[i];
    var declaredBy;
    try {
      declaredBy = req && req.tcr != null ? _csrKeyIdentity(req.tcr)
        : (req && req.crm != null ? _crmKeyIdentity(req.crm) : null);
    } catch (_e) { declaredBy = null; }
    if (req && (req.tcr != null || req.crm != null)) sawRequest = true;
    if (!declaredBy || !declaredBy.ski) continue;
    declaredSki = true;
    if (guard.crypto.constantTimeEqual(declaredBy.ski, idBytes) &&
        declaredBy.spki && guard.crypto.constantTimeEqual(declaredBy.spki, signerSpki)) {
      return;
    }
  }
  if (!sawRequest) {
    throw E("cmc/bad-signer",
      "a key-only signer signs with the key of a certification request in this message, but this PKIData carries none (RFC 5272 sec. 3.2)");
  }
  if (!declaredSki) {
    throw E("cmc/bad-signer",
      "no certification request in this PKIData declares a Subject Key Identifier, which sec. 3.2 requires " +
      "of the request whose key signs the message (RFC 5272 sec. 3.2)");
  }
  throw E("cmc/bad-signer",
    "the key-only signer does not match any certification request in this PKIData: sec. 3.2 requires the " +
    "SignerInfo to name the Subject Key Identifier of the request whose key is signing, AND that request " +
    "to be the one asking for this very public key (RFC 5272 sec. 3.2)");
}

function _crmKeyIdentity(crmDer) {
  var msg = _asCertReqMsg(_der(crmDer, "a crm CertReqMsg"));
  var msgs = crmf.parse(b.sequence([msg])).messages;
  var tmpl = msgs && msgs[0] && msgs[0].certReq && msgs[0].certReq.certTemplate;
  var found = null;
  ((tmpl && tmpl.extensions) || []).forEach(function (e) {
    if (e.name !== "subjectKeyIdentifier" || found) return;
    found = asn1.read.octetString(asn1.decode(e.value));
  });
  var msg0 = msgs && msgs[0];
  var pk = (tmpl && tmpl.publicKey) ||
    (msg0 && msg0.popo && msg0.popo.poposkInput && msg0.popo.poposkInput.publicKey);
  return { ski: found, spki: Buffer.isBuffer(pk) ? pk : (pk && pk.bytes) || null };
}

function _csrKeyIdentity(csrDer) {
  var parsed = csr.parse(_der(csrDer, "a tcr certificationRequest"));
  var found = null;
  (parsed.attributes || []).forEach(function (a) {
    if (a.name !== "extensionRequest") return;
    (a.extensions || []).forEach(function (e) {
      if (e.name !== "subjectKeyIdentifier" || found) return;
      found = asn1.read.octetString(asn1.decode(e.value));
    });
  });
  var spki = parsed.subjectPublicKeyInfo;
  return { ski: found, spki: (spki && spki.bytes) || null };
}

module.exports = { build: build, macPassword: macPassword };
