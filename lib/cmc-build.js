// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cmc.build implementation. So the pki.cmc namespace has ONE @module home,
// the operator-facing @module pki.cmc + the @primitive pki.cmc.build documentation block live in
// cmc-verify.js, which re-exports this build function.
//
/**
 * RFC 5272 Full PKI Request production -- the producing half of `pki.cmc`.
 *
 * `build(spec, signer, opts)` assembles a PKIData (all four sequences, each
 * possibly empty), allocates a unique body part identifier for every element,
 * attaches controls through an OID-keyed encoder registry that enforces the RFC
 * 6402 placement rules, computes the Identity Proof / POP Link witnesses over the
 * bytes it is about to EMIT, and signs the result through `pki.cms.sign` with
 * `eContentType: id-cct-PKIData`.
 *
 * The witness rule is the load-bearing one. RFC 5272 sec. 6.2.1 step 1 says the
 * value to be validated is "The PKIData reqSequence field (encoded exactly as it
 * appears in the Full PKI Request including the sequence type and length)". So
 * the reqSequence TLV is built ONCE and both the message and the witness are
 * derived from that single buffer -- computing the witness over a second
 * serialization would agree with itself while disagreeing with the wire the
 * moment any encoding detail differed.
 */

var nodeCrypto = require("node:crypto");
var asn1 = require("./asn1-der");
var csr = require("./schema-csr");    // to read the Subject Key Identifier a tcr request declares
var crmf = require("./schema-crmf");  // ... and the one a crm request declares
var cmcFmt = require("./schema-cmc");  // to read the assembled message back before signing it
var oid = require("./oid");
var cmsSign = require("./cms-sign");
var guard = require("./guard-all");
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

// The identity-bearing controls a renewal must NOT carry: RFC 5272 sec. 3.2 (a)
// -- "The Identification and Identity Proof controls are absent."
//
// "Identity Proof" is BOTH versions: the original id-cmc-identityProof (sec.
// 6.2.2) and identityProofV2 (sec. 6.2.1). Listing only V2 would leave a renewal
// able to carry the v1 control, which is the same nonconformance the rule names.
var RENEWAL_FORBIDDEN = {};
RENEWAL_FORBIDDEN[OID_IDENTIFICATION] = "Identification";
RENEWAL_FORBIDDEN[O("id-cmc-identityProof")] = "Identity Proof";
RENEWAL_FORBIDDEN[OID_IDENTITY_PROOF_V2] = "Identity Proof V2";

// RFC 6402 sec. 2.6: responseBody appears ONLY in a PKIResponse. Enforced at
// BUILD time as well as at parse, so a caller cannot emit a message its own
// decoder would refuse.
var OID_RESPONSE_BODY = O("id-cmc-responseBody");

// RFC 5272 sec. 6.2.1 says "Implementations MUST be able to support tokens at
// least 16 characters long" -- a requirement on what an implementation must be
// ABLE to accept, not a floor every token has to clear. Reading it as a minimum
// inverts it, and would refuse a shorter secret a CA legitimately provisioned.
// The shared secret's strength is the deploying CA's policy; what this layer can
// say is that an empty string is not a credential at all.
// PL1: R "SHOULD be at least 512 bits in length".
var POP_LINK_RANDOM_BYTES = 64;

// The spec fields pki.cmc.build understands. Anything else is a caller mistake
// caught at the entry point rather than silently dropped from the message.
var KNOWN_SPEC_KEYS = {
  requests: 1, controls: 1, cmsSequence: 1, otherMsgSequence: 1,
  // NOT `identification`: the Identification control is attached through
  // identityProof.identity, which is what emits it. Listing a key nothing reads
  // would recreate the very hole this table closes -- accepted at the door and
  // silently absent from the message.
  identityProof: 1, popLink: 1, renewal: 1,
  // The exchange binding (RFC 5272 sec. 6.6 / 6.4). First-class here because
  // pki.cmc.verify names these same three when checking the response: a builder
  // that made the caller hand-encode them while the verifier took them by name is
  // the asymmetry that lets a request ship with no replay defence.
  transactionId: 1, senderNonce: 1, dataReturn: 1,
};

var OID_TRANSACTION_ID = O("id-cmc-transactionId");
var OID_SENDER_NONCE = O("id-cmc-senderNonce");
var OID_DATA_RETURN = O("id-cmc-dataReturn");

// AlgorithmIdentifier { OID } with no parameters -- the form the MAC / hash
// algorithm identifiers in these two controls take.
function algId(o) { return b.sequence([b.oid(o)]); }

// ---- body part identity ---------------------------------------------

// RFC 5272 sec. 3.2.2: identifiers are unique across the WHOLE message and 0 is
// reserved for the reference to the current PKIData. The allocator therefore
// starts at 1, and a caller-supplied value is validated rather than adjusted --
// silently renumbering would break any control that already references it.
function makeIdAllocator() {
  var used = Object.create(null);
  // Reserved ahead of allocation and not yet consumed by the element that owns
  // it. Kept distinct from `used` so an element re-claiming its OWN reservation
  // is a no-op, while a second element asking for the same value is still the
  // duplicate the rule forbids.
  var pending = Object.create(null);
  var next = 1;
  function assertValid(requested, what) {
    if (typeof requested !== "number" || !Number.isInteger(requested) || requested < 0 || requested > 4294967295) {
      throw E("cmc/bad-input", "a bodyPartID must be an integer in 0..4294967295, got " + requested + " (" + what + ")");
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
      if (pending[requested]) { delete pending[requested]; return requested; }   // consume our own reservation
      if (used[requested]) {
        throw E("cmc/bad-input",
          "bodyPartID " + requested + " is used more than once; identifiers MUST be unique within a single PKIData (RFC 5272 sec. 3.2.2)");
      }
      used[requested] = true;
      return requested;
    },
  };
}

// ---- requests --------------------------------------------------------

// TaggedRequest ::= CHOICE { tcr [0], crm [1], orm [2] }, IMPLICIT tags. For the
// crm arm the identity is the CertReqMsg's own certReqId (sec. 3.2.2), so it is
// read back out of the supplied message rather than allocated -- allocating one
// would put a second, contradictory identifier on the wire.
// The identifier a request FIXES, or null when it leaves the choice to us. Read
// in a pre-pass so every caller-determined value is reserved before a single
// generated one is handed out -- otherwise acceptance depends on the order the
// caller happened to write the list in, which is not a property of the message.
// The fields a request descriptor understands -- the same door KNOWN_SPEC_KEYS
// closes on the spec, on the objects nested inside it. A misspelled `bodyPartID`
// is not a harmless extra: the request would be auto-allocated a DIFFERENT
// identifier while a control the caller wrote still references the intended one,
// and the builder would sign a message whose halves point at different requests.
var KNOWN_REQUEST_KEYS = { tcr: 1, crm: 1, orm: 1, bodyPartID: 1 };
// The same door on the other descriptors nested in a spec. A control's identifier
// is always allocated, so a `bodyPartID` written on one is ignored outright; and a
// misspelled `identity` does not merely go missing -- the Identification control
// it would have emitted is what tells the server to derive the Identity Proof key
// from the secret AND the identity, so the message would carry a witness no
// conforming server can reproduce.
var KNOWN_CONTROL_KEYS = { type: 1, value: 1 };
var KNOWN_IDENTITY_PROOF_KEYS = { identity: 1, secret: 1 };
var KNOWN_POP_LINK_KEYS = { secret: 1 };

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
  // A crm arm's identity is its CertReqMsg's own certReqId, so it is ALWAYS fixed
  // -- there is nothing to allocate and nothing that may displace it. A caller who
  // ALSO writes bodyPartID is stating an identity, and the only reason to state one
  // is that something already references it; taking the certReqId silently would
  // sign a message whose control points at no request in it. Equal is accepted --
  // the caller is agreeing with the message, not overriding it.
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

function encodeRequest(req, ids, index) {
  if (req.tcr != null) {
    // A tcr arm IS a PKCS#10 CertificationRequest, so it is parsed rather than
    // taken on the tag: the readback of the assembled message checks the CMC
    // structure around it, and would pass an empty SEQUENCE here as happily as a
    // real request. Signing a request body that is not one produces an enrolment
    // no CA can act on, and the producer is where that is cheap to catch.
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
    // Parsed as the CertReqMsg it is, the same way a tcr is parsed as a
    // CertificationRequest: the readback checks the CMC structure around the
    // request, and would pass a SEQUENCE that merely starts like one.
    try { crmf.parse(b.sequence([msg])); }
    catch (e) {
      throw E("cmc/bad-input", "a crm request must be an RFC 4211 CertReqMsg: " +
        (e && e.message ? e.message : "it did not parse as one"), e);
    }
    // CLAIM, not just read. The certReqId was reserved in the pre-pass with every
    // other caller-determined identifier; leaving the reservation outstanding lets
    // a later cmsSequence or otherMsg element asking for the same number be taken
    // for its owner, and the message would then carry the identifier twice -- a
    // PKIData this toolkit's own parser refuses. The tcr and orm arms already
    // claim; this arm is the same rule.
    var certReqId = ids.claim(_certReqIdOf(msg), "a crm request");
    // IMPLICIT [1]: the tag REPLACES the CertReqMsg SEQUENCE tag, so the content
    // is re-headered rather than nested.
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

// A TaggedRequest's crm arm carries ONE CertReqMsg, but `pki.crmf.build` returns
// a CertReqMessages (SEQUENCE SIZE(1..MAX) OF CertReqMsg) -- which is what a
// caller naturally has in hand. Both are accepted, told apart structurally:
//
//   CertReqMsg      ::= SEQUENCE { certReq CertRequest, ... }   first child is a
//                       SEQUENCE whose OWN first child is an INTEGER (certReqId)
//   CertReqMessages ::= SEQUENCE OF CertReqMsg                  first child is a
//                       CertReqMsg, whose own first child is a SEQUENCE
//
// A CertReqMessages carrying more than one message is REFUSED rather than having
// its first taken: each CertReqMsg is its own TaggedRequest with its own identity,
// so silently dropping the rest would emit a request the caller did not ask for.
function _asCertReqMsg(der) {
  var node = asn1.decode(der);
  var first = node.children && node.children[0];
  if (!first || !first.children || !first.children.length) {
    throw E("cmc/bad-input", "a crm arm must be a CertReqMsg or a CertReqMessages carrying one");
  }
  var grand = first.children[0];
  if (grand.tagClass === "universal" && grand.tagNumber === asn1.TAGS.INTEGER) return der;   // already a CertReqMsg
  if (node.children.length !== 1) {
    throw E("cmc/bad-input",
      "a crm arm carries exactly one CertReqMsg; this CertReqMessages holds " + node.children.length +
      " -- pass each as its own request so each keeps its own certReqId");
  }
  return first.bytes;
}

// A CertReqMsg's identity: CertReqMsg ::= SEQUENCE { certReq CertRequest, ... },
// CertRequest ::= SEQUENCE { certReqId INTEGER, ... }.
function _certReqIdOf(msg) {
  var node = asn1.decode(msg);
  var certReq = node.children && node.children[0];
  if (!certReq || !certReq.children || !certReq.children.length) {
    throw E("cmc/bad-input", "a crm CertReqMsg must lead with a CertRequest whose first element is certReqId");
  }
  var v = asn1.read.integer(certReq.children[0]);
  return guard.range.int(v, 0n, 4294967295n, E, "cmc/bad-input", "a crm certReqId");
}

// A pre-encoded TaggedContentInfo / OtherMsg supplied by the caller. Only its
// leading bodyPartID is read -- the payload is the caller's and stays untouched --
// so the identifier joins the same allocation space every other element draws
// from and a collision is refused here rather than discovered by the parser.
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

// The binding controls have a named spec field AND can be hand-encoded into
// spec.controls. Emitting both would put two of the same control in one message,
// and duplicates of these three are what decide what the response must echo -- two
// values means no value. Also refuses two hand-encoded copies, since the same
// ambiguity arrives that way.
var BINDING_BY_OID = {};
BINDING_BY_OID[O("id-cmc-transactionId")] = "transactionId";
BINDING_BY_OID[O("id-cmc-senderNonce")] = "senderNonce";
BINDING_BY_OID[O("id-cmc-dataReturn")] = "dataReturn";

// ... and the type each one carries. The CMC parser keeps every control value RAW,
// so nothing downstream of the builder objects to a Transaction Identifier encoded
// as an OCTET STRING -- but these three are read, not carried: pki.cmc.verify
// compares them against the response, and pki.est.fullcmc reads them back out of
// the request before it goes out. A hand-encoded value of the wrong type therefore
// signs a request that this toolkit's own client will refuse to send. The type is
// checked by READING the value, so a wrong tag and a malformed encoding of the
// right one are refused alike.
var BINDING_READER = {
  transactionId: function (node) { return asn1.read.integer(node); },
  senderNonce: function (node) { return asn1.read.octetString(node); },
  dataReturn: function (node) { return asn1.read.octetString(node); },
};
var BINDING_TYPE_NAME = {
  transactionId: "an INTEGER (RFC 5272 sec. 6.6)",
  senderNonce: "an OCTET STRING (RFC 5272 sec. 6.6)",
  dataReturn: "an OCTET STRING (RFC 5272 sec. 6.4)",
};

function _assertNoDuplicateBinding(callerControls, spec) {
  var seen = {};
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

// A Transaction Identifier is an unbounded INTEGER on the wire; the shared authoring
// guard normalizes the number-or-bigint a caller naturally has.
function _asBigInt(v, what) { return guard.range.authoredInteger(v, E, "cmc/bad-input", what); }

function _der(v, what) {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  throw E("cmc/bad-input", what + " must be DER bytes");
}
function _oidOf(v) {
  if (typeof v !== "string") throw E("cmc/bad-input", "an OID must be a name or a dotted string");
  return /^\d+(\.\d+)+$/.test(v) ? v : O(v);
}

// ---- controls --------------------------------------------------------

// TaggedAttribute ::= SEQUENCE { bodyPartID, attrType, attrValues SET OF ANY }.
function encodeControl(attrType, values, ids) {
  if (attrType === OID_RESPONSE_BODY) {
    throw E("cmc/control-misplaced",
      "id-cmc-responseBody may appear only in the control sequence of a PKIResponse (RFC 6402 sec. 2.6)");
  }
  var id = ids.claim(null, "a control");
  return b.sequence([b.integer(BigInt(id)), b.oid(attrType), b.set(values)]);
}

// ---- the witnesses ---------------------------------------------------

function _assertSecret(secret, what) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw E("cmc/bad-input",
      what + " requires the shared secret as a non-empty string; got " +
      (typeof secret === "string" ? "an empty string" : typeof secret));
  }
}

// IdentifyProofV2 ::= SEQUENCE { hashAlgID, macAlgID, witness OCTET STRING }.
// key = hash(shared-secret as a UTF8 string); witness = MAC(reqSequenceBytes, key).
// `reqSequenceBytes` is the buffer that will BE the message's reqSequence -- not
// a re-encode of it (RFC 5272 sec. 6.2.1 step 1).
function identityProofV2(secret, reqSequenceBytes, identity) {
  _assertSecret(secret, "an Identity Proof V2 control");
  // RFC 5272 sec. 6.2.3: the Identification control is OPTIONAL ("servers MAY
  // require" it), but when it IS present the key derivation is ALTERED -- "the
  // hash of the concatenation of the shared-secret and the UTF8 identity value
  // (without the type and length bytes) are hashed rather than just the
  // shared-secret". Same controls on the wire, different key: a producer that
  // emits the Identification control while hashing the secret alone computes a
  // witness every conforming server rejects.
  var material = identity == null
    ? Buffer.from(secret, "utf8")
    : Buffer.concat([Buffer.from(secret, "utf8"), Buffer.from(identity, "utf8")]);
  var key = nodeCrypto.createHash("sha256").update(material).digest();
  var witness = nodeCrypto.createHmac("sha256", key).update(reqSequenceBytes).digest();
  try {
    return b.sequence([algId(OID_SHA256), algId(OID_HMAC_SHA256), b.octetString(witness)]);
  } finally {
    guard.secret.zeroize(key, CmcError, "cmc/bad-input", "the Identity Proof MAC key");
  }
}

// PopLinkWitnessV2 ::= SEQUENCE { keyGenAlgorithm, macAlgorithm, witness }.
// key = keyGen(shared-secret); witness = MAC(R, key), with R carried alongside in
// the POP Link Random control -- PL1 makes that control mandatory in the same
// request, which is why the two are produced together and never separately.
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
  // Assembled SYNCHRONOUSLY. _build reads the spec, every request buffer and the
  // signer as it goes, so deferring that work would read them a turn after the
  // call -- and a caller reusing a pooled CSR buffer, or reaching back into the
  // spec on the next line, would have the message signed over something other
  // than what was handed in. Only the signing itself is async, and by then the
  // bytes are fixed.
  try {
    return _build(spec, signer, opts);
  } catch (e) {
    return Promise.reject(e);   // the surface stays promise-rejecting, never throwing
  }
}

function _build(spec, signer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Array.isArray(spec) || Buffer.isBuffer(spec)) {
    throw E("cmc/bad-input", "the CMC request spec must be an object");
  }
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw E("cmc/bad-input", "pki.cmc.build options must be an object");
  // A misspelled or unsupported spec field fails OPEN in the quietest way there is:
  // the message builds, is signed, and simply does not carry what was asked for.
  // That is worst for the exchange-binding fields below -- a request built without
  // them has no replay defence, and pki.cmc.verify cannot enforce a binding the
  // client never sent, so the omission is invisible from both ends.
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, E, "cmc/bad-input", "unknown spec field ");
  var requests = spec.requests || [];
  if (!Array.isArray(requests)) throw E("cmc/bad-input", "spec.requests must be an array");
  var callerControls = spec.controls || [];
  if (!Array.isArray(callerControls)) throw E("cmc/bad-input", "spec.controls must be an array");

  var ids = makeIdAllocator();

  // EVERY identifier the CALLER determines is reserved before a single generated
  // one is handed out. There are four sources, and reserving only some of them
  // makes acceptance depend on the order the caller wrote things in rather than
  // on the message:
  //   1. a request's explicit bodyPartID
  //   2. a crm arm's certReqId, which is fixed by the CertReqMsg itself
  //   3. a cmsSequence element's bodyPartID
  //   4. an otherMsgSequence element's bodyPartID
  // Auto-allocation walks upward from 1, so anything minted before these were
  // claimed could take a value the caller already spent -- and the caller's own
  // element would then be rejected as a duplicate of whatever displaced it.
  requests.forEach(function (r, i) {
    var fixed = fixedRequestId(r, i);
    if (fixed != null) ids.reserve(fixed, "request " + i);
  });
  var cmsSequence = (spec.cmsSequence || []).map(function (el, i) {
    return _claimRawElement(el, ids, "a cmsSequence element (index " + i + ")");
  });
  var otherMsgSequence = (spec.otherMsgSequence || []).map(function (el, i) {
    return _claimRawElement(el, ids, "an otherMsgSequence element (index " + i + ")");
  });

  // Now the requests: a fixed identifier is re-claimed as a no-op against the
  // reservation above, and only the ones that omitted it are allocated. The
  // reqSequence bytes this produces are what the Identity Proof witness covers.
  var encodedRequests = requests.map(function (r, i) { return encodeRequest(r, ids, i); });
  var reqSequenceBytes = b.sequence(encodedRequests.map(function (r) { return r.der; }));

  // A renewal carries neither identity control. Refusing the combination is the
  // point: dropping the control silently would emit a message that looks like a
  // renewal to us and an identity-proofed request to nobody.
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
    // A renewal is authenticated by the certificate being renewed: sec. 6.3.3 says
    // "the outermost signature layer is created using the current signing
    // certificate, which allows the original identity to be associated with the
    // certification request". That identity is the whole mechanism -- it is what
    // replaces the Identity Proof this mode just refused. A key-only signer has no
    // certificate and so carries no prior identity, leaving a message with nothing
    // for the CA to authenticate the renewal against.
    var renewalSigners = Array.isArray(signer) ? signer : [signer];
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
  callerControls.forEach(function (c) {
    if (!c || typeof c !== "object" || c.type == null || c.value == null) {
      throw E("cmc/bad-input", "each control is { type, value }");
    }
    guard.identifier.assertKnownKeys(c, KNOWN_CONTROL_KEYS, E, "cmc/bad-input", function (k) {
      return "unknown field " + JSON.stringify(k) + " on a control -- a control is { type, value }, " +
        "and its bodyPartID is allocated by the builder";
    });
    controls.push(encodeControl(_oidOf(c.type), [_der(c.value, "a control value")], ids));
  });

  // The exchange binding (RFC 5272 sec. 6.6 Transaction Identifier / Sender Nonce,
  // sec. 6.4 Data Return). These are what pki.cmc.verify checks the response
  // against, and a request that omits them has no replay defence -- so they are
  // named fields here rather than something the caller hand-encodes into
  // spec.controls and can silently get wrong.
  // A named field and a hand-encoded control of the same type would emit the
  // control TWICE, and a message carrying two of them has no single value the
  // response can be bound to -- this toolkit's own /fullcmc refuses exactly that.
  // Refuse it at the source rather than sign something no one can bind to.
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

  if (spec.identityProof) {
    guard.identifier.assertKnownKeys(spec.identityProof, KNOWN_IDENTITY_PROOF_KEYS, E, "cmc/bad-input",
      function (k) { return "unknown field " + JSON.stringify(k) + " on identityProof -- it is { secret, identity? }"; });
    var identity = spec.identityProof.identity;
    if (identity != null && typeof identity !== "string") {
      throw E("cmc/bad-input", "identityProof.identity is the UTF8String the Identification control carries");
    }
    // The pair is emitted together when an identity is given, because the two are
    // coupled: the Identification control tells the server WHICH shared secret to
    // look up, and its presence is what changes how the key is derived. Letting a
    // caller supply one without the other would put that coupling out of reach.
    if (identity != null) controls.push(encodeControl(OID_IDENTIFICATION, [b.utf8(identity)], ids));
    controls.push(encodeControl(OID_IDENTITY_PROOF_V2,
      [identityProofV2(spec.identityProof.secret, reqSequenceBytes, identity)], ids));
  }

  if (spec.popLink) {
    guard.identifier.assertKnownKeys(spec.popLink, KNOWN_POP_LINK_KEYS, E, "cmc/bad-input",
      function (k) { return "unknown field " + JSON.stringify(k) + " on popLink -- it is { secret }"; });
    var rBytes = opts.popLinkRandomBytes == null ? POP_LINK_RANDOM_BYTES : opts.popLinkRandomBytes;
    if (typeof rBytes !== "number" || !Number.isInteger(rBytes) || rBytes < 1) {
      throw E("cmc/bad-input", "popLinkRandomBytes must be a positive integer");
    }
    var R = nodeCrypto.randomBytes(rBytes);
    // Both are emitted together: PL1 makes the Random control mandatory whenever
    // the witness is present, so producing one without the other is not an option
    // the API offers.
    controls.push(encodeControl(OID_POP_LINK_RANDOM, [b.octetString(R)], ids));
    controls.push(encodeControl(O("id-cmc-popLinkWitnessV2"),
      [popLinkWitnessV2(spec.popLink.secret, R)], ids));
  }

  // PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence,
  // otherMsgSequence } -- all four emitted, the unused ones empty (sec. 3.2.1).
  // reqSequenceBytes is spliced in as the SAME buffer the witness was computed
  // over, which is the whole of IP1.
  var pkiData = b.sequence([
    b.sequence(controls),
    b.raw(reqSequenceBytes),
    b.sequence(cmsSequence),
    b.sequence(otherMsgSequence),
  ]);

  // Read the assembled message back through the shipped parser before signing it.
  // Every arm here splices CALLER-supplied DER -- a tcr's CertificationRequest, a
  // cmsSequence TaggedContentInfo, an otherMsg's value -- and checking each shape
  // by hand would restate the parser's rules in a second place, where they would
  // drift and where a newly added arm would silently miss them. One round-trip
  // covers them all, including arms not yet written: whatever the parser refuses,
  // this refuses at build time rather than emitting a message whose recipient --
  // this toolkit's own decoder included -- cannot read it.
  try {
    cmcFmt.parsePkiData(pkiData);
  } catch (e) {
    throw E("cmc/bad-input",
      "the assembled PKIData does not parse as one, so it would be refused by its recipient: " +
      (e && e.message ? e.message : "malformed"), e);
  }

  _assertKeyOnlySigner(signer, requests);

  // The signer is copied for the same reason the message was assembled at the
  // call: cms.sign reads `key` inside its own promise chain, so a caller who
  // swaps signer.key on the next line would have the request signed by the
  // replacement while the original certificate stays embedded -- a message whose
  // signature does not belong to the certificate beside it.
  //
  // cms.sign resolves eContentType through oid.byName, so it takes the registry
  // NAME; handing it the dotted value resolves to undefined.
  return cmsSign.sign(pkiData, _copySigners(signer), { eContentType: "id-cct-PKIData", pem: opts.pem });
}

// Each signer descriptor, and every byte value in it. cms.sign reads these inside
// its own promise chain, so both levels matter: re-pointing signer.key is one way
// to change who signs, and rewriting the PKCS#8 buffer it already points at is
// the other. A CryptoKey handle is passed through as-is -- it is an opaque
// reference the caller is meant to share, and there is nothing to copy.
function _copySigners(signer) {
  function one(s) {
    if (!s || typeof s !== "object") return s;
    var out = {}, k;
    for (k in s) {
      if (!Object.prototype.hasOwnProperty.call(s, k)) continue;
      out[k] = copyValue(s[k]);
    }
    return out;
  }
  // One level further for a COMPOSITE key, which is an object of component keys
  // ({ mldsa, trad }) rather than a buffer. Copying only the top level would leave
  // those components -- the actual PKCS#8 bytes that sign -- the caller's to
  // replace or zeroize while cms.sign reads them in a later turn. A CryptoKey is
  // an opaque handle and is passed through as-is.
  function copyValue(v) {
    if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.from(v);
    if (!v || typeof v !== "object" || typeof v.type === "string") return v;   // CryptoKey / scalar
    var c = {}, ck;
    for (ck in v) {
      if (!Object.prototype.hasOwnProperty.call(v, ck)) continue;
      var cv = v[ck];
      c[ck] = (Buffer.isBuffer(cv) || cv instanceof Uint8Array) ? Buffer.from(cv) : cv;
    }
    return c;
  }
  return Array.isArray(signer) ? signer.map(one) : one(signer);
}

/**
 * RFC 5272 sec. 3.2, the three rules that apply when the signature is made with
 * the private key of a certification request the message carries rather than with
 * an already-certified key:
 *
 *   a. that request MUST include a Subject Key Identifier extension;
 *   b. the subjectKeyIdentifier form of SignerIdentifier MUST be used;
 *   c. its value MUST be the Subject Key Identifier that request specifies.
 *
 * (b) is structural and pki.cms.sign already emits only that form for a key-only
 * signer. (a) and (c) are about agreement between the signer and the requests
 * beside it, which is checked here: an identifier the requests never declare
 * leaves the CA unable to tie the signature to the key being enrolled, so the
 * request is signed but unusable -- and it is the producer's job to catch that,
 * not the CA's to guess.
 *
 * This lives HERE rather than in pki.cms.sign because it is a CMC rule: only this
 * layer knows the content is a PKIData and which requests are in it. Teaching the
 * generic CMS signer to parse CMC content would put the protocol's rules in the
 * wrong module.
 *
 * A signer WITH a certificate is untouched -- it identifies itself by that
 * certificate, and the clause does not reach it.
 */
function _assertKeyOnlySigner(signer, requests) {
  var all = Array.isArray(signer) ? signer : [signer];
  var keyOnly = all.filter(function (x) { return x && x.cert == null && x.spki != null; });
  if (!keyOnly.length) return;
  // Sec. 3.2's fourth rule: "If the request key is used for signing, there MUST be
  // only one SignerInfo in the SignedData." A request key has no certificate and
  // so no independent identity; letting it sign alongside others would produce a
  // message whose signer set the CA cannot reason about.
  if (all.length !== 1) {
    throw E("cmc/bad-signer",
      "a Full PKI Request signed with a certification request's own key MUST carry exactly one SignerInfo, " +
      "got " + all.length + " (RFC 5272 sec. 3.2)");
  }
  keyOnly.forEach(function (so) { _assertKeyOnlySignerBinding(so, requests); });
}

// The sec. 3.2a/3.2c binding for ONE key-only signer.
function _assertKeyOnlySignerBinding(so, requests) {
  var id = so.keyIdentifier;
  var idBytes = (Buffer.isBuffer(id) || id instanceof Uint8Array) ? Buffer.from(id) : null;
  if (!idBytes) {
    throw E("cmc/bad-signer",
      "a key-only signer must name the Subject Key Identifier its certification request declares (RFC 5272 sec. 3.2)");
  }
  var signerSpki = (Buffer.isBuffer(so.spki) || so.spki instanceof Uint8Array) ? Buffer.from(so.spki) : null;
  if (!signerSpki) {
    throw E("cmc/bad-signer", "a key-only signer must carry its spki as DER bytes (RFC 5272 sec. 3.2)");
  }
  var declaredSki = false, sawRequest = false;
  for (var i = 0; i < requests.length; i++) {
    var req = requests[i];
    // BOTH key-bearing arms: sec. 3.2 says the signing key may belong to a request
    // "included in the TaggedRequest tcr or crm fields", so reading only PKCS#10
    // would reject every conforming CRMF enrolment of a brand-new key.
    var declaredBy;
    try {
      declaredBy = req && req.tcr != null ? _csrKeyIdentity(req.tcr)
        : (req && req.crm != null ? _crmKeyIdentity(req.crm) : null);
    } catch (_e) { declaredBy = null; }   // a request this layer cannot read declares nothing
    if (req && (req.tcr != null || req.crm != null)) sawRequest = true;
    if (!declaredBy || !declaredBy.ski) continue;
    declaredSki = true;
    // The identifier AND the key. Matching the identifier alone would accept a
    // signer holding key A while the request it points at asks to certify key B --
    // the SKI is caller-chosen, so the two can be made to agree while the keys do
    // not, and a CA resolving the SID to the requested key could then not verify
    // the carrier at all. The identifier says WHICH request; the key is what makes
    // the claim true. The comparison runs through the toolkit's shared byte
    // equality; neither value here is secret, but there is one way to compare.
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

// { ski, spki } for a CRMF certification request -- the identifier it declares and
// the key it asks to have certified. The CertTemplate carries extensions directly,
// so there is no attribute wrapper to unwrap; the extnValue is the same DER
// SubjectKeyIdentifier OCTET STRING.
function _crmKeyIdentity(crmDer) {
  var msg = _asCertReqMsg(_der(crmDer, "a crm CertReqMsg"));
  // pki.schema.crmf reads CertReqMessages (SEQUENCE OF CertReqMsg); one message is
  // wrapped rather than decoded here, so the CRMF rules stay in the CRMF parser.
  var msgs = crmf.parse(b.sequence([msg])).messages;
  var tmpl = msgs && msgs[0] && msgs[0].certReq && msgs[0].certReq.certTemplate;
  var found = null;
  ((tmpl && tmpl.extensions) || []).forEach(function (e) {
    if (e.name !== "subjectKeyIdentifier" || found) return;
    found = asn1.read.octetString(asn1.decode(e.value));
  });
  // RFC 4211 sec. 4.1: the requested key may live in the signature POP's
  // POPOSigningKeyInput rather than the CertTemplate, and the CRMF parser surfaces
  // it there. Reading only the template would refuse a key-only signer whose
  // request is perfectly conforming.
  var msg0 = msgs && msgs[0];
  var pk = (tmpl && tmpl.publicKey) ||
    (msg0 && msg0.popo && msg0.popo.poposkInput && msg0.popo.poposkInput.publicKey);
  return { ski: found, spki: Buffer.isBuffer(pk) ? pk : (pk && pk.bytes) || null };
}

// { ski, spki } for a PKCS#10 certification request. Read through the shipped CSR
// parser and the extensionRequest attribute it already decodes, so the extension
// rules are not restated here.
function _csrKeyIdentity(csrDer) {
  var parsed = csr.parse(_der(csrDer, "a tcr certificationRequest"));
  var found = null;
  (parsed.attributes || []).forEach(function (a) {
    if (a.name !== "extensionRequest") return;
    (a.extensions || []).forEach(function (e) {
      if (e.name !== "subjectKeyIdentifier" || found) return;
      // extnValue holds a DER SubjectKeyIdentifier ::= OCTET STRING; the identifier
      // is its contents, not the TLV.
      found = asn1.read.octetString(asn1.decode(e.value));
    });
  });
  var spki = parsed.subjectPublicKeyInfo;
  return { ski: found, spki: (spki && spki.bytes) || null };
}

module.exports = { build: build };
