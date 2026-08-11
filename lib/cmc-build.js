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

// RFC 5272 sec. 6.2.1: "Implementations MUST be able to support tokens at least
// 16 characters long." A shorter shared secret is a caller mistake worth failing
// at config time rather than emitting a weak proof.
var MIN_SECRET_CHARS = 16;
// PL1: R "SHOULD be at least 512 bits in length".
var POP_LINK_RANDOM_BYTES = 64;

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
function fixedRequestId(req, index) {
  if (!req || typeof req !== "object") throw E("cmc/bad-input", "each request must be an object");
  var arms = ["tcr", "crm", "orm"].filter(function (k) { return req[k] != null; });
  if (arms.length !== 1) {
    throw E("cmc/bad-input",
      "each request names exactly one of tcr / crm / orm, got " + (arms.length ? arms.join(" + ") : "none") +
      " (request " + index + ")");
  }
  // A crm arm's identity is its CertReqMsg's own certReqId, so it is ALWAYS fixed
  // -- there is nothing to allocate and nothing that may displace it.
  if (req.crm != null) return _certReqIdOf(_asCertReqMsg(_der(req.crm, "a crm CertReqMsg")));
  return req.bodyPartID == null ? null : req.bodyPartID;
}

function encodeRequest(req, ids, index) {
  if (req.tcr != null) {
    var id = ids.claim(req.bodyPartID, "a tcr request");
    return { bodyPartID: id, der: b.contextConstructed(0, Buffer.concat([b.integer(BigInt(id)), _der(req.tcr, "a tcr certificationRequest")])) };
  }
  if (req.crm != null) {
    var msg = _asCertReqMsg(_der(req.crm, "a crm CertReqMsg"));
    var certReqId = _certReqIdOf(msg);
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
  if (typeof secret !== "string" || secret.length < MIN_SECRET_CHARS) {
    throw E("cmc/bad-input",
      what + " requires a shared secret of at least " + MIN_SECRET_CHARS +
      " characters (RFC 5272 sec. 6.2.1); got " + (typeof secret === "string" ? secret.length : typeof secret));
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
  return Promise.resolve().then(function () { return _build(spec, signer, opts); });
}

function _build(spec, signer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Array.isArray(spec) || Buffer.isBuffer(spec)) {
    throw E("cmc/bad-input", "the CMC request spec must be an object");
  }
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw E("cmc/bad-input", "pki.cmc.build options must be an object");
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
  }

  var controls = [];
  callerControls.forEach(function (c) {
    if (!c || typeof c !== "object" || c.type == null || c.value == null) {
      throw E("cmc/bad-input", "each control is { type, value }");
    }
    controls.push(encodeControl(_oidOf(c.type), [_der(c.value, "a control value")], ids));
  });

  if (spec.identityProof) {
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

  // cms.sign resolves eContentType through oid.byName, so it takes the registry
  // NAME; handing it the dotted value resolves to undefined.
  return cmsSign.sign(pkiData, signer, { eContentType: "id-cct-PKIData", pem: opts.pem });
}

module.exports = { build: build };
