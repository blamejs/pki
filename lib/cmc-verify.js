// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.cmc
 * @nav        Enrollment
 * @title      CMC
 * @intro Interpret an RFC 5272 Full PKI Response. `verify(response, sent)` takes the response
 *   a CA returned and the state the client retained from its request, binds the two together
 *   (transaction identifier, the Sender/Recipient Nonce echo, the Data Return echo), reads the
 *   ordered status verdicts, and reduces them to ONE terminal outcome: `issued`, `pending`,
 *   `confirm-required`, `pop-required` or `rejected`. The issued certificates come from the CMS
 *   certificate bag, where RFC 5272 sec. 4.2 puts them. Nothing here is trusted: the bag and any
 *   Publish Trust Anchors control are surfaced as DATA for the caller to validate through
 *   `pki.path.validate`.
 * @spec RFC 5272, RFC 5273, RFC 6402
 * @card Interpret a CMC Full PKI Response into one terminal verdict -- transaction and nonce
 *   binding, the status verdicts, the certificate bag surfaced untrusted.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var cmc = require("./schema-cmc");
var cmsVerify = require("./cms-verify");   // PD14: the carrier's signature MUST be verified
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var CmcError = frameworkError.CmcError;
function E(code, message, cause) { return new CmcError(code, message, cause); }
function O(name) { return oid.byName(name); }

var OID_TRANSACTION_ID = O("id-cmc-transactionId");
var OID_SENDER_NONCE = O("id-cmc-senderNonce");
var OID_RECIPIENT_NONCE = O("id-cmc-recipientNonce");
var OID_DATA_RETURN = O("id-cmc-dataReturn");
var OID_TRUSTED_ANCHORS = O("id-cmc-trustedAnchors");
var OID_CONFIRM_CERT_ACCEPTANCE = O("id-cmc-confirmCertAcceptance");

// CMCStatus -> the terminal outcome a caller acts on. RFC 5272 sec. 6.1.3 gives
// seven statuses; four of them mean "this exchange did not produce a certificate
// and will not without another message", so they collapse to `rejected` while the
// status list keeps the detail.
var OUTCOME_BY_STATUS = {
  success: "issued",
  pending: "pending",
  partial: "pending",
  confirmRequired: "confirm-required",
  popRequired: "pop-required",
  failed: "rejected",
  noSupport: "rejected",
};

// Which outcome governs when a response carries SEVERAL status controls (sec.
// 6.1 requires a client to cope with that). Ranked worst-first so the verdict can
// never be improved by the ORDER the controls happen to appear in -- reporting
// the first one seen would let a server bury a failure behind a success.
var OUTCOME_SEVERITY = { rejected: 4, "pop-required": 3, "confirm-required": 2, pending: 1, issued: 0 };

// The single AttributeValue of a control that carries exactly one.
function _singleValue(control, what) {
  if (control.values.length !== 1) {
    throw E("cmc/bad-control", "the " + what + " control carries exactly one value, got " + control.values.length);
  }
  return control.values[0];
}
// The single instance of a control, or null when absent.
//
// Body-part identity is unique per element, so a responder can legally carry the
// SAME control type twice under different bodyPartIDs. Taking the first match
// would let an attacker pair one correct echo with a contradictory one and still
// satisfy the binding -- so a duplicate is refused as ambiguous rather than
// resolved. The exchange either has one answer or it has none.
function _findControl(controls, attrType, what) {
  var found = null;
  for (var i = 0; i < controls.length; i++) {
    if (controls[i].attrType !== attrType) continue;
    if (found) {
      throw E("cmc/duplicate-control",
        "the response carries more than one " + what + " control; which one binds the exchange is ambiguous, so it is refused");
    }
    found = controls[i];
  }
  return found;
}
function _octets(control, what) {
  return asn1.read.octetString(asn1.decode(_singleValue(control, what)));
}

// The certificate / CRL bag, from whichever carrier holds it. A SignedData keeps
// them at the top level; an AuthenticatedData keeps them under `originatorInfo`
// (RFC 5652 sec. 9.1). Both carriers are accepted for a Full PKI Response, so
// reading only the SignedData shape would silently return an empty bag -- and
// "no certificates were issued" is exactly the wrong thing to report when some
// were.
function _bagOf(parsedCms, originatorKey, topKey) {
  if (!parsedCms) return [];
  var list = parsedCms[topKey];
  if ((!list || !list.length) && parsedCms.originatorInfo) list = parsedCms.originatorInfo[originatorKey];
  return (list || []).map(function (c) { return c.bytes; });
}

/**
 * The transaction binding -- RFC 5272 sec. 6.6, RFC 5273 sec. 6.
 *
 * Both halves are CONDITIONAL on what the client sent, which is the subtlety: a
 * client that sent no transactionId cannot demand one back, and a client that
 * sent no senderNonce has nothing to compare a recipientNonce against. What is
 * NOT conditional is the converse -- having sent one, an absent or differing echo
 * is a refusal, because that is exactly the replay the nonce exists to stop.
 */
function _assertBound(body, sent) {
  if (sent.transactionId != null) {
    var txControl = _findControl(body.controls, OID_TRANSACTION_ID, "Transaction Identifier");
    if (!txControl) {
      throw E("cmc/transaction-mismatch",
        "the request carried a Transaction Identifier control, so the response MUST include the same one (RFC 5272 sec. 6.6)");
    }
    var got = asn1.read.integer(asn1.decode(_singleValue(txControl, "Transaction Identifier")));
    if (got !== BigInt(sent.transactionId)) {
      throw E("cmc/transaction-mismatch",
        "the response Transaction Identifier " + got + " does not match the request's " + sent.transactionId);
    }
  }

  if (sent.senderNonce != null) {
    var rn = _findControl(body.controls, OID_RECIPIENT_NONCE, "Recipient Nonce");
    if (!rn) {
      throw E("cmc/nonce-mismatch",
        "the request carried a Sender Nonce, so the response MUST reflect it back as a Recipient Nonce control (RFC 5272 sec. 6.6)");
    }
    // Constant-time and by FULL value: guard.crypto.constantTimeEqual gates the
    // length first, so a truncation or a prefix is an honest false rather than a
    // match on the bytes that happen to line up.
    if (!guard.crypto.constantTimeEqual(_octets(rn, "Recipient Nonce"), Buffer.from(sent.senderNonce))) {
      throw E("cmc/nonce-mismatch", "the response Recipient Nonce does not match the Sender Nonce the request sent");
    }
  }

  // RFC 5272 sec. 6.4: "If the Data Return control appears in a Full PKI Request,
  // the server MUST return it as part of the PKI Response." The data is opaque to
  // the server, so the check is that the SAME bytes came back.
  if (sent.dataReturn != null) {
    var dr = _findControl(body.controls, OID_DATA_RETURN, "Data Return");
    if (!dr) {
      throw E("cmc/data-return-missing",
        "the request carried a Data Return control, so the server MUST return it in the PKI Response (RFC 5272 sec. 6.4)");
    }
    if (!_octets(dr, "Data Return").equals(Buffer.from(sent.dataReturn))) {
      throw E("cmc/data-return-mismatch", "the returned Data Return control does not carry the bytes the request sent");
    }
  }
}

// The worst outcome across every status control, with success assumed when there
// is none at all (RFC 5272 sec. 6.1.2: "If no status exists for a Simple or Full
// PKI Request, then the value of success is assumed").
function _reduceOutcome(statuses) {
  var outcome = "issued";
  for (var i = 0; i < statuses.length; i++) {
    var candidate = OUTCOME_BY_STATUS[statuses[i].status];
    if (OUTCOME_SEVERITY[candidate] > OUTCOME_SEVERITY[outcome]) outcome = candidate;
  }
  return outcome;
}

// The pendInfo / failInfo detail belonging to the status that GOVERNED, so a
// caller reading `pendToken` gets the one attached to the pending verdict rather
// than whichever status happened to carry a token.
function _governingStatus(statuses, outcome) {
  for (var i = 0; i < statuses.length; i++) {
    if (OUTCOME_BY_STATUS[statuses[i].status] === outcome) return statuses[i];
  }
  return null;
}

/**
 * @primitive  pki.cmc.verify
 * @signature  pki.cmc.verify(response, sent?) -> Promise<verdict>
 * @since      0.4.16
 * @status     experimental
 * @spec       RFC 5272, RFC 5273, RFC 6402
 * @defends    cmc-response-replay (CWE-294)
 * @related    pki.schema.cmc.parse, pki.path.validate, pki.cms.verify
 *
 * Interpret a Full PKI Response into ONE terminal verdict. `response` is the DER (or a PEM `CMS`
 * block, or an already-parsed message); `sent` is what the client retained from its request --
 * `transactionId`, `senderNonce`, `dataReturn`. Each of those is checked only if it was sent, and
 * once sent an absent or differing echo is a refusal: that asymmetry is the replay defence.
 *
 * The verdict's `outcome` is `issued`, `pending`, `confirm-required`, `pop-required` or
 * `rejected`. When a response carries several status controls the WORST governs, so a failure
 * cannot be hidden behind a success earlier in the sequence.
 *
 * The carrier's signature MUST be verified (RFC 5272 sec. 3.2.1.3.4), so that is fail-closed with a
 * NAMED opt-out rather than a silent one: pass `certs` and the CMS signature is checked, or
 * `allowUnverified: true` and the verdict reports `signatureVerified: false`. Doing neither is
 * refused -- that is the case where a caller would otherwise assume a check happened. A carrier with
 * no SignerInfo at all is not a Full PKI Response and is refused outright.
 *
 * `certs` supplies certificates for signer LOOKUP; it does not pin the signer (a SignedData carries
 * its own signer certificate, which is what the signature is checked against) and it establishes no
 * trust. Deciding the signer is acceptable is path validation, which is the caller's.
 *
 * Nothing is trusted here. `certificates` is the CMS certificate bag -- where RFC 5272 sec. 4.2
 * puts the issued certificates -- surfaced raw for the caller to run through `pki.path.validate`,
 * and a Publish Trust Anchors control is surfaced as `publishTrustAnchors` with `trusted: false`,
 * never added to any store (RFC 5272 sec. 6.15 makes accepting one a four-part manual decision).
 * The CMS signature is likewise the caller's to verify through `pki.cms.verify`.
 *
 * @opts
 *   - `transactionId` (number|bigint) -- the Transaction Identifier the request sent.
 *   - `senderNonce` (Buffer) -- the Sender Nonce the request sent, echoed back as Recipient Nonce.
 *   - `dataReturn` (Buffer) -- the Data Return payload the request sent, echoed verbatim.
 *   - `certs` (Buffer[]) -- certificates for CMS signer lookup; supplying them enables verification.
 *   - `allowUnverified` (boolean) -- interpret without verifying the carrier; sets `signatureVerified: false`.
 * @example
 *   var b = pki.asn1.build, oid = pki.oid;
 *   var sid = b.sequence([b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")),
 *     b.utf8("CA")])])]), b.integer(1n)]);
 *   var attrs = b.contextConstructed(0, Buffer.concat([
 *     b.sequence([b.oid(oid.byName("contentType")), b.set([b.oid(oid.byName("id-cct-PKIResponse"))])]),
 *     b.sequence([b.oid(oid.byName("messageDigest")), b.set([b.octetString(Buffer.alloc(32, 3))])])]));
 *   var si = b.sequence([b.integer(1n), sid, b.sequence([b.oid(oid.byName("sha256")), b.nullValue()]),
 *     attrs, b.sequence([b.oid(oid.byName("rsaEncryption")), b.nullValue()]), b.octetString(Buffer.alloc(8, 1))]);
 *   var body = b.sequence([b.sequence([]), b.sequence([]), b.sequence([])]);
 *   var encap = b.sequence([b.oid(oid.byName("id-cct-PKIResponse")), b.explicit(0, b.octetString(body))]);
 *   var sd = b.sequence([b.integer(3n), b.set([]), encap, b.set([si])]);
 *   var der = b.sequence([b.oid(oid.byName("signedData")), b.explicit(0, sd)]);
 *   var v = await pki.cmc.verify(der, { allowUnverified: true });
 *   v.outcome;             // "issued" -- no status control means success is assumed
 *   v.signatureVerified;   // false -- the opt-out was named, so nothing was checked
 */
function verify(response, sent) {
  return Promise.resolve().then(function () { return _verify(response, sent); });
}

// A private copy of the input when -- and only when -- it is memory the caller can
// still write to. Anything else is returned untouched so this cannot narrow the
// input contract of the parse it feeds; pki.schema.cmc.parse stays the one place
// that decides what an acceptable input is, and keeps raising its own typed error.
function _snapshotIfBytes(input) {
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    return guard.bytes.snapshot(input, CmcError, "cmc/bad-input", "pki.cmc.verify");
  }
  return input;
}

function _verify(response, sent) {
  if (sent == null) sent = {};
  if (typeof sent !== "object" || Array.isArray(sent) || Buffer.isBuffer(sent)) {
    throw E("cmc/bad-input", "pki.cmc.verify options must be an object");
  }
  // Parse and verify MUST read the same bytes. This function decodes the response
  // synchronously and checks its signature in a LATER promise turn, so without a
  // private copy every range the parse surfaced stays a view into the caller's
  // memory across that await -- and a buffer rewritten in the gap would leave the
  // verdict describing one message while the signature was checked over another.
  var body = cmc.parse(_snapshotIfBytes(response));
  if (body.kind !== "pkiResponse") {
    throw E("cmc/not-a-response",
      "pki.cmc.verify interprets a Full PKI Response (id-cct-PKIResponse); this message is a " + body.kind);
  }

  return _assertAuthentic(body, sent).then(function (signatureVerified) {
    _assertBound(body, sent);
    return _shape(body, sent, signatureVerified);
  });
}

/**
 * PD14 -- RFC 5272 sec. 3.2.1.3.4: "As part of processing a PKI Request/Response,
 * the signature(s) MUST be verified."
 *
 * A Full PKI Response is a SignedData (sec. 4.2), so a carrier with no SignerInfo
 * at all is not one -- that is the Simple response's shape, and reading an
 * `issued` verdict off it would report an enrollment result nobody signed.
 *
 * Verification needs the signer's certificate, which this layer cannot invent.
 * So the posture is fail-closed with a NAMED opt-out rather than a silent one:
 * supply `certs` and the signature is checked; supply `allowUnverified: true` and
 * the verdict says `signatureVerified: false` so nothing downstream can mistake
 * it for an authenticated answer. Doing neither is refused, because that is the
 * case where a caller would otherwise believe a check happened.
 */
function _assertAuthentic(body, sent) {
  return Promise.resolve().then(function () {
    // The two accepted carriers are authenticated DIFFERENTLY, so the rule has to
    // be written for both: a SignedData by its SignerInfo signatures, an
    // AuthenticatedData by a MAC over a key this layer never holds. Checking only
    // the SignedData shape would reject every conforming AuthenticatedData
    // response for having no signer -- which is not a defect in the message.
    if (body.cms && body.cms.contentTypeName === "authData") {
      if (sent.allowUnverified === true) return false;
      throw E("cmc/unverified-response",
        "an AuthenticatedData response is authenticated by its MAC, which needs the recipient key this layer does not hold -- verify it with pki.cms.decrypt, or pass `allowUnverified: true` to interpret it unauthenticated");
    }
    var signerInfos = (body.cms && body.cms.signerInfos) || [];
    if (!signerInfos.length) {
      throw E("cmc/unsigned-response",
        "a Full PKI Response is a SignedData carrying at least one SignerInfo; this carrier has none, so there is no signature to verify (RFC 5272 sec. 4.2 / 3.2.1.3.4)");
    }
    if (!sent.certs || !sent.certs.length) {
      if (sent.allowUnverified === true) return false;
      throw E("cmc/unverified-response",
        "the CMC response signature MUST be verified (RFC 5272 sec. 3.2.1.3.4) -- pass `certs` with the responder's certificate, or `allowUnverified: true` to accept an unauthenticated response deliberately");
    }
    return cmsVerify.verify(body.cms, { certs: sent.certs }).then(function (res) {
      if (!res.valid) {
        throw E("cmc/unverified-response",
          "the CMC response signature did not verify against the supplied certificates" +
          (res.signers && res.signers[0] && res.signers[0].code ? " (" + res.signers[0].code + ")" : ""));
      }
      return true;
    });
  });
}

function _shape(body, sent, signatureVerified) {
  var outcome = _reduceOutcome(body.statuses);
  var governing = _governingStatus(body.statuses, outcome);
  var anchors = _findControl(body.controls, OID_TRUSTED_ANCHORS, "Publish Trust Anchors");
  var confirm = _findControl(body.controls, OID_CONFIRM_CERT_ACCEPTANCE, "Confirm Certificate Acceptance");
  var serverNonce = _findControl(body.controls, OID_SENDER_NONCE, "Sender Nonce");

  return {
    outcome: outcome,
    statuses: body.statuses,
    // The detail belonging to the governing verdict, flattened for the common read.
    failInfo: governing ? governing.failInfoName : null,
    failInfoValue: governing ? governing.failInfo : null,
    extendedFailInfo: governing ? governing.extendedFailInfo : null,
    pendToken: governing && governing.pendInfo ? governing.pendInfo.pendToken : null,
    pendTime: governing && governing.pendInfo ? governing.pendInfo.pendTime : null,
    statusString: governing ? governing.statusString : null,
    transactionId: sent.transactionId != null ? sent.transactionId : null,
    // The responder's OWN nonce, retained by the caller for the next leg of the
    // same transaction (RFC 5272 sec. 6.6).
    senderNonce: serverNonce ? _octets(serverNonce, "Sender Nonce") : null,
    // Surfaced, never acted on -- see the primitive's note on trust.
    certificates: _bagOf(body.cms, "certs", "certificates"),
    crls: _bagOf(body.cms, "crls", "crls"),
    publishTrustAnchors: anchors ? anchors.values.slice() : null,
    confirmCertId: confirm ? _singleValue(confirm, "Confirm Certificate Acceptance") : null,
    // Whether the CARRIER's signature was checked. False only via the explicit
    // allowUnverified opt-out -- there is no path that leaves it false silently.
    signatureVerified: signatureVerified,
    // Whether anything in here was TRUSTED, which is never: the certificate bag
    // and any Publish Trust Anchors control are the caller's to path-validate.
    trusted: false,
    controls: body.controls,
    unhandled: body.unhandled,
    cms: body.cms,
  };
}

/**
 * @primitive  pki.cmc.build
 * @signature  pki.cmc.build(spec, signer, opts?) -> Promise<Buffer|string>
 * @since      0.4.16
 * @status     experimental
 * @spec       RFC 5272, RFC 6402
 * @defends    enrollment-request-substitution (CWE-345)
 * @related    pki.cmc.verify, pki.schema.cmc.parse, pki.cms.sign
 *
 * Build and sign an RFC 5272 Full PKI Request. `spec.requests` is the list of certification
 * requests, each naming exactly one arm -- `tcr` (a PKCS#10 CSR), `crm` (a CRMF CertReqMsg, or the
 * CertReqMessages `pki.crmf.build` returns when it carries exactly one) or `orm`
 * (`{ type, value }`). `spec.controls` are additional controls as `{ type, value }`, and `signer`
 * is the `{ cert, key }` that signs the enclosing CMS SignedData.
 *
 * Body part identifiers are allocated automatically, unique across the whole message and never 0
 * (RFC 5272 sec. 3.2.2). A caller may pin one, and a clash is REFUSED rather than renumbered --
 * silently moving an identifier would break any control that already referenced it. For a `crm`
 * arm the identity is the CertReqMsg's own `certReqId`, read back out of the supplied message.
 *
 * `spec.identityProof: { secret, identity? }` attaches an Identity Proof V2 control whose witness is
 * computed over the reqSequence bytes exactly as they are emitted (sec. 6.2.1 step 1 -- "encoded
 * exactly as it appears in the Full PKI Request including the sequence type and length"). Supplying
 * `identity` also emits the Identification control naming the shared secret, and -- per sec. 6.2.3 --
 * derives the MAC key from `hash(secret || identity)` rather than `hash(secret)`: the two travel
 * together because the control's presence is what changes the derivation. And
 * `spec.popLink: { secret }` attaches a POP Link Witness V2 together with the POP Link Random
 * control that PL1 requires in the same request. `spec.renewal: true` marks a renewal, which MUST
 * carry neither Identification nor Identity Proof (sec. 3.2 (a)) -- asking for both is refused
 * rather than silently dropped.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CMS` block instead of DER.
 *   - `popLinkRandomBytes` (number) -- the length of R; default 64 (PL1 SHOULD: >= 512 bits).
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var spki = await pki.key.export(pair.publicKey);
 *   var cert = await pki.x509.sign({ subject: "client", subjectPublicKey: spki,
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var csr = await pki.csr.sign({ subject: "client", subjectPublicKey: spki }, { key: key });
 *   var req = await pki.cmc.build({ requests: [{ tcr: csr }] }, { cert: cert, key: key });
 *   pki.schema.cmc.parse(req).requests[0].arm;   // "tcr"
 */
var build = require("./cmc-build").build;

module.exports = { verify: verify, build: build };
