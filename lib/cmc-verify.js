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
 * The carrier's signature MUST be verified (RFC 5272 sec. 3.2.1.3.4). A conforming SignedData
 * carries its own signer certificate, so the ordinary case needs nothing from the caller: the
 * signature is checked and the verdict reports `signatureVerified: true`. Where the signer cannot be
 * found -- not embedded and not supplied -- the posture is fail-closed with a NAMED opt-out rather
 * than a silent one: pass `certs` with the responder's certificate, or `allowUnverified: true` and
 * the verdict reports `signatureVerified: false`. Doing neither is refused, because that is the case
 * where a caller would otherwise assume a check happened. The opt-out covers "could not check",
 * never "checked and it failed": a signature that is present and wrong is always a refusal. A
 * carrier with no SignerInfo at all is not a Full PKI Response and is refused outright.
 *
 * `certs` SUPPLEMENTS the certificates the message carries; it does not pin the signer (a SignedData
 * names its own, which is what the signature is checked against) and it establishes no trust.
 * Deciding the signer is acceptable is path validation, which is the caller's.
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
 *   - `certs` (Buffer[]) -- extra certificates for signer lookup, for a message that does not carry
 *     its own signer; the certificates the message carries are searched either way.
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
  // Both snapshots are taken SYNCHRONOUSLY, here, before anything is deferred.
  // Taking them inside the async body would be too late by one microtask: a caller
  // that mutates the buffer or the options object on the line after this call has
  // already changed them before that body ever runs, which is the easiest version
  // of the race to hit by accident.
  var frozenResponse, frozenSent;
  try {
    frozenSent = _snapshotSent(_assertOpts(sent));
    frozenResponse = _snapshotIfBytes(response);
  } catch (e) {
    return Promise.reject(e);   // the surface stays promise-rejecting, never throwing
  }
  return Promise.resolve().then(function () { return _verify(frozenResponse, frozenSent); });
}

function _assertOpts(sent) {
  if (sent == null) return {};
  if (typeof sent !== "object" || Array.isArray(sent) || Buffer.isBuffer(sent)) {
    throw E("cmc/bad-input", "pki.cmc.verify options must be an object");
  }
  return sent;
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

// A private copy of the exchange state the binding checks compare against. Scalars
// are copied by value and every byte buffer is copied, so nothing the caller still
// holds a reference to can change what "what we sent" means once verification has
// begun. Unknown fields are carried through untouched -- this fixes the values the
// checks below read, it does not narrow what the options object may contain.
function _snapshotSent(sent) {
  var out = {}, k;
  for (k in sent) { if (Object.prototype.hasOwnProperty.call(sent, k)) out[k] = sent[k]; }
  if (Buffer.isBuffer(out.senderNonce) || out.senderNonce instanceof Uint8Array) {
    out.senderNonce = Buffer.from(out.senderNonce);
  }
  if (Buffer.isBuffer(out.dataReturn) || out.dataReturn instanceof Uint8Array) {
    out.dataReturn = Buffer.from(out.dataReturn);
  }
  if (Array.isArray(out.certs)) {
    out.certs = out.certs.map(function (c) {
      return (Buffer.isBuffer(c) || c instanceof Uint8Array) ? Buffer.from(c) : c;
    });
  }
  out.allowUnverified = sent.allowUnverified === true;
  return out;
}

// `response` and `sent` arrive already frozen by verify() above -- BOTH sides of
// every comparison, not just the response bytes. The checks below run across an
// await and compare what the CA returned against what the caller says it sent, so
// freezing one side while reading the other live would leave half of each
// comparison mutable.
function _verify(response, sent) {
  var body = cmc.parse(response);
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
    // TRY first, and only report "cannot verify" when the signer certificate is
    // genuinely nowhere to be found. A conforming SignedData carries its own signer
    // certificate, which is the shape pki.cmc.build emits and the one a CA sends --
    // demanding that the caller ALSO pass it would make the ordinary
    // build-then-verify flow fail for a message that already contains everything
    // needed. `certs` supplements the embedded bag; it was never meant to be the
    // only source. What does not change is the posture: a signature that is present
    // and does not verify is a refusal, and an unverifiable one still needs the
    // named opt-out rather than passing quietly.
    return cmsVerify.verify(body.cms, sent.certs && sent.certs.length ? { certs: sent.certs } : {})
      .then(function (res) {
        if (res.valid) return true;
        // EVERY failing signer, not just the first. A response may carry several,
        // and the opt-out may only be honoured when none of them was actually
        // checked and rejected: one signer whose certificate is missing must not
        // let a DIFFERENT signer's failed signature through beside it.
        var failed = (res.signers || []).filter(function (s) { return !s.ok; });
        var code = failed.length ? failed[0].code : null;
        var onlyMissing = failed.length > 0 && failed.every(function (s) {
          return s.code === "cms/signer-cert-not-found";
        });
        // No signer certificate anywhere is "could not check", which the opt-out
        // covers. A signature that failed against a certificate we DID find is a
        // real failure, and no opt-out excuses it.
        if (onlyMissing && sent.allowUnverified === true) return false;
        throw E("cmc/unverified-response",
          "the CMC response signature did not verify" + (code ? " (" + code + ")" : "") +
          " -- pass `certs` with the responder's certificate if it is not carried in the message, or " +
          "`allowUnverified: true` to accept an unauthenticated response deliberately");
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
 * `spec.transactionId` (number|bigint), `spec.senderNonce` and `spec.dataReturn` (bytes) attach the
 * exchange-binding controls (RFC 5272 sec. 6.6 / 6.4) -- the same three `pki.cmc.verify` checks the
 * response against. They are named fields rather than something to hand-encode into
 * `spec.controls`, because a request that quietly omits them has no replay defence and neither end
 * can tell: the verifier only enforces the halves the client says it sent. An unrecognized spec
 * field is refused for the same reason -- a misspelling would otherwise build and sign a message
 * that simply does not carry what was asked for.
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
