// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.cmc
 * @nav        Enrollment
 * @title      CMC
 * @fullname   CMC (Certificate Management over CMS, RFC 5272)
 * @intro Interpret an RFC 5272 Full PKI Response. `verify(response, sent)` takes the response
 *   a CA returned and the state the client retained from its request, binds the two together
 *   (transaction identifier, the Sender/Recipient Nonce echo, the Data Return echo), reads the
 *   ordered status verdicts, and reduces them to one terminal outcome: `issued`, `pending`,
 *   `confirm-required`, `pop-required` or `rejected`. The issued certificates come from the CMS
 *   certificate bag, where RFC 5272 sec. 4.2 puts them. Nothing here is trusted: the bag and any
 *   Publish Trust Anchors control are surfaced as DATA for the caller to validate through
 *   `pki.path.validate`.
 * @spec RFC 5272, RFC 5273, RFC 6402
 * @card Interpret a CMC Full PKI Response into one terminal verdict: transaction and nonce
 *   binding, the status verdicts, the certificate bag surfaced untrusted.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var cmc = require("./schema-cmc");
var cmsVerify = require("./cms-verify");   // PD14: the carrier's signature MUST be verified
var cmsDecrypt = require("./cms-decrypt"); // ... and an AuthenticatedData carrier by its MAC
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
// Own-key membership through an operation taken at load. Written out, the question reads two
// replaceable properties to answer one thing, and here it decides which controls a response carries.
var _hasOwn = intrinsic.hasOwn;
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
// never be improved by the order the controls happen to appear in: reporting
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
// same control type twice under different bodyPartIDs. Taking the first match
// would let an attacker pair one correct echo with a contradictory one and still
// satisfy the binding, so a duplicate is refused as ambiguous instead of
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
// reading only the SignedData shape would silently return an empty bag, and
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
 * not conditional is the converse: having sent one, an absent or differing echo
 * is a refusal, because that is exactly the replay the nonce exists to stop.
 *
 * Returns which halves ran, because "conditional" and "checked" are different
 * facts and the verdict has to be able to tell them apart.
 */
function _assertBound(body, sent) {
  // A zero-length value binds nothing. An empty senderNonce echoes equal in every
  // exchange that also used one, so counting its presence would report boundToRequest
  // true for a response captured from any of them -- the exact replay this gate exists
  // to refuse, passing because the comparison it ran was vacuous. The same holds for an
  // empty transactionId or dataReturn: a binding has to carry entropy to be a binding.
  function _carries(v) {
    if (v == null) return false;
    if (typeof v === "string") return v.length > 0;
    if (Buffer.isBuffer(v) || v instanceof Uint8Array) return v.length > 0;   // allow:byte-source-narrow -- sent.senderNonce / dataReturn are already normalized to a Buffer by _snapshotSent; this is a length test on a settled value, not an input door
    return true;   // an integer or other scalar identifier is its own value
  }
  var bound = {
    transactionId: _carries(sent.transactionId),
    senderNonce: _carries(sent.senderNonce),
    dataReturn: _carries(sent.dataReturn),
    bodyPartIDs: Array.isArray(sent.bodyPartIDs),
  };
  if (sent.transactionId != null) {
    var txControl = _findControl(body.controls, OID_TRANSACTION_ID, "Transaction Identifier");
    if (!txControl) {
      throw E("cmc/transaction-mismatch",
        "the request carried a Transaction Identifier control, so the response MUST include the same one (RFC 5272 sec. 6.6)");
    }
    var got = asn1.read.integer(asn1.decode(_singleValue(txControl, "Transaction Identifier")));
    // Compared against the value the authoring guard validated, never a fresh
    // conversion of the caller's input -- a number too large to hold an integer
    // exactly has already lost the digits that distinguish it from its neighbor.
    if (got !== sent.transactionIdValue) {
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
    // Constant-time and by full value: guard.crypto.constantTimeEqual gates the
    // length first, so a truncation or a prefix is an honest false and not a
    // match on the bytes that happen to line up.
    if (!guard.crypto.constantTimeEqual(_octets(rn, "Recipient Nonce"), Buffer.from(sent.senderNonce))) {
      throw E("cmc/nonce-mismatch", "the response Recipient Nonce does not match the Sender Nonce the request sent");
    }
  }

  // RFC 5272 sec. 6.4: "If the Data Return control appears in a Full PKI Request,
  // the server MUST return it as part of the PKI Response." The data is opaque to
  // the server, so the check is that the same bytes came back.
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

  // A status names, in its bodyList, the body parts it is ABOUT (RFC 5272
  // sec. 6.1.1). A status about a body part the request never carried is not an
  // answer to this request -- and the binding controls do not catch it, because a
  // server can echo the transaction and nonce correctly while reporting on
  // something else entirely. Held to the same asymmetry as every other half of the
  // binding: checked only when the client kept the set, and once kept, a reference
  // outside it is a refusal.
  // Element-by-element, and the lengths must agree: a retained `[a, b]` must not admit a
  // reported `[a, b, c]`, which names a part one level deeper than anything sent.
  function _pathRetained(retained, want) {
    if (!Array.isArray(retained)) return false;
    return retained.some(function (have) {
      return Array.isArray(have) && have.length === want.length && have.every(function (seg, i) {
        return String(seg) === String(want[i]);
      });
    });
  }
  if (Array.isArray(sent.bodyPartIDs)) {
    var known = Object.create(null);
    sent.bodyPartIDs.forEach(function (id) { known[String(id)] = true; });
    // 0 is reserved as the reference to the enclosing PKIData itself (sec. 3.2.1),
    // so a status about the request as a whole is in the set by definition.
    known["0"] = true;
    body.statuses.forEach(function (s) {
      (s.bodyList || []).forEach(function (ref) {
        var path = ref.bodyPartPath;
        // A bodyPartPath descends INTO a nested message. Checking only its head would
        // accept `[a part we sent, 999]`, a status about something arbitrary wearing a
        // reference that passes, so the whole path is matched against the paths the
        // request actually composed. Those are retained by reading each nested message
        // back; a nested message that could not be read back contributes none, so a path
        // into it finds no match and is refused. Either way the tail is never waved through.
        if (path && path.length > 1) {
          if (_pathRetained(sent.bodyPartPaths, path)) return;
          throw E("cmc/body-part-unknown",
            "a status control reports on a body part nested inside another message (path " + path.join("/") +
            "), which this request never sent -- nothing here can confirm what that names " +
            "(RFC 5272 sec. 6.1.1)");
        }
        var id = ref.bodyPartID != null ? ref.bodyPartID : (path && path.length ? path[0] : null);
        if (id == null || known[String(id)]) return;
        throw E("cmc/body-part-unknown",
          "a status control reports on body part " + id + ", which this request never sent -- the response " +
          "is about a different message (RFC 5272 sec. 6.1.1)");
      });
    });
  }

  // Every check above is conditional on the caller having retained something, so a
  // caller who retained nothing runs none of them and still gets a full verdict
  // (`issued`, signature verified, certificates surfaced) off a Full PKI Response
  // captured from any earlier exchange with the same CA. That is the CWE-294 this
  // module names as its defense, and leaving it opt-in leaves the defense off for
  // whoever did not know to ask.
  //
  // The posture here is the one _assertAuthentic already takes for the carrier
  // signature, applied to the other question: check it when the caller supplies
  // what it takes, and refuse when nothing does, unless the caller names that. The
  // two opt-outs stay separate because they answer separate questions. A replayed
  // response is authentic, so `allowUnverified` covering it would let "I could not
  // check the signature" stand in for "I did not check which exchange this
  // answers".
  //
  // bodyPartIDs does not count toward it. Identifiers are allocated per message
  // from a small range (sec. 3.2.2), so the same set recurs across requests and a
  // status naming one says nothing about which request it answers.
  bound.boundToRequest = bound.transactionId || bound.senderNonce || bound.dataReturn;
  if (!bound.boundToRequest && sent.allowUnbound !== true) {
    throw E("cmc/unbound-response",
      "nothing ties this response to a request. Pass what the request retained (`transactionId`, " +
      "`senderNonce`, whose echo is the replay defense of RFC 5272 sec. 6.6, or `dataReturn`) so the " +
      "echo can be checked, or `allowUnbound: true` to interpret a response that could be a replay of " +
      "any earlier exchange with this CA");
  }
  return bound;
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
 * Interpret a Full PKI Response into one terminal verdict. `response` is the DER or a PEM `CMS`
 * block; an already-parsed message is interpreted too, but only under `allowUnverified: true`,
 * because both carriers authenticate over BYTES and a parsed object the caller still owns pins
 * none. `sent` is what the client retained from its request --
 * `transactionId`, `senderNonce`, `dataReturn`, and `bodyPartIDs` (every identifier the request
 * carried). Each of those is checked only if it was sent, and once sent an absent or differing
 * echo is a refusal: that asymmetry is the replay defense. `bodyPartIDs` is the same rule applied
 * to what the response is ABOUT -- a status naming a body part the request never sent is refused
 * with `cmc/body-part-unknown`, which the transaction and nonce cannot catch, since a server can
 * echo both correctly while reporting on something else.
 *
 * Because each half is conditional, a caller who retains nothing runs none of them. A Full PKI
 * Response captured from any earlier exchange with the same CA would then read as this request's
 * answer, correctly signed. That case is refused as `cmc/unbound-response` unless the caller names
 * it with `allowUnbound: true`, a separate opt-out from `allowUnverified` because it answers a
 * separate question: a replayed response is authentic. `bodyPartIDs` alone does not satisfy it,
 * since identifiers are allocated per message from a small range (RFC 5272 sec. 3.2.2) and the
 * same set recurs across requests. The verdict reports which halves ran as `bound.transactionId`,
 * `bound.senderNonce`, `bound.dataReturn` and `bound.bodyPartIDs`, with `boundToRequest` for the
 * roll-up.
 *
 * The verdict carries the response's own `cmsSequence` and `otherMsgs` raw, because a request whose
 * only arm was the other-message form has no certificate to return and RFC 5272 sec. 4.1 puts its
 * answer there instead.
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
 * The other carrier sec. 3.2 permits, AuthenticatedData, is authenticated by its MAC instead: pass
 * `recipient` with the key material and the MAC is checked through `pki.cms.decrypt`, so a caller
 * who holds the key gets an authenticated verdict instead of the unauthenticated opt-out.
 *
 * Nothing is trusted here. `certificates` is the CMS certificate bag, where RFC 5272 sec. 4.2
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
 *   - `recipient` (object) -- key material for an AuthenticatedData carrier, in the shape
 *     `pki.cms.decrypt` takes. Its MAC is then checked and the verdict reports
 *     `signatureVerified: true`; the content it authenticates is bound to the content the verdict
 *     was read from, so a MAC over other bytes cannot stand in for it.
 *   - `allowUnverified` (boolean) -- interpret without verifying the carrier; sets `signatureVerified: false`.
 *   - `allowUnbound` (boolean) -- interpret a response nothing ties to a request; sets
 *     `boundToRequest: false`. Needed only when none of `transactionId`, `senderNonce` or
 *     `dataReturn` was retained, and what it accepts is a possible replay.
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
 *   var v = await pki.cmc.verify(der, { allowUnverified: true, allowUnbound: true });
 *   v.outcome;             // "issued" -- no status control means success is assumed
 *   v.signatureVerified;   // false -- the opt-out was named, so nothing was checked
 *   v.boundToRequest;      // false: nothing ties this response to a request either
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
  return guard.async.deferred(function () { return _verify(frozenResponse, frozenSent); });
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
  // EVERY byte form the parser accepts, not just the two most common. It takes a
  // BufferSource, so an ArrayBuffer or a DataView reaches the decoder too -- and
  // leaving those aliased would reopen the window for exactly the inputs that came
  // in by the wider door.
  if (guard.bytes.isByteSource(input)) {
    return guard.bytes.snapshotSource(input, CmcError, "cmc/bad-input", "pki.cmc.verify");
  }
  return input;
}

// A private copy of the exchange state the binding checks compare against. Scalars
// are copied by value and every byte buffer is copied, so nothing the caller still
// holds a reference to can change what "what we sent" means once verification has
// begun. Unknown fields are carried through untouched -- this fixes the values the
// checks below read, it does not narrow what the options object may contain.
// EVERY byte form, not just the two most common: a DataView or a bare ArrayBuffer arrives by the
// same door as a Buffer, and copying only Buffer and Uint8Array would leave those aliased across
// the very gap this closes -- reopening the window for exactly the inputs that came in by the
// wider one. A DataView is copied over its OWN window, not the whole buffer it happens to sit in.
// One call, because guard.bytes decides what a byte form is and where its bytes are. The three
// hand-rolled branches this replaces read `v.buffer`, `v.byteOffset` and `v.byteLength` off the
// value, and all three are accessors a caller's subclass can answer: one that lied copied a
// different store than the array held, so the bytes checked here and the bytes signed later were
// two different reads.
function _copyAnyBytes(v) {
  if (!guard.bytes.isByteSource(v)) return v;
  return guard.bytes.snapshotSource(v, CmcError, "cmc/bad-input", "a byte field of the request");
}

function _snapshotSent(sent) {
  var out = {}, k;
  for (k in sent) { if (_hasOwn(sent, k)) out[k] = sent[k]; }
  // Normalized through the SAME authoring guard pki.cmc.build puts an authored
  // integer through. A Transaction Identifier is an unbounded INTEGER on the wire,
  // so one above Number.MAX_SAFE_INTEGER has already been rounded by the time it
  // arrives as a `number` -- 9007199254740993 is 9007199254740992 before this code
  // sees it, and a response echoing that NEIGHBORING identifier would compare
  // equal. Held here rather than converted, so a value too large to be a number is
  // refused with the shape to use instead (a bigint) rather than silently bound to
  // something adjacent.
  // Validated, not replaced: the verdict echoes `transactionId` as the caller gave
  // it, so the check is added without changing what comes back.
  // Through ONE helper so nothing here can copy "the two common byte forms" and leave the rest
  // aliased -- the narrowing that reopens this window for whatever came in by the wider door.
  if (out.transactionId != null) {
    out.transactionIdValue = guard.range.authoredInteger(out.transactionId, E, "cmc/bad-input", "sent.transactionId");
  }
  out.senderNonce = _copyAnyBytes(out.senderNonce);
  out.dataReturn = _copyAnyBytes(out.dataReturn);
  // Copied for the same reason the nonce is: the check runs after an await, and an
  // array the caller still holds could have body parts appended to it in the gap,
  // widening what the response is allowed to report on.
  if (Array.isArray(out.bodyPartIDs)) out.bodyPartIDs = out.bodyPartIDs.slice();
  // Both levels: the outer array AND each path, since appending a segment to a retained path
  // in the gap would widen what the response may report on exactly as appending an id does.
  if (Array.isArray(out.bodyPartPaths)) {
    out.bodyPartPaths = out.bodyPartPaths.map(function (p) { return Array.isArray(p) ? p.slice() : p; });
  }
  if (out.recipient && typeof out.recipient === "object") {
    var r = {}, rk;
    for (rk in out.recipient) {
      if (!_hasOwn(out.recipient, rk)) continue;
      r[rk] = _copyAnyBytes(out.recipient[rk]);
    }
    out.recipient = r;
  }
  if (Array.isArray(out.certs)) out.certs = out.certs.map(_copyAnyBytes);
  // Both opt-outs normalized to a strict boolean off the ORIGINAL object, so a
  // truthy-but-not-true value cannot switch a check off by accident.
  out.allowUnverified = sent.allowUnverified === true;
  out.allowUnbound = sent.allowUnbound === true;
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

  return _assertAuthentic(body, sent, response).then(function (signatureVerified) {
    return _shape(body, sent, signatureVerified, _assertBound(body, sent));
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
function _assertAuthentic(body, sent, responseBytes) {
  return Promise.resolve().then(function () {
    // Authentication is over BYTES, and that is true of BOTH carriers -- a MAC and
    // a signature alike. The already-parsed input form hands this layer an object
    // the CALLER still owns: the verdict is read from it synchronously, the check
    // runs a microtask later, and a caller that swaps the encapsulated content,
    // the signers and the certificate bag in the gap would get one message's
    // verdict reported beside another message's verified signature. There are no
    // bytes to pin, so the honest answer is that nothing was authenticated.
    var haveBytes = typeof responseBytes === "string" ||
      Buffer.isBuffer(responseBytes) || responseBytes instanceof Uint8Array;   // allow:byte-source-narrow -- responseBytes is _snapshotIfBytes's return: any BufferSource is already a Buffer here, so this is Buffer-or-string by construction
    // The two accepted carriers are authenticated DIFFERENTLY, so the rule has to
    // be written for both: a SignedData by its SignerInfo signatures, an
    // AuthenticatedData by a MAC over a key this layer never holds. Checking only
    // the SignedData shape would reject every conforming AuthenticatedData
    // response for having no signer -- which is not a defect in the message.
    if (body.cms && body.cms.contentTypeName === "authData") {
      // The MAC needs key material this layer does not invent -- but a caller who
      // HAS it should not be forced through the unauthenticated opt-out, which
      // would report signatureVerified:false for a response whose MAC checked out.
      // pki.cms.decrypt owns AuthenticatedData; `recipient` is handed to it rather
      // than the MAC being recomputed here.
      if (sent.recipient != null) {
        // pki.cms.decrypt deliberately refuses a pre-parsed object too, so nothing
        // can hand it a parse result that skipped DER validation. When the caller
        // used the already-parsed input form there are no bytes to check, and
        // saying exactly that is the honest answer -- reporting "did not
        // authenticate" would blame the message for what is a missing input.
        if (!haveBytes) {
          throw E("cmc/bad-input",
            "authenticating an AuthenticatedData response needs the response as DER bytes or PEM, " +
            "because its MAC is computed over them -- pass the encoded response rather than a parsed one");
        }
        // It re-parses, and the content check below then ties its result back to
        // what was interpreted here.
        return cmsDecrypt.decrypt(responseBytes, sent.recipient).then(null, function (e) {
          // The CMS layer's code does not escape this surface. cms/decrypt-failed is
          // deliberately oracle-free -- every secret-dependent failure collapses into
          // it -- and that property is preserved by re-throwing it as this domain's
          // own verdict with the cause chained, rather than adding any detail.
          throw E("cmc/unverified-response",
            "the AuthenticatedData response did not authenticate under the supplied recipient key", e);
        }).then(function (res) {
          if (!res || res.authenticated !== true) {
            throw E("cmc/unverified-response", "the AuthenticatedData response did not authenticate under the supplied recipient key");
          }
          // The MAC covers BYTES; bind them to the ones that were interpreted.
          // Verifying a MAC over content and then reporting a verdict read from
          // somewhere else is the same defect as checking a signature over the
          // wrong region -- authentic, and about a different message.
          // Both are already Buffers -- pki.cms.decrypt returns one, and the parse
          // surfaces one -- so they are compared directly rather than re-wrapped.
          var authed = res.content;
          var eContent = body.cms.encapContentInfo && body.cms.encapContentInfo.eContent;
          if (!eContent || !Buffer.isBuffer(authed) || !guard.crypto.constantTimeEqual(authed, eContent)) {
            throw E("cmc/unverified-response",
              "the authenticated content is not the content this verdict was read from");
          }
          return true;
        });
      }
      if (sent.allowUnverified === true) return false;
      throw E("cmc/unverified-response",
        "an AuthenticatedData response is authenticated by its MAC, which needs the recipient key this layer does not hold -- pass `recipient` with the key material (the shape pki.cms.decrypt takes), or `allowUnverified: true` to interpret it unauthenticated");
    }
    var signerInfos = (body.cms && body.cms.signerInfos) || [];
    if (!signerInfos.length) {
      throw E("cmc/unsigned-response",
        "a Full PKI Response is a SignedData carrying at least one SignerInfo; this carrier has none, so there is no signature to verify (RFC 5272 sec. 4.2 / 3.2.1.3.4)");
    }
    // Same rule as the MAC arm above, applied where a signature is equally over
    // bytes. The carrier's SHAPE is judged first -- an unsigned one is refused
    // whatever form it arrived in -- and only the act of authenticating needs the
    // bytes. A caller who has nothing but a parsed message can still interpret it
    // through the named opt-out, which reports signatureVerified:false; what is
    // refused is the combination that would claim a check nothing pinned.
    if (!haveBytes) {
      if (sent.allowUnverified === true) return false;
      throw E("cmc/bad-input",
        "verifying a CMC response signature needs the response as DER bytes or PEM, because the " +
        "signature is over them -- pass the encoded response rather than a parsed one, or " +
        "`allowUnverified: true` to interpret it unauthenticated");
    }
    // Verified over the SAME immutable snapshot the verdict was parsed from, not
    // over the parse result: the two cannot describe different messages when both
    // come from one private copy of the bytes.
    //
    // TRY first, and only report "cannot verify" when the signer certificate is
    // genuinely nowhere to be found. A conforming SignedData carries its own signer
    // certificate, which is the shape pki.cmc.build emits and the one a CA sends --
    // demanding that the caller ALSO pass it would make the ordinary
    // build-then-verify flow fail for a message that already contains everything
    // needed. `certs` supplements the embedded bag; it was never meant to be the
    // only source. What does not change is the posture: a signature that is present
    // and does not verify is a refusal, and an unverifiable one still needs the
    // named opt-out rather than passing quietly.
    return cmsVerify.verify(responseBytes, sent.certs && sent.certs.length ? { certs: sent.certs } : {})
      .then(function (res) {
        if (res.valid) return true;
        // EVERY failing signer, not just the first. A response may carry several,
        // and the opt-out may only be honored when none of them was actually
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

function _shape(body, sent, signatureVerified, bound) {
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
    // The response's OWN two sequences, raw. For a request whose only arm was the
    // other-message form there is no certificate to return, and RFC 5272 sec. 4.1
    // puts the answer here instead -- so leaving them out would give such an
    // exchange a successful verdict with its result unreachable, and send the
    // caller back to the encapsulated bytes to re-parse what was already decoded.
    cmsSequence: (body.cmsSequence || []).slice(),
    otherMsgs: (body.otherMsgs || []).slice(),
    publishTrustAnchors: anchors ? anchors.values.slice() : null,
    confirmCertId: confirm ? _singleValue(confirm, "Confirm Certificate Acceptance") : null,
    // Whether the CARRIER's signature was checked. False only via the explicit
    // allowUnverified opt-out -- there is no path that leaves it false silently.
    signatureVerified: signatureVerified,
    // Which halves of the exchange binding ran (RFC 5272 sec. 6.6 / 6.4). Each is
    // conditional on the caller having retained the value, so a bare `outcome`
    // cannot say whether this response answers this request or an earlier one.
    // These can. `boundToRequest` is false only via the explicit allowUnbound
    // opt-out; nothing leaves it false silently.
    bound: {
      transactionId: bound.transactionId,
      senderNonce: bound.senderNonce,
      dataReturn: bound.dataReturn,
      bodyPartIDs: bound.bodyPartIDs,
    },
    boundToRequest: bound.boundToRequest,
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
 * requests, each naming exactly one arm: `tcr` (a PKCS#10 CSR), `crm` (a CRMF CertReqMsg, or the
 * CertReqMessages `pki.crmf.build` returns when it carries exactly one) or `orm`
 * (`{ type, value }`). `spec.controls` are additional controls as `{ type, value }`, and `signer`
 * is the `{ cert, key }` that signs the enclosing CMS SignedData. A `tcr` request is verified against
 * its own proof-of-possession first: a PKCS#10 whose self-signature does not verify under its subject
 * public key is refused (`cmc/bad-popo`) rather than signed into a message a CA would reject.
 *
 * Body part identifiers are allocated automatically, unique across the whole message and never 0
 * (RFC 5272 sec. 3.2.2). A caller may pin one, and a clash is refused, never renumbered, because
 * silently moving an identifier would break any control that already referenced it. For a `crm`
 * arm the identity is the CertReqMsg's own `certReqId`, read back out of the supplied message.
 *
 * `spec.identityProof: { secret, identity? }` attaches an Identity Proof V2 control whose witness is
 * computed over the reqSequence bytes exactly as they are emitted (sec. 6.2.1 step 1: "encoded
 * exactly as it appears in the Full PKI Request including the sequence type and length"). Supplying
 * `identity` also emits the Identification control naming the shared secret and, per sec. 6.2.3,
 * derives the MAC key from `hash(secret || identity)` in place of `hash(secret)`: the two travel
 * together because the control's presence is what changes the derivation. And
 * `spec.popLink: { secret }` attaches a POP Link Witness V2 together with the POP Link Random
 * control that PL1 requires in the same request. `spec.renewal: true` marks a renewal, which MUST
 * carry neither Identification nor Identity Proof (sec. 3.2 (a)), so asking for both is refused
 * and never silently dropped.
 *
 * `spec.transactionId` (number|bigint), `spec.senderNonce` and `spec.dataReturn` (bytes) attach the
 * exchange-binding controls (RFC 5272 sec. 6.6 / 6.4), the same three `pki.cmc.verify` checks the
 * response against. They are named fields, not something to hand-encode into
 * `spec.controls`, because a request that quietly omits them has no replay defense and neither end
 * can tell: the verifier only enforces the halves the client says it sent. An unrecognized spec
 * field is refused for the same reason: a misspelling would otherwise build and sign a message
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
