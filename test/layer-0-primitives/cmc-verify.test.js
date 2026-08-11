// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cmc.verify (RFC 5272 sec. 4, 6.1, 6.4, 6.6; RFC 5273 sec. 6).
 *
 * The interpreting half of the CMC message layer: given a Full PKI Response and
 * the state the client retained from its request, produce ONE terminal verdict.
 * Spec-first conformance vectors, RED-first -- pki.cmc.verify is undefined until
 * the module lands, so every vector throws and the suite drives it GREEN.
 *
 * The rules this file exists to pin, each one a place where a plausible
 * implementation is wrong:
 *   - ST5: the ABSENCE of a status control means SUCCESS. "If no status exists
 *     for a Simple or Full PKI Request, then the value of success is assumed."
 *     A verifier that demands one rejects conforming responses.
 *   - TX2: the nonce echo is compared in CONSTANT TIME and by full value --
 *     a prefix of the sent nonce is not a match, because length is part of
 *     identity.
 *   - TX1/TX2 are CONDITIONAL on the client having sent them: a client that sent
 *     no senderNonce cannot demand a recipientNonce back.
 *   - CT6: a Data Return control the client sent MUST come back.
 *   - PR4/PR5: the issued certificates live in the CMS bag, and NOTHING here is
 *     trusted -- the certificate bag and any Publish Trust Anchors control are
 *     surfaced as data for the caller to validate.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

var ID_CCT_PKI_RESPONSE = "1.3.6.1.5.5.7.12.3";
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var SHA256 = "2.16.840.1.101.3.4.2.1";
var ID_CMC_STATUS_INFO_V2 = "1.3.6.1.5.5.7.7.25";
var ID_CMC_TRANSACTION_ID = "1.3.6.1.5.5.7.7.5";
var ID_CMC_SENDER_NONCE = "1.3.6.1.5.5.7.7.6";
var ID_CMC_RECIPIENT_NONCE = "1.3.6.1.5.5.7.7.7";
var ID_CMC_DATA_RETURN = "1.3.6.1.5.5.7.7.4";
var ID_CMC_TRUSTED_ANCHORS = "1.3.6.1.5.5.7.7.26";

async function acode(fn) {
  try { await fn(); return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); }
}

function attr(id, type, values) {
  return b.sequence([b.integer(BigInt(id)), b.oid(type), b.set(values)]);
}
function statusV2(id, status, other) {
  var f = [b.integer(BigInt(status)), b.sequence([b.sequence([b.integer(1n)])])];
  if (other) f.push(other);
  return attr(id, ID_CMC_STATUS_INFO_V2, [b.sequence(f)]);
}

// A PKIResponse in a SignedData carrier. certs go in the CMS certificates [0]
// bag, which is where RFC 5272 sec. 4.2 puts the ISSUED certificates -- never
// inside PKIResponse itself.
// A synthetic SignerInfo. These interpretation vectors are about the CMC layer,
// not the signature, so the carrier carries a structurally present signer and the
// vectors pass `allowUnverified: true` -- the named opt-out, so the file says out
// loud that it is not exercising authentication rather than quietly relying on it
// not being checked.
function fakeSignerInfo() {
  var sid = b.sequence([b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]), b.integer(1n)]);
  // RFC 5652 sec. 5.3 requires signedAttrs whenever the content type is not
  // id-data, and the CMS parser enforces it -- so the synthetic signer carries
  // the two mandatory attributes rather than being a shape the parser refuses.
  var signedAttrs = b.contextConstructed(0, Buffer.concat([
    b.sequence([b.oid("1.2.840.113549.1.9.3"), b.set([b.oid(ID_CCT_PKI_RESPONSE)])]),
    b.sequence([b.oid("1.2.840.113549.1.9.4"), b.set([b.octetString(Buffer.alloc(32, 3))])]),
  ]));
  return b.sequence([b.integer(1n), sid, b.sequence([b.oid(SHA256), b.nullValue()]), signedAttrs,
    b.sequence([b.oid("1.2.840.113549.1.1.1"), b.nullValue()]), b.octetString(Buffer.alloc(8, 1))]);
}

function response(controls, certsDer) { return _response(controls, certsDer, true); }
// The same message with NO SignerInfo at all -- the shape RFC 5272 sec. 4.2 says
// a Full PKI Response is not.
function unsignedResponse(controls) { return _response(controls, null, false); }

function _response(controls, certsDer, withSigner) {
  var body = b.sequence([b.sequence(controls || []), b.sequence([]), b.sequence([])]);
  var encap = b.sequence([b.oid(ID_CCT_PKI_RESPONSE), b.explicit(0, b.octetString(body))]);
  var fields = [b.integer(3n), b.set([b.sequence([b.oid(SHA256), b.nullValue()])]), encap];
  if (certsDer && certsDer.length) fields.push(b.contextConstructed(0, Buffer.concat(certsDer)));
  fields.push(withSigner ? b.set([fakeSignerInfo()]) : b.set([]));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(fields))]);
}

// A PKIResponse in an AuthenticatedData carrier, with the certificate bag under
// originatorInfo. RFC 5652 sec. 9.1 requires authAttrs (carrying contentType +
// messageDigest) whenever the encapsulated content type is not id-data, and a
// digestAlgorithm [1] whenever authAttrs are present; both context tags are
// IMPLICIT, so each REPLACES the tag of the type it stands for.
function authenticatedData(certDer) {
  var body = b.sequence([b.sequence([]), b.sequence([]), b.sequence([])]);
  var encap = b.sequence([b.oid(ID_CCT_PKI_RESPONSE), b.explicit(0, b.octetString(body))]);
  var originatorInfo = b.contextConstructed(0, b.contextConstructed(0, certDer));
  var iasn = b.sequence([b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]), b.integer(1n)]);
  var ktri = b.sequence([b.integer(0n), iasn,
    b.sequence([b.oid("1.2.840.113549.1.1.1"), b.nullValue()]), b.octetString(Buffer.alloc(16, 7))]);
  var authAttrs = b.contextConstructed(2, Buffer.concat([
    b.sequence([b.oid("1.2.840.113549.1.9.3"), b.set([b.oid(ID_CCT_PKI_RESPONSE)])]),
    b.sequence([b.oid("1.2.840.113549.1.9.4"), b.set([b.octetString(Buffer.alloc(32, 3))])]),
  ]));
  var ad = b.sequence([
    b.integer(0n), originatorInfo, b.set([ktri]),
    b.sequence([b.oid("1.2.840.113549.2.9")]),                                  // macAlgorithm HMAC-SHA256
    b.contextConstructed(1, Buffer.concat([b.oid(SHA256), b.nullValue()])),     // digestAlgorithm [1] IMPLICIT
    encap, authAttrs, b.octetString(Buffer.alloc(32, 9)),
  ]);
  return b.sequence([b.oid(pki.oid.byName("authData")), b.explicit(0, ad)]);
}

async function run() {
  var TX = 4242;
  var NONCE = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
  var SERVER_NONCE = Buffer.from("fedcba9876543210fedcba9876543210", "hex");

  function txControls(extra) {
    return [
      attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX))]),
      attr(2, ID_CMC_RECIPIENT_NONCE, [b.octetString(NONCE)]),
      attr(3, ID_CMC_SENDER_NONCE, [b.octetString(SERVER_NONCE)]),
    ].concat(extra || []);
  }
  var sent = { transactionId: TX, senderNonce: NONCE, allowUnverified: true };

  // ---- D1 / ST5: absence of a status control is SUCCESS ----------------
  var d1 = await pki.cmc.verify(response([]), { allowUnverified: true });
  check("D1. a PKIResponse with NO status control verifies as issued (ST5: success is assumed)",
    d1.outcome === "issued" && d1.statuses.length === 0);

  // ---- E1: the happy path binds the exchange ---------------------------
  var e1 = await pki.cmc.verify(response(txControls([statusV2(4, 0, null)])), sent);
  check("E1. a matching transactionId + echoed recipientNonce verifies",
    e1.outcome === "issued" && e1.transactionId === TX);
  check("E1b. the responder's own senderNonce is surfaced for the next leg (TX2)",
    Buffer.isBuffer(e1.senderNonce) && Buffer.compare(e1.senderNonce, SERVER_NONCE) === 0);

  // ---- E2 / E3: the nonce compare is by FULL VALUE ---------------------
  var flipped = Buffer.from(NONCE); flipped[flipped.length - 1] ^= 0x01;
  check("E2. a recipientNonce differing by one byte is refused",
    (await acode(function () {
      return pki.cmc.verify(response([
        attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX))]),
        attr(2, ID_CMC_RECIPIENT_NONCE, [b.octetString(flipped)]),
      ]), sent);
    })) === "cmc/nonce-mismatch");

  // A prefix must NOT match: length is part of the nonce's identity, and a
  // compare that stopped at the shorter length would accept a truncation.
  check("E3. a recipientNonce that is a PREFIX of the sent nonce is refused",
    (await acode(function () {
      return pki.cmc.verify(response([
        attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX))]),
        attr(2, ID_CMC_RECIPIENT_NONCE, [b.octetString(NONCE.subarray(0, 8))]),
      ]), sent);
    })) === "cmc/nonce-mismatch");

  // ---- E4: the transaction identity -----------------------------------
  check("E4. a differing transactionId is refused (TX1)",
    (await acode(function () {
      return pki.cmc.verify(response([
        attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX + 1))]),
        attr(2, ID_CMC_RECIPIENT_NONCE, [b.octetString(NONCE)]),
      ]), sent);
    })) === "cmc/transaction-mismatch");

  check("E4b. an ABSENT transactionId is refused when the request carried one",
    (await acode(function () {
      return pki.cmc.verify(response([attr(2, ID_CMC_RECIPIENT_NONCE, [b.octetString(NONCE)])]), sent);
    })) === "cmc/transaction-mismatch");

  // ---- E5 / E6: the echo is conditional on having SENT a nonce ---------
  check("E5. a response omitting recipientNonce is refused when the request sent one (TX2)",
    (await acode(function () {
      return pki.cmc.verify(response([attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX))])]), sent);
    })) === "cmc/nonce-mismatch");

  var e6 = await pki.cmc.verify(response([statusV2(1, 0, null)]), { allowUnverified: true });
  check("E6. a client that sent NO senderNonce accepts a response carrying no recipientNonce",
    e6.outcome === "issued");

  // ---- E7: the Data Return echo (CT6) ---------------------------------
  var DATA = Buffer.from("client state");
  check("E7. a dataReturn control the client sent must come back (CT6)",
    (await acode(function () {
      return pki.cmc.verify(response(txControls([statusV2(4, 0, null)])),
        { transactionId: TX, senderNonce: NONCE, dataReturn: DATA, allowUnverified: true });
    })) === "cmc/data-return-missing");

  var e7 = await pki.cmc.verify(
    response(txControls([statusV2(4, 0, null), attr(5, ID_CMC_DATA_RETURN, [b.octetString(DATA)])])),
    { transactionId: TX, senderNonce: NONCE, dataReturn: DATA, allowUnverified: true });
  check("E7b. an echoed dataReturn verifies", e7.outcome === "issued");

  check("E7c. a dataReturn echoed with DIFFERENT bytes is refused",
    (await acode(function () {
      return pki.cmc.verify(
        response(txControls([attr(5, ID_CMC_DATA_RETURN, [b.octetString(Buffer.from("tampered"))])])),
        { transactionId: TX, senderNonce: NONCE, dataReturn: DATA, allowUnverified: true });
    })) === "cmc/data-return-mismatch");

  // ---- the terminal verdicts ------------------------------------------
  var pend = await pki.cmc.verify(response([statusV2(1, 3,
    b.sequence([b.octetString(Buffer.from("tok")), b.generalizedTime(new Date("2026-03-01T00:00:00Z"))]))]), { allowUnverified: true });
  check("D4b. a pending status yields outcome pending with the token and time surfaced",
    pend.outcome === "pending" && pend.pendToken.toString() === "tok" &&
    pend.pendTime.toISOString() === "2026-03-01T00:00:00.000Z");

  var confirm = await pki.cmc.verify(response([statusV2(1, 5, null)]), { allowUnverified: true });
  check("D15. confirmRequired yields outcome confirm-required (the caller owes a Confirm control, CT5)",
    confirm.outcome === "confirm-required");

  var popReq = await pki.cmc.verify(response([statusV2(1, 6, null)]), { allowUnverified: true });
  check("D15b. popRequired yields outcome pop-required", popReq.outcome === "pop-required");

  var failed = await pki.cmc.verify(response([statusV2(1, 2, b.integer(7n))]), { allowUnverified: true });
  check("D3b. a failed status yields outcome rejected carrying the failInfo name",
    failed.outcome === "rejected" && failed.failInfo === "badIdentity");

  var noSupport = await pki.cmc.verify(response([statusV2(1, 4, null)]), { allowUnverified: true });
  check("D15c. noSupport yields outcome rejected", noSupport.outcome === "rejected");

  // A response carrying BOTH a success and a failure is not a verdict this
  // layer may pick from -- the worst outcome governs, never the first seen.
  var mixed = await pki.cmc.verify(response([statusV2(1, 0, null), statusV2(2, 2, b.integer(7n))]), { allowUnverified: true });
  check("ST1b. with several status controls the FAILING one governs, not the first",
    mixed.outcome === "rejected" && mixed.statuses.length === 2);

  // ---- PR4 / PR5: certificates are surfaced, never trusted --------------
  var pair = await pki.key.generate("Ed25519");
  var certDer = await pki.x509.sign({
    subject: "issued.example", subjectPublicKey: await pki.key.export(pair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
  }, { key: await pki.key.export(pair.privateKey) });

  var withCert = await pki.cmc.verify(response([statusV2(1, 0, null)], [certDer]), { allowUnverified: true });
  check("PR5. the issued certificate is read from the CMS bag, not from PKIResponse",
    withCert.certificates.length === 1 && Buffer.compare(withCert.certificates[0], certDer) === 0);

  var anchors = await pki.cmc.verify(
    response([statusV2(1, 0, null), attr(2, ID_CMC_TRUSTED_ANCHORS, [b.octetString(Buffer.from([1]))])], [certDer]), { allowUnverified: true });
  check("CT7. a Publish Trust Anchors control is SURFACED and nothing is auto-trusted",
    anchors.publishTrustAnchors !== null && anchors.trusted === false);

  // ---- the OTHER accepted carrier ---------------------------------------
  // RFC 5272 sec. 4.2 admits an AuthenticatedData as well as a SignedData, and
  // the two keep their certificate bag in DIFFERENT places: a SignedData at the
  // top level, an AuthenticatedData under originatorInfo (RFC 5652 sec. 9.1).
  // Reading only the SignedData shape returns an empty bag for a perfectly valid
  // response -- reporting "no certificates issued" when some were.
  var authDer = authenticatedData(certDer);
  check("PR5b. an AuthenticatedData carrier is accepted (the registry name is authData, not the prose spelling)",
    pki.schema.cms.parse(authDer).contentTypeName === "authData");
  var authVerdict = await pki.cmc.verify(authDer, { allowUnverified: true });
  check("PR5c. its certificates are read from originatorInfo, where that carrier keeps them",
    authVerdict.outcome === "issued" && authVerdict.certificates.length === 1 &&
    Buffer.compare(authVerdict.certificates[0], certDer) === 0);

  // ---- duplicate binding controls are AMBIGUOUS, not first-wins ---------
  // Body-part identity is unique, so a responder may legally carry TWO
  // Transaction Identifier controls under different bodyPartIDs. A verifier that
  // takes the first match lets an attacker pair one correct echo with a
  // contradictory one and still pass the binding -- the check has to be that
  // exactly one instance exists, not that some instance agrees.
  check("V3. two Transaction Identifier controls are refused rather than first-match-wins",
    (await acode(function () {
      return pki.cmc.verify(response([
        attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX))]),
        attr(2, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX + 99))]),
        attr(3, ID_CMC_RECIPIENT_NONCE, [b.octetString(NONCE)]),
      ]), sent);
    })) === "cmc/duplicate-control");

  check("V4. two Recipient Nonce controls are refused",
    (await acode(function () {
      return pki.cmc.verify(response([
        attr(1, ID_CMC_TRANSACTION_ID, [b.integer(BigInt(TX))]),
        attr(2, ID_CMC_RECIPIENT_NONCE, [b.octetString(NONCE)]),
        attr(3, ID_CMC_RECIPIENT_NONCE, [b.octetString(flipped)]),
      ]), sent);
    })) === "cmc/duplicate-control");

  check("V5. two Data Return controls are refused",
    (await acode(function () {
      return pki.cmc.verify(response(txControls([
        attr(5, ID_CMC_DATA_RETURN, [b.octetString(DATA)]),
        attr(6, ID_CMC_DATA_RETURN, [b.octetString(Buffer.from("other"))]),
      ])), { transactionId: TX, senderNonce: NONCE, dataReturn: DATA, allowUnverified: true });
    })) === "cmc/duplicate-control");

  // ---- PD14: the carrier's signature is not optional --------------------
  // RFC 5272 sec. 3.2.1.3.4: "As part of processing a PKI Request/Response, the
  // signature(s) MUST be verified." A Full PKI Response is a SignedData (sec.
  // 4.2), so a carrier with NO SignerInfo is not one -- and reporting `issued`
  // off an unsigned message would hand a caller an enrollment result that nobody
  // authenticated. Verification is fail-closed: it needs signer certificates, and
  // proceeding without them is an explicit, named decision.
  check("PD14. a Full PKI Response whose carrier carries no SignerInfo is refused",
    // Even WITH the opt-out: allowUnverified skips checking a signature, it does
    // not conjure one. A carrier with no signer is the wrong structure, not an
    // unverified one.
    (await acode(function () { return pki.cmc.verify(unsignedResponse([statusV2(1, 0, null)]), { allowUnverified: true }); }))
      === "cmc/unsigned-response");

  var signedResp = await pki.cms.sign(
    b.sequence([b.sequence([statusV2(1, 0, null)]), b.sequence([]), b.sequence([])]),
    { cert: certDer, key: await pki.key.export(pair.privateKey) },
    { eContentType: "id-cct-PKIResponse" });

  check("PD14b. a signed response with no signer certificates supplied is refused by default",
    // Deliberately NO opt-out here: this is the default posture, and the default
    // must be a refusal rather than a quiet pass.
    (await acode(function () { return pki.cmc.verify(signedResp, {}); })) === "cmc/unverified-response");

  var okVerified = await pki.cmc.verify(signedResp, { certs: [certDer] });
  check("PD14c. supplying the signer certificate verifies the carrier and yields the verdict",
    okVerified.outcome === "issued" && okVerified.signatureVerified === true);

  // Note what `certs` does and does not do: it supplies certificates for SIGNER
  // LOOKUP. It does not pin the signer -- a SignedData carries its own signer
  // certificate, which is what the signature is checked against -- and it
  // establishes no trust. Deciding the signer is acceptable is path validation,
  // which is why the verdict surfaces the bag rather than judging it.
  var tampered = Buffer.from(signedResp);
  tampered[tampered.length - 1] ^= 0xff;              // corrupt the signature bytes
  check("PD14d. a corrupted signature fails closed rather than reporting issued",
    (await acode(function () {
      return pki.cmc.verify(tampered, { certs: [certDer] });
    })) === "cmc/unverified-response");

  var unverified = await pki.cmc.verify(signedResp, { allowUnverified: true });
  check("PD14e. the bootstrap opt-out is explicit and says so in the verdict",
    unverified.outcome === "issued" && unverified.signatureVerified === false);

  // PD14f -- the verdict must describe the bytes the signature was checked
  // against. verify() parses synchronously and verifies in a later promise turn,
  // so every byte range the parse surfaced is a view into the caller's memory
  // with an await in the middle. Rewriting that memory in the gap must not be
  // able to produce a verdict built from one message and a signature checked over
  // another. Driven the way it actually happens: the buffer is mutated from a
  // queued microtask, between the parse and the verification.
  var raced = Buffer.from(signedResp);
  var racedOutcome = null, racedError = null;
  var racePromise = pki.cmc.verify(raced, { certs: [certDer] });
  raced.fill(0x41);                       // rewritten on the very next line -- the
                                          // easiest version of the race to hit, and
                                          // the one a deferred snapshot loses to
  try { racedOutcome = await racePromise; } catch (e) { racedError = e; }
  check("PD14f. rewriting the caller's buffer between parse and verify cannot forge a verified verdict",
    // Either answer is correct -- what must NOT happen is `issued` with
    // signatureVerified true off a buffer that no longer holds the signed bytes.
    racedError !== null || (racedOutcome.outcome === "issued" && racedOutcome.signatureVerified === true));

  check("PD14g. the verdict from the raced call still describes the ORIGINAL message",
    // The snapshot is what makes this hold: parse and verify both read the private
    // copy, so the overwrite cannot reach either half.
    racedError === null && racedOutcome.statuses.length === 1);

  // PD14h -- both sides of the comparison are frozen, not just the response.
  // The binding checks run after the signature check's await, so a `sent` the
  // caller keeps mutating would be read post-mutation: the nonce would be
  // compared against a value the request never carried, and flipping
  // allowUnverified before its promise turn would skip the signature check the
  // default posture requires.
  var liveNonce = Buffer.alloc(16, 7);
  var liveSent = { allowUnverified: true };
  var mutating = pki.cmc.verify(response([statusV2(1, 0, null)]), liveSent);
  liveSent.allowUnverified = false;                 // flip AFTER the call, before its turn
  liveNonce.fill(0xff);
  var mutated = await mutating;
  check("PD14h. options mutated after the call do not change what was already decided",
    mutated.outcome === "issued" && mutated.signatureVerified === false);

  // ---- input discipline ------------------------------------------------
  check("V1. a Full PKI REQUEST handed to verify is refused (it interprets responses)",
    (await acode(function () {
      var body = b.sequence([b.sequence([]), b.sequence([]), b.sequence([]), b.sequence([])]);
      var encap = b.sequence([b.oid("1.3.6.1.5.5.7.12.2"), b.explicit(0, b.octetString(body))]);
      var sd = b.sequence([b.integer(3n), b.set([b.sequence([b.oid(SHA256), b.nullValue()])]), encap, b.set([])]);
      return pki.cmc.verify(b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, sd)]), { allowUnverified: true });
    })) === "cmc/not-a-response");

  check("V2. a non-object opts is refused config-time",
    (await acode(function () { return pki.cmc.verify(response([]), 7); })) === "cmc/bad-input");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
