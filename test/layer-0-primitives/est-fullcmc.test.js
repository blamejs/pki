// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.est.fullcmc (RFC 7030 sec. 4.3, RFC 8951 sec. 3, RFC 5273 sec. 4).
 *
 * The EST /fullcmc verb: POST a Full PKI Request, interpret the Full PKI Response.
 * Driven over `fakeTransport` so the whole state machine runs with no socket, and
 * every gate that must precede the transport is proven by `calls.length === 0`.
 *
 * The rules this file exists to pin, each one a place the sibling verbs differ:
 *   - FC5: a 200 may be EITHER `certs-only` OR `CMC-response`. Two named values,
 *     not "anything", and not the single value the other verbs take.
 *   - FC8/FC8a: on /fullcmc a 404 OR a 501 means "not implemented" -- a THIRD
 *     distinct meaning of 404 in the classifier, alongside cacerts (an error) and
 *     csrattrs (none-available).
 *   - FC7/FC7a: a CMC error response MUST be included on a rejection, so the CMC
 *     verdict is surfaced -- but an undecodable body must never MASK the HTTP
 *     fault, which is the opposite posture to the sibling enroll clause.
 *   - FC11: a bootstrap /fullcmc does NOT relax the trust-anchor requirement, and
 *     a Publish Trust Anchors control is surfaced rather than acted on.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var fakeTransport = require("../helpers/fake-transport").fakeTransport;

var ID_CCT_PKI_RESPONSE = "1.3.6.1.5.5.7.12.3";
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_DATA = "1.2.840.113549.1.7.1";
var SHA256 = "2.16.840.1.101.3.4.2.1";
var ID_CCT_PKI_DATA = "1.3.6.1.5.5.7.12.2";
var ID_CMC_STATUS_INFO_V2 = "1.3.6.1.5.5.7.7.25";
var ID_CMC_TRUSTED_ANCHORS = "1.3.6.1.5.5.7.7.26";
var TLS = { anchors: [] };   // presence is what the gate checks; no socket is opened

async function acode(fn) {
  try { await fn(); return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); }
}
async function acaught(fn) {
  try { await fn(); return null; } catch (e) { return e; }
}

function attr(id, type, values) { return b.sequence([b.integer(BigInt(id)), b.oid(type), b.set(values)]); }
function statusV2(id, status, other) {
  var f = [b.integer(BigInt(status)), b.sequence([b.sequence([b.integer(1n)])])];
  if (other) f.push(other);
  return attr(id, ID_CMC_STATUS_INFO_V2, [b.sequence(f)]);
}

// The same status with the bodyList naming an explicit body part, so a vector can
// report on a part the request never sent.
function statusV2About(bodyPart, status) {
  return attr(1, ID_CMC_STATUS_INFO_V2, [b.sequence([
    b.integer(BigInt(status)), b.sequence([b.sequence([b.integer(BigInt(bodyPart))])])])]);
}

// A Full PKI Response in a SignedData, certificates in the CMS bag (RFC 5272 sec. 4.2).
// A structurally present SignerInfo: RFC 5272 sec. 3.2.1.3.4 makes verifying the
// carrier's signature mandatory, so a Full PKI Response with no signer is refused
// outright. These vectors are about the VERB (routing, statuses, the transport
// gates), so they carry a signer and pass `allowUnverifiedResponse: true` -- the
// named opt-out, which keeps it visible that authentication is exercised in
// cmc-verify.test.js rather than silently skipped here.
function fakeSignerInfo() {
  var sid = b.sequence([b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]), b.integer(1n)]);
  var signedAttrs = b.contextConstructed(0, Buffer.concat([
    b.sequence([b.oid("1.2.840.113549.1.9.3"), b.set([b.oid(ID_CCT_PKI_RESPONSE)])]),
    b.sequence([b.oid("1.2.840.113549.1.9.4"), b.set([b.octetString(Buffer.alloc(32, 3))])]),
  ]));
  return b.sequence([b.integer(1n), sid, b.sequence([b.oid(SHA256), b.nullValue()]), signedAttrs,
    b.sequence([b.oid("1.2.840.113549.1.1.1"), b.nullValue()]), b.octetString(Buffer.alloc(8, 1))]);
}

function pkiResponse(controls, certsDer) {
  var body = b.sequence([b.sequence(controls || []), b.sequence([]), b.sequence([])]);
  var encap = b.sequence([b.oid(ID_CCT_PKI_RESPONSE), b.explicit(0, b.octetString(body))]);
  var fields = [b.integer(3n), b.set([b.sequence([b.oid(SHA256), b.nullValue()])]), encap];
  if (certsDer && certsDer.length) fields.push(b.contextConstructed(0, Buffer.concat(certsDer)));
  fields.push(b.set([fakeSignerInfo()]));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(fields))]);
}

// A Full PKI Request, hand-assembled. pki.cmc.build refuses to emit a binding
// control whose value is not the type the toolkit reads, which is what makes the
// vectors below need this: they are about what the CLIENT does when handed such a
// request from somewhere else -- another implementation, or a stored one -- and a
// fixture that could only come from our own builder would not exercise that.
function pkiRequest(controls) {
  var body = b.sequence([b.sequence(controls || []), b.sequence([]), b.sequence([]), b.sequence([])]);
  var encap = b.sequence([b.oid(ID_CCT_PKI_DATA), b.explicit(0, b.octetString(body))]);
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence([
    b.integer(3n), b.set([b.sequence([b.oid(SHA256), b.nullValue()])]), encap,
    b.set([fakeSignerInfo()])]))]);
}

// A certs-only Simple PKI Response: SignedData v1 over id-data, no eContent, empty signerInfos.
function certsOnly(certsDer) {
  var sd = b.sequence([b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)]),
    b.contextConstructed(0, Buffer.concat(certsDer)), b.set([])]);
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, sd)]);
}

function ct(smimeType) {
  return { "content-type": "application/pkcs7-mime" + (smimeType ? "; smime-type=" + smimeType : "") };
}

async function run() {
  var pair = await pki.key.generate("Ed25519");
  var key = await pki.key.export(pair.privateKey);
  var spki = await pki.key.export(pair.publicKey);
  var certDer = await pki.x509.sign({
    subject: "device.example", subjectPublicKey: spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
  }, { key: key });
  var clientCert = certDer;
  var csrDer = await pki.csr.sign({ subject: "device.example", subjectPublicKey: spki }, { key: key });
  var requestDer = await pki.cmc.build({ requests: [{ tcr: csrDer }] }, { cert: clientCert, key: key });

  // ---- G1: the request that crosses the wire ----------------------------
  var t1 = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  var r1 = await pki.est.fullcmc("https://ca.example", requestDer, { transport: t1, tls: TLS, allowUnverifiedResponse: true });
  check("G1. a certs-only 200 yields outcome issued with the certificates surfaced",
    r1.outcome === "issued" && r1.certificates.length === 1 &&
    Buffer.compare(r1.certificates[0], certDer) === 0);
  // Both response arms must answer the SAME question about authentication. A
  // certs-only body is a degenerate SignedData with no signers by definition
  // (RFC 5652 sec. 5.2), so there is nothing here to verify -- but the field has
  // to SAY that rather than be absent, or a caller reading verdict.signatureVerified
  // gets `false` on one arm and `undefined` on the other for the same code path.
  check("G1a. the certs-only arm reports signatureVerified false rather than omitting it",
    r1.signatureVerified === false && r1.trusted === false);
  check("G1b. the verb POSTs (RFC 5273 sec. 4: clients MUST use POST)", t1.calls[0].method === "POST");
  check("G1c. it targets /.well-known/est/fullcmc (RFC 7030 sec. 3.2.2)",
    /\/\.well-known\/est\/fullcmc$/.test(t1.calls[0].url));
  check("G1d. the content-type is application/pkcs7-mime; smime-type=CMC-request (sec. 4.3.1)",
    String(t1.calls[0].headers["content-type"]).toLowerCase() ===
      "application/pkcs7-mime; smime-type=cmc-request");
  check("G1e. the body is the RFC 8951 base64 transfer encoding of the request DER",
    t1.calls[0].body === pki.est.transferEncode(requestDer));

  // G1f/G1g -- a certs-only body carries no status and no request reference, so
  // the ONLY thing tying it to this exchange is a public-key match against what
  // was submitted (RFC 5272 sec. 4.1 forbids picking positionally). Without that,
  // a bag holding an unrelated certificate -- or just a CA chain -- reads as a
  // successful issuance for a request it never answered.
  var otherPair = await pki.key.generate("Ed25519");
  var otherCert = await pki.x509.sign({
    subject: "someone.else.example", subjectPublicKey: await pki.key.export(otherPair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
  }, { key: await pki.key.export(otherPair.privateKey) });

  check("G1f. a certs-only bag carrying only an unrelated certificate is not an issuance",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(certsOnly([otherCert])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/no-issued-cert");

  // G1h -- a request carrying TWO certification requests is only answered when
  // BOTH are: a bag holding one of the two certificates is a partial enrolment,
  // and calling it issued would report the unanswered half as done.
  var secondCsr = await pki.csr.sign(
    { subject: "second.example", subjectPublicKey: await pki.key.export(otherPair.publicKey) },
    { key: await pki.key.export(otherPair.privateKey) });
  var twoReq = await pki.cmc.build({ requests: [{ tcr: csrDer }, { tcr: secondCsr }] },
    { cert: clientCert, key: key });

  check("G1h. a two-request message answered by only one certificate is not an issuance",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", twoReq, {
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(certsOnly([certDer])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/no-issued-cert");

  check("G1i. answering both requests issues, and every issued certificate is surfaced",
    (await pki.est.fullcmc("https://ca.example", twoReq, {
      transport: fakeTransport({ status: 200, headers: ct("certs-only"),
        body: pki.est.transferEncode(certsOnly([otherCert, certDer].sort(Buffer.compare))) }),
      tls: TLS, allowUnverifiedResponse: true })).issuedCertificates.length === 2);

  // G1o/G1p -- two requests may deliberately share ONE public key (different
  // subjects, same key), and a CA answering both returns two certificates for it.
  // How many certificates should match a key is answered by how many requests
  // asked for it: refusing the second as ambiguous would reject the complete,
  // correct response, and accepting one would let a half-answer through.
  var sameKeyCsrA = await pki.csr.sign({ subject: "a.example", subjectPublicKey: spki }, { key: key });
  var sameKeyCsrB = await pki.csr.sign({ subject: "b.example", subjectPublicKey: spki }, { key: key });
  var sharedReq = await pki.cmc.build({ requests: [{ tcr: sameKeyCsrA }, { tcr: sameKeyCsrB }] },
    { cert: clientCert, key: key });
  var certA = await pki.x509.sign({ subject: "a.example", subjectPublicKey: spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
  var certB = await pki.x509.sign({ subject: "b.example", subjectPublicKey: spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });

  check("G1o. two requests sharing a key are answered by two certificates for it",
    (await pki.est.fullcmc("https://ca.example", sharedReq, {
      transport: fakeTransport({ status: 200, headers: ct("certs-only"),
        body: pki.est.transferEncode(certsOnly([certA, certB].sort(Buffer.compare))) }),
      tls: TLS, allowUnverifiedResponse: true })).issuedCertificates.length === 2);

  check("G1p. one certificate for two such requests is still a half-answer",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", sharedReq, {
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(certsOnly([certA])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/no-issued-cert");

  check("G1q. more certificates for a key than requests for it is ambiguous",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {   // ONE request for this key
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(certsOnly([certA, certB].sort(Buffer.compare))) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/ambiguous-issued-cert");

  check("G1g. the issued certificate is named, not left for the caller to guess from the bag",
    // The bag holds the unrelated certificate too; `certificate` is the one whose
    // key the request actually asked to have certified.
    (await pki.est.fullcmc("https://ca.example", requestDer, {
      transport: fakeTransport({ status: 200, headers: ct("certs-only"),
        // A CMS certificates SET is DER-ordered, so the bag is sorted rather than
        // written in the order that would make the point read most directly.
        body: pki.est.transferEncode(certsOnly([otherCert, certDer].sort(Buffer.compare))) }),
      tls: TLS, allowUnverifiedResponse: true })).certificate.equals(certDer));

  // G1j/G1k -- the bytes are about to be labelled `smime-type=CMC-request`, so
  // they are confirmed to BE one before anything leaves the process. A caller
  // mistake belongs at the entry point, not POSTed to a CA under a label that
  // does not describe it.
  var noCall = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  check("G1j. a Full PKI RESPONSE handed in as the request is refused before the POST",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example",
        pkiResponse([statusV2(1, 0, null)], [certDer]), { transport: noCall, tls: TLS });
    })) === "est/bad-input");
  check("G1k. and nothing was sent",
    noCall.calls.length === 0);

  check("G1l. bytes that are not CMC at all are refused the same way",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", certDer, { transport: noCall, tls: TLS });
    })) === "est/bad-input");

  // G1m -- the exchange's meaning is fixed at the call, not a turn later. A
  // caller that flips allowUnverifiedResponse on the next line must not be able
  // to reach back into a request already in flight and switch off the signature
  // check it was started with.
  var liveOpts = { transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
    body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [certDer])) }),
    tls: TLS, allowUnverifiedResponse: true };
  var inFlight = pki.est.fullcmc("https://ca.example", requestDer, liveOpts);
  liveOpts.allowUnverifiedResponse = false;    // flipped after the call
  check("G1m. options changed after the call do not alter the exchange already begun",
    (await inFlight).outcome === "issued");

  // ...and the request bytes likewise: they are parsed for the correlation keys
  // now and transmitted later, so the two must not be able to disagree.
  var liveReq = Buffer.from(requestDer);
  var t1m = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  var reqInFlight = pki.est.fullcmc("https://ca.example", liveReq, { transport: t1m, tls: TLS, allowUnverifiedResponse: true });
  liveReq.fill(0x41);                          // rewritten on the next line
  check("G1n. the request posted is the request that was correlated",
    (await reqInFlight).outcome === "issued" && t1m.calls[0].body === pki.est.transferEncode(requestDer));

  // G1r -- the richer est/cmc-failed is an UPGRADE for an actual rejection, never
  // a substitute that contradicts itself. A CMC body inside an HTTP failure that
  // says the request was issued is the server disagreeing with its own status
  // line; reporting "the server rejected the Full PKI Request: issued" would hand
  // the caller a success wrapped in a rejection, so the HTTP fault stands instead.
  check("G1r. a success CMC body inside an HTTP failure leaves the HTTP fault reported",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 500, headers: ct("CMC-response"),
          body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [certDer])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/http-error");

  // G1s -- a request mixing a readable arm with an unreadable one must not be
  // sent. The CMC parser validates request arms only far enough to find their
  // identity, so a malformed one reaches the correlation as "no key" -- and a
  // response covering only the readable arm would then look like a complete
  // issuance for a request that also asked for something else.
  var mixed = b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence([
    b.integer(3n), b.set([b.sequence([b.oid(SHA256), b.nullValue()])]),
    b.sequence([b.oid(ID_CCT_PKI_DATA), b.explicit(0, b.octetString(b.sequence([
      b.sequence([]),
      b.sequence([
        b.contextConstructed(0, Buffer.concat([b.integer(1n), csrDer])),          // readable
        b.contextConstructed(0, Buffer.concat([b.integer(2n), b.sequence([])])),  // not a CSR
      ]),
      b.sequence([]), b.sequence([]),
    ])))]),
    b.set([]),
  ]))]);
  var noSend = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  check("G1s. a request whose second arm cannot be read is refused before sending",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", mixed, { transport: noSend, tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-input");
  check("G1t. and nothing was sent for it",
    noSend.calls.length === 0);

  // G1u -- the CMC-fault upgrade belongs to REJECTION statuses only. A non-error
  // response that fails its own validation (a 200 whose smime-type is missing or
  // unrecognized) must report THAT, even when the body happens to be a readable
  // signed CMC rejection: otherwise a malformed 200 answers as a clean refusal and
  // the validation it failed is never reported.
  check("G1u. a 200 with no smime-type reports the content-type fault, not a CMC verdict",
    // The EXACT code, not merely "not cmc-failed": an assertion broader than the
    // claim would pass on any other failure and prove nothing about this one.
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" },
          body: pki.est.transferEncode(pkiResponse([statusV2(1, 2, null)], [])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-content-type");

  // G1w -- an orm-only request asks for NO certificate, so a successful response to
  // it is not an issuance and there is nothing to correlate. RFC 5272 lets the
  // server return its result in the cmsSequence or otherMsgSequence instead;
  // demanding a matching certificate would make this verb unable to carry the
  // exchange at all. The certs-only arm keeps the opposite rule, because that body
  // is nothing but a claim of issuance.
  var ormRequest = await pki.cmc.build(
    { requests: [{ orm: { type: "1.3.6.1.4.1.99999.7", value: b.octetString(Buffer.from([1, 2, 3])) } }] },
    { cert: clientCert, key: key });
  var ormVerdict = await pki.est.fullcmc("https://ca.example", ormRequest, {
    transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
      body: pki.est.transferEncode(pkiResponse([statusV2About(1, 0)], [])) }),
    tls: TLS, allowUnverifiedResponse: true });
  check("G1w. an orm-only request gets a successful verdict with no certificate correlated",
    ormVerdict.outcome === "issued" && ormVerdict.certificate === undefined &&
    ormVerdict.issuedCertificates.length === 0);

  check("G1w2. but a CERTS-ONLY answer to it is still refused -- that body claims an issuance",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", ormRequest, {
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(certsOnly([certDer])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/no-issued-cert");

  // G1u4 -- a Content-Type declaring BOTH arms selects neither. RFC 2045 sec. 5.1
  // gives a parameter at most one value, and taking the first would let the order
  // of two labels decide which shape the body is read as, on the very header whose
  // job is to say which one it is.
  check("G1u4. a 200 whose Content-Type declares two smime-types is refused",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200,
          headers: { "content-type": "application/pkcs7-mime; smime-type=CMC-response; smime-type=certs-only" },
          body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [certDer])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-content-type");

  check("G1u5. and on the ERROR path the ambiguous label reports the HTTP fault, not a CMC verdict",
    // Returning null there rather than throwing keeps the server's real error
    // visible: a content-type complaint would hide the thing to act on.
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 400,
          headers: { "content-type": "application/pkcs7-mime; smime-type=CMC-response; smime-type=certs-only" },
          body: pki.est.transferEncode(pkiResponse([statusV2(1, 2, null)], [])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/http-error");

  // G1u2 -- the verb retains WHICH body parts it sent, so a status about one it
  // never sent is refused. The transaction and nonce cannot catch this: a server
  // can echo both correctly and still report on a different message. The request
  // above carries one certification request, so a status about body part 999 is
  // about something that was never in it.
  check("G1u2. a status reporting on a body part the request never sent is refused",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
          body: pki.est.transferEncode(pkiResponse([statusV2About(999, 0)], [certDer])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "cmc/body-part-unknown");

  check("G1u3. and a status about the body part it DID send is accepted",
    (await pki.est.fullcmc("https://ca.example", requestDer, {
      transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
        body: pki.est.transferEncode(pkiResponse([statusV2About(1, 0)], [certDer])) }),
      tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  // G1v -- the AuthenticatedData carrier, reachable AUTHENTICATED from the verb an
  // operator actually calls. A capability that exists only one layer down is not
  // one this surface has: without responseRecipient the carrier could be reached
  // only through the unauthenticated opt-out.
  var authRespDer = await pki.cms.authenticate(
    b.sequence([b.sequence([statusV2(1, 6, null)]), b.sequence([]), b.sequence([])]),
    [{ password: "s3cret" }], { contentType: "id-cct-PKIResponse" });
  var authTransport = fakeTransport({ status: 200, headers: ct("CMC-response"),
    body: pki.est.transferEncode(authRespDer) });

  var authVerdict = await pki.est.fullcmc("https://ca.example", requestDer,
    { transport: authTransport, tls: TLS, responseRecipient: { password: "s3cret" } });
  check("G1v. an AuthenticatedData response authenticates through fullcmc",
    authVerdict.outcome === "pop-required" && authVerdict.signatureVerified === true);

  check("G1w. and without the key it is still refused rather than passed unauthenticated",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,
        { transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
          body: pki.est.transferEncode(authRespDer) }), tls: TLS });
    })) === "cmc/unverified-response");

  // G1x -- RFC 4211 sec. 4.1 lets a CRMF request omit CertTemplate.publicKey and
  // carry the requested key in the signature POP's POPOSigningKeyInput instead.
  // This toolkit's own CRMF parser accepts that form, so reading only the template
  // would refuse a conforming request before it was ever sent.
  var crmTemplateKey = await pki.crmf.build(
    { certReqId: 9, certTemplate: { subject: "crm.example", publicKey: spki } }, { key: key });
  var crmReq = await pki.cmc.build({ requests: [{ crm: crmTemplateKey }] },
    { cert: clientCert, key: key });
  check("G1x. a CRMF request's key is found for correlation",
    (await pki.est.fullcmc("https://ca.example", crmReq, {
      transport: fakeTransport({ status: 200, headers: ct("certs-only"),
        body: pki.est.transferEncode(certsOnly([certDer])) }),
      tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  // G1y/G1z -- a certs-only body carries no controls, so it cannot echo a
  // transaction or nonce. A client that sent those asked for replay binding, and
  // the public-key correlation is not one: an OLD response for the same key still
  // matches. Silently accepting would give none of what was asked for.
  var askedForBinding = await pki.cmc.build(
    { requests: [{ tcr: csrDer }], transactionId: 77, senderNonce: Buffer.alloc(16, 3) },
    { cert: clientCert, key: key });
  check("G1y. a certs-only answer to a request that asked for replay binding is refused",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", askedForBinding, {
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(certsOnly([certDer])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/unbound-response");

  check("G1z. and it is still accepted for a request that asked for none",
    // The refusal is about the binding the caller asked for, not about the arm.
    (await pki.est.fullcmc("https://ca.example", requestDer, {
      transport: fakeTransport({ status: 200, headers: ct("certs-only"),
        body: pki.est.transferEncode(certsOnly([certDer])) }),
      tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  // ---- G2 / G3: the OTHER accepted smime-type, and its case-insensitivity
  var t2 = fakeTransport({ status: 200, headers: ct("CMC-response"),
    body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [certDer])) });
  var r2 = await pki.est.fullcmc("https://ca.example", requestDer, { transport: t2, tls: TLS, allowUnverifiedResponse: true });
  check("G2. a CMC-response 200 yields issued, with the certificates from the CMS bag (PR5)",
    r2.outcome === "issued" && r2.certificates.length === 1 && r2.controls.length === 1);

  // G2b -- the SAME correlation on this arm. A status control is the server's
  // word that it issued something; the key match is what shows it issued
  // something to THIS request. A success status over a bag holding only an
  // unrelated certificate is not an issuance here any more than it is on the
  // certs-only arm -- the rule is one rule, applied to both.
  check("G2b. a success status over a bag with no requested key is not an issuance",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
          body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [otherCert])) }),
        tls: TLS, allowUnverifiedResponse: true });
    })) === "est/no-issued-cert");

  check("G2c. a non-issued outcome is NOT correlated -- it is no claim a certificate exists",
    // CMCStatus popRequired(6). Correlating an answer that asks for more from the
    // client would turn "not yet" into a failure: a CA that has not issued has
    // nothing to return, and there is nothing to match.
    (await pki.est.fullcmc("https://ca.example", requestDer, {
      transport: fakeTransport({ status: 200, headers: ct("CMC-response"),
        body: pki.est.transferEncode(pkiResponse([statusV2(1, 6, null)], [])) }),
      tls: TLS, allowUnverifiedResponse: true })).outcome === "pop-required");

  var t3 = fakeTransport({ status: 200, headers: { "content-type": 'application/pkcs7-mime; smime-type="CMC-RESPONSE"' },
    body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [certDer])) });
  check("G3. a quoted, upper-case smime-type is accepted (FC3a: compare case-insensitively)",
    (await pki.est.fullcmc("https://ca.example", requestDer, { transport: t3, tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  // G3b -- HTTP header names are case-INSENSITIVE (RFC 9110 sec. 5.1). A server
  // sending `Content-type` is conformant, and the classifier already normalizes;
  // a second, hand-rolled lookup that only tries two spellings would silently
  // read no smime-type and route a certs-only body down the CMC-response arm.
  var t3b = fakeTransport({ status: 200,
    headers: { "Content-type": "application/pkcs7-mime; smime-type=certs-only" },
    body: pki.est.transferEncode(certsOnly([certDer])) });
  check("G3b. an oddly-cased Content-type header is read the same way",
    (await pki.est.fullcmc("https://ca.example", requestDer, { transport: t3b, tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  // ---- G4: a pending verdict is DATA, not a throw ------------------------
  var pend = pkiResponse([statusV2(1, 3,
    b.sequence([b.octetString(Buffer.from("tok")), b.generalizedTime(new Date("2026-03-01T00:00:00Z"))]))]);
  var t4 = fakeTransport({ status: 200, headers: ct("CMC-response"), body: pki.est.transferEncode(pend) });
  var r4 = await pki.est.fullcmc("https://ca.example", requestDer, { transport: t4, tls: TLS, allowUnverifiedResponse: true });
  check("G4. a pending CMC status is surfaced as a verdict, never thrown",
    r4.outcome === "pending" && r4.pendToken.toString() === "tok");

  // ---- G5: a 202 is surfaced, never slept --------------------------------
  var t5 = fakeTransport({ status: 202, headers: { "retry-after": "60" }, body: "" });
  var r5 = await pki.est.fullcmc("https://ca.example", requestDer, { transport: t5, tls: TLS, allowUnverifiedResponse: true });
  check("G5. a 202 surfaces the Retry-After without sleeping (one call, no wait)",
    r5.retry === true && r5.retryAfterSeconds === 60 && t5.calls.length === 1);

  // ---- G6: the optional CA label -----------------------------------------
  var t6 = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  await pki.est.fullcmc("https://ca.example", requestDer, { transport: t6, tls: TLS, allowUnverifiedResponse: true, label: "myca" });
  check("G6. an opts.label puts the segment before the operation (sec. 3.2.2)",
    /\/\.well-known\/est\/myca\/fullcmc$/.test(t6.calls[0].url));

  // ---- G7 / G8: the transfer encoding is CTE-blind and whitespace-tolerant
  var wrapped = pki.est.transferEncode(certsOnly([certDer])).replace(/(.{16})/g, "$1\r\n\t");
  var t7 = fakeTransport({ status: 200, headers: ct("certs-only"), body: wrapped });
  check("G7. a base64 body with embedded CRLF and tabs decodes (RFC 8951 sec. 3.1)",
    (await pki.est.fullcmc("https://ca.example", requestDer, { transport: t7, tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  var t8 = fakeTransport({ status: 200,
    headers: { "content-type": "application/pkcs7-mime; smime-type=certs-only", "content-transfer-encoding": "binary" },
    body: pki.est.transferEncode(certsOnly([certDer])) });
  check("G8. a Content-Transfer-Encoding header is ignored; the body is base64 regardless (sec. 3.2.3)",
    (await pki.est.fullcmc("https://ca.example", requestDer, { transport: t8, tls: TLS, allowUnverifiedResponse: true })).outcome === "issued");

  // ---- G9 / G10: 404 AND 501 both mean not-implemented -------------------
  check("G9. a 404 means this service is not implemented, not a generic HTTP error (FC8)",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,
        { transport: fakeTransport({ status: 404, headers: {}, body: "" }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/not-implemented");

  check("G10. a 501 means the same -- testing only 404 is the partial-rule trap",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,
        { transport: fakeTransport({ status: 501, headers: {}, body: "" }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/not-implemented");

  // ---- G11 / G12: the statuses that stay ordinary faults ------------------
  check("G11. a 400 with no CMC body is an ordinary HTTP fault",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,
        { transport: fakeTransport({ status: 400, headers: {}, body: "" }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/http-error");

  check("G12. a 204 is a fault here -- /fullcmc has no none-available arm (the csrattrs branch was not widened)",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,
        { transport: fakeTransport({ status: 204, headers: {}, body: "" }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/http-error");

  // ---- G13: a CMC error response carries the verdict ----------------------
  var failed = pkiResponse([statusV2(1, 2, b.integer(7n))]);   // failInfo 7 = badIdentity
  var e13 = await acaught(function () {
    return pki.est.fullcmc("https://ca.example", requestDer, {
      transport: fakeTransport({ status: 400, headers: ct("CMC-response"), body: pki.est.transferEncode(failed) }),
      tls: TLS, allowUnverifiedResponse: true });
  });
  check("G13. a 4xx carrying a CMC response surfaces the CMC verdict (FC7)",
    e13 && e13.code === "est/cmc-failed" && e13.cmc && e13.cmc.failInfo === "badIdentity" &&
    e13.httpStatus === 400);

  // G13b -- the binding applies to the ERROR path too. A caller that asked for
  // replay binding gets it on every arm: an old or unrelated CMC failure that
  // does not echo this exchange's transaction is not this request's answer, so it
  // must not be attached as one. It falls back to the plain HTTP fault.
  var ID_CMC_TRANSACTION_ID = "1.3.6.1.5.5.7.7.5";
  // The request must genuinely CARRY the transaction it is bound to: the verb reads
  // the binding out of the request rather than taking the caller's word, so a
  // request without the control cannot be bound to one.
  var boundReq = await pki.cmc.build({ requests: [{ tcr: csrDer }], transactionId: 42 },
    { cert: clientCert, key: key });
  var failedOther = pkiResponse([
    attr(1, ID_CMC_TRANSACTION_ID, [b.integer(999n)]),
    statusV2(2, 2, b.integer(7n)),
  ]);
  var e13b = await acaught(function () {
    return pki.est.fullcmc("https://ca.example", boundReq, {
      transport: fakeTransport({ status: 400, headers: ct("CMC-response"),
        body: pki.est.transferEncode(failedOther) }),
      tls: TLS, allowUnverifiedResponse: true });
  });
  check("G13b. a CMC error response for a DIFFERENT transaction is not attached to this one",
    e13b && e13b.code === "est/http-error");

  // ...and the same response DOES bind when the transaction matches, so the
  // previous check is about the binding rather than about rejecting everything.
  var failedMine = pkiResponse([
    attr(1, ID_CMC_TRANSACTION_ID, [b.integer(42n)]),
    statusV2(2, 2, b.integer(7n)),
  ]);
  var e13c = await acaught(function () {
    return pki.est.fullcmc("https://ca.example", boundReq, {
      transport: fakeTransport({ status: 400, headers: ct("CMC-response"),
        body: pki.est.transferEncode(failedMine) }),
      tls: TLS, allowUnverifiedResponse: true });
  });
  check("G13c. the matching-transaction error response IS surfaced as the CMC verdict",
    e13c && e13c.code === "est/cmc-failed" && e13c.cmc.failInfo === "badIdentity");

  // G13d/G13e -- the binding is read OUT OF THE REQUEST, never taken on the
  // caller's word. Claiming a transaction the request does not carry would have the
  // response checked against a binding this exchange never sent, and a replayed
  // response echoing the claimed value would satisfy it.
  var noSend13 = fakeTransport({ status: 400, headers: ct("CMC-response"),
    body: pki.est.transferEncode(failedMine) });
  check("G13d. claiming a transaction the request does not carry is refused",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,   // built with NO transactionId
        { transport: noSend13, tls: TLS, allowUnverifiedResponse: true, transactionId: 42 });
    })) === "est/bad-input");
  check("G13e. and nothing was sent under a binding that did not exist",
    noSend13.calls.length === 0);

  // G13g -- a binding control that is PRESENT but unreadable must not decay into
  // "absent": that would send the request with no echo requirement at all, a weaker
  // exchange than the one the message purports to carry.
  // Hand-assembled: pki.cmc.build refuses to EMIT this, which is the point --
  // the client must still refuse a request that reached it some other way.
  var malformedBinding = pkiRequest([attr(1, ID_CMC_TRANSACTION_ID, [b.octetString(Buffer.from([1, 2, 3]))])]);
  var noSend13g = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  check("G13g. an unreadable transactionId control is refused rather than ignored",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", malformedBinding,
        { transport: noSend13g, tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-input");
  check("G13h. and it never reached the network",
    noSend13g.calls.length === 0);

  // G13i -- two of the same binding control leave no single value to bind the
  // response to. Taking the last would pick one of the two arbitrarily, and
  // pki.cmc.verify already refuses duplicates on the response side.
  // Hand-assembled: pki.cmc.build now refuses to EMIT this shape, which is the
  // right behaviour and means the fixture cannot come from it. A request from
  // another producer can still arrive this way, and that is what is being tested.
  var dupBinding = b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence([
    b.integer(3n), b.set([b.sequence([b.oid(SHA256), b.nullValue()])]),
    b.sequence([b.oid(ID_CCT_PKI_DATA), b.explicit(0, b.octetString(b.sequence([
      b.sequence([attr(1, ID_CMC_TRANSACTION_ID, [b.integer(1n)]),
        attr(2, ID_CMC_TRANSACTION_ID, [b.integer(2n)])]),
      b.sequence([b.contextConstructed(0, Buffer.concat([b.integer(3n), csrDer]))]),
      b.sequence([]), b.sequence([]),
    ])))]),
    b.set([]),
  ]))]);
  var noSend13i = fakeTransport({ status: 200, headers: ct("certs-only"),
    body: pki.est.transferEncode(certsOnly([certDer])) });
  check("G13i. duplicate binding controls are refused before transport",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", dupBinding,
        { transport: noSend13i, tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-input");
  check("G13j. and that request never left either",
    noSend13i.calls.length === 0);

  check("G13k. an error body labelled something other than CMC-response is not read as a verdict",
    // The success path refuses a label that disagrees with the bytes; accepting any
    // pkcs7-mime here would make that agreement decorative and read a CMC verdict
    // out of a body the server said was something else. The HTTP fault stands.
    (await acaught(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 400, headers: ct("certs-only"),
          body: pki.est.transferEncode(failedMine) }),
        tls: TLS, allowUnverifiedResponse: true });
    })).code === "est/http-error");

  check("G13f. a value that AGREES with the request is accepted",
    // The option is not forbidden -- it must simply match what is in the message.
    (await acaught(function () {
      return pki.est.fullcmc("https://ca.example", boundReq, {
        transport: fakeTransport({ status: 400, headers: ct("CMC-response"),
          body: pki.est.transferEncode(failedMine) }),
        tls: TLS, allowUnverifiedResponse: true, transactionId: 42 });
    })).code === "est/cmc-failed");

  // ---- G14: an undecodable error body must not MASK the HTTP fault --------
  var e14 = await acaught(function () {
    return pki.est.fullcmc("https://ca.example", requestDer, {
      transport: fakeTransport({ status: 400, headers: ct("CMC-response"), body: "!!!! not base64 !!!!" }),
      tls: TLS, allowUnverifiedResponse: true });
  });
  check("G14. garbage in a 4xx CMC body leaves the HTTP fault reported, not an asn1/* leak (FC7a)",
    e14 && e14.code === "est/http-error");

  // ---- G16 / G17: the content-type is two NAMED values, not anything ------
  check("G16. a 200 with no smime-type is refused (FC5 names two values)",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" },
          body: pki.est.transferEncode(certsOnly([certDer])) }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-content-type");

  check("G17. a 200 with an unrelated smime-type is refused",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: ct("signed-data"),
          body: pki.est.transferEncode(certsOnly([certDer])) }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-content-type");

  // ---- G18: the LABEL and the BYTES must agree ----------------------------
  check("G18. a certs-only label over a Full PKI Response body is refused (label and bytes must agree)",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {
        transport: fakeTransport({ status: 200, headers: ct("certs-only"),
          body: pki.est.transferEncode(pkiResponse([statusV2(1, 0, null)], [certDer])) }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/not-certs-only");

  // ---- G19 / G20: the body itself -----------------------------------------
  check("G19. a 200 with an empty body is refused",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer,
        { transport: fakeTransport({ status: 200, headers: ct("certs-only"), body: "" }), tls: TLS, allowUnverifiedResponse: true });
    })) === "est/empty-body");

  // ---- G21 / G22 / G23: the gates that precede the transport --------------
  var t21 = fakeTransport({ status: 200, headers: ct("certs-only"), body: "" });
  check("G21. an http:// base URL is refused BEFORE anything is sent",
    (await acode(function () {
      return pki.est.fullcmc("http://ca.example", requestDer, { transport: t21, tls: TLS, allowUnverifiedResponse: true });
    })) === "est/insecure-url" && t21.calls.length === 0);

  // No injected transport: the anchor gate belongs to the DEFAULT transport (an
  // injected one owns its own TLS), so this drives the real path. It refuses
  // before any socket is opened, and a bootstrap /fullcmc gets no exemption --
  // RFC 7030 sec. 4.1.1 permits an unauthenticated bootstrap, but the Publish
  // Trust Anchors control it may return "must be accepted manually", so the
  // provisional decision stays the caller's rather than being relaxed in here.
  check("G22. a bootstrap /fullcmc does NOT relax the trust-anchor requirement (FC11)",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, {});
    })) === "est/no-trust-anchors");
  check("G22b. an empty anchors array is not an anchor",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", requestDer, { tls: { anchors: [] } });
    })) === "est/no-trust-anchors");

  var t23 = fakeTransport({ status: 200, headers: ct("certs-only"), body: "" });
  check("G23. a non-DER request is refused before the transport",
    (await acode(function () {
      return pki.est.fullcmc("https://ca.example", 123, { transport: t23, tls: TLS, allowUnverifiedResponse: true });
    })) === "est/bad-input" && t23.calls.length === 0);

  // ---- G24: a Publish Trust Anchors control is DATA, never acted on -------
  var anchored = pkiResponse([statusV2(1, 0, null),
    attr(2, ID_CMC_TRUSTED_ANCHORS, [b.octetString(Buffer.from([1]))])], [certDer]);
  var r24 = await pki.est.fullcmc("https://ca.example", requestDer, {
    transport: fakeTransport({ status: 200, headers: ct("CMC-response"), body: pki.est.transferEncode(anchored) }),
    tls: TLS, allowUnverifiedResponse: true });
  check("G24. a Publish Trust Anchors control is surfaced and nothing is auto-trusted (FC11 / CT7)",
    r24.publishTrustAnchors !== null && r24.trusted === false);

  // ---- H: the regression on the removed code ------------------------------
  var h1 = pki.est.classifyResponse(200, { "content-type": "application/pkcs7-mime; smime-type=certs-only" },
    "x", { op: "fullcmc" });
  check("H1. classifyResponse no longer refuses /fullcmc -- it classifies it",
    h1.status === "ok");
  check("H2. an unknown op still fails closed (CLASSIFIABLE_OPS was extended, not disabled)",
    (function () {
      try { pki.est.classifyResponse(200, {}, "", { op: "typo" }); return "NO-THROW"; }
      catch (e) { return e.code; }
    })() === "est/unsupported-operation");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
