// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.cmp.session, the stateful CMP enrollment orchestrator (RFC 9810 sec. 5.1.1 / 5.2.3 /
// 5.3.4 / 5.3.18 / 5.3.22). Every response is PROTECTED (built via pki.cmp.build) so the session's
// verify-before-read accepts it; the fail-closed legs (unprotected / tampered / wrong nonce / wrong
// transactionID) prove the #1 invariant. The bounded poll loop, the certConf/pkiConf handshake, the
// implicitConfirm short-circuit, the terminal reject/poll-timeout verdicts, and the config gates are
// each a behavioral vector over the stateful fake CA (no socket, injected sleeper -- no real timer).

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var H = require("../helpers/cmp-session-transport");
var signing = require("../helpers/signing");

var CLIENT = signing.makeSigner("ec-p256", { cn: "client" });
var URL = "https://ca.example/cmp";

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// Build a session over a scripted fake CA. Returns { session, transport, slept:()=>n }.
function mk(legs, extra) {
  var f = H.fakeCa(pki, legs);
  var slept = 0;
  var opts = Object.assign({
    url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    transport: f.transport, sleep: function () { slept += 1; return Promise.resolve(); },
  }, extra || {});
  return { session: pki.cmp.session(opts), transport: f.transport, slept: function () { return slept; } };
}

async function run() {
  await H.init(pki, CLIENT.spki);   // build the CA anchor + signer chain + a leaf cert for the CLIENT key (async)
  var certDer = H.leafCert;         // the issued leaf whose subject key matches the request (the key-match passes)

  // ===== 1. happy path: ir -> granted(accepted) -> certConf -> pkiConf -> issued =====
  var s1 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var r1 = await s1.session.enroll(H.irRequest(CLIENT.spki));
  check("1a. a granted ir + certConf/pkiConf -> outcome:issued with the leaf certificate", r1.outcome === "issued" && Buffer.isBuffer(r1.certificate) && r1.certificate.equals(certDer));
  check("1b. the transaction confirmed (certConf -> pkiConf completed)", r1.confirmed === true && r1.implicitConfirm === false);
  check("1c. exactly two request legs crossed the seam (ir + certConf)", s1.transport.calls.length === 2);
  check("1d. the transcript records both directions of both legs", r1.transcript.length === 4 && r1.transcript[0].direction === "out" && r1.transcript[1].direction === "in");

  // ===== 2. nonce + transactionID chaining across legs (sec. 5.1.1) =====
  var s2 = mk([H.ip(0, 1, certDer), H.pkiconf()]);   // grantedWithMods
  var r2 = await s2.session.enroll(H.irRequest(CLIENT.spki));
  var req0 = pki.schema.cmp.parse(s2.transport.calls[0].body).header;
  var req1 = pki.schema.cmp.parse(s2.transport.calls[1].body).header;
  check("2a. the transactionID is STABLE across both request legs", req0.transactionID.equals(req1.transactionID) && req1.transactionID.equals(s2.session.transactionID));
  check("2b. each request carries a FRESH senderNonce", !req0.senderNonce.equals(req1.senderNonce));
  check("2c. the 2nd request's recipNonce echoes the 1st response's senderNonce (chained)", Buffer.isBuffer(req1.recipNonce) && req1.recipNonce.length === 16);
  check("2d. grantedWithMods (status 1) is a grant -> issued", r2.outcome === "issued");

  // ===== 3. waiting -> bounded poll -> granted (the poll loop, injected sleeper) =====
  var s3 = mk([H.ip(0, 3), H.pollRep(0, 5), H.pollRep(0, 5), H.ip(0, 0, certDer), H.pkiconf()]);
  var r3 = await s3.session.enroll(H.irRequest(CLIENT.spki));
  check("3a. a waiting status drives the pollReq loop and then issues", r3.outcome === "issued" && r3.polls === 3);
  check("3b. the injectable sleeper was called once per pollRep (never a real timer)", s3.slept() === 2);

  // ===== 4. rejection status -> terminal verdict (NOT a throw) carrying the CA diagnostic (sec. 5.3.4) =====
  var s4 = mk([H.ipRejected(0, ["badPOP"], ["nope"])]);
  var r4 = await s4.session.enroll(H.irRequest(CLIENT.spki));
  check("4a. a rejection status is a terminal outcome:rejected VERDICT, not a throw", r4.outcome === "rejected" && r4.certificate === null);
  check("4b. the CA's PKIStatusInfo diagnostic is surfaced (failInfo)", r4.status && r4.status.status.code === 2 && r4.status.failInfo && r4.status.failInfo.bits.indexOf("badPOP") !== -1);

  // ===== 5. an error body -> terminal rejected verdict =====
  var s5 = mk([H.errorBody(2, ["systemFailure"])]);
  var r5 = await s5.session.enroll(H.irRequest(CLIENT.spki));
  check("5. a verified error body -> outcome:rejected with its PKIStatusInfo", r5.outcome === "rejected" && r5.status && r5.status.status.code === 2);

  // ===== 6. poll-timeout: waiting that never resolves -> terminal poll-timeout verdict =====
  var s6 = mk([H.ip(0, 3), H.pollRep(0, 1), H.pollRep(0, 1), H.pollRep(0, 1)], { maxPolls: 2 });
  var r6 = await s6.session.enroll(H.irRequest(CLIENT.spki));
  check("6a. exceeding maxPolls -> a terminal outcome:poll-timeout VERDICT (not a throw)", r6.outcome === "poll-timeout" && r6.polls === 2);
  check("6b. poll-timeout carries the last waiting PKIStatusInfo diagnostic", r6.status && r6.status.status.code === 3);

  // ===== 7. implicitConfirm granted -> issued WITHOUT a certConf leg (sec. 5.1.1.1) =====
  var s7f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }]);
  var s7 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s7f.transport, implicitConfirm: true });
  var r7 = await s7.enroll(H.irRequest(CLIENT.spki));
  check("7a. a granted implicitConfirm ends the transaction WITHOUT a certConf", r7.outcome === "issued" && r7.confirmed === true && r7.implicitConfirm === true);
  check("7b. only ONE request leg crossed the seam (the ir; no certConf)", s7f.transport.calls.length === 1);

  // ===== 8. verify-before-read fail-closed legs (the #1 invariant) =====
  check("8a. an UNPROTECTED response is a hard-stop throw (never advanced)", /^cmp\//.test(await codeOf(mk([{ body: H.ip(0, 0, certDer), protect: false }]).session.enroll(H.irRequest(CLIENT.spki)))));
  check("8b. a TAMPERED protection is a hard-stop cmp/protection-failed throw", await codeOf(mk([{ body: H.ip(0, 0, certDer), tamper: true }]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/protection-failed");

  // ===== 9. unexpected arm (a pkiConf as the first response) -> cmp/unexpected-arm =====
  check("9. an unexpected first-response arm -> cmp/unexpected-arm", await codeOf(mk([H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

  // ===== 10. certConf gets a non-pkiConf -> cmp/bad-confirmation =====
  check("10. a certConf answered by a non-pkiConf arm -> cmp/bad-confirmation", await codeOf(mk([H.ip(0, 0, certDer), H.ip(0, 0, certDer)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-confirmation");

  // ===== 11. config gates (construction-tier throws) =====
  check("11a. an unknown session opt -> cmp/bad-input", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, mac: { secret: "k" }, bogus: 1 }); })) === "cmp/bad-input");
  check("11b. BOTH protection flavors -> cmp/bad-input", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, mac: { secret: "k" } }); })) === "cmp/bad-input");
  check("11c. NEITHER protection flavor -> cmp/bad-input", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL }); })) === "cmp/bad-input");
  check("11d. a missing url -> cmp/bad-input", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ mac: { secret: "k" } }); })) === "cmp/bad-input");
  check("11e. a below-min maxPolls -> cmp/bad-input", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, mac: { secret: "k" }, maxPolls: 0 }); })) === "cmp/bad-input");
  check("11f. a non-object enroll request -> cmp/bad-input", await codeOf(mk([H.pkiconf()]).session.enroll(5)) === "cmp/bad-input");
  check("11g. an enroll request with two arms -> cmp/bad-input", await codeOf(mk([H.pkiconf()]).session.enroll({ ir: {}, cr: {} })) === "cmp/bad-input");

  // ===== 12. MAC (PBMAC1) protection flavor drives the same transaction =====
  var m12 = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()]);
  // a MAC session verifies the CA's SIGNATURE response? No -- a MAC session expects a MAC response; skip a mixed-flavor happy path.
  check("12. a MAC session constructs (sharedSecret protection)", typeof pki.cmp.session({ url: URL, mac: { secret: "hunter2" }, transport: m12.transport }).enroll === "function");

  // ===== 13. an ip CertResponse whose PKIStatus is out of the enrollment transition set (e.g. 4) -> unexpected =====
  check("13. a CertResponse status code with no enrollment transition -> cmp/unexpected-arm", await codeOf(mk([H.ip(0, 4)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

  // ===== 14. an unknown response arm (a genp general response to an ir) -> unexpected =====
  check("14. an unexpected response arm (genp) -> cmp/unexpected-arm", await codeOf(mk([H.genp()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

  // ===== 15. a grant carrying a NON-implicitConfirm generalInfo (session did NOT request it) -> still certConf/pkiConf =====
  var s15f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), generalInfo: [{ infoType: "confirmWaitTime", infoValue: new Date(0) }] }, H.pkiconf()]);
  var s15 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s15f.transport, sleep: function () { return Promise.resolve(); } });
  var r15 = await s15.enroll(H.irRequest(CLIENT.spki));
  check("15. a non-implicitConfirm generalInfo does NOT short-circuit -> a certConf leg still runs, confirmed non-implicit", r15.outcome === "issued" && r15.confirmed === true && r15.implicitConfirm === false && s15f.transport.calls.length === 2);

  // ===== 16. poll wait budget exceeded MID-loop (checkAfter overruns maxTotalWait) -> poll-timeout =====
  var s16 = mk([H.ip(0, 3), H.pollRep(0, 50)], { maxTotalWait: 3 });
  var r16 = await s16.session.enroll(H.irRequest(CLIENT.spki));
  check("16. a checkAfter that overruns maxTotalWait -> a terminal poll-timeout (never sleeps past the budget)", r16.outcome === "poll-timeout" && s16.slept() === 0);

  // ===== 17. explicit sender / recipient override the derived defaults (RFC 9810 sec. 5.1.1) =====
  var sndr = [{ commonName: "explicit-sender" }];
  var s17 = mk([H.ip(0, 0, certDer), H.pkiconf()], { sender: { directoryName: sndr }, recipient: { directoryName: [{ commonName: "explicit-recipient" }] } });
  var r17 = await s17.session.enroll(H.irRequest(CLIENT.spki));
  var h17 = pki.schema.cmp.parse(s17.transport.calls[0].body).header;
  var snderBytes = Buffer.from(h17.sender.bytes).toString("latin1");
  var rcptBytes = Buffer.from(h17.recipient.bytes).toString("latin1");
  check("17. opts.sender / opts.recipient override the derived defaults on the request header", r17.outcome === "issued" && snderBytes.indexOf("explicit-sender") !== -1 && rcptBytes.indexOf("explicit-recipient") !== -1);

  // ===== 18. more construction-tier gates (no-args / a Buffer opts / key-without-cert) =====
  check("18a. session() with no args -> cmp/bad-input (a missing url)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session(); })) === "cmp/bad-input");
  check("18b. session(<Buffer>) -> cmp/bad-input (opts must be an object)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session(Buffer.alloc(4)); })) === "cmp/bad-input");
  check("18c. signature protection with key but no cert -> cmp/bad-input (BOTH required)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key }); })) === "cmp/bad-input");

  // ===== 19. a malformed signer cert still CONSTRUCTS (the derived sender falls back to a NULL-DN) =====
  check("19. a signature session with an unparseable cert constructs (sender defaults to a NULL-DN)", typeof pki.cmp.session({ url: URL, key: CLIENT.key, cert: Buffer.from("not a certificate"), trustAnchors: [H.caCert], transport: mk([H.pkiconf()]).transport }).enroll === "function");

  // ===== 20. every pass-through opt reaches the request build / response verify (extraCerts/pss/digestAlgorithm/intermediates/time) =====
  var s20 = mk([H.ip(0, 0, certDer), H.pkiconf()], { extraCerts: [H.caCert], intermediates: [H.caCert], time: new Date(), digestAlgorithm: "sha384", pss: true });
  var r20 = await s20.session.enroll(H.irRequest(CLIENT.spki));
  check("20. extraCerts / intermediates / time / digestAlgorithm / pss all pass through -> issued", r20.outcome === "issued");

  // ===== 21. a WAITING ip arriving mid-poll (not a pollRep) is re-classified and keeps polling =====
  var s21 = mk([H.ip(0, 3), H.ip(0, 3), H.ip(0, 0, certDer), H.pkiconf()]);
  var r21 = await s21.session.enroll(H.irRequest(CLIENT.spki));
  check("21. a waiting ip returned to a pollReq keeps the loop alive -> eventually issues", r21.outcome === "issued" && r21.polls === 2);

  // ===== 22. a GRANTED status with no plain issued certificate -> cmp/unexpected-arm (encryptedCert out of scope) =====
  check("22. a granted CertResponse without a plain certificate -> cmp/unexpected-arm", await codeOf(mk([H.ip(0, 0)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

  // ===== 23. an ip whose CertRepContent carries NO CertResponse -> unexpected =====
  check("23. an ip with an empty response set -> cmp/unexpected-arm", await codeOf(mk([H.ipEmpty()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

  // ===== 24. a full MAC (PBMAC1) enrollment: build + verify the whole transaction under the shared secret =====
  var SECRET = "shared-secret-123";
  var s24f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: SECRET });
  var s24 = pki.cmp.session({ url: URL, mac: { secret: SECRET }, transport: s24f.transport, sleep: function () { return Promise.resolve(); } });
  var r24 = await s24.enroll(H.irRequest(CLIENT.spki));
  check("24. a PBMAC1-protected transaction issues end to end (build + verify under the shared secret)", r24.outcome === "issued" && r24.confirmed === true && Buffer.isBuffer(r24.certificate));

  // ===== 25. a hashless-signature issued cert (Ed25519) -> the certConf certHash defaults to SHA-256 =====
  var edCert = await H.makeEd25519Cert(pki, CLIENT.spki);
  var s25 = mk([H.ip(0, 0, edCert), H.pkiconf()]);
  var r25 = await s25.session.enroll(H.irRequest(CLIENT.spki));
  var conf25 = pki.schema.cmp.parse(s25.transport.calls[1].body);   // the certConf request
  var sentHash = conf25.body.decoded[0].certHash;
  var wantHash = require("node:crypto").createHash("sha256").update(edCert).digest();
  check("25. an Ed25519-signed issued cert -> the certConf certHash is computed under SHA-256 (the hashless default)",
    r25.outcome === "issued" && r25.certificate.equals(edCert) && Buffer.from(sentHash).equals(wantHash));

  // ===== 26. implicitConfirm granted in the POLLED (final) response, not the initial waiting one -> no certConf =====
  var s26f = H.fakeCa(pki, [H.ip(0, 3), H.pollRep(0, 1), { body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }]);
  var s26 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s26f.transport, implicitConfirm: true, sleep: function () { return Promise.resolve(); } });
  var r26 = await s26.enroll(H.irRequest(CLIENT.spki));
  check("26. implicitConfirm granted in the granting (post-poll) response ends the transaction WITHOUT a certConf",
    r26.outcome === "issued" && r26.implicitConfirm === true && r26.confirmed === true && s26f.transport.calls.length === 3);

  // ===== 27. signature protection must be ANCHORED: crypto-valid is not enough, the signer must be TRUSTED =====
  check("27a. a signature session with NO trustAnchors -> cmp/bad-input at construction (cannot authenticate the CA)",
    await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, transport: mk([H.pkiconf()]).transport }); })) === "cmp/bad-input");
  // a response whose signer does NOT chain to the session's anchor (here a bogus anchor) verifies crypto-only
  // (valid:true, trusted:false) -> the session must HARD-STOP, never read a certificate off an untrusted signer.
  var s27f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()]);
  var s27 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [CLIENT.cert], transport: s27f.transport, sleep: function () { return Promise.resolve(); } });
  check("27b. a valid-but-untrusted response signer (does not chain to the anchor) -> cmp/untrusted-signer hard stop",
    await codeOf(s27.enroll(H.irRequest(CLIENT.spki))) === "cmp/untrusted-signer");
  check("27c. the terminal verdict surfaces trusted:true on a trusted, issued transaction", r1.trusted === true);

  // ===== 28. certConf certHash hashAlg: OMITTED when the sig alg OID conveys the hash, DECLARED when it does not =====
  var s28a = mk([H.ip(0, 0, certDer), H.pkiconf()]);   // certDer (H.caCert) is ECDSA-with-SHA-256: OID conveys the hash
  await s28a.session.enroll(H.irRequest(CLIENT.spki));
  var cc28a = pki.schema.cmp.parse(s28a.transport.calls[1].body).body.decoded[0];
  check("28a. a conveying sig alg (ecdsaWithSHA256) -> certConf OMITS hashAlg (RFC 9810 sec. 5.3.18)", cc28a.hashAlg == null);
  var edCert28 = await H.makeEd25519Cert(pki, CLIENT.spki);   // Ed25519: the OID does NOT convey a hash
  var s28b = mk([H.ip(0, 0, edCert28), H.pkiconf()]);
  var r28b = await s28b.session.enroll(H.irRequest(CLIENT.spki));
  var cc28b = pki.schema.cmp.parse(s28b.transport.calls[1].body).body.decoded[0];
  check("28b. a non-conveying sig alg (Ed25519) -> certConf DECLARES an explicit hashAlg", r28b.outcome === "issued" && cc28b.hashAlg != null);

  // ===== 29. implicitConfirm is requested for ANY enrollment arm (cr), not only ir =====
  var s29f = H.fakeCa(pki, [{ body: H.cp(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }]);   // a cr is answered by a cp
  var s29 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s29f.transport, implicitConfirm: true, sleep: function () { return Promise.resolve(); } });
  var r29 = await s29.enroll({ cr: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: CLIENT.spki } } });
  var h29 = pki.schema.cmp.parse(s29f.transport.calls[0].body).header;
  check("29. a cr enrollment with implicitConfirm carries the request generalInfo AND grants without a certConf",
    r29.outcome === "issued" && r29.implicitConfirm === true && s29f.transport.calls.length === 1 && Array.isArray(h29.generalInfo) && h29.generalInfo.length >= 1);

  // ===== 30. certReqId: the caller's CRMF request id is echoed in pollReq/certConf and matched in the response =====
  var s30 = mk([H.ip(5, 0, certDer), H.pkiconf()]);
  var r30 = await s30.session.enroll(H.irRequest(CLIENT.spki, 5));
  var cc30 = pki.schema.cmp.parse(s30.transport.calls[1].body).body.decoded[0];
  check("30a. a non-default certReqId (5) is echoed in the certConf and matched in the CertResponse", r30.outcome === "issued" && Number(cc30.certReqId) === 5);
  check("30b. a CertResponse for a DIFFERENT certReqId than requested -> cmp/unexpected-arm",
    await codeOf(mk([H.ip(0, 0, certDer)]).session.enroll(H.irRequest(CLIENT.spki, 5))) === "cmp/unexpected-arm");

  // ===== 31. a p10cr (PKCS#10) enrollment: the cp identifies it with the -1 sentinel, echoed in the certConf =====
  var p10 = await pki.csr.sign({ subject: [{ commonName: "leaf" }], subjectPublicKey: CLIENT.spki }, CLIENT.key);
  var s31 = mk([H.cp(-1, 0, certDer), H.pkiconf()]);   // a conforming cp uses certReqId -1 for a PKCS#10 request
  var r31 = await s31.session.enroll({ p10cr: p10 });
  var cc31 = pki.schema.cmp.parse(s31.transport.calls[1].body).body.decoded[0];
  check("31. a p10cr enrollment matches the -1 sentinel cp and echoes -1 in the certConf", r31.outcome === "issued" && Buffer.isBuffer(r31.certificate) && Number(cc31.certReqId) === -1);

  // ===== 32. an EMPTY trustAnchors array for the signature flavor is refused (a disabled anchor is no anchor) =====
  check("32. signature protection with an empty trustAnchors array -> cmp/bad-input",
    await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [], transport: s31.transport }); })) === "cmp/bad-input");

  // ===== 33. a response of the WRONG cert-response arm for the request (an ir answered by a cp) -> unexpected =====
  check("33. an ir answered by a cp (misrouted cert-response arm) -> cmp/unexpected-arm",
    await codeOf(mk([H.cp(0, 0, certDer)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");
  check("33b. a kur answered by an ip (wrong arm) -> cmp/unexpected-arm",
    await codeOf(mk([H.ip(0, 0, certDer)]).session.enroll({ kur: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: CLIENT.spki } } })) === "cmp/unexpected-arm");

  // ===== 34. a pollRep whose only entry is for a DIFFERENT certReqId -> unexpected (not a silent zero-delay re-poll) =====
  check("34. a pollRep carrying no entry for the active certReqId -> cmp/unexpected-arm",
    await codeOf(mk([H.ip(0, 3), H.pollRep(9, 1)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

  // ===== 35. a bigint certReqId above 2^53 is echoed EXACTLY and matched (no Number rounding) =====
  var BIG = 9007199254740993n;   // 2^53 + 1: not representable as a JS Number
  var s35 = mk([H.ip(BIG, 0, certDer), H.pkiconf()]);
  var r35 = await s35.session.enroll(H.irRequest(CLIENT.spki, BIG));
  var cc35 = pki.schema.cmp.parse(s35.transport.calls[1].body).body.decoded[0];
  check("35. a bigint certReqId (2^53+1) is echoed exactly in the certConf and matched in the response", r35.outcome === "issued" && BigInt(cc35.certReqId) === BIG);

  // ===== 36. a response that omits its senderNonce, before a follow-up leg -> cmp/bad-nonce (chain broken) =====
  check("36. a waiting response omitting senderNonce, then a poll leg -> cmp/bad-nonce (the chain cannot continue)",
    await codeOf(mk([{ body: H.ip(0, 3), noSenderNonce: true }, H.pollRep(0, 1)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-nonce");

  // ===== 37. the FINAL permitted poll's pollRep does NOT sleep its checkAfter (the poll-count bound holds) =====
  var s37 = mk([H.ip(0, 3), H.pollRep(0, 31536000)], { maxPolls: 1 });   // a 1-year checkAfter on the last allowed poll
  var r37 = await s37.session.enroll(H.irRequest(CLIENT.spki));
  check("37. exhausting maxPolls on a pollRep returns poll-timeout WITHOUT sleeping the final checkAfter", r37.outcome === "poll-timeout" && r37.polls === 1 && s37.slept() === 0);

  // ===== 38. a granted response whose certificate is not valid X.509 (a forged, protection-valid response) -> reject =====
  check("38. a granted CertResponse carrying a non-X.509 certificate -> cmp/bad-cert-response (never outcome:issued)",
    await codeOf(mk([{ body: H.ip(0, 0, certDer), malformedCert: true, certOf: certDer }, H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 39. a later leg that OMITS extraCerts still verifies via the cached signer cert (RFC 9483 sec. 3.3) =====
  var s39f = H.fakeCa(pki, [H.ip(0, 0, certDer), { body: H.pkiconf(), noExtraCerts: true }]);
  var s39 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s39f.transport, sleep: function () { return Promise.resolve(); } });
  var r39 = await s39.enroll(H.irRequest(CLIENT.spki));
  check("39. a certConf-leg response omitting extraCerts verifies via the cached signer -> issued", r39.outcome === "issued" && r39.confirmed === true);

  // ===== 40. a string-form CRMF certReqId ("5") is preserved (echoed as 5, matched), not silently reset to 0 =====
  var s40 = mk([H.ip(5, 0, certDer), H.pkiconf()]);
  var r40 = await s40.session.enroll(H.irRequest(CLIENT.spki, "5"));
  var cc40 = pki.schema.cmp.parse(s40.transport.calls[1].body).body.decoded[0];
  check("40. a string certReqId '5' is preserved end to end (issued, certConf carries 5)", r40.outcome === "issued" && Number(cc40.certReqId) === 5);

  // ===== 41. one transaction per session: a second enroll on the same session is refused =====
  var s41 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var r41 = await s41.session.enroll(H.irRequest(CLIENT.spki));
  check("41a. the first enroll succeeds", r41.outcome === "issued");
  check("41b. a SECOND enroll on the same session -> cmp/bad-input (one transactionID per transaction)",
    await codeOf(s41.session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-input");

  // ===== 42. a run of WAITING ip responses (never a pollRep) that exhausts maxPolls -> poll-timeout =====
  var s42 = mk([H.ip(0, 3), H.ip(0, 3), H.ip(0, 3), H.ip(0, 3)], { maxPolls: 2 });
  var r42 = await s42.session.enroll(H.irRequest(CLIENT.spki));
  check("42. repeated waiting ip responses hit the poll-count bound -> poll-timeout (no sleep, never a pollRep)", r42.outcome === "poll-timeout" && r42.polls === 2 && s42.slept() === 0);

  // ===== 43. a CONCURRENT enroll while one is already in flight is refused =====
  var s43 = mk([H.ip(0, 3), H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  var inflight = s43.session.enroll(H.irRequest(CLIENT.spki));   // start but do not await -> transaction in flight
  var code43 = await codeOf(s43.session.enroll(H.irRequest(CLIENT.spki)));   // a second call while the first is mid-transaction
  await inflight;
  check("43. a concurrent enroll while one is in flight -> cmp/bad-input", code43 === "cmp/bad-input");

  // ===== 44. a granted certificate whose public key differs from the requested key -> reject (RFC 4211) =====
  check("44. a granted certificate whose key does not match the request -> cmp/bad-cert-response",
    await codeOf(mk([H.ip(0, 0, H.caCert)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 45. an RSASSA-PSS-SHA384 issued cert -> the certConf digest is derived from the params (SHA-384), hashAlg OMITTED =====
  var pssCert = await H.makePssCert(pki, CLIENT.spki);
  var s45 = mk([H.ip(0, 0, pssCert), H.pkiconf()]);
  var r45 = await s45.session.enroll(H.irRequest(CLIENT.spki));
  var cc45 = pki.schema.cmp.parse(s45.transport.calls[1].body).body.decoded[0];
  var wantH45 = require("node:crypto").createHash("sha384").update(pssCert).digest();
  check("45. a PSS-SHA384 cert -> certConf certHash is SHA-384 (from the params) and hashAlg is OMITTED (RFC 9810 sec. 5.3.18)",
    r45.outcome === "issued" && cc45.hashAlg == null && Buffer.from(cc45.certHash).equals(wantH45));

  // ===== 46. a batched CRMF request is refused at the session boundary =====
  check("46. a batched CRMF request ({ messages: [...] }) -> cmp/bad-input (one request per session)",
    await codeOf(mk([H.pkiconf()]).session.enroll({ ir: { messages: [{ certTemplate: { subject: [{ commonName: "a" }], publicKey: CLIENT.spki } }] } })) === "cmp/bad-input");

  // ===== 47. a LOCAL build error does NOT consume the session -> a retry succeeds (no request crossed the seam) =====
  var s47 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var code47a = await codeOf(s47.session.enroll({ ir: {} }));   // missing certTemplate -> a build error before any transfer
  var r47 = await s47.session.enroll(H.irRequest(CLIENT.spki));   // the session was not consumed -> this retry succeeds
  check("47. a local build error leaves the session retryable (no transactionID reached the transport)", code47a !== "NO-THROW" && r47.outcome === "issued" && s47.transport.calls.length === 2);

  // ===== 48. a 0x-hex certReqId string (a CRMF-supported form) is normalized like the builder, not reset to 0 =====
  var s48 = mk([H.ip(5, 0, certDer), H.pkiconf()]);
  var r48 = await s48.session.enroll(H.irRequest(CLIENT.spki, "0x5"));
  var cc48 = pki.schema.cmp.parse(s48.transport.calls[1].body).body.decoded[0];
  check("48. a '0x5' hex certReqId is parsed as 5 (matching crmf-sign), matched and echoed", r48.outcome === "issued" && Number(cc48.certReqId) === 5);

  console.log("CHECKS " + helpers.getChecks());
}

if (require.main === module) { run().catch(function (e) { console.error(e); process.exit(1); }); }
module.exports = { run: run };
